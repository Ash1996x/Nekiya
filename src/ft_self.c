#ifdef FT_DIAGNOSTICS

#include "ft.h"

#include <stdlib.h>
#include <string.h>

static int ft_self_sb(void) {
    ft_sb s;
    ft_sb_init(&s);
    ft_sb_adds(&s, "{\"k\":");
    ft_sb_addf(&s, "%d", 42);
    ft_sb_adds(&s, ",\"s\":");
    ft_sb_addj(&s, "a\"b\\c\nd");
    ft_sb_adds(&s, "}");
    if (!s.buf || strcmp(s.buf, "{\"k\":42,\"s\":\"a\\\"b\\\\c\\nd\"}") != 0) {
        fprintf(stderr, "selftest: FAIL string builder - %s\n", s.buf ? s.buf : "(null)");
        ft_sb_free(&s);
        return 1;
    }
    ft_sb_free(&s);
    return 0;
}

static int ft_self_pe(const char* path, const char* label) {
    uint8_t* img;
    size_t size = 0;
    ft_pe pe;
    int fails = 0;

    img = ft_read_file(path, &size);
    if (!img) {
        fprintf(stderr, "selftest: FAIL %s - cannot read %s\n", label, path);
        return 1;
    }
    if (!ft_pe_open(img, size, &pe)) {
        fprintf(stderr, "selftest: FAIL %s - not a PE32+ image (%s)\n", label, path);
        free(img);
        return 1;
    }
    if (pe.nsec == 0) {
        fprintf(stderr, "selftest: FAIL %s - no sections\n", label);
        fails++;
    }
    printf("selftest: ok   %s PE32+ image, %u sections, %u bytes\n", label,
           pe.nsec, (unsigned)size);
    free(img);
    return fails;
}

static int ft_self_ntos_exports(void) {
    static const char* wanted[] = {
        "PsInitialSystemProcess",
        "PsLoadedModuleList",
        "EtwRegister",
        NULL
    };
    int i;
    int fails = 0;

    for (i = 0; wanted[i]; i++) {
        uint32_t rva = 0;
        if (!ft_ntos_export_rva(NULL, wanted[i], &rva) || rva == 0) {
            fprintf(stderr, "selftest: FAIL export %s not found in ntoskrnl.exe\n",
                    wanted[i]);
            fails++;
        } else {
            printf("selftest: ok   export %-26s rva 0x%x\n", wanted[i], rva);
        }
    }
    return fails;
}

static int ft_self_etwti(void) {
    uint32_t handle_rva = 0;
    uint32_t reg_rva = 0;
    if (!ft_etwti_discover(&handle_rva, &reg_rva) || handle_rva == 0) {
        fprintf(stderr,
                "selftest: FAIL ETW Threat-Intelligence provider handle not found\n");
        return 1;
    }
    printf("selftest: ok   ETW-TI handle rva 0x%x (EtwRegister rva 0x%x)\n",
           handle_rva, reg_rva);
    return 0;
}

static int ft_self_driver(const char* dir) {
    char path[FT_MAX_PATH + 64];
    char alt[FT_MAX_PATH + 64];
    DWORD attr;

    if (!dir || !dir[0]) {
        fprintf(stderr, "selftest: FAIL no self directory\n");
        return 1;
    }
    snprintf(path, sizeof path, "%s\\kernel\\msft.sys", dir);
    attr = GetFileAttributesA(path);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        snprintf(alt, sizeof alt, "%s\\..\\kernel\\msft.sys", dir);
        attr = GetFileAttributesA(alt);
        if (attr != INVALID_FILE_ATTRIBUTES) {
            memcpy(path, alt, sizeof alt < sizeof path ? sizeof alt : sizeof path);
            path[sizeof path - 1] = '\0';
        }
    }
    if (attr == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "selftest: WARN BYOVD driver not found at %s "
                        "(pass --sys <path>)\n", path);
        return 0;
    }
    return ft_self_pe(path, "msft.sys");
}

typedef struct ft_exp_ctx {
    const char* pat;
    int         hits;
} ft_exp_ctx;

static int ft_exp_cb(void* ctx, const char* name, uint32_t rva) {
    ft_exp_ctx* e = (ft_exp_ctx*)ctx;
    if (e->pat && *e->pat) {

        size_t nl = strlen(name);
        size_t pl = strlen(e->pat);
        size_t i;
        int hit = 0;
        if (pl == 0) hit = 1;
        for (i = 0; i + pl <= nl && !hit; i++) {
            size_t k;
            for (k = 0; k < pl; k++) {
                char ca = e->pat[k];
                char cb = name[i + k];
                if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
                if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
                if (ca != cb) break;
            }
            if (k == pl) hit = 1;
        }
        if (!hit) return 0;
    }
    printf("  %-46s rva 0x%x%s\n", name, rva, rva ? "" : " (forwarded)");
    e->hits++;
    return 0;
}

int ft_list_exports(const char* pattern) {
    char path[FT_MAX_PATH];
    uint8_t* img;
    size_t size = 0;
    ft_pe pe;
    ft_exp_ctx e;

    if (!ft_sysdir_file("ntoskrnl.exe", path, sizeof path)) {
        fprintf(stderr, "cannot locate ntoskrnl.exe\n");
        return 1;
    }
    img = ft_read_file(path, &size);
    if (!img) { fprintf(stderr, "cannot read ntoskrnl.exe\n"); return 1; }
    if (!ft_pe_open(img, size, &pe)) { free(img); fprintf(stderr, "bad PE\n"); return 1; }
    e.pat = pattern;
    e.hits = 0;
    ft_pe_enum_exports(&pe, ft_exp_cb, &e);
    free(img);
    printf("%d export(s) matched\n", e.hits);
    return 0;
}

static void ft_doc_reg(ft_ctx* c, const char* label, const char* path,
                       const char* name) {
    DWORD v = 0;
    if (ft_reg_get_dword(path, name, &v)) {
        ft_info(c, label, "\"key\":\"%s\",\"name\":\"%s\",\"value\":%lu", path, name, v);
    } else {
        ft_info(c, label, "\"key\":\"%s\",\"name\":\"%s\",\"value\":null", path, name);
    }
}

static void ft_doc_service(ft_ctx* c, const char* name) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    SC_HANDLE svc;
    DWORD state = 0;
    DWORD start = 0;

    if (!scm) {
        ft_info(c, "doc_service", "\"name\":\"%s\",\"state\":\"no_scm\"", name);
        return;
    }
    svc = OpenServiceA(scm, name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (!svc) {
        ft_info(c, "doc_service", "\"name\":\"%s\",\"state\":\"absent\"", name);
        CloseServiceHandle(scm);
        return;
    }
    {
        SERVICE_STATUS ss;
        char cfg[4096];
        DWORD need = 0;
        if (QueryServiceStatus(svc, &ss)) state = ss.dwCurrentState;
        if (QueryServiceConfigA(svc, (LPQUERY_SERVICE_CONFIGA)(void*)cfg,
                                (DWORD)sizeof cfg, &need) && need >= 8) {

            start = *(DWORD*)(cfg + 4);
        }
    }
    ft_info(c, "doc_service",
            "\"name\":\"%s\",\"state\":%lu,\"start_type\":%lu", name,
            (unsigned long)state, (unsigned long)start);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}

int ft_doctor(ft_ctx* c) {
    static const char* svcs[] = {
        "WinNotify", "WinDefend", "WdNisSvc", "WdFilter", "SenseNdrvSvc", "wscsvc", NULL
    };
    static const char* drvs[] = {
        "msft.sys", "WdFilter.sys", "SenseNdrv.sys", NULL
    };
    int i;

    ft_info(c, "doc_build", "\"build\":%u", c ? c->build : 0);
    ft_info(c, "doc_token", "\"system\":%d",
            c ? (ft_proc_is_system(c) ? 1 : 0) : 0);

    ft_doc_reg(c, "doc_hvci",
               "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
               "Enabled");
    ft_doc_reg(c, "doc_blocklist",
               "SYSTEM\\CurrentControlSet\\Control\\CI\\Config",
               "VulnerableDriverBlocklistEnable");
    ft_doc_reg(c, "doc_defender_rtm",
               "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection",
               "DisableRealtimeMonitoring");
    ft_doc_reg(c, "doc_defender_anti",
               "SOFTWARE\\Policies\\Microsoft\\Windows Defender",
               "DisableAntiSpyware");

    for (i = 0; svcs[i]; i++) ft_doc_service(c, svcs[i]);

    if (c && c->km_ready) {
        for (i = 0; drvs[i]; i++) {
            uint64_t base = 0, size = 0;
            if (ft_mod_range(c, drvs[i], &base, &size)) {
                ft_info(c, "doc_driver", "\"name\":\"%s\",\"base\":\"0x%llx\",\"size\":%llu",
                        drvs[i], (unsigned long long)base, (unsigned long long)size);
            } else {
                ft_info(c, "doc_driver", "\"name\":\"%s\",\"loaded\":false", drvs[i]);
            }
        }
    }

    if (c) {
        ft_etw_count_sessions(c);
    }
    ft_ok(c, "doctor_done", "");
    return FT_OK;
}

int ft_selftest(ft_ctx* c) {
    int fails = 0;
    char path[FT_MAX_PATH + 64];

    printf("nekiya selftest\n------------------\n");
    fails += ft_self_sb();
    if (ft_sysdir_file("ntoskrnl.exe", path, sizeof path)) {
        fails += ft_self_pe(path, "ntoskrnl.exe");
    } else {
        fprintf(stderr, "selftest: FAIL cannot locate ntoskrnl.exe\n");
        fails++;
    }
    fails += ft_self_ntos_exports();
    fails += ft_self_etwti();
    fails += ft_self_driver(c ? c->self_dir : NULL);

    printf("------------------\nselftest: %d failure(s)\n", fails);
    return fails ? 1 : 0;
}

#endif
