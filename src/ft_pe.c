#include "ft.h"

#include <stdlib.h>
#include <string.h>

static uint16_t rd16(const uint8_t* p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int ft_pe_open(const uint8_t* data, size_t size, ft_pe* pe) {
    uint32_t e_lfanew;
    uint16_t magic;
    uint16_t size_opt;
    uint32_t i;
    size_t opt_off;
    size_t sec_off;
    uint32_t nsections;

    if (!data || !pe) return 0;
    memset(pe, 0, sizeof(*pe));
    pe->data = data;

    if (size < 0x40) return 0;
    if (!(data[0] == 'M' && data[1] == 'Z')) return 0;

    e_lfanew = rd32(data + 0x3C);
    if (e_lfanew < 0x40 || (size_t)e_lfanew + 0x18 > size) return 0;
    if (!(data[e_lfanew] == 'P' && data[e_lfanew + 1] == 'E' &&
          data[e_lfanew + 2] == 0 && data[e_lfanew + 3] == 0)) return 0;

    opt_off = (size_t)e_lfanew + 0x18;
    if (opt_off + 0x70 > size) return 0;

    magic = rd16(data + opt_off);
    if (magic != 0x20B) return 0;

    size_opt = rd16(data + (size_t)e_lfanew + 0x14);
    if (size_opt < 0xF0) return 0;

    pe->image_base = rd32(data + opt_off + 0x18);

    nsections = rd16(data + (size_t)e_lfanew + 6);
    pe->sec_rva = rd32(data + opt_off + 0xC8);
    pe->sec_size = rd32(data + opt_off + 0xCC);
    pe->exp_rva = rd32(data + opt_off + 0x70);
    pe->exp_size = rd32(data + opt_off + 0x74);

    sec_off = opt_off + size_opt;
    if (nsections > FT_SCN_CNT) {
        fprintf(stderr, "ft_pe: warning: image has %u sections, only %d tracked\n",
                nsections, FT_SCN_CNT);
        nsections = FT_SCN_CNT;
    }
    if (sec_off + (size_t)nsections * 40 > size) return 0;

    pe->nsec = nsections;
    for (i = 0; i < nsections; i++) {
        const uint8_t* s = data + sec_off + (size_t)i * 40;
        ft_sec* d = &pe->sec[i];
        memcpy(d->name, s, 8);
        d->name[8] = '\0';
        d->vsize = rd32(s + 8);
        d->va = rd32(s + 12);
        d->raw_size = rd32(s + 16);
        d->raw_off = rd32(s + 20);
        d->flags = rd32(s + 36);
    }
    pe->size = size;
    if (pe->exp_rva != 0 && pe->exp_size != 0) {
        size_t off;
        if (ft_pe_rva_to_off(pe, pe->exp_rva, (size_t)pe->exp_size, &off)) {
            pe->exp_dir = data + off;
        }
    }
    return 1;
}

int ft_pe_rva_to_off(const ft_pe* pe, uint32_t rva, size_t len, size_t* off) {
    uint32_t i;
    if (!pe || !off) return 0;
    for (i = 0; i < pe->nsec; i++) {
        const ft_sec* s = &pe->sec[i];
        uint32_t span = s->vsize ? s->vsize : s->raw_size;
        uint32_t delta;
        size_t o;
        if (rva < s->va) continue;
        if (rva >= s->va + span) continue;
        delta = rva - s->va;
        o = (size_t)s->raw_off + (size_t)delta;
        if (o > pe->size) return 0;
        if (len && o + len > pe->size) return 0;
        *off = o;
        return 1;
    }
    if (pe->nsec > 0 && rva < pe->sec[0].va) {
        if ((size_t)rva + len > pe->size) return 0;
        *off = rva;
        return 1;
    }
    return 0;
}

int ft_pe_off_to_rva(const ft_pe* pe, size_t off, uint32_t* rva) {
    uint32_t i;
    if (!pe || !rva) return 0;
    for (i = 0; i < pe->nsec; i++) {
        const ft_sec* s = &pe->sec[i];
        if (off < s->raw_off) continue;
        if (off >= (size_t)s->raw_off + s->raw_size) continue;
        *rva = s->va + (uint32_t)(off - s->raw_off);
        return 1;
    }
    if (pe->nsec > 0 && off < pe->sec[0].raw_off) {
        *rva = (uint32_t)off;
        return 1;
    }
    return 0;
}

int ft_pe_data_dir(const ft_pe* pe, uint32_t idx, uint32_t* rva, uint32_t* size) {
    uint32_t e;
    size_t opt;
    if (!pe || !rva || !size) return 0;
    if (idx > 15) return 0;
    e = rd32(pe->data + 0x3C);
    opt = (size_t)e + 0x18;
    if (opt + 0x78 + 8 > pe->size) return 0;
    *rva = rd32(pe->data + opt + 0x70 + (size_t)idx * 8);
    *size = rd32(pe->data + opt + 0x74 + (size_t)idx * 8);
    return 1;
}

int ft_pe_section_of(const ft_pe* pe, uint32_t rva, const ft_sec** out, int* writable) {
    uint32_t i;
    if (!pe) return 0;
    for (i = 0; i < pe->nsec; i++) {
        const ft_sec* s = &pe->sec[i];
        uint32_t span = s->vsize ? s->vsize : s->raw_size;
        if (rva < s->va) continue;
        if (rva >= s->va + span) continue;
        if (out) *out = s;
        if (writable) *writable = (s->flags & 0x80000000u) ? 1 : 0;
        return 1;
    }
    return 0;
}

static int ft_name_eq(const char* s, size_t avail, const char* name) {
    size_t k;
    size_t nl = strlen(name);
    if (nl >= avail) return 0;
    for (k = 0; k < nl; k++) {
        if (s[k] != name[k]) return 0;
    }
    if (s[nl] != '\0') return 0;
    return 1;
}

int ft_pe_export_rva(const ft_pe* pe, const char* name, uint32_t* rva) {
    const uint8_t* dir;
    uint32_t nfuncs;
    uint32_t nnames;
    uint32_t base;
    uint32_t afunc;
    uint32_t anames;
    uint32_t aords;
    uint32_t i;

    if (!pe || !name || !rva) return 0;
    *rva = 0;
    if (!pe->exp_dir) return 0;
    dir = pe->exp_dir;

    nfuncs = rd32(dir + 20);
    nnames = rd32(dir + 24);
    base = rd32(dir + 16);
    afunc = rd32(dir + 28);
    anames = rd32(dir + 32);
    aords = rd32(dir + 36);
    if (nnames == 0 || nnames > 0x10000u) return 0;
    if (nfuncs == 0 || nfuncs > 0x10000u) return 0;

    for (i = 0; i < nnames; i++) {
        uint32_t nrva;
        uint32_t ord;
        uint32_t frva;
        size_t off;
        size_t avail;

        if (!ft_pe_rva_to_off(pe, anames + i * 4, 4, &off)) return 0;
        nrva = rd32(pe->data + off);
        if (!ft_pe_rva_to_off(pe, nrva, 1, &off)) return 0;
        avail = pe->size - off;
        if (avail > 256) avail = 256;
        if (!ft_name_eq((const char*)(pe->data + off), avail, name)) continue;

        if (!ft_pe_rva_to_off(pe, aords + i * 2, 2, &off)) return 0;
        ord = rd16(pe->data + off);
        if (ord + base >= nfuncs) continue;
        if (!ft_pe_rva_to_off(pe, afunc + ord * 4, 4, &off)) return 0;
        frva = rd32(pe->data + off);
        if (frva == 0) continue;

        if (pe->exp_rva != 0 && frva >= pe->exp_rva &&
            frva < pe->exp_rva + pe->exp_size) {
            return 0;
        }
        *rva = frva;
        return 1;
    }
    return 0;
}

int ft_pe_enum_exports(const ft_pe* pe, ft_export_cb cb, void* ctx) {
    const uint8_t* dir;
    uint32_t nfuncs;
    uint32_t nnames;
    uint32_t base;
    uint32_t afunc;
    uint32_t anames;
    uint32_t aords;
    uint32_t i;
    int found = 0;

    if (!pe || !cb || !pe->exp_dir) return 0;
    dir = pe->exp_dir;

    nfuncs = rd32(dir + 20);
    nnames = rd32(dir + 24);
    base = rd32(dir + 16);
    afunc = rd32(dir + 28);
    anames = rd32(dir + 32);
    aords = rd32(dir + 36);
    if (nnames == 0 || nnames > 0x10000u) return 0;
    if (nfuncs == 0 || nfuncs > 0x10000u) return 0;

    for (i = 0; i < nnames; i++) {
        uint32_t nrva;
        uint32_t ord;
        uint32_t frva;
        size_t off;
        size_t avail;
        char name[128];

        if (!ft_pe_rva_to_off(pe, anames + i * 4, 4, &off)) return found;
        nrva = rd32(pe->data + off);
        if (!ft_pe_rva_to_off(pe, nrva, 1, &off)) return found;
        avail = pe->size - off;
        if (avail > sizeof name) avail = sizeof name;
        {
            size_t k = 0;
            while (k < avail && pe->data[off + k] != '\0' && k + 1 < sizeof name) k++;
            memcpy(name, pe->data + off, k);
            name[k] = '\0';
        }
        if (!ft_pe_rva_to_off(pe, aords + i * 2, 2, &off)) return found;
        ord = rd16(pe->data + off);
        if (ord + base >= nfuncs) continue;
        if (!ft_pe_rva_to_off(pe, afunc + ord * 4, 4, &off)) return found;
        frva = rd32(pe->data + off);
        if (frva == 0) continue;
        if (pe->exp_rva != 0 && frva >= pe->exp_rva &&
            frva < pe->exp_rva + pe->exp_size) {
            frva = 0;
        }
        found++;
        if (cb(ctx, name, frva)) return found;
    }
    return found;
}

static uint8_t* g_ntos_img = NULL;
static size_t   g_ntos_size = 0;
static ft_pe    g_ntos_pe;
static int      g_ntos_ready = 0;

int ft_ntos_export_rva(ft_ctx* c, const char* name, uint32_t* rva) {
    char path[FT_MAX_PATH];

    (void)c;
    if (!name || !rva) return 0;
    *rva = 0;

    if (!g_ntos_ready) {
        if (!ft_sysdir_file("ntoskrnl.exe", path, sizeof path)) return 0;
        g_ntos_img = ft_read_file(path, &g_ntos_size);
        if (!g_ntos_img) return 0;
        if (!ft_pe_open(g_ntos_img, g_ntos_size, &g_ntos_pe)) {
            free(g_ntos_img);
            g_ntos_img = NULL;
            return 0;
        }
        g_ntos_ready = 1;
    }
    if (!ft_pe_export_rva(&g_ntos_pe, name, rva)) return 0;
    return 1;
}

int ft_ntos_rva_bytes(ft_ctx* c, uint32_t rva, void* dst, size_t len) {
    size_t off = 0;

    (void)c;
    if (!dst || len == 0) return 0;
    if (!g_ntos_ready) {
        char path[FT_MAX_PATH];
        if (!ft_sysdir_file("ntoskrnl.exe", path, sizeof path)) return 0;
        g_ntos_img = ft_read_file(path, &g_ntos_size);
        if (!g_ntos_img) return 0;
        if (!ft_pe_open(g_ntos_img, g_ntos_size, &g_ntos_pe)) {
            free(g_ntos_img);
            g_ntos_img = NULL;
            return 0;
        }
        g_ntos_ready = 1;
    }
    if (!ft_pe_rva_to_off(&g_ntos_pe, rva, len, &off)) return 0;
    memcpy(dst, g_ntos_img + off, len);
    return 1;
}
