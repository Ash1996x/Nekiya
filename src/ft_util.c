#include "ft.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

void ft_sb_init(ft_sb* s) {
    s->buf = NULL;
    s->len = 0;
    s->cap = 0;
    s->err = 0;
}

void ft_sb_free(ft_sb* s) {
    if (!s) return;
    free(s->buf);
    s->buf = NULL;
    s->len = 0;
    s->cap = 0;
}

static int ft_sb_reserve(ft_sb* s, size_t extra) {
    size_t need = s->len + extra + 1;
    size_t cap;
    char* nb;

    if (s->err) return 0;
    if (need <= s->cap) return 1;
    cap = s->cap ? s->cap : 256;
    while (cap < need) cap *= 2;
    nb = (char*)realloc(s->buf, cap);
    if (!nb) { s->err = 1; return 0; }
    s->buf = nb;
    s->cap = cap;
    return 1;
}

void ft_sb_adds(ft_sb* s, const char* str) {
    size_t n;
    if (!s || !str) return;
    n = strlen(str);
    if (!ft_sb_reserve(s, n)) return;
    memcpy(s->buf + s->len, str, n);
    s->len += n;
    s->buf[s->len] = '\0';
}

void ft_sb_addf(ft_sb* s, const char* fmt, ...) {
    va_list ap;
    int n;
    char stackbuf[512];

    if (!s || !fmt) return;
    va_start(ap, fmt);
    n = vsnprintf(stackbuf, sizeof stackbuf, fmt, ap);
    va_end(ap);
    if (n < 0) { s->err = 1; return; }
    if ((size_t)n < sizeof stackbuf) {
        ft_sb_adds(s, stackbuf);
        return;
    }
    if (!ft_sb_reserve(s, (size_t)n)) return;
    va_start(ap, fmt);
    vsnprintf(s->buf + s->len, (size_t)n + 1, fmt, ap);
    va_end(ap);
    s->len += (size_t)n;
}

void ft_sb_addj_n(ft_sb* s, const char* str, size_t n) {
    size_t i;
    if (!s) return;
    if (!str) { ft_sb_adds(s, "null"); return; }
    ft_sb_adds(s, "\"");
    for (i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)str[i];
        switch (ch) {
        case '"':  ft_sb_adds(s, "\\\""); break;
        case '\\': ft_sb_adds(s, "\\\\"); break;
        case '\n': ft_sb_adds(s, "\\n");  break;
        case '\r': ft_sb_adds(s, "\\r");  break;
        case '\t': ft_sb_adds(s, "\\t");  break;
        default:
            if (ch < 0x20 || ch == 0x7f) ft_sb_addf(s, "\\u%04x", ch);
            else ft_sb_addf(s, "%c", ch);
        }
    }
    ft_sb_adds(s, "\"");
}

void ft_sb_addj(ft_sb* s, const char* str) {
    if (!str) { ft_sb_adds(s, "null"); return; }
    ft_sb_addj_n(s, str, strlen(str));
}

void ft_esc(char* out, size_t cap, const char* in) {
    size_t n = 0;
    if (!out || cap == 0) return;
    out[0] = '\0';
    if (!in) return;
    if (n + 1 < cap) out[n++] = '"';
    for (; *in && n + 7 < cap; in++) {
        unsigned char ch = (unsigned char)*in;
        switch (ch) {
        case '"':  out[n++] = '\\'; out[n++] = '"';  break;
        case '\\': out[n++] = '\\'; out[n++] = '\\'; break;
        case '\n': out[n++] = '\\'; out[n++] = 'n';  break;
        case '\r': out[n++] = '\\'; out[n++] = 'r';  break;
        case '\t': out[n++] = '\\'; out[n++] = 't';  break;
        default:
            if (ch < 0x20) {
                n += (size_t)snprintf(out + n, cap - n, "\\u%04x", ch);
            } else {
                out[n++] = (char)ch;
            }
        }
    }
    if (n + 1 < cap) out[n++] = '"';
    out[n] = '\0';
}

static void ft_log_v(ft_ctx* c, const char* level, const char* event,
                     const char* fmt, va_list ap) {
    ft_sb line;
    char frag[2048];
    char ts[64];
    SYSTEMTIME st;

    if (!c) return;
    frag[0] = '\0';
    if (fmt) {
        vsnprintf(frag, sizeof frag, fmt, ap);
        frag[sizeof frag - 1] = '\0';
    }

    GetLocalTime(&st);
    _snprintf(ts, sizeof ts, "%04u-%02u-%02uT%02u:%02u:%02u.%03u",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
               st.wMilliseconds);

    ft_sb_init(&line);
    ft_sb_addf(&line, "{\"ts\":\"%s\",\"level\":\"%s\",\"event\":\"%s\"",
               ts, level ? level : "info", event ? event : "-");
    if (frag[0]) {
        if (frag[0] == ',') ft_sb_adds(&line, frag);
        else ft_sb_addf(&line, ",%s", frag);
    }
    ft_sb_adds(&line, "}");

    printf("[%-4s] %-24s %s\n", level ? level : "info", event ? event : "-", frag);
    fflush(stdout);

    if (c->status) {
        fprintf(c->status, "%s\n", line.buf ? line.buf : "{}");
        fflush(c->status);
    }
    ft_sb_free(&line);
}

void ft_log(ft_ctx* c, const char* level, const char* event, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    ft_log_v(c, level, event, fmt, ap);
    va_end(ap);
}

void ft_ok(ft_ctx* c, const char* event, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    ft_log_v(c, "ok", event, fmt, ap);
    va_end(ap);
}

void ft_info(ft_ctx* c, const char* event, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    ft_log_v(c, "info", event, fmt, ap);
    va_end(ap);
}

void ft_warn(ft_ctx* c, const char* event, const char* fmt, ...) {
    va_list ap;
    c->warns++;
    va_start(ap, fmt);
    ft_log_v(c, "warn", event, fmt, ap);
    va_end(ap);
}

void ft_err(ft_ctx* c, const char* event, const char* fmt, ...) {
    va_list ap;
    c->fails++;
    va_start(ap, fmt);
    ft_log_v(c, "err", event, fmt, ap);
    va_end(ap);
}

void ft_note(ft_ctx* c, const char* fmt, ...) {
    va_list ap;
    (void)c;
    char buf[1024];
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    printf("       %s\n", buf);
    fflush(stdout);
}

void ft_status_open(ft_ctx* c, const char* path) {
    if (!c || !path || !*path) return;
    c->status = fopen(path, "a");
    if (!c->status) {
        fprintf(stderr, "nekiya: cannot open status file %s\n", path);
    }
}

void ft_status_raw(ft_ctx* c, const char* json) {
    if (!c || !c->status || !json || !*json) return;
    fprintf(c->status, "%s\n", json);
    fflush(c->status);
}

void ft_status_close(ft_ctx* c) {
    if (!c || !c->status) return;
    fclose(c->status);
    c->status = NULL;
}

int ft_get_build(uint32_t* out) {
    typedef LONG (WINAPI *ft_rtl_get_version_fn)(OSVERSIONINFOEXW*);
    OSVERSIONINFOEXW vi;
    HMODULE nt;
    union { FARPROC p; ft_rtl_get_version_fn f; } u;

    if (!out) return 0;
    *out = 0;
    memset(&vi, 0, sizeof vi);
    vi.dwOSVersionInfoSize = (DWORD)sizeof vi;
    nt = GetModuleHandleA("ntdll.dll");
    if (!nt) return 0;
    u.p = GetProcAddress(nt, "RtlGetVersion");
    if (!u.p) return 0;
    if (u.f(&vi) != 0) return 0;
    *out = (uint32_t)vi.dwBuildNumber;
    return 1;
}

uint8_t* ft_read_file(const char* path, size_t* out_size) {
    HANDLE h;
    LARGE_INTEGER li;
    uint8_t* buf;
    DWORD got = 0;

    if (out_size) *out_size = 0;
    if (!path || !*path) return NULL;
    h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    if (!GetFileSizeEx(h, &li) || li.QuadPart <= 0 || li.QuadPart > (LONGLONG)0x4000000) {
        CloseHandle(h);
        return NULL;
    }
    buf = (uint8_t*)malloc((size_t)li.QuadPart);
    if (!buf) { CloseHandle(h); return NULL; }
    if (!ReadFile(h, buf, (DWORD)li.QuadPart, &got, NULL) || got != (DWORD)li.QuadPart) {
        free(buf);
        CloseHandle(h);
        return NULL;
    }
    CloseHandle(h);
    if (out_size) *out_size = (size_t)li.QuadPart;
    return buf;
}

char* ft_sysdir_file(const char* name, char* out, size_t cap) {
    UINT n;
    if (!out || cap == 0) return NULL;
    out[0] = '\0';
    if (!name || !*name) return NULL;
    n = GetSystemDirectoryA(out, (UINT)cap);
    if (n == 0 || n >= cap) { out[0] = '\0'; return NULL; }
    if ((size_t)n + strlen(name) + 2 >= cap) { out[0] = '\0'; return NULL; }
    strcat(out, "\\");
    strcat(out, name);
    return out;
}
