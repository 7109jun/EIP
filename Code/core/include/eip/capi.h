// EIP native core - capi.h
// Flat, stable C ABI exposed by eip_core.dll (Windows) / libeip_core.so
// (Linux, for the PE/pattern-only subset). This is the ONLY boundary the
// Python layer crosses (see python/eip/_native.py) - no Python code ever
// calls Windows APIs directly, satisfying the required layering:
//   Python Application -> EIP Python API -> EIP Runtime -> EIP Native Core -> Windows Process/PE
//
// Conventions:
//  - Every function returns an eip_status (0 = EIP_OK, matches ErrorCode).
//    Call eip_last_error_message() for details after a non-zero return.
//  - Handles are opaque pointers; always created by one eip_*_create/open/
//    attach call and destroyed by exactly one matching eip_*_destroy/close.
//  - Strings are UTF-8, NUL-terminated, caller-owned unless documented
//    otherwise (eip_string_free frees anything this API allocated).
//  - Not thread-safe across handles sharing a process attachment; the
//    Python layer serializes access per Session (see python/eip/_native.py).
#pragma once

#include <cstdint>

#if defined(_WIN32)
  #define EIP_API extern "C" __declspec(dllexport)
#else
  #define EIP_API extern "C" __attribute__((visibility("default")))
#endif

extern "C" {

typedef int32_t eip_status;      // mirrors eip::ErrorCode numerically
typedef uint64_t eip_address;
typedef uint32_t eip_rva;

typedef struct eip_session_s* eip_session;       // attached process + engines (Windows-only)
typedef struct eip_feature_s* eip_feature;       // a Feature belonging to a session
typedef struct eip_transaction_s* eip_transaction;
typedef struct eip_pe_s* eip_pe;                 // a parsed PE file (portable, works on Linux too)
typedef struct eip_patcher_s* eip_patcher;       // persistent patch builder (portable)

// ---------------------------------------------------------------------------
// Error reporting
// ---------------------------------------------------------------------------
EIP_API const char* eip_error_name(eip_status code);
EIP_API const char* eip_error_message(eip_status code);
// Full detail string ("CODE: message (detail)") for the most recent failing
// call on this thread. Valid until the next eip_* call on the same thread.
EIP_API const char* eip_last_error_detail(void);

// ---------------------------------------------------------------------------
// Value type codes (mirrors eip::ValueType)
// ---------------------------------------------------------------------------
enum eip_value_type {
    EIP_VT_I8 = 0, EIP_VT_U8 = 1, EIP_VT_I16 = 2, EIP_VT_U16 = 3,
    EIP_VT_I32 = 4, EIP_VT_U32 = 5, EIP_VT_I64 = 6, EIP_VT_U64 = 7,
    EIP_VT_F32 = 8, EIP_VT_F64 = 9, EIP_VT_PTR32 = 10, EIP_VT_PTR64 = 11,
    EIP_VT_BOOL8 = 12, EIP_VT_CSTR_ASCII = 13, EIP_VT_CSTR_UTF16 = 14, EIP_VT_BYTES = 15,
};

typedef struct {
    int32_t type;      // eip_value_type
    int64_t as_int;
    double as_float;
    const char* as_bytes; // points at an internal buffer, valid until the next call on this thread
    uint32_t as_bytes_len;
} eip_scalar;

// ---------------------------------------------------------------------------
// Process enumeration (Windows-only; NotImplementedOnPlatform elsewhere)
// ---------------------------------------------------------------------------
typedef struct { uint32_t pid; char name[260]; char path[520]; } eip_process_summary;

// Fills `out` (caller-allocated array of `max_count`) and returns the number
// of processes actually written via *out_count. Returns EIP_ERR_* on failure.
EIP_API eip_status eip_process_list(eip_process_summary* out, uint32_t max_count, uint32_t* out_count);
EIP_API eip_status eip_process_find(const char* name_substr, eip_process_summary* out, uint32_t max_count, uint32_t* out_count);

// ---------------------------------------------------------------------------
// Session: attach / detach
// ---------------------------------------------------------------------------
EIP_API eip_status eip_attach_pid(uint32_t pid, eip_session* out);
EIP_API eip_status eip_attach_name(const char* exe_name, eip_session* out);
EIP_API eip_status eip_detach(eip_session s);
EIP_API uint32_t eip_session_pid(eip_session s);
EIP_API int32_t eip_session_arch(eip_session s); // 1=x86, 2=x64

typedef struct { char name[260]; char path[520]; eip_address base; uint64_t size; } eip_module_info;
EIP_API eip_status eip_modules(eip_session s, eip_module_info* out, uint32_t max_count, uint32_t* out_count);

// ---------------------------------------------------------------------------
// Target resolution
// ---------------------------------------------------------------------------
EIP_API eip_status eip_resolve(eip_session s, const char* target, eip_address* out);

// ---------------------------------------------------------------------------
// Value
// ---------------------------------------------------------------------------
EIP_API eip_status eip_value_read(eip_session s, const char* target, int32_t type, uint32_t capacity, eip_scalar* out);
EIP_API eip_status eip_value_set(eip_session s, const char* target, int32_t type, uint32_t capacity, const eip_scalar* value);

// ---------------------------------------------------------------------------
// Function
// ---------------------------------------------------------------------------
EIP_API eip_status eip_function_find_export(eip_session s, const char* module, const char* name, eip_address* out);
EIP_API eip_status eip_function_find_pattern(eip_session s, const char* module, const char* pattern, eip_address* out);
// Allocates RWX memory, writes machine_code into it, returns its address.
EIP_API eip_status eip_function_add(eip_session s, const uint8_t* machine_code, uint32_t len, eip_address* out);
// Patches `target` to jump to `new_impl`; on success *out_saved_len gives
// how many original bytes were overwritten (needed to restore later).
EIP_API eip_status eip_function_replace(eip_session s, eip_address target, eip_address new_impl,
                                         uint8_t* out_original, uint32_t max_original_len, uint32_t* out_saved_len);
EIP_API eip_status eip_function_restore(eip_session s, eip_address target, const uint8_t* original, uint32_t len);

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------
typedef struct { eip_address target; eip_address detour; eip_address trampoline; } eip_hook_handle;
EIP_API eip_status eip_hook_install(eip_session s, eip_address target, eip_address detour, eip_hook_handle* out);
EIP_API eip_status eip_hook_remove(eip_session s, eip_hook_handle* h);

// ---------------------------------------------------------------------------
// Event
// ---------------------------------------------------------------------------
typedef struct { eip_address ring_addr; uint32_t capacity; } eip_ring;
typedef struct { eip_address target; eip_address stub; eip_ring ring; uint32_t event_id; } eip_event_handle;
EIP_API eip_status eip_event_create_ring(eip_session s, uint32_t capacity, eip_ring* out);
EIP_API eip_status eip_event_install(eip_session s, const char* name, eip_address target, uint32_t event_id,
                                      eip_ring ring, eip_event_handle* out);
EIP_API eip_status eip_event_remove(eip_session s, eip_event_handle* h);
typedef struct { uint32_t event_id; uint32_t sequence; } eip_event_entry;
EIP_API eip_status eip_event_poll(eip_session s, eip_ring ring, uint32_t since_sequence,
                                   eip_event_entry* out, uint32_t max_count, uint32_t* out_count);

// ---------------------------------------------------------------------------
// Transaction
// ---------------------------------------------------------------------------
EIP_API eip_status eip_tx_begin(eip_session s, eip_transaction* out);
EIP_API eip_status eip_tx_add_value_set(eip_transaction tx, const char* target, int32_t type, uint32_t capacity, const eip_scalar* value);
EIP_API eip_status eip_tx_add_function_replace(eip_transaction tx, eip_address target, eip_address new_impl);
EIP_API eip_status eip_tx_add_hook_install(eip_transaction tx, eip_address target, eip_address detour);
EIP_API eip_status eip_tx_commit(eip_transaction tx);
EIP_API eip_status eip_tx_rollback(eip_transaction tx);
EIP_API void eip_tx_destroy(eip_transaction tx);

// ---------------------------------------------------------------------------
// Feature
// ---------------------------------------------------------------------------
EIP_API eip_status eip_feature_create(eip_session s, const char* name, eip_feature* out);
EIP_API eip_status eip_feature_add_value(eip_feature f, const char* target, int32_t type, uint32_t capacity, const eip_scalar* value);
EIP_API eip_status eip_feature_add_function(eip_feature f, eip_address target, const uint8_t* code, uint32_t len);
EIP_API eip_status eip_feature_add_hook(eip_feature f, eip_address target, eip_address detour);
EIP_API eip_status eip_feature_add_event(eip_feature f, const char* name, eip_address target, uint32_t event_id);
EIP_API eip_status eip_feature_add_command(eip_feature f, const char* command_name);
EIP_API eip_status eip_feature_install(eip_feature f);
EIP_API eip_status eip_feature_uninstall(eip_feature f);
EIP_API int32_t eip_feature_is_installed(eip_feature f);

// ---------------------------------------------------------------------------
// Runtime state tracking
// ---------------------------------------------------------------------------
typedef struct { uint64_t sequence; int32_t kind; int32_t state; eip_address address; char description[256]; } eip_change_record;
EIP_API eip_status eip_runtime_changes(eip_session s, eip_change_record* out, uint32_t max_count, uint32_t* out_count);
EIP_API uint64_t eip_runtime_checkpoint(eip_session s);
EIP_API eip_status eip_runtime_diff_since(eip_session s, uint64_t checkpoint, eip_change_record* out, uint32_t max_count, uint32_t* out_count);

// ---------------------------------------------------------------------------
// PE engine (portable: works without an attached process, on any platform)
// ---------------------------------------------------------------------------
EIP_API eip_status eip_pe_parse_file(const char* path, eip_pe* out);
EIP_API void eip_pe_close(eip_pe pe);
EIP_API int32_t eip_pe_arch(eip_pe pe);          // 1=x86, 2=x64
EIP_API int32_t eip_pe_is_pe32plus(eip_pe pe);
EIP_API eip_address eip_pe_image_base(eip_pe pe);
EIP_API uint32_t eip_pe_size_of_image(eip_pe pe);
EIP_API uint32_t eip_pe_entry_point_rva(eip_pe pe);

typedef struct { char name[16]; eip_rva virtual_address; uint32_t virtual_size; uint32_t raw_size; uint32_t raw_offset; uint32_t characteristics; } eip_pe_section;
EIP_API eip_status eip_pe_sections(eip_pe pe, eip_pe_section* out, uint32_t max_count, uint32_t* out_count);

typedef struct { char name[256]; uint32_t ordinal; eip_rva rva; int32_t is_forwarder; } eip_pe_export;
EIP_API eip_status eip_pe_exports(eip_pe pe, eip_pe_export* out, uint32_t max_count, uint32_t* out_count);
EIP_API eip_status eip_pe_find_export(eip_pe pe, const char* name, eip_rva* out);

EIP_API eip_status eip_pe_read_rva(eip_pe pe, eip_rva rva, uint8_t* out, uint32_t size);
EIP_API eip_status eip_pe_patch_bytes(eip_pe pe, eip_rva rva, const uint8_t* data, uint32_t size); // in-memory only
EIP_API eip_status eip_pe_add_section(eip_pe pe, const char* name, const uint8_t* data, uint32_t size, uint32_t characteristics, eip_rva* out_rva);
EIP_API eip_status eip_pe_save(eip_pe pe, const char* path);

// ---------------------------------------------------------------------------
// Persistent patch (portable)
// ---------------------------------------------------------------------------
EIP_API eip_status eip_patcher_create(const char* input_path, eip_patcher* out);
EIP_API void eip_patcher_close(eip_patcher p);
EIP_API eip_status eip_patcher_add_value_change(eip_patcher p, eip_rva rva, const uint8_t* new_bytes, uint32_t len, const char* description);
EIP_API eip_status eip_patcher_add_code_injection(eip_patcher p, const char* section_name, const uint8_t* code, uint32_t len, uint32_t characteristics, const char* description);
EIP_API eip_status eip_patcher_apply(eip_patcher p, const char* output_path);

} // extern "C"
