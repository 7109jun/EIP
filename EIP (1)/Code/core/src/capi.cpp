#include "eip/capi.h"
#include "eip/runtime.h"
#include "eip/feature.h"
#include "eip/transaction.h"
#include "eip/pe.h"
#include "eip/patch.h"
#include <cstring>
#include <string>
#include <thread>

using namespace eip;

namespace {
thread_local std::string g_last_error_detail;
thread_local std::string g_last_bytes_buffer; // backing store for eip_scalar.as_bytes

void set_last_error(const EipError& e) {
    g_last_error_detail = std::string(error_code_name(e.code())) + ": " + error_code_message(e.code());
    if (!e.detail().empty()) {
        g_last_error_detail += " (" + e.detail() + ")";
    }
}

void copy_cstr(char* dst, std::size_t dst_size, const std::string& src) {
    std::size_t n = std::min(src.size(), dst_size - 1);
    std::memcpy(dst, src.data(), n);
    dst[n] = '\0';
}

eip_scalar to_capi(const ScalarValue& v) {
    eip_scalar out{};
    out.type = static_cast<int32_t>(v.type);
    out.as_int = v.as_int;
    out.as_float = v.as_float;
    g_last_bytes_buffer = v.as_string;
    out.as_bytes = g_last_bytes_buffer.c_str();
    out.as_bytes_len = static_cast<uint32_t>(g_last_bytes_buffer.size());
    return out;
}

ScalarValue from_capi(const eip_scalar& v) {
    ScalarValue out;
    out.type = static_cast<ValueType>(v.type);
    out.as_int = v.as_int;
    out.as_float = v.as_float;
    if (v.as_bytes && v.as_bytes_len) {
        out.as_string.assign(v.as_bytes, v.as_bytes_len);
    } else if (v.as_bytes) {
        out.as_string = v.as_bytes; // NUL-terminated convenience path
    }
    return out;
}

} // namespace

// Opaque struct definitions.
struct eip_session_s { Session session; explicit eip_session_s(ProcessHandle p) : session(std::move(p)) {} };
struct eip_feature_s { Feature* feature; };
struct eip_transaction_s { Transaction tx; eip_session_s* owner; explicit eip_transaction_s(eip_session_s* o) : tx(&o->session.runtime()), owner(o) {} };
struct eip_pe_s { PEImage image; };
struct eip_patcher_s { PersistentPatcher patcher; explicit eip_patcher_s(std::string path) : patcher(std::move(path)) {} };

#define EIP_TRY try {
#define EIP_CATCH \
    } catch (const EipError& e) { set_last_error(e); return static_cast<eip_status>(e.code()); } \
      catch (const std::exception& e) { g_last_error_detail = std::string("InternalError: ") + e.what(); return static_cast<eip_status>(ErrorCode::InternalError); } \
      catch (...) { g_last_error_detail = "InternalError: unknown exception"; return static_cast<eip_status>(ErrorCode::InternalError); }

extern "C" {

const char* eip_error_name(eip_status code) { return error_code_name(static_cast<ErrorCode>(code)); }
const char* eip_error_message(eip_status code) { return error_code_message(static_cast<ErrorCode>(code)); }
const char* eip_last_error_detail(void) { return g_last_error_detail.c_str(); }

eip_status eip_process_list(eip_process_summary* out, uint32_t max_count, uint32_t* out_count) {
    EIP_TRY
        auto list = process::list();
        uint32_t n = static_cast<uint32_t>(std::min<std::size_t>(list.size(), max_count));
        for (uint32_t i = 0; i < n; i++) {
            copy_cstr(out[i].name, sizeof(out[i].name), list[i].name);
            copy_cstr(out[i].path, sizeof(out[i].path), list[i].path);
            out[i].pid = list[i].pid;
        }
        *out_count = n;
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_process_find(const char* name_substr, eip_process_summary* out, uint32_t max_count, uint32_t* out_count) {
    EIP_TRY
        auto list = process::find(name_substr ? name_substr : "");
        uint32_t n = static_cast<uint32_t>(std::min<std::size_t>(list.size(), max_count));
        for (uint32_t i = 0; i < n; i++) {
            copy_cstr(out[i].name, sizeof(out[i].name), list[i].name);
            copy_cstr(out[i].path, sizeof(out[i].path), list[i].path);
            out[i].pid = list[i].pid;
        }
        *out_count = n;
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_attach_pid(uint32_t pid, eip_session* out) {
    EIP_TRY
        ProcessHandle ph = ProcessHandle::attach_pid(pid);
        *out = new eip_session_s(std::move(ph));
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_attach_name(const char* exe_name, eip_session* out) {
    EIP_TRY
        ProcessHandle ph = ProcessHandle::attach_name(exe_name ? exe_name : "");
        *out = new eip_session_s(std::move(ph));
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_detach(eip_session s) {
    EIP_TRY
        delete s;
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

uint32_t eip_session_pid(eip_session s) { return s ? s->session.process().pid() : 0; }
int32_t eip_session_arch(eip_session s) { return s ? static_cast<int32_t>(s->session.process().arch()) : 0; }

eip_status eip_modules(eip_session s, eip_module_info* out, uint32_t max_count, uint32_t* out_count) {
    EIP_TRY
        auto mods = s->session.process().modules();
        uint32_t n = static_cast<uint32_t>(std::min<std::size_t>(mods.size(), max_count));
        for (uint32_t i = 0; i < n; i++) {
            copy_cstr(out[i].name, sizeof(out[i].name), mods[i].name);
            copy_cstr(out[i].path, sizeof(out[i].path), mods[i].path);
            out[i].base = mods[i].base_address;
            out[i].size = mods[i].size;
        }
        *out_count = n;
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_resolve(eip_session s, const char* target, eip_address* out) {
    EIP_TRY
        *out = s->session.values().resolve(target ? target : "");
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_value_read(eip_session s, const char* target, int32_t type, uint32_t capacity, eip_scalar* out) {
    EIP_TRY
        ScalarValue v = s->session.values().read(target ? target : "", static_cast<ValueType>(type), capacity);
        *out = to_capi(v);
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_value_set(eip_session s, const char* target, int32_t type, uint32_t capacity, const eip_scalar* value) {
    EIP_TRY
        ScalarValue v = from_capi(*value);
        v.type = static_cast<ValueType>(type);
        s->session.values().set(target ? target : "", v, capacity);
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_function_find_export(eip_session s, const char* module, const char* name, eip_address* out) {
    EIP_TRY
        auto r = s->session.functions().find_export(module ? module : "", name ? name : "");
        if (!r) throw EipError(ErrorCode::FunctionNotFound, name ? name : "");
        *out = r->address;
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_function_find_pattern(eip_session s, const char* module, const char* pattern, eip_address* out) {
    EIP_TRY
        auto r = s->session.functions().find_pattern(module ? module : "", pattern ? pattern : "");
        if (!r) throw EipError(ErrorCode::FunctionNotFound, pattern ? pattern : "");
        *out = r->address;
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_function_add(eip_session s, const uint8_t* machine_code, uint32_t len, eip_address* out) {
    EIP_TRY
        std::vector<u8> code(machine_code, machine_code + len);
        *out = s->session.functions().add(code);
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_function_replace(eip_session s, eip_address target, eip_address new_impl,
                                 uint8_t* out_original, uint32_t max_original_len, uint32_t* out_saved_len) {
    EIP_TRY
        auto result = s->session.functions().replace(target, new_impl);
        uint32_t n = static_cast<uint32_t>(std::min<std::size_t>(result.original_bytes.size(), max_original_len));
        std::memcpy(out_original, result.original_bytes.data(), n);
        *out_saved_len = static_cast<uint32_t>(result.original_bytes.size());
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_function_restore(eip_session s, eip_address target, const uint8_t* original, uint32_t len) {
    EIP_TRY
        std::vector<u8> bytes(original, original + len);
        s->session.functions().restore(target, bytes);
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_hook_install(eip_session s, eip_address target, eip_address detour, eip_hook_handle* out) {
    EIP_TRY
        HookRecord rec = s->session.hooks().install(target, detour);
        out->target = rec.target;
        out->detour = rec.detour;
        out->trampoline = rec.trampoline;
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_hook_remove(eip_session s, eip_hook_handle* h) {
    EIP_TRY
        HookRecord rec;
        rec.target = h->target;
        rec.detour = h->detour;
        rec.trampoline = h->trampoline;
        rec.active = true;
        // original_bytes is unknown here by design (eip_hook_handle is a
        // thin cross-ABI handle); Python keeps the full record and should
        // use eip_function_restore directly if it needs raw-byte control.
        // For the common path, Hook::remove needs original_bytes, so the
        // Python layer is expected to retain them from install's result
        // via a separate read before install if exact restore is required.
        // Here we re-derive by reading function.find is not possible, so
        // this call restores via the trampoline's own saved copy instead.
        s->session.hooks().remove(rec);
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_event_create_ring(eip_session s, uint32_t capacity, eip_ring* out) {
    EIP_TRY
        EventEngine ee(s->session.process());
        RingBuffer rb = ee.create_ring(capacity);
        out->ring_addr = rb.addr;
        out->capacity = rb.capacity;
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_event_install(eip_session s, const char* name, eip_address target, uint32_t event_id,
                              eip_ring ring, eip_event_handle* out) {
    EIP_TRY
        EventEngine ee(s->session.process());
        RingBuffer rb{ring.ring_addr, ring.capacity};
        EventHookRecord rec = ee.install(name ? name : "", target, event_id, rb);
        out->target = rec.target;
        out->stub = rec.stub;
        out->ring = ring;
        out->event_id = event_id;
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_event_remove(eip_session s, eip_event_handle* h) {
    EIP_TRY
        EventEngine ee(s->session.process());
        EventHookRecord rec;
        rec.target = h->target;
        rec.stub = h->stub;
        rec.active = true;
        // As with hook_remove, original_bytes aren't round-tripped across
        // this thin handle; callers needing byte-exact restore should keep
        // the record on the Python side (python/eip/event.py does).
        ee.remove(rec);
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_event_poll(eip_session s, eip_ring ring, uint32_t since_sequence,
                           eip_event_entry* out, uint32_t max_count, uint32_t* out_count) {
    EIP_TRY
        EventEngine ee(s->session.process());
        RingBuffer rb{ring.ring_addr, ring.capacity};
        auto entries = ee.poll(rb, since_sequence);
        uint32_t n = static_cast<uint32_t>(std::min<std::size_t>(entries.size(), max_count));
        for (uint32_t i = 0; i < n; i++) {
            out[i].event_id = entries[i].event_id;
            out[i].sequence = entries[i].sequence;
        }
        *out_count = n;
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_tx_begin(eip_session s, eip_transaction* out) {
    EIP_TRY
        *out = new eip_transaction_s(s);
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_tx_add_value_set(eip_transaction tx, const char* target, int32_t type, uint32_t capacity, const eip_scalar* value) {
    EIP_TRY
        ScalarValue v = from_capi(*value);
        v.type = static_cast<ValueType>(type);
        tx->tx.value_set(tx->owner->session.values(), target ? target : "", static_cast<ValueType>(type), v, capacity);
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_tx_add_function_replace(eip_transaction tx, eip_address target, eip_address new_impl) {
    EIP_TRY
        tx->tx.function_replace(tx->owner->session.functions(), target, new_impl);
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_tx_add_hook_install(eip_transaction tx, eip_address target, eip_address detour) {
    EIP_TRY
        auto rec = std::make_shared<HookRecord>();
        tx->tx.hook_install(tx->owner->session.hooks(), target, detour, rec);
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_tx_commit(eip_transaction tx) {
    EIP_TRY
        tx->tx.commit();
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_tx_rollback(eip_transaction tx) {
    EIP_TRY
        tx->tx.rollback();
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

void eip_tx_destroy(eip_transaction tx) { delete tx; }

eip_status eip_feature_create(eip_session s, const char* name, eip_feature* out) {
    EIP_TRY
        Feature& f = s->session.features().create(name ? name : "");
        eip_feature_s* handle = new eip_feature_s();
        handle->feature = &f;
        *out = handle;
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_feature_add_value(eip_feature f, const char* target, int32_t type, uint32_t capacity, const eip_scalar* value) {
    EIP_TRY
        ScalarValue v = from_capi(*value);
        v.type = static_cast<ValueType>(type);
        f->feature->add_value(target ? target : "", static_cast<ValueType>(type), v, capacity);
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_feature_add_function(eip_feature f, eip_address target, const uint8_t* code, uint32_t len) {
    EIP_TRY
        std::vector<u8> c(code, code + len);
        f->feature->add_function(target, std::move(c));
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_feature_add_hook(eip_feature f, eip_address target, eip_address detour) {
    EIP_TRY
        f->feature->add_hook(target, detour);
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_feature_add_event(eip_feature f, const char* name, eip_address target, uint32_t event_id) {
    EIP_TRY
        f->feature->add_event(name ? name : "", target, event_id);
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_feature_add_command(eip_feature f, const char* command_name) {
    EIP_TRY
        f->feature->add_command(command_name ? command_name : "");
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_feature_install(eip_feature f) {
    EIP_TRY
        f->feature->install();
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_feature_uninstall(eip_feature f) {
    EIP_TRY
        f->feature->uninstall();
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

int32_t eip_feature_is_installed(eip_feature f) { return f && f->feature->installed() ? 1 : 0; }

eip_status eip_runtime_changes(eip_session s, eip_change_record* out, uint32_t max_count, uint32_t* out_count) {
    EIP_TRY
        auto& changes = s->session.runtime().changes();
        uint32_t n = static_cast<uint32_t>(std::min<std::size_t>(changes.size(), max_count));
        for (uint32_t i = 0; i < n; i++) {
            out[i].sequence = changes[i].sequence;
            out[i].kind = static_cast<int32_t>(changes[i].kind);
            out[i].state = static_cast<int32_t>(changes[i].state);
            out[i].address = changes[i].address;
            copy_cstr(out[i].description, sizeof(out[i].description), changes[i].description);
        }
        *out_count = n;
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

uint64_t eip_runtime_checkpoint(eip_session s) { return s ? static_cast<uint64_t>(s->session.runtime().checkpoint()) : 0; }

eip_status eip_runtime_diff_since(eip_session s, uint64_t checkpoint, eip_change_record* out, uint32_t max_count, uint32_t* out_count) {
    EIP_TRY
        auto changes = s->session.runtime().diff_since(static_cast<std::size_t>(checkpoint));
        uint32_t n = static_cast<uint32_t>(std::min<std::size_t>(changes.size(), max_count));
        for (uint32_t i = 0; i < n; i++) {
            out[i].sequence = changes[i].sequence;
            out[i].kind = static_cast<int32_t>(changes[i].kind);
            out[i].state = static_cast<int32_t>(changes[i].state);
            out[i].address = changes[i].address;
            copy_cstr(out[i].description, sizeof(out[i].description), changes[i].description);
        }
        *out_count = n;
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

// --- PE engine ---------------------------------------------------------
eip_status eip_pe_parse_file(const char* path, eip_pe* out) {
    EIP_TRY
        eip_pe_s* handle = new eip_pe_s{PEImage::parse_file(path ? path : "")};
        *out = handle;
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

void eip_pe_close(eip_pe pe) { delete pe; }
int32_t eip_pe_arch(eip_pe pe) { return pe ? static_cast<int32_t>(pe->image.arch()) : 0; }
int32_t eip_pe_is_pe32plus(eip_pe pe) { return pe && pe->image.is_pe32plus() ? 1 : 0; }
eip_address eip_pe_image_base(eip_pe pe) { return pe ? pe->image.image_base() : 0; }
uint32_t eip_pe_size_of_image(eip_pe pe) { return pe ? pe->image.size_of_image() : 0; }
uint32_t eip_pe_entry_point_rva(eip_pe pe) { return pe ? pe->image.entry_point_rva() : 0; }

eip_status eip_pe_sections(eip_pe pe, eip_pe_section* out, uint32_t max_count, uint32_t* out_count) {
    EIP_TRY
        auto& secs = pe->image.sections();
        uint32_t n = static_cast<uint32_t>(std::min<std::size_t>(secs.size(), max_count));
        for (uint32_t i = 0; i < n; i++) {
            copy_cstr(out[i].name, sizeof(out[i].name), secs[i].name);
            out[i].virtual_address = secs[i].virtual_address;
            out[i].virtual_size = secs[i].virtual_size;
            out[i].raw_size = secs[i].raw_size;
            out[i].raw_offset = secs[i].raw_offset;
            out[i].characteristics = secs[i].characteristics;
        }
        *out_count = n;
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_pe_exports(eip_pe pe, eip_pe_export* out, uint32_t max_count, uint32_t* out_count) {
    EIP_TRY
        auto& exps = pe->image.exports();
        uint32_t n = static_cast<uint32_t>(std::min<std::size_t>(exps.size(), max_count));
        for (uint32_t i = 0; i < n; i++) {
            copy_cstr(out[i].name, sizeof(out[i].name), exps[i].name);
            out[i].ordinal = exps[i].ordinal;
            out[i].rva = exps[i].rva;
            out[i].is_forwarder = exps[i].is_forwarder ? 1 : 0;
        }
        *out_count = n;
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_pe_find_export(eip_pe pe, const char* name, eip_rva* out) {
    EIP_TRY
        auto r = pe->image.find_export(name ? name : "");
        if (!r) throw EipError(ErrorCode::FunctionNotFound, name ? name : "");
        *out = *r;
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_pe_read_rva(eip_pe pe, eip_rva rva, uint8_t* out, uint32_t size) {
    EIP_TRY
        auto bytes = pe->image.read_rva(rva, size);
        std::memcpy(out, bytes.data(), bytes.size());
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_pe_patch_bytes(eip_pe pe, eip_rva rva, const uint8_t* data, uint32_t size) {
    EIP_TRY
        pe->image.patch_bytes(rva, data, size);
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_pe_add_section(eip_pe pe, const char* name, const uint8_t* data, uint32_t size, uint32_t characteristics, eip_rva* out_rva) {
    EIP_TRY
        std::vector<u8> bytes(data, data + size);
        *out_rva = pe->image.add_section(name ? name : "", bytes, characteristics);
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_pe_save(eip_pe pe, const char* path) {
    EIP_TRY
        pe->image.save(path ? path : "");
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

// --- Persistent patch ----------------------------------------------------
eip_status eip_patcher_create(const char* input_path, eip_patcher* out) {
    EIP_TRY
        *out = new eip_patcher_s(input_path ? input_path : "");
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

void eip_patcher_close(eip_patcher p) { delete p; }

eip_status eip_patcher_add_value_change(eip_patcher p, eip_rva rva, const uint8_t* new_bytes, uint32_t len, const char* description) {
    EIP_TRY
        std::vector<u8> bytes(new_bytes, new_bytes + len);
        p->patcher.add_value_change(rva, std::move(bytes), description ? description : "");
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_patcher_add_code_injection(eip_patcher p, const char* section_name, const uint8_t* code, uint32_t len, uint32_t characteristics, const char* description) {
    EIP_TRY
        std::vector<u8> bytes(code, code + len);
        p->patcher.add_code_injection(section_name ? section_name : "", std::move(bytes), characteristics, description ? description : "");
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

eip_status eip_patcher_apply(eip_patcher p, const char* output_path) {
    EIP_TRY
        p->patcher.apply(output_path ? output_path : "");
        return static_cast<eip_status>(ErrorCode::Ok);
    EIP_CATCH
}

} // extern "C"
