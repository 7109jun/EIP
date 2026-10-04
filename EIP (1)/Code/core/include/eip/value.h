// EIP native core - value.h
// Typed read/set against a resolved target ("existing value change", spec
// section 3/4). Backs Python's `program.value.read(...)` / `.set(...)`.
#pragma once
#include "eip/common.h"
#include "eip/process.h"
#include "eip/target.h"
#include <variant>
#include <string>

namespace eip {

// A decoded value carried across the C ABI / Python boundary. Only one
// member is meaningful, selected by `type`.
struct ScalarValue {
    ValueType type;
    i64 as_int = 0;       // I8..I64, U8..U64 (sign-extended/zero-extended as appropriate), Pointer32/64, Bool8
    double as_float = 0;  // F32, F64
    std::string as_string; // CStringAscii, CStringUtf16 (UTF-8 in this struct; converted at the UTF-16 boundary), Bytes (raw bytes, not NUL-terminated)
};

class ValueEngine {
public:
    explicit ValueEngine(const ProcessHandle& proc) : proc_(proc), resolver_(proc) {}

    Address resolve(const std::string& target) const { return resolver_.resolve(target); }

    ScalarValue read(const std::string& target, ValueType type, std::size_t capacity_for_strings = 0) const;

    // Returns the raw bytes this write would produce, WITHOUT touching the
    // process - used by Transaction to capture a before-image first.
    std::vector<u8> read_raw_bytes(Address addr, std::size_t size) const;

    // Writes `value` at the resolved target, returning the number of bytes
    // written (needed by the caller/Transaction to know how many original
    // bytes to have captured beforehand for rollback).
    std::size_t set(const std::string& target, const ScalarValue& value, std::size_t capacity_for_strings = 0) const;

    // Low-level variants used once an address is already known (Transaction
    // replay, Hook bookkeeping, etc. - avoids re-resolving the target string).
    ScalarValue read_at(Address addr, ValueType type, std::size_t capacity_for_strings = 0) const;
    std::size_t set_at(Address addr, const ScalarValue& value, std::size_t capacity_for_strings = 0) const;

private:
    const ProcessHandle& proc_;
    TargetResolver resolver_;
};

} // namespace eip
