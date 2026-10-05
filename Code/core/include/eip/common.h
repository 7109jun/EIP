// EIP (Exe In Python) - Native Core
// common.h : shared fundamental types, error codes, and state-tracking enums
// used by every other header in the native core.
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <stdexcept>

namespace eip {

// ---------------------------------------------------------------------------
// Fixed width aliases used across the PE / process / memory layers.
// ---------------------------------------------------------------------------
using u8  = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using i8  = std::int8_t;
using i16 = std::int16_t;
using i32 = std::int32_t;
using i64 = std::int64_t;

// A virtual address inside a target process (or a file offset while a PE is
// only mapped from disk). Always 64-bit so 32-bit and 64-bit targets share
// one representation; 32-bit targets simply never use the high dword.
using Address = u64;

// Relative Virtual Address: offset from a module's base, as stored in PE
// structures on disk.
using RVA = u32;

// ---------------------------------------------------------------------------
// Error codes. Every fallible native-core operation returns one of these
// (or throws an EipError carrying one) instead of using a bare bool/errno.
// This is the same vocabulary that crosses the C ABI into Python, where
// each value becomes a distinct Python exception type (see capi.h / errors.py).
// ---------------------------------------------------------------------------
enum class ErrorCode : i32 {
    Ok = 0,

    ProcessNotFound = 1,
    ProcessAccessDenied = 2,
    ProcessAlreadyAttached = 3,
    ProcessNotAttached = 4,

    ModuleNotFound = 10,

    AddressInvalid = 20,
    MemoryReadFailed = 21,
    MemoryWriteFailed = 22,
    MemoryProtectFailed = 23,
    MemoryAllocFailed = 24,

    ValueTypeMismatch = 30,
    ValueTargetUnresolved = 31,

    FunctionNotFound = 40,
    FunctionTooSmallToHook = 41,
    FunctionAlreadyHooked = 42,
    FunctionNotHooked = 43,

    HookInstallFailed = 50,
    HookRemoveFailed = 51,

    PatchConflict = 60,
    PatchNotFound = 61,

    TransactionFailed = 70,
    TransactionAlreadyCommitted = 71,
    TransactionEmpty = 72,

    UnsupportedPE = 80,
    PEParseFailed = 81,
    PEWriteFailed = 82,

    ArchitectureMismatch = 90,

    FeatureInstallError = 100,
    FeatureNotFound = 101,
    FeatureAlreadyInstalled = 102,

    IoError = 110,
    NotImplementedOnPlatform = 111,
    InvalidArgument = 112,
    InternalError = 120,
};

// Human readable name for an ErrorCode, used both in C++ exception messages
// and surfaced across the C ABI so the Python layer can build exception
// messages without duplicating this table.
const char* error_code_name(ErrorCode code) noexcept;
const char* error_code_message(ErrorCode code) noexcept;

// EipError is the single exception type the native core throws. It always
// carries a machine-readable ErrorCode plus a human-readable detail string
// (e.g. "target process pid=1234", "address 0x7ff6... out of range").
class EipError : public std::runtime_error {
public:
    EipError(ErrorCode code, std::string detail)
        : std::runtime_error(build_message(code, detail)),
          code_(code),
          detail_(std::move(detail)) {}

    ErrorCode code() const noexcept { return code_; }
    const std::string& detail() const noexcept { return detail_; }

private:
    static std::string build_message(ErrorCode code, const std::string& detail) {
        std::string msg = error_code_name(code);
        msg += ": ";
        msg += error_code_message(code);
        if (!detail.empty()) {
            msg += " (";
            msg += detail;
            msg += ")";
        }
        return msg;
    }

    ErrorCode code_;
    std::string detail_;
};

// ---------------------------------------------------------------------------
// Architecture of a target module / process.
// ---------------------------------------------------------------------------
enum class Arch : i32 {
    Unknown = 0,
    X86 = 1,     // 32-bit (IMAGE_FILE_MACHINE_I386)
    X64 = 2,     // 64-bit (IMAGE_FILE_MACHINE_AMD64)
};

// ---------------------------------------------------------------------------
// Value type system (section "Value" in the spec: int/float/pointer/string...)
// ---------------------------------------------------------------------------
enum class ValueType : i32 {
    I8 = 0, U8 = 1,
    I16 = 2, U16 = 3,
    I32 = 4, U32 = 5,
    I64 = 6, U64 = 7,
    F32 = 8, F64 = 9,
    Pointer32 = 10,
    Pointer64 = 11,
    Bool8 = 12,
    CStringAscii = 13,   // fixed-capacity, NUL terminated
    CStringUtf16 = 14,   // fixed-capacity, NUL terminated (Windows WCHAR)
    Bytes = 15,          // raw fixed-size byte blob
};

std::size_t value_type_fixed_size(ValueType t); // 0 for variable-length types (strings honor an explicit capacity instead)

// ---------------------------------------------------------------------------
// Change tracking (spec section 10: Original/Modified/Added/Removed/Hooked/Restored)
// ---------------------------------------------------------------------------
enum class ChangeState : i32 {
    Original = 0,
    Modified = 1,
    Added = 2,
    Removed = 3,
    Hooked = 4,
    Restored = 5,
};

enum class ChangeKind : i32 {
    ValueSet = 0,
    MemoryPatch = 1,
    FunctionReplace = 2,
    FunctionAdd = 3,
    HookInstall = 4,
    FeatureInstall = 5,
};

} // namespace eip
