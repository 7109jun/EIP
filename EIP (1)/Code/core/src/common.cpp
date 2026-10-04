#include "eip/common.h"

namespace eip {

const char* error_code_name(ErrorCode code) noexcept {
    switch (code) {
        case ErrorCode::Ok: return "Ok";
        case ErrorCode::ProcessNotFound: return "ProcessNotFound";
        case ErrorCode::ProcessAccessDenied: return "ProcessAccessDenied";
        case ErrorCode::ProcessAlreadyAttached: return "ProcessAlreadyAttached";
        case ErrorCode::ProcessNotAttached: return "ProcessNotAttached";
        case ErrorCode::ModuleNotFound: return "ModuleNotFound";
        case ErrorCode::AddressInvalid: return "AddressInvalid";
        case ErrorCode::MemoryReadFailed: return "MemoryReadFailed";
        case ErrorCode::MemoryWriteFailed: return "MemoryWriteFailed";
        case ErrorCode::MemoryProtectFailed: return "MemoryProtectFailed";
        case ErrorCode::MemoryAllocFailed: return "MemoryAllocFailed";
        case ErrorCode::ValueTypeMismatch: return "ValueTypeMismatch";
        case ErrorCode::ValueTargetUnresolved: return "ValueTargetUnresolved";
        case ErrorCode::FunctionNotFound: return "FunctionNotFound";
        case ErrorCode::FunctionTooSmallToHook: return "FunctionTooSmallToHook";
        case ErrorCode::FunctionAlreadyHooked: return "FunctionAlreadyHooked";
        case ErrorCode::FunctionNotHooked: return "FunctionNotHooked";
        case ErrorCode::HookInstallFailed: return "HookInstallFailed";
        case ErrorCode::HookRemoveFailed: return "HookRemoveFailed";
        case ErrorCode::PatchConflict: return "PatchConflict";
        case ErrorCode::PatchNotFound: return "PatchNotFound";
        case ErrorCode::TransactionFailed: return "TransactionFailed";
        case ErrorCode::TransactionAlreadyCommitted: return "TransactionAlreadyCommitted";
        case ErrorCode::TransactionEmpty: return "TransactionEmpty";
        case ErrorCode::UnsupportedPE: return "UnsupportedPE";
        case ErrorCode::PEParseFailed: return "PEParseFailed";
        case ErrorCode::PEWriteFailed: return "PEWriteFailed";
        case ErrorCode::ArchitectureMismatch: return "ArchitectureMismatch";
        case ErrorCode::FeatureInstallError: return "FeatureInstallError";
        case ErrorCode::FeatureNotFound: return "FeatureNotFound";
        case ErrorCode::FeatureAlreadyInstalled: return "FeatureAlreadyInstalled";
        case ErrorCode::IoError: return "IoError";
        case ErrorCode::NotImplementedOnPlatform: return "NotImplementedOnPlatform";
        case ErrorCode::InvalidArgument: return "InvalidArgument";
        case ErrorCode::InternalError: return "InternalError";
    }
    return "UnknownError";
}

const char* error_code_message(ErrorCode code) noexcept {
    switch (code) {
        case ErrorCode::Ok: return "no error";
        case ErrorCode::ProcessNotFound: return "target process could not be found";
        case ErrorCode::ProcessAccessDenied: return "access to the target process was denied";
        case ErrorCode::ProcessAlreadyAttached: return "this handle is already attached to a process";
        case ErrorCode::ProcessNotAttached: return "no process is currently attached";
        case ErrorCode::ModuleNotFound: return "module not found in the target process";
        case ErrorCode::AddressInvalid: return "address is not valid in the target address space";
        case ErrorCode::MemoryReadFailed: return "failed to read target process memory";
        case ErrorCode::MemoryWriteFailed: return "failed to write target process memory";
        case ErrorCode::MemoryProtectFailed: return "failed to change memory protection";
        case ErrorCode::MemoryAllocFailed: return "failed to allocate memory in target process";
        case ErrorCode::ValueTypeMismatch: return "value type does not match the stored/target type";
        case ErrorCode::ValueTargetUnresolved: return "could not resolve value target to an address";
        case ErrorCode::FunctionNotFound: return "function could not be located";
        case ErrorCode::FunctionTooSmallToHook: return "function is too small to safely hook";
        case ErrorCode::FunctionAlreadyHooked: return "function already has an active hook";
        case ErrorCode::FunctionNotHooked: return "function has no active hook to remove";
        case ErrorCode::HookInstallFailed: return "failed to install hook";
        case ErrorCode::HookRemoveFailed: return "failed to remove hook";
        case ErrorCode::PatchConflict: return "patch conflicts with an already-applied change";
        case ErrorCode::PatchNotFound: return "no matching patch found";
        case ErrorCode::TransactionFailed: return "transaction failed and was rolled back";
        case ErrorCode::TransactionAlreadyCommitted: return "transaction was already committed or rolled back";
        case ErrorCode::TransactionEmpty: return "transaction has no operations to commit";
        case ErrorCode::UnsupportedPE: return "PE file format is not supported";
        case ErrorCode::PEParseFailed: return "failed to parse PE structure";
        case ErrorCode::PEWriteFailed: return "failed to write PE output file";
        case ErrorCode::ArchitectureMismatch: return "32/64-bit architecture mismatch";
        case ErrorCode::FeatureInstallError: return "feature installation failed";
        case ErrorCode::FeatureNotFound: return "feature not found";
        case ErrorCode::FeatureAlreadyInstalled: return "feature is already installed";
        case ErrorCode::IoError: return "I/O error";
        case ErrorCode::NotImplementedOnPlatform: return "operation requires the Windows native core and is unavailable on this platform";
        case ErrorCode::InvalidArgument: return "invalid argument";
        case ErrorCode::InternalError: return "internal error";
    }
    return "unknown error";
}

std::size_t value_type_fixed_size(ValueType t) {
    switch (t) {
        case ValueType::I8: case ValueType::U8: case ValueType::Bool8: return 1;
        case ValueType::I16: case ValueType::U16: return 2;
        case ValueType::I32: case ValueType::U32: case ValueType::F32: case ValueType::Pointer32: return 4;
        case ValueType::I64: case ValueType::U64: case ValueType::F64: case ValueType::Pointer64: return 8;
        case ValueType::CStringAscii: case ValueType::CStringUtf16: case ValueType::Bytes: return 0;
    }
    return 0;
}

} // namespace eip
