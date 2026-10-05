// EIP native core - target.h
// Resolves a human-written target string to a concrete address in the
// attached process. This is what turns `target="Demo.exe!g_RunSpeed"` (or
// a raw address, or "Module.exe+0x1234") into something Value/Function/Hook
// can actually read or write.
//
// Supported forms:
//   "0x7FF6A1B2C3D4"        - absolute address (hex, with or without 0x)
//   "Module.exe!symbolName"  - resolved via that module's PE export table
//   "Module.exe!symbolName+0x10" - export address plus a byte offset
//   "Module.exe+0x2000"      - module base plus a raw RVA
#pragma once
#include "eip/common.h"
#include "eip/process.h"
#include <string>

namespace eip {

class TargetResolver {
public:
    explicit TargetResolver(const ProcessHandle& proc) : proc_(proc) {}

    // Throws EipError(ValueTargetUnresolved | ModuleNotFound | FunctionNotFound).
    Address resolve(const std::string& target) const;

private:
    const ProcessHandle& proc_;
};

} // namespace eip
