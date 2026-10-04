// EIP native core - function.h
// Function discovery (export lookup / byte-pattern scan) and the two raw
// code-level operations Hook and Feature build on: replace (overwrite in
// place with a jump to new code) and add (allocate + write brand new code
// into the target process).
#pragma once
#include "eip/common.h"
#include "eip/process.h"
#include "eip/target.h"
#include <vector>
#include <optional>
#include <string>

namespace eip {

struct FunctionInfo {
    std::string name;
    Address address;
    std::string module_name;
};

// One pattern byte: either a fixed value or a wildcard ('??' in the textual form).
struct PatternByte {
    bool wildcard;
    u8 value;
};

std::vector<PatternByte> parse_pattern(const std::string& text); // "48 89 5C 24 ?? 48"

class FunctionEngine {
public:
    explicit FunctionEngine(const ProcessHandle& proc) : proc_(proc), resolver_(proc) {}

    // Export-table lookup: "Module.exe!FunctionName".
    std::optional<FunctionInfo> find_export(const std::string& module, const std::string& name) const;

    // Scans `module`'s executable sections for the first match of `pattern`
    // (a space-separated hex/?? string, e.g. "48 89 5C 24 ?? 48 89 74 24").
    std::optional<FunctionInfo> find_pattern(const std::string& module, const std::string& pattern) const;

    // Overwrites the function at `target` in place with a jump to
    // `new_impl`, after saving enough whole instructions (via x86len) to
    // safely restore later. Returns the bytes that were overwritten
    // (needed by Transaction/Hook for rollback) and how many bytes were
    // patched.
    struct ReplaceResult {
        std::vector<u8> original_bytes;
        std::size_t patched_size;
    };
    ReplaceResult replace(Address target, Address new_impl) const;

    // Restores `original_bytes` at `target` (undo of replace()).
    void restore(Address target, const std::vector<u8>& original_bytes) const;

    // Allocates RWX memory in the target and writes `machine_code` into it.
    // Used for "add a brand new function" (spec section 3/4: function.add).
    Address add(const std::vector<u8>& machine_code) const;

private:
    const ProcessHandle& proc_;
    TargetResolver resolver_;
};

} // namespace eip
