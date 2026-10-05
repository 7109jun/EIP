// EIP native core - hook.h
// Inline trampoline hooking: redirect a function to a detour while keeping
// a callable "original" (the trampoline) - the mechanism spec section 4
// calls Hook, distinct from Function::replace which doesn't preserve a
// callable original.
#pragma once
#include "eip/common.h"
#include "eip/process.h"
#include "eip/function.h"

namespace eip {

struct HookRecord {
    Address target = 0;          // the hooked function's original entry address
    Address detour = 0;          // the user-supplied replacement function
    Address trampoline = 0;      // allocated stub: saved original instructions + jmp back to target+patch_size
    std::vector<u8> original_bytes; // bytes that were overwritten at `target` (for restore)
    std::size_t patch_size = 0;
    bool active = false;
};

class HookEngine {
public:
    explicit HookEngine(const ProcessHandle& proc) : proc_(proc), functions_(proc) {}

    // Installs a hook: `target` starts jumping to `detour`; the returned
    // record's `trampoline` address still runs the original instructions
    // (so the detour can call it to preserve original behavior) before
    // jumping back into `target` just past the patched region.
    HookRecord install(Address target, Address detour) const;

    // Restores `target`'s original bytes and frees the trampoline.
    void remove(HookRecord& rec) const;

private:
    const ProcessHandle& proc_;
    FunctionEngine functions_;
};

} // namespace eip
