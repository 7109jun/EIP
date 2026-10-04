#include "eip/hook.h"
#include <cstring>

namespace eip {

namespace {
void append_u64_le(std::vector<u8>& v, u64 x) {
    for (int i = 0; i < 8; i++) v.push_back(static_cast<u8>((x >> (8 * i)) & 0xFF));
}
void append_u32_le(std::vector<u8>& v, u32 x) {
    for (int i = 0; i < 4; i++) v.push_back(static_cast<u8>((x >> (8 * i)) & 0xFF));
}
} // namespace

HookRecord HookEngine::install(Address target, Address detour) const {
    // Step 1: patch `target` to jump into `detour` (this also gives us the
    // saved original bytes and the exact whole-instruction span patched).
    auto replaced = functions_.replace(target, detour);

    HookRecord rec;
    rec.target = target;
    rec.detour = detour;
    rec.original_bytes = replaced.original_bytes;
    rec.patch_size = replaced.patched_size;

    // Step 2: build a trampoline = [the original bytes we just overwrote]
    // + [a jump back to target + patch_size], allocated in the target
    // process so the detour can call it to run "the real function".
    Arch arch = proc_.arch();
    std::vector<u8> tramp = rec.original_bytes;

    Address resumeAt = target + rec.patch_size;
    if (arch == Arch::X64) {
        tramp.push_back(0x48); tramp.push_back(0xB8); // mov rax, imm64
        append_u64_le(tramp, resumeAt);
        tramp.push_back(0xFF); tramp.push_back(0xE0); // jmp rax
    } else {
        // placeholder address; patched to the real relative offset once we
        // know where the trampoline itself landed (see below).
        tramp.push_back(0xE9);
        append_u32_le(tramp, 0);
    }

    Address trampAddr = proc_.memory().allocate(tramp.size(), /*PAGE_EXECUTE_READWRITE*/ 0x40);

    if (arch != Arch::X64) {
        // Fix up the rel32 now that we know the trampoline's real address.
        std::size_t jmpOpcodeOffset = rec.original_bytes.size();
        i32 rel = static_cast<i32>(static_cast<i64>(resumeAt) -
                                    static_cast<i64>(trampAddr + jmpOpcodeOffset + 5));
        std::memcpy(tramp.data() + jmpOpcodeOffset + 1, &rel, 4);
    }

    proc_.memory().write(trampAddr, tramp.data(), tramp.size());
    rec.trampoline = trampAddr;
    rec.active = true;
    return rec;
}

void HookEngine::remove(HookRecord& rec) const {
    if (!rec.active) return;
    functions_.restore(rec.target, rec.original_bytes);
    if (rec.trampoline) {
        proc_.memory().free(rec.trampoline);
    }
    rec.active = false;
}

} // namespace eip
