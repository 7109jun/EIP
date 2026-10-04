// Real test of the x86/x86-64 instruction-length decoder (core/src/x86len.cpp)
// against ground truth taken directly from `objdump -d` output of an actual
// mingw-compiled function (Demo.exe's WinMain-equivalent prologue). See the
// comment on each instruction for the objdump disassembly it corresponds to.
#include "eip/x86len.h"
#include <cstdio>
#include <cstdlib>

#define CHECK(cond, msg) do { \
    if (!(cond)) { std::fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); std::exit(1); } \
    else { std::printf("  ok: %s\n", msg); } \
} while (0)

int main() {
    // Ground truth from: x86_64-w64-mingw32-objdump -d tiny.exe (WinMain):
    //   140001480: 55                      push   %rbp
    //   140001481: 48 89 e5                mov    %rsp,%rbp
    //   140001484: 48 89 4d 10             mov    %rcx,0x10(%rbp)
    //   140001488: 48 89 55 18             mov    %rdx,0x18(%rbp)
    //   14000148c: 4c 89 45 20             mov    %r8,0x20(%rbp)
    //   140001490: 44 89 4d 28             mov    %r9d,0x28(%rbp)
    //   140001494: 8b 05 66 1b 00 00       mov    0x1b66(%rip),%eax
    //   14000149a: 5d                      pop    %rbp
    //   14000149b: c3                      ret
    //   14000149c: 90                      nop  (x4)
    eip::u8 code[] = {
        0x55,
        0x48,0x89,0xe5,
        0x48,0x89,0x4d,0x10,
        0x48,0x89,0x55,0x18,
        0x4c,0x89,0x45,0x20,
        0x44,0x89,0x4d,0x28,
        0x8b,0x05,0x66,0x1b,0x00,0x00,
        0x5d,
        0xc3,
        0x90,0x90,0x90,0x90,
    };
    std::size_t expect[] = {1,3,4,4,4,4,6,1,1,1,1,1,1};
    std::size_t pos = 0;
    for (int i = 0; i < 13; i++) {
        auto len = eip::x86len::decode_length(code + pos, sizeof(code) - pos, /*is64=*/true);
        CHECK(len.has_value(), "decode succeeded");
        char msg[128];
        std::snprintf(msg, sizeof(msg), "instr[%d] length == %zu (objdump ground truth)", i, expect[i]);
        CHECK(*len == expect[i], msg);
        pos += *len;
    }
    CHECK(pos == sizeof(code), "decoded length covers the entire ground-truth byte sequence");

    // A handful of additional common prologue/epilogue patterns, hand-
    // verified against objdump when these were developed (see git history
    // / design notes) - guards against regressions in the opcode tables.
    {
        eip::u8 sub_rsp[] = {0x48, 0x83, 0xEC, 0x28}; // sub rsp, 0x28
        auto len = eip::x86len::decode_length(sub_rsp, sizeof(sub_rsp), true);
        CHECK(len.has_value() && *len == 4, "sub rsp, imm8 decodes to 4 bytes");
    }
    {
        eip::u8 mov_imm64[] = {0x48,0xB8,1,2,3,4,5,6,7,8}; // mov rax, imm64
        auto len = eip::x86len::decode_length(mov_imm64, sizeof(mov_imm64), true);
        CHECK(len.has_value() && *len == 10, "mov rax, imm64 decodes to 10 bytes");
    }
    {
        eip::u8 jmp_rax[] = {0xFF, 0xE0}; // jmp rax
        auto len = eip::x86len::decode_length(jmp_rax, sizeof(jmp_rax), true);
        CHECK(len.has_value() && *len == 2, "jmp rax (FF /4) decodes to 2 bytes");
    }
    {
        eip::u8 call_rel32[] = {0xE8, 0,0,0,0}; // call rel32
        auto len = eip::x86len::decode_length(call_rel32, sizeof(call_rel32), true);
        CHECK(len.has_value() && *len == 5, "call rel32 decodes to 5 bytes");
    }
    {
        eip::u8 retn[] = {0xC3};
        auto len = eip::x86len::decode_length(retn, sizeof(retn), true);
        CHECK(len.has_value() && *len == 1, "ret decodes to 1 byte");
    }
    {
        // truncated instruction: mov rax, imm64 opcode present but only 4 of
        // the 8 immediate bytes available - must fail, not guess.
        eip::u8 truncated[] = {0x48,0xB8,1,2,3,4};
        auto len = eip::x86len::decode_length(truncated, sizeof(truncated), true);
        CHECK(!len.has_value(), "truncated instruction correctly reported as undecodable");
    }

    std::printf("ALL X86LEN GROUND-TRUTH TESTS PASSED\n");
    return 0;
}
