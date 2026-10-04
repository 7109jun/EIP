// EIP native core - x86len.h
// A length-only x86/x86-64 instruction decoder. It does not build a full
// instruction (no mnemonic, no operand values) - it only answers "how many
// bytes does the instruction starting here occupy?". That is exactly, and
// all, that Hook::install needs: to find a whole-instruction boundary at or
// past the patch size (5 bytes for a rel32 jmp, 14 for an abs64 jmp+mov) so
// the trampoline can copy complete instructions instead of slicing one in
// half.
//
// Coverage: legacy prefixes, REX, one- and two-byte (0F xx) opcodes with
// ModRM/SIB/disp8/disp32 and the common immediate-size table. It does not
// cover 0F38/0F3A three-byte opcodes or VEX/EVEX (AVX) encodings - those are
// rare in ordinary compiler-generated function prologues and, if
// encountered, decode_length() returns std::nullopt rather than guessing.
#pragma once
#include "eip/common.h"
#include <optional>

namespace eip::x86len {

// Decodes exactly one instruction starting at `code` (at most `max_len`
// bytes available). `is64` selects x86-64 (REX prefixes, 64-bit default
// operand size rules) vs plain x86. Returns the instruction length in
// bytes, or std::nullopt if the encoding isn't recognized.
std::optional<std::size_t> decode_length(const u8* code, std::size_t max_len, bool is64);

} // namespace eip::x86len
