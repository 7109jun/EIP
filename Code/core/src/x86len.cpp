#include "eip/x86len.h"

namespace eip::x86len {

namespace {

struct ModRmResult {
    std::size_t total_bytes; // bytes consumed by ModRM + SIB + displacement
};

// Parses a ModRM (+ SIB + displacement) starting at `p`. Returns nullopt if
// it would read past `avail` bytes.
std::optional<ModRmResult> parse_modrm(const u8* p, std::size_t avail) {
    if (avail < 1) return std::nullopt;
    u8 modrm = p[0];
    u8 mod = (modrm >> 6) & 0x3;
    u8 rm = modrm & 0x7;
    std::size_t consumed = 1;

    bool has_sib = (mod != 3 && rm == 4);
    u8 sib_base = 0;
    if (has_sib) {
        if (avail < consumed + 1) return std::nullopt;
        sib_base = p[consumed] & 0x7;
        consumed += 1;
    }

    std::size_t disp = 0;
    if (mod == 0) {
        if (rm == 5) disp = 4;                         // RIP-relative (x86-64) / disp32 (x86-32)
        else if (has_sib && sib_base == 5) disp = 4;     // [SIB] with no base register
    } else if (mod == 1) {
        disp = 1;
    } else if (mod == 2) {
        disp = 4;
    }
    // mod == 3: register-direct, no displacement.

    if (avail < consumed + disp) return std::nullopt;
    consumed += disp;
    return ModRmResult{consumed};
}

} // namespace

std::optional<std::size_t> decode_length(const u8* code, std::size_t max_len, bool is64) {
    std::size_t pos = 0;
    bool has66 = false;
    bool rexW = false;
    bool haveRex = false;

    // --- legacy prefixes (max a handful; bail out if we never find an opcode) ---
    for (int guard = 0; guard < 8; guard++) {
        if (pos >= max_len) return std::nullopt;
        u8 b = code[pos];
        if (b == 0x66) { has66 = true; pos++; continue; }
        if (b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 ||
            b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65) {
            pos++; continue;
        }
        break;
    }

    // --- REX prefix (x86-64 only) ---
    if (is64 && pos < max_len && (code[pos] & 0xF0) == 0x40) {
        rexW = (code[pos] & 0x08) != 0;
        haveRex = true;
        pos++;
    }
    (void)haveRex;

    if (pos >= max_len) return std::nullopt;
    u8 op = code[pos++];

    auto immZ = [&]() -> std::size_t { return has66 ? 2 : 4; };

    // --- two-byte opcodes (0F xx) ---
    if (op == 0x0F) {
        if (pos >= max_len) return std::nullopt;
        u8 op2 = code[pos++];

        // Jcc rel32: 0F 80-0F8F
        if (op2 >= 0x80 && op2 <= 0x8F) {
            if (pos + 4 > max_len) return std::nullopt;
            return pos + 4;
        }
        // setcc r/m8: 0F 90-0F9F -> modrm, no imm
        if (op2 >= 0x90 && op2 <= 0x9F) {
            auto mr = parse_modrm(code + pos, max_len - pos);
            if (!mr) return std::nullopt;
            return pos + mr->total_bytes;
        }
        switch (op2) {
            case 0x05: case 0x0B: case 0x1E: // syscall, ud2, endbr64 (F3 0F 1E FA handled generically; plain 0F 1E modrm form below)
                // endbr64 is F3 0F 1E FA - the FA is a modrm-looking byte (mod=11) but it's fixed;
                // parse_modrm handles mod==3 correctly as "1 byte, no extra", so fall through to generic.
                if (op2 == 0x1E) {
                    auto mr = parse_modrm(code + pos, max_len - pos);
                    if (!mr) return std::nullopt;
                    return pos + mr->total_bytes;
                }
                return pos; // syscall/ud2: no modrm, no imm
            case 0x1F: // multi-byte NOP /r
            case 0x10: case 0x11: case 0x28: case 0x29: case 0x2A: case 0x2B:
            case 0x2C: case 0x2D: case 0x2E: case 0x2F:
            case 0x6E: case 0x7E: case 0xD6:
            case 0xAF: // imul r, r/m
            case 0xB6: case 0xB7: case 0xBE: case 0xBF: // movzx/movsx
            case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45: case 0x46: case 0x47: // cmovcc
            {
                auto mr = parse_modrm(code + pos, max_len - pos);
                if (!mr) return std::nullopt;
                return pos + mr->total_bytes;
            }
            default:
                return std::nullopt; // unsupported 2-byte opcode: refuse rather than guess
        }
    }

    // --- register-in-opcode forms: no modrm, no immediate ---
    if ((op >= 0x50 && op <= 0x5F) ||          // push/pop r
        (op >= 0x91 && op <= 0x97) ||          // xchg eAX, r
        op == 0x90 || op == 0x98 || op == 0x99 || op == 0x9C || op == 0x9D ||
        op == 0xC3 || op == 0xC9 || op == 0xCC || op == 0xF4) {
        return pos;
    }

    // mov r, imm32/imm64 : 0xB8-0xBF
    if (op >= 0xB8 && op <= 0xBF) {
        std::size_t immSize = rexW ? 8 : (has66 ? 2 : 4);
        if (pos + immSize > max_len) return std::nullopt;
        return pos + immSize;
    }
    // mov r8, imm8 : 0xB0-0xB7
    if (op >= 0xB0 && op <= 0xB7) {
        if (pos + 1 > max_len) return std::nullopt;
        return pos + 1;
    }

    // Jcc rel8 : 0x70-0x7F
    if (op >= 0x70 && op <= 0x7F) {
        if (pos + 1 > max_len) return std::nullopt;
        return pos + 1;
    }

    switch (op) {
        // ALU r/m,r and r,r/m forms (add/or/adc/sbb/and/sub/xor/cmp), 0x00-0x3B family, no immediate
        case 0x00: case 0x01: case 0x02: case 0x03:
        case 0x08: case 0x09: case 0x0A: case 0x0B:
        case 0x10: case 0x11: case 0x12: case 0x13:
        case 0x18: case 0x19: case 0x1A: case 0x1B:
        case 0x20: case 0x21: case 0x22: case 0x23:
        case 0x28: case 0x29: case 0x2A: case 0x2B:
        case 0x30: case 0x31: case 0x32: case 0x33:
        case 0x38: case 0x39: case 0x3A: case 0x3B:
        case 0x84: case 0x85: case 0x86: case 0x87:   // test, xchg
        case 0x88: case 0x89: case 0x8A: case 0x8B:   // mov
        case 0x8D:                                     // lea
        case 0x8F: {                                   // pop r/m
            auto mr = parse_modrm(code + pos, max_len - pos);
            if (!mr) return std::nullopt;
            return pos + mr->total_bytes;
        }

        // ALU AL/eAX, imm8 / imm32 forms
        case 0x04: case 0x0C: case 0x14: case 0x1C:
        case 0x24: case 0x2C: case 0x34: case 0x3C:
        case 0xA8: {
            if (pos + 1 > max_len) return std::nullopt;
            return pos + 1;
        }
        case 0x05: case 0x0D: case 0x15: case 0x1D:
        case 0x25: case 0x2D: case 0x35: case 0x3D:
        case 0xA9: {
            std::size_t sz = immZ();
            if (pos + sz > max_len) return std::nullopt;
            return pos + sz;
        }

        case 0x68: { // push imm32/imm16
            std::size_t sz = immZ();
            if (pos + sz > max_len) return std::nullopt;
            return pos + sz;
        }
        case 0x6A: { // push imm8
            if (pos + 1 > max_len) return std::nullopt;
            return pos + 1;
        }
        case 0x69: { // imul r, r/m, imm32
            auto mr = parse_modrm(code + pos, max_len - pos);
            if (!mr) return std::nullopt;
            std::size_t sz = immZ();
            if (pos + mr->total_bytes + sz > max_len) return std::nullopt;
            return pos + mr->total_bytes + sz;
        }
        case 0x6B: { // imul r, r/m, imm8
            auto mr = parse_modrm(code + pos, max_len - pos);
            if (!mr) return std::nullopt;
            if (pos + mr->total_bytes + 1 > max_len) return std::nullopt;
            return pos + mr->total_bytes + 1;
        }
        case 0x80: case 0xC0: case 0xC1: case 0xC6: { // grp1/grp2 Eb,Ib / Ev,Ib / mov Eb,Ib
            auto mr = parse_modrm(code + pos, max_len - pos);
            if (!mr) return std::nullopt;
            if (pos + mr->total_bytes + 1 > max_len) return std::nullopt;
            return pos + mr->total_bytes + 1;
        }
        case 0x81: case 0xC7: { // grp1 Ev,Iz / mov Ev,Iz
            auto mr = parse_modrm(code + pos, max_len - pos);
            if (!mr) return std::nullopt;
            std::size_t sz = immZ();
            if (pos + mr->total_bytes + sz > max_len) return std::nullopt;
            return pos + mr->total_bytes + sz;
        }
        case 0x83: { // grp1 Ev,Ib (very common: sub rsp, imm8)
            auto mr = parse_modrm(code + pos, max_len - pos);
            if (!mr) return std::nullopt;
            if (pos + mr->total_bytes + 1 > max_len) return std::nullopt;
            return pos + mr->total_bytes + 1;
        }
        case 0xD0: case 0xD1: case 0xD2: case 0xD3:
        case 0xFE: {
            auto mr = parse_modrm(code + pos, max_len - pos);
            if (!mr) return std::nullopt;
            return pos + mr->total_bytes;
        }
        case 0xFF: { // grp5: inc/dec/call/jmp/push r/m -- no immediate
            auto mr = parse_modrm(code + pos, max_len - pos);
            if (!mr) return std::nullopt;
            return pos + mr->total_bytes;
        }
        case 0xF6: { // grp3 Eb: test has imm8, others (not/neg/mul/div) do not
            if (pos >= max_len) return std::nullopt;
            u8 reg = (code[pos] >> 3) & 0x7;
            auto mr = parse_modrm(code + pos, max_len - pos);
            if (!mr) return std::nullopt;
            std::size_t extra = (reg == 0 || reg == 1) ? 1 : 0;
            if (pos + mr->total_bytes + extra > max_len) return std::nullopt;
            return pos + mr->total_bytes + extra;
        }
        case 0xF7: { // grp3 Ev: test has imm32/16, others do not
            if (pos >= max_len) return std::nullopt;
            u8 reg = (code[pos] >> 3) & 0x7;
            auto mr = parse_modrm(code + pos, max_len - pos);
            if (!mr) return std::nullopt;
            std::size_t extra = (reg == 0 || reg == 1) ? immZ() : 0;
            if (pos + mr->total_bytes + extra > max_len) return std::nullopt;
            return pos + mr->total_bytes + extra;
        }
        case 0xC2: { // ret imm16
            if (pos + 2 > max_len) return std::nullopt;
            return pos + 2;
        }
        case 0xE8: case 0xE9: { // call rel32 / jmp rel32
            if (pos + 4 > max_len) return std::nullopt;
            return pos + 4;
        }
        case 0xEB: { // jmp rel8
            if (pos + 1 > max_len) return std::nullopt;
            return pos + 1;
        }
        default:
            return std::nullopt; // unsupported / not needed for typical prologues: refuse rather than guess
    }
}

} // namespace eip::x86len
