#include "eip/function.h"
#include "eip/x86len.h"
#include <sstream>
#include <algorithm>
#include <cstring>

namespace eip {

namespace {
// x64: mov rax, imm64 (48 B8 + 8 bytes) ; jmp rax (FF E0)  = 12 bytes.
// Using mov+jmp instead of FF 25 [rip+0] + abs64 so no extra data read is
// needed and the stub is a flat, position-independent 12 bytes.
constexpr std::size_t X64_JMP_STUB_SIZE = 12;
// x86: E9 rel32 = 5 bytes.
constexpr std::size_t X86_JMP_STUB_SIZE = 5;

std::size_t jmp_stub_size(Arch arch) {
    return arch == Arch::X64 ? X64_JMP_STUB_SIZE : X86_JMP_STUB_SIZE;
}

void build_jmp_stub(Arch arch, Address from, Address to, std::vector<u8>& out) {
    out.clear();
    if (arch == Arch::X64) {
        out.push_back(0x48); out.push_back(0xB8); // mov rax, imm64
        for (int i = 0; i < 8; i++) out.push_back(static_cast<u8>((to >> (8 * i)) & 0xFF));
        out.push_back(0xFF); out.push_back(0xE0); // jmp rax
    } else {
        i32 rel = static_cast<i32>(static_cast<i64>(to) - static_cast<i64>(from + 5));
        out.push_back(0xE9);
        out.push_back(static_cast<u8>(rel & 0xFF));
        out.push_back(static_cast<u8>((rel >> 8) & 0xFF));
        out.push_back(static_cast<u8>((rel >> 16) & 0xFF));
        out.push_back(static_cast<u8>((rel >> 24) & 0xFF));
    }
}

// Finds how many bytes from `target` must be saved/overwritten to fit a
// whole number of original instructions covering at least `needed` bytes.
std::size_t whole_instruction_span(const std::vector<u8>& window, std::size_t needed, bool is64) {
    std::size_t pos = 0;
    while (pos < needed) {
        auto len = x86len::decode_length(window.data() + pos, window.size() - pos, is64);
        if (!len || *len == 0) {
            throw EipError(ErrorCode::HookInstallFailed,
                "could not decode instruction at offset " + std::to_string(pos) +
                " while measuring a safe patch span (unsupported encoding)");
        }
        pos += *len;
    }
    return pos;
}
} // namespace

std::vector<PatternByte> parse_pattern(const std::string& text) {
    std::vector<PatternByte> out;
    std::istringstream iss(text);
    std::string tok;
    while (iss >> tok) {
        if (tok == "??" || tok == "?") {
            out.push_back({true, 0});
        } else {
            out.push_back({false, static_cast<u8>(std::stoul(tok, nullptr, 16))});
        }
    }
    return out;
}

std::optional<FunctionInfo> FunctionEngine::find_export(const std::string& module, const std::string& name) const {
    auto mod = proc_.module(module);
    if (!mod) throw EipError(ErrorCode::ModuleNotFound, module);
    PEImage pe = proc_.read_module_pe(*mod);
    auto rva = pe.find_export(name);
    if (!rva) return std::nullopt;
    FunctionInfo fi;
    fi.name = name;
    fi.module_name = module;
    fi.address = mod->base_address + *rva;
    return fi;
}

std::optional<FunctionInfo> FunctionEngine::find_pattern(const std::string& module, const std::string& pattern) const {
    auto mod = proc_.module(module);
    if (!mod) throw EipError(ErrorCode::ModuleNotFound, module);
    auto pat = parse_pattern(pattern);
    if (pat.empty()) throw EipError(ErrorCode::InvalidArgument, "empty pattern");

    PEImage pe = proc_.read_module_pe(*mod);
    for (auto& sec : pe.sections()) {
        if (!sec.executable()) continue;
        std::vector<u8> buf(sec.virtual_size);
        if (!proc_.memory().try_read_into(mod->base_address + sec.virtual_address, buf.data(), buf.size())) continue;
        if (buf.size() < pat.size()) continue;
        for (std::size_t i = 0; i + pat.size() <= buf.size(); i++) {
            bool ok = true;
            for (std::size_t j = 0; j < pat.size(); j++) {
                if (!pat[j].wildcard && buf[i + j] != pat[j].value) { ok = false; break; }
            }
            if (ok) {
                FunctionInfo fi;
                fi.name = "pattern_match";
                fi.module_name = module;
                fi.address = mod->base_address + sec.virtual_address + i;
                return fi;
            }
        }
    }
    return std::nullopt;
}

FunctionEngine::ReplaceResult FunctionEngine::replace(Address target, Address new_impl) const {
    Arch arch = proc_.arch();
    std::size_t needed = jmp_stub_size(arch);

    constexpr std::size_t WINDOW = 32;
    std::vector<u8> window(WINDOW);
    proc_.memory().read_into(target, window.data(), WINDOW);

    std::size_t span = whole_instruction_span(window, needed, arch == Arch::X64);
    if (span < needed) {
        throw EipError(ErrorCode::FunctionTooSmallToHook,
            "only " + std::to_string(span) + " bytes available, need " + std::to_string(needed));
    }

    std::vector<u8> original(window.begin(), window.begin() + static_cast<long>(span));

    std::vector<u8> stub;
    build_jmp_stub(arch, target, new_impl, stub);
    std::vector<u8> patch(span, 0x90); // pad any trailing bytes (within the last whole instruction) with NOP
    std::memcpy(patch.data(), stub.data(), stub.size());

    proc_.memory().write_protected(target, patch.data(), patch.size());

    return ReplaceResult{original, span};
}

void FunctionEngine::restore(Address target, const std::vector<u8>& original_bytes) const {
    proc_.memory().write_protected(target, original_bytes.data(), original_bytes.size());
}

Address FunctionEngine::add(const std::vector<u8>& machine_code) const {
    Address mem = proc_.memory().allocate(machine_code.size(), /*PAGE_EXECUTE_READWRITE*/ 0x40);
    proc_.memory().write(mem, machine_code.data(), machine_code.size());
    return mem;
}

} // namespace eip
