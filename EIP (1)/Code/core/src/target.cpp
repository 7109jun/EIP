#include "eip/target.h"
#include <cctype>
#include <algorithm>

namespace eip {

namespace {
bool looks_hex_address(const std::string& s) {
    std::string t = s;
    if (t.rfind("0x", 0) == 0 || t.rfind("0X", 0) == 0) t = t.substr(2);
    if (t.empty()) return false;
    return std::all_of(t.begin(), t.end(), [](unsigned char c) { return std::isxdigit(c); });
}

u64 parse_hex(const std::string& s) {
    std::string t = s;
    if (t.rfind("0x", 0) == 0 || t.rfind("0X", 0) == 0) t = t.substr(2);
    return std::stoull(t, nullptr, 16);
}
} // namespace

Address TargetResolver::resolve(const std::string& target) const {
    if (target.empty()) {
        throw EipError(ErrorCode::ValueTargetUnresolved, "empty target string");
    }

    // Pure absolute address.
    if (looks_hex_address(target)) {
        return static_cast<Address>(parse_hex(target));
    }

    // "Module!symbol[+0xOFF]" or "Module+0xRVA"
    std::string module_part, rest;
    char sep = 0;
    auto bangPos = target.find('!');
    auto plusPos = target.find('+');
    if (bangPos != std::string::npos && (plusPos == std::string::npos || bangPos < plusPos)) {
        module_part = target.substr(0, bangPos);
        rest = target.substr(bangPos + 1);
        sep = '!';
    } else if (plusPos != std::string::npos) {
        module_part = target.substr(0, plusPos);
        rest = target.substr(plusPos + 1);
        sep = '+';
    } else {
        throw EipError(ErrorCode::ValueTargetUnresolved,
            "target '" + target + "' is neither a hex address nor Module!symbol / Module+0xRVA");
    }

    auto mod = proc_.module(module_part);
    if (!mod) {
        throw EipError(ErrorCode::ModuleNotFound, "module '" + module_part + "'");
    }

    if (sep == '+') {
        // rest is a raw RVA in hex.
        if (!looks_hex_address(rest)) {
            throw EipError(ErrorCode::ValueTargetUnresolved, "'" + rest + "' is not a hex RVA");
        }
        return mod->base_address + parse_hex(rest);
    }

    // sep == '!': rest is "symbolName" or "symbolName+0xOFF"
    std::string symbol = rest;
    u64 extraOffset = 0;
    auto symPlus = rest.find('+');
    if (symPlus != std::string::npos) {
        symbol = rest.substr(0, symPlus);
        std::string offStr = rest.substr(symPlus + 1);
        if (!looks_hex_address(offStr)) {
            throw EipError(ErrorCode::ValueTargetUnresolved, "'" + offStr + "' is not a hex offset");
        }
        extraOffset = parse_hex(offStr);
    }

    PEImage pe = proc_.read_module_pe(*mod);
    auto rva = pe.find_export(symbol);
    if (!rva) {
        throw EipError(ErrorCode::FunctionNotFound, "export '" + symbol + "' not found in module '" + module_part + "'");
    }
    return mod->base_address + *rva + extraOffset;
}

} // namespace eip
