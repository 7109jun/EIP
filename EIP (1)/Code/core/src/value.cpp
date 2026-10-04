#include "eip/value.h"
#include <cstring>

namespace eip {

std::vector<u8> ValueEngine::read_raw_bytes(Address addr, std::size_t size) const {
    return proc_.memory().read(addr, size);
}

ScalarValue ValueEngine::read(const std::string& target, ValueType type, std::size_t capacity) const {
    return read_at(resolve(target), type, capacity);
}

std::size_t ValueEngine::set(const std::string& target, const ScalarValue& value, std::size_t capacity) const {
    return set_at(resolve(target), value, capacity);
}

ScalarValue ValueEngine::read_at(Address addr, ValueType type, std::size_t capacity) const {
    ScalarValue out;
    out.type = type;
    switch (type) {
        case ValueType::I8: { i8 v; proc_.memory().read_into(addr, &v, 1); out.as_int = v; break; }
        case ValueType::U8: { u8 v; proc_.memory().read_into(addr, &v, 1); out.as_int = v; break; }
        case ValueType::Bool8: { u8 v; proc_.memory().read_into(addr, &v, 1); out.as_int = v != 0; break; }
        case ValueType::I16: { i16 v; proc_.memory().read_into(addr, &v, 2); out.as_int = v; break; }
        case ValueType::U16: { u16 v; proc_.memory().read_into(addr, &v, 2); out.as_int = v; break; }
        case ValueType::I32: { i32 v; proc_.memory().read_into(addr, &v, 4); out.as_int = v; break; }
        case ValueType::U32: { u32 v; proc_.memory().read_into(addr, &v, 4); out.as_int = v; break; }
        case ValueType::I64: { i64 v; proc_.memory().read_into(addr, &v, 8); out.as_int = v; break; }
        case ValueType::U64: { u64 v; proc_.memory().read_into(addr, &v, 8); out.as_int = static_cast<i64>(v); break; }
        case ValueType::Pointer32: { u32 v; proc_.memory().read_into(addr, &v, 4); out.as_int = v; break; }
        case ValueType::Pointer64: { u64 v; proc_.memory().read_into(addr, &v, 8); out.as_int = static_cast<i64>(v); break; }
        case ValueType::F32: { float v; proc_.memory().read_into(addr, &v, 4); out.as_float = v; break; }
        case ValueType::F64: { double v; proc_.memory().read_into(addr, &v, 8); out.as_float = v; break; }
        case ValueType::CStringAscii: {
            std::size_t cap = capacity ? capacity : 256;
            std::vector<u8> buf(cap, 0);
            proc_.memory().read_into(addr, buf.data(), cap);
            out.as_string.assign(reinterpret_cast<char*>(buf.data()),
                strnlen(reinterpret_cast<char*>(buf.data()), cap));
            break;
        }
        case ValueType::CStringUtf16: {
            std::size_t cap = capacity ? capacity : 256; // bytes
            std::vector<u16> buf(cap / 2, 0);
            proc_.memory().read_into(addr, buf.data(), buf.size() * 2);
            std::string utf8;
            for (u16 ch : buf) {
                if (ch == 0) break;
                if (ch < 0x80) utf8.push_back(static_cast<char>(ch));
                else if (ch < 0x800) {
                    utf8.push_back(static_cast<char>(0xC0 | (ch >> 6)));
                    utf8.push_back(static_cast<char>(0x80 | (ch & 0x3F)));
                } else {
                    utf8.push_back(static_cast<char>(0xE0 | (ch >> 12)));
                    utf8.push_back(static_cast<char>(0x80 | ((ch >> 6) & 0x3F)));
                    utf8.push_back(static_cast<char>(0x80 | (ch & 0x3F)));
                }
            }
            out.as_string = utf8;
            break;
        }
        case ValueType::Bytes: {
            std::size_t cap = capacity ? capacity : 16;
            std::vector<u8> buf(cap);
            proc_.memory().read_into(addr, buf.data(), cap);
            out.as_string.assign(reinterpret_cast<char*>(buf.data()), buf.size());
            break;
        }
    }
    return out;
}

std::size_t ValueEngine::set_at(Address addr, const ScalarValue& value, std::size_t capacity) const {
    switch (value.type) {
        case ValueType::I8: case ValueType::U8: case ValueType::Bool8: {
            u8 v = static_cast<u8>(value.as_int);
            proc_.memory().write_protected(addr, &v, 1);
            return 1;
        }
        case ValueType::I16: case ValueType::U16: {
            u16 v = static_cast<u16>(value.as_int);
            proc_.memory().write_protected(addr, &v, 2);
            return 2;
        }
        case ValueType::I32: case ValueType::U32: {
            u32 v = static_cast<u32>(value.as_int);
            proc_.memory().write_protected(addr, &v, 4);
            return 4;
        }
        case ValueType::I64: case ValueType::U64: {
            u64 v = static_cast<u64>(value.as_int);
            proc_.memory().write_protected(addr, &v, 8);
            return 8;
        }
        case ValueType::Pointer32: {
            u32 v = static_cast<u32>(value.as_int);
            proc_.memory().write_protected(addr, &v, 4);
            return 4;
        }
        case ValueType::Pointer64: {
            u64 v = static_cast<u64>(value.as_int);
            proc_.memory().write_protected(addr, &v, 8);
            return 8;
        }
        case ValueType::F32: {
            float v = static_cast<float>(value.as_float);
            proc_.memory().write_protected(addr, &v, 4);
            return 4;
        }
        case ValueType::F64: {
            double v = value.as_float;
            proc_.memory().write_protected(addr, &v, 8);
            return 8;
        }
        case ValueType::CStringAscii: {
            std::size_t cap = capacity ? capacity : (value.as_string.size() + 1);
            std::vector<u8> buf(cap, 0);
            std::size_t n = std::min(value.as_string.size(), cap - 1);
            std::memcpy(buf.data(), value.as_string.data(), n);
            proc_.memory().write_protected(addr, buf.data(), cap);
            return cap;
        }
        case ValueType::CStringUtf16: {
            std::vector<u16> units;
            for (unsigned char c : value.as_string) units.push_back(c); // ASCII-only input assumed for the demo path
            std::size_t cap = capacity ? capacity / 2 : (units.size() + 1);
            std::vector<u16> buf(cap, 0);
            std::size_t n = std::min(units.size(), cap - 1);
            std::memcpy(buf.data(), units.data(), n * 2);
            proc_.memory().write_protected(addr, buf.data(), cap * 2);
            return cap * 2;
        }
        case ValueType::Bytes: {
            proc_.memory().write_protected(addr, value.as_string.data(), value.as_string.size());
            return value.as_string.size();
        }
    }
    throw EipError(ErrorCode::ValueTypeMismatch, "unhandled ValueType");
}

} // namespace eip
