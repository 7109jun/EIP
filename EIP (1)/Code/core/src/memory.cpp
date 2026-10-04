#include "eip/memory.h"

#ifndef _WIN32

namespace eip {
// Non-Windows build: the whole class degrades to NotImplementedOnPlatform.
// This lets the rest of the native core (and its Linux unit tests for the
// Windows-independent pieces) compile without #ifdef soup at every call
// site; only this translation unit needs the platform split.
std::vector<u8> Memory::read(Address, std::size_t) const {
    throw EipError(ErrorCode::NotImplementedOnPlatform, "Memory::read");
}
void Memory::read_into(Address, void*, std::size_t) const {
    throw EipError(ErrorCode::NotImplementedOnPlatform, "Memory::read_into");
}
bool Memory::try_read_into(Address, void*, std::size_t) const { return false; }
void Memory::write(Address, const void*, std::size_t) const {
    throw EipError(ErrorCode::NotImplementedOnPlatform, "Memory::write");
}
void Memory::write_protected(Address, const void*, std::size_t) const {
    throw EipError(ErrorCode::NotImplementedOnPlatform, "Memory::write_protected");
}
u32 Memory::protect(Address, std::size_t, u32) const {
    throw EipError(ErrorCode::NotImplementedOnPlatform, "Memory::protect");
}
std::optional<MemoryRegionInfo> Memory::query(Address) const { return std::nullopt; }
Address Memory::allocate(std::size_t, u32) const {
    throw EipError(ErrorCode::NotImplementedOnPlatform, "Memory::allocate");
}
void Memory::free(Address) const {
    throw EipError(ErrorCode::NotImplementedOnPlatform, "Memory::free");
}
bool MemoryRegionInfo::readable() const { return false; }
bool MemoryRegionInfo::writable() const { return false; }
bool MemoryRegionInfo::executable() const { return false; }
} // namespace eip

#else // _WIN32

namespace eip {

bool MemoryRegionInfo::readable() const {
    switch (protect & 0xFF) {
        case PAGE_READONLY: case PAGE_READWRITE: case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READ: case PAGE_EXECUTE_READWRITE: case PAGE_EXECUTE_WRITECOPY:
            return true;
        default: return false;
    }
}
bool MemoryRegionInfo::writable() const {
    switch (protect & 0xFF) {
        case PAGE_READWRITE: case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READWRITE: case PAGE_EXECUTE_WRITECOPY:
            return true;
        default: return false;
    }
}
bool MemoryRegionInfo::executable() const {
    switch (protect & 0xFF) {
        case PAGE_EXECUTE: case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE: case PAGE_EXECUTE_WRITECOPY:
            return true;
        default: return false;
    }
}

std::vector<u8> Memory::read(Address addr, std::size_t size) const {
    std::vector<u8> out(size);
    read_into(addr, out.data(), size);
    return out;
}

void Memory::read_into(Address addr, void* out, std::size_t size) const {
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(handle_, reinterpret_cast<LPCVOID>(addr), out, size, &bytesRead) || bytesRead != size) {
        throw EipError(ErrorCode::MemoryReadFailed,
            "addr=0x" + std::to_string(addr) + " size=" + std::to_string(size) +
            " gle=" + std::to_string(GetLastError()));
    }
}

bool Memory::try_read_into(Address addr, void* out, std::size_t size) const {
    SIZE_T bytesRead = 0;
    return ReadProcessMemory(handle_, reinterpret_cast<LPCVOID>(addr), out, size, &bytesRead) && bytesRead == size;
}

void Memory::write(Address addr, const void* data, std::size_t size) const {
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(handle_, reinterpret_cast<LPVOID>(addr), data, size, &bytesWritten) || bytesWritten != size) {
        throw EipError(ErrorCode::MemoryWriteFailed,
            "addr=0x" + std::to_string(addr) + " size=" + std::to_string(size) +
            " gle=" + std::to_string(GetLastError()));
    }
}

void Memory::write_protected(Address addr, const void* data, std::size_t size) const {
    DWORD oldProtect = 0;
    BOOL ok = VirtualProtectEx(handle_, reinterpret_cast<LPVOID>(addr), size, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (!ok) {
        throw EipError(ErrorCode::MemoryProtectFailed,
            "addr=0x" + std::to_string(addr) + " gle=" + std::to_string(GetLastError()));
    }
    try {
        write(addr, data, size);
    } catch (...) {
        DWORD restore = 0;
        VirtualProtectEx(handle_, reinterpret_cast<LPVOID>(addr), size, oldProtect, &restore);
        throw;
    }
    DWORD restore = 0;
    VirtualProtectEx(handle_, reinterpret_cast<LPVOID>(addr), size, oldProtect, &restore);
    FlushInstructionCache(handle_, reinterpret_cast<LPCVOID>(addr), size);
}

u32 Memory::protect(Address addr, std::size_t size, u32 new_protect) const {
    DWORD oldProtect = 0;
    if (!VirtualProtectEx(handle_, reinterpret_cast<LPVOID>(addr), size, static_cast<DWORD>(new_protect), &oldProtect)) {
        throw EipError(ErrorCode::MemoryProtectFailed,
            "addr=0x" + std::to_string(addr) + " gle=" + std::to_string(GetLastError()));
    }
    return static_cast<u32>(oldProtect);
}

std::optional<MemoryRegionInfo> Memory::query(Address addr) const {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQueryEx(handle_, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0) {
        return std::nullopt;
    }
    MemoryRegionInfo info;
    info.base_address = reinterpret_cast<Address>(mbi.BaseAddress);
    info.region_size = mbi.RegionSize;
    info.protect = mbi.Protect;
    info.state = mbi.State;
    info.type = mbi.Type;
    return info;
}

Address Memory::allocate(std::size_t size, u32 protect_flags) const {
    LPVOID p = VirtualAllocEx(handle_, nullptr, size, MEM_COMMIT | MEM_RESERVE, static_cast<DWORD>(protect_flags));
    if (!p) {
        throw EipError(ErrorCode::MemoryAllocFailed, "size=" + std::to_string(size) + " gle=" + std::to_string(GetLastError()));
    }
    return reinterpret_cast<Address>(p);
}

void Memory::free(Address addr) const {
    VirtualFreeEx(handle_, reinterpret_cast<LPVOID>(addr), 0, MEM_RELEASE);
}

} // namespace eip

#endif
