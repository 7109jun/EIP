// EIP native core - memory.h
// Thin, typed wrapper over the Windows cross-process memory primitives.
// Windows-only: every function here goes through ReadProcessMemory /
// WriteProcessMemory / VirtualProtectEx / VirtualQueryEx against a handle
// owned by Process (process.h). Build with _WIN32 defined (mingw-w64 or MSVC).
#pragma once

#include "eip/common.h"
#include <vector>
#include <optional>

#ifdef _WIN32
  #ifndef NOMINMAX
  #define NOMINMAX // prevent windows.h's min/max macros from shadowing std::min/std::max
  #endif
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
#include <windows.h>
#endif

namespace eip {

struct MemoryRegionInfo {
    Address base_address;
    u64 region_size;
    u32 protect;      // PAGE_* flags
    u32 state;         // MEM_COMMIT / MEM_FREE / MEM_RESERVE
    u32 type;          // MEM_PRIVATE / MEM_IMAGE / MEM_MAPPED
    bool readable() const;
    bool writable() const;
    bool executable() const;
};

// Wraps a live process handle (see Process::native_handle()) and exposes
// the memory operations every higher layer (Value, Function, Hook) is
// built on. Does not own the handle's lifetime.
class Memory {
public:
#ifdef _WIN32
    explicit Memory(HANDLE process_handle) : handle_(process_handle) {}
#endif

    std::vector<u8> read(Address addr, std::size_t size) const;
    void read_into(Address addr, void* out, std::size_t size) const; // throws on partial read
    bool try_read_into(Address addr, void* out, std::size_t size) const; // false instead of throwing

    void write(Address addr, const void* data, std::size_t size) const; // throws

    // Temporarily makes [addr, addr+size) writable (if not already),
    // writes, then restores the original protection. Needed for patching
    // code in .text sections, which are normally PAGE_EXECUTE_READ.
    void write_protected(Address addr, const void* data, std::size_t size) const;

    u32 protect(Address addr, std::size_t size, u32 new_protect) const; // returns old protect, throws on failure

    std::optional<MemoryRegionInfo> query(Address addr) const;

    Address allocate(std::size_t size, u32 protect) const; // VirtualAllocEx, throws MemoryAllocFailed
    void free(Address addr) const; // VirtualFreeEx (MEM_RELEASE)

private:
#ifdef _WIN32
    HANDLE handle_ = nullptr;
#endif
};

} // namespace eip
