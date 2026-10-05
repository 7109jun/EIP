// EIP native core - process.h
// Process enumeration/attach and module listing. Windows-only (built on
// Toolhelp32 + OpenProcess). This is the top of the object graph every
// other Windows-side layer (Memory, Value, Function, Hook, Transaction,
// Feature) hangs off of: one ProcessHandle per attached target.
#pragma once

#include "eip/common.h"
#include "eip/memory.h"
#include "eip/pe.h"
#include <string>
#include <vector>
#include <memory>
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

struct ProcessSummary {
    u32 pid;
    std::string name;
    std::string path; // full path when accessible, else same as name
};

struct ModuleInfo {
    std::string name;      // e.g. "Demo.exe", "kernel32.dll"
    std::string path;      // full path if known
    Address base_address;
    u64 size;
};

namespace process {
    // Lists all running processes visible to the current user/privileges.
    std::vector<ProcessSummary> list();

    // Finds processes whose image name matches `name_or_glob` case-insensitively
    // (exact match on the executable file name, e.g. "Demo.exe").
    std::vector<ProcessSummary> find(const std::string& name_or_glob);
}

// A live attachment to one target process. Mirrors the Python
// `eip.attach("A.exe")` / `program.*` object.
class ProcessHandle {
public:
    ProcessHandle() = default;
    ~ProcessHandle();
    ProcessHandle(const ProcessHandle&) = delete;
    ProcessHandle& operator=(const ProcessHandle&) = delete;
    ProcessHandle(ProcessHandle&& other) noexcept;
    ProcessHandle& operator=(ProcessHandle&& other) noexcept;

    // Attaches by PID or by exact executable file name (first match).
    static ProcessHandle attach_pid(u32 pid);
    static ProcessHandle attach_name(const std::string& exe_name);

    void detach();
    bool attached() const;
    u32 pid() const { return pid_; }

    const Memory& memory() const { return memory_; }

    std::vector<ModuleInfo> modules() const;
    std::optional<ModuleInfo> module(const std::string& name) const;

    // Parses the PE headers of a loaded module directly out of the target's
    // memory (Loaded layout - see pe.h). This is how Value/Function resolve
    // `"Module.exe!symbol"` targets to a live address: export RVA + module
    // base, read straight from the remote process.
    PEImage read_module_pe(const ModuleInfo& mod) const;

    Arch arch() const { return arch_; }

#ifdef _WIN32
    HANDLE native_handle() const { return handle_; }
#endif

private:
#ifdef _WIN32
    HANDLE handle_ = nullptr;
#endif
    u32 pid_ = 0;
    Arch arch_ = Arch::Unknown;
    Memory memory_{
#ifdef _WIN32
        nullptr
#endif
    };
};

} // namespace eip
