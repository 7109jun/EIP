#include "eip/process.h"

#ifndef _WIN32

namespace eip {
namespace process {
std::vector<ProcessSummary> list() {
    throw EipError(ErrorCode::NotImplementedOnPlatform, "process::list");
}
std::vector<ProcessSummary> find(const std::string&) {
    throw EipError(ErrorCode::NotImplementedOnPlatform, "process::find");
}
}

ProcessHandle::~ProcessHandle() {}
ProcessHandle::ProcessHandle(ProcessHandle&&) noexcept = default;
ProcessHandle& ProcessHandle::operator=(ProcessHandle&&) noexcept = default;

ProcessHandle ProcessHandle::attach_pid(u32) {
    throw EipError(ErrorCode::NotImplementedOnPlatform, "ProcessHandle::attach_pid");
}
ProcessHandle ProcessHandle::attach_name(const std::string&) {
    throw EipError(ErrorCode::NotImplementedOnPlatform, "ProcessHandle::attach_name");
}
void ProcessHandle::detach() {}
bool ProcessHandle::attached() const { return false; }
std::vector<ModuleInfo> ProcessHandle::modules() const { return {}; }
std::optional<ModuleInfo> ProcessHandle::module(const std::string&) const { return std::nullopt; }
PEImage ProcessHandle::read_module_pe(const ModuleInfo&) const {
    throw EipError(ErrorCode::NotImplementedOnPlatform, "ProcessHandle::read_module_pe");
}
} // namespace eip

#else // _WIN32

#include <tlhelp32.h>
#include <psapi.h>
#include <algorithm>
#include <cctype>
#include <cstdio>

// Temporary diagnostic tracing: this session's sandbox has no Windows
// kernel, so attach-path code here was cross-compiled but never actually
// executed before a real Windows CI runner hit a crash (exit code
// 0xC0000409) somewhere in or around ProcessHandle::attach_name(). These
// traces pin down exactly which Win32 call it happens in; remove once the
// root cause is fixed and confirmed green on a real run.
#define EIP_TRACE(msg) do { std::fprintf(stderr, "[eip-trace] %s\n", msg); std::fflush(stderr); } while (0)

namespace eip {

namespace {
std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

// RAII snapshot handle so every early-return path below still closes it.
struct SnapshotGuard {
    HANDLE h;
    explicit SnapshotGuard(DWORD flags, DWORD pid = 0) : h(CreateToolhelp32Snapshot(flags, pid)) {}
    ~SnapshotGuard() { if (h != INVALID_HANDLE_VALUE && h) CloseHandle(h); }
    bool valid() const { return h != INVALID_HANDLE_VALUE && h != nullptr; }
};
} // namespace

namespace process {

std::vector<ProcessSummary> list() {
    EIP_TRACE("list(): enter");
    std::vector<ProcessSummary> out;
    EIP_TRACE("list(): calling CreateToolhelp32Snapshot");
    SnapshotGuard snap(TH32CS_SNAPPROCESS);
    EIP_TRACE("list(): CreateToolhelp32Snapshot returned");
    if (!snap.valid()) {
        throw EipError(ErrorCode::InternalError, "CreateToolhelp32Snapshot failed gle=" + std::to_string(GetLastError()));
    }
    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);
    EIP_TRACE("list(): calling Process32First");
    if (Process32First(snap.h, &pe)) {
        EIP_TRACE("list(): Process32First returned true, entering loop");
        int iter = 0;
        do {
            ProcessSummary s;
            s.pid = pe.th32ProcessID;
            s.name = pe.szExeFile;
            s.path = pe.szExeFile; // full path resolved lazily via module() for the attached case
            // Temporary: log any process name that might plausibly be our
            // target, to see what attach_name's "no match" is actually
            // seeing it as (wrong name? already exited and replaced by
            // something else? not visible at all?).
            std::string lname = s.name;
            std::transform(lname.begin(), lname.end(), lname.begin(), [](unsigned char c) { return (char)std::tolower(c); });
            if (lname.find("demo") != std::string::npos) {
                EIP_TRACE(("list(): candidate process pid=" + std::to_string(s.pid) + " name='" + s.name + "'").c_str());
            }
            out.push_back(std::move(s));
            iter++;
        } while (Process32Next(snap.h, &pe));
        EIP_TRACE(("list(): loop finished, iterations=" + std::to_string(iter)).c_str());
        bool any_demo = false;
        for (auto& s2 : out) {
            std::string ln = s2.name;
            std::transform(ln.begin(), ln.end(), ln.begin(), [](unsigned char c) { return (char)std::tolower(c); });
            if (ln.find("demo") != std::string::npos) any_demo = true;
        }
        if (!any_demo) EIP_TRACE("list(): no process name containing 'demo' was seen in this snapshot");
    } else {
        EIP_TRACE("list(): Process32First returned false");
    }
    EIP_TRACE("list(): returning");
    return out;
}

std::vector<ProcessSummary> find(const std::string& name_or_glob) {
    std::vector<ProcessSummary> out;
    std::string needle = lower(name_or_glob);
    for (auto& p : list()) {
        if (lower(p.name) == needle || lower(p.name).find(needle) != std::string::npos) {
            out.push_back(p);
        }
    }
    return out;
}

} // namespace process

ProcessHandle::~ProcessHandle() { detach(); }

ProcessHandle::ProcessHandle(ProcessHandle&& other) noexcept
    : handle_(other.handle_), pid_(other.pid_), arch_(other.arch_), memory_(other.handle_) {
    other.handle_ = nullptr;
    other.pid_ = 0;
}

ProcessHandle& ProcessHandle::operator=(ProcessHandle&& other) noexcept {
    if (this != &other) {
        detach();
        handle_ = other.handle_;
        pid_ = other.pid_;
        arch_ = other.arch_;
        memory_ = Memory(handle_);
        other.handle_ = nullptr;
        other.pid_ = 0;
    }
    return *this;
}

namespace {
Arch detect_arch(HANDLE process) {
    EIP_TRACE("detect_arch: enter");
    BOOL isWow64 = FALSE;
    SYSTEM_INFO sysInfo{};
    EIP_TRACE("detect_arch: calling GetNativeSystemInfo");
    GetNativeSystemInfo(&sysInfo);
    EIP_TRACE("detect_arch: GetNativeSystemInfo returned");
    bool hostIs64 = (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64);
    if (!hostIs64) { EIP_TRACE("detect_arch: host not amd64, returning X86"); return Arch::X86; }
    EIP_TRACE("detect_arch: calling IsWow64Process");
    BOOL ok = IsWow64Process(process, &isWow64);
    EIP_TRACE("detect_arch: IsWow64Process returned");
    if (ok && isWow64) return Arch::X86;
    return Arch::X64;
}
} // namespace

ProcessHandle ProcessHandle::attach_pid(u32 pid) {
    EIP_TRACE(("attach_pid: enter pid=" + std::to_string(pid)).c_str());
    EIP_TRACE("attach_pid: calling OpenProcess");
    HANDLE h = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
        PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | PROCESS_SUSPEND_RESUME | SYNCHRONIZE,
        FALSE, pid);
    EIP_TRACE("attach_pid: OpenProcess returned");
    if (!h) {
        DWORD gle = GetLastError();
        ErrorCode code = (gle == ERROR_ACCESS_DENIED) ? ErrorCode::ProcessAccessDenied : ErrorCode::ProcessNotFound;
        throw EipError(code, "pid=" + std::to_string(pid) + " gle=" + std::to_string(gle));
    }
    ProcessHandle ph;
    ph.handle_ = h;
    ph.pid_ = pid;
    EIP_TRACE("attach_pid: calling detect_arch");
    ph.arch_ = detect_arch(h);
    EIP_TRACE("attach_pid: detect_arch returned, constructing Memory");
    ph.memory_ = Memory(h);
    EIP_TRACE("attach_pid: returning ProcessHandle");
    return ph;
}

ProcessHandle ProcessHandle::attach_name(const std::string& exe_name) {
    EIP_TRACE(("attach_name: enter name='" + exe_name + "'").c_str());
    auto matches = process::find(exe_name);
    EIP_TRACE(("attach_name: process::find returned, matches=" + std::to_string(matches.size())).c_str());
    if (matches.empty()) {
        throw EipError(ErrorCode::ProcessNotFound, "name='" + exe_name + "'");
    }
    EIP_TRACE(("attach_name: calling attach_pid for pid=" + std::to_string(matches.front().pid)).c_str());
    return attach_pid(matches.front().pid);
}

void ProcessHandle::detach() {
    if (handle_) {
        CloseHandle(handle_);
        handle_ = nullptr;
    }
    pid_ = 0;
}

bool ProcessHandle::attached() const { return handle_ != nullptr; }

std::vector<ModuleInfo> ProcessHandle::modules() const {
    std::vector<ModuleInfo> out;
    if (!handle_) throw EipError(ErrorCode::ProcessNotAttached, "");

    SnapshotGuard snap(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid_);
    if (!snap.valid()) {
        throw EipError(ErrorCode::InternalError, "module snapshot failed gle=" + std::to_string(GetLastError()));
    }
    MODULEENTRY32 me{};
    me.dwSize = sizeof(me);
    if (Module32First(snap.h, &me)) {
        do {
            ModuleInfo mi;
            mi.name = me.szModule;
            mi.path = me.szExePath;
            mi.base_address = reinterpret_cast<Address>(me.modBaseAddr);
            mi.size = me.modBaseSize;
            out.push_back(std::move(mi));
        } while (Module32Next(snap.h, &me));
    }
    return out;
}

std::optional<ModuleInfo> ProcessHandle::module(const std::string& name) const {
    std::string needle = name;
    std::transform(needle.begin(), needle.end(), needle.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    for (auto& m : modules()) {
        std::string mn = m.name;
        std::transform(mn.begin(), mn.end(), mn.begin(), [](unsigned char c) { return (char)std::tolower(c); });
        if (mn == needle) return m;
    }
    return std::nullopt;
}

PEImage ProcessHandle::read_module_pe(const ModuleInfo& mod) const {
    if (!handle_) throw EipError(ErrorCode::ProcessNotAttached, "");
    HANDLE h = handle_;
    // PEImage::parse_loaded addresses everything as an RVA from `base`; this
    // closure turns that back into a real ReadProcessMemory call against the
    // module's actual load address in the target process.
    Address base = mod.base_address;
    auto boundReader = [h, base](std::uint64_t rva, void* out, std::size_t size) -> bool {
        SIZE_T got = 0;
        return ReadProcessMemory(h, reinterpret_cast<LPCVOID>(base + rva), out, size, &got) && got == size;
    };
    return PEImage::parse_loaded(boundReader, base, mod.size);
}

} // namespace eip

#endif
