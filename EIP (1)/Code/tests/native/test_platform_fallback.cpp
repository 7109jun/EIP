// Real test of the Windows/non-Windows split in memory.cpp and process.cpp:
// on a non-Windows build, every Windows-only operation must fail cleanly
// with ErrorCode::NotImplementedOnPlatform rather than crashing, calling
// into undefined behavior, or silently no-op'ing. This is exactly the
// contract core/src/process.cpp and memory.cpp promise under #ifndef _WIN32,
// and it's what lets the rest of the native core (and this whole test
// suite) build and run on Linux for CI/local iteration while the real
// Windows-process paths wait for an actual Windows host to execute.
#include "eip/process.h"
#include "eip/memory.h"
#include <cstdio>
#include <cstdlib>

#define CHECK(cond, msg) do { \
    if (!(cond)) { std::fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); std::exit(1); } \
    else { std::printf("  ok: %s\n", msg); } \
} while (0)

int main() {
#ifdef _WIN32
    std::printf("this test only applies to non-Windows builds; nothing to check here.\n");
    return 0;
#else
    std::printf("[1] process::list / process::find\n");
    bool threw = false;
    try { eip::process::list(); } catch (const eip::EipError& e) { threw = (e.code() == eip::ErrorCode::NotImplementedOnPlatform); }
    CHECK(threw, "process::list() raises NotImplementedOnPlatform on non-Windows");

    threw = false;
    try { eip::process::find("x"); } catch (const eip::EipError& e) { threw = (e.code() == eip::ErrorCode::NotImplementedOnPlatform); }
    CHECK(threw, "process::find() raises NotImplementedOnPlatform on non-Windows");

    std::printf("[2] ProcessHandle::attach_pid / attach_name\n");
    threw = false;
    try { eip::ProcessHandle::attach_pid(1); } catch (const eip::EipError& e) { threw = (e.code() == eip::ErrorCode::NotImplementedOnPlatform); }
    CHECK(threw, "ProcessHandle::attach_pid() raises NotImplementedOnPlatform on non-Windows");

    threw = false;
    try { eip::ProcessHandle::attach_name("x.exe"); } catch (const eip::EipError& e) { threw = (e.code() == eip::ErrorCode::NotImplementedOnPlatform); }
    CHECK(threw, "ProcessHandle::attach_name() raises NotImplementedOnPlatform on non-Windows");

    std::printf("[3] a default-constructed ProcessHandle is safely 'not attached'\n");
    eip::ProcessHandle ph;
    CHECK(!ph.attached(), "default ProcessHandle reports not attached");
    ph.detach(); // must not crash even though nothing is attached

    std::printf("ALL PLATFORM FALLBACK TESTS PASSED\n");
    return 0;
#endif
}
