// Live end-to-end test: requires an actual Windows host with Demo.exe
// already running (examples/demo_program/Demo.exe). Cross-compiles cleanly
// here (mingw-w64) to prove the interfaces are correct, but OpenProcess /
// ReadProcessMemory / etc. only do real work on Windows, so execution of
// this binary is deferred to the user's own Windows machine per the agreed
// verification plan for this session.
//
// Usage (on Windows):
//   examples\demo_program\Demo.exe &
//   test_windows_live.exe
//
// Exercises, against the real running process:
//   - ProcessHandle::attach_name, modules()
//   - ValueEngine::read/set (RunSpeed 10 -> 20)
//   - FunctionEngine::find_export
//   - Transaction commit (two value changes atomically) and rollback
//     (an intentionally-failing transaction leaves no partial state)
//   - HookEngine::install/remove (byte-level before/after verification)
//   - Feature::install/uninstall (the Export-menu feature, end to end)
//   - Runtime::checkpoint/diff_since
#include "eip/runtime.h"
#include "eip/feature.h"
#include "eip/transaction.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

#define CHECK(cond, msg) do { \
    if (!(cond)) { std::fprintf(stderr, "FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); std::exit(1); } \
    else { std::printf("  ok: %s\n", msg); } \
} while (0)

using namespace eip;

int main() {
    std::printf("[1] attach to Demo.exe\n");
    ProcessHandle ph = ProcessHandle::attach_name("Demo.exe");
    CHECK(ph.attached(), "attached to Demo.exe");
    CHECK(ph.arch() == Arch::X64, "Demo.exe is x64 (built by examples/demo_program/build.sh)");

    Session session(std::move(ph));

    std::printf("[2] value read/set: RunSpeed 10 -> 20\n");
    ScalarValue before = session.values().read("Demo.exe!g_RunSpeed", ValueType::I32);
    CHECK(before.as_int == 10, "initial RunSpeed is 10");

    ScalarValue twenty; twenty.type = ValueType::I32; twenty.as_int = 20;
    session.values().set("Demo.exe!g_RunSpeed", twenty);
    ScalarValue after = session.values().read("Demo.exe!g_RunSpeed", ValueType::I32);
    CHECK(after.as_int == 20, "RunSpeed reads back as 20 after value.set");

    std::printf("[3] function discovery\n");
    auto fn = session.functions().find_export("Demo.exe", "GetRunSpeed");
    CHECK(fn.has_value(), "GetRunSpeed found via export table");

    std::printf("[4] transaction commit (atomic multi-change)\n");
    {
        Transaction tx(&session.runtime());
        ScalarValue rs; rs.type = ValueType::I32; rs.as_int = 55;
        ScalarValue mc; mc.type = ValueType::I32; mc.as_int = 3;
        tx.value_set(session.values(), "Demo.exe!g_RunSpeed", ValueType::I32, rs);
        tx.value_set(session.values(), "Demo.exe!g_MenuCount", ValueType::I32, mc);
        tx.commit();
    }
    ScalarValue rsNow = session.values().read("Demo.exe!g_RunSpeed", ValueType::I32);
    CHECK(rsNow.as_int == 55, "transaction commit applied RunSpeed=55");

    std::printf("[5] transaction rollback on failure leaves no partial state\n");
    ScalarValue beforeFail = session.values().read("Demo.exe!g_RunSpeed", ValueType::I32);
    bool threw = false;
    try {
        Transaction tx(&session.runtime());
        ScalarValue rs; rs.type = ValueType::I32; rs.as_int = 999;
        tx.value_set(session.values(), "Demo.exe!g_RunSpeed", ValueType::I32, rs);
        // Force a failure: resolving a bogus module should throw during apply().
        ScalarValue bogus; bogus.type = ValueType::I32; bogus.as_int = 1;
        tx.value_set(session.values(), "NoSuchModule.dll!NoSuchSymbol", ValueType::I32, bogus);
        tx.commit();
    } catch (const EipError& e) {
        threw = (e.code() == ErrorCode::TransactionFailed);
    }
    CHECK(threw, "failing transaction raises TransactionFailed");
    ScalarValue afterFail = session.values().read("Demo.exe!g_RunSpeed", ValueType::I32);
    CHECK(afterFail.as_int == beforeFail.as_int, "RunSpeed unchanged after rolled-back transaction (no partial state)");

    std::printf("[6] hook install/remove (byte-level verification)\n");
    std::vector<u8> originalBytes = session.process().memory().read(fn->address, 16);
    HookRecord hook = session.hooks().install(fn->address, fn->address); // detour==target is harmless for this byte-level check
    CHECK(hook.active, "hook reports active after install");
    std::vector<u8> hookedBytes = session.process().memory().read(fn->address, 16);
    CHECK(std::memcmp(originalBytes.data(), hookedBytes.data(), 12) != 0, "function bytes changed after hook install");
    session.hooks().remove(hook);
    CHECK(!hook.active, "hook reports inactive after remove");
    std::vector<u8> restoredBytes = session.process().memory().read(fn->address, 16);
    CHECK(std::memcmp(originalBytes.data(), restoredBytes.data(), originalBytes.size()) == 0, "function bytes restored exactly after hook remove");

    std::printf("[7] feature install/uninstall (Export menu item)\n");
    std::size_t checkpoint = session.runtime().checkpoint();
    Feature& feature = session.features().create("Export");
    ScalarValue exportLabel; exportLabel.type = ValueType::CStringAscii; exportLabel.as_string = "Export";
    feature.add_value("Demo.exe!g_MenuItems+0x30", ValueType::CStringAscii, exportLabel, 16);
    ScalarValue four; four.type = ValueType::I32; four.as_int = 4;
    feature.add_value("Demo.exe!g_MenuCount", ValueType::I32, four);
    feature.install();
    CHECK(feature.installed(), "feature reports installed");
    ScalarValue mcAfter = session.values().read("Demo.exe!g_MenuCount", ValueType::I32);
    CHECK(mcAfter.as_int == 4, "g_MenuCount is 4 after feature install");
    ScalarValue item = session.values().read("Demo.exe!g_MenuItems+0x30", ValueType::CStringAscii, 16);
    CHECK(item.as_string == "Export", "g_MenuItems[3] == 'Export' after feature install");

    feature.uninstall();
    CHECK(!feature.installed(), "feature reports not installed after uninstall");

    std::printf("[8] runtime change tracking\n");
    auto diff = session.runtime().diff_since(checkpoint);
    CHECK(!diff.empty(), "runtime recorded changes for the feature install/uninstall");

    std::printf("ALL WINDOWS LIVE TESTS PASSED\n");
    return 0;
}
