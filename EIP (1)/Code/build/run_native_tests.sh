#!/usr/bin/env bash
# Builds and runs every native test that can actually execute on this host.
#
# Portable tests (PE engine, persistent patch, error codes, platform
# fallback, x86 instruction-length decoder) run for real right here, on any
# OS, because they touch no Windows API.
#
# test_windows_live is cross-compiled (via mingw-w64) to prove it builds
# against the real headers and links against the real native core, but it
# is NOT executed here - it requires an actual Windows host with
# examples/demo_program/Demo.exe running. See tests/README.md.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PORTABLE_SRC="core/src/common.cpp core/src/pe.cpp core/src/patch.cpp"
FULL_SRC="core/src/common.cpp core/src/pe.cpp core/src/memory.cpp core/src/process.cpp \
          core/src/x86len.cpp core/src/target.cpp core/src/value.cpp core/src/function.cpp \
          core/src/hook.cpp core/src/event.cpp core/src/transaction.cpp core/src/feature.cpp \
          core/src/runtime.cpp core/src/patch.cpp"

echo "building Demo.exe (needed as the PE fixture for several tests)..."
if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    bash examples/demo_program/build.sh >/dev/null
fi
DEMO="examples/demo_program/Demo.exe"

echo "building the 32-bit PE32 fixture (tests PE32 vs PE32+ handling)..."
PE32_FIXTURE="$TMP/pe32_fixture.exe"
if command -v i686-w64-mingw32-gcc >/dev/null 2>&1; then
    i686-w64-mingw32-gcc -O0 -o "$PE32_FIXTURE" tests/native/fixtures/pe32_fixture.c
fi

pass=0
fail=0

run_test() {
    local name="$1"; shift
    echo "--- $name ---"
    if "$@"; then
        pass=$((pass+1))
    else
        echo "*** $name FAILED ***" >&2
        fail=$((fail+1))
    fi
}

echo "=== compiling portable native tests ==="
g++ -std=c++17 -Icore/include -o "$TMP/test_pe_smoke" $PORTABLE_SRC tests/native/test_pe_smoke.cpp
g++ -std=c++17 -Icore/include -o "$TMP/test_pe32" core/src/common.cpp core/src/pe.cpp tests/native/test_pe32.cpp
g++ -std=c++17 -Icore/include -o "$TMP/test_patch_and_errors" $PORTABLE_SRC tests/native/test_patch_and_errors.cpp
g++ -std=c++17 -Icore/include -o "$TMP/test_platform_fallback" core/src/common.cpp core/src/pe.cpp core/src/memory.cpp core/src/process.cpp tests/native/test_platform_fallback.cpp
g++ -std=c++17 -Icore/include -o "$TMP/test_x86len" core/src/common.cpp core/src/x86len.cpp tests/native/test_x86len_ground_truth.cpp

cp "$DEMO" "$TMP/Demo.exe" 2>/dev/null || true
DEMO_COPY="$TMP/Demo.exe"

run_test "PE smoke (export/patch/section/save round trip)" "$TMP/test_pe_smoke" "$DEMO_COPY"
if [ -f "$PE32_FIXTURE" ]; then
    run_test "PE32 (32-bit) parsing" "$TMP/test_pe32" "$PE32_FIXTURE"
else
    echo "i686-w64-mingw32-gcc not available; skipping PE32 test" >&2
fi
run_test "Persistent patch + error codes"                   "$TMP/test_patch_and_errors" "$DEMO_COPY"
run_test "Platform fallback (NotImplementedOnPlatform)"     "$TMP/test_platform_fallback"
run_test "x86 instruction-length decoder (vs. objdump)"     "$TMP/test_x86len"

echo "=== cross-compiling Windows-only tests (build check; execution needs real Windows) ==="
if command -v x86_64-w64-mingw32-g++ >/dev/null 2>&1; then
    if x86_64-w64-mingw32-g++ -std=c++17 -Icore/include $FULL_SRC tests/native/test_windows_live.cpp -o "$TMP/test_windows_live.exe" 2>"$TMP/winlive.log"; then
        echo "ok: test_windows_live.exe cross-compiled successfully (run it on Windows against a live Demo.exe)"
        pass=$((pass+1))
    else
        echo "*** test_windows_live FAILED TO COMPILE ***" >&2
        cat "$TMP/winlive.log" >&2
        fail=$((fail+1))
    fi
else
    echo "mingw-w64 not available; skipping Windows cross-compile check" >&2
fi

echo ""
echo "=== native test summary: $pass passed, $fail failed ==="
exit $fail
