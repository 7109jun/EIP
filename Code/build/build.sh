#!/usr/bin/env bash
# Builds the entire EIP native core:
#   - build/eip_core.dll    (Windows, full functionality, via mingw-w64 cross-compile
#                             or MSVC/clang-cl natively on a Windows host)
#   - build/libeip_core.so  (Linux, portable PE/patch subset only - Process/Memory/
#                             Hook/Event compile but every call raises
#                             NotImplementedOnPlatform; useful for running
#                             tests/python and tests/native's portable tests
#                             without a Windows host)
#   - examples/demo_program/Demo.exe (the test target binary)
#
# On a real Windows host, replace the mingw invocation with MSVC's cl.exe
# (see the WINDOWS NATIVE BUILD comment below) - the source is portable
# standard C++17 either way.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
SRC="core/src/common.cpp core/src/pe.cpp core/src/memory.cpp core/src/process.cpp \
     core/src/x86len.cpp core/src/target.cpp core/src/value.cpp core/src/function.cpp \
     core/src/hook.cpp core/src/event.cpp core/src/transaction.cpp core/src/feature.cpp \
     core/src/runtime.cpp core/src/patch.cpp core/src/capi.cpp"

mkdir -p build

echo "=== [1/3] Windows DLL (eip_core.dll) via mingw-w64 cross-compile ==="
if command -v x86_64-w64-mingw32-g++ >/dev/null 2>&1; then
    x86_64-w64-mingw32-g++ -std=c++17 -O2 -Wall -Wextra -Icore/include \
        $SRC -shared -o build/eip_core.dll \
        -Wl,--out-implib,build/libeip_core.a
    echo "built build/eip_core.dll"
else
    echo "x86_64-w64-mingw32-g++ not found; skipping Windows DLL build." >&2
    echo "Install with: apt install g++-mingw-w64-x86-64" >&2
fi

echo "=== [2/3] Linux shared library (libeip_core.so, portable subset) ==="
g++ -std=c++17 -O2 -Wall -Wextra -Icore/include -fPIC \
    $SRC -shared -o build/libeip_core.so
echo "built build/libeip_core.so"

echo "=== [3/3] Demo.exe (test target) ==="
if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    bash examples/demo_program/build.sh
else
    echo "x86_64-w64-mingw32-gcc not found; skipping Demo.exe build." >&2
fi

echo "=== build complete ==="
ls -la build/

cat <<'EOF'

WINDOWS NATIVE BUILD (on an actual Windows machine, no mingw needed):
    cl /std:c++17 /EHsc /LD /Icore\include core\src\*.cpp /Fe:build\eip_core.dll
    cl /std:c++17 /EHsc /O2 examples\demo_program\Demo.c /Fe:examples\demo_program\Demo.exe
EOF
