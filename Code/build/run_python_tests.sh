#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    bash examples/demo_program/build.sh >/dev/null
fi

if [ ! -f build/libeip_core.so ] && [ ! -f build/eip_core.dll ]; then
    echo "native core not built yet; running build/build.sh first..." >&2
    bash build/build.sh
fi

export EIP_CORE_PATH="${EIP_CORE_PATH:-$(pwd)/build/libeip_core.so}"
[ -f "$EIP_CORE_PATH" ] || EIP_CORE_PATH="$(pwd)/build/eip_core.dll"
export EIP_CORE_PATH

python3 -m unittest discover -s tests/python -v
