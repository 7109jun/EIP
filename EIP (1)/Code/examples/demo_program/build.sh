#!/usr/bin/env bash
# Builds Demo.exe with mingw-w64 (works on Linux/macOS/Windows+MSYS2 alike).
set -euo pipefail
cd "$(dirname "$0")"
CC="${EIP_MINGW_CC:-x86_64-w64-mingw32-gcc}"
"$CC" -O0 -g -o Demo.exe Demo.c
echo "built: $(pwd)/Demo.exe"
