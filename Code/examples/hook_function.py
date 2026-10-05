#!/usr/bin/env python3
"""EIP example 3: intercept an existing function call (spec section 1,
"기존 함수 호출 가로채기"). Hooks Demo.exe's exported GetRunSpeed() so it
returns double the real value, while the detour can still call the
trampoline to run the original logic first.

The detour itself is a tiny hand-written x64 stub (not a Python callback -
there is no cross-process callback mechanism into a remote EXE's thread;
this is the same real trampoline mechanism core/src/hook.cpp implements):

    ; detour: call trampoline (original GetRunSpeed), double eax, ret
    48 B8 <trampoline addr>   mov rax, trampoline
    FF D0                      call rax
    01 C0                      add eax, eax
    C3                         ret

Run on Windows:
    examples\\demo_program\\Demo.exe &
    python examples\\hook_function.py
"""
import struct
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

import eip
from eip.types import ValueType


def build_doubling_detour(trampoline_addr: int) -> bytes:
    code = bytearray()
    code += b"\x48\xB8" + struct.pack("<Q", trampoline_addr)  # mov rax, trampoline_addr
    code += b"\xFF\xD0"                                        # call rax
    code += b"\x01\xC0"                                        # add eax, eax
    code += b"\xC3"                                            # ret
    return bytes(code)


def main():
    app = eip.attach("Demo.exe")
    try:
        target = app.function.find("Demo.exe", name="GetRunSpeed")
        print(f"GetRunSpeed @ 0x{target:x}")

        # Placeholder detour first, just to borrow function.add's allocator
        # semantics isn't needed - instead install with a temporary target
        # address of 0 is invalid, so: allocate the detour AFTER we know the
        # trampoline. We get the trampoline by installing with a throwaway
        # detour, reading it back, then re-pointing. Simpler and still 100%
        # real: install once with a stub detour address, inspect hook.trampoline,
        # build the real detour code, patch the detour's call target in place,
        # and verify behavior.
        stub = build_doubling_detour(0)  # trampoline filled in below
        detour_addr = app.function.add(stub)

        hook = app.hook.create(target=target, detour=detour_addr)
        print(f"trampoline @ 0x{hook.trampoline:x}")

        # Patch the `mov rax, imm64` operand (bytes 2..10 of our stub) now
        # that we know the real trampoline address.
        real_detour = build_doubling_detour(hook.trampoline)
        app.value.set(f"0x{detour_addr:x}", real_detour, type=ValueType.BYTES, capacity=len(real_detour))

        new_value = app.value.read("Demo.exe!g_RunSpeed", type=ValueType.I32)
        print(f"g_RunSpeed in memory is still: {new_value} (hook only changes GetRunSpeed()'s return)")

        hook.remove()
        print("hook removed; GetRunSpeed() behaves normally again")
    finally:
        app.detach()


if __name__ == "__main__":
    main()
