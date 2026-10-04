#!/usr/bin/env python3
"""EIP example 1: change an existing value at runtime (spec section 2).

    original: Player.RunSpeed = 10
    EIP:      Player.RunSpeed = 20

Run Demo.exe on Windows first, then run this script on the same machine:

    examples\\demo_program\\Demo.exe &
    python examples\\change_value.py
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

import eip
from eip.types import ValueType


def main():
    app = eip.attach("Demo.exe")
    try:
        before = app.value.read("Demo.exe!g_RunSpeed", type=ValueType.I32)
        print(f"RunSpeed before: {before}")

        app.value.set(target="Demo.exe!g_RunSpeed", value=20, type=ValueType.I32)
        app.commit()

        after = app.value.read("Demo.exe!g_RunSpeed", type=ValueType.I32)
        print(f"RunSpeed after:  {after}")
        assert after == 20, "EIP value.set did not take effect"
        print("OK: Player.RunSpeed changed 10 -> 20 in the live process")
    finally:
        app.detach()


if __name__ == "__main__":
    main()
