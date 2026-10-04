#!/usr/bin/env python3
"""EIP example 2: add a brand new feature that never shipped (spec section 2/4).

    original menu: Open, Save, Exit
    EIP:           Open, Save, Export, Exit

Demo.exe's menu is backed by a fixed-capacity array (g_MenuItems[8][16]) and
a count (g_MenuCount). This Feature writes "Export" into the next unused
slot and bumps the count - a real new menu entry, installed into a running
process, that the original program's source never contained.

Run on Windows:
    examples\\demo_program\\Demo.exe &
    python examples\\add_export_feature.py
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

import eip
from eip.types import ValueType


def main():
    app = eip.attach("Demo.exe")
    try:
        count_before = app.value.read("Demo.exe!g_MenuCount", type=ValueType.I32)
        print(f"menu item count before: {count_before}")

        feature = app.feature.create("Export")
        # Slot `count_before` (index 3, the first unused 16-byte row) gets
        # the new label; g_MenuCount is bumped so PrintMenu's loop reaches it.
        slot_offset = count_before * 16
        feature.add_value(
            f"Demo.exe!g_MenuItems+0x{slot_offset:x}",
            "Export",
            type=ValueType.CSTR_ASCII,
            capacity=16,
        )
        feature.add_value("Demo.exe!g_MenuCount", count_before + 1, type=ValueType.I32)
        feature.add_command("export")
        feature.install()

        count_after = app.value.read("Demo.exe!g_MenuCount", type=ValueType.I32)
        new_item = app.value.read("Demo.exe!g_MenuItems+0x30", type=ValueType.CSTR_ASCII, capacity=16)
        print(f"menu item count after:  {count_after}")
        print(f"new menu item:          {new_item!r}")
        assert count_after == count_before + 1
        assert new_item == "Export"
        print("OK: 'Export' now exists in Demo.exe's menu - it was never in the original binary")

        feature.uninstall()
        print("feature uninstalled; menu restored to Open/Save/Exit")
    finally:
        app.detach()


if __name__ == "__main__":
    main()
