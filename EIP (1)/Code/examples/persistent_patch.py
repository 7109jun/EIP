#!/usr/bin/env python3
"""EIP example 4: Persistent Patch (spec section 5) - write a modified copy
of Demo.exe to disk without touching the original or requiring a running
process at all. Applies both scenarios statically:

    Demo.exe  ->  Demo.modified.exe
      g_RunSpeed: 10 -> 20
      menu:       Open/Save/Exit -> Open/Save/Export/Exit

This runs on ANY platform (Linux included) because it only parses and
rewrites PE bytes on disk - no attach, no Windows APIs.
"""
import struct
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

import eip

DEMO_DIR = os.path.join(os.path.dirname(__file__), "demo_program")


def main():
    input_path = os.path.join(DEMO_DIR, "Demo.exe")
    output_path = os.path.join(DEMO_DIR, "Demo.modified.exe")

    with eip.pe.parse(input_path) as img:
        run_speed_rva = img.find_export("g_RunSpeed")
        menu_count_rva = img.find_export("g_MenuCount")
        menu_items_rva = img.find_export("g_MenuItems")

    patcher = eip.patch.Patcher(input_path)
    patcher.add_value_change(run_speed_rva, struct.pack("<i", 20), "RunSpeed 10 -> 20")
    patcher.add_value_change(menu_count_rva, struct.pack("<i", 4), "menu count 3 -> 4")
    export_slot = ("Export" + "\x00" * 16).encode("ascii")[:16]
    patcher.add_value_change(menu_items_rva + 3 * 16, export_slot, "menu item[3] = 'Export'")
    patcher.apply(output_path)
    patcher.close()

    print(f"wrote {output_path}")

    with eip.pe.parse(output_path) as verify:
        rs = struct.unpack("<i", verify.read_rva(run_speed_rva, 4))[0]
        mc = struct.unpack("<i", verify.read_rva(menu_count_rva, 4))[0]
        item3 = verify.read_rva(menu_items_rva + 3 * 16, 16).split(b"\x00")[0].decode()
        print(f"verified: g_RunSpeed={rs} g_MenuCount={mc} g_MenuItems[3]={item3!r}")
        assert rs == 20 and mc == 4 and item3 == "Export"
        print("OK: persistent patch applied and verified, original Demo.exe untouched")


if __name__ == "__main__":
    main()
