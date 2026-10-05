"""Real tests of eip.patch.Patcher (persistent patch) end-to-end."""
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "python"))

import eip

DEMO = os.path.join(os.path.dirname(__file__), "..", "..", "examples", "demo_program", "Demo.exe")


class TestPersistentPatch(unittest.TestCase):
    def setUp(self):
        with eip.pe.parse(DEMO) as img:
            self.run_speed_rva = img.find_export("g_RunSpeed")
            self.menu_count_rva = img.find_export("g_MenuCount")
            self.menu_items_rva = img.find_export("g_MenuItems")

    def test_original_untouched_after_patch(self):
        out = "/tmp/test_patch_untouched.exe"
        p = eip.patch.Patcher(DEMO)
        p.add_value_change(self.run_speed_rva, struct.pack("<i", 42), "test")
        p.apply(out)
        p.close()

        with eip.pe.parse(DEMO) as original:
            val = struct.unpack("<i", original.read_rva(self.run_speed_rva, 4))[0]
            self.assertEqual(val, 10, "original file must be untouched")

    def test_patched_output_has_new_value(self):
        out = "/tmp/test_patch_value.exe"
        p = eip.patch.Patcher(DEMO)
        p.add_value_change(self.run_speed_rva, struct.pack("<i", 42), "RunSpeed->42")
        p.apply(out)
        p.close()

        with eip.pe.parse(out) as patched:
            val = struct.unpack("<i", patched.read_rva(self.run_speed_rva, 4))[0]
            self.assertEqual(val, 42)

    def test_menu_feature_injection(self):
        out = "/tmp/test_patch_menu.exe"
        p = eip.patch.Patcher(DEMO)
        p.add_value_change(self.menu_count_rva, struct.pack("<i", 4), "count->4")
        export_slot = b"Export" + b"\x00" * 10
        p.add_value_change(self.menu_items_rva + 3 * 16, export_slot, "item[3]=Export")
        p.apply(out)
        p.close()

        with eip.pe.parse(out) as patched:
            count = struct.unpack("<i", patched.read_rva(self.menu_count_rva, 4))[0]
            self.assertEqual(count, 4)
            item = patched.read_rva(self.menu_items_rva + 3 * 16, 16).split(b"\x00")[0].decode()
            self.assertEqual(item, "Export")

    def test_overlapping_changes_raise_patch_conflict(self):
        out = "/tmp/test_patch_conflict.exe"
        p = eip.patch.Patcher(DEMO)
        p.add_value_change(self.run_speed_rva, b"\x11\x11\x11\x11", "A")
        p.add_value_change(self.run_speed_rva + 2, b"\x22\x22", "B overlaps A")
        with self.assertRaises(eip.errors.PatchConflict):
            p.apply(out)
        p.close()

    def test_output_is_structurally_valid_pe(self):
        out = "/tmp/test_patch_structural.exe"
        p = eip.patch.Patcher(DEMO)
        p.add_value_change(self.run_speed_rva, struct.pack("<i", 1), "x")
        p.apply(out)
        p.close()

        with eip.pe.parse(out) as img:
            self.assertEqual(img.arch, "x64")
            exports = {e.name for e in img.exports()}
            self.assertIn("GetRunSpeed", exports)
            self.assertIn("PrintMenu", exports)


if __name__ == "__main__":
    unittest.main()
