"""Real tests of eip.pe against actual mingw-built PE files. Run with:

    EIP_CORE_PATH=build/libeip_core.so python3 -m pytest tests/python -v

(or plain `python3 tests/python/test_pe.py` to run without pytest).
"""
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "python"))

import eip
from eip.types import ValueType

DEMO = os.path.join(os.path.dirname(__file__), "..", "..", "examples", "demo_program", "Demo.exe")


class TestPeEngine(unittest.TestCase):
    def test_parse_and_arch(self):
        with eip.pe.parse(DEMO) as img:
            self.assertEqual(img.arch, "x64")
            self.assertTrue(img.is_pe32plus)
            self.assertGreater(img.size_of_image, 0)

    def test_sections_present(self):
        with eip.pe.parse(DEMO) as img:
            names = {s.name for s in img.sections()}
            self.assertIn(".text", names)
            self.assertIn(".data", names)

    def test_exports_present(self):
        with eip.pe.parse(DEMO) as img:
            names = {e.name for e in img.exports()}
            self.assertIn("g_RunSpeed", names)
            self.assertIn("GetRunSpeed", names)
            self.assertIn("g_MenuItems", names)
            self.assertIn("g_MenuCount", names)

    def test_run_speed_initial_value(self):
        with eip.pe.parse(DEMO) as img:
            rva = img.find_export("g_RunSpeed")
            val = struct.unpack("<i", img.read_rva(rva, 4))[0]
            self.assertEqual(val, 10)

    def test_menu_items_layout(self):
        with eip.pe.parse(DEMO) as img:
            rva = img.find_export("g_MenuItems")
            raw = img.read_rva(rva, 8 * 16)
            items = [raw[i * 16:(i + 1) * 16].split(b"\x00")[0].decode() for i in range(8)]
            self.assertEqual(items[:3], ["Open", "Save", "Exit"])
            self.assertEqual(items[3], "")

    def test_in_memory_patch_and_reparse_roundtrip(self):
        with eip.pe.parse(DEMO) as img:
            rva = img.find_export("g_RunSpeed")
            img.patch_bytes(rva, struct.pack("<i", 999))
            val = struct.unpack("<i", img.read_rva(rva, 4))[0]
            self.assertEqual(val, 999)
            out = "/tmp/test_pe_roundtrip.exe"
            img.save(out)

        with eip.pe.parse(out) as reparsed:
            rva2 = reparsed.find_export("g_RunSpeed")
            val2 = struct.unpack("<i", reparsed.read_rva(rva2, 4))[0]
            self.assertEqual(val2, 999)

    def test_add_section(self):
        with eip.pe.parse(DEMO) as img:
            before = len(img.sections())
            rva = img.add_section(".eiptest", b"\xC3", 0x60000020)
            self.assertNotEqual(rva, 0)
            self.assertEqual(len(img.sections()), before + 1)
            self.assertEqual(img.read_rva(rva, 1), b"\xC3")

    def test_find_export_missing_raises(self):
        with eip.pe.parse(DEMO) as img:
            with self.assertRaises(eip.errors.FunctionNotFound):
                img.find_export("ThisDoesNotExist")

    def test_parse_missing_file_raises_io_error(self):
        with self.assertRaises(eip.errors.IoError):
            eip.pe.parse("/no/such/file.exe")


if __name__ == "__main__":
    unittest.main()
