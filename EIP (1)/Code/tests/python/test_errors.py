"""Real tests of the Python exception mapping (eip.errors) and the
platform-fallback behavior for Windows-only calls when run on a non-Windows
host - both exercised through the actual native library, not mocked."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "python"))

import eip


class TestErrorMapping(unittest.TestCase):
    def test_io_error_has_detail(self):
        try:
            eip.pe.parse("/definitely/not/a/real/file.exe")
            self.fail("expected IoError")
        except eip.errors.IoError as e:
            self.assertIn("IoError", str(e))
            self.assertEqual(e.code, 110)

    def test_function_not_found(self):
        with eip.pe.parse(
            os.path.join(os.path.dirname(__file__), "..", "..", "examples", "demo_program", "Demo.exe")
        ) as img:
            with self.assertRaises(eip.errors.FunctionNotFound) as ctx:
                img.find_export("TotallyMissingSymbol")
            self.assertEqual(ctx.exception.code, 40)

    def test_unsupported_pe_on_non_pe_file(self):
        # A plain text file is neither missing nor a PE - should fail PE
        # parsing specifically, not be misreported as IoError.
        path = "/tmp/test_not_a_pe.txt"
        with open(path, "wb") as f:
            f.write(b"this is not a PE file, just some bytes 0123456789")
        try:
            with self.assertRaises(eip.errors.PEParseFailed):
                eip.pe.parse(path)
        finally:
            os.remove(path)

    def test_attach_on_linux_raises_not_implemented(self):
        if sys.platform.startswith("win"):
            self.skipTest("this checks the Linux/non-Windows fallback path")
        with self.assertRaises(eip.errors.NotImplementedOnPlatform):
            eip.attach("Demo.exe")

    def test_process_list_on_linux_raises_not_implemented(self):
        if sys.platform.startswith("win"):
            self.skipTest("this checks the Linux/non-Windows fallback path")
        with self.assertRaises(eip.errors.NotImplementedOnPlatform):
            eip.process.list()


if __name__ == "__main__":
    unittest.main()
