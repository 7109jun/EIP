"""eip.patch - persistent patch builder: writes a modified copy of a PE file
without touching the original (spec section 5, "Persistent Patch")."""
from __future__ import annotations

from ctypes import byref, c_void_p

from . import _native


class Patcher:
    def __init__(self, input_path: str):
        handle = c_void_p()
        status = _native.calls.patcher_create(_native.enc(input_path), byref(handle))
        _native.check(status)
        self._handle = handle
        self.input_path = input_path

    def add_value_change(self, rva: int, new_bytes: bytes, description: str = "") -> "Patcher":
        buf = _native.bytes_to_array(new_bytes)
        status = _native.calls.patcher_add_value_change(self._handle, rva, buf, len(new_bytes), _native.enc(description))
        _native.check(status)
        return self

    def add_code_injection(self, section_name: str, code: bytes, characteristics: int, description: str = "") -> "Patcher":
        buf = _native.bytes_to_array(code)
        status = _native.calls.patcher_add_code_injection(
            self._handle, _native.enc(section_name), buf, len(code), characteristics, _native.enc(description)
        )
        _native.check(status)
        return self

    def apply(self, output_path: str) -> str:
        status = _native.calls.patcher_apply(self._handle, _native.enc(output_path))
        _native.check(status)
        return output_path

    def close(self) -> None:
        if self._handle:
            _native.calls.patcher_close(self._handle)
            self._handle = None

    def __enter__(self) -> "Patcher":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
