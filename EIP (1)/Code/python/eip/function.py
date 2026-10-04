"""eip.function - function discovery, replace and add (program.function.*)."""
from __future__ import annotations

from ctypes import byref, c_uint32, c_uint64

from . import _native


class FunctionNamespace:
    def __init__(self, session):
        self._session = session

    def find(self, module: str, name: str | None = None, pattern: str | None = None) -> int:
        """find(module, name=...) does an export lookup; find(module, pattern=...)
        does a byte-pattern scan ("48 89 5C 24 ?? 48 89 74 24")."""
        out = c_uint64()
        if name is not None:
            status = _native.calls.function_find_export(
                self._session._handle, _native.enc(module), _native.enc(name), byref(out)
            )
        elif pattern is not None:
            status = _native.calls.function_find_pattern(
                self._session._handle, _native.enc(module), _native.enc(pattern), byref(out)
            )
        else:
            raise TypeError("function.find requires name= or pattern=")
        _native.check(status)
        return out.value

    def add(self, machine_code: bytes) -> int:
        """Allocates RWX memory in the target and writes `machine_code` into
        it; returns the address of the newly added function."""
        buf = _native.bytes_to_array(machine_code)
        out = c_uint64()
        status = _native.calls.function_add(self._session._handle, buf, len(machine_code), byref(out))
        _native.check(status)
        return out.value

    def replace(self, target: int, new_impl: int) -> bytes:
        """Overwrites `target` in place with a jump to `new_impl`. Returns the
        original bytes that were overwritten (pass to `restore` to undo)."""
        buf = (_native.c_uint8 * 32)()
        saved_len = c_uint32()
        status = _native.calls.function_replace(
            self._session._handle, target, new_impl, buf, 32, byref(saved_len)
        )
        _native.check(status)
        return bytes(buf[: saved_len.value])

    def restore(self, target: int, original_bytes: bytes) -> None:
        buf = _native.bytes_to_array(original_bytes)
        status = _native.calls.function_restore(self._session._handle, target, buf, len(original_bytes))
        _native.check(status)
