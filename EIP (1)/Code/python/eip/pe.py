"""eip.pe - portable PE file inspection (works without an attached process,
and on any host OS, since it only parses bytes - see core/src/pe.cpp)."""
from __future__ import annotations

from ctypes import byref, c_uint32, c_void_p

from . import _native


class PeSection:
    def __init__(self, raw: "_native.PeSection"):
        self.name = raw.name.decode("utf-8", "replace").rstrip("\x00")
        self.virtual_address = raw.virtual_address
        self.virtual_size = raw.virtual_size
        self.raw_size = raw.raw_size
        self.raw_offset = raw.raw_offset
        self.characteristics = raw.characteristics

    def __repr__(self) -> str:
        return f"<PeSection {self.name!r} va=0x{self.virtual_address:x} size=0x{self.virtual_size:x}>"


class PeExport:
    def __init__(self, raw: "_native.PeExport"):
        self.name = raw.name.decode("utf-8", "replace")
        self.ordinal = raw.ordinal
        self.rva = raw.rva
        self.is_forwarder = bool(raw.is_forwarder)

    def __repr__(self) -> str:
        return f"<PeExport {self.name!r} rva=0x{self.rva:x} ordinal={self.ordinal}>"


class PEImage:
    """A parsed PE file. Use `with PEImage.open(path) as img:` or call
    `.close()` explicitly."""

    def __init__(self, handle):
        self._handle = handle

    @classmethod
    def open(cls, path: str) -> "PEImage":
        handle = c_void_p()
        status = _native.calls.pe_parse_file(_native.enc(path), byref(handle))
        _native.check(status)
        return cls(handle)

    def close(self) -> None:
        if self._handle:
            _native.calls.pe_close(self._handle)
            self._handle = None

    def __enter__(self) -> "PEImage":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    @property
    def arch(self) -> str:
        a = _native.calls.pe_arch(self._handle)
        return {1: "x86", 2: "x64"}.get(a, "unknown")

    @property
    def is_pe32plus(self) -> bool:
        return bool(_native.calls.pe_is_pe32plus(self._handle))

    @property
    def image_base(self) -> int:
        return _native.calls.pe_image_base(self._handle)

    @property
    def size_of_image(self) -> int:
        return _native.calls.pe_size_of_image(self._handle)

    @property
    def entry_point_rva(self) -> int:
        return _native.calls.pe_entry_point_rva(self._handle)

    def sections(self):
        buf = (_native.PeSection * 128)()
        count = c_uint32()
        status = _native.calls.pe_sections(self._handle, buf, 128, byref(count))
        _native.check(status)
        return [PeSection(buf[i]) for i in range(count.value)]

    def exports(self):
        buf = (_native.PeExport * 4096)()
        count = c_uint32()
        status = _native.calls.pe_exports(self._handle, buf, 4096, byref(count))
        _native.check(status)
        return [PeExport(buf[i]) for i in range(count.value)]

    def find_export(self, name: str) -> int:
        out = _native.eip_rva()
        status = _native.calls.pe_find_export(self._handle, _native.enc(name), byref(out))
        _native.check(status)
        return out.value

    def read_rva(self, rva: int, size: int) -> bytes:
        buf = (_native.c_uint8 * size)()
        status = _native.calls.pe_read_rva(self._handle, rva, buf, size)
        _native.check(status)
        return bytes(buf)

    def patch_bytes(self, rva: int, data: bytes) -> None:
        buf = _native.bytes_to_array(data)
        status = _native.calls.pe_patch_bytes(self._handle, rva, buf, len(data))
        _native.check(status)

    def add_section(self, name: str, data: bytes, characteristics: int) -> int:
        buf = _native.bytes_to_array(data)
        out = _native.eip_rva()
        status = _native.calls.pe_add_section(self._handle, _native.enc(name), buf, len(data), characteristics, byref(out))
        _native.check(status)
        return out.value

    def save(self, path: str) -> None:
        status = _native.calls.pe_save(self._handle, _native.enc(path))
        _native.check(status)


def parse(path: str) -> PEImage:
    return PEImage.open(path)
