"""eip.value - the Value namespace (program.value.read / program.value.set)."""
from __future__ import annotations

from ctypes import byref, c_int64, c_uint64

from . import _native
from .types import ValueType, infer_type, _INT_TYPES, _FLOAT_TYPES, _STRING_TYPES


def _scalar_to_python(scalar: "_native.Scalar", vtype: ValueType):
    if vtype in _INT_TYPES:
        return int(scalar.as_int)
    if vtype in _FLOAT_TYPES:
        return float(scalar.as_float)
    if vtype in _STRING_TYPES:
        if scalar.as_bytes is None:
            return b"" if vtype == ValueType.BYTES else ""
        raw = scalar.as_bytes[: scalar.as_bytes_len] if scalar.as_bytes_len else scalar.as_bytes
        if vtype == ValueType.BYTES:
            return bytes(raw)
        return raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
    raise TypeError(f"unhandled ValueType {vtype!r}")


def _python_to_scalar(value, vtype: ValueType) -> "_native.Scalar":
    scalar = _native.Scalar()
    scalar.type = int(vtype)
    if vtype in _INT_TYPES:
        scalar.as_int = int(value)
    elif vtype in _FLOAT_TYPES:
        scalar.as_float = float(value)
    elif vtype in _STRING_TYPES:
        if isinstance(value, str):
            data = value.encode("utf-8")
        else:
            data = bytes(value)
        scalar.as_bytes = data
        scalar.as_bytes_len = len(data)
        # keep the bytes object alive for the duration of the native call by
        # stashing it on the scalar instance (ctypes won't do this for us).
        scalar._keepalive = data
    else:
        raise TypeError(f"unhandled ValueType {vtype!r}")
    return scalar


class ValueNamespace:
    """Backs `program.value.read(...)` / `program.value.set(...)`."""

    def __init__(self, session):
        self._session = session

    def read(self, target: str, type: ValueType | None = None, capacity: int = 0):
        if type is None:
            raise TypeError("value.read requires an explicit type= (e.g. eip.types.ValueType.I32)")
        out = _native.Scalar()
        status = _native.calls.value_read(
            self._session._handle, _native.enc(target), int(type), capacity, byref(out)
        )
        _native.check(status)
        return _scalar_to_python(out, ValueType(type))

    def set(self, target: str, value, type: ValueType | None = None, capacity: int = 0) -> None:
        vtype = ValueType(type) if type is not None else infer_type(value)
        scalar = _python_to_scalar(value, vtype)
        status = _native.calls.value_set(
            self._session._handle, _native.enc(target), int(vtype), capacity, byref(scalar)
        )
        _native.check(status)

    def resolve(self, target: str) -> int:
        out = c_uint64()
        status = _native.calls.resolve(self._session._handle, _native.enc(target), byref(out))
        _native.check(status)
        return out.value
