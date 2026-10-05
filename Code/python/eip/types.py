"""Value type enum exposed to Python, mirroring eip::ValueType (common.h)."""
from __future__ import annotations

from enum import IntEnum


class ValueType(IntEnum):
    I8 = 0
    U8 = 1
    I16 = 2
    U16 = 3
    I32 = 4
    U32 = 5
    I64 = 6
    U64 = 7
    F32 = 8
    F64 = 9
    PTR32 = 10
    PTR64 = 11
    BOOL8 = 12
    CSTR_ASCII = 13
    CSTR_UTF16 = 14
    BYTES = 15


_INT_TYPES = {
    ValueType.I8, ValueType.U8, ValueType.I16, ValueType.U16,
    ValueType.I32, ValueType.U32, ValueType.I64, ValueType.U64,
    ValueType.PTR32, ValueType.PTR64, ValueType.BOOL8,
}
_FLOAT_TYPES = {ValueType.F32, ValueType.F64}
_STRING_TYPES = {ValueType.CSTR_ASCII, ValueType.CSTR_UTF16, ValueType.BYTES}


def infer_type(value) -> ValueType:
    """Best-effort ValueType inference for callers that don't pass `type=`
    explicitly, matching the ergonomic `value.set(target=..., value=20)` form
    from the spec. Ambiguous cases (which integer width?) default to I32,
    the common case for gameplay-style values like RunSpeed.
    """
    if isinstance(value, bool):
        return ValueType.BOOL8
    if isinstance(value, int):
        return ValueType.I32
    if isinstance(value, float):
        return ValueType.F64
    if isinstance(value, (bytes, bytearray)):
        return ValueType.BYTES
    if isinstance(value, str):
        return ValueType.CSTR_ASCII
    raise TypeError(f"cannot infer ValueType for Python value of type {type(value)!r}")
