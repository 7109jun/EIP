"""eip.runtime - change state tracking (program.runtime.*).

Spec section 10: every applied change is tracked as
Original/Modified/Added/Removed/Hooked/Restored, with an API to diff
before/after states.
"""
from __future__ import annotations

from ctypes import byref, c_uint32
from enum import IntEnum

from . import _native


class ChangeKind(IntEnum):
    VALUE_SET = 0
    MEMORY_PATCH = 1
    FUNCTION_REPLACE = 2
    FUNCTION_ADD = 3
    HOOK_INSTALL = 4
    FEATURE_INSTALL = 5


class ChangeState(IntEnum):
    ORIGINAL = 0
    MODIFIED = 1
    ADDED = 2
    REMOVED = 3
    HOOKED = 4
    RESTORED = 5


class Change:
    def __init__(self, sequence: int, kind: ChangeKind, state: ChangeState, description: str, address: int):
        self.sequence = sequence
        self.kind = ChangeKind(kind)
        self.state = ChangeState(state)
        self.description = description
        self.address = address

    def __repr__(self) -> str:
        return f"<Change #{self.sequence} {self.state.name} {self.kind.name} {self.description!r} @0x{self.address:x}>"


def _unpack(records, count: int):
    out = []
    for i in range(count):
        r = records[i]
        out.append(Change(r.sequence, r.kind, r.state, r.description.decode("utf-8", "replace"), r.address))
    return out


class RuntimeNamespace:
    """Backs `program.runtime.*`."""

    def __init__(self, session):
        self._session = session

    def changes(self, max_count: int = 4096):
        buf = (_native.ChangeRecord * max_count)()
        count = c_uint32()
        status = _native.calls.runtime_changes(self._session._handle, buf, max_count, byref(count))
        _native.check(status)
        return _unpack(buf, count.value)

    def checkpoint(self) -> int:
        return _native.calls.runtime_checkpoint(self._session._handle)

    def diff_since(self, checkpoint: int, max_count: int = 4096):
        buf = (_native.ChangeRecord * max_count)()
        count = c_uint32()
        status = _native.calls.runtime_diff_since(self._session._handle, checkpoint, buf, max_count, byref(count))
        _native.check(status)
        return _unpack(buf, count.value)
