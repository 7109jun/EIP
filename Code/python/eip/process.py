"""eip.process / eip.attach - process enumeration and the live Process
("program") object that every other namespace hangs off of.
"""
from __future__ import annotations

from ctypes import byref, c_uint32, c_void_p

from . import _native
from .value import ValueNamespace
from .function import FunctionNamespace
from .hook import HookNamespace
from .event import EventNamespace
from .feature import FeatureNamespace
from .transaction import TransactionNamespace
from .runtime import RuntimeNamespace


class ProcessSummary:
    def __init__(self, raw: "_native.ProcessSummary"):
        self.pid = raw.pid
        self.name = raw.name.decode("utf-8", "replace")
        self.path = raw.path.decode("utf-8", "replace")

    def __repr__(self) -> str:
        return f"<ProcessSummary pid={self.pid} name={self.name!r}>"


class Module:
    def __init__(self, raw: "_native.ModuleInfo"):
        self.name = raw.name.decode("utf-8", "replace")
        self.path = raw.path.decode("utf-8", "replace")
        self.base = raw.base
        self.size = raw.size

    def __repr__(self) -> str:
        return f"<Module {self.name!r} base=0x{self.base:x} size=0x{self.size:x}>"


def list() -> list[ProcessSummary]:
    buf = (_native.ProcessSummary * 1024)()
    count = c_uint32()
    status = _native.calls.process_list(buf, 1024, byref(count))
    _native.check(status)
    return [ProcessSummary(buf[i]) for i in range(count.value)]


def find(name_substr: str) -> list[ProcessSummary]:
    buf = (_native.ProcessSummary * 256)()
    count = c_uint32()
    status = _native.calls.process_find(_native.enc(name_substr), buf, 256, byref(count))
    _native.check(status)
    return [ProcessSummary(buf[i]) for i in range(count.value)]


class Process:
    """The live attached program - what `eip.attach(...)` returns.

    Exposes every namespace from the spec: .value, .function, .hook, .event,
    .feature, .transaction, .runtime, plus .modules()/.detach().
    """

    def __init__(self, handle):
        self._handle = handle
        self.value = ValueNamespace(self)
        self.function = FunctionNamespace(self)
        self.hook = HookNamespace(self)
        self.event = EventNamespace(self)
        self.feature = FeatureNamespace(self)
        self.transaction = TransactionNamespace(self)
        self.runtime = RuntimeNamespace(self)
        self._detached = False

    @property
    def pid(self) -> int:
        return _native.calls.session_pid(self._handle)

    @property
    def arch(self) -> str:
        a = _native.calls.session_arch(self._handle)
        return {1: "x86", 2: "x64"}.get(a, "unknown")

    def modules(self) -> list[Module]:
        buf = (_native.ModuleInfo * 512)()
        count = c_uint32()
        status = _native.calls.modules(self._handle, buf, 512, byref(count))
        _native.check(status)
        return [Module(buf[i]) for i in range(count.value)]

    def module(self, name: str) -> Module | None:
        for m in self.modules():
            if m.name.lower() == name.lower():
                return m
        return None

    def commit(self) -> None:
        """Compatibility no-op: `value.set` / `function.replace` / etc. in
        the direct (non-transaction) API below apply immediately, matching
        the spec's `app.value.set(...); app.commit()` example. For atomic,
        rollback-capable batches, use `program.transaction.begin()` or
        `program.feature.create(...)` instead - both are backed by a real
        native Transaction (see transaction.py / feature.py)."""
        return None

    def detach(self) -> None:
        if self._detached:
            return
        status = _native.calls.detach(self._handle)
        self._detached = True
        _native.check(status)

    def __enter__(self) -> "Process":
        return self

    def __exit__(self, *exc) -> None:
        self.detach()

    def __del__(self):
        try:
            self.detach()
        except Exception:
            pass


def attach(target) -> Process:
    """eip.attach("A.exe") or eip.attach(pid)."""
    handle = c_void_p()
    if isinstance(target, int):
        status = _native.calls.attach_pid(target, byref(handle))
    else:
        status = _native.calls.attach_name(_native.enc(str(target)), byref(handle))
    _native.check(status)
    return Process(handle)


def detach(process: Process) -> None:
    process.detach()
