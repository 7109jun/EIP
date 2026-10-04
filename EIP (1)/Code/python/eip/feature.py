"""eip.feature - the top-level "install a new capability" unit.

    feature = program.feature.create("Export")
    feature.add_function(target_addr, machine_code)
    feature.add_command("export")
    feature.install()
    ...
    feature.uninstall()

Backed by the native Feature (core/src/feature.cpp), which applies every
queued change as one atomic Transaction at install() time.
"""
from __future__ import annotations

from ctypes import byref, c_void_p

from . import _native
from .types import ValueType, infer_type
from .value import _python_to_scalar


class Feature:
    def __init__(self, session, name: str, handle):
        self._session = session
        self.name = name
        self._handle = handle

    def add_value(self, target: str, value, type: ValueType | None = None, capacity: int = 0) -> "Feature":
        vtype = ValueType(type) if type is not None else infer_type(value)
        scalar = _python_to_scalar(value, vtype)
        status = _native.calls.feature_add_value(self._handle, _native.enc(target), int(vtype), capacity, byref(scalar))
        _native.check(status)
        return self

    def add_function(self, target: int, machine_code: bytes) -> "Feature":
        buf = _native.bytes_to_array(machine_code)
        status = _native.calls.feature_add_function(self._handle, target, buf, len(machine_code))
        _native.check(status)
        return self

    def add_hook(self, target: int, detour: int) -> "Feature":
        status = _native.calls.feature_add_hook(self._handle, target, detour)
        _native.check(status)
        return self

    def add_event(self, name: str, target: int, event_id: int) -> "Feature":
        status = _native.calls.feature_add_event(self._handle, _native.enc(name), target, event_id)
        _native.check(status)
        return self

    def add_command(self, command_name: str) -> "Feature":
        status = _native.calls.feature_add_command(self._handle, _native.enc(command_name))
        _native.check(status)
        return self

    def install(self) -> None:
        status = _native.calls.feature_install(self._handle)
        _native.check(status)

    def uninstall(self) -> None:
        status = _native.calls.feature_uninstall(self._handle)
        _native.check(status)

    @property
    def installed(self) -> bool:
        return bool(_native.calls.feature_is_installed(self._handle))


class FeatureNamespace:
    """Backs `program.feature.create(name)`."""

    def __init__(self, session):
        self._session = session

    def create(self, name: str) -> Feature:
        handle = c_void_p()
        status = _native.calls.feature_create(self._session._handle, _native.enc(name), byref(handle))
        _native.check(status)
        return Feature(self._session, name, handle)
