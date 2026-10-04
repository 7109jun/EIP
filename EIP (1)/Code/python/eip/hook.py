"""eip.hook - inline trampoline hooking (program.hook.create / .remove)."""
from __future__ import annotations

from ctypes import byref

from . import _native


class Hook:
    """A live hook. `trampoline` is the address to call to run the original
    function's real behavior (it still runs the original instructions before
    jumping back past the patched region)."""

    def __init__(self, session, target: int, detour: int, trampoline: int):
        self._session = session
        self.target = target
        self.detour = detour
        self.trampoline = trampoline
        self._active = True

    @property
    def active(self) -> bool:
        return self._active

    def remove(self) -> None:
        if not self._active:
            return
        handle = _native.HookHandle(target=self.target, detour=self.detour, trampoline=self.trampoline)
        status = _native.calls.hook_remove(self._session._handle, byref(handle))
        _native.check(status)
        self._active = False


class HookNamespace:
    def __init__(self, session):
        self._session = session

    def create(self, target: int, detour: int) -> Hook:
        handle = _native.HookHandle()
        status = _native.calls.hook_install(self._session._handle, target, detour, byref(handle))
        _native.check(status)
        return Hook(self._session, handle.target, handle.detour, handle.trampoline)
