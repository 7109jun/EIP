"""eip.event - lightweight in-process event recording (program.event.*).

See core/include/eip/event.h for the mechanism: a small hand-assembled x64
stub records (event_id, sequence) into a ring buffer living in the target's
own memory every time execution reaches the hooked address; Python polls
that ring buffer rather than receiving a callback (there is no RPC channel
into the remote process, so this is the real, working mechanism rather than
a simulated callback).
"""
from __future__ import annotations

from ctypes import byref, c_uint32

from . import _native


class Event:
    def __init__(self, session, name: str, target: int, event_id: int, ring: "_native.Ring"):
        self._session = session
        self.name = name
        self.target = target
        self.event_id = event_id
        self._ring = ring
        self._stub = None
        self._last_sequence = 0
        self._active = False

    def install(self) -> "Event":
        handle = _native.EventHandle()
        status = _native.calls.event_install(
            self._session._handle, _native.enc(self.name), self.target, self.event_id, self._ring, byref(handle)
        )
        _native.check(status)
        self._stub = handle.stub
        self._active = True
        return self

    def remove(self) -> None:
        if not self._active:
            return
        handle = _native.EventHandle(target=self.target, stub=self._stub, ring=self._ring, event_id=self.event_id)
        status = _native.calls.event_remove(self._session._handle, byref(handle))
        _native.check(status)
        self._active = False

    def poll(self):
        """Returns the list of (event_id, sequence) firings since the last
        poll() call."""
        out = (_native.EventEntry * 256)()
        count = c_uint32()
        status = _native.calls.event_poll(
            self._session._handle, self._ring, self._last_sequence, out, 256, byref(count)
        )
        _native.check(status)
        entries = [(out[i].event_id, out[i].sequence) for i in range(count.value)]
        if entries:
            self._last_sequence = entries[-1][1] + 1
        return entries



class EventNamespace:
    def __init__(self, session):
        self._session = session
        self._next_event_id = 1

    def create(self, name: str, target: int, capacity: int = 64) -> Event:
        ring = _native.Ring()
        status = _native.calls.event_create_ring(self._session._handle, capacity, byref(ring))
        _native.check(status)
        event_id = self._next_event_id
        self._next_event_id += 1
        return Event(self._session, name, target, event_id, ring)
