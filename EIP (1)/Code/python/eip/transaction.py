"""eip.transaction - explicit atomic transactions (program.transaction.begin()).

Mirrors spec section 6 exactly:

    tx = program.transaction.begin()
    tx.value.set(...)
    tx.function.replace(...)
    tx.hook.create(...)
    tx.commit()        # or tx.rollback()

Backed by the native Transaction (core/src/transaction.cpp): every queued
operation is applied in order at commit() time, and if any step fails the
whole transaction is rolled back in reverse order - no partial state is
left behind.
"""
from __future__ import annotations

from ctypes import byref, c_void_p

from . import _native
from .types import ValueType, infer_type
from .value import _python_to_scalar


class _TxValueNamespace:
    def __init__(self, tx):
        self._tx = tx

    def set(self, target: str, value, type: ValueType | None = None, capacity: int = 0) -> None:
        vtype = ValueType(type) if type is not None else infer_type(value)
        scalar = _python_to_scalar(value, vtype)
        status = _native.calls.tx_add_value_set(self._tx._handle, _native.enc(target), int(vtype), capacity, byref(scalar))
        _native.check(status)


class _TxFunctionNamespace:
    def __init__(self, tx):
        self._tx = tx

    def replace(self, target: int, new_impl: int) -> None:
        status = _native.calls.tx_add_function_replace(self._tx._handle, target, new_impl)
        _native.check(status)


class _TxHookNamespace:
    def __init__(self, tx):
        self._tx = tx

    def create(self, target: int, detour: int) -> None:
        status = _native.calls.tx_add_hook_install(self._tx._handle, target, detour)
        _native.check(status)


class Transaction:
    def __init__(self, session):
        self._session = session
        handle = c_void_p()
        status = _native.calls.tx_begin(session._handle, byref(handle))
        _native.check(status)
        self._handle = handle
        self.value = _TxValueNamespace(self)
        self.function = _TxFunctionNamespace(self)
        self.hook = _TxHookNamespace(self)
        self._finished = False

    def commit(self) -> None:
        status = _native.calls.tx_commit(self._handle)
        self._finished = True
        _native.check(status)

    def rollback(self) -> None:
        status = _native.calls.tx_rollback(self._handle)
        self._finished = True
        _native.check(status)

    def __del__(self):
        try:
            if self._handle:
                _native.calls.tx_destroy(self._handle)
        except Exception:
            pass

    def __enter__(self) -> "Transaction":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._finished:
            return
        if exc_type is None:
            self.commit()
        else:
            self.rollback()


class TransactionNamespace:
    """Backs `program.transaction.begin()`."""

    def __init__(self, session):
        self._session = session

    def begin(self) -> Transaction:
        return Transaction(self._session)
