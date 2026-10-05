"""EIP (Exe In Python) - a general-purpose Windows process extension runtime.

    import eip
    app = eip.attach("Demo.exe")
    app.value.set(target="Demo.exe!g_RunSpeed", value=20)

Layering (see core/include/eip/capi.h for the full rationale):

    Python Application
           |
    EIP Python API     <- this package
           |
    EIP Runtime        <- core/src/runtime.cpp, transaction.cpp, feature.cpp
           |
    EIP Native Core     <- core/src/pe.cpp, process.cpp, memory.cpp, function.cpp, hook.cpp, event.cpp
           |
    Windows Process / PE
"""
from __future__ import annotations

from . import process as _process_module
from . import pe as pe
from . import patch as patch
from . import types as types
from . import errors as errors
from .process import Process, Module, ProcessSummary, attach, detach
from .types import ValueType
from .hook import Hook
from .event import Event
from .feature import Feature
from .transaction import Transaction

# `eip.process` is also a namespace (eip.process.list() / eip.process.find()),
# matching the spec's `eip.process.list()` / `eip.process.find(...)` calls.
process = _process_module

__all__ = [
    "attach",
    "detach",
    "Process",
    "Module",
    "ProcessSummary",
    "process",
    "pe",
    "patch",
    "types",
    "errors",
    "ValueType",
    "Hook",
    "Event",
    "Feature",
    "Transaction",
]

__version__ = "1.0.0"
