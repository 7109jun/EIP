"""ctypes binding to eip_core (Windows) / libeip_core (Linux, PE-only subset).

This is the ONLY file in the Python package that touches ctypes or knows the
native ABI. Every other eip.* module calls through the wrappers defined here
and never pokes at raw pointers or structs itself - this is what keeps the
required layering intact:

    Python Application -> EIP Python API -> EIP Runtime -> EIP Native Core -> Windows Process/PE

`lib` loaded here IS "EIP Runtime + EIP Native Core" from that diagram: the
runtime logic (transactions, feature bookkeeping, change tracking) lives in
C++ (core/src/runtime.cpp, feature.cpp, transaction.cpp), not reimplemented
in Python - Python only marshals calls across the boundary.
"""
from __future__ import annotations

import ctypes
import os
import platform
import sys
from ctypes import (
    c_char,
    c_char_p,
    c_double,
    c_int32,
    c_uint8,
    c_uint32,
    c_uint64,
    c_void_p,
    POINTER,
    Structure,
    byref,
)

from . import errors


def _find_library() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = []
    override = os.environ.get("EIP_CORE_PATH")
    if override:
        candidates.append(override)
    if platform.system() == "Windows":
        names = ["eip_core.dll"]
    else:
        names = ["libeip_core.so"]
    for name in names:
        candidates.append(os.path.join(here, "..", "..", "build", name))
        candidates.append(os.path.join(here, name))
        candidates.append(name)
    for path in candidates:
        if os.path.exists(path):
            return path
    raise OSError(
        "could not locate the EIP native core library ("
        + ", ".join(names)
        + "); build it first (see build/README or run the build script), "
        "or set EIP_CORE_PATH"
    )


_LIB_PATH = _find_library()
lib = ctypes.CDLL(_LIB_PATH)

eip_status = c_int32
eip_address = c_uint64
eip_rva = c_uint32
eip_session = c_void_p
eip_feature = c_void_p
eip_transaction = c_void_p
eip_pe = c_void_p
eip_patcher = c_void_p


class ProcessSummary(Structure):
    _fields_ = [("pid", c_uint32), ("name", c_char * 260), ("path", c_char * 520)]


class ModuleInfo(Structure):
    _fields_ = [
        ("name", c_char * 260),
        ("path", c_char * 520),
        ("base", eip_address),
        ("size", c_uint64),
    ]


class Scalar(Structure):
    _fields_ = [
        ("type", c_int32),
        ("as_int", ctypes.c_int64),
        ("as_float", c_double),
        ("as_bytes", c_char_p),
        ("as_bytes_len", c_uint32),
    ]


class HookHandle(Structure):
    _fields_ = [("target", eip_address), ("detour", eip_address), ("trampoline", eip_address)]


class Ring(Structure):
    _fields_ = [("ring_addr", eip_address), ("capacity", c_uint32)]


class EventHandle(Structure):
    _fields_ = [("target", eip_address), ("stub", eip_address), ("ring", Ring), ("event_id", c_uint32)]


class EventEntry(Structure):
    _fields_ = [("event_id", c_uint32), ("sequence", c_uint32)]


class ChangeRecord(Structure):
    _fields_ = [
        ("sequence", c_uint64),
        ("kind", c_int32),
        ("state", c_int32),
        ("address", eip_address),
        ("description", c_char * 256),
    ]


class PeSection(Structure):
    _fields_ = [
        ("name", c_char * 16),
        ("virtual_address", eip_rva),
        ("virtual_size", c_uint32),
        ("raw_size", c_uint32),
        ("raw_offset", c_uint32),
        ("characteristics", c_uint32),
    ]


class PeExport(Structure):
    _fields_ = [
        ("name", c_char * 256),
        ("ordinal", c_uint32),
        ("rva", eip_rva),
        ("is_forwarder", c_int32),
    ]


def _sig(name, restype, argtypes):
    fn = getattr(lib, name)
    fn.restype = restype
    fn.argtypes = argtypes
    return fn


# --- error reporting -------------------------------------------------------
_eip_last_error_detail = _sig("eip_last_error_detail", c_char_p, [])


def check(status: int) -> None:
    if status != 0:
        detail = _eip_last_error_detail()
        errors.raise_for_code(status, detail.decode("utf-8", "replace") if detail else "")


# --- process -----------------------------------------------------------
_eip_process_list = _sig("eip_process_list", eip_status, [POINTER(ProcessSummary), c_uint32, POINTER(c_uint32)])
_eip_process_find = _sig("eip_process_find", eip_status, [c_char_p, POINTER(ProcessSummary), c_uint32, POINTER(c_uint32)])
_eip_attach_pid = _sig("eip_attach_pid", eip_status, [c_uint32, POINTER(eip_session)])
_eip_attach_name = _sig("eip_attach_name", eip_status, [c_char_p, POINTER(eip_session)])
_eip_detach = _sig("eip_detach", eip_status, [eip_session])
_eip_session_pid = _sig("eip_session_pid", c_uint32, [eip_session])
_eip_session_arch = _sig("eip_session_arch", c_int32, [eip_session])
_eip_modules = _sig("eip_modules", eip_status, [eip_session, POINTER(ModuleInfo), c_uint32, POINTER(c_uint32)])
_eip_resolve = _sig("eip_resolve", eip_status, [eip_session, c_char_p, POINTER(eip_address)])

# --- value ---------------------------------------------------------------
_eip_value_read = _sig("eip_value_read", eip_status, [eip_session, c_char_p, c_int32, c_uint32, POINTER(Scalar)])
_eip_value_set = _sig("eip_value_set", eip_status, [eip_session, c_char_p, c_int32, c_uint32, POINTER(Scalar)])

# --- function --------------------------------------------------------------
_eip_function_find_export = _sig("eip_function_find_export", eip_status, [eip_session, c_char_p, c_char_p, POINTER(eip_address)])
_eip_function_find_pattern = _sig("eip_function_find_pattern", eip_status, [eip_session, c_char_p, c_char_p, POINTER(eip_address)])
_eip_function_add = _sig("eip_function_add", eip_status, [eip_session, POINTER(c_uint8), c_uint32, POINTER(eip_address)])
_eip_function_replace = _sig("eip_function_replace", eip_status, [eip_session, eip_address, eip_address, POINTER(c_uint8), c_uint32, POINTER(c_uint32)])
_eip_function_restore = _sig("eip_function_restore", eip_status, [eip_session, eip_address, POINTER(c_uint8), c_uint32])

# --- hook ------------------------------------------------------------------
_eip_hook_install = _sig("eip_hook_install", eip_status, [eip_session, eip_address, eip_address, POINTER(HookHandle)])
_eip_hook_remove = _sig("eip_hook_remove", eip_status, [eip_session, POINTER(HookHandle)])

# --- event -------------------------------------------------------------
_eip_event_create_ring = _sig("eip_event_create_ring", eip_status, [eip_session, c_uint32, POINTER(Ring)])
_eip_event_install = _sig("eip_event_install", eip_status, [eip_session, c_char_p, eip_address, c_uint32, Ring, POINTER(EventHandle)])
_eip_event_remove = _sig("eip_event_remove", eip_status, [eip_session, POINTER(EventHandle)])
_eip_event_poll = _sig("eip_event_poll", eip_status, [eip_session, Ring, c_uint32, POINTER(EventEntry), c_uint32, POINTER(c_uint32)])

# --- transaction -------------------------------------------------------
_eip_tx_begin = _sig("eip_tx_begin", eip_status, [eip_session, POINTER(eip_transaction)])
_eip_tx_add_value_set = _sig("eip_tx_add_value_set", eip_status, [eip_transaction, c_char_p, c_int32, c_uint32, POINTER(Scalar)])
_eip_tx_add_function_replace = _sig("eip_tx_add_function_replace", eip_status, [eip_transaction, eip_address, eip_address])
_eip_tx_add_hook_install = _sig("eip_tx_add_hook_install", eip_status, [eip_transaction, eip_address, eip_address])
_eip_tx_commit = _sig("eip_tx_commit", eip_status, [eip_transaction])
_eip_tx_rollback = _sig("eip_tx_rollback", eip_status, [eip_transaction])
_eip_tx_destroy = _sig("eip_tx_destroy", None, [eip_transaction])

# --- feature -----------------------------------------------------------
_eip_feature_create = _sig("eip_feature_create", eip_status, [eip_session, c_char_p, POINTER(eip_feature)])
_eip_feature_add_value = _sig("eip_feature_add_value", eip_status, [eip_feature, c_char_p, c_int32, c_uint32, POINTER(Scalar)])
_eip_feature_add_function = _sig("eip_feature_add_function", eip_status, [eip_feature, eip_address, POINTER(c_uint8), c_uint32])
_eip_feature_add_hook = _sig("eip_feature_add_hook", eip_status, [eip_feature, eip_address, eip_address])
_eip_feature_add_event = _sig("eip_feature_add_event", eip_status, [eip_feature, c_char_p, eip_address, c_uint32])
_eip_feature_add_command = _sig("eip_feature_add_command", eip_status, [eip_feature, c_char_p])
_eip_feature_install = _sig("eip_feature_install", eip_status, [eip_feature])
_eip_feature_uninstall = _sig("eip_feature_uninstall", eip_status, [eip_feature])
_eip_feature_is_installed = _sig("eip_feature_is_installed", c_int32, [eip_feature])

# --- runtime -------------------------------------------------------------
_eip_runtime_changes = _sig("eip_runtime_changes", eip_status, [eip_session, POINTER(ChangeRecord), c_uint32, POINTER(c_uint32)])
_eip_runtime_checkpoint = _sig("eip_runtime_checkpoint", c_uint64, [eip_session])
_eip_runtime_diff_since = _sig("eip_runtime_diff_since", eip_status, [eip_session, c_uint64, POINTER(ChangeRecord), c_uint32, POINTER(c_uint32)])

# --- PE engine -----------------------------------------------------------
_eip_pe_parse_file = _sig("eip_pe_parse_file", eip_status, [c_char_p, POINTER(eip_pe)])
_eip_pe_close = _sig("eip_pe_close", None, [eip_pe])
_eip_pe_arch = _sig("eip_pe_arch", c_int32, [eip_pe])
_eip_pe_is_pe32plus = _sig("eip_pe_is_pe32plus", c_int32, [eip_pe])
_eip_pe_image_base = _sig("eip_pe_image_base", eip_address, [eip_pe])
_eip_pe_size_of_image = _sig("eip_pe_size_of_image", c_uint32, [eip_pe])
_eip_pe_entry_point_rva = _sig("eip_pe_entry_point_rva", c_uint32, [eip_pe])
_eip_pe_sections = _sig("eip_pe_sections", eip_status, [eip_pe, POINTER(PeSection), c_uint32, POINTER(c_uint32)])
_eip_pe_exports = _sig("eip_pe_exports", eip_status, [eip_pe, POINTER(PeExport), c_uint32, POINTER(c_uint32)])
_eip_pe_find_export = _sig("eip_pe_find_export", eip_status, [eip_pe, c_char_p, POINTER(eip_rva)])
_eip_pe_read_rva = _sig("eip_pe_read_rva", eip_status, [eip_pe, eip_rva, POINTER(c_uint8), c_uint32])
_eip_pe_patch_bytes = _sig("eip_pe_patch_bytes", eip_status, [eip_pe, eip_rva, POINTER(c_uint8), c_uint32])
_eip_pe_add_section = _sig("eip_pe_add_section", eip_status, [eip_pe, c_char_p, POINTER(c_uint8), c_uint32, c_uint32, POINTER(eip_rva)])
_eip_pe_save = _sig("eip_pe_save", eip_status, [eip_pe, c_char_p])

# --- persistent patch ------------------------------------------------------
_eip_patcher_create = _sig("eip_patcher_create", eip_status, [c_char_p, POINTER(eip_patcher)])
_eip_patcher_close = _sig("eip_patcher_close", None, [eip_patcher])
_eip_patcher_add_value_change = _sig("eip_patcher_add_value_change", eip_status, [eip_patcher, eip_rva, POINTER(c_uint8), c_uint32, c_char_p])
_eip_patcher_add_code_injection = _sig("eip_patcher_add_code_injection", eip_status, [eip_patcher, c_char_p, POINTER(c_uint8), c_uint32, c_uint32, c_char_p])
_eip_patcher_apply = _sig("eip_patcher_apply", eip_status, [eip_patcher, c_char_p])


def enc(s: str) -> bytes:
    return s.encode("utf-8")


def bytes_to_array(data: bytes):
    buf = (c_uint8 * len(data))(*data)
    return buf


# Re-export the raw call wrappers under short names used by the rest of the
# package, each paired with its `check()` so callers never see a raw status.
class NativeCalls:
    process_list = staticmethod(_eip_process_list)
    process_find = staticmethod(_eip_process_find)
    attach_pid = staticmethod(_eip_attach_pid)
    attach_name = staticmethod(_eip_attach_name)
    detach = staticmethod(_eip_detach)
    session_pid = staticmethod(_eip_session_pid)
    session_arch = staticmethod(_eip_session_arch)
    modules = staticmethod(_eip_modules)
    resolve = staticmethod(_eip_resolve)

    value_read = staticmethod(_eip_value_read)
    value_set = staticmethod(_eip_value_set)

    function_find_export = staticmethod(_eip_function_find_export)
    function_find_pattern = staticmethod(_eip_function_find_pattern)
    function_add = staticmethod(_eip_function_add)
    function_replace = staticmethod(_eip_function_replace)
    function_restore = staticmethod(_eip_function_restore)

    hook_install = staticmethod(_eip_hook_install)
    hook_remove = staticmethod(_eip_hook_remove)

    event_create_ring = staticmethod(_eip_event_create_ring)
    event_install = staticmethod(_eip_event_install)
    event_remove = staticmethod(_eip_event_remove)
    event_poll = staticmethod(_eip_event_poll)

    tx_begin = staticmethod(_eip_tx_begin)
    tx_add_value_set = staticmethod(_eip_tx_add_value_set)
    tx_add_function_replace = staticmethod(_eip_tx_add_function_replace)
    tx_add_hook_install = staticmethod(_eip_tx_add_hook_install)
    tx_commit = staticmethod(_eip_tx_commit)
    tx_rollback = staticmethod(_eip_tx_rollback)
    tx_destroy = staticmethod(_eip_tx_destroy)

    feature_create = staticmethod(_eip_feature_create)
    feature_add_value = staticmethod(_eip_feature_add_value)
    feature_add_function = staticmethod(_eip_feature_add_function)
    feature_add_hook = staticmethod(_eip_feature_add_hook)
    feature_add_event = staticmethod(_eip_feature_add_event)
    feature_add_command = staticmethod(_eip_feature_add_command)
    feature_install = staticmethod(_eip_feature_install)
    feature_uninstall = staticmethod(_eip_feature_uninstall)
    feature_is_installed = staticmethod(_eip_feature_is_installed)

    runtime_changes = staticmethod(_eip_runtime_changes)
    runtime_checkpoint = staticmethod(_eip_runtime_checkpoint)
    runtime_diff_since = staticmethod(_eip_runtime_diff_since)

    pe_parse_file = staticmethod(_eip_pe_parse_file)
    pe_close = staticmethod(_eip_pe_close)
    pe_arch = staticmethod(_eip_pe_arch)
    pe_is_pe32plus = staticmethod(_eip_pe_is_pe32plus)
    pe_image_base = staticmethod(_eip_pe_image_base)
    pe_size_of_image = staticmethod(_eip_pe_size_of_image)
    pe_entry_point_rva = staticmethod(_eip_pe_entry_point_rva)
    pe_sections = staticmethod(_eip_pe_sections)
    pe_exports = staticmethod(_eip_pe_exports)
    pe_find_export = staticmethod(_eip_pe_find_export)
    pe_read_rva = staticmethod(_eip_pe_read_rva)
    pe_patch_bytes = staticmethod(_eip_pe_patch_bytes)
    pe_add_section = staticmethod(_eip_pe_add_section)
    pe_save = staticmethod(_eip_pe_save)

    patcher_create = staticmethod(_eip_patcher_create)
    patcher_close = staticmethod(_eip_patcher_close)
    patcher_add_value_change = staticmethod(_eip_patcher_add_value_change)
    patcher_add_code_injection = staticmethod(_eip_patcher_add_code_injection)
    patcher_apply = staticmethod(_eip_patcher_apply)


calls = NativeCalls()
