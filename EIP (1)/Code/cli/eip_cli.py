#!/usr/bin/env python3
"""EIP CLI - a thin frontend over the eip Python API (spec section 11).

    eip list
    eip inspect A.exe
    eip attach A.exe
    eip modules A.exe
    eip status A.exe
    eip apply feature.py A.exe
    eip detach A.exe
    eip patch A.exe --output A.modified.exe --set-value NAME=RVA:HEXBYTES ...

`inspect` and `patch` are fully portable (pure PE parsing/rewriting) and run
on any host OS. `attach`/`modules`/`status`/`apply` require a live Windows
process and the Windows-only native core; on other platforms they report
NotImplementedOnPlatform, same as the underlying API.

Since a CLI invocation is a fresh process each time, there is no
process-lifetime "session" to keep open between `eip attach` and a later
`eip status` call the way the Python API's `Process` object does within one
script. `attach`/`detach`/`modules`/`status` here each open a fresh
attachment by process name, perform one action, and detach - which is the
right behavior for a CLI used from a shell, and is explicitly how `apply`
is meant to be driven (it owns the full attach -> run feature script ->
detach lifecycle in one process).
"""
from __future__ import annotations

import argparse
import struct
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "python"))

import eip
from eip.types import ValueType


def cmd_list(args: argparse.Namespace) -> int:
    for p in eip.process.list():
        print(f"{p.pid:>8}  {p.name}")
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    with eip.pe.parse(args.path) as img:
        print(f"path:          {args.path}")
        print(f"arch:          {img.arch}")
        print(f"pe32plus:      {img.is_pe32plus}")
        print(f"image_base:    0x{img.image_base:x}")
        print(f"size_of_image: 0x{img.size_of_image:x}")
        print(f"entry_rva:     0x{img.entry_point_rva:x}")
        print(f"sections:")
        for s in img.sections():
            flags = ""
            if s.characteristics & 0x20000000:
                flags += "X"
            if s.characteristics & 0x40000000:
                flags += "R"
            if s.characteristics & 0x80000000:
                flags += "W"
            print(f"  {s.name:<10} va=0x{s.virtual_address:<8x} vsize=0x{s.virtual_size:<8x} raw=0x{s.raw_size:<8x} [{flags}]")
        exports = img.exports()
        if exports:
            print(f"exports ({len(exports)}):")
            for e in exports:
                tag = " (forwarder)" if e.is_forwarder else ""
                print(f"  {e.name or '(ordinal only)':<32} rva=0x{e.rva:x} ord={e.ordinal}{tag}")
    return 0


def cmd_attach(args: argparse.Namespace) -> int:
    app = eip.attach(args.target)
    try:
        print(f"attached: pid={app.pid} arch={app.arch}")
    finally:
        app.detach()
    return 0


def cmd_modules(args: argparse.Namespace) -> int:
    app = eip.attach(args.target)
    try:
        for m in app.modules():
            print(f"0x{m.base:016x}  {m.size:>10}  {m.name}")
    finally:
        app.detach()
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    app = eip.attach(args.target)
    try:
        changes = app.runtime.changes()
        if not changes:
            print("no changes recorded in this session")
        for c in changes:
            print(f"#{c.sequence:<4} {c.state.name:<10} {c.kind.name:<18} {c.description}")
    finally:
        app.detach()
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    """Runs a user-supplied Feature script against `target`. The script must
    define `def build(app) -> eip.Feature:` which configures (but does not
    necessarily install) a Feature; this command installs it."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("eip_user_feature_script", args.script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "build"):
        print(f"error: {args.script} must define build(app) -> eip.Feature", file=sys.stderr)
        return 2

    app = eip.attach(args.target)
    try:
        feature = module.build(app)
        if not feature.installed:
            feature.install()
        print(f"feature '{feature.name}' installed")
    finally:
        app.detach()
    return 0


def cmd_detach(args: argparse.Namespace) -> int:
    # Each CLI invocation is its own process, so "detach" is really just
    # confirming the target still exists and is reachable right now - there
    # is no cross-invocation handle to release.
    app = eip.attach(args.target)
    app.detach()
    print(f"ok: {args.target} is reachable and was cleanly detached")
    return 0


def _parse_hex_bytes(s: str) -> bytes:
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]
    return bytes.fromhex(s)


def cmd_patch(args: argparse.Namespace) -> int:
    patcher = eip.patch.Patcher(args.path)
    for item in args.set_bytes or []:
        name, rest = item.split("=", 1)
        rva_str, hex_str = rest.split(":", 1)
        rva = int(rva_str, 16) if rva_str.lower().startswith("0x") else int(rva_str)
        data = _parse_hex_bytes(hex_str)
        patcher.add_value_change(rva, data, name)
    for item in args.set_i32 or []:
        name, rest = item.split("=", 1)
        rva_str, val_str = rest.split(":", 1)
        rva = int(rva_str, 16) if rva_str.lower().startswith("0x") else int(rva_str)
        patcher.add_value_change(rva, struct.pack("<i", int(val_str)), name)
    output = args.output or (os.path.splitext(args.path)[0] + ".modified.exe")
    patcher.apply(output)
    patcher.close()
    print(f"wrote {output}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="eip", description="EIP (Exe In Python) CLI")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("list", help="list running processes")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("inspect", help="inspect a PE file's structure")
    sp.add_argument("path")
    sp.set_defaults(func=cmd_inspect)

    sp = sub.add_parser("attach", help="attach to a running process and report its arch/pid")
    sp.add_argument("target", help="process name, e.g. A.exe")
    sp.set_defaults(func=cmd_attach)

    sp = sub.add_parser("modules", help="list modules loaded in a running process")
    sp.add_argument("target")
    sp.set_defaults(func=cmd_modules)

    sp = sub.add_parser("status", help="show the EIP change log for a running process")
    sp.add_argument("target")
    sp.set_defaults(func=cmd_status)

    sp = sub.add_parser("apply", help="attach, run a Feature script's build(app), install it, detach")
    sp.add_argument("script", help="Python file defining build(app) -> eip.Feature")
    sp.add_argument("target")
    sp.set_defaults(func=cmd_apply)

    sp = sub.add_parser("detach", help="verify a target is reachable, then detach")
    sp.add_argument("target")
    sp.set_defaults(func=cmd_detach)

    sp = sub.add_parser("patch", help="apply a persistent patch to a PE file on disk")
    sp.add_argument("path")
    sp.add_argument("--output", "-o", help="output path (default: <input>.modified.exe)")
    sp.add_argument("--set-bytes", action="append", metavar="NAME=RVA:HEXBYTES",
                     help="e.g. RunSpeed=0x8000:14000000")
    sp.add_argument("--set-i32", action="append", metavar="NAME=RVA:INT",
                     help="e.g. RunSpeed=0x8000:20")
    sp.set_defaults(func=cmd_patch)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except eip.errors.EipException as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
