# EIP (Exe In Python)

A general-purpose Windows process extension/modification runtime. EIP
attaches to a running Windows PE process and lets you change existing
values, replace or hook existing functions, add brand-new functions, and
install brand-new "Features" (bundled sets of changes) into a program at
runtime - capabilities the original program's source never had.

```python
import eip

app = eip.attach("A.exe")
app.value.set(target="Player.RunSpeed", value=20)
app.commit()
```

## Architecture

```
Python Application
       |
EIP Python API        python/eip/*.py           (this is the public API)
       |
EIP Runtime            core/src/runtime.cpp,     (transactions, feature
                        transaction.cpp,           bookkeeping, change
                        feature.cpp                tracking)
       |
EIP Native Core         core/src/pe.cpp, process.cpp, memory.cpp,
                         function.cpp, hook.cpp, event.cpp, x86len.cpp
       |
Windows Process / PE
```

Python never calls a Windows API directly. Every call crosses exactly one
boundary - a flat C ABI (`core/include/eip/capi.h`, implemented by
`core/src/capi.cpp`) exposed by `eip_core.dll` - and `python/eip/_native.py`
is the only file that touches `ctypes`.

## Layout

```
eip/
├── core/
│   ├── include/eip/   public C++ headers (common, pe, process, memory,
│   │                  value, function, hook, event, transaction, feature,
│   │                  runtime, patch, capi, x86len, target)
│   └── src/           native core + C API implementation
├── python/eip/        the Python API (ctypes binding + typed wrappers)
├── cli/eip_cli.py      `eip list|inspect|attach|modules|status|apply|detach|patch`
├── examples/
│   ├── demo_program/   Demo.exe - the test target (RunSpeed + Open/Save/Exit menu)
│   ├── change_value.py          (scenario: RunSpeed 10 -> 20)
│   ├── add_export_feature.py    (scenario: add "Export" to the menu)
│   ├── hook_function.py         (intercept GetRunSpeed())
│   ├── persistent_patch.py      (patch Demo.exe on disk, no process needed)
│   └── feature_script.py        (for `eip apply`)
├── tests/
│   ├── native/         C++ tests (see tests/README.md for what runs where)
│   └── python/         Python tests (fully run in this environment)
└── build/
    ├── build.sh              builds eip_core.dll + libeip_core.so + Demo.exe
    ├── run_native_tests.sh   builds and runs every native test
    └── run_python_tests.sh   builds Demo.exe/native core, then runs pytest-style tests
```

## Building

```bash
bash build/build.sh
```

Produces `build/eip_core.dll` (Windows, full functionality - cross-compiled
here with mingw-w64; rebuild natively with MSVC on a real Windows box for
production use) and `build/libeip_core.so` (Linux, the portable PE-parsing
and persistent-patch subset, used for local testing without a Windows
machine). Also builds `examples/demo_program/Demo.exe`.

## Testing

```bash
bash build/run_native_tests.sh   # C++ tests
bash build/run_python_tests.sh   # Python tests
```

**Verification status for this session**: every test that does not require
a live Windows process (PE parsing, in-memory and persistent patching,
section injection, 32-bit vs 64-bit detection, error-code propagation, the
x86-64 instruction-length decoder validated against real `objdump` output)
has been built and run for real in this environment, with real mingw-w64
compiled PE binaries as fixtures - not mocked. Code paths that require
`OpenProcess`/`ReadProcessMemory`/etc. (attach, live value/function/hook/
feature changes, transaction rollback against live memory) are fully
implemented and cross-compile cleanly to a working `eip_core.dll`, but
their *execution* was deferred to a real Windows host per this session's
agreed verification plan - see `tests/README.md` for exact run instructions
and `tests/native/test_windows_live.cpp` for the full live test.

## CLI

```
eip list                          # running processes
eip inspect A.exe                 # PE structure, sections, exports
eip attach A.exe                  # attach, report pid/arch
eip modules A.exe                 # loaded modules
eip status A.exe                  # EIP's change log for that process
eip apply feature.py A.exe        # attach, install a Feature script, detach
eip detach A.exe
eip patch A.exe -o A.modified.exe --set-i32 RunSpeed=0x8000:20
```

`inspect` and `patch` work on any OS. The rest need Windows.

## Key design points

- **PE engine is portable.** `core/src/pe.cpp` has zero Windows dependency:
  it parses both an on-disk file and a live process's loaded memory image
  through the same `ByteSource` abstraction, so the identical code answers
  `eip inspect` (file) and resolves `"Module.exe!symbol"` targets against a
  running process (live memory).
- **Hooking preserves a callable original.** `HookEngine::install` uses the
  x86/x86-64 instruction-length decoder (`x86len.cpp`, validated against
  real disassembly) to find a whole-instruction boundary, builds a
  trampoline containing the saved original instructions plus a jump back,
  and only then overwrites the target with a jump to the detour.
- **Transactions guarantee no partial state.** Every operation in
  `core/src/transaction.cpp` carries its own `apply`/`rollback` pair; if any
  operation throws during `commit()`, everything already applied is undone
  in reverse order before the exception propagates.
- **Events use a real mechanism, not a simulated callback.** There is no
  RPC channel into a remote EXE, so `EventEngine` hand-assembles an x64
  stub that records `(event_id, sequence)` into a ring buffer living in the
  target's own memory; Python polls that buffer.
