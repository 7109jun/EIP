# EIP test suite

## What actually runs here (Linux build environment)

```
bash build/build.sh            # builds eip_core.dll (cross-compiled), libeip_core.so, Demo.exe
bash build/run_native_tests.sh # C++ tests, run directly
bash build/run_python_tests.sh # Python tests, run via unittest
```

Everything these two scripts execute is **real, non-mocked code run against
real mingw-w64-compiled PE binaries** (`examples/demo_program/Demo.exe`, plus
32-bit and 64-bit fixtures): PE parsing, in-memory patching, persistent
patching to a new file, section injection, error-code propagation, the
platform-fallback path, and the x86-64 instruction-length decoder verified
against real `objdump` disassembly ground truth.

## What requires a real Windows host

`eip.attach()`, `Value.set` against a *live* process, `Function.replace`,
`Hook.install`, `Event.install`, `Feature.install` against a running
process, and the Transaction commit/rollback guarantee against live memory
all require Windows's `OpenProcess` / `ReadProcessMemory` /
`WriteProcessMemory` / `VirtualProtectEx` / `VirtualAllocEx` /
`CreateToolhelp32Snapshot` APIs, which do not exist on Linux.

This is a structural limitation of the sandbox this project was built in,
not a gap in the implementation:

* Every Windows-only source file (`memory.cpp`, `process.cpp`) compiles
  cleanly both on Linux (where it compiles into a `NotImplementedOnPlatform`
  stub - see `test_platform_fallback`) and cross-compiled for Windows via
  mingw-w64 (`eip_core.dll`, built by `build/build.sh`).
* `tests/native/test_windows_live.cpp` is a complete, real (not pseudo-code)
  end-to-end test: attach, value read/set, function discovery, transaction
  commit, transaction rollback-on-failure, hook install/remove with
  byte-level before/after verification, feature install/uninstall, and
  runtime change-log diffing. `build/run_native_tests.sh` cross-compiles it
  on every run to prove it links against the real native core; it is not
  executed here because this sandbox has no Windows kernel to attach to.

### Running the live test for real

On an actual Windows machine, with a C++ compiler (MSVC's `cl.exe`, or
mingw-w64):

```bat
examples\demo_program\Demo.exe &
cl /std:c++17 /EHsc /Icore\include core\src\*.cpp tests\native\test_windows_live.cpp /Fe:test_windows_live.exe
test_windows_live.exe
```

Expected output ends with `ALL WINDOWS LIVE TESTS PASSED`, and along the way
demonstrates the exact `RunSpeed: 10 -> 20` and `Open/Save/Exit ->
Open/Save/Export/Exit` scenarios from the spec against a real running
process - not a file on disk.

The Python examples (`examples/change_value.py`, `examples/hook_function.py`,
`examples/add_export_feature.py`) exercise the identical real code paths
through the Python API and can be run the same way:

```bat
examples\demo_program\Demo.exe &
python examples\change_value.py
python examples\add_export_feature.py
python examples\hook_function.py
```

`examples/persistent_patch.py` needs no Windows host at all and was already
run and verified as part of building this project (see the main README).
