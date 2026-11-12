<!-- SPDX-License-Identifier: Apache-2.0 -->

# Cross-Compilation

BHF cross-compiles C, C++ and Ada harnesses. `bhf build` and `bhf auto` share
one toolchain description: command-line flags, or a `[toolchain]` table in a
`--config` file (the table is documented under
[`bhf auto` → Config file](../auto/#config-file)). Command-line flags override
the file key by key, and relative paths in the file resolve against its
directory.

## Build Flags

A C or C++ harness:

```sh
bhf build bhf_work --harness H-C0001 --target aarch64-linux-gnu
```

`--target` selects `aarch64-linux-gnu-gcc` / `aarch64-linux-gnu-g++`
(`--toolchain <prefix>` does the same for a prefix), unless `--cc`/`--cxx` name
the compilers; a clang compiler gets `--target=<triple>` instead. `--sysroot`,
`--cflags`, `--cxxflags`, `--ldflags`, `--define` and `--toolchain-include`
complete the toolchain. bhf announces the compilers it uses, and the generated
Makefile picks GCC- or clang-spelled coverage and sanitizer flags from the
compiler that actually runs. The binary is foreign, so run it under an emulator:
`bhf replay --qemu-user qemu-aarch64 --qemu-arg=-L --qemu-arg=/usr/aarch64-linux-gnu`.
`--runtime`, `--probe-backend` and the `--ada-*` flags apply to Ada harnesses
only; on a C/C++ harness they are an error rather than silently ignored.

An Ada harness:

```sh
bhf build bhf_work \
  --harness H-TEST \
  --target aarch64-linux-gnu \
  --runtime light \
  --toolchain aarch64-linux-gnu
```

`--target` and `--runtime` are written into the generated `bhf_build.gpr` as
`for Target use` and `for Runtime ("Ada") use`. `--toolchain` is the tool
prefix: bhf runs `<prefix>-gprbuild` when it exists and the multi-target
`gprbuild` otherwise, and probes the compiler with `<prefix>-gnatmake` (or
`<prefix>-gnat`). When `--target` is omitted the prefix is the target. The
prefix is never written as `Toolchain_Name`: that attribute takes a gprconfig
compiler name, and a value such as `GNAT` or `GNAT_LLVM` given to `--toolchain`
is written as `for Toolchain_Name ("Ada") use` instead. `--ada-gprbuild` /
`--ada-gnat` name the programs explicitly, and `--ada-switch` appends compiler
switches to bhf's own.

The generated project `extends` the governing project, so its `Target`,
`Runtime` and source settings are inherited, but its `package Compiler` is
not: bhf writes its own `Default_Switches` (`-g`, assertions, coverage), which
replace the parent project's. Switches such as `-O1` from the parent project
are therefore not used; add the ones the harness needs with `--ada-switch` or
`toolchain.ada.switches`.

In a config file, `toolchain.ada.prefix` applies to Ada harnesses only. To
choose the compilers of a C/C++ harness there, set `toolchain.target` or
`toolchain.cc`/`toolchain.cxx`; `bhf build` notes a prefix that chose nothing.

## Whole-Sweep Cross Targets

`bhf auto` builds every C/C++ candidate for one target when the toolchain names
a runner:

```sh
bhf auto src --work-dir bhf_work \
  --target-triple aarch64-linux-gnu --runner qemu-aarch64
```

or, in a config file passed with `--config`:

```toml
[toolchain]
target = "aarch64-linux-gnu"
runner = "qemu-aarch64"
runner-args = ["-L", "/usr/aarch64-linux-gnu"]
```

Each harness is built with the cross compiler and SanitizerCoverage
(`trace-pc,trace-cmp` for GCC, `trace-pc-guard,trace-cmp` for clang, when the
compiler accepts it) and run as `<runner> <runner-args> <harness>`, so the sweep
is coverage-guided with input-to-state comparison hooks. `run.json`,
`finding.json` (`build.binary.coverage_instrumentation`) and the reports name
the instrumentation the harness binary carries: `sancov-trace-pc` when GCC's
debug information records code compiled with `trace-pc`, and `edge-bitmap`
for a build the compiler had to make without coverage. ASan is not armed, because its shadow memory does not survive
qemu-user; hard faults are reported as crashes, and `cflags` can add trap-mode
checks (`BHF_CROSS_GUARDS=1` arms the probed guard set). With no sanitizer
runtime to intercept `memcmp`, `bcmp` and the `str*cmp` family, the harness is
linked with `-Wl,--wrap=` for each of them, and bhf's driver reports those
comparisons itself, so string and buffer gates still feed the fuzzer's
comparison log. Without `runner-args`, a qemu-user runner gets
`-L <sysroot>`, or `-L /usr/<triple>` when that directory exists. The triple
comes from `--target-triple`, or from `<cc> -dumpmachine` when only `--cc` (or
`CC`) names a cross compiler.

bhf records the runner beside each cross-built harness (`bhf_runner.json`), so
the comparison evidence a finding records after fuzzing (and the one
`bhf explain` records for a finding that has none) replays the harness under
the same emulator, which passes the evidence variable through to it. The
capture's `gate_capture.runner` names the emulator. `bhf replay`,
`bhf minimize`, `bhf fuzz`, `bhf decode-args`, `bhf corpus minimize` and
`bhf report --backfill` run such a harness under the recorded runner too
when no `--qemu-user` is given (a binary `bhf build` staged into
`build/<id>/main` uses the one recorded in its harness dir), with a
`note: running <harness> under the recorded runner <program args>` line; the
generated `replay.py` embeds it as `RUNNER` (override it with
`BHF_REPLAY_RUNNER`). A harness whose ELF machine this host cannot run, with
no runner given or recorded, is refused before it runs:
`<harness> is built for aarch64; run it under an emulator: --qemu-user
qemu-aarch64 [--qemu-arg ...]`.

A trap instruction is a crash: `__builtin_trap` and checks built with
`-fsanitize-trap` raise SIGTRAP on AArch64 (SIGILL on x86_64), and both are
BHF-210 findings that name their signal. bhf's driver prints the faulting pc
for such a crash (see [Sanitizers](sanitizers.md)). An emulated child never
gets `abort_on_error=1` (a sanitizer report exits non-zero instead, because a
guest abort makes qemu-user spend minutes on its own address space) and runs
with core dumps off. The fidelity record of a cross-sweep finding says the
harness was `built for <triple> and run under <runner> user-mode emulation`,
gives the target's byte order, and lists only the sanitizer runtimes the
binary links (none for a cross sweep, so `sanitizers` is `not_exercised`).

A runner turns the C/C++ sweep into a cross sweep only when the C/C++ toolchain
builds for another target: a `target`, or a compiler whose `-dumpmachine` names
a triple this host cannot run. A runner given only for a foreign Ada target
(`[toolchain.ada] target`) runs the Ada harnesses, with `-L /usr/<ada triple>`
for a qemu-user runner (the C/C++ `sysroot` only when the C/C++ sweep builds for
the same triple); the C/C++ candidates keep their native, sanitizer-instrumented
builds. A runner with nothing foreign to run is an error.

The reverse is refused too: a target, an Ada target, or a C/C++ compiler (from
`--cc`/`--cxx`, the config file or `CC`/`CXX`) that builds for a platform the
host cannot run, with no runner, is an error before anything builds.

`--probe-build`, `--build-command` and `--run-untrusted` still run the
project's build for this host. Its compile database and generated headers apply
to the cross sweep. The static archives it builds hold host objects, so bhf
rebuilds each one for the target before the sweep: the archives in the probe
directory, and the ones the build leaves in the tree (a plain Makefile builds
beside its sources) or in its `build/`-style directories. Every member is
compiled again from its compile-database entry with the cross compiler and the
sweep's code-generation flags (the project's defines, include paths and
language flags kept; bhf's host instrumentation, `-march=`/`-mcpu=` and the
like dropped), and the result, under `<work-dir>/auto/probe-archives/<triple>/`,
is linked into the cross-built harnesses. A member is found by its object's
name; when several translation units write an object of that name (two
libraries that each compile a `util.c`), it is the one whose object file the
build left holds the member's bytes. An archive that cannot be rebuilt (a
member with no compile command or no way to tell its translation unit, a
member that does not compile for the target) is named with the reason, and its
targets are built from their sources. An archive already built for the target
is linked as it is. The configuration the
host build generated (a `config.h`) describes the host, which matters for a
target with a different data model. A project archive found in the tree is
linked into a cross build only when its objects are for the target's
architecture. The guard-driven lanes below build their targets from source.

In a native sweep whose toolchain is GCC, the build probe builds the project
with that GCC and GCC-spelled sanitizer and `trace-pc` coverage flags, so the
archives it leaves link into the GCC-built harnesses; the programs the probe
build links of its own (CMake's compiler checks) get no-op coverage hooks, an
object kept in the probe directory, or under the system temporary directory
when the tree's path has a space or comma.

## Foreign-Platform Targets in `bhf auto`

`bhf auto` does NOT host-filter foreign-platform code. A function whose
definition is guarded by a non-host platform/arch conditional — a C/C++
`#ifdef _WIN32` / `_MSC_VER`, an Ada `__win32` unit, or a SIMD-arch backend dir
(`arm64`, `neon`) — is discovered, ranked, and tagged with a `foreign_guard`
instead of being dropped. The attempt loop then picks a build+fuzz strategy:

- **Windows (`_WIN32`) C/C++ → mingw + wine (real Windows execution).** When the
  `x86_64-w64-mingw32` cross toolchain and `wine` are on `PATH`, the harness is
  cross-compiled to a real Windows PE and fuzzed under wine, exercising the
  target's actual Win32 behavior. Coverage and cmplog are real: mingw-w64 gcc
  supports `-fsanitize-coverage=trace-pc,trace-cmp` (the driver implements the
  guard-less `__sanitizer_cov_trace_pc` hook), so the engine gets edge coverage +
  input-to-state feedback. There is no ASan runtime for mingw, so memory-safety
  faults are detected by a unhandled-exception filter the driver installs: a
  hardware fault (access violation, stack overflow, …) becomes an immediate,
  distinctive process exit the engine classifies as a crash.
- **Arch/SIMD (aarch64, armhf, neon) → cross toolchain + qemu-user.** A 64-bit
  ARM / NEON guard builds with `aarch64-linux-gnu-gcc` under `qemu-aarch64`; a
  32-bit ARM (armv7/armhf) guard builds with `arm-linux-gnueabihf-gcc` under
  `qemu-arm`. The build arms GCC's `trace-pc,trace-cmp` coverage when the cross
  compiler accepts it, so the emulated harness is fuzzed coverage-guided. ASan
  does not survive qemu-user and stays off; hard crashes surface via
  SIGSEGV/SIGABRT.
- **Windows fallback → native stub-isolated build.** When mingw/wine is absent,
  a `_WIN32` C/C++ target (not Ada or Rust) is built NATIVELY with `_WIN32` defined and a synthesized
  fake `<windows.h>` so its portable logic type-checks and fuzzes with real host
  ASan + coverage. Findings are flagged REDUCED-FIDELITY (the platform surface is
  faked: handles are inert, Win32 behavior is not modeled).
- **No strategy → actionable skip.** A guard with neither a platform stub nor an
  installed cross toolchain is skipped with a reason naming exactly what to install.

### Overriding a Lane's Toolchain

Each guard-driven lane has a built-in toolchain and emulator: `mingw`
(`x86_64-w64-mingw32-gcc`, `wine`), `aarch64` (`aarch64-linux-gnu-gcc`,
`qemu-aarch64`), `armhf` (`arm-linux-gnueabihf-gcc`, `qemu-arm`), `ppc64le`,
`ppc64`, `ppc`, `mipsel`, `mips` and `sparc64` (`<triple>-gcc`, `qemu-<arch>`).
A `[cross.<lane>]` table in an explicit `--config` replaces any of them for
the candidates that lane takes:

```toml
[cross.aarch64]
cc = "/opt/arm/bin/aarch64-none-linux-gnu-gcc"   # cxx follows: ...-g++
sysroot = "/opt/arm/aarch64-none-linux-gnu/libc"
runner = "qemu-aarch64"
runner-args = ["-L", "/opt/arm/aarch64-none-linux-gnu/libc"]

[cross.armhf]
runner = "tools/run-armhf"       # relative paths resolve against the config file

[cross.mingw]
runner = "wine64"
```

`target` sets the triple (and, without `cc`/`cxx`, `<target>-gcc` /
`<target>-g++`); `cc`/`cxx` name the compilers (one given alone selects its
pair); `sysroot` is passed to every compile and link as `--sysroot=`, bhf's
driver object included, and to a qemu-user runner without `runner-args` as
`-L`; `runner` and `runner-args` replace the emulator. A clang `cc` builds for
the lane's triple: bhf adds `--target=<triple>` to every compile and link (and
links no clang sanitizer runtime, which a foreign target does not have). The
lane's `--sysroot=`/`--target=` replace a `[toolchain]` sysroot or target for
its candidates. A distribution's multiarch directory (`/usr/aarch64-linux-gnu`)
is not a sysroot: its `libc.so` names absolute paths that a `--sysroot=` link
cannot find, so leave `sysroot` out for the distribution's own cross compilers
(and for clang, which finds their libraries itself). A key left out keeps the built-in value. An unknown lane or
key, a target that is not a triple, or a program or path a generated Makefile
cannot carry is an error before anything builds; bhf prints what each table
selects and names any of its programs that is not installed (the lane's
candidates are then skipped with that reason; only its C++ candidates when
just the C++ compiler is missing). The tables do not apply to a
whole-sweep cross target, which builds every C/C++ candidate itself, and an
auto-loaded `.bhf.toml` ignores them, as it does `[toolchain]`.

### Cross-compilation scope and oracle limitations

These guard-driven strategies cover C and C++ targets. A foreign-platform Ada
target is skipped with an actionable reason unless the sweep has an Ada
toolchain for a target (`[toolchain.ada]`, `--ada-prefix`/`--ada-target`), in
which case every Ada candidate is built for that target and, when the host
cannot run it, fuzzed under the `[toolchain] runner`. Rust
cross-compilation is partial (it shares the qemu-user path), and Java targets
cannot be cross-compiled — they run only on the host JVM.

Emulated targets (qemu-user / wine) run WITHOUT the LD_PRELOAD runtrace shim, so
the behavioral and taint-tracking oracles (BHF-405 path-controlled file access,
BHF-304 command injection, BHF-417 insecure temp files, BHF-305 sensitive-environment
exposure) are unavailable — only crashes and, where the toolchain supports it,
edge coverage and the comparison log (with comparison evidence for each
finding on qemu-user targets) surface. To catch those vulnerability classes,
fuzz the target natively.

The AFL++ secondary engine is native C/C++ only, so cross-compiled or emulated
C/C++ targets — along with all Ada, Rust, and Java targets — fall back to the
built-in engine.

### Prerequisites for the Windows path

```sh
# Debian/Ubuntu
sudo apt-get install gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 wine64
# Initialize the wine prefix once and disable the crash dialog so an unhandled
# guest fault exits fast instead of blocking on a debugger popup (the driver's
# own exception handler already terminates on a fault, but this is belt-and-suspenders):
wineboot -i
wine reg add 'HKCU\Software\Wine\WineDbg' /v ShowCrashDialog /t REG_DWORD /d 0 /f
```

The coverage / cmplog shared-memory maps are backed by real files, so the engine
(running on the Linux host) and the wine'd harness see the same bytes; wine maps
the host root at drive `Z:` so the absolute paths the engine passes resolve.

## Building bhf Natively for Windows

bhf also cross-compiles to a native Windows binary (in addition to Linux):

```sh
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu -p bhf
# -> target/x86_64-pc-windows-gnu/release/bhf.exe
```

`bhf.exe` runs the full CLI on Windows and fuzzes Windows harnesses. With no
POSIX signals on Windows, a harness fault is classified as a crash via the
driver's unhandled-exception exit sentinel (`0x39`). Validated under wine;
on a real Windows host, use clang/mingw for the harness build step.

Current native-Windows scope:

- ✅ Builds clean for `x86_64-pc-windows-gnu`; the CLI + reporting run natively.
- ✅ Fuzzes a built harness and detects crashes.
- ✅ Coverage-guided feedback + the persistent fork-server run on Windows the same
  as on Linux: the shared-memory coverage/cmplog readers are implemented on Win32
  file mapping (`CreateFileMappingW`/`MapViewOfFile`) on both the engine and
  harness sides.

The one native-Windows gap is the LD_PRELOAD runtrace shim, which is Linux-only
(an empty stub on Windows), so the behavioral/taint oracles are unavailable
natively. To get those oracles on a Windows target, run bhf on Linux and let
it cross-compile + emulate the target under wine (the section above). See
[Windows](./windows.md) for the native-host guide.

## Probe Backends

- `host_file` writes the event stream through host file I/O.
- `memory_buffer` keeps events in an exported target memory ring buffer.
- `semihosting` writes through an imported semihosting support hook.
- `stub` preserves testcase result status without emitting an event stream.

To *run* a cross-built harness on a device or full-system emulator and read the
`memory_buffer`/`semihosting` coverage back — the on-device agent, gdb-remote
debug-probe, and `qemu-system` snapshot transports — see
[On-Target & Embedded](../on-target-fuzzing/). This page covers the build and
`qemu-user` replay; that page covers the on-target execution seam.

## qemu-user Replay

```sh
bhf replay --finding F-0001 \
  --harness build/H-TEST/main \
  --qemu-user qemu-aarch64 \
  --qemu-arg=-L \
  --qemu-arg=/usr/aarch64-linux-gnu
```

The runner still passes testcase bytes on stdin and preserves BHF finding
normalization, so host and emulated replay results can be compared. Without
`--qemu-user`, the runner recorded beside the harness (`bhf_runner.json`)
runs it; `bhf fuzz` and `bhf decode-args` take the same `--qemu-user` and
`--qemu-arg` flags.

## Sandbox Execution

Harness execution can be wrapped with a user-installed Linux sandbox:

```sh
bhf replay --finding F-0001 \
  --harness build/H-TEST/main \
  --sandbox firejail \
  --sandbox-tool /usr/bin/firejail \
  --sandbox-strict
```

`--sandbox auto` tries `bwrap` and then `firejail`. Without `--sandbox-strict`,
missing sandbox tooling falls back to direct execution and records
`sandbox.mode = "none"` in fuzz summaries and findings. With strict mode,
BHF reports a clear missing-sandbox error.
