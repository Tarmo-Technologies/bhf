<!-- SPDX-License-Identifier: Apache-2.0 -->

# Cross-Compilation

bhf cross-compiles C, C++ and Ada harnesses. `bhf build` and `bhf auto` share one toolchain description: command-line flags, or a `[toolchain]` table in a `--config` file (the table is documented under [Auto: Config file](auto.md#config-file)). Command-line flags override the file key by key, and relative paths in the file resolve against the file's directory.

## Build Flags

A C or C++ harness:

```sh
bhf build bhf_work --harness H-C0001 --target aarch64-linux-gnu
```

| Flag | Effect on a C/C++ harness |
|---|---|
| `--target <triple>` | Selects `<triple>-gcc` / `<triple>-g++`, unless `--cc`/`--cxx` name the compilers; a clang compiler gets `--target=<triple>` instead. |
| `--toolchain <prefix>` | Selects `<prefix>-gcc` / `<prefix>-g++`. |
| `--cc`, `--cxx` | Name the compilers. |
| `--sysroot`, `--cflags`, `--cxxflags`, `--ldflags`, `--define`, `--toolchain-include` | Complete the toolchain. |
| `--runner <program>`, `--runner-arg <arg>` | The emulator that runs a binary built for another target (`--runner-arg` is repeatable). |

A compiler derived from `--cc` or `--target` (`g++` next to a `--cc gcc`) must exist only when a C++ harness needs it, so a toolchain with only a C compiler builds C harnesses. bhf prints the compilers it uses, and the generated Makefile picks GCC- or clang-spelled coverage and sanitizer flags from the compiler that runs.

When the selected compiler builds for a target this host cannot run (judged by its `-dumpmachine`, so a `--toolchain` prefix or a cross `--cc` counts too), `bhf build` says the binary needs an emulator. Name one with `--runner qemu-aarch64` (a qemu-user runner defaults to `-L <sysroot>` or `-L /usr/<triple>` as its arguments), or with `toolchain.runner` and `runner-args` in the config file. bhf records the runner (schema `bhf.harness_runner.v1`) in `build/<id>/bhf_runner.json` and beside the harness; a later native build of the harness drops it. When no `--qemu-user` is given, `bhf replay`, `bhf minimize`, `bhf fuzz`, `bhf decode-args`, `bhf corpus minimize`, `bhf report --backfill` and the finding's `replay.py` run the binary under the recorded runner (see [qemu-user Replay](#qemu-user-replay)).

A runner for a build this host runs natively is an error, as in `bhf auto`. A compiler that does not name its target (`-dumpmachine` fails) keeps the runner, with its `--runner-arg`s, as given. Without a runner, run the binary under an emulator yourself:

```sh
bhf replay --qemu-user qemu-aarch64 --qemu-arg=-L --qemu-arg=/usr/aarch64-linux-gnu ...
```

`[cross.<lane>]` tables in the config file apply to `bhf auto` only; `bhf build` names them and builds with the `[toolchain]` table. `--runtime`, `--probe-backend` and the `--ada-*` flags apply to Ada harnesses only; on a C/C++ harness they are an error.

An Ada harness:

```sh
bhf build bhf_work \
  --harness H-TEST \
  --target aarch64-linux-gnu \
  --runtime light \
  --toolchain aarch64-linux-gnu
```

`--target` and `--runtime` are written into the generated `bhf_build.gpr` as `for Target use` and `for Runtime ("Ada") use`. `--toolchain` is the tool prefix: bhf runs `<prefix>-gprbuild` when it exists and the multi-target `gprbuild` otherwise, and probes the compiler with `<prefix>-gnatmake` (or `<prefix>-gnat`). When `--target` is omitted, the prefix is the target. The prefix is never written as `Toolchain_Name`, because that attribute takes a gprconfig compiler name; a value such as `GNAT` or `GNAT_LLVM` given to `--toolchain` is written as `for Toolchain_Name ("Ada") use` instead. `--ada-gprbuild` and `--ada-gnat` name the programs explicitly, and `--ada-switch` appends compiler switches to bhf's own.

`--runner` and `toolchain.runner` apply to an Ada harness built for another target (the Ada target, else the prefix). bhf records the runner beside the binary (`build/<id>/obj/bhf_runner.json`) and beside the harness, where the same commands find it. A runner for an Ada harness built for this host is an error, as for a C/C++ one.

A `--probe-backend` (or `toolchain.ada.probe-backend`) other than `host_file` keeps the probe events on the target, so it needs a foreign `--target`. For an Ada harness built for this host, `bhf build` refuses it (exit 2), whether it comes from the flag or the config file. A `--probe-backend` given on the command line wins over the config key, `--probe-backend host_file` included.

The generated project `extends` the governing project, so it inherits its `Target`, `Runtime` and source settings. When the parent declares a `package Compiler`, the generated one extends it (`package Compiler extends <Parent>.Compiler is`) and sets `Default_Switches ("Ada")` to the parent's switches followed by bhf's own (`-g`, assertions, coverage, the dialect). A switch the sources need (`-O1`, a `-gnateD` symbol an `#if` tests) and the parent's per-file `Switches` still apply, and bhf's switches win where the two conflict. `bhf build` prints the parent switches it merged. A parent without a `package Compiler` gets bhf's switches alone. Add further switches with `--ada-switch` or `toolchain.ada.switches`.

In a config file, `toolchain.ada.prefix` applies to Ada harnesses only. To choose the compilers of a C/C++ harness there, set `toolchain.target` or `toolchain.cc`/`toolchain.cxx`; `bhf build` notes a prefix that chose nothing.

## Whole-Sweep Cross Targets

`bhf auto` builds every C/C++ candidate for one target when the toolchain names a runner:

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

Each harness is built with the cross compiler and SanitizerCoverage (`trace-pc,trace-cmp` for GCC, `trace-pc-guard,trace-cmp` for clang, when the compiler accepts it) and runs as `<runner> <runner-args> <harness>`, so the sweep is coverage-guided with input-to-state comparison hooks. `run.json`, `finding.json` (`build.binary.coverage_instrumentation`) and the reports name the instrumentation the harness binary carries: `sancov-trace-pc` when GCC's debug information records code compiled with `trace-pc`, and `edge-bitmap` for a build the compiler made without coverage.

ASan is not armed, because its shadow memory does not survive qemu-user. Hard faults are reported as crashes, and `cflags` can add trap-mode checks (`BHF_CROSS_GUARDS=1` arms the probed guard set). With no sanitizer runtime to intercept `memcmp`, `bcmp` and the `str*cmp` family, the harness is linked with `-Wl,--wrap=` for each of them, and bhf's driver reports those comparisons itself, so string and buffer gates still feed the fuzzer's comparison log. Without `runner-args`, a qemu-user runner gets `-L <sysroot>`, or `-L /usr/<triple>` when that directory exists. The triple comes from `--target-triple`, or from `<cc> -dumpmachine` when only `--cc` (or `CC`) names a cross compiler.

bhf records the runner beside each cross-built harness (`bhf_runner.json`). The comparison evidence a finding records after fuzzing (and the evidence `bhf explain` records for a finding that has none) replays the harness under the same emulator, which passes the evidence variable through to it; the capture's `gate_capture.runner` names the emulator. When no `--qemu-user` is given, `bhf replay`, `bhf minimize`, `bhf fuzz`, `bhf decode-args`, `bhf corpus minimize` and `bhf report --backfill` run such a harness under the recorded runner too, and print `note: running <harness> under the recorded runner <program args>`. A binary that `bhf build` staged into `build/<id>/main` uses the runner recorded beside it, else the one in its harness dir. The generated `replay.py` embeds the runner as `RUNNER` (override it with `BHF_REPLAY_RUNNER`). A harness whose ELF machine this host cannot run, with no runner given or recorded, is refused before it runs: `<harness> is built for aarch64; run it under an emulator: --qemu-user qemu-aarch64 [--qemu-arg ...]`.

A trap instruction is a crash: `__builtin_trap` and checks built with `-fsanitize-trap` raise SIGTRAP on AArch64 (SIGILL on x86_64), and both are BHF-210 findings that name their signal. bhf's driver prints the faulting pc for such a crash (see [Sanitizers](sanitizers.md)). An emulated child never gets `abort_on_error=1`: a sanitizer report exits non-zero instead, because a guest abort makes qemu-user spend minutes on its own address space. It also runs with core dumps off. The fidelity record of a cross-sweep finding says the harness was `built for <triple> and run under <runner> user-mode emulation`, gives the target's byte order, and lists only the sanitizer runtimes the binary links (none for a cross sweep, so `sanitizers` is `not_exercised`).

A runner turns the C/C++ sweep into a cross sweep only when the C/C++ toolchain builds for another target: a `target`, or a compiler whose `-dumpmachine` names a triple this host cannot run. A runner given only for a foreign Ada target (`[toolchain.ada] target`) runs the Ada harnesses, with `-L /usr/<ada triple>` for a qemu-user runner (and the C/C++ `sysroot` only when the C/C++ sweep builds for the same triple); the C/C++ candidates keep their native, sanitizer-instrumented builds. A runner with nothing foreign to run is an error.

The reverse is an error too: a target, an Ada target, or a C/C++ compiler (from `--cc`/`--cxx`, the config file or `CC`/`CXX`) that builds for a platform the host cannot run, with no runner, stops the run before anything builds.

### Project builds in a cross sweep

`--probe-build`, `--build-command` and `--run-untrusted` still run the project's build for this host. Its compile database and generated headers apply to the cross sweep. The static archives it builds hold host objects, so bhf rebuilds each one for the target before the sweep: the archives in the probe directory, and the ones the build leaves in the tree (a plain Makefile builds beside its sources) or in its `build/`-style directories.

- Every member is compiled again from its compile-database entry with the cross compiler and the sweep's code-generation flags. The project's defines, include paths and language flags are kept; bhf's host instrumentation, `-march=`/`-mcpu=` and similar flags are dropped. The result, under `<work-dir>/auto/probe-archives/<triple>/`, is linked into the cross-built harnesses.
- A member is found by its object's name. When several translation units write an object of that name (two libraries that each compile a `util.c`), bhf picks the one whose object file, as the build left it, holds the member's bytes.
- An archive that cannot be rebuilt (a member with no compile command or no way to tell its translation unit, a member that does not compile for the target) is named with the reason, and its targets are built from their sources. An archive already built for the target is linked as it is.
- A project archive found in the tree is linked into a cross build only when its objects are for the target's architecture.

The configuration the host build generated (a `config.h`) describes the host, which matters for a target with a different data model. The guard-driven lanes below build their targets from source.

In a native sweep whose toolchain is GCC, the build probe builds the project with that GCC and GCC-spelled sanitizer and `trace-pc` coverage flags, so the archives it leaves link into the GCC-built harnesses. The programs the probe build links on its own (CMake's compiler checks) get no-op coverage hooks, an object kept in the probe directory, or under the system temporary directory when the tree's path has a space or comma.

## Foreign-Platform Targets in `bhf auto`

`bhf auto` keeps foreign-platform code. A function whose definition is guarded by a non-host platform or architecture conditional (a C/C++ `#ifdef _WIN32` / `_MSC_VER`, an Ada `__win32` unit, or a SIMD-architecture backend directory such as `arm64` or `neon`) is discovered, ranked and tagged with a `foreign_guard`. The attempt loop then picks a build and fuzz strategy:

- **Windows (`_WIN32`) C/C++: mingw and wine.** When the `x86_64-w64-mingw32` cross toolchain and `wine` are on `PATH`, the harness is cross-compiled to a Windows PE and fuzzed under wine, which exercises the target's Win32 behaviour. mingw-w64 gcc supports `-fsanitize-coverage=trace-pc,trace-cmp` (the driver implements the guard-less `__sanitizer_cov_trace_pc` hook), so the engine gets edge coverage and input-to-state feedback. mingw has no ASan runtime, so the driver installs an unhandled-exception filter: a hardware fault (access violation, stack overflow and so on) becomes an immediate, distinctive process exit that the engine classifies as a crash.
- **Architecture/SIMD (aarch64, armhf, neon): cross toolchain and qemu-user.** A 64-bit ARM or NEON guard builds with `aarch64-linux-gnu-gcc` under `qemu-aarch64`; a 32-bit ARM (armv7/armhf) guard builds with `arm-linux-gnueabihf-gcc` under `qemu-arm`. The build arms GCC's `trace-pc,trace-cmp` coverage when the cross compiler accepts it, so the emulated harness is fuzzed coverage-guided. ASan does not survive qemu-user and stays off; hard crashes surface as SIGSEGV or SIGABRT.
- **Windows fallback: native stub-isolated build.** When mingw or wine is absent, a `_WIN32` C/C++ target (not Ada or Rust) is built natively with `_WIN32` defined and a synthesized `<windows.h>`, so its portable logic type-checks and fuzzes with host ASan and coverage. Findings are flagged REDUCED-FIDELITY: the platform surface is faked, handles are inert, and Win32 behaviour is not modelled.
- **No strategy: a skip with the fix.** A guard with neither a platform stub nor an installed cross toolchain is skipped, with a reason naming what to install.

### Overriding the Toolchain for a Lane

Each guard-driven lane has a built-in toolchain and emulator: `mingw` (`x86_64-w64-mingw32-gcc`, `wine`), `aarch64` (`aarch64-linux-gnu-gcc`, `qemu-aarch64`), `armhf` (`arm-linux-gnueabihf-gcc`, `qemu-arm`), and `ppc64le`, `ppc64`, `ppc`, `mipsel`, `mips` and `sparc64` (`<triple>-gcc`, `qemu-<arch>`). A `[cross.<lane>]` table in an explicit `--config` replaces any of them for the candidates that lane takes:

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

| Key | Effect |
|---|---|
| `target` | The triple; without `cc`/`cxx` it also selects `<target>-gcc` / `<target>-g++`. |
| `cc`, `cxx` | The compilers; one given alone selects its pair. A clang `cc` builds for the lane's triple: bhf adds `--target=<triple>` to every compile and link, and links no clang sanitizer runtime (a foreign target has none). |
| `sysroot` | Passed to every compile and link as `--sysroot=`, bhf's driver object included, and to a qemu-user runner without `runner-args` as `-L`. |
| `runner`, `runner-args` | Replace the emulator and its arguments. |

The lane's `--sysroot=` and `--target=` replace a `[toolchain]` sysroot or target for its candidates. A key left out keeps the built-in value. A distribution's multiarch directory (`/usr/aarch64-linux-gnu`) is not a sysroot: its `libc.so` names absolute paths that a `--sysroot=` link cannot find. Leave `sysroot` out for the distribution's own cross compilers, and for clang, which finds their libraries itself.

An unknown lane or key, a target that is not a triple, or a program or path a generated Makefile cannot carry is an error before anything builds. bhf prints what each table selects and names any of its programs that is not installed; the lane's candidates are then skipped with that reason (only its C++ candidates when only the C++ compiler is missing). The tables do not apply to a whole-sweep cross target, which builds every C/C++ candidate itself. An auto-loaded `.bhf.toml` ignores them, as it ignores `[toolchain]`.

### Cross-compilation scope and oracle limitations

The guard-driven strategies cover C and C++ targets. A foreign-platform Ada target is skipped with a reason, unless the sweep has an Ada toolchain for a target (`[toolchain.ada]`, `--ada-prefix`/`--ada-target`). Then every Ada candidate is built for that target and, when the host cannot run it, fuzzed under the `[toolchain] runner`. Rust harnesses build for the host triple, and Java targets run on the host JVM.

Emulated targets (qemu-user, wine) run without the LD_PRELOAD runtrace shim. Their findings are crashes, with edge coverage and the comparison log where the toolchain supports them, and comparison evidence for each finding on qemu-user targets. The behavioural and taint oracles (BHF-405 path-controlled file access, BHF-304 command injection, BHF-417 insecure temporary files, BHF-305 sensitive-environment access) need a native run of the target.

The AFL++ engine runs native C/C++, COBOL, Fortran, Rust and Ada targets. Cross-compiled and emulated targets, and the targets of the other lanes, use the built-in engine.

### Prerequisites for the Windows path

```sh
# Debian/Ubuntu
sudo apt-get install gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 wine64
# Optional: turn off Wine's crash dialog. The driver's exception handler
# already ends the harness on a fault; this stops a debugger popup on a
# desktop if a fault gets past it.
wine reg add 'HKCU\Software\Wine\WineDbg' /v ShowCrashDialog /t REG_DWORD /d 0 /f
```

Wine keeps its settings in a prefix directory, `$WINEPREFIX` or `~/.wine` by default. When the prefix does not exist yet, bhf creates it before the first harness runs under Wine and prints `bhf: creating the Wine prefix ...`. This applies to `bhf auto` and to every command that runs a harness under Wine: `bhf replay`, `bhf minimize`, `bhf fuzz`, `bhf decode-args`, `bhf corpus minimize`, `bhf report --backfill`, and `bhf binary fuzz --runner wine` (which `bhf project` uses), so a finding replays on a machine that has never run Wine. bhf runs `wine wineboot --init`, then `wineserver --wait`, with `WINEDEBUG=-all`. It skips Wine's Mono and Gecko add-ons, which a harness does not use, unless `WINEDLLOVERRIDES` is already set. Creating a prefix takes about 15 seconds and does not count against `--per-target-time`. If the prefix exists, bhf checks only that its `system.reg` file is there. If Wine fails to create the prefix, or takes more than 5 minutes, `bhf auto` reports the target as `missing_toolchain` with Wine's own error text and does not try again for the run's other Windows targets; the other commands stop with that error. To create a prefix yourself, run `WINEPREFIX=<dir> wineboot --init`.

The coverage and cmplog shared-memory maps are backed by real files, so the engine (running on the Linux host) and the harness under wine see the same bytes. wine maps the host root at drive `Z:`, so the absolute paths the engine passes resolve.

## Building bhf Natively for Windows

The release ships native MSVC builds of `bhf.exe` and the daemon; see [Windows](windows.md) for installing and running them. To build a Windows `bhf.exe` on Linux instead:

```sh
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu -p bhf
# -> target/x86_64-pc-windows-gnu/release/bhf.exe
```

On Windows a harness fault has no POSIX signal, so the driver's unhandled-exception handler exits with the sentinel code `0x39`, which bhf classifies as a crash. Coverage-guided feedback and the persistent fork-server work as on Linux: the shared-memory coverage and cmplog maps use Win32 file mapping (`CreateFileMappingW`/`MapViewOfFile`) on both the engine and the harness side. The LD_PRELOAD runtrace shim is Linux-only, so its behavioural and taint oracles do not run on native Windows; the [Windows](windows.md) guide describes the runtime-event collector that covers some of them.

## Probe Backends

These apply to Ada harnesses (`--probe-backend`):

- `host_file` (default) writes the event stream through host file I/O.
- `memory_buffer` keeps events in an exported ring buffer in target memory.
- `semihosting` writes through an imported semihosting support hook.
- `stub` keeps the testcase result status without emitting an event stream.

To run a cross-built harness on a device or a full-system emulator and read the `memory_buffer` or `semihosting` coverage back (the on-device agent, the gdb-remote debug probe and the `qemu-system` snapshot transports), see [On-Target & Embedded](on-target-fuzzing.md). This page covers the build and `qemu-user` replay.

## qemu-user Replay

```sh
bhf replay --finding F-0001 \
  --harness build/H-TEST/main \
  --qemu-user qemu-aarch64 \
  --qemu-arg=-L \
  --qemu-arg=/usr/aarch64-linux-gnu
```

The runner passes testcase bytes on stdin and keeps bhf's finding normalization, so host and emulated replay results compare directly. Without `--qemu-user`, the runner recorded beside the harness (`bhf_runner.json`) runs it. `bhf fuzz` and `bhf decode-args` take the same `--qemu-user` and `--qemu-arg` flags.

## Sandbox Execution

Harness execution can run inside a Linux sandbox you have installed:

```sh
bhf replay --finding F-0001 \
  --harness build/H-TEST/main \
  --sandbox firejail \
  --sandbox-tool /usr/bin/firejail \
  --sandbox-strict
```

`--sandbox` takes `none`, `auto` (the default), `firejail` or `bubblewrap`; `auto` tries `bwrap` and then `firejail`. Without `--sandbox-strict`, missing sandbox tooling falls back to direct execution and records `sandbox.mode = "none"` in fuzz summaries and findings. With `--sandbox-strict`, bhf stops with a missing-sandbox error.
