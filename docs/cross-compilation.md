<!-- SPDX-License-Identifier: Apache-2.0 -->

# Ada Cross-Compilation and Probe Backends

This page covers building an Ada harness for another target with GNAT/GPRbuild, the embedded probe backends, and qemu-user replay of an Ada harness. C and C++ cross builds, wine for Windows targets, RTOS platform-stub packs (VxWorks, INTEGRITY, QNX) and whole-sweep cross targets in `bhf auto` are in [Cross-Compilation](site/cross-compilation.md). That page also lists what runs under emulation: Rust cross builds share the qemu-user path, Java runs on the host JVM only, and the LD_PRELOAD runtrace shim (behavioral and taint oracles) and the AFL++ engine run on native targets only.

## Build Flags

`bhf build` takes the target, the Ada runtime and the tool prefix:

```sh
bhf build bhf_work \
  --harness H-TEST \
  --target aarch64-linux-gnu \
  --runtime ravenscar-full \
  --toolchain aarch64-linux-gnu
```

The generated `bhf_build.gpr` then contains:

```gpr
for Target use "aarch64-linux-gnu";
for Runtime ("Ada") use "ravenscar-full";
```

`--toolchain` is the prefix of the executables on `PATH`. With the example above, bhf runs:

- `aarch64-linux-gnu-gprbuild` for the project build, or the multi-target `gprbuild` when there is no prefixed one;
- `aarch64-linux-gnu-gnatmake`, else `aarch64-linux-gnu-gnat`, for the capability canary.

Without `--toolchain`, the `--target` triple is the prefix. Without `--target`, the prefix is the target.

A `--toolchain` value that is a plain identifier, such as `GNAT` or `GNAT_LLVM`, is a gprconfig compiler name. bhf writes it as `for Toolchain_Name ("Ada") use "GNAT";` and does not use it as a prefix. A value with a `-` in it is always a prefix.

`--ada-gprbuild` and `--ada-gnat` name the programs explicitly, and `--ada-switch` appends a compiler switch to bhf's own. The same settings can come from the `[toolchain.ada]` table of a `--config` file; see [Cross-Compilation](site/cross-compilation.md#build-flags).

Before building, the capability probe compiles a small canary unit:

```sh
<prefix>-gnatmake -c -gnatc <dialect> canary.adb
```

When there is no prefixed `gnatmake`, it runs `<prefix>-gnat` with the same switches.

When a required prefixed tool is missing, `bhf build` exits with code `2` and prints:

```text
host toolchain <prefix> for target <target> not found: missing <tool> on PATH
```

`bhf stub` takes the same `--target`, `--runtime`, `--toolchain` and `--probe-backend` flags, so stub generation from build diagnostics uses the same project attributes and compiler.

## Probe Backends

The probe backend is the body of the `AdaFuzz.Probe` runtime package: it decides where the harness writes its coverage and testcase events. Select it with `--probe-backend` on `bhf build` or `bhf stub` (config key `toolchain.ada.probe-backend`):

```sh
bhf build bhf_work \
  --harness H-TEST \
  --target arm-eabi \
  --runtime light-cortex-m3 \
  --toolchain arm-eabi \
  --probe-backend memory_buffer
```

| Backend | Where the events go | Needs |
|---|---|---|
| `host_file` (default) | A file on the host, through host file I/O (`BHF_EVENTS_PATH`) | `Ada.Streams.Stream_IO` and environment access |
| `memory_buffer` | A 64 KiB ring buffer in target RAM | Nothing beyond the runtime |
| `semihosting` | Host file descriptor `2`, through a semihosting call | An `adafuzz_semihosting_write` symbol from the runtime, BSP or link inputs |
| `stub` | No event stream; the result class becomes the process exit status | `Ada.Command_Line` |

bhf copies the selected body into the build's runtime source directory as `adafuzz-probe.adb`, so each build compiles exactly one probe body.

A backend other than `host_file` keeps the events on the target. For an Ada harness built for this host, `bhf build` refuses it with exit code `2`.

### memory_buffer

The `memory_buffer` body compiles the same probe API against the in-RAM ring. It uses neither `Ada.Streams.Stream_IO` nor environment variables. It exports these C symbols for a runner, emulator, JTAG probe or serial drain to read:

- `adafuzz_probe_memory_buffer` (the ring)
- `adafuzz_probe_memory_buffer_capacity`
- `adafuzz_probe_memory_buffer_write` (the write cursor)
- `adafuzz_probe_memory_buffer_wrapped` (set once the ring wraps)

`bhf fuzz --target-transport` with `--transport-coverage-map` reads this ring over a gdb stub, qemu-system or Renode. See [Hardware-in-the-Loop Bring-Up](hil-bringup.md) and [On-Target Fuzzing](site/on-target-fuzzing.md).

### semihosting

The `semihosting` body is for ARM and RISC-V semihosting runs. It writes the same binary event stream to host file descriptor `2` through an imported hook:

```c
void adafuzz_semihosting_write(uint32_t fd, const void *buf, uint32_t len);
```

The target runtime, the BSP or your own link inputs must define this symbol. When nothing defines it, the target link fails.

### stub

The `stub` body is for ROM-only smoke runs. It keeps the `AdaFuzz.Probe` API and the breadcrumb and current-testcase state for instrumented code, and writes no event stream. A top-level harness handler records a failure status, and a nonzero `End_Testcase` result class is passed to `Ada.Command_Line.Set_Exit_Status`. A runner that sees only the process return code still gets a coarse signature class.

## qemu-user Replay

`bhf replay` and `bhf minimize` run an ELF-Linux cross-built harness under a qemu-user emulator:

```sh
bhf replay --finding F-0001 \
  --harness build/H-TEST/main \
  --qemu-user qemu-aarch64 \
  --qemu-arg=-L \
  --qemu-arg=/usr/aarch64-linux-gnu
```

The command line is:

```text
<qemu-user> <qemu-args...> <harness>
```

bhf pipes the testcase bytes to the harness's stdin and sets `BHF_EVENTS_PATH`, so use the `host_file` probe backend for this path.

Without `--qemu-user`, bhf uses the runner that `bhf build --runner` recorded beside the harness (`build/<id>/obj/bhf_runner.json` for an Ada harness). A harness built for another architecture with neither is refused. bhf does not ship qemu: install `qemu-<arch>` or `qemu-<arch>-static` yourself and pass any sysroot or library-path arguments the target needs.

## aarch64 Acceptance Fixture

`examples/swallowed_constraint_error/` is the acceptance fixture for ELF-Linux cross replay. Its generated direct harness reaches a swallowed `Constraint_Error` in `Pkg.Parse`. The test builds and runs the harness on the host, builds it again for `aarch64-linux-gnu`, replays the host finding under qemu-user and checks that the cross run produces the same finding.

Run the test from a bhf source checkout:

```sh
cargo test -p bhf --test m17_aarch64_cross_fixture swallowed_constraint_error_ -- --nocapture
```

The aarch64 case runs only when these tools are installed, and is skipped otherwise:

- the multi-target `gprbuild`
- `aarch64-linux-gnu-gnat` (Ubuntu package `gnat-13-aarch64-linux-gnu`)
- `qemu-aarch64` or `qemu-aarch64-static`

| Variable | Effect |
|---|---|
| `BHF_AARCH64_QEMU_USER` | qemu-user program to use in place of the one found on `PATH` |
| `BHF_AARCH64_SYSROOT` | Sysroot passed to qemu-user as `-L <sysroot>`; defaults to `/usr/aarch64-linux-gnu` when that directory exists |
