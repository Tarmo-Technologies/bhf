<!-- SPDX-License-Identifier: Apache-2.0 -->
# On-Target & Embedded Fuzzing (RTOS / radar / firmware)

BHF builds, harnesses, and fuzzes code that does not run as an ordinary x86-64
Linux process. The **targets it aims at** are RTOS images (VxWorks, Green Hills
INTEGRITY, QNX, RTEMS, FreeRTOS), Cortex-M / ARM / PowerPC / MIPS / SPARC
firmware, radar and other message- and register-driven embedded software, and
big-endian targets. What is **validated today** is narrower than that list — see
the support matrix below before you rely on a mode: only host stubs, `qemu-user`
ISA testing, the debug-probe/gdbstub path, and full-system **bare-metal**
Cortex-M are proven under emulation; proprietary RTOS execution, the on-target
agent, and physical boards are built-and-harnessed but **unproven** until you run
them against the resource. This page explains **what** the embedded lane is and
gives the exact commands to **set up and run** each mode.

For host-side cross-*build* mechanics (toolchains, `qemu-user` replay,
sandboxing) see [Cross-Compilation](../cross-compilation/); this page covers the
on-target *execution* seam that runs a harness on a device or full-system
emulator and reads coverage back.

> **Fidelity first.** Every finding records what was and was not exercised
> (arch, endianness, RTOS runtime, hardware, concurrency). A clean host-stub run
> is never reported as target assurance. BHF ships **no** proprietary RTOS
> images or vendor toolchains — you bring those; BHF brings the harnessing,
> transport, and coverage.

---

## How it fits together

An embedded campaign has two halves:

1. **Front half — build & instrument.** BHF generates a harness for the target
   entry point, cross-builds it with your toolchain, and compiles in a coverage
   *probe backend* (semihosting or an in-RAM ring buffer) plus SanitizerCoverage
   trace-pc/trace-cmp instrumentation. For a target guarded by a vendor header it
   can also drop declaration-only fake headers and fuzz the portable algorithmic
   body on the host under sanitizers ("stub-isolation lane").
2. **Back half — execute & harvest.** The `--target-transport` seam delivers an
   input, triggers one execution on the real target (on-device agent, debug
   probe/emulator over gdb-remote, or a full-system `qemu-system` guest), and
   reads back coverage + status + faults. The built-in engine consumes all
   transports through one trait and stays backend-agnostic.

Pick a mode by how much of the real target you can run. **Validated** states
what has been proven under emulation on the dev lane (see *What is and isn't
proven*); the rest is built and harnessed but you prove it against your resource.
All of this lives on `main`; it is not a claim about any particular published
binary release.

| You have… | Mode | Fidelity | Validated |
|---|---|---|---|
| Only source, no device/emulator | **Host stub-isolation** (default) | Portable logic only, on x86-64 under ASan/UBSan | ✅ in-tree |
| A cross toolchain + `qemu-user` | **qemu-user replay** (see Cross-Compilation) | Real ISA/endianness, no RTOS/peripherals | ✅ RV-1 (`qemu-ppc64`) |
| A gdbstub (OpenOCD/J-Link/QEMU) | **Debug-probe / gdb-remote** | Real target memory + coverage ring | ✅ RV-2 (`qemu-arm`); real board gated |
| A cross toolchain + `qemu-system` | **Full-system emulator (bare-metal)** | Real core, MMIO, interrupts, snapshot reset | ✅ RV-3 (`qemu-system-arm`, bare-metal Cortex-M — **not** an RTOS) |
| An open RTOS (FreeRTOS) | **Actual RTOS execution** | Scheduler / tasks / queues | ✅ FreeRTOS reference profile (`crates/target_transport/tests/freertos/`): cooperative Cortex-M3 image build, boot, snapshot reset, task/queue input drive, HardFault classification, and clean → fault → clean CLI test under `qemu-system-arm`. Kernel is bring-your-own (not vendored); physical boards and other RTOSes are unvalidated. |
| A proprietary RTOS image | **Actual RTOS execution** | VxWorks/INTEGRITY/QNX scheduler | ⛔ unproven (bring the image + toolchain) |
| An on-device agent (TCP/serial) | **On-target agent** | Real device; coverage over the agent protocol | ⛔ unproven |
| A physical board | **HIL** (hardware-in-the-loop) | Silicon | ⛔ unproven (`BHF_HIL_GDB`) |

---

## 1. Host stub-isolation (default, no hardware)

The zero-setup path. BHF defines the vendor platform guard, stubs the vendor
headers (handles are inert — reduced fidelity), and fuzzes the portable body on
the host. Nothing extra to install.

```sh
bhf auto ./firmware-src --target parse_track_msg
```

RTOS/hardware behavior is **not** modeled here; use it to shake out the
algorithmic bugs (parsers, decoders, state machines) before you have a device.

---

## 2. Cross-build for the target

Cross-building is driven by three `bhf build` flags (and works under `bhf auto`
once the toolchain is on `PATH`):

```sh
# Bare-metal Cortex-M3 (matches the qemu-system mps2-an385 example below).
# --target        target triple / default tool prefix (looks for arm-eabi-*)
# --runtime       Ada runtime passed through the generated GPR (Ada targets)
# --toolchain     tool prefix when it differs from --target
# --probe-backend how the target emits coverage (see below)
bhf build bhf_work --harness H-C0001 \
  --target arm-eabi \
  --runtime light-cortex-m3 \
  --toolchain arm-eabi \
  --probe-backend memory_buffer
```

When `--toolchain` is omitted the `--target` triple is used as the tool prefix.
Common triples: `arm-eabi`, `aarch64-linux-gnu`, `powerpc64-linux-gnu`,
`mips-linux-gnu`; Ada runtimes: `ravenscar-full`, `light-cortex-m3`.

### Probe backends (`--probe-backend`)

The coverage channel compiled into the harness runtime:

| Backend | Use when | Coverage path |
|---|---|---|
| `host_file` (default) | host / qemu-user | event stream via host file I/O |
| `memory_buffer` | on-target, no I/O | in-RAM ring buffer read back over the transport |
| `semihosting` | emulator/probe with semihosting | events over the semihosting hook |
| `stub` | smoke build | result status only, no event stream |

For the `gdb` and `qemu-system` transports use `memory_buffer` — the host reads
the ring out of target memory (see the coverage-map spec below).

### Vendor RTOS build systems

If the target uses a vendor toolchain or an unusual build, recover its real
compile wiring with `bhf auto --build-command`, which interposes on `cc`/`gcc`/
`clang` **and** named vendor compilers (Wind River Diab, Green Hills, QNX,
Keil/IAR, TI) plus cross-prefixed GNU/LLVM:

```sh
# --extra-include  real struct layouts/typedefs from SDK/BSP headers
# --sanitizers none  crash-only; no ASan FP-storm on RTOS code
bhf auto ./rtos-app --build-command "make CROSS=arm-none-eabi-" \
  --extra-include /opt/vendor-sdk/include \
  --sanitizers none
```

`--extra-include` points at SDK/BSP headers outside the swept tree (e.g. cFE
OSAL/PSP). `--sanitizers none` builds coverage-only — the escape hatch for
shared-memory / custom-allocator / RTOS code that false-positives under ASan.

---

## 3. On-target execution: `bhf fuzz --target-transport`

`--target-transport <SPEC>` runs the fuzz loop against an off-host backend
instead of the host libFuzzer/AFL lane. It is **additive**: absent, the host
path is byte-for-byte unchanged. A malformed spec is a descriptive error. The
memory-read transports (`gdb`, `qemu-system`) also need `--transport-coverage-map`
to locate the on-target coverage ring.

### Coverage-map spec

For `gdb` and `qemu-system`, tell BHF where the `memory_buffer` ring lives
(addresses are decimal or `0x`-hex, from your linker map / `nm`):

```
--transport-coverage-map input=<addr>,ring=<addr>,write=<addr>,wrapped=<addr>,cap=<n>
```

- `input`   — where BHF writes the fuzz input on the target
- `ring`    — base of the coverage ring
- `write`   — the ring's write cursor
- `wrapped` — the ring's wrapped flag
- `cap`     — ring capacity in **bytes** (the length read back), not a record count

The `agent` transport carries coverage over its own protocol and rejects this
option.

### 3a. Debug probe / emulator gdbstub (`gdb:HOST:PORT`)

Drives the real gdb-remote (RSP) client against any gdbstub — OpenOCD, J-Link
GDB server, or a `qemu-*` `-g` stub.

```sh
# e.g. a qemu-user or qemu-system gdbstub on :3333, memory_buffer harness built at §2
bhf fuzz bhf_work --harness H-C0001 \
  --target-transport gdb:127.0.0.1:3333 \
  --transport-coverage-map input=0x2000020c,ring=0x20000004,write=0x20000204,wrapped=0x20000208,cap=512
```

### 3b. Full-system emulator (`qemu-system:qmp=…,gdb=…[,snapshot=TAG]`)

The flagship path: boot a `qemu-system-*` guest, attach QMP + gdb, take a
`savevm` baseline, then per input `loadvm`-reset → write input → run → read the
coverage ring. Deterministic and reset-clean. The CLI parses **TCP** `HOST:PORT`
endpoints for both `qmp=` and `gdb=` (there is no Unix-socket form), so expose
QMP over TCP.

The spec's completion-contract keys make the shipped CLI self-sufficient on a
Cortex-M — no out-of-band debugger needed:

- `done=<addr>[,done_kind=<n>]` — BHF plants a gdbstub breakpoint at the
  harness-done symbol (default `done_kind=2`, ARM Thumb) so `continue` returns
  each iteration. A Cortex-M cannot self-halt with `bkpt` under the QEMU gdbstub
  (it escalates to a HardFault), so this is required there; `--timeout` bounds a
  missing one instead of hanging.
- `fault=<addr>[,fault_width=4,fault_clear=0]` — the firmware fault-status word.
  A fault handler that returns through `done` reports a benign `SIGTRAP`, so BHF
  reads this word and classifies a recorded fault as a crash rather than a silent
  clean pass.

Pinned example (QEMU 8.2.2 + `arm-none-eabi-gcc`; the exact mps2-an385 fixture
and symbol discovery used by the live RV-3 test — see
`docs/validation/2026-09-27-hil-emu-live-qemu.md`):

```sh
# scratch drive so savevm works even on a diskless -kernel boot; QMP over TCP
qemu-system-arm -M mps2-an385 -kernel harness.elf -S \
  -gdb tcp::3333 -qmp tcp:127.0.0.1:4444,server,nowait \
  -drive if=none,file=scratch.qcow2,format=qcow2,id=sc0 &

# done=/fault= are the harness_done and bhf_fault_flag addresses from `nm harness.elf`
bhf fuzz bhf_work --harness H-C0001 \
  --target-transport "qemu-system:qmp=127.0.0.1:4444,gdb=127.0.0.1:3333,snapshot=base,done=0x1a8,fault=0x20000100" \
  --transport-coverage-map input=0x2000020c,ring=0x20000004,write=0x20000204,wrapped=0x20000208,cap=512
```

`savevm` needs a block device (attach a small scratch `qcow2` even for a diskless
`-kernel` boot) — the transport handles the rest.

### 3c. On-target agent (`agent:tcp:HOST:PORT` / `agent:serial:/dev/ttyX`)

For a device running a small BHF agent that receives inputs and streams edges +
faults back over TCP or serial. No coverage-map needed — coverage rides the
agent protocol.

```sh
bhf fuzz bhf_work --harness H-C0001 --target-transport agent:tcp:192.0.2.10:9000
bhf fuzz bhf_work --harness H-C0001 --target-transport agent:serial:/dev/ttyUSB0
```

---

## 4. Faults and the real-time deadline oracle

**On-target faults → findings.** Beyond a host POSIX signal, BHF maps
target-side faults into findings through the transport: a Cortex-M CPU
exception / hard-fault vector or an MMU/MPU fault becomes a classified crash,
a watchdog reset or a deadline overrun a timing/availability finding (BHF-555),
and a reachable assertion a CWE-617 finding — backend-neutral, so the same input
that faults on a board, an emulator, or the host is reported the same way, and a
fault that ran no sanitizer is never tagged as one. A fault whose handler returns
through the completion breakpoint needs the `fault=` status word (see §3b) to be
observable. The emulator validation (RV-3) asserts this end to end: input `0xF7`
vectors to `HardFault_Handler` and is recorded as a classified crash through
`RunOutcome.fault`, not a silent pass — and a clean input after it does not
inherit the fault.

**Timing oracle (`--deadline`).** Real-time targets fail by *overrunning a
budget*, not only by crashing. `bhf fuzz --deadline <D>` records any completed
input whose execution exceeds `D` as a **BHF-555** finding (CWE-400
timing/availability) instead of discarding it as a slow unit the way `--timeout`
does. It applies on the `--target-transport` loop (measured as host-observed
round-trip time) as well as the host lane, and `--timeout` bounds each on-target
execution so a hung target is a distinct, non-clean outcome rather than a
campaign that never returns:

```sh
bhf fuzz bhf_work --harness H-C0001 --deadline 1s          # >1s response = finding
BHF_DEADLINE_MS=250 bhf fuzz bhf_work --harness H-C0001    # sub-second budget
```

Use it for watchdog / control-loop / radar-frame deadlines where a late answer
is a defect. Off by default — unset, hang handling is byte-for-byte unchanged.

---

## 5. Big-endian & non-x86 fidelity

BHF emits target-byte-order struct images and matches the target ABI, so a
big-endian-only bug (e.g. a field byte-swapped only on PPC) is reachable under
`qemu-ppc64` / a PPC gdbstub where it would be invisible on the little-endian
host. Cross-build with a big-endian triple (`powerpc64-linux-gnu`, `mips-linux-gnu`)
and run it through a transport from §3.

## 6. Comparison-progress for format gates

Multi-byte magic/format gates (headers, checksummed frames) give a whole-compare
edge no gradient. Add laf-intel comparison-progress so an input that matches one
more leading byte is retained and energized:

```sh
bhf auto ./firmware-src --comparison-progress   # alias: --cmp-progress
```

Composes with cmplog/RedQueen (armed by default), value-profile, and the
hit-count buckets.

---

## 7. HIL: fuzzing a physical board over gdb-remote

Hardware-in-the-loop reuses the exact `gdb:` transport from §3a against a real
board's gdbstub (e.g. an ST Nucleo via OpenOCD on `:3333`). Full bring-up —
bill of materials, toolchain, the firmware contract the on-board harness must
expose, and run-control differences between real silicon and an emulated core —
is in the HIL bring-up runbook checked in at `docs/hil-bringup.md` in the
BHF repository. In brief:

1. Flash a harness whose memory map exports the input region and a
   `memory_buffer` coverage ring, and that halts at a known `harness_done` symbol.
2. Start OpenOCD/gdbserver; note the input/ring/write/wrapped addresses from your
   linker map.
3. Point BHF at the stub:

```sh
bhf fuzz bhf_work --harness H-C0001 \
  --target-transport gdb:127.0.0.1:3333 \
  --transport-coverage-map input=0x2000020c,ring=0x20000004,write=0x20000204,wrapped=0x20000208,cap=512
```

---

## 8. Verifying the emulator lane locally

`scripts/hil-emu.sh` runs the real (non-skippable) live-QEMU validations —
big-endian PPC64 fidelity (RV-1), the gdb-remote client against a real
`qemu-arm` stub (RV-2), and the full-system Cortex-M snapshot path with a
planted HardFault (RV-3), and the pinned FreeRTOS task/queue profile with
CLI finding and replay (RV-4). It **hard-fails** if a required tool is missing so the
lane cannot silently skip:

```sh
BHF_HIL_REQUIRE=1 scripts/hil-emu.sh
```

Prerequisites (Debian/Ubuntu): `qemu-system-arm qemu-user qemu-utils
gcc-arm-none-eabi libnewlib-dev libnewlib-arm-none-eabi gcc-arm-linux-gnueabihf gcc-powerpc64-linux-gnu binutils`.
RV-1 through RV-3 were validated on QEMU in September 2026 (see
`docs/validation/2026-09-27-hil-emu-live-qemu.md`). RV-4 passed locally on
October 4, 2026; hosted HIL-emu workflow evidence remains pending.

---

## What is and isn't proven

- **Validated live on emulators (2026-09-27, QEMU 8.2.2):** the transport
  layer's own live lane passed — cross-endian fidelity (RV-1, `qemu-ppc64`), the
  gdb-remote client + coverage read (RV-2, `qemu-arm` gdbstub), and the
  full-system snapshot + coverage-ring + planted-fault path (RV-3,
  `qemu-system-arm`). Evidence: `docs/validation/2026-09-27-hil-emu-live-qemu.md`.
- **The `--target-transport` CLI flag is wired to those same backends:** it
  parses the spec (including the `done=`/`fault=` completion contract), bounds
  each connection/read/write (`--timeout`), and dials the resource on the first
  execution (a dead endpoint fails with a connection error, not
  "unimplemented"). A gated end-to-end test (`transport_fuzz_qemu_cli`, present
  when `qemu-system-arm` + `arm-none-eabi-gcc` are installed) drives the real
  mps2-an385 fixture through the shipped `bhf fuzz --target-transport
  qemu-system:…` binary and asserts it plants the breakpoint itself and persists
  a classified fault finding. Running the CLI against *your* live stub/emulator
  or board remains the dependency-gated step you perform with the resource.
- **Still gated (unproven until you run it against the resource):** a live
  physical board (`hil_board.rs` + `BHF_HIL_GDB`), the TCP/serial `agent`
  transport, proprietary RTOS images / vendor toolchains (BHF ships none — bring
  your own), and Renode.
- **Non-goals:** BHF does not bundle or crack vendor toolchains, ship RTOS
  images, or act as a full-system emulator (it integrates `qemu-system`/Renode,
  it does not replace them).
