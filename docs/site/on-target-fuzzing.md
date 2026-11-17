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
| An on-device agent (TCP/serial) | **On-target agent** | Real device; coverage over the agent protocol | ⛔ unproven: the host side ships; no target-side agent does yet ([#289](https://github.com/Tarmo-Technologies/bhf/issues/289)), so you write one to the frame format in §3c |
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
| `semihosting` | emulator/probe with semihosting | events over the semihosting hook; **not read yet**: no transport decodes this output ([#292](https://github.com/Tarmo-Technologies/bhf/issues/292)), so a campaign over it runs without coverage |
| `stub` | smoke build | result status only, no event stream |

For the `gdb` and `qemu-system` transports use `memory_buffer` — the host reads
the ring out of target memory (see the coverage-map spec below). It is the only
backend a transport reads today.

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
--transport-coverage-map input=<addr>,input_cap=<n>[,input_len=<addr>],ring=<addr>,write=<addr>,wrapped=<addr>,cap=<n>
```

- `input`   — where BHF writes the fuzz input on the target
- `input_cap` — the size in bytes of the staging buffer at `input`
  (required). BHF never writes past it: `--max-len` is cut to it (with a
  note), and an input longer than it (a seed) is written only up to it. An
  input written past the buffer would overwrite the guest globals after it,
  and when the next one is the `fault=` word every such input reads as a CPU
  exception. Each finding's `transport_profile.json` records the capacity.
- `input_len` — optional: the address of a little-endian `u32` the firmware
  reads the input's length from. BHF writes it before the input each run.
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
  --transport-coverage-map input=0x2000020c,input_cap=64,ring=0x20000004,write=0x20000204,wrapped=0x20000208,cap=512
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
  --transport-coverage-map input=0x2000020c,input_cap=64,ring=0x20000004,write=0x20000204,wrapped=0x20000208,cap=512
```

`savevm` needs a block device (attach a small scratch `qcow2` even for a diskless
`-kernel` boot) — the transport handles the rest.

**Task identity.** `task_id=ADDR` (on `qemu-system:` and `gdb:`) names a
32-bit word the firmware sets to the task that runs the input, such as the
FreeRTOS handle `xTaskGetCurrentTaskHandle()` returns. BHF reads it after each
run and records it in a fault finding as `target_task.id`.

**Firmware identity.** `firmware=PATH` (on `qemu-system:`, and as
`gdb:HOST:PORT,firmware=PATH`) names the ELF the target runs. Before anything
connects, BHF reads it and records in each finding's `finding.json` and
`transport_profile.json` a `firmware_identity` block:

- its SHA-256, size, architecture and GNU build-id;
- the toolchain its `.comment` names (`GCC 13.2.1`);
- the RTOS version string it carries: FreeRTOS's
  `"FreeRTOS Kernel " tskKERNEL_VERSION_NUMBER`, or Zephyr's
  `Zephyr OS build v…` banner.

An image it cannot read, or one that is not an ELF file, stops the run with
exit 2. `bhf replay` warns when the image at that path no longer has the
recorded SHA-256. FreeRTOS keeps no version string in an image unless the
application references one; the reference profile's `app.c` keeps
`bhf_kernel_version` for this. Without `firmware=`, the profile says that no
identity was recorded.

### 3c. On-target agent (`agent:tcp:HOST:PORT` / `agent:serial:/dev/ttyX[,baud=N]`)

For a device running an agent that receives inputs and streams edges and
faults back over TCP or serial. No coverage-map needed — coverage rides the
agent protocol.

```sh
bhf fuzz bhf_work --harness H-C0001 --target-transport agent:tcp:192.0.2.10:9000
bhf fuzz bhf_work --harness H-C0001 --target-transport agent:serial:/dev/ttyUSB0,baud=115200
```

BHF opens a serial port raw: 8N1, no flow control, no echo, no line editing
and no newline translation, so every frame byte crosses unchanged, at
`baud=` when given and otherwise at the port's current rate. Each read ends at
`--timeout`, so a silent device stops the run instead of hanging it. On Linux
and macOS the device is a tty path; on Windows it is a COM port (`COM3`,
`COM10`).

BHF ships a reference target-side agent in freestanding C99,
`c_runtime/bhf_agent.{h,c}`: no heap, and no libc beyond `<stdint.h>`,
`<stddef.h>` and `<setjmp.h>`. The board gives it:

- read and write callbacks over its UART, socket or debug channel;
- an input buffer (a longer input is refused, not run);
- an edge buffer;
- the function under test, which has `LLVMFuzzerTestOneInput`'s signature.

Build the code under test with `-fsanitize-coverage=trace-pc-guard`. The
agent provides the SanitizerCoverage callbacks and reports each guard an input
reaches once. Build the agent itself without them. A fault vector or signal
handler calls `bhf_agent_fault(kind, addr, detail)`: the agent reports the
fault for the running input and goes on with the next, returning from the
handler by `longjmp`. On a target where that is not safe, define
`BHF_AGENT_NO_SETJMP`, reset, and report the fault the reset kept.
`c_runtime/examples/agent_posix.c` runs it on a POSIX host for `agent:tcp`:

```sh
cc -c c_runtime/bhf_agent.c
cc -I c_runtime -c c_runtime/examples/agent_posix.c
clang -fsanitize-coverage=trace-pc-guard -c target.c   # defines LLVMFuzzerTestOneInput
cc -o agent agent_posix.o bhf_agent.o target.o
./agent 9000 &
bhf fuzz bhf_work --harness H-agent --target-transport agent:tcp:127.0.0.1:9000 --max-len 4096
```

Set `--max-len` to the agent's input buffer. An agent that implements the
protocol itself uses this frame format. Every integer is little-endian, one
round trip per input:

| Direction | Field | Size | Meaning |
|---|---|---|---|
| host → target | `len` | `u32` | input length in bytes |
| host → target | `input` | `len` bytes | the input |
| target → host | `status` | `u32` | `0` ran to completion, `1` crashed, `2` timed out, `3` refused: the input is longer than the agent's buffer and was read and dropped, not run (the run is inconclusive); any other value is a protocol error |
| target → host | `n_edges` | `u32` | number of coverage edges that follow |
| target → host | `edges` | `n_edges` × `u32` | the edge ids this input hit |
| target → host | `fault_present` | `u32` | `1` when a fault block follows, else `0` |
| target → host | `kind` | `u32` | fault kind: `0` CPU exception, `1` memory protection, `2` watchdog, `3` assertion/panic, `4` stack overflow, `5` timeout; another value is kept as-is |
| target → host | `addr` | `u64` | faulting address, `0` when none applies |
| target → host | `detail_len` | `u32` | length of the detail text |
| target → host | `detail` | `detail_len` bytes | a short description of the fault |

The `kind`, `addr`, `detail_len` and `detail` fields are sent only when
`fault_present` is `1`. The host refuses an input over 16 MiB, more than 2^20
edges or a detail over 64 KiB before it allocates. The agent has no stdout
channel.

### 3d. Protocol sessions on the target

A stateful command set on the board is fuzzed as sessions by naming the
transport in `--session-transport transport:<spec>` with a protocol profile
(see the [CLI reference](cli.md)):

```sh
bhf fuzz bhf_work --harness H-CMD --protocol-profile profiles/cmd.toml \
  --session-transport transport:agent:tcp:192.168.1.50:7000 --iterations 5000
```

Each message of a session is one execution through the backend, in order:
the agent or the harness reads it as its input. A fault, a crash or a hang at
a message ends the session there; bhf drives the session again on a fresh
target session, and a fault at the same message is a finding with the
session and the fault in its detail, which `bhf replay` reproduces. The
executions' edges feed the session lane's code channel (`coverage_source`
`target`), so a session that reaches new firmware code is kept. A reply is
the backend's stdout, which the agent does not have: a profile over the
agent captures nothing from replies and its oracles are the faults. The
`gdb` and `qemu-system` backends take `--transport-coverage-map` here as
they do for `--target-transport`. `--session-reset reconnect` (the default)
arms a fresh target session for each protocol session; `none` keeps one
armed for the campaign.

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
timing/availability), where `--timeout` only kills a slow unit. It applies on
the `--target-transport` loop (measured as host-observed round-trip time) as
well as the host lane, and `--timeout` bounds each on-target execution so a
hung target is a distinct, non-clean outcome rather than a campaign that never
returns. On the host lane an overrun is re-run in up to three fresh processes
and is a finding only when two of them overrun `D` too, so one run slowed by a
loaded host is not; the finding's `deadline_confirmation` records the
deadline, each re-run's time (`rerun_ms`) and how many overran it:

```sh
bhf fuzz bhf_work --harness H-C0001 --deadline 1s          # >1s response = finding
BHF_DEADLINE_MS=250 bhf fuzz bhf_work --harness H-C0001    # sub-second budget
```

Use it for watchdog / control-loop / radar-frame deadlines where a late answer
is a defect. Off by default — unset, hang handling is byte-for-byte unchanged.

**Target time (`cycles=`, `cpu_hz=`).** The host's round-trip time includes the
debugger link, the reset and the host's load. On the `gdb:` and `qemu-system:`
transports, `cycles=dwt` reads the Cortex-M DWT cycle counter around each run
instead: BHF enables it (`DEMCR.TRCENA`, `DWT_CTRL.CYCCNTENA`) and zeroes it
after delivering the input. `cycles=ADDR` reads a free-running 32-bit up-counter
at `ADDR` before and after the run. With `cpu_hz=N`, the counter's rate,
`--deadline` times each run by the target (the BHF-555 message names the
cycles), and the transport profile records that basis for `bhf replay`. The
run summary's `target_cycles` gives the fewest and most cycles any run took.

QEMU's Cortex-M models do not count `DWT_CYCCNT`, so on an emulator use a
counter the machine models: on `mps2-an385` the FPGAIO `COUNTER` at
`0x40028018` counts at 25 MHz, and under `-icount` it advances with the
instructions run. A counter that never advances is reported once, and the
deadline falls back to host time.

```sh
--target-transport "qemu-system:qmp=127.0.0.1:4444,gdb=127.0.0.1:3333,done=0x1a8,cycles=0x40028018,cpu_hz=25000000"
```

**Nondeterminism (`bhf replay --stability-runs N`).** `bhf replay` re-drives
a transport finding's input through the recorded transport once. With
`--stability-runs N` it runs it N times, each from the transport's reset, and
its `runs` line says how many reproduced the finding. When some do and others
do not, the result is `MISMATCH nondeterministic, K of N runs reproduced the
finding` (exit 3), and the differences list what the other runs did. Such a
finding depends on state the reset does not restore (a peripheral, timing,
an uninitialized word), not only on its input.

**Minimizing (`bhf minimize`).** `bhf minimize <finding>` rebuilds the
transport from the finding's profile as `bhf replay` does (relocate it with
`--transport-endpoint HOST:PORT`) and delta-debugs the input on the target: a
reduction is kept only when re-driving it faults with the same rule at the
same site, or, for a deadline finding, is again a clean run past the
deadline. The result is `min_testcase.bin`, with `minimization.lane =
"transport"` in `finding.json`. An input that no longer reproduces is an
error, and `--strategy typed`, which needs a host harness's argument layout,
is refused.

---

### Device registers on the host

Firmware that reads a peripheral through a fixed address
(`#define UART_SR (*(volatile uint32_t *)(UART1_BASE + 0x00))`, a CMSIS
`((UART_TypeDef *) UART1_BASE)`, or a cast of a literal) SEGVs on the host, where
nothing is mapped there. `bhf auto` reads the pointer casts of constants in the
crash path's sources and the headers they include, macros expanded, and a SEGV
whose address lies on one of those registers (or the same 4 KiB page) is an
environment result, not an out-of-bounds read: the finding records
`environment_origin` (`kind: "mmio_register"`, the fault and register addresses
and the macro), its verdict is `lab_only` (`verdict_reason: "mmio_register"`) at
low severity, and its `hardware_peripherals` fidelity is `not_exercised` with
the register named. Fuzz such a target on a transport from §3, or give the
register an accessor the harness can fake.

## 5. Big-endian & non-x86 fidelity

A cross build runs the target's own byte order: a big-endian-only bug (a field
byte-swapped only on PPC) is reachable under `qemu-ppc64` or a PPC gdbstub where
it would be invisible on the little-endian host. Cross-build with a big-endian
triple (`powerpc64-linux-gnu`, `mips-linux-gnu`) and run it through a transport
from §3. BHF's C decoder (`bhf_decode.h`) reads a harness's scalar arguments
little-endian on every target, big-endian ones included. The builtin mutator
takes each decoded scalar argument's span from the harness's `arg-layout.json`
and writes typed boundary values into it (0, 1, -1 and the type's extremes) in
that order, at the argument's width, on the host and through a transport alike
([#299](https://github.com/Tarmo-Technologies/bhf/issues/299)). It does not
emit raw struct images in a big-endian target's own byte order: a target that
reads a struct straight out of the input gets byte-level mutation.

## 6. Comparison-progress for format gates

Multi-byte magic/format gates (headers, checksummed frames) give a whole-compare
edge no gradient. Add laf-intel comparison-progress so an input that matches one
more leading byte is retained and energized:

```sh
bhf auto ./firmware-src --comparison-progress   # alias: --cmp-progress
```

Composes with cmplog/RedQueen (armed by default), value-profile, and the
hit-count buckets.

A transport campaign (`bhf fuzz --target-transport ...`) gets the gate's magic
from a dictionary instead: the mutator splices in the tokens of `--dict
<FILE>` (AFL format, `name="token"`) and of the harness's `dictionary.txt`.
With `--grammar <FILE>` it sends only derivations of the grammar, for a
target-side parser of a text format.

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
  --transport-coverage-map input=0x2000020c,input_cap=64,ring=0x20000004,write=0x20000204,wrapped=0x20000208,cap=512
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

- **Five levels of validation, kept apart:**
  1. **Host stubs.** Vendor headers stubbed on the host test portable logic
     only. They establish no RTOS behaviour.
  2. **ISA emulation.** `qemu-user` checks instruction semantics and byte order.
  3. **Full-system bare metal.** The `qemu-system-arm` mps2-an385 fixture checks
     the reset, the coverage ring and fault classification, with no scheduler.
  4. **An actual RTOS.** The FreeRTOS reference profile
     (`crates/target_transport/tests/freertos/`) runs under `qemu-system-arm`
     with a scheduler, a queue, and task- and interrupt-driven entry points. It
     has clean, fault, timeout and state-contamination controls, firmware
     identity, task identity and target cycles. Its CLI tests run with
     `BHF_RTOS_CLI=1`.
  5. **Silicon.** A physical board over gdb-remote is not validated here. A
     board profile reuses the same transport contract and must record the
     silicon, the probe and the RTOS versions it ran.
- **Validated live on emulators (2026-09-27, QEMU 8.2.2):** the transport
  layer's own live lane passed — cross-endian fidelity (RV-1, `qemu-ppc64`), the
  gdb-remote client + coverage read (RV-2, `qemu-arm` gdbstub), and the
  full-system snapshot + coverage-ring + planted-fault path (RV-3,
  `qemu-system-arm`). Evidence: `docs/validation/2026-09-27-hil-emu-live-qemu.md`.
- **The `--target-transport` CLI flag is wired to those same backends:** it
  parses the spec (including the `done=`/`fault=` completion contract), bounds
  each connection/read/write (`--timeout`), and dials the resource on the first
  execution (a dead endpoint fails with a connection error, not
  "unimplemented"). It takes the seed, length, time, iteration, timeout,
  deadline and RNG-seed flags; a host-lane flag it does not wire (`--workers`,
  `--grammar`, `--cmplog-log` and the others [cli.md](cli.md) lists) is
  refused with exit 2 instead of silently dropped. A gated end-to-end test (`transport_fuzz_qemu_cli`, present
  when `qemu-system-arm` + `arm-none-eabi-gcc` are installed) drives the real
  mps2-an385 fixture through the shipped `bhf fuzz --target-transport
  qemu-system:…` binary and asserts it plants the breakpoint itself and persists
  a classified fault finding. Running the CLI against *your* live stub/emulator
  or board remains the dependency-gated step you perform with the resource.
- **Still gated (unproven until you run it against the resource):** a live
  physical board (`hil_board.rs` + `BHF_HIL_GDB`), the TCP/serial `agent`
  transport (no target-side agent ships yet, [#289](https://github.com/Tarmo-Technologies/bhf/issues/289)), and proprietary
  RTOS images / vendor toolchains (BHF ships none — bring your own).
- **Not available yet:** a Renode full-system transport ([#340](https://github.com/Tarmo-Technologies/bhf/issues/340));
  `--target-transport` takes `agent`, `gdb` and `qemu-system` only. Renode's
  gdbserver can be driven through `gdb:`, without snapshot reset. Semihosting
  coverage ([#292](https://github.com/Tarmo-Technologies/bhf/issues/292)) is not
  wired either, nor typed mutation of a raw struct image in a big-endian
  target's byte order (decoded arguments are typed, little-endian as the
  decoder reads them; §5).
- **Non-goals:** BHF does not bundle or crack vendor toolchains, ship RTOS
  images, or act as a full-system emulator (it drives `qemu-system`, it does
  not replace it).
