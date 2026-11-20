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
   probe/emulator over gdb-remote, or a full-system `qemu-system` guest or
   Renode board), and
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
| A cross toolchain + Renode (a board `qemu-system` does not model: most STM32, nRF52, i.MX RT parts) | **Full-system emulator (Renode)** | Real core, Renode's peripheral models, `Save`/`Load` reset | ✅ Renode 1.17, bare-metal Cortex-M3 on a minimal board (`live_renode`, `transport_fuzz_renode_cli`; they run when Renode is installed). Vendor board scripts and an RTOS under Renode are unvalidated. |
| An open RTOS (FreeRTOS, Zephyr) | **Actual RTOS execution** | Scheduler / tasks / queues | ✅ FreeRTOS reference profile (`crates/target_transport/tests/freertos/`): cooperative Cortex-M3 image build, boot, snapshot reset, task/queue input drive, HardFault classification, and clean → fault → clean CLI test under `qemu-system-arm`. ✅ The reference agent as a Zephyr module (`c_runtime/zephyr/`): its `qemu_cortex_m3` sample runs clean → fault → clean and replays under `qemu-system-arm`. Kernels are bring-your-own (not vendored); physical boards and other RTOSes are unvalidated. |
| A proprietary RTOS image | **Actual RTOS execution** | VxWorks/INTEGRITY/QNX scheduler | ⛔ unproven (bring the image + toolchain) |
| An on-device agent (TCP/serial) | **On-target agent** | Real device; coverage over the agent protocol | ⛔ unproven: the host side ships; no target-side agent does yet ([#289](https://github.com/Tarmo-Technologies/bhf/issues/289)), so you write one to the frame format in §3c |
| A physical board | **HIL** (hardware-in-the-loop) | Silicon | ⛔ unproven (`BHF_HIL_GDB`) |
| A Linux driver's source, and syzkaller | **syzkaller descriptions and crash import** (`bhf kernel syzlang`, `bhf kernel import`, §10) | syzkaller runs the kernel and its KCOV coverage; bhf describes the driver's ioctls and triages the crashes | ✅ snapshot of the widget fixture's description, and the import of a crash directory in syz-manager's layout; ⛔ syz-sysgen acceptance and a fresh syz-manager workdir gated (need syzkaller) |
| Only a firmware image (ELF or flash dump), no source | **Rehosting** (`bhf binary rehost`, §9) | bhf's own Cortex-M interpreter: the real instructions; peripheral reads from per-register models (input-fed, constant, or bit-extract inferred from polling loops); interrupts the firmware enables, raised on a schedule the input chooses | ✅ fixture images in `crates/rehost/tests/fixtures/`: edge coverage that grows with the input, invalid-access, bad-PC and HardFault findings, a parser fed through a peripheral data register, a polled UART's parser bug reached through inferred models, an RX-interrupt handler's bug reached through the interrupt schedule, `bhf replay` MATCH |

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
| `semihosting` | emulator/probe with semihosting, no RAM to spare for a ring | events written to the semihosting stderr, read by the `gdb` and `qemu-system` transports with `coverage=semihosting` (see [Semihosting coverage](#semihosting-coverage)) |
| `stub` | smoke build | result status only, no event stream |

The `gdb` and `qemu-system` transports read either `memory_buffer`, whose ring
the host reads out of target memory, or `semihosting`, whose writes the target's
semihosting calls hand to the debugger (see the coverage-map spec below).

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
to locate the input buffer and the on-target coverage ring.

The run summary's `executions_per_sec` is the campaign's executions per second of
wall-clock time, and each finding's `transport_profile.json` records it in a
`throughput` block (`executions`, `elapsed_secs`, `executions_per_sec`).

### Coverage-map spec

For `gdb` and `qemu-system`, tell BHF where the `memory_buffer` ring lives
(addresses are decimal or `0x`-hex, from your linker map / `nm`):

```
--transport-coverage-map input=<addr>,input_cap=<n>[,input_len=<addr>],ring=<addr>,write=<addr>,wrapped=<addr>,cap=<n>[,cmplog=<addr>,cmplog_cap=<n>]
```

or, for the `semihosting` backend, that coverage comes from the semihosting
channel, in place of the ring keys:

```
--transport-coverage-map input=<addr>,input_cap=<n>[,input_len=<addr>],coverage=semihosting[,cmplog=<addr>,cmplog_cap=<n>]
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
- `coverage` — `memory_buffer` (the default) or `semihosting`. With
  `semihosting` the map names no ring: a ring key beside it is an error.
- `cmplog`, `cmplog_cap` — optional, together: the address of the firmware's
  comparison record and how many entries it holds (at most 43690, one
  read's worth). See [CmpLog on the target](#cmplog-on-the-target).

The `agent` transport carries coverage over its own protocol and rejects this
option.

### Semihosting coverage

The `semihosting` probe backend writes its event stream to file descriptor 2
through `adafuzz_semihosting_write`, which the BSP provides: on ARM, open
`:tt` for append (`SYS_OPEN` mode 8, the semihosting stderr) and `SYS_WRITE`
the buffer to it. A semihosting call is the debugger's to serve when the
target runs under one: QEMU with `-semihosting-config enable=on,target=gdb`,
OpenOCD with `arm semihosting enable` and `arm semihosting_fileio enable`, or a
Black Magic Probe. Each write then reaches BHF's gdb connection as a File-I/O
request. BHF reads the buffer out of target memory, answers the call, and, with
`coverage=semihosting`, decodes what fd 2 got during each run as that run's
coverage. A write to fd 1 is console output, kept with the run like the stub's
`O` packets.

```sh
qemu-system-arm -M mps2-an385 -nographic -S -kernel fw.elf \
  -semihosting-config enable=on,target=gdb \
  -gdb tcp::1234 -qmp tcp:127.0.0.1:4444,server,nowait \
  -drive if=none,file=scratch.qcow2,format=qcow2,id=sc0 &
bhf fuzz work/ --harness H-FW \
  --target-transport qemu-system:qmp=127.0.0.1:4444,gdb=127.0.0.1:1234,done=0x1a8 \
  --transport-coverage-map input=0x2000020c,input_cap=64,coverage=semihosting
```

Under QEMU, `target=gdb` is needed: QEMU's default `target=auto` picks the
console when the guest starts, before BHF connects, and the stream goes to
QEMU's own output. Anything else the firmware writes to its semihosting stderr
lands in the same stream and breaks its decoding: that run's coverage is then
recorded as incomplete. Each write is a round trip to the host, so a ring is
faster where the target has RAM for one.

### CmpLog on the target

A 4-byte magic compare is out of reach of random mutation. Build the code
under test with `-fsanitize-coverage=trace-cmp` (GCC or clang) and give the
firmware callbacks that record each comparison in RAM:

```c
#define BHF_CMPLOG_CAP 32
volatile struct {
  uint32_t count;      /* bhf zeroes it before each run */
  uint32_t reserved;
  struct { uint64_t lhs, rhs; uint32_t width, site; } entries[BHF_CMPLOG_CAP];
} bhf_cmplog;

void __sanitizer_cov_trace_const_cmp4(uint32_t a, uint32_t b) {
  uint32_t n = bhf_cmplog.count;
  if (n < BHF_CMPLOG_CAP) {
    bhf_cmplog.entries[n].lhs = a;
    bhf_cmplog.entries[n].rhs = b;
    bhf_cmplog.entries[n].width = 4;
    bhf_cmplog.entries[n].site = (uint32_t)__builtin_return_address(0);
  }
  bhf_cmplog.count = n + 1;
}
/* ... and the same for __sanitizer_cov_trace_cmp{1,2,4,8} and
 * __sanitizer_cov_trace_const_cmp{1,2,8}, at their widths. */
```

Keep the callbacks out of the instrumented files. Then name the record in
the coverage map: `cmplog=<addr of bhf_cmplog>,cmplog_cap=32`. All fields
are little-endian. A `count` past the capacity means the record filled; bhf
reads the entries it holds.

bhf zeroes `count` before each run on the `gdb` and `qemu-system`
transports, and reads the record after the run. It keeps the comparisons of
each corpus entry's run. A mutation of that entry then replaces an operand
it finds in the input with the value it was compared against. The run
summary's `comparisons` counts the comparisons read.

The gated `transport_fuzz_qemu_cli` test solves a 4-byte magic on the
mps2-an385 fixture within 300 executions with `cmplog=`, and not without it.
A session-lane spec (`--session-transport transport:…`) rejects `cmplog=`.

### 3a. Debug probe / emulator gdbstub (`gdb:HOST:PORT`)

Drives the real gdb-remote (RSP) client against any gdbstub — OpenOCD, J-Link
GDB server, or a `qemu-*` `-g` stub.

```sh
# e.g. a qemu-user or qemu-system gdbstub on :3333, memory_buffer harness built at §2
bhf fuzz bhf_work --harness H-C0001 \
  --target-transport gdb:127.0.0.1:3333 \
  --transport-coverage-map input=0x2000020c,input_cap=64,ring=0x20000004,write=0x20000204,wrapped=0x20000208,cap=512
```

Each input starts from a reset. A board takes the same completion contract as
`qemu-system:` (§3b) and says how it resets:

- `done=<addr>[,done_kind=<n>]` and `fault=<addr>[,fault_width=4,fault_clear=0]`
  — the completion breakpoint, planted once when the run starts, and the
  firmware fault-status word, cleared before each input and read after it.
- `reset=restart` (the default) sends the RSP `R` restart, as gdbserver and
  OpenOCD serve it. `reset=monitor:<command>` runs a monitor command instead:
  `monitor:reset halt` on OpenOCD or a J-Link, `monitor:system_reset` on QEMU,
  whose system gdbstub refuses `R`.

```sh
bhf fuzz bhf_work --harness H-BOARD \
  --target-transport "gdb:127.0.0.1:3333,done=0x08000200,fault=0x20000208,reset=monitor:reset halt" \
  --transport-coverage-map input=0x2000020c,input_cap=64,ring=0x20000000,write=0x20000200,wrapped=0x20000204,cap=512
```

A **board profile** keeps a board's specs in one file:
`bhf fuzz --board-profile board.toml` takes `--target-transport` and
`--transport-coverage-map` from its `gdb` and `coverage_map`, and
`--board-lane serial` takes `--target-transport` from its `serial` (the agent
on the board's UART). `docs/hil-boards/nucleo-f411re.toml` is the template and
`docs/hil-bringup.md` the bring-up, step by step.

### 3b. Full-system emulator (`qemu-system:qmp=…,gdb=…[,snapshot=TAG][,reset=…]`)

The flagship path: boot a `qemu-system-*` guest, attach QMP + gdb, take a
`savevm` baseline, then per input `loadvm`-reset → write input → run → read the
coverage ring. Deterministic and reset-clean; `reset=persistent` trades the
`loadvm` per input for the firmware's own input loop (see
[Persistent loop](#persistent-loop)), and `reset=fast` for a machine reset
plus the RAM pages the run wrote (see [Fast snapshot](#fast-snapshot)). The CLI parses **TCP** `HOST:PORT`
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

#### Persistent loop

`reset=persistent` (it needs `done=`) restores the snapshot only before the
first input and after a crash, a hang or an inconclusive run. After a clean
run the guest stays at the `done=` breakpoint, and the next input continues
the firmware's own loop: BHF steps the guest off the breakpoint (removing it
for the step, as gdb does), empties the coverage ring, puts back the staging
bytes a longer previous input left past a shorter one, writes the input and
runs. `reset=loadvm`, the default, restores before every input.

The firmware's done function must return, into a loop that reads the input
region again and records the run's coverage:

```c
__attribute__((noinline)) void harness_done(void) { __asm volatile("" ::: "memory"); }

void Reset_Handler(void) {
  for (;;) {
    run_one(bhf_input);   /* the code under test */
    harness_done();       /* BHF stops here, and continues from here */
  }
}
```

- Everything else in the guest carries over from one clean input to the
  next, as in any persistent-mode fuzzer: state the code under test keeps is
  the firmware's to reset. Record faults in a `fault=` word. A fault handler
  that returns through `done` with no fault word looks like a clean stop, and
  BHF would continue from it.
- A done function that branches to itself, such as a noinline `for (;;) {}`
  built with optimization (one `b .`), is refused on the first continuation:
  the step off it changes no register, so BHF stops the run with an error
  that says to use `reset=loadvm` or make done return.
- A continuation proves the loop when it comes back to `done` cleanly with
  coverage. Until one has, any other continuation (one that crashes, hangs,
  comes back with no coverage, or whose step off `done` does not trap) is
  run again from the snapshot, and that run is the one reported, so a
  firmware that does not loop neither misses a fault nor makes a false one.
  The `--deadline` oracle times the reported run, not the discarded
  continuation. The third continuation that crashes or hangs where its run
  from the snapshot does not, comes back with no coverage, or does not step
  off `done` stops the run with an error that says the done function does
  not return into a loop. A firmware that records no coverage cannot prove
  its loop and needs `reset=loadvm`.
- QEMU reports each stop and resume of the guest to QMP. BHF reads the
  monitor every 128 continuations so that backlog stays bounded.
- `bhf replay` and its minimization restore the snapshot before every input,
  so they run a persistent finding from the snapshot. A finding that needs
  the inputs before it may not replay; its transport profile's `limitations`
  says so, and its `reset_mechanism` names the persistent loop.
- The session lane (`--session-transport transport:qemu-system:…`) refuses
  `reset=persistent`: it would carry guest state from one message, and one
  session, into the next.
- On the RV-3 mps2-an385 image under QEMU 8.2.2, a `loadvm` per input ran
  about 150 to 200 inputs per second and `reset=persistent` about 650 to 770
  (3.8x on an idle host, 4.1x to 4.4x under some load, 8.5x on a heavily
  loaded one), in `docs/validation/2026-11-19-fullsystem-persistent-loop.md`.
  A larger guest costs more per `loadvm`, and the persistent loop does not.

```sh
bhf fuzz bhf_work --harness H-C0001 \
  --target-transport "qemu-system:qmp=127.0.0.1:4444,gdb=127.0.0.1:3333,done=0x1a8,fault=0x20000100,reset=persistent" \
  --transport-coverage-map input=0x2000020c,input_cap=64,ring=0x20000004,write=0x20000204,wrapped=0x20000208,cap=512
```

#### Fast snapshot

`reset=fast,dirty_log=PATH` restores only what a run changed. Before each
input but the first, BHF resets the machine with `system_reset`, which brings
back every CPU and device (a HardFault's exception state included) and keeps
RAM, then writes back over gdb the RAM pages the last run wrote, from their
baseline. A crash or a hang needs no `loadvm`. The RAM the plugin cannot see
written is the exception: see **What is not restored** below.

BHF sends `system_reset` as a monitor command over the gdbstub (`qRcmd`, one
round trip) and reads the register block after it, which must be the
baseline's. A gdbstub that takes no monitor command, or registers that do
not show the reset, switch the session to QMP `system_reset`, which waits for
QEMU's `RESET` event; registers that still differ stop the run with an
error, since a reset does not bring that machine back to its baseline. BHF
reads the monitor every 128 resets so QEMU's QMP event backlog stays bounded.

The pages come from bhf's QEMU TCG plugin, which logs the guest-physical
page of every guest store to RAM in the file `dirty_log=` names. Load it into
each emulator; with `--workers`, give each worker's QEMU a log of its own
(`dirty_log=/tmp/bhf-dirty-{worker}.log`, and `log=` to match): specs that
name one log are refused with exit 2.

```sh
# bhf_qemu_dirty_pages.c ships in bhf (crates/target_transport/qemu_plugin/); a run with
# reset=fast and no log builds it under <work>/qemu-plugin/ and prints the line.
cc -shared -fPIC -O2 -o libbhf_qemu_dirty_pages.so bhf_qemu_dirty_pages.c -lpthread

qemu-system-arm -M mps2-an385 -kernel harness.elf -S \
  -gdb tcp::3333 -qmp tcp:127.0.0.1:4444,server,nowait \
  -drive if=none,file=scratch.qcow2,format=qcow2,id=sc0 \
  -plugin ./libbhf_qemu_dirty_pages.so,log=/tmp/bhf-dirty.log &

bhf fuzz bhf_work --harness H-C0001 \
  --target-transport "qemu-system:qmp=127.0.0.1:4444,gdb=127.0.0.1:3333,done=0x1a8,fault=0x20000100,reset=fast,dirty_log=/tmp/bhf-dirty.log" \
  --transport-coverage-map input=0x2000020c,input_cap=64,ring=0x20000004,write=0x20000204,wrapped=0x20000208,cap=512
```

- **The baseline** is the machine as a reset leaves it: arming sends
  `system_reset` before the `savevm`, so the guest starts each input from its
  reset vector, as it does from a fresh `-S` boot.
- **Learning.** BHF learns a page's baseline the first time a run writes it:
  that reset is a `loadvm`, after which BHF reads the page from the restored
  guest. Once the pages a target writes are known, every reset is fast. The
  pages QEMU's reset reloads by itself (each image segment it loaded into
  RAM, from `info roms`) are neither learned nor written. Baselines are
  capped at 64 MiB; a run that writes a page past the cap, a store whose
  physical address QEMU does not report, a full log (65,536 pages by default,
  `capacity=` on the plugin) and the reset after one that failed part way
  all restore with `loadvm`.
- **Addresses are physical.** The plugin logs physical pages, so the session
  puts the gdbstub in QEMU's physical-memory mode (`Qqemu.PhyMemMode:1`); the
  coverage map's addresses are physical, as they are on a core without an
  MMU.
- **Cortex-M cores.** When the gdbstub's target description is M-profile,
  BHF reads QEMU's memory map (`info mtree -f`) at arm. A store through a
  bit-band alias reaches RAM through QEMU's bit-band device, out of the
  plugin's sight, so the plugin logs it as the RAM word it writes, for the
  windows whose aliased memory is RAM. The core stacks an exception frame
  without a store, so before each reset BHF reads `xPSR`, and while an
  exception is active (a fault, or an interrupt the stop came in) the stack
  pointer and `PSP`: it restores the stack from the stop's stack pointer up to
  the baseline's (or the 4 KiB above it when the firmware moved the stack
  more than 64 KiB away), and the frame at `PSP`.
- **What is not restored**: RAM written by something other than a guest
  store and that BHF does not know of: a device's DMA, and on a Cortex-M core
  the frame of an exception taken and returned before the stop (an
  interrupt), in a page no store dirtied. On other cores, the plugin does not
  see what QEMU writes for the CPU outside an instruction's own stores, such
  as an x86 interrupt's stack frame. Device state a reset does not clear (a
  flash part's contents) is not restored either. When the firmware's
  behaviour depends on any of these, use `reset=loadvm`.
- **The log is checked.** After a run that reached a stop, the log must show
  that the plugin saw the guest run in its current epoch, and its epoch must
  be the one BHF left it in: a log no plugin in this QEMU writes (one left by
  an earlier run), or one a second session empties, stops the run with an
  error rather than carry state from one input to the next.
- **Pages**: 256 bytes by default; `page_bits=N` on the plugin (6 to 16) sets
  2^N.
- **License profile.** The plugin runs inside QEMU (GPL-2.0), so `reset=fast`
  runs under a profile that allows the `qemu_plugin` subprocess id:
  `external-tools` (which asking for `reset=fast` opts into when
  `BHF_PROFILE` is unset) or `research-lab`. `BHF_PROFILE=strict-permissive`
  refuses it with exit 2.
- **Host.** The plugin shares its log with bhf through POSIX `mmap`, so bhf
  builds it on a Linux or macOS host only. On Windows use `reset=loadvm` or
  `reset=persistent`.
- **QEMU versions.** The plugin declares plugin API version 1, which QEMU 8.x
  takes. For a QEMU that wants another, build it with
  `-DBHF_QEMU_PLUGIN_VERSION=N` (or set `BHF_QEMU_PLUGIN_VERSION=N` for the
  build `bhf fuzz` does); the calls it makes are the same in every version.
- `bhf replay` and its minimization restore with `loadvm`, so a replay needs
  no plugin. A finding's `transport_profile.json` names the fast snapshot in
  `reset_mechanism` and what it does not restore in `limitations`, and each
  `RunOutcome` reports the reset it followed (`kind`, `time`, `pages`). The
  session lane (`--session-transport transport:qemu-system:...`) does not
  take `reset=fast`, since its replay would rebuild the same transport.
- On the RV-3 mps2-an385 image under QEMU 8.2.2, the fast snapshot's mean
  reset took about a tenth or less of a `loadvm`'s, with the planted fault
  among the inputs, in
  `docs/validation/2026-11-19-fullsystem-fast-snapshot.md`.

#### Renode boards

`renode:monitor=HOST:PORT,gdb=HOST:PORT[,snapshot=PATH]` is the same lane for
a board Renode models and `qemu-system` does not. Start
Renode with its monitor on a TCP port and the board loaded but **not
started** (no `start` in the script):

```sh
renode --disable-gui -P 1234 board.resc &   # board.resc: mach create,
                                            # LoadPlatformDescription, sysbus LoadELF
bhf fuzz bhf_work --harness H-C0001 \
  --target-transport "renode:monitor=127.0.0.1:1234,gdb=127.0.0.1:3333,snapshot=/tmp/base.save,done=0x188,fault=0x20000100" \
  --transport-coverage-map input=0x2000020c,input_cap=64,ring=0x20000004,write=0x20000204,wrapped=0x20000208,cap=512
```

BHF connects to the monitor, `pause`s, and writes the baseline with
`Save @PATH`. Before each input it runs `Load @PATH`, then
`machine StartGdbServer PORT` with the `gdb=` port, because `Load` replaces
the machine and its gdb server goes with it. It then dials gdb, plants the
`done=` breakpoint and runs the input as on `qemu-system:`. The other keys
(`done_kind`, `fault_width`, `fault_clear`, `firmware`, `cycles`, `cpu_hz`,
`task_id`) work as they do there.

- `snapshot=` is a path on the Renode host; the default `bhf-baseline.save` is
  relative to Renode's working directory. Its directory must exist: Renode
  1.17 exits when `Save` cannot write the file. Each `Save` replaces the
  file. The path may use only `[A-Za-z0-9._/\:-]`, since it is part of a
  monitor command line.
- Renode's gdb server listens on the port `gdb=` dials, so dial it directly,
  not through a port mapping that changes the number.
- A failed monitor command (`There was an error executing command ...`,
  `No such command or device`) stops the run with Renode's text.
- `Load` reloads the whole emulation, so a run costs more than a `loadvm`:
  about 0.4 s per input on the minimal board in the tests.

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

Set `--max-len` to the agent's input buffer. On a board the agent runs as a
task over the UART. `crates/target_transport/tests/freertos/agent_task.c` is
one, for FreeRTOS on `mps2-an385` under QEMU, and its `Makefile` builds it.
Its HardFault handler returns from the exception into a function that reports
the fault from the task. The run is recorded in
[validation](../validation/2026-11-18-freertos-agent.md).

`c_runtime/zephyr/` is the agent as a Zephyr module: set `CONFIG_BHF_AGENT=y`,
name the UART with the devicetree's chosen `bhf,agent-uart`, and call
`bhf_agent_zephyr_run(LLVMFuzzerTestOneInput)`. Zephyr ends a thread that
faults, so the module's `k_sys_fatal_error_handler` records the fault, and the
calling thread sends the reply and starts a new agent thread. Its
`qemu_cortex_m3` sample is in `c_runtime/zephyr/samples/agent`, and its
README has the commands; the run is recorded in
[validation](../validation/2026-11-18-zephyr-agent.md). An agent that
implements the protocol itself uses this frame format. Every integer is little-endian, one
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

### Several targets at once

`--workers N` drives N targets, one per worker: name each worker's in the spec
with `{worker}` (0 to N-1) or `{BASE+worker}`:

```sh
bhf fuzz bhf_work --harness H-C0001 --workers 4 \
  --target-transport agent:tcp:127.0.0.1:{9000+worker}
```

The workers share one corpus, coverage map and schedule, so an input one
worker keeps is mutated by all of them. They also share one finding set: a
fault several workers reach is one finding. Its transport profile names the
spec of the worker that found it, and `bhf replay` re-drives it there.
`--iterations` and `--time` are the whole campaign's, and the summary's
`workers` counts the workers. A run-control halt on one target (a hang, a
lost link) stops the campaign, as it does for one worker.

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
they do for `--target-transport`; `qemu-system` does not take
`reset=persistent` or `reset=fast` here. `--session-reset reconnect` (the default)
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
`0x40028018` counts at 25 MHz, and under `-icount shift=0,sleep=off` it
advances with the instructions run, the same count on every run. With
icount's default `sleep=on` the clock follows host time while the guest
idles, so a loaded host adds cycles. A counter that never advances is
reported once, and the deadline falls back to host time.

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
`((UART_TypeDef *) UART1_BASE)` whose members are `__IO`, or a volatile cast of
a literal) would SEGV on the host, where nothing is mapped there. So the C
direct harness (`bhf auto` and `bhf generate-harness --kind direct` for a C
target) maps those registers. The C sequence harness (a handle-lifecycle C
target) and the C++ harness do not: their register reads still fault, and the
classification below applies.

The generator reads the volatile register accesses of constants in the
target's source file and the headers beside it that it includes, macros
expanded: a `volatile` (or `__IO`, `__I`, `__O`) cast, or a cast to a struct
whose members are. It keeps the ones the target's own code reaches, through
the functions it calls in those files and the macros it uses, and maps each
4 KiB page they lie on (adjacent pages merged, at most 16 windows). A plain
pointer cast is no register: list.h's `LIST_POISON1` (`(void *) 0x00100100`)
and other poison or sentinel values (`*_POISON*`, `0xdeadbeef` and the like)
are never mapped, so a dereference of one still faults. A target that reaches
no register gets no window, whatever else its file reads.

On Linux the harness maps each window once, through the runtrace shim's
`bhf_shim_mmio_fill` when the shim is loaded and with its own `mmap` otherwise,
and before every input refills it from that input: byte `i` of a window is
input byte `i % size`. A register read returns fuzz-chosen bytes, so a bug
behind a register's value (a framing-error path, a status bit) is reachable,
and a register the target writes does not carry into the next input.

A register keeps one value for the whole run, so a loop that polls it would
spin until the per-input timeout on every input that leaves its bit clear. A
page whose register a loop condition reads (`while (!(UART_SR & 0x80)) {}`, a
`do ... while`, the test of a `for`, an `if (...) break;`, directly or through
a macro or a function the condition calls) is therefore left unmapped: its read
faults, and the target keeps its throughput and the environment result below.
A poll the scan cannot see (through a function pointer, or in another
translation unit) still spins.

The harness lists the windows it was generated with in `mmio-windows.txt`.
After `bhf auto` builds it natively, it asks the harness which of them it
could map on this host (`BHF_MMIO_PROBE=1`: the harness maps them, prints
them and exits) and records those in `mmio-mapped.txt`. A window the build
cannot map is left unmapped, and its read faults as before: the address is in
use, or the sanitizer reserves it (ASan's shadow gap on x86-64 holds the
Cortex-M system control space at 0xE000E000). Only the target's mapped
windows set its findings' `hardware_peripherals` fidelity to `not_exercised`
with a reason that starts `emulated:` and names them: the registers were
memory, not a device. A cross build is not probed and claims none.
`BHF_MMIO_VERBOSE=1` prints each window the harness could not map, and
`BHF_NO_MMIO_EMULATION=1` leaves every register unmapped.

When a register read still faults, because it was not mapped, `bhf auto` reads
the pointer casts of constants in the crash path's sources and the headers they
include, macros expanded, and a SEGV whose address lies on one of those
registers (or the same 4 KiB page) is an environment result, not an
out-of-bounds read: the finding records
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
CLI finding and replay (RV-4), and the Renode transport, library and CLI,
against the Renode `BHF_RENODE` names (RV-7). It **hard-fails** if a required
tool is missing so the lane cannot silently skip:

```sh
eval "$(scripts/ci/install-renode.sh ~/.local/opt/renode-ci | sed 's/^/export /')"
BHF_HIL_REQUIRE=1 scripts/hil-emu.sh
```

Prerequisites (Debian/Ubuntu): `qemu-system-arm qemu-user qemu-utils
gcc-arm-none-eabi libnewlib-dev libnewlib-arm-none-eabi gcc-arm-linux-gnueabihf gcc-powerpc64-linux-gnu binutils`.
RV-1 through RV-3 were validated on QEMU in September 2026 (see
`docs/validation/2026-09-27-hil-emu-live-qemu.md`). RV-4 passed locally on
October 4, 2026; hosted HIL-emu workflow evidence remains pending. The script
also runs the ignored RV-3 benchmarks, on the nightly schedule, a manual
dispatch or a local run (a pull request or a push skips them), one after the
other: one measures `reset=persistent` against a `loadvm` per input in one
test and needs 3x the runs
(`docs/validation/2026-11-19-fullsystem-persistent-loop.md`), the other
`reset=fast` against a `loadvm`, with the planted fault among the inputs, and
needs a mean reset at most a tenth of a `loadvm`'s
(`docs/validation/2026-11-19-fullsystem-fast-snapshot.md`). The script needs
the host `cc` for the fast snapshot's QEMU plugin.

---

## 9. Rehosting a firmware image (no source): `bhf binary rehost`

When all you have is the image, a monolithic Cortex-M firmware ELF or a flash
dump, `bhf binary rehost` runs it unmodified in bhf's own emulator (the
`rehost` crate, an ARMv7-M Thumb-2 interpreter) instead of on the target. No
source, toolchain, harness or instrumentation is involved.

For each input the emulator resets the core the way the hardware does: the
stack pointer and the reset vector come from the vector table. The input
reaches the firmware in a fixed buffer in its memory (the receive buffer its
parser reads, with an optional length word), through its peripheral reads
(MMIO models, below), or both. Execution runs until the core goes idle
(`WFI`, `WFE`, a branch to itself) with no interrupt to wake it, reaches an
`--exit-at` address, exits
through semihosting, requests a system reset, runs out of input at a
peripheral read, faults, or uses `--max-instructions`. Every basic block the core enters is counted in a
64 KiB edge map that steers the builtin engine's mutator and power schedule.

```sh
# An ELF names its own symbols:
bhf binary rehost firmware.elf --work-dir bhf_work \
  --input-buffer rx_buf --input-length rx_len --inject-at main \
  --seed-file seed.bin --iterations 20000

# A raw image needs its load address, and addresses instead of symbols:
bhf binary rehost firmware.bin --base 0x08000000 --work-dir bhf_work \
  --input-buffer 0x20000008 --input-size 64 --inject-at 0x080000f0 \
  --ram 0x20000000:0x20000

# No buffer: the firmware reads its input from a peripheral's data
# register, after checking an ID register that must read a fixed value:
bhf binary rehost firmware.elf --work-dir bhf_work \
  --mmio 0x40013000=constant:0x4c31a5c3 --seed-file seed.bin

# Firmware that sleeps until its UART interrupts it: interrupts are raised
# on the input's schedule by default, here a tick every 500 instructions:
bhf binary rehost firmware.elf --work-dir bhf_work \
  --interrupt-interval 500 --seed-file seed.bin
```

- Addresses are hex, `0x` optional, so a value copied from `nm` or `objdump`
  output (`080000f0`) works as it is; a name the ELF's symbol table holds is
  that symbol.
- `--input-buffer` is an address or a symbol; `--input-size` defaults to
  the symbol's size. `--inject-at` writes the input when the core first
  reaches that address (usually `main`), after the start-up code has cleared
  `.bss`; without it the input is written at reset, where a `.bss` buffer is
  then zeroed. The run JSON's `input_not_delivered` counts the runs that
  never reached `--inject-at` and so ignored their input. A run is the same
  for every input until the input is written, so when no seed reaches it,
  no run will: bhf warns on stderr. Check the address, and whether the
  start-up code polls a peripheral first.
- **Peripheral reads (MMIO models).** A load from the peripheral window
  (`0x40000000`-`0x5fffffff`) is served by a model:
  `--mmio ADDR[@PC]=MODEL` (repeatable) names one for the register at ADDR,
  or with `@PC` for the instruction at PC only, which wins over a model for
  the register. ADDR and PC are hex or ELF symbols; MODEL is `passthrough`
  (each read takes as many bytes as it is wide from the input, so the
  fuzzer drives what the firmware sees there; Fuzzware calls this model
  "identity"), `constant:VALUE` (hex; a fixed value, such as the ID or
  ready bit a driver checks once) or `bitextract:MASK` (hex; the bits of
  MASK come from the input, lowest first, a byte for each eight of them,
  and the others read as zero: a status register whose one ready bit
  matters). A register no model names reads as
  `--mmio-default`: `passthrough` when there is no `--input-buffer`, so
  every unmodelled read takes the input, and `zero` when there is one, as
  before models existed. Peripheral reads take the input in order, after
  the bytes the buffer holds (when peripheral reads take input as well, the
  buffer takes at most the input's first 4096 bytes, so an input the
  mutator makes can reach the peripherals however large the buffer is; a
  seed feeds them only with its bytes past the buffer's share), and a
  run whose reads want more input than it has stops as `input_exhausted` in
  the run JSON's `stops`: a clean stop, not a finding. Writes to peripheral
  registers are dropped. A model for an address that `--ram` or an image
  segment maps is refused, since memory answers those reads before any
  model would.
  `--mmio-models FILE` loads models from a JSON file: the `mmio` object a
  run JSON's `setup` or a finding's `rehost.setup` records (or either whole
  document), so a later campaign or a teammate starts from the same models;
  `--mmio` adds to them. A file whose `mmio` object has no `default` leaves
  the default to the rule above. The run JSON's `mmio_reads` counts the peripheral
  reads of the campaign, and a finding's `input` block says how many bytes
  its peripheral reads took (`mmio_bytes`).
- **Polling loops (inferred bit-extract models).** Firmware that waits for a
  status bit (`while (!(USART->SR & RXNE)) {}`) stalls on a zero read and,
  fed whole from the input, eats several input bytes a poll on a bit the
  fuzzer must hit by chance. Before the campaign bhf runs the seeds, and an
  input of zeros, recording every peripheral read. A register one
  instruction reads at least 8 times in a row, with no other peripheral
  read between and no model serving it, is a polling loop. Probes pause
  the run just before the loop's first read and run it on from there with
  one bit of the read flipped at a time; a bit whose flip changes the path
  to the next peripheral read
  (another register is read next, or none, or the same one after a
  different number of instructions) is one the firmware tests (when no
  single bit does, all are flipped and then the ones the loop does not need
  are put back). The polling instruction gets a `bitextract` model for
  those bits, so the input decides each poll with one byte; with
  `--input-buffer` and no peripheral input it gets a `constant` that ends
  the loop instead.
  A getter that reads a data register in a dispatch loop
  (`for (;;) { c = fifo_pop(); ... }`) repeats the same way, but every bit
  of what it reads matters, and a test such as `c == 'X'` shows in no
  single-bit flip. A read the zero default answers only gains bits from a
  model, but under the `passthrough` default the read already takes the
  input whole, so its loop keeps that unless it is shown to be a status
  poll: some bit must end the loop, the loop must store nothing to memory
  between its reads but the same stores each time round (a call's saved
  registers, say), and no value of the bits outside the mask may change its
  path. The last check tries every value of those bits for an 8- or 16-bit
  read, and every value of each byte's for a 32-bit read, so a 32-bit data
  register compared against a constant that spans bytes at once can still
  be narrowed; name it `--mmio ADDR=passthrough` to keep it whole.
  Inference repeats past the loops it found, each pinned to a value that
  ends it, so a loop behind another (the receive poll after a prompt's
  transmit poll) is found too. The run JSON's `mmio_inference` lists each
  loop (`pc`, `address`, `polls`, the deciding `mask`, the `exit` value,
  whether it `writes` memory between its reads, why it is `not_a_poll`
  when its read keeps the input: `no_exit`, `writes_memory`, or
  `other_bits` with the `value` that showed it, and the `model` added) with
  the rounds and probes it took; inferred models carry `"inferred": true`
  in the recorded setup, so `bhf replay` and a rerun with `--mmio-models`
  use them without inferring again, and the rerun's setup still marks them
  inferred. `--no-mmio-inference` turns it off. Loops that alternate
  between two registers, or whose exit depends on more than the bits of
  one read, are not inferred; name those with `--mmio`.
- **Interrupts (an input-chosen schedule).** Firmware that sleeps until its
  peripherals interrupt it (a UART's receive interrupt, a timer tick) never
  progresses when nothing raises one. bhf models the NVIC (its enable,
  pending, active and priority registers, `AIRCR.PRIGROUP`, and `ICSR`'s
  PendSV and SysTick bits) and raises interrupts on a schedule that is part
  of the testcase, as Fuzzware's fuzzer-chosen interrupt triggers do. Every
  tick, `--interrupt-interval` instructions apart (default 1000), takes one
  byte of the input, from the same stream the peripheral reads take, in
  order with them, and pends one of the interrupts the firmware has enabled:
  its NVIC IRQs, and SysTick when its counter and its interrupt are on. The
  byte modulo how many are enabled picks which, lowest exception number
  first, and its top three bits pick the wait until the next tick: the
  interval, a half, a quarter, one instruction, 4, 8 or 16 times it, or
  twice it (`000` to `111`). A tick with nothing enabled takes no byte, and a
  tick the input has no byte left for raises nothing. A core that sleeps
  (`WFI`, `WFE`, a branch to itself) runs on to the next tick at once, and
  ends the run idle only when nothing enabled could wake it or the input is
  used up. A pending interrupt is taken between two instructions when its
  group priority preempts the core's execution priority (the active
  exceptions, `BASEPRI`, `PRIMASK`, `FAULTMASK`); the frame is stacked and
  the handler entered as the hardware does, and the pending bits the
  firmware sets itself (`NVIC_ISPR`, `PENDSVSET`, `PENDSTSET`) are taken the
  same way. An `SVC` in a handler is taken when SVCall's priority preempts
  the handler's, and escalates otherwise; an exception return clears
  `FAULTMASK`. A handler counts its own edges: the edge into it is from the
  interrupt, not from where it landed, and its return counts none, so an
  interrupt's timing alone makes no new coverage. An input buffer setup
  gets room for the schedule too: the buffer then takes at most the input's
  first 4096 bytes, as with peripheral input. With an input fed through
  peripheral reads, a status register that every interrupt's handler reads
  once is a loop to inference like a status poll, and gets a bit-extract
  model for the bit the handler tests. A finding records the interrupts its
  run took (`rehost.interrupts`: how many, the schedule's input bytes, and
  the first 64 with the instruction count, exception and IRQ number and the
  instruction each interrupted), the exception whose handler faulted
  (`rehost.fault.exception`, 16 + n for IRQ n), and the schedule in its
  setup (`rehost.setup.interrupts`), which `bhf replay` runs; a finding
  recorded before the schedule existed replays without one.
  `--no-interrupts` raises none: the NVIC's registers then hold what is
  written to them and a core that sleeps ends the run. No peripheral raises
  an interrupt of its own accord; NMI and the fault exceptions are never
  raised (a fault ends the run), and tail-chaining runs as a return and a
  fresh entry.
- `--ram BASE:SIZE` (repeatable) maps RAM; the default is
  `0x20000000:0x100000`, and an ELF's `.data` and `.bss` RAM is mapped as
  well. An initial stack pointer outside RAM is refused before anything
  runs. `--vector-table` overrides where the vector table is.
- A run that faults is a finding under
  `<work-dir>/results/findings/BF-NNNN/` (`kind: rehost_fault`,
  `finding_kind: binary`, rule `BHF-501`), classified as:
  - `invalid_access`: a load or store outside the image, its RAM, the
    peripheral window and the system space, a store to read-only image
    memory, or a misaligned multi-word access;
  - `bad_pc`: a fetch from an address that holds no code (unmapped, or
    peripheral or system space), a branch that cleared the Thumb bit, or an
    invalid exception-return value;
  - `hard_fault`: an undefined instruction (`UDF`, or an encoding ARMv7-M
    leaves unallocated), a divide by zero with
    `CCR.DIV_0_TRP` set, a coprocessor instruction with the coprocessor off,
    `BKPT` with no debugger, or an `SVC` at a priority that cannot take it.

  The finding records the fault (kind, PC, address, the branch that went
  there, the registers), the testcase and the machine setup, its MMIO
  models and default included (`rehost.setup.mmio`). Its
  `crash.signature` is the class, the kind and the faulting instruction (for
  a bad PC, the branch), so inputs that fault the same way are one finding.
- `bhf replay <finding>` runs the testcase through the recorded setup,
  peripheral models included, again and reports `MATCH` when it faults with
  the same signature; `--harness`
  names another copy of the image to run. It is the reproduce command
  `results/INDEX.md` and `findings.json` give for these findings (producer
  `binary rehost`); they get no `replay.py`, which runs a host harness.

**Fidelity.** The run JSON and every finding carry a `fidelity` block. The
CPU runs the real instructions: the Cortex-M3/M4 integer set with the M4's
halfword multiplies and saturation, the banked stack pointers, `SVC` and
interrupt exception entry and return, the NVIC, and the System Control
Block registers start-up code writes. Peripherals are modelled only as far
as their reads go: each read returns what its model says (the input's bytes
or a constant), writes are dropped, and nothing a peripheral does on its
own (a FIFO filling, a timer counting) happens; its interrupts come from
the schedule (`interrupts` says so, or `not modelled` under
`--no-interrupts`). With no models and the `zero` default the block says
peripherals are not modelled. The FPU, the M4's SIMD instructions, the MPU
and privilege are not modelled. An instruction outside the model
ends the run as `unsupported` in the run JSON's `stops` and `unsupported`
fields, never as a finding. An UNPREDICTABLE encoding (one that sets a bit
the architecture says should be clear, say) runs as the instruction it
encodes or ends the run as `unsupported`; QEMU takes a HardFault on many of
them.

---

## 10. Linux kernel drivers: syzkaller descriptions

A Linux driver's bugs are in the kernel, which a user-space harness never
runs. bhf does not fuzz the kernel itself; it gives syzkaller what it needs
to: `bhf kernel syzlang` reads the driver's C source and writes the syzkaller
description (syzlang) of its ioctl interface, and `bhf kernel import` brings
the crashes syzkaller finds back into `results/` (below).

```sh
# The driver's directory and the uapi header that defines its commands:
bhf kernel syzlang drivers/misc/widget include/uapi/linux/widget.h \
  --out ~/syzkaller/sys/linux
cd ~/syzkaller && make descriptions   # runs syz-sysgen; then build and run syz-manager
```

- **The handler.** An ioctl handler is a function a `struct file_operations`
  initializer registers as `.unlocked_ioctl`, `.compat_ioctl` or `.ioctl`;
  without one, a function named `*ioctl*` that takes `(struct file *,
  unsigned int, unsigned long)`.
- **The commands.** The handler's `switch` on its command parameter names
  them. A call that passes the command on (`return widget_do_xfer(state,
  cmd, argp);`) is followed into the callee's `switch` on that parameter, up
  to four calls deep. A command is a macro defined as `_IO`, `_IOR`, `_IOW`
  or `_IOWR` (directly or through `#define A B`), or a plain number a `case`
  names. When the handler's switch names none (a dispatch table indexed with
  `_IOC_NR(cmd)`, say), every `_IO`-family macro of the source read is
  described, and the header comment says so.
- **The argument.** `_IOW` becomes `ptr[in, T]`, `_IOR` `ptr[out, T]`,
  `_IOWR` `ptr[inout, T]`, and `_IO` an `intptr`. A plain-number command
  takes `ptr[inout, array[int8]]`. Structs and unions are described from
  their definitions in the source read: `__u8` to `__u64` and the other
  fixed-width spellings as `int8` to `int64`, `__aligned_u64` and its kin as
  `align64[int64]` (8-aligned on 386 too), `__be16`/`__be32`/`__be64` as
  big-endian, `long`, `size_t` and their kin as `intptr`, arrays (lengths
  from macros), bit-fields (`int8:4`; in a union, which syzlang gives no
  bit-fields, the whole integer), the bits an unnamed bit-field or `: 0`
  skips as zero padding, packing (`__packed`, `__attribute__((packed))`),
  nested and anonymous structs and unions (a union C pads past its largest
  member gets `[size[N]]`), and pointers (`ptr[inout, ...]`; a `void *` or
  `char *` is a byte array). Typedefs are followed. Struct names take the
  description's name as a prefix (`widget_config`), so they do not collide
  with syzkaller's own; a member named after a syzlang keyword or reserved
  name (`resource`, `include`, `parent`, ...) gets a `_` suffix.
- **The layout check.** Each struct and union is laid out twice per
  architecture: as C lays it out (GCC's and Clang's rules for that ABI) and
  as syzkaller's compiler will lay out the description. A command whose
  argument would differ, so the kernel would read a member where syzkaller
  did not put it, is left out with the member and architecture (a 64-bit
  bit-field that straddles a 4-byte boundary on 386, say); behind a pointer,
  such a type becomes a byte array instead. Each command's comment names the
  macro and where it is defined (`# WIDGET_IOC_RESET defined at
  include/uapi/linux/widget.h:50: ...`), worded so syzkaller never takes it
  for an `include` or `define` directive.
- **The device node.** A `struct miscdevice`'s `.nodename` or `.name`, a
  `device_create` or `register_chrdev` name, or `--device`. The fd resource
  is opened with `openat$<name>`; a name with a `%d` becomes
  `syz_open_dev$<name>` with `#` for the number.
- **The numbers.** `dev_<name>.txt.const` gives each command's number for
  each of the nine architectures syzkaller builds for Linux (386, amd64,
  arm, arm64, loong64, mips64le, ppc64le, riscv64, s390x): the argument's
  size under that architecture's data model (4-byte `long` and pointers on
  386 and arm, a 4-aligned 64-bit integer on 386) in its `_IOC` encoding (13
  size bits and 3 direction bits on mips and powerpc). No kernel build or
  `syz-extract` is needed.

A command bhf cannot describe, because its argument type is not defined in
the source read (a kernel type such as `struct timespec64`, say), has a
size no ioctl number holds, or has a layout syzkaller cannot give it, is
left out: the description says why in a
`# Not described:` comment, and stdout lists it. Name more of the source (the
header that defines the type) to describe it. Not read: a command or type
built by a function-like macro (`#define WIDGET_IOW(nr, t) _IOW('W', nr, t)`),
`sizeof` in a command or array length, `__attribute__((aligned(N)))` on a
member, `#pragma pack`, and a command whose number is computed at run time.
Exit status: 0 when at least one command was described, 1 otherwise (no
handler found, or no command describable).

### Importing syzkaller crashes: `bhf kernel import`

```sh
# A syz-manager workdir, its crashes/ directory, or one crash directory:
bhf kernel import ~/syzkaller/workdir --work-dir bhf_work --source-root ~/linux
```

Each crash directory syz-manager wrote (`crashes/<id>/`) becomes a finding
under `<work-dir>/results/findings/F-KERNEL-NNNN-<hash>/`, and `results/` is
rebuilt as after any producer (`INDEX.md`, `findings.json`, SARIF):

- **Class.** The title (`description`) gives the crash class, rule and CWE:
  KASAN and KFENCE out-of-bounds (`BHF-201`, CWE-122 and CWE-787 for a
  write, CWE-125 for a read), use-after-free (`BHF-202`), double free,
  invalid free; KMSAN uninit-value and kernel-infoleak; UBSAN checks under
  bhf's UBSan rules; KCSAN data races; general protection faults, NULL
  dereferences and paging requests; `WARNING`, `kernel BUG` and the other
  `BUG:` checks (CWE-617); hung tasks and RCU stalls; lockdep deadlocks;
  kmemleak leaks. `fuzz.exception.name` is the class (`SLAB_OUT_OF_BOUNDS`),
  `fuzz.exception.sanitizer` the detector (`kasan`), the title is
  syzkaller's, and `finding.json` keeps it all under `kernel`.
- **Stack and access.** The report (`report0`, else `repro.report`, else the
  console log) gives the stack, without the detector's own frames, printk
  and the syscall entry; the access (`Write of size 16`); the object it hit
  (`0 bytes to the right of allocated 104-byte region`); and its
  allocation and free stacks. With `--source-root` (the kernel or driver
  tree the report's paths are relative to) the finding keeps the frames of
  that tree's files, and names them relative to it.
- **Reproducer.** `repro.cprog` and `repro.prog` are copied as `repro.c`
  and `repro.syz` (evidence roles `repro_c` and `repro_syz`), the report as
  `sanitizer.log` and `log0` as `console.log`. The reproduce command is the
  C program compiled and run, else `syz-execprog` with the options syz-repro
  recorded (`-threaded`, `-repeat` with its count, `-procs`, `-sandbox` and
  `-sandbox_arg`), read from the comment atop `repro.prog` in the form
  syz-manager writes (`# {Threaded:true Repeat:true ... Sandbox:namespace
  ...}`) or the dashboard's JSON (`#{"threaded":true,...}`), and kept under
  `kernel.reproducer.options` with the JSON form's keys; run either in the
  test VM, not on the host. A crash with a reproducer has confidence `high`,
  one without `medium`. The finding's entry path (`reachability`, SARIF
  `actionabilityEntryPath`) is `syscall`: the program syzkaller reached it
  with (`repro.syz`, else `repro.c`, else `console.log`), not a harness
  input.

Importing a crash again updates its finding in place (a reproducer
syz-repro found since is added). A crash of syzkaller's own test machine
(`lost connection to test machine`, `SYZFAIL`) is skipped and listed. Exit
status: 0 when at least one crash was imported, 1 otherwise.

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
  deadline, RNG-seed, `--dict`, `--grammar` and `--workers` flags; a host-lane
  flag it does not wire (`--cmplog-log`, `--len-control` and the others
  [cli.md](cli.md) lists) is refused with exit 2 instead of silently dropped. A gated end-to-end test (`transport_fuzz_qemu_cli`, present
  when `qemu-system-arm` + `arm-none-eabi-gcc` are installed) drives the real
  mps2-an385 fixture through the shipped `bhf fuzz --target-transport
  qemu-system:…` binary and asserts it plants the breakpoint itself and persists
  a classified fault finding. Running the CLI against *your* live stub/emulator
  or board remains the dependency-gated step you perform with the resource.
- **Still gated (unproven until you run it against the resource):** a live
  physical board (`hil_board.rs` + `BHF_HIL_GDB`), the TCP/serial `agent`
  transport (no target-side agent ships yet, [#289](https://github.com/Tarmo-Technologies/bhf/issues/289)), and proprietary
  RTOS images / vendor toolchains (BHF ships none — bring your own).
- **Renode:** `renode:` was run against Renode 1.17 with a bare-metal
  Cortex-M3 image on a minimal board (`crates/target_transport/tests/live_renode.rs`
  and `crates/cli/tests/transport_fuzz_renode_cli.rs`, which skip without
  Renode; `BHF_RENODE=/path/to/renode` points them at a portable build). Vendor
  board scripts, peripherals and an RTOS under Renode are unvalidated.
- **syzkaller descriptions (§10):** the description of the widget driver
  fixture (`tests/fixtures/kernel_widget/`) is a snapshot the tests compare
  byte for byte; the unit tests check the `_IOC` encoding against command
  numbers the kernel defines (`FS_IOC_GETFLAGS`, `KVM_CREATE_VM`). That syz-sysgen
  accepts it is checked by `kernel_syzlang_cli`'s gated test, which needs a
  syzkaller checkout (`BHF_SYZKALLER_CLI=1`, `BHF_SYZKALLER=<checkout>`); no
  CI job installs syzkaller. bhf runs no kernel and collects no KCOV
  coverage: syzkaller does both. `bhf kernel import` is tested on a crash
  directory written in syz-manager's layout for the fixture's planted bug
  (`tests/fixtures/kernel_widget/crashes/`); `kernel_import_cli`'s gated
  test imports a real syz-manager workdir (`BHF_SYZKALLER_CLI=1`,
  `BHF_SYZKALLER_WORKDIR=<workdir>`).
- **Not available yet:** typed mutation of a raw struct image in a big-endian
  target's byte order (decoded arguments are typed, little-endian as the
  decoder reads them; §5).
- **Non-goals:** BHF does not bundle or crack vendor toolchains, ship RTOS
  images, or act as a full-system emulator (it drives `qemu-system`, it does
  not replace it).
