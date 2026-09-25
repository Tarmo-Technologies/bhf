<!-- SPDX-License-Identifier: Apache-2.0 -->
# High-demand fuzzing roadmap — RTOS, radar, and embedded targets

Objective: extend BHF from a host-process, argument-shape-driven memory-safety
fuzzer into a tool that can build, harness, and fuzz the "high-demand" targets
common in government/defense work — radars, RTOS images (VxWorks, Green Hills
INTEGRITY, QNX, RTEMS, FreeRTOS), and other systems whose execution model
(shared memory, DMA/MMIO peripherals, interrupt- and message-driven entry
points, non-x86 big-endian ISAs, hard real-time timing, and rich concurrency)
breaks the assumptions standard fuzzers — and BHF as it stands today — are
built on.

Status: **planning + phased implementation.** This roadmap was produced from a
read-only capability audit of the tree (2026-09-25). Authorization for the work
is recorded in [`Authorization.md`](../Authorization.md) (defensive tooling
development on this repository). This document is the work list; each phase
below carries its own acceptance criteria and an honest split between what is
implementable and testable in-tree versus what is gated on external resources
(hardware, full-system emulators, proprietary vendor toolchains, or licensed
RTOS images) that this repository cannot itself provide.

Related reading: [`docs/cross-compilation.md`](cross-compilation.md) (current
Ada/C/C++ cross + embedded probe backends), [`docs/expected-gaps.md`](expected-gaps.md)
(honest gap inventory), [`docs/site/runtime-virtualisation.md`](site/runtime-virtualisation.md)
(the runtrace shim), and [`ROADMAP.md`](../ROADMAP.md) §§5–13 (discovery,
harness generation, engines).

---

## 1. Where BHF stands today (evidence)

BHF's embedded/RTOS support today is a **host-side stub-isolation lane**: for a
target guarded by (or including) a vendor platform header, BHF defines the
platform guard, drops declaration-only fake headers, and fuzzes the *portable
algorithmic body* on the x86-64 Linux host under sanitizers. The end-to-end
proof of this is `crates/cli/tests/auto_rtos_stub.rs`, which fuzzes a
`parse_track_msg(buf, len)` radar-track parser after stubbing `vxWorks.h` /
`semLib.h` / `msgQLib.h`. RTOS *behavior* is explicitly not modeled
(`crates/cli/src/auto/cross_target.rs:209-216`, "handles are inert … reduced
fidelity").

The audit found that BHF already has the **front half** of embedded fuzzing but
not the **back half**:

- **Front half present.** Transport-agnostic Ada source-rewrite instrumentation
  (`crates/instrumenter/src/breadcrumbs.rs:53-56`); two embedded coverage
  *emitters* — semihosting (`ada_runtime/adafuzz-probe-semihosting.adb`) and an
  in-RAM ring buffer (`ada_runtime/adafuzz-probe-memory_buffer.adb`) selected by
  `bhf build --probe-backend {semihosting,memory_buffer}`
  (`crates/cli/src/probe_backend.rs`); cross/embedded build flags
  `--target/--runtime/--toolchain` incl. `ravenscar-full`, `light-cortex-m3`,
  `arm-eabi` (`docs/cross-compilation.md`); a **working** fuzz-driven POSIX
  dependency model in the runtrace shim for `shm_open`/`shmget`/`mmap`,
  `mq_receive`, and `/dev/mem|uio|i2c|spidev` map-and-read
  (`crates/bhf_runtrace_shim/src/hooks/{mem,mqueue,fs,ioctl}.rs`); full IDL/ROS
  parsing with Ada CORBA mapping emission (`crates/idl_parser`); an offline
  GIOP/CDR/IIOP decoder (`crates/iiop`); lifecycle-aware API sequence harnesses
  (`crates/harness_gen/src/c_generate.rs`); TSan/MSan replay lanes.

- **Back half missing.** No host-side *reader* consumes the semihosting or
  memory-buffer coverage channels. No off-host *runner* exists (no
  `qemu-system`, Renode, avatar2, Unicorn, JTAG/OpenOCD, gdbserver, or
  serial/TCP on-target agent) — only qemu-**user**/wine argv-prefix
  (`crates/cli/src/runner.rs:13-56`) and a host-only `afl-fuzz -Q` shell-out
  (`crates/cli/src/binary_fuzz.rs`). The Nyx snapshot backend is a stub
  (`crates/fuzz_engine/nyx_adapter/src/lib.rs` returns `NotImplemented`;
  software replay collects zero coverage). Crash detection is `#[cfg(unix)]` on
  `ExitStatus::signal()` (`crates/cli/src/fatal_signal.rs:38-58`). The
  `fork_server` crate (AFL 198/199) is wired into nothing
  (`crates/fork_server/src/lib.rs:20-24`); the `iiop` decoder and
  `ada_state_machine` extractor are not wired into the engine.

The consequence: as shipped, a target must run as a **host Linux child
process** (natively, sandboxed, or under qemu-user/wine) to be fuzzed with
feedback. A VxWorks image, a Cortex-M board, or a `qemu-system` guest cannot be.

## 2. Design principles and non-goals

**Principles.**

1. **Reuse the front half.** Build the missing back half against the coverage
   emitters and instrumentation that already exist, rather than replacing them.
2. **A single target-transport seam.** All new execution backends (on-target
   agent, debug probe, full-system emulator) implement one trait; the builtin
   engine consumes coverage/status/faults through it and stays backend-agnostic.
3. **Fidelity is a first-class, structured property.** Every finding records
   *what was and was not exercised* (arch, endianness, RTOS runtime, hardware,
   concurrency), so a clean host-stub run is never mistaken for target
   assurance. This is a safety requirement for DO-178/safety-critical users.
4. **Honest gating.** Software is implemented and unit/integration-tested
   in-tree; validation that requires hardware, a full-system emulator image, or
   a proprietary vendor toolchain is written to self-skip when the resource is
   absent (repo convention), and its unproven status is recorded, never faked.
5. **No proprietary redistribution.** BHF ships no VxWorks/INTEGRITY headers,
   no vendor toolchains, and no RTOS images. Vendor-API models are BHF-authored
   scaffolding (as the existing stubs already are).

**Non-goals (this roadmap).** Bundling or cracking proprietary toolchains;
shipping RTOS images; live testing of third-party fielded systems (the
authorization is for local development fixtures and permitted public source);
becoming a general-purpose full-system emulator (we integrate qemu-system /
Renode, we do not write one).

## 3. Capability gap inventory

Verdicts follow `docs/expected-gaps.md`: **GAP** = BHF's own limitation,
fixable here; **DEPENDENCY** = needs an external resource not in the tree
(implemented behind a seam, validated when the resource is present).

| Track | Gap | Priority | Verdict |
|---|---|---|---|
| HDF-1 | No off-host/on-target execution + coverage transport (the back half) | P0 | GAP (seam) + DEPENDENCY (hardware/emulator validation) |
| HDF-2 | Crash/fault detection assumes host POSIX signals | P1 | GAP |
| HDF-3 | No big-endian / PowerPC·MIPS·SPARC arch fidelity | P0 | GAP + DEPENDENCY (cross toolchains) |
| HDF-4 | No full-system / snapshot fuzzing (Nyx stub; no qemu-system/Renode) | P0 | GAP (seam) + DEPENDENCY (emulator/images) |
| HDF-5 | No discovery/harness synthesis for non-buffer entry points (ISR/DMA/MMIO/queue) | P1 | GAP |
| HDF-6 | Fuzz-driven dependency model is POSIX-libc only | P1 | GAP |
| HDF-7 | No binary-framed (TLV/length/CRC) or on-the-wire stateful protocol input | P1 | GAP |
| HDF-8 | No concurrency-schedule exploration or real-time/timing oracles | P2 | GAP |
| CC-1 | Reduced-fidelity findings under-labeled (false-assurance risk) | P1 | GAP |
| CC-2 | Dead/unwired capabilities (fork_server, iiop, ada_state_machine, nyx, embedded emitters) | P2 | GAP |

## 4. Sequencing

```
        CC-1  (fidelity labels — do first; cheap, de-risks everything)
          │
HDF-1 ────┼──► HDF-2 ───► HDF-4 ───► HDF-8
(transport│    (faults)   (full-sys) (concurrency/timing)
 + reader)│
          ├──► HDF-3 (big-endian/arch; parallel prerequisite for meaning)
          │
HDF-5 ────┴──► HDF-6 ───► HDF-7  (entry points → dep model → protocol I/O)
```

The keystone is **HDF-1 + HDF-2**: an on-target transport with a coverage
reader and non-signal fault reporting turns the existing cross/embedded *build*
support into an actual on-target fuzzing lane. **CC-1** ships first because it
is cheap and makes every later result trustworthy. **HDF-3** runs in parallel;
without it, results do not correspond to real big-endian radar targets.
**HDF-5→6→7** is the entry-point/dependency/protocol axis and can proceed
independently of the execution axis. **HDF-4** and **HDF-8** build on the
transport.

---

## HDF-1 — On-target execution and coverage transport (the back half)

**Goal.** A single `TargetTransport` seam through which the builtin engine
delivers an input, triggers one execution, and receives coverage + status +
faults — regardless of whether the target is a host child, an on-target agent
over serial/TCP, a debug probe, or a full-system emulator.

**Current evidence.** Execution/harvest is hardcoded to a host child:
`command.spawn()`, stdin/stdout pipes, `BHF_EVENTS_PATH` host file
(`ada_runtime/adafuzz-probe.adb:58`), `mmap(MAP_SHARED)` on `BHF_COV_SHM`
(`ada_runtime/adafuzz_cov.c:56-66`), `/proc/<pid>/statm`, `waitpid`. The
semihosting and memory-buffer emitters write coverage off-host but **no reader
consumes them** (whole-tree search finds no consumer).

**Deliverables.**

1. **`TargetTransport` trait** (new crate `crates/target_transport`): `arm() ->
   Session`; `Session::run_input(&[u8]) -> RunOutcome { exit, coverage_edges,
   fault: Option<Fault>, stdout }`. The existing host/fork-server path becomes
   the first impl (`HostChildTransport`) with no behavior change.
2. **Coverage-channel readers** for the two emitters that already exist:
   - `SemihostingReader` — decodes the `BHF_EVENTS` tag-length stream arriving
     on the semihosting channel.
   - `MemoryBufferReader` — reads the 64 KiB in-RAM ring
     (`adafuzz_probe_memory_buffer[_write/_wrapped/_capacity]`) out of target
     memory (via the debug-probe or emulator memory API) and reconstructs the
     event/edge stream, honoring the `_wrapped` flag.
3. **On-target agent protocol** (`AgentTransport`): a small framed protocol
   (`{u32 len, bytes}` input → `{status, edge-delta, fault}`) over a
   `Read+Write` channel (TCP socket, serial `/dev/tty*`, or stdio), plus a
   reference agent skeleton the target BSP links (BHF-authored, no vendor code).
4. **Debug-probe bridge** (`GdbRemoteTransport`): drive execution and read the
   coverage buffer via the GDB remote serial protocol (OpenOCD / gdbserver /
   QEMU gdbstub), with reset-between-iterations.
5. Generalize `coverage_from_env` / the fork-server delta read
   (`crates/cli/src/fuzz.rs:5291-5318`) to pull from the transport rather than a
   host file/shm directly.

**Design sketch.** The engine loop already is: publish input → run once → read
coverage delta → classify. HDF-1 factors the "run once + read coverage delta +
classify" span behind `TargetTransport::run_input`. The host path keeps its
`mmap`/`waitpid` implementation verbatim; new backends supply their own.

**Acceptance criteria.**

- In-tree (must pass in CI, no hardware): `HostChildTransport` reproduces the
  current host lane exactly on the existing C/Ada fixtures (byte-for-byte same
  findings on `auto_rtos_stub.rs` and one C direct-harness fixture).
- In-tree: a **mock agent** (a host process speaking the framed agent protocol,
  emitting a scripted edge set and a scripted fault) exercises `AgentTransport`
  end-to-end; a fixture with a planted branch is reached and the edge count is
  nonzero and monotonic across inputs.
- In-tree: `MemoryBufferReader` reconstructs a known event stream from a
  captured ring image, including the wrap case, byte-for-byte.
- Hardware/emulator-gated (self-skip when absent, status recorded): `GdbRemoteTransport`
  drives a QEMU gdbstub `qemu-system-arm` "hello" image, resets between inputs,
  and reads a nonzero coverage buffer.

**In-tree vs gated.** Trait, host impl, both readers, agent protocol + mock, and
the gdb-remote client are pure software (in-tree, fully tested). Validation
against a real board or a live `qemu-system` gdbstub is DEPENDENCY (gated).

## HDF-2 — Fault detection without host POSIX signals

**Goal.** Detect and classify target faults that never produce a host
`SIGSEGV`/exit status — on-target CPU exceptions, MMU/MPU traps, watchdog
resets, stack/guard-region violations.

**Current evidence.** `fatal_signal::classify` is `#[cfg(unix)]` on
`ExitStatus::signal()` (`crates/cli/src/fatal_signal.rs:38-58`); the non-unix
branch only recognizes wine's `0x39`. On an RTOS single-address-space image a
fault does not reach `waitpid`.

**Deliverables.**

1. A backend-neutral `Fault` taxonomy (CPU exception vector, MMU/MPU fault,
   watchdog/reset, assertion/panic, stack-overflow/guard, timeout) decoupled
   from POSIX signal numbers.
2. A target-side fault-report contract carried over the HDF-1 transport (fault
   vector + fault address + optional register snapshot), emitted by the agent
   skeleton / a default exception-vector hook.
3. Mapping of the new taxonomy to existing finding rules (`BHF-210` family) and
   to compiler-assisted guards that survive cross builds (`-fsanitize=bounds`,
   stack protectors, shadow-call-stack) where full ASan cannot cross-compile.

**Acceptance criteria.**

- In-tree: the mock agent (HDF-1) reports each fault class; BHF classifies each
  to the correct finding rule and produces a replayable finding.
- In-tree: a host fixture built with `-fsanitize=bounds`/stack-protector traps a
  planted overflow and is classified without relying on a POSIX signal path.
- Gated: a real exception-vector hook on an emulated Cortex-M image reports a
  hard-fault back to BHF.

## HDF-3 — Big-endian and multi-arch fidelity (PowerPC, MIPS, SPARC)

**Goal.** Faithful fuzzing for the architectures that dominate fielded
RTOS/radar systems — big-endian PowerPC first — both for cross-execution and
for the host stub-isolation lane's input generation.

**Current evidence.** `resolve_cross_target` maps only aarch64/armhf (LE Linux)
and mingw; `ppc64`/`powerpc`/`mips`/`sparc`/`riscv64`/`s390x` return `None`
(`crates/cli/src/auto/cross_target.rs:90-129`, tested at `:947-957`). The typed
generator is hardcoded little-endian (`crates/fuzz_engine/builtin/src/typed.rs:105`).

**Deliverables.**

1. Cross-target mappings for `powerpc(64)(le)-linux-gnu`, `mips(el)-linux-gnu`,
   `sparc64-linux-gnu` (toolchain + emulator resolution), reusing the existing
   `CrossTarget`/`missing_tools` actionable-skip machinery.
2. A **target ABI model** (endianness, word size, alignment, struct-packing
   rules) threaded through `crates/type_model` and `typed.rs`, so typed inputs
   and struct layouts are generated in the *target's* byte order and layout, not
   the host's.
3. Byte-order-correct coverage/crash paths (no host-word-size assumptions in the
   transport readers from HDF-1).

**Acceptance criteria.**

- In-tree: the ABI model emits a known struct's bytes identically to a
  target-compiled layout for BE and LE (golden-vector test); a signed-integer
  candidate set is generated in target byte order.
- In-tree: `resolve_cross_target` returns actionable toolchain hints for the new
  triples; unknown remains `None`.
- Gated: a BE-only bug fixture (a byte-order-dependent parser) is found under
  `qemu-ppc64` but not on the LE host, proving fidelity gain.

## HDF-4 — Full-system and snapshot fuzzing

**Goal.** Fuzz code that only runs meaningfully in privileged/full-system
context — RTOS images, BSPs, drivers, ISRs — via full-system emulation with
snapshot/reset, feeding the HDF-1 transport.

**Current evidence.** Nyx adapter is a stub (`NotImplemented`; zero-coverage
software replay). No `qemu-system`/Renode/avatar2/Unicorn anywhere.

**Deliverables.**

1. A `FullSystemTransport` impl over `qemu-system-*` (gdbstub + QMP), with
   snapshot save/restore between iterations and coverage via QEMU edge
   instrumentation or the HDF-1 memory-buffer reader.
2. A Renode integration for MCU/peripheral-modeled targets (Renode scripts as
   the "board"), coverage via the same reader.
3. Either finish a real Nyx/kAFL backend (x86 VM snapshot; useful for
   Linux-based radar ground/C2 systems) **or** formally retire the stub in favor
   of `FullSystemTransport` (see CC-2).

**Acceptance criteria.**

- In-tree: the transport driver logic (snapshot/restore/step state machine) is
  unit-tested against a scripted QMP/gdbstub mock.
- Gated: a `qemu-system-arm` image with a planted vulnerable handler is fuzzed
  to a crash with coverage feedback and snapshot reset.

**Progress (2026-09-25).** Deliverable 1 landed: `FullSystemTransport` in
`crates/target_transport/src/fullsystem.rs`, a `TargetTransport` over
`qemu-system-*` composed from a new `QmpClient` (QMP handshake, `stop`/`cont`,
and `savevm`/`loadvm` via `human-monitor-command`) plus the existing `GdbClient`
(input delivery + coverage-ring readback via `MemoryBufferReader`). The
snapshot/reset state machine — `arm()` = QMP `stop` + `savevm <baseline>`;
`run_input()` = QMP `stop` + `loadvm <baseline>` (the per-iteration reset,
replacing gdb's unreliable `R`) + gdb input write + gdb `c` + ring read — is
unit-tested against the scripted `MockQmpServer` + `MockGdbStub`
(`crates/target_transport/src/testsupport.rs`): handshake and per-iteration
`loadvm`/input-write are asserted, coverage reconstructs the expected edges,
determinism (same input ⇒ same outcome) holds, and malformed/oversized QMP
messages and short memory reads are bounded, descriptive errors. All QMP reads
are capped (`QmpLimits`) against allocation/spin bombs. The live `qemu-system`
run remains **gated** (emulator + lawful image; unproven until run).

*Deliverable 2 (Renode)* is a documented follow-up (see the `fullsystem` module
docs): a Renode `.resc` board exposes a GDB server, so the same `GdbClient` +
`MemoryBufferReader` reconstruct coverage and Renode `Save`/`Load` play the
snapshot role; only a small monitor adapter (Renode's telnet CLI, not QMP) is
needed in place of `QmpClient`. It is deferred rather than shipped untested
because there is no Renode instance in-tree to validate against.

*Deliverable 3 (Nyx)* resolves roadmap **CC-2** for nyx by **retiring** the
`nyx_adapter` stub: it has no consumers, does not implement the transport seam,
and its software replay collects zero coverage (strictly weaker than
`HostChildTransport`). Rather than route a misleading zero-coverage backend
through the seam, its crate docs now mark it as scaffolding superseded by
`FullSystemTransport`, and `NyxError::NotImplemented` names `FullSystemTransport`
(HDF-4) as the replacement (asserted by a test). No coverage is fabricated.

## HDF-5 — Non-buffer entry-point discovery and environment/peripheral harness synthesis

**Goal.** Recognize and harness the entry points that carry attacker-influenced
data on RTOS/radar systems but take no byte-buffer argument: ISR handlers, task
entries, message-queue/pub-sub consumers, MMIO register readers, DMA callbacks.

**Current evidence.** Ranking is signature-shape + name only
(`crates/target_rank/src/c_rank.rs:1-19`); no buffer arg → `ReachabilityUnproven`
(−20). Zero awareness of `intConnect`/`taskSpawn`/`msgQReceive`. Harness gen is
"decode params, call once"; peripheral structs are zeroed scratch, callback
fields nulled to no-op trampolines (`crates/harness_gen/src/c_generate.rs:1313-1413`).

**Deliverables.**

1. Discovery recognizers for registration/consumer idioms — `intConnect`,
   `taskSpawn`, `msgQReceive`/`msgQReceive`-loops, MMIO map+read, cFS
   `CFE_SB_*`, DDS `take`/`read` — that mark the *registered/consuming* function
   as the fuzz unit regardless of its parameter signature, feeding
   `InputReachability` a new provenance class at rank time (not only the
   post-run `IpcChannelReachable` relabel).
2. An environment/peripheral harness model: fabricate device/peripheral structs
   and DMA buffers, and drive a *sequence* of register/queue reads that return
   successive fuzz-controlled values across one input.
3. Fuzz the bodies of registered callbacks instead of nulling them.

**Acceptance criteria.**

- In-tree: a fixture registering an ISR/consumer via `intConnect`/`msgQReceive`
  is discovered and ranked as attacker-reachable (not `ReachabilityUnproven`).
- In-tree: a generated harness for a polled-register reader delivers a
  fuzz-controlled *sequence* of reads and reaches a planted branch gated on the
  3rd read value.
- In-tree: a callback-driven parser fixture is fuzzed through the callback body,
  not a no-op trampoline.

## HDF-6 — Fuzz-driven dependency model beyond POSIX libc

**Goal.** Extend the runtrace shim's fuzz-driven-dependency capability (today:
POSIX `shm`/`mq`/mmap-device only, Linux/LD_PRELOAD only) to vendor RTOS APIs
and bare-metal MMIO.

**Current evidence.** Shim is `#![cfg(target_os = "linux")]` + `dlsym(RTLD_NEXT)`
(`crates/bhf_runtrace_shim/src/lib.rs:16-30`), POSIX symbols only. Vendor RTOS
calls (`msgQReceive`/`semTake`/`taskSpawn`/`intConnect`) are declaration-stubbed
then resolved as inert `return 0` (`crates/c_stub_gen/src/lib.rs:544-636`);
`stub_gen`/`c_stub_gen` have no fuzz-the-return-value mode.

**Deliverables.**

1. A **fuzz-driven stub mode** in `c_stub_gen`/`stub_gen`: a stubbed dependency
   (e.g. a hardware-read accessor) draws its return value from the live fuzz
   input (via `bhf_shim_set_fuzz_input`, keyed per symbol) instead of a constant.
2. Vendor-RTOS channel mappings: `msgQReceive`/`semTake`/etc. become
   fuzz-driven channels the way POSIX `mq_receive` already is
   (`crates/bhf_runtrace_shim/src/hooks/mqueue.rs`), for the host stub-isolation
   lane.
3. Compiler-assisted MMIO interception for bare-metal `volatile` register reads
   (not syscalls, so the LD_PRELOAD path cannot see them): an instrumentation
   pass that redirects fixed-address volatile loads to a fuzz-fed shadow.

**Acceptance criteria.**

- In-tree: a fixture reading a stubbed `read_sensor()` reaches a branch gated on
  a fuzz-controlled return value (constant-stub build cannot; fuzz-driven-stub
  build can).
- In-tree: a native `msgQReceive` consumer built host-side receives a
  fuzz-controlled message (today it receives an inert empty stub).
- In-tree: an MMIO fixture (`*(volatile uint32_t*)ADDR`) reaches a
  fuzz-controlled branch under the interception pass.

## HDF-7 — Binary-framed and on-the-wire stateful protocol input

**Goal.** Generate structurally valid binary protocol frames (length-prefixed /
TLV / checksummed) and drive stateful, on-the-wire protocol sessions — radar/
telemetry formats and defense middleware (IIOP/GIOP, DDS).

**Current evidence.** Input is always one flat buffer; the grammar
(`crates/fuzz_engine/builtin/src/grammar.rs`) is text-CFG with no computed
length/CRC/back-reference fields. `iiop` is a decode-only, unwired GIOP/CDR
library. `ada_state_machine` feeds only a print-JSON CLI subcommand, not the
engine.

**Deliverables.**

1. A structured/binary input model with **computed fields** — length, checksum/
   CRC, tag-length-value, offsets, back-references — either as grammar semantic
   actions or a typed message-descriptor format, so a mutated frame stays
   internally consistent.
2. Wire the `iiop` GIOP/CDR decoder into an actual IIOP fuzzer: add an encoder +
   transport + servant dispatch, so fuzz bytes → GIOP request → servant call.
3. Connect `ada_state_machine` (and a C equivalent) to the engine for
   AFLNet-style protocol-state-guided input ordering.
4. A transport layer (socket/DDS/queue) to inject a message sequence into a live
   consumer.

**Acceptance criteria.**

- In-tree: a length+CRC-framed fixture is reached past its integrity check by
  generated frames (a naive byte fuzzer cannot pass the CRC gate).
- In-tree: a GIOP request built by the new encoder round-trips through the
  existing decoder and dispatches to a fake servant.
- In-tree: a state-machine-guided session reaches a state unreachable by
  single-shot inputs.

## HDF-8 — Concurrency-schedule exploration and real-time/timing oracles

**Goal.** Find the dominant RTOS/radar bug classes — races, priority inversion,
deadlock, ISR-vs-task races, missed deadlines — rather than catching them by
luck.

**Current evidence.** `multicore_fuzz` is throughput sharding only. The sole
concurrency capability is TSan corpus-replay: C-only, host-only, observational,
nondeterministic (`crates/cli/src/auto/tsan.rs`). All timing is wall-clock
hang-detection; no virtual time, no deadline oracle. Replay is single-shot
deterministic-only.

**Deliverables.**

1. Systematic concurrency testing: schedule-perturbation / PCT-style exploration
   (or a controlled scheduler under emulation) so a specific interleaving can be
   forced and searched.
2. Deterministic/virtual-time injection and a **deadline oracle** ("must respond
   within D"), so watchdog/timing-dependent behavior is testable, not just
   "it hung."
3. Multi-run + schedule-pinned replay so a concurrency/timing crash reproduces.

**Acceptance criteria.**

- In-tree: a fixture with a race reachable only under a specific interleaving is
  found by schedule exploration (plain fuzzing misses it within the budget).
- In-tree: a deadline-violation fixture is reported as a *finding*, not silently
  killed-and-skipped.
- In-tree: the pinned-schedule replay reproduces a found race deterministically.

---

## CC-1 — Structured fidelity labeling (do first)

**Goal.** Replace the coarse per-target "reduced-fidelity" text caveat
(`crates/cli/src/auto/report.rs:3200-3208`) with a structured record, on every
finding and every campaign summary, of the dimensions exercised vs not:
`{arch, endianness, rtos_runtime, hardware/peripherals, concurrency,
sanitizers}`. A clean host-stub run must read as "portable logic fuzzed on host;
target ISA / RTOS runtime / hardware / concurrency NOT exercised," never as
target assurance.

**Acceptance criteria.** In-tree: the RTOS stub fixture's report explicitly
enumerates the un-exercised dimensions; a fully-native host target does not
carry spurious caveats; the JSON finding schema (`docs/finding-report-fields.md`)
gains the fidelity block.

## CC-2 — Finish or retire dead capabilities

**Goal.** Remove the misleading "capability surface" of unwired code: the
`fork_server` crate, the `iiop` decoder, the `ada_state_machine` extractor, the
Nyx `nyx-engine` stub, and the semihosting/memory-buffer emitters are all
present but not reachable end-to-end. Each is either wired in by a track above
(iiop→HDF-7, emitters→HDF-1, ada_state_machine→HDF-7, fork_server→HDF-1) or
explicitly marked as scaffolding in its crate docs and in `ROADMAP.md`, so
users and the roadmap are not misled.

**Acceptance criteria.** In-tree: no crate advertises an end-to-end capability
it does not have; each formerly-dead component is either wired (with a test
proving reachability) or documented as scaffolding with the tracking track named.

---

## 5. Risks and honest limitations

- **Hardware/emulator/toolchain dependence.** HDF-1 (probe/agent), HDF-3
  (PPC/MIPS/SPARC toolchains + emulators), and HDF-4 (qemu-system/Renode/images)
  have validation steps this repository cannot run without external resources.
  The software is built and tested behind mocks in-tree; those gated steps are
  recorded as **unproven** until run in an environment that has the resource.
  Completion of a track's *software* is not a claim of validated on-target
  capability.
- **Proprietary RTOS fidelity.** BHF's vendor-API models are scaffolding; they
  make code build and fuzz on the host, they do not reproduce Wind River /
  Green Hills runtime semantics. HDF-4 (real images under emulation) is the only
  path to true RTOS-semantic fidelity, and depends on the user supplying a
  lawfully-obtained image.
- **Concurrency completeness.** HDF-8 schedule exploration reduces but does not
  eliminate the luck factor; exhaustive interleaving search is intractable for
  real targets. Claims are bounded to "found within budget under exploration,"
  with preserved no-repro trials.
- **Scope.** This is a multi-wave program. Each track lands independently behind
  the HDF-1 transport seam; partial adoption (e.g. HDF-1+HDF-2+CC-1 only) is a
  coherent, shippable increment.

## 6. Definition of done (per track)

A track is *software-complete* when its in-tree acceptance criteria pass under
`cargo test` (self-skipping the gated cases), its findings carry a correct CC-1
fidelity record, and `cargo clippy`/`fmt` are clean. A track is *validated* only
when its gated acceptance criteria have been run against the real resource and
the evidence (versions, commands, coverage/exec counts, artifacts) is recorded
in `docs/validation/`. The two states are reported separately and never
conflated.
