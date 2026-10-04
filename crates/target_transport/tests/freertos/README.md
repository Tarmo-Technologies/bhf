<!-- SPDX-License-Identifier: Apache-2.0 -->
# FreeRTOS reference profile (full-system qemu-system-arm)

A **BHF-authored** benign queue/message application running on a **real open
RTOS** (FreeRTOS kernel) under `qemu-system-arm -M mps2-an385` (Cortex-M3),
driven through the shipped `FullSystemTransport` exactly like the bare-metal
RV-3 fixture. This is the first *actual-RTOS* reference profile, distinct from
the host vendor-header stubs (which exercise portable logic only and do **not**
establish RTOS behavior) and from the bare-metal Cortex-M fixture (no scheduler,
tasks, or queues).

BHF ships **no** RTOS image. The FreeRTOS kernel is fetched at build time at a
pinned commit (below) — "bring your own source" — and is **not** vendored into
this repository. Only the BHF-authored app, config, startup, and linker script
live here.

## Validation status

- **Validated today** (gated test, `BHF_RTOS_LIVE=1`): the real FreeRTOS image
  builds against the pinned kernel, boots on `mps2-an385`, the QMP + gdb attach
  and the harness-done breakpoint plant succeed, and the deterministic `savevm`
  baseline is captured. The app provably runs its tasks and emits task-aware
  coverage (verified by a direct run under gdb: the `consumer` task executes,
  the `0x75C0` task marker + branch crumbs appear in the coverage ring).
- **Gated / in progress** (`BHF_RTOS_FULL=1`): the full per-input fuzz drive
  (run to the harness-done stop, classify, reset) is not yet green. Two concrete
  follow-ups remain (isolated during bring-up):
  1. **Harness-done stop not observed.** A gdb/Z0 breakpoint at `harness_done`
     does not stop this FreeRTOS guest under `continue` (even without
     `savevm`/`loadvm`), though a direct free-run reaches the consumer and emits
     coverage. `harness_done` is now `noinline` (so it is a real call target),
     but the stop still needs debugging (breakpoint vs. the Cortex-M3 boot /
     scheduler-start path under QEMU TCG).
  2. **Input survives reset.** Unlike the bare-metal fixture, this startup must
     zero `.bss` and init `.data` (FreeRTOS requires it), which overwrites the
     transport's post-`loadvm` write to `bhf_input`. Move `bhf_input` into a
     `.noinit` section the startup does not clear so the delivered input
     survives the boot.

  Gated rather than asserted unvalidated, consistent with the roadmap's RTOS
  stance; this is the remaining actual-RTOS validation step.

## What it demonstrates (target contract)

- A **real FreeRTOS scheduler** with two tasks and a queue: a `producer` task
  forwards the fuzz input as one queue message; the `consumer` task (the
  selected entry point) receives it, records its **task identity**
  (`bhf_task_id`, plus a `0x75C0` *task-marker* coverage crumb so task-aware
  execution is visible in `coverage_edges`), dispatches on the input, and emits
  coverage.
- **Task-aware, input-gated coverage** read back over the transport's coverage
  ring (the Ada `memory_buffer` format), identical to the bare-metal lane.
- **Fault classification** through the `#72` fault-status channel: input `0xF7`
  executes `udf #0` → `HardFault_Handler` sets `bhf_fault_flag` and routes
  through `harness_done`, which the transport reads to classify a crash rather
  than a silent clean pass.
- **Deterministic reset** via QMP `savevm`/`loadvm`: the same input reproduces
  the same outcome after a fresh restore.

## Determinism / fidelity limitations (declared, not implied)

- **Cooperative scheduling** (`configUSE_PREEMPTION = 0`): task switches happen
  only at explicit blocks/yields, so execution is deterministic per input and
  safe for snapshot fuzzing. Preemptive/tick-race interleavings are **not**
  exercised; this profile makes no real-time or exhaustive-interleaving claim.
- Single core; **no peripheral / DMA / MMIO / cache modeling** beyond what the
  mps2-an385 machine provides; no multi-core.
- Host round-trip time is distinct from target execution time (the transport
  measures host-observed timing; see `--deadline`).
- This is an **emulator** profile. A physical board reuses the same transport
  contract (`docs/hil-bringup.md`) and must record the actual silicon / probe /
  RTOS versions; absence of board validation stays explicit.

## Pinned versions

- FreeRTOS-Kernel commit: `8be86d4a24fd4091f8f4192018423ab590f408db`
  (`https://github.com/FreeRTOS/FreeRTOS-Kernel`), GCC `ARM_CM3` port, `heap_4`.
- Toolchain: `arm-none-eabi-gcc`; emulator: `qemu-system-arm -M mps2-an385`
  (validated with QEMU 8.2.2 — see `docs/validation/2026-09-27-hil-emu-live-qemu.md`).

## Build & run (what the gated test automates)

```sh
# 1. Fetch the pinned kernel next to this dir (NOT committed).
git clone https://github.com/FreeRTOS/FreeRTOS-Kernel kernel
git -C kernel checkout 8be86d4a24fd4091f8f4192018423ab590f408db

# 2. Build the image (K = kernel dir).
arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -nostdlib -nostartfiles -ffreestanding -O1 -g \
  -I . -I "$K/include" -I "$K/portable/GCC/ARM_CM3" -T link.ld -o rtos.elf \
  startup.c app.c "$K/tasks.c" "$K/queue.c" "$K/list.c" \
  "$K/portable/GCC/ARM_CM3/port.c" "$K/portable/MemMang/heap_4.c"

# 3. Discover symbols (bhf_input, adafuzz_probe_memory_buffer{,_write,_wrapped},
#    harness_done, bhf_fault_flag, bhf_task_id) with `nm rtos.elf`.

# 4. Boot and drive through the shipped CLI (QMP + gdb over TCP).
qemu-system-arm -M mps2-an385 -nographic -S -kernel rtos.elf \
  -gdb tcp::3333 -qmp tcp:127.0.0.1:4444,server,nowait \
  -drive if=none,file=scratch.qcow2,format=qcow2,id=sc0 &
bhf fuzz bhf_work --harness freertos-queue \
  --target-transport "qemu-system:qmp=127.0.0.1:4444,gdb=127.0.0.1:3333,snapshot=base,done=<harness_done>,fault=<bhf_fault_flag>" \
  --transport-coverage-map "input=<bhf_input>,ring=<ring>,write=<write>,wrapped=<wrapped>,cap=512"
```

## Gated test

`crates/target_transport/tests/live_rtos.rs` automates the above and asserts the
control outcomes (clean / default / planted-fault), task-aware coverage, and
determinism. It self-skips unless `BHF_RTOS_LIVE=1` and the toolchain/emulator
are present; set `BHF_RTOS_KERNEL=<path>` to point at an already-fetched kernel
instead of cloning.
