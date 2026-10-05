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

- `BHF_RTOS_LIVE=1 cargo test -p target_transport --test live_rtos -- --nocapture`
  builds the pinned kernel and runs the smoke and full-drive tests. The full
  drive verifies task-aware input branches, a classified HardFault, and a clean
  input after snapshot reset. This passed on October 4, 2026 with the local
  ARM GCC/QEMU toolchain.
- `BHF_RTOS_CLI=1 cargo test -p bhf --test transport_fuzz_qemu_cli
  cli_freertos_clean_fault_clean -- --nocapture` exercises the shipped CLI
  against the FreeRTOS guest. It passed clean → fault → clean with a retained
  crash finding and a `bhf replay` MATCH. Each CLI invocation boots a fresh
  stopped guest; an existing guest parked at `harness_done` is not a valid new
  baseline.
- The operator's arbitrary FreeRTOS project, physical-board path, and retained
  production campaign are separate acceptance work. This reference profile covers
  one cooperative Cortex-M3 image under QEMU.

`BHF_RTOS_KERNEL=<path>` reuses a local kernel checkout for both tests. Otherwise
these opt-in tests fetch the pinned kernel commit. An explicitly enabled test
fails if it cannot obtain or verify that revision.

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

## Build & run (operator command path)

This is the `bhf fuzz` command path. The gated CLI test automates a
clean → fault → clean sequence with a retained finding and successful `bhf replay`.

```sh
# 1. Fetch the pinned kernel next to this dir (NOT committed) and point K at it.
git clone https://github.com/FreeRTOS/FreeRTOS-Kernel kernel
git -C kernel checkout 8be86d4a24fd4091f8f4192018423ab590f408db
K="$(pwd)/kernel"

# 2. Build the image.
arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -nostdlib -nostartfiles -ffreestanding -O1 -g \
  -I . -I "$K/include" -I "$K/portable/GCC/ARM_CM3" -T link.ld -o rtos.elf \
  startup.c app.c "$K/tasks.c" "$K/queue.c" "$K/list.c" \
  "$K/portable/GCC/ARM_CM3/port.c" "$K/portable/MemMang/heap_4.c"

# 3. Discover symbols (bhf_input, adafuzz_probe_memory_buffer{,_write,_wrapped},
#    harness_done, bhf_fault_flag, bhf_task_id) with `nm rtos.elf`.

# 4. Create the scratch disk savevm/loadvm needs (any small qcow2).
qemu-img create -f qcow2 scratch.qcow2 16M

# 5. Boot and drive through the shipped CLI (QMP + gdb over TCP).
qemu-system-arm -M mps2-an385 -nographic -S -kernel rtos.elf \
  -gdb tcp::3333 -qmp tcp:127.0.0.1:4444,server,nowait \
  -drive if=none,file=scratch.qcow2,format=qcow2,id=sc0 &
bhf fuzz bhf_work --harness freertos-queue \
  --target-transport "qemu-system:qmp=127.0.0.1:4444,gdb=127.0.0.1:3333,snapshot=base,done=<harness_done>,fault=<bhf_fault_flag>" \
  --transport-coverage-map "input=<bhf_input>,ring=<ring>,write=<write>,wrapped=<wrapped>,cap=512" \
  --max-len 64
```

`--max-len 64` bounds a generated input to the 64-byte `bhf_input` staging buffer.
The transport has no staging-capacity field and the CLI's default maximum is
larger, so without this cap a longer input would be written past `bhf_input[64]`
into adjacent guest memory. Keep `--max-len` ≤ the staging buffer size.

## Gated tests

The two commands in [Validation status](#validation-status) run the transport
and CLI tests. They require `arm-none-eabi-gcc`, `qemu-system-arm`, `qemu-img`,
and `nm`. The kernel commit is pinned above; bring a local checkout with
`BHF_RTOS_KERNEL` for disconnected validation.
