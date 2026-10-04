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

- **Validated today** (gated smoke `live_rtos_freertos_build_boot_arm_snapshot_smoke`,
  `BHF_RTOS_LIVE=1`): the real FreeRTOS image builds against the pinned kernel,
  boots on `mps2-an385`, the QMP + gdb attach and the harness-done breakpoint
  plant succeed, and the deterministic `savevm` baseline is captured. `arm()`
  succeeding IS the assertion — this tier does **not** drive inputs. The app runs
  its tasks and emits task-aware coverage under a direct gdb free-run (the
  `consumer` task executes; the `0x75C0` task marker + branch crumbs appear in the
  ring) — bring-up evidence, not an automated per-input assertion.
- **Gated / in progress** (full drive `live_rtos_freertos_full_fuzz_drive`,
  `BHF_RTOS_LIVE=1` **and** `BHF_RTOS_FULL=1`): the full per-input fuzz drive (run
  to the harness-done stop, classify, reset) is **not yet green** and is excluded
  from the ordinary gated run — it must not be read as passing. One concrete
  follow-up remains:
  1. **Harness-done stop not observed.** A gdb/Z0 breakpoint at `harness_done`
     does not stop this FreeRTOS guest under `continue` (even without
     `savevm`/`loadvm`), though a direct free-run reaches the consumer and emits
     coverage. `harness_done` is `noinline` (so it is a real call target), but the
     stop still needs debugging (breakpoint vs. the Cortex-M3 boot /
     scheduler-start path under QEMU TCG).

  Fixed during this review (no longer a blocker): **input now survives reset.**
  `bhf_input` is declared in a `.noinit` section (see `link.ld`) placed after
  `.bss` and marked `NOLOAD`, so neither startup's `.bss` zero loop nor the
  `.data` copy clears the transport's post-`loadvm` write — the delivered input
  reaches the producer. The ring/flags intentionally stay in `.bss`/`.data` so
  they reset per run (fresh coverage, no inherited fault).

  Gated rather than asserted unvalidated, consistent with the roadmap's RTOS
  stance; the harness-done stop is the remaining actual-RTOS validation step, and
  #84 stays open until the clean → fault → clean CLI path passes end to end.

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

This is the `bhf fuzz` command path. The gated **smoke** automates only the
build/boot/arm/snapshot portion (it drives the transport library, not this CLI);
the clean → fault → clean CLI run with a retained finding + replay is the #84
acceptance that is **not yet passing** (blocked on the harness-done stop above).

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

## Gated test

`crates/target_transport/tests/live_rtos.rs` drives the transport **library**
directly (not the `bhf fuzz` CLI above) in two self-skipping tiers; set
`BHF_RTOS_KERNEL=<path>` to reuse an already-fetched kernel instead of cloning:

- `live_rtos_freertos_build_boot_arm_snapshot_smoke` (`BHF_RTOS_LIVE=1`) — builds
  the real pinned kernel, boots it, completes the QMP + gdb attach, plants the
  harness breakpoint, and captures the `savevm` baseline. `arm()` succeeding is
  the assertion; it does **not** drive inputs.
- `live_rtos_freertos_full_fuzz_drive` (`BHF_RTOS_LIVE=1` **and**
  `BHF_RTOS_FULL=1`) — the per-input clean / default / planted-fault assertions,
  task-aware coverage, and determinism. **KNOWN-INCOMPLETE**: blocked on the
  harness-done stop (follow-up #1 above), so it is excluded from the ordinary
  gated run and must not be read as passing.

Neither tier establishes the operator CLI path: obtaining a clean → fault → clean
run through `bhf fuzz` with a retained finding and a successful `bhf replay` is
the remaining #84 acceptance, which keeps the issue open.
