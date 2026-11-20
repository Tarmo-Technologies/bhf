<!-- SPDX-License-Identifier: Apache-2.0 -->
# FreeRTOS reference profile (full-system qemu-system-arm)

A small queue and message application, written for bhf, running on the
FreeRTOS kernel under `qemu-system-arm -M mps2-an385` (Cortex-M3). bhf drives
it through the full-system transport (`--target-transport qemu-system:...`),
the same way as the bare-metal Cortex-M fixture. Unlike the host builds
against vendor-header stubs, which exercise portable logic, and the bare-metal
fixture, which has no scheduler, this profile runs a real RTOS scheduler with
tasks and a queue.

bhf ships no RTOS image. The FreeRTOS kernel is fetched at build time at the
pinned commit below and is not vendored into this repository. This directory
holds only the application, the FreeRTOS config, the startup code and the
linker script.

## Validation status

- `BHF_RTOS_LIVE=1 cargo test -p target_transport --test live_rtos -- --nocapture`
  builds the pinned kernel and runs the smoke and full-drive tests. The full
  drive checks task-aware input branches, a classified HardFault, and a clean
  input after a snapshot reset. Last recorded pass: 2026-10-04, with
  `arm-none-eabi-gcc` and QEMU.
- `BHF_RTOS_CLI=1 cargo test -p bhf --test transport_fuzz_qemu_cli
  cli_freertos_clean_fault_clean -- --nocapture` runs the `bhf` CLI against the
  FreeRTOS guest: clean, fault, clean, with a retained crash finding and a
  `bhf replay` MATCH. Each CLI invocation boots a fresh guest stopped at reset;
  a guest already parked at `harness_done` is not a valid new baseline.
  `cli_freertos_hang_times_out_and_the_reset_clears_state` runs the timeout
  and state-contamination controls below.
- The profile covers one cooperative Cortex-M3 image under QEMU. Your own
  FreeRTOS project and a physical board each need their own bring-up
  ([`docs/hil-bringup.md`](../../../../docs/hil-bringup.md)).

`BHF_RTOS_KERNEL=<path>` makes both tests use a local kernel checkout, which
must be at the pinned commit. Without it, the tests fetch the pinned commit.
A test you enabled fails if it cannot obtain or verify that revision.

## What it demonstrates

- **An interrupt-driven entry point.** Built with `-DBHF_ISR_ENTRY`, the image
  takes its input from external interrupt 0 (UART0 RX on mps2-an385), whose
  handler posts it to the consumer with `xQueueSendFromISR`, and no producer
  task is created. QEMU ignores a debugger's writes to the NVIC, so `main()`
  pends the interrupt itself, standing for the byte arriving. The CLI test
  `cli_freertos_isr_entry_finds_a_fault_and_records_the_task` finds the
  `0xF7` fault through it, and `task_id=` (the address of `bhf_task_id`)
  records which task ran the input.
- **A FreeRTOS scheduler** with two tasks and a queue: a `producer` task
  forwards the fuzz input as one queue message; the `consumer` task (the
  selected entry point) receives it, records its **task identity**
  (`bhf_task_id`, plus a `0x75C0` task-marker coverage crumb so task-aware
  execution shows in `coverage_edges`), dispatches on the input, and emits
  coverage.
- **Task-aware, input-gated coverage**, read back over the transport's
  coverage ring (the Ada `memory_buffer` format), as in the bare-metal lane.
- **Fault classification** through the fault-status channel: input `0xF7`
  executes `udf #0`, `HardFault_Handler` sets `bhf_fault_flag` and routes
  through `harness_done`, and the transport reads the flag and classifies the
  run as a crash.
- **Deterministic reset** through QMP `savevm`/`loadvm`: the same input gives
  the same outcome after a fresh restore.
- **A timeout control**: input `0xD0` loops without reaching `harness_done`,
  so the run ends at `--timeout` with a deadline finding (BHF-555).
- **A state-contamination control**: input `0xC5` sets `bhf_carryover`, which
  lives in `.noinit` so startup does not clear it, and a `0x42` that sees it
  set faults. Run after a `0xC5` in one session, the `0x42` is clean because
  the snapshot restore resets the guest's memory; after a plain
  `system_reset` it faults.

## Determinism and fidelity

- **Cooperative scheduling** (`configUSE_PREEMPTION = 0`): tasks switch only
  at explicit blocks and yields, so execution is deterministic per input and
  safe for snapshot fuzzing. Preemption and tick-driven interleavings do not
  occur in this profile.
- Single core. Peripherals, DMA, MMIO and caches are whatever the mps2-an385
  machine model provides.
- Host round-trip time and target execution time are separate measurements.
  `--deadline` uses host-observed time unless the spec reads a target counter
  (`cycles=`, `cpu_hz=`). QEMU does not count `DWT_CYCCNT`; the CLI test
  reads the FPGAIO `COUNTER` under `-icount`, and inputs `0xB0`..`0xBF`
  busy-loop in proportion to their low nibble.
- This is an emulator profile. A physical board uses the same transport
  contract ([`docs/hil-bringup.md`](../../../../docs/hil-bringup.md)); record
  the silicon, probe and RTOS versions you validate on.

## Pinned versions

- FreeRTOS-Kernel commit `8be86d4a24fd4091f8f4192018423ab590f408db`
  (`https://github.com/FreeRTOS/FreeRTOS-Kernel`), GCC `ARM_CM3` port,
  `heap_4`.
- Toolchain `arm-none-eabi-gcc`; emulator `qemu-system-arm -M mps2-an385`,
  validated with QEMU 8.2.2
  ([`docs/validation/2026-09-27-hil-emu-live-qemu.md`](../../../../docs/validation/2026-09-27-hil-emu-live-qemu.md)).

## Build and run

These are the commands the gated CLI test automates (clean, fault, clean, a
retained finding and a successful `bhf replay`). Run them from this directory.

```sh
# 1. Fetch the pinned kernel here (not committed) and point K at it.
git clone https://github.com/FreeRTOS/FreeRTOS-Kernel kernel
git -C kernel checkout 8be86d4a24fd4091f8f4192018423ab590f408db
K="$(pwd)/kernel"

# 2. Build the image.
arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -nostdlib -nostartfiles -ffreestanding -O1 -g \
  -I . -I "$K/include" -I "$K/portable/GCC/ARM_CM3" -T link.ld -o rtos.elf \
  startup.c app.c "$K/tasks.c" "$K/queue.c" "$K/list.c" \
  "$K/portable/GCC/ARM_CM3/port.c" "$K/portable/MemMang/heap_4.c"

# 3. Find the symbol addresses (bhf_input, adafuzz_probe_memory_buffer{,_write,_wrapped},
#    harness_done, bhf_fault_flag, bhf_task_id) with `nm rtos.elf`. nm prints
#    a Thumb function's address with bit 0 set (harness_done at 0x189 is code
#    at 0x188). bhf clears that bit for done= when done_kind is 2 (the default)
#    and says so; a breakpoint at the odd address would never hit.

# 4. Create the scratch disk savevm/loadvm needs (any small qcow2).
qemu-img create -f qcow2 scratch.qcow2 16M

# 5. Boot the guest and fuzz it through the CLI (QMP and gdb over TCP).
qemu-system-arm -M mps2-an385 -nographic -S -kernel rtos.elf \
  -gdb tcp::3333 -qmp tcp:127.0.0.1:4444,server,nowait \
  -drive if=none,file=scratch.qcow2,format=qcow2,id=sc0 &
bhf fuzz bhf_work --harness freertos-queue \
  --target-transport "qemu-system:qmp=127.0.0.1:4444,gdb=127.0.0.1:3333,snapshot=base,done=<harness_done>,fault=<bhf_fault_flag>" \
  --transport-coverage-map "input=<bhf_input>,input_cap=64,ring=<ring>,write=<write>,wrapped=<wrapped>,cap=512"
```

Replace each `<...>` with the address from step 3: `<ring>`, `<write>` and
`<wrapped>` are `adafuzz_probe_memory_buffer`,
`adafuzz_probe_memory_buffer_write` and `adafuzz_probe_memory_buffer_wrapped`.
`input_cap=64` is the size of the `bhf_input` staging buffer. bhf lowers
`--max-len` to it and never writes an input past it; a longer input would
overwrite the guest memory after `bhf_input[64]` (here `bhf_fault_flag`, so
every such input would read as a fault).

## Gated tests

The two commands in [Validation status](#validation-status) run the transport
and CLI tests. They need `arm-none-eabi-gcc`, `qemu-system-arm`, `qemu-img`
and `nm`. To run them without network access, set `BHF_RTOS_KERNEL` to a local
checkout at the pinned commit.

## The reference agent as a task

`agent_task.c` runs the reference target-side agent (`c_runtime/bhf_agent.c`)
as a FreeRTOS task serving the agent protocol over UART0, and
`agent_target.c` is its code under test. `make agent.elf KERNEL=<kernel>`
builds the image, and
`BHF_RTOS_CLI=1 cargo test -p bhf --test transport_freertos_agent_cli` drives
it through `bhf fuzz --target-transport agent:tcp` under `qemu-system-arm`.
See [the validation record](../../../../docs/validation/2026-11-18-freertos-agent.md).
