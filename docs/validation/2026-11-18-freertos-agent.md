<!-- SPDX-License-Identifier: Apache-2.0 -->
# Reference agent as a FreeRTOS task under QEMU, 2026-11-18

Before this record, the agent lane (`--target-transport agent:tcp` / `agent:serial`) ran against mocks. This record runs the reference target-side agent (`c_runtime/bhf_agent.c`, #289) as a FreeRTOS task on an emulated Cortex-M3 (#290), driven by the shipped `bhf fuzz` and `bhf replay`.

## Setup

- `qemu-system-arm -M mps2-an385` (Cortex-M3), FreeRTOS kernel at the pinned commit `8be86d4a24fd4091f8f4192018423ab590f408db`, `arm-none-eabi-gcc` 13.2.1.
- `crates/target_transport/tests/freertos/agent_task.c` serves the agent protocol over UART0. `-serial tcp:127.0.0.1:PORT,server=on,wait=off` makes the UART a socket for `agent:tcp:127.0.0.1:PORT`.
- The code under test, `agent_target.c`, is built with `-fsanitize-coverage=trace-pc`. Its edges are the block addresses the agent reports. `BUG` reaches an undefined instruction, which is a HardFault.
- A fault returns from the HardFault exception into a recovery function on the agent task's stack. That function reports the fault for the running input and goes on with the next. The image has no C library, so it carries its own ten-register `setjmp`/`longjmp`.

## Run

```sh
BHF_RTOS_CLI=1 BHF_RTOS_KERNEL=<kernel checkout> \
  cargo test -p bhf --test transport_freertos_agent_cli -- --nocapture
```

Or by hand: `make agent.elf KERNEL=<kernel>` in `crates/target_transport/tests/freertos`, then boot it and point `bhf fuzz` at the UART socket (the Makefile's header has the commands).

## Result

One boot runs three `bhf fuzz --iterations 1` passes and a replay. It passed in 2.2 s on the local toolchain:

| Input | Outcome |
|---|---|
| `A` | clean, no finding; the agent's edges reached the engine |
| `BUG` | HardFault, a finding whose detail names it |
| `A` | clean again in the same boot: the task recovered from the fault |
| `bhf replay <finding>` | `MATCH`, re-driven through the agent in the same guest |

The run used QEMU, `agent:tcp`, and a fault handler that returns to the task. An image whose fault handler cannot return uses the reset-and-report path that `BHF_AGENT_NO_SETJMP` selects; the [Zephyr record](2026-11-18-zephyr-agent.md) runs that path under QEMU. A physical board and `agent:serial` on a real UART are not yet tested.
