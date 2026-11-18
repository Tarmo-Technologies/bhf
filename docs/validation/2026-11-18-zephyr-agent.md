<!-- SPDX-License-Identifier: Apache-2.0 -->
# Reference agent on Zephyr under QEMU, 2026-11-18

This record runs the reference target-side agent (`c_runtime/bhf_agent.c`,
#289) as a Zephyr module (#291) on an emulated Cortex-M3, driven by the
shipped `bhf fuzz` and `bhf replay`.

## Setup

- Zephyr v3.7.0 with its CMSIS module, `qemu_cortex_m3` (TI LM3S6965, QEMU's
  `lm3s6965evb`), built with Ubuntu's `arm-none-eabi-gcc` 13.2.1 through the
  `gnuarmemb` toolchain variant.
- `c_runtime/zephyr/samples/agent` serves the agent protocol on UART1.
  `-serial null -serial tcp:127.0.0.1:PORT,server=on,wait=off` makes it a
  socket for `agent:tcp:127.0.0.1:PORT`.
- The code under test, `src/target.c`, is built with
  `-fsanitize-coverage=trace-pc`. `BUG` reaches an undefined instruction, a
  CPU exception.
- Zephyr ends a thread that faults, so the agent is built with
  `BHF_AGENT_NO_SETJMP`. The module's `k_sys_fatal_error_handler` records
  the fault for the running input. The thread that started the agent sends
  the reply (`bhf_agent_report_fault`) and starts a new agent thread.

## Run

```sh
BHF_ZEPHYR_CLI=1 ZEPHYR_BASE=<zephyr> \
  cargo test -p bhf --test transport_zephyr_agent_cli -- --nocapture
```

The test builds the sample with `west`, boots it, and runs three
`bhf fuzz --iterations 1` passes and a replay in one boot. It passed in 6.6 s,
the `west build` included:

| Input | Outcome |
|---|---|
| `A` | clean, no finding; the agent's edges reached the engine |
| `BUG` | a finding whose detail is `Zephyr fatal error` |
| `A` | clean again in the same boot, served by a new agent thread |
| `bhf replay <finding>` | `MATCH`, re-driven through the agent in the same guest |

The glue also runs on the host, against a stand-in for the Zephyr API it
uses (`crates/target_transport/tests/agent/zephyr_host/`), in
`agent_loopback`. That test needs no Zephyr tree and runs on every build: three
faults in a row, each followed by a clean input on a new agent thread.

What this does not cover is a physical board and `agent:serial` on a real
UART.
