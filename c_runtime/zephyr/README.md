<!-- SPDX-License-Identifier: Apache-2.0 -->
# bhf reference agent on Zephyr

A Zephyr module that serves the bhf agent protocol (`c_runtime/bhf_agent.h`) on a UART, for `bhf fuzz --target-transport agent:serial:PATH`, or for `agent:tcp` through anything that exposes the UART as a socket. The agent protocol and the target-side agent are described in [`docs/site/on-target-fuzzing.md`](../../docs/site/on-target-fuzzing.md) (section 3c).

- `zephyr/module.yml`, `CMakeLists.txt`, `Kconfig`: the module. Add this directory to `ZEPHYR_EXTRA_MODULES` and set `CONFIG_BHF_AGENT=y`.
- `bhf_agent_zephyr.{h,c}`: `bhf_agent_zephyr_run(entry)` serves on the UART that the devicetree's chosen `bhf,agent-uart` names, running `entry` (with `LLVMFuzzerTestOneInput`'s signature) for each input.
- `samples/agent/`: an application for `qemu_cortex_m3` with a planted fault behind the input `BUG`.

Build the code under test with `-fsanitize-coverage=trace-pc` (GCC) or `trace-pc-guard` (clang) and no other coverage flags: the agent provides the callbacks. A fatal error in the code under test (a CPU exception, a failed `__ASSERT`) ends Zephyr's agent thread. The module's `k_sys_fatal_error_handler` records the fault for the running input, and the thread that called `bhf_agent_zephyr_run` sends its reply and starts a new agent thread for the next input. A fatal error in any other thread halts, as Zephyr's default handler does.

## The sample under QEMU

You need a Zephyr tree (`ZEPHYR_BASE`), `west`, `qemu-system-arm`, and Ubuntu's `arm-none-eabi-gcc` used through Zephyr's `gnuarmemb` toolchain variant:

```sh
export ZEPHYR_TOOLCHAIN_VARIANT=gnuarmemb GNUARMEMB_TOOLCHAIN_PATH=/usr
west build -b qemu_cortex_m3 -d build c_runtime/zephyr/samples/agent
qemu-system-arm -M lm3s6965evb -nographic -monitor none \
  -serial null -serial tcp:127.0.0.1:9000,server=on,wait=off \
  -kernel build/zephyr/zephyr.elf &
bhf fuzz bhf_work --harness H-zephyr --target-transport agent:tcp:127.0.0.1:9000 \
  --max-len 4096
```

With an agent transport, `--harness` only names the campaign; the code under test runs in the guest. UART0 keeps the console, and the sample's overlay puts the agent on UART1, QEMU's second `-serial`.

`crates/cli/tests/transport_zephyr_agent_cli.rs` runs this sample end to end when `BHF_ZEPHYR_CLI=1` is set, and `crates/target_transport/tests/agent_loopback.rs` runs the glue on the host against a stand-in for the Zephyr API it uses.
