<!-- SPDX-License-Identifier: Apache-2.0 -->

# HIL bring-up: fuzzing a real ARM board over gdb-remote

This is the drop-in lane for running BHF's on-target transport
(`crates/target_transport`) against a **physical** ARM board, once you have one on
your desk. It is the hardware counterpart to the emulator validations that
already run here:

| Lane | Backend | Runs where | Test |
|---|---|---|---|
| RV-2 | `qemu-arm` user-mode gdbstub | this VM / CI (`hil-emu.yml`) | `tests/live_gdb.rs` |
| RV-3 | `qemu-system-arm -M mps2-an385` + QMP snapshot | this VM / CI (`hil-emu.yml`) | `tests/live_fullsystem.rs` |
| HIL stand-in | `qemu-system-arm -M mps2-an385`, gdbstub only, run from a board profile | this VM / CI (`hil-emu.yml`) | `tests/hil_board.rs` |
| Agent stand-in | the reference agent on a pseudo-terminal, from a board profile's serial lane | this VM / CI | `crates/cli/tests/transport_agent_serial_cli.rs` |
| **HIL** | **real board via OpenOCD gdbstub** | **your bench** | `tests/hil_board.rs` |

The same `GdbClient` / `GdbRemoteTransport` RSP code drives all of them. A board
is described once, in a **board profile** (`docs/hil-boards/nucleo-f411re.toml`
is the template): the `gdb:` spec of its probe with the completion breakpoint,
the fault-status word and the reset, the coverage map of its firmware, and the
`agent:serial:` spec of its UART. `tests/hil_board.rs` and
`bhf fuzz --board-profile` both read it. The stand-ins run the same profile
format against QEMU and a pty, so every step below except the hardware ones is
exercised without a board; the run on a physical board is tracked as #357.

> The same board is also drivable from the shipped CLI —
> `bhf fuzz … --target-transport gdb:HOST:PORT --transport-coverage-map …` — over
> the identical RSP path. See the published **On-Target & Embedded** guide
> (`docs/site/on-target-fuzzing.md`) for the flag-driven workflow; this runbook
> is the hardware bring-up detail (BOM, wiring, firmware contract) behind it.

## BOM

| Item | ~Price | Why |
|---|---|---|
| **ST Nucleo-F411RE** | ~$15 | Cortex-M4, **on-board ST-Link/V2-1** (USB → SWD, no separate probe needed), Arduino + Morpho headers. The on-board ST-Link is a full gdb-capable SWD probe, so this single board is enough to run everything below. |
| USB-A → mini-B cable | ~$3 | Powers + debugs the Nucleo via the ST-Link. |
| *(optional)* **Segger J-Link EDU Mini** | ~$20 | Only if you want **RTT** (SEGGER Real-Time Transfer) as the coverage channel instead of memory-mapped ring readback, or faster/HW breakpoints. Not required — the on-board ST-Link + memory readback covers the ring path. |

The Nucleo-F411RE is the recommended first board: cheapest path to a real
Cortex-M HardFault vector, real SWD halting-debug, and a genuine on-chip SRAM ring
that the existing `MemoryBufferReader` reads back verbatim.

## Toolchain

```bash
sudo apt-get install -y \
  gcc-arm-none-eabi \    # build the firmware/harness
  gdb-multiarch \        # optional: manual poking
  openocd               # the SWD ↔ gdbstub bridge
```

## Bring-up

Each step gives the command and what it prints when it works. Steps 1 to 3 need
the board; the rest are the same against the stand-ins (see
[Without a board](#without-a-board-the-stand-ins)).

1. **Plug in the board and find its probe.**

   ```bash
   lsusb | grep -i st-link
   ```

   Expected: a line like `ID 0483:374b STMicroelectronics ST-LINK/V2.1`. On
   Linux a non-root user needs the udev rules from the `openocd` package.

2. **Start OpenOCD.** It serves the gdb remote serial protocol on `:3333` and
   its command line on `:4444`.

   ```bash
   openocd -f board/st_nucleo_f4.cfg
   ```

   Expected, among its startup lines:
   `Info : Listening on port 3333 for gdb connections`. For a J-Link instead:
   `openocd -f interface/jlink.cfg -f target/stm32f4x.cfg`.

3. **Flash the harness** (your instrumented firmware; see
   [Firmware contract](#firmware-contract-what-the-harness-on-the-board-must-expose)).

   ```bash
   gdb-multiarch harness.elf -batch -ex 'target extended-remote :3333' \
     -ex 'monitor reset halt' -ex load -ex 'monitor reset halt'
   ```

   Expected: `Loading section .text, size ...`, then
   `Transfer rate: ...` and no error. From OpenOCD's command line,
   `flash write_image erase harness.elf` prints `wrote N bytes`.

4. **Read the firmware's contract addresses.**

   ```bash
   arm-none-eabi-nm -n harness.elf | grep -E \
     'bhf_input|harness_done|bhf_fault_flag|adafuzz_probe_memory_buffer'
   ```

   Expected: one line per symbol, for example
   `08000200 T harness_done`, `20000000 B adafuzz_probe_memory_buffer`,
   `20000200 B adafuzz_probe_memory_buffer_write`,
   `20000204 B adafuzz_probe_memory_buffer_wrapped`,
   `20000208 B bhf_fault_flag` and `2000020c B bhf_input`. `bhf_input` must be
   in a section the startup code leaves alone (`.noinit` in the linker
   script; `arm-none-eabi-objdump -t harness.elf | grep bhf_input` names it):
   bhf writes it after the reset, before the firmware runs.

5. **Write the board profile.** Copy `docs/hil-boards/nucleo-f411re.toml` and
   put the addresses of step 4 in it: `done=` is `harness_done`, `fault=` is
   `bhf_fault_flag`, and the coverage map's `input=`, `ring=`, `write=` and
   `wrapped=` are the input buffer and the ring. `input_cap` is the input
   buffer's size and `cap` the ring's. `reset=monitor:reset halt` resets the
   chip through OpenOCD before each input. bhf checks every spec in the profile
   when it reads it, so a mistyped one is refused before anything connects,
   with the spec error and the file's path.

6. **Check the lane with the test.**

   ```bash
   BHF_HIL_PROFILE=board.toml BHF_HIL_INPUT=41 \
     cargo test -p target_transport --test hil_board -- --nocapture
   ```

   Expected, in order: `hil_board: attached, initial stop = Signal(5)`,
   `hil_board: read N register bytes`, a
   `hil_board: run_input([41]) -> exit=Ok, fault=None, edges [...]` line with
   at least one edge, and `hil_board: PASSED against gdbstub 127.0.0.1:3333`.
   No edges means the ring map is wrong or the firmware emitted no crumbs; a
   run that never stops means `done=` is not where the run ends.

7. **Fuzz the board.**

   ```bash
   bhf fuzz work --harness H-BOARD --board-profile board.toml \
     --seed-input A --time 10m
   ```

   Expected: a JSON summary on stdout with `"executions"` and
   `"coverage_edges"` above zero, `"incomplete_observations": 0` and
   `"halted": null`. A fault the HardFault handler records through `fault=`
   is a finding under `work/results/findings/`, its detail
   `firmware fault-status 0x... at 0x...`.

8. **Fuzz over the UART instead** (the reference agent in the firmware,
   `c_runtime/bhf_agent.c`, with the board's UART as its read and write
   callbacks).

   ```bash
   bhf fuzz work --harness H-BOARD --board-profile board.toml \
     --board-lane serial --seed-input A --time 10m
   ```

   Expected: `bhf fuzz: board "nucleo-f411re" over agent:serial:/dev/ttyACM0,baud=115200`
   on stderr, then a summary as in step 7. A silent UART ends the run with
   `"halted": "... the serial device sent nothing within ..."`.

## Without a board: the stand-ins

Both lanes run here against stand-ins that use the same profile format:

```bash
cargo test -p target_transport --test hil_board -- --nocapture
```

builds a Cortex-M firmware that starts as a board's does (it zeroes `.bss` and
keeps its input in `.noinit`), boots it under `qemu-system-arm` with only a
gdbstub, writes its profile (`reset=monitor:system_reset`: QEMU's system
gdbstub refuses `R`) and runs four inputs. Expected:
`hil_board: run_input([41]) -> exit=Ok, fault=None, edges [100, 300]`,
`run_input([f7]) -> exit=Crash, fault=Some("firmware fault-status 0xdeadfa11 at ..."), edges [100, 1fa, fa17]`,
`run_input([42]) -> exit=Ok, ... edges [100, 200, 201]` and `[41]` again with
the edges of the first, since each input runs from reset.

```bash
cargo test -p bhf --test transport_agent_serial_cli -- --nocapture
```

builds the reference agent with `c_runtime/examples/agent_posix.c --pty`, which
serves a pseudo-terminal and prints its path, writes a profile whose `serial`
lane names it, and runs two 300-input campaigns over it. Expected: the test
`the_reference_agent_on_a_pty_runs_a_board_profiles_serial_lane ... ok`; the
second campaign's seeds reach deeper code and record the agent's fault once.

## Firmware contract (what the harness on the board must expose)

The board lane reuses the exact memory-buffer coverage channel the Ada runtime
already emits (`ada_runtime/adafuzz-probe-memory_buffer.adb`) and that
`target_transport::coverage::MemoryBufferReader` reconstructs. Your firmware
harness must, in a fixed SRAM layout:

* accept an input at a fixed **input** address (the fuzzer writes the testcase
  there over SWD before each run),
* fill the **coverage ring** in the `MemoryBufferReader` format — a base buffer
  plus a `_write` cursor (`u32`, little-endian) and a `_wrapped` flag (`u8`),
  written byte-for-byte like the Ada `Write_Byte` (`BHF_EVENTS` `Crumb` records:
  tag byte `3` then the `u32` breadcrumb id, little-endian), and
* end each run at a known **`harness_done`** symbol (a tight loop) where the host
  plants a breakpoint.

Real **HardFault vectors** work naturally here: a planted fault path (illegal
access / `udf`) traps to the chip's `HardFault_Handler`, which records a distinct
fault breadcrumb before reaching `harness_done` — exactly as
`tests/live_fullsystem.rs` demonstrates on the emulated core.

### Run-control: real boards vs. the emulated core

An important difference the emulator lane exposed: under the QEMU gdbstub,
halting-debug is off by default, so a guest `BKPT` **escalates to a HardFault**
instead of halting to the debugger — the emulator harness therefore self-halts by
having the host plant a **gdbstub software breakpoint** (`Z0`) at `harness_done`
(`FullSystemTransport::with_harness_breakpoint`). On a **real board over SWD**,
OpenOCD enables halting-debug (`C_DEBUGEN`), so both a hardware breakpoint (`Z1`,
FPB unit) and a literal `BKPT` instruction halt cleanly to the debugger. Either
works; the `GdbClient::insert_sw_breakpoint(addr, kind)` path is identical.

## Environment variables (`tests/hil_board.rs`)

| Variable | Meaning |
|---|---|
| `BHF_HIL_PROFILE=board.toml` | The board profile; it replaces the variables below except `BHF_HIL_INPUT`. |
| `BHF_HIL_GDB=host:port` | Without a profile, **required**: the OpenOCD/gdbserver gdbstub (e.g. `127.0.0.1:3333`). |
| `BHF_HIL_PROBE_ADDR=0x…` | Optional. An address to read back as a liveness check. |
| `BHF_HIL_PROBE_LEN=N` | Optional. Bytes to read at `PROBE_ADDR` (default 16). |
| `BHF_HIL_INPUT_ADDR=0x…` | Input staging address the fuzzer writes to. |
| `BHF_HIL_RING_ADDR=0x…` | Base of the coverage ring. |
| `BHF_HIL_RING_WRITE_ADDR=0x…` | Address of the `_write` cursor (`u32` LE). |
| `BHF_HIL_RING_WRAPPED_ADDR=0x…` | Address of the `_wrapped` flag (`u8`). |
| `BHF_HIL_RING_CAP=N` | Ring capacity in bytes (default 65536, the Ada capacity). |
| `BHF_HIL_INPUT=deadbeef` | Optional hex input delivered before the run. |

Set the four `..._ADDR` variables (and, if not the default, `RING_CAP`) to drive
a full `GdbRemoteTransport::run_input`: it writes the input, continues, and reads
the on-board ring back into coverage edges. Discover the addresses from your
firmware's map file (`arm-none-eabi-nm harness.elf`), mask the Thumb bit (bit 0)
off any function symbol used as a breakpoint address.

## RTT (optional, J-Link)

If you fit a J-Link and prefer SEGGER RTT to memory-mapped ring readback, the RTT
control block is just another in-RAM buffer; `openocd`'s `rtt` commands or
`JLinkRTTLogger` stream it out. BHF's `coverage::SemihostingReader` /
`MemoryBufferReader` already decode the `BHF_EVENTS` stream regardless of the
byte channel it arrives on, so an RTT bridge is a channel adapter, not a
new decoder. This is a documented follow-up — the memory-ring path above is the
supported one and needs no extra hardware.

## Semihosting (alternative coverage channel)

With `--probe-backend semihosting` firmware and OpenOCD's `arm semihosting
enable` and `arm semihosting_fileio enable`, each semihosting write reaches BHF's
gdb connection as a File-I/O request, and `coverage=semihosting` in the coverage
map decodes the `BHF_EVENTS` stream the probe writes to fd 2 (see
[Semihosting coverage](site/on-target-fuzzing.md#semihosting-coverage)). Use
this when the board has no spare SRAM for a ring; otherwise prefer the memory
ring, which costs no host round trip per write.
