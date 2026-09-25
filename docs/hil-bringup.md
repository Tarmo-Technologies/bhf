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
| **HIL** | **real board via OpenOCD gdbstub** | **your bench** | `tests/hil_board.rs` |

The same `GdbClient` / `GdbRemoteTransport` RSP code drives all three. The board
lane needs no new code: attach a board, start OpenOCD, set `BHF_HIL_GDB`, and
`tests/hil_board.rs` runs the real-hardware path.

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

1. **Plug in** the Nucleo (ST-Link enumerates as USB; on Linux you may need the
   udev rules from the `stlink`/`openocd` packages so a non-root user can access
   it).

2. **Start OpenOCD** — it exposes a **gdb remote serial protocol server on
   `:3333`** (and a Telnet monitor on `:4444`):

   ```bash
   openocd -f board/st_nucleo_f4.cfg
   # ... "Info : Listening on port 3333 for gdb connections"
   ```

   For a J-Link instead: `openocd -f interface/jlink.cfg -f target/stm32f4x.cfg`.

3. **Flash the harness** (your instrumented firmware — see "Firmware contract"
   below). Either from OpenOCD's Telnet monitor:

   ```bash
   telnet localhost 4444
   > reset halt
   > flash write_image erase harness.elf
   > reset halt
   ```

   or with gdb: `gdb-multiarch harness.elf -ex 'target remote :3333' -ex load`.

4. **Point BHF at the gdbstub and run the board lane:**

   ```bash
   BHF_HIL_GDB=127.0.0.1:3333 \
   cargo test -p target_transport --test hil_board -- --nocapture
   ```

   With only `BHF_HIL_GDB` set, the test attaches, reads the general registers,
   and (if `BHF_HIL_PROBE_ADDR` is set) reads back a memory region — proving the
   link is live. Set the five ring-map variables to exercise a full
   `run_input` + coverage-ring readback (below).

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
| `BHF_HIL_GDB=host:port` | **Required.** The OpenOCD/gdbserver gdbstub (e.g. `127.0.0.1:3333`). |
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

With `-semihosting` firmware and OpenOCD's `arm semihosting enable`, the
`SemihostingReader` consumes the same `BHF_EVENTS` stream written to the
semihosting output channel. Use this when the board has no spare SRAM for a ring;
otherwise prefer the memory ring, which needs no host-side stream capture.
