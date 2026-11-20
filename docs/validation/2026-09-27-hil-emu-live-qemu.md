<!-- SPDX-License-Identifier: Apache-2.0 -->
# Emulator-in-the-loop validation — live QEMU (2026-09-27)

Ran `scripts/hil-emu.sh` with `BHF_HIL_REQUIRE=1` (a missing tool is a hard
failure, so gated tests cannot skip themselves). This exercises the RTOS/radar
HDF-1, HDF-3 and HDF-4 back-half tracks that §1a of the
[high-demand fuzzing roadmap](../high-demand-fuzzing-roadmap.md) listed as
**software-complete in-tree but "unproven until run"** against a live
emulator/cross toolchain. It is the first recorded run of the live path in
this environment.

**Result: RV-1, RV-2 and RV-3 ran the live path and passed (exit 0).**

## Environment

- git: `main` at `dfee887`. The `target_transport` crate and its live tests
  merged to `main` in `c16f879` (2026-09-25).
- QEMU 8.2.2 (Debian): `qemu-system-arm`, `qemu-arm`, `qemu-ppc64`, `qemu-img`.
- `arm-none-eabi-gcc` 13.2.1; `powerpc64-linux-gnu-gcc` 13.3.0;
  `arm-linux-gnueabihf-gcc`; `nm`; `cc`.

## What passed

| ID | Track | What ran | Evidence |
|---|---|---|---|
| RV-1 | HDF-3 big-endian fidelity | `big_endian_input_reaches_a_native_endian_branch_only_on_the_target`: the same input bytes reach a native-endian branch on the big-endian ppc64 target under `qemu-ppc64` and miss it on the little-endian host | `cli` unit test, 1 passed |
| RV-2 | HDF-1 on-target transport | real `GdbClient`/`GdbRemoteTransport` (RSP) against a real `qemu-arm` user-mode gdbstub: read a fixed 16-byte `known_region` out of the live target (bytes matched), continue-to-exit, reset packet, `arm()` attach; 6 live checks | `live_gdb`, 1 passed |
| RV-3 | HDF-4 full-system | `FullSystemTransport` end-to-end on emulated Cortex-M (`qemu-system-arm -M mps2-an385`): QMP handshake + gdb attach + `savevm` baseline → per-input `loadvm` reset → input write over gdb → `MemoryBufferReader` reads the coverage ring → asserted edges, **determinism** (0x42 → same edges twice), and the **planted HardFault** on input `0xF7` (`udf #0` → `HardFault_Handler`, distinct fault-marker breadcrumb) | `live_fullsystem`, 1 passed |

Key RV-3 trace:
```
live_fullsystem: arm() OK — QMP handshake + gdb attach + savevm baseline
live_fullsystem: input=0x42 edges=[100, 101, 200, 201] exit=Ok
live_fullsystem: input=0x00 edges=[100, 101, 300]
live_fullsystem: input=0xF7 edges=[100, 101, 1fa, fa17] — REAL Cortex-M HardFault path taken
live_fullsystem: determinism — 0x42 again edges=[100, 101, 200, 201] (== first run)
```

## Scope

- **Emulator.** The run targets QEMU. The physical-board lane
  (`crates/target_transport/tests/hil_board.rs`, driven by
  `BHF_HIL_GDB=host:port` against OpenOCD and a Nucleo board, as in
  [HIL bring-up](../hil-bringup.md)) needs a board, and none was attached.
- **Images.** The Cortex-M image is a bare-metal harness written for BHF, and
  the ppc64 target is a Linux user-mode process. BHF ships no VxWorks,
  INTEGRITY or QNX images or vendor toolchains, and this run used none.
- **HDF-7** was library-only on this date: IIOP dispatch and
  `ProtocolStateGraph` had no `bhf` command. `bhf fuzz --protocol-profile`
  (c8c8fd0, 2026-10-02) later exposed protocol sessions, and 10060d8 added
  the IIOP session backend; see the
  [stateful protocol sessions design](../designs/2026-10-02-stateful-protocol-sessions.md).

## Reproduce

```sh
BHF_HIL_REQUIRE=1 scripts/hil-emu.sh
```
