<!-- SPDX-License-Identifier: Apache-2.0 -->
# Emulator-in-the-loop validation — live QEMU (2026-09-27)

Ran `scripts/hil-emu.sh` with `BHF_HIL_REQUIRE=1` (missing-tool = hard failure,
gated tests cannot self-skip). This exercises the RTOS/radar / HDF-1 / HDF-3 /
HDF-4 back-half tracks that `docs/high-demand-fuzzing-roadmap.md` §1a lists as
**software-complete in-tree but "unproven until run"** against a live
emulator/cross toolchain. This is the first recorded execution of the real live
path in this environment.

**Result: RV-1, RV-2, RV-3 all executed the REAL live path and passed (exit 0).**

## Environment

- git: `main` @ `dfee887`; `target_transport` + live tests are tracked on main
  (the transport/validation code landed on main at `c16f879`, 2026-09-25 — it is
  **not** stranded on the `rtos-radar-fuzzing` branch, which is now behind main).
- QEMU 8.2.2 (Debian) — `qemu-system-arm`, `qemu-arm`, `qemu-ppc64`, `qemu-img`.
- `arm-none-eabi-gcc` 13.2.1; `powerpc64-linux-gnu-gcc` 13.3.0;
  `arm-linux-gnueabihf-gcc`; `nm`; `cc`.

## What passed

| ID | Track | What actually ran | Evidence |
|---|---|---|---|
| RV-1 | HDF-3 big-endian fidelity | `big_endian_input_reaches_a_native_endian_branch_only_on_the_target` — same input bytes reach a native-endian branch **only** on the big-endian ppc64 target under `qemu-ppc64`, not on the LE host | `cli` unit test, 1 passed |
| RV-2 | HDF-1 on-target transport | real `GdbClient`/`GdbRemoteTransport` (RSP) against a real `qemu-arm` user-mode gdbstub: read a fixed 16-byte `known_region` out of the live target (bytes matched), continue-to-exit, reset packet, `arm()` attach — 6 live checks | `live_gdb`, 1 passed |
| RV-3 | HDF-4 full-system (flagship) | `FullSystemTransport` end-to-end on emulated Cortex-M (`qemu-system-arm -M mps2-an385`): QMP handshake + gdb attach + `savevm` baseline → per-input `loadvm` reset → input write over gdb → `MemoryBufferReader` reads the coverage ring → asserted edges, **determinism** (0x42 → same edges twice), and the **planted HardFault** on input `0xF7` (`udf #0` → `HardFault_Handler`, distinct fault-marker breadcrumb) | `live_fullsystem`, 1 passed |

Key RV-3 trace:
```
live_fullsystem: arm() OK — QMP handshake + gdb attach + savevm baseline
live_fullsystem: input=0x42 edges=[100, 101, 200, 201] exit=Ok
live_fullsystem: input=0x00 edges=[100, 101, 300]
live_fullsystem: input=0xF7 edges=[100, 101, 1fa, fa17] — REAL Cortex-M HardFault path taken
live_fullsystem: determinism — 0x42 again edges=[100, 101, 200, 201] (== first run)
```

## Honest carve-outs (still gated)

- **Emulator, not silicon.** This validates against QEMU, not a physical board.
  The real-hardware lane (`crates/target_transport/tests/hil_board.rs`, driven by
  `BHF_HIL_GDB=host:port` against OpenOCD/a Nucleo board per `docs/hil-bringup.md`)
  is **not** exercised here — no board present.
- **No proprietary RTOS image.** VxWorks / INTEGRITY / QNX images and vendor
  toolchains are still not run (BHF ships none; non-goal). The Cortex-M image is
  a BHF-authored bare-metal harness, and the ppc64 target is a Linux-user process.
- **HDF-7 remains library-only** (IIOP dispatch + `ProtocolStateGraph` not wired
  to a `bhf` subcommand) — unchanged by this run.

## Reproduce

```sh
BHF_HIL_REQUIRE=1 scripts/hil-emu.sh
```
