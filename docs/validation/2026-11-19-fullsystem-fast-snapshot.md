<!-- SPDX-License-Identifier: Apache-2.0 -->
# Full-system dirty-page fast snapshot (`reset=fast`) — live QEMU (2026-11-19)

`reset=persistent` (#346) leaves a clean run's guest where it stopped, but a
crash, a hang or an inconclusive run is still followed by a full `loadvm`.
`reset=fast` needs none, faults included: a `system_reset` brings back the
CPUs and devices, and bhf writes back only the RAM pages the last run wrote,
which its QEMU TCG plugin logs, with the Cortex-M writes the plugin cannot
see (bit-band stores and the exception frames still stacked at the stop)
added. [Limits](#limits) lists what it does not restore. This record measures
the reset against a `loadvm` on the RV-3 image, and lists the checks behind
the mode.

## Environment

- Base `343bc959` plus the `reset=fast` change.
- QEMU 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.18), `qemu-system-arm -M mps2-an385`
  (Cortex-M3), a 16 MB scratch `qcow2` for `savevm`, QMP on a Unix socket, the
  gdbstub on loopback TCP with `TCP_NODELAY`.
- `arm-none-eabi-gcc` 13.2.1, `-O0`; the plugin built by the host `cc`
  (`-shared -fPIC -O2 -Wall -Werror`). Linux 6.8, 6 vCPUs, shared with other
  builds (load averages below).
- The image is the RV-3 harness of
  `crates/target_transport/tests/live_fullsystem.rs`, plain build: one
  `run_one(); harness_done();` per boot, a real `udf #0` HardFault for input
  `0xF7` whose handler sets `bhf_fault_flag` and returns through
  `harness_done`.

## Reset latency

`live_fullsystem_fast_snapshot_resets_five_times_faster_than_loadvm` (`#[ignore]`, run by `scripts/hil-emu.sh` on the nightly schedule, a manual dispatch or a local run) boots two guests from the same image, one with `reset=loadvm` and one with the plugin and `reset=fast`. After a warm-up of nine inputs each (the fast snapshot learns its pages there), it gives each 3 s in six 500 ms slices taken in turn, running `0x42`, `0x00`, `0xF7` in a cycle, so a third of the inputs are HardFaults. It checks every run's exit and coverage, that no measured fast reset needed a `loadvm`, and that the mean fast reset is at most a fifth of the mean `loadvm`, and prints the measured ratio. Each reset's time is the session's own, in `RunOutcome::target.reset.time`.

When this record was taken the test required a tenth and was named `live_fullsystem_fast_snapshot_resets_ten_times_faster_than_loadvm`. A scheduled run on a GitHub runner then measured 9.5x, so the threshold is now 5x (#452): below every ratio measured here and on the runners, and still a failure for a fast snapshot that regresses toward a `loadvm`'s cost.

```sh
cargo test -p target_transport --test live_fullsystem \
  live_fullsystem_fast_snapshot_resets_five_times_faster_than_loadvm -- --ignored --nocapture
```

| Host load (1 min) | `loadvm` mean reset | `reset=fast` mean reset | Ratio | exec/s (loadvm, fast) |
|---|---|---|---|---|
| 1.0 | 5.75 ms | 377 µs | 15.3x | 146.3, 747.0 |
| 1.1 | 5.96 ms | 384 µs | 15.5x | 140.3, 734.3 |
| 1.9 (`--ignored`, after the persistent benchmark) | 5.69 ms | 355 µs | 16.1x | 150.0, 814.3 |
| 1.9 | 5.54 ms | 377 µs | 14.7x | 152.7, 761.7 |
| 0.1 (gdb read a byte at a time) | 4.82 ms | 387 µs | 12.4x | 167.0, 617.7 |
| 2.0 (gdb read a byte at a time) | 5.68 ms | 460 µs | 12.4x | 141.0, 525.7 |
| 2.0 (gdb read a byte at a time, `--ignored`) | 12.9 ms | 618 µs | 20.8x | 65.7, 466.7 |

The first four rows are the final form. A fast reset of this image is a
register read (`xPSR`, with the stack pointers after a fault), the
dirty-page log read (about 15 µs), the gdbstub monitor's `system_reset` and a
`g` to check it, and two page writes of 256 bytes: the stack page and the
input's page. The pages the image's `.data`/`.bss` segment covers whole are
reloaded by QEMU's reset itself, so bhf does not write them. The rows marked
"a byte at a time" are the same reset with gdb's packets read one byte per
`read` call; reading a buffer at a time took the mean fast reset from
about 430 µs to about 370 µs.

An earlier form, before the register read, measured 15.4x to 17.0x at load
3.5. One that sent QMP `system_reset` (a QMP round trip, about 200 to 300 µs
here) where this form sends the gdbstub monitor command measured 11.6x to
15.5x. One that also wrote each dirty page by itself, toggled the gdbstub's
physical-memory mode around every reset, and logged loads as well as stores
(QEMU 8.2 calls a `QEMU_PLUGIN_MEM_W` callback for an instruction's loads
too, so a PC-relative literal load dirtied a code page) measured 9.2x at
load 4.9, with five pages per reset.

## Behaviour checks

- `live_fullsystem_fast_snapshot_brings_a_fault_back_without_a_loadvm`: inputs
  `0x42, 0x00, 0xF7, 0xF7, 0x42, 0x00, 0xF7, 0x42, 0xF7, 0xF7, 0x00` on one
  guest. The QMP channel carried one `loadvm`, the reset before the second
  input, which learned two pages; every later reset was a dirty-page one,
  the resets after each HardFault included. Every run's coverage was its
  own, each `0xF7` was a `Crash`/`CpuException`, and each other input was
  clean with the fault word put back. Two HardFaults in a row both ran the
  handler: a HardFault leaves the Cortex-M in handler mode with the fault
  active, and a second one there would lock the core, so the reset had
  cleared the first.
- `cli_qemu_system_fast_reset_builds_its_plugin_finds_the_fault_and_replays`
  (`crates/cli/tests/transport_fuzz_qemu_cli.rs`): `bhf fuzz` with
  `reset=fast,dirty_log=PATH` against a QEMU without the plugin exited 2,
  built `<work>/qemu-plugin/libbhf_qemu_dirty_pages.so` and printed the
  `-plugin` argument. Against a QEMU started with it, seeds
  `0x42, 0x00, 0xF7, 0x42, 0x00, 0x42` ran 6 executions with one crash and one
  finding (the inputs after the fault were clean); the finding's
  `transport_profile.json` named the fast snapshot in `reset_mechanism`, and
  `bhf replay` on a fresh guest without the plugin reported `MATCH`.
- `live_fullsystem_fast_snapshot_restores_bitband_stores_and_fault_frames`:
  the `-DBHF_STATE` build of the harness sets a word at `0x2001_0000` through
  the SRAM bit-band alias (`0x2220_0000`) on every run, and input `0xF5` moves
  the stack to `0x2002_0010` and faults, so the HardFault's 32-byte frame
  reaches 16 bytes into the page at `0x2002_0000`, which no store writes. Both
  lie outside every image segment, so QEMU's reset leaves them. A run that
  finds either from an earlier run emits a crumb for it. Over inputs
  `0x42, 0xF5, 0x42, 0x00, 0xF5, 0xF5, 0x42, 0x00, 0xF5, 0x42` every run's
  coverage was the baseline's, and every reset from the fourth input on was a
  dirty-page one. With the bit-band windows left out of the log's header, the
  fourth input found the word (crumb `0x5B`); with the frame ranges left out,
  the sixth found the frame (crumb `0x5F`). The reset after a fault on the
  moved stack writes 20 pages (the 4 KiB above the stop's stack pointer and
  the logged ones), about 1.4 ms.
- `live_fullsystem_fast_snapshot_refuses_a_log_no_plugin_writes`: a QEMU
  started without the plugin and a well-formed log at `dirty_log=`. The first
  input ran; the reset before the second stopped the session with "the guest
  ran, and no dirty-page plugin saw it run", where without the check the
  second input ran on a guest whose stores went unrestored.
- Library tests against a mock guest memory (`fast_snapshot.rs`): only the
  dirty pages are written back, consecutive ones in one write; a page's first
  write is learned from a full restore; the host's own writes (the input) are
  restored with the guest's; an overflowed log, a page past the baseline
  cap, and the reset after a failed one restore in full; pages the device
  reset reloads are neither learned nor written; a frame noted as an
  unlogged write is learned and written back as a dirty page is; the plugin's
  log file is read, emptied into a new epoch, and refused when missing or
  foreign, when no plugin acknowledged the epoch a run ran in, and when
  another session emptied it; the bit-band windows are written to its header.
  QEMU's `info mtree -f` is read for RAM and the bit-band windows onto it, a
  Cortex-M target description for `sp`, `xPSR` and `PSP`, and the frame
  ranges are those above the stack pointer while an exception is active,
  clipped to RAM.
- Mock QMP and gdbstub tests (`fullsystem.rs`): arm resets the machine
  before `savevm` and switches the gdbstub to physical-memory mode once; the
  reset is the gdbstub's monitor command and a `g`; a gdbstub without a
  monitor falls back to QMP; registers a reset does not bring back stop the
  run; a hung guest is stopped before its reset; a `query-status` every
  128 device resets keeps the QMP event backlog bounded; on a Cortex-M stub
  arm reads the memory map and puts the SRAM bit-band window in the log, a
  thread-mode stop reads `xPSR` alone, and after a HardFault the stack up to
  the baseline's stack pointer and the frame at `PSP` are learned and
  written back though no store wrote them; a Cortex-M machine whose memory
  map names no RAM is refused; and a log no plugin writes stops the session
  at the reset after the first run.
- bhf library tests: `--workers` specs that resolve to one `dirty_log=`,
  however it is spelled, are refused; the session lane refuses `reset=fast`,
  on a campaign and on the replay of a stored spec.

## Limits

- `reset=fast` runs on QEMU, through its TCG plugin interface (`-plugin`);
  the board lane (`gdb:`) and Renode keep their own resets.
- The baseline is the machine as a reset leaves it. A firmware that must
  boot past its reset vector before the input is staged runs that boot for
  every input, as it does under `reset=loadvm` from a `-S` start.
- What the log does not see is not restored: RAM a device writes (DMA), on a
  Cortex-M core the frame of an exception taken and returned before the stop
  (an interrupt) in a page no store wrote, on other cores what QEMU writes
  for the CPU outside an instruction's stores (an x86 interrupt's frame), and
  device state a reset does not clear (a flash part's contents). The frames
  are found from the stop's registers: the stack up to the baseline's stack
  pointer when the stop's lies within 64 KiB below it, else the 4 KiB above
  the stop's, and 0xD8 bytes at `PSP`.
- The plugin declares plugin API version 1, which QEMU 8.x takes. Another
  QEMU needs the plugin built with `-DBHF_QEMU_PLUGIN_VERSION=N`; when bhf
  builds it, set the environment variable `BHF_QEMU_PLUGIN_VERSION=N`. This
  record ran QEMU 8.2.2.
- The rates are wall-clock host rates for a minimal image, measured in a
  debug build, and include the gdb round trips. The benchmark has run on this
  host; its margin on hosted runners waits on a nightly HIL-emu run.
