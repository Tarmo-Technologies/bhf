<!-- SPDX-License-Identifier: Apache-2.0 -->
# Full-system persistent loop (`reset=persistent`) — live QEMU (2026-11-19)

The `qemu-system:` lane restored its `savevm` baseline with a QMP `stop` plus
HMP `loadvm` before every input and recorded no throughput. `reset=persistent`
restores only before the first input and after a crash, a hang or an
inconclusive run; between clean inputs the firmware's own loop reads the next
input. This record measures both modes on the RV-3 image and the checks behind
the mode.

## Environment

- Base `00f443eb` plus the `reset=persistent` change.
- QEMU 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.18), `qemu-system-arm -M mps2-an385`
  (Cortex-M3), a 16 MB scratch `qcow2` for `savevm`, QMP on a Unix socket, the
  gdbstub on loopback TCP with `TCP_NODELAY`.
- `arm-none-eabi-gcc` 13.2.1, `-O0`. Linux 6.8, 6 vCPUs, shared with other
  builds.
- The image is the RV-3 harness of
  `crates/target_transport/tests/live_fullsystem.rs` built with
  `-DBHF_PERSISTENT`: `harness_done` returns, and `Reset_Handler` loops over
  `run_one(); harness_done();`. A `0x50` crumb marks the loop's first turn
  after a restore, so coverage shows whether a run followed a `loadvm`.

## Throughput

`live_fullsystem_persistent_loop_outruns_a_loadvm_per_input` (`#[ignore]`,
run by `scripts/hil-emu.sh` on the nightly schedule, a manual dispatch or a
local run, not on a pull request or a push) boots two guests from the same
image, one per mode, and gives each 3 s in six 500 ms slices taken in turn,
so a change in the host's load meets both alike. It runs alternating clean inputs (`0x42`,
`0x00`), checks every run's exit and coverage, and requires the persistent
count to be at least 3x the `loadvm` count.

```sh
cargo test -p target_transport --test live_fullsystem -- --ignored --nocapture
```

| Host load (1 min) | `reset=loadvm` | `reset=persistent` | Ratio |
|---|---|---|---|
| 1.4 | 409 runs, 136.3 exec/s | 1712 runs, 570.7 exec/s | 4.19x |
| 2.1 | 445 runs, 148.3 exec/s | 1883 runs, 627.7 exec/s | 4.23x |
| 2.3 | 470 runs, 156.7 exec/s | 2086 runs, 695.3 exec/s | 4.44x |
| 2.3 | 490 runs, 163.3 exec/s | 2022 runs, 674.0 exec/s | 4.13x |
| 2.6 | 457 runs, 152.3 exec/s | 2026 runs, 675.3 exec/s | 4.43x |
| 0.7 | 599 runs, 199.7 exec/s | 2305 runs, 768.3 exec/s | 3.85x |
| 0.6 | 582 runs, 194.0 exec/s | 2246 runs, 748.7 exec/s | 3.86x |
| 0.7 | 558 runs, 186.0 exec/s | 2189 runs, 729.7 exec/s | 3.92x |
| 0.8 | 590 runs, 196.7 exec/s | 2232 runs, 744.0 exec/s | 3.78x |

The last four rows are the final form of the mode, with the step check and
the proof by coverage below, on a near-idle host. There a `loadvm` is
cheaper, so the ratio is lower; the form before those checks measured 3.78x
and 4.12x in the same conditions, so the checks, which run only until the
loop is proven, cost no measurable throughput.

An earlier form of the test measured the modes one after the other, 3 s
each: 3.70x to 4.88x on the same host at a load near 2.8, and 8.49x (65.3
against 555.0 exec/s) at a load near 17. A `loadvm` took 4.4 ms to 9.9 ms
depending on the host's disk and page cache, with outliers past 40 ms; the
persistent rate moved much less.

A persistent run costs a breakpoint remove, step and insert, two ring-word
writes, the input write, the `c`, and the fault-word and ring reads (and,
until the loop is proven, a `g` before and after the step). A
`loadvm` run costs the QMP `stop` and `loadvm` in place of the step and the
ring writes. This board's RAM is small, so its `loadvm` is about as cheap as
one gets; a larger guest costs more per `loadvm`, and the persistent loop
does not.

After the persistent window (over 1,600 continuations) the same test runs the
planted fault: it is a `Crash`, and the next input shows the `0x50` crumb and
a second `loadvm` on the QMP channel.

## Behaviour checks

- `live_fullsystem_persistent_loop_restores_only_after_a_fault`: inputs
  `0x42, 0x00, 0x42, 0xF7, 0x42, 0x00, 0x42`. The QMP channel carried one
  `loadvm` for the first four and a second only after the `0xF7` HardFault,
  which classified as `Crash`/`CpuException` on a continuation. Each run's
  coverage was its own (the ring is emptied before a continuation), and the
  `0x50` crumb appeared on the first input and the one after the fault only.
- `live_fullsystem_persistent_loop_refuses_a_firmware_that_does_not_loop`: the
  plain RV-3 image, whose `harness_done` spins after its `-O0` prologue, under
  `reset=persistent` with a 500 ms deadline. Each continuation stepped off
  `done` and hung, was run again from the snapshot and reported clean (no
  false hang); the fourth input stopped the session with `reset=persistent: 3
  continuations of the guest's input loop did not show that the guest ran
  their input ... the firmware's done function must return into a loop that
  runs the next input from the staging region ...`.
- `live_fullsystem_persistent_loop_refuses_a_done_that_spins_in_place`: the
  RV-3 harness with `harness_done` a noinline `for (;;) {}`, built `-O1`, which
  is one `b.n .` at `0x68`. Inputs `0x42, 0x00, 0xF7, 0x42, 0xF7, 0x00, 0xF7`:
  each input after a clean run was refused (`the step off done= at 0x68
  changed no register, so the done function branches to itself ... use
  reset=loadvm`), each other one ran from the snapshot, and the `0xF7`s were a
  `Crash` with the fault edges or a refusal, never a clean run. Before the step
  check, the same sequence reported `0x00` as a clean run with no coverage,
  and that clean continuation counted as proof of the loop.
- `cli_qemu_system_persistent_reset_finds_the_fault_and_records_executions_per_sec`
  (`crates/cli/tests/transport_fuzz_qemu_cli.rs`): `bhf fuzz` with
  `reset=persistent` over seeds `0x42, 0x00, 0xF7, 0x42, 0x00` ran 5
  executions with one crash finding; the summary's `executions_per_sec` and the
  finding's `transport_profile.json` `throughput` block were set, its
  `reset_mechanism` named the persistent loop, and `bhf replay` on a fresh
  guest reported `MATCH`.
- The deadline oracle: a continuation that hangs before the loop is proven
  is run again from the snapshot, and the session reports that run's own
  host time, which `--deadline` judges. The library test
  `a_hung_continuation_rerun_from_the_snapshot_is_no_deadline_finding` (mock
  QMP and gdbstub, a 400 ms execution deadline, `--deadline 150ms`) made a
  false response-deadline finding before this and none after it.
- Mock-gdbstub tests in `fullsystem.rs` cover the rest: a step that leaves
  the registers unchanged is refused and does not park the guest; a
  continuation that comes back with no coverage is run from the snapshot,
  where its crash is reported; three of them are refused; a step that does
  not trap is run from the snapshot; and a proven loop reads no registers.
- The QMP event backlog: QEMU sends a `STOP` and a `RESUME` event for each gdb
  step and continue. With the periodic `query-status` disabled, the restore
  after the benchmark window failed with `QMP emitted more than 4096 events
  without a response to "stop"`; with it every 128 continuations, it passed.

## Limits

- Emulator only; the board lane (`gdb:`) and Renode keep their own resets.
- Between clean inputs the guest's state carries over, as in any
  persistent-mode fuzzer. A finding that needs the inputs before it may not
  replay from the snapshot, and its transport profile says so.
- The loop is proven by coverage: a firmware that records none cannot prove
  it and is refused after three continuations, and needs `reset=loadvm`.
- The session lane refuses `reset=persistent`.
- The benchmark has run on this host only; its margin on hosted runners
  waits on a nightly HIL-emu run.
- The rates are wall-clock host rates for a minimal image and include the gdb
  round trips; they are not target execution time.
- Much of either mode's run is bhf's gdb client, which reads the link one byte
  per `read` call and reads the coverage ring's whole capacity. With the gdb
  stream buffered on the test side, the rates rose to about 1,050 and 218
  exec/s (4.8x). Those costs are shared with the `gdb:` and `renode:` lanes and
  are not changed here.
