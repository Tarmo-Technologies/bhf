<!-- SPDX-License-Identifier: Apache-2.0 -->

# BHF v0.2.33 release notes

Released 2026-09-28.

This release makes the built-in fuzzing engine solve comparison gates on its
own, and ships the first user-facing documentation for the on-target / embedded
(RTOS / radar / firmware) lane. There are no breaking changes; a run that does
not hit an integer/magic-value gate behaves as before.

## Built-in `bhf fuzz` solves comparison gates by default

The built-in coverage-guided engine already carried a RedQueen-style cmplog
mutator and a value-profile channel, but only `bhf auto` armed them. The raw
`bhf fuzz` command never wired the in-campaign input-to-state shared-memory
channels — `BHF_CMP_SHM` (per-input comparison operands, #400) and `BHF_VP_SHM`
(value profile, #398) — so it ran **blind** against an integer or magic-value
comparison gate and could only clear one by chance (~2⁻³² for a 32-bit compare).

`prepare()` now arms both channels by default for built-in / BhfFramed
harnesses, exactly as `bhf auto` does, with `BHF_DISABLE_REDQUEEN=1` as the
kill-switch. There is no throughput cost on the exploration path (measured
60.3k exec/s armed vs 60.6k off on a non-crashing target); the engine colorizes
and captures operands once per corpus base and biases that base's children
toward the offset-aware splice.

On the `redqueen_int` engine-parity fixture — a crash gated behind a 32-bit
comparison against a length-derived magic — the built-in engine moves from
**0/10 to 10/10**, at a 0.43s median time-to-first-crash. That matches the
AFL++ cmplog and libFuzzer value-profile lanes it is benchmarked against; BHF
now solves all four parity fixtures (`magic_byte`, `const_gate`, `len_field`,
`redqueen_int`). A regression test now drives the `bhf fuzz` path cold — the
prior gate only exercised `bhf auto`, which is why the gap went unnoticed.

## On-target / embedded documentation and validation

A new **On-Target & Embedded** guide documents the RTOS / radar / firmware lane
end to end — what each feature is and the exact commands to set it up and run
it:

- cross-build (`--target` / `--runtime` / `--toolchain`) and the coverage
  probe backends (`--probe-backend`);
- vendor RTOS builds via `--build-command` (Wind River Diab, Green Hills, QNX,
  Keil/IAR, TI), `--extra-include`, and `--sanitizers none`;
- the three `--target-transport` backends — on-device agent (`agent:tcp` /
  `agent:serial`), gdb-remote debug probe (`gdb:`), and full-system
  `qemu-system` snapshot — with the `--transport-coverage-map` spec;
- on-target faults → findings and the `--deadline` real-time timing oracle
  (BHF-555);
- big-endian / non-x86 fidelity, comparison-progress, HIL boards, and the
  emulator-in-the-loop validation lane.

`--deadline`, `--target-transport`, and `--transport-coverage-map` are now in
the CLI reference (previously documented only in `--help`).

The emulator-in-the-loop lane was **validated live on QEMU 8.2.2** — RV-1
(big-endian ppc64 fidelity under `qemu-ppc64`), RV-2 (the gdb-remote client
against a live `qemu-arm` gdbstub), and RV-3 (`FullSystemTransport` on
`qemu-system-arm`: savevm/loadvm snapshot reset + coverage-ring readback + a
planted HardFault). Evidence is recorded under `docs/validation/`, and the RTOS
roadmap's status language was reconciled to match. Genuinely resource-gated
paths — real silicon, the TCP/serial agent transport, proprietary RTOS images,
and Renode — remain honestly gated.

## Upgrading

No configuration change is required. If you drive `bhf fuzz` directly and rely
on the previous blind-mutation behavior, `BHF_DISABLE_REDQUEEN=1` restores it.
