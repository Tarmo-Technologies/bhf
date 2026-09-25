<!-- SPDX-License-Identifier: Apache-2.0 -->
# Builtin harness protocol resolution

Finding recorded before implementation, 2026-09-24. Scope: the builtin fuzz
runner's protocol choice in `crates/cli/src/fuzz.rs`; the generated harness and
build layouts remain unchanged.

Resumed checkpoint, 2026-09-24: the real public generate → build → fuzz
regression now passes with framed execution, nonzero edge feedback and a
reproduced ASan finding. The integration also covers no-fork execution. It
exposed a second defect: fresh-process isolation of a framed driver must pass
the input filename as argv[1], since raw stdin does not call the target in
that mode. The runner now does so for native framed binaries. The rebuilt
release binary also passed a BHF-only benchmark smoke using the documented
split generated/build layout. See the root development plan for hashes and
remaining qualification gates.
The broader C++ amalgamation test then caught a related guard error: its
fresh-process recheck still required the external libFuzzer classification,
which framed drivers no longer have. The recheck now runs for framed-driver
coverage candidates. The five-test amalgamation target passed, including a
state-masked ASan crash reproduced from its saved testcase.

## Reproduced failure

The engine-parity `magic_byte` manual C workflow generated
`<work>/generated_harnesses/H-C0017/main.c` with a `BHF_FRAMED` persistent-loop
marker, then built `<work>/build/H-C0017/main`. The existing driver check only
read a `main.c` beside the **built binary**, and attempted to decode the binary
itself as UTF-8. It missed the generated source. The separate libFuzzer check
saw `main.c` in `generated_harnesses` and selected single-input argv mode.

Evidence in `benchmarks/engine-comparison/results/smoke-valid-20260924-01-runs/`
`magic_byte/trial-1/builtin/work/fuzz_runs/H-C0017-latest.json`: 125
executions in three seconds, `harness_protocol: libfuzzer_single_input`,
`forkserver: false`, no coverage edges, and no finding. The generated C source
contains `BHF_FRAMED`; the 1.57 MiB built ELF resides under `build/`, while the
24 KiB source resides under `generated_harnesses/`. This is a protocol mismatch,
not a performance comparison. A later unmodified benchmark repetition by the
feature agent reported the same protocol/coverage mismatch; execution count
varied with runner staging and must not be treated as a throughput baseline.

## Narrow resolution design

Resolve one harness-protocol classification from the runner path and work dir:
first look for an explicit `BHF_FRAMED` marker in bounded text reads of source
beside the binary, then in the matching `generated_harnesses`, `harnesses`, and
legacy `auto` source layouts, plus a textual launcher. Explicit framed evidence
wins over the presence of C/C++ source. Only source layouts without that marker
retain the existing libFuzzer single-input fallback; no C source remains the
stdin/event-log fallback. This retains real external libFuzzer support and
interpreted/script launchers while fixing the split generated/build layout.

Use the same classification for forkserver eligibility, coverage feedback,
single-input argv dispatch, crash replay/filtering, and the run summary. Resolve
once for the hot fuzz loop; replay-only helpers use the same resolver. Bound text
reads to a small fixed maximum and reject binary-looking executable prefixes
before reading the rest, so protocol detection never loads a whole ELF as a
UTF-8 string. A missing/oversized marker source falls back conservatively; the
forkserver handshake remains the runtime backstop.

## Regression acceptance

- Unit layouts: manual `build/<id>/main` plus
  `generated_harnesses/<id>/main.c` with `BHF_FRAMED`; sibling auto source;
  textual launcher; external libFuzzer C source without `BHF_FRAMED`; source
  absent; and a large binary that is not scanned as text.
- A bounded integration must invoke real generate-harness, build, then fuzz on
  a planted C crash fixture. Assert the built path differs from generated
  source, protocol is not `libfuzzer_single_input`, forkserver is active when
  requested, coverage edges are nonzero, and the expected sanitizer finding is
  emitted. Record execution count only as a diagnostic, never as a parity or
  throughput claim. Keep fixture local and deterministic; no benchmark trial
  is required for this regression.
