<!-- SPDX-License-Identifier: Apache-2.0 -->
# Builtin harness protocol resolution

The builtin fuzz engine has to know how a harness binary takes its input before it can fuzz it. `crates/cli/src/protocol_detect.rs` makes that choice once, and `bhf fuzz`, `bhf replay`, `bhf minimize` and `bhf report --backfill` all use it. The generated harness and build layouts are the same for every protocol.

## Protocols

| Protocol | `harness_protocol` value | How the harness runs |
|---|---|---|
| bhf framed | `bhf_framed` | bhf's C/C++ (or Go, Rust, launcher) driver: a framed fork-server loop, plus one input by file name (`argv[1]`) outside the loop. |
| libFuzzer single input | `libfuzzer_single_input` | A libFuzzer-style binary run on one input file per process. |
| stdin event log | `stdin_event_log` | The Ada runtime: input on stdin, results in an event log. |

The run summary `<work-dir>/fuzz_runs/<harness-id>-latest.json` records the chosen protocol as `execution.harness_protocol`, and whether the fork server started as `execution.forkserver`.

## Resolution order

The first rule that matches decides:

1. An `input_mode` declared in a `harness-protocol.json` sidecar next to the binary (`bhf project run` writes it from a `bhf.project.v1` target), unless the binary is a libFuzzer binary without bhf's driver (rule 3).
2. The `BHF_FRAMED` marker in a launcher script that is the harness itself.
3. The libFuzzer runtime's messages in a binary without bhf's `BHF_FRAMED` driver: a libFuzzer target, whatever source sits beside it.
4. A bhf `main.c` or `main.cpp` with `BHF_FRAMED` beside the binary, or in a harness directory of the work dir: `generated_harnesses/<id>/`, `harnesses/<id>/`, `auto/<id>/` or `build/<id>/`.
5. Strings compiled into the binary. bhf's C/C++ driver and the Ada runtime both read `BHF_FRAMED`; a GNAT-bound main also embeds `GNAT Version: `. The whole file is scanned, so a binary copied alone into `build/<id>/main` is still recognised.
6. A C/C++ source without the marker: a plain libFuzzer target.
7. Otherwise, the Ada stdin/event-log protocol.

bhf's generated C source defines both `LLVMFuzzerTestOneInput` and its own `BHF_FRAMED` `main`, so the presence of C source never overrides the marker. Source and launcher reads are bounded, and an executable whose first 4 KiB looks binary is not decoded as text.

For a `-fsanitize=fuzzer` binary without bhf's driver, `bhf fuzz` runs one input file per process, without coverage guidance, and prints how to wrap the fuzz target with `bhf generate-harness <fuzz_target.cc> --target LLVMFuzzerTestOneInput` for coverage-guided fuzzing.

## Background: the split-layout defect (2026-09-24)

The engine-parity `magic_byte` manual C workflow generated `<work>/generated_harnesses/H-C0017/main.c`, with the `BHF_FRAMED` marker, and built `<work>/build/H-C0017/main`. The driver check of that time read only a `main.c` beside the built binary, so it missed the generated source; the separate libFuzzer check found `main.c` under `generated_harnesses/` and chose single-input mode. The run recorded `harness_protocol: libfuzzer_single_input`, `forkserver: false`, no coverage edges and no finding.

The fix resolves the protocol in one place, from the work-dir layouts above, and gives an explicit `BHF_FRAMED` marker priority over plain C/C++ source. Fresh-process runs of a framed driver pass the input file name as `argv[1]`, because raw stdin does not call the target in that mode.

Regression coverage:

- Unit tests cover the manual `build/<id>/main` plus `generated_harnesses/<id>/main.c` layout, sibling auto source, a textual launcher, an external libFuzzer C source without `BHF_FRAMED`, no source, and a large binary.
- An integration test runs `generate-harness`, `build` and `fuzz` on a planted C crash fixture. It checks that the built path differs from the generated source, the protocol is not `libfuzzer_single_input`, the fork server runs when requested, coverage edges are nonzero, and the sanitizer finding is reported. Its execution count is diagnostic only.
- The C++ amalgamation tests cover a fresh-process recheck of framed-driver coverage candidates, including a state-masked ASan crash reproduced from its saved testcase.
