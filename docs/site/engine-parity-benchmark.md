<!-- SPDX-License-Identifier: Apache-2.0 -->

# Engine parity benchmark (time-to-first-crash)

The parity benchmark measures how fast bhf's **built-in** engine finds a planted bug **cold**, with no seed that triggers it, on a set of gated parsers. Each parser stands for one class of gate that a fuzzer has to get past. This time-to-first-crash (TTFC) is the measure used for libFuzzer parity ([#376](https://github.com/Tarmo-Technologies/bhf/issues/376)).

## Fixtures

Each gate class has one small, self-contained C harness under `tests/fixtures/engine_parity/`:

| Fixture | Gate | Crash |
|---|---|---|
| `magic_byte` | `buf[0]==0x55 && buf[1]==0x55`, then a length byte in {0,1,2} | stack out-of-bounds write (PX4 st24 style) |
| `const_gate` | first 4 bytes == `0xDEADBEEF` | out-of-bounds write |
| `len_field` | a 1-byte length field > 8 | out-of-bounds read |
| `redqueen_int` | first 4 bytes == a `u32` magic derived from the input's length, reachable only by capturing the compare operand through trace-cmp | stack out-of-bounds write |
| `stack_depth` | none: bracket recursion with no depth limit, where every depth runs the same edges | stack exhaustion, reported as uncontrolled recursion (BHF-207) |

### RedQueen discriminator (#400)

`redqueen_int` is gated by an **integer** comparison against a magic derived from the input's length. To reach the crash, the engine captures the compare operand through SanitizerCoverage trace-cmp and splices it into the input at the offset where it was compared. The shim's cmplog (memory and string comparisons only), the static dictionary, and blind or structured mutation cannot reach it. The fixture has its own gate test ([#400](https://github.com/Tarmo-Technologies/bhf/issues/400)):

```sh
cargo test -p bhf --test redqueen_cmplog -- --ignored --nocapture
```

The test asserts that the gate is solved cold with per-input capture **on** and stays unsolved with it disabled (`BHF_DISABLE_REDQUEEN=1`, the dictionary-only path).

### Stack depth as progress (#220)

`stack_depth` has its own test, `stack_depth_novelty`, which runs in the default test suite on Linux. Edge coverage keeps none of the deeper inputs, because every depth runs the same edges. With the driver's stack-depth word as a novelty channel, each deeper input joins the corpus until the stack runs out.

```sh
cargo test -p bhf --test stack_depth_novelty
```

## Running it

```sh
cargo test -p bhf --test engine_parity -- --ignored --nocapture
```

The sweep runs `magic_byte`, `const_gate` and `len_field` cold through `bhf auto`. It needs clang with libFuzzer and `make`, and skips when they are missing. It prints a TTFC table (executions, findings, solved or unsolved) and **asserts that each case is solved cold**; that assertion is the parity gate.

`BHF_PARITY_SECS` sets the total fuzz budget per target (default 8 s), split across the passes under one shared deadline. That matches a libFuzzer `-max_total_time=8` campaign. The sweep is marked `#[ignore]`, so it runs on demand and in the nightly build rather than on every commit.

## Baseline (2026-06-21)

All three sweep cases are **solved cold**, with no trigger seed:

| Case | Cold result (8 s total) |
|---|---|
| `magic_byte` | solved, about 28k executions |
| `const_gate` | solved, about 626k executions (about 78k executions/s) |
| `len_field` | solved, in tens of executions |

Two parts make this work:

- **Feedback.** The generated `dictionary.txt` carries the magic bytes as raw values (for example `"U"` = `0x55`, `"\x03"`) from the static comparison-operand dictionary ([#379](https://github.com/Tarmo-Technologies/bhf/issues/379)), together with cmplog ([#378](https://github.com/Tarmo-Technologies/bhf/issues/378)), edge coverage ([#381](https://github.com/Tarmo-Technologies/bhf/issues/381)) and the entropic schedule ([#382](https://github.com/Tarmo-Technologies/bhf/issues/382)).
- **Throughput.** Generated C harnesses run under the persistent fork-server driver ([#399](https://github.com/Tarmo-Technologies/bhf/issues/399)) at tens of thousands of executions per second, against tens per second when each input started a new process. That speed lets dictionary insertion reach the gate cold.

## Multi-engine trade study (2026-09-27)

`benchmarks/engine-comparison/trade_study.py` runs the four gate fixtures under bhf's built-in engine, AFL++, libFuzzer and honggfuzz, from the same source and the same zero-byte seed. Each run had a 30 s budget, 10 trials per engine and target, and one pinned core per campaign. Every engine's crashes are replayed through one independent ASan and UBSan binary, and only confirmed crashes count.

| Target | bhf built-in | AFL++ 4.09c | libFuzzer (clang 18) | honggfuzz |
|---|---|---|---|---|
| `magic_byte` | 10/10, 0.499 s | 10/10, 0.234 s | 10/10, 8.805 s | 10/10 |
| `const_gate` | 10/10, 0.426 s | 10/10, 0.163 s | 10/10, 8.897 s | 10/10 |
| `len_field` | 10/10, 0.264 s | 10/10, 0.167 s | 10/10, 8.613 s | 10/10 |
| `redqueen_int` | 10/10, 0.426 s | 10/10, 0.173 s | 10/10, 8.693 s | 10/10 |

Each cell gives the confirmed crash-find rate and the median TTFC. honggfuzz writes no native crash artifact, so it has no TTFC.

The AFL++, libFuzzer and honggfuzz columns come from the four-engine run of 2026-09-27 (bhf `0.2.32-62`). In that run bhf solved `redqueen_int` in 0 of 10 trials. The bhf column comes from the bhf-only rerun of 2026-09-28, on a build one commit later (`0.2.32-63`), which solved all four targets in every trial.

The data and the method are in [benchmarks/engine-comparison/](../../benchmarks/engine-comparison/METHODOLOGY.md): `results/trade-study-report-20260927.md`, `results/trade-study-4engine-20260927.json` and `results/trade-study-bhf-refix-20260928.json`.
