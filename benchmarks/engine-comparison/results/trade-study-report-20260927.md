<!-- SPDX-License-Identifier: Apache-2.0 -->
# Multi-engine fuzzing trade study — BHF vs AFL++ vs libFuzzer vs honggfuzz

Generated: 2026-09-28T04:14:13Z · elapsed 5602.6s · 160 raw trial rows.

**Host:** 13th Gen Intel(R) Core(TM) i9-13900H (6 cores; each campaign pinned to one core via taskset).

**Budget:** 30s wall per trial · **trials:** 10 per (engine,target) · **max_len:** 64 · identical zero-seed corpus for every engine.

## Tool versions

- **BHF:** `bhf 0.2.32-62-ga4c9e6c-dirty`
- **AFL++:** system build **4.09c** at `/usr/bin` (afl-cc wraps `Ubuntu clang version 17.0.6 (9ubuntu1)`). **NOTE: this differs from the prior study's pinned 5.03c — this run is a fresh 4-engine measurement, NOT a splice into the old 5.03c file.**
- **libFuzzer / clang:** `Ubuntu clang version 18.1.3 (1ubuntu1)`
- **honggfuzz:** source build at `/tmp/honggfuzz`

## Methodology

- **Targets:** controlled coverage-gated bug fixtures — a human-audited bug sits behind a gate (a magic value / length field) so the metric is how well each engine's mutator reaches deep, guarded code. Each fixture defines one `target_one_input(data,size)`; every engine drives the SAME source.
- **Independent crash oracle:** each engine's saved crash artifact AND its final corpus are replayed through one ASan+UBSan binary the engines never see; only oracle-confirmed crashes count. This neutralizes each engine's own crash classifier (honggfuzz's persistent+ASan loop, for instance, keeps the crasher in its corpus without flagging it).
- **Engine-neutral coverage:** every engine's final corpus is merged through ONE shared libFuzzer-sancov binary (`-merge=1`), so `edges`/`features` use identical instrumentation and are directly comparable — not each engine's own counter.
- **Time-to-first-crash (TTFC):** wall seconds from campaign start to the first oracle-confirmed crash artifact, polled at 10 ms. Only engines that write a native crash artifact get a TTFC (honggfuzz reports crash REACHABILITY via the corpus backstop, no TTFC).
- **Setup/build time is separated from campaign time.** Native exec/s is recorded but is **not** cross-engine comparable (each engine defines an execution differently).

## Target: `magic_byte`

_2-byte sync + length gate → stack OOB (st24-style)_

| Engine | Crash-find rate | Median TTFC (s) | Min TTFC (s) | Median cov edges | Max cov edges | Median native exec/s | Median build (s) |
|---|---|---|---|---|---|---|---|
| BHF (builtin) | 100% (10/10) | 0.502 | 0.466 | 7 | 7 | 1640 | 0.497 |
| AFL++ 4.09c | 100% (10/10) | 0.234 | 0.193 | 7 | 7 | 14785.1 | 0.328 |
| libFuzzer | 100% (10/10) | 8.805 | 6.454 | 6 | 7 | 447.9 | 0.164 |
| honggfuzz | 100% (10/10) | — | — | 7 | 7 | 302.1 | 0.114 |

## Target: `const_gate`

_multi-byte constant gate → bug_

| Engine | Crash-find rate | Median TTFC (s) | Min TTFC (s) | Median cov edges | Max cov edges | Median native exec/s | Median build (s) |
|---|---|---|---|---|---|---|---|
| BHF (builtin) | 100% (10/10) | 0.39 | 0.375 | 4 | 4 | 199.5 | 0.497 |
| AFL++ 4.09c | 100% (10/10) | 0.163 | 0.152 | 4 | 4 | 10786.7 | 0.329 |
| libFuzzer | 100% (10/10) | 8.897 | 5.78 | 4 | 4 | 153.1 | 0.164 |
| honggfuzz | 100% (10/10) | — | — | 4 | 4 | 1055.4 | 0.114 |

## Target: `len_field`

_length-field record parse → bug_

| Engine | Crash-find rate | Median TTFC (s) | Min TTFC (s) | Median cov edges | Max cov edges | Median native exec/s | Median build (s) |
|---|---|---|---|---|---|---|---|
| BHF (builtin) | 100% (10/10) | 0.193 | 0.183 | 4 | 5 | 8.8 | 0.497 |
| AFL++ 4.09c | 100% (10/10) | 0.167 | 0.152 | 4 | 5 | 107.8 | 0.329 |
| libFuzzer | 100% (10/10) | 8.613 | 6.002 | 3 | 5 | 1.6 | 0.164 |
| honggfuzz | 100% (10/10) | — | — | 5 | 5 | 2.1 | 0.139 |

## Target: `redqueen_int`

_magic 32-bit integer comparison → bug (cmplog/redqueen probe)_

| Engine | Crash-find rate | Median TTFC (s) | Min TTFC (s) | Median cov edges | Max cov edges | Median native exec/s | Median build (s) |
|---|---|---|---|---|---|---|---|
| BHF (builtin) | 0% (0/10) | — | — | 4 | 4 | 63465.1 | 0.513 |
| AFL++ 4.09c | 100% (10/10) | 0.173 | 0.162 | 4 | 4 | 20235 | 0.328 |
| libFuzzer | 100% (10/10) | 8.693 | 5.997 | 4 | 4 | 1384.2 | 0.164 |
| honggfuzz | 100% (10/10) | — | — | 4 | 4 | 3709.6 | 0.114 |

## Cross-target rollup

| Target | Fastest confirmed crash | Best common coverage |
|---|---|---|
| `magic_byte` | AFL++ 4.09c (0.234s) | BHF (builtin) (7 edges) |
| `const_gate` | AFL++ 4.09c (0.163s) | BHF (builtin) (4 edges) |
| `len_field` | AFL++ 4.09c (0.167s) | honggfuzz (5 edges) |
| `redqueen_int` | AFL++ 4.09c (0.173s) | BHF (builtin) (4 edges) |

### Overall crash-find reliability (all targets pooled)

| Engine | Confirmed crashes / trials | Rate |
|---|---|---|
| BHF (builtin) | 30/40 | 75% |
| AFL++ 4.09c | 40/40 | 100% |
| libFuzzer | 40/40 | 100% |
| honggfuzz | 40/40 | 100% |

## Caveats

- These are **controlled micro-fixtures** with planted, gated bugs — they isolate mutator reach and magic-value solving, not whole-program throughput on production code. They do not establish enterprise superiority on real targets; pair with the real-code reach study in `benchmarks/harness-parity-20/` (BHF-generated vs expert harness).
- Single-core, one host, bounded budget. `min_ttfc` and rate are the robust signals; a single median can hide variance — the raw rows are in the evidence JSON.
- Native exec/s differs in definition per engine and is reported for context only.
- A licensed Mayhem comparison is out of scope (no license/environment).

