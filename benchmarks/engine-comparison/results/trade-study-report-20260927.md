<!-- SPDX-License-Identifier: Apache-2.0 -->
# Multi-engine fuzzing trade study: BHF, AFL++, libFuzzer and honggfuzz

Generated: 2026-09-28T04:14:13Z · elapsed 5602.6s · 160 raw trial rows.

**Host:** 13th Gen Intel(R) Core(TM) i9-13900H (6 cores; each campaign pinned to one core via taskset).

**Budget:** 30s wall per trial · **trials:** 10 per (engine,target) · **max_len:** 64 · identical zero-seed corpus for every engine.

## Tool versions

- **BHF:** `bhf 0.2.32-62-ga4c9e6c-dirty`
- **AFL++:** system build **4.09c** at `/usr/bin` (afl-cc wraps `Ubuntu clang
  version 17.0.6 (9ubuntu1)`). The earlier study pinned AFL++ 5.03c; this run
  measured all four engines afresh, with 4.09c.
- **libFuzzer / clang:** `Ubuntu clang version 18.1.3 (1ubuntu1)`
- **honggfuzz:** source build at `/tmp/honggfuzz`

## Methodology

- **Targets:** controlled, coverage-gated bug fixtures. A human-audited bug
  sits behind a gate (a magic value or a length field), so the metric is how
  well each engine's mutator reaches deep, guarded code. Each fixture defines
  one `target_one_input(data,size)`, and every engine drives the same source.
- **Independent crash oracle:** each engine's saved crash artifact and its
  final corpus are replayed through one ASan+UBSan binary the engines never
  see; only oracle-confirmed crashes count. This removes each engine's own
  crash classifier from the count (honggfuzz's persistent+ASan loop, for
  instance, keeps the crasher in its corpus without flagging it).
- **Engine-neutral coverage:** every engine's final corpus is merged through
  one shared libFuzzer-sancov binary (`-merge=1`), so `edges` and `features`
  use identical instrumentation and are directly comparable across engines.
- **Time-to-first-crash (TTFC):** wall seconds from campaign start to the
  first oracle-confirmed crash artifact, polled at 10 ms. TTFC needs a native
  crash artifact; honggfuzz's crashes are counted through the corpus replay,
  which gives a crash-find rate and no TTFC.
- **Setup and build time are separate from campaign time.** Native exec/s
  uses each engine's own definition of an execution, so compare it within one
  engine only.

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

## BHF re-run after the RedQueen change

In this run, the builtin engine behind `bhf fuzz` did not arm its RedQueen
(input-to-state) and value-profile channels; `bhf auto` already did. Commit
`9d5bdfbf` arms both by default for `bhf fuzz`. The BHF-only re-run on
2026-09-28 (`bhf 0.2.32-63-gdfee887-dirty`, evidence in
`trade-study-bhf-refix-20260928.json`) confirmed a crash in 10/10 trials on
every target, `redqueen_int` included (median TTFC 0.426 s).

## Scope

- The targets are **controlled micro-fixtures** with planted, gated bugs.
  They measure mutator reach and magic-value solving. For reach on real code,
  see the [harness parity study](../../harness-parity-20/README.md)
  (BHF-generated against expert harnesses).
- Each campaign ran on one core of one host, with a 30 s budget. The minimum
  TTFC and the crash-find rate are the steadier signals; a median can hide
  variance, and the raw rows are in the evidence JSON
  (`trade-study-4engine-20260927.json`).
- Native exec/s uses each engine's own definition and is reported for
  context.

