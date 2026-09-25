<!-- SPDX-License-Identifier: Apache-2.0 -->
# Engine comparison: evidence and benchmark plan

## Current evidence boundary

There is not yet evidence to claim that BHF matches AFL++ or Mayhem on production
targets. The repository's `engine_parity` and `redqueen_cmplog` integration tests
are useful correctness gates for BHF's own discovery and comparison guidance,
but they are not head-to-head benchmarks: both exercise BHF only, use deliberately
small C gates, and are ignored by default. In a bounded run on 2026-09-24 at
revision `5528a41df1968e7ec7efb843b9dac12cbe377c8c`,
`engine_parity` solved three gates with one 3-second campaign each (48, 26, and
16 reported executions; 1 finding each). `redqueen_cmplog` did not solve the
integer gate without cmplog (108,075 executions), and did solve it with cmplog
(51 executions). Those test outcomes show the exercised behavior works; the
different corpus/control flow and tiny sample do not support comparative speed
or quality claims. Full raw output is retained at
`/tmp/bhf-e3-engine-parity.log` and `/tmp/bhf-e3-redqueen-cmplog.log` in the
validation environment.

Initial competitor-runner smoke attempts are preserved under
`benchmarks/engine-comparison/results/`. The first BHF command used an
unsupported millisecond spelling for a whole-second timeout; later
`smoke-valid-*.json` attempts exposed a separate standalone BHF
protocol-discovery issue. The CLI classified a built generated harness as
`libfuzzer_single_input`, with no observed coverage or finding, even though the
generated C driver carries the BHF framed marker in a different directory.
Candidate AFL++/libFuzzer artifacts independently replayed under the ASan
oracle, but those first attempts were invalidated by BHF's protocol mismatch.
The earlier `smoke-*.json` files document bring-up and diagnosis, not
comparative performance evidence.

The resumed 2026-09-24 checkpoint fixed BHF's split generated/build protocol
resolution and fresh-process replay. A rebuilt release binary completed the
unmodified documented workflow and saved a crash that replayed under the common
ASan oracle (`results/smoke-p1-20260924-01.json`). The pinned AFL++ v5.03c
LLVM build then succeeded with GCC 13 selected through `CXXFLAGS`. A bounded
three-engine diagnostic (`results/smoke-p1-three-engine-20260924-01.json`)
contains one five-second trial on `magic_byte`: BHF and AFL++ saved confirmed
in-budget crashes, first observed at 0.63s and 0.18s; libFuzzer's confirmed
artifact was first observed at 8.56s and is classified `out_of_budget_crash`.
BHF's recorded summary shows `bhf_framed`, forkserver active and 13 edges. The
single toy trial validates runner and protocol behavior; it cannot establish
relative effectiveness on real code or Mayhem parity. The earlier `smoke-*.json`
files retain their diagnostic-only status.

## Reproducible smoke runner

`benchmarks/engine-comparison/run.py` is the checked-in start of a reproducible
comparison harness. It derives each engine's target from the same fixture source
and `target_one_input` callback, initializes every lane with the same 8-byte
all-zero seed, pins all work to one selected CPU by default, and records
source/tool/binary hashes, commands, build logs, run logs, build duration,
campaign duration, artifact time-to-first-crash, replay confirmation, and
right-censored no-crash observations. A candidate crash is counted as solved
only when the saved artifact independently reproduces the fixture's expected
ASan stack-buffer-overflow using `benchmarks/harnesses/replay_stdin.c`. Build
failures, runner errors, supervisor timeouts, and unconfirmed artifacts are not
treated as censored campaigns. Native execution counters are retained but never
treated as cross-tool comparable. AFL++ and libFuzzer use small checked-in C ABI
adapters; BHF discovers and generates its harness.

After building the release CLI and ensuring local `afl++` and `clang` are
available, a one-case smoke can be run as follows:

```sh
cargo build --release -p bhf
python3 -B benchmarks/engine-comparison/run.py \
  --case magic_byte --trials 1 --budget 10 --timeout-ms 1000 \
  --max-len 64 --cpu 0 \
  --output benchmarks/engine-comparison/results/smoke-<unique-id>.json
```

Each output filename must be new. The runner refuses to overwrite evidence and
creates a sibling `*-runs/` directory containing per-engine source, corpora,
artifacts, and logs. `--engines builtin` or another subset is useful for local
bring-up, but a partial set is not a comparison. Use `--cpu none` only when
unrestricted scheduling is intentional and recorded. Run multiple trials with
distinct RNG seeds before computing summaries; this runner stores every trial
row rather than dropping no-crash observations.

The runner is smoke-study tooling, not a benchmark suite yet. BHF and
libFuzzer interfaces express per-input timeouts in whole seconds, so the runner
rounds up from the millisecond control supplied to AFL++; recorded
`effective_timeout_ms` makes that difference explicit. BHF builds with `-O1`,
ASan/UBSan and sanitizer edge/compare coverage; AFL++ builds with `-O1`,
ASan/UBSan and AFL++ instrumentation (plus a separate CMPLOG binary); libFuzzer
builds with `-O1`, ASan/UBSan and libFuzzer instrumentation/value profiling.
These are documented, but not a fully normalized instrumentation matrix.
Fuzzer startup and shutdown overhead can exceed a short requested campaign
budget; inspect recorded actual wall durations. Crash-artifact detection is
polled at 10 ms, so TTFC has that measurement resolution rather than being an
exact event timestamp. The C fixture suite currently has only toy gates; these
limitations must remain visible in any reporting.

## What a credible enterprise comparison requires

Use FuzzBench as the primary model for a real-code experiment rather than
extrapolating from the toy fixtures. Its published reports run many fuzzers on
real-world benchmarks with repeated trials and equal campaign budgets; its
analysis compares per-benchmark distributions and aggregate results rather than
presenting a single lucky run. See the [FuzzBench project](https://github.com/google/fuzzbench),
the [report methodology](https://google.github.io/fuzzbench/reference/report/),
and [trial terminology](https://google.github.io/fuzzbench/reference/glossary/).
For AFL++, retain its own `fuzzer_stats` and campaign metadata as raw evidence
([AFL++ status-screen fields](https://aflplus.plus/docs/status_screen/)).

Before any broad conclusion, the next study should:

1. Select maintained, representative real-code targets with existing fuzz
   harnesses or adapter shims that call the same callback and have documented
   crash/coverage oracles. Include multiple target families and avoid selecting
   only targets known to favor one engine.
2. Use identical target revisions, harness semantics, seed corpus bytes,
   maximum input length, sanitizer policy, environment, CPU quota, campaign
   budget, and repeated independent seeds for every engine. Record unavoidable
   differences explicitly rather than silently tuning one lane.
3. Separate compilation/setup cost from campaign time; report both end-to-end
   time-to-first-crash and campaign-only time-to-first-crash. Store every
   no-crash result as right-censored at the observed campaign end, plus crashes,
   coverage, executions with each engine's native definition, and resource use.
4. Use enough repetitions for distributions and confidence intervals, publish
   raw machine-readable rows, exact commands/tool versions/source hashes, and
   the analysis script. Treat crash counts carefully when duplicates or
   different sanitizer findings are possible.
5. Run a separate, licensed Mayhem evaluation only if an authorized account,
   version, target integration, and equivalent budget are available. No
   Mayhem comparison has been run here, and this document makes no Mayhem parity
   claim.

An eventual FuzzBench-backed suite should be versioned with this repository,
but should not be added as a default CI job: full real-code campaigns are
resource intensive. A small deterministic smoke can remain in CI for protocol
and adapter regressions, while statistically powered runs are scheduled and
publish their immutable evidence separately.

## Multi-engine trade study (4 engines) — 2026-09-25

`benchmarks/engine-comparison/trade_study.py` extends the smoke runner into a
statistically powered head-to-head across **four** engines — BHF's builtin
engine, AFL++ (pinned 5.03c), libFuzzer, and honggfuzz (source build) — over the
controlled `engine_parity` fixtures (`magic_byte`, `const_gate`, `len_field`,
`redqueen_int`), with 10 independent trials per (engine, target) at a fixed
per-trial wall budget. It reuses the reviewed helpers in `run.py` and adds three
things the smoke runner lacked:

1. **honggfuzz and an explicit pinned-AFL++ toolchain.** honggfuzz builds the
   same `LLVMFuzzerTestOneInput` harness via `hfuzz-cc`/`libhfuzz`; AFL++ uses the
   pinned 5.03c `afl-cc` with a separate CMPLOG binary.
2. **Engine-neutral coverage.** Every engine's FINAL corpus is merged through ONE
   shared libFuzzer-sancov binary (`-merge=1`, crash-robust), so `edges`/
   `features` use identical instrumentation and are directly comparable rather
   than trusting each engine's own counter.
3. **Engine-neutral crash oracle.** Each engine's native crash artifact AND its
   final corpus are replayed through one independent ASan+UBSan binary; only
   oracle-confirmed crashes count. This is required because honggfuzz's
   persistent+ASan loop keeps a coverage-increasing crasher in its corpus without
   flagging it as a crash — the corpus backstop still records bug reachability
   (its precise time-to-first-crash is reported as null, since no native artifact
   is written).

Build/setup time is separated from campaign time; native exec/s is recorded but
flagged not cross-engine comparable. Raw per-trial rows, the aggregated summary,
tool versions, and source/oracle/coverage-binary hashes are written to
`results/trade-study-4engine-<date>.json`; `analyze_trade_study.py` renders the
Markdown report `results/trade-study-report-<date>.md`.

```sh
cargo build --release -p bhf
python3 -B benchmarks/engine-comparison/trade_study.py \
  --trials 10 --budget 30 \
  --afl-path <pinned-aflpp-5.03c>/src --honggfuzz-dir <honggfuzz-build> \
  --output benchmarks/engine-comparison/results/trade-study-4engine-<date>.json
python3 -B benchmarks/engine-comparison/analyze_trade_study.py \
  --input  benchmarks/engine-comparison/results/trade-study-4engine-<date>.json \
  --output benchmarks/engine-comparison/results/trade-study-report-<date>.md
```

These fixtures are controlled coverage-gated micro-bugs: they isolate mutator
reach and magic-value solving (the `redqueen_int` gate specifically probes
cmplog/redqueen/value-profile), not whole-program throughput on production code.
They complement — they do not replace — the real-code reach study in
`benchmarks/harness-parity-20/` (bhf-generated vs expert harness). No Mayhem
comparison is included (no licensed environment).
