<!-- SPDX-License-Identifier: Apache-2.0 -->
# Engine Comparison Benchmarks

bhf's effectiveness is measured by two separate experiments, which are
reported separately (issue #85). Their schemas, offline run instructions and
limits are in
[`benchmarks/engine-comparison/METHODOLOGY.md`](../benchmarks/engine-comparison/METHODOLOGY.md).
The per-language comparisons behind the white paper are described in
[`benchmarks/README.md`](../benchmarks/README.md), and the cold-start
time-to-first-crash benchmark in
[Engine parity benchmark](site/engine-parity-benchmark.md).

| | Engine quality | Auto-harness productivity |
|---|---|---|
| Question | With the harness fixed, how does bhf's engine compare with other engines? | From a raw checkout, how good a harness does bhf generate? |
| Driver | `benchmarks/engine-comparison/trade_study.py` | [`benchmarks/harness-parity-20/`](../benchmarks/harness-parity-20/README.md) |
| Method | FuzzBench-style: repeated trials, one shared coverage binary, one independent crash oracle, distributions with confidence intervals | End-to-end: checkout, build recovery, body execution, comparison with a reviewed expert harness |
| Reports | Median, interquartile range, range and a Wilson or bootstrap interval, per target and pooled; failed, censored and unsupported trials stay in the table | Setup time apart from campaign time; build failures counted |

## Results so far

**Engine quality, controlled fixtures.** The four-engine trade study of
2026-09-27 ran bhf's builtin engine, AFL++ 4.09c, libFuzzer (clang 18.1.3) and
honggfuzz on the four `engine_parity` fixtures (`magic_byte`, `const_gate`,
`len_field`, `redqueen_int`), 10 trials each, 30 s per trial, one pinned core.
Report:
[`results/trade-study-report-20260927.md`](../benchmarks/engine-comparison/results/trade-study-report-20260927.md).

| Fixture | Fastest confirmed crash (AFL++ median) | bhf median time to first crash | Highest median shared coverage |
|---|---|---|---|
| `magic_byte` | AFL++ (0.234 s) | 0.502 s | bhf, AFL++, honggfuzz (7 edges) |
| `const_gate` | AFL++ (0.163 s) | 0.390 s | all four (4 edges) |
| `len_field` | AFL++ (0.167 s) | 0.193 s | honggfuzz (5 edges) |
| `redqueen_int` | AFL++ (0.173 s) | no crash in 10 trials | all four (4 edges) |

AFL++, libFuzzer and honggfuzz confirmed a crash in 40 of 40 trials, and bhf
in 30 of 40. A bhf-only rerun after a fix, on 2026-09-28 with the same
fixtures, trials and budget
(`benchmarks/engine-comparison/results/trade-study-bhf-refix-20260928.json`),
confirmed a crash in 40 of 40 trials, with a median time to first crash of
0.264–0.499 s per fixture, `redqueen_int` 0.426 s.

The fixtures are planted, gated micro-bugs. They measure how well a mutator
gets past a magic value or a length field (`redqueen_int` needs comparison
operand capture), not throughput on whole programs.

**Auto-harness productivity, real code.** The audit of 2026-08-14
([`harness-parity-20/ANALYSIS.md`](../benchmarks/harness-parity-20/ANALYSIS.md))
ran 30 pinned native parser and decompressor projects. On every project, bhf's
generated harness built, fuzzed and produced an implementation-line
measurement comparable with the expert harness. Generated harnesses covered
50,340 comparable implementation lines against 48,742 for the expert
harnesses; 19 of the 30 projects had no line that only the expert harness
reached.

**Integration tests.** `engine_parity` and `redqueen_cmplog` are bhf-only
integration tests on small C gates, ignored by default. They check bhf's
input discovery and comparison guidance. On 2026-09-24 at revision
`5528a41df1968e7ec7efb843b9dac12cbe377c8c`:

- `engine_parity` solved three gates, each in one 3-second campaign (48, 26
  and 16 executions, one finding each);
- `redqueen_cmplog` solved the integer gate with cmplog in 51 executions, and
  did not solve it without cmplog in 108,075 executions.

The raw output is in `/tmp/bhf-e3-engine-parity.log` and
`/tmp/bhf-e3-redqueen-cmplog.log` on the validation host.

## Trade study runner

`trade_study.py` compares
four engines: bhf's builtin engine, AFL++, libFuzzer and honggfuzz (a source
build). It reuses the helpers in `run.py` and adds:

1. **honggfuzz and an explicit AFL++ toolchain.** honggfuzz builds the same
   `LLVMFuzzerTestOneInput` harness through `hfuzz-cc` and `libhfuzz`. AFL++
   uses the `afl-cc` from `--afl-path`, with a separate CMPLOG binary.
2. **Shared coverage.** Every engine's final corpus is merged through one
   libFuzzer sancov binary (`-merge=1`), so `edges` and `features` come from
   the same instrumentation for every engine.
3. **Independent crash oracle.** Each engine's crash artifacts and its final
   corpus are replayed through one ASan+UBSan binary, and a crash counts when
   that binary confirms it. honggfuzz's persistent ASan loop keeps a
   coverage-increasing crasher in its corpus without flagging it, so the
   corpus replay records that the bug was reached; its time to first crash is
   `null`, because no crash artifact is written.

Build and setup time are recorded apart from campaign time. Native exec/s is
recorded per engine and marked as not comparable across engines.

```sh
cargo build --release -p bhf
python3 -B benchmarks/engine-comparison/trade_study.py \
  --trials 10 --budget 30 \
  --afl-path <aflpp-checkout>/src --honggfuzz-dir <honggfuzz-build> \
  --output benchmarks/engine-comparison/results/trade-study-4engine-<date>.json
python3 -B benchmarks/engine-comparison/analyze_trade_study.py \
  --input  benchmarks/engine-comparison/results/trade-study-4engine-<date>.json \
  --output benchmarks/engine-comparison/results/trade-study-report-<date>.md
```

The JSON holds every trial row, the aggregated summary, tool versions, and
the hashes of the sources, the oracle and the coverage binary.

Rendering into an existing report replaces only its generated results, between the `<!-- analyze_trade_study.py: generated results ... -->` markers, and keeps the prose around them; a report without the markers is left as it is.

| Option | Default | Meaning |
|---|---|---|
| `--engines` | `bhf aflpp libfuzzer honggfuzz` | Engines to run |
| `--cases` | all targets | Restrict to these target names |
| `--manifest` | the four fixtures | Real-code target manifest (`.json` or `.toml`) |
| `--fetch` | off | Clone the manifest's upstreams at their pins, then exit |
| `--sources` | `<workdir>/sources` | Checkout root for `--fetch` |
| `--dry-run` | off | Validate and print the plan without building |
| `--list-targets` | off | Print the resolved target set and exit |
| `--trials` | `10` | Trials per engine and target |
| `--budget` | `60` | Fuzzing wall seconds per trial |
| `--timeout-ms` | `1000` | Per-input timeout |
| `--max-len` | `64` | Maximum input length |
| `--cpu` | `0` | CPU or CPU list for `taskset`; `none` disables pinning |
| `--afl-path`, `--honggfuzz-dir` | host-specific paths | AFL++ `src/` directory and honggfuzz build directory; pass both |

### Real-code targets

With `--manifest`, the same harness, coverage and crash machinery runs pinned
real-code targets. The schema and an example
(`experiment1-real-code.example.json`) are in
`benchmarks/engine-comparison/`, and every field is described in
`METHODOLOGY.md`. `aggregate()` reports, per target and pooled, the median,
interquartile range and full range, a Wilson interval (crash rate) or a
percentile-bootstrap interval (continuous values), and the count of distinct
confirmed defects. Each trial is classified (confirmed, censored,
build_failed, timeout, incomplete, unsupported), and each engine's breakdown
is printed with the rate, so the sample size behind it is visible. A no-crash
campaign keeps its censor time. A real-code target that needs a full project
build appears as an `unsupported` row with its upstream pin until a build
recipe exists for it.

## Smoke runner

`benchmarks/engine-comparison/run.py` runs a single-case smoke
comparison of bhf's builtin engine, AFL++ and libFuzzer. For each engine it:

- builds the target from the same fixture source and `target_one_input`
  callback (AFL++ and libFuzzer through small checked-in C adapters; bhf
  discovers the target and generates its own harness);
- starts from the same 8-byte all-zero seed;
- pins the work to one CPU (`--cpu 0` by default);
- records the source, tool and binary hashes, commands, build and run logs,
  build and campaign durations, time to first crash, replay confirmation, and
  right-censored no-crash results.

A crash counts as solved only when the saved artifact reproduces the
fixture's expected ASan stack-buffer-overflow under
`benchmarks/harnesses/replay_stdin.c`.
Build failures, runner errors, supervisor timeouts and unconfirmed artifacts
are recorded as such, not as censored campaigns. Native execution counters
are kept and never compared across tools.

With a release build of bhf, `afl++` and `clang` on `PATH`:

```sh
cargo build --release -p bhf
python3 -B benchmarks/engine-comparison/run.py \
  --case magic_byte --trials 1 --budget 10 --timeout-ms 1000 \
  --max-len 64 --cpu 0 \
  --output benchmarks/engine-comparison/results/smoke-<unique-id>.json
```

- Give each run a new output filename: the runner refuses to overwrite
  evidence. It writes per-engine sources, corpora, artifacts and logs to a
  sibling `*-runs/` directory.
- `--engines builtin` (or another subset) is for local bring-up; a comparison
  needs all three engines.
- Use `--cpu none` only when you want unpinned scheduling, and record it.
- Run several trials with distinct RNG seeds before summarizing. Every trial
  row is stored, including no-crash results.

Measurement details:

- bhf and libFuzzer take per-input timeouts in whole seconds, so the runner
  rounds the millisecond value it passes to AFL++ up for them; each row
  records `effective_timeout_ms`.
- Builds: bhf uses `-O1`, ASan/UBSan and sanitizer edge and compare coverage;
  AFL++ uses `-O1`, ASan/UBSan and AFL++ instrumentation, plus a separate
  CMPLOG binary; libFuzzer uses `-O1`, ASan/UBSan and libFuzzer
  instrumentation with value profiling.
- Fuzzer startup and shutdown can take longer than a short campaign budget;
  check the recorded wall durations.
- Crash artifacts are polled every 10 ms, which is the resolution of the time
  to first crash.

### Smoke-run history

The files in
[`benchmarks/engine-comparison/results/`](../benchmarks/engine-comparison/results/)
record the runner's bring-up:

- `smoke-*.json` and `smoke-valid-*.json` (2026-09-24) are diagnostic runs.
  The first bhf command passed a millisecond timeout where a whole-second
  value was required. The `smoke-valid-*` runs exposed a protocol-discovery
  defect: bhf classified a built generated harness as
  `libfuzzer_single_input`, with no coverage or finding, because the
  generated C driver carrying the framed-protocol marker was in a different
  directory. The AFL++ and libFuzzer artifacts from those runs replayed under
  the ASan oracle.
- After the fix to protocol resolution and fresh-process replay, a release
  build completed the documented workflow and saved a crash that replayed
  under the shared ASan oracle (`smoke-p1-20260924-01.json`).
- `smoke-p1-three-engine-20260924-01.json` is one five-second trial on
  `magic_byte`, with AFL++ v5.03c built with GCC 13 selected through
  `CXXFLAGS`. bhf and AFL++ saved confirmed crashes, first seen at 0.63 s and
  0.18 s. libFuzzer's confirmed artifact was first seen at 8.56 s and is
  classified `out_of_budget_crash`. bhf's summary shows `bhf_framed`, the fork
  server active and 13 edges.

## Requirements for a real-code comparison

FuzzBench is the model for a real-code experiment: many fuzzers on real-world
benchmarks, repeated trials, equal campaign budgets, and per-benchmark
distributions next to aggregate results. See the
[FuzzBench project](https://github.com/google/fuzzbench), its
[report methodology](https://google.github.io/fuzzbench/reference/report/) and
its [trial terminology](https://google.github.io/fuzzbench/reference/glossary/).
For AFL++, keep its `fuzzer_stats` and campaign metadata as raw evidence
([AFL++ status-screen fields](https://aflplus.plus/docs/status_screen/)).

A real-code study should:

1. Select maintained real-code targets from several target families, with
   existing fuzz harnesses or adapter shims that call the same callback, and
   documented crash and coverage oracles. Avoid targets known to favour one
   engine.
2. Give every engine the same target revisions, harness semantics, seed bytes,
   maximum input length, sanitizer policy, environment, CPU quota and
   campaign budget, with independent seeds per trial. Record any difference
   that cannot be removed instead of tuning one lane.
3. Record compilation and setup time apart from campaign time, and report
   both the end-to-end and the campaign-only time to first crash. Store every
   no-crash result as right-censored at the campaign end, together with
   crashes, coverage, executions (in each engine's own definition) and
   resource use.
4. Run enough trials for distributions and confidence intervals, and publish
   the raw rows, exact commands, tool versions, source hashes and the analysis
   script. Deduplicate crashes before counting them.
5. Run a Mayhem evaluation only with an authorized account, a fixed version,
   a target integration and an equivalent budget. No Mayhem comparison has
   been run.

A real-code suite belongs in this repository, versioned with it, and runs on
a schedule rather than as a default CI job, because full campaigns are
resource intensive. A small deterministic smoke run can stay in CI to catch
protocol and adapter regressions.
