<!-- SPDX-License-Identifier: Apache-2.0 -->
# Effectiveness benchmarks: two separate experiments (issue #85)

bhf makes two different claims and they need two different studies. Conflating
them is how a benchmark starts lying. This document describes both, how to run
the powered versions offline, and exactly what is *not* yet established.

| | Experiment 1 — engine quality | Experiment 2 — auto-harness productivity |
|---|---|---|
| Question | Given a fixed harness, how good is bhf's engine vs other engines? | From a raw source checkout, how well does bhf auto-produce a useful harness? |
| Driver | `benchmarks/engine-comparison/trade_study.py` | `benchmarks/harness-parity-20/run.py` |
| Model | FuzzBench-style: many trials, shared coverage oracle, independent crash oracle, distributions | End-to-end setup study: checkout → build recovery → body execution → comparison |
| Renderer | `analyze_trade_study.py` | `summary.md` + `run-metadata.json` |

The two must never be merged into one headline number: Experiment 1 holds the
harness fixed to isolate the engine; Experiment 2 varies the harness on purpose.

## Experiment 1 — engine quality (FuzzBench-style)

Reuses the reviewed machinery already in `trade_study.py`/`run.py`: one fixed
harness per target drives every engine, every engine's final corpus is merged
through ONE shared libFuzzer-sancov binary (so coverage edges are directly
comparable), and every saved crash plus final corpus is replayed through ONE
independent ASan/UBSan oracle (so crash-find is engine-neutral). Build/setup time
is separated from campaign time.

What issue #85 added on top:

- **Pluggable target set** (`targets.py`). With no `--manifest` the study runs the
  four checked-in controlled gates exactly as before. With `--manifest` it runs
  pinned **real-code** targets through the identical machinery.
- **Distribution reporting** (`stats.py`). `aggregate()` reports, per-target AND
  pooled across targets: a Wilson 95% interval for crash-find over *valid
  campaigns only*; median + interquartile range + full range + a deterministic
  percentile-bootstrap CI for TTFC, shared coverage edges/features, and build
  time; and the count of distinct confirmed-defect signatures.
- **Failures stay visible.** Every trial is classified (`confirmed_crash`,
  `censored_no_crash`, `build_failed`, `supervisor_timeout`, `incomplete`,
  `unsupported`) and the per-engine `outcomes` breakdown is printed, so the
  effective sample size behind a rate is never hidden. Right-censored no-crash
  campaigns keep their censor time.
- **Native counters are not a shared unit.** `native_execs_per_s` is reported
  per-engine with `comparable_across_engines: false`; it is never pooled.

### Running Experiment 1

Builtin controlled fixtures (the historical default, needs the engines installed):

```sh
cargo build --release -p bhf
python3 -B benchmarks/engine-comparison/trade_study.py \
  --trials 10 --budget 30 \
  --afl-path <pinned-aflpp-5.03c>/src --honggfuzz-dir <honggfuzz-build> \
  --output benchmarks/engine-comparison/results/trade-study-<date>.json
python3 -B benchmarks/engine-comparison/analyze_trade_study.py \
  --input  benchmarks/engine-comparison/results/trade-study-<date>.json \
  --output benchmarks/engine-comparison/results/trade-study-report-<date>.md
```

Real-code targets via a manifest (see the schema below and
`experiment1-real-code.example.json`):

```sh
# 1. inspect the plan without building anything
python3 -B benchmarks/engine-comparison/trade_study.py \
  --manifest benchmarks/engine-comparison/experiment1-real-code.example.json --dry-run

# 2. clone each upstream at its pinned commit
python3 -B benchmarks/engine-comparison/trade_study.py \
  --manifest <manifest> --fetch --sources /path/to/checkouts

# 3. after wiring adapters + sources (below), run the study
python3 -B benchmarks/engine-comparison/trade_study.py \
  --manifest <manifest> --trials 10 --budget 300 \
  --afl-path ... --honggfuzz-dir ... \
  --output benchmarks/engine-comparison/results/engine-quality-realcode-<date>.json
```

### Manifest schema (`targets.py`)

A manifest is JSON or TOML with a top-level `targets` array. Paths resolve
relative to the manifest file unless absolute.

| Field | Required | Meaning |
|---|---|---|
| `name` | yes | unique target id |
| `kind` | no (`self_contained`) | `self_contained` real code, or `builtin_fixture` |
| `status` | no (`runnable`) | `runnable`, `requires_build_recipe`, or `manual`; only `runnable` is built — others become visible `unsupported` rows |
| `upstream` | yes for real code | `{url, commit}` provenance pin |
| `sources` | yes if runnable | translation units compiled with the harness adapter; one must define `target_one_input` (or set `target_callback`) |
| `include_dirs` | no | `-I` paths |
| `extra_cflags` | no | extra compile flags (e.g. `-std=c++17`) |
| `target_callback` | no | symbol to wrap as `target_one_input` if no source defines it |
| `seed_dir` | no | seed corpus (defaults to the shared 8-byte zero seed) |
| `budget_s`, `max_len` | no | per-target overrides |
| `sanitizer_policy` | no (`asan_ubsan`) | oracle/fuzz sanitizer selection, pinned per target |
| `bhf_harness_mode` | no (`generated`) | `generated` (bhf writes its own harness — only honest on a self-contained TU) or `provided` (harness held fixed across engines — the correct engine-quality mode) |

To promote a `requires_build_recipe` target to `runnable`: fetch its sources
(step 2 above), write a small adapter `.c` that includes the library header and
defines `int target_one_input(const unsigned char*, size_t)` calling the pinned
API, point `sources`/`include_dirs` at the adapter plus the needed project
translation units, and set `status=runnable` with `bhf_harness_mode=provided`.

## Experiment 2 — auto-harness productivity

`harness-parity-20/run.py` drives bhf `auto` from a clean pinned checkout of each
real project and compares the generated harness's project-line coverage against a
reviewed expert harness at the identical revision (`BHF_BLIND_EXPERT_HARNESSES=1`
hides the project's own fuzz driver from mining). Issue #85 added:

- **Setup separated from campaign.** `setup_wall_s` (clone/fetch/checkout) and
  `auto_wall_s` (the single `bhf auto`, covering discovery + build recovery +
  harness generation + fuzz) are recorded per project; a finer build-vs-fuzz
  split is surfaced when bhf emits it.
- **A funnel that counts every attempted project.** `attempted → checkout_ok →
  produced_result → body_executed → expert_comparable → parity_or_better`, with
  *projects attempted* as the denominator at every stage. A project that fails to
  check out or build is a stage that drops out, never a row that is removed.
- **Provenance.** `run-metadata.json` pins the binary sha256/version, git commit,
  host, config, and every project commit.

```sh
cargo build --release -p bhf
python3 benchmarks/harness-parity-20/run.py --seconds 15 --jobs 2 \
  --output /path/to/output
```

"Useful retained findings" in the issue's sense (confirmed crash/sanitizer
findings, not just coverage parity) is a dimension this coverage-parity suite
does not yet capture; see limitations.

## Honest limitations (what is NOT established)

- **Supported niche + measured advantage.** The controlled gates show bhf's
  engine reaches gate-guarded bugs competitively on micro-fixtures; the
  harness-parity suite shows bhf auto-generates harnesses whose project-line
  coverage reaches expert parity on a pinned real-code set. Neither establishes a
  general "industry-leading effectiveness" claim on arbitrary production targets.
  State the niche and the measured number; do not extrapolate.
- **No licensed-tool comparison.** No Mayhem (or other licensed tool) evaluation
  has been run; make no such parity claim without an actual authorized run.
- **Coverage-over-time** is not yet recorded — Experiment 1 measures final-corpus
  coverage, not a time series. A powered study should snapshot corpora over the
  budget.
- **Real-code multi-file builds.** The single clang/afl-cc/hfuzz-cc invocation
  cannot configure an arbitrary project build; such targets ship as
  `requires_build_recipe` (visible `unsupported` rows) until a recipe is wired.
- **bhf provided-harness CLI.** `bhf_harness_mode=provided` is the correct
  engine-quality mode for real code but is not wired to a concrete `bhf fuzz`
  invocation here; the bhf lane records a visible `unsupported` row until a
  maintainer supplies the exact command.
- **Native execution counters** are never compared across engines.

## CI boundary

The powered campaign drivers are deliberately NOT in any workflow (`ci.yml` runs
the Rust nextest fast/smoke only). The one per-PR-eligible piece is the
deterministic classification/stats/manifest smoke in
`benchmarks/engine-comparison/test_runner.py`, which builds and fuzzes nothing:

```sh
python3 -m pytest benchmarks/engine-comparison/
```

Powered real-code studies are run offline/scheduled and publish their immutable
evidence (raw rows, hashes, commands, analysis doc) separately.

## Dependency note

These drivers are intentionally standard-library only (dataclasses + strict
validation that raises descriptive errors, not Pydantic) so the offline powered
study runs on a bare `python3` with no third-party install on the benchmark host.
