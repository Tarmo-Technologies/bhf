<!-- SPDX-License-Identifier: Apache-2.0 -->
# Effectiveness benchmarks: two experiments

Two questions about bhf need two separate studies: how good its fuzzing
engine is, and how well it writes harnesses from source. This page describes
both experiments, how to run them offline, and the scope of each result.

| | Experiment 1: engine quality | Experiment 2: auto-harness productivity |
|---|---|---|
| Question | Given a fixed harness, how good is bhf's engine vs other engines? | From a raw source checkout, how well does bhf auto-produce a useful harness? |
| Driver | `benchmarks/engine-comparison/trade_study.py` | `benchmarks/harness-parity-20/run.py` |
| Model | FuzzBench-style: many trials, shared coverage oracle, independent crash oracle, distributions | End-to-end setup study: checkout → build recovery → body execution → comparison |
| Renderer | `analyze_trade_study.py` | `summary.md` + `run-metadata.json` |

Report the two as separate numbers. Experiment 1 holds the harness fixed to
isolate the engine; Experiment 2 varies the harness on purpose.

## Experiment 1: engine quality (FuzzBench-style)

`trade_study.py` and `run.py` drive every engine with one fixed harness per
target. Every engine's final corpus is merged through one shared
libFuzzer-sancov binary, so coverage edges are comparable across engines, and
every saved crash and final corpus is replayed through one independent
ASan/UBSan oracle, so a crash counts the same whichever engine found it.
Build and setup time are recorded apart from campaign time.

The study also provides:

- **Pluggable target set** (`targets.py`). With no `--manifest` the study runs
  the four checked-in controlled gates. With `--manifest` it runs pinned
  **real-code** targets through the same machinery.
- **Distribution reporting** (`stats.py`). `aggregate()` reports, per-target AND
  pooled across targets: a Wilson 95% interval for crash-find over *valid
  campaigns only*; median + interquartile range + full range + a deterministic
  percentile-bootstrap CI for TTFC, shared coverage edges/features, and build
  time; and the count of distinct confirmed-defect signatures.
- **Failures stay visible.** Every trial is classified (`confirmed_crash`,
  `censored_no_crash`, `build_failed`, `supervisor_timeout`, `incomplete`,
  `unsupported`) and the per-engine `outcomes` breakdown is printed, so every
  rate shows the sample size behind it. Right-censored no-crash campaigns keep
  their censor time.
- **Native counters stay per engine.** `native_execs_per_s` is reported per
  engine with `comparable_across_engines: false` and is never pooled.
- **Coverage over time.** While a campaign runs, the study copies the
  engine's on-disk corpus at 10, 25, 50 and 75% of the budget
  (`stats.CHECKPOINT_FRACTIONS`; libFuzzer's corpus dir, AFL++'s queue,
  honggfuzz's output corpus, and for bhf the `BHF_LIVE_CORPUS_DIR` it is
  given, since bhf writes its queue when the pass ends). After the campaign
  each snapshot, with the seeds, is replayed through the shared sancov binary;
  the final corpus is the 1.0 point. A row's `coverage_over_time` lists the
  points (`fraction`, `t_s`, `edges`, `features`, `corpus_size`), and the
  summary's `coverage_over_time` gives each fraction's distribution over the
  trials. A trial that ended early (libFuzzer stops at its first crash) is
  missing from the later points, which their `n` shows.
- **Retained findings.** After a campaign every crash input the engine
  kept (libFuzzer's `crash-*` artifacts, AFL++'s `crashes/`, honggfuzz's crash
  dir, bhf's `results/findings/*/testcase.bin`), at most 64, is replayed
  through the oracle. A row's `retained_findings` gives how many were kept,
  replayed and confirmed, and how many distinct normalized diagnostics the
  confirmed ones give (a grouping aid for triage); the summary has the
  distributions of the confirmed count and of the diagnostics. It shows what
  an engine keeps past its first crash: libFuzzer stops there, AFL++ and bhf
  go on.

### Running Experiment 1

The four built-in controlled fixtures (the default; needs the engines
installed):

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

A new report gets the methodology and scope prose, with the results between two `<!-- analyze_trade_study.py: generated results ... -->` markers. Rendering into an existing report replaces only what is between the markers, so prose edited after the first render stays. A report without them, such as `results/trade-study-report-20260927.md`, was written by hand, and the renderer leaves it as it is and exits non-zero.

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
| `status` | no (`runnable`) | `runnable`, `requires_build_recipe`, or `manual`; only `runnable` is built; the others become `unsupported` rows |
| `upstream` | yes for real code | `{url, commit}` provenance pin |
| `sources` | yes if runnable without a `recipe` | translation units compiled with the harness adapter; one must define `target_one_input` (or set `target_callback`) |
| `recipe` | no | a build recipe in `recipes.py` that supplies `sources`, `include_dirs` and `extra_cflags` from the fetched checkout at run time |
| `include_dirs` | no | `-I` paths |
| `extra_cflags` | no | extra compile flags (e.g. `-std=c++17`) |
| `target_callback` | no | symbol to wrap as `target_one_input` if no source defines it |
| `seed_dir` | no | seed corpus (defaults to the shared 8-byte zero seed) |
| `budget_s`, `max_len` | no | per-target overrides |
| `sanitizer_policy` | no (`asan_ubsan`) | oracle/fuzz sanitizer selection, pinned per target |
| `bhf_harness_mode` | no (`generated`) | `generated` (bhf writes its own harness; use it only for a self-contained translation unit) or `provided` (the same harness for every engine; use it to compare engines) |

To promote a `requires_build_recipe` target to `runnable`: fetch its sources
(step 2 above), write a small adapter `.c` that includes the library header and
defines `int target_one_input(const unsigned char*, size_t)` calling the pinned
API, point `sources`/`include_dirs` at the adapter plus the needed project
translation units, and set `status=runnable` with `bhf_harness_mode=provided`.

### Build recipes

A target with a `recipe` needs no hand-listed sources. At run time
(`trade_study.py --manifest ... --sources <fetch root>`), `recipes.py` takes the
checkout `--fetch` cloned at the pin, checks the SHA-256 of every file it uses,
generates whatever the project's own build would, checks the generated files
too, and returns the adapter (`adapters/<name>_adapter.c`) and the project's
translation units, include dirs and flags. A checksum mismatch stops the run:
the manifest names one exact variant, and a moved pin or a changed generator
gives a different one. Generated files live under `<workdir>/recipes/<name>/`.

| Recipe | Builds |
|---|---|
| `cjson` | `cJSON.c` (pinned) with `adapters/cjson_adapter.c`, which parses the input with `cJSON_ParseWithLengthOpts` and prints what parsed |
| `sqlite` | the amalgamation SQLite 3.54.0's `configure --disable-tcl && make sqlite3.c` generates out of tree (deterministic under its bundled jimsh; `sqlite3.c`/`sqlite3.h` pinned), with `adapters/sqlite_adapter.c`, which runs the input as SQL on an in-memory database (`sqlite3_prepare_v2`, a progress budget and a row cap); `SQLITE_THREADSAFE=0`, no extension loading |
| `zlib` | the core translation units (no `gz*` file I/O) with the checked-in `zconf.h`, all pinned, with `adapters/zlib_adapter.c`, which decompresses the input with `uncompress2` into a 64 KiB buffer |
| `libyaml` | `src/*.c` (pinned) with the `config.h` its configure writes for 0.2.5, generated into the recipe dir (a header, since a quoted string define does not survive bhf's make recipe), with `adapters/libyaml_adapter.c`, which parses the input event by event |
| `libpng` | the library translation units with the `pnglibconf.h` it ships prebuilt (pinned), linked with the `zlib` recipe's sources from the zlib checkout beside it (fetch both), with `adapters/libpng_adapter.c`, which decodes the input to RGBA with the simplified API |
| `re2` | RE2 2023-06-01: `re2/*.cc` and `util/{rune,strutil}.cc` (pinned) against the system Abseil through pkg-config (`libabsl-dev`), with `adapters/re2_adapter.cc`, which compiles the input as a pattern under a memory budget and matches it; `-fno-sanitize=vptr`, since the C driver links no UBSan C++ runtime. The pin is the latest release that builds with the Abseil distributions ship (20220623); later ones need `absl_check` |

Each adapter is named `<target>_adapter`, since the trial dir holds every
source by its file name and RE2 has its own `re2.cc`; two sources with one
name stop the run. A recipe's libraries (`link_flags`) follow the sources on
every compiler line, and reach bhf as `bhf build --ldflags`.

A smoke build prepares every recipe and builds and runs its libFuzzer harness:

```sh
BHF_TRADE_STUDY_SOURCES=<fetch root> python3 -m unittest discover \
  -s benchmarks/engine-comparison -p test_runner.py
```

## Experiment 2: auto-harness productivity

[`harness-parity-20/run.py`](../harness-parity-20/README.md) runs `bhf auto`
from a clean pinned checkout of each real project and compares the generated
harness's project-line coverage against a reviewed expert harness at the same
revision (`BHF_BLIND_EXPERT_HARNESSES=1` hides the project's own fuzz driver
from recipe mining). The runner records:

- **Setup separated from campaign.** `setup_wall_s` (clone/fetch/checkout) and
  `auto_wall_s` (the single `bhf auto`: discovery, build recovery, harness
  generation and fuzzing) per project, and a finer build-versus-fuzz split
  when bhf emits one.
- **A funnel that counts every attempted project.** `attempted → checkout_ok →
  produced_result → body_executed → expert_comparable → parity_or_better`, with
  *projects attempted* as the denominator at every stage. A project that fails
  to check out or build stays in the table and drops out at that stage.
- **Provenance.** `run-metadata.json` records the binary's SHA-256 and
  version, the git commit, the host, the configuration and every project
  commit.

```sh
cargo build --release -p bhf
python3 benchmarks/harness-parity-20/run.py --seconds 15 --jobs 2 \
  --output /path/to/output
```

Experiment 2 measures coverage parity. Confirmed crash and sanitizer findings
per engine are measured by Experiment 1 (`retained_findings`).

## Scope of the results

- **What each experiment measures.** The controlled gates measure how bhf's
  engine reaches gate-guarded bugs in micro-fixtures. The harness-parity suite
  measures the project-line coverage of bhf's generated harnesses against
  expert harnesses on a pinned real-code set. Quote each result with the
  target set it was measured on.
- **Engines compared.** bhf's built-in engine, AFL++, libFuzzer and honggfuzz.
- **Real-code multi-file builds.** Each engine's build is a single clang,
  `afl-cc` or `hfuzz-cc` invocation. A target whose project build needs more
  than that has a recipe in `recipes.py`, or ships as `requires_build_recipe`
  and shows as an `unsupported` row.
- **bhf with a provided harness.** With `bhf_harness_mode=provided` (the mode
  for comparing engines on real code) the bhf lane wraps the same
  `harnesses/libfuzzer.c` every other engine builds:
  `bhf generate-harness harnesses/libfuzzer.c --target LLVMFuzzerTestOneInput
  --id H-PROVIDED --output <work>/harnesses`, with each target source as
  `--extra-source` and each include dir as `--extra-include`, then
  `bhf build <work> --harness H-PROVIDED --cflags "<extra_cflags>"` and the
  same `bhf fuzz` budget, seeds and flags as the generated mode.
  `--bhf-harness-mode provided|generated` overrides the mode for every target
  (the builtin fixtures default to `generated`).
- **Native execution counters** are never compared across engines.

## CI boundary

No workflow runs the campaign drivers. `ci.yml` runs the deterministic
classification, statistics and manifest tests in
`benchmarks/engine-comparison/test_runner.py` ("Test the engine-comparison
scripts"), before bhf is built, so they build and fuzz nothing; the provided-
harness smoke among them runs only where a bhf binary (`$BHF_TRADE_STUDY_BHF`,
else `target/release/bhf`) and clang exist:

```sh
python3 -m unittest discover -s benchmarks/engine-comparison -p 'test_*.py'
```

Full real-code studies run offline or on a schedule and publish their evidence
(raw rows, hashes, commands, analysis) separately.

## Dependencies

The drivers use only the Python standard library (dataclasses, with strict
validation that raises descriptive errors), so a study runs on a bare
`python3` with nothing else installed on the benchmark host.
