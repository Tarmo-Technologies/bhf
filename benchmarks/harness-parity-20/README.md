<!-- SPDX-License-Identifier: Apache-2.0 -->
# Blind 30-project harness parity suite

This suite compares a bhf-generated harness with a small, reviewed expert harness for the same API, on 30 C and C++ projects. Projects and revisions are pinned in `projects.tsv`, and the expert harnesses are in `expert/`. The runner sets `BHF_BLIND_EXPERT_HARNESSES=1`, which keeps the project's own fuzz entry points out of recipe mining, and sets `BHF_EXPERT_HARNESS` to the exact expert file the coverage oracle measures against.

Run a short sweep:

```sh
cargo build --release -p bhf
python3 benchmarks/harness-parity-20/run.py --seconds 15 --jobs 2
```

| Option | Default | Meaning |
|---|---|---|
| `--bhf` | `target/release/bhf` | bhf binary |
| `--output` | `/tmp/bhf-harness-parity-20` | where clones, work directories, logs, raw JSON, `results.tsv` and `summary.md` go |
| `--sources` | `<output>/sources` | where the pinned checkouts are cloned and reused |
| `--seconds` | 15 | fuzzing budget per project |
| `--jobs` | 2 | projects run at once |
| `--resume` | off | pass `--resume` to `bhf auto` instead of `--fresh-discovery` |
| `--only` | all | run only the named project (repeatable) |

A project counts as measured only when both harnesses build and the oracle reports comparable implementation files. The checked-in results used five-second campaigns (`--seconds 5`).

The directory keeps the name of the original 20-project suite. `projects.tsv` and the checked-in 2026-08-14 results in `results/` cover 30 projects: the expansion added libxml2, PCRE2, libwebp, Snappy, msgpack-c, Lua, cmark, libucl, tomlc99 and libcsv. [`ANALYSIS.md`](ANALYSIS.md) has the method, the results and the open gaps, and [`results/summary.md`](results/summary.md) the per-project table.

This suite is Experiment 2 (auto-harness productivity) in [`../engine-comparison/METHODOLOGY.md`](../engine-comparison/METHODOLOGY.md), which also describes the engine-quality experiment. Each run records `setup_wall_s` (checkout) apart from `auto_wall_s` (the `bhf auto` campaign, including build recovery), writes a funnel whose denominator is every attempted project (checkout and build failures stay in it), and writes `run-metadata.json` with the binary's SHA-256 and version, the git commit, the host and the project commits.
