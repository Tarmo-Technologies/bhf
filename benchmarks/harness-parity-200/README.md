<!-- SPDX-License-Identifier: Apache-2.0 -->
# 200-project multilingual harness-parity audit

This audit measures bhf's generated harnesses against independent expert drivers in all sixteen language lanes. It sits beside two other studies:

- the [500-project sweep](../campaign-2026-07-25/README.md) asks whether any generated target builds and executes;
- the [30-project native suite](../harness-parity-20/README.md) compares C/C++ implementation-line sets in depth;
- this audit takes a balanced 200-project sample and records the strongest comparable evidence available in every lane.

The sample has 12 projects per language plus one more in each of the eight core lanes (C, C++, Rust, Java, Python, Go, JavaScript, TypeScript), 200 in all. In every language it includes up to four projects where the 2026-07-27 sweep reached no target; the rest fuzzed in that sweep. PHP has only three such rows in the source results, so its twelfth project is one that fuzzed. Within each group, projects are taken in star-rank order, preferring repositories under 50 MB so the audit can be repeated on one host. Every repository and revision is pinned in `projects.tsv`.

Evidence is reported in three tiers, each counted on its own:

1. discovery, build and target entry for every project;
2. semantic parity against an independently reviewed expert driver;
3. source-line parity, where both harnesses expose compatible covered-line coordinates.

Generate the pinned manifest from the 500-project corpus:

```sh
python3 benchmarks/harness-parity-200/select.py
```

Run one project per language as a toolchain and runner pilot:

```sh
cargo build --release -p bhf
python3 benchmarks/harness-parity-200/run.py --limit-per-language 1 \
  --keep-sources --output /tmp/bhf-harness-parity-200-pilot
```

The audit lets `bhf auto` try up to ten candidate targets per project (`--max-attempts 10`, the default). `--max-attempts 1` stresses target ranking and measures something different; keep its results apart.

Run or resume the complete audit:

```sh
python3 benchmarks/harness-parity-200/run.py --jobs 4
python3 benchmarks/harness-parity-200/run.py --jobs 4 --resume
```

After a change that affects only some lanes, rerun those projects into the same output with `--include-existing`. The fresh rows replace the old ones and the final report still covers the whole audit:

```sh
python3 benchmarks/harness-parity-200/run.py --jobs 4 \
  --only-language rust --only-language java --include-existing
```

| `run.py` option | Default | Meaning |
|---|---|---|
| `--bhf` | `target/release/bhf` | bhf binary |
| `--output` | `/tmp/bhf-harness-parity-200` | rows, `results.tsv` and `summary.md` |
| `--seconds` | 5 | fuzzing budget per project |
| `--jobs` | 2 | projects run at once |
| `--max-attempts` | 10 | candidate targets `bhf auto` tries per project |
| `--project-timeout`, `--clone-timeout` | 240, 300 | seconds |
| `--resume` | off | skip projects that already have a row |
| `--include-existing` | off | include rows of projects not run this time in the summary |
| `--keep-sources` | off | keep each clone after its row is written |
| `--only`, `--only-language` | all | restrict to a project or a language (repeatable) |
| `--limit-per-language` | none | at most this many projects per language |
| `--bhf-arg` | none | extra `bhf auto` argument for every project, recorded in each row (repeatable) |

The runner writes one JSON row per project before it removes the temporary clone, so an interrupted audit resumes without redoing finished projects. Every row records the bhf version and the SHA-256 of the binary, and the summary lists every hash it saw, so a mixed incremental rerun shows as one. Write the residual-gap matrix (`gaps.tsv`, `gap-report.md`) at any point with:

```sh
python3 benchmarks/harness-parity-200/analyze.py
```

Compare the rows with the expert set (one pinned real project and checked-in driver per language, listed in `expert-projects.tsv`):

```sh
python3 benchmarks/harness-parity-200/compare.py
```

`compare.py` exits with an error if a language or an expert file is missing. It reports dynamic target-entry and body evidence apart from target-selection parity, and lists the state, resource, dependency, object or ABI setup each expert driver uses. It writes `expert-parity-report.md` and `expert-harnesses.tsv` (the SHA-256 of every expert file) to the output directory. The [`expert/`](expert/README.md) directory has one real driver per language.

[`FINDINGS.md`](FINDINGS.md) summarizes the measured baseline, the final focused controls, the gaps closed and the remaining expert-parity paths. `rows-2026-11-17-zoxide/` holds the rows of the zoxide in-crate rerun ([validation record](../../docs/validation/2026-11-17-zoxide-incrate-parity.md)).
