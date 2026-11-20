<!-- SPDX-License-Identifier: Apache-2.0 -->
# 500-project sweep (2026-07)

One sweep of bhf over 500 pinned open-source projects in sixteen language lanes, run to find bugs and feature gaps in bhf. Every number below is reproducible from the files in this directory. The written comparison is [`docs/site/sweep-500.md`](../../docs/site/sweep-500.md).

## How to reproduce

```sh
export BHF_BIN=/path/to/pinned/bhf  # the binary every project runs
sh launch_full.sh                   # run the sweep in the background
python3 aggregate.py --blockers 25  # the tables below
python3 publish.py                  # the Results section of docs/site/sweep-500.md
python3 charts.py                   # the figures
python3 surfaces.py --project <dir> # 22 command checks against one project
python3 compare.py sloc|static|sbom|fuzz  # against cloc/tokei, cppcheck/..., syft
```

Run the commands from this directory. Every launch script runs the binary in `BHF_BIN` and stops if it is missing; the scripts' defaults point at the copies under `/home/ubuntu/bhf-sweep-bin/` that produced the checked-in rows. Copy the binary once and point `BHF_BIN` at the copy: rebuilding during a sweep would mix bhf versions across the corpus. `compare.py` reads its clones from `--projects` (default `/home/ubuntu/bhf-corpus-500`); its results on twelve projects are in [compare-section.md](compare-section.md).

`publish.py` counts only the repositories pinned in `corpus.tsv` and writes the page's reviewed wording, so run over the same rows it leaves `docs/site/sweep-500.md` unchanged. Its blocker table ranks why bhf could not drive a target and leaves out build failures (`failed_build`), which the page's reading of the table does not cover; `aggregate.py --blockers` ranks every category.

`python3 build_corpus.py select` rebuilds the corpus from a fresh GitHub search. It needs network access and the `gh` CLI, and it overwrites the pinned `corpus.tsv` and `pool.tsv`.

The corpus is pinned in `corpus.tsv` (lane, repository, clone URL, stars, size), with ranked replacements in `pool.tsv`. Each project is cloned, measured and deleted in turn, so the sweep keeps only a few working trees on disk at once. `results/` holds one JSON row per project: the target-status histogram, the residual blockers, the findings, the exit code and wall time of each command, and any panic.

## Corpus selection

The corpus is the top-starred GitHub repositories per language, without fuzzing corpora and deliberately vulnerable trees (they bring their own bugs), awesome-lists and courses (no code), forks, archived repositories and anything over 400 MB.

GitHub's primary-language label is often wrong: JavaScript wrappers tagged COBOL, C projects tagged Perl, editor-config trees tagged Lua. Each clone is checked against its lane before it counts, and a clone that is not mostly that lane's source is replaced from the pool.

## What the sweep exercises

For every project the sweep runs `sloc`, `list targets`, `static-scan` (report and SARIF), `sbom`, `auto` (discover, harness, repair, build, fuzz, report) and `report` in all four formats. `surfaces.py` runs 22 command checks against one project, including the commands the per-project sweep skips: the triage chain (`minimize`, `replay`, `explain`, `capsule`, `verify-poc`, `cartography`), `license-audit`, governance (`policy`, `audit`, `export`), `binary scan`, `snippet` and `ci`.

## Defects the sweep found

Each defect below was fixed in bhf and the fix was checked against the project that exposed it:

| Defect | Effect | Verified fix |
|---|---|---|
| Extension-only language detection | cloc (20k lines of Perl) discovered **0** targets, because its code lives in a file named `cloc` | shebang detection; 0 → 6/6 fuzzed |
| `require` compiles into the caller's package | a script's `main::` subs looked undefined to the harness | load as `main`; part of the same 0 → 6/6 |
| Driver and Fortran glue both defined `__sanitizer_cov_trace_pc` | **every** Fortran target failed to link | weak symbol; LAPACK failed_build → built+fuzzed |
| Only MODULE-defining Fortran files were pre-compiled | FORTRAN 77 projects had nothing to link against | symbol-directed link closure |
| C# TFM table hardcoded net8.0, ignored platform suffixes and `Directory.Build.props` | v2rayN: **0/25** targets | dynamic SDK ceiling; 0 → 3/5 at 9.5k exec/s |
| `dotnet build -o` across a project graph | every C# harness after the first died in MSB4018 | build in place, copy output |
| Interpreted lanes searched only the file's directory and the checkout root | Ruby and Lua skipped nearly everything as "not loadable" | package-root recovery |
| `app/` on the non-library exclusion list | scrcpy, a C project, discovered **0** C targets | recover a language that would otherwise be empty; 0 → 759 candidates |
| ANSI `(void)` prototypes and commented-out example calls read as K&R | modern C files routed to report-only, never fuzzed | comment-aware scan, keywords are not parameter names |
| `--campaign-time` billed from process start | discovery on a large tree used the whole budget; 8606 candidates, **0** attempted | bill from the sweep |
| `--campaign-time` did not bound work in flight | a 150s budget ran ten minutes | clamp subprocesses, stop repairing past the budget |
| Undefined function-like macro in a `#if` | scrcpy's FFmpeg version check left every target in the TU unbuildable | numeric function-like expansion |
| `verify-poc` on a known-non-reproducing capsule | reported FAIL, reading as a regression | report the packaged verdict |
| Blocker histogram keyed on the first line | MSBuild's "Build FAILED." banner merged every C# failure into one row naming nothing | prefer the line that names an error; keep diagnostic codes intact |
| A package that isn't installed reported as "a parameter couldn't be driven" | 661 corpus targets advised to run `--force`, which cannot install a package, while `missing-deps.txt` reported nothing missing | one shared reason builder for all six interpreted lanes; the triage counts the two causes apart |
| CPython quotes the module name, and the extractor stopped at the quote | the Python needle never fired, so no Python package was ever named | skip the opening quote |
| A Composer tree with no `vendor/` matched nothing | the shape of nearly every real PHP project produced no requirement at all | `Failed opening required` needle → `vendor/autoload.php`, with `composer install` as the hint |
| A backtick assumed to close with an apostrophe | rustc- and interpreter-style `` `foo` `` leaked the name into the grouping key; the published table carried a mangled `target module "X"torch"X"` row | close a backtick on either delimiter |
| The external-class degradation matched compiler wording | bhf no longer emits the substitution it was written for (an opaque scalar), so an unsuppliable MFC class stayed a bare failed_build | decide on provenance: a diagnostic in the project's own source is not a bhf codegen bug |
| Seven wall-clock-budgeted fuzz assertions on six cores | a planted OOB went unfound at ~6 executions where one test alone gets ~32 | serialize the fuzz-bearing tests |

### Re-measuring one surface, or an A/B

`run_sweep.py --merge` updates only the surfaces named by `--surfaces` and keeps the rest of an existing row: a `sloc`-only pass over the corpus takes minutes, a full re-run takes hours. `--results-dir` writes rows to another directory, so an A/B wave (for example with `--auto-force`) can be compared with `aggregate.py --compare` while the baseline stays intact.

## The 2026-07-27 and 2026-07-28 re-runs

`sh launch_full_0727.sh` and `sh launch_full_0728.sh` (bhf 0.2.22) re-run the same corpus and budgets with newer pinned binaries, writing to `results-0727/` and `results-0728/` so that `results/` stays as the baseline. Read a re-run with `python3 aggregate.py --results results-0727`.

Scored over the 500 repositories pinned in `corpus.tsv`, the basis `docs/site/sweep-500.md` publishes:

| | 2026-07-26 (`results/`) | 2026-07-27 (`results-0727/`) | 2026-07-28 (`results-0728/`) |
|---|---:|---:|---:|
| projects measured | 438 | 439 | 457 |
| targets discovered | 1,033,736 | 1,047,407 | 1,182,129 |
| attempted | 3,493 | 3,420 | 3,449 |
| **built + fuzzed** | **987 (28.3%)** | **983 (28.7%)** | **984 (28.5%)** |
| findings | 290 | 332 | 329 |

**Score a re-run against the pinned corpus.** A bare `aggregate.py` rolls up every row file in the directory, and each directory also holds rows for repositories the lane check later replaced from the pool: 35, 26 and 27 of them. On that all-rows basis the three runs read 453/463/482 projects and 28.5%/29.4%/29.4% built and fuzzed. The pinned-corpus rates above stay within half a point of each other; the all-rows rise comes from the corpus changing between runs. `aggregate.py` prints the all-rows totals, so name the basis whenever you quote a number from this directory.

The 2026-07-27 re-run found four defects, each in `CHANGELOG.md`: a cyclic C++ construction recipe that used 12 GiB and got 22 projects OOM-killed during discovery, POSIX/GLib scalar typedefs misread as opaque handles, a `java.io.File` parameter that could not be driven, and the blocker histogram corrupting its own grouping key in two ways. [`docs/open-defects-discovery-cost.md`](../../docs/open-defects-discovery-cost.md) records how the discovery-cost defects were isolated and fixed.

**Re-run a blocker row before you work on it.** Half of the largest blocker rows in `results/` (`Cannot find module "X"); run "X"`, `target module "X"torch"X"`, the PHP row that read `  thrown in PATH on line N`) came from a binary older than the fix for them. The fastest check is to reproduce the row on a five-line fixture with the current binary, which takes about a minute.

## Result directories

| Directory | Contents |
|---|---|
| `results/` | 2026-07-26 full sweep (`launch_full.sh`) |
| `results-0727/`, `results-0728/` | Full re-runs (`launch_full_0727.sh`, `launch_full_0728.sh`) |
| `results-0729/`, `results-0729b/`, `results-0730/` | 48-project waves, three projects per lane |
| `results-force/`, `results-force3/`, `results-plain2/` | The `--force` A/B over 126 projects (`launch_force_ab*.sh`, `launch_plain2.sh`); compare with `force_delta.py`, see [`docs/open-defects-force-and-reach.md`](../../docs/open-defects-force-and-reach.md) |
| `results-1116-*/`, `results-1117-*/`, `results-1118-*/` | `go1_rerun.py` re-runs, at the measured commits, of the targets `results-0728/` skipped for one blocker class |
| `baseline-w0/` | The pre-fix one-project-per-language smoke wave that the before/after figure compares against |
| `charts/` | The figures |
