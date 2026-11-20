<!-- SPDX-License-Identifier: Apache-2.0 -->
# What 500 real projects say about bhf

This page reports bhf run over 500 open-source projects picked by star rank
rather than by suitability, across all sixteen languages bhf supports, with
every failure counted.

The sweep was run to find defects in bhf. It found thirty, listed below
with the project that exposed each one. The measurements below were taken
after the fixes, with a single pinned binary over the whole corpus.

## Method

- **Corpus**: 500 repositories, star-ranked per language, pinned in
  `benchmarks/campaign-2026-07-25/corpus.tsv`. Excluded: fuzzing corpora and
  deliberately vulnerable trees (they supply their own bugs), awesome-lists
  and courses (no code), forks, archived trees, and anything over 400 MB.
  GitHub's language label is not trusted: each clone is checked against its
  lane and replaced from a ranked pool if it is not mostly that language.
- **Budget**: every project gets the same budget. There is no per-project
  tuning, no hand-written harness, no build fix, and no dependency
  installation beyond what a developer of that language would already have.
- **Counting**: a target counts as fuzzed only if it built and the fuzz
  entry point was reached. A build that links against stubs and executes
  none of the project's own code is recorded separately
  (`fuzzed_stub_only`) and is not counted in the headline.
- **Basis**: the results table and its totals are rolled up over the 500
  repositories pinned in `corpus.tsv` and nothing else. `results/` holds 534
  row files, because the lane check replaced repositories from the ranked
  pool as the campaign ran and the superseded rows were kept; 35 of them
  name repositories that are no longer in the pinned corpus, and they are
  excluded here. Of the 500 pinned repositories, 499 produced a row and 438
  produced a measurable `auto` run; the rest were rejected by the lane check
  or timed out before reporting. The `--force` comparison below is scored
  separately, as a pairwise per-repository delta over the 126 projects
  measured in both arms.

Everything needed to re-run the sweep is in
[benchmarks/campaign-2026-07-25/](../../benchmarks/campaign-2026-07-25/README.md).
Score a re-run against the pinned corpus to reproduce the table below; a
bare `aggregate.py` over `results/` prints the larger all-rows totals.

## What the sweep measures

The sweep measures how much of a large code estate bhf can fuzz without
anyone writing harnesses first. On one hand-written harness, libFuzzer and
AFL++ are strong engines; the work that does not get done at scale is
writing the harnesses. An engineer with a week can write five harnesses, not
five hundred.

So the headline is coverage of the estate:

- targets discovered, per language, across 500 projects nobody prepared;
- of those attempted, how many built and fuzzed;
- what stopped the rest, named precisely enough to fix.

## Defects the sweep found

Each of these was a bug in bhf, not in the project, and each is fixed with a
regression test:

| Language | What was wrong | Effect on the project that exposed it |
|---|---|---|
| Perl | code was classified by file extension only | cloc (20k lines of Perl in a file named `cloc`) discovered **0** targets; now 6/6 fuzzed |
| Perl | `require FILE` compiles into the caller's package | a script's `main::` subs looked undefined |
| Fortran | the C driver and the Fortran glue both defined `__sanitizer_cov_trace_pc` | **every** Fortran target failed to link |
| Fortran | only MODULE-defining files were pre-compiled | FORTRAN 77 (LAPACK, BLAS) had nothing to link against |
| C# | the framework table was hardcoded to net8.0 and ignored `Directory.Build.props` | v2rayN: **0 of 25** targets; now 3/5 at 9.5k exec/s |
| C# | `dotnet build -o` across a project graph | every harness after the first died in MSB4018 |
| Ruby, Lua | the interpreter saw only the file's directory and the checkout root | nearly everything skipped as "not loadable" |
| Python | a module whose name is not an identifier | git's `git-p4.py`: **0 of 3**, reported as the project's syntax error; now 3/3 |
| C | `app/` was on the non-library exclusion list | scrcpy, a C project, discovered **0** C targets; now 759 candidates |
| C | ANSI `(void)` prototypes and commented-out examples read as K&R | modern C files routed to report-only, never fuzzed |
| C | an undefined function-like macro in a `#if` | scrcpy's FFmpeg version check left a whole TU unbuildable |
| core | `--campaign-time` was billed from process start | discovery on a large tree consumed the budget: 8606 candidates, **0** attempted |
| core | the budget did not bound work already running | a 150-second budget took ten minutes |
| triage | `verify-poc` on a capsule packaged as non-reproducing | reported FAIL, which reads as a regression, for a capsule recorded as not reproducing |
| Rust | a binary-only crate has no `src/lib.rs`, and the generated manifest did not say where the library was | cargo refused the manifest: "can't find library `vaultwarden`" |
| Rust | a path dependency inside the crate was pinned back to the original tree, which the copy also contained | "package collision in the lockfile" |
| C# | an old-style project declares `<TargetFrameworkVersion>`, not `<TargetFramework>` | .NET Framework projects were referenced anyway and died on reference assemblies that do not exist off Windows: 28 targets |
| core | parsing recurses, and a main thread's 8 MiB is not enough for real source | vllm and milvus **aborted the whole run** during discovery |
| report | a file's static findings were keyed by the target being harnessed | one Fortran project reported **120 findings for 24 real weaknesses** |
| report | a compiler `note:` was read as the blocker | Ventoy's histogram named a deprecation notice as what stopped the build |
| sloc, static | the file walk admitted ten of the sixteen fuzzed lanes | a 217-file PHP project measured **333 lines**, all of it config; Ruby, Lua, C#, COBOL and Fortran were equally invisible |
| sbom | the gemspec parser required parentheses | every gemspec-driven Ruby project reported **zero** components |
| afl++ | the armed `ASAN_OPTIONS` reached afl-fuzz without `symbolize=0`, which AFL++ v4 refuses to start without | the **entire `--engine afl++` path was dead**: harnesses built, AFL aborted in pre-flight, no target ever counted as fuzzed |
| Python, JavaScript, PHP | a target that could not load because a package is not installed was reported as "a parameter couldn't be driven", and named no package | the **largest single blocker class in the corpus** told the operator to run `--force`, which cannot install a package, while `missing-deps.txt` said no dependency was missing |
| Python | the extractor for CPython's `No module named 'x'` stopped at the opening quote | the pattern was in the table but never matched |
| PHP | a Composer project with no `vendor/` produced no requirement at all | the shape of nearly every real PHP tree; now recorded as `vendor/autoload.php` with `composer install` as the remedy |
| report | a backtick span was assumed to close with an apostrophe (the GNAT `` `foo' `` form) | rustc- and interpreter-style `` `foo` `` messages leaked the identifier into the grouping key, so each distinct name became its own histogram row instead of one grouped row |
| C++ | the check that degrades an unsuppliable external class to a report-only scan matched on the compiler's *wording*, and the substitution it was written for is no longer the one bhf emits | an out-of-tree MFC class stayed a bare `failed_build`. The check now decides on provenance (a diagnostic in the project's own source cannot be a bhf codegen bug), so a later change of substitution shape does not break it |
| fuzz | the AFL++ fix above armed `symbolize=0` on **every** fuzz child, and the file:line in a sanitizer report is what joins a crash to the static finding at the same line | **every `fuzz_confirmed` static finding became `fuzz_exercised`**. The two engines need opposite settings, and each now gets its own |
| C, C++ | UBSan's `nonnull` check (how `memcpy(NULL, …)` is reported) was not one of the four the parser named, and it returned nothing for the rest | the abort read as the target rejecting the input and the crash was **discarded**, so `bhf capsule` had nothing to package and the provenance pass had nothing to demote to `lab_only`. An unrecognised check is now reported generically rather than dropped |

## Results

438 projects measured out of 500 pinned, 152,772,744 lines of code, 1,033,736 fuzzable targets discovered, with no harness written by hand.

`Projects` counts pinned repositories that produced a result row; `Measured` counts those that produced an `auto` run to roll up. `Rate` is fuzzed over attempted.

| Language | Projects | Measured | SLOC | Targets found | Attempted | Fuzzed | Rate | Findings |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Java | 38 | 37 | 8,580,880 | 258,290 | 237 | 42 | 18% | 2 |
| C | 59 | 51 | 56,922,324 | 205,601 | 404 | 95 | 24% | 56 |
| Rust | 40 | 40 | 10,958,714 | 139,262 | 236 | 56 | 24% | 10 |
| Go | 40 | 39 | 13,252,595 | 117,922 | 366 | 63 | 17% | 17 |
| C++ | 55 | 27 | 14,625,817 | 64,419 | 174 | 33 | 19% | 4 |
| Ada | 25 | 22 | 3,108,735 | 42,034 | 203 | 39 | 19% | 6 |
| Ruby | 22 | 21 | 4,376,372 | 40,810 | 201 | 55 | 27% | 0 |
| Perl | 20 | 14 | 2,238,429 | 40,161 | 124 | 68 | 55% | 1 |
| Python | 40 | 36 | 3,565,164 | 32,958 | 354 | 125 | 35% | 11 |
| Fortran | 20 | 19 | 12,808,458 | 24,996 | 124 | 37 | 30% | 159 |
| PHP | 22 | 21 | 4,685,622 | 24,842 | 206 | 109 | 53% | 0 |
| TypeScript | 25 | 25 | 5,159,766 | 12,624 | 210 | 55 | 26% | 2 |
| Lua | 20 | 19 | 3,005,378 | 10,733 | 173 | 54 | 31% | 1 |
| COBOL | 18 | 14 | 1,889,093 | 8,415 | 73 | 27 | 37% | 7 |
| C# | 25 | 25 | 6,002,013 | 5,887 | 180 | 22 | 12% | 4 |
| JavaScript | 30 | 28 | 1,593,384 | 4,782 | 228 | 107 | 47% | 10 |
| **All 16** | **499** | **438** | **152,772,744** | **1,033,736** | **3493** | **987** | **28.3%** | **290** |

One repository, `DeusData/codebase-memory-mcp`, contributes 37,987,460 of those lines (25% of the corpus) at roughly 46,000 lines per file: generated or amalgamated content rather than written code. Without it the corpus is 114,785,284 lines, which is the figure to reason about; it is left in because the corpus is star-ranked, not curated.

### Robustness

Across the 499 pinned projects and 2,439 surface invocations: **0 panics**, **15 timeouts**.

### What blocked the rest

| Targets | Language | Cause |
|---:|---|---|
| 176 | typescript | Cannot find module "X"); run "X" |
| 167 | python | ModuleNotFoundError: No module named "X" |
| 78 | c | C parameter "X" of type "X" has no byte-buffer decoder after struct sy |
| 76 | php | target "X" |
| 69 | java | Java target "X" parameter #N has an unsupported type "X" |
| 58 | go | unsupported Go parameter type "X" |
| 56 | javascript | Error [ERR_MODULE_NOT_FOUND]: Cannot find package "X" imported from /h |
| 53 | cpp | [cpp20] blocked_by_non_self_contained_header: "X" cannot be included b |
| 47 | rust | Rust parameter type "X" has no bhf-native byte decoder |
| 44 | javascript | Cannot find module "X"); run "X" |
| 37 | cpp | C++ parameter "X" of type "X" has no byte-buffer decoder (auto-harness |
| 31 | csharp | instance method "X" |

## Reading the blocker table

The largest single class is uninstalled dependencies. The top TypeScript
(176) and Python (167) entries are "cannot find module": the corpus was
cloned and measured without running `npm install` or `pip install` for 500
projects, so a target whose module graph reaches a package that is not on
the machine cannot be loaded. Install the dependencies and those targets
load.

The interpreted lanes name the missing package, record it as an acquirable
requirement (`missing-deps.json`, actionable with `--install-deps`), and
separate it in the triage from the skips `--force` is for.

The next tier is bhf's own limits: parameters whose types the project never
defines (78 in C, 37 in C++, 47 in Rust, 58 in Go), C++ headers that cannot
be included outside their owning translation unit (53), and instance
methods whose receiver cannot be constructed (31 in C#).

## Limits

- A target whose parameters are types the project does not define (an
  external SDK's opaque handle, for example) is skipped, and the skip reason
  names the type. bhf does not invent a definition and report the result as
  a clean fuzz.
- A project whose dependencies are not installed is reported as needing
  them, with the package named, instead of being fuzzed against stubs by
  default. For a compiled lane, `--force` drives past a missing type or
  symbol and records the result as stub-only. For an interpreted lane,
  `--force` cannot get past a missing package, and the skip reason says to
  install it.
- Measured over the 126 corpus projects that had at least one undrivable
  target, applying `--force` from the start of the sweep reached 13 fewer
  targets than not passing it (214 → 201), for one extra fuzz finding. A
  forced attempt costs about 36% more, and the campaign budget ran out
  before the viable targets were reached. `--force` is now a second pass
  that runs after the normal one, so it can only add reach. In this
  measurement it turned unbuildable targets into static analysis rather
  than into fuzzing.
- Interpreted lanes execute the target's module to load it, which runs the
  module's top-level code, as fuzzing it does.
- The per-project budget bounds how many targets are attempted. A project
  with thousands of candidates has a fraction of them measured here. The
  rate is reported over attempted targets, with the discovered total beside
  it, so the difference is visible.
