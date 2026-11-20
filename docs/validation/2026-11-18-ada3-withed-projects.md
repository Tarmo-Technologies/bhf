<!-- SPDX-License-Identifier: Apache-2.0 -->
# Ada-3 withed-project re-run, 2026-11-18

This record re-runs, by name, every Ada target that the 2026-07-28 campaign sweep (`results-0728`) failed to build because a unit "cannot belong to several projects". That is the Ada-3 class of [expected-gaps.md](../expected-gaps.md). The project is re-run at the commit that sweep measured. The bhf under test is a release build of the wave-12 branch, which leaves the units of the projects a target's project `with`s to those projects (#287).

The rows are under `benchmarks/campaign-2026-07-25/`:

| Directory | What it is |
|---|---|
| `results-0728/` | Before: the 2026-07-28 sweep |
| `results-1118-ada3/` | After: the 10 targets, in 1 project |

## Reproduce

```sh
cd benchmarks/campaign-2026-07-25
BHF_BIN=<bhf> python3 go1_rerun.py results-0728 results-1118-ada3 \
  --lang ada --class Ada-3
```

As for [Ada-4](2026-11-18-ada4-vendored-runtime.md), each July failed build without a reason is given its row's most common one.

## Before and after

All 10 are in mk270/whitakers-words, whose `commands.gpr` `with`s `words_engine.gpr`, which `with`s `support_utils.gpr`, which `with`s `latin_utils.gpr`. Each project owns its `src/<name>` directory, and the last three are library projects. The July rows count `Inflections_Package`'s three `Get` overloads as three targets; the re-run attempts the name once, so the table counts subprograms.

| | Before | After |
|---|---:|---:|
| Subprograms re-run | 8 | 8 |
| Failed build: a unit cannot belong to several projects | 8 | 0 |
| Built and fuzzed | 0 | 7 |
| Failed build: the harness gives a record's components integer literals (#418) | 0 | 1 |

`English_Support_Package.Ewds_Record_Io.Get` now builds past the project structure and stops in its own harness: the record it takes has string and enumeration components, which the harness initializes with integer literals. That is a harness generation gap, tracked as #418.

The run reported 9 findings. 7 are in the project's own code: index and range checks in the word comparisons (`Word_Package`, 4), the Roman-numeral parser (1) and the inflection record reader (2), on input they do not validate. The other 2 are false positives from the harness: an `out` parameter of the fixed-length `Stem_Type` is declared as an empty `String`, so the call fails its length check before the project's code runs. That is #418 too.

## What it took

bhf staged an instrumented copy of every unit the target's closure needs in one directory, and built it with a project that extends the target's own. A unit of a project the target's project `with`s then had two owners, the staged copy and the withed project, and gprbuild refused it. Four changes got the 7 built and fuzzed:

- **A withed project's units are left to it.** bhf reads the closure of projects the governing one `with`s (following `extends` and the project path) and their `Source_Dirs`, and stages none of their units: the build compiles them where they are, uninstrumented. The log says how many.
- **`Source_Dirs` as gprbuild reads it.** whitakers-words spells each one `"src/" & project'Name`. bhf now evaluates that, `**` and the project-directory default, so it picks the project that owns the target's source to govern the build (alphabetically, it had picked `commands.gpr`).
- **A library project governs as it is.** A library project cannot be extended, so its build stands alone and takes its `with`s with it.
- **Copies an earlier target staged.** The staging is shared by the run's targets, and gprbuild reads every unit in it, not only the target's closure. A copy that `support_utils`' own targets staged would be a second owner for a `words_engine` target, so bhf removes the staged copies of the withed projects' units before it stages a target's closure.
