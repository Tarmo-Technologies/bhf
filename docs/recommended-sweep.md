<!-- SPDX-License-Identifier: Apache-2.0 -->
# The recommended BHF sweep

Use this command for the usual job: point BHF at a source tree you control,
fuzz what it can build, and get a static-analysis and supply-chain report for
the whole tree.

```sh
bhf auto /path/to/source-tree \
  --work-dir bhf_work \
  --jobs 4 \
  --per-target-time 60 \
  --campaign-time 3600 \
  --max-targets 40 \
  --unsafe-search-and-run-build-commands \
  --force \
  --static \
  --sbom \
  --sloc sloc.txt \
  --debug
```

Read `bhf_work/results/INDEX.md` first. `results/findings.json` and
`results/findings.csv` are the machine-readable root-cause indexes, and
`results/findings/` holds the full evidence for each finding. The campaign and
coverage reports are `auto/run.md`, `auto/run.json`, and `auto/summary.txt`.

## What each flag does, and how to size it

| Flag | What it does |
|---|---|
| `--work-dir bhf_work` | Where everything the run produces goes: harnesses, corpora, findings, reports. **Keep it outside the tree being scanned**, or the next run discovers BHF's own generated harnesses as targets. |
| `--max-work-dir-mb 4096` | The default ceiling on the work directory's allocated size (not in the command above). Once it is reached, BHF keeps completed and in-flight work and starts no new targets; `0` disables it. Parallel in-flight targets can overshoot it by their final artifacts. |
| `--max-corpus-mb 64` | The default per-target ceiling on the retained coverage corpus, in memory and in `corpus/<id>/queue/` (not in the command above). Finding testcases are never deleted. Raise it for deep formats with large inputs when disk allows. |
| `--jobs 4` | Candidates built and fuzzed at once. The default is half the host's parallelism. Child memory is about `jobs × --rss-limit-mb`, plus room for BHF, the compilers and the OS, so on a small or cgroup-capped host lower it before raising it. Ada targets build one at a time because they share one staged source tree. |
| `--per-target-time 60` | Fuzz wall-clock seconds per target, split across the three passes (empty, rng, fuzz-driven) under one shared deadline; the counterpart of libFuzzer `-max_total_time` and AFL `-V`. 60 seconds finds shallow bugs; raise it for a real campaign. |
| `--campaign-time 3600` | Outer cap for the whole sweep, counted from the first build attempt. Discovery and preflight are not counted, so a large tree that takes minutes to index still fuzzes. Once it is exceeded, no new targets start; the in-flight one finishes. |
| `--max-targets 40` | Stop once 40 targets have **fuzzed**. Unsupported parameters and failed builds do not count, so lower-ranked viable targets fill the slots. Add `--max-attempts N` to also cap how many candidates are inspected. |
| `--unsafe-search-and-run-build-commands` | **Runs code from the scanned tree.** Finds the project's own build entry point (`build.sh`, autotools, CMake, Meson, SCons, Waf, Bazel) and runs it under BHF's compiler-interception shim to recover the real compile flags. On most C/C++ trees this is what makes targets build. Use it only on sources you trust. For untrusted code, drop it, and pass `--build-command` if you know the build command. |
| `--force` | A second phase over the targets phase one could not fuzz: synthesize a driver for a parameter BHF cannot drive, stub whatever the compiler reports missing, and fall back to a static-only report instead of failing. Phase one runs unforced first, so `--force` never lowers the fuzzed count. Findings from a forced build are marked low confidence with a note, because a fabricated value can cause a crash by itself. |
| `--static` | Runs the static analyzer over the whole tree as well as fuzzing, so files with no fuzzable entry point are analyzed and fuzzed targets also get static coverage. Static findings merge into the same report. |
| `--sbom` | Writes an evidence-graded SBOM and VEX bundle to `<work-dir>/sbom/` at the end of the campaign. Components a harness drove are marked exercised. Off by default because it adds time. |
| `--sloc sloc.txt` | Writes a per-language SLOC breakdown of the tree; a relative path lands in `<work-dir>/auto/`. A `.json` extension writes JSON instead of a table. |
| `--debug` | Captures a backtrace if BHF itself panics, keeps going past a file that crashes it, and adds detail to `bug-report.json`. It costs little; leave it on. |

## Variations

- **Reclaiming disk.** `bhf clean bhf_work --compact` removes disposable
  compiler caches and scratch files and keeps findings, reports, corpora,
  checkpoints, generated harness source, and replay binaries. `--corpus`,
  `--reports`, `--findings`, and `--all` each delete one named scope.
- **Untrusted source.** Drop `--unsafe-search-and-run-build-commands`. BHF
  still recovers what it can from `compile_commands.json` and its own probes.
- **A quick look instead of a campaign.** Use `--per-target-time 5
  --max-targets 10` and drop `--sbom`.
- **Some languages only.** `--languages c,cpp`. All sixteen languages are on
  by default: Ada, C, C++, Rust, Java, Python, Perl, Go, COBOL, Fortran, C#,
  JavaScript, TypeScript, Ruby, Lua, PHP.
- **Resuming.** `--resume` over the same work dir skips targets that already
  completed and runs the rest. If the target source changed, every target is
  attempted again.
  `--resume --force` keeps every target that already fuzzed and forces only
  the rest.
- **A second engine.** `--engine builtin,afl++` runs both engines on each C,
  C++, COBOL, Fortran, Rust and Ada target when AFL++ is installed, splitting
  `--per-target-time` between them.
- **Broken or incomplete Ada/C/C++ drops.** The offline auto runbook
  (`AUTO-OFFLINE-RUNBOOK.md` in a distribution,
  `docs/site/offline-auto-runbook.md` in the repository) gives the
  known-build and unknown-build recipes and how the recovery flags combine.

## Reading the result

`results/INDEX.md` is the summary to read and share. `auto/summary.txt`
counts each target under one outcome:

- **built+fuzzed**: a harness was built and executed the target.
  **built+fuzzed (STUB-ONLY)** means the harness exercised only stubs, not the
  real library.
- **built, NOT entered**: the harness built and ran, but the target entry was
  never reached.
- **static-only**: BHF could not build the target and analyzed it statically
  instead. The residual-blocker histogram at the end says why.
- **skipped**: BHF could not synthesize a driver for the parameters, or the
  lane's toolchain is not installed. `--force` retries the first kind.
- **failed build**, **link error**, **runtime error**: the build or the first
  run failed; the per-target line gives the reason.

Findings from a forced build are low confidence and carry a note saying what
was fabricated. Treat them as leads to confirm by replay.
