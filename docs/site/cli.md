<!-- SPDX-License-Identifier: Apache-2.0 -->

# CLI

The `bhf` command runs every step of a fuzzing campaign: finding targets in
a source tree, generating and building harnesses, fuzzing, replaying and
minimizing findings, and writing reports. This page describes each command
group. `bhf --help` lists every command, and `bhf <command> --help` gives the
exact flags, defaults and accepted values of the build you have.

Most runs start with [bhf auto](#auto), which does every step for a whole
source tree; the [Auto guide](auto.md) walks through it. The other commands
run one step at a time or work on the results.

## Contents

- [Command map](#command-map)
- [Common flow](#common-flow): the manual pipeline, one step at a time
- [Auto](#auto): the whole tree in one command
- [Listing targets](#listing-targets)
- [Generating and building a harness](#generating-and-building-a-harness)
- [Fuzzing a harness](#fuzzing-a-harness), including
  [stateful protocol sessions](#stateful-protocol-sessions)
- [Dictionaries and structured inputs](#dictionaries-and-structured-inputs)
- [Actionability modes](#actionability-modes)
- [Runtime oracles, collectors and postconditions](#runtime-oracles-collectors-and-postconditions)
- [Differential and metamorphic testing](#differential-and-metamorphic-testing)
- [Replaying a finding](#replaying-a-finding)
- [Minimizing a finding](#minimizing-a-finding)
- [Crash to PoC, explanation and one-shot fuzzing](#crash-to-poc-explanation-and-one-shot-fuzzing)
- [Reports](#reports)
- [Static analysis and SLOC](#static-analysis-and-sloc)
- [Binaries without source](#binaries-without-source)
- [Fake CORBA and IDL dictionaries](#fake-corba-and-idl-dictionaries)
- [Introspection](#introspection)
- [Cleaning a work directory](#cleaning-a-work-directory)
- [Policy profiles](#policy-profiles)
- [Enterprise operations](#enterprise-operations): policy, runners, update
  packs, SBOM, export
- [Optional LLM and agent assistance](#optional-llm-and-agent-assistance)
- [External project profiles](#external-project-profiles), including
  [importing an OSS-Fuzz build](#importing-an-oss-fuzz-build)
- [Out-of-process extensions](#out-of-process-extensions)
- [Coverage-guided relational policy fuzzing](#coverage-guided-relational-policy-fuzzing)
- [Other commands](#other-commands)
- [Release commands](#release-commands)

## Command map

| Area | Commands |
|---|---|
| Whole-tree and manual pipeline | `auto`, `snippet`, `scan`, `list targets`, `generate-harness`, `build`, `fuzz`, `report`, `model` |
| Build and instrumentation support | `stub`, `instrument`, `fake-corba` |
| Corpus and crash triage | `corpus`, `minimize`, `replay`, `capsule`, `verify-poc`, `env-capsule`, `differential`, `relational`, `cmplog`, `explain`, `cartography`, `decode-args` |
| Binaries without source | `binary` (`scan`, `adapter`, `fuzz`, `rehost`) |
| Linux kernel drivers (syzkaller, a qemu-system guest) | `kernel` (`syzlang`, `import`, `run`, `fuzz`, `replay`); see [On-target fuzzing §10](on-target-fuzzing.md#10-linux-kernel-drivers-syzkaller-descriptions) |
| External project profiles | `project` (`validate`, `list`, `run`, `import-ossfuzz`) |
| Out-of-process extensions | `extension` (`validate`, `evaluate`, `session`, `minimize`), and `fuzz --extension` |
| Static analysis and supply chain | `static-scan`, `sloc`, `sbom`, `license-audit`, `extract-state-machines` |
| Reference | `rules` (`list`, `show`), `list oracles` |
| Governance | `policy`, `audit`, `pack`, `export` |
| CI and operations | `ci`, `runners`, `clean`, `introspect`, `bug-report` |
| Optional model assistance | `llm` (`status`, `test`, `prompt`, `assist`), in a bhf built with the `llm` feature; see [below](#optional-llm-and-agent-assistance) |

`bhf auto` and `bhf list targets` find targets in all sixteen supported
languages. `bhf scan` and `bhf generate-harness` take Ada, C and C++ sources,
as do the `llm` harness task and the MCP harness preflight.

`bhf rules list` prints the rule catalog, one rule per line, and
`bhf rules show <RULE>` prints one rule's definition, with its CWE, CERT and
MISRA mappings (`bhf rules show BHF-201`). `bhf list oracles` prints the
bug-oracle inventory.

### Text from the target

bhf prints text a target controls (its sanitizer report, an exception
message, its own output, and the fuzz input quoted in them) with control
characters written as escapes: `\x1b`, `\x07`, `\u{9b}`, and `\u{202e}` for a
bidirectional override. Tab is kept, and a block of output, such as a
harness's own output, keeps its line breaks. An escape sequence in a finding
therefore cannot retitle or clear your terminal. The JSON outputs and the
files in the work dir keep the original text.

## Common Flow

The manual pipeline for one Ada subprogram, run from the directory that holds
`path/to/pkg.adb` and its spec `path/to/pkg.ads`, with GNAT and GPRbuild on
`PATH`:

```sh
bhf list targets path/to/pkg.adb --top 20
bhf instrument path/to/pkg.adb --output bhf_work/src_instrumented
bhf generate-harness bhf_work/src_instrumented/pkg.adb --target Pkg.Parse --id H-PKG-PARSE --output bhf_work/generated_harnesses
bhf build bhf_work --harness H-PKG-PARSE
bhf fuzz bhf_work --harness H-PKG-PARSE --iterations 1000 --seed-input smoke
bhf replay --finding bhf_work/results/findings/<finding-id>
bhf minimize --finding bhf_work/results/findings/<finding-id>
bhf report --findings bhf_work/results/findings --out bhf_work/reports
```

`bhf instrument` copies the package spec beside the instrumented body, which
the build needs. `--id` names the harness the later steps use; without it,
`generate-harness` derives one from the file and target, the id `bhf list
targets` prints. `<finding-id>` is the directory `bhf fuzz` writes under
`bhf_work/results/findings/` (`bhf_work/results/INDEX.md` lists it), and
`--finding <finding-id>` alone finds it in `./bhf_work`. Without `--harness`,
`bhf replay` and `bhf minimize` run the harness the finding records, here
`bhf_work/build/H-PKG-PARSE/obj/main`. A `--finding` that names no finding is
refused with the path bhf looked at, before anything runs.

Other entry points, on a source tree and on a binary:

```sh
bhf scan path/to/src --work-dir bhf_work
bhf static-scan path/to/src --out bhf_work/static --sarif
bhf introspect path/to/src --work-dir bhf_work
bhf binary scan path/to/bin-or-firmware --out bhf_work/binary
bhf --profile external-tools binary adapter path/to/bin --adapter rizin --out bhf_work/binary-adapter
bhf binary fuzz path/to/bin --work-dir bhf_work --input-mode stdin --seed-input smoke
bhf binary rehost path/to/firmware.elf --work-dir bhf_work --input-buffer rx_buf --inject-at main
bhf clean bhf_work --build --corpus --reports
```

The adapter line needs `rizin` on `PATH`; without it, it exits `1` and says
so. It writes the binary's functions, call edges, strings and xrefs.

Replaying and minimizing a finding are described in [Replaying a
finding](#replaying-a-finding) and [Minimizing a
finding](#minimizing-a-finding).

## Auto

`bhf auto <PATH>` sweeps a source tree in any of the sixteen supported
languages (Ada, C, C++, Rust, Java, Python, Perl, Go, COBOL, Fortran, C#,
JavaScript, TypeScript, Ruby, Lua and PHP), including C and C++ headers that
hold definitions. It generates one harness per fuzzable function, stubs
missing headers and undefined symbols until the code builds, and runs a
three-pass fuzz cascade (empty, rng, fuzz-driven) on each built harness. On
Linux it loads the runtime virtualisation shim into each harness except
those of the Java, C#, JavaScript and TypeScript lanes and cross-compiled or
emulated targets. It also sweeps a partial tree that does not build as it is.

Findings go to `<work>/results/`: start with `results/INDEX.md`, use
`results/findings.csv` or `findings.json` as the machine-readable index, and
open `results/findings/` for each finding's evidence. `auto/summary.txt`
lists the targets that built, fuzzed or were skipped; campaign mechanics,
coverage, and the `needed_for_build` ledger are in `<work>/auto/run.md` and
`run.json`.

```sh
bhf auto path/to/src --work-dir bhf_work --per-target-time 60
```

Keep the work directory outside the source tree. The main flags follow;
`bhf auto --help` lists every one.

- `--work-dir <DIR>` — output root. Default `bhf_work`.
- `--config <PATH>` — load run options from a TOML file; command-line flags override it. Without it, a `.bhf.toml` at the root of the scanned tree is loaded, and only its keys that run nothing are honoured. `bhf auto --help` lists the keys.
- `--max-work-dir-mb <MiB>` — stop starting new targets when the allocated work-directory size reaches this ceiling. Default `4096`; `0` disables it. Findings are kept, and targets already running in parallel may finish past the ceiling.
- `--max-corpus-mb <MiB>` — the retained corpus per target, in memory and on disk. Default `64`. Finding testcases are kept separately and are not counted.
- `--per-target-time <SECS>` — the total fuzz time per target, split evenly across the passes under one shared deadline, so a target fuzzes for about this long whatever the number of passes. Default `60`, as libFuzzer's `-max_total_time` and AFL++'s `-V`. When more than one engine runs for a target (see `--engine`), the time is split evenly across the engines too.
- `--engine <builtin[,afl++][,winafl]>` — the fuzz engines for each target, comma-separated. `builtin` (default) is bhf's in-process coverage-guided engine. `afl++` drives AFL++ on the build `auto` recovered: `auto` runs `make afl` for the AFL-instrumented `main_afl` and `make afl_cmplog` for its CmpLog build `main_afl_cmplog`, then `afl-fuzz -c main_afl_cmplog -l 2AT`; its crashes go through the same findings pipeline, and `run.json` attributes the pass to `afl++`. `--engine builtin,afl++` runs both on each target and splits `--per-target-time` evenly between them. AFL++ applies to native C/C++, COBOL, Fortran, Rust and Ada targets: the COBOL and Fortran lanes' C glue builds with afl-clang-fast, linked the way the lane links `main` (`lane-ldflags.txt` in the harness directory), and AFL++ sees gfortran's trace-pc edges through its own guard table; a Rust harness's `build-afl.sh` rebuilds its crate with bhf's instrumentation and links the staticlib with afl-clang-fast, as cargo-afl does; an Ada harness's objects are linked again with AFL++'s runtime (`afl-compiler-rt.o`, found in `AFL_PATH` or beside `afl-fuzz`) into `build/<id>/main_afl`, its trace-pc edges forwarded into AFL++'s map, and an exception that escapes the target aborts it (`BHF_CRASH_ON_FINDING`), so AFL++ saves it; each crash is replayed with the event log and reported as the builtin engine reports it. bhf does not use AFL++'s GCC plugin, which loads only into the GCC point release it was built for. Other lanes and cross-compiled targets fall back to the builtin engine, and so does a run without `afl-fuzz` and `afl-clang-fast` on `PATH`, with one warning. Since `auto` recovers the build first, `--engine afl++` here needs no separate build step and works on a tree that does not build as it is. `winafl` (native Windows; refused on other hosts before anything is built) runs `make winafl` to build `main_winafl.exe`, the target's sources without sanitizers, and fuzzes it with WinAFL; the crashes and hangs WinAFL saves are replayed through the sanitized `main.exe`, and `run.json` attributes the pass to `winafl`. A missing WinAFL or DynamoRIO, an ARM64 target (`--vs-arch arm64`, or an ARM64 machine's default), or `--winafl-page-heap` in a shell that is not elevated exits `2` before anything is built. `--winafl-path`, `--dynamorio-path` (config keys `winafl-path` and `dynamorio-path`, read from an explicit `--config` only), `--winafl-instrumentation`, `--winafl-iterations`, `--winafl-coverage-module` and `--winafl-page-heap` work as on `bhf fuzz`, and `--rss-limit-mb` becomes WinAFL's `-m`; see [Windows](windows.md#winafl-engine).
- `--per-target-finding-count <N>` — stop a target's cascade once it has produced N distinct findings (crash signatures), or when `--per-target-time` is spent, whichever comes first. It is checked during a pass, so the target stops as the Nth finding lands and its remaining passes are skipped. `1` stops at the first finding, as libFuzzer does by default. Unset by default: every finding is collected.
- `--total-time <SECS>` — a deprecated alias of `--per-target-time`, hidden from `--help`; it overrides `--per-target-time` when set.
- `--iterations <N>` — a cap on executions per pass (libFuzzer `-runs`). Unset, or `0`, lets `--per-target-time` decide how deep each pass goes.
- `--timeout <DURATION>` / `--deadline <DURATION>` — the per-execution timeout and the response deadline (timing oracle) for every fuzzed target, as on `bhf fuzz`. An input that hangs again at twice the timeout is a hang finding (BHF-230), and one that takes longer than the deadline in two of three fresh re-runs is a response-deadline finding (BHF-555). The deadline must be shorter than the timeout (exit 2). `run.md` and `run.json` count each target's hangs.
- `--rss-limit-mb <MB>` — the resident-memory cap of each harness. A test case over it is killed and reported as a BHF-209 out-of-memory finding instead of exhausting the host's memory (libFuzzer `-rss_limit_mb`). The default is a quarter of the available host or cgroup memory, clamped to 512..8192 MiB; pass an exact value, or `0` to disable it. The finding records the limit (`rss_limit_mb`), and `bhf replay` and `bhf minimize` run its testcase under it, so the replay reproduces the out-of-memory kill (MATCH) without taking the host's memory; a BHF-209 finding recorded without it replays under the default.
- `--max-targets <N>` — stop once N targets have reached the fuzz phase. Candidates are attempted in rank order; a target with unsupported parameters or a failed build does not count, so lower-ranked viable targets take its place. The sweep stops at the cap, at the `--campaign-time` deadline, or when the candidates run out. Unset by default: every viable target is fuzzed.
- `--max-attempts <N>` — a cap on the ranked candidates inspected (built or attempted), however many of them fuzz. `--dry-run` shows the top N. Unset by default.
- `--campaign-time <SECS>` — a budget for the whole sweep, charged from the first build attempt, so discovery and preflight on a large tree do not use it up. By default it is an outer wall-clock cap: once it is spent, `auto` starts no new target (the one in flight finishes) and reports how many of the discovered targets it reached. With `--min-target-time` it is split across targets instead (next item). Unset by default.
- `--min-target-time <SECS>` — split mode, with `--campaign-time` only (an error otherwise): the campaign budget is divided across the N attempted targets, each getting `max(min, campaign / N)` of fuzz time, and only the top `floor(campaign / per_target)` ranked targets are attempted; the rest are logged as not fuzzed. No target gets less than this floor. It overrides `--per-target-time`. Unset by default.
- `--jobs <N>` / `-j <N>` — build and fuzz up to N targets at once. `jobs × --rss-limit-mb` covers the harness processes; leave memory as well for bhf's own declaration index and results, the compilers, and the OS. Results are aggregated in the same order whatever order the targets finish in. Default `1`.
- `--workers-per-target <N>` — run each target's builtin passes on N cores: each pass is a campaign of N `bhf fuzz` workers that share the corpus entries they keep, merged into the target's when the pass ends. With `--jobs J` that is up to J × N fuzz processes, each with `--rss-limit-mb`. Default `1`.
- `--passes <SET>` — run a comma-separated subset of the passes (`empty`, `rng`, `fuzz`); `--passes fuzz` runs the fuzz-driven pass alone, which then gets the whole `--per-target-time` instead of a third of it. Cannot be combined with `--single-pass`. Default: all passes.
- `--single-pass` — the same as `--passes fuzz`.
- `--max-repair-rounds <N>` — a cap on build-fail, repair, retry rounds per target. Default `16`. A round runs only when the one before applied a new repair, so this is a ceiling, not a fixed cost; a low value (2 or 3) gives up on unbuildable targets quickly in a triage sweep of a large tree.
- The discovery cache is on by default. A re-run reuses the earlier discovery from `<work>/discovery-cache.json` when a content fingerprint of the target source (file paths, sizes and content hashes, and the directory filter) is unchanged, and skips the tree-sitter parse and the ranking. The fingerprint depends only on the fuzzed code, so a rebuilt bhf still uses the cache. A mismatch runs discovery again and rewrites the cache. `--discovery-cache <PATH>` names another cache file.
- `--fresh-discovery` — run discovery afresh this time, ignoring the cache, and overwrite the cache.
- `--no-discovery-cache` — neither read nor write the discovery cache.
- `--resume` — resume an earlier sweep of the same work dir: each target writes `harnesses/<id>/result.json` as it finishes, so an interrupted run is resumable. The targets that completed are reloaded into the new report (outcome buckets, repair manifest, findings, pass detail), counted as `resumed`, and the rest are run. Results are reused while the build context is unchanged, per source file: a target whose own file changed runs again. With `--no-discovery-cache` bhf records no source files, so a target whose file changed is reused too.
- `--reuse-discovery` — deprecated; it does nothing, since caching is the default.
- `--sanitizers <LIST|none>` — the native C/C++ sanitizer matrix of the auto build: `asan`, `ubsan` and `lsan`, which combine; `msan` or `tsan`, each alone; `hwasan` in place of `asan` on an AArch64 host; and `cfi`, which adds a control-flow integrity replay of each harness's corpus (`make cfi`) after the fuzz passes. `none` builds with coverage and no sanitizer, for crash-only fuzzing. The other lanes own their instrumentation.
- `--languages <LIST>` (alias `--lang`) — sweep only these of the sixteen languages, comma-separated: `ada`, `c`, `cpp`, `rust`, `java`, `python`, `perl`, `go`, `cobol`, `fortran`, `csharp`, `javascript`, `typescript`, `ruby`, `lua`, `php`. Candidates in other languages are dropped after discovery and before `--list-targets` and `--max-targets`, so the ranked list and the top N reflect the filter. Common spellings are accepted (`c++`, `cxx` and `cc` for cpp, `rs` for rust, `py` for python, `pl` for perl, `golang` for go), in any case. Unset: every language found. The SBOM pass always covers the whole tree.
- `--target <NAME>` — attempt only targets with this name: the full discovered name, the bare name, or a qualified suffix such as `Class::method`, optionally with the parameter list. An exact spelling wins: the suffix match applies only when no target has exactly that name. Repeat it for a small named set. A name that selects nothing prints the closest discovered names. A project fuzz driver (`LLVMFuzzerTestOneInput`) is skipped when the tree has other targets, unless `--target`, `--target-file` or `--harness-id` selects it.
- `--target-file <PATH>` — attempt only targets in this source file, given as an absolute path or relative to the sweep root.
- `--harness-id <ID>` — attempt only the target with this stable harness id, from an earlier report or `bhf list targets`.
- `--exclude-path <TEXT>` — drop targets whose normalized relative source path contains `TEXT`. Repeatable.
- `--exclude <tests,tools,examples>` — drop these common project areas before any attempt.
- `--exclude-dir <NAME>` / `--include-dir <NAME>` — skip more directory names in discovery, or keep a directory a built-in default skips (tests, examples, benchmarks, vendored dependencies, docs). Repeatable.
- `--no-stubs` — skip auto-stubbing, for diagnostics.
- `--mode reporting|attacking` — the [actionability profile](#actionability-modes) and, in attacking mode, the target order.
- `--seed-file <PATH>` / `--seed-dir <DIR>` — seed bytes for every target's corpus, such as a real `.zip`, `.bz2` or sample document, so parsers reach deep code. Used byte for byte. Repeatable. Without them, auto mines seeds from the tree's own test data.
- `--no-seed-mining` — do not mine seeds from the tree's test data (config key `seed-mining = false`). Every run lists the seeds it used in `auto/seeds.json`; `-v` prints them.
- `--extra-include <DIR>` — extra C/C++ include directories for dependency headers outside the swept tree, such as cFE OSAL/PSP or a vendored SDK's `include/`. Read from local disk. Repeatable.
- `--max-decode-depth <N>` — C decoder synthesis: the deepest recursion into nested struct, union and array decoders; past it a field is left zeroed. Default `4`.
- `--max-array-elems <N>` — C decoder synthesis: the most elements decoded per fixed array; a larger array fuzzes its fill count `0..cap` instead of every slot. Default `64`.
- `--max-decl-bytes <BYTES>` — C decoder synthesis: the largest decoder body for one parameter; a larger body rejects the parameter. Default `65536`. C++ has `--container-size-max`, `--bitset-max-size` and `--array-max-size`.
- `--ada-deps <DIR>` — local Ada dependency source directories to put on the build path (read offline, never fetched). Repeatable. Alire dependencies cached locally are found without it.
- `--comparison-progress` (alias `--cmp-progress`) — laf-intel comparison-progress coverage for multi-byte magic and format gates: the engine rewards an input that matches more leading bytes of a comparison. Off by default.
- `--probe-build` — run the project's own build once, offline, before harnessing (a CMake configure, or `make` under a compiler-interposing wrapper), under `<work>/probe/`, to recover real compile flags and generated headers. It runs the project's build scripts, inside bhf's sandbox when bwrap or firejail is present. Off by default.
- `--run-untrusted` — consent to run the project's own build and code generation: `--probe-build`, an Ada build probe (`alr build` / `gprbuild`), and the Maven, Gradle, Cargo and MSBuild project builds of the Java, Rust and C# lanes. It implies `--probe-build`. Off by default.
- `--build-command <CMD>` — recover flags from a custom build (a `build.sh`, Bazel, SCons, Waf, a vendor RTOS build) by running `<CMD>` under a compiler-interposing shim, for a build `--probe-build` does not detect (it detects CMake, Meson, Make, Ninja and Visual Studio). It runs the command, in the sandbox when one is available.
- `--unsafe-search-and-run-build-commands` — search the tree for its own build entry point (build.sh, autotools, SCons, Waf, Bazel) and run it under the shim, with the `--probe-build` tiers and the Ada build probe. It runs code from the scanned tree; use it on trusted sources only.
- `--deps-only` — build each target as far as possible, stubbing what is missing, and write the missing-dependency manifest (`<work>/auto/missing-deps.txt`), without fuzzing.
- `--install-deps` — after the sweep, fetch the dependencies that still block a build (apt-get for known headers and libraries, `alr get` for Ada units). It is opt-in and the one part of `auto` that uses the network.
- `--msbuild-solution <PATH>` / `--msbuild-config <CONFIG|PLATFORM>` / `--no-msbuild-import` — the Visual Studio project import, on by default for a tree with a solution or project and no compile database or CMake/Meson build (off Windows, only when the solution is the tree's only build description): which solution it reads (relative to the scanned tree; a missing file is an error), which configuration, or no import. The import runs nothing; see [C and C++ fuzzing](c-cpp.md).
- `--msbuild-evaluate` — let an installed MSBuild evaluate the imported projects instead of bhf's static reading. It runs their property functions and imported `.props`/`.targets` files, which is code from the scanned tree, so it is opt-in; `--probe-build` implies it.
- `--no-vs-env` / `--vs-arch <ARCH>` (global, Windows; listed in `--help` on Windows) — turn off Visual Studio and Windows SDK discovery, or pick its target architecture; see [Windows](windows.md).
- `--static` — run the static analyzer over the whole tree as well as fuzzing it. Its findings (`static_scan`, ids `F-STATIC-*`) join the fuzz findings in the report. It is the engine of `bhf static-scan`.
- `--sbom` — write an SBOM and VEX bundle at the end of the campaign, into `<work-dir>/sbom/`, marking the components a harness drove as exercised.
- `--force` (alias `--force-fuzz`) — force-fuzz mode: a second phase over the targets the normal run could not fuzz, so it never lowers the fuzzed count. It attempts a target even when a parameter type cannot be driven or a type or symbol is undefined: C, C++ and Ada fabricate the parameter and stub the missing symbol; Go drives the parameter as its type's zero value and calls a method on a zero receiver; C# allocates a receiver whose type has no accessible parameterless constructor without running a constructor. Findings from a forced build are stamped low-confidence with a note, since a fabricated value can crash on its own account.
- `--differential <A:B>` — two-compiler differential fuzzing for C/C++ (for example `clang:gcc`): after the run, rebuild each C/C++ harness with both compilers, replay the corpus through both, and report each input whose exit or crash behaviour differs as a BHF-301 finding.
- `--no-minimize` — skip the minimization after fuzzing. By default `auto` minimizes the representative finding of each root-cause group into `min_testcase.bin`, at most 30 s per group and 5 min in total; `results/INDEX.md` lists the groups the budget did not reach.
- `--list-targets` — print the ranked targets, with file:line, language and input reachability, and exit without building anything.
- `--dry-run` — discover and rank targets, run the toolchain preflight, print the build-recovery plan, and exit without building or fuzzing.
- `--list-fakes` — print the fake-resource plugin inventory and exit.
- `--verbose` / `-v` — print an extra indented line per target: why it was skipped or failed, the repairs applied, and each pass's execution and finding counts.

Exit codes: `0` at least one target built and ran (a target that built but
ran no input, a report-only target or a finding also gives `0`); `1`
discovery found candidates but none built and ran (each failed to build, was
skipped, or was built but not entered), or `auto` stopped on an error; `2`
no candidates were discovered (a source path that does not exist included),
the toolchain configuration was refused, as for `bhf build`, or bhf hit an
internal panic; `3` harnesses built, but none ran, because their sanitizer
runtime does not start on this host (re-run with `--sanitizers none`).
[Exit Codes](auto.md#exit-codes) in the Auto guide has the same list as a
table.

A refused toolchain configuration is a compiler, runner or Ada tool that is
not installed, a target with no runner to run it, a runner with nothing
foreign to run, a probe backend a host sweep cannot read, a config file that
cannot be read or parsed (an unknown key included) or that holds an invalid
value (`max-corpus-mb = 0`, an unknown `languages` entry), or an unusable
`[cross.*]` table.

The runtime audit and the shim's faking modes run on Linux. On other hosts
`bhf auto` runs the build-time sweep and prints a one-line notice that the
runtime audit is off.

See [Auto](auto.md) for the whole pipeline and [Runtime
virtualisation](runtime-virtualisation.md) for the LD_PRELOAD shim, the
three-pass cascade and the replay environment variables.

## Listing Targets

`bhf list targets <PATH>` ranks the fuzzable functions of a source tree and
prints them as a table, or as JSON with `--format json` (`--top`, default
20). Each candidate has a stable `harness_id`, the id `bhf auto` uses for the
same tree however the root is spelled (`src/p1`, its absolute path, or `.`
from inside it). Pass it to `bhf auto --harness-id <ID>` to rerun one target
when names collide across files.

`bhf list targets` takes the same `--target`, `--harness-id` and
`--target-file` selections as `bhf auto`. In both commands a selection that
matches nothing prints `--harness-id '<ID>' matched no target; closest: ...`
(and the same for the other two), and when nothing is left the command exits
2, `bhf auto --dry-run` and `--list-targets` included. `--changed-since
<GIT_REF>` keeps the targets in files changed between that ref and `HEAD`.

## Generating and Building a Harness

`bhf generate-harness <SOURCE> --target <NAME>` writes the harness for one
function of a C, C++ or Ada source. A source in another language `bhf auto`
fuzzes (Python, Ruby, Go, Java, Rust and the rest) is refused with its
language named; run `bhf auto <dir> --target <function>` to build that
harness instead. `--id` names the harness; without it, bhf derives a stable
id from the source path and the target.

- For C and C++, `--target` is required. For C++ it accepts the bare name, a
  `::`-qualified suffix (`Parser::parse`), the fully qualified name as
  `bhf list targets` prints it, or any of those with a parameter list. An
  exact spelling wins over a suffix, a leading `::` names the global
  namespace only, and a miss lists the closest definitions. `--target-line`
  picks one of several matching definitions.
- For Ada, `--target` takes the bare name (`Parse`) or the package-qualified
  one (`Pkg.Parse`); without it, bhf harnesses the highest-ranked target.
  When the target body depends on parent package specs outside its
  directory, pass each extra source root with `--source-root`:

```sh
bhf generate-harness src/base/dates/util-dates-iso8601.adb --target Value --source-root src/core --source-root src/base/dates
```

A C or C++ target that needs more translation units, more include
directories, or cleanup of its return value takes `--extra-source`,
`--extra-include` and `--cleanup` on `bhf generate-harness`. See [C and C++
fuzzing](c-cpp.md) for the parameter shapes bhf decodes and their limits,
and [Custom C and C++ harnesses](custom-harness.md) for writing your own
harness.

The generated C/C++ harness is Makefile-based, so `bhf build` runs `make` and
stages `build/<harness-id>/main`:

```sh
bhf generate-harness src/parser.cpp --target Parser::parse --id H-CPP000A --output bhf_work/harnesses
bhf build bhf_work --harness H-CPP000A
bhf fuzz bhf_work --harness H-CPP000A --iterations 1000 --seed-input smoke
```

`bhf build` takes the work directory; it also accepts a harness directory,
`bhf_work/harnesses/<id>`, and says so. `--harness` picks the harness and
defaults to the only one present. When the lookup fails, bhf names the
harness ids it found. When the link fails, it names the in-tree sources that
define the missing symbols, with the `--extra-source` flags and an
`AUTO_EXTRA_SOURCES` command that add them. When C++ sources use standard
library names without `std::` (`string`, `map`, `list`), it writes a prelude
header with `using std::` declarations into the harness directory and prints
the `AUTO_EXTRA_INCLUDES='-include <prelude>'` command.

`bhf build` takes the toolchain from `--cc`/`--cxx`, `--target <triple>` (or
`--toolchain <prefix>`, for `<prefix>-gcc`/`<prefix>-g++`), `--sysroot`,
`--cflags`, `--cxxflags`, `--ldflags`, `--define`, `--toolchain-include` and
`--no-fuzzing-build-mode` (see [C and C++ fuzzing](c-cpp.md)), or from the
`[toolchain]` table of `--config <file>`, the table `bhf auto --config`
reads. In that table the compilers come from `target` or `cc`/`cxx`, since
`toolchain.ada.prefix` applies to Ada harnesses only. bhf appends the flags
to its own coverage and sanitizer flags and prints the compilers it uses.
`--runtime`, `--probe-backend` and the `--ada-*` flags apply to Ada harnesses
and are refused for a C/C++ harness. See
[Cross-compilation](cross-compilation.md).

```sh
bhf build bhf_work --harness H-CPP000A --target aarch64-linux-gnu
bhf build bhf_work --harness H-CPP000A --cxx g++ --define BOARD=3
```

### Builds for other engines

`bhf build --c-engine` picks the Makefile target of a C/C++ harness:
`libfuzzer` (the default; `make`, which builds `main`), `afl++` (`make afl`,
the persistent-mode AFL++ build) or `winafl` (`make winafl`, the WinAFL build
without sanitizers, on native Windows).

For AFL++ on a generated C/C++ harness:

```sh
bhf build bhf_work --harness H-CPP000A --c-engine afl++
bhf fuzz bhf_work --harness H-CPP000A --engine afl++ --time 30s --seed-input smoke
```

For WinAFL on native Windows, build the sanitized `main.exe` (which replays
what WinAFL saves) and `main_winafl.exe` (which WinAFL fuzzes):

```sh
bhf build bhf_work --harness H-CPP000A
bhf build bhf_work --harness H-CPP000A --c-engine winafl
bhf fuzz bhf_work --harness H-CPP000A --engine winafl --time 60s
```

To add coverage inside a stripped, source-less library the harness loads, run
AFL++ in QEMU (or Frida) binary-only mode and scope instrumentation to that
module, so the campaign sees edges in the dependency as well as in the
harness:

```sh
bhf build bhf_work --harness H-CPP000A --c-engine afl++
bhf fuzz bhf_work --harness H-CPP000A --engine afl++ \
  --afl-mode qemu --afl-inst-range libtarget.so --time 30s --seed-input smoke
```

## Fuzzing a Harness

`bhf fuzz <WORK_DIR> --harness <ID>` fuzzes the harness built under
`<WORK_DIR>/build/<ID>/`, with the built-in coverage-guided engine unless
`--engine` names another (see [Engines](#engines)). Seeds come from
`--seed-input` (a literal; its UTF-8 bytes), `--seed-file` (used byte for
byte, so binary seeds go here) and `--symbolic-seed-source` (an Ada file whose
guarded string literals are mined into prototype seeds). A C/C++ harness
that decodes fixed-width parameters before its buffer also gets each
`--seed-input` and `--seed-file` seed behind that many zero bytes (from its
`arg-layout.json`), so the buffer starts with the seed; a `--workers`
campaign makes these once, and its workers add none.

The run writes corpus entries under `<WORK_DIR>/corpus/` (with the harness
input format in `corpus/<ID>/metadata.json`), findings under
`<WORK_DIR>/results/findings/`, and the latest run metadata in
`<WORK_DIR>/fuzz_runs/<ID>-latest.json`. Run summaries and finding records
include `sandbox` metadata, so reports tell sandboxed and unsandboxed
executions apart.

A crash whose root cause is already recorded for the harness (a finding under
`results/findings/` from an earlier run) is not recorded again. The summary
lists those findings under `duplicates_of_existing`, counts the matching
executions in `duplicate_crashes_of_existing`, and stderr gets a one-line note,
so a run whose crashes were all known does not read as clean.

The `bhf fuzz` flags, several of them named after their libFuzzer
equivalents:

- `--engine <builtin|afl++|libfuzzer|honggfuzz|libafl|winafl>` — engine to run. Default `builtin`. `libfuzzer` runs the harness's `main_libfuzzer`, `honggfuzz` honggfuzz on its `main_honggfuzz`, and `libafl` a LibAFL campaign on its `main` in a bhf built with the `libafl-engine` feature (see [Engines](#engines)). `winafl` (native Windows; refused elsewhere) runs WinAFL on `main_winafl.exe` beside the sanitized `main.exe` and replays the crashes and hangs it saves through `main` for the report; see [WinAFL on Windows](windows.md#winafl-engine). `--target-transport` and `--protocol-profile` run the builtin engine's own loops and take no other engine (exit `3`). A `winafl` run stopped by Ctrl-C ends without replaying what WinAFL saved and prints where it is; the next `winafl` run of that harness in the same work dir replays it. With `winafl`, a host other than native Windows also exits `3`; a missing or unusable WinAFL or DynamoRIO, a refused `--winafl-coverage-module` or an ARM64 harness exits `1`, as a missing `afl-fuzz` does.
- `--winafl-path <DIR>` — WinAFL directory for `--engine winafl`: the one holding `afl-fuzz.exe` and `winafl.dll`, or a WinAFL checkout with `build64\bin\Release`. Default: `BHF_WINAFL_PATH`, then `afl-fuzz.exe` on `PATH`.
- `--dynamorio-path <DIR>` — DynamoRIO install root, or its `bin64` directory, for `--engine winafl`. Default: `BHF_DYNAMORIO_PATH`, then `DYNAMORIO_HOME`, then `drrun.exe` on `PATH`.
- `--winafl-instrumentation <dynamorio|intel-pt>` — WinAFL coverage: DynamoRIO (`afl-fuzz -D`, default) or Intel Processor Trace (`afl-fuzz -P`; needs an Intel CPU with PT and a WinAFL built with `-DINTELPT=1`, and runs in a VM only when the hypervisor passes PT through).
- `--winafl-iterations <N>` — WinAFL `-fuzz_iterations`: calls of the persistent entry before the harness process restarts. Default `5000`.
- `--winafl-coverage-module <MODULE>` — another module (a DLL of the target the harness loads) for WinAFL to measure coverage in, beside the harness executable. Repeatable. A name with a space or a quote is refused: WinAFL passes it to DynamoRIO unquoted.
- `--winafl-page-heap` — run the WinAFL build under full PageHeap, so a heap overflow or use after free faults at once and WinAFL saves it as a crash. WinAFL fuzzes a copy of `main_winafl.exe` under a name only this run uses (`main_winafl-<pid>-<n>-<stamp>.exe`), bhf sets the PageHeap Image File Execution Options key for that name, prints it, and removes key and copy when the run ends, and on Ctrl-C, Ctrl-Break or a closed console after stopping the target. A run killed outright is cleaned up by the next WinAFL run in that harness directory, or by `make clean` there; bhf deletes only copies its marker file (`<copy>.bhf-run`) proves it made. Needs an elevated shell, and is refused up front without one (exit `3`).
- `--afl-mode <native|qemu|frida>` — AFL++ execution mode for `--engine afl++`. `native` (default) uses compile-time instrumentation; `qemu` (`afl-fuzz -Q`) and `frida` (`afl-fuzz -O`) add coverage inside a stripped, source-less dependency the harness loads, without rebuilding it. Ignored by the builtin engine.
- `--afl-path <DIR>` — AFL++ install directory. Sets `AFL_PATH` and locates `afl-fuzz`, so QEMU/Frida mode finds `afl-qemu-trace` / `afl-frida-trace.so` from a build that is not on `PATH`.
- `--afl-inst-range <RANGE>` — scope binary-only instrumentation to a module or address range (e.g. `target.so` or `0x555000-0x556000`). Repeatable; joined into `AFL_QEMU_INST_RANGES` (`--afl-mode qemu`) or `AFL_FRIDA_INST_RANGES` (`--afl-mode frida`). Requires a binary-only `--afl-mode`.
- `--iterations <N>` — execution cap. Defaults to `256` when neither this nor `--time` is set; with `--time` set and this omitted, the run is bounded only by the time budget.
- `--time <DURATION>` — whole-campaign wall-clock budget (e.g. `30s`, `5m`, `1h`). A builtin fork-server pass ends inside it: near the end it stops issuing inputs so its background fresh-process re-runs can finish, and stops a re-run still going at the deadline (see [Sanitizers](./sanitizers.md)).
- `--max-len <BYTES>` — maximum generated input length (libFuzzer `-max_len`). Default `4096`. With adaptive length control on this is the ceiling.
- `--len-control <N>` — adaptive length control (libFuzzer `-len_control`): executions without a new corpus signature before the effective length doubles toward `--max-len`. Default `100`; `0` disables it.
- `--timeout <DURATION>` — per-input timeout (libFuzzer `-timeout`): a single C/C++ harness execution longer than this is killed, and an input that hangs again when re-run with twice the timeout is a hang finding (BHF-230; see [Sanitizers: Hangs](./sanitizers.md#hangs)). It is not `--time`, the campaign budget. Default `10s`. The Ada lane bounds a runaway input with CPU rlimits instead. A duration (`--timeout`, `--time`, `--deadline`) is a number with `ms`, `s`, `m` or `h`, seconds when bare, and may be fractional: `500ms`, `0.5s`, `10s`, `1.5m`.
- `--deadline <DURATION>` — a real-time response deadline, the timing oracle (off by default). An input whose wall-clock execution exceeds the deadline, and exceeds it again in at least two of three fresh re-runs, is a finding (BHF-555, a CWE-400 timing and availability failure); the finding's `deadline_confirmation` records each re-run's time. Use it for watchdog, RTOS and radar targets, where overrunning a time budget is itself a fault. A duration (`250ms`, `0.5s`, `1s`); `BHF_DEADLINE_MS` sets it from the environment. See [On-Target & Embedded](./on-target-fuzzing.md).
- `--rss-limit-mb <MB>` — per-execution resident-memory ceiling for a C/C++ harness (libFuzzer `-rss_limit_mb`); an execution over budget is killed and reported as an OOM finding. `0` (default) disables it. With `--engine winafl` it also becomes WinAFL's `-m`, the committed-memory cap of drrun and the target: the limit plus 1024 MiB for DynamoRIO, or `-m none` for `0`. For an x86 harness it is `-m none` when that cap is not below what the 32-bit process can address (2 GiB, or 4 GiB when large-address aware).
- `--print-final-stats` — print a final-stats line (libFuzzer `-print_final_stats`): executions, exec/s, new vs duplicate corpus signatures, findings, elapsed time.
- `--quiet` (`-q`) — print no progress lines. Without it the builtin engine prints a status line on stderr 2s into the run, then at doubling intervals up to every 30s: `bhf: fuzz: 8123 execs (4061/s) | corpus: 12 | findings: 0 | edges: 214 | elapsed: 2.0s`, with `| stability: N%` before the elapsed time once stability calibration has measured it. Workers of `--workers` run quiet.
- Crashes in the loop are not symbolized: the builtin engine runs its own executions with `symbolize=0:abort_on_error=0` appended to the sanitizer options, tells crashes apart by their rule, kind and top five unsymbolized frames (`module+offset`), counts a crash whose signature was reported against that finding, and re-runs a new one in a fresh process with the symbolized options replays use, whose report becomes the finding. Symbolizing each crashing execution and aborting it through the kernel's core pattern costs most of a second per crash, which would hold a target whose inputs mostly crash to a few executions a second. `BHF_IN_LOOP_SYMBOLIZE=1` symbolizes in the loop.
- `BHF_LIVE_CORPUS_DIR=<dir>` — the builtin engine also writes each input it keeps into `<dir>` as it keeps it, named `<sha256>.bin` as the queue names it, so a tool watching a campaign sees the corpus grow, for coverage over time. The queue itself is written when the pass ends, after its re-run checks, without the inputs they rejected; the live dir keeps those too.
- `BHF_SYMCC=1` — what `bhf auto --symcc` sets: when the harness has a `main_symcc` beside it (`make symcc`, see [C/C++](c-cpp.md)) and the license profile permits SymCC, the builtin engine runs a solver loop. Once the pool has not grown for `BHF_SYMCC_PLATEAU_MS` (default 5000), its newest entries SymCC has not run (`BHF_SYMCC_ENTRIES` per round, default 8) run through `main_symcc`, each for at most `BHF_SYMCC_TIMEOUT_MS` (default 10000), under the harness's `--sandbox` (SymCC's build directory bound read-only, for its runtime library) and with `--rss-limit-mb` as its address-space limit (`RLIMIT_AS`; `main_symcc` has no sanitizer shadow), and each input SymCC writes that the pool does not have runs next, as a `--workers` peer's entry does. The run summary's `symcc` block counts the rounds, the entries SymCC ran and the inputs it gave, and `symcc-import.log` in the work dir lists each input with the entry it came from.
- `--workers <N|auto>` — run multiple fuzz workers. While they run, the workers share their corpus: every `BHF_SYNC_INTERVAL_MS` (10 s by default; their syncs are spread over the interval) each writes the entries its pool kept to `fuzz_campaigns/<harness>/sync/worker-<id>/<sha256>.bin` and runs the ones the others wrote that it has not seen, keeping those that add coverage. An entry is written once, by the first worker to write it, and each worker logs what it imported to `sync-import.log` in its work dir. When the campaign ends, their findings move into `<work-dir>/results/findings` under fresh ids, one per crash cluster; duplicates stay in the worker dirs while the finding they duplicate is in `results/findings`. Once that finding is removed (or `results/` is wiped), the next campaign drops them instead of merging them back. With `--engine afl++`, `--workers N` runs N afl-fuzz instances in one output directory: `-M main`, which runs CmpLog, and `-S sec1`..`-S secN-1`, which sync each other's queues at start and then every quarter of `--time` (1 to 30 minutes; `AFL_SYNC_TIME` overrides it). `auto` runs one per core. Each instance logs to `afl_out/<harness>/afl-fuzz-<instance>.log`; their crashes and hangs are harvested and their queues taken into the corpus, and the summary's `afl.instances` names them.
- `--fork-server` / `--no-fork-server` — persistent framed execution is the default for the builtin engine. Native drivers and the Java, Python, Perl, Go, C#, JavaScript/TypeScript, Ruby, Lua, and PHP launchers each keep one target runtime alive and feed it inputs over the same protocol. Every finding is confirmed by a replay in a fresh process, so a crash caused by state that earlier inputs left behind is not recorded, and every new corpus input is re-run once in a fresh process on a background thread before it is saved in the corpus queue (see [Sanitizers](./sanitizers.md)). `--no-fork-server` runs a fresh process per input; use it for a target that carries fuzz-relevant global state across calls by design. The persistent engine calibrates each input it would add to the corpus, as AFL++ does: it re-runs the input four times, each from a zeroed edge bitmap, and an edge one run hit and another did not is variable. An input whose runs differ is added only if every run hit an edge no calibrated input hit every time before; one whose only new coverage was variable edges is left out, and the re-runs' edges count as seen, so a state-dependent edge is not new coverage later. `stability` in `fuzz_runs/<harness>-latest.json` gives `stability_pct` (the share of the edges calibration saw that no run varied on), `variable_edges`, `calibrated_entries` and `unstable_entries_dropped`. Below 90% bhf prints a note that the harness keeps state between executions, with this flag as one remedy. A harness that speaks the framed protocol gets `--timeout`, but at least 10 s (never more than `--time`), to start its fork-server, so a slow start on a loaded machine does not drop the run to a fresh process per input; bhf prints a note if it still misses that. Any other harness gets a 2 s probe.
- `--differential-harness <PATH>` — differential fuzzing in the builtin engine's own loop: a second build of the harness (another compiler, other flags, another version of the target), also linked with bhf's driver, that every input the loop runs also runs through, on a fork-server of its own. The builds are compared on how each run ended (clean, rejected, crashed, hung) and on what it observed: the bytes the target hands `bhf_diff_observe(ptr, len)`, the target's return value in a generated harness, and `bhf_run_one`'s. The second build's persistent process runs every input the fuzzed build's runs, the CmpLog, colorization and calibration re-runs too, and both start over when either dies, so a target that keeps state from one input to the next holds the same state in both. An input they disagree on is re-run in a fresh process of each with twice `--timeout` (a build that is only slower than the timeout does not hang), and, when they disagree there, once more each: when each build repeats itself and they disagree again it is a BHF-301 `differential-output-runtime` finding, one per kind of disagreement, with a `differential` block (`mode: in_loop`, both builds, `divergence` `outcome` or `observation`, each build's `outcome_*` and `observation_*`, `report_*` for a build that crashed, whose report is the finding's `sanitizer.log`, and the re-runs' `timeout_ms`). A kind of disagreement the work dir already holds a finding of is listed in `duplicates_of_existing`, not recorded again. An input that grows either build's coverage is kept. The run summary's `differential` block counts the second build's executions and the `divergences` in the loop, each of them `confirmed`, `unconfirmed` (the builds agreed in fresh processes), `nondeterministic` (a build disagreed with itself) or `not_rerun` (its kind was recorded already, or four re-runs of it did not hold), and the `findings`. `bhf replay` of such a finding runs both builds and compares them (lane `differential`), and is `UNVERIFIED` (exit `4`) when the second build is gone. Builtin engine and one worker only: with another `--engine`, `--workers`, a sanitizer matrix, `--target-transport` or `--protocol-profile` it exits `2`, and a harness that does not speak bhf's framed protocol exits `3`. See [differential fuzzing](../differential-fuzzing.md).
- `--cmplog-log <PATH>` — replay a runtrace audit log captured with `BHF_CMPLOG=1`; recovered cmplog operands seed both the mutator dictionary and an offset-aware RedQueen-style splice that replaces `operand_a` with `operand_b` at the offset it appears in the current input.
- `--sanitizers <asan,msan,ubsan,tsan,lsan|none>` — the native C/C++ sanitizer campaign matrix, one worker per sanitizer (`hwasan` in place of `asan` on an AArch64 host). `none` builds with coverage and no `-fsanitize=`, for crash-only fuzzing. The other lanes own their instrumentation.
- `--target-transport <SPEC>` — run the loop against an off-host or on-target backend instead of a host harness. Spec forms: `agent:tcp:HOST:PORT`, `agent:serial:/dev/ttyX[,baud=N]` (a Windows port is `COM3`), `gdb:HOST:PORT[,done=ADDR][,fault=ADDR][,reset=restart|monitor:CMD]`, `qemu-system:qmp=…,gdb=…[,snapshot=TAG][,reset=loadvm|persistent|fast]` (`reset=persistent` continues the firmware's own input loop and restores the snapshot only after a crash, hang or inconclusive run; see [the persistent loop](on-target-fuzzing.md#persistent-loop); `reset=fast,dirty_log=PATH` resets the machine and writes back only the RAM pages the run wrote, which bhf's QEMU plugin logs, a crash included; see [the fast snapshot](on-target-fuzzing.md#fast-snapshot)), `renode:monitor=…,gdb=…[,snapshot=PATH]`. On-device agent, debug-probe/emulator gdbstub, or a full-system `qemu-system` or Renode snapshot (Renode's telnet monitor saves and loads the baseline with `Save`/`Load`; see [Renode boards](on-target-fuzzing.md#renode-boards)). With `--workers N`, the spec names each worker's target, `{worker}` its number (0 to N-1) and `{BASE+worker}` a port per worker (`agent:tcp:127.0.0.1:{9000+worker}`); the N workers share one corpus, coverage map and finding set, and `--iterations` and `--time` are the campaign's. A spec without either is refused with `--workers`, and so is a `reset=fast` spec whose workers would share one `dirty_log=` (put `{worker}` in it). See [On-Target & Embedded](./on-target-fuzzing.md).
- `--transport-coverage-map <SPEC>` — for the memory-read transports (`gdb`, `qemu-system`, `renode`), locate the on-target coverage ring: `input=<addr>,input_cap=<n>,ring=<addr>,write=<addr>,wrapped=<addr>,cap=<n>` (decimal or `0x`-hex), plus `input_len=<addr>` when the firmware reads the input's length from a `u32` there, and `cmplog=<addr>,cmplog_cap=<n>` to read the comparisons the firmware records for CmpLog ([CmpLog on the target](on-target-fuzzing.md#cmplog-on-the-target)). `input_cap`, the staging buffer's size, is required: `--max-len` is cut to it and no input is written past it (see [On-target fuzzing](on-target-fuzzing.md#coverage-map-spec)). The `agent` transport carries coverage over its protocol and rejects this. With `--session-transport transport:gdb:…` or `transport:qemu-system:…` it locates the same ring for the session lane.
- `--protocol-profile <PATH>` — load a versioned protocol profile (TOML, `bhf.protocol.v1`) and fuzz the target with response-dependent, multi-message sessions: the session lane, which needs `--session-transport`. See [Stateful protocol sessions](#stateful-protocol-sessions) below; `profiles/protocols/` holds [reference profiles](#reference-profiles) for Modbus/TCP and MQTT 3.1.1 over TCP and CoAP and RTPS/DDS over UDP, and a `kind = "giop"` profile sends [GIOP requests](#giop-profiles) to an IIOP endpoint.
- `--board-profile <PATH>` — take `--target-transport` and `--transport-coverage-map` from a board profile: a TOML file of one board's specs, `gdb` and `coverage_map` for its debug probe and `serial` for the agent on its UART (`docs/hil-boards/nucleo-f411re.toml` is the template). Every spec in it is checked when it is read, and either flag beside it is refused (exit `2`). `--board-lane <gdb|serial>` (default `gdb`) picks the lane. The bring-up is in [HIL bring-up](../hil-bringup.md).
- `--session-transport <SPEC>` — request/response backend for the session lane. `tcp:HOST:PORT` connects a socket per session. `udp:HOST:PORT` sends each message as one datagram, from a socket of its own per session (so the target sees a new source port), and waits for one reply datagram. `serial:PATH[,baud=N]` drives a UART or a pty, opened raw as the agent's `serial:` transport is (no echo, line editing or newline translation; 8N1, no flow control), at baud `N` when given; requests and replies are framed as the profile says, and `--session-reset reconnect` reopens the device while `none` keeps it open. `transport:TARGET-TRANSPORT-SPEC` drives a session through a `--target-transport` backend (`transport:agent:tcp:HOST:PORT`, `transport:gdb:HOST:PORT` with `--transport-coverage-map`, …): each message is one execution on the target, a fault, a crash or a hang ends the session at that message, and the executions' edges feed the code channel. A reply is the backend's stdout, which the agent backends do not have, so a profile over them captures nothing from replies. `--session-reset reconnect` arms a fresh target session for each protocol session; `none` keeps one armed. See [On-target fuzzing](on-target-fuzzing.md#3d-protocol-sessions-on-the-target). Required with `--protocol-profile`.
- `--session-reply-timeout <DURATION>` — how long the session lane waits for a reply before the target is taken to have ended the session: 5s over TCP and 1s over UDP by default. A UDP datagram that gets no reply in time, or that the target's host refuses (port unreachable), ends the session as a closed TCP connection does. A finding records the timeout, and `bhf replay` waits as long.
- `--grammar <PATH>` — a JSON grammar describing the target's input format, for structure-aware generation plus tree mutation: the builtin engine generates inputs from the grammar, keeps each one's derivation tree, and mutates a kept input on its tree (a subtree derived afresh, a recursion repeated, or a subtree spliced in from another input's tree of the same rule), so those mutants stay sentences of the grammar. Each rule maps a non-terminal to a list of production strings where `{NAME}` references another rule; the start symbol is `START` if present, else the first rule. A derivation ends within `--max-len`: as it nears the length, or 40 levels of nesting, it takes each rule's smallest production, so a sentence is never cut off. Most children of an input with a tree are tree mutations (the others are byte mutations, for the malformed input a parser must reject); an input the grammar did not make, such as a seed, gets fresh derivations and byte mutations. A grammar whose smallest derivation nests more than 512 rules deep is refused.
- `--frame <PROFILE>` — a binary frame descriptor for a single-input harness such as `parse_frame(buf, len)`: a protocol profile (TOML, `bhf.protocol.v1`) of one `[[message]]`, the session lane's message schema for one frame. The builtin engine decodes every input into the message's fields: a fixed-width field (an integer, an enum) by position, a variable-length `bytes` or `tlv` value by the length field that gives it (a `length(...)` field before it that covers it and otherwise only fixed fields, or a TLV's own length), and the last variable-length field takes the bytes the others leave. Half the mutants are a field edit (a payload grown, shrunk or overwritten within its `max`, an integer set to a boundary value or nudged, an enum set to one of its `variants`), the other half a byte mutation of the whole frame; either way every `length`, `crc32`, `crc16`, `sum8`, `xor8`, `offset` and TLV length is recomputed before the harness runs the input, so a mutant passes the target's length/CRC gate and reaches the code behind it. Seeds are decoded and re-encoded the same way, and the message's own frame (its fields' `value`s) is a seed. A TLV keeps the profile's `tag`. A profile with more than one message, a `giop` profile, an `optional` field or a `ref` field (a single input has no reply) is refused with exit `2`, as is `--frame` with an engine other than `builtin` or with `--target-transport` or `--protocol-profile`.
- `--dict <PATH>` — an AFL/libFuzzer dictionary (`name="token"` lines, `\xNN` escapes) whose tokens the mutator splices into inputs, on top of the harness's own `dictionary.txt`. The host loop and the transport lane read it; a file that cannot be read stops the run. The transport lane also reads the harness's `dictionary.txt` and `--grammar`: with a grammar, a seed is a derivation of it when no `--seed-input` or `--seed-file` is given, and every other input is a fresh derivation, so a target that parses the grammar receives only its sentences.
- The transport (`--target-transport`) and session (`--protocol-profile`) lanes run their own loops and refuse, with exit `2` and the flags named, each host-lane flag they do not use: `--workers`, `--cmplog-log`, `--len-control`, `--rss-limit-mb`, the fork-server, qemu-user, extension, sanitizer, symbolic-seed, sandbox, runtime-oracle, structured-input, final-stats and collector flags. The transport lane also refuses the session flags; the session lane, whose seeds come from the profile, also refuses `--grammar`, `--dict`, `--seed-input`, `--seed-file`, `--max-len`, `--timeout`, `--deadline` and `--transport-coverage-map`.
- `--session-reset <reconnect|none>` — how a session is reset between testcases: `reconnect` (default; a fresh connection gives fresh per-session target state, so a new handle/id/nonce is captured each run) or `none` (keep one connection). Recorded as the run's reset fidelity.
- `--max-session-messages <N>` — the most messages a session may hold (default `64`); a sequence mutation that would exceed it fails with a diagnostic.
- `--rng-seed <N>` — deterministic RNG seed for built-in mutation.

Multi-worker campaigns (`--workers N` with N > 1, or `--sanitizers` with more
than one sanitizer, one worker per sanitizer) resolve the harness executable
in the parent, as a single run does. Each harness dir the lookup reads
(`build/<id>/` and the `bhf auto` layouts `harnesses/<id>/`, `auto/<id>/`,
`generated_harnesses/<id>/`) in each `worker-<id>-N/` dir is made an exact
copy of the parent's: the worker's copy of a dir the parent does not have is
removed, and a copy that differs from the parent's (a file added, missing,
resized or rewritten) is copied again. A worker therefore runs the executable
the parent resolved, never one left by an earlier campaign. Without a built
harness the campaign exits `3` before starting any worker. Each worker's
stderr goes to `worker-<id>-N/worker-stderr.log`; for a worker that did not
complete, the summary's `per_worker[].stderr_tail` and stderr show its last
lines, and `per_worker[].stopped_at_deadline` marks a worker stopped at the
time limit. Each worker's own JSON summary goes to
`worker-<id>-N/worker-stdout.json`. The findings are merged before the
campaign summary is printed, so it also lists the parent ids the workers' new
findings were merged under (`merged_findings`) and, as a single run does, the
findings recorded before the campaign that its crashes matched
(`duplicates_of_existing`, with `duplicate_crashes_of_existing` counting those
crashes), with the same one-line note on stderr. That covers a worker's copy
the merge finds to duplicate a recorded finding and a crash a worker skipped
because its tree still holds such a copy from an earlier campaign
(`per_worker[].duplicates_of_existing` names that copy). Every worker gets the
run's `--runtime-oracles` mode (the summary's `runtime_oracles`), so its
oracle findings merge with its crashes; `on` without a usable runtrace shim
exits `3` before any worker starts. Every worker also gets `--grammar`,
`--frame`, `--dict`, `--deadline` and the fork-server switch. A flag whose
output stays in a worker's own dir or log is refused, with exit `2` and the
flag named: `--collector`, `--collector-window-ms`, `--extension` and
`--print-final-stats`. Run those with one worker and one sanitizer. When every
worker exits non-zero (or is killed by a signal), `bhf fuzz` exits non-zero
(the workers' shared exit code, else `1`). Workers stopped at the time limit
fuzzed until then: when they recorded findings, the campaign keeps its usual
exit code and stderr says they were stopped; when none recorded anything, it
exits `1`.

### Engines

`bhf fuzz --engine` takes `builtin` (the default), `afl++`, `libfuzzer`,
`honggfuzz`, `libafl` and, on native Windows, `winafl`. A generated C/C++
harness exposes `LLVMFuzzerTestOneInput`, and its default `main` binary is
bhf's own framed fork-server driver.

- `--engine libfuzzer` runs the harness's libFuzzer build instead,
  `main_libfuzzer` in `build/<id>/` or the harness directory, and builds it
  with `make libfuzzer` (clang) when there is none. It runs for `--time` (or
  `--iterations` as `-runs=`), with `--timeout`, `--max-len`,
  `--rss-limit-mb`, `--rng-seed` and the harness dictionary, and keeps its
  corpus in `libfuzzer/<harness>/corpus/`. libFuzzer runs in process and
  stops at its first crash. Each `crash-`, `oom-` and `leak-` artifact it
  saves is replayed through `main_libfuzzer` and recorded as a finding, as
  AFL++'s crashes are, and a `timeout-` artifact that hangs again at twice
  the timeout is a hang finding. It runs one process: `--workers` and a
  sanitizer matrix are refused, and `bhf auto` refuses the engine.
- `--engine honggfuzz` runs honggfuzz in persistent mode on the harness's
  `main_honggfuzz`, built with `make honggfuzz` (honggfuzz's `hfuzz-clang`,
  with ASan and UBSan) when there is none. bhf runs the honggfuzz in
  `BHF_HONGGFUZZ_PATH` (its build directory) or on `PATH`. It takes the same
  budget, limits and dictionary, keeps its corpus in
  `honggfuzz/<harness>/corpus/`, and replays the crash files honggfuzz saves
  through `main_honggfuzz` into findings. honggfuzz saves no hangs, so a run
  has no hang findings. It runs one process.
- `--engine libafl` runs a LibAFL campaign on the harness's `main`, in a bhf
  built with `cargo build --release -p bhf --features libafl-engine`; any
  other bhf refuses it and prints that command. LibAFL schedules and mutates
  (havoc plus the harness dictionary's tokens), runs each input in a fresh
  `main` process, and uses the edge bitmap `main` writes to `BHF_COV_SHM` as
  its coverage map. It runs for `--time` (or 100 ms per `--iterations`), with
  `--timeout`, `--max-len` and `--rng-seed`. Its corpus is in memory, and the
  inputs that crashed `main` are replayed through it into findings. It runs
  one process, and `bhf auto` refuses it.

A binary you compiled yourself with `-fsanitize=fuzzer` and placed at
`build/<id>/main` is recognized by the libFuzzer runtime in it and run on
one input file per process, so a crash it finds is recorded with the input
that caused it. Without bhf's runtime it gets no coverage guidance, and
`bhf fuzz` says so once, also for a `--workers` campaign (whose workers'
stderr goes to their logs). For coverage, wrap the fuzz target with
`bhf generate-harness <fuzz_target.cc> --target LLVMFuzzerTestOneInput`,
then build and fuzz that harness.

`bhf replay`, `bhf minimize` and built-in fuzzing take
`--sandbox none|auto|firejail|bubblewrap` (default `auto`). `--sandbox-tool`
names a specific wrapper executable, and `--sandbox-strict` fails when the
requested wrapper is missing instead of running without it.

`bhf fuzz` keeps its shared-memory maps (coverage, value profile, comparison
operands) in `<work>/fuzz_shm/`, named `<pid>-<random>.shm`. They go when the
run ends, when SIGINT, SIGTERM or SIGHUP stops it (the signal still ends the
run), and, for a run killed with SIGKILL, when a later `bhf fuzz` in the same
work dir finds their process gone, or with `bhf clean --all`.

### Stateful protocol sessions

`bhf fuzz --protocol-profile <PATH>` drives the target through
response-dependent, multi-message sessions: a later message echoes a
per-session value (a handle, id or nonce) that an earlier message's reply
returned, while both messages carry computed length and CRC fields. A
testcase is a sequence of structured messages. Mutation edits both the field
values and the sequence, and a repair pass then recomputes the derived fields
and re-resolves the response back-references before each frame is sent. The
violation this lane looks for exits cleanly, with no crash; an oracle the
profile declares flags it, on a sentinel response field or on arrival in a
declared violation state. `--harness` gives the id the findings record; the
session lane runs no harness binary.

The profile (TOML, `schema = "bhf.protocol.v1"`) declares the message types and
their typed fields (byte order / width / enums / bounded variable-length data /
optional fields), the computed fields (`length(..)`, `crc32(..)`/`crc16(..)`/
`sum8(..)`/`xor8(..)`, `offset(..)`, TLV) and response back-references
(`ref = "OPEN.response.handle"`), the legal message ordering as transitions, the
response captures a reply exposes, the session `reset`, and the `[[oracle]]`
that marks the clean-exit finding. bhf builds the seed session from the
profile, as a legal walk that satisfies every reference.

How messages are delimited on the wire is the profile's `[framing]`, and the
transport adds nothing of its own:

| `kind` | A request is | A reply ends |
|---|---|---|
| `raw` (the default) | written as it is | when no byte arrives for `reply_idle_ms` (50) after the first, or the peer closes |
| `length_prefix` | preceded by its length in `width` bytes (1, 2 or 4; 2 by default), `endian` `big` (the default) or `little`; `includes_prefix = true` when the length counts the prefix | after the length its prefix declares |
| `length_field` | written as it is: its length is a field of its own header at byte `offset` (0 by default), which the profile computes with `length(..)`, `width` 1, 2 or 4 bytes in `endian` order, or `"varint"` (MQTT's variable byte integer), counting the bytes after the field | after the length its field declares; the reply is the whole message, header included |
| `delimiter` | followed by `delimiter` (`"\r\n"`) | at the delimiter, which is not part of the reply |
| `fixed` | `size` bytes: a shorter request is padded with zeros, a longer one cut | after `size` bytes |

```toml
[framing]
kind = "length_prefix"
width = 2
endian = "big"
```

The run summary's `framing` names it (`length_prefix(u16 big)`,
`length_field(varint at 1)`).

#### Reference profiles

bhf ships profiles for real protocols under `profiles/protocols/`; each
file's header says what it models and how to point it at a server. Every
state they declare is reached only when the server answers with the reply
the request expects (each captures the reply's type as an enum naming only
that reply), so the summary's `states_covered` counts states the server took
the session to.

| Profile | Protocol | The session |
|---|---|---|
| `modbus-tcp.toml` | Modbus/TCP (`--session-transport tcp:HOST:502`) | Read Holding Registers, Write Single Register with the value the read returned, Write Multiple Registers; an exception response does not advance it |
| `mqtt-3.1.1.toml` | MQTT 3.1.1 (`tcp:HOST:1883`) | CONNECT, SUBSCRIBE, PUBLISH at QoS 2, PUBREL with the packet id the PUBREC named, PINGREQ; a refused CONNECT does not advance it |
| `coap.toml` | CoAP, RFC 7252 (`udp:HOST:5683`) | Confirmable GET of `/.well-known/core`, GET of `/limit`, PUT of `/limit` with an If-Match of the ETag the GET returned; only the piggybacked 2.05 or 2.04 advances it |
| `rtps.toml` | RTPS 2.3, the DDS wire protocol (`udp:HOST:7410`) | an SPDP participant announcement, a HEARTBEAT of the SEDP publications writer to the participant that answered (an INFO_DST of the GUID prefix it announced), the publication at the sequence number its ACKNACK asked for; the participant must answer to the datagram's source |

```sh
bhf fuzz bhf_work --harness H-MODBUS \
  --protocol-profile profiles/protocols/modbus-tcp.toml \
  --session-transport tcp:192.0.2.10:502 --iterations 5000
```

A server that closes the connection on a malformed request, as an MQTT
broker must, has the session lane record each such session as dropped (a
`session-disconnect` finding, see below). Under `--session-server-cmd`, a
server that crashes gives a `session-server-crash` or `session-server-exit`
finding instead.

#### GIOP profiles

A profile with `kind = "giop"` makes every message a GIOP 1.2 Request, for
an IIOP endpoint over `--session-transport tcp:HOST:PORT`. The `[giop]`
table gives the `object_key` the requests address (a message can give its
own) and their `endian` (`big`, the default, or `little`). A message's
`operation` is the operation it invokes (its name by default), and its
fields are the operation's `in` parameters, in order, at their IDL types:
`octet`, `boolean`, `char`, `short`, `unsigned short`, `long`, `unsigned
long`, `enum` (marshalled as an unsigned long), `string` and
`sequence<octet>`; a signed type's seed may be negative, and a field may be a
`ref` to a captured value. bhf marshals them in CDR with its `iiop` crate,
so a giop message has no computed or `tlv` fields: CDR carries its own
lengths. Each reply is framed by its GIOP header (the summary's `framing` is
`giop`) and must be the Reply to the request's id. A capture named
`reply_status` or `request_id` reads that field of the Reply header, and
every other capture reads the next value of the body (the result, then the
out parameters), so a capture takes no `at`. A body capture needs a reply
with no exception; a `reply_status` enum of `{ no_exception = 0 }` has only
such a reply advance the session.

```toml
kind = "giop"

[giop]
object_key = "Warehouse"

[[message]]
name = "STORE"
operation = "store"

[[message.field]]
name = "bin"
type = "unsigned long"
ref = "OPEN_BIN.response.bin"

[[message.field]]
name = "slot"
type = "unsigned short"
value = 1

[message.response]
[[message.response.capture]]
name = "reply_status"
type = "enum"
variants = { no_exception = 0 }

[[message.response.capture]]
name = "stocked"
type = "long"
```

A servant that crashes on a request takes its connection with it, which the
session lane records as a dropped session (a `session-disconnect` finding at
that message).

A response capture of `type = "tlv"` takes the value of a tag-length-value
record in the reply: the records from `at` are walked until one has `tag`
(the record at `at` when there is no `tag`), each with a `tag_width` and a
`len_width` of `u8`, `u16` (the default) or `u32` in the capture's `endian`.
The value is bytes, which a later request echoes from a `bytes` field
(`ref = "HELLO.response.cookie"`) or a `tlv` field of its own `tag`; a
`length(..)` or CRC that covers it is computed over it.

```toml
[[message.response.capture]]
name = "cookie"
type = "tlv"
at = 1
tag = 2
```

`--session-server-cmd COMMAND` has bhf run the service itself, through the
shell, with its stderr kept under `<work_dir>/session_server/`. bhf waits until
it serves the `--session-transport` port, and after each session checks
whether it exited. A session after which it exits is driven again on the
service started again; if it exits again, that is a finding, written from the
sanitizer report in the service's stderr (with its rule, stack and
`sanitizer.log`, oracle `session-server-crash`) or, with no report, a BHF-210
finding (oracle `session-server-exit`). The service is started again and the
campaign goes on; the summary's `server_starts` counts the starts. Unless the
environment sets `ASAN_OPTIONS`, the service runs with
`halt_on_error=1:abort_on_error=0:detect_leaks=0:symbolize=1`. A service that
exits before it serves its port, or does not serve it within 10s, stops the
run with exit `2` and its stderr. `bhf replay` and `bhf minimize` of such a
finding start the service for each drive.

The service also gets `BHF_COV_SHM`, an edge map bhf keeps for the campaign.
A service built with SanitizerCoverage and bhf's `c_runtime/bhf_service_cov.c`
fills it: bhf reads the edges after each session and keeps a session that
reached new code, as one that reached a new protocol state is. The map
outlives a restart of the service. bhf's source tree has an example service,
`tests/fixtures/session_server/echo_server.c`:

```sh
clang -fsanitize=address -fsanitize-coverage=trace-pc-guard \
  echo_server.c /path/to/bhf/c_runtime/bhf_service_cov.c -o build/echo_server
```

With `--runtime-oracles on` (or `auto`) the service runs under the runtrace
shim. Before each session bhf writes the bytes the session carries (its byte
and TLV field values) where the shim matches sinks against its input. After
the session, bhf evaluates the events the service logged during it, so what
the service does before it serves is no session's. A command, path, library
or query built from those bytes is a finding of that session, once per rule
and sink API for the campaign (BHF-431 and BHF-304 for a command, for
instance), with `session.json` and `session_meta.json`. `bhf replay` runs the
service under the shim again and looks for the same hit. Without
`--session-server-cmd` there is no process to trace, and `--runtime-oracles`
is refused.

GCC builds use `-fsanitize-coverage=trace-pc`. The summary's `coverage_edges`
counts the service's edges. Its `coverage_source` is `service`, or
`uninstrumented_service` for a service that never wrote the map, `target` for
a `transport:` backend that reported edges, and otherwise `none`.

A campaign on a service bhf starts, with a profile of your own for its
protocol:

```sh
bhf fuzz bhf_work --harness H-PROTO \
  --protocol-profile path/to/echo-profile.toml \
  --session-transport tcp:127.0.0.1:9000 \
  --session-server-cmd './build/echo_server 9000' --iterations 2000
```

A campaign on a service already listening on port 9000, with the toy
OPEN/WRITE profile from bhf's test fixtures:

```sh
bhf fuzz bhf_work --harness H-PROTO \
  --protocol-profile crates/protocol_session/tests/fixtures/toy-open-write.toml \
  --session-transport tcp:127.0.0.1:9000 \
  --session-reset reconnect --iterations 2000
```

The run reports code-coverage novelty (`coverage_edges`,
`coverage_blocks`) and protocol-state novelty (`states_covered`,
`transitions_covered`) as separate fields. A plain request/response transport
reports no code edges, so on such a target the code channel stays at zero
and the state channel carries the novelty; a service built with
`bhf_service_cov.c`, or a `transport:` backend, supplies edges. The run and
every finding record the profile's SHA-256 and the transport and reset
fidelity in effect (for example `tcp;reset=reconnect`).

A finding is written to the usual `results/` layout, which importers, SARIF
and vulnerability-management tools read, with a `session.json` artifact (the
structured message sequence, the state path, the captured reply of each
step, and the bindings taken from responses) and a self-contained
`session_meta.json` sidecar (the profile inline and the transport spec).
`bhf replay <finding>` and `bhf minimize <finding>` find that artifact on
their own. Replay drives the recorded session again after a fresh reset,
capturing a new handle and re-resolving the reference, so it still
reproduces. Minimize shrinks the sequence and the bytes fields, repairs the
computed fields after each change, and keeps the bindings live.

A session the target ends after accepting it (it closes or resets the
connection, or stops answering within the I/O timeout) is a crash candidate:
the session is kept under `<work_dir>/session_disconnects/`, driven again on a
new connection, and written as a BHF-210 finding (oracle `session-disconnect`,
deduplicated by the message it dropped at) when the target drops it at the same
message again; the summary counts these in `crashes` and the ones a second drive
did not repeat in `unconfirmed_disconnects`. The campaign goes on. A failure to
connect skips the session, and three in a row stop the campaign (exit `1`),
naming them; the wait before each retry grows by 200 ms, so a service that
restarts after a crash has time to come back. `bhf replay` of a
`session-disconnect` finding is a `MATCH` when the target drops the session
again.

A malformed profile, an unresolved reference, a truncated response, a
message count over `--max-session-messages`, and an oversized frame each
fail with a named error.

## Dictionaries and Structured Inputs

`bhf fuzz --structured-inputs <MODE>` sets how the built-in engine builds
structured inputs from the loaded dictionaries:

| Mode | Effect |
|---|---|
| `auto` (default) | every family below, `recursive` included |
| `record`, `json`, `xml`, `kv`, `url`, `multipart`, `csv`, `http`, `ini`, `toml`, `yaml` | one family: record/TLV, JSON-shaped, XML elements, key/value text, URL-encoded query strings, multipart/form-data, CSV rows, raw HTTP requests, INI sections and keys, TOML tables and keys, YAML sections and keys |
| `recursive` | nested-grammar and recursive-structure synthesis |
| `off` | byte and dictionary mutation, with no structured synthesis |

When bhf generates a harness it mines a `dictionary.txt` from the source:

- Ada harnesses: enum literals and string literals;
- C and C++ harnesses: constants from the source and its headers, including
  C++ namespaced `enum class` members and `switch` case labels, but not
  `#include` paths;
- the Rust, Go, Java, Python, Perl, C#, JavaScript, Ruby, Lua and PHP lanes:
  string and number literals.

A `# from <file>:<line>` comment before each token names up to three places
it was found, with files relative to the target source's directory (for
example `# from parser.c:42, include/parser.h:7`). A token bhf adds itself
has no comment. Each integer literal is also written as its raw little- and
big-endian bytes, under a `# raw bytes of the literal above` comment.

### Learned dictionary

While a harness is fuzzed, the comparison operands it meets accumulate in
`cmplog.jsonl` beside `dictionary.txt`. After each `bhf auto` fuzz pass that
recorded any, bhf rewrites `learned_dictionary.txt` from the constants among
them:

- A constant is an operand that met more distinct values at one comparison
  site than any of those values met there. A constant is compared with input
  after input while the mutated input varies, and each input meets only the
  constants it is checked against. At a keyword-table lookup, a keyword
  counts once it has met more inputs than there are keywords; before that,
  neither side counts.
- Records from bhf's driver name their comparison site (`"s"`). Records the
  runtrace shim writes for a harness built without a sanitizer, and records
  of a harness built with an older driver, have no site. An operand
  `dictionary.txt` lists is kept as well, and a record without a site can
  only confirm such a token.
- The driver also records the constant of each integer comparison the
  compiler emitted against one (an `"int"` record), including a constant
  computed at build time that no source literal spells, such as a key folded
  from a hash of a literal. One such record makes it a constant, written as
  its little-endian bytes and then big-endian. A constant of at most 0xff, or
  of all ones, is not recorded.
- The shim's own comparisons, its checks of the paths, device names and
  environment variables a target uses, are never recorded.
- Tokens are at most 64 bytes, and a one-byte variant of a stronger token is
  left out. This run's constants come first, then those an earlier run
  learned, up to 256 tokens, under a header that says how they were chosen.
- A file an earlier release wrote held every operand, mutated inputs
  included. Of its tokens, bhf keeps those this run also found constant or
  `dictionary.txt` lists.

`bhf fuzz`, and the first pass of a later `bhf auto` run, load
`dictionary.txt` and then `learned_dictionary.txt` when they are present,
each token once. Later passes of the same `bhf auto` run also read
`cmplog.jsonl` itself and skip the tokens already loaded. AFL++ runs get both
files with `-x`.

## Actionability Modes

`bhf auto` and `bhf fuzz` take `--mode reporting|attacking`. The default is
`reporting`.

- `reporting` serves the developer who fixes the bug: each finding comes
  with its replay command, a minimized input when there is one, the source
  location to fix, patch guidance, and a label on lab-only paths.
- `attacking` fuzzes first the targets that look externally reachable and
  security-relevant. Findings that depend on generated stubs, fake
  resources, missing-environment shims or mocks are still recorded, as
  `lab_only`, and are left out of the real-reachable counts.

CI can gate on a finding's actionability verdict:

```text
bhf ci . --fail-on-actionability likely --min-actionability-confidence medium
```

| `--fail-on-actionability` | Fails on the verdicts | Use it for |
|---|---|---|
| `real` | `real_reachable` | a strict gate on attacker-reachable findings |
| `likely` | `real_reachable`, `likely_reachable` | a security gate that accepts strong static entry and sink evidence |
| `lab` | those and `lab_only` | failing the build on lab-only findings too |
| `any` | every verdict, `blocked` and `unknown` included | failing on every recorded finding |

`--min-actionability-confidence` (`high`, `medium` or `low`; default `low`)
is the confidence a finding needs to count.

## Runtime Oracles, Collectors and Postconditions

These options turn a security violation into a finding when the target
exits cleanly, as well as when it crashes.

### Runtime sink oracles: `--runtime-oracles`

`--runtime-oracles auto|on|off`, on `bhf fuzz` and `bhf binary fuzz`, loads
the runtrace sink oracles through the `LD_PRELOAD` shim. A fuzz-controlled
command execution, path escape, `dlopen`, network egress or SQL query is
then reported even when the target exits zero.

| Value | Effect |
|---|---|
| `off` (default) | crash-only fuzzing |
| `auto` | load the oracles where the shim and the platform (Linux) support them, and skip them elsewhere |
| `on` | require the oracles; exit with an error when they are unavailable |

The oracles run in native Linux processes, the same layer `bhf auto` uses.
On `bhf binary fuzz` they need the builtin engine. `bhf binary fuzz` passes
each input to the shim through an inherited file descriptor, so a black-box
target still gets byte-origin taint. Its oracle findings are
`kind: binary_semantic`, with the oracle rule, API, taint evidence and shim
hash, and replay by re-confirming the oracle instead of a crash signature.

### Runtime-event collector: `--collector`

`--collector auto|none|PATH`, on `bhf fuzz`, `bhf binary fuzz` and
`bhf auto`, arms a runtime-event collector: a provider that observes the
process, filesystem and module-load effects of a target, clean exits
included, and emits the versioned `bhf.collector-event.v1` JSONL contract
(`schemas/bhf.collector-event.v1.schema.json`). bhf attributes the events to
the testcase's descendant process tree within a window after it exits
(`--collector-window-ms`, default `250`) and runs them through the bug-oracle
registry the runtime oracles use. A controlled process execution (BHF-431), a
path escaping the allowed root (BHF-405) or a controlled library load
(BHF-435) becomes a `kind: binary_semantic` finding with no crash.

| Value | Provider |
|---|---|
| `none` (default) | no collector |
| `auto` | the platform's built-in provider: on Windows the native ETW provider `bhf-collector-win`; on Linux the `LD_PRELOAD` runtrace adapter, which arms the runtrace shim for the run and re-expresses the shim's effect events as the collector contract. With `--runtime-oracles off` it writes no runtime-oracle findings, and it stays inactive when the shim is unavailable |
| `PATH` | an external sidecar that speaks the protocol |

The contract is a JSONL wire format, so a provider can live outside bhf. On
Linux the collector reads the same shim events as `--runtime-oracles` and
leaves that flag's behaviour as it is.

On Windows, `bhf binary fuzz` replays a retained input under the native
sidecar, which roots its attribution at the PID bhf hands it. A process the
target starts through `ShellExecuteEx` with a controlled command is a
BHF-431 finding, and a constant command is no finding; see
[Windows](windows.md). `bhf fuzz` does not replay a harness under a sidecar.
In `bhf auto`, after a target's passes, its retained inputs (its findings,
then its corpus, at most 16) are replayed one by one under the collector,
and `run.json` records each target's `collector`.

A collector finding stores its raw `CollectorSession` evidence beside
`finding.json`, as `collector_session.jsonl`. `bhf replay <id>` re-evaluates
the oracle registry over that stored evidence and shows the attributing
event and the descendant process tree; it needs no `--harness`. Lost events,
an API the platform does not expose, and a denied permission are recorded as
fidelity limitations, and a run that has one claims no clean result. Each
run and finding records the collector's provenance: the backend's name,
version and hash, the process-tree scope, the observation window, the event
classes the backend declares it supports and, kept apart, the classes
observed this run, and the fidelity limitations. `bhf minimize` on a
collector finding re-confirms that it reproduces and leaves it as it is,
since the captured evidence does not depend on the testcase bytes.

On Linux, `bhf fuzz --collector auto` reads the whole campaign's runtrace as
one aggregate session. It keeps one finding per rule, oracle and API (a
fuzzed `system()` runs a different command for each input, which a replay
would count as distinct violations), writes none for a rule the
runtime-oracle lane already reported with its testcase, labels the effects
with their POSIX APIs (`execve`, `dlopen`), records them at `medium`
confidence with no clean result, and stores the session once, in
`results/collector/`, which each finding's `paths.collector_evidence` names.
It reads the runtrace log this run armed (and emptied when it armed it),
never one an earlier run left in the work dir. Such a finding has no input,
so `bhf replay` reports it `UNVERIFIED` (exit `4`) when its evidence still
produces its signature.

### Postcondition oracles: `bhf binary fuzz`

`bhf binary fuzz` takes user-defined postcondition oracles with per-case
fixture hooks:

| Hook | Runs |
|---|---|
| `--setup-command` | before each testcase, to prepare a fresh fixture |
| `--oracle-command` | after it, to check a security invariant |
| `--reset-command` | afterwards, to restore state |

Each case gets a fresh `BHF_CASE_DIR`. The hooks and the target receive
`BHF_CASE_DIR` and `BHF_TESTCASE` in their environment. The oracle also gets
`BHF_TARGET_EXIT`, `BHF_TARGET_SIGNAL`, `BHF_TARGET_TIMEOUT` and
`BHF_TARGET_STDERR`, and the testcase path as `$1`. Its exit code is the
contract: `0` is clean, `1` is a finding (its first stdout line is the stable
signature or classification), and any other code is an infrastructure
error. A violation is a `kind: binary_postcondition` finding (BHF-502) even
when the target exited zero, and `bhf replay` and `bhf minimize` re-run
setup, target and oracle to re-confirm the signature. Use it for a rule
specific to the application that the built-in sink oracles do not know, such
as "this input must not make the target write outside the allowed root,
launch an unlisted process, or perform an unauthorized operation".

### Findings from runtrace events

Runtrace events promote to these oracle findings:

| Event | Finding |
|---|---|
| a handled `Constraint_Error` range or index check (a `runtime_check` event of Ada instrumentation) | BHF-102 `ada-runtime-constraint-check`, with check, handler, message and source evidence |
| a handled `Storage_Error` | BHF-103 `ada-runtime-storage-error` |
| a handled `Tasking_Error` | BHF-104 `ada-runtime-tasking-error` |
| a handled user-defined Ada exception | BHF-105 `ada-runtime-user-exception` |
| `dlopen` of a bare, relative, parent-directory, temporary-directory or other non-system library path | BHF-413 `dynamic-library-load-runtime` |
| a successful `unlink`, `unlinkat` or `remove` of a path with a parent-directory segment | BHF-414 `file-deletion-runtime` |
| a native C/C++ assertion failure the shim observed | BHF-415 `native-assertion-contract`, with expression and source evidence |
| an open of a path that carried byte-origin taint from the fuzz input and was never opened untainted in the run | BHF-405 `path-controlled-open-runtime`, with a `taint_path` string (`fuzz_input[offset..] → open(path)`) |

BHF-405 findings come from matching across executions: once per run, not
per input, and capped per harness.

The LD_PRELOAD runtrace shim produces BHF-413, BHF-414, BHF-415 and BHF-405,
and the BHF-304 command-injection, BHF-417 insecure-temp and BHF-305
sensitive-environment oracles. bhf arms it for native C, C++, Ada, Rust, Go,
COBOL and Fortran harnesses, and `bhf auto` also preloads it into the
Python, Perl, Ruby, Lua and PHP launchers, where it records from the
target's entry on. The Java, C# and JavaScript/TypeScript lanes, and
cross-compiled or emulated runs (qemu-user, Wine), fuzz without it, on their
own coverage, crash and exception signals.

## Differential and Metamorphic Testing

`bhf differential --harness-a <A> --harness-b <B> --inputs <DIR>` replays
each input through two implementations, each given the input path as
`argv[1]`, and reports a BHF-301 output-divergence finding when their
stdout, exit status or timeout behaviour differs. Findings go under
`<work-dir>/results/findings/F-DIFF-NNNN/` (`--work-dir`, default
`bhf_work`; `--out DIR` is a deprecated alias), and `results/` is rebuilt.
Differential findings carry `oracle.name = "differential-output-runtime"`
evidence from the same executable-oracle registry as runtime runtrace
findings. `--timeout-secs` (default 5) bounds each side.

`bhf differential --harness <H> --metamorphic-transform <NAME>[,<NAME>...]
--inputs <DIR>` replays each input through one harness, and again as the
variant each transform makes of it. A variant that breaks its transform's
relation is a BHF-307 `metamorphic-relation-runtime` finding, with the
original and the transformed testcase bytes and the `transform` and
`relation` it broke.

| Transform | Variant | Must keep |
|---|---|---|
| `append-newline` | a `\n` after the input | stdout and the exit status |
| `trailing-whitespace` | a space and a tab at the end of every line | stdout and the exit status |
| `reorder-json-keys` | every JSON object's members in reverse order, every other byte kept | stdout and the exit status |
| `utf8-bom` | a byte order mark before the input | the exit status |

Several transforms, comma-separated or the flag repeated, are each applied
to every input. A transform that does not apply to an input (no JSON object
to reorder, a BOM already there) skips it.

`bhf fuzz --differential-harness` compares two builds inside the fuzz loop,
and `bhf auto --differential` compares two compilers; see [Fuzzing a
harness](#fuzzing-a-harness) and [Auto](#auto).

## Replaying a Finding

`bhf replay --finding <id-or-dir>` re-runs a finding's testcase against its
harness and says whether the recorded crash reproduced. The first line is the
verdict:

| Verdict | Stream | Exit | Meaning |
|---|---|---|---|
| `MATCH` | stdout | `0` | the recorded crash at the recorded place; `last_seen` and a `replay` history entry are recorded |
| `MISMATCH recorded=<rule> actual=<rule> differs=<fields>` | stderr | `3` | a compared field differs, or no crash (`actual=<none>`, `actual=<timeout>`) |
| `UNVERIFIED recorded=<rule> actual=<rule> not_compared=<fields>` | stderr | `4` | nothing differs, but where it crashed could not be compared; nothing is recorded |
| error | stderr | `1` | the replay could not run |

A divergence `bhf fuzz --differential-harness` found in its loop (a finding
whose `differential.mode` is `in_loop`) replays through both builds (lane
`differential`): `MATCH` when they disagree as recorded, `MISMATCH
recorded=BHF-301 <what differs>` otherwise, and `UNVERIFIED recorded=BHF-301
the second build <path> is not there ...` (exit `4`) when the second build is
gone.

Under the verdict line comes a summary of what ran:

```text
MATCH
  finding    F-0003-9c1d22e0 (bhf_work/results/findings/F-0003-9c1d22e0)
  compared   rule BHF-201; kind heap-buffer-overflow; sink Widget::copy_at (widget/widget.cc:12)
  crash      BHF-201 heap-buffer-overflow (asan): ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000031 ...
  sink       Widget::copy_at (widget/widget.cc:12)
  frames     #0 Widget::copy_at(char const*, unsigned long) /src/widget/widget.cc:12
             #1 parse_record(char const*) /src/widget/parse.cc:40
  access     WRITE of size 1 at 0x602000000031; 0 bytes after a 1-byte heap region (offset 1)
  allocated  #0 malloc
             #1 parse_record(char const*) /src/widget/parse.cc:38
  exit       signal 6 (SIGABRT) after 0.05s
  harness    bhf_work/harnesses/H-C0001/main (bhf framed: ...); sha256 matches the recorded build
  testcase   .../testcase.bin, 12 bytes, sha256 0f1e2d3c4b5a6978
```

- **Matching.** A replay is a `MATCH` only when the rule, the crash kind and
  the place match: the sink (the top project frame, chosen as for
  `actionability.sink`, compared by function and `file:line`) or, for a finding
  recorded without frames (a UBSan report from an earlier release), the site
  the sanitizer printed. A fatal signal without a sanitizer report also
  compares its signal (`exception.signal`, or the signal an older record's
  message names): an abort is not reproduced by an illegal instruction
  (`differs=signal`). A COBOL finding is recorded as the libcob runtime error
  its harness printed before the signal (kind `cobol-runtime-error`, site the
  `.cob` line libcob named); replay, `bhf minimize` and `bhf report --backfill`
  read the replayed run's libcob error the same way, so it matches the same
  error at the same COBOL line by the same signal, and a bare signal without
  that error is `differs=kind`. A crash of the same rule elsewhere is a
  `MISMATCH` whose `differs=` field and `differs` line name what differed.
  Rules and kinds earlier releases gave the same report still match. A hang
  is reported as `actual=<timeout>` after 10 s, a clean exit as
  `actual=<none>` with its exit status.
- **Oracle, assertion and capability findings.** A finding that is not a
  sanitizer crash replays with the runtrace shim recording what the harness
  did. A runtime-oracle finding (`classification: "oracle_hit"`, such as a
  failed assertion, BHF-415, or a fuzz-controlled format string, BHF-408) is a
  `MATCH` when the oracle registry, run over the replay's runtrace, reports
  the same rule at the same API with the same site evidence (an assertion's
  `source` and `expression`). An assertion the runtrace did not record (the
  shim did not run in the harness) is read from the message the C runtime
  printed: glibc's `` Assertion `expr' failed. ``, the Microsoft C runtime's
  `Assertion failed: expr, file f, line n`, or the BSD or musl form; its
  expression must be the same and its source the same file and line. An
  input-triggered capability finding (BHF-668) is a `MATCH` when the replay of
  its testcase (a corpus entry that reached the capability) reaches the same
  kind of capability with an operand that entry reached. A crash `bhf auto`
  filed as the format-string bug compares as the crash its sanitizer reported
  (`format_string.crash_rule_id`); when that crash does not come back (the
  format reads whatever is in the argument area), the format-string oracle
  firing at the recorded call is the `MATCH`, and a note says so.
- **Unverified.** A replayed report that names no function and no source
  position (an unsymbolized one) cannot be compared by place, so the verdict
  is `UNVERIFIED ... not_compared=sink`
  (exit `4`); `last_seen` and the history are left as they were
  (`finding.json` does not change). Like every replay it writes the replay
  log (`replay.log`, or `replay-other-harness.log` for another harness than
  the finding's own), and `results/` is rebuilt so the attestation covers it.
  When the harness is the recorded build (its sha256 is
  `build.binary.sha256`), replay first symbolizes the report itself with
  `llvm-symbolizer` (or `addr2line`) from `PATH` and compares again. A finding
  that records no crash location at all (no frames, sink, site or pc, such as
  a rule-only record from an earlier release) is a `MATCH` only against the
  recorded build, and so is the faulting pc offset a fatal signal records
  (`not_compared=location`, `not_compared=pc` otherwise). A `note` line names
  the cause: a fatal signal that printed no sanitizer report, a stripped
  harness binary, a `symbolize=0` in `ASAN_OPTIONS` or `UBSAN_OPTIONS` that
  still reached the harness (bhf appends `symbolize=1` to the inherited
  value), or no symbolizer. Replay puts the LLVM toolchain `bhf auto`
  uses on `PATH` (the RHEL 7 LLVM Toolset when the base `clang` lacks
  SanitizerCoverage); elsewhere put `llvm-symbolizer` on `PATH` or set
  `ASAN_SYMBOLIZER_PATH`.
- **Timeout.** The harness runs in its own process group: after 10 s it is
  killed with every process it started (a launcher script's children too),
  and replay does not wait more than 2 s for output a leftover process holds.
  An interrupted replay or minimize (Ctrl-C, `SIGTERM` or `SIGHUP`) kills
  that group too before bhf ends by the signal.
- **Build identity.** When the harness's sha256 differs from the finding's
  `build.binary.sha256`, the harness line says so.
- **`--json`** prints one `bhf.replay.v1` document on stdout instead: `verdict`
  (`match`, `mismatch` or `unverified`),
  every compared field (`compared[]` with `outcome`: `equal`, `legacy`,
  `differs`, `not_recorded` or `not_comparable`), `differences`, `notes`, the
  replayed `crash` (rule, kind, sink, frames, `access` region, allocation
  frames), `exit` (code, signal, `timed_out`, duration), `harness` (path,
  protocol and why, sha256) and `testcase`. Exit codes are unchanged.
- **`--show-output`** also prints the harness's raw stderr and stdout (the full
  sanitizer report).
- **`replay.log`.** Every replay, `MATCH`, `MISMATCH` or `UNVERIFIED`, writes
  a replay log, `<finding>/replay.log`: the verdict, what ran, the exit
  status, the harness's raw stderr and stdout (each kept to its first 256 KiB
  and last 768 KiB, with the cut marked, so a sanitizer report at the end
  survives) and any `--debugger` transcript. The summary names it (`log`, and
  `replay_log` in `--json`). It is overwritten by the next replay of the
  finding's own harness (or the next `MATCH`), is not one of the finding's
  evidence files, and results/ is rebuilt after it is written so
  `attestation.json` stays current. It also has the summary's crash,
  differences and details lines. A lane with no harness output to keep
  (session, collector, transport, Ada event log) writes those and why there
  is no output. A replay of another harness than the finding's own
  that does not `MATCH` (a `--harness` whose sha256 is not the recorded
  `build.binary.sha256`, a rebuild at the same path, or, for a finding that
  records no build, another file than the harness it names) writes
  `<finding>/replay-other-harness.log` instead (overwritten by the next such
  replay, and attested the same way) and leaves `replay.log` as it was, so
  that log keeps the last replay of the finding's own harness.
- **`--show-args`** runs a generated C/C++ harness with `BHF_TRACE_ARGS=1` and
  prints the value it decoded for each parameter under the summary: name,
  type, the testcase bytes it came from, its value (or a buffer's length and
  allocation size, and an output's value after the call) and a hex preview.
  When the access starts in a traced buffer, a last line names that parameter.
  With `--json` they are `arguments.traced` (with
  `arguments.accessed_parameter`). A harness generated without the trace, and
  the other lanes, say why there are no arguments. See the [C/C++
  guide](c-cpp.md#seeing-the-decoded-arguments).
- **`--debugger [gdb|lldb|cdb]`** also re-runs the testcase under a debugger in
  batch mode (with no value, the first found: gdb, then lldb; cdb first on
  Windows) and prints its transcript under the summary (`debugger` in
  `--json`: tool, command, breakpoint, transcript, notes). The session breaks
  at the target function named by the harness's `generation-metadata.json`
  (`target_function`), prints `info args` and `bt full` (lldb: `frame
  variable`, `bt all`; cdb: `dv`, `kP`), removes the breakpoint, continues to
  the crash and prints the full stack again. The harness runs with the
  replay's environment: the finding's runtime mode, the variables it recorded
  as injected, and the runtrace shim, which is preloaded into the harness
  alone (gdb through an `env` exec-wrapper, lldb through `target.env-vars`),
  never into the debugger. AddressSanitizer runs with
  `handle_segv=0` (and the other signal handlers off) so the debugger sees a
  SEGV, `abort_on_error=1` so a report stops there, and `detect_leaks=0`
  (LeakSanitizer does not run under ptrace); UBSan aborts on its first
  report. lldb runs its crash-site commands as on-crash (`-k`) commands, since
  its batch mode stops running the others once the harness crashes, and stops
  a sanitizer report at a breakpoint on the sanitizer's report function
  (`__sanitizer::Die`, `__ubsan_handle_*`). A harness generated by an older
  bhf names no target: the session breaks at the finding's recorded sink
  instead and says so in a note. The harness
  runs natively and outside any sandbox: `--debugger` cannot be combined with
  `--qemu-user`, `--sandbox firejail|bubblewrap` or `--sandbox-strict` (with
  the default `--sandbox auto`, a note says the session ran unsandboxed), and
  applies only to C/C++ harness replays. When
  the debugger is not installed, replay exits `1` before running anything and
  says what to install. Harnesses build with `-O1`: arguments at the target's
  entry are reliable, some locals print `<optimized out>`.
- **Other finding kinds.** Binary, session, collector and transport findings
  print the same kind of summary under their `MATCH`/`MISMATCH` line, for what
  their replay compares: a binary target's crash, oracle or postcondition
  signature with its exit status, binary sha256 and any sanitizer report; the
  session oracle verdict; the collector oracle signature re-evaluated over the
  stored evidence, with the attributing event and process tree; the transport
  fault identity (rule and fault site) or deadline predicate. `--json` prints
  the same `bhf.replay.v1` document with `lane` (`binary`, `session`,
  `collector` or `transport`) and `details`; `harness` is present only for a
  binary finding. `--show-output` prints a binary target's stderr; the other
  lanes run no local harness. `--stability-runs <N>` drives an on-target
  transport finding's input N times, each from the transport's reset, and
  reports a finding that some runs reproduce and others do not as
  `MISMATCH nondeterministic, K of N` (exit `3`); `--transport-endpoint
  HOST:PORT` relocates the recorded endpoint.
- **Kernel crashes.** A `F-KERNEL-*` finding ran in a kernel, not a harness:
  `bhf replay` and `bhf minimize` exit `1` and name what reproduces it,
  `bhf kernel replay <finding>` for one `bhf kernel fuzz` found in its guest
  (its program is `testcase.bin`, and as C `repro.c`), or the syzkaller
  reproducer to run in the kernel's test VM for an imported one. `bhf
  explain` shows the kernel report, the program's calls and those commands.
- **Ada (event-log) findings.** The verdict compares event-log signatures;
  the summary says what both runs raised. `crash` is the replayed exception
  the verdict rests on (the rule and classification, then `NAME: message`),
  `reported` its raise site (the explicit `raise` the event log records, or
  the `file.adb:LINE` GNAT puts first in a failed check's message, put back
  on the source line through `src_instrumented/` of the harness's work dir,
  or of the finding's when the harness is outside one), `handled` its
  handler or that it reached the harness, and `recorded` the same for the
  exception the finding recorded. On a `MATCH` that is the exception with
  the recorded signature. On a `MISMATCH` it is the replayed exception
  closest to the recorded one, wherever it came in the run: the same
  exception with the same classification and handler, then with either,
  then at the same raise site; failing that, one that reached the harness,
  then the first. `actual=`, `crash` and the `differs` lines (the
  exception, the raise site, the handler, the classification, the target or
  the last breadcrumb) all describe that one, or say that the replay raised
  none; any other exception the replay raised, such as one it handled
  first, is listed under `also`. `--json` carries both sides in
  `exceptions` (`recorded`, and `replayed` in event-log order, each with
  `name`, `message`, `classification`, `raised_at`, `handled_at`,
  `target_id`, `last_breadcrumb` and `signature`), with the harness exit
  status and duration in `exit`.
- **Sanitizer options.** C/C++ replays use the fuzz child's options:
  `ASAN_OPTIONS` gets `abort_on_error=1:halt_on_error=1:symbolize=1` (plus
  `detect_leaks=1` for a leak finding) and `UBSAN_OPTIONS` also
  `symbolize=1`, `print_stacktrace=1` and `report_error_type=1`, merged after
  your own values, so an inherited `symbolize=0` cannot erase the location.
  Leak detection is never turned off.
- **Harness resolution.** Without `--harness`, the finding's `fixture_path` is
  used. bhf records it relative to the work dir and resolves it there, never
  relative to the current directory; an absolute path from an earlier release
  is first mapped into the work dir holding the finding, so a copied or moved
  work dir runs its own harness. Then `harness_id` is looked up under
  `harnesses/`, `auto/`, `generated_harnesses/` and `build/`. Only when none of
  those exists is an absolute `fixture_path` into another work dir used as
  recorded. To pass `--harness` yourself, a C or C++ harness replays from the
  `build/<id>/main` that `bhf build` stages or from
  `bhf_work/harnesses/<id>/main`. On Windows each harness binary is named
  with `.exe`: `main.exe`, `main_cov.exe`, `main_afl.exe`, and so on.
- **Runner.** `--qemu-user` (with `--qemu-arg`) runs the harness under an
  emulator. Without it, a cross-built harness runs under the emulator its
  build recorded beside it (`bhf_runner.json`), with a note naming it, and a
  harness built for an architecture this host cannot run is refused before it
  runs, with the flag to pass. Under an emulator the sanitizer options get
  `abort_on_error=0` and core dumps are off. `bhf minimize`, `bhf fuzz`,
  `bhf decode-args`, `bhf corpus minimize` and `bhf report --backfill` resolve
  the runner the same way. See
  [Cross-compilation](cross-compilation.md#qemu-user-replay).
- **Protocol.** `bhf fuzz`, `bhf replay` and `bhf minimize` decide how a
  harness takes its input the same way: a `harness-protocol.json` next to the
  binary (written by `bhf project run`; a libFuzzer binary without bhf's
  driver is not framed whatever it declares), the `BHF_FRAMED` marker in a
  launcher script, the libFuzzer runtime in a binary without bhf's driver
  (which decides it before any source beside the binary), a bhf
  `main.c`/`main.cpp` beside the binary or in any harness dir of the work dir,
  bhf's driver strings compiled into the binary (so a binary that `bhf build`
  staged alone into `build/<id>/main` still replays; an Ada harness, which
  also reads `BHF_FRAMED`, is told apart by the version string GNAT's binder
  puts in every Ada main), or a plain libFuzzer source. The summary's harness
  line names the protocol and why.
- **Results stay current.** A `MATCH` stamps `last_seen` in `finding.json`; when
  the work dir has a results index, replay rebuilds it so
  `results/findings.json` and `results/attestation.json` match the files on
  disk. This holds for every kind of finding. A `MISMATCH` or an `UNVERIFIED`
  replay records nothing in the finding (only `replay.log`, or
  `replay-other-harness.log` for another harness).

## Minimizing a Finding

`bhf minimize --finding <id-or-dir>` shrinks a finding's testcase while the
finding still reproduces, and writes `min_testcase.bin` beside it. Without
`--harness` it runs the harness the finding records, found as
[bhf replay](#replaying-a-finding) finds it.

Before it reduces anything, `bhf minimize` runs the testcase and compares
the crash with the finding the way `bhf replay` does, in the environment
`bhf replay` gives the harness (the finding's recorded runtime mode and
injected variables too), and it compares every reduction it tries the same
way. Another crash is refused with exit `3` and nothing is written. A crash
that cannot be shown to be the recorded one is minimized with a note;
`bhf auto` names all such findings in one line.

After an intentional rebuild whose inlining, line numbers or symbolizer
moved the sink, `--allow-other-crash` minimizes against the crash the
harness reports instead. It prints a warning naming what differs and
records it as `minimization.other_crash` in `finding.json`.

A runtime-oracle finding (a failed assertion, a fuzz-controlled format
string) and an input-triggered capability finding minimize the same way:
each reduction must still show what `bhf replay` compares for them, the
oracle's rule, API and site, or the capability with an operand the testcase
reached.

| `--strategy` | Reduces |
|---|---|
| `bytes` (default) | the input's bytes, by delta debugging |
| `typed` | the value of each argument the harness decodes, keeping the input's layout |
| `grammar` | a `--grammar` finding, on its derivation tree |

`--strategy typed` sets each integer or flag to the first of 0, 1, -1 and
its type's limits that still crashes, then moves an integer to the value
nearest zero that does, the boundary where its crash starts. It applies to
an Ada harness and to a generated C/C++ harness, through the
`arg-layout.json` beside it. A finding of another lane, a binary finding and
an on-target transport finding have no argument layout; bhf refuses them by
name, and `--strategy bytes` minimizes them.

`--strategy grammar --grammar <PATH>` minimizes a finding of a `--grammar`
campaign on its derivation tree, so the minimized input is still a sentence
of the grammar; a byte-wise reduction can leave bytes the target's parser
rejects before it reaches the bug. bhf parses the testcase with the grammar
(an Earley parse) and replaces each subtree, outermost first, while the
finding reproduces: with its rule's smallest derivation, with a subtree of
the same rule inside it, or with a smaller production of its rule that
keeps its children. It tries at most 4096 candidates, and the finding's
`minimization` block records `grammar.nodes_before`, `nodes_after`,
`candidates_tried` and `candidates_kept`. A testcase the grammar does not
derive is refused with the byte where its parse stops, and a binary or
on-target transport finding is refused by name. `bhf auto --grammar`
minimizes a finding whose testcase the grammar derives the same way, and
any other byte by byte.

An on-target transport finding minimizes through the transport it was found
on, rebuilt from its profile (`--transport-endpoint HOST:PORT` relocates
it), on the same fault rule and site (see [On-target
fuzzing](on-target-fuzzing.md#4-faults-and-the-real-time-deadline-oracle)).
A session finding minimizes by driving its recorded session again (see
[Stateful protocol sessions](#stateful-protocol-sessions)), and a collector
finding is re-confirmed and kept as it is.

## Crash to PoC, Explanation, and One-Shot Fuzzing

These commands package a finding as a portable proof of concept (PoC) and
explain it. They run offline, use no model, and give the same result for
the same input:

```sh
bhf explain --work-dir bhf_work --finding-id <finding-id>
bhf capsule --work-dir bhf_work --finding-id <finding-id> --tar
bhf verify-poc bhf_work/capsules/capsule_<finding-id>
```

- `bhf snippet [INPUT]` — fuzz one pasted function with no project, build or
  dependencies. It detects the language, writes a one-file project around
  the function, and runs the whole `auto` pipeline on it, in `./bhf_snippet`
  with a 15 s `--per-target-time` by default. Without `INPUT` it reads the
  snippet from stdin (`pbpaste | bhf snippet --lang c`). Use it to try bhf
  on a single routine.
- `bhf capsule` — package a crash into a portable, self-verifying PoC capsule:
  the generated harness, the target sources (and, for C and C++, the project
  headers they include, in their original directory layout, so `#include
  "sub/x.h"` still resolves), the stubs bhf synthesized, bhf's runtime for the
  language, the build settings the harness was built with, the dependencies an
  offline rebuild needs, and the crash input. What a capsule holds and how it
  rebuilds depends on its lane, one per harness language (see the table
  below). Capsules go under `<work-dir>/capsules/` (`--out`), and `--tar` also
  writes a `.tar.gz` of each. The input is the finding's `min_testcase.bin`
  when it reproduces the finding's crash, else its `testcase.bin`; it ships as
  `input/testcase.bin`, and the output and `manifest.json` (`input_source`)
  say which it is. For a C or C++ finding "reproduces" means the rebuilt PoC
  shows the crash the finding recorded, compared field by field as `bhf
  replay` compares it (rule, kind, then sink or site; manifest
  `finding_identity`): a minimized input that crashes another way does not
  ship, and when no input shows the finding's crash the capsule says what the
  rebuilt PoC showed instead (`reproduced: false`, `reproduced_other_crash:
  true`, `other_crash`). A C or C++ runtime-oracle or capability finding is
  packaged too: its capsule records the oracle hit or capability in the
  capsule's paths (`finding_oracle`), and the rebuilt PoC reproduces it when a
  replay under bhf's runtrace shim shows it the way `bhf replay` decides
  (`oracle_comparison`; a failed assertion is also read from the message the C
  runtime printed). The summary counts every runtime finding as written,
  skipped (each with its reason) or failed (each with its error). Every path
  the harness's build and launch files name is relocated into the capsule:
  `build.sh` renders those files into `build/` with the capsule's own location
  and the programs it finds on the host, builds there, and writes `./poc`, so
  the shipped files stay as packaged. The rebuilt PoC is replayed with the
  input protocol the shared detector reads off it: the input file as
  `argv[1]`, or, for an Ada harness, the input piped to stdin with the
  runtime's event log in `$BHF_EVENTS_PATH` (`manifest.json` `protocol` and
  `run`). `manifest.json` also records the programs the rebuild needs and the
  version each one printed when the capsule was made (`requires`), the
  expected crash signature, and the lane's build facts (`build_recipe`).

  For a C or C++ harness the headers that ship are the ones the compiler's
  `-M` lists for the build (when that fails, every header under the include
  roots ships, plus the project headers the sources' `#include` lines reach,
  also through `..`), and the build settings are the Makefile plus what the
  build took from the environment, recorded in
  `<harness dir>/coverage-build-recipe.json` by `bhf auto` and by `bhf build`:
  the language standard (`CXX_STD`/`C_STD` or the dialect ladder's), the
  extra sources and include dirs, the `AUTO_EXTRA_INCLUDES` and
  `AUTO_EXTRA_LDFLAGS` words, the `[toolchain]` flags, the work dir's
  compatibility flags (`-fcommon` for C; for C++ clang's `-fms-extensions`
  and gcc's `-fpermissive`, which `build.sh` picks by the family of the
  compiler that runs it, and `build.ps1` spells `/permissive` for cl and
  clang-cl) and the compiler family. A forced include that names
  no file next to the build (`-include iostream`, from a compile database,
  `AUTO_EXTRA_INCLUDES` or the toolchain flags) is a header the compiler finds
  on its own search path, and `build.sh` passes it as written. The stubs and
  forwarding
  headers bhf synthesized name the headers they need by absolute path; the
  capsule ships those headers and rewrites each such `#include` relative to
  the stub. A capsule is portable when no file it ships and no manifest field
  names the work dir or the scanned tree (the manifest's `sink` names the file
  as the capsule ships it); otherwise the summary says `⚠ not portable:
  <file> names <path>` and the manifest records `portable: false` and the
  `portability` problems. The compiler is `$CC`/`$CXX`,
  else the family that built the harness binary (a harness bhf built with gcc
  rebuilds with gcc), and `build.sh` asks the compiler that runs it which
  family it is and passes that family's sanitizer flags, as the harness
  Makefile does. A launcher in front of the compiler (`ccache clang++`) runs as
  its words. For a C++ capsule whose compiler cannot find the C++ standard
  library itself, the scan and `build.sh` fall back to the newest installed
  libstdc++ headers and library, else (a libc++ host) to `-stdlib=libc++` or
  an installed libc++ header dir; `build.sh` probes for them on the host that
  runs it. A rebuild that fails is reported by the compiler's first `error:`
  line (or MSVC's `error C2065:` / `error LNK2019:`). The capsule is staged in a
  scratch dir and moved into place only when complete, so a refused or failed
  finding leaves nothing behind; it is built and replayed from a copy outside
  the work dir, so the build reaches nothing beside the capsule. Where that
  copy cannot run what was built in it (a temp dir mounted noexec: the PoC, or
  a build script the build runs, `Permission denied`), it is built and
  replayed in place.

  A C or C++ capsule also ships `build.ps1`, its Windows build, which needs no
  POSIX shell (`powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1`,
  then `.\poc.exe input/testcase.bin`; manifest `build_windows`, `run_windows`
  and `requires_windows`). It builds the way the harness Makefile builds on
  Windows, linking bhf's driver (`runtime/bhf_driver.c`), with the compiler
  family recorded for the harness (its `bhf_toolchain.stamp`; for the MSVC
  lane, the compiler bhf's cl front end ran, recorded in
  `coverage-build-recipe.json` `msvc_compiler`): cl gets `/fsanitize=address`
  and cl's SanitizerCoverage flags (`inline-8bit-counters`, `edge`,
  `trace-cmp`, `trace-div`, linking `libsancov.lib`), spelled by the bhf-cl
  front end's translation, and bhf's weak repair stubs compile from MSVC
  copies (`stubs_msvc/`); clang-cl gets the same without `libsancov.lib`;
  clang (targeting MSVC) gets the Makefile's ASan, UBSan and coverage flags.
  `$CC`/`$CXX` names another compiler, and when it is unset and the recorded
  one is not installed, the script takes the first of cl, clang-cl and clang
  that is (manifest `build_recipe` `windows_compiler`,
  `windows_compiler_dialect`, `windows_compiler_source`). Each compile runs
  from a response file, so arguments with spaces and quotes stay whole;
  outside a Developer shell the script takes the environment cl and clang-cl
  read (`INCLUDE`, `LIB`, `PATH`) from the newest Visual Studio instance with
  the C++ toolset; and it copies the sanitizer
  runtime DLL of the compiler that ran next to `poc.exe`. On Windows, `bhf
  capsule` and `bhf verify-poc` rebuild with `build.ps1`.
- `bhf verify-poc <CAPSULE>` — rebuild a PoC capsule offline in place (or in a
  scratch copy of a `.tar.gz`) and assert the recorded crash reproduces. The
  path may be absolute or relative to the current dir. It
  needs only the programs the manifest lists under `requires` and a shell, so
  a capsule verifies on a clean machine without bhf's work dir or the scanned
  tree; it checks them first and names each missing one and the variable that
  overrides it. On Windows it rebuilds a C or C++ capsule with `build.ps1`
  and checks the programs `requires_windows` lists, so no POSIX shell is
  needed. A path that does not exist is reported as such, with the
  `bhf capsule` command that writes it. A C or C++ capsule's replay is
  compared with the finding's identity the way `bhf replay` compares it:
  `PASS` names the compared fields, and another crash, of the same sanitizer
  class or not, is `MISMATCH` with each differing field (exit 1). A rebuilt
  PoC that dies by a signal without a sanitizer report passes with its site
  not compared, and a capsule packaged before it recorded the finding's
  identity is compared by sanitizer class, with a note saying so. A capsule
  of a finding that recorded no sanitizer report has no identity to compare;
  its manifest says why (`identity_comparison` `verdict: none`, `reason`) and
  verify-poc prints that reason. A capsule whose own rebuild failed when it
  was packaged (manifest `rebuilt: false`, `build_error`) is reported as such
  when its rebuild fails here too, with both errors; one that rebuilds here
  but whose input does not crash says that instead. A capsule that records a
  `finding_oracle` is verified by replaying its input under the runtrace shim:
  `PASS` names the compared fields, and a replay that does not show it is a
  `FAIL` with what differed.
- `bhf env-capsule` — record and replay the shim-served faked environment so an
  environment-driven crash (missing files, unset env, unreachable sockets)
  reproduces deterministically. It works on the built harness of a native lane
  (C, C++, Ada, Rust, COBOL, Fortran): the runtrace shim is preloaded into the
  harness process, so a statically linked harness (Go) and one that runs in a
  language runtime (Java, C#, Python, JavaScript, TypeScript, Ruby, Perl, PHP,
  Lua) are refused with that reason. The world is recorded under the shim mode
  the finding fired in (`finding.json` `runtime_mode.pass`: `fuzz_driven` or
  `rng`) with the environment variables the fuzz loop injected, which
  `replay.sh` sets too; an Ada harness is fed its input on stdin and its
  unhandled exception in the event log is the crash. The capsule ships the
  first input that crashes under the recorded environment: `min_testcase.bin`,
  then `testcase.bin`, then the corpus input that crashed while recording;
  `manifest.json` (`input_source`) says which.
- `bhf explain` — explain why a crash fired, each claim with its evidence or
  a line saying there is none:
  - the input: `min_testcase.bin` when the finding was minimized, else
    `testcase.bin`, named with its size, and whether it, or its `testcase.bin`
    (the crashing input as found, before minimizing), is one of bhf's built-in
    starting inputs (empty, `A`, `AAAAAAAA`) or a byte-identical copy of a
    seed listed in `auto/seeds.json`; and one `Lineage (testcase.bin):` line
    from `finding.json` `lineage` (see [Seed lineage](auto.md#seed-lineage)):
    `descends from mined seed tests/data/x.bin (sha256 4f1b6e0c2a9d…) after 7
    mutation generations` (or user seed, a start input no seed list names, a
    queue entry with no lineage record, an input bhf generated (no seed): a
    built-in start input, or one a generator built mid-run), `is ... itself,
    unmutated` when the saved input is that seed (`is an input bhf generated
    (no seed) ..., unmutated` when bhf built it), and `unknown (<reason>)`
    when bhf does not know, such as for an AFL++ crash or a finding saved
    before lineage was kept. It names the input the fuzzer saved, before
    minimization; a root is where that input's mutation chain starts. A
    finding that saves no testcase but records a lineage (the MSan and TSan
    corpus replays) gets the same line, headed `Lineage (input sha256 <first
    12 hex digits>…):` for the queue entry it ran, with that entry's full
    sha256 in the section heading;
  - comparison evidence for that input: each input span that reached a
    comparison of the target, with its offset, the operand, what it was
    compared with, whether they were equal, the comparison (`cmp`, `switch`,
    `memcmp`, `strcmp`, ...) and its source position. It is recorded by
    replaying the input with the driver's comparison capture
    (`BHF_CMP_EVIDENCE`): an operand counts only when its bytes occur in the
    input and a replay with those bytes changed shows the operand change with
    them. Flipping input bytes also finds operands computed from them, such
    as a folded `x == 0 || x > 32` range check: every byte of an input of up
    to 32 bytes, and for a longer one first the bytes the harness decodes its
    scalar parameters from (`arg-layout.json`), then byte ranges, halved
    where a flip changed a comparison, down to the bytes, within 256 replays.
    Two replays of the unchanged input bracket the flips, and an operand that
    differs between them (a process id, a clock reading) is not evidence.
    When that search did not cover the whole input (`finding.json`
    `gate_capture.derived_search` `partial`, or `too_long` over 1 MiB), a line
    says `range checks computed from input bytes were searched in N of M
    bytes`, also beside the comparisons that were found. Comparisons the
    harness makes before entering the target are discarded, and later ones in
    harness code are left out when `llvm-symbolizer` can locate them. Under
    AddressSanitizer the `memcmp`/`bcmp` interceptor reports itself as the
    call site; the gate is placed at the first caller frame the driver
    recorded that is not the sanitizer runtime, and reads `site not
    attributable (sanitizer interceptor)` when none resolves. `bhf auto`
    records it after minimization (`finding.json` `gates`); for a finding
    without it, explain replays the input once (nothing is written). An
    AFL++ finding's `main_afl` is compiled without bhf's driver, so its
    evidence is recorded by replaying the input through the driver build
    `main` beside it, built from the same harness source
    (`gate_capture.harness` names it when that replay ran, and explain says
    `replayed through main`). Otherwise it prints `No comparison evidence
    recorded:` and the reason, which says what was not searched (computed
    operands beyond the
    replay budget, comparisons past the driver's 8192-record limit), or, when
    the target made no comparison the driver recorded, how many comparisons
    the run recorded and why each was left out (before the target was
    entered, in bhf's harness code, on pointer values). Only harnesses that
    link bhf's driver record comparisons: those of the C, C++, Rust, Fortran
    and COBOL lanes. A harness that cannot record them says why: an AFL++
    build with no driver build beside it; a lane whose harnesses do not link
    the driver (Python, Java, Go, Ada and the others); a Rust, Fortran or
    COBOL binary without it (built by an earlier bhf or some other way:
    re-run `bhf auto`); a C or C++ harness an earlier bhf generated (rebuild
    it); one this bhf generated whose binary was built some other way; or
    one bhf did not generate. Dictionary tokens found in the input are
    listed as labelled substring matches (at least 3 bytes, at most 3
    occurrences);
  - the harness arguments: the value each parameter was decoded to, from the
    argument trace recorded with the finding. An argument whose input bytes a
    recorded comparison read is tagged `[compared at <file>:<line>]` (the
    comparison's address when it has no source position, or `site not
    attributable (sanitizer interceptor)`); the length of a `(buffer, length)`
    pair, which holds the input's size, is not. The trace was recorded on
    `testcase.bin`; when the input shown is a `min_testcase.bin` with other
    bytes, each parameter is decoded from those bytes with the harness's
    `arg-layout.json` instead, and one it cannot decode statically reads
    `(not decodable statically; testcase.bin: <value>)`. Without the layout
    the table keeps `testcase.bin`'s values and says so. The memory access
    and `Sanitizer report` lines of such a finding say `(recorded on
    testcase.bin, N bytes)`: a value the report names (a shift exponent, an
    index) is that input's, not the minimized one's. WHAT HAPPENED names the
    input shown;
  - the environment: the runtrace events of that input's own replay when the
    runtrace shim was loaded for it, else the harness's last fuzz pass (all of
    its inputs, labelled so), and `environment not observed (runtrace shim not
    loaded)` when the shim was not loaded (`finding.json`
    `runtime_mode.shim_armed`, true only when the fuzz pass's runtrace log
    holds the `shim_loaded` line the shim writes when it first opens the log,
    before any event, even one a library's constructor causes). An
    installed bhf without the shim beside it can be pointed at one with
    `BHF_RUNTRACE_SHIM=/path/libbhf_runtrace_shim.so`;
  - reachability: the verdict and what it rests on. A verdict inferred from the
    entry's signature says it "matches an input-taking shape, so likely
    reachable from input; not proven", naming the parameter it rests on and its
    type as spelled and resolved (``because parameter `buf` (`const u8_t *`,
    resolves to `const uint8_t *`) is a read-only byte buffer``); an unproven
    one says when the classifier read the types with their typedefs resolved,
    and a `static` entry says it has internal linkage; an entry with no recorded
    reachability reads "not assessed". A registered entry point says which call
    in its source file registers it ("is passed to `intConnect` in its source
    file, which registers it as a task, interrupt or callback"), and a channel
    consumer says what its body reads ("reads a message with `mq_receive`", or
    "reads memory through a volatile pointer (the memory-mapped register
    idiom)"); both say "not proven", and a finding recorded before bhf kept
    that call says the call it matched was not recorded. A `Caveat:` line
    follows when the input is empty or all zero bytes (a real caller may
    never pass all-zero arguments) or the method ran on an object bhf's
    harness constructed (a default constructor, a factory, or decoded
    constructor arguments, which a real caller may never produce). An
    overflow of a buffer the generated harness sized itself for a pointer
    parameter it passes without a length (a decoded C string, or a copy of
    the input with no length companion in the harness source) reads
    "precondition-dependent" (verdict `lab_only`). A harness
    buffer passed together with its length, such as the buffer of a
    `(buf, len)` pair, keeps the entry's verdict;
  - the recorded memory access (direction, width, the region hit and its
    allocation site), the sink and frames, and how to fix and reproduce it.

  Each block names its harness. Findings of one root cause (the same
  `cluster_key_full`, such as one site reached through several harnesses; for
  a finding an earlier release keyed on one constant per rule, the key its
  report gets now) are explained once, by the first, which lists the others
  and their harnesses; `--all-members` explains each one. `bhf explain` covers
  runtime crashes (`classification: unhandled`) and oracle findings
  (`oracle_hit`); an oracle finding's WHAT HAPPENED names the oracle, the API
  it watched and its evidence (`Oracle:` and `Evidence:` lines) instead of a
  sanitizer verdict. A `--finding-id` it cannot explain (no such finding, an
  unreadable `finding.json`, or a finding of another classification, such as a
  static scan row) exits 1 with the reason; without `--finding-id`, a work dir
  with nothing to explain exits 0.
- `bhf decode-args [TESTCASE] [--finding <id>|--finding-id <id>] [--harness <bin|dir|id>]` —
  the value each C/C++ harness parameter receives from a testcase: from the
  harness's own argument trace (`BHF_TRACE_ARGS=1`) when its binary runs, else
  (or with `--static`) from its `arg-layout.json`, naming each parameter that
  cannot be decoded statically and why. A `--harness` id is looked up under
  `--work-dir` (`harnesses/<id>`, then `build/<id>`); a `--harness` that names
  nothing is an error saying so. `--json` prints a
  `bhf.decode-args.v1` document. See the
  [C/C++ guide](c-cpp.md#decoding-a-testcase-without-running-it).
- `bhf cartography` — map, by perturbation, which input bytes control which
  sink operand (offset, size, index): the exploit-primitive view of a C or C++
  finding. A SEGV on a wild pointer has no region-relative offset, so its
  bytes are mapped by the faulting address instead: replays run with
  address-space randomization off, and a byte that moves the address is
  `controls_address` (primitive `controlled_address_read`/`_write`). When two
  identical replays fault on different addresses, the bytes are `unknown`
  (primitive `unattributed_crash`); a crash no byte gates is
  `uncontrolled_crash`. Cartography maps the minimized and the original
  testcase and keeps the stronger result, and it also replays the input one
  byte shorter and eight bytes longer: an access whose size follows the
  input's length (a copy of `min(data[0], len - 1)` bytes, which minimization
  pins so no byte flip moves it) is `input_sized_linear_write` (high) or
  `input_sized_linear_read` (medium). Turning randomization off needs the
  `personality(2)` system call, which a container's default seccomp profile
  refuses (Docker's, even with `--cap-add=SYS_PTRACE`). There, cartography
  prints a warning, and a wild pointer's bytes show as `unknown`; run the
  container with `--security-opt seccomp=unconfined` to map them. Heap, stack
  and global overflows are mapped by their region-relative offset and are not
  affected.

`capsule`, `verify-poc`, `cartography` and `env-capsule` work on runtime crash
findings (`classification: unhandled`). The language comes from
`generation-metadata.json` in the harness dir (else the `H-C`/`H-X`/`H-A`...
id prefix, else the driver file the dir holds), and the harness is looked up in
`harnesses/`, `auto/`, `generated_harnesses/` and `build/`, so a harness made
by hand with `generate-harness --id <name>`, `build` and `fuzz` works too.
`capsule` and `verify-poc` take every language below; `env-capsule` the native
ones; `cartography` C and C++ (it maps AddressSanitizer reports). A finding a
command does not take (an oracle hit, `classification: oracle_hit`; a missing
harness or input; a harness its lane cannot rebuild offline) is refused with
its own reason and, when there is one, a command that does reproduce it
(`python3 <finding>/replay.py` when a harness it runs exists, or the built
harness run on the input with the sanitizer options `bhf replay` uses, leak
detection included for a leak finding, under the emulator recorded beside a
cross-built harness). A finding whose harness is gone from the work dir is
told to pass a binary of the harness to `bhf replay --harness`, or to get the
harness back first: `bhf auto` on the tree generates and builds it again, or
`bhf generate-harness <source> --target <function> --id <id> --output
<work>/harnesses` and then `bhf build <work> --harness <id>` (`bhf build`
alone has no harness dir to build from). `replay.py` counts as available when
the harness it would run exists: its recorded `fixture_path`, a relative one
resolved in the finding's work dir (not the current directory), or a built
`main` in the harness dirs. `bhf explain` applies the same first check:
it offers `bhf capsule`/`bhf verify-poc` only for findings whose lane and
harness layout capsule takes, and `bhf cartography` for AddressSanitizer
crashes it can map. For a crash whose capture replay crashed while the
runtrace shim served it faked bytes (a fake file's content, a socket peer's
data, a stubbed dependency's return value; `finding.json`
`gate_capture.served_resources`, recorded only for a replay that crashed, the
same rule env-capsule accepts a finding on) it offers
`bhf env-capsule` first, or says why it does not apply, and flags every
other command, in a trailing `#` comment, as replaying without the faked
environment. A finding of a faking pass (`rng`, `fuzz_driven`) whose
capture did not record what was served gets that comment, and, when no
capture replay ran its harness with the shim (a harness whose driver records
no comparisons, such as an Ada one), a `bhf env-capsule` line whose comment
says it may reproduce the crash and the capture replay could not check.
Injected environment variables alone do not count, since `replay.py` sets
them too. What capsule checks while it packages (dependencies in the local
cargo, module or NuGet cache, the size of the tree it ships, paths it cannot
relocate) can still refuse a finding explain offered; capsule then says why.

Per-lane requirements (a capsule records what it needs in `manifest.json`
`requires`; each program can be overridden by its variable):

| Lane (id prefix) | The capsule ships | Rebuild and replay need | Crash oracle | Refused when |
|---|---|---|---|---|
| C (`H-C`) | driver, target sources and their headers, stubs, C runtime headers and bhf's driver source, `build.sh` and `build.ps1` | `clang` or the compiler that built the harness (`CC`); on Windows (`build.ps1`) the recorded cl, clang-cl or clang | ASan / UBSan report | built with a cross compiler; no `main` rule in the Makefile |
| C++ (`H-X`) | as C | `clang++` or the compiler that built the harness (`CXX`); on Windows (`build.ps1`) the recorded cl, clang-cl or clang++ | ASan / UBSan report | as C |
| Ada (`H-A`) | `bhf_build.gpr`, `adafuzz_runtime.gpr` and the runtime sources, `src_instrumented/`, the generated harness, the stub packages, the operator projects it extends or `with`s (with the scanned tree) | `gprbuild` (`GPRBUILD`) and GNAT (`GNAT`) | unhandled exception in the event log, or a sanitizer report | never built (no `build/<id>/bhf_build.gpr`); built for another target; a project file it names lies outside the scanned tree |
| Rust (`H-R`) | harness crate, bhf's driver, the `rust_runtime` crate, the scanned tree, `vendor/` (`cargo vendor --offline`) when the lock file names crates.io or git packages | `cargo +nightly` through rustup (`BHF_CARGO`; `BHF_RUST_NIGHTLY` names the nightly) and `clang` (`CC`) | the panic, or an ASan report | a package not in the local cargo cache |
| Go (`H-G`) | harness module, the scanned tree, `vendor/` when the module needs modules from outside it | `go` (`GO`) | the recovered panic (`== bhf go finding:`) | a module not in the local module cache |
| Java (`H-J`) | launcher, harness source, bhf's JVM agent jar, the scanned tree, dependency jars on the classpath | `javac` (`JAVAC`) and `java` (`JAVA`) | `== bhf JVM finding:` | target classes built by Maven or Gradle |
| C# (`H-S`) | harness project, bhf's .NET driver, the entry, the scanned tree, `SharpFuzz.Common.dll`, the NuGet packages the restore resolved | the .NET SDK, `dotnet` (`DOTNET`) | `== bhf csharp finding:` | a NuGet package not in the local package cache |
| Python (`H-P`) | launcher, bhf's driver, decoder and coverage helpers, the generated harness, the scanned tree | `python3` (`PYTHON`) | `== bhf python finding:` | the run recorded no scanned tree |
| JavaScript (`H-N`) | launcher, bhf's driver, the scanned tree (with `node_modules`) | `node` (`NODE`) | `== bhf js finding:` | as Python |
| TypeScript (`H-T`) | as JavaScript, plus the transpiled target | `node` (`NODE`) | `== bhf js finding:` | as Python |
| Ruby (`H-U`) | launcher, bhf's driver, the generated harness, the scanned tree | `ruby` (`RUBY`) | `== bhf ruby finding:` | as Python |
| Perl (`H-L`) | launcher, bhf's driver and coverage module, the generated harness, the scanned tree | `perl` (`PERL`) | `== bhf perl finding:` | as Python |
| PHP (`H-W`) | launcher, bhf's driver, the generated harness, the scanned tree | `php` (`PHP`) | `== bhf php finding:` | as Python |
| Lua (`H-V`) | launcher, bhf's driver, the generated harness, the scanned tree | `lua`, `lua5.4`, `lua5.3` or `luajit` (`LUA`) | `== bhf lua finding:` | as Python |
| COBOL (`H-B`) | as C, with the `cobc -C` translation and the COBOL source | `clang` (`CC`) and the GnuCOBOL runtime (`cob-config --libs`, else `-lcob -lm`) | libcob's runtime check (`libcob: ... error:`) | as C |
| Fortran (`H-F`) | as C, with the Fortran sources (`harnesses/<id>/fortran-build.json` records how each object was compiled) | `clang` (`CC`) and `gfortran` (`FC`) | ASan report | as C |

The lanes that relocate their harness (all but C, C++, COBOL and Fortran)
refuse a tree they would have to copy that holds more than 20,000 files or
256 MiB, and a build file `build.sh` renders that still names the work dir or
the scanned tree after relocation. A text file they ship unchanged (a target
source, say) that names them is reported in a warning when the capsule is
written. The C, C++, COBOL and Fortran lanes ship the sources and headers the
build reads instead; the header copy stops at 10,000 files or 128 MiB, with a
warning.

A program `build.sh` finds under several names is met by any of them: the Lua
capsule records the interpreter it was packaged with and the others
(`requires[].alternatives`), so a capsule made where `lua` is installed
verifies where only `lua5.4` is. Setting the override variable checks that
program alone.

An Ada exception finding is checked against the exception the finding
recorded (manifest `finding_signature`). A rebuilt PoC that raises another
exception does not count as reproducing it (`reproduced: false`,
`reproduced_other_crash: true`), and `verify-poc` reports `MISMATCH` with the
expected exception.

Exit codes: each of the four exits non-zero when a requested `--finding-id` is
refused (or cannot be packaged, mapped or captured, or its capsule did not
reproduce), and when a run without `--finding-id` writes nothing although the
work dir has runtime findings. A work dir with no runtime findings exits 0.

## Reports

`bhf report` has two modes:

- **Work-dir mode**, the default, with neither `--findings` nor `--out`,
  rebuilds `<work-dir>/results/` in place (`--work-dir`, default
  `bhf_work`). Every command that writes findings runs the same rebuild;
  run `bhf report` to refresh the index after the fact.
  `results/findings.sarif` and `results/findings.csv` are always written, so
  `--sarif` and `--csv` change nothing in this mode.
- **Explicit mode**, with `--findings <DIR>`, `--out <DIR>` or both, reports
  over any findings directory and writes a standalone Markdown and JSON
  report to `--out`, leaving `results/` as it is. `--sarif` and `--csv` add
  `<run>.sarif` and `<run>.csv` there (`<run>` is `--run`, default `last`).

`--junit` (a switch; it takes no path) writes `<run>.junit.xml`, in `--out`
or, in work-dir mode, in `<work-dir>/results/report/`, with the
`bhf.report.v2` snapshot. `--baseline <PATH>` and `--model <PATH>` write that
snapshot there as well, and a later `--baseline` comparison reads it.
`--gitlab-sast` (a switch, work-dir mode) writes `results/gl-sast-report.json`,
a GitLab SAST report of the findings (see [CI](ci.md#gitlab-ci)).

`--backfill` (work-dir mode) first replays, against its harness and as
`bhf replay` does, each C/C++ sanitizer finding that has no `sanitizer.log`,
such as a finding migrated from a 0.2.x work dir. When the replay is a
`MATCH`, it writes `sanitizer.log`, the crash frames and the memory access
into the finding; the finding's id and signature stay the same. A finding
that records no crash location is backfilled only from the build it was
recorded with (its `build.binary.sha256`). A finding with no `decoded.json`
whose harness has the argument trace also gets its decoded arguments
(`decoded.json` and `decoded_args`), from one run with `BHF_TRACE_ARGS=1`,
and a runtime finding whose harness records comparisons gets its input's
comparison evidence (`gates` in `finding.json`). The backfill lists, and
leaves as they were, the findings whose harness is gone, whose replay
crashes elsewhere, that record no crash location and whose harness is not
their recorded build, or whose replay is unsymbolized. To symbolize, the
backfill puts the LLVM toolchain `bhf auto` uses on `PATH`; where there is
none, put `llvm-symbolizer` on `PATH` or set `ASAN_SYMBOLIZER_PATH`.

`bhf model train --labels <FILE> --out <MODEL>` trains the confidence model
`bhf report --model` applies. The labels file is a JSON list of records (or an
object whose `labels` holds that list); each record has a `label`,
`true_positive`, `false_positive` or `low_value`, and its finding, either
inline as `finding` (a `finding.json` object) or as `finding_path` (a
`finding.json`, or the finding's directory, relative to the labels file):

```json
[
  {"label": "true_positive", "finding_path": "bhf_work/results/findings/F-0001"},
  {"label": "false_positive", "finding": {"rule_id": "BHF-205", "kind": "signed-integer-overflow"}}
]
```

## Static Analysis and SLOC

`bhf scan <PATH>` indexes an Ada, C or C++ source file or tree. It writes
`<work-dir>/scan_index.json` (`--work-dir`, default `bhf_work`), prints the
same JSON summary to stdout, records each skipped source file with a
diagnostic, and exits `1` only when it scanned no supported source file.

`bhf static-scan <PATH>` runs the static rules over a source tree. It
writes `static-report.json` and `static-report.md` to
`<work-dir>/results/static/` (`--work-dir`, default `bhf_work`) and rebuilds
`results/`. `--out <DIR>` writes them to that directory instead, leaves
`results/` as it is, and prints a note saying so.

| Option | Effect |
|---|---|
| `--sarif` | also write `static-report.sarif` |
| `--suppressions <JSON>` | exact rule/path/line suppressions |
| `--baseline <static-report.json>` | mark each finding `new`, `unchanged` or `resolved` against an earlier report |
| `--policy <JSON>`, `--enable-rule <ID>`, `--disable-rule <ID>` | policy-as-code rule filters |
| `--fail-on low\|medium\|high\|critical` | exit non-zero when an active finding meets the severity, for a CI gate |
| `--since <rev>` | scan only the files changed since a git revision |
| `--jobs <N>` | the number of parallel file workers |
| `--max-memory-mb <MB>` | the scan's resident-memory ceiling |
| `--sloc <FILE>` | also write a per-language SLOC breakdown |
| `--external-tools` | also run the installed gosec, Bandit, semgrep and GNATcheck as subprocesses and write their findings to `<out>/external-findings.json`; the license profile gates them, and this flag selects `external-tools` unless `BHF_PROFILE` names another |

In work-dir mode, `--since <rev>` replaces
`results/static/static-report.json` with the diff-scoped subset, so
`results/` then holds only those static findings; run a full `static-scan`
(without `--since`) afterwards to get the rest back. An explicit
`--out <work>/results/static` writes into `results/` without rebuilding the
index; run `bhf report` afterwards to fold the new static report into
`findings.json` and `INDEX.md`.

At the memory ceiling the scanner stops admitting new work and records an
analysis gap. Target discovery (`bhf auto`, `bhf list targets`) stops the
same way and says its list is partial. On Linux the default ceiling is the
smaller of 80% of the host's available memory and 70% of the cgroup memory
limit. On Windows it is 80% of the available physical memory, measured
against the process's working set. Windows pages a process that runs out of
memory instead of killing it, so there the ceiling keeps the host responsive
at the cost of the rest of the scan; raise it with `--max-memory-mb` on a
host with little memory free. A source file larger than 1/64 of the ceiling
(at least 16 MiB, at most 256 MiB) is skipped and recorded as a gap;
`BHF_MAX_FILE_BYTES` sets that cap exactly. On other hosts bhf does not
measure resident memory, so no ceiling applies and the file cap is 64 MiB.
On an 8 GiB host, start with `--jobs 2 --max-memory-mb 4096`.

`--sloc <FILE>` writes a per-language SLOC breakdown (`LANGUAGE`, `FILES`,
`TOTAL`, `COMMENTS`, `BLANKS`, `SLOC`) with the scan. A `.json` extension
writes JSON, and any other name an aligned text table. A relative path is
written into the report directory, beside `static-report.json`; an absolute
path is written as given. Comments are counted per language (Ada `--`,
C-family `//` and `/* */`, hash comments, Perl POD, Python docstrings), and
the scan's dependency and build-tree pruning applies, so vendored code,
`node_modules` and `.venv` are left out. `bhf auto --sloc <FILE>` writes the
same breakdown; there a relative path lands in `<work-dir>/auto/`.

`bhf sloc <PATH>...` counts lines without scanning: it runs the SLOC tree
walk alone, without the parse and rules that `static-scan --sloc` runs. It
takes one or more roots and prints a table per root, plus a grand total when
there are several, to stdout or to `--out`. A `.json` `--out`, or `--json`,
writes JSON with a corpus-wide `total.code_lines`.

```sh
bhf sloc path/to/src              # text table to stdout
bhf sloc repos/* --out sloc.json  # whole corpus as JSON, with the grand total
```

### What the static rules report

- A cross-file interprocedural taint trace from source to sink. It traces
  command execution in Ada, C, C++, Go, Rust, Java, Python and Perl, and
  the same engine confirms path traversal, SQL injection, SSRF, XXE, LDAP
  injection, unsafe reflection, uncontrolled allocation size, open redirect,
  and log injection or log forging where the language has modelled sinks. A
  finding carries its source-to-sink trace and replaces a lower-confidence
  pattern finding at the same site. The trace follows local assignment
  aliases and Ada named-argument mapping; stops at sanitizers and constants,
  language-standard shell quoters included; resolves C++ local calls by
  namespace and class, member calls on typed objects, `this` and
  initialized objects, and overloads by arity; matches comments with string
  literals taken into account; and records an unresolved-call gap where
  source is missing.
- CWE, CERT and MISRA-oriented seed rules for unsafe string copy,
  path-controlled file opens, environment reads, unchecked integer
  conversion, and non-literal format strings.
- Ada structural rules, which read a statement and scope model of the
  source: suppressed index, range and overflow checks, access values forged
  by `Unchecked_Conversion`, address overlays, local `'Unchecked_Access`
  escapes, double free and use after free through an alias, unprotected task
  writes, non-constant spawns, SQL concatenation, unsafe C imports, leaked
  `New_String`, secrets in logs, exceptions escaping C exports or
  `Finalize`, peer-sized `String'Input`, predictable random values and
  MD5/SHA-1 password hashes, and broad `when others => null` handlers. See
  the [Ada rule design](../designs/2026-10-16-ada-static-rules.md).
- Framework and embedded-browser hardening checks for Django deployment
  settings (`SECURE_SSL_REDIRECT`, HSTS, proxy HTTPS state, nosniff,
  referrer policy, CSRF and session cookies), Flask host and CSRF controls,
  Electron renderer isolation, and Qt WebEngine settings such as sandboxing,
  mixed content, local file and remote URL access, plugins, clipboard,
  WebRTC local IP exposure, screen capture, canvas readback, and hyperlink
  auditing.
- Path predicates, blocked-path demotion, actionability metadata, triage
  states from baselines and suppressions, and SARIF related locations for
  trace steps.

The rules match source patterns, with the taint tracking described above.
[Static CWE coverage](static-cwe-coverage.md) maps the CWEs they detect in
each language.

## Binaries Without Source

### Inventory: `bhf binary scan`

`bhf binary scan <PATH>` writes `binary-inventory.json` (into `--out`,
default `bhf_work/binary`) with offline metadata for ELF, PE and Mach-O
files, `ar` archives (static `.a` libraries and Debian `.deb` packages), and
raw firmware-style blobs. It walks containers recursively: a `.deb`'s
`data.tar.*` and `control.tar.*` members are decompressed (gzip, xz or zstd,
in-process, with no external tool) and walked as tar archives, so each
binary inside is inventoried with its container path, such as
`pkg.deb!data.tar.zst!usr/bin/foo`. Decompression is size-capped
(`--max-bytes`, else 1 GiB) and the nesting depth is bounded, so a
decompression or recursion bomb is skipped. `--max-bytes <N>` also skips
each file or archive member larger than `N` bytes, and `--cve-db <FILE>`
matches the inventoried components against an offline CVE database.

For each binary the inventory records:

- format, architecture, bitness, endianness, size, SHA-256, and ELF build-id
  notes;
- producer and toolchain provenance: GCC, clang, Go and Rust versions from
  embedded strings;
- for a static Go binary, the module dependency tree from its embedded
  buildinfo, as `go version -m` prints it, with the Go standard library as a
  `pkg:golang/stdlib@goX.Y.Z` component, so version-gated Go standard
  library CVEs match;
- the entry point and header layout, and the symbol and debug-info state;
- exact import and export names, from the ELF and Mach-O symbol tables and
  from PE import thunks and the export directory, and the risky import APIs
  among them;
- dynamic library, interpreter and RPATH evidence (ELF `PT_INTERP`,
  `DT_NEEDED`, `DT_RPATH` and `DT_RUNPATH`, PE import descriptors, Mach-O
  dylib load commands), and the ELF link mode, static or dynamic, from
  `PT_INTERP` and `DT_NEEDED`;
- entropy and packed-binary evidence, and named sections and segments;
- the exploit-mitigation posture, read the way `checksec` and `winchecksec`
  read it:
  - ELF: RELRO (Full or Partial, from `PT_GNU_RELRO` and `BIND_NOW`), stack
    canary, PIE (a PIE executable told apart from a shared object by
    `PT_INTERP`, as checksec does), NX/executable stack (`PT_GNU_STACK`),
    and `_FORTIFY_SOURCE`;
  - PE: ASLR (`DYNAMIC_BASE`), DEP (`NX_COMPAT`) and Control Flow Guard
    (`GUARD_CF`) from the `DllCharacteristics` field, and Authenticode
    signing (the Security data directory);
  - Mach-O: `MH_PIE`, a non-executable stack (`MH_ALLOW_STACK_EXECUTION`)
    and code signing (`LC_CODE_SIGNATURE`);
- credentials in the binary's strings: AWS access keys, GitHub, GitLab,
  Slack, Stripe, Google API and OAuth, npm, PyPI and SendGrid tokens, and PEM
  private keys, the provider set of the source-tree BHF-429 scan. Each
  carries a CWE (`CWE-798`, or `CWE-321` for a private key), is redacted in
  the report, and is promoted to high-priority triage;
- infostealer indicators: embedded browser credential-store file names and
  Discord or Telegram exfiltration endpoints, the compiled counterpart of the
  source-side supply-chain rules;
- triage risk factors, container and member provenance, skipped malformed
  inputs, and size-limit skips.

Writable or relative RPATH/RUNPATH entries are promoted to loader-path
review triage. High entropy, UPX or other packed section names, sections or
segments that are both executable and writable, and an executable stack
(`hardening:nx_disabled`) are promoted to packed-binary or binary-layout
review triage.

### Functions, strings and xrefs: `bhf binary adapter`

`bhf binary adapter <BINARY> --adapter mock|rizin|ghidra|angr --out <DIR>`
writes `binary-adapter-report.json` (`bhf.binary.adapter.v1`). It holds:

- `functions`: name, address, size, signature, and `imported` for an import
  stub;
- `call_graph`: caller and callee by name;
- `strings`: address, value and section, without the symbol-table sections;
- `xrefs`: from, to, and `kind` `call`, `code`, `data` or `string`;
- `truncated` and `errors`;
- `target_sha256`, the analysed binary's hash.

Addresses are the binary's link-time virtual addresses, as its headers and
`nm` give them; a PIE's are offsets from 0, whatever base the tool loaded it
at. bhf runs each tool as a subprocess, with a fixed command or a bundled
script:

| Adapter | Tool (`--tool` names another) | What runs |
|---|---|---|
| `rizin` | `rizin` | `rizin -q -c 'aaa; aflj; axlj; izj'` |
| `ghidra` | Ghidra's `support/analyzeHeadless` (Ghidra 12 needs a JDK 25) | an import and auto-analysis in a throwaway project, then the bundled `BhfExport.java` post-script |
| `angr` | a Python that imports `angr` | the bundled `angr_export.py`: CFGFast over the main object, with data and cross references |
| `mock` | none | reads `--mock-output` JSON, for contract tests of a consumer |

The `rizin`, `ghidra` and `angr` adapters need `--profile external-tools` or
`research-lab`; the default `strict-permissive` profile refuses them. Each
run is bounded by `--timeout-secs` (default 900) and 128 MiB of output. Each
array keeps at most 50,000 functions or strings, or 200,000 call edges or
xrefs; `truncated` names an array that was cut and how many entries it kept.
The report's `status` is:

- `ok`, exit 0, with the analysis;
- `error`, exit 1, when the analysis failed (`timeout`, `tool_error`,
  `output_too_large` or `bad_output`), with the tool's last output;
- `skipped` with `tool_not_found`, exit 1, when the tool is missing or the
  Python cannot import angr.

`bhf binary fuzz` and `bhf binary scan` take a report with
`--adapter-report <binary-adapter-report.json>`. Only an `ok` report is
taken. From it they get:
- dictionary tokens: the strings the binary's code references first, then
  its other data strings, at most 256 of 2 to 64 bytes. `binary fuzz` seeds
  the builtin engine's mutation dictionary with them, and afl-fuzz's `-x`.
- a ranking of the binary's own functions as fuzz entry points. A call to
  an input-handling import (`strncmp`, `memcpy`, `read`, `sscanf`, ...)
  scores 3, a referenced string 2, a call to another of its functions 1;
  the C runtime's functions are left out. The first is the candidate
  persistent address.

`binary fuzz` records them in its run JSON's `adapter_report`: the token
count, the top ten functions with their reasons, and `persistent_candidate`.
`binary scan` adds the same object as `adapter` to the inventory entry whose
SHA-256 is the report's `target_sha256`; a report of a binary the scan did
not inventory is exit 1.

### Black-box fuzzing: `bhf binary fuzz`

`bhf binary fuzz <BINARY>` runs an executable you have no source for. It
delivers each input on stdin or as a file (`--input-mode stdin|file`, default
`stdin`), starts from `--seed-input` and `--seed-file` seeds, kills an
execution after `--timeout-ms` (default 10000), and takes repeatable
`--env KEY=VALUE` launch settings. The target runs with your user's access
and no sandbox; `--sandbox` only sets the label in each finding's
provenance, so run an untrusted binary in a VM or container. Crashes and
timeouts are written under
`<work-dir>/results/findings/BF-NNNN/` as `kind: binary_crash` findings, with
the command, input mode, testcase, environment, binary SHA-256, a stderr
excerpt, and the exit or timeout signature. `bhf replay`, `bhf minimize` and
`bhf ci --fail-on` take these findings like any other.

A manually authored binary-only harness can name a runner and fixed target
arguments: `--runner <PROG>` launches the target under an emulator/loader (e.g.
`wine`, `qemu-x86_64`) with repeatable `--runner-arg`, and repeatable
`--target-arg` passes fixed arguments to the target before the fuzz input. A
literal `@@` among the target args marks where the input-file path goes (file
mode); without one, file-mode input is appended last. An argument that
starts with `-` takes the `=` form (`--target-arg=--mode`). For example, a
Wine/PE harness that loads a stock vendor DLL:

```sh
bhf binary fuzz ./stock_dll_harness.exe --runner wine \
  --target-arg=--mode --target-arg fuzz --input-mode file
```

The runner, runner args, target args, and the full `@@`-marked argv are
recorded in the finding, so `bhf replay` and `bhf minimize` reproduce the
exact launch. `--runner` is builtin-engine only (afl-qemu and afl-frida run
the binary under QEMU or Frida themselves); `--target-arg` applies to every
engine.

`--engine` selects the execution engine:

| Engine | What runs |
|---|---|
| `builtin` | the seeds, then a blind havoc loop: each input is a seed with 1, 2 or 4 byte-level mutations stacked on it, from `--rng-seed`, with no coverage feedback, until `--iterations` (default 256), `--time` or the first crash |
| `afl-qemu` | coverage-guided mutation of a binary-only or foreign-architecture target through AFL++'s QEMU mode (`afl-fuzz -Q`) |
| `afl-frida` | AFL++'s Frida mode (`afl-fuzz -O`), which instruments the binary as it runs on the host CPU, for a native binary that QEMU mode emulates poorly or slowly |
| `auto` (default) | `afl-qemu` when its toolchain is present, else `builtin` |

The builtin engine's run JSON says what it did: `engine`, `fidelity` with
`seeds_run` and `mutated_inputs`, and `degraded: true` with a
`degraded_reason` that names the missing afl-qemu tool when `auto` fell
back. bhf finds `afl-qemu-trace` through `BHF_AFL_QEMU_TRACE`, `PATH`,
`AFL_PATH` and the AFL++ install directories, and `afl-frida-trace.so`
through `BHF_AFL_FRIDA_TRACE`, `AFL_PATH`, the `lib/afl` beside `afl-fuzz`
and the install directories; the bhf container image ships both. Under
`afl-qemu` and `afl-frida`, `--timeout-ms` is passed to `afl-fuzz` as the
per-execution timeout (`-t`), so the mutation campaign and the crash-replay
oracle share one policy, and `--mem-mb <MiB|none>` sets the child memory
limit (`afl-fuzz -m`). It defaults to `none` because QEMU mode maps a large
virtual address space and a tight cap aborts the campaign. The run
provenance JSON records both limits, `engine`, the trace program or library,
`executions`, and a `fidelity` object: the coverage source, `cmplog`,
`edges_found`, and the persistent and entry addresses.

afl-fuzz normally binds itself to a free CPU core. When bhf runs on only some
CPUs (`taskset`), bhf sets `AFL_NO_AFFINITY=1` so afl-fuzz stays on them.
When other CPU-locked processes hold every core, afl-fuzz refuses to start
(`No more free CPU cores`), and bhf runs it again once with
`AFL_NO_AFFINITY=1`. The run JSON's `no_affinity` records why afl-fuzz ran
unbound: `pinned`, `no_free_core`, or `requested` (`AFL_NO_AFFINITY` was
already set). It is absent when afl-fuzz bound a core itself. The AFL++ lane
for source builds does the same; see [C and C++](c-cpp.md#findings).

The two AFL++ modes also take:

- `--persistent-addr <ADDR>` — run the target in a persistent loop from this
  address (hex), restoring its registers on each pass, so the binary is not
  started again for every input: `AFL_QEMU_PERSISTENT_ADDR` with
  `AFL_QEMU_PERSISTENT_GPR=1`, or `AFL_FRIDA_PERSISTENT_ADDR`. Point it at a
  function that reads one input and returns, such as the one `main` calls
  with the input file's path; the loop ends where that function returns.
  For a position-independent binary the address is where the emulator loads
  it, which differs from what `nm` prints; a non-PIE build is simpler to
  point at.
- `--entrypoint <ADDR>` — start the fork server at this address (hex)
  instead of the binary's entry point (`AFL_ENTRYPOINT`), so each run skips
  the start-up before it.
- `--no-cmplog` — run without CmpLog. By default `afl-fuzz` runs `-c 0`: it
  logs the target's comparisons and puts their operands into the input, which
  solves a magic value the havoc stage rarely guesses.

```sh
bhf binary fuzz ./parser --engine afl-qemu --input-mode file \
  --seed-file samples/record.bin --persistent-addr 0x4011b6 --time 10m
```

### Firmware rehosting: `bhf binary rehost`

`bhf binary rehost <IMAGE>` fuzzes an unmodified Cortex-M firmware image (an
ELF, or a raw image with `--base`) in bhf's own emulator. The core starts
from the reset vector, and basic-block edge coverage steers the mutation.
Each input reaches the firmware in either or both of two ways:

- written into a fixed buffer: `--input-buffer` (an address or ELF symbol),
  with `--input-size`, `--input-length` and `--inject-at`;
- through MMIO models of the firmware's peripheral reads:
  `--mmio ADDR[@PC]=MODEL` (`passthrough` from the input, `constant:VALUE`
  or `bitextract:MASK`), `--mmio-models FILE`, and
  `--mmio-default zero|passthrough`. Before the campaign bhf infers
  bit-extract models for polling loops on a status register
  (`--no-mmio-inference` turns that off). `--svd FILE` takes the peripheral
  windows from the part's CMSIS-SVD file, so an access between its
  peripherals is an invalid access.

Interrupts the firmware enables are raised on a schedule the input chooses:
each tick (`--interrupt-interval`, default 1000 instructions) takes one
input byte that picks the interrupt and the wait to the next tick, and a
sleeping core runs on to the next tick (`--no-interrupts` raises none).
Addresses are hex, `0x` optional, as `nm` prints them.

An invalid memory access, a bad PC or a HardFault is a `kind: rehost_fault`
finding, which `bhf replay` reproduces through the recorded machine setup
and MMIO models. Each carries the fidelity label `rehosted,
peripheral-modelled` (its `fidelity_caveat` in `results/`). See [On-target
fuzzing §9](on-target-fuzzing.md#9-rehosting-a-firmware-image-no-source-bhf-binary-rehost)
for the flags and the fidelity.

## Fake CORBA and IDL Dictionaries

`bhf fake-corba <work-dir> --idl <file.idl>` writes Ada mapping packages
(Helper, Skel and Stub) for the IDL model; `--ros-interface` translates a ROS
`.msg`, `.srv` or `.action` file through the same pipeline, and
`--idl-define` and `--idl-include-dir` drive the IDL preprocessor. When the
IDL or the translated ROS interfaces hold reusable tokens, it also writes
`fake_corba/dictionary.txt`: module, interface, operation, struct, enum,
exception, typedef, constant, union and case-label names, and constant
values. `bhf fuzz` falls back to this work-dir dictionary when a harness has
no dictionary of its own, and the built-in engine uses its tokens as
insertions and in the structured inputs of `--structured-inputs`. See
[Fake CORBA](fake-corba.md).

## Introspection

`bhf introspect <PATH>` lists the fuzz targets it discovers in a source tree
and, when `<work-dir>/auto/run.json` exists, compares them with that earlier
`bhf auto` run. Each target is marked as fuzzed, built but not fuzzed,
blocked at build or link, unsupported, or new since that run.

It also builds a static call graph of the tree, for C/C++ and for Ada. The
Ada call graph resolves simple local calls; package-qualified calls in a
package body, such as `Helpers.Helper;`; parenthesized calls whose argument
count matches the discovered callee; grouped formal parameter lists, such as
`procedure Helper (Left, Right : in String)`; defaulted formals, such as
`procedure Helper (Required : in String; Optional : in String := "fallback")`;
body headers whose profile and `is` are on separate lines; and parameterless
procedure statements, such as `Helper;`.

From the graph and the earlier run, `introspect` reports coverage blockers:

| Blocker | When | Recommendation |
|---|---|---|
| `static_reachability_gap` | a fuzzed target reaches, directly or through a call chain, a discovered target that was not in the earlier run | add or rerun a harness for the blocked callee; the blocker carries its depth and a `call_chain` such as `parse_packet -> parse_header -> parse_magic` |
| `unreached_public_target` | a public target was not in the earlier run, and no fuzzed static caller explains it | add or run a harness |
| `unresolved_static_call` | a fuzzed target makes a project-local call the graph cannot resolve, such as a missing Ada statement call (`Missing_Helper;`) or an Ada arity mismatch (`Helper (Input);` when only `Helper;` exists) | add source roots, headers or wrappers so the reachable code is visible |
| `comparison_gate` | CmpLog in an earlier built-in fuzz run (`<work-dir>/fuzz_runs/<harness>-latest.json`) observed comparison operands, and no seed splice candidate existed | add the suggested operand tokens to the seeds or dictionaries |

The top-level `coverage_blockers` array is in priority order: direct static
callee gaps, then deeper static paths, unresolved static calls, dynamic
comparison gates, and public targets that never ran. The JSON output also
has, per target, a `static_reachability` object (direct callees, uncovered
direct callees, reachable callees, uncovered reachable callees, unresolved
calls) and, when the fuzz run recorded CmpLog evidence, `dynamic_coverage`.

```sh
bhf introspect path/to/src --work-dir bhf_work
bhf introspect path/to/src --work-dir bhf_work --format json --top 50
```

Run it after `bhf auto` to see where coverage is missing, or before the
first run to see the highest-priority targets.

## Cleaning a Work Directory

`bhf clean <WORK_DIR>` removes the outputs you select. With no option it
removes nothing and prints `no clean scope selected`.

| Option | Removes |
|---|---|
| `--compact` | disposable compiler caches and scratch files; findings, reports, corpora, checkpoints, generated source and replay binaries stay |
| `--build` | build outputs, after the `--compact` pass |
| `--corpus` | corpora and queues |
| `--reports` | `results/report/`, the `bhf report` snapshots; the rest of `results/` stays |
| `--findings` | `results/` (findings, indexes, `static/` and `sbom/` reports), and the legacy paths at the top of a work dir from before `results/`: `findings/`, `FINDINGS.md` and `findings.csv` |
| `--all` | every work-dir subtree bhf owns, including the fuzz loop's scratch (`fuzz_inputs/`, `fuzz_shm/`, `fuzz_campaigns/`) and the `.tmp*` shared-map files an older `bhf fuzz` left at the top of the work dir |

## Policy Profiles

The global `--profile` option sets the license and capability profile,
which decides the external tools bhf may run. Every profile links only
Apache-2.0, MIT, BSD-2-Clause and BSD-3-Clause code.

| Profile | Permits |
|---|---|
| `strict-permissive` (default) | no capability probe (`--probe`); dependency license expressions must be on the project allow-list |
| `external-tools` | the GNAT compiler-action probe (`--probe gnat_actions`), and these tools as subprocesses: the rizin, Ghidra and angr binary adapters, the gosec, Bandit, semgrep and GNATcheck analyzers (`static-scan --external-tools`), SymCC (`auto --symcc`), and bhf's QEMU dirty-page plugin (`reset=fast`) |
| `research-lab` | every probe, the GPL research tools Libadalang, GnatFuzz, GNATcoverage and PolyORB included, and any subprocess |

`static-scan --external-tools`, `auto --external-tools`, `auto --symcc`
and the `qemu-system:` lane's `reset=fast` take their profile from the
`BHF_PROFILE` environment variable, not from `--profile`, and use
`external-tools` when it is unset. GNAT, GPRbuild and AFL++ run under every
profile. Use `external-tools` where running those tools is allowed, and
`research-lab` only in a lab where any external analysis tool may run.

## Enterprise Operations

These commands govern offline enclaves and CI systems:

```sh
bhf policy validate bhf-policy.json --out bhf_work/policy-summary.json
bhf runners validate runners.json --out bhf_work/runner-summary.json
bhf runners plan runners.json --queue runner-queue.json --policy bhf-policy.json --out bhf_work/runner-plan.json
bhf pack keygen --private-key keys/offline-root.der --public-key keys/offline-root.pub
bhf pack create --root packs/current --pack-id rules-2026-06 --item rules:rules/static.json --signing-key keys/offline-root.der --key-id offline-root --out packs/current/update-pack.json
bhf pack verify update-pack.json --root packs/current --out bhf_work/pack-verify.json
bhf pack import-osv osv/crates.io osv/PyPI --out packs/current/cve-db.json
bhf pack import-nvd nvd/nvdcve-2.0-2025.json nvd/nvdcve-2.0-2026.json --out packs/current/cve-db-nvd.json
bhf sbom path/to/src --out bhf_work/sbom --vuln-db packs/current/cve-db.json --policy bhf-policy.json
bhf ci . --work-dir bhf_work --policy bhf-policy.json --runner-plan bhf_work/runner-plan.json --dashboard-out bhf_work/ci-dashboard.json
bhf export --work-dir bhf_work --out bhf_work/export-manifest.json --bundle-dir bhf_work/export-bundle --policy bhf-policy.json --update-pack update-pack.json --runner-plan bhf_work/runner-plan.json
```

`bhf export regression --work-dir bhf_work --out suite [--lang c|ada]` writes
a standalone regression suite of the work dir. Each harness keeps its sources,
its Makefile (C/C++) or `regress.gpr` (Ada, against the scanned tree's own
sources and a copy of bhf's Ada runtime), the build context bhf recovered for
it, its corpus (at most `--max-corpus`, 500 by default, smallest first) and the
minimized input of each of its findings. A finding of a replay lane's build
(MSan, TSan, CFI, RealtimeSanitizer) is left out, since the suite runs each
harness's own build. `suite/run.sh` builds every harness against the scanned
tree (`SOURCE_ROOT=<checkout>` names another) and runs every input; it exits 1
when one crashes, so a finding's input fails the suite until its bug is fixed.

### Policy and runners

`bhf policy validate` checks a policy-as-code document and writes a
deterministic summary of its enabled languages, rule counts, runner
requirements, CI thresholds and allowed update-pack kinds.

`bhf runners validate` checks an offline runner capability manifest and
lists the runner ids, kinds, languages, engines, sandbox settings and target
triples the enclave declares.

`bhf runners plan` reads a queue of offline fuzz, static and binary jobs,
applies the policy's runner allow-lists, sandbox requirements, target
triples and capabilities and the runners' capacity, and writes a
deterministic assignment plan. A job that policy or capacity blocks stays in
`unassigned` with a diagnostic, and the command exits non-zero unless every
job is assigned.

### Update packs

`bhf pack create` builds a deterministic air-gapped update-pack manifest
from `kind:path` items under `--root`, with each item's SHA-256.
`bhf pack keygen` makes an Ed25519 key pair, and `--signing-key` with
`--key-id` signs the whole manifest with it. The verifying policy supplies
the matching public key in `update_packs.trusted_public_keys` and can revoke
a key id in `update_packs.revoked_keys`. The deprecated `--sign-key` adds a
`sha256-items-v1` integrity digest, which authenticates no publisher.

`bhf pack verify` recomputes the hashes under `--root` and enforces the
update-pack policy (`--policy`), publisher authentication included;
`--require-authenticated` refuses a pack without a verified signature from a
trusted key. A tampered or missing item makes verification exit non-zero.
[Enterprise pack authentication](../enterprise-pack-authentication.md)
specifies the canonical bytes and key rotation.

`bhf pack import-osv` and `bhf pack import-nvd` build the advisory database
`bhf sbom --vuln-db` reads, from OSV records or NVD CVE JSON 2.0 files; they
report and skip malformed records.

### SBOM and vulnerability matching

`bhf sbom <PATH>` inventories a source tree, a work directory or a component
manifest. Without `--out` it writes under `<work-dir>/results/sbom/`
(`--work-dir`, default `bhf_work`) and rebuilds `results/`, where each
vulnerability match becomes an `sca` finding in `findings.json`. `--out
<DIR>` writes to that directory instead and leaves `results/` as it is.

`--emit <LIST>` selects the artifacts, comma-separated. By default bhf
writes all of them except `spdx-json`:

| `--emit` name | Writes |
|---|---|
| `sbom` | `sbom.json` |
| `cyclonedx` | `cyclonedx.json`, CycloneDX 1.6 JSON |
| `cyclonedx-vex` | the per-vulnerability CycloneDX `analysis` (VEX), in `cyclonedx.json` |
| `vulnerabilities` | `vulnerabilities.json`, the offline CVE matches |
| `openvex` | `openvex.json`, an OpenVEX document |
| `vex-review` | `vex-review.json`, the matches that need an analyst's review |
| `csv` | `sbom.csv`, one row per component, and `vulnerabilities.csv`, one row per CVE match |
| `spdx-json` | `sbom.spdx.json`, SPDX 2.3; `--format spdx-json` is the same |

`--vex` adds both VEX outputs (`openvex` and `cyclonedx-vex`) to the
selection. `sbom.csv` carries name, version, ecosystem, type, supplier,
license, purl, cpe, sha256, identity confidence, matching method, usage,
runtime harnesses and evidence, escaped as RFC 4180 says.
`vulnerabilities.csv` carries component, version, purl, cve, severity,
cvss_score, cwe, kev, reachability and advisory; its CWE comes from the
same normalized field as `vulnerabilities.json` and the CycloneDX
`vulnerabilities` entries.

Components come from local manifests (`Cargo.toml`, `package.json`,
declared component JSON, vendored `VERSION` directories; `--ecosystems`
limits the catalogers), from `--binary-inventory` evidence, and from the
runtime `dlopen` observations in `auto/run.json`, as `runtime-dlopen`
components. Declared component JSON may set `supplier`, `license` and
`sha256` strings, which fill the matching SBOM and CycloneDX fields. The
CycloneDX output carries component purls, declared CPEs, hashes, dependency
relationships, declared supplier and license metadata, BHF evidence
properties, and BHF tool metadata (supplier, license and package URL).

Matching uses an offline `--vuln-db`, from an update pack or built by
`bhf pack import-osv` or `bhf pack import-nvd` (see [Inventory
assurance](inventory-assurance.md#advisory-database-format) for the
format). An advisory names its package by
`package.ecosystem`/`package.name`, `package.purl` or `package.cpe`, with
`affected_versions` (exact versions, `*` for all) or `affected_ranges`
(version bounds). A PURL or CPE match is high-confidence
(`matching_method: "purl"` or `"cpe"`). Identifiers are compared
structurally: case-insensitively, with CPE 2.2 URIs and CPE 2.3 formatted
strings both accepted and `*` fields as wildcards, and an advisory purl
without a version matches every component version `affected_versions`
covers. An advisory purl or CPE that contradicts the component's identifier
vetoes a name/version match.

An advisory can carry `kev` metadata (`known_exploited`, `date_added`,
`due_date`, `required_action`), CVSS metadata (`version`, `score`,
`vector`), CWE metadata (`cwe` or `cwes`), and advisory and reference URLs.
`vulnerabilities.json` keeps them and counts KEV matches in
`counts.kev_matches`. The same matches appear as CycloneDX `vulnerabilities`
entries, with affected component refs, CVSS ratings, CWE ids, `advisories`,
and BHF properties for match method, confidence, reachability and KEV
status.

When an `auto/run.json` is under the scanned root or a sibling work
directory, or `--run-json` names one, a CVE match whose source or binary
component evidence overlaps a built-and-fuzzed target, or whose
runtime-dlopen component a built-and-fuzzed harness loaded, gets
`reachability.status: "reached_by_fuzz"` and is counted in
`counts.reached_matches`.

`--fail-on low|medium|high|critical` gates on the matched severity, and
`--policy` reads that gate from `/ci/fail_on_vulnerability_severity`. Both
need `--vuln-db`, since nothing can match without advisories: `--fail-on`
without it is a usage error (exit 2), and a policy gate without it exits 1.
`--fail-on-unreviewed` exits non-zero for matches that need review and
always writes `vex-review.json`. `vulnerabilities.json` records the database
the matches came from as `advisory_db` (its path, sha256 and number of
entries), or `null` when none was given.

`bhf license-audit` checks the licenses of bhf's own Cargo dependencies, in
a checkout of bhf's source (`--root`, default `.`; `--package`, default
`bhf`), against bhf's Apache-2.0/MIT/BSD policy and the `THIRD_PARTY.md`
matrix. To list a scanned tree's dependencies and their licenses, use
`bhf sbom`.

### Export and CI budgets

`bhf export` writes a deterministic manifest of the handoff artifacts in the
work directory: `results/` (`INDEX.md`, `findings.{json,csv,sarif}`,
`manifest.json`, `attestation.json`, `static/`, `sbom/`), report
JSON/Markdown/SARIF/JUnit/CSV, static reports, SPDX-style and CycloneDX
SBOMs, vulnerability reports, `auto` run metadata, policy files, and
update-pack manifests. `--runner-plan` adds the assignment evidence to the
export and its governance summary. `--bundle-dir` copies every exported
artifact into a deterministic `artifacts/<kind>/...` tree and writes a
bundle-local `export-manifest.json`, for an air-gapped handoff.

`bhf ci --runner-plan` uses the same plan to fill the dashboard's budget
allocation counts. A policy can set `/ci/require_runner_plan` and
`/ci/require_full_runner_assignment` to fail CI when the scheduling evidence
is missing or a job is unassigned.

`bhf ci` passes `bhf auto`'s budget flags on, so a CI run is bounded the
same way: `--per-target-time` (the total fuzz time per target),
`--per-target-finding-count N` (stop a target after N distinct findings;
`1` stops at the first), and `--campaign-time` (a cap on the whole run, or,
with `--min-target-time`, a budget split evenly across the targets). See
[CI](ci.md) for the CI gates and integrations.

## Optional LLM and Agent Assistance

`bhf llm` asks a model for advice on bhf's evidence. It is a separate
command, not a stage of `bhf auto`, and it exists in a bhf built with the
`llm` feature:

```sh
cargo build --locked -p bhf -p bhf-daemon --features bhf/llm,bhf-daemon/llm
```

The release archives are built without that feature, so there `bhf llm` is
an unrecognized subcommand.

```sh
bhf llm status --json
bhf llm test --provider codex
bhf llm prompt --task diagnose-error --input bhf_work/auto/run.json
bhf llm assist --provider local --model '<served-model>' \
  --task analyze-findings --input bhf_work/results/findings/F-0001/finding.json
```

The tasks are `plan-run`, `generate-harness`, `analyze-findings`,
`explain-code` and `diagnose-error`. `generate-harness` needs
`--target-symbol`, and its `--language` takes Ada, C or C++. `--provider`
selects a cached session of a vendor's command-line tool (`codex`, the
default, is one), the `openai` or `anthropic` API with an explicit
`--model`, or `local`, an OpenAI-compatible endpoint with an explicit
`--model`. API keys are read from environment variables only
(`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or the one `--api-key-env` names).

For agent work, `bhf-daemon --mcp` serves three read-only tools that return
deterministic evidence: `bhf_scan`, `bhf_list_targets` and
`bhf_load_findings`. A build with the `llm` feature adds
`bhf_prepare_assistance`, for prompt preparation, and `bhf_preflight_harness`,
an Ada/C/C++ harness preflight. The tools run no shell command and no
long-running or state-changing pipeline step. [LLM assistance](llm.md) has
the schemas, registration, provider privacy, root-cause workflows, memory
controls, and the deterministic checks that accept or reject a model's
suggestion.

## External Project Profiles

`bhf project` validates and runs a project manifest (`bhf.project.v1`,
TOML) that you keep outside bhf's source tree. One manifest puts a private
harness (source or a prebuilt binary) together with its corpora, layered
dictionaries, grammar and launch settings, under one or more stable target
ids, so a private campaign is reproducible without adding it to bhf. `run`
uses the existing engines: `builtin` and `afl++` targets go through the
`bhf fuzz` lane, and `binary` targets through the `bhf binary fuzz` lane.

A `builtin` or `afl++` target's `binary` must be a bhf harness binary,
built from a harness directory bhf generated (for C/C++, its `make main` or
`make afl`), because `bhf fuzz` drives it through bhf's harness protocol and
coverage map. Any other executable belongs on `engine = "binary"`.
`validate` and `run` refuse a `builtin` target whose binary is a
`-fsanitize=fuzzer` build without bhf's driver, since libFuzzer would run its
own fuzzing loop inside every execution, and name the two ways to run it:
`engine = "binary"` with `input-mode = "file"`, or wrapping the fuzz target
with `bhf generate-harness <fuzz_target.cc> --target LLVMFuzzerTestOneInput`.

```sh
# Type-check every target: resolve and hash each asset, and report missing
# assets, duplicate ids, an unsupported schema or bhf version, invalid
# relative paths and unsafe secret interpolation. Runs no campaign and no
# build command.
bhf project validate --manifest path/to/bhf-project.toml

# List the declared targets with their engine, input mode and assets.
bhf project list --manifest path/to/bhf-project.toml

# Set up an isolated work dir (default ./bhf_work_project/<project-id>/<target-id>),
# resolve and hash the assets, write provenance, and run one target. The
# target's build command runs, since naming the manifest is the act of
# trust; --skip-build reuses a prebuilt binary instead.
bhf project run --manifest path/to/bhf-project.toml --target alpha
```

Every path in the manifest is resolved relative to the manifest's own
directory. By default a path may not be absolute or escape that directory
(`..`); `--allow-external-paths` allows it. `--json` prints a
machine-readable validation or provenance report on any of the three
subcommands.

**Input mode.** A `builtin` target's binary is staged into
`<work>/build/<id>/main`, with a `harness-protocol.json` beside it that
declares the target's input mode (`framed`). `bhf fuzz`, and later
`bhf replay` and `bhf minimize`, read that file instead of detecting the
protocol from the binary, so a prebuilt bhf harness gets the framed protocol
and its coverage map. The libFuzzer runtime in a binary without bhf's driver
outranks a declared `framed`: such a binary is run on one input file per
process.

**Trust boundary.** bhf loads a manifest only from an explicit `--manifest`
path; it never searches for one. `validate` and `list` never run a target's
`build-command`. `run` does, because naming the manifest is the operator's
act of trust, and `run --skip-build` reuses a prebuilt binary and runs
nothing else.

**Provenance.** `run` writes `results/project.json` (the project id,
version, schema, manifest SHA-256, the resolved and redacted launch, and
every asset's SHA-256) and puts a `project-provenance.json` sidecar beside
each finding and in the native run-summary directory, so findings, replay
and minimization keep the project and target identity for importers such as
SARIF and vulnerability-management tools. In a target's env,
`${secret:NAME}` is replaced by the value of `BHF_SECRET_<NAME>`, and
`${env:NAME}` by the value of `NAME` in the process environment. Only the
reference is recorded; the resolved value never appears in provenance.

**Example manifest.**

```toml
schema = "bhf.project.v1"

[project]
id = "my-project"
version = "1.0.0"
requires-bhf = ">=0.2.0"

[[target]]
id = "parser"
engine = "builtin"                       # builtin | afl++ | binary
binary = "prebuilt/harness"              # resolved relative to this manifest
build-command = ["make", "harness"]      # trusted; run only by `bhf project run`
seeds = ["corpus/parser"]                # files and/or directories
dictionaries = ["dict/base.dict", "dict/parser.dict"]  # layered, merged in order
grammar = "grammar/parser.json"

[target.env]
PROFILE = "release"
TOKEN = "${secret:API_TOKEN}"            # resolved from BHF_SECRET_API_TOKEN, redacted
```

**Composition fields.** A target composes the engines' launch features:

- `runner`, `runner-args` and `target-args` — launch the target under a
  runner or emulator (such as `wine` or `qemu-x86_64`) with fixed arguments.
  A literal `@@` in `target-args` marks the input-file position (file mode).
  These are for the binary engine: a native harness uses bhf's framed
  fork-server protocol, which takes no per-launch arguments, and a native
  target that declares any of them is rejected. `arguments` is an alias for
  `target-args` (setting both is rejected), and `runner-args` requires
  `runner`. A target that names a `runner` runs on the binary lane's builtin
  engine; afl-qemu provides its own `-Q` runner.
- `runtime-oracles` — `"auto"`, `"on"` or `"off"` (default). Loads the
  runtrace sink oracles, so a clean-exit semantic violation becomes a
  finding. It applies to both lanes.
- `[target.postcondition]` — the `setup-command`, `oracle-command` and
  `reset-command` postcondition hooks run around each testcase (see
  [Postcondition oracles](#postcondition-oracles-bhf-binary-fuzz)).
  `oracle-command` is required. A postcondition is for the binary engine and
  selects the binary lane's builtin engine.

```toml
[[target]]
id = "channel-parser"
engine = "binary"
binary = "harnesses/parser"
input-mode = "file"
runner = "wine"                          # launch under an emulator or loader
runner-args = ["--mode", "fuzz"]
target-args = ["@@"]                     # @@ = fuzz input-file position
runtime-oracles = "auto"                 # clean-exit sink oracles

[target.postcondition]                   # user security postcondition
setup-command = "./prepare-case"
oracle-command = "./check-postcondition" # required; exit 0=clean / 1=finding
reset-command = "./reset-case"
```

An unknown field, such as a misspelled key, is rejected when the manifest
is parsed.

### Importing an OSS-Fuzz build

`bhf project import-ossfuzz` builds a project's existing OSS-Fuzz or
ClusterFuzzLite integration and collects the fuzzers its `build.sh` leaves in
`$OUT`:

```sh
# A source tree with its own build.sh (or .clusterfuzzlite/build.sh):
bhf project import-ossfuzz path/to/libfoo --work-dir bhf_work

# An OSS-Fuzz projects/<name>/ directory, and the checkout it builds:
bhf project import-ossfuzz oss-fuzz/projects/libfoo --src path/to/libfoo \
  --work-dir bhf_work
```

`build.sh` runs as OSS-Fuzz runs it, `bash -eux $SRC/build.sh` from
`$SRC/<name>`, with the OSS-Fuzz build variables:

| Variable | Value |
|---|---|
| `$SRC` | `<work>/ossfuzz/src`. The source tree is copied to `$SRC/<name>` (`--name`; by default the tree's directory name), and the script to `$SRC/build.sh` (`--build-script` names another) |
| `$WORK` | `<work>/ossfuzz/work`, for intermediate files |
| `$OUT` | `<work>/ossfuzz/out`, where the fuzzers go |
| `$CC`, `$CXX` (`$CCC`) | clang and clang++ |
| `$CFLAGS`, `$CXXFLAGS` | OSS-Fuzz's address build, `-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope`, with `-fsanitize-coverage=trace-pc-guard,trace-cmp` (the coverage bhf's driver reads) in place of `-fsanitize=fuzzer-no-link`, and `-fdebug-prefix-map=$SRC/<name>=<source tree>`, so a crash stack names the tree's own files (left out for a path with whitespace or, in the copy's, a `=`) |
| `$LIB_FUZZING_ENGINE` | `<work>/ossfuzz/engine/libFuzzingEngine.a`: bhf's driver, the `main` and coverage runtime a generated harness links, with a `bhf_run_one` that calls the target's `LLVMFuzzerTestOneInput` |
| `$SANITIZER`, `$FUZZING_ENGINE`, `$FUZZING_LANGUAGE`, `$ARCHITECTURE` | `address`, `libfuzzer`, `c++`, and the host's architecture |

Nothing else of bhf's environment reaches the build: `PATH` is kept, `HOME`
is `$WORK`, `TMPDIR` is `$WORK/tmp`, and `ASAN_OPTIONS` turns leak detection
off for the build, as OSS-Fuzz does. `$SRC`, `$WORK` and `$OUT` are emptied
before each import, and the source tree itself is never written.

**Sandbox.** `build.sh` runs project code, so it runs in bubblewrap (`bwrap`)
or, without that, firejail, with no network and no writes outside `$SRC`,
`$WORK` and `$OUT`. Under bubblewrap the build sees the system directories
(`/usr`, `/etc`, `/opt`, ...) and bhf's engine read-only and the three
directories read-write, with an empty, read-only `/tmp` and no home
directory. Under firejail the whole filesystem is read-only except the three
directories. Before anything is staged, bhf runs the sandbox once with the
build's mounts; when no sandbox works it refuses the import and says which
tool is missing or why it failed. An unprivileged `bwrap` on Ubuntu 24.04
gets no user namespace while `kernel.apparmor_restrict_unprivileged_userns`
is 1 and no AppArmor profile allows it. `--sandbox bubblewrap` or
`--sandbox firejail` picks one, `--sandbox-tool` names its executable, and
`--sandbox none` runs `build.sh` directly, with your network and file
access.

**Fuzzers.** The fuzzers are the files in `$OUT`, and in its
subdirectories, that OSS-Fuzz takes for fuzz targets: executable regular
files named `[A-Za-z0-9_-]+`, with no extension or `.exe`, not
`jazzer_driver*`, whose name ends in `_fuzzer` or whose bytes contain
`LLVMFuzzerTestOneInput`. A tool the build leaves beside them is not one.
The import lists them, writes the import record to
`<work>/ossfuzz/import.json` (`--json` prints it), and keeps the build's
output in `<work>/ossfuzz/build.log`. A failing `build.sh` fails the import
with the end of that log. A target linked with `-fsanitize=fuzzer` instead
of `$LIB_FUZZING_ENGINE` is listed as a `libFuzzer single input` binary.

**Harnesses.** Each fuzzer is registered as a harness of the work dir under
its own name: copied to `<work>/build/<name>/main`, where `bhf fuzz`,
`bhf replay` and `bhf minimize` find it, with a `harness-protocol.json`
declaring the framed input mode beside one linked with bhf's driver. The
listing names each one and the commands that fuzz it:

```sh
bhf fuzz bhf_work --harness parse_record_fuzzer --time 60s
bhf project run --manifest bhf_work/ossfuzz/bhf.project.toml \
  --target parse_record_fuzzer --work-dir bhf_work
```

The import also writes a `bhf.project.v1` manifest,
`<work>/ossfuzz/bhf.project.toml`, with one target per fuzzer: `engine =
"builtin"` for a fuzzer linked with bhf's driver, which the builtin engine
drives through the framed protocol with coverage, and `engine = "binary"`
with `input-mode = "file"` for a libFuzzer binary linked without it, which
runs one input file per process. Importing again rewrites the manifest and
the registered binaries. A target has no `time`, so `bhf project run` runs
`bhf fuzz`'s default budget; add `time = "10m"` to a target for a timed
campaign.

**Seeds, dictionaries and options.** What OSS-Fuzz takes from beside a
fuzzer in `$OUT` comes with it:

- `<name>_seed_corpus.zip` is unpacked with the system `unzip` (bhf links no
  zip library) into `<work>/ossfuzz/seeds/<name>/`, the target's `seeds`.
  `unzip` keeps every entry inside that directory, and a symlink it restores
  is removed, since it could name a host file. When the build leaves a seed
  corpus and `unzip` is not on PATH, the import stops and names the corpus
  and the package to install.
- `<name>.dict` and the dictionary the `.options` file's `dict` names
  (relative to the fuzzer, inside `$OUT`) are merged, in that order and
  without duplicate tokens, into `<work>/build/<name>/dictionary.txt`, which
  `bhf fuzz` loads, and are the target's `dictionaries`. A dictionary that is
  not UTF-8 or is over the size limit is left out with a note.
- The `[libfuzzer]` options with a bhf equivalent set the target's
  `max-len` (`max_len`), `timeout` (`timeout`, in seconds) and
  `rss-limit-mb` (`rss_limit_mb`); the listing prints them as `bhf fuzz`
  flags. Every other option (`close_fd_mask`, `only_ascii`, the `[asan]`
  and `[afl]` sections, ...) is reported as not applied. A binary-lane
  target takes the seeds and `timeout` (as `timeout-ms`) only.

`bhf project run` on the manifest applies all three; `bhf fuzz` loads the
dictionary, takes the options as the flags the listing prints, and takes
each seed with `--seed-file`.

**`bhf auto`.** A later `bhf auto` of the same tree with the same
`--work-dir` fuzzes every imported fuzzer linked with bhf's driver as a
[provided harness](auto.md#provided-harnesses), ahead of the targets it
generates, with its seeds, dictionaries and options applied, and leaves the
registrations under `<work>/build/` in place:

```sh
bhf project import-ossfuzz path/to/libfoo --work-dir bhf_work
bhf auto path/to/libfoo --work-dir bhf_work
```

## Out-of-Process Extensions

`bhf extension` drives an out-of-process extension that you trust
explicitly and that speaks the versioned `bhf.extension.v1` protocol:
length-framed JSON over stdin and stdout. An extension is a private semantic
oracle, written in any language and kept outside bhf, that judges whether an
input that exits cleanly broke a contract. See [the extension
protocol](extension-protocol.md) and the Python reference extension,
`crates/extension_host/tests/fixtures/reference_extension.py`.

```sh
# Start the extension, negotiate the protocol and capabilities, and print the
# negotiated protocol version, the required and negotiated capabilities, and
# the executable and config SHA-256. Drives no case.
bhf extension validate --manifest path/to/extension.toml

# Run oracle.evaluate on one input: a clean-exit semantic violation becomes a
# replayable finding under <work>/results/findings/. An extension crash,
# timeout, or oversized, malformed or unsupported reply is an infrastructure
# result.
bhf extension evaluate --manifest path/to/extension.toml --input case.bin --work bhf_work

# Shrink an extension-oracle finding while the oracle still returns the same
# signature; writes min_testcase.bin beside it.
bhf extension minimize --manifest path/to/extension.toml \
  --finding bhf_work/results/findings/<finding-id>

# Drive a whole multi-message session: lifecycle.reset a fresh root, take each
# scenario.next message, let the extension mutate it (--mutate SEED) and
# codec.repair it before it reaches the target, bind each response into a
# later message (scenario.observe-response), then oracle.evaluate the outcome.
bhf extension session --manifest path/to/extension.toml --input seed.bin --work bhf_work \
  --mutate 42 --repair true

# The same session against a real service: bhf starts it, waits for its port,
# and sends each scenario message to it over TCP.
bhf extension session --manifest path/to/extension.toml --input seed.bin --work bhf_work \
  --session-transport tcp:127.0.0.1:7000 --session-server-cmd './toy-server 7000'

# Fuzz with the extension's stages in the builtin loop (below), then run the
# retained corpus through its oracle. When the extension provides
# codec.repair, a frame it recognizes is repaired before the oracle sees it,
# and a corpus entry it rejects is evaluated as it is. An extension fault
# neither stops the campaign nor becomes a target finding.
bhf fuzz bhf_work --harness H-0001 --extension path/to/extension.toml
```

**Stages in the fuzz loop.** `bhf fuzz --extension` also gives the builtin
loop the stages the extension provides:

- `mutator.mutate`: one in four mutated children is the extension's mutation
  of the base the loop picked.
- `codec.decode` with `codec.encode`: a child is the base decoded to the
  extension's structured value, one value of it mutated (a number nudged or
  set to a boundary, a string edited or doubled, a boolean flipped, an array
  element duplicated or dropped), and encoded back, so a framed format keeps
  its length and checksum fields right. With both stages the two take turns.
  A decode or encode the extension rejects is counted (`codec_errors`), never
  a finding.
- `lifecycle.setup`, `reset` and `teardown`: setup runs before the campaign
  with a case root (`<work-dir>/fuzz_scratch/extension-<harness>`), reset
  before every case after the first, and teardown after the campaign. A setup
  or reset the extension answers as failed (`infrastructure_error`) or
  unsupported stops the campaign with its message, since the cases would run
  on a fixture the extension did not prepare.

The mutation and codec stages make at most 1000 calls per pass and spend at
most a quarter of its `--time` (60 s without one). A call that times out, an
extension that crashes or answers garbage, or a stage past its bound is cut off
for the rest of the pass, and the campaign goes on with the builtin mutations.
The run summary's `extension.stages` records what each stage did: `calls`,
`mutated`, `encoded`, `codec_errors`, `lifecycle.resets` and `cut_off` (why a
stage stopped, or `null`).

**The session's target.** Without `--session-transport`, `bhf extension
session` drives a built-in toy target that speaks the reference extension's
OPEN/WRITE protocol. With `--session-transport SPEC` it drives a real one over
the session lane's transport, the spec `bhf fuzz --session-transport` takes
(`tcp:HOST:PORT`, `udp:HOST:PORT`, `serial:PATH[,baud=N]` or
`transport:SPEC`). The extension frames every message, so bhf sends each one
as `scenario.next` (and any mutate and repair) left it, and takes as its reply
every byte the target sends until it goes quiet for 50 ms, which
`scenario.observe-response` gets. bhf connects before `lifecycle.setup` runs,
and a TCP target it cannot connect to is exit `2`. `--session-reply-timeout`
bounds how long a reply may take to start (5 s over TCP, 1 s over UDP).

`--session-server-cmd COMMAND` runs the service as the session lane's flag
does: through the shell, in its own process group, with its stderr in
`<work>/session_server/`. bhf waits until it serves the port (a service that
does not start is exit `2`, with its stderr), drives the session, checks
whether the service exited (waiting up to 2 s when the session lost the
target), and stops it.

A target that ends the session (closes or resets the connection, or does not
answer in time) or a service that exits is the target's result, exit `3`:
`extension.json` says `target_error: <why>` or `target_exited: <status>`, and
the oracle does not judge a session that did not finish. A service that exits
after answering the whole session is still exit `1` when the oracle fired on
it, with the exit recorded. `session.target` records the transport, the
exchanges, the error, and the service's command, starts and exit (its status,
the sanitizer report's kind, rule and message when its stderr has one, and the
log dir). To hunt crashes in a service over many sessions, use `bhf fuzz
--protocol-profile --session-server-cmd`.

`bhf extension evaluate` and `bhf extension session` exit with:

| Exit | Meaning |
|---|---|
| `0` | the input is benign |
| `1` | a semantic finding was written |
| `2` | a manifest or usage error |
| `3` | `session` over `--session-transport`: the target ended the session |
| `4` | an infrastructure failure on the extension's side |

`--json` prints a machine-readable report.

**Capabilities.** The host drives the whole `bhf.extension.v1` surface:
`oracle.evaluate`, `codec.decode`/`encode`/`repair`, `mutator.mutate`,
`scenario.next`/`observe-response`, and
`lifecycle.setup`/`reset`/`teardown`. Negotiation offers all of them as
optional on top of the manifest's `required-capabilities`, so an extension
that implements a subset works. Messages are length-framed JSON; an
extension that offers no `json` format is refused at the handshake. See
[the extension protocol](extension-protocol.md) for the wire shapes.

**Trust boundary.** bhf loads a manifest only from an explicit `--manifest`
path and never searches for one; naming the manifest is the operator's act
of trust. The child runs with a cleared environment that holds only the
allow-listed variables (only the names of passed and dropped variables are
recorded), and on Unix under `setrlimit` caps (`RLIMIT_AS`, `RLIMIT_CPU`).

**Failures.** An extension crash, a per-call timeout, an oversized or
malformed response, a mismatched case identity, and an `unsupported` reply
each become an infrastructure result, never a target finding. A crash or
timeout triggers the restart policy (`max-restarts`), and a spent restart
budget is recorded as a terminal loss event.

**Provenance.** A finding carries an `extension` block (the extension's
executable and config SHA-256, the negotiated protocol version, and the
negotiated capabilities), and `evaluate` writes a run-level
`extension.json`, so a consumer can audit which trusted extension produced a
result. `bhf fuzz --extension` adds an `extension` block to the run summary
and leaves the summary's `schema_version` as it is.

**Example manifest.**

```toml
schema = "bhf.extension-manifest.v1"
id = "path-oracle"
executable = "./path-oracle"             # resolved relative to this manifest
args = ["--serve"]
required-capabilities = ["oracle.evaluate"]
env-passthrough = ["ACME_MODE"]          # only these host vars reach the child

[limits]
call-timeout-ms = 5000
max-frame-bytes = 1048576
max-restarts = 1
address-space-bytes = 1073741824         # RLIMIT_AS (unix)
cpu-seconds = 30                          # RLIMIT_CPU (unix)
```

By default the `executable` may not be absolute or escape the manifest
directory (`..`); `allow-external-paths = true` allows it. bhf refuses a
manifest whose `requires-bhf = ">=X.Y[.Z]"` bound it does not meet.

A `bhf.project.v1` manifest can declare the same extension inline in an
`[[extension]]` section, which `bhf project run` turns into a trusted
`bhf.extension-manifest.v1` and loads for its native-engine campaigns:

```toml
# In a bhf.project.v1 manifest: declare a trusted extension the run loads.
[[extension]]
id = "path-oracle"
executable = "./path-oracle"             # resolved relative to the manifest
args = ["--serve"]
required-capabilities = ["oracle.evaluate"]
optional-capabilities = ["codec.repair", "scenario.next"]
env-passthrough = ["ACME_MODE"]

[extension.limits]
call-timeout-ms = 5000
max-restarts = 1
```

## Coverage-Guided Relational Policy Fuzzing

`bhf relational` runs one generated testcase under several named launch or
session profiles, which differ in runner, arguments, environment, declared
target allowlist and secret references, and evaluates declarative relational
predicates over what each profile did. It reports unexpected divergence and
unexpected equivalence against an explicit policy: authorization bugs whose
runs can all exit `0` with byte-identical stdout. The signal is each
profile's effect (what it launched, reached or decided).

| Command | Defaults |
|---|---|
| `bhf relational run --config <FILE> --seeds <DIR>` | `--out findings_relational`, `--max-execs 10000`, `--timeout-secs 5` per profile and case, `--seed 0`, `--max-len 4096`, `--max-findings 1024` |
| `bhf relational replay --finding <ID_OR_DIR>` | `--work-dir findings_relational` (for a bare id), `--timeout-secs 5`; `--config` defaults to the policy saved beside the finding |
| `bhf relational minimize --finding <ID_OR_DIR>` | as `replay` |

```sh
# Coverage-guided campaign: mutate a shared testcase, run it under every profile,
# retain inputs that reach new code in any profile or a new cross-profile outcome,
# and emit a finding when a policy relation breaks. Findings land under
# <out>/results/findings/F-REL-*.
bhf relational run --config policy.toml --seeds corpus/ --out findings_relational

# Re-run every profile the finding requires and re-confirm the violated relation
# (exit 0 when it still reproduces, non-zero when it no longer does). Resolved
# secrets stay redacted; a replay.json bundle is written beside the finding.
bhf relational replay --finding findings_relational/results/findings/F-REL-0000

# Shrink the finding's testcase while the relation still holds and reduce the
# required profile set to the minimum that still proves it.
bhf relational minimize --finding findings_relational/results/findings/F-REL-0000
```

**Policy (`bhf.relational.v1`).** A TOML file declares the profiles and the
relational predicates:

```toml
schema = "bhf.relational.v1"

[status_map]                              # exit-code -> authorization status
allowed = [0]
denied = [77]
auth_failure = [66]                       # a failed session/auth bootstrap

[[profiles]]
name = "administrator"
runner = "/bin/sh"
args = ["launcher.sh", "administrator"]
allowlist = ["administrator-helper", "viewer-helper"]
collector = "runtrace"                    # auto | runtrace | none
[profiles.env]
TOKEN = "lab:admin-token"                 # a secret reference, never a value

[[profiles]]
name = "viewer"
runner = "/bin/sh"
args = ["launcher.sh", "viewer"]
allowlist = ["viewer-helper"]
collector = "runtrace"

# viewer must stay denied whenever administrator is allowed (BHF-308)
[[predicates]]
rule = "viewer must stay denied when administrator is allowed"
require = { kind = "status_relation", profile = "viewer", status = "denied" }
when = { kind = "status_is", profile = "administrator", status = "allowed" }

# viewer may only launch targets in its declared allowlist (BHF-309)
[[predicates]]
rule = "viewer spawned targets must be a subset of its allowlist"
require = { kind = "subset", set = "viewer.spawned", of = "viewer.allowlist" }
```

| Relation | Holds when |
|---|---|
| `status_relation` | a profile's derived status matches |
| `subset` | an observed target set is within a declared allowlist |
| `equal`, `differ` | selector values across profiles are equal, or differ |
| `external` | a trusted out-of-process comparator says so, over the whole cross-profile observation bundle |

A selector reads `profile.field`, where the field is `spawned`, `allowlist`,
`status`, `response` or `edges`.

**External comparator.** An `external` predicate names a comparator by the
path of a `bhf.extension-manifest.v1` manifest, loaded explicitly as in
`bhf extension` and `bhf project`:

```toml
[[predicates]]
rule = "a trusted comparator decides the cross-profile relation"
require = { kind = "external", comparator = "comparators/authz.toml" }
```

The driver starts and negotiates the comparator before the first testcase
(a manifest that does not load fails the run). For each testcase it
serializes the cross-profile observation bundle, with secrets redacted, and
calls `oracle.evaluate` over the `bhf.extension.v1` protocol. The
comparator's verdict maps to an outcome:

| Verdict | Outcome |
|---|---|
| `ok` | `compliant` |
| `finding` | `violation`: a BHF-312 finding with the comparator's own signature and classification, and the comparator's executable and config SHA-256 and protocol version as provenance |
| `unsupported`, `reject`, or an infrastructure fault | `policy_unknown`, kept apart from a setup, auth or missing-observation outcome |

Resolved secrets are removed before the bundle is sent and never appear in a
finding or replay bundle.

**What a finding records.** Each violation is a finding: BHF-308
(unexpected authorization), BHF-309 (allowlist escape), BHF-310 (unexpected
equivalence), BHF-311 (unexpected divergence) or BHF-312
(external-comparator violation). It carries the violated relation, the
profiles involved, each profile's normalized observation, the testcase, the
evidence events, and the hashes of the policy and of each profile. It has
the shape of every other finding kind, so SARIF and vulnerability-management
importers read relational findings with the same reader.

**Per-profile isolation.** Each profile runs with its own coverage map file
(`BHF_COV_SHM`), runtime-trace log (`BHF_RUNTRACE_LOG`) and scratch dir, so
the coverage and effect events of one profile stay out of another's.
Novelty is tracked per profile, so an input that is new in one profile only
is still kept. Effect events come from the runtime-trace collector, and the
platform-neutral `bhf.collector-event.v1` source feeds the same path where
it is active. A target that emits its own trace stream, or must not be
instrumented, sets `BHF_RUNTRACE_SHIM=off` to skip the LD_PRELOAD shim.

**Secrets.** A profile env value with the `lab:` prefix is a reference. The
driver resolves it in-process from `BHF_SECRET_<NAME>` (the name upper-cased,
and every character other than a letter or digit mapped to `_`) and redacts
the value from every finding and replay bundle before anything is written;
only the reference from the policy is kept.

## Other Commands

| Command | What it does |
|---|---|
| `bhf stub <WORK_DIR>` | generates Ada stubs for the units and subprograms a harness build reports missing, rebuilding until the harness compiles |
| `bhf instrument <SOURCE>` | rewrites an Ada source to record runtrace events (probe points and a breadcrumb sidecar), into `bhf_work/src_instrumented/` by default |
| `bhf corpus import`, `export`, `merge`, `minimize` | moves a corpus between the AFL++, libFuzzer, honggfuzz and bhf layouts, merges corpus directories without duplicates, or keeps the inputs that add coverage (libFuzzer `-merge=1`) |
| `bhf cmplog ingest` | reads a runtrace audit log and prints the comparison operands it recovers, as a JSON token list |
| `bhf extract-state-machines <PATH>` | infers Ada protected and task types from source as JSON state machines |
| `bhf audit append`, `read` | appends to, or reads and summarizes, a JSONL compliance audit log |
| `bhf runners list`, `select`, `handoff`, `lease`, `complete` | manage distributed runner profiles and their offline handoff and leases; `validate` and `plan` are described under [Policy and runners](#policy-and-runners) |
| `bhf kernel syzlang`, `import`, `run`, `fuzz`, `replay` | Linux kernel drivers with syzkaller descriptions and a qemu-system guest; see [On-target fuzzing §10](on-target-fuzzing.md#10-linux-kernel-drivers-syzkaller-descriptions) |
| `bhf bug-report <WORK_DIR>` | writes a scrubbed support report of an `auto` work dir, with no source or private names, to `<work-dir>/auto/support-report.txt`; `--preview` prints what a `--bundle` archive would hold. When bhf itself fails, run the command again with `--debug` first |

## Release Commands

The release archives ship `bhf-daemon` beside `bhf`. Use `bhf` for batch
work, `bhf-daemon` in its default JSON-RPC mode for editor integrations, and
`bhf-daemon --mcp` for the read-only agent tools; see [Daemon](daemon.md).
