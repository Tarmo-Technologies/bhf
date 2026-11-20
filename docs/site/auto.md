<!-- SPDX-License-Identifier: Apache-2.0 -->

# Auto

`bhf auto <PATH>` runs the whole pipeline over a source tree. It finds and
ranks candidate functions, generates a harness for each, builds it, fuzzes
it, and writes a findings report. It covers sixteen languages: Ada, C, C++,
Rust, Java, Python, Perl, Go, COBOL, Fortran, C#, JavaScript, TypeScript,
Ruby, Lua and PHP.

The C, C++ and Ada lanes build code with broken `#include` chains, undefined
externs, missing types or missing `with` clauses: `auto` reads the compiler's
errors and writes placeholder headers, types and stubs until the harness
links (see [Repair Synthesis](#repair-synthesis)). On Linux, a runtime shim
fakes the files, devices, environment variables and network endpoints the
code expects, for native harnesses and the Python, Perl, Ruby, Lua and PHP
interpreters (see [Three-Pass Cascade](#three-pass-cascade)).

```sh
bhf auto path/to/src --work-dir bhf_work --per-target-time 60
```

For a first run on an unfamiliar tree, fuzz one target for ten seconds:

```sh
bhf auto path/to/src --work-dir bhf_work --jobs 1 --max-targets 1 --per-target-time 10
```

Keep the work directory outside the scanned tree. Read
`bhf_work/results/INDEX.md` for the findings and `bhf_work/auto/summary.txt`
for what built, fuzzed or was skipped. [Outputs](#outputs) lists every file a
run writes. Add `--resume` to the same command to continue a stopped run. For
a whole-tree campaign, start from the [recommended
sweep](../recommended-sweep.md).

`auto` never calls a language model. The optional model assistant is built
only with `cargo build -p bhf --features llm`; the [LLM and MCP
guide](llm.md) shows how to use it to plan a run, diagnose an artifact, or
review findings after `auto` has produced them. Model output does not change
target ranking, build status, coverage, finding verdicts, replay or
minimization.

## What It Does

For each candidate function in the tree, `auto`:

1. Generates a harness for the function's lane. Ada, C and C++ use the same
   generator as `bhf generate-harness`; the other lanes have their own
   builders. A C API whose functions take a handle as their first parameter,
   and a C++ method whose class has visible setup methods, get a
   lifecycle-sequence harness first and a direct-call harness if that fails.
2. Builds the harness. When the build fails, `auto` classifies the compiler
   diagnostics, applies the smallest repair that lets the build progress, and
   builds again. Repairs accumulate from round to round. The loop stops when a
   round finds no new repair, or after `--max-repair-rounds` rounds (default
   16), so a target costs one round per distinct missing piece.
3. Fuzzes the harness in three passes, `empty`, `rng` and `fuzz_driven` (see
   [Three-Pass Cascade](#three-pass-cascade)). `--per-target-time` is the
   target's total fuzz time: the passes split it evenly under one shared
   deadline. `--iterations N` also caps each pass at N executions, and
   `--per-target-finding-count N` stops the target once it has N distinct
   findings.
4. Records the findings, the runtime-audit events and the prosthetic ledger
   (every stub, placeholder and fake the run supplied; see
   [needed_for_build](#needed_for_build)) in `auto/run.md` and
   `auto/run.json`, and writes the findings to `results/`.

Only the C, C++ and Ada lanes enter the repair loop. The other lanes build or
check the target with their own toolchain before the fuzz passes, and a target
that does not build there is skipped with the reason:

| Lane | Build step | Runs under |
|---|---|---|
| Rust | `cargo` staticlib with SanitizerCoverage and ASan | bhf's C fork-server driver |
| Java | `javac`, Maven or Gradle | bhf's JVM bytecode coverage agent |
| Python | `py_compile` and an import smoke test | a persistent CPython process |
| Perl | `perl -c` and a `require` smoke test | a persistent `perl -d:BhfCov` process |
| Go | `go build` against the target package (through a module `replace`) | a native fork-server binary |
| COBOL | GnuCOBOL (`cobc`) | a native binary |
| Fortran | `gfortran` with ASan | a native binary |
| C# | `dotnet` with SharpFuzz IL instrumentation | the .NET runtime |
| JavaScript, TypeScript | TypeScript transpiled with esbuild | a warm Node process |
| Ruby, Lua, PHP | loaded by the interpreter | their own interpreter, with in-process edge coverage |

**Targets that fail before any input.** A built Go harness is first started
once with `BHF_GO_LOAD_ONLY` set, which runs every package's `init` and stops
before reading an input. When that run fails, every input would fail the same
way, for example a dependency's `init` that refuses the installed Go release.
bhf then reports the target as `built, NOT entered (target environment)`, with
a reason that names the package whose `init` panicked and the panic message,
and writes no finding. A JavaScript or TypeScript target gets the same outcome
when every input bhf tries on it before fuzzing stops at the same undefined
global, such as `FileReader` or a name only the host defines; [Browser
globals](javascript.md#browser-globals) lists the inputs it tries.

**Interpreter crashes.** When an interpreter (Python, Perl, Ruby, Lua, PHP or
Node) dies by SIGSEGV without an error message of its own, bhf reports
BHF-210 with CWE-674 (uncontrolled recursion) rather than an invalid memory
access (CWE-119). Deep recursion that exhausts the interpreter's native stack
is the usual cause; PHP without a stack limit set does this, for example. The
finding's explanation names a defect in a native extension as the other cause,
and its fix hint is to bound the recursion depth.

## Flags

The flags are grouped by purpose below. `bhf auto --help` prints the same
flags, except the two deprecated ones it hides (`--total-time`,
`--reuse-discovery`). A flag with a config key can also be set in a [config
file](#config-file).

### Output and reports

| Flag | Default | Purpose |
|---|---|---|
| `--work-dir <DIR>` | `bhf_work` | Output root. Keep it outside the scanned tree |
| `--max-work-dir-mb <MiB>` | `4096` | Stop starting new targets once the work directory's allocated size reaches this ceiling. Completed and running targets finish and are reported, so parallel jobs can overshoot by their final artifacts. Findings are never deleted to stay under it. `0` disables the ceiling |
| `--max-corpus-mb <MiB>` | `64` | Per-target ceiling on the retained coverage corpus, both in memory and in `corpus/<harness-id>/queue/`. Finding testcases are stored separately and always kept |
| `--reuse-legacy-corpus` | off | In a work dir from an earlier release (migrated from the 0.2.x layout, or written by an earlier `bhf auto`), keep reseeding its old corpus instead of moving it to `corpus-legacy/` on the first run (see [Seed lineage](#seed-lineage)) |
| `--config <PATH>` | `.bhf.toml` in the tree root | Load run options from a TOML file so a project's runs are reproducible; see [Config file](#config-file). Command-line flags override it, relative paths in it resolve against the file's own directory, and an unknown key is an error. A `.bhf.toml` that is auto-loaded from the scanned tree is untrusted: bhf ignores, with a note, the keys that execute something (`build-command`, `run-untrusted`, `unsafe-search-and-run-build-commands`, `probe-build`, `msbuild-evaluate`, `winafl-path`, `dynamorio-path`, and the `[toolchain]` and `[cross.<guard>]` tables) unless the file is passed with `--config` |
| `--dry-run` | off | Plan only: discover and rank targets, run the toolchain preflight, print the build-recovery plan, and exit without building or fuzzing. Use it to check scope, config and toolchains before a long run |
| `--list-targets` | off | Print the ranked targets (highest score first, with file:line, language and input reachability) and exit without building or fuzzing |
| `--list-fakes` | off | Print the fake-resource plugin inventory and exit |
| `--verbose` / `-v` | off | Print one more line per target: why it was skipped or failed, the repairs applied, and per-pass execution and finding counts |
| `--debug` | off | For problems in bhf itself: record a backtrace for any internal panic (sets `RUST_BACKTRACE`), keep going past a file that crashes bhf, and always write `auto/bug-report.json` and `bug-report.md` |
| `--profile <PROFILE>` | `strict-permissive` | Global license profile, checked against the capabilities named with the top-level `bhf --probe <PROBE>` option. `--external-tools` and `--symcc` take their profile from `BHF_PROFILE` instead (see their rows and [Licensing](licensing.md)) |
| `--deps-only` | off | Build each target as far as it goes, write the missing-dependency manifest (`auto/missing-deps.txt`), and skip fuzzing. Use it to collect everything an offline host needs in one pass |
| `--install-deps` | off | After the sweep, fetch the still-blocking dependencies from the manifest with the package managers present (`apt-get` for known headers and libraries, `alr get` for Ada units). This is the only part of `auto` that uses the network. A manager that is missing or fails is reported with the command to run by hand; nothing is fatal. Re-run `auto` afterwards |
| `--sbom` | off | At the end of the run, write an evidence-graded SBOM and VEX bundle to `<work>/sbom/` (`sbom.json`, `cyclonedx.json`, `vulnerabilities.json`, `openvex.json`, `sbom.csv`). Components a harness drove, according to `auto/run.json`, are marked exercised. `bhf sbom` has finer `--emit` and `--ecosystems` control |
| `--sloc <FILE>` | unset | Write a per-language SLOC breakdown of the tree (files, total, comments, blanks, SLOC), then run as usual. A relative path lands in `<work>/auto/`; a `.json` name writes JSON, any other name a text table |
| `--mode <reporting\|attacking>` | `reporting` | Actionability profile. In `attacking` mode, target scheduling prefers real source targets and dangerous-sink evidence (see [Actionability](#actionability-in-auto-runs)) |

### Time, scale and memory

| Flag | Default | Purpose |
|---|---|---|
| `--per-target-time <SECS>` | `60` | Total fuzz time per target, split evenly across its passes under one shared deadline, like libFuzzer's `-max_total_time` or AFL++'s `-V`. Config key `per-target-time` |
| `--per-target-finding-count <N>` | unset (collect all) | Stop a target once it has N distinct findings (crash signatures), or when its `--per-target-time` is spent, whichever comes first. Checked during a pass; the remaining passes are skipped. `1` matches libFuzzer's stop-on-first-crash |
| `--iterations <N>` | unset | Cap each pass at N executions, like libFuzzer's `-runs`. Unset or `0` lets `--per-target-time` decide |
| `--total-time <SECS>` | unset | Deprecated alias of `--per-target-time`, hidden from `--help`. When set, it overrides `--per-target-time` |
| `--campaign-time <SECS>` | unset (no cap) | Budget for the whole sweep, counted from the first build attempt. Once it is spent, `auto` starts no new target, lets the running ones finish, and reports how many of the discovered targets it reached. Discovery is not charged to it but has its own limit of half the budget (at least 30 s); files not parsed by then are skipped, with a note. With `--min-target-time`, the budget is split across targets instead (see [Split a fixed budget](#split-a-fixed-budget-across-targets)) |
| `--min-target-time <SECS>` | unset | Split mode, valid only with `--campaign-time`: each attempted target gets `max(min, campaign / N)` seconds of fuzzing, and only the top `floor(campaign / per_target)` ranked targets are attempted; the rest are logged as unfuzzed. Overrides `--per-target-time` |
| `--max-targets <N>` | unset (every viable target) | Stop once N targets have reached the fuzz phase. Candidates that do not build or have unsupported parameters do not count, so lower-ranked viable targets fill their places. The sweep also stops at the `--campaign-time` deadline or when candidates run out. `--dry-run` prints the plan; `--list-targets` still prints the full ranked list. Config key `max-targets` |
| `--max-attempts <N>` | unset | Stop after inspecting (building or attempting) N ranked candidates, however many of them fuzzed. Use it on a large legacy tree where most candidates do not build, so the `--max-targets` backfill cannot work through all of them |
| `--jobs <N>` / `-j <N>` | half the host's cores, from 1 to 8 (`BHF_DEFAULT_JOBS` overrides) | Build and fuzz up to N targets at once; `--jobs 1` runs one at a time. Ada targets build one at a time regardless, since they share the staged source tree. Each fuzzing child may use up to `--rss-limit-mb`, so with both defaults the children alone can use more than half the host's memory; bhf, the compilers and the OS need room on top. Results are merged in a fixed order whatever order the jobs finish in. Config key `jobs` |
| `--workers-per-target <N>` | `1` | Run each builtin fuzz pass of a target as N `bhf fuzz` workers, each in its own copy of the work dir. Workers share the corpus entries they keep every `BHF_SYNC_INTERVAL_MS` (default 10000), as `bhf fuzz --workers` does, and their queues and findings merge into the target's (`corpus/<id>/queue`, `results/findings`) when the pass ends; the worker copies are then removed. `fuzz_runs/<id>-latest.json` gains a `workers` block (each worker's executions, queue entries and the peer entries it ran); its `hangs`, `fresh_reruns` and `symcc` counts are summed over the workers and its `stability` is the least stable worker's. `run.json` and `run.md` count all workers' executions and hangs, and with `--symcc` each worker's `symcc-import.log` lines are appended to `<work>/symcc-import.log`. With `--jobs J` that is up to J × N fuzz processes, each with its own `--rss-limit-mb`. A cross-built target run under an emulator, and the AFL++ engine, use one worker. `--per-target-finding-count` is checked between passes, not inside one |
| `--passes <SET>` | `empty,rng,fuzz` | Run only these passes, comma-separated (`empty`, `rng`, `fuzz`; `fuzz` is the `fuzz_driven` pass), in the order given. The passes share `--per-target-time`, so `--passes fuzz` gives the fuzz-driven pass the whole budget instead of a third of it. Cannot be combined with `--single-pass`; ignored with `--deps-only` |
| `--single-pass` | off | Same as `--passes fuzz` |
| `--rss-limit-mb <MB>` | a quarter of available host or cgroup memory, from 512 to 8192 MiB | Per-harness resident-memory ceiling. An input that allocates past it is killed and reported as a BHF-209 out-of-memory finding instead of exhausting the host. `0` disables it. Config key `rss-limit-mb` |
| `--timeout <DUR>` | `10s` | Per-execution timeout (`10s`, `500ms`). An execution past it is killed, and an input that hangs again when re-run with twice the timeout is a hang finding (BHF-230; see [Sanitizers: Hangs](sanitizers.md#hangs)). `run.md` and `run.json` count the hangs. Config key `timeout` |
| `--deadline <DUR>` | off | Response deadline for every fuzzed target (`50ms`, `1s`): an input whose execution takes longer, in two of three fresh re-runs as well, is a response-deadline finding (BHF-555). It must be shorter than `--timeout`; `0` or a longer value is refused (exit 2). Config key `deadline` |

### Target selection

| Flag | Default | Purpose |
|---|---|---|
| `--languages <LIST>` (alias `--lang`) | every language found | Fuzz only these languages, comma-separated: `ada`, `c`, `cpp`, `rust`, `java`, `python`, `perl`, `go`, `cobol`, `fortran`, `csharp`, `javascript`, `typescript`, `ruby`, `lua`, `php`. Common spellings work, case-insensitively (`c++`, `cxx` and `cc` for cpp, `rs` for rust, `py` for python, `pl` for perl, `golang` for go). Other languages are dropped after discovery, so one discovery cache serves every subset, and before `--list-targets` and `--max-targets`, so both reflect the filter. The SBOM pass still scans every ecosystem in the tree. Config key `languages` |
| `--target <NAME>` | every discovered target | Fuzz only the targets this name selects: the full discovered name (as `--list-targets` prints it), the bare name, or a qualified suffix (`Class::method`), each optionally with its parameter list. An exact spelling wins; the suffix match applies only when no target has exactly that name, and a leading `::` names the global namespace only. Repeatable. A name that matches nothing prints the closest names. This also selects a project fuzz driver (`LLVMFuzzerTestOneInput`), which `auto` otherwise skips when the tree has other targets |
| `--target-file <PATH>` | every source file | Fuzz only the targets in this file, given as an absolute path or relative to the sweep root. Repeatable |
| `--harness-id <ID>` | every harness id | Fuzz only the target with this stable harness id, as an earlier `run.md` or `run.json` names it. Repeatable |
| `--exclude-path <TEXT>` | none | Drop targets whose normalized relative source path contains `TEXT`. Repeatable. Config key `exclude-path` |
| `--exclude <tests,tools,examples>` | none | Drop these common project areas before any attempt runs |
| `--exclude-dir <NAME>` | none | Skip directories with this name during discovery, on top of the defaults (see [Discovery](#discovery)). Matched case-insensitively on the whole path component. Repeatable |
| `--include-dir <NAME>` | none | Keep directories with this name that a default would skip (`--include-dir tools` for a project whose parser lives in `tools/`). Repeatable |
| `--preprocess <auto\|always\|never>` | `auto` | Run the CPP-lite preprocessor over C and C++ files before discovery, so a function compiled out under the active configuration is not discovered; a line map keeps reported locations right. `auto` preprocesses only files with heavy conditional compilation (see [C and C++: Discovery](c-cpp.md#discovery)) |

### Discovery cache and resume

| Flag | Default | Purpose |
|---|---|---|
| _(discovery cache)_ | on | Discovery is saved to `<work>/discovery-cache.json` and reused when a content fingerprint of the target source (file paths, sizes, content hashes and the directory filter) is unchanged, skipping the tree-sitter parse and ranking, the largest cost of a re-run on a big tree. The fingerprint depends only on the fuzzed code, so rebuilding bhf keeps it valid. A mismatch recomputes and rewrites the cache; a stale cache is never used |
| `--discovery-cache <PATH>` | `<work>/discovery-cache.json` | Keep the cache at this path instead, for example on a known volume or across work dirs |
| `--fresh-discovery` | off | Discover again this run, ignoring the cache, then overwrite it |
| `--no-discovery-cache` | off | Never read or write the cache |
| `--reuse-discovery` | off | Deprecated, no effect: caching is the default. Hidden from `--help` |
| `--resume` | off | Continue a sweep in the same work dir: reload the targets that completed and run only the rest. Each target writes `harnesses/<id>/result.json` the moment it finishes, so an interrupted run can be resumed. A reloaded target appears in the new `run.json` and `run.md` with its outcome, repairs, findings and per-pass detail, and the report counts it under `resumed`. Results are reused only while the build context is unchanged, and per source file: a target whose own file changed is attempted again. With `--no-discovery-cache` bhf records no source files, so a target whose file changed is reused too. A target whose toolchain was missing (`missing_toolchain`), whose sanitizer runtime could not start (`sanitizer_runtime_unavailable`), or that needed `--run-untrusted` (`consent_required`) is always attempted again, since the host may have been fixed or this run may give the consent. In a work dir written by a different bhf build, targets that fuzzed are kept and the rest are attempted again |

### Build recovery

| Flag | Default | Purpose |
|---|---|---|
| `--max-repair-rounds <N>` | `16` | Ceiling on build, repair and retry rounds per target. The loop still stops at the first round with no new repair, so this is a cap, not a fixed cost. 16 covered every successful build in a 53-repository validation matrix of clean and damaged projects (95th percentile 6 rounds, maximum 14). A low value (2 or 3) gives up on hard-to-build targets quickly in a triage sweep |
| `--no-stubs` | off | Do not stub at build time; report the diagnostics only |
| `--force` / `--force-fuzz` | off | Add a second phase. The sweep first runs as it would without the flag, then retries only the targets that did not reach the fuzz phase, forced: a best-effort driver for opaque, function-pointer or unknown parameters, stubs for every symbol the compiler reports undefined, and report-only as the worst outcome. Go drives an undrivable parameter as its type's zero value and calls a method on a zero receiver; C# allocates a receiver whose type has no accessible parameterless constructor without running a constructor. A forced retry can only replace an outcome with a fuzzed one, so `--force` never lowers the fuzzed count, and it cannot help a target whose parameters were never the problem. Findings from a forced build are set to **Low** confidence with a `forced` note and counted separately, since a stub can cause a crash of its own. With `--resume` over a finished campaign it keeps every target that fuzzed and forces only the rest, without repeating the unforced attempt. It honors `--max-repair-rounds` and does not imply `--static`. Config key `force` |
| `--extra-include <DIR>` | none | Extra C/C++ include directories for dependency headers outside the swept tree, put on every harness's `-I` path ahead of synthesized placeholders. Read from local disk only; paths with spaces are quoted. Repeatable. Config key `extra-include` |
| `--extra-source <FILE>` | none | More C/C++ sources (`.c`, `.cpp`) compiled and linked into every harness, for a library whose target calls into sibling translation units that would otherwise be stubbed. Read from local disk only. Repeatable. Config key `extra-source` |
| `--cxx-std <STD>` | auto | Pin the C++ standard for every harness build (`gnu++14`, `c++03`). By default `auto` builds C++ at the modern standard and, on a dialect error, retries older standards (`gnu++17`, `gnu++14`, ... `gnu++98`) until one builds, caching the choice per project. Config key `cxx-std` |
| `--no-fuzzing-build-mode` | off | Build without `-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`, which every C/C++ lane otherwise defines (OSS-Fuzz's convention), so code a project leaves out of fuzz builds, such as a signature check, runs. `BHF_FUZZING_BUILD_MODE=0` does the same |
| `--probe-build` | off | Run the project's own build offline to recover its real compile flags and generated headers. Detects and drives CMake, Meson, Visual Studio, Make and autotools (through a compiler-interposing wrapper), Ninja, and, under compiler interception, Bazel and SCons. It builds under `<work>/probe/`, never in the tree (CMake and Meson into a build directory there; Make and intercepted commands in a copy of the tree), so the tree stays byte-identical and a read-only checkout can be probed. A probe that yields no compile database says why. EXECUTES the project's build scripts, sandboxed with bwrap or firejail when one is installed and with the tree read-only. Config key `probe-build` (explicit `--config` only) |
| `--build-command <CMD>` | unset | Recover flags from any other build (a `build.sh`, Waf, a vendor RTOS build) by running `<CMD>` under two interceptors: a compiler shim placed first on `PATH` for `cc`, `gcc`, `clang`, the named vendor compilers (Diab, Green Hills, QNX, Keil/IAR, TI) and cross-prefixed toolchains, and an `LD_PRELOAD` exec interposer for compilers started by absolute path or `posix_spawn`. Takes a script (`--build-command ./build.sh`) or a full command (`--build-command "make -C src lib"`), run through `sh -c` (on Windows through `cmd.exe`, with executable shims and an MSBuild build captured through its CL task; see [Windows](windows.md)). Takes precedence over the auto-detected build. EXECUTES the command, sandboxed when available. When builds fail and the tree has a custom build script, `auto` prints a ready-to-run hint with this flag. Config key `build-command` (explicit `--config` only) |
| `--run-untrusted` | off | Consent for builds that run project code: `--probe-build`, the Ada build probe (`alr build` / `gprbuild`), Rust builds (Cargo build scripts and proc macros), C# builds (MSBuild targets), and Java Maven or Gradle builds. Java builds run Maven offline or Gradle `--offline`, so stage the dependencies first; bare Java source still builds with `javac` without this flag. Without it, a Rust or C# target, and a Java target whose `javac` fallback also fails, is reported as `consent_required` ("needs --run-untrusted"). Implies `--probe-build`. Language project builds run as the calling user; isolate the host or its network yourself. Direct compilers, interpreters and the selected target run in every `auto` run, with or without this flag. Config key `run-untrusted` (explicit `--config` only) |
| `--unsafe-search-and-run-build-commands` | off | Search the tree for its own build entry point and EXECUTE it to recover flags, instead of you passing `--build-command`. Finds a custom build (`build.sh`, autotools `bootstrap`/`autogen`/`configure`, SCons, Waf, Bazel) and runs it under the compiler-intercepting shim, and turns on the `--probe-build` tiers (CMake, Meson, Make) and the Ada build probe. Runs sandboxed when available, but it executes code from the scanned tree: use it only on sources you trust. An explicit `--build-command` takes precedence. Config key `unsafe-search-and-run-build-commands` (explicit `--config` only) |
| `--msbuild-solution <PATH>` | shallowest `.sln`/`.slnx` | The Visual Studio solution the default project import reads. The import applies to a tree with a solution or `.vcxproj` and no compile database or CMake/Meson build; off Windows, only when the solution is the tree's only build description, unless this flag names it. A relative path is resolved against the scanned tree, a solution outside the tree is imported too, and a missing file is an error. The import runs nothing: it evaluates the projects' property sheets and `Condition=`s for one configuration and writes `<work>/auto/msbuild/compile_commands.json`. See [C and C++: Visual Studio solutions](c-cpp.md#visual-studio-solutions) |
| `--msbuild-config <CONFIG\|PLATFORM>` | first listed for x64 | The configuration the project import applies (`Release\|x64`) |
| `--no-msbuild-import` | off | Do not import a Visual Studio solution |
| `--msbuild-evaluate` | off | Let an installed MSBuild evaluate the imported projects (`msbuild -getItem:ClCompile`), with the static reading as the fallback. Evaluation runs the projects' property functions and imported `.props`/`.targets` files, code from the scanned tree, so it is opt-in (see [Windows](windows.md)). `--probe-build` and `--run-untrusted` imply it. Config key `msbuild-evaluate` (explicit `--config` only) |
| `--project <PATH>` | the project that owns each target's source | The Ada project (`.gpr`) to use for generation, staging, scenario exclusions and the build, when a multi-project layout is ambiguous. By default `auto` takes the non-aggregate project whose active `Source_Dirs` hold the target's source. A missing path is an error. Config key `project` |
| `--ada-deps <DIR>` | none | Local Ada dependency source directories to put on the build path (never fetched). Repeatable. Locally cached Alire dependencies under the project are picked up automatically. Config key `ada-deps` |
| `--rust-private` | off | Harness private Rust targets inside the crate: admit `pub(crate)` and private functions and methods, and inject each harness as a module into a copy of the crate so it calls them by their `crate::` path, with a path-backed resource for a target that opens one. `rust-private = true` in the config, or `BHF_RUST_INCRATE_PRIVATE=1`, turns it on too. A target the lane admits but cannot set up (a parameter or resource it has no recipe for) has the outcome `unsupported_setup`. The crate's build needs `--run-untrusted`, as every Rust build does |

### Compilers and cross builds

| Flag | Default | Purpose |
|---|---|---|
| `--cc <PROGRAM>` / `--cxx <PROGRAM>` | `clang` / `clang++` | C/C++ compiler for every harness build (a name on `PATH` or a path), replacing `CC`/`CXX`. The generated Makefile picks matching instrumentation for gcc, a cross-prefixed gcc, or clang, so no flag needs adapting. A C++ compiler derived from `--cc` or `--target-triple` (`g++` next to `gcc`) must exist only when the sweep has a C++ candidate. The choice is printed. Config keys `toolchain.cc` / `toolchain.cxx` |
| `--cflags <FLAGS>` / `--cxxflags <FLAGS>` / `--ldflags <FLAGS>` | none | Extra compile and link flags, appended after bhf's coverage and sanitizer flags (whitespace-separated; repeatable). Their preprocessor words (`-D`, `-U`, `-I`, `-isystem`, `-include`) and the library operands of `--ldflags` (`-L`, `-l`, archives, objects, `-Wl,...`, `-Xlinker ...`, `-pthread`, in order, with the `-fuse-ld=` or `--ld-path=` they are written for) reach every build lane: coverage, AFL++, libFuzzer, MSan, TSan and differential. The other flags apply to the lanes built with `$(CC)`/`$(CXX)`. A `CFLAGS`/`CXXFLAGS` in the environment is appended to the `main` build too, after bhf's flags, except in a build whose compiler bhf picked in place of yours (a platform guard's cross lane, the `--sanitizers` clang fallback). A lane that still fails to build is reported in `run.json` (`targets[].lanes`, with `recorded_at`), `summary.txt` and `run.md`; a lane of a target `--resume` reloaded is marked as recorded by an earlier run. Config keys `toolchain.cflags` / `toolchain.cxxflags` / `toolchain.ldflags` |
| `--define <NAME[=VALUE]>` / `--toolchain-include <DIR>` | none | Preprocessor definitions and `-I` directories for every harness compile and every lane, bhf's driver object included. Repeatable. Config keys `toolchain.defines` / `toolchain.include-dirs` |
| `--sysroot <DIR>` | unset | Passed to the compiler as `--sysroot=`, and to a qemu-user runner as `-L <DIR>` when no `--runner-arg` is given. Config key `toolchain.sysroot` |
| `--target-triple <TRIPLE>` | host | Build every C/C++ candidate for this GNU triple (`aarch64-linux-gnu`), with `<triple>-gcc` and `<triple>-g++` unless `--cc`/`--cxx` name the compilers (a clang gets `--target=`). A triple the host cannot run needs `--runner`. Config key `toolchain.target` |
| `--runner <PROGRAM>` / `--runner-arg <ARG>` | unset | Program that runs each harness built for another target (`qemu-aarch64`), with its arguments placed before the harness. With `--target-triple` or a cross `--cc` the whole sweep is a cross sweep: every C/C++ candidate is built for the target with coverage and fuzzed under the runner. With only a foreign `--ada-target`, it runs the Ada harnesses and the C/C++ candidates stay native. A runner with nothing foreign to run is an error. See [Cross-Compilation](cross-compilation.md#whole-sweep-cross-targets). Config keys `toolchain.runner` / `toolchain.runner-args` |
| `--ada-prefix`, `--ada-target`, `--ada-runtime`, `--ada-gprbuild`, `--ada-gnat`, `--ada-switch`, `--probe-backend` | host GNAT; `host_file` | The Ada toolchain for every Ada harness build: the tool prefix (`<prefix>-gnat`), `for Target use`, `for Runtime ("Ada") use`, explicit `gprbuild` and `gnat` programs, extra compiler switches appended to bhf's, and the AdaFuzz probe backend (`host_file`, `memory_buffer`, `semihosting`, `stub`). `--ada-target` defaults to `--target-triple`. When the tree has Ada candidates the toolchain must be installed (a `<prefix>-gprbuild`, or `gprbuild` with `<prefix>-gnat`, or the explicit programs), or the run and `--dry-run` stop with exit 2 naming the key. A probe backend other than `host_file` needs an on-target transport, so a host sweep without a runner refuses it; `bhf build` refuses it too for an Ada harness built for this host. The choice is printed. Config keys `toolchain.ada.prefix`, `toolchain.ada.target`, `toolchain.ada.runtime`, `toolchain.ada.gprbuild`, `toolchain.ada.gnat`, `toolchain.ada.switches`, `toolchain.ada.probe-backend` |

### Fuzzing

| Flag | Default | Purpose |
|---|---|---|
| `--engine <LIST>` | `builtin` | Fuzz engines for the fuzz phase, comma-separated. `builtin` is bhf's in-process coverage-guided engine. `afl++` drives AFL++ on the recovered build for C/C++, COBOL, Fortran, Rust and Ada targets; it needs `afl-fuzz` and `afl-clang-fast` on `PATH` and otherwise falls back to builtin with a warning, as it does for a target of another lane. `--engine builtin,afl++` runs both and splits `--per-target-time` between them. `winafl` drives WinAFL for C/C++ targets on native Windows (refused elsewhere): it fuzzes a build without sanitizers and replays each saved crash and hang through the sanitized harness. Config key `engine` |
| `--sanitizers <LIST>` | `address,undefined` | Sanitizers for native C/C++ builds, comma-separated: `asan`, `ubsan`, `lsan`, `msan`, `tsan`, `hwasan`, `cfi`, `realtime`, or `none`. `asan`, `ubsan` and `lsan` combine; `msan` and `tsan` each stand alone. `hwasan` takes ASan's place on an AArch64 host and is refused on any other. `cfi` is not armed in the fuzzed build: it adds a control-flow-integrity replay of the corpus after the fuzz passes. `realtime` (clang 20+) likewise adds a RealtimeSanitizer replay of the nonblocking targets' corpora. `none` builds with coverage and no `-fsanitize=`, for crash-only fuzzing of code that floods ASan with false positives (shared memory, custom allocators, RTOS code). Your `<SAN>_OPTIONS` (suppressions, `detect_container_overflow=0`) are merged with bhf's, not replaced. Other lanes own their instrumentation. See [Sanitizers](sanitizers.md). Config key `sanitizers` |
| `--nonblocking <entry-points\|all\|NAME>` | `entry-points` | With the `realtime` sanitizer: the targets that run in a real-time context, so RealtimeSanitizer reports each allocation, lock, sleep or system call they make. `entry-points` marks interrupt handlers and RTOS task bodies, `all` every target, and a name that target (repeatable). An error without `--sanitizers ...,realtime`. See [Sanitizers](sanitizers.md#the-realtimesanitizer-replay). Config key `nonblocking` |
| `--comparison-progress` (alias `--cmp-progress`) | off | laf-intel comparison-progress coverage for C/C++: the engine rewards an input that matches more leading bytes of a multi-byte magic value or format check |
| `--seed-file <PATH>` | none | Seed input file whose bytes start every target's corpus, used byte for byte (binary formats included). Repeatable. Any explicit seed turns seed mining off, even one that loads nothing (a missing file, an empty directory). Config key `seed-file` |
| `--seed-dir <DIR>` | none | Directory of seed inputs, one per regular file, in name order. Repeatable. Config key `seed-dir` |
| `--no-seed-mining` | off | Do not seed targets from the tree's own test-data files (see [Seeds](#seeds)). Config key `seed-mining = false` |
| `--grammar <PATH>` | unset | JSON grammar of the target's input format, for structure-aware generation (a Nautilus-style grammar mutator) on every fuzzed target. Each rule maps a non-terminal to production strings in which `{NAME}` references another rule; the start symbol is `START` or the first rule. A bad grammar fails the run before it starts. Config key `grammar` |
| `--max-len <N\|auto>` | `auto` | Maximum input length. `auto` lets each target's inputs grow freely up to about 1 MiB, and beyond that only while longer inputs keep finding new coverage, so a large-object target (image, archive, firmware) needs no seed corpus. A positive integer sets a fixed cap. Seeds are kept whole up to the cap for both engines. With `--engine afl++`, a fixed cap below AFL++'s 1 MiB default is passed to afl-fuzz as `-G` when it supports it (AFL++ 4.00c and later); an older afl-fuzz gets only the capped seeds, with a note on stderr. Config key `max-len` |
| `--max-array-elems <N>` / `--max-decode-depth <N>` / `--max-decl-bytes <BYTES>` | `64` / `4` / `65536` | C decoder bounds: elements decoded per fixed array (a larger array fuzzes its fill count instead), the nesting depth of struct, union and array decoders (deeper fields stay zero), and the size ceiling of one parameter's decoder (a larger one rejects the parameter) |
| `--container-size-max <N>` / `--array-max-size <N>` / `--bitset-max-size <N>` | `16` / `4096` / `4096` | C++ decoder bounds: a dynamic container's element count (`vector`, `set`, `map`, `span`, ...; also limited by the 1 MiB per-parameter budget), the largest `std::array<T, N>` accepted when `T`'s size is unknown at generation time, and the largest `std::bitset<N>` decoded bit by bit |
| `--differential <A:B>` | unset | Two-compiler differential fuzzing for C/C++, such as `clang:gcc`. After the normal run, each C/C++ harness is rebuilt under both compilers and its corpus replayed through both; an input whose exit or crash behavior differs (a code-generation or undefined-behavior bug) is a BHF-301 finding. Either side may be a compiler path; a path with spaces is quoted |
| `--symcc` | off | Build a SymCC variant of each native C/C++ harness (`make symcc` gives `main_symcc`, built with SymCC's `symcc` for C and `sym++` for C++), a concolic lane that solves comparisons against values the input holds only after hashing or modular arithmetic. SymCC is GPL-3.0 and runs only as a subprocess, under a license profile that permits it: `BHF_PROFILE=external-tools` or `research-lab`. Without `BHF_PROFILE` the flag selects `external-tools`; `BHF_PROFILE=strict-permissive` refuses it, with a note. Needs `symcc` and `sym++` on `PATH` (`scripts/ci/install-symcc.sh` builds them), or `SYMCC_CC`/`SYMCC_CXX` naming them; `sym++` uses the system C++ library unless `SYMCC_LIBCXX_PATH` names a SymCC-instrumented libc++. A harness whose SymCC build fails is fuzzed without it, and `run.json` `targets[].lanes.symcc` says why. In each builtin pass of a harness with the lane, once the corpus has not grown for `BHF_SYMCC_PLATEAU_MS` (default 5000), the newest entries SymCC has not run (`BHF_SYMCC_ENTRIES` per round, default 8) go through `main_symcc`, each for at most `BHF_SYMCC_TIMEOUT_MS` (default 10000), under the harness's sandbox and with `--rss-limit-mb` as its address-space limit. Every new input SymCC solves runs next and stays in the corpus when it adds coverage. A line after the pass says what SymCC solved; `fuzz_runs/<id>-latest.json` has the pass's `symcc` counts and `<work>/symcc-import.log` lists each input it gave. Three SymCC runs in a row that fail or time out without an input stop the loop for that pass. `BHF_SYMCC=1` does the same as the flag, and also turns the loop on for `bhf fuzz` of a harness with `main_symcc` beside it |
| `--collector <SPEC>` | `none` | Runtime-event collector run after each fuzzed target's passes: the target's retained inputs (its findings, then its corpus, at most 16) are replayed one by one under it, as `bhf fuzz --collector` does. `auto` selects the platform's provider (the native Windows ETW provider, or the runtrace shim on Linux); a path runs an external sidecar that speaks `bhf.collector-event.v1`. A violation the runtime oracles did not already report becomes a `binary_semantic` finding with its input, and each target in `run.json` carries its `collector` observation (each replay's testcase, input SHA-256 and PID) |
| `--collector-window-ms <MS>` | `250` | How long the collector keeps watching a replayed input's descendant processes after it exits |
| `--cxx-expected-exception <TYPE>` | none | A C++ exception type an API throws to report bad input to its callers (`std::invalid_argument`, `json::parse_error`; `*` for any type). Such an exception leaving the target is not an uncaught-exception finding (BHF-231). Any other exception that leaves a C++ target is one, since it would terminate a program that calls the target the same way, and one that escapes a `noexcept` function always is. Repeatable. Sets `BHF_CXX_EXPECTED_EXCEPTIONS`, which `bhf fuzz` children read too. Config key `cxx-expected-exception` |
| `--no-minimize` | off | Skip minimizing each root-cause representative after fuzzing. Minimization is bounded to 30 s per group and 5 min in all, works on the crash for C/C++ and on the event-log signature for Ada, and writes `min_testcase.bin` |

### WinAFL (native Windows)

| Flag | Default | Purpose |
|---|---|---|
| `--winafl-path <DIR>` / `--dynamorio-path <DIR>` | `BHF_WINAFL_PATH`, then `afl-fuzz.exe` on `PATH` / `BHF_DYNAMORIO_PATH`, then `DYNAMORIO_HOME`, then `drrun.exe` on `PATH` | WinAFL's directory (holding `afl-fuzz.exe` and `winafl.dll`) and DynamoRIO's install root (or its `bin64`) for `--engine winafl`; see [Windows](windows.md#installing-winafl-and-dynamorio). Config keys `winafl-path` / `dynamorio-path` (explicit `--config` only) |
| `--winafl-instrumentation <dynamorio\|intel-pt>` / `--winafl-iterations <N>` / `--winafl-coverage-module <MODULE>` | `dynamorio` / `5000` / none | WinAFL's coverage source (DynamoRIO, `afl-fuzz -D`; or Intel PT, `-P`, which needs an Intel CPU, a WinAFL built with `-DINTELPT=1` and no virtual machine in between unless the hypervisor passes PT through), its `-fuzz_iterations` (persistent-entry calls per process), and another module (a target DLL) to measure coverage in (repeatable) |
| `--winafl-page-heap` | off | Run the WinAFL build under full PageHeap, so a heap overflow faults as a crash. WinAFL fuzzes a copy of `main_winafl.exe` under a name only the run uses, with an Image File Execution Options key that bhf sets and removes after the run. Needs an elevated shell and is refused up front otherwise |

### Static analysis

| Flag | Default | Purpose |
|---|---|---|
| `--static` | off | Run the static analyzer over the whole tree as well as fuzzing. Its findings (classification `static_scan`, ids `F-STATIC-*`) merge into `findings.csv`, `run.json` and the SARIF log next to the fuzz findings, so a target that fuzzed also gets static analysis, and files with no fuzzable function are analyzed too. Same engine as `bhf static-scan`. bhf's own harnesses and stubs in the work dir are excluded, and dependency, build and cache trees (`node_modules`, virtualenvs, `dist`, vendored dependencies, generated JavaScript `compiled/` bundles) are pruned before analysis. Without this flag, the analyzer runs only on targets that could not be built or fuzzed |
| `--external-tools` | off | Also run installed external analyzers (gosec, Bandit, semgrep, GNATcheck) as subprocesses, never linked in, and merge their SARIF into the report (ids `F-EXT-*`), where the [fuzz-confirmation](#fuzz-confirmation) join applies to them too. Each tool runs only if the license profile permits its subprocess. The profile comes from `BHF_PROFILE`; without it, the flag selects `external-tools`, and `BHF_PROFILE=strict-permissive` runs none. Missing tools are skipped. Implies `--static` |
| `--static-dynamic` | off | Deprecated, no effect. `results/findings.csv` always marks a static row apart from a fuzzed one in its `kind` column, and says whether fuzzing confirmed it in `confirmation` |

## Config file

A config file holds run options as TOML. Pass it with `--config <PATH>`, or
put it in the scanned tree's root as `.bhf.toml`, where `auto` loads it
without the flag. A key applies when the command line does not give its flag;
a flag on the command line wins even when it repeats the default value.
Relative paths resolve against the config file's directory, so the file means
the same thing from any working directory. Only these keys exist, each
spelled like its flag:

- Run budget and limits: `per-target-time`, `max-targets`, `jobs`,
  `rss-limit-mb`, `max-work-dir-mb`, `max-corpus-mb`, `max-len`, `timeout`,
  `deadline`.
- Build inputs: `cxx-std`, `grammar`, `extra-include`, `extra-source`,
  `exclude-path`, `project`, `ada-deps`, `cxx-expected-exception`.
- Seeds and selection: `seed-file`, `seed-dir`, `seed-mining = false` (the
  `--no-seed-mining` flag), `sanitizers`, `nonblocking`, `engine`,
  `languages`, `passes`, `force`, `rust-private`.
- Explicit `--config` only, because they execute something: `build-command`,
  `run-untrusted`, `unsafe-search-and-run-build-commands`, `probe-build`,
  `msbuild-evaluate`, `winafl-path` and `dynamorio-path` (the WinAFL and
  DynamoRIO installs `--engine winafl` runs), the `[toolchain]` table and the
  `[cross.<guard>]` tables.

The other flags (target selection, `--resume`, `--dry-run`, output and
diagnostic switches) have no key.

The `[toolchain]` table is shared with `bhf build --config`:

```toml
[toolchain]
cc = "aarch64-linux-gnu-gcc"     # program on PATH, or a path
cxx = "aarch64-linux-gnu-g++"
cflags = ["-O1"]                 # appended to bhf's instrumentation
cxxflags = []
ldflags = []
defines = ["BOARD=3"]            # NAME or NAME=VALUE
include-dirs = ["vendor/include"]
target = "aarch64-linux-gnu"     # without cc/cxx: <target>-gcc / <target>-g++
sysroot = "/opt/sdk/sysroot"
runner = "qemu-aarch64"          # runs whatever is built for another target
runner-args = ["-L", "/usr/aarch64-linux-gnu"]

[toolchain.ada]
prefix = "aarch64-linux-gnu"     # <prefix>-gnat; also the Target by default (Ada only)
gprbuild = "/opt/gnat/bin/gprbuild"
gnat = "/opt/gnat/bin/aarch64-linux-gnu-gnat"
target = "aarch64-linux-gnu"     # defaults to [toolchain] target
runtime = "light"
switches = ["-O1"]
probe-backend = "memory_buffer"
```

Every value is checked before the sweep starts. Each of these is an error
that names the key:

- an unknown key;
- a define that is not `NAME[=VALUE]`, or a target that is not a triple;
- `runner-args` without a `runner`;
- a compiler or runner that is not installed;
- a target (C/C++ or Ada), or a C/C++ compiler (including `CC`/`CXX` from the
  environment), that builds for a platform the host cannot run, with no
  runner;
- a runner with nothing foreign to run.

The C/C++ candidates become a cross sweep only when the C/C++ side builds for
another target (`target`, or a cross `cc`). A runner set for a foreign
`[toolchain.ada] target` alone runs only the Ada harnesses, and the C/C++
candidates keep their native sanitizer builds. In a cross sweep, the static
archives that `probe-build`, `build-command` or `run-untrusted` built for this
host (in the probe directory, or in the tree for a plain Makefile) are rebuilt
for the target from the captured compile commands and linked in their place;
an archive that cannot be rebuilt is named with the reason. In a native sweep
with a GCC toolchain, the build probe builds its archives with that GCC and
GCC-spelled instrumentation. See
[Cross-Compilation](cross-compilation.md#whole-sweep-cross-targets).

A `[cross.<guard>]` table overrides the toolchain and emulator of one
guard-driven cross lane, the lane that candidates guarded for that platform
are built in:

```toml
[cross.aarch64]                  # lanes: mingw, aarch64, armhf, ppc64le, ppc64, ppc, mipsel, mips, sparc64
cc = "/opt/arm/bin/aarch64-none-linux-gnu-gcc"   # cxx follows (g++), or set cxx
target = "aarch64-linux-gnu"     # without cc/cxx: <target>-gcc / <target>-g++
sysroot = "/opt/arm/sysroot"     # --sysroot= for every compile and link, bhf's driver included
runner = "qemu-aarch64"          # program that runs the harness
runner-args = ["-L", "/opt/arm/sysroot"]
```

A key left out keeps bhf's built-in choice for the lane, and a clang `cc` gets
`--target=<triple>`. See
[Cross-Compilation](cross-compilation.md#overriding-the-toolchain-for-a-lane).

An Ada harness's project extends the governing project and its `package
Compiler`: bhf's switches follow the parent's `Default_Switches ("Ada")`, so a
switch the sources need (`-O1`, a `-gnateD` symbol) stays; add further ones
with `switches`.

`toolchain.cflags` reach bhf's driver object as well as the target's
translation units (without `-std=` and `-Werror`), so an ABI-selecting flag
(`-m32`, `-mabi=...`) applies to the whole link. In a C++ harness the driver,
which is C compiled by the C++ compiler, takes only the `cxxflags` that select
the ABI or target (`-m*`, `--target=`, `-fPIC`, `-fshort-wchar`, ...) and
`-D`/`-U`/`-I`/`-isystem`, so a C++-only flag such as `-include iostream` or
`-fno-rtti` reaches the target and not the driver.

Every sanitized lane, the gcc probe build and a capsule's `build.sh` end
their compiles with `-U_FORTIFY_SOURCE -Wp,-U_FORTIFY_SOURCE
-Wp,-D_FORTIFY_SOURCE=0`, after the build context's and the toolchain's
flags: glibc's fortification, on by default in Ubuntu's gcc and in many
distributions' build flags, would otherwise abort an overflow in a fortified
call (`*** buffer overflow detected ***`) before AddressSanitizer reports it.
The `-Wp,` words win over a `-Wp,-D_FORTIFY_SOURCE=N` in the build flags
(Fedora's, RHEL's and Arch's spelling), which the compiler applies after
every plain `-D` and `-U`.

## Outputs and disk cleanup

Start with `<work>/results/INDEX.md`. It lists the findings by impact, each
with its source location, confidence, evidence links, remediation and replay
command. The machine-readable root-cause indexes are
`<work>/results/findings.json` (schema `bhf.findings.v1`) and
`<work>/results/findings.csv`; `results/findings.sarif` is the SARIF log, and
`<work>/results/findings/<id>/` holds each finding's evidence. How the
campaign ran, and the coverage notes, are in `auto/run.md`, `auto/run.json`
and `auto/summary.txt`. [Outputs](#outputs) shows the whole tree.

bhf deletes each Rust Cargo `target/` tree as soon as the final replay harness
is linked. To reclaim those caches and other scratch files from an older or
interrupted run, while keeping findings, reports, corpora, result checkpoints,
generated source and replay binaries, run:

```sh
bhf clean bhf_work --compact
```

At startup, `auto` also removes the private Cargo target trees older releases
left behind, and at the end of a run it compacts scratch data. The
work-directory ceiling (`--max-work-dir-mb`, 4096 MiB by default) counts
allocated filesystem blocks, does not follow symlinks, and stops admitting
new targets instead of deleting evidence. Targets already running finish, so
parallel runs can overshoot it by their final artifacts. The report records
when the ceiling stopped the campaign; `--max-work-dir-mb 0` disables it.

## Harness setup

In every lane, a generated harness records a checkpoint immediately before it
calls the selected target. A harness that decodes input, loads a module or
runs setup and never reaches that call is reported as `built_not_entered`, not
as a fuzzed target. Target ranking reads identifier tokens: it puts public
parsers, decoders, whole-artifact entry points and stateful execution surfaces
first and moves debug and reporting helpers down (see [Target
Ranking](target-ranking.md)).

The lane generators also write the call setup a fuzzing engineer would
otherwise write by hand:

- JavaScript, Ruby and COBOL back a path argument with a temporary file.
- JavaScript awaits an asynchronous call before cleanup.
- Go can mine a one-input feeder call followed by a zero-argument terminal
  call.
- PHP constructs bounded, typed value objects recursively.
- C++ handles defaulted arguments, common public member templates and
  byte-string instantiations.
- Fortran emits descriptors for assumed-shape character arrays.
- C# instruments the project's IL in a separate target assembly.
- Go coverage retries the selected package alone when module-wide
  instrumentation fails on unrelated platform packages.

Private Rust targets need `--rust-private`. Projects with generated or
platform-specific build graphs, framework hosts, scientific arrays with
coupled dimensions, or longer constructor, feed, execute and cleanup
protocols need a hand-written wrapper; such a target is reported with the
reason it was not fuzzed. The [200-project expert harness parity
audit](harness-parity-audit.md) compares these generators with
hand-written drivers, lane by lane.

### Scaling to large trees

A project of modest size can have hundreds of candidates: one large header
(a header-only C/C++ library is the common case) expands into hundreds of
fuzzable signatures. By default `auto` analyzes and fuzzes every candidate,
with no cap on the total run time, and the declaration-index phase can run
for tens of seconds with little output. When a tree has more than 150
candidates and neither `--max-targets` nor `--campaign-time` is set, `auto`
prints a hint naming the flags that bound the run:

- `--max-targets N` stops once N targets reach the fuzz phase (candidates
  that do not build are skipped and lower-ranked ones fill in);
  `--max-attempts N` also bounds how many candidates are inspected.
- `--campaign-time SECONDS` caps the whole sweep. Add `--min-target-time` to
  split the budget evenly instead of stopping at a deadline.
- `--jobs N` builds and fuzzes N candidates at once.

For a tree with tens of thousands of candidates, combine them into a bounded
triage sweep:

```sh
bhf auto path/to/huge-tree \
  --max-targets 500 \
  --single-pass \
  --max-repair-rounds 3 \
  --jobs 2 \
  --campaign-time 3600
```

This run reuses the cached discovery when the source is unchanged, stops once
500 targets have fuzzed, runs only the fuzz-driven pass (which then gets the
whole per-target time), gives up on a target after 3 repair rounds,
builds and fuzzes 2 targets at once, and starts no new target after one hour.
Each flag bounds something different: `--max-targets` how many targets fuzz
(`--max-attempts`, how many are inspected), `--campaign-time` how long the
sweep runs, and `--jobs` how much runs at once, and so the peak memory (about
the children's allowance plus bhf's own index, compiler and report memory).
The run prints each bound it hit, with the number of targets reached out of
the total and the campaign-time cutoff.

For a tree of 10 million lines or more, 8 GiB of RAM is enough only for a
serial run (`--jobs 1`, usually with `--rss-limit-mb 1536`); 16 GiB is
recommended for whole-tree static analysis and build recovery. See [Resource
Requirements](../../README.md#resource-requirements) in the README for the
static-analysis ceiling and per-file safeguards.

Under `auto`, each target's in-memory and on-disk coverage corpus shares the
`--max-corpus-mb` budget (64 MiB by default), and its entry limit is derived
from that budget and `--max-len`. `BHF_MAX_CORPUS_ENTRIES` sets a stricter
entry limit. Standalone `bhf fuzz` sizes its corpus from available memory
(`BHF_MAX_CORPUS_BYTES`). Captured target diagnostics and runtrace event data
also have memory-aware defaults. Discovery keeps a compact declaration and
candidate index and the final reports keep metadata for every attempted
target, so bound a sweep with many candidates with `--max-targets`,
`--campaign-time` and `--per-target-finding-count`.

Each memory-aware default can be raised when a target needs more:

| Override | Controls |
|---|---|
| `--max-corpus-mb`, `BHF_MAX_CORPUS_ENTRIES` | Per-target mutation corpus and on-disk coverage corpus under `auto` |
| `BHF_MAX_CORPUS_BYTES` | Mutation corpus bytes of standalone `bhf fuzz` |
| `BHF_MAX_SOURCE_FILE_BYTES`, `BHF_MAX_FILE_BYTES` | Largest source file admitted by discovery and by static analysis |
| `BHF_MAX_SUBPROCESS_OUTPUT_BYTES`, `BHF_MAX_HARNESS_OUTPUT_BYTES` | Build-command and target-diagnostic output captured per stream |
| `BHF_MAX_EVENT_DELTA_BYTES`, `BHF_MAX_RUNTRACE_PARSE_BYTES` | Runtrace data admitted per execution and per log |
| `BHF_MAX_SINK_TRACKING_BYTES`, `BHF_MAX_SINK_SUBJECTS` | Tainted-sink evidence kept across executions |
| `BHF_MAX_EXTERNAL_TOOL_OUTPUT_BYTES` | External analyzer JSON and SARIF captured |

Values are in bytes, except `BHF_MAX_CORPUS_ENTRIES` and
`BHF_MAX_SINK_SUBJECTS`, which are counts. Other overrides are named in the
warning printed when their limit is reached. These limits apply to data bhf
keeps, so a run can briefly use more because parsers, compilers, reports,
other workers and allocator overhead are live at the same time. Use an OS or
cgroup memory limit when you need a hard ceiling.

### Stop a target once it has enough findings

`--per-target-finding-count N` ends a target's passes as soon as it has N
distinct findings, instead of spending the rest of `--per-target-time` on
duplicates of the same bug. `--per-target-finding-count 1` is libFuzzer's
stop-on-first-crash; a larger N collects a few distinct bugs per target before
moving on. It also applies in split mode.

### Split a fixed budget across targets

`--campaign-time` alone is a deadline: the best-ranked targets run first until
the time is spent. Add `--min-target-time` to divide the budget evenly
instead. Each attempted target gets `max(min, campaign / N)` seconds of
fuzzing, and only the top `floor(campaign / per_target)` ranked targets are
attempted; the rest are logged as unfuzzed. For example,
`--campaign-time 600 --min-target-time 30` over 40 ranked targets gives each
target 30 s (`600 / 40 = 15`, below the floor) and attempts the top
`floor(600 / 30) = 20`. With 10 targets, each gets `600 / 10 = 60` s. Use it
when you want a predictable amount of fuzzing per target.

### Actionability in auto runs

The `auto` reports count findings by actionability verdict and impact. In
`--mode attacking`, scheduling prefers real source targets and dangerous-sink
evidence; the verdicts still come from each finding's evidence. A finding that
depends on generated stubs, fake resources, injected environment or mocks gets
the verdict `lab_only`, and one that needs a real resource bhf could not
supply or substitute gets `blocked`.

### Fuzz-confirmation

When a run both scans statically and fuzzes (`--static`, or the static
analysis of targets that could not be fuzzed), bhf matches each static
finding (`F-STATIC-*`, `F-RO-*`) against the run's runtime findings (fuzz
crashes and oracle hits) by source site, file and line:

- **Match.** The static finding is updated in place to
  `confirmation: fuzz_confirmed`, its confidence is set to `high`, and it
  joins the confirming crash's cluster, so the report shows one issue row: the
  crash as representative and the static finding as a member, with both
  CWEs. When the fuzzer reached the site only through an entry point that is
  not attacker-reachable, the finding is confirmed with the verdict
  `lab_only`.
- **No match.** The static finding keeps `confirmation: static` and its
  confidence, since a site the fuzzer did not reach can still be reachable.
  The one exception is a static finding in a function whose fuzzed entry was
  shown not to be attacker-reachable (input reachability
  `reachability_unproven` or `output_serializer`): its verdict becomes
  `lab_only`.

Every row of `findings.csv` and every SARIF result carries a `confirmation`
value (`static`, `fuzz`, `runtime` or `fuzz_confirmed`), and the `run.json`
summary counts the `fuzz_confirmed` findings. A `fuzz_confirmed` finding is a
static finding at the same file and line as a crash or oracle hit the fuzzer
produced.

## Coverage report

After the sweep, each C/C++ harness is rebuilt with source coverage and its
corpus replayed. The replay writes the lines the campaign executed to
`harnesses/<id>/covered-lines.txt`, and the covered and instrumented line
counts to `harnesses/<id>/coverage-summary.json`. Both count the project's
lines only: the generated `main.c`, its repairs and stubs, and bhf's C runtime
headers (`bhf_*`) are left out. The terminal summary's `Coverage: N edges (the
most any one target reached)` is the largest edge count of a single target,
not a total, since each target has its own edge map.

The same replay writes each harness's coverage report to
`results/coverage/<id>/`, covering only files under the sweep's root:

- `lcov.info`: the line and function records, for `genhtml`, an IDE or a CI
  coverage service.
- `html/index.html`: llvm-cov's report, with line counts for each file.
- `functions.txt`: llvm-cov's per-function table (regions, lines and branches
  covered). `functions.json` gives each function's file, line, calls over the
  corpus, and instrumented and covered lines. A function with no calls is one
  the campaign never reached.
- `blockers.txt` and `blockers.json`: the comparisons the corpus reached and
  never passed. Each is a line whose branch llvm-cov saw go one way only, at a
  comparison the harness recorded (an integer compared with a constant, a
  `memcmp`, a `strcmp`). Each entry names the file, line and function, the
  operand the branch wants (in hex, little-endian for an integer) and some of
  the values it got instead. A dictionary entry, a seed or a harness change at
  these places takes the campaign further; the sweep prints how many there
  are.

The report needs `llvm-cov` and `llvm-profdata` (or their `-18` names), as
the replay does, and the blockers need `llvm-symbolizer` to place each
comparison. A part llvm-cov cannot render is left out, and
`harnesses/<id>/coverage-replay-diagnostic.txt` says why.

An Ada harness gets the same report from its edges, without the HTML and the
blockers. GNAT instruments with `-fsanitize-coverage=trace-pc` and writes no
coverage mapping, so the replay records the PC of each edge an input reaches
(`BHF_COV_PCS`), takes the binary's calls to the trace-pc callback as the
instrumented edges, and places both on Ada lines with `addr2line` (or
`llvm-symbolizer`) and the line maps of the instrumented copies. `lcov.info`
has the lines and subprograms. `functions.txt` and `functions.json` list each
subprogram (`checks.classify` for GNAT's `checks__classify`) with its first
line and its covered and instrumented lines; `calls` is `null`, since an edge
records only whether it ran. The covered lines also go to the harness's
`covered-lines.txt`. This needs `objdump` from binutils, which is installed
with GNAT.

## Running a harness under another fuzzer

The generated native harnesses (C, C++, Rust, Ada, COBOL and Fortran) are
self-contained: the default binary reads one input per run and runs the
target once, which is what an external fuzzer expects. Each C, C++, Rust and
Ada harness directory (`<work>/harnesses/<id>/`) also holds:

- a `Mayhemfile`: run `mayhem run .` from the harness directory. C, C++ and
  Rust take the input as a file (`@@`, ASan-instrumented, `sanitizer: true`);
  Ada reads stdin, in Mayhem's base-executable mode.
- a `PORTABILITY.md` with the build and run commands for Mayhem, libFuzzer,
  AFL++ and honggfuzz for that lane.

| Lane | Black-box (Mayhem base executable, AFL file input) | libFuzzer | AFL++ persistent mode |
|---|---|---|---|
| C / C++ | `make` → `./main <file>` | `make libfuzzer` → `./main_libfuzzer` | `make afl` → `./main_afl`; `make afl_cmplog` → `./main_afl_cmplog` (for `-c`) |
| C / C++ (SymCC, `--symcc`) | `make symcc` → `SYMCC_INPUT_FILE=<file> SYMCC_OUTPUT_DIR=<dir> ./main_symcc <file>` writes the inputs SymCC solved into `<dir>` | none | none |
| COBOL / Fortran | `./main <file>` (built by default) | none | `make afl AUTO_EXTRA_LDFLAGS="$(cat lane-ldflags.txt)"` → `./main_afl` |
| Rust | `./main <file>` (built by default) | `./build-libfuzzer.sh` → `./main_libfuzzer` | `./build-afl.sh` → `./main_afl`, `./main_afl_cmplog` (for `-c`) |
| Ada | `./main < input` (stdin) | none | `bhf auto --engine afl++` links `build/<id>/main_afl` (fork server, input on stdin, `BHF_CRASH_ON_FINDING=1`) |

The libFuzzer binaries use a generated `bhf_libfuzzer.c` shim that forwards
libFuzzer's `LLVMFuzzerTestOneInput` to bhf's `bhf_run_one`. A harness that
wraps the project's own `LLVMFuzzerTestOneInput` has no shim: `make libfuzzer`
links the project's sources directly. Rust's libFuzzer binary is a separate
instrumented build (`build-libfuzzer.sh`), because current libFuzzer cannot
link bhf's default `trace-pc-guard` staticlib.

**Ada exceptions.** A caught top-level Ada exception is a finding, but the
process does not crash, so an engine that keys on crashes misses it. Set
`BHF_CRASH_ON_FINDING=1` (the generated Ada `Mayhemfile` does) to abort the
process with `SIGABRT` when a finding is reported.

The interpreted and managed lanes (Python, JavaScript, TypeScript, Java, C#,
Ruby, Lua, PHP and Perl) run through bhf's own interpreter drivers rather than
one portable binary, so they get no `Mayhemfile`.

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | At least one target built and ran. A target that built but ran no input, a report-only target or a finding also gives 0, and so do `--dry-run`, `--list-targets` and `--list-fakes` |
| 1 | Candidates were discovered but none built and ran: each one failed to build, was skipped, or built but was not entered (`built, NOT entered` in the summary, a target-environment failure included), or `auto` stopped on an error |
| 2 | No candidates discovered (an empty tree, or a source path that does not exist), or a refused configuration or flag value. An internal bhf panic also exits 2, after writing the bug report |
| 3 | Harnesses built, but none ran because their sanitizer runtime does not start on this host. Re-run with `--sanitizers none`, or with a compiler whose sanitizer runtime starts here |

## Discovery

Discovery walks the source tree and skips build output and bhf's own
directories: `.git`, `target`, `build`, `bhf_work`, `harnesses`,
`generated_harnesses`, `node_modules`, `.bhf-build` and the run's work
directory. By default it also skips code that is not the project's own
library. `bhf scan` and `bhf list targets` include that code, and
`list targets` marks its rows `(bhf auto skips: ...)`. Skipped by default:

- a directory named (case-insensitively) `t`, `test`, `tests`, `testing`,
  `testsuite`, `test-suite`, `unittest`, `unittests`, `gtest`, `googletest`,
  `spec`, `specs`, `example`, `examples`, `sample`, `samples`, `demo`,
  `demos`, `benchmark`, `benchmarks`, `bench`, `benches`, `fuzz`, `fuzzing`,
  `fuzzer`, `fuzzers`, `ossfuzz`, `oss-fuzz`, `tool`, `tools`, `dev-tools`,
  `devtools`, `dev_tools`, `program`, `programs`, `bin`, `cli`, `app`,
  `apps`, `regress`, `research`, `experimental`, `experiments`, `playground`,
  `sandbox`, `perf`, `script`, `scripts`, `snippet`, `snippets`, `contrib`,
  `third_party`, `thirdparty`, `third-party`, `3rdparty`, `3rd_party`,
  `vendor`, `vendored`, `extern`, `external`, `deps`, `dependencies`,
  `subprojects`, `doc`, `docs` or `documentation`;
- any directory whose name contains `test` (`integration_tests`,
  `jsontestrunner`; `latest`, `fastest`, `greatest`, `contest`, `protest`
  and names containing `attest` are kept) or `fuzz` (`fuzz_targets`,
  `libfuzzer`);
- a source file whose name marks a test runner or tool (`test_foo.c`,
  `pngtest.c`, `runtest.c`, `foo_test.cc`, `ltests.c`).

Inside a Maven or Gradle source root (`src/main/java`, `src/main/kotlin`) and
inside a C/C++ public header directory (`include/<name>/`, `inc/<name>/`),
these name rules do not apply, since a directory there is a package or
namespace (`tools.jackson.core`, `include/CLI/`); only `--exclude-dir` names
are skipped there.

`--include-dir <name>` keeps a directory the defaults skip (repeatable, for
example `--include-dir tools` for a project whose parser lives in `tools/`),
and `--exclude-dir <name>` skips another. When the defaults leave anything
out, `bhf auto` prints a line such as `bhf auto: skipped as non-library code
by default: tests/ (3 files), tools/ (1 file), ...` after discovery.

Each file is parsed by its extension. [Target Ranking](target-ranking.md)
describes how candidates are scored and ordered, with the weights for each
language.

| Extension | Language | Candidates |
|---|---|---|
| `.ads`, `.adb` | Ada | subprograms |
| `.c` | C | functions |
| `.h` | C or C++, chosen from the header's contents | functions |
| `.cpp`, `.cc`, `.cxx`, `.C`, `.hpp`, `.hh`, `.hxx` | C++ | functions and methods |
| `.rs` | Rust | functions and methods |
| `.java` | Java | methods |
| `.py` | Python | functions and methods |
| `.pl`, `.pm` | Perl | subs |
| `.go` | Go | functions; `_test.go` files are skipped, and their fuzz tests are [provided harnesses](#provided-harnesses) |
| `.cob`, `.cbl`, `.cobol`, `.cble` | COBOL | programs with a byte-buffer `LINKAGE` / `USING` parameter |
| `.f`, `.for`, `.f77`, `.f90`, `.f95`, `.f03`, `.f08` | Fortran | procedures with a character argument |
| `.cs` | C# | public methods that take bytes, a string or a stream |
| `.js`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.mts`, `.cts` | JavaScript, TypeScript | exported functions and public methods of exported classes (`.d.ts` files are skipped) |
| `.rb` | Ruby | callable methods that take input |
| `.lua` | Lua | callable functions that take input |
| `.php` | PHP | functions and public methods with an input channel |

A candidate whose parameters bhf has no decoder for is skipped with the
outcome `unsupported_params` and the reason; `--force` retries it with a
best-effort driver.

### Provided harnesses

A fuzz harness the project already ships is fuzzed as it is, since it shows
how the project means its code to be fuzzed. bhf looks for these where the
discovery walk above does not (`_test.go` files, `fuzz/` and test
directories), ranks them ahead of every generated target, and starts each
from the seeds that come with it. After discovery `bhf auto` prints
`provided harnesses: N the project ships (...)`; `run.json` marks each one
with `targets[].provided_harness` (see [run.json](#runjson)), and the
summary lists them under `Provided harnesses`.

The search for them skips the work dir, build output, VCS and other hidden
directories, vendored dependencies (`vendor/`, `third_party/`, ...),
`testdata/` and every `--exclude-dir`, and, for Go fuzz tests, directories
whose names start with `_`, which the go tool ignores too. `--languages`,
`--target` and the other filters apply to them as to any target. The note on
what discovery skipped by default does not count their files, since the run
fuzzes them.

#### Go native fuzz tests

A top-level `func FuzzXxx(f *testing.F)` in a `_test.go` file, the entry
point `go test -fuzz` runs, is a target named `FuzzXxx` (an `H-G` id).
Because `go test` runs it with Go's own engine, bhf builds it the way
OSS-Fuzz builds native Go fuzzers. The test file is copied into its package
as an ordinary source, with its `testing` import pointed at a stand-in
package whose `f.Fuzz` hands bhf's inputs to the fuzz target, and a generated
`main` runs the fuzz test in its package's directory, as `go test` does.

The package and what it imports from its module are copied into the harness
directory (`bhf_module/`), each file with a `//line` directive naming the
original, so `go build -cover` gives edge coverage and a panic names the
project's file and line. The scanned tree is not written to. An external test
(`package x_test`) gets a harness package of its own. When the fuzz test needs
a helper that another test file of its package defines, the build is retried
with the package's other test files; for an external test, it is then retried
with the package's internal test files as well, compiled into the package's
copy as `go test` compiles them (an `export_test.go` that exports what the
external test calls, for example).

The fuzz target's arguments (`[]byte`, `string`, `bool`, the integer types,
`float32`, `float64`) are decoded from each input in the layout bhf's
generated Go harnesses use:

- a `[]byte` or `string` takes the rest of the input when it is the last
  argument, otherwise one length byte and then that many bytes;
- a `bool` or `byte` takes one byte;
- any other integer, and a float, takes 8 bytes, little-endian.

The fuzz test's `f.Add` seeds and the files of its seed corpus
(`testdata/fuzz/FuzzXxx/`, in the `go test fuzz v1` encoding) are written in
that layout to `harnesses/<id>/provided-seeds/` and start the fuzz passes. A
seed whose values do not match the fuzz target's argument types is counted in
the record's `notes`. A recovered panic is a finding, and so is a failure the
fuzz target reports through its `*testing.T` (`t.Error`, `t.Fatal`), as it is
to `go test`; `t.Skip` skips the input. A fuzz test that fails or skips before
it reaches `f.Fuzz` is skipped with the reason.

#### Atheris harnesses

The function a Python file registers with `atheris.Setup(sys.argv,
TestOneInput)` is a target named after that function (an `H-P` id), however
the file imports `atheris` or `Setup` and whether the function is passed
positionally or as `test_one_input=`; it must be a module-level `def`. The
file's other functions are harness glue, not targets.

Atheris runs a harness under libFuzzer; bhf runs it under its own Python
driver instead, so Atheris does not need to be installed. The harness
directory holds a stand-in `atheris` module, found ahead of an installed one:

- `Setup` and `Fuzz` only record and return when bhf imports the harness file
  (its `if __name__ == "__main__":` block does not run);
- `instrument_imports`, `instrument_func` and `instrument_all` change nothing,
  since bhf's tracer measures line-edge coverage over the whole tree;
- `FuzzedDataProvider` decodes `Consume*` values from the front of the input:
  text as Atheris does (a first byte chooses ASCII, UTF-16 or UTF-32) and
  integers as little-endian two's complement.

The harness file runs with the tree and its `src/` on the module path, as an
installed project would. As under Atheris, every exception the function lets
escape is a finding, including a `ValueError` or the library's own exception
class (which a generated Python harness treats as input rejections);
`SystemExit` and `KeyboardInterrupt` are not. A finding's stack starts past
the harness file's frames, so the finding is located in the code that raised
the exception, unless the harness raised it itself. A `<stem>.dict` beside
the harness joins its dictionary, and the files of its seed corpus
(`<stem>_seed_corpus/`, `<stem>_corpus/`, `corpus/<stem>/` or
`seeds/<stem>/` beside it) are copied unchanged to
`harnesses/<id>/provided-seeds/` and start the fuzz passes. A harness file
that cannot be imported, or that uses a part of the `atheris` API the
stand-in does not provide, is skipped with the reason.

#### Imported OSS-Fuzz fuzzers

When the work dir holds a `bhf project import-ossfuzz` of the tree (or of a
tree that contains it, or that it contains; see [Importing an OSS-Fuzz
build](cli.md#importing-an-oss-fuzz-build)), each fuzzer the import
registered is a target named after the fuzzer, in the C or C++ file of the
same name that defines `LLVMFuzzerTestOneInput`. Its `H-C` or `H-X` id names
the registration, so it stays the same from run to run.

The fuzzer's binary, already built by the project's `build.sh` with bhf's
driver, is staged from `<work>/ossfuzz/out/` as the harness; nothing is
generated or rebuilt. It starts from its unpacked seed corpus, with the
dictionaries the import merged for it, and the `max_len`, `timeout` and
`rss_limit_mb` of its `.options` file replace the run's `--max-len`,
per-input timeout and memory limit. A generated target in the same file, such
as the passthrough harness of its `LLVMFuzzerTestOneInput`, is the same
fuzzer and is not fuzzed again. A fuzzer the build linked with
`-fsanitize=fuzzer` rather than `$LIB_FUZZING_ENGINE` is skipped with the
reason (`bhf project run` runs it), and an import of another tree is left out
with a note.

A fresh run refreshes `<work>/build/` but keeps the import's registrations
there, and a run over another tree archives the earlier run but leaves the
import (`<work>/ossfuzz/` and those registrations) in place. The import
builds with a `-fdebug-prefix-map` from its `$SRC/<name>` copy to the tree,
so a finding is located in the tree's files; a fuzzer imported by an earlier
release names the copy until it is imported again.

### C, C++ and Lua targets

C and C++ harnesses are Makefile-based. `auto` builds them with `clang` and
`clang++` unless `CC`/`CXX` (or `--cc`/`--cxx`) name other compilers, and it
carries the include paths, defines and standard flags of a nearby
`compile_commands.json` into the generated Makefile. [C and C++
Fuzzing](c-cpp.md) covers the supported parameter shapes, how inputs become
arguments, and the limits of the C and C++ lanes.

A Lua colon method (`function Reader:average(data)`) is called on an
instance of its class: the table that defines it (the returned module, its
field named for the class, or that global), built by its `new`, `create` or
`init` constructor called with no arguments, or else an empty table with the
class as its metatable. The Lua driver counts how many of its first 1000
inputs end in a nil-value error. At 95% or more (over at least 20 inputs),
the target's `run.json` entry carries `stub_executed` and its `run.md` row
says `stub executed:`, since such a run exercised the error path, not the
target.

The Lua driver's coverage hook gets line events only while a target chunk
runs (code under the target's root, not the driver or the harness). A
function that runs 256 line events with no new edge stops getting them until
a count hook resumes them 100000 instructions later, so a long loop or a deep
recursion costs a few times a plain run. A Lua finding is located at the
target frame the driver records when the error is raised: a stack overflow is
reported at the recursing line, not in the driver.

## Repair Synthesis

The `build_classifier` crate sorts the compiler's diagnostics into error
classes, and a repair planner for the language answers each class. Repair
synthesis applies to the C, C++ and Ada lanes only; the other lanes build or
check their targets before the attempt loop (see [What It Does](#what-it-does)).
The declaration index the planners consult is built once per `auto` run,
before the attempt loop, and kept in memory for all targets.

C and C++ (`crates/c_stub_gen`):

| Error class | Repair |
|---|---|
| `MissingHeader{path}` | Synthesised placeholder header under `<harness>/repairs/auto_includes/<path>`, added to `-I` |
| `MissingType{name}` | `typedef void *T;` appended to `<harness>/repairs/auto_types.h` |
| `UndefinedSymbol{name}` | Looked up in the declaration index: a match gets a declared stub, no match a blind `void(void)` stub, appended to `<harness>/repairs/auto_stubs.c`. A compiler or sanitizer runtime name (`__asan_*`, `__llvm_profile_*`, `__cxa_*`, `__stack_chk_fail`) is never stubbed, and neither is, when linking against the Windows C runtime, a name of that runtime or of MinGW's (`_dup`, `__mingw_fprintf`, `__main`, `__chkstk`). For those, only the tree's own definition is linked; otherwise the build fails with the linker's error, since the reference means a runtime library is missing or objects from two toolchains were mixed. Off Windows, `_write` and `_read` (a newlib port's syscall hooks) are ordinary symbols |
| `MissingSharedLib{name}` | Not auto-repaired. Flows to `needed_for_build.missing_libraries` and the `missing-deps` manifest; the target is marked `unrecoverable_link` |
| Standard-library names used without `std::` (`unknown type name 'string'`, `no template named 'map'`, g++'s `'map' does not name a type`) | The std prelude that `bhf build` writes, `<harness>/std_prelude.h`, force-included into every translation unit; see below |
| `ConfigGuardError{file,line}` | A `#error` reached by a build-configuration guard (libssh's `#error "no strtoull function found"`). The conditional that owns the `#error` is read, and the macro it tests is `#define`d in `auto_defines.h` with the value the guard requires (`#if (DEPTH != 8)` gives `8`, a plain feature test `1`). A guard bhf cannot decide (a comparison, a compound condition, or an error that fires because a macro is defined) is left unrepaired |

Ada (`crates/stub_gen`):

| GNAT diagnostic | Repair |
|---|---|
| `file ".+\.ads" not found` | Empty `PackageSpec` under `<harness>/repairs/auto_ada/` |
| `"X" is undefined` | `Identifier` stub |
| `"X.Y" is not visible` | `Visibility` stub |
| `missing body for unit "X"` | Empty `PackageBody` |
| `cannot find "X.gpr"` | Not auto-repaired; flows to `needed_for_build.missing_gpr_imports` |

**Standard names without `std::`.** A pre-standard C++ header often writes
`string`, `map<string, int>` or `list<T>` without `std::`, relying on a
`using namespace std;` that the project's own sources put before including
it; the generated harness has none. When a C++ harness build fails on such
names, and before the other retries (the dialect ladder, the other compiler),
`auto` writes the same prelude `bhf build` writes, `<harness>/std_prelude.h`,
with each name's standard header and a `using std::` declaration for it (an
existing file only gains the lines it lacks). It force-includes the prelude
into every translation unit of the harness through
`<harness>/repairs/auto_std_prelude.h` and builds again.

clang++ stops after 20 errors, so a long header can hide names behind the
first ones. While a rebuild reports names the prelude lacks, they are added
and the harness is rebuilt; each pass adds at least one standard name, so the
loop ends. The build prints one note naming the types (``bhf auto: <id>: the
sources use string, map, ... without `std::` ...``), and a later round that
reports more names adds them to the same file.

The rules are `bhf build`'s (see [Custom
harnesses](custom-harness.md#headers-that-rely-on-using-namespace-std)).
Diagnostics in C code get no prelude, and a stream object alone (`cerr`)
keeps the stream-header repair. A name the scanned tree declares as a C++
type of its own (a class, struct, enum or typedef in a C++ source or header,
or in a `.h` header that C++ code includes) is never declared from `std`.
Where the source writes the name as a template (`list<string>`, `no template
named 'list'`), only a class template of the tree's own counts. A C struct of
the same name, in a `.c` source or in a header that only C sources include,
does not count.

The repair is recorded among the target's repairs as `std_prelude` (`path`,
`names`, `headers`) in `run.json`, and `targets[].real_headers_included` and
`run.md` list it. Every lane's build and the target's capsule force-include it
too. If the build still fails on standard names used without `std::`, whether
or not the prelude declares them, their `missing-deps` entries say so and
name the prelude (or, when the build wrote none, the declarations to
force-include), and they are not listed as harness or code-generation
errors.

## Three-Pass Cascade

Each built harness runs three passes, one after another. The runtime shim
fakes the resources the code opens (files, devices, sockets, environment
variables), and `BHF_RUNTRACE_MODE` sets what a fake resource returns in each
pass:

- `empty`: a fake `read()` returns end-of-file on the first call. This reaches
  the code paths for an absent external world.
- `rng`: each fake resource serves bytes from its own xorshift generator,
  seeded by `(harness_id, resource_name, fuzz_seed)`. This reaches
  length-field and type-confusion bugs in code that parses external bytes.
- `fuzz_driven`: fake reads come from a shared memfd filled from each fuzz
  input, so the engine's coverage feedback learns which bytes to send to the
  fake resource that guards a code path.

All three passes run by default, since each reaches paths the others do not.
`--passes`, `--single-pass`, the shared deadline and
`--per-target-finding-count` can stop or skip the remaining passes.

The runtime shim (see [Runtime Virtualisation](runtime-virtualisation.md))
runs on Linux. It is armed for native C, C++, Ada, Rust, Go, COBOL and
Fortran harnesses, and for the Python, Perl, Ruby, Lua and PHP interpreters,
where it records only from the moment the harness first calls the target, so
the interpreter's own startup is not audited. It is not armed for Java, C#,
JavaScript or TypeScript, which use their runtime's own coverage and crash
signals, or for cross-compiled or emulated (qemu, wine) targets. Those
targets do not get the runtrace oracles such as BHF-405, BHF-304, BHF-417 and
BHF-305. Each fuzzed target's `behavioral_oracles` in `run.json` (and its
`[behavioral oracles: …]` note in `run.md`) says `on`, `driver` (the Java and
JavaScript/TypeScript drivers' own sink checks) or `off`, with the reason.

## Outputs

```
<work>/
├── auto/
│   ├── run.md                      # human-readable report
│   ├── run.json                    # machine-readable report
│   ├── summary.txt                 # the summary the run printed
│   ├── seeds.json                  # every seed the run used, with provenance
│   ├── missing-deps.json           # missing-dependency manifest
│   ├── missing-deps.txt            # the same, human-readable
│   ├── blockers.json               # what stopped the unfuzzed targets, grouped (when any)
│   └── bug-report.json, .md        # problems in bhf itself (when any, or with --debug)
├── harnesses/<harness-id>/
│   ├── main.c | main.cpp | main.adb
│   ├── Makefile | H_<id>.gpr
│   ├── repairs/
│   │   ├── auto_stubs.c
│   │   ├── auto_types.h
│   │   ├── auto_includes/…
│   │   └── auto_ada/…
│   ├── arg-layout.json             # how an input decodes into arguments (C/C++)
│   ├── generation-metadata.json
│   ├── Mayhemfile, PORTABILITY.md  # running the harness under another fuzzer
│   ├── covered-lines.txt           # lines the corpus executed (after the coverage replay)
│   ├── coverage-summary.json
│   ├── result.json                 # per-target resume record
│   └── runtrace.jsonl              # per-target shim events
├── corpus/<harness-id>/queue/      # persisted coverage corpus
├── corpus/<harness-id>/lineage.jsonl  # what each queue entry was mutated from
├── fuzz_runs/<harness-id>-latest.json
├── discovery-cache.json            # the discovery a re-run reuses
└── results/
    ├── INDEX.md                    # start here
    ├── findings.json               # schema bhf.findings.v1
    ├── findings.csv
    ├── findings.sarif
    ├── manifest.json               # what each file holds, with digests
    ├── attestation.json
    ├── coverage/<harness-id>/      # lcov.info, html/, functions.*, blockers.*
    └── findings/<finding-id>/      # finding.json, testcase.bin, replay.py, ...
```

[Finding report fields](../finding-report-fields.md) describes what each
finding file holds.

### `run.md`

The top section summarises discovery, build outcomes and finding counts. If
any target fuzzed only stubs, a `## ⚠ STUB-ONLY (FALSE CLEAN)` block comes
first, naming each such target and its blind-stub fraction (see
[stub_execution](#stub_execution-false-clean-guard)).

A `## Targets` section follows, with one line for every target. Each line for
a fuzzed target shows the outcome label, a per-pass breakdown
(`empty=4123execs/1000exec_s/0f rng=… fuzz_driven=…`) and the total
`cov=Nedges`. A `[!]` note marks a target whose fuzzed parameters are not an
attacker-controlled input channel. A target whose executions ran past
`--timeout` shows `hangs=C/K`: C of its K killed executions hung again when
re-run, each a BHF-230 finding or a later hit of one. The top section's
`Hangs:` line totals them across targets: killed, hung again, finished when
re-run, and not re-run (because the pass had already re-run four, or ran out
of time). In `run.json`, each pass carries the same counts as `hangs`
(`timeout_ms`, `observed`, `confirmed`, `cleared`, `not_rerun`).

The `Upstream delta` section is the prosthetic ledger (see
[needed_for_build](#needed_for_build)).

### `blockers.json`

When targets are left unfuzzed, `auto/blockers.json` has one row per
language, outcome and cause, with the number of targets that share it, most
common first. The cause is the first informative line of the diagnostic with
its per-instance details removed: a leading `file:line:col:`, other
free-standing numbers (shown as `N`) and host paths (shown as `PATH`). The
identifier it names stays, in double quotes (`unknown type name "pcap_t"`),
as does a dialect's version (`Python 2`, `Ada 95`). So one missing type that
blocks twenty targets is one row with a count of twenty, and two missing types
are two rows.

### `run.json`

The machine-readable report. Each `built_and_fuzzed` target carries
throughput and budget fields under `targets[].outcome`, comparable to
libFuzzer's `average_exec_per_sec` and AFL's `execs_per_sec`:

- `executions_per_sec`: the target's throughput, total executions over total
  elapsed time across its passes (not a mean of the per-pass rates).
- `per_pass_budget_secs` and `total_wall_budget_secs`: the per-pass and total
  fuzz time budgets.
- `passes[]`: one entry per pass, each with `executions`, `coverage_edges`,
  `coverage_instrumentation`, `elapsed_secs` (measured, not budgeted),
  `executions_per_sec` and `findings`. `coverage_instrumentation` is read from
  the harness binary and names what fed the edge map: `sancov-trace-pc-guard`
  for clang's guard section, `sancov-trace-pc` when GCC's debug information
  records a translation unit compiled with `-fsanitize-coverage=trace-pc`,
  `go-cover`, or `edge-bitmap` when the binary shows neither (a build without
  coverage, for example).

The top-level `summary` carries `fuzz_confirmed`, the number of static
findings a fuzz or oracle finding confirmed at the same source site (omitted
when zero; see [Fuzz-confirmation](#fuzz-confirmation)).

A target that is a harness the project ships ([Provided
harnesses](#provided-harnesses)) carries `targets[].provided_harness`:

- `origin`: `go-fuzz-test`, `atheris` or `ossfuzz-import`;
- `entry`: the fuzz test's name, the function registered with
  `atheris.Setup`, or the imported fuzzer's name;
- `source`: the file that defines it;
- `seeds` and `seed_sources`: how many starting inputs came with it, and its
  seed corpus directories;
- `dictionaries` and `dictionary_tokens`: the dictionaries that came with it,
  merged into its harness's `dictionary.txt`, and their token count (omitted
  when there are none);
- `options`: an imported fuzzer's `max_len`, `timeout_secs` and
  `rss_limit_mb`, which its fuzz passes use (omitted when it has none);
- `notes`: what came with it that could not be used, and why.

The top-level `summary.provided_harnesses` counts them (omitted when zero),
and `run.md` tags each one's row `[provided harness: <origin>, N seed(s)]`.

The top-level `seeds` block records where the run's seeds came from:
`source` (`user`, `mined` or `none`), `count`, `mining` (`ran`,
`skipped_user_seeds` or `disabled`) and `manifest`, the path of the per-seed
list (`auto/seeds.json`; see [Seeds](#seeds)).

### `stub_execution` (false-clean guard)

Each `built_and_fuzzed` target in `run.json` carries a
`targets[].stub_execution` object that says how much of the harness's
external symbol surface was real and how much was stubbed:
`blind_stubbed_symbols`, `declared_stubbed_symbols`, `real_linked_symbols`,
`resolved_called_symbols`, `blind_stub_fraction` and the boolean `stub_only`.

`stub_only` is set when at least 90% of the external symbols the harness
called were satisfied by blind stubs and no real dependency source was linked.
Such a run fuzzed invented empty function bodies, not the library, so a
result with no findings says nothing about the library. bhf calls this a
false clean. `run.md`, the terminal summary and the per-target outcome label
(`built+fuzzed (STUB-ONLY)`) mark it, and the summary counts it under
`summary.fuzzed_stub_only`. Coverage limited to the harness itself is the
other sign. Supply the missing dependency sources (see
[missing-deps](#missing-deps)) and run again to fuzz the real code.

### `needed_for_build`

Lists every prosthetic the sweep applied and everything it could not supply,
one entry per resource, each with a `referenced_by_targets` array and a
`count`. There are four layers:

| Layer | Contents |
|---|---|
| A: build time | Synthesised headers, declared and blind stubs, typedef placeholders, Ada package stubs |
| B: link time, not repaired | `-l<name>` misses, missing `.gpr` imports, glibc version mismatches |
| C: run time, observed during fuzzing | Environment variables, missing files, missing devices, network endpoints, `dlopen` and `gethostbyname` failures |
| D: unrecoverable | Build-time repairs bhf could not synthesise (a struct returned by value without a declaration, for example) |

### `missing-deps`

`auto` writes the dependency checkpoint (`auto/missing-deps.json` and
`missing-deps.txt`) before build probing or target discovery, refreshes it
right after an opted-in build probe, and replaces it atomically after every
completed target, parallel jobs included. The JSON carries `complete` and
`completed_targets`, so you can tell a final list from the last checkpoint an
interrupted or out-of-memory run left. The last terminal line of a run points
at the text file, with the counts of blocking and substituted entries.

The text report lists first the compatible compilers, target runtimes and
emulators, generated-source and code-generation tools, unfetched Git
submodules, and declared Alire sources that are absent. Each row has a basis
(`declared`, `observed` or `inferred`) and its evidence. bhf reports the exact
path, URL, version, output or tool when project metadata or diagnostics give
it, and does not guess a proprietary vendor, version, ABI or semantics for an
unidentified missing type.

Every `failed_build` target has at least one entry. Each unresolved final
diagnostic (a missing header, type, symbol or build-configuration macro, a
malformed or generated declarator, or any unclassified error) is recorded as a
still-blocking entry with a hint on how to obtain what is missing. A missing
header that a configure or CMake step generates (c-ares' `ares_build.h`, for
example) is recognised by a sibling `.in`, `.dist`, `.cmake` or `.cmake.in`
template, and its hint is to run the project's configure step or use
`--probe-build`, not an `apt-file` search. `--deps-only` writes this manifest
without the fuzz phase, and `--install-deps` fetches the still-blocking
entries.

A compile error in a file of the project's own tree, such as an undeclared
identifier in `src/bad.c`, is a `source_error` entry named by the file, line
and message (`bad.c:3: use of undeclared identifier 'x'`). It is counted
apart from the external dependencies ("1 compile error in the project's own
source"), and `bug-report.md` files the target as `[failed-build]`, not as a
bhf `[codegen-bug]`. A lookup error in the generated harness driver or its
`repairs/` is still a code-generation defect. The manifest says "the tree
built against its own sources" only when no target failed to build.

### Per-Finding Replay

Each finding's `finding.json` records the pass it was found in, whether the
runtrace shim was armed (`runtime_mode.pass`, `runtime_mode.shim_armed`), and
the environment variables the run injected (`runtime_mode.env_injected`).
`bhf replay --finding <F>` replays under the same pass and environment. A
fake resource in the `rng` pass serves bytes seeded from its own name, so the
pass and the environment reproduce what it served.

## Re-Runs

`bhf auto <same path>` reuses the per-target `repairs/` files a previous run
left, so accumulated repairs are not found again. The discovery cache is on
by default: an unchanged fingerprint of the source and directory filter reuses
`<work>/discovery-cache.json`, a changed one rebuilds it, and
`--fresh-discovery` forces a rebuild. `bhf clean --all <work>` removes all of
bhf's state from a work directory.

A work directory belongs to one source tree. When `bhf auto` is pointed at a
different tree with a work directory an earlier run used (the default
`./bhf_work/`, for example), it first moves everything that run left,
findings and corpus included, to `<work>/archived/<UTC time>-<tree name>/`
and prints `bhf auto: note: <work> held a run over <other tree>; moved it to
...`, so `results/` and the console report only the current tree. Nothing is
deleted, and a run over the same tree keeps its findings. A `bhf project
import-ossfuzz` in the work dir stays where it is, since it belongs to the
import, not to the earlier run.

At the end of each run, the coverage corpus is saved to
`corpus/<harness-id>/queue/` (files named by content hash, seeds included),
so it carries over between passes and runs and can be replayed for coverage
measurement and `bhf corpus minimize`. The queue and the in-memory mutation
pool share the `--max-corpus-mb` ceiling; finding testcases are stored
separately and never evicted by it. Every pass after the first reseeds from a
bounded subset of this queue, so deep code one pass reached stays reachable
for the next.

### Seeds

Each target's corpus starts from a few built-in inputs plus the run's seeds:
the `--seed-file` and `--seed-dir` files when any are given, otherwise files
mined from the tree's own test data. Mining takes regular files directly
inside `test/`, `tests/`, `examples/`, `samples/` and similar directories,
and inside `data/`, `testdata/`, `fixtures/`, `corpus/` and similar
directories below them. It skips source and prose files, build and IDE
artifacts (`.vcxproj`, `.sln`, `.filters`, `.user`, `.suo`, `.props`,
`.pdb`, `.dll`, `.lib`, `.obj`, `.ilk`, `.exp`, ...) and files over 256 KiB,
and stops at 64 files. Turn it off with `--no-seed-mining` or
`seed-mining = false`. An explicit `--seed-file` or `--seed-dir` (or the
config keys `seed-file` and `seed-dir`) turns it off too, even when it loads
no seed (a missing file, an empty directory): the run says so, and
`seeds.json` records `skipped_user_seeds` with a `reason`.

Seeds reach the engine byte for byte, as do the corpus entries a later pass
or the AFL++ stage reseeds from `corpus/<harness-id>/queue/`.
`auto/seeds.json` lists every seed the run used, with its `path`, `source`
(`user` or `mined`), file `size`, `bytes_used`, and the `sha256` of the bytes
used. A seed that adds coverage is kept as
`corpus/<harness-id>/queue/<sha256>.bin`, and a crashing seed becomes a
finding's testcase. The file also records whether mining `ran`, was
`skipped_user_seeds` or was `disabled`. `run.json` carries the same summary
under `seeds`, and `-v` prints the list. A run that stops before it resolves
seeds (one that finds no fuzzable target, for example) removes any list an
earlier run left in the work dir, and its `run.json` has no `seeds` block.

A seed is a sample of the target's input format, but a C/C++ harness decodes
its fixed-width scalar parameters from the first input bytes and gives the
buffer the bytes after them (see [C and C++](c-cpp.md#decoding-layout)), so a
seed given unchanged lands partly in the scalars. When a target's
`arg-layout.json` puts K bytes before the buffer (every fixed-width parameter
before it, plus 4 for the length of each other buffer's slice before it,
which a zero leaves empty), each seed is also given behind K zero bytes, so
the buffer starts with the seed; the unchanged seed is still given too.
`auto/seeds.json` lists these under `layout_variants`, one entry per target,
with its `harness_id`, `layout_prefix` (K) and the `sha256` of each prefixed
seed. `bhf fuzz` does the same for its `--seed-file` and `--seed-input`
seeds, once per campaign however many workers it runs; the other seeds it
uses (its built-in seeds, a shared queue's inputs) are not prefixed.

### Seed lineage

The built-in engine records what each input it keeps was mutated from, so a
finding can name the seed it grew out of. `corpus/<harness-id>/lineage.jsonl`
sits beside the queue, one JSON line per entry, keyed by the `sha256` of the
entry's bytes. A line holds the entry's `parent`, the entry its mutation
started from (and `donor`, the entry a splice took its second part from), or,
for a root, its `origin`:

- `seed`, with `source` and `path` when `auto/seeds.json` or the `bhf fuzz`
  command line names it, and `layout_prefix` and `seed_sha256` for a seed
  given behind its layout prefix;
- `corpus`, a reseeded queue entry with no line of its own (saved before
  lineage was kept, or dropped by the record cap below). An entry is matched
  by its bytes, whatever its file is named, such as a crash input named by its
  signature or a file the multi-worker merge renamed `worker-N-<name>`;
- `generated`, an input with no seed: the empty or built-in start inputs, or
  an input built by a structured or `--grammar` generator or the random-byte
  fallback.

An input the run was given as a seed is a root again, whatever produced it
before. A later pass, or `--resume`, that reseeds from the queue continues the
chains it finds there. Each worker of a multi-worker `bhf fuzz` starts from the
campaign's `lineage.jsonl` and `auto/seeds.json`. The shared queue's entries
and the files the campaign writes for its workers (a seed's layout-prefixed
variant, a programmatic seed) are bhf's copies, not seeds given to the worker,
so a worker's finding names the seed they came from, never the copy. The
campaign merges each worker's lines into its own.

The first line recorded for an input's bytes is kept: when the same bytes are
reached again, by another mutation, pass or worker, the line does not change.
The chain a finding reports is therefore one real derivation of those bytes,
not necessarily the one this run took. Every writer (a pass, or the merge of a
multi-worker campaign) reads the whole file, up to 524288 lines, and writes
back at most twice the queue's entry limit (`BHF_MAX_CORPUS_ENTRIES` when set)
or twice the number of files in the queue, whichever is more, and never more
than 524288 lines. The merge takes the union of the workers' queues, so the
shared queue can hold more files than the limit, and each of them keeps its
line. Lines are kept in this order: those the pool's entries need (for the
merge, the shared queue's), with their ancestors; then, for a pass over the
cap, those its queue's entries need; then the rest in sha256 order. An entry
whose line was dropped is reported as having no lineage record.

When a finding is saved, its input's chain is followed back to the root
through each entry's `parent` (a splice's donor is named, not followed) and
written into `finding.json` as `lineage`:

- `origin`: `mined_seed`, `user_seed`, `seed`, `corpus`, `generated` or
  `unknown`;
- `root_sha256` (a seed's own, as `auto/seeds.json` lists it), `root_path`
  and `layout_prefix`;
- `depth`: mutation generations from the root, `0` when the input is the root;
- `parent_sha256` and `donor_sha256`;
- `reason`, when the lineage stops short of a seed or is unknown.

The lineage is `unknown`, with a reason, when the chain names an entry with no
record (a corpus saved before lineage was kept, or a line the record cap
dropped), loops, or runs past 100000 generations. It is also `unknown` for a
crash AFL++ found, through `bhf fuzz --engine afl++` or
`bhf binary-fuzz --engine afl-qemu`: AFL++ schedules its own queue, so bhf
does not see what that input was mutated from, and the reason names the AFL++
crash file. A harness run one input per process (a `-fsanitize=fuzzer`
binary) still gets its lineage, since bhf's own engine picks every input it
runs. The lineage describes `testcase.bin`, the input the fuzzer saved;
minimization does not change it.

Lanes that replay inputs bhf already knows record their lineage too:

- The corpus replays (the MSan and TSan replays, the memory profile and the
  `--differential` post-pass) look up the queue entry they ran in
  `lineage.jsonl`, as a pass does; an entry with no line there is a `corpus`
  root.
- An MSan or TSan finding's lineage is that of the queue entry that first
  showed the site, which its oracle evidence names by `input_sha256` (left
  out, with the reason in the lineage, when the entry could not be read back).
  `bhf explain` prints that lineage under the entry's sha256. An MSan finding
  also saves that entry as its `testcase.bin`.
- The capability profile folds what the whole corpus reached into one
  finding, and saves as its `testcase.bin` the queue entry that reached the
  most of the finding's operands (named in `capability.testcase_operands`),
  so its lineage is that entry's. With no such entry it is `unknown`, and the
  reason says so.
- `bhf differential` and the builtin engine of `bhf binary-fuzz` run your
  inputs unchanged: `user_seed`, depth `0`, with the file's path (`generated`
  for the empty input `bhf binary-fuzz` runs when it has no seed). A blind
  mutation of one in `bhf binary-fuzz` is one generation below it: depth `1`,
  with `parent_sha256` the seed's.

Findings saved before lineage was kept have no `lineage`, and neither do the
findings of lanes that observe a whole run rather than one input: the
target-transport and protocol-session lanes, `bhf relational`, the JVM sink
oracle, the campaign-wide collector view, and extensions.

### Corpus from an earlier release

A work directory written by an earlier release can hold corpus entries in
which every byte that was not valid UTF-8 was replaced by `EF BF BD`. In a work
dir from an earlier release (one migrated from the 0.2.x layout, or one with
`auto/run.json` or `auto/work-state.json` from an earlier `bhf auto` and no
`auto/legacy-corpus.json`), the first `bhf auto` run moves `corpus/` to
`corpus-legacy/` (kept, not reseeded) and records that in
`auto/legacy-corpus.json`; pass `--reuse-legacy-corpus` to keep reseeding it.
Every run writes that record before anything else, so a new work dir is
recorded as `fresh` and its corpus is never set aside. A plan-only run
(`--dry-run`, `--list-targets`) leaves an earlier release's corpus for the
first run that fuzzes. `results/INDEX.md`, `bhf report` and the end of each
run warn when a work dir from an earlier release holds testcases or corpus
entries with several `EF BF BD` sequences. See [Upgrading a 0.2.x work
dir](../finding-report-fields.md#upgrading-a-02x-work-dir).

## Limitations

- **Targets bhf cannot drive are skipped, and the sweep continues.** A
  candidate whose input type has no byte-buffer decoder (an opaque nested
  array, an in-crate trait-impl method, a type that needs an external SDK not
  available offline), whose generated harness does not compile, or whose own
  build fails is logged and skipped. These are recorded in
  `<work>/auto/bug-report.json` and `bug-report.md`, with an `issue_count`
  and a `category` per issue (`unsupported-type`, `codegen-defect`,
  `failed-build`, `target-not-reached`, `unsafe-build-path`, ...). A non-zero
  `issue_count` counts candidates bhf could not fully drive; it does not mean
  the run failed. `--debug` adds a backtrace for each internal panic and
  writes the report even when it is empty.
- **Outcomes that need a change on the host, not in bhf.** These are not
  filed in the bug report, and `--force` does not change them:
  - `unsafe_build_path` (`bug-report.md` row `unsafe-build-path`): a source
    path, include directory or compile flag holds a character no quoting makes
    safe in a build recipe (`$`, `#`, a backtick, a shell operator). Rename or
    move the path.
  - `missing_toolchain` (`summary.missing_toolchain`, terminal label
    "skipped: toolchain not installed"): the lane's toolchain is missing (no
    `node` or no esbuild for a JavaScript or TypeScript target). Install the
    tool the reason names.
  - `consent_required` (`summary.consent_required`, terminal label "needs
    --run-untrusted"): a Rust or C# target, or a Java target whose Maven or
    Gradle build needs it and whose `javac` fallback fails, builds by running
    project code. Give that consent with `--run-untrusted`, with the
    dependencies staged and the network isolated; `--resume` tries the target
    again.
  - `sanitizer_runtime_unavailable` (`summary.sanitizer_runtime_unavailable`;
    see [Sanitizers](sanitizers.md)): a C/C++ harness built, but its
    sanitizer runtime cannot start on this host.
- **Private Rust targets.** A private target that `--rust-private` admits but
  cannot set up (a parameter or resource the in-crate lane has no recipe for)
  has the outcome `unsupported_setup` (`summary.unsupported_setup`, terminal
  label "skipped: the in-crate Rust lane cannot set it up"), and its reason
  names what is missing.
- **Blind stubs.** A blind `void log_warn(void)` stub compiles, but the call
  site may pass arguments the stub ignores. That is acceptable for fuzzing,
  not for verification. When the harness's calls are almost all blind stubs,
  `run.json` sets `stub_execution.stub_only` (see
  [above](#stub_execution-false-clean-guard)).
- **Static linking.** `LD_PRELOAD` does not apply to a statically linked
  binary, so such a harness runs without the runtime shim: the build-time
  sweep runs as usual, and layer C of `needed_for_build` stays empty for it.
- **Cross-architecture sweeps.** A whole sweep builds for another
  architecture with `--target-triple` and runs under `--runner` (see
  [Whole-Sweep Cross Targets](cross-compilation.md#whole-sweep-cross-targets)),
  coverage-guided with the compiler's SanitizerCoverage. ASan is not armed,
  because its shadow memory does not work under qemu-user, so the crashes are
  hard faults, and the runtrace shim and its behavioral oracles do not run
  under the emulator (see [Cross-compilation scope and oracle
  limitations](cross-compilation.md#cross-compilation-scope-and-oracle-limitations)).
- **Multi-threaded targets.** The shim is thread-safe, but each fake resource
  has one random-number state, so two threads reading the same fake file
  descriptor compete for its bytes.
- **Runtime shim by lane.** The `LD_PRELOAD` behavioral and taint shim is
  armed for native Ada, C, C++, Rust, Go, COBOL and Fortran harnesses and for
  the Python, Perl, Ruby, Lua and PHP interpreters. Java, C#, JavaScript and
  TypeScript targets, and cross-built or emulated targets, keep their fuzz
  coverage and their crash and exception oracles, and do not get the runtrace
  findings (BHF-405, BHF-304, BHF-417, BHF-305 and the other runtime
  promotions). Java and JavaScript/TypeScript drivers run their own sink
  checks; each fuzzed target's `behavioral_oracles` in `run.json` says which
  applied.
- **C++ API lifecycles.** C++ harnesses cover direct calls and lifecycle
  sequences, and the sequence selection is heuristic. Template
  metaprogramming, user-defined literals, abstract receivers that need
  non-default constructors, and operator-overload or `shared_ptr` receivers
  usually need a wrapper or more manual flags (see [C and C++: Current
  Limits](c-cpp.md#current-limits)).
- **Go coverage.** Go gets block coverage from
  `go build -cover -covermode=atomic`, and each input's executed blocks are
  folded into the shared edge map. If module-wide `-coverpkg` fails, the lane
  retries with the selected package alone, then falls back to black-box mode;
  the target is kept and no coverage is invented.
- **Hand-written wrappers.** Private Rust targets that need an in-package
  harness, complex generated or platform-specific build graphs, framework
  hosts, coherent scientific array and dimension inputs, and longer state or
  resource protocols can need a hand-written wrapper. See the [expert harness
  parity audit](harness-parity-audit.md) for the measured differences.

See [Runtime Virtualisation](runtime-virtualisation.md) for the shim's
intercept list, environment-variable contract and replay envelope.
