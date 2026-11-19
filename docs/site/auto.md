<!-- SPDX-License-Identifier: Apache-2.0 -->

# Auto

`bhf auto <PATH>` is the point-and-shoot entry point. It takes a source tree
in any of the sixteen supported languages (Ada, C, C++, Rust, Java, Python, Perl,
Go, COBOL, Fortran, C#, JavaScript, TypeScript, Ruby, Lua, and PHP) — including
code with broken `#include` chains, undefined externs, missing types, missing
`with` clauses, or no runtime environment — and produces a fuzz lab plus a
findings report without manual harnessing.

Optional LLM assistance is compiled only with `cargo build -p bhf --features llm`.
It is not part of this pipeline and `auto` never calls a model. Use the [LLM and MCP guide](../llm/) to plan a bounded run, diagnose an
artifact, or review findings after the deterministic command has produced
evidence. Model output does not change target ranking, build status, coverage,
finding verdicts, replay, or minimization.

```sh
bhf auto path/to/src --work-dir bhf_work --per-target-time 60
```

## What It Does

For each candidate function discovered in the source tree:

1. Generate a lane-specific harness. Ada/C/C++ use the same generator as the
   narrower `generate-harness` subcommand; the other lanes use their dedicated
   `auto` builders. C first-parameter handle APIs and C++ class methods with
   visible same-class setup methods are tried as lifecycle sequence harnesses
   first, then fall back to direct-call harnesses.
2. Try to build it. On build failure, classify the diagnostics, synthesise the
   smallest repair that lets the build progress, retry. Retries stop at a
   configurable safety cap (`--max-repair-rounds`, default 16), but the loop
   breaks the moment a round applies no new repair — so the real cost is bounded
   by how many distinct repairs a target needs (deep flight-software
   type/config chains surface one new dependency per
   round), not by the cap. Repairs are cumulative.
3. Run the built harness through three fuzz passes (Empty, Rng, FuzzDriven)
   with the runtime virtualisation shim loaded. Each pass runs until its
   wall-clock budget is spent (no fixed iteration cap; `--iterations N` caps it
   explicitly). `--per-target-time` is the per-target TOTAL fuzz wall: the
   passes split it evenly and share one deadline, so the per-target wall ≈ the
   requested total regardless of pass count (#402). A target stops early once it
   hits `--per-target-finding-count` distinct findings, if set.
4. Capture findings, runtime-audit events, and the prosthetic ledger into
   `run.md` / `run.json`.

Rust and Java take a shorter path: their harnesses are generated and built
before this loop (attempt Step 0/0a) and skip the C/Ada harness-gen + repair
loop entirely, then drop straight into the step-3 fuzz cascade.

Python, Perl, and Go likewise bypass the C/Ada harness-gen + repair loop. Their
"build" is done by the interpreter/compiler itself before the fuzz cascade —
`py_compile` + an import smoke-test (Python), `perl -c` + a `require` smoke-test
(Perl), and `go build` to a native fork-server binary (Go) — and an
un-importable/uncompilable target skips cleanly rather than entering repair.

The remaining lanes follow the same "pre-build then fuzz" pattern with their own
toolchains: COBOL via GnuCOBOL (`cobc`), Fortran via `gfortran` with ASan, C#
via `dotnet` + SharpFuzz IL instrumentation, JavaScript/TypeScript under a warm
Node process (TypeScript transpiled with esbuild), and Ruby, Lua, and PHP under
their own interpreters with in-process edge coverage.

An interpreter (Python, Perl, Ruby, Lua, PHP, Node) killed by SIGSEGV with no
error of its own, as PHP 8.3 is by deep recursion with no stack limit set,
reports under BHF-210 with CWE-674 (uncontrolled recursion), not as an
invalid-memory access (CWE-119): code the interpreter runs cannot corrupt
memory, so its native stack ran out. The explanation says so and the fix hint
is to bound the recursion depth.

## Flags

| Flag | Default | Purpose |
|---|---|---|
| `--work-dir <DIR>` | `./bhf_work/` | Output root |
| `--max-work-dir-mb <MiB>` | `4096` | Stop starting new targets once the allocated work-directory size reaches the ceiling. Completed and in-flight targets are preserved and reported, so parallel jobs can overshoot by their final artifacts. `0` disables the ceiling; findings are never deleted to meet it |
| `--max-corpus-mb <MiB>` | `64` | Per-target retained coverage-corpus ceiling for both memory and `corpus/<harness-id>/queue/`. Finding testcases are separate and always preserved |
| `--reuse-legacy-corpus` | off | In a work dir from an earlier release (migrated from the 0.2.x layout, or run by an earlier `bhf auto`), keep reseeding its old corpus instead of moving it to `corpus-legacy/` on the first run |
| `--config <PATH>` | auto-load `.bhf.toml` | Load run options from a TOML file so a project's runs are reproducible; CLI flags always override it, and relative paths in it resolve against the file's own directory. Only the keys listed under [Config file](#config-file) are accepted, any other key is an error. Without this flag, a `.bhf.toml` in the scanned tree root is auto-loaded — but since that tree is untrusted, an auto-loaded config honors only SAFE knobs; the keys that EXECUTE something (`build-command`, `run-untrusted`, `unsafe-search-and-run-build-commands`, `probe-build`, `msbuild-evaluate`, `winafl-path`, `dynamorio-path`, and the whole `[toolchain]` and `[cross.<guard>]` tables) are ignored, with a note, unless the config is passed explicitly with `--config` |
| `--dry-run` | off | Plan only: discover + rank targets, run the toolchain preflight, report the build-recovery plan, then EXIT without building or fuzzing — validate scope, config, and toolchains before a long run |
| `--per-target-time <SECS>` | `60` | **Total** per-target fuzz wall, split evenly across the passes under one shared deadline (so the per-target wall ≈ this, not × pass count). libFuzzer `-max_total_time` / AFL `-V` parity (#402) |
| `--per-target-finding-count <N>` | unset (collect all) | Stop a target as soon as it has produced N **distinct** findings (crash signatures), or when its `--per-target-time` is spent — whichever first. Checked mid-pass (stops the instant the Nth lands; remaining passes skipped). `1` ≈ libFuzzer stop-on-first-crash |
| `--total-time <SECS>` | unset | **Deprecated** alias of `--per-target-time` (overrides it when set); retained for existing benchmark/parity invocations. Hidden from `--help` |
| `--iterations <N>` | unset (wall-clock governs) | Per-pass execution cap (libFuzzer `-runs`); `0`/unset lets `--per-target-time` govern depth. Retired the old hardcoded 1024 cap |
| `--rss-limit-mb <MB>` | dynamic | Per-harness resident-set cap; defaults to one quarter of available host/cgroup memory, clamped to 512..8192 MiB. An over-budget input is killed and reported as a BHF-209 OOM finding instead of OOM-killing the host; pass an exact value or `0` to disable |
| `--max-targets <N>` | unset (fuzz every viable target) | Cap on the targets that reach the **fuzz** phase (successful builds), not on the candidates inspected. The sweep attempts ranked candidates in order and stops once N of them fuzz; a candidate that does not build or has unsupported parameters does not count, so lower-ranked viable targets are backfilled instead of being starved by a nonviable prefix. Stops at the cap, the `--campaign-time` deadline, or when candidates run out. `--dry-run` prints the plan; `--list-targets` still prints the full ranked list |
| `--max-attempts <N>` | unset (as many as `--max-targets` needs) | Hard ceiling on the ranked candidates **inspected** (built or attempted), however many fuzz: bounds a huge legacy tree where most candidates are nonviable, so the `--max-targets` backfill cannot grind through all of it |
| `--campaign-time <SECS>` | unset (run all) | Whole-**run** budget across all targets. Default: an OUTER wall-clock cap — once exceeded, `auto` stops STARTING new (ranked) targets (the in-flight one finishes) and reports how many of the N discovered were reached. With `--min-target-time`, switches to SPLIT mode (see below). Bounds *how long* a huge-tree sweep runs |
| `--min-target-time <SECS>` | unset | SPLIT-mode floor, used **only** with `--campaign-time` (errors otherwise): divide the campaign budget across the N attempted targets — each gets `max(min, campaign / N)` of fuzz time, and only the top `floor(campaign / per_target)` ranked targets are attempted (the rest logged unfuzzed), never less than this floor. Overrides `--per-target-time` |
| `--jobs <N>` / `-j <N>` | half the host's cores (at least 1, at most 8; `BHF_DEFAULT_JOBS` overrides) | Build+fuzz up to N targets CONCURRENTLY via a bounded worker pool; `--jobs 1` runs one at a time. Child allowance is `jobs × --rss-limit-mb`, so with both defaults (half the cores, a quarter of memory each) the children alone may reach well over half the host's memory; total peak also includes the parent declaration index/results, compilers, and the OS. Results aggregate deterministically regardless of completion order |
| `--passes <SET>` | all (`empty,rng,fuzz`) | Restrict the per-target cascade to a comma list of passes (`empty`, `rng`, `fuzz`). E.g. `--passes fuzz` runs only the fuzz-driven pass — ~3× the throughput of the full 3-pass cascade. Mutually exclusive with `--single-pass` |
| `--single-pass` | off | Convenience for `--passes fuzz`: run ONLY the fuzz-driven pass per target |
| `--max-repair-rounds <N>` | `16` | Ceiling on build-fail → repair → retry rounds per target. The default covers all 95 successful clean/damaged samples in the strengthened 53-repository matrix (p95 6, p99/max 14 rounds); the no-progress early-break still applies, so it is a cap, not a fixed cost |
| `--no-minimize` | off | Skip minimizing each root-cause representative after fuzzing (bounded to 30 s a group, 5 min in all; C/C++ on the crash, Ada on its event-log signature), which writes its `min_testcase.bin` |
| _(discovery cache)_ | **on** | Discovery is cached by default to `<work>/discovery-cache.json` and reused on a re-run when a **build-stable** content fingerprint of the target source (file paths + sizes + content hashes + dir-filter) is unchanged, skipping the tree-sitter re-parse + re-rank — the dominant re-run cost on a big tree. The fingerprint depends only on the fuzzed code (not on which bhf build computed it), so rebuilding bhf does not invalidate it. A mismatch recomputes and rewrites the cache; a stale cache is never used silently |
| `--discovery-cache <PATH>` | `<work>/discovery-cache.json` | Put the default-on cache at an explicit path, useful when work directories change or the cache belongs on a known volume |
| `--fresh-discovery` | off | Force a fresh discovery this run (ignore any cache), then overwrite the cache with the new result |
| `--no-discovery-cache` | off | Disable the discovery cache entirely (never read or write it) |
| `--resume` | off | Resume a prior sweep over the SAME work-dir: reload targets that already completed and re-run only the rest. A per-target `harnesses/<id>/result.json` is written the moment each target finishes (so an INTERRUPTED run is resumable), and on a re-run it is loaded back into the report FULLY re-integrated — its outcome bucket, repair manifest, findings, and per-pass detail all appear in the new `run.json`/`run.md` exactly as if it had been re-run, plus a `resumed` count of how many were carried over. Requires the discovery cache to hit (target source unchanged); on a source change every target is re-attempted to avoid stale results. A target whose lane's toolchain was missing (`missing_toolchain`), whose sanitizer runtime could not start (`sanitizer_runtime_unavailable`), or that needed `--run-untrusted` (`consent_required`) is always tried again, since the host may have been fixed, or the run may give that consent, since |
| `--reuse-discovery` | — | Deprecated no-op (caching is now the default); accepted for back-compat |
| `--sanitizers <asan,ubsan,msan,tsan,lsan,hwasan,cfi,realtime \| none>` | `address,undefined` (ASan and UBSan) | Arm the named matrix for native C/C++ builds instead of the default (the other lanes own their instrumentation). `hwasan` takes ASan's place on an AArch64 host and is refused on any other. `cfi` is not armed in the fuzzed build: it adds a control-flow integrity replay of the corpus after the fuzz passes. `realtime` (clang 20+) likewise adds a RealtimeSanitizer replay of the nonblocking targets' corpora. The opt-out `none` builds native C/C++ coverage-only with no `-fsanitize=` (crash-only, zero ASan/UBSan false positives). Operator `<SAN>_OPTIONS` (suppressions / FP-killers) are merged, not clobbered. See [Sanitizers](../sanitizers/) |
| `--nonblocking <entry-points \| all \| NAME>` | `entry-points` | With the `realtime` lane: the targets whose harness runs in a real-time context, so RealtimeSanitizer reports each allocation, lock, sleep or system call they make. `entry-points` marks interrupt handlers and RTOS task bodies, `all` every target, and a name that target (repeatable). An error without `--sanitizers ...,realtime`. See [Sanitizers](../sanitizers/#the-realtimesanitizer-replay) |
| `--comparison-progress` | off | Enable laf-intel comparison-progress coverage (#421); rewards an input that matches more leading bytes of a multi-byte magic/format gate. Alias `--cmp-progress` |
| `--engine <LIST>` | `builtin` | Fuzz engine(s) for the per-target fuzz phase, comma-separated. `builtin` is the in-process coverage-guided engine; `afl++` drives AFL++ on the auto-recovered build (C/C++, COBOL, Fortran, Rust and Ada; needs `afl-fuzz` + `afl-clang-fast`, else falls back to builtin with a warning). `--engine builtin,afl++` runs both per target, splitting `--per-target-time` between them |
| `--winafl-path <DIR>` / `--dynamorio-path <DIR>` | `BHF_WINAFL_PATH`, then `afl-fuzz.exe` on PATH / `BHF_DYNAMORIO_PATH`, then `DYNAMORIO_HOME`, then `drrun.exe` on PATH | WinAFL's directory (holding `afl-fuzz.exe` and `winafl.dll`) and DynamoRIO's install root (or its `bin64`) for `--engine winafl` (see [Windows](windows.md#installing-winafl-and-dynamorio)) |
| `--winafl-instrumentation <dynamorio\|intel-pt>` / `--winafl-iterations <N>` / `--winafl-coverage-module <MODULE>` | `dynamorio` / `5000` / none | WinAFL's coverage (`afl-fuzz -D`, or Intel PT with `-P`, which needs an Intel CPU, a WinAFL built with `-DINTELPT=1` and no VM in between), its `-fuzz_iterations` (persistent-entry calls per process), and another module (a target DLL) to measure coverage in (repeatable) |
| `--winafl-page-heap` | off | Run the WinAFL build under full PageHeap, so a heap overflow faults as a crash: WinAFL fuzzes a copy of `main_winafl.exe` under a name only the run uses, with an Image File Execution Options key bhf sets and removes after the run. Needs an elevated shell (refused up front otherwise) |
| `--differential <A:B>` | unset | Two-compiler differential fuzzing (C/C++), e.g. `clang:gcc`: after the normal run, rebuild each C/C++ harness under both compilers and replay the corpus through both, flagging any input whose exit/crash behavior diverges (a codegen- or UB-dependent bug) as a BHF-301 finding. Either side may be a compiler path; paths with spaces are quoted |
| `--seed-file <PATH>` | none | Seed-input file whose bytes bootstrap every target's corpus, used byte for byte (binary formats included); repeatable. Any explicit seed input turns tree seed mining off, even one that loads nothing (a missing file, an empty dir) |
| `--seed-dir <DIR>` | none | Directory of seed inputs (one per regular file, in name order); repeatable |
| `--no-seed-mining` | off | Do not seed targets from the tree's own test-data files (see [Seeds](#seeds)). Config key: `seed-mining = false` |
| `--extra-include <DIR>` | none | Extra C/C++ include dirs for dependency headers outside the swept tree; seeded onto every harness `-I` ahead of synthesized placeholders. Read from local disk only; paths with spaces are quoted; repeatable |
| `--extra-source <FILE>` | none | More C/C++ sources (`.c`/`.cpp`) compiled and linked into every harness, for a library whose target calls into sibling translation units the auto-linker would otherwise stub. Read from local disk only. Repeatable |
| `--cc <PROGRAM>` / `--cxx <PROGRAM>` | `clang` / `clang++` | C/C++ compiler for every harness build (a name on `PATH` or a path), replacing `CC`/`CXX`. The Makefile picks matching instrumentation (gcc, a cross-prefixed gcc, or clang), so no flag spelling has to be adapted. A C++ compiler derived from `--cc` or `--target-triple` (`g++` next to `gcc`) must exist only when the sweep has a C++ candidate. The choice is announced; config keys `toolchain.cc` / `toolchain.cxx` |
| `--cflags <FLAGS>` / `--cxxflags <FLAGS>` / `--ldflags <FLAGS>` | none | Extra compile / link flags, APPENDED to bhf's coverage and sanitizer flags (whitespace-separated; repeatable). Their preprocessor words (`-D`, `-U`, `-I`, `-isystem`, `-include`) and the library operands of `ldflags` (`-L`, `-l`, archives, objects, linker options `-Wl,...`/`-Xlinker ...`, `-pthread`, in their order, with the linker choice `-fuse-ld=`/`--ld-path=` they are written for) reach every build lane (coverage, AFL++, libFuzzer, MSan, TSan, differential); the rest apply to the lanes built with `$(CC)`/`$(CXX)`. A `CFLAGS`/`CXXFLAGS` in the environment is appended to the `main` build as well, after bhf's flags, except in a build whose compiler bhf picked in place of the operator's (a platform guard's cross lane, the `--sanitizers` clang fallback). A lane that still fails to build is reported (`run.json` `targets[].lanes`, with the time each lane was recorded in `recorded_at`, `summary.txt`, `run.md`; a lane of a target `--resume` reloaded is marked as recorded by an earlier run); config keys `toolchain.cflags` / `toolchain.cxxflags` / `toolchain.ldflags` |
| `--define <NAME[=VALUE]>` / `--toolchain-include <DIR>` | none | Preprocessor definitions and `-I` directories for every harness compile and every lane, bhf's driver object included (repeatable); config keys `toolchain.defines` / `toolchain.include-dirs` |
| `--sysroot <DIR>` | unset | Handed to the compiler as `--sysroot=`, and to a qemu-user runner as `-L <DIR>` when `--runner-arg` is not given; config key `toolchain.sysroot` |
| `--target-triple <TRIPLE>` | host | Build every C/C++ candidate for this triple, with `<triple>-gcc`/`<triple>-g++` unless `--cc`/`--cxx` name the compilers (a clang gets `--target=`). A triple the host cannot run needs `--runner`; config key `toolchain.target` |
| `--runner <PROGRAM>` / `--runner-arg <ARG>` | unset | Whole-sweep cross mode: every C/C++ candidate is built for the target WITH coverage and fuzzed under this emulator (`qemu-aarch64`). Arguments go between the runner and the harness; see [Cross-Compilation](../cross-compilation/#whole-sweep-cross-targets). Config keys `toolchain.runner` / `toolchain.runner-args` |
| `--ada-prefix`, `--ada-target`, `--ada-runtime`, `--ada-gprbuild`, `--ada-gnat`, `--ada-switch`, `--probe-backend` | host GNAT, `host_file` | The Ada toolchain of every Ada harness build: tool prefix (`<prefix>-gnat`), `for Target use`, `for Runtime ("Ada") use`, explicit `gprbuild`/`gnat` programs, extra compiler switches appended to bhf's, and the AdaFuzz probe backend. `--ada-target` defaults to `--target-triple`. When the tree has Ada candidates, the toolchain must be installed: a `<prefix>-gprbuild` (or `gprbuild` with `<prefix>-gnat`), or the explicit programs, else the run (and `--dry-run`) stops with exit 2 naming the key. A probe backend other than `host_file` needs an on-target transport, so without a runner it is refused the same way: a host sweep reads events only through `host_file`; `bhf build` refuses it too for an Ada harness built for this host (no foreign `--target`), whether it comes from the flag or the config. The choice is announced. Config keys `toolchain.ada.prefix`, `toolchain.ada.target`, `toolchain.ada.runtime`, `toolchain.ada.gprbuild`, `toolchain.ada.gnat`, `toolchain.ada.switches`, `toolchain.ada.probe-backend` |
| `--ada-deps <DIR>` | none | Local Ada dependency-source dirs put on the build path (offline: never fetched); repeatable. Locally-cached Alire deps are picked up automatically |
| `--project <PATH>` | the project owning each target's source | The Ada project (`.gpr`) to use for generation, staging, scenario exclusions and the build, when a multi-project layout is ambiguous. By default `auto` takes the non-aggregate project whose active `Source_Dirs` hold the target's source. An error when the path is missing |
| `--probe-build` | off | Run the project's own build offline to recover real compile flags and generated headers. Detects + drives CMake, Meson, Visual Studio, Make/autotools (compiler-interposing wrapper), Ninja, and — under interception — Bazel/SCons. It builds under `<work>/probe/`, never in the tree (CMake/Meson into a build directory there, Make and intercepted commands in a copy of the tree), so the tree is left byte-identical and a read-only checkout can be probed; a probe that yields no compile database says why. EXECUTES untrusted build scripts (sandboxed when bwrap/firejail is present, with the tree read-only) |
| `--msbuild-solution <PATH>` | shallowest `.sln`/`.slnx` | The Visual Studio solution the default project import reads (a tree with a solution or `.vcxproj` and no compile database or CMake/Meson build; off Windows, only when the solution is the tree's only build description, unless this flag names it). A relative PATH is resolved against the scanned tree, a solution outside the tree is imported too, and a missing file is an error. The import runs nothing: it evaluates the projects' property sheets and `Condition=`s for one configuration and writes `<work>/auto/msbuild/compile_commands.json`. See [c-cpp.md](c-cpp.md) |
| `--msbuild-config <CONFIG\|PLATFORM>` | first listed for x64 | The configuration the project import applies (`Release\|x64`) |
| `--no-msbuild-import` | off | Do not import a Visual Studio solution by default |
| `--msbuild-evaluate` | off | Let an installed MSBuild evaluate the imported projects (`msbuild -getItem:ClCompile`), with the static reading as the fallback. Runs the projects' property functions and imported `.props`/`.targets`, code from the scanned tree, so it is opt-in (see [windows.md](windows.md)); `--probe-build` and `--run-untrusted` imply it |
| `--build-command <CMD>` | unset | Recover flags from any CUSTOM build (a `build.sh`, Waf, a vendor RTOS build) by running `<CMD>` under (1) a front-of-`PATH` compiler shim for `cc`/`gcc`/`clang` + named vendor compilers (Diab, Green Hills, QNX, Keil/IAR, TI) + cross-prefixed toolchains invoked by name, and (2) an `LD_PRELOAD` exec-interposer for compilers invoked by absolute path or `posix_spawn`. The universal escape hatch; takes precedence over the auto-detected tier. Accepts either a script (`--build-command ./build.sh`) or a full command (`--build-command "make -C src lib"`), run via `sh -c` (on Windows via `cmd.exe`, with executable shims and an MSBuild build captured through its CL task; see [windows.md](windows.md)). EXECUTES the command (sandboxed when available). When builds fail and a custom build script is present, `auto` prints a ready-to-run hint with this flag |
| `--cxx-std <STD>` | auto | Pin the C++ standard for every harness build (`gnu++14`, `c++03`, …) for legacy C++. By default `auto` builds C++ at the modern standard and, on a dialect failure, automatically retries successively older standards (`gnu++17`→`gnu++14`→…→`gnu++98`) until one builds — the chosen standard is cached per project, so no flag is needed for old code unless you want to override the search |
| `--no-fuzzing-build-mode` | off | Build without `-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`, which every C/C++ lane otherwise defines (OSS-Fuzz's convention), so code a project compiles out of fuzz builds (a signature check) runs. `BHF_FUZZING_BUILD_MODE=0` does the same |
| `--grammar <PATH>` | unset | JSON grammar describing the target's input format for structure-aware generation (a Nautilus-style grammar mutator), applied to every fuzzed target. Each rule maps a non-terminal to production strings where `{NAME}` references another rule; the start symbol is `START` or the first rule. Validated up front (a bad grammar fails the run fast) |
| `--max-len <N \| auto>` | `auto` | Maximum fuzz input length. `auto` grows the effective length adaptively per target — free up to ~1 MiB, and beyond that only while longer inputs keep finding new coverage — so a large-object target (image, archive, firmware) is handled WITHOUT a seed corpus, and a small-format one is not grown pointlessly. A positive integer sets a fixed cap. Seeds are kept whole up to this cap for both engines; with `--engine afl++` a fixed cap below AFL++'s 1 MiB default is also passed to afl-fuzz as `-G` when it has that option (AFL++ 4.00c or newer; an older afl-fuzz gets only the capped seeds, and a note on stderr) |
| `--max-array-elems <N>` / `--max-decode-depth <N>` / `--max-decl-bytes <BYTES>` | `64` / `4` / `65536` | C decoder bounds: array elements decoded per fixed array (a larger array fuzzes its fill count instead), recursion depth of nested struct/union/array decoders (deeper fields stay zeroed), and the byte ceiling of one parameter's decoder body (a larger one rejects the parameter) |
| `--container-size-max <N>` / `--array-max-size <N>` / `--bitset-max-size <N>` | `16` / `4096` / `4096` | C++ decoder bounds: a dynamic container's fuzzed element count (`vector`, `set`, `map`, `span`, ...; also clamped by the ~1 MiB per-parameter budget), the largest `std::array<T, N>` accepted when `T`'s size is unknown at generation time, and the largest `std::bitset<N>` decoded bit by bit |
| `--timeout <DUR>` | `10s` | Per-execution timeout (e.g. `10s`, `500ms`). An execution past it is killed, and an input that hangs again when re-run with twice the timeout is a hang finding (BHF-230; see [Sanitizers: Hangs](./sanitizers.md#hangs)). `run.md` and `run.json` count the hangs |
| `--deadline <DUR>` | off | Response deadline for every fuzzed target (e.g. `50ms`, `1s`), the timing oracle: an input whose execution takes longer, in two of three fresh re-runs as well, is a response-deadline finding (BHF-555). It must be shorter than `--timeout`; `0` or a longer one is refused (exit 2). Config key `deadline` |
| `--collector <SPEC>` | `none` | Runtime-event collector run after each fuzzed target's passes: the target's retained inputs (its findings, then its corpus, at most 16) are replayed one by one under it, as `bhf fuzz --collector` does. `auto` selects the platform's provider (the native Windows ETW provider, or on Linux the runtrace shim); a path runs an external sidecar speaking `bhf.collector-event.v1`. A violation the runtime oracles did not already report becomes a `binary_semantic` finding with its input, and each target in run.json carries its `collector` observation (each replay's testcase, input SHA-256 and PID) |
| `--collector-window-ms <MS>` | `250` | How long the collector keeps observing a replayed input's descendant processes after it exits |
| `--cxx-expected-exception <TYPE>` | none | A C++ exception type an API throws to tell its callers about bad input (`std::invalid_argument`, `json::parse_error`; `*` for any type). One that leaves the target is not an uncaught-exception finding (BHF-231); every other exception that leaves a C++ target is, since it would terminate a program that calls the target the same way, and one that escapes a `noexcept` function always is. Repeatable; config key `cxx-expected-exception`. Sets `BHF_CXX_EXPECTED_EXCEPTIONS`, which `bhf fuzz` children read too |
| `--run-untrusted` | off | Consent umbrella for `--probe-build`, Ada (`alr build` / `gprbuild`) build probes, Rust (Cargo build scripts and proc macros) and C# (MSBuild targets) builds, and Java Maven/Gradle project builds. Java project builds use Maven offline mode or Gradle `--offline`; stage target dependencies first. Bare Java source can still use `javac` without this flag. Without it a Rust or C# target, and a Java one whose `javac` fallback fails too, is reported as `consent_required` ("needs --run-untrusted") rather than unsupported, and the next steps ask for the flag, not `--force`. Implies `--probe-build`. EXECUTES untrusted scripts |
| `--unsafe-search-and-run-build-commands` | off | UNSAFE convenience: search the tree for its own build entry point and EXECUTE it to recover flags, instead of you passing `--build-command`. Finds a custom build (build.sh, autotools bootstrap/autogen/configure, SCons, Waf, Bazel) and runs it under the compiler-intercepting shim, and enables the `--probe-build` tiers (CMake/Meson/Make) + the Ada build probe. Runs sandboxed when available, but it executes UNTRUSTED code from the scanned tree — use only on sources you trust. An explicit `--build-command` overrides the search |
| `--deps-only` | off | Build each target as far as possible, emit the missing-dependency manifest, and SKIP fuzzing — the fast "what does this tree need?" scan |
| `--static` | off | Run the static analyzer over the WHOLE tree in addition to fuzzing — not only as a fallback when a target can't be built/fuzzed. Findings (classification `static_scan`, ids `F-STATIC-*`) merge into the unified report (findings.csv, run.json, SARIF) next to the fuzz findings, so a target that built+fuzzed still gets static coverage and files with no fuzzable subprogram are analyzed too. Same engine as the standalone `bhf static-scan`. BHF's own generated harnesses/stubs under the work-dir are excluded, and dependency/build/cache trees such as `node_modules`, virtualenvs, `dist`, vendored deps, and generated JS `compiled/` bundles are pruned before analysis — the scan reports the target tree, not scaffolding or dependency payloads |
| `--external-tools` | off | Also drive installed EXTERNAL analyzers (gosec/Bandit/semgrep/GNATcheck) as **subprocesses** (never linked), parse their SARIF into the report (ids `F-EXT-*`), and let the fuzz-confirmation join confirm/downgrade them too. Each tool runs only if the active license profile (`BHF_PROFILE`, default `strict-permissive`) permits its subprocess — the default runs NONE, so the default profile never invokes a GPL tool; set `BHF_PROFILE=external-tools` to opt in. Missing tools are skipped. Implies `--static` |
| `--symcc` | off | Build a SymCC variant of each native C/C++ harness (`make symcc` → `main_symcc`, compiled by SymCC's `symcc` for C and `sym++` for C++), the concolic lane that solves a comparison against a value the input holds only after hashing or modular arithmetic. SymCC is GPL-3.0 and runs only as a subprocess, under a license profile that permits it: `BHF_PROFILE=external-tools` or `research-lab`; without `BHF_PROFILE` the flag opts into `external-tools`, and `strict-permissive` refuses it (with a note). Needs `symcc` and `sym++` on PATH (`scripts/ci/install-symcc.sh` builds them), or `SYMCC_CC`/`SYMCC_CXX` naming them; `sym++` uses the system C++ library unless `SYMCC_LIBCXX_PATH` names a libc++ SymCC instrumented. A harness whose SymCC build fails is fuzzed without it, and `run.json` `targets[].lanes.symcc` says why. Each builtin pass of a harness with the lane runs a solver loop (#331): once the pass's corpus has not grown for `BHF_SYMCC_PLATEAU_MS` (default 5000), its newest entries SymCC has not run (`BHF_SYMCC_ENTRIES` per round, default 8) run through `main_symcc` (each for at most `BHF_SYMCC_TIMEOUT_MS`, default 10000, under the harness's sandbox and with `--rss-limit-mb` as its address-space limit), and every input SymCC solves that the pass does not have runs next and stays in the corpus when it adds coverage. A line after the pass says what SymCC solved; `fuzz_runs/<id>-latest.json` has the pass's `symcc` counts and `<work>/symcc-import.log` each input it gave. Three SymCC runs in a row that fail or time out without an input stop the loop for that pass. `BHF_SYMCC=1` does the same as the flag, and turns the loop on for `bhf fuzz` of a harness with `main_symcc` beside it |
| `--sbom` | off | Write an evidence-graded SBOM and VEX bundle at the end of the run into `<work>/sbom/` (`sbom.json`, `cyclonedx.json`, `vulnerabilities.json`, `openvex.json`, `sbom.csv`). The tree's components are enriched with the run's `auto/run.json`, so libraries a harness drove are marked exercised. `bhf sbom` gives finer `--emit` and `--ecosystems` control |
| `--sloc <FILE>` | unset | Write a per-language SLOC breakdown (files, total, comments, blanks, SLOC) of the tree, then run as usual. A relative path lands in `<work>/auto/`; a `.json` name writes JSON, anything else a text table |
| `--force` / `--force-fuzz` | off | Adds a SECOND pass. The sweep first runs exactly as it would without the flag, then re-attempts only the targets that did not reach the fuzz phase — forced: a best-effort driver for opaque/function-pointer/unknown params, stubs for whatever the compiler reports undefined, and no hard failure (report-only is the floor). The managed lanes have their own force paths: Go drives an undrivable parameter as its type's zero value and calls a method on a zero receiver, and C# allocates a receiver whose type has no accessible parameterless constructor without running one. A forced retry may only ever *replace* a target's outcome by fuzzing it, so `--force` cannot lower the fuzzed count; it also cannot rescue a target whose parameters were never the problem. Findings from a forced build are floored to **Low** confidence with a `forced` note and counted separately — a forced crash may be a stub artifact, not a real defect. With `--resume` over a finished campaign it keeps every target that already fuzzed and forces only the rest, without repeating the unforced attempt. Persistence honors `--max-repair-rounds`; does not imply `--static` |
| `--rust-private` | off | Harnesses private Rust targets in-crate (#83): admits `pub(crate)` and private functions and methods, and injects each harness as a module into a copy of the crate, so it calls them by their `crate::` path, with a materialized path-backed resource for a target that opens one. `rust-private = true` in the config, or `BHF_RUST_INCRATE_PRIVATE=1`, turns it on too. A target the lane admits but cannot set up (a parameter or resource it has no recipe for) is outcome `unsupported_setup`, apart from `unsupported_params`. The crate's build needs `--run-untrusted`, as every Rust target's does |
| `--static-dynamic` | — | Deprecated, no effect. `results/findings.csv` always tells a static-scan row from a fuzzed one, in its `kind` column, and says whether fuzzing confirmed it in `confirmation` |
| `--install-deps` | off | After the sweep, fetch still-blocking deps from the manifest (apt-get / `alr get`). Opt-in and the only ONLINE part of `auto`; nothing is fatal |
| `--list-fakes` | — | Print the fake-resource plugin inventory and exit |
| `--languages <LIST>` (alias `--lang`) | all languages found | Restrict the sweep to a comma-separated subset of source languages. Accepts any of the sixteen fuzzable languages: `ada`, `c`, `cpp`, `rust`, `java`, `python`, `perl`, `go`, `cobol`, `fortran`, `csharp`, `javascript`, `typescript`, `ruby`, `lua`, `php`. Candidates in any other language are dropped **after** discovery (so one discovery cache serves every language subset) and **before** `--list-targets` and `--max-targets`, so the ranked list and the top-N both reflect the filter. Common spellings are accepted (`c++`/`cxx`/`cc`→cpp, `rs`→rust, `py`→python, `pl`→perl, `golang`→go); matching is case-insensitive. The SBOM/SCA pass is unaffected — it always scans the whole tree across all ecosystems regardless of this fuzzing-lane filter |
| `--target <NAME>` | all discovered targets | Target-name filter: the full discovered name, the bare name, or a qualified suffix (`Class::method`), optionally with the parameter list. An exact spelling wins; the suffix match applies only when no target has exactly that name. Repeat to run a small named subset. A miss prints the closest names. Selects a project fuzz driver (`LLVMFuzzerTestOneInput`) that other targets would otherwise shadow |
| `--target-file <PATH>` | all discovered source files | Exact source-file filter; accepts absolute paths or paths relative to the sweep root |
| `--harness-id <ID>` | all discovered harness ids | Exact stable harness-id filter from a prior auto report |
| `--exclude-path <TEXT>` | none | Drop targets whose normalized relative source path contains `TEXT`; repeatable |
| `--exclude <tests,tools,examples>` | none | Drop common project areas before attempts run |
| `--preprocess <auto\|always\|never>` | `auto` | Run the CPP-lite preprocessor over C/C++ before discovery, resolving `#if`/`#ifdef` branches and expanding object-like macros, so a function compiled out under the active configuration is not discovered (a line map keeps locations right). `auto` preprocesses only files with heavy conditional compilation |
| `--no-stubs` | off | Skip build-time auto-stubbing (diagnostics only) |
| `--mode reporting\|attacking` | `reporting` | Actionability profile and, in attacking mode, target scheduling |
| `--verbose` / `-v` | off | Per-target outcome detail: skip/fail reason, repairs applied, per-pass exec/finding counts |

## Config file

`--config <PATH>` (or a `.bhf.toml` auto-loaded from the scanned tree root)
holds run options as TOML. A key fills a flag the command line did not give
(a flag given with its default value still wins); relative paths resolve against the config file's directory, so the
file means the same thing from any working directory. Only these keys exist,
each spelled like its flag:

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
diagnostic switches) have no key; a unit test keeps this list and the flag set
in step.

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

Every value is validated before the sweep starts: an unknown key, a define
that is not `NAME[=VALUE]`, a target that is not a triple, `runner-args`
without a `runner`, a compiler or runner that is not installed, a target (C/C++
or Ada) or a C/C++ compiler (including `CC`/`CXX` from the environment) that
builds for a platform the host cannot run without a runner, and a runner with
nothing foreign to run are all errors naming the key.

The C/C++ candidates become a cross sweep only when the C/C++ side builds for
another target (`target`, or a cross `cc`); a runner set for a foreign
`[toolchain.ada] target` alone runs just the Ada harnesses, and the C/C++
candidates keep their native sanitizer builds. In a cross sweep, the archives
`probe-build`/`build-command`/`run-untrusted` build for this host (in the probe
directory, or in the tree for a plain Makefile) are rebuilt for the target from
the captured compile commands and linked in their place; an archive that cannot
be rebuilt is named with the reason. In a native sweep
with a GCC toolchain, the build probe builds its archives with that GCC and
GCC-spelled instrumentation. See
[Cross-Compilation](../cross-compilation/#whole-sweep-cross-targets).

`[cross.<guard>]` tables override the toolchain and emulator of one
guard-driven cross lane, the one candidates guarded for that platform take:

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
[Cross-Compilation](../cross-compilation/#overriding-a-lanes-toolchain).

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

The primary human handoff is `<work>/results/INDEX.md`, ordered by impact with
source locations, confidence, evidence links, remediation, and replay commands.
`<work>/results/findings.json` (`bhf.findings.v1`) and
`<work>/results/findings.csv` are the machine-readable root-cause indexes,
`results/findings.sarif` the SARIF log, and `<work>/results/findings/<id>/`
holds each finding's complete evidence bundle. Campaign mechanics and coverage
caveats remain in `auto/run.md`, `run.json`, and `summary.txt`.

BHF deletes Rust Cargo `target/` trees as soon as their final replay harness
is linked. To reclaim the same caches from an older/interrupted run plus scratch
files, without deleting findings, reports, corpora, result checkpoints, generated
source, or replay binaries, run:

```sh
bhf clean bhf_work --compact
```

At startup, `auto` also removes stale private Cargo target trees left by older
BHF releases. At the end of a run it compacts disposable scratch data. The
4 GiB work-directory ceiling is based on allocated filesystem blocks, does not
follow symlinks, and stops target admission instead of deleting evidence. Targets
already running are allowed to finish, so parallel runs can overshoot the limit
by their final artifacts. The report records that the output limit stopped the
campaign; `--max-work-dir-mb 0` disables only this admission ceiling.

## Expert-parity harness behavior

The auto generators checkpoint entry immediately before the selected call in all
sixteen lanes. A driver that merely decodes input, loads a module, or runs setup is
reported as built-but-not-entered rather than successful fuzzing. Target ranking is
identifier-token aware and prioritizes public parsers, decoders, whole-artifact
entrypoints, and stateful execution surfaces while demoting debug/reporting helpers.

The lane-specific generators also recover call setup an expert would normally
write by hand: path arguments are backed by temporary files in JavaScript, Ruby,
and COBOL; asynchronous JavaScript calls are awaited before cleanup; Go can mine a
one-input feeder followed by a zero-argument terminal; PHP recursively constructs
bounded typed value objects; C++ supports defaulted arguments, common public member
templates, and byte-string instantiation; Fortran emits descriptors for assumed-
shape character arrays; and C# instruments project IL in a separate target
assembly. Go coverage retries the exact selected package when module-wide
instrumentation is blocked by unrelated platform packages.

These behaviors and their residual limits are measured in the
[200-project expert-parity audit](./harness-parity-audit.md). Private Rust
targets need `--rust-private`. These behaviors do not make every project
automatically harnessable: generated or platform-specific build graphs, framework hosts, scientific arrays with coupled
dimensions, and general constructor/feed/execute/cleanup protocols remain explicit
gaps rather than silently fabricated successes.

### Scaling to large trees

Even a modestly sized project can discover hundreds of candidates — a single
large header (a header-only C/C++ library is the common case) expands into
hundreds of fuzzable signatures. The default sweep analyzes and fuzzes **every**
discovered candidate with **no** outer wall-clock cap, and its declaration-index
phase can run for tens of seconds with little output, so a large run can look
stuck when it is simply working. `auto` prints a hint naming the bounding flags
once a tree exceeds a few hundred candidates; reach for them interactively, not
only in CI:

- `--max-targets N` — stop once N targets reach the fuzz phase (nonviable
  candidates are skipped and lower-ranked ones backfill), and `--max-attempts N`
  to also bound how many candidates are inspected.
- `--campaign-time SECONDS` — cap total sweep wall-clock (add `--min-target-time` to split the budget evenly instead of a hard cutoff).
- `--jobs N` — build and fuzz N candidates concurrently.

The default sweep — every discovered target, the full three-pass cascade, one
target at a time — is the wrong shape for a tree with tens of thousands of
candidates. The flags above compose into a bounded triage sweep:

```sh
bhf auto path/to/huge-tree \
  --max-targets 500 \
  --single-pass \
  --max-repair-rounds 3 \
  --jobs 2 \
  --campaign-time 3600
```

That run reuses a prior discovery (skipping the tree-sitter re-parse + re-rank),
stops once 500 targets have fuzzed, fuzzes each with the fuzz-driven pass
only (~3× throughput), gives up on un-buildable targets after 3 repair rounds,
builds+fuzzes 2 targets concurrently, and stops starting new targets after one
hour of wall-clock. The three bounds are orthogonal: `--max-targets` bounds
*how many* targets fuzz (with `--max-attempts`, how many are inspected),
`--campaign-time` bounds *how long* the whole
sweep runs, and `--jobs` bounds throughput against host RAM (peak ≈
the child allowance plus parent/index/compiler/report overhead).
Every bound is logged — the kept-vs-total target count and the campaign-time
cutoff both print — so a bounded run is never silently mistaken for full
coverage.

For a 10M+ SLOC tree, 8 GiB is a practical minimum only for a deliberately
serial run (`--jobs 1`, normally `--rss-limit-mb 1536`); 16 GiB is recommended
for whole-tree static analysis and build recovery. Under `auto`, each target's
in-memory and persisted coverage corpus shares the explicit `--max-corpus-mb`
budget (64 MiB by default), and its entry allowance is derived from that byte
budget and `--max-len`. `BHF_MAX_CORPUS_ENTRIES` can impose a stricter entry
count; standalone `bhf fuzz` retains the memory-derived
`BHF_MAX_CORPUS_BYTES` behavior. Captured target
diagnostics/event deltas use memory-aware defaults with explicit environment
overrides. Discovery still retains a compact
declaration/candidate index and final reports retain attempted-target metadata,
so use `--max-targets`, `--campaign-time`, and `--per-target-finding-count` to
bound high-cardinality sweeps. See the README's Resource Requirements for the
static-analysis ceiling and per-file safeguards.

The memory-aware defaults can all be replaced when a target needs more depth:

| Environment override | Controls |
|---|---|
| `--max-corpus-mb`, `BHF_MAX_CORPUS_ENTRIES` | Per-auto-target mutation and on-disk coverage-corpus retention |
| `BHF_MAX_CORPUS_BYTES` | Standalone `bhf fuzz` mutation-corpus bytes |
| `BHF_MAX_SOURCE_FILE_BYTES`, `BHF_MAX_FILE_BYTES` | Auto/discovery and static-analysis source-file admission |
| `BHF_MAX_SUBPROCESS_OUTPUT_BYTES`, `BHF_MAX_HARNESS_OUTPUT_BYTES` | Build-command and target-diagnostic capture per stream |
| `BHF_MAX_EVENT_DELTA_BYTES`, `BHF_MAX_RUNTRACE_PARSE_BYTES` | Dynamic runtrace data admitted per execution/log |
| `BHF_MAX_SINK_TRACKING_BYTES`, `BHF_MAX_SINK_SUBJECTS` | Cross-execution tainted-sink evidence retention |
| `BHF_MAX_EXTERNAL_TOOL_OUTPUT_BYTES` | External analyzer JSON/SARIF capture |

Values are bytes except `BHF_MAX_CORPUS_ENTRIES` and
`BHF_MAX_SINK_SUBJECTS`. Additional specialist overrides are named in the
warning emitted when their safeguard is reached. These are in-process retention
budgets, so a run can briefly exceed one budget because parsers, compiler
processes, reports, other workers, and allocator overhead remain live too. Use an
OS/cgroup limit when a strict hard boundary is required.

**Stop a target once it has enough findings.** `--per-target-finding-count N`
ends a target's cascade the instant it has produced N distinct findings, instead
of spending the whole `--per-target-time` budget collecting duplicates of the
same bug. `--per-target-finding-count 1` is the classic libFuzzer
stop-on-first-crash; a higher N keeps fuzzing for a few distinct bugs per target
before moving on. It composes with everything above — a split-mode target still
stops early on its finding count.

**Split a fixed budget evenly across targets.** Pair `--campaign-time` with
`--min-target-time` to switch from the outer-cap guillotine to an even split:
the campaign budget is divided across the attempted targets, each getting
`max(min, campaign / N)` of fuzz time, and only the top
`floor(campaign / per_target)` ranked targets are attempted (the rest logged
unfuzzed). E.g. `--campaign-time 600 --min-target-time 30` over 40 ranked
targets gives every target 30s (`600 / 40 = 15 < 30`, so the floor binds) and
attempts the top `floor(600 / 30) = 20`; with only 10 targets each would instead
get the even `600 / 10 = 60s`. Use it when you want a predictable per-target
floor rather than "best-ranked first until the clock runs out."

### Actionability in auto runs

Auto run reports include actionability counts by verdict and impact. In
attacking mode, candidate scheduling prefers real source targets and dangerous
sink evidence, but verdicts are still derived from collected finding evidence.
Generated stubs, fake resources, missing-environment injections, and mocks force
the verdict to `lab_only`; missing real resources without a substitution produce
`blocked`.

### Fuzz-confirmation

bhf both statically scans **and** fuzzes the same tree,
so a fuzz run can *confirm* a static finding. After the sweep, bhf joins each
static finding (`--static` / static-only, `F-STATIC-*` / `F-RO-*`) against the
run's runtime findings (fuzz crashes + oracle hits) by source site (file:line):

- **Match** → the static finding is upgraded in place to
  `confirmation: fuzz_confirmed`, its confidence boosted to `high`, and it is
  **clustered with the confirming crash** so the report renders ONE issue row
  (the crash as representative, the static finding a member with a unioned CWE)
  instead of two orphaned rows. A site reached only through a proven
  non-attacker-reachable entry is confirmed but capped to `lab_only`.
- **No match** → the static finding stays `confirmation: static`. It is **not**
  downgraded: the fuzzer not reaching a site does not prove the site unreachable,
  so silence never manufactures a false negative.

Every row in `findings.csv` and every SARIF result carries a `confirmation`
column/property with the provenance (`static` | `fuzz` | `runtime` |
`fuzz_confirmed`), and `run.json`'s summary reports a `fuzz_confirmed` count. A
`fuzz_confirmed` finding is not a maybe — it is a defect a fuzzer walked into at
the exact line the scanner flagged.

After the sweep each C/C++ harness is rebuilt with source coverage and its
corpus replayed, which writes the lines the campaign executed to
`harnesses/<id>/covered-lines.txt` and the covered and instrumented line
counts to `harnesses/<id>/coverage-summary.json`. Both count the project's
lines only, not bhf's: the generated `main.c`, its repairs and stubs, and the
C runtime's `bhf_*` headers are left out. The summary's `Coverage: N edges
(the most any one target reached)` is the largest edge count of one target,
not a total, since each target has its own edge map.

The same replay writes each harness's coverage report to
`results/coverage/<id>/`, about the files under the sweep's root only:

- `lcov.info` — the line and function records, for `genhtml`, an IDE or a CI
  coverage service;
- `html/index.html` — llvm-cov's report, each file with its line counts;
- `functions.txt` — llvm-cov's per-function table (regions, lines and branches
  covered), and `functions.json`, each function's file, line, calls over the
  corpus, and its instrumented and covered lines.

- `blockers.txt` and `blockers.json` — the comparisons the corpus reached and
  never passed: a line whose branch llvm-cov saw run one way and never the
  other, where the harness recorded a comparison (an integer compare against a
  constant, a `memcmp`, a `strcmp`). Each names the file, line and function,
  the operand the branch wants (hex; little-endian for an integer) and some of
  the values it got instead. These are the places a dictionary entry, a seed
  or a harness change would take the campaign further; the sweep says how
  many there are.

An Ada harness gets the same report from its edges, without the HTML and the
blockers. GNAT instruments with `-fsanitize-coverage=trace-pc` and no coverage
mapping, so the replay records the PC of each edge an input reaches
(`BHF_COV_PCS`), takes the binary's calls to the trace-pc callback as the
instrumented edges, and places both on Ada lines with `addr2line` (or
`llvm-symbolizer`) and the instrumented copies' line maps. `lcov.info` has the
lines and subprograms; `functions.txt` and `functions.json` list each
subprogram (`checks.classify` for GNAT's `checks__classify`) with its first
line and its covered and instrumented lines; `calls` is `null`, since an edge
says only whether it ran. The covered lines also go to the harness's
`covered-lines.txt`, as for C/C++. It needs `objdump` from binutils, which
GNAT installs with.

A function the table shows with no calls is one the campaign never reached.
The report needs `llvm-cov` and `llvm-profdata` (or their `-18` names), as the
replay does, and the blockers `llvm-symbolizer` to place each comparison; a part llvm-cov cannot render is left out, and
`harnesses/<id>/coverage-replay-diagnostic.txt` says why.

## Running a harness under another fuzzer

The generated native harnesses (C, C++, Rust, Ada) are self-contained: the
default binary reads one input per run and executes the target once — the
black-box contract an external fuzzer expects. To make that portability
discoverable and drivable, each C/C++/Rust/Ada harness dir
(`<work>/harnesses/<id>/`) also carries:

- a **`Mayhemfile`** — run `mayhem run .` from the harness dir. C/C++/Rust take
  the input as a file (`@@`, ASan-instrumented, `sanitizer: true`); Ada reads
  stdin (Mayhem's base-executable mode, the only mode it supports for Ada).
- a **`PORTABILITY.md`** — the exact build/run commands for Mayhem, libFuzzer,
  AFL++, and honggfuzz for that lane.

| Lane | Black-box (Mayhem base-exe / AFL file) | libFuzzer | AFL++ persistent |
|---|---|---|---|
| C / C++ | `make` → `./main <file>` | `make libfuzzer` → `./main_libfuzzer` | `make afl` → `./main_afl`, `make afl_cmplog` → `./main_afl_cmplog` (`-c`) |
| C / C++ (SymCC, `--symcc`) | `make symcc` → `SYMCC_INPUT_FILE=<file> SYMCC_OUTPUT_DIR=<dir> ./main_symcc <file>` writes the inputs SymCC solved into `<dir>` | — | — |
| COBOL / Fortran | `./main <file>` (built by default) | — | `make afl AUTO_EXTRA_LDFLAGS="$(cat lane-ldflags.txt)"` → `./main_afl` |
| Rust | `./main <file>` (built by default) | `./build-libfuzzer.sh` → `./main_libfuzzer` | `./build-afl.sh` → `./main_afl`, `./main_afl_cmplog` (`-c`) |
| Ada | `./main < input` (stdin) | — | `bhf auto --engine afl++` links `build/<id>/main_afl` (fork server, input on stdin, `BHF_CRASH_ON_FINDING=1`) |

The libFuzzer binaries use a generated `bhf_libfuzzer.c` shim that forwards
libFuzzer's `LLVMFuzzerTestOneInput` to bhf's `bhf_run_one`. A harness that
wraps the project's own `LLVMFuzzerTestOneInput` has no shim: `make libfuzzer`
links the project's sources directly. For Rust it is a
separate instrumented build (`build-libfuzzer.sh`), because modern libFuzzer
cannot consume bhf's default `trace-pc-guard` staticlib.

**Ada caveat:** a caught top-level Ada exception is a finding but does not crash
the process, so a crash-keying engine would miss it. Set
`BHF_CRASH_ON_FINDING=1` (the generated Ada Mayhemfile already does) to abort the
process with `SIGABRT` when a finding is reported.

Interpreted lanes (Python, JS/TS, Java, C#, Ruby, Lua, PHP, Perl) are driven
through bhf's own interpreter driver, not a single portable binary, so no
Mayhemfile is emitted for them.

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | At least one target built and ran |
| 1 | Candidates discovered, none built |
| 2 | No candidates discovered (empty tree, or a source path that does not exist), or a refused configuration or flag value |
| 3 | Harnesses built, but none ran: their sanitizer runtime does not start on this host (re-run with `--sanitizers none`) |

## Discovery

See [Target Ranking](target-ranking.md) for the scheduling objective, exact
language-specific weights, call-graph adjustment, worked comparison, testing,
and current limitations.

Walks the source tree with the same exclusions the `scan` subcommand uses
(`.git`, `target`, `build`, `bhf_work`, `harnesses`,
`generated_harnesses`, `node_modules`), and by default also skips code that is
not the project's own library: `bhf scan` and `bhf list targets` include it, so
`list targets` marks those rows `(bhf auto skips: ...)`. Skipped by default:

- a directory named (case-insensitively) `t`, `test`, `tests`, `testing`, `testsuite`, `test-suite`, `unittest`, `unittests`, `gtest`, `googletest`, `spec`, `specs`, `example`, `examples`, `sample`, `samples`, `demo`, `demos`, `benchmark`, `benchmarks`, `bench`, `benches`, `fuzz`, `fuzzing`, `fuzzer`, `fuzzers`, `ossfuzz`, `oss-fuzz`, `tool`, `tools`, `dev-tools`, `devtools`, `dev_tools`, `program`, `programs`, `bin`, `cli`, `app`, `apps`, `regress`, `research`, `experimental`, `experiments`, `playground`, `sandbox`, `perf`, `script`, `scripts`, `snippet`, `snippets`, `contrib`, `third_party`, `thirdparty`, `third-party`, `3rdparty`, `3rd_party`, `vendor`, `vendored`, `extern`, `external`, `deps`, `dependencies`, `subprojects`, `doc`, `docs`, `documentation`;
- any directory whose name contains `test` (`integration_tests`,
  `jsontestrunner`; `latest`, `fastest`, `greatest`, `contest`, `protest` and
  names containing `attest` are kept) or `fuzz` (`fuzz_targets`, `libfuzzer`);
- a source file whose name marks a test runner or tool (`test_foo.c`,
  `pngtest.c`, `runtest.c`, `foo_test.cc`, `ltests.c`).

`--include-dir <name>` keeps a directory the defaults skip (repeatable, e.g.
`--include-dir tools` for a project whose parser lives in `tools/`), and
`--exclude-dir <name>` skips another. When the defaults leave anything out,
`bhf auto` prints `bhf auto: skipped as non-library code by default: tests/ (3
files), tools/ (1 file), ...` after discovery.

Per-file dispatch by extension:

| Extension | Parser | Ranker |
|---|---|---|
| `.ads`, `.adb` | `ada_parser::reconcile::build_structural_ast` | `target_rank::rank_targets` |
| `.c` | `c_parser::parse_c_functions` | `target_rank::rank_c_targets` |
| `.h` | C or C++ parser, selected by header contents | matching C/C++ ranker |
| `.cpp`, `.cc`, `.cxx`, `.C`, `.hpp`, `.hh`, `.hxx` | `cpp_parser::parse_cpp_functions` | `target_rank::rank_cpp_targets` |
| `.rs` | `rust_parser::parse_rust_functions` | `target_rank::rank_rust_targets` |
| `.java` | `java_parser::parse_java_methods` | `target_rank::rank_java_targets` |
| `.py` | `python_parser::parse_python_functions` | `target_rank::rank_python_targets` |
| `.pl`, `.pm` | `perl_parser::parse_perl_subs` | `target_rank::rank_perl_targets` |
| `.go` (skips `_test.go`) | `go_parser::parse_go_functions` | `target_rank::rank_go_targets` |
| `.cob`, `.cbl`, `.cobol`, `.cble` | lane-specific `parse_cobol` | byte-buffer `LINKAGE` / `USING` eligibility |
| `.f`, `.for`, `.f77`, `.f90`, `.f95`, `.f03`, `.f08` | lane-specific `parse_fortran` | character-argument eligibility |
| `.cs` | lane-specific `parse_csharp` | public byte/string/stream input methods |
| `.js`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.mts`, `.cts` | lane-specific `parse_js` | exported functions/public exported-class methods (`.d.ts` skipped) |
| `.rb` | lane-specific `parse_ruby` | callable input methods |
| `.lua` | lane-specific `parse_lua` | callable input functions |
| `.php` | lane-specific `parse_php` | functions/public methods with an input channel |

Candidates with unsupported parameter types are dropped before the attempt
loop runs, so the report does not carry pre-doomed entries.

C and C++ harnesses are Makefile-based. Auto uses `clang` / `clang++` for the
default coverage-guided sanitizer build unless `CC` / `CXX` are set. See
[C and C++ Fuzzing](../c-cpp/) for supported C++ parameter shapes and
limitations. Nearby `compile_commands.json` files are used when present to
carry project include paths, defines, and standard flags into generated
Makefiles. Rust targets instead build a `cargo` staticlib (sancov + ASan)
linked into the C fork-server driver, and Java targets compile with `javac` /
`maven` / `gradle` under bhf's own JVM bytecode coverage agent; both are
built before the attempt loop and bypass the C/Ada repair path. Python and Perl
targets "build" by interpreter check (`py_compile` + import smoke-test;
`perl -c` + `require`) and run under a persistent CPython / `perl -d:BhfCov`
process over the framed fork-server protocol; Go targets compile with `go build`
(against the target package via a module `replace`) to a native framed
fork-server binary. COBOL, Fortran, C#, JavaScript/TypeScript, Ruby, Lua, and PHP
likewise use their lane-specific pre-build/interpreter paths described above.
All of these lanes bypass the Ada/C/C++ repair path.

A Lua colon method (`function Reader:average(data)`) is called on an instance
of its class: the table that defines it (the returned module, its field named
for the class, or that global), built by its `new`, `create` or `init`
constructor called with no arguments, else an empty table with the class as
its metatable. The Lua driver counts how many of its first 1000 inputs end in a
nil-value error; at 95% or more (over at least 20 inputs) the target's
`run.json` entry carries `stub_executed` and its `run.md` row says
`stub executed:`, since such a run exercised the error path, not the target.
The Lua driver's coverage hook gets line events only while a target chunk
(under the target's root, not the driver or the harness) runs, and a function
that runs 256 line events with no new edge stops getting them until a count
hook resumes them 100000 instructions later, so a long loop or a deep recursion
costs a few times a plain run. A Lua finding is located at the target frame the
driver records when the error is raised (a stack overflow at the recursing
line, not in the driver).

## Repair Synthesis

Build errors are matched against compiler diagnostics by the `build_classifier`
crate and dispatched to language-specific repair planners. Repair synthesis
applies to the C/C++ and Ada lanes only. Every other lane is prebuilt or
interpreter-checked before the attempt loop and never enters the
diagnostics-driven repair path.

C / C++ (`crates/c_stub_gen`):

| Error class | Repair |
|---|---|
| `MissingHeader{path}` | Synthesised placeholder header under `<harness>/repairs/auto_includes/<path>`, added to `-I` |
| `MissingType{name}` | `typedef void *T;` appended to `<harness>/repairs/auto_types.h` |
| `UndefinedSymbol{name}` | Looked up in the declaration index. Match → declared stub. No match → blind `void(void)` stub. Appended to `<harness>/repairs/auto_stubs.c`. A name of a compiler or sanitizer runtime (`__asan_*`, `__llvm_profile_*`, `__cxa_*`, `__stack_chk_fail`) is never stubbed, nor, on a link against the Windows C runtime, a name of that runtime or MinGW's (`_dup`, `__mingw_fprintf`, `__main`, `__chkstk`): only the tree's own definition of it is linked, otherwise the build fails with the linker's error, since such a reference means a runtime library is missing or objects of two toolchains were mixed. Off Windows, `_write` and `_read` (a newlib port's syscall hooks) are ordinary symbols |
| `MissingSharedLib{name}` | Not auto-repaired. Flows to `needed_for_build.missing_libraries` and the `missing-deps` manifest; the target is marked `unrecoverable_link` |
| Standard-library names used without `std::` (`unknown type name 'string'`, `no template named 'map'`, g++'s `'map' does not name a type`) | The std prelude `bhf build` writes, `<harness>/std_prelude.h`, force-included into every translation unit; see below |
| `ConfigGuardError{file,line}` | A `#error` a build-config guard reached (libssh's `#error "no strtoull function found"`). The conditional owning the `#error` is read and the macro it tests is `#define`d into `auto_defines.h`, with the value the guard requires (`#if (DEPTH != 8)` → `8`, a plain feature test → `1`). An undecidable guard — a comparison, a compound condition, or an error that fires *because* a macro is defined — is refused rather than guessed |

Ada (`crates/stub_gen`):

| GNAT diagnostic | Repair |
|---|---|
| `file ".+\.ads" not found` | Empty `PackageSpec` under `<harness>/repairs/auto_ada/` |
| `"X" is undefined` | `Identifier` stub |
| `"X.Y" is not visible` | `Visibility` stub |
| `missing body for unit "X"` | Empty `PackageBody` |
| `cannot find "X.gpr"` | Not auto-repaired; flows to `needed_for_build.missing_gpr_imports` |

A pre-standard C++ header often writes `string`, `map<string, int>` or
`list<T>` without `std::`, relying on a `using namespace std;` that the
project's own sources put before including it; the generated harness has
none. When a C++ harness build fails on such names, before the other retries
(the dialect ladder, the other compiler) the build writes the prelude
`bhf build` writes, `<harness>/std_prelude.h` (each name's standard header
and a `using std::` declaration for it; an existing file only gains the
lines it lacks), force-includes it into every translation unit of the
harness through `<harness>/repairs/auto_std_prelude.h`, and builds again.
clang++ stops after 20 errors, so a long header can hide names behind the
first ones: while a rebuild reports names the prelude lacks, they are added
and the harness is rebuilt. Each pass adds at least one standard name, so
this ends. The build prints one note naming the types (``bhf auto: <id>: the
sources use string, map, ... without `std::` ...``), and a later round that
reports more names adds them to the same file. The rules are `bhf build`'s
(see [Custom harnesses](custom-harness.md#headers-that-rely-on-using-namespace-std)):
diagnostics in C code get no prelude, and a stream object alone (`cerr`)
keeps the stream-header repair. A name the scanned tree declares as a C++
type of its own is never declared from `std`: a class, struct, enum or
typedef in a C++ source or header, or in a `.h` header that C++ code
includes. Where the source writes the name as a template (`list<string>`,
`no template named 'list'`), only a class template of the tree's own counts.
A C struct of the same name, in a `.c` source or in a header only C sources
include, never does. The repair is recorded among the target's repairs as
`std_prelude` (`path`, `names`, `headers`) in `run.json`, and
`targets[].real_headers_included` and `run.md` list it; every lane's build
and the target's capsule force-include it too. If the build still fails on
standard names used without `std::`, whether the prelude declares them or
not, their `missing-deps` entries say so and name the prelude (or, when the
build wrote none, the declarations to force-include), and they are not
listed as harness/codegen errors.

The declaration index is built once per `auto` run before the attempt loop
and held in memory across all targets.

## Three-Pass Cascade

Each built harness runs three passes back-to-back. The shim's behaviour for
fake resources is set per pass via `BHF_RUNTRACE_MODE`:

- `empty` — fake `read()` returns EOF on first call. Catches "external world
  absent" code paths.
- `rng` — each fake resource serves bytes from its own xorshift RNG, seeded
  by `(harness_id, resource_name, fuzz_seed)`. Catches length-field and
  type-confusion bugs in code that parses external bytes.
- `fuzz_driven` — fake reads pull from a shared memfd populated each fuzz
  iteration. The engine's coverage feedback learns to route interesting
  bytes to whichever fake resource gates a code path.

By default all three passes run because they exercise orthogonal paths. An
explicit `--passes`/`--single-pass`, the shared deadline, or
`--per-target-finding-count` can stop or skip remaining passes.

The runtime-virtualisation shim that backs these passes is Linux-only. It is
armed for native C/C++/Ada/Rust/Go/COBOL/Fortran harnesses. It is off for the
interpreted and managed lanes (Python, Perl, Ruby, Lua, PHP, Java, C#,
JavaScript/TypeScript), where the runtime's own startup activity would create
false positives, and for cross-compiled or emulated (qemu/wine) targets. Those
configurations do not receive the BHF-405/BHF-304/BHF-417/BHF-305 runtrace
oracles. Each fuzzed target's `behavioral_oracles` in `run.json` (and its
`[behavioral oracles: …]` note in `run.md`) says `on`, `driver` (the Java and
JavaScript/TypeScript drivers' own sink checks) or `off`, with the reason.

## Outputs

```
<work>/
├── auto/
│   ├── run.md                                  # human report
│   ├── run.json                                # machine report
│   ├── seeds.json                              # every seed the run used, with provenance
│   ├── missing-deps.json                       # missing-dependency manifest (#418)
│   ├── missing-deps.txt                        # same, human-readable
│   ├── summary.txt                             # the summary the run printed
│   └── blockers.json                           # what stopped each unfuzzed target, grouped (when one was)
├── harnesses/<harness-id>/
│       ├── main.c | main.cpp | main.adb
│       ├── Makefile | H_<id>.gpr
│       ├── repairs/
│       │   ├── auto_stubs.c
│       │   ├── auto_types.h
│       │   ├── auto_includes/…
│       │   └── auto_ada/…
│       ├── result.json                         # per-target resume marker
│       └── runtrace.jsonl                      # per-target shim events
├── corpus/<harness-id>/queue/                  # persisted coverage-minimal corpus (#401)
├── corpus/<harness-id>/lineage.jsonl           # what each queue entry was mutated from
├── fuzz_runs/<harness-id>-latest.json
├── discovery-cache.json                        # the discovery index a re-run reuses
└── results/
    ├── INDEX.md                                # start here
    ├── findings.json                           # bhf.findings.v1
    ├── findings.csv
    ├── findings.sarif
    ├── manifest.json                           # what each file holds, with digests
    ├── attestation.json
    ├── coverage/<harness-id>/                  # lcov.info, html/, functions.*, blockers.* (when the coverage replay ran)
    └── findings/<finding-id>/                  # finding.json, testcase.bin, replay.py, ...
```

### `run.md`

Top section summarises discovery, build outcomes, and finding counts. If any
target fuzzed STUB-ONLY, a loud `## ⚠ STUB-ONLY (FALSE CLEAN)` block leads,
naming each false-clean target and its blind-stub fraction (see
[`stub_execution`](#stub_execution-false-clean-guard)). A `## Targets` section
follows with one line per target — every target, not a truncated top-N. Each
built-and-fuzzed line shows the outcome label and a per-pass breakdown
(`empty=4123execs/1000exec_s/0f rng=… fuzz_driven=…`) plus the total
`cov=Nedges`; a `[!]` note marks a target whose fuzzed parameters are not an
attacker-controlled input channel. A target whose executions ran past
`--timeout` shows `hangs=C/K`: C of its K killed executions hung again when
re-run, each a BHF-230 finding or a later hit of one. The top section's
`Hangs:` line totals them across targets: killed, hung again, finished when
re-run, and not re-run (the pass had re-run four, or lacked the time). In
`run.json` each pass carries the same counts as `hangs` (`timeout_ms`,
`observed`, `confirmed`, `cleared`, `not_rerun`). The `Upstream delta` section is the
prosthetic ledger described below.

### `blockers.json`

A sweep that leaves targets unfuzzed writes one row per language, outcome and
cause, with the number of targets that share it, most common first. The cause
is the diagnostic's first informative line with its per-instance noise
removed: a leading `file:line:col:`, other free-standing numbers (they become
`N`) and host paths (`PATH`). The identifier it names stays, in double quotes
(`unknown type name "pcap_t"`), as does a dialect's version (`Python 2`,
`Ada 95`). So one missing type that blocks twenty targets is one row of
twenty, and two missing types are two rows.

### `run.json`

The machine report. Each `built_and_fuzzed` target carries, under
`targets[].outcome`, throughput and budget fields for libFuzzer
`average_exec_per_sec` / AFL `execs_per_sec` parity (#405):

- `executions_per_sec` — target-level throughput (time-weighted Σexecs / Σelapsed
  across passes, not a mean of per-pass rates).
- `per_pass_budget_secs` / `total_wall_budget_secs` — the per-pass and effective
  total fuzz wall budgets (#402).
- `passes[]` — one entry per pass, each with `executions`, `coverage_edges`,
  `coverage_instrumentation` (the instrumentation that fed the edge map, read
  from the harness binary: `sancov-trace-pc-guard` for clang's guard section,
  `sancov-trace-pc` when GCC's debug information records a translation unit
  compiled with `-fsanitize-coverage=trace-pc`, `go-cover`, or `edge-bitmap`
  when the binary shows neither, as for a build without coverage),
  `elapsed_secs` (measured, not budget), `executions_per_sec`, and `findings`.

The top-level `summary` carries `fuzz_confirmed` — how many static findings a
fuzz/oracle hit confirmed at the same source site (omitted when zero). See
[Fuzz-confirmation](#fuzz-confirmation).

The top-level `seeds` block records where the run's seeds came from:
`source` (`user`, `mined` or `none`), `count`, `mining` (`ran`,
`skipped_user_seeds` or `disabled`) and `manifest`, the path of the per-seed
list (`auto/seeds.json`, see [Seeds](#seeds)).

### `stub_execution` (false-clean guard)

Each `built_and_fuzzed` target in `run.json` carries a `targets[].stub_execution`
object (omitted for non-fuzzed outcomes) summarising
how much of the harness's external symbol surface was real vs stubbed:
`blind_stubbed_symbols`, `declared_stubbed_symbols`, `real_linked_symbols`,
`resolved_called_symbols`, `blind_stub_fraction`, and the boolean `stub_only`.
`stub_only` is set when **≥ 90 % of the external symbols the harness called were
satisfied by blind stubs and no real dependency source was linked** — i.e. the
run fuzzed only invented empty function bodies, never the real library. Such a
target is a **FALSE CLEAN**: a 0-finding result over millions of executions does
*not* mean the library is safe (the only other tell is harness-only coverage).
`run.md`, the terminal summary, and the per-target outcome label
(`built+fuzzed (STUB-ONLY)`) all flag it loudly, and the summary counts it under
`summary.fuzzed_stub_only`. Supply the missing dependency sources (see
[`missing-deps`](#missing-deps)) and re-run to fuzz the real code.

### `needed_for_build`

Aggregates every prosthetic the sweep applied plus everything it could not
fix. One entry per resource, with a `referenced_by_targets` array and a
`count`. Four layers:

| Layer | Source |
|---|---|
| A — build-time | Synthesised headers, declared/blind stubs, typedef placeholders, Ada package stubs |
| B — link-time, not auto-repaired | `-l<name>` misses, missing `.gpr` imports, glibc version mismatches |
| C — runtime, observed during fuzzing | env vars, missing files, missing devices, network endpoints, `dlopen` / `gethostbyname` failures |
| D — unrecoverable | Build-time repairs we tried and could not synthesise (e.g., struct-by-value return without a declaration) |

### `missing-deps`

A dependency checkpoint is created before project build probing or target discovery,
refreshed immediately after an opted-in build probe, then atomically replaced after
every completed target (including parallel jobs). The JSON carries
`complete` and `completed_targets`, so an operator can distinguish a final list
from the last valid checkpoint left by an interrupt or parent-process OOM. The
last terminal line always points at the human file with blocking/substituted
counts.

The text report puts compatible compilers, target runtimes/emulators, generated
source/codegen tools, unfetched Git submodules, and absent declared Alire source
first. Rows include a `declared`, `observed`, or `inferred` basis plus evidence.
BHF reports exact path/URL/version/output/tool data when project metadata or
diagnostics provide it; it does not guess a proprietary vendor, version, ABI, or
semantics from an otherwise unidentified missing type.

A `failed_build` is never opaque. Every unresolved final diagnostic — missing
header, type, symbol, build-config macro, malformed/codegen declarator, or any
unclassified error — is recorded in `missing-deps.json` / `missing-deps.txt` as a
still-blocking entry with an acquisition hint, and each failed target is
guaranteed at least one entry (#418). A missing configure/cmake-generated header
(e.g. c-ares' `ares_build.h`) is detected by a sibling `.in` / `.dist` /
`.cmake` / `.cmake.in` template and gets a configure-step remediation (run the
project's configure step, or `--probe-build`) instead of a dead-end apt-file
hint. `--deps-only` writes this manifest without paying for the fuzz phase;
`--install-deps` fetches the still-blocking entries.

A compile error the compiler reports in a file of the project's own tree, such
as an undeclared identifier in `src/bad.c`, is a `source_error` entry named by
the file, line and message (`bad.c:3: use of undeclared identifier 'x'`). It is
counted apart from the external dependencies ("1 compile error in the
project's own source"), and `bug-report.md` files the target as a
`[failed-build]`, not a bhf `[codegen-bug]`. A lookup error in the generated
harness driver or its `repairs/` stays a codegen defect. The manifest says
"the tree built against its own sources" only when no target failed to build.

### Per-Finding Replay

Each finding's `finding.json` records the pass it was found in and whether
the runtrace shim was armed (`runtime_mode.pass`, `runtime_mode.shim_armed`),
and the environment variables the run injected (`runtime_mode.env_injected`).
`bhf replay --finding <F>` reuses that pass and environment. A fake resource
in the `rng` pass serves bytes seeded from its own name, so the pass and the
environment reproduce what it served.

## Re-Runs

`bhf auto <same path>` reuses any per-target `repairs/` files surviving
from a prior run, so cumulative repairs are not redone. Discovery caching is on
by default: an unchanged source/filter fingerprint reuses
`<work>/discovery-cache.json`; a mismatch rebuilds the index, and
`--fresh-discovery` forces that rebuild. Use `bhf clean --all <work>` to
wipe state.

A work directory belongs to one source tree. When `bhf auto` is pointed at a
different tree with a work directory an earlier run used (the default
`./bhf_work/`, say), it moves everything that run left, findings and corpus
included, to `<work>/archived/<UTC time>-<tree name>/` and prints
`bhf auto: note: <work> held a run over <other tree>; moved it to ...` before
it starts, so `results/` and the console report only the current tree.
Nothing is deleted, and a run over the same tree keeps its findings.

The coverage-guided corpus is persisted to `corpus/<harness-id>/queue/`
(content-hash-named, seeds included) at the end of each run (#401), so it
survives across passes and runs and stays replayable for coverage measurement
and `corpus minimize`. The queue and the active mutation pool share the
`--max-corpus-mb` retention ceiling; finding testcases are stored separately and
are never evicted by it. Every pass after the first reseeds from a bounded subset
of this queue, so deep code reached once stays reachable instead of each pass
restarting from the tiny built-in seeds.

### Seeds

Each target's corpus starts from a few built-in inputs plus the run's seeds:
the `--seed-file`/`--seed-dir` files when any are given, otherwise files mined
from the tree's own test data (regular files directly inside `test/`, `tests/`,
`examples/`, `samples/`, … and inside `data/`, `testdata/`, `fixtures/`,
`corpus/`, … directories below them). Mining skips source and prose files and
build/IDE artifacts (`.vcxproj`, `.sln`, `.filters`, `.user`, `.suo`, `.props`,
`.pdb`, `.dll`, `.lib`, `.obj`, `.ilk`, `.exp`, …), files over 256 KiB, and
stops at 64 files. Turn it off with `--no-seed-mining` or `seed-mining = false`.
An explicit `--seed-file`/`--seed-dir` (or config `seed-file`/`seed-dir`)
turns it off too, even when it loads no seed (a missing file, an empty dir):
the run says so, and `seeds.json` records `skipped_user_seeds` with a
`reason`.

Seeds reach the engine byte for byte, as do the corpus entries a later pass or
the AFL++ stage reseeds from `corpus/<harness-id>/queue/`. `auto/seeds.json`
lists every seed the run used: its `path`, `source` (`user` or `mined`), file
`size`, `bytes_used`, and the `sha256` of the bytes used (when the seed adds
coverage it is kept as `corpus/<harness-id>/queue/<sha256>.bin`, and a crashing
seed becomes a finding's testcase), plus whether mining `ran`, was
`skipped_user_seeds`, or was `disabled`. `run.json` carries the same summary
under `seeds`, and `-v` prints the list. A run that stops before it resolves
seeds (one that finds no fuzzable target, for example) removes a list an
earlier run left in the work dir, and its `run.json` has no `seeds` block.

A seed is a sample of the target's input format, but a C/C++ harness decodes
its fixed-width scalar parameters from the first input bytes and gives its
buffer the bytes after them (see [C and C++](c-cpp.md#decoding-layout)), so a
seed given as is starts in the scalars. When a target's `arg-layout.json`
gives K such bytes before the buffer (every parameter before it of a fixed
width, and 4 for the length of each other buffer's slice before it, which a
zero leaves empty), each seed is also given behind K zero bytes, so the
buffer starts with the seed; the seed itself is still given as is.
`auto/seeds.json` lists these under `layout_variants`, one entry per target
with its `harness_id`, `layout_prefix` (K) and the `sha256` of each prefixed
seed. `bhf fuzz` does the same for its `--seed-file` and `--seed-input`
seeds, once per campaign however many workers it runs; the seeds it is
handed otherwise (its built-in seeds, a shared queue's inputs) are not
prefixed.

### Seed lineage

The built-in engine records what each input it keeps was mutated from, so a
finding can name the seed it grew out of. `corpus/<harness-id>/lineage.jsonl`
sits beside the queue, one JSON line per entry, keyed by the `sha256` of the
entry's bytes: `parent`, the entry its mutation started from (and `donor`,
the entry a splice took its second part from), or for a root its `origin`:
`seed` (with `source` and `path` when `auto/seeds.json` or the `bhf fuzz`
command line names it, and `layout_prefix` and `seed_sha256` for a seed given
behind its layout prefix), `corpus` (a reseeded queue entry with no line of
its own: saved before lineage was kept, or dropped by the record cap below;
an entry by its bytes, whatever its file is named, such as a crash input
named by its signature or a file the multi-worker merge renamed
`worker-N-<name>`) or `generated` (no seed: the empty or built-in start inputs, or an input a
structured or `--grammar` generator or the random-byte fallback built). An
input the run was handed as a seed is a root again, whatever made it before.
A later pass or `--resume` that reseeds from the queue continues the chains
it finds there. Each worker of a multi-worker `bhf fuzz` starts from the
campaign's `lineage.jsonl` and `auto/seeds.json`; the shared queue's entries
and the files the campaign writes for its workers (a seed's layout-prefixed
variant, a programmatic seed) are bhf's copies, not seeds given to the
worker, so a worker's finding names the seed they came from, never the copy.
The campaign merges each worker's lines into its own.

The first line recorded for an input's bytes stays: the same bytes reached
again, by another mutation, pass or worker, keep it. The chain a finding
reports is therefore one real derivation of those bytes, not necessarily
the one this run took. Every writer (a pass, and the merge of a multi-worker
campaign) reads the whole file, up to 524288 lines, and writes back at most
twice the queue's entry limit (`BHF_MAX_CORPUS_ENTRIES` when set) or twice
the files the queue holds, whichever is more, and never more than 524288
lines. The merge takes the union of the workers' queues, so the shared
queue can hold more files than the limit, and each of them keeps its line.
First come the lines its pool's entries need (for the merge, the shared
queue's), they and their ancestors, then, for a pass over the cap, those
its queue's entries need, then the rest in sha256 order. An entry whose line was dropped is reported as having no lineage
record, saved before lineage was kept or dropped by the record cap.

When a finding is saved, its input's chain is followed back to the root
through each entry's `parent` (a splice's donor is named, not followed) and
written into `finding.json` as `lineage`: `origin` (`mined_seed`,
`user_seed`, `seed`, `corpus`, `generated` or `unknown`), `root_sha256` (a
seed's own, as `auto/seeds.json` lists it), `root_path`, `layout_prefix`,
`depth` (mutation generations from the root; `0` when the input is the root
itself), `parent_sha256`, `donor_sha256` and, when the lineage stops short
of a seed or is unknown, `reason`. The lineage is `unknown`, with a reason,
when the chain names an entry with no record (a corpus saved before lineage
was kept, or one the record cap dropped), loops, or runs past 100000
generations, and for a crash AFL++ found, through `bhf fuzz --engine afl++`
or `bhf binary-fuzz --engine afl-qemu`: AFL++ schedules its own queue, so
bhf does not see what that input was mutated from (the AFL++ crash file name
is in the reason). bhf does not guess. A harness run one input per process
(a `-fsanitize=fuzzer` binary) still gets its lineage: bhf's own engine
picks every input it runs. The lineage is of `testcase.bin`, the input the
fuzzer saved; minimization does not change it.

Lanes that replay inputs bhf already knows record their lineage too. The
corpus replays (the MSan and TSan replays, the memory profile and the
`--differential` post-pass) look up the queue entry they ran in
`lineage.jsonl`, as a pass does; an entry with no line there is a `corpus`
root. An MSan or TSan finding's lineage is that of the queue entry that
first showed the site, which its oracle evidence names by `input_sha256`
(left out, with the reason in the lineage, when the entry could not be read
back), and `bhf explain` prints that lineage under the entry's sha256. An
MSan finding also saves that entry as its `testcase.bin`. The capability profile folds what the whole corpus
reached into one finding, and saves as its `testcase.bin` the queue entry
that reached the most of the finding's operands (named in
`capability.testcase_operands`), so its lineage is that entry's; with no
such entry it is `unknown` and the reason says so. `bhf differential` and the builtin engine of `bhf binary-fuzz` run the
operator's inputs as they are: `user_seed`, depth `0`, with the file's path
(`generated` for the empty input `bhf binary-fuzz` runs when it is given no
seed). A blind mutation of one in `bhf binary-fuzz` is a generation below it:
depth `1`, `parent_sha256` the seed's. Findings saved before lineage was kept, and those of lanes that
keep none (the target-transport and protocol-session lanes, `bhf
relational`, the JVM sink oracle and the campaign-wide collector view, which
observe a whole run rather than one input, and extensions), have no
`lineage`.

A work directory written by an earlier release can hold corpus entries in
which every byte that was not valid UTF-8 was replaced by `EF BF BD`. In a work
dir from an earlier release (one migrated from the 0.2.x layout, or one with
state an earlier `bhf auto` left, `auto/run.json` or `auto/work-state.json`,
and no `auto/legacy-corpus.json`), the first `bhf auto` run moves `corpus/` to
`corpus-legacy/` (kept, not reseeded) and records that in
`auto/legacy-corpus.json`; pass `--reuse-legacy-corpus` to keep reseeding it.
Every run writes that record before anything else, so a new work dir is
recorded as `fresh` and its corpus is never set aside. A plan-only run
(`--dry-run`, `--list-targets`) leaves an earlier release's corpus to the
first run that fuzzes. `results/INDEX.md`, `bhf report` and the end of each
run warn when a work dir from an earlier release holds testcases or corpus
entries with several `EF BF BD` sequences.
See [Upgrading a 0.2.x work dir](https://github.com/Tarmo-Technologies/bhf/blob/main/docs/finding-report-fields.md#upgrading-a-02x-work-dir).

## Limitations

- **Targets bhf can't drive are skipped, not errors.** A candidate whose input
  type has no byte-buffer decoder (an opaque nested array, an in-crate
  trait-impl method, a type needing an offline-unavailable external SDK), whose
  generated harness does not compile, or whose own build fails is logged and
  skipped while the sweep continues. Run with `--debug` to capture these in
  `<work>/auto/bug-report.json` — `issue_count` plus a per-issue `category`
  (`unsupported-type`, `codegen-defect`, `failed-build`, `target-not-reached`,
  `unsafe-build-path`, …). An `unsafe-build-path` row (outcome
  `unsafe_build_path` in `run.json`) is a target refused because a source path,
  include dir or compile flag holds a character no quoting makes safe in a
  build recipe (`$`, `#`, a backtick, a shell operator): an environment problem,
  fixed by renaming or moving the path, not a bhf gap. A JavaScript or
  TypeScript target whose lane's toolchain is not installed (no `node`, no
  esbuild) has the outcome `missing_toolchain` (`summary.missing_toolchain`,
  terminal label "skipped: toolchain not installed"): install the tool the
  reason names; it is not filed in the bug report and `--force` cannot help.
  A Rust or C# target run without `--run-untrusted` (and a Java one whose
  Maven or Gradle build needs it and whose bare `javac` fallback fails) has
  the outcome `consent_required` (`summary.consent_required`, terminal label
  "needs --run-untrusted"): its build runs project-controlled code, so the
  remedy is that consent, with the dependencies staged and the network
  isolated; `--force` cannot help, and `--resume` tries it again.
  A private Rust target `--rust-private` admits but cannot set up (a parameter
  or a resource the in-crate lane has no recipe for) has the outcome
  `unsupported_setup` (`summary.unsupported_setup`, terminal label "skipped:
  the in-crate Rust lane cannot set it up"); its reason names what is missing.
  A C/C++ target whose harness built but whose sanitizer runtime cannot start
  on the host has the outcome `sanitizer_runtime_unavailable`
  (`summary.sanitizer_runtime_unavailable`; see [Sanitizers](sanitizers.md)),
  also an environment problem that is not filed in the bug report.
  A non-zero `issue_count` is **informational**: it counts candidates bhf could
  not fully drive, not a run failure. `--debug` also sets `RUST_BACKTRACE` and
  keeps going past a file that would otherwise crash bhf itself, enriching the
  report so the bug can be fixed offline.
- **Stub soundness.** A blind `void log_warn(void)` stub compiles but the
  call site may pass arguments the stub ignores. Fine for fuzzing, not for
  verification. When *every* symbol the harness calls is blind-stubbed the run
  exercises only stubs — `run.json` flags this as `stub_execution.stub_only`
  (see above) so it is never mistaken for a real fuzz of the library.
- **Static linking.** LD_PRELOAD does not apply to static binaries. The
  build-time sweep still runs; the runtime audit falls back to a strace-style
  audit (no faking).
- **Cross-arch.** A whole sweep builds for another architecture with
  `--target-triple` and runs under `--runner` (see
  [Whole-Sweep Cross Targets](cross-compilation.md#whole-sweep-cross-targets)),
  coverage-guided with the compiler's SanitizerCoverage. ASan is not armed,
  because its shadow memory does not survive qemu-user, so hard faults are
  the crashes, and the runtrace shim and its behavioural oracles do not run
  under the emulator (see
  [Cross-compilation scope and oracle limitations](cross-compilation.md#cross-compilation-scope-and-oracle-limitations)).
- **Multi-threaded targets.** The shim is thread-safe, but fake-data RNGs
  are single-state per resource — two threads reading the same fake fd race
  for bytes.
- **Runtime virtualisation by lane.** The LD_PRELOAD behavioral/taint shim is
  armed for native Ada/C/C++/Rust/Go/COBOL/Fortran harnesses. It is not armed
  for the Python, Perl, Ruby, Lua, PHP, Java, C# or JavaScript/TypeScript lanes,
  or for cross/emulated targets. Those configurations retain
  their documented fuzz coverage and crash/exception oracles;
  BHF-405/BHF-304/BHF-417/BHF-305 runtrace findings are the unavailable layer.
- **C++ API lifecycle.** C++ harnesses cover both direct-call and
  lifecycle-sequence shapes but remain partly heuristic. Template
  metaprogramming and user-defined literals, abstract receivers that require
  non-default constructors, and operator-overload / `shared_ptr` receivers are
  still partial and usually need a wrapper or more manual flags.
- **Go coverage fallback.** Go normally gets real block feedback from
  `go build -cover -covermode=atomic`; each input's executed-block set is folded
  into the shared edge map. If module-wide `-coverpkg` fails, the lane retries the
  exact selected package before falling back safely to black-box mode instead of
  discarding the target or inventing coverage.
- **Expert-only setup remains possible.** Private Rust targets that require an
  in-package harness, complex generated/platform build graphs, framework hosts,
  coherent scientific array/dimension synthesis, and longer state/resource
  protocols can still require a manual wrapper. See the
  [expert-parity audit](./harness-parity-audit.md) for measured residuals.

See [Runtime Virtualisation](../runtime-virtualisation/) for the shim's
intercept list, env-var contract, and replay envelope.
