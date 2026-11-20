<!-- SPDX-License-Identifier: Apache-2.0 -->
# Docker validation — 32-project sixteen-language sweep (2026-09-24)

This record validates the production container (`Dockerfile`) end to end: one
image that can **build, harness, and fuzz** all sixteen of bhf's languages,
tested against a reproducible corpus of **two small, real, SHA-pinned projects
per language (32 total)**. For how to build and run the image, see the
[Docker guide](../site/docker.md).

## Environment

| | |
|---|---|
| Host | Linux 6.8, x86_64, 6 vCPU, 13.6 GiB RAM, cgroup v2 |
| Docker | 29.1.3, overlay2, BuildKit |
| Base image | `ubuntu:24.04` (digest-pinned) |
| Image size | 3.62 GB (1.25 GB as `docker save \| gzip`); fits a single-layer DVD-5 |
| bhf | 0.2.32 (built from source in the builder stage) |

## Method

- **Corpus:** `docker/sweep-manifest.tsv`, 2 projects × 16 languages, each
  pinned to a full commit SHA, each a small single-purpose parser/decoder with
  a public, auto-harnessable entry point.
- **Runner:** `docker/bhf-sweep.sh` runs `bhf auto` per project with real build
  recovery (`--unsafe-search-and-run-build-commands`) and `--force`, under a
  bounded budget: 10 s/target, 2 targets/project, 120 s campaign, `--jobs 1`.
- **Hardening posture under test:** the sweep ran with `--cap-drop=ALL
  --cap-add=SYS_PTRACE --security-opt no-new-privileges --shm-size=2g
  --memory=12g`, as the unprivileged `fuzzer` user: the production posture.
- **PASS** = bhf built ≥1 harness, instrumented it, and executed the fuzzer
  against real library code (executions > 0).

## Result

**16 / 16 language lanes build, harness, and fuzz inside the hardened container;
32 / 32 projects PASS.**

| Language | Project | Result | Targets fuzzed | Executions | Edges | Findings |
|---|---|:--:|--:|--:|--:|--:|
| ada | json-ada | PASS | 2 | 190058 | 357 | 0 |
| ada | ada-yaml | PASS | 2 | 226825 | 1192 | 0 |
| c | cjson | PASS | 2 | 8097 | 283 | 0 |
| c | inih | PASS | 2 | 20094 | 96 | 0 |
| cpp | pugixml | PASS | 2 | 6382 | 446 | 4 |
| cpp | cpp-httplib | PASS | 1 | 3584 | 8 | 0 |
| rust | json-rust | PASS | 2 | 167602 | 692 | 0 |
| rust | rust-csv | PASS | 2 | 7590 | 148 | 0 |
| java | json-java | PASS | 2 | 329675 | 49 | 0 |
| java | minimal-json | PASS | 2 | 210155 | 405 | 0 |
| python | toml | PASS | 2 | 5266 | 746 | 2 |
| python | html5lib | PASS | 1 | 3859 | 12 | 0 |
| perl | json-pp | PASS | 2 | 194303 | 131 | 0 |
| perl | uri | PASS | 2 | 166602 | 175 | 0 |
| go | fastjson | PASS | 2 | 3197 | 81 | 2 |
| go | jsonparser | PASS | 2 | 35556 | 18 | 0 |
| fortran | json-fortran | PASS | 2 | 10162 | 968 | 0 |
| fortran | csv-fortran | PASS | 1 | 5667 | 1210 | 0 |
| cobol | carddemo | PASS | 1 | 328 | 80 | 0 |
| cobol | cobolcraft | PASS | 2 | 649 | 88 | 0 |
| csharp | sprache | PASS | 2 | 319543 | 33 | 0 |
| csharp | superpower | PASS | 2 | 316780 | 4 | 0 |
| javascript | bytes | PASS | 2 | 41634 | 17 | 0 |
| javascript | marked | PASS | 2 | 17541 | 54 | 0 |
| typescript | yaml | PASS | 2 | 25734 | 870 | 0 |
| typescript | zod | PASS | 2 | 39426 | 457 | 0 |
| ruby | csv | PASS | 2 | 20398 | 361 | 0 |
| ruby | parser | PASS | 2 | 257620 | 2 | 0 |
| lua | json-lua | PASS | 2 | 95649 | 133 | 0 |
| lua | lunajson | PASS | 2 | 173811 | 0 | 0 |
| php | php-parser | PASS | 2 | 603534 | 0 | 0 |
| php | symfony-yaml | PASS | 2 | 158445 | 0 | 0 |
| **Total** | **32 projects · 16 langs** | **32 PASS** | | **3,665,766** | | **8** |

## Defects found and fixed during validation

Validation found two defects, both fixed:

1. **Rust lane could not build any harness from a source-built binary.** bhf
   stages its embedded `rust_runtime` crate into a temp dir and a generated
   harness path-depends on it, but `crates/rust_runtime/Cargo.toml` inherited
   every package field (`edition`, `version`, ...) from the workspace root.
   Staged standalone, there is no workspace root, so cargo failed with
   *"failed to find a workspace root"* and the whole Rust lane produced zero
   executions. Fixed by making the runtime crate's manifest self-contained
   (concrete fields), since it is staged and built alone. Both Rust projects
   went from zero executions to the counts in the table above.

2. **Sweep runner consumed its own manifest via stdin.** The `while read` loop
   fed the manifest on stdin, and a build-recovery subprocess (e.g. Maven) read
   stdin and swallowed the remaining rows, so the first run stopped after 9
   projects. Fixed by reading the manifest on FD 3 and giving `bhf`
   `</dev/null`.

## bhf auto-harness boundaries observed

Four initially chosen projects did not fuzz. Each hit a limit of bhf's
*auto*-harnesser, and in each language the paired project fuzzed throughout.
They were swapped for better-fit targets:

| Language | Dropped | Why it could not auto-harness | Replaced with |
|---|---|---|---|
| python | feedparser | fuzzable surface is instance methods; clean entry `parse()` does network I/O | `uiri/toml` (`toml.loads`) |
| javascript | JSON-js | IIFE-wrapped, no named exports → 0 targets discovered | `visionmedia/bytes.js` |
| csharp | commandline | discovered targets are `internal` types, uncallable from an external harness assembly | `sprache/Sprache` (public API) |
| go | gjson | transitive deps (`tidwall/match`,`pretty`) don't resolve in the generated harness module | `valyala/fastjson` (zero-dep) |

bhf auto-harnesses functions whose parameters it can drive from bytes and
whose symbols it can link. At the time of this sweep, internal-only APIs,
instance methods without a constructible receiver, and Go targets with
external module dependencies fell outside that set. In each case bhf behaved
inside the container as it does outside.

## Follow-up: offline hardening, compile-DB fix, and size reduction

A second pass hardened the image for air-gapped use, fixed a bug that deleted
a user's compile database, and cut the image to fit a DVD.

### Offline / air-gap: staged bhf's own instrumentation deps

On a disconnected host, two lanes failed because bhf fetched its own
instrumentation dependencies from the internet (the operator stages the
target's dependencies separately). Both are now staged at build time and
verified with `--network none`:

- **Java:** `java_runtime/build-agent.sh` curled `asm`/`asm-tree` from Maven
  Central to shade into the JVM coverage agent; offline every Java target
  failed with `could not build the bhf JVM agent jar: curl: Could not resolve
  host: repo1.maven.org`. Fix: install `libasm-java` and set
  `ASM_JAR_DIR=/usr/share/java`. Verified: `mvn -o clean compile` under
  `--network none` → 2 built+fuzzed, 76,877 executions.
- **C#:** the harness restores `SharpFuzz` from NuGet; the image now primes
  the default NuGet cache with SharpFuzz 2.3.0. A target's own
  `PackageReference`s still need staging into `NUGET_PACKAGES`, exactly like a
  Maven target's `~/.m2`.

### compile_commands.json: `--probe-build` no longer deletes a user database

`probe_build` wiped `<tree>/.bhf-build/` before regenerating. That is the
path its own failure message names, so a `compile_commands.json` a user placed
there (even through a symlink) was deleted without warning when regeneration
failed offline. Fixed in `crates/cli/src/auto/build_probe.rs`: the existing
database is saved before the wipe, then restored and used if regeneration
produces none (regression test
`probe_build_restores_a_user_supplied_compile_db_when_regeneration_fails`).
Verified in the image: the user's file is kept and the harness builds with its
flags. A `compile_commands.json` in the project root or a `build/` directory,
real or symlinked, is used without `--probe-build`; that path already
worked.

### Size: 5.01 GB → 3.62 GB (1.25 GB compressed)

| Cut | Saved |
|---|---|
| Install the Rust toolchain as the `fuzzer` user instead of `chown -R` over it | ~0.94 GB (a duplicated layer) |
| Headless JDK + drop Gradle (removes the AWT/Mesa + second-LLVM pull) | ~0.4 GB |
| Drop the `rust-src` component (bhf instruments via SanitizerCoverage, not `-Zbuild-std`) | ~0.09 GB |

The remaining two-LLVM footprint (clang-18 for the C/C++ lane, clang-17 pulled
by AFL++) is the cost of the optional AFL++ engine; drop `afl++` from the
Dockerfile for a further ~0.2 GB if you only use the built-in engine.

### gcc-recovered flags no longer break the clang harness build

bhf recovers a project's real compile flags but builds the harness (and the
instrumented static libraries) with **clang** for SanitizerCoverage. Two kinds
of gcc flag leaked through and broke harness builds for projects whose own gcc
build compiles cleanly:

- **`-Werror` + a clang warning.** A project built `-Werror`, and a recovered
  flag such as `-fcx-fortran-rules` trips clang's `-Woverriding-option`, so the
  replay died with `clang++: error: overriding '' option with
  '-fcx-fortran-rules' [-Werror,-Woverriding-option]`. Fix: the injected
  instrumentation now appends `-Wno-error`, so a project warning cannot fail
  the harness build, and the per-harness allowlist drops `-Werror`/`-Werror=*`
  (`build_probe.rs`, `generate_harness.rs`).
- **gcc-only `-m` machine flags.** The `-m*` allowlist forwarded flags like
  `-mindirect-branch=thunk` that clang rejects with a hard `unknown argument`
  that `-Wno-error` cannot rescue. Fix: each forwarded `-m` flag is probed
  against clang once (cached) and dropped if rejected, keeping the valid ones
  (`-mavx`, `-march=…`). Regression tests
  `warnings_as_errors_are_not_forwarded_from_compile_db` and
  `gcc_only_machine_flag_clang_rejects_is_dropped`; both reproductions were
  verified to build and fuzz with no sanitizing needed.

## Runtime notes confirmed

- `--cap-add=SYS_PTRACE` is required for the ASan/LeakSanitizer
  stop-the-world; the C lane's LSan findings reproduce with it and degrade
  without it.
- All lanes work under `--cap-drop=ALL` + `no-new-privileges` (git clone,
  every compiler, and the fuzzers need no extra capabilities).
- Build recovery runs each target's own build system; the container is the
  sandbox that confines what `--unsafe-search-and-run-build-commands` runs on
  real trees.
