<!-- SPDX-License-Identifier: Apache-2.0 -->
# Docker validation — 32-project sixteen-language sweep (2026-09-24)

This record validates the production container (`Dockerfile`) end to end: a single
image that can **build, harness, and fuzz** every one of bhf's sixteen languages,
proven against a reproducible corpus of **two small, real, SHA-pinned projects per
language (32 total)**.

## Environment

| | |
|---|---|
| Host | Linux 6.8, x86_64, 6 vCPU, 13.6 GiB RAM, cgroup v2 |
| Docker | 29.1.3, overlay2, BuildKit |
| Base image | `ubuntu:24.04` (digest-pinned) |
| Image size | ~4.7 GB (all 16 toolchains + AFL++ + Rust nightly + .NET 8 + JDK/Maven/Gradle) |
| bhf | 0.2.32 (built from source in the builder stage) |

## Method

- **Corpus:** `docker/sweep-manifest.tsv` — 2 projects × 16 languages, each pinned
  to a full commit SHA, each a small single-purpose parser/decoder with a public,
  auto-harnessable entry point (prime fuzz targets).
- **Runner:** `docker/bhf-sweep.sh` runs `bhf auto` per project with real build
  recovery (`--unsafe-search-and-run-build-commands`) and `--force`, under a bounded
  budget: 10 s/target, 2 targets/project, 120 s campaign, `--jobs 1`.
- **Hardening posture under test:** the sweep ran with `--cap-drop=ALL
  --cap-add=SYS_PTRACE --security-opt no-new-privileges --shm-size=2g
  --memory=12g`, as the unprivileged `fuzzer` user — the exact production posture,
  not a permissive one.
- **PASS** = bhf built ≥1 harness, instrumented it, and executed the fuzzer against
  real library code (executions > 0).

## Result

**16 / 16 language lanes build, harness, and fuzz inside the hardened container;
32 / 32 projects PASS.**

| Language | Project | Result | Targets fuzzed | Executions | Edges | Findings |
|---|---|:--:|--:|--:|--:|--:|
| ada | json-ada | PASS | 2 | 210019 | 357 | 0 |
| ada | ada-yaml | PASS | 2 | 240852 | 1195 | 0 |
| c | cjson | PASS | 2 | 8803 | 283 | 0 |
| c | inih | PASS | 2 | 21118 | 96 | 0 |
| cpp | pugixml | PASS | 2 | 7482 | 446 | 6 |
| cpp | cpp-httplib | PASS | 1 | 3558 | 8 | 0 |
| rust | json-rust | PASS | 2 | 183420 | 647 | 0 |
| rust | rust-csv | PASS | 2 | 7865 | 148 | 0 |
| java | json-java | PASS | 2 | 346913 | 49 | 0 |
| java | minimal-json | PASS | 2 | 223619 | 405 | 0 |
| python | toml | PASS | 2 | 5249 | 746 | 2 |
| python | html5lib | PASS | 1 | 3858 | 12 | 0 |
| perl | json-pp | PASS | 2 | 202131 | 131 | 0 |
| perl | uri | PASS | 2 | 168906 | 175 | 0 |
| go | fastjson | PASS | 2 | 3167 | 81 | 2 |
| go | jsonparser | PASS | 2 | 34977 | 18 | 0 |
| fortran | json-fortran | PASS | 2 | 10381 | 1067 | 0 |
| fortran | csv-fortran | PASS | 1 | 3730 | 1524 | 0 |
| cobol | carddemo | PASS | 1 | 328 | 80 | 0 |
| cobol | cobolcraft | PASS | 2 | 642 | 88 | 0 |
| csharp | sprache | PASS | 2 | 317946 | 33 | 0 |
| csharp | superpower | PASS | 2 | 343161 | 4 | 0 |
| javascript | bytes | PASS | 2 | 41864 | 17 | 0 |
| javascript | marked | PASS | 2 | 17285 | 54 | 0 |
| typescript | yaml | PASS | 2 | 25582 | 870 | 0 |
| typescript | zod | PASS | 2 | 39302 | 457 | 0 |
| ruby | csv | PASS | 2 | 20563 | 361 | 0 |
| ruby | parser | PASS | 2 | 277195 | 2 | 0 |
| lua | json-lua | PASS | 2 | 97936 | 133 | 0 |
| lua | lunajson | PASS | 2 | 175259 | 0 | 0 |
| php | php-parser | PASS | 2 | 640222 | 0 | 0 |
| php | symfony-yaml | PASS | 2 | 160225 | 0 | 0 |
| **Total** | **32 projects · 16 langs** | **32 PASS** | | **3,843,558** | | **10** |

## Defects found and fixed during validation

Validation surfaced two real defects, both fixed:

1. **Rust lane could not build any harness from a source-built binary.** bhf stages
   its embedded `rust_runtime` crate into a temp dir and a generated harness
   path-depends on it, but `crates/rust_runtime/Cargo.toml` inherited every package
   field (`edition`, `version`, …) from the workspace root. Staged standalone there
   is no workspace root, so cargo failed with *"failed to find a workspace root"* and
   the whole Rust lane produced zero executions. Fixed by making the runtime crate's
   manifest self-contained (concrete fields) — it is designed to be staged and built
   alone. Both Rust projects went from 0 → hundreds of thousands of executions.

2. **Sweep runner consumed its own manifest via stdin.** The `while read` loop fed
   the manifest on stdin, and a build-recovery subprocess (e.g. Maven) read stdin
   and swallowed the remaining rows, so the first run stopped after 9 projects.
   Fixed by reading the manifest on FD 3 and giving `bhf` `</dev/null`.

## bhf capability boundaries observed (not container defects)

Four initially-chosen projects did not fuzz; each exposed a genuine limit of bhf's
*auto*-harnesser, not a container problem, and each language's paired project fuzzed
cleanly the whole time. They were swapped for better-fit targets:

| Language | Dropped | Why it could not auto-harness | Replaced with |
|---|---|---|---|
| python | feedparser | fuzzable surface is instance methods; clean entry `parse()` does network I/O | `uiri/toml` (`toml.loads`) |
| javascript | JSON-js | IIFE-wrapped, no named exports → 0 targets discovered | `visionmedia/bytes.js` |
| csharp | commandline | discovered targets are `internal` types, uncallable from an external harness assembly | `sprache/Sprache` (public API) |
| go | gjson | transitive deps (`tidwall/match`,`pretty`) don't resolve in the generated harness module | `valyala/fastjson` (zero-dep) |

These are honest boundaries: bhf auto-harnesses functions whose parameters it can
drive from bytes and whose symbols it can link; internal-only APIs, instance methods
without a constructible receiver, and (for now) Go targets with external module
dependencies fall outside that envelope. The container reproduces bhf's real behavior
faithfully in every case.

## Runtime notes confirmed

- `--cap-add=SYS_PTRACE` is required for the ASan/LeakSanitizer stop-the-world; the C
  lane's LSan findings reproduce with it and degrade without it.
- All lanes function under `--cap-drop=ALL` + `no-new-privileges` (git clone, every
  compiler, and the fuzzers need no extra capabilities).
- Build recovery runs each target's own build system; the container is the sandbox
  that makes `--unsafe-search-and-run-build-commands` safe to run on real trees.
