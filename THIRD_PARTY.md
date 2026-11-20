<!-- SPDX-License-Identifier: Apache-2.0 -->

# Third-Party Licensing

This page lists the libraries bhf links and the external tools it can run, with each one's license and the tier it may be used in. [Licensing](docs/site/licensing.md) describes the `--profile` values (`strict-permissive`, `external-tools`, `research-lab`) and the `bhf license-audit` command.

Tiers used in the matrix:

| Tier | Meaning |
|---|---|
| **Core** | Linked into the bhf binaries. Only Apache-2.0, MIT, BSD and the other permissive licenses `bhf license-audit` accepts. |
| **Core dev** / **Core build** | Used only by tests or at build time; not shipped. |
| **Optional embedded** | Linked only into a bhf built with the named Cargo feature. |
| **Optional adapter** / **Optional external** / **External-only** | Installed by you and run by bhf as a subprocess; never bundled or linked. |
| **Optional plug-in** | Off by default; enabled per run (for example `--probe gnat_actions`) in a profile that allows it. |
| **Candidate** / **Not used** | License reviewed; not in `Cargo.lock`. |
| **Forbidden** | Never linked. Where the row says `research-lab` only, the tool is allowed only under `--profile research-lab`. |

## Dependency matrix

| Component | Purpose | License | Tier | Risk | Recommendation |
|---|---|---|---|---|---|
| From-scratch scanner (bhf) | Permissive Ada lexer + structural parser | Apache-2.0 (ours) | **Core** | Grammar drift | Written in-house, so the Ada scanner stays permissive. |
| tree-sitter | Generic incremental parser engine | MIT | **Core** | Low | Link directly. |
| tree-sitter-ada | Ada grammar for tree-sitter | MIT (verify per release) | **Core** (after license re-verification per upgrade) | License churn, grammar coverage gaps | Vendored at a pinned commit under `vendor/tree-sitter-ada/`; the License Audit workflow checks its license checksum. |
| tree-sitter-c | C grammar for tree-sitter | MIT | **Core** | Low | Link directly for C source scanning. |
| tree-sitter-cpp | C++ grammar for tree-sitter | MIT | **Core** | Low | Link directly for C++ source scanning. |
| tree-sitter-rust | Rust grammar for tree-sitter | MIT | **Core** | Low | Link directly for Rust source scanning (native Rust discovery lane). |
| tree-sitter-java | Java grammar for tree-sitter | MIT | **Core** | Low | Link directly for Java source scanning (native Java discovery lane). |
| tree-sitter-python | Python grammar for tree-sitter | MIT | **Core** | Low | Link directly for Python source scanning (native Python discovery lane). |
| tree-sitter-perl | Perl grammar for tree-sitter | MIT | **Core** | Low | Link directly for Perl source scanning (native Perl discovery lane). |
| tree-sitter-go | Go grammar for tree-sitter | MIT | **Core** | Low | Link directly for Go source scanning (native Go discovery lane). |
| ASM (org.ow2.asm) | JVM bytecode instrumentation for bhf's own coverage agent | BSD-3-Clause | **Core (subprocess/agent runtime)** | Low (permissive, strict-permissive clean) | Not linked into the bhf Rust binary. Bundled into the standalone `bhf-jvm-agent.jar` (a `-javaagent` for the user's JVM, like GNAT subprocess use); built from `java_runtime/` by `build-agent.sh`, ASM is fetched into a cache, or pre-staged on an air-gapped host. |
| cc (Rust) | Build helper for vendored parser C sources | MIT/Apache-2.0 | **Core build** | Low | Build-time only; covered by `bhf license-audit` and `cargo deny`. |
| GPR2 library | Programmatic .gpr parsing | GPLv3 (with RLE for runtime, not for tooling linkage) | **Forbidden** (linked); **External-only** via `gprbuild --print-*` parsing | Copyleft contamination if linked | Do not link. Parse `.gpr` ourselves; shell out to `gprbuild` for builds. |
| GPRbuild | Project build driver | GPLv3 | **External-only** | None when invoked as subprocess | User-installed subprocess, run under every profile; not bundled. |
| FSF GNAT/GCC | Ada compiler | GPLv3 + GCC Runtime Library Exception | **External-only** | The GCC RLE permits compiled-program redistribution but does not let us link Ada front-end libraries | Subprocess only; see [GCC RLE boundary](#gcc-rle-boundary). End users may compile generated Ada code against the GNAT runtime for their own harnesses. |
| GNAT.Exception_Actions | Global raise hook | GPLv3 + GCC RLE | **Optional plug-in** (`external-tools`) | Same RLE terms as the runtime; implementation-defined unit | Source instrumentation is the default. `--probe gnat_actions` is allowed in `external-tools` and refused in `strict-permissive`. |
| GNAT.Exception_Traces | Symbolic backtrace | GPLv3 + GCC RLE | **Optional plug-in** | Same | Opt-in. |
| GNATfuzz | AdaCore fuzzing tool | Proprietary / non-free distribution | **Forbidden** in core | License incompatible | Not a dependency; `research-lab` only (`--probe gnatfuzz`). |
| GNATcoverage | Coverage tool | GPLv3 | **Forbidden** in core | Copyleft tooling obligations even as a subprocess | `research-lab` only (`--probe gnatcoverage`). |
| AFL++ | Coverage-guided fuzzer | Apache-2.0 | **Optional adapter** | Low | Run as a subprocess (`bhf fuzz --engine afl++`, `bhf auto --engine afl++`). Not in the bhf binaries or release bundles; the container image installs Ubuntu's `afl++` package and the QEMU/Frida modes, with their notices under `/usr/share/bhf/licenses/afl` (see [`docker/compliance/README.md`](docker/compliance/README.md)). `bhf auto` uses it for C/C++, COBOL, Fortran, Rust and Ada targets and runs the builtin engine for other lanes. |
| LibAFL | Embeddable fuzzing library | MIT/Apache-2.0 dual | **Optional embedded** | Low | Optional Cargo feature `libafl-engine` (`bhf fuzz --engine libafl`). |
| LLVM / libFuzzer | LLVM compiler infra and in-process fuzzer | Apache-2.0 with LLVM exceptions | **Optional adapter** | Low | User-installed with clang; not bundled. `bhf fuzz --engine libfuzzer` builds and runs the harness's `main_libfuzzer`. The Rust lane's generated cargo-fuzz crate links the libFuzzer runtime into your harness, not into bhf. |
| honggfuzz | Coverage-guided fuzzer | Apache-2.0 | **Optional adapter** | Low | User-installed subprocess (`bhf fuzz --engine honggfuzz`); not bundled. |
| WinAFL | Coverage-guided fuzzer for Windows binaries | Apache-2.0 | **Optional adapter** | Low | User-installed subprocess on native Windows (`--engine winafl`, with a user-installed DynamoRIO); not bundled. |
| PolyORB | Free Ada ORB | GPLv3 | **Forbidden** as core dep | Copyleft | `research-lab` only. |
| TAO | C++ ORB | DOC license (BSD-ish but unusual) | **Forbidden** in core | Audit cost | `research-lab` only. |
| omniORB | C++ ORB | LGPL/GPL | **Forbidden** | Copyleft on linkage | `research-lab` only. |
| JacORB | Java ORB | LGPL | **Forbidden** | Copyleft | `research-lab` only. |
| Libadalang | Semantic Ada front end | GPLv3 with runtime exception | **Optional plug-in only** | Linkage and audit risk | Out-of-process plug-in via JSON-RPC / subprocess. Never linked into core. |
| Alire | Ada package manager | Apache-2.0 | **Optional external** | Low | Used to fetch user dependencies in `external-tools`. |
| Langkit | Front-end generator | GPLv3 | **Forbidden** | Copyleft | Not used. |
| ASIS | Compiler-vendor semantic API | Vendor-dependent | **Forbidden** | Vendor lock | Not used. |
| serde / serde_json (Rust) | Serialization | MIT/Apache-2.0 | **Core** | Low | Allow. |
| clap (Rust) | CLI parsing | MIT/Apache-2.0 | **Core** | Low | Allow. |
| terminal_size (Rust) | Terminal width, so help wraps to it (clap's `wrap_help`) and short help lays out for it | MIT/Apache-2.0 | **Core** | Low | Allow. |
| anyhow / thiserror | Error types | MIT/Apache-2.0 | **Core** | Low | Allow. |
| tempfile (Rust) | RAII cleanup for compiler capability canary files | MIT/Apache-2.0 | **Core** | Low | Allow. |
| tera (Rust) | Harness template engine | MIT | **Core** | Low | Allow. |
| tokio | Async runtime | MIT | **Candidate** (not in `Cargo.lock`) | Low | License reviewed for a future async need; not linked. |
| nom / chumsky | Parser combinators (IDL) | MIT/Apache-2.0 | **Not used** | Low | The IDL subset parser (`crates/idl_parser`) is hand-rolled; neither crate is linked. |
| zstd / lz4 | Corpus compression | BSD-3 / BSD-2 | **Candidate** (not in `Cargo.lock`) | Low | License reviewed; corpus storage is uncompressed. |
| sha2 | Hashing | MIT/Apache-2.0 | **Core** | Low | Allow. `blake3` (BSD/CC0/Apache-2.0) is license-reviewed and not linked. |
| ring (Rust) | Ed25519 signing and verification for authenticated packs and release artifacts | Apache-2.0 AND ISC | **Core** | Low | Allow. Verify the resolved version and retain its license notices in distribution review. |
| regex | Diagnostic parsing | MIT/Apache-2.0 | **Core** | Low | Allow. |
| num_cpus (Rust) | Detect host CPU count for `bhf auto` worker pool | MIT/Apache-2.0 | **Core** | Low | Allow. |
| rayon (Rust) | Data-parallel static-scan file pipeline (10M-SLOC scale) | MIT/Apache-2.0 | **Core** | Low | Allow. Work-stealing pool bounded to cores-1; deterministic order-preserving collect. |
| jiff (Rust) | RFC 3339 timestamps in findings and `bhf auto` reports | Unlicense OR MIT | **Core** | Low | `default-features = false` + `std` only: UTC timestamps, no time-zone database. Replaces chrono, which RUSTSEC-2026-0543 marks unmaintained. |
| which (Rust) | Compiler binary discovery on PATH | MIT | **Core** | Low | Allow. |
| libc (Rust) | Unix `prctl` / `setrlimit` safety rails on spawned fuzz harnesses | MIT/Apache-2.0 | **Core** | Low | Allow. |
| tar (Rust) | `data.tar` member extraction for `binary scan` DEB/tarball recursion | MIT/Apache-2.0 | **Core** | Low | Allow. Pure-Rust (no `-sys`); keeps RHEL 7 / Windows MSVC / cross builds C-toolchain-free. |
| flate2 (Rust) | gzip (`data.tar.gz`) decoding for `binary scan` container recursion | MIT/Apache-2.0 | **Core** | Low | Allow. `default-features = false` + `rust_backend` (miniz_oxide) only — no `libz-sys`. |
| lzma-rs (Rust) | xz (`data.tar.xz`) decoding for `binary scan` container recursion | MIT | **Core** | Low | Allow. Pure-Rust; no `liblzma-sys`/C linkage. |
| ruzstd (Rust) | zstd (`data.tar.zst`) decoding for `binary scan` container recursion | MIT | **Core** | Low | Allow. Pure-Rust zstd (distinct from the C `zstd` candidate above); no `zstd-sys`. |
| windows-sys (Rust) | Native Windows ETW / Win32 bindings for the `bhf_collector_win` runtime-event provider sidecar | MIT OR Apache-2.0 | **Core (Windows-only sidecar)** | Low | Allow. Pure-Rust generated FFI (no `cc`/C toolchain), declared under `[target.'cfg(windows)'.dependencies]` so it never enters a non-Windows build; the crate compiles to its pure core on the Linux matrices. Transitive `windows-targets`/`windows_*_msvc` stay transitive. |
| ureq + rustls/webpki roots (Rust) | Bounded synchronous HTTPS for optional OpenAI/Anthropic LLM providers | MIT/Apache-2.0; certificate trust-anchor data is CDLA-Permissive-2.0 | **Core (optional network path at runtime)** | Remote data disclosure if explicitly selected; certificate data has a permissive attribution license | No request occurs by default. API keys are environment-only, response sizes/timeouts are bounded, and local/MCP modes remain token-free. |
| criterion | Bench (dev-only) | Apache-2.0/MIT | **Candidate** dev (not in `Cargo.lock`) | Low | License reviewed for benchmarking; not a dev-dependency. |
| toml (Rust) | Parsing config files, project and protocol manifests, and Cargo manifests for SBOM ingestion | MIT/Apache-2.0 | **Core** | Low | Allow. Also used by tests for hand-written corpus manifests. |

The License Audit workflow runs `cargo deny check`, the per-file SPDX header check (`crates/spdx_check`), and `bhf license-audit`, which checks the resolved core dependency graph and fails when a direct third-party dependency of a workspace crate has no row in this matrix. Add the row in the same change as the dependency.

BHF generates its own fake-CORBA scaffolding and IDL-to-Ada mapping and links none of the ORB libraries above (PolyORB, TAO, omniORB, JacORB); their rows record their tier.

The LD_PRELOAD runtrace shim (`bhf_runtrace_shim`) that supplies bhf's behavioral and taint oracles is bhf's own Apache-2.0 code. [Sink oracles](docs/site/sink-oracles.md) lists the lanes it loads into.

## Test fixtures

- **Arm CMSIS-SVD example (`ARM_Example.svd`, version 1.2)** — vendored
  unmodified under `crates/rehost/tests/fixtures/` (test-only; not
  redistributed in the bhf binary), to show the rehost crate's SVD reader
  on a vendor-written file. License: BSD-3-Clause, Copyright (C) 2012-2014
  ARM Limited (the notice is kept in the file). Upstream:
  <https://github.com/ARM-software/CMSIS_5>, `CMSIS/Utilities/ARM_Example.svd`
  at commit `4cbd1fb00fd84a3c8766742f36a32666a73ed120`; sha256
  `d1a385a7e6792ea99211e17cc507c51a6641ed5356d1e156cf97471f9c030eb8`.
- **miniz 3.0.2** — vendored under
  `tests/fixtures/build_recovery/fixtures/miniz/` (test-only;
  not redistributed in the bhf binary). License: MIT.
  Upstream: <https://github.com/richgel999/miniz>. Release zip
  sha256 `ada38db0b703a56d3dd6d57bf84a9c5d664921d870d8fea4db153979fb5332c5`.

## GCC RLE boundary

Generated Ada files (`adafuzz-*.ad?`, harnesses, fake-CORBA, and stubs) are Apache-2.0 and include SPDX headers. End users compile those generated files against their own GNAT runtime. The GCC Runtime Library Exception applies to redistribution of binaries produced by that compilation; bhf does not link GPL Ada front-end libraries into the core Rust graph.
