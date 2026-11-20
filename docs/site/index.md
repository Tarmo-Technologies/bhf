<!-- SPDX-License-Identifier: Apache-2.0 -->

# BHF Documentation

bhf (Build Harness Fuzz) finds the functions in a source tree that take
input, writes a fuzzing harness for each one, builds and fuzzes the
harnesses, and reports what it found, offline, in sixteen languages: Ada, C,
C++, Rust, Java, Python, Perl, Go, COBOL, Fortran, C#, JavaScript,
TypeScript, Ruby, Lua and PHP. This index lists every guide by task.

The guides are Markdown files in `docs/site/`, in the source repository and
in the full Linux bundle, and the links between them work in both. They also
render as HTML with `scripts/docs/build-site.py`; no public host serves it yet
(see [Architecture: Docs Site](architecture.md#docs-site)). Pages elsewhere
under `docs/` (reference notes, design notes and dated validation records)
are listed in [the docs folder](../README.md).

## Install

- [Install](install.md): building from source, the release files, the
  supported operating systems, and the toolchain each language needs.
- [Installing a release](../../INSTALL.md): verifying and installing the full
  Linux bundle, the component archives and the Windows CLI.
- [Docker](docker.md): the container images, Compose, language selection and
  offline use.
- [Windows](windows.md): the native Windows release, Visual Studio
  solutions, MSVC-only code, WinAFL, and how each lane runs on Windows.
- [Offline / Air-Gapped Deployment](offline-deployment.md): installing and
  updating bhf on a disconnected host, staging toolchains, and content
  packs.
- [Verified distribution handoff](../verified-distribution-handoff.md): how
  `verify-offline-dist.py` checks a bundle's signature and hands over the
  verified bytes.

## First run

- [Auto](auto.md): `bhf auto <PATH>`, the whole pipeline over a source
  tree: discovery, harness generation, build recovery, fuzzing, its flags,
  the config file, outputs and exit codes.
- [The recommended sweep](../recommended-sweep.md): the command to start
  with, and how to size each flag.
- [Offline Ada/C/C++ Auto Runbook](offline-auto-runbook.md): commands for a
  source drop with a known or unknown build, dependency staging, IDL code
  generation, and the forced fallback run kept in a separate work directory.
- [Run Modes](run-modes.md): `--mode reporting|attacking`, how each orders
  targets and presents findings.
- [Target Ranking](target-ranking.md): how `auto` scores candidates and
  decides which to attempt first.
- [Sanitizers](sanitizers.md): the `--sanitizers` matrix, what the default
  build arms, and when to add LSan, MSan or TSan.

## Languages

- [C and C++ Fuzzing](c-cpp.md): prerequisites, manual commands, supported
  parameter shapes, engine modes and limits.
- [Custom C and C++ Harnesses](custom-harness.md): write your own
  `LLVMFuzzerTestOneInput` or edit a generated harness, then build, fuzz and
  triage it with bhf.
- [C#](csharp.md), [JavaScript and TypeScript](javascript.md),
  [COBOL](cobol.md) and [Fortran](fortran.md): setup, coverage, harness
  behaviour and limits of each lane.
- Ada, Rust, Java, Python, Perl, Go, Ruby, Lua and PHP:
  [Auto: Discovery](auto.md#discovery) describes what each lane discovers,
  and [Instrumentation](instrumentation.md) how each gets coverage.
- [Fake-CORBA](fake-corba.md): IDL scaffolding for legacy Ada servants.
- [Ada cross-compilation and probe backends](../cross-compilation.md):
  GNAT/GPRbuild cross builds, the embedded probe backends, and qemu-user
  replay of an Ada harness.
- [Symbolic seed generation](../symbolic-seed-generation.md): seeds mined
  from the guards of an Ada source file.
- Ada example fixtures, each a small project that shows one harness or
  build-recovery case:
  [access parameters](../../examples/access_param/README.md),
  [annotated IDL](../../examples/annotated_idl/README.md),
  [fake CORBA servant](../../examples/fake_corba_servant/README.md),
  [legacy IDL acceptance](../../examples/legacy_idl_acceptance/README.md),
  [missing dependency](../../examples/missing_dependency/README.md),
  [private state](../../examples/private_state/README.md) and
  [swallowed Constraint_Error](../../examples/swallowed_constraint_error/README.md).

## Build environment and runtime

- [Runtime Virtualisation](runtime-virtualisation.md): the `LD_PRELOAD`
  shim that supplies the files, sockets and environment a fuzz target
  expects, the three-pass cascade, and the replay envelope.
- [Fake-resource SDK](fake-resource-sdk.md): writing a fake resource for the
  runtrace shim.
- [Instrumentation](instrumentation.md): how each lane gets coverage, Ada
  source rewriting, and the probe backends.
- [Cross-Compilation](cross-compilation.md): target toolchains, platform
  stub packs, qemu-user and wine runners, and sandboxing.

## Embedded, firmware and kernel targets

- [On-Target & Embedded](on-target-fuzzing.md): RTOS, radar and firmware
  code: host stub isolation, cross builds, the `--target-transport` modes
  (on-device agent, gdb-remote probe, full-system `qemu-system` snapshot),
  coverage maps, big-endian targets, firmware rehosting, and Linux kernel
  drivers.
- [Hardware-in-the-loop bring-up](../hil-bringup.md): fuzzing a physical ARM
  board over gdb-remote.

## CI, IDEs and automation

- [CI](ci.md): fuzzing the code a pull request changes, SARIF annotations,
  the PR gate, GitLab CI, and what a passing check covers.
- [Daemon](daemon.md): `bhf-daemon`, the IDE JSON-RPC server, and its
  three read-only MCP tools (five
  with the `llm` feature).
- [Daemon JSON-RPC](../daemon-json-rpc.md): the wire format and methods.
- [VS Code thin client](../vscode-thin-client.md),
  [GNAT Studio plugin](../gnatstudio-plugin.md) and
  [IDE parity](../ide-parity.md): the editor integrations.
- [Extension Protocol](extension-protocol.md): `bhf.extension.v1`, for an
  out-of-process semantic oracle you trust.
- [LLM Assistance](llm.md): the optional `llm` build feature, its providers
  and workflows, and what data it sends.

## Results and findings

- [Results reference](../finding-report-fields.md): the `results/`
  directory, the `bhf.findings.v1` and `bhf.finding.v1` formats, and the CSV
  columns.
- [Campaign comparison and triage](../report-comparison.md):
  `bhf report --baseline`, carrying triage decisions forward, and the
  offline HTML view.
- [Taint-Confirmed Sink Oracles](sink-oracles.md): how bhf confirms that
  fuzz input controls a dangerous sink, and the full sink matrix with CWEs.
- [Static CWE Coverage Matrix](static-cwe-coverage.md): what the static
  analyzer detects per language and CWE, and how fuzzing confirms it.
- [Inventory Assurance](inventory-assurance.md): what an SBOM match records,
  and the VEX review queue.
- [Differential fuzzing](../differential-fuzzing.md): `bhf differential`
  and `bhf fuzz --differential-harness`, which report the inputs on which
  two builds disagree.

## Reference

- [CLI](cli.md): every command and its options. Each command's `--help` is
  the authoritative list.
- [Architecture](architecture.md): the pipeline and the crates that make it
  up.
- [libFuzzer Parity](libfuzzer-parity.md): how the built-in engine's flags
  map to libFuzzer's, and CmpLog/RedQueen as the value-profile equivalent.
- [libFuzzer adapter](../libfuzzer-adapter.md): the libFuzzer-compatible
  binaries a generated harness builds.
- [Licensing](licensing.md): license profiles, SPDX metadata and the license
  audit; [ATO / RMF](ato.md) maps the container to NIST controls.
- [Release Packaging](release-packaging.md): the release archives,
  checksums, signatures and content packs; the
  [Release Checklist](release-checklist.md) lists what every release must
  ship.
- [CI acceptance](../ci-acceptance.md) and
  [release controls](../enterprise-release-controls.md): how a commit
  passes CI and how a release is tied to it.

## Measurements and comparisons

- [Comparison](comparison.md): bhf and the most widely used fuzzer for C,
  Rust, Java and Ada on the same planted-bug targets, and the benchmark
  suite; [Comparison: July 2026](comparison-2026-07.md) is a campaign on 14
  repositories.
- [Engine Parity Benchmark](engine-parity-benchmark.md): time to first crash
  on planted-bug parsers with magic-byte and other input gates.
- [Engine comparison benchmarks](../enterprise-engine-benchmark.md) and their
  [methodology](../../benchmarks/engine-comparison/METHODOLOGY.md): the two
  effectiveness experiments, their schemas and how to run them offline.
- [200-Project Expert Harness Parity](harness-parity-audit.md): generated
  harnesses measured against independently written expert fuzz drivers in
  all sixteen languages.
- [500-Project Sweep](sweep-500.md) and
  [Measured gaps](../expected-gaps.md): bhf run over 500 open-source
  projects, and each class of target it did not fuzz.
- [Vulnerability Coverage](vulnerability-coverage.md): the vulnerability
  classes bhf's oracles report beyond crashes, measured against crash-only
  fuzzers.
- [SAST Comparison](sast-comparison.md): bhf's static scanner and the
  standard open-source SAST tool for each language on 50 GitHub projects.
- White papers: [One fuzzer for the whole codebase](whitepaper.md) and
  [The bugs a crash-only fuzzer does not report](whitepaper-coverage.md).
- [Benchmarks](../../benchmarks/README.md): every benchmark study in the
  repository, its results and how to re-run it.
- [Validation records](../validation/README.md): dated runs of bhf on real
  projects, platforms, containers and emulators.

## Local Build

In a source checkout, render the HTML version with:

```sh
python3 scripts/docs/build-site.py --out target/docs-site
```

Then open `target/docs-site/index.html`.
