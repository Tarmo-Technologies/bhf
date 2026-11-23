<!-- SPDX-License-Identifier: Apache-2.0 -->

# Offline `auto` Runbook for Ada, C, and C++

This runbook covers fuzzing an Ada, C or C++ source drop on an offline host, so that as many targets as possible reach real fuzz execution. It runs the evidence-preserving sweep and the forced, stub-heavy fallback separately, so the reports show which results exercised the project's real behaviour.

## Required Offline Content

bhf recovers compile flags, generates harnesses, repairs an incomplete build closure, synthesizes stand-ins for some missing dependencies, and works around an original build that does not run. Fuzzing still needs working compilers and runtimes on the offline host. Stage these before the scan:

- the complete source drop, including the local Git history if deleted tracked files must be recovered exactly;
- matching GNAT/GPRbuild and C/C++ compiler and runtime toolchains;
- vendored dependency headers and sources whose real behaviour matters;
- the project's code generators and their inputs, if the real generated output matters;
- representative input files or corpora for structured formats.

`--install-deps` needs the network, so do not use it on the offline host. bhf cannot reconstruct a missing compiler, generated interface or source file from nothing; `auto/run.json` and `auto/missing-deps.txt` record what is missing.

bhf writes `auto/missing-deps.txt` and `auto/missing-deps.json` before the first target starts. Their first section is the offline handoff list: missing host and cross compilers, target runtimes and emulators, generated source and code-generation tools, unfetched Git submodules, and declared Alire source that is not staged locally. Each row says whether it was `declared`, `observed` or `inferred`, and includes the metadata or diagnostic behind it. Configure and CMake templates and commands are reported as generated source, not as guessed distribution header packages. C, C++ and Ada source paths that CMake declares but the drop lacks are listed separately as vendor or project source; bhf does not stand in for their implementation.

The files are checkpointed atomically after every completed target, parallel sweeps included, and the final line of output points to `missing-deps.txt` with its blocking and substituted counts. Build-probe diagnostics are checkpointed before target discovery begins. If the bhf parent process is OOM-killed, the last valid checkpoint keeps the latest project metadata, build-probe and preflight pass and every target completed before the kill. The target that was running can be missing, because a killed process cannot run its classifier; `complete: false` in the JSON and `run still in progress` in the text mark that.

A row is exact where the project or toolchain provides evidence: a `.gitmodules` path and URL, an `alire.toml` version constraint, a CMake output and command, a compiler diagnostic, or a mapped platform guard. When an absent proprietary SDK or source has no identifying metadata, bhf records the unresolved type or guard and marks it `inferred`; it does not invent a vendor, version, ABI or implementation.

`--run-untrusted`, `--build-command` and `--unsafe-search-and-run-build-commands` execute code from the scanned tree. Use them only in an isolated scan VM, or an equivalent sandbox, with networking disabled.

## Known Build Command

When you know the build entry point, name it. `--build-command` runs the build, intercepts its compiler invocations and recovers a compile database; `--run-untrusted` also enables the Ada build and code-generation probe.

```sh
bhf auto /src/project \
  --work-dir /results/bhf-real \
  --languages ada,c,cpp \
  --run-untrusted \
  --build-command "./build.sh" \
  --static \
  --sanitizers asan,ubsan \
  --comparison-progress \
  --seed-dir /offline/seeds \
  --per-target-time 300 \
  --jobs 2 \
  --verbose
```

For a recognized CMake, Meson, Make, Ninja, Visual Studio, Alire or GPRbuild project that needs no custom command, leave out `--build-command` and keep `--run-untrusted`, which enables the normal C/C++ and Ada build probes.

`--sanitizers asan,ubsan` builds each C/C++ harness with `-fsanitize=address,undefined` and arms the matching `<SAN>_OPTIONS`, so UBSan reports become saved crashes. If a legacy compiler rejects the sanitizers, rerun with `--sanitizers none`: each harness then builds with coverage and no `-fsanitize=`, and only hard faults are detected.

## Unknown Build Command

When you do not know the build entry point and the source is trusted enough to execute in the isolated VM, let bhf find it:

```sh
bhf auto /src/project \
  --work-dir /results/bhf-real \
  --languages ada,c,cpp \
  --unsafe-search-and-run-build-commands \
  --static \
  --sanitizers asan,ubsan \
  --comparison-progress \
  --seed-dir /offline/seeds \
  --per-target-time 300 \
  --jobs 2 \
  --verbose
```

`--unsafe-search-and-run-build-commands` finds and runs a custom build entry point when one exists (`build.sh`, an autotools bootstrap, SCons, Waf, Bazel), enables the recognized build-system probes, and enables the Ada build and code-generation probe. It includes the consent that `--run-untrusted` gives.

## Supply Real Offline Dependencies

Add only the flags that describe content you actually staged:

```sh
  --extra-include /offline/deps/include \
  --extra-source /src/project/lib/helper.c \
  --ada-deps /offline/deps/ada-src \
  --seed-file /offline/seeds/valid-message.bin \
  --seed-dir /offline/seeds
```

| Flag | Effect |
|---|---|
| `--extra-include DIR` | Supplies real C/C++ dependency headers. Repeatable. |
| `--extra-source FILE` | Links a known sibling translation unit instead of stubbing its symbols. Repeatable. |
| `--ada-deps DIR` | Puts vendored Ada dependency sources on the build path. Repeatable. |
| `--include-dir NAME` | Keeps a directory in discovery that bhf would otherwise skip by default. |
| `--seed-file`, `--seed-dir`, `--grammar FILE` | Help structured parsers pass format checks and reach deeper code. |
| `--engine builtin,afl++` | Adds AFL++ for native C/C++, COBOL, Fortran, Rust and Ada targets when its binaries are installed offline. The per-target time is split between the engines. |

Leave `--cxx-std` unset unless you know the required dialect: the automatic dialect ladder gives legacy C++ a better chance. Keep the default `--max-repair-rounds 16`; in validation over clean and damaged trees, no successful build needed more than 14 rounds.

## IDL and Generated Source

`auto` handles in-tree `.idl` files without a manual step. Its offline parser resolves cross-directory IDL includes, emits fake CORBA base packages and Ada Helper/Skel/Stub mapping units under `bhf_work/fake_corba`, adds that source directory to Ada builds, and derives fuzz dictionary tokens.

Project-specific C/C++ client and server code generated from IDL needs the project's own generator. Use `--run-untrusted` or `--build-command` when the generator is staged offline. When the generator or its inputs are absent, bhf synthesizes header and type scaffolding only, and the generated code's behaviour is not reproduced.

## Forced Fallback

`--force` runs the normal sweep first, then a second phase over the C/C++ and Ada targets whose parameters or dependencies could not be driven: it fabricates the parameter and stubs the missing symbols. Run it into a different work directory, so the evidence-preserving results stay in their own:

```sh
bhf auto /src/project \
  --work-dir /results/bhf-forced \
  --languages ada,c,cpp \
  --run-untrusted \
  --build-command "./build.sh" \
  --force \
  --static \
  --comparison-progress \
  --seed-dir /offline/seeds \
  --per-target-time 300 \
  --jobs 2 \
  --verbose
```

For the unknown-build variant, replace `--run-untrusted --build-command ...` with `--unsafe-search-and-run-build-commands`.

Findings from forced and stub-heavy builds are marked low confidence because they can depend on fabricated behaviour. Keep their success counts separate from the evidence-preserving run's.

## Flag Combination Rules

- `--force` combines with either known-build or unknown-build recovery.
- `--run-untrusted` implies `--probe-build`; you need not pass both.
- An explicit `--build-command` overrides `--unsafe-search-and-run-build-commands`; choose one.
- `--static` adds static analysis of the whole tree, including files that still cannot run.
- `--resume` continues an interrupted run with the same work directory and unchanged source. It does not turn the evidence-preserving run into a forced one; start the forced run in its own work directory.
- Size `--jobs` against memory. `jobs × --rss-limit-mb` is the fuzz-child allowance, not the total peak; also reserve RAM for bhf's declaration index, the retained target results, compiler processes and the OS. Use `--jobs 1` on an 8 GiB host unless you have measured spare headroom.

## Compact Scrubbed Support Report

If the campaign produces no working harness, run the bundled collector instead of copying many command outputs by hand. It also works while the campaign is still running, because each completed target has an atomic result checkpoint:

```sh
bhf-bug-report /results/bhf-real
```

The script writes and prints `bhf-support-report.txt`, capped at 4,000 bytes. It holds version, host and toolchain lines, outcomes by language, structured build-error and repair counts, checkpoint health, and the most frequent diagnostic shapes. It does not read or include source, generated harness code or corpus inputs. Project paths, file names, targets, variables, types, Ada units, symbols and macros are replaced with typed placeholders before the report is written.

For transfer outside the enclave, prefer the self-tested archive form:

```sh
bhf-bug-report /results/bhf-real --bundle bhf-bug-report.tar.gz
```

The archive contains the scrubbed report, manifest and self-test result. It refuses to write when its final secret/path scan detects a leak. The equivalent text-only CLI command is:

```sh
bhf bug-report /results/bhf-real \
  --output bhf-support-report.txt \
  --stdout --examples 6 --max-bytes 4000
```

Send only the self-tested bundle or that scrubbed text file. The raw `result.json`, `run.json`, build trees and source are not needed for ordinary build and harness triage.

## Disk, memory and cleanup

The work directory is evidence and is intentionally persistent. `bhf auto` bounds its own work tree with `--max-work-dir-mb` (4 GiB by default) and each corpus with `--max-corpus-mb` (64 MiB by default); findings are never deleted to satisfy a cap. Run `bhf clean <work-dir> --compact` after exporting evidence to remove compiler caches and scratch while preserving findings, corpora, reports and replay binaries. Remove the entire work directory only under the site's evidence-retention policy.

Temporary build directories created through the CLI are RAII-managed and are removed at normal exit. SIGKILL and host power loss can prevent cleanup, so an offline workstation should run campaigns in a dedicated results filesystem, check it after reboot, and treat an abandoned work directory as evidence until an operator explicitly compacts or removes it. For long campaigns, compare RSS, PID count, file descriptors and filesystem use at fixed intervals; a single completed run is not a memory-leak test.

## Acceptance Check

`/results/bhf-real/auto/run.json` is the machine-readable evidence. A target that fuzzed successfully reports `built_and_fuzzed`, at least one execution, and positive coverage. Review these fields and files:

- `summary.built_and_fuzzed` and the per-target outcomes;
- per-pass `executions` and `coverage_edges`;
- the repairs and the `needed_for_build` ledger;
- `fuzzed_stub_only`, forced notes, and stub execution evidence;
- `auto/missing-deps.txt`, for offline content that still blocks a build; read its first section, `Required toolchains, runtimes, generated and vendor source`, before the lower-level headers and symbols;
- `auto/bug-report.md`, for defects in bhf itself.

A zero-coverage run, a forced-only result or a stub-only result is a gap: it does not show that the real target was fuzzed.
