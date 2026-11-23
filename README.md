# BHF (Build Harness Fuzz)

<div align="center">
  <a href="https://github.com/Tarmo-Technologies/bhf/security/code-scanning"><img src="https://github.com/Tarmo-Technologies/bhf/actions/workflows/github-code-scanning/codeql/badge.svg" alt="CodeQL"></a> <a href="https://www.rust-lang.org"><img src="https://img.shields.io/badge/rust-1.88%2B-blue" alt="Rust 1.88+"></a> <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-green" alt="License: Apache-2.0"></a>
</div>

bhf is a fuzzer that writes its own harnesses. Point it at a source tree and it finds the functions that take input, generates a harness for each one, builds the harnesses with the compilers you have installed, and fuzzes them with coverage feedback. It covers sixteen languages: Ada, C, C++, Rust, Java, Python, Perl, Go, COBOL, Fortran, C#, JavaScript, TypeScript, Ruby, Lua and PHP. It runs offline. Each finding comes with its input, the sanitizer report and a replay command, and every target bhf could not build or fuzz is listed with the reason.

[What bhf does](#what-bhf-does) · [Install](#install) · [First run](#first-run) · [Read the results](#read-the-results) · [Commands](#commands) · [Documentation](#documentation)

## What bhf does

- **Harnesses.** `bhf auto` discovers candidate functions, ranks them, and generates a typed harness and the stubs it needs for each one.
- **Build recovery.** bhf takes compiler settings from `compile_commands.json`, the tree's own build system, or a `--build-command` you give it, and supplies missing headers, types and symbols. A target that still does not build is analyzed statically instead.
- **One engine for sixteen languages.** Every language lane feeds bhf's built-in coverage-guided engine. AFL++ (`--engine afl++`) is an optional second engine for C, C++, COBOL, Fortran, Rust and Ada targets, and WinAFL for C and C++ on native Windows.
- **Bugs that do not crash.** Sink oracles report a fuzz input that reaches a command, a file path, a library load, an SQL query or another dangerous sink with bytes from the input. They run through the Linux runtrace shim in native C, C++, Ada, Rust, Go, COBOL and Fortran harnesses and in the Python, Perl, Ruby, Lua and PHP interpreters; the Java and Node.js drivers check their own sinks. `auto/run.md` and `auto/run.json` say for each target whether its sink oracles ran.
- **Static analysis.** `bhf static-scan`, or `bhf auto --static`, runs an offline rule set over Ada, C, C++, Rust, Java, Python, Perl, Go, JavaScript/TypeScript, QML and configuration/IaC files, with taint traces and SARIF code flows. A static finding that fuzzing reaches at the same site is marked fuzz-confirmed.
- **SBOM and SCA.** `bhf sbom` inventories components from package manifests (Cargo, npm, PyPI, Maven, Gradle, Go modules, NuGet, RubyGems, Composer, CPAN, Conan, vcpkg, Alire), vendored C and Ada sources and binary inventories. It writes CycloneDX, SPDX and OpenVEX, and matches components against an offline CVE database you supply.
- **Binaries and firmware.** `bhf binary scan` inventories ELF, PE, Mach-O and raw firmware, including the members of `ar`, `.deb` and gzip/xz/zstd tar archives. `bhf binary fuzz` fuzzes an executable with no source, with coverage under AFL++ QEMU or Frida mode, or with a blind havoc loop when neither is installed. `bhf binary rehost` runs Cortex-M firmware in bhf's emulator.
- **Embedded and kernel targets.** bhf fuzzes code on a device through an on-target agent, a gdb-remote probe or a `qemu-system` snapshot, and Linux kernel drivers through syzlang descriptions and a KCOV guest.
- **Legacy code.** Fuzzes old-style (K&R) definitions in C through the prototype their parameter declarations give, `pragma Ada_83` units from a modern Ada harness, and sources written for `python2` when that interpreter is installed (report-only without it). Discovers and statically analyzes pre-C++98 sources (report-only: they are not fuzzed), and reads Latin-1/Windows-1252 sources.
- **Offline, permissive core.** bhf needs no network access, sends no telemetry and has no updater. In `bhf auto`, only the opt-in `--install-deps` downloads anything. The binaries link only Apache-2.0, MIT and BSD code; GPL tools such as GNAT, GPRbuild and AFL++ run as separate processes when you install them.

## Install

| You want to | Use |
|---|---|
| Install everything on x86_64 Linux, including a host with no network | The full bundle and its `install.sh`: [below](#linux-full-bundle), and [INSTALL.md](INSTALL.md) |
| Install the CLI on a connected Linux host (x86_64 or ARM64) | The component installers: [below](#linux-component-installers) |
| Run on Windows 11 or Windows Server | The PowerShell installer: [below](#windows) |
| Keep the target's build away from your host | The Docker image: [below](#docker) |
| Build bhf yourself | [From source](#from-source) |

Then install the compiler or interpreter for each language you want to fuzz. C and C++ need `clang` and `make`, plus Visual Studio Build Tools on Windows. [Installing bhf](docs/site/install.md) lists the toolchain for every language.

### Which release files do I need?

| What you want to do | Install or download |
|---|---|
| Install complete BHF on Linux with one `install.sh` | `bhf-dist-0.4.0-x86_64-unknown-linux-gnu.tar.gz` plus its `.sha256` and `.sig` files |
| Run the CLI on Windows | `bhf-installer.ps1`, or `bhf-x86_64-pc-windows-msvc.zip` plus its `.sha256` file for a manual or offline install |
| Run basic CLI workflows on Linux | `bhf-installer.sh`, or `bhf-x86_64-unknown-linux-gnu.tar.xz` (`bhf-aarch64-unknown-linux-gnu.tar.xz` on 64-bit ARM) plus its `.sha256` file |
| Get the Linux runtime audit, sink oracles and fake resources | Add `bhf_runtrace_shim-installer.sh`, or the matching `bhf_runtrace_shim-*.tar.xz` archive |
| Recover C/C++ builds with `--probe-build` or `--build-command` | Add `bhf_cc_intercept-installer.sh`, or the matching `bhf_cc_intercept-*.tar.xz` archive |
| Use an IDE, JSON-RPC or the read-only MCP service | Add `bhf-daemon-installer.sh` / `.ps1`, or the matching daemon archive |
| Audit or rebuild the release source | `source.tar.gz` plus `source.tar.gz.sha256` |
| Automate or verify downloads | Each archive's `.sha256` file, or `sha256.sum` for all of them; `dist-manifest.json` describes every component |

The full bundle is built for x86_64 only; on 64-bit ARM Linux use the component installers or the `aarch64-unknown-linux-gnu` archives. The two shims are Linux-only.

### Linux: full bundle

The bundle holds the CLI, the daemon, both Linux shims, the harness runtimes, a signed content pack with the static-analysis rule catalog, and this documentation under `docs/`. Its `install.sh` installs all of it. On a host with no network, stage the system toolchains first and add `--no-system-packages --no-rustup`.

Before you download, get three things through a channel other than the download itself; [INSTALL.md](INSTALL.md#what-you-need-before-you-start) explains each one and gives the policy template:

- the verifier, [`scripts/verify-offline-dist.py`](https://github.com/Tarmo-Technologies/bhf/blob/main/scripts/verify-offline-dist.py) from the bhf repository, saved as `verify-offline-dist.py`;
- the publisher's 64-character Ed25519 public key and key ID, saved as `publisher.pub`;
- a trust policy, `operator-policy.json`, that names that key.

Keep them outside the extracted bundle. The verifier needs Python 3.8 or newer and OpenSSL with Ed25519 support. From your download directory:

```sh
VERSION=0.4.0
BASE="https://github.com/Tarmo-Technologies/bhf/releases/download/${VERSION}"
ARCHIVE="bhf-dist-${VERSION}-x86_64-unknown-linux-gnu.tar.gz"

curl --proto '=https' --tlsv1.2 -fLO "$BASE/$ARCHIVE"
curl --proto '=https' --tlsv1.2 -fLO "$BASE/$ARCHIVE.sha256"
curl --proto '=https' --tlsv1.2 -fLO "$BASE/$ARCHIVE.sig"
sha256sum -c "$ARCHIVE.sha256"
python3 ./verify-offline-dist.py \
  --archive "$ARCHIVE" --signature "$ARCHIVE.sig" \
  --trusted-public-key ./publisher.pub \
  --verified-copy bhf-verified.tar.gz
tar xzf bhf-verified.tar.gz
cd "${ARCHIVE%.tar.gz}"
./install.sh --trust-policy ../operator-policy.json
```

The installer asks which language toolchains, targets, fuzzers and extras to set up, installs to `/opt/bhf`, links `bhf`, `bhf-daemon` and `bhf-bug-report` into `/usr/local/bin`, and runs a bundled C smoke test. `./install.sh --help` lists the non-interactive, custom-prefix and offline options.

### Linux: component installers

On a connected host, the component installers download and install their archives:

```sh
VERSION=0.4.0
BASE="https://github.com/Tarmo-Technologies/bhf/releases/download/${VERSION}"

curl --proto '=https' --tlsv1.2 -LsSf "$BASE/bhf-installer.sh" | sh
curl --proto '=https' --tlsv1.2 -LsSf "$BASE/bhf_runtrace_shim-installer.sh" | sh
curl --proto '=https' --tlsv1.2 -LsSf "$BASE/bhf_cc_intercept-installer.sh" | sh
```

To place the archives yourself, put both shims in the directory that holds `bhf`, or set `BHF_RUNTRACE_SHIM` and `BHF_CC_INTERCEPT` to their absolute paths. [INSTALL.md](INSTALL.md#choice-2-manually-co-locate-component-archives) has the commands.

### Windows

The PowerShell installers install the native x64 CLI and daemon. For C and C++ fuzzing, first install LLVM, the Visual Studio 2022 Build Tools with the Windows SDK, and GNU make from an elevated PowerShell, for example with Chocolatey:

```powershell
choco install llvm make visualstudio2022buildtools `
  visualstudio2022-workload-vctools -y

$Version = "0.4.0"
$Base = "https://github.com/Tarmo-Technologies/bhf/releases/download/$Version"
irm "$Base/bhf-installer.ps1" | iex
irm "$Base/bhf-daemon-installer.ps1" | iex       # optional: RPC/MCP service
```

Open a new PowerShell after installing the tools. bhf finds Visual Studio, the Windows SDK and clang itself, so you do not need a Developer shell. The [Windows guide](docs/site/windows.md) covers `winget` and w64devkit setups, Visual Studio solutions, the `--cc cl` MSVC lane, WinAFL, and how each language lane behaves on Windows.

### Docker

The default image has the toolchains for all sixteen languages and keeps the target's build system off your host. It builds for Linux x86-64 and ARM64 and runs under Docker Desktop on Windows and macOS.

```sh
git clone https://github.com/Tarmo-Technologies/bhf.git && cd bhf
docker build -t bhf:local -f Dockerfile .
docker run --rm --shm-size=2g --cap-add=SYS_PTRACE \
  -v "$PWD":/src:ro -v bhf_work:/work \
  bhf:local auto /src --work-dir /work/run --per-target-time 60
```

`--cap-add=SYS_PTRACE` lets LeakSanitizer run, and `--shm-size=2g` gives the coverage and CmpLog maps room in shared memory. The results stay in the `bhf_work` volume under `/work/run/results/`. To read the index:

```sh
docker run --rm -v bhf_work:/work bhf:local sh -c 'cat /work/run/results/INDEX.md'
```

The [Docker guide](docs/site/docker.md) covers Compose, the smaller `core` and `ada` images, and offline use.

### From source

Building needs Rust. The checkout's `rust-toolchain.toml` selects Rust 1.99.0, which rustup installs on the first build; the minimum supported version is 1.88. The ARM64 Linux runtime shim also needs `lld`.

```sh
git clone https://github.com/Tarmo-Technologies/bhf.git && cd bhf
cargo build --locked --release -p bhf -p bhf-daemon -p bhf_runtrace_shim -p bhf_cc_intercept
./target/release/bhf --version
```

The binaries and both shims land in `target/release/`, where bhf finds the shims. Apple Silicon Macs build and fuzz natively, without the Linux-only runtrace shim; see [macOS from source](docs/site/install.md#macos-apple-silicon-from-source).

### Supported release platforms

The release CLI and daemon run on 64-bit GNU/Linux and 64-bit Windows:

| Family | Versions | Tested by |
|---|---|---|
| RHEL | 7, 8, 9 and 10 | A glibc 2.17 ABI check, and native C scan, build and fuzz runs on CentOS 7.9 and AlmaLinux 8.10, 9.8 and 10.2 |
| Ubuntu LTS | 22.04, 24.04 and 26.04 | Native release-binary scan, build and fuzz jobs on each version |
| Windows x64 | Windows 11 Enterprise 25H2; Windows 11 Enterprise LTSC 2024 (24H2 codebase); Windows Server 2019, Windows Server 2022 and Windows Server 2025 | Native MSVC binaries with C scan, build and fuzz runs |

The Linux binaries are built on manylinux2014 and need glibc 2.17 or newer. RHEL support is tested on the RHEL-compatible distributions above.

On RHEL 7, the C/C++ lane needs LLVM Toolset 7.0 from Software Collections, because the stock Clang 3.4 lacks the SanitizerCoverage bhf uses. Install it before bhf:

```sh
sudo subscription-manager repos --enable rhel-server-rhscl-7-rpms
sudo yum install -y curl tar xz gcc gcc-c++ make \
  llvm-toolset-7.0-clang llvm-toolset-7.0-compiler-rt
```

bhf finds and activates the toolset itself; you do not need an `scl enable` shell. The verifier needs a newer OpenSSL than RHEL 7 ships, so verify the bundle on another host or with a newer OpenSSL build. Other language lanes need their toolchains from an approved repository or an offline package mirror. [Installing bhf](docs/site/install.md) has the full OS matrix and per-language prerequisites.

### Choosing languages

All sixteen languages are enabled by default. Choosing languages at install time decides which toolchains are installed; `bhf auto --languages` limits one run. In a source checkout, build a container image with only the Java and Python toolchains:

```sh
scripts/build-container-release.sh bhf:java-python --languages java,python
```

From an extracted native bundle:

```sh
./install.sh --non-interactive --no-content --languages java,python
```

[Installation selection versus run selection](docs/site/docker.md#installation-selection-versus-run-selection) lists the aliases, conflicts and shared dependencies.

## First run

Start with one target to check the toolchain:

```sh
bhf --version
bhf auto /path/to/source --work-dir /path/to/bhf_work \
  --jobs 1 --max-targets 1 --per-target-time 10
```

Keep the work directory outside the source tree. `--max-targets 1` stops after one target has been fuzzed, and `--per-target-time 10` fuzzes it for 10 seconds. `bhf auto --help` lists the run limits, language selection and build options, and ends with the recommended sweep below.

### The recommended sweep

For a source tree you trust, start with this command. The [recommended sweep guide](docs/recommended-sweep.md) explains how to size each flag.

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

| Flag | Purpose |
|---|---|
| `--jobs 4` | Targets built and fuzzed at once. Budget `jobs × --rss-limit-mb` of RAM, plus memory for bhf, the compilers and the OS. |
| `--per-target-time 60` | Fuzzing time per target, in seconds. |
| `--campaign-time 3600` | Cap on the whole sweep, in seconds; no new target starts after it. |
| `--max-targets 40` | Stop once 40 targets have been fuzzed. Targets that fail to build do not count. |
| `--unsafe-search-and-run-build-commands` | Run the tree's own build to recover its compile flags. This executes code from the tree: trusted sources only. |
| `--force` | Retry the targets that did not fuzz, with fabricated inputs and stubs. Their findings are marked low-confidence. |
| `--static` | Add static analysis of the whole tree. |
| `--sbom` | Write SBOM and VEX files, marking the components a harness exercised. |
| `--sloc sloc.txt` | Write a per-language line count (`.json` for JSON). |
| `--debug` | Record a backtrace if bhf itself panics. |

## Read the results

Open `results/INDEX.md` in the work directory first. It lists every finding grouped by root cause, with its severity, source location, evidence, fix advice and replay command. `auto/summary.txt` counts the targets that were built and fuzzed, analyzed statically only, skipped or forced, and names the top blockers.

| Path in the work directory | What it holds |
|---|---|
| `results/INDEX.md` | Summary, then the findings grouped by root cause |
| `results/findings.json` | Every finding, machine-readable (`bhf.findings.v1`; schema in `schemas/`) |
| `results/findings.csv`, `results/findings.sarif` | Spreadsheet and code-scanning views |
| `results/findings/<id>/` | One finding's evidence: `finding.json`, `testcase.bin`, `min_testcase.bin`, `sanitizer.log`, `replay.py` |
| `auto/run.md`, `auto/run.json` | The campaign report: every target, its outcome, coverage and repairs |
| `auto/summary.txt` | What built, fuzzed or was skipped, and the top blockers |
| `auto/missing-deps.txt` | Dependencies the tree needs that this host lacks |
| `sbom/` | The `--sbom` output |
| `results/static/`, `results/sbom/` | Reports of `bhf static-scan` and `bhf sbom` run with this work directory |

To reproduce a finding, run `bhf replay` on its directory. It prints `MATCH` and exits 0 when the input crashes the same way again:

```sh
bhf replay bhf_work/results/findings/<id>
```

`bhf report --work-dir bhf_work` rebuilds the index. The [results reference](docs/finding-report-fields.md) describes every file and field, and [Auto](docs/site/auto.md#outputs) the whole work-directory tree and the exit codes.

`auto` keeps at most 64 MiB of corpus per target and stops starting new targets when the work directory reaches 4 GiB. Change these with `--max-corpus-mb` and `--max-work-dir-mb` (`0` turns off the work-directory limit). Findings are never deleted to stay under either limit. To reclaim compiler caches and scratch files and keep findings, corpora, reports and replay binaries, run `bhf clean bhf_work --compact`.

For offline support, do not send the work directory. Run `bhf-bug-report
bhf_work --bundle bhf-bug-report.tar.gz`; the self-tested archive omits source,
harness and corpus content and replaces paths, filenames, targets, variables,
types, units, symbols and macros with typed placeholders.

### Watch and steer a live sweep

On a terminal, `auto` keeps a status block below the scrolling results:

```text
phase 1/2 unforced   fuzzed  7/50 ██░░░░░░░░░░░░  attempts 213/26409   6m12s · eta ~38m
7 fuzzed · 118 failed-build · 88 skipped   2 finding(s)   top blocker: missing header X (c) (61)
jobs 3/16 · cap 50 · target-time 1m00s · force off · verbose off   cpu 42%   rss 1.2 GB/9.0 GB
keys: [q] stop & report · [p] pause · [+/-] jobs · [{/}] cap · [</>] target-time · [f] force · [v] verbose · [?] help
now  H-C0042            mz_compress            c      building (retry 1) 9s
     H-C0051            mz_crc32               c      fuzz:cmplog 14s/1m00s  8.1k execs 512/s  318 edges  last edge 4s
```

`last edge` and `last find` show the time since the target last found new coverage or a finding. With `--max-targets`, progress counts fuzzed targets; without it, candidates. These keys steer the run:

| Key | Effect |
|---|---|
| `q` | Start no new targets, let the running ones finish, write the reports, and skip the forced phase. |
| `p` | Pause or resume starting new targets; running targets continue. |
| `+` / `-` | Change `--jobs`, between 1 and the number of CPU cores (or the starting `--jobs`, if higher). |
| `]` / `[` (or `}` / `{`) | Change `--max-targets` by 10%, never below the number already fuzzed. On a run with no cap, `[` sets one 10 above the number already fuzzed. |
| `>` / `<` | Change `--per-target-time` by 25% for the targets that start next. Not available when `--campaign-time` with `--min-target-time` splits the budget. |
| `f` | Turn the forced second phase on or off while phase 1 runs, with or without `--force`. |
| `v` | Show or hide per-target detail. |
| `?` | Show or hide the key legend; any other key also hides it. |

Discovery and build options such as `--sanitizers`, `--cxx-std` and `--build-command` are fixed for the run. Ctrl-C stops at once and writes no final report. When the output is piped, `auto` prints one line per target instead, and `--verbose` adds a heartbeat every 30 seconds.

### Resume an interrupted run

`bhf auto` records each target as it completes. To resume, repeat the original command with the same source tree, work directory and options, and add `--resume`:

```sh
bhf auto path/to/src \
  --work-dir bhf_work \
  --per-target-time 60 \
  --resume
```

Completed targets are skipped and included in the new report; findings and corpora are kept, and interrupted targets start again. bhf reuses a completed result while the build context is unchanged: `compile_commands.json`, GNAT projects (`.gpr`), IDL files, Visual Studio solutions and projects, and the harness options, including project selection, decoder limits, stubbing, engines, passes and sanitizers. A change to the build context retries every target. A changed source file retries only the targets in that file, with or without `--no-discovery-cache`, so edits to documentation or other files keep the results. In a work directory written by a different bhf build, the targets that fuzzed are kept and the rest run again.

## Resource Requirements

RAM needs depend on the size of the tree, the sanitizers, the input limits and how many targets run at once:

| Workload | RAM | Suggested settings |
|---|---:|---|
| Small repository, or a PR/diff-scoped run | 4 GiB minimum | `--jobs 1`; keep the default harness RSS cap |
| Whole-tree run on a large repository | 8 GiB | `--jobs 1 --rss-limit-mb 1536`; for static analysis, `--jobs 2 --max-memory-mb 4096` |
| 10M+ lines with static analysis and build recovery | 16 GiB recommended | Start with `--jobs 2`; raise it after measuring peak RSS |
| Parallel sanitizer campaigns | 32 GiB or more | Size from the measured target RSS, and leave room for bhf and the OS |

`--rss-limit-mb` caps each fuzzed child process, not the whole run. Budget at least `jobs × rss-limit-mb` for the children, plus bhf's discovery, index and report data, the compiler processes and the OS. On an 8 GiB machine, run one target at a time:

```sh
BHF_STATIC_JOBS=2 BHF_MAX_MEMORY_KB=4194304 \
  bhf auto path/to/10m-sloc-tree \
  --jobs 1 --rss-limit-mb 1536 --max-targets 500 \
  --single-pass --campaign-time 3600
```

For `bhf static-scan`, the same limits are `--jobs 2 --max-memory-mb 4096`. The static analyzer stops admitting new work at its memory ceiling and records an analysis gap. By default the ceiling is the smaller of 80% of available host RAM and 70% of the cgroup limit, and `auto` sizes each harness's RSS cap from available memory. Corpus, source-file and captured-output limits also scale with available memory; the [scaling guide](docs/site/auto.md#scaling-to-large-trees) lists the defaults and the `BHF_MAX_*` overrides.

## Optional LLM assistance

Default builds and the release binaries contain no LLM code. To add it, build from source with the `llm` feature:

```sh
cargo build --locked --release -p bhf -p bhf-daemon \
  --features bhf/llm,bhf-daemon/llm
```

That build adds `bhf llm` (`status`, `test`, `prompt`, `assist`) and two more MCP tools in `bhf-daemon --mcp`. It works with local command-line agents, hosted model APIs and local OpenAI-compatible servers. bhf checks every suggestion against its own build, reachability, coverage, replay and minimization results. The [LLM assistance guide](docs/site/llm.md) lists the providers and covers setup, the workflows and what data leaves the host.

## Run bhf on every pull request

This workflow fuzzes the code a pull request changes:

```yaml
# .github/workflows/bhf-pr.yml
name: bhf PR
on: pull_request
permissions:
  contents: read
  pull-requests: write
  security-events: write
jobs:
  bhf:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: Tarmo-Technologies/bhf/.github/actions/bhf-pr@main
        with: { path: ., campaign-time: "180" }
```

The action limits the run to the changed files, uploads SARIF for inline annotations, posts a summary comment, and fails the check on a fuzz-confirmed finding. [CI](docs/site/ci.md) lists its inputs and the `bhf ci` command behind it.

## Commands

| Command | What it does |
|---|---|
| `bhf auto <src>` | Discover, harness, build and fuzz a whole tree |
| `bhf auto <src> --static` | Add static analysis of the whole tree to the run |
| `bhf auto <src> --engine afl++` | Fuzz with AFL++ (C, C++, COBOL, Fortran, Rust and Ada targets) |
| `bhf auto <src> --force` | Retry unfuzzed C/C++/Ada, Go and C# targets with fabricated parameters and stubs; their findings are low-confidence |
| `bhf auto <src> --differential clang:gcc` | Build C/C++ harnesses with both compilers and report inputs on which they behave differently (BHF-301) |
| `bhf ci <src> --changed-since <ref> --sarif <file> --pr-gate confirmed` | Fuzz the changed files, write SARIF, and exit non-zero on a fuzz-confirmed finding |
| `bhf static-scan <src> --sarif` | Static analysis only (JSON, Markdown and SARIF) |
| `bhf sbom <src> --vuln-db <db>` | SBOM with offline CVE and VEX matching |
| `bhf binary scan <bin>` | Inventory and hardening triage for ELF, PE, Mach-O and firmware, including `ar`/`.deb` and tar members |
| `bhf binary fuzz <bin>` | Fuzz an executable with no source (blind havoc, or AFL++ QEMU or Frida mode) |
| `bhf binary rehost <image>` | Fuzz Cortex-M firmware in bhf's emulator |
| `bhf kernel ...` | Generate syzlang for a Linux driver, import syzkaller crashes, or fuzz a kernel in a `qemu-system` guest |
| `bhf replay <finding-dir>` | Reproduce a finding: exit 0 `MATCH`, 3 `MISMATCH`, 4 `UNVERIFIED` |
| `bhf report --work-dir <dir>` | Rebuild `results/`; add `--junit` or `--gitlab-sast` for those formats |
| `bhf sloc <src>` | Count source lines per language |
| `bhf generate-harness <file> --target <fn>` | Generate one Ada, C or C++ harness by hand |
| `bhf bug-report <work-dir> --preview` | Show the scrubbed support report bhf would share when bhf itself fails |

`bhf --help` groups every command by area, and `bhf <command> --help` gives its options. The [CLI reference](docs/site/cli.md) describes each one.

## Documentation

Every guide is a Markdown file under `docs/`, in this repository and in the full Linux bundle, so the links below also work offline.

- [Documentation index](docs/site/index.md): every user guide, grouped by task (install, first run, languages, Windows, embedded, CI, results, reference).
- [The docs folder](docs/README.md): the reference, release, measurement and planning pages outside `docs/site/`.
- [Benchmarks](benchmarks/README.md): each benchmark study, its results and how to re-run it.
- [Validation records](docs/validation/README.md) and [design notes](docs/designs/README.md): dated records of validation runs, and the designs written before a feature was built.

The pages most readers need first:

- [Installing bhf](docs/site/install.md) and [INSTALL.md](INSTALL.md)
- [Auto](docs/site/auto.md), the `bhf auto` guide, and the [recommended sweep](docs/recommended-sweep.md)
- [Results reference](docs/finding-report-fields.md)
- [CLI reference](docs/site/cli.md)
- [Offline deployment](docs/site/offline-deployment.md) and the [offline Ada/C/C++ runbook](docs/site/offline-auto-runbook.md)
- [Windows](docs/site/windows.md) and [On-target and embedded fuzzing](docs/site/on-target-fuzzing.md)

[RELEASE_NOTES.md](RELEASE_NOTES.md) describes the current release, [CHANGELOG.md](CHANGELOG.md) lists every change, and the engineering roadmap is in [ROADMAP.md](ROADMAP.md).

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) covers the build, the tests and the formatting, lint and SPDX checks. See also the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Report vulnerabilities privately through the repository's [Security tab](https://github.com/Tarmo-Technologies/bhf/security/advisories/new), not in a public issue. [SECURITY.md](SECURITY.md) has the details.

## License

Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). The bhf binaries link only Apache-2.0, MIT and BSD dependencies. GPL tools you install, such as FSF GNAT, GPRbuild and AFL++, run as separate processes and are never linked. [THIRD_PARTY.md](THIRD_PARTY.md) lists every dependency and tool with its license, and [Licensing](docs/site/licensing.md) describes the license profiles.
