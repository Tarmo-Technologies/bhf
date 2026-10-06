# BHF — Build Harness Fuzz

<div align="center">
  <em><strong>THE POINT-AND-CLICK FUZZER.</strong></em>
  <br><br>
  <a href="https://github.com/Tarmo-Technologies/bhf/security/code-scanning"><img src="https://github.com/Tarmo-Technologies/bhf/actions/workflows/github-code-scanning/codeql/badge.svg" alt="CodeQL"></a>
  <a href="https://www.rust-lang.org"><img src="https://img.shields.io/badge/rust-1.88%2B-blue" alt="Rust 1.88+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-green" alt="License: Apache-2.0"></a>
</div>

<p align="center">
<strong>BHF (Build Harness Fuzz)</strong> is an automated fuzzer and harness generator for Ada, C, C++, Rust, Java, Python, Perl, Go, COBOL, Fortran, C#, JavaScript, TypeScript, Ruby, Lua, and PHP. Point it at a source tree; it discovers candidate functions,
generates harnesses, and attempts to build and fuzz them with your installed
toolchains. Missing dependencies and unsupported targets are reported.
</p>

<p align="center">
  <a href="#why-bhf">Why bhf?</a> ·
  <a href="#what-it-does">What It Does</a> ·
  <a href="#quick-start">Quick Start</a> ·
  <a href="#resource-requirements">Resources</a> ·
  <a href="#commands">Commands</a> ·
  <a href="#documentation">Docs</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

## Why bhf?

- **Automatic harnesses.** BHF discovers functions and generates typed harnesses and stubs.
- **Build recovery.** It recovers compiler settings and supplies missing headers,
  types, and symbols. Targets that cannot build can still receive static and taint analysis.
- **Sixteen languages.** All use a shared coverage-guided engine. AFL++ is an optional
  adapter for native C/C++.
- **Legacy code.** Supports Ada 83, K&R C, pre-C++98, and Latin-1/Windows-1252 sources.
- **Offline operation.** No network access, telemetry, or automatic updates required.
- **Permissive core.** Apache-2.0, MIT, and BSD dependencies.

## What It Does

- **Fuzzing** — `bhf auto` across all sixteen languages, with build recovery, typed harness/stub
  generation, a coverage-guided engine (edge coverage + CmpLog/RedQueen), and an optional
  AFL++ adapter for native C/C++. → [auto.md](docs/site/auto.md)
- **Static analysis (SAST)** — `bhf static-scan` (or `auto --static`) runs an offline rule
  pack across eight of those languages (Ada, C, C++, Rust, Java, Python, Perl, Go) plus
  JavaScript/TypeScript, QML, and config/IaC, with taint traces and SARIF codeFlows; fuzzing
  then confirms static findings. → [static CWE coverage](docs/site/static-cwe-coverage.md)
- **SBOM / SCA** — multi-language SBOMs across 12 ecosystems (CycloneDX + OpenVEX) with
  offline CVE/VEX correlation.
- **Binary triage** — `bhf binary scan` / `binary fuzz` over ELF, PE, Mach-O, and raw
  firmware blobs — recursing into `ar` / Debian `.deb` packages and their compressed
  (`gzip`/`xz`/`zstd`) tar members — with source-unavailable crash replay, including
  AFL++ QEMU/Frida binary-only coverage.

Behavioral / taint oracles (path control, command injection, insecure temp, sensitive env) run
under the Linux runtime virtualization shim on native C/C++/Ada/Rust/Go/COBOL/Fortran
targets and the Python/Perl/Ruby/Lua/PHP interpreters. The shim is disabled for Java, C#, JavaScript/TypeScript, and cross/emulated targets.

## Quick Start

### Run in Docker

The Docker image includes all sixteen language toolchains and isolates the
target's build system from the host. It builds for Linux x86-64 or ARM64 and runs
through Docker Desktop on Windows and macOS.

```sh
git clone https://github.com/Tarmo-Technologies/bhf.git && cd bhf
docker build -t bhf:local -f Dockerfile .
docker run --rm --shm-size=2g --cap-add=SYS_PTRACE \
  -v "$PWD":/src:ro -v bhf_work:/work \
  bhf:local auto /src --work-dir /work/run --per-target-time 60
```

Use `--cap-add=SYS_PTRACE` for LeakSanitizer and `--shm-size=2g` for coverage/CmpLog
shared memory. Results are saved in the `bhf_work` Docker volume under `/work/run/results/`.
See the [Docker guide](docs/site/docker.md) for Compose setup and validation results.

### Install a prebuilt release

For a prebuilt release, use the [complete Linux bundle](#complete-linux-install-with-installsh)
or the [Windows installer](#windows-11--windows-server-quick-install).
The Linux bundle includes the CLI, daemon, both shims, and harness runtimes.
Install the compiler or interpreter for the languages you want to fuzz;
C/C++ needs `clang` and `make` (plus Visual Studio Build Tools on Windows).

After installing, start with one target:

```sh
bhf --version
bhf --help
bhf auto /path/to/source --work-dir /path/to/bhf_work \
  --jobs 1 --max-targets 1 --per-target-time 10
```

Keep the work directory outside the source tree. Read
`/path/to/bhf_work/results/INDEX.md` for findings and
`/path/to/bhf_work/auto/summary.txt` for what built, ran, or was skipped.
Use `bhf auto --help` for run limits, language selection, and build options.

### Build from source

You need Rust 1.88 or newer, plus the selected language's toolchain.
The Linux ARM64 runtime shim also requires `lld`:

```sh
git clone https://github.com/Tarmo-Technologies/bhf.git && cd bhf
cargo build --locked --release -p bhf -p bhf-daemon -p bhf_runtrace_shim -p bhf_cc_intercept
```

Run `auto` on a source tree:

```sh
./target/release/bhf auto path/to/src --work-dir bhf_work --per-target-time 60
```

BHF recovers build settings from `compile_commands.json`, supported build systems,
or `--build-command`. Findings go in `bhf_work/results/`; campaign and coverage
reports go in `bhf_work/auto/`.

### The recommended sweep

For a trusted source tree, start with this command. See the
[recommended sweep guide](docs/recommended-sweep.md) for sizing options.

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
| `--jobs 4` | Concurrent targets; budget `jobs × --rss-limit-mb` plus BHF, compiler, and OS memory. |
| `--per-target-time 60` | Fuzzing time per target, in seconds. |
| `--campaign-time 3600` | Hard cap on the whole sweep; no new targets start after it. |
| `--max-targets 40` | Stop after 40 targets have been fuzzed; failures do not count. |
| `--unsafe-search-and-run-build-commands` | Run the tree's build to recover compile flags. Trusted sources only. |
| `--force` | Retry unfuzzed targets with fabricated inputs and stubs; findings are marked low-confidence. |
| `--static` | Include whole-tree static analysis. |
| `--sbom` | Generate SBOM and VEX reports, marking exercised components. |
| `--sloc sloc.txt` | Per-language SLOC breakdown (`.json` for JSON). |
| `--debug` | Include a backtrace if BHF panics. |

### Where results go

Findings go in `<work-dir>/results/` (default `bhf_work/results/`):

| Path | What |
|---|---|
| `results/INDEX.md` | Summary and findings grouped by root cause |
| `results/findings.json` | Machine-readable findings (`bhf.findings.v1`; schema in `schemas/`) |
| `results/findings.csv` / `findings.sarif` | Spreadsheet / code-scanning views |
| `results/findings/<ID>/` | Evidence: `finding.json`, `testcase.bin`, `min_testcase.bin`, `sanitizer.log`, `replay.py` |
| `results/static/`, `results/sbom/` | Native `static-scan` and `sbom` reports |

`bhf report` rebuilds the index on demand.

Start with `results/INDEX.md` for findings, evidence, fixes, and replay commands.
Check `auto/summary.txt` for built-and-fuzzed, static-only, skipped, and forced targets.

Auto-runs cap each retained target corpus at 64 MiB and stop starting new targets
when the work directory reaches 4 GiB by default. Tune these with
`--max-corpus-mb` and `--max-work-dir-mb` (`0` disables only the work-directory
ceiling). BHF removes transient Rust Cargo caches automatically. Run `bhf clean bhf_work --compact`
to remove temporary files while keeping findings, corpora, reports, checkpoints,
and replay binaries.

### Watching and steering a live sweep

On a terminal, `auto` keeps a status block pinned below the scrolling results:

```text
phase 1/2 unforced   fuzzed  7/50 ██░░░░░░░░░░░░  attempts 213/26409   6m12s · eta ~38m
7 fuzzed · 118 failed-build · 88 skipped   2 finding(s)   top blocker: missing header X (c) (61)
jobs 3/16 · cap 50 · target-time 1m00s · force off · verbose off   cpu 42%   rss 1.2 GB/9.0 GB
keys: [q] stop & report · [p] pause · [+/-] jobs · [{/}] cap · [</>] target-time · [f] force · [v] verbose · [?] help
now  H-C0042            mz_compress            c      building (retry 1) 9s
     H-C0051            mz_crc32               c      fuzz:cmplog 14s/1m00s  8.1k execs 512/s  318 edges  last edge 4s
```

The block shows progress, build failures, resource usage, and active targets.
`last edge` and `last find` show time since new coverage or a finding.
Progress counts fuzzed targets with `--max-targets`, or candidates otherwise.

### Steering a run from the keyboard

Press `?` for keyboard help.

| Key | Effect |
|---|---|
| `q` | Stop after active targets finish, write reports, and skip forced phase 2. |
| `p` | Pause or resume starting new targets; active targets finish. |
| `+` / `-` | Adjust `--jobs` between 1 and the CPU core count. |
| `]` / `[` | Adjust `--max-targets` by 10%, never below the number already fuzzed. An uncapped run can be capped. |
| `>` / `<` | Adjust `--per-target-time` by 25% for subsequent targets. Unavailable when `--campaign-time` controls the budget. |
| `f` | Enable or disable forced phase 2 during phase 1, even without `--force`. |
| `v` | Toggle per-target details. |
| `?` | Expand or close the key legend; any action key also closes it. |

Discovery and build options such as `--sanitizers`, `--cxx-std`, and
`--build-command` cannot change mid-run. Ctrl-C aborts without writing a final
report. Piped output uses static per-target lines; `--verbose` adds a heartbeat
every 30 seconds.

### Resume an interrupted `auto` campaign

`bhf auto` saves each completed target. To resume, repeat the original command
with the same source tree, work directory, and campaign options, adding `--resume`:

```sh
./target/release/bhf auto path/to/src \
  --work-dir bhf_work \
  --per-target-time 60 \
  --resume
```

Completed targets are skipped and included in the new report. Findings and corpora
are retained; interrupted targets restart from the beginning.

Completed results are reused only if both remain unchanged:

- **Source:** targetable source files and the directory filter.
- **Build context:** `compile_commands.json`, GNAT projects (`.gpr`), IDL files,
  and harness options, including project selection, decoder limits, stubbing,
  engines/passes, and sanitizers.

Changes to either cause all targets to be retried. Documentation-only edits do
not invalidate a resume. Resume requires a compatible BHF build; do not
combine it with `--fresh-discovery` or `--no-discovery-cache`.

See the [installation guide](docs/site/install.md) for prebuilt binaries, per-language
toolchains, offline/air-gapped install, and Windows.

### Which release files do I need?

The full Linux bundle (`bhf-dist-*.tar.gz`) includes `install.sh`, the CLI,
daemon, both shims, harness runtimes, a checksum-verified content pack, and
installation and usage guides. Component installers download their matching
archives automatically; choose the installer or the archive.

| What you want to do | Install or download |
|---|---|
| Install complete BHF on Linux with one `install.sh` | `bhf-dist-0.3.0-x86_64-unknown-linux-gnu.tar.gz` plus its `.sha256` and `.sig` files |
| Run the CLI on Windows | `bhf-installer.ps1`, or `bhf-x86_64-pc-windows-msvc.zip` plus its `.sha256` file for a manual/offline install |
| Run basic CLI workflows on Linux | `bhf-installer.sh`, or `bhf-x86_64-unknown-linux-gnu.tar.xz` plus its `.sha256` file |
| Get the full Linux `bhf auto` runtime audit and fake-resource support | Add `bhf_runtrace_shim-installer.sh`, or its matching `bhf_runtrace_shim-*.tar.xz` archive |
| Recover complex C/C++ builds that use `--probe-build` or `--build-command` | Add `bhf_cc_intercept-installer.sh`, or its matching `bhf_cc_intercept-*.tar.xz` archive |
| Use the IDE, JSON-RPC, or read-only MCP service | Add the OS-appropriate `bhf-daemon-installer.sh` / `.ps1`, or the matching daemon archive |
| Audit or rebuild the release source | `source.tar.gz` plus `source.tar.gz.sha256`; this is not needed to run a prebuilt release |
| Automate or verify downloads | The archive's `*.sha256` sidecar, or `sha256.sum` for all archives; `dist-manifest.json` is machine-readable component-release metadata |

For a full Linux installation, use the bundle or place `bhf` and both shims
in the same directory. On Windows, install the CLI; add the daemon for IDE/MCP
use. The shims are Linux-only. See [INSTALL.md](INSTALL.md) for details.

#### Complete Linux install with `install.sh`

The full bundle includes the CLI, daemon, shims, harness runtimes, and a signed
content pack containing analysis rules, vulnerability databases, and seed inputs.
Installing the content pack requires three files:

- **Verification script:** save [verify-offline-dist.py](scripts/verify-offline-dist.py)
  from this repository as `verify-offline-dist.py` in your download directory.
- **Publisher public key:** ask the BHF release maintainers, or whoever supplied
  your bundle, for its signing public key and key ID. The key verifies that the
  bundle was signed by that publisher. Save the supplied 64-character hexadecimal
  key as `publisher.pub`. Confirm it through an established contact or your
  organization's software administrator, independently of the bundle download.
- **Trust policy:** create `operator-policy.json` in your download directory using
  the template below. Replace both placeholders with the supplied key ID and
  public key. This tells the installer which publisher's content signatures to accept.

```json
{
  "schema_version": "bhf.policy.v1",
  "policy_id": "local-install",
  "update_packs": {
    "require_signature": true,
    "trusted_public_keys": {
      "REPLACE_WITH_KEY_ID": "REPLACE_WITH_64_CHARACTER_PUBLIC_KEY"
    }
  }
}
```

Keep these files outside the extracted bundle. Verification needs Python 3.8+
and OpenSSL with Ed25519 support; on RHEL 7, verify on a newer host or use a
newer OpenSSL installation. From your download directory:

```sh
VERSION=0.3.0
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

The installer prompts for language toolchains, targets, fuzzers, and optional
extras, then runs a bundled C smoke test. Run `./install.sh --help` for
non-interactive, custom-prefix, offline, and smoke-test controls.

#### Manual Linux component co-location

After verifying and extracting the three matching Linux `.tar.xz` archives,
copy both shims beside the CLI:

```sh
CLI_DIR=bhf-x86_64-unknown-linux-gnu

install -m 0755 \
  bhf_runtrace_shim-x86_64-unknown-linux-gnu/libbhf_runtrace_shim.so \
  "$CLI_DIR/"
install -m 0755 \
  bhf_cc_intercept-x86_64-unknown-linux-gnu/libbhf_cc_intercept.so \
  "$CLI_DIR/"

"./$CLI_DIR/bhf" --version
```

Run from that directory or copy it intact to a permanent prefix. If the shims
must remain elsewhere, set `BHF_RUNTRACE_SHIM` and
`BHF_CC_INTERCEPT` to their absolute paths. The complete download,
checksum, optional-daemon, and user-local prefix commands are in
[INSTALL.md](INSTALL.md).

### Supported release platforms

The CLI and daemon support **64-bit Windows** and **64-bit GNU/Linux**:

| Family | Supported versions | Validation |
|---|---|---|
| RHEL | 7, 8, 9, and 10 | EL7 ABI gate plus native C scan/build/fuzz runs on CentOS 7.9 and AlmaLinux 8.10, 9.8, and 10.2 |
| Ubuntu LTS | 22.04, 24.04, and 26.04 | Native release-binary scan/build/fuzz jobs on every listed LTS |
| Windows x64 | Windows 11 Enterprise 25H2; Windows 11 Enterprise LTSC 2024 (24H2 codebase); Windows Server 2019, Windows Server 2022, and Windows Server 2025 | Native MSVC binaries plus real C scan/build/fuzz runs |

The Linux artifact is built in a pinned manylinux2014 environment and
CI-enforced to require no newer than glibc 2.17. RHEL-compatible guests are used
when licensed Red Hat media is unavailable; this is a compatibility claim, not
Red Hat certification. RHEL 7 needs Software Collections LLVM 7.0 for the C/C++
fuzzing lane because its stock Clang 3.4 lacks the required SanitizerCoverage;
BHF detects and activates that toolset automatically. See the
[installation guide](docs/site/install.md) for the full OS matrices and
prerequisites.

#### RHEL 7 quick install

For C/C++ fuzzing on RHEL 7, install the compiler prerequisites first:

```sh
sudo subscription-manager repos --enable rhel-server-rhscl-7-rpms
sudo yum install -y curl tar xz gcc gcc-c++ make \
  llvm-toolset-7.0-clang llvm-toolset-7.0-compiler-rt
```

Then install the full bundle above, or use the component installers for the CLI
and shims:

```sh
VERSION=0.3.0
BASE="https://github.com/Tarmo-Technologies/bhf/releases/download/${VERSION}"

curl --proto '=https' --tlsv1.2 -LsSf "$BASE/bhf-installer.sh" | sh
curl --proto '=https' --tlsv1.2 -LsSf "$BASE/bhf_runtrace_shim-installer.sh" | sh
curl --proto '=https' --tlsv1.2 -LsSf "$BASE/bhf_cc_intercept-installer.sh" | sh
```

BHF discovers and activates LLVM Toolset 7 automatically; no interactive
`scl enable` shell is needed. Other language lanes need their corresponding
toolchains from an organization-approved repository or offline package mirror.

#### Windows 11 / Windows Server quick install

The PowerShell release installers install the native x64 CLI and daemon only.
For C/C++ fuzzing on Windows 11 Enterprise 25H2, Windows 11 Enterprise LTSC
2024, Windows Server 2019, Windows Server 2022, or Windows Server 2025, first
install LLVM, VS 2022 Build Tools/Windows SDK, and GNU make from
an elevated PowerShell. One Chocolatey-based setup is:

```powershell
choco install llvm make visualstudio2022buildtools `
  visualstudio2022-workload-vctools -y

$Version = "0.3.0"
$Base = "https://github.com/Tarmo-Technologies/bhf/releases/download/$Version"
irm "$Base/bhf-installer.ps1" | iex
irm "$Base/bhf-daemon-installer.ps1" | iex       # optional: RPC/MCP service
```

Start a new **x64 Developer PowerShell for VS 2022** after tool installation.
See the [Windows guide](docs/site/windows.md) for `winget`/w64devkit alternatives,
Visual Studio environment initialization, and native-Windows lane limits.

### Selected language installations

All sixteen languages are enabled by default. Container `--languages` controls
installed toolchains,
while `bhf auto --languages` controls only the current run. For example:

```sh
scripts/build-container-release.sh bhf:java-python --languages java,python
```

For a native bundle:

```sh
./install.sh --non-interactive --no-content --languages java,python
```

See [selection and dependency details](docs/site/docker.md#installation-selection-versus-run-selection).

## Resource Requirements

RAM requirements depend on target size, sanitizers, input limits, and concurrency:

| Workload | RAM | Suggested settings |
|---|---:|---|
| Small repository or PR/diff-scoped run | 4 GiB minimum | `--jobs 1`; keep the default harness RSS cap |
| Whole-tree run on a large repository | 8 GiB practical minimum | `--jobs 1 --rss-limit-mb 1536`; static `--jobs 2 --max-memory-mb 4096` |
| 10M+ SLOC with static analysis/build recovery | 16 GiB recommended | Start with `--jobs 2`; increase only after measuring peak RSS |
| Parallel sanitizer campaigns | 32 GiB+ recommended | Size from measured target RSS and leave parent/OS headroom |

`--rss-limit-mb` caps each fuzz child, not the whole run. Budget at least
`jobs × rss-limit-mb` for children **plus** BHF's discovery/index/report data,
compiler processes, and the OS. On an 8 GiB machine, use a serial bounded sweep:

```sh
BHF_STATIC_JOBS=2 BHF_MAX_MEMORY_KB=4194304 \
  bhf auto path/to/10m-sloc-tree \
  --jobs 1 --rss-limit-mb 1536 --max-targets 500 \
  --single-pass --campaign-time 3600
```

For `bhf static-scan`, the equivalent controls are `--jobs 2
--max-memory-mb 4096`. Linux static scans also respect cgroup memory limits and
record an analysis gap when the RSS ceiling is reached. By default, the static
ceiling is the smaller of 80% of available host RAM and 70% of the cgroup limit.
`auto` also sizes its per-harness RSS allowance from available memory.

Corpus, source-file, and captured-output limits scale with available memory.
See the [scaling guide](docs/site/auto.md#scaling-to-large-trees) for defaults and
`BHF_MAX_*` overrides. On constrained hosts, omit `--sarif` to reduce report memory.

## LLM Assistance (Optional)

LLM support is excluded from default builds and prebuilt releases. To enable it,
build from source with:

```sh
cargo build --locked --release -p bhf -p bhf-daemon \
  --features bhf/llm,bhf-daemon/llm
```

BHF supports Codex and Claude CLIs, OpenAI and Anthropic APIs, and local
OpenAI-compatible servers. With `bhf-daemon --mcp`, your existing Codex or Claude
session calls BHF tools without a separate API token. Direct CLI calls use the
provider's cached login in a temporary session.

```sh
./target/release/bhf llm status --json
./target/release/bhf llm test --provider codex
./target/release/bhf llm test --provider claude
./target/release/bhf llm prompt --task diagnose-error --input bhf_work/auto/run.json
```

LLM suggestions are checked against build, reachability, coverage, replay, and
minimization results. API keys are read from environment variables; provider and
evidence buffers have configurable memory limits. See the
[LLM assistance guide](docs/site/llm.md) for setup, workflows, and privacy details.

## Run bhf on every pull request

Fuzz changed files on each pull request:

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

The action diff-scopes the run to changed files, uploads SARIF for inline code-scanning
annotations, posts a sticky summary comment, and fails only on a fuzz-confirmed finding. See
[docs/site/ci.md](docs/site/ci.md).

## Commands

| Command | What it does |
|---|---|
| `bhf auto <src>` | Discover, harness, build, and fuzz a whole tree |
| `bhf auto <src> --static` | Fold a whole-tree SAST pass into the run |
| `bhf auto <src> --engine afl++` | Fuzz recovered native C/C++ targets with AFL++ |
| `bhf auto <src> --force` | Retry unfuzzed C/C++/Ada, Go, and C# targets with fabricated parameters and stubs; low-confidence findings |
| `bhf auto <src> --differential clang:gcc` | Two-compiler differential (C/C++): flag inputs where the clang and gcc builds diverge (BHF-301) |
| `bhf ci <src> --changed-since <ref>` | Fuzz changed files, emit SARIF, and fail on confirmed findings |
| `bhf static-scan <src> --sarif` | Offline SAST only (JSON/Markdown/SARIF) |
| `bhf sbom <src> --vuln-db <db>` | SBOM + offline CVE/VEX correlation |
| `bhf binary scan <bin>` | Inventory + hardening triage for ELF/PE/Mach-O/firmware; recurses into `ar`/`.deb` + tar archives |
| `bhf binary fuzz <bin>` | Fuzz a source-unavailable executable (builtin, or AFL++ QEMU mode) |
| `bhf sloc <src>` | Fast per-language SLOC count |
| `bhf generate-harness <file> --target <fn>` | Generate one harness by hand |
| `bhf llm status\|test\|prompt\|assist` | Optional LLM assistance; MCP is served by `bhf-daemon --mcp` |

See the [CLI reference](docs/site/cli.md) or `bhf --help` for all commands.

## Documentation

- [Installation](docs/site/install.md) — from source, prebuilt binaries, offline, Windows.
- [Recommended sweep](docs/recommended-sweep.md) — starting command, flags, and resource sizing.
- [`bhf auto`](docs/site/auto.md) — campaigns, large trees, forced fuzzing, and static analysis.
- [Target ranking](docs/site/target-ranking.md) — scoring, weights, examples, and limitations.
- [PR-native CI](docs/site/ci.md) — the GitHub Action, diff-scoping, and the confirmed-findings gate.
- [C/C++ guide](docs/site/c-cpp.md) — prerequisites, supported parameter shapes, limits.
- [COBOL guide](docs/site/cobol.md) and [Fortran guide](docs/site/fortran.md) — translated/compiler lanes, coverage, oracles, and limits.
- [C# / .NET guide](docs/site/csharp.md) — .NET, SharpFuzz, and coverage.
- [JavaScript / Node.js guide](docs/site/javascript.md) — Node.js and V8 coverage.
- [CLI reference](docs/site/cli.md) — every subcommand.
- [Architecture](docs/site/architecture.md) — pipeline and crate boundaries.
- [Runtime virtualization](docs/site/runtime-virtualisation.md) — the LD_PRELOAD shim and replay envelope.
- [Cross-compilation](docs/site/cross-compilation.md) — qemu-user / wine backends and sandboxes.
- [Windows](docs/site/windows.md) — native install + Visual Studio solution fuzzing.
- [Offline deployment](docs/site/offline-deployment.md) — air-gapped install and content packs.
- [Offline Ada/C/C++ `auto` runbook](docs/site/offline-auto-runbook.md) — build recovery, dependencies, IDL code generation, and forced fuzzing.
- [LLM and MCP assistance](docs/site/llm.md) — providers, harness help, diagnostics, privacy, and validation.
- [Licensing](docs/site/licensing.md) — policy profiles and audits.
- Validation: [DoD-domain recovery](docs/validation/2026-06-15-dod-domain-recovery.md), [real code / broken builds](docs/validation/2026-06-08-real-code-broken-builds.md), [memory scaling](docs/validation/2026-07-20-memory-scaling-benchmarks.md), and [LLM/MCP paths](docs/validation/2026-07-20-llm-mcp-validation.md).

The engineering roadmap is in [ROADMAP.md](ROADMAP.md).

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the build, test, and
formatting/lint/SPDX gates, and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Security

Please report vulnerabilities **privately** via the repository's
[Security tab](https://github.com/Tarmo-Technologies/bhf/security/advisories/new), not a
public issue — see [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). The core links only Apache-2.0 / MIT /
BSD dependencies; user-installed GPL tools (FSF GNAT, GPRbuild, AFL++) may be driven as optional
subprocesses, never linked. See the [licensing matrix](ROADMAP.md#1-licensing-and-dependency-policy).
