<!-- SPDX-License-Identifier: Apache-2.0 -->
# Installing bhf

bhf is a Rust workspace. Building it also produces the runtime virtualisation shim (`libbhf_runtrace_shim.so`) and the build-time compiler interception shim (`libbhf_cc_intercept.so`) next to the binaries, where `bhf auto` locates them automatically. How much CPU, memory and disk a run needs, per lane and per tree size, is in the README's [Resource Requirements](../../README.md#resource-requirements).

## From source

Prerequisites:

- **Rust** 1.88 or newer. `rust-toolchain.toml` pins Rust 1.99.0, and `rustup` installs it on the first build.
- **`make`** and **`clang`/`clang++`** with SanitizerCoverage, ASan and UBSan support, to build and fuzz C and C++ with the built-in engine.

```sh
git clone https://github.com/Tarmo-Technologies/bhf.git
cd bhf
cargo build --release --workspace
./target/release/bhf --help
```

The binaries land in `target/release/` (`bhf`, `bhf-daemon`) next to `libbhf_runtrace_shim.so` and `libbhf_cc_intercept.so`. Put `bhf` on your `PATH`, or run `cargo install --path crates/cli`. `cargo install` installs only the binary, so then also build the shims with `cargo build --release -p bhf_runtrace_shim -p bhf_cc_intercept` and set `BHF_RUNTRACE_SHIM` and `BHF_CC_INTERCEPT` to their paths.

### Supported OS matrices

The published GNU/Linux release target is x86_64 and supports RHEL 7, 8, 9 and 10. Supported means three things: the release binaries keep to the EL7 glibc 2.17 ABI, the installer handles the `yum` or `dnf` family, and bhf can select a compiler with the sanitizer-coverage features it needs.

| Version | Release status | Package manager | C/C++ compiler | Validation evidence |
|---|---|---|---|---|
| RHEL 7 | Supported by the prebuilt x86_64 release | `yum` | Software Collections `llvm-toolset-7.0-clang`; stock Clang 3.4 is insufficient | CentOS 7.9 EL7-compatible Proxmox guest, glibc 2.17, SELinux enforcing |
| RHEL 8 | Supported by the prebuilt x86_64 release | `dnf` | AppStream Clang/LLVM | AlmaLinux 8.10 RHEL-compatible Proxmox guest, SELinux enforcing |
| RHEL 9 | Supported by the prebuilt x86_64 release | `dnf` | AppStream Clang/LLVM | AlmaLinux 9.8 RHEL-compatible Proxmox guest, SELinux enforcing |
| RHEL 10 | Supported by the prebuilt x86_64 release | `dnf` | AppStream Clang/LLVM | AlmaLinux 10.2 RHEL-compatible Proxmox guest, SELinux enforcing |

The validation guests run the binary-compatible distributions in the last column. The [EL7 validation record](../validation/2026-07-21-rhel7-proxmox.md), the [EL9 validation record](../validation/2026-07-20-rhel9-proxmox.md) and the [current-platform validation record](../validation/2026-07-21-current-platform-matrix.md) list the exact VMs and results.

The 64-bit ARM (`aarch64-unknown-linux-gnu`) component archives and installers build on the same glibc 2.17 baseline and are smoke-tested on an Ubuntu 24.04 ARM64 runner; the guest validation above is x86_64. Release 0.3.0 ships x86_64 Linux and Windows assets, so check a release's asset list for the ARM64 archives. Other architectures build from source.

The tested Ubuntu and Windows versions:

| Family | Supported x86_64 versions | Notes |
|---|---|---|
| Ubuntu LTS | 22.04, 24.04, 26.04 | The same EL7-baseline Linux artifact is scan/build/fuzz tested on every listed LTS. |
| Windows client | Windows 11 Enterprise 25H2; Windows 11 Enterprise LTSC 2024 (24H2 codebase) | Native `x86_64-pc-windows-msvc` CLI and daemon; C/C++ fuzzing also needs LLVM, VS Build Tools/Windows SDK, and GNU make. |
| Windows Server | Windows Server 2019, Windows Server 2022, Windows Server 2025 | Windows Server 2019 is the oldest supported Windows baseline; Windows Server 2022 and Windows Server 2025 are persistent CI environments. |

The tested matrix does not include Windows 10 or Windows Server 2016. See [Running bhf on Windows](./windows.md) for setup and for the features native Windows runs.

### Per-language toolchains

bhf fuzzes sixteen languages. Each lane needs its own toolchain, which you install only if you fuzz that language; a target whose toolchain is missing is skipped with a reason. On Debian or Ubuntu:

```sh
sudo apt-get update
sudo apt-get install -y make clang llvm                 # C/C++ (required to build/fuzz)
sudo apt-get install -y gnat gprbuild                   # Ada
sudo apt-get install -y default-jdk maven gradle        # Java
sudo apt-get install -y python3                         # Python (3.12+ for sys.monitoring coverage)
sudo apt-get install -y perl                            # Perl
sudo apt-get install -y golang-go                       # Go
rustup toolchain install nightly                        # Rust lane (sancov + ASan staticlib needs nightly)
sudo apt-get install -y gfortran                        # Fortran
sudo apt-get install -y gnucobol                        # COBOL (GnuCOBOL cobc)
sudo apt-get install -y nodejs npm                      # JavaScript / TypeScript (TS via esbuild)
sudo apt-get install -y ruby                            # Ruby
sudo apt-get install -y lua5.4                          # Lua
sudo apt-get install -y php-cli                         # PHP
# C#: install a .NET 8 SDK, then stage the instrumentation CLI (and its NuGet package offline if needed)
dotnet tool install --global SharpFuzz.CommandLine
sudo apt-get install -y afl++                           # optional: AFL++ engine (C/C++, COBOL, Fortran, Rust, Ada)
```

On RHEL 8, 9 or 10 and compatible distributions (AlmaLinux, Rocky Linux), the base and AppStream repositories provide the core build and most language toolchains:

```sh
sudo dnf install -y curl tar xz                         # release installer prerequisites
sudo dnf install -y gcc gcc-c++ make clang llvm lld    # source build + C/C++ fuzzing
sudo dnf install -y java-17-openjdk-devel maven        # Java
sudo dnf install -y python3 perl golang                # Python / Perl / Go
sudo dnf install -y gcc-gfortran                       # Fortran
sudo dnf install -y nodejs npm ruby lua php-cli        # interpreter lanes
rustup toolchain install nightly                       # Rust fuzzing lane
```

On RHEL 7, the released bhf binaries run against the system glibc 2.17. The stock Clang 3.4 cannot instrument bhf harnesses, so enable the Red Hat Software Collections repository approved for the host and install LLVM 7.0:

> The `bhf-installer.sh` release asset installs the CLI. Enable the repositories, install the packages below and install the Linux runtime shims yourself: prepare the host first, then run the component installers shown under [Prebuilt release binaries](#prebuilt-release-binaries).

```sh
sudo subscription-manager repos --enable rhel-server-rhscl-7-rpms
sudo yum install -y curl tar xz gcc gcc-c++ make \
  llvm-toolset-7.0-clang llvm-toolset-7.0-compiler-rt
```

bhf finds and activates `/opt/rh/llvm-toolset-7.0/root/usr` by itself; you do not need an `scl enable` shell.

RHEL 7 hosts need an active vendor or organisation package source, and CentOS 7 test hosts need an archive mirror because the original mirrorlist is retired. The stock EL7 linker is too old to link the current preload shim from source, so use the prebuilt release, or reproduce the release build in the pinned manylinux2014 image from `.github/workflows/release.yml`.

The standard RHEL repositories do not reliably carry GNAT and GPRbuild, GnuCOBOL, Gradle, AFL++, Wine and mingw, or foreign-architecture cross compilers. Enable an approved supplemental repository, or stage those tools separately, for the lanes that need them. The distribution installer uses `dnf` on RHEL and installs every selected dependency it can find; a missing optional package does not block the core C/C++ setup.

The full per-lane matrix lives in [offline-deployment.md](./offline-deployment.md#toolchains-on-the-offline-host). For Windows-native cross-fuzzing (mingw + wine) and foreign-arch fuzzing (qemu-user), see [cross-compilation.md](./cross-compilation.md).

### Optional LLM and agent integration

bhf needs no model, API key or network connection. The release binaries leave out the `llm` feature. Build with `--features bhf/llm,bhf-daemon/llm` to add the `bhf llm` assistance commands and the MCP prompt and preflight tools. Assistance then needs one of these:

- the `bhf-daemon` component and an MCP-capable agent host, for the current-session workflow;
- an installed, authenticated provider CLI, for a separate one-off request;
- a hosted-provider API credential in an environment variable, with an explicit model id; or
- a locally served OpenAI-compatible model endpoint.

`bhf llm status --json` lists the installed provider CLIs and the configured credentials without making a model call, and prints no credential values. `bhf llm test --provider <name>` makes a small live request. Read [LLM Assistance](./llm.md), which names the supported providers, before you register MCP or send source and findings to any provider.

## Prebuilt release binaries

GNU/Linux release artifacts are built in a pinned manylinux2014 (CentOS 7) userspace. CI rejects an artifact that needs a symbol newer than glibc 2.17, so the published binaries run on RHEL 7, 8, 9 and 10. A binary you build on a newer distribution can need a newer glibc; if the loader reports `GLIBC_2.xx not found`, use the published artifact or the same pinned build image.

GitHub releases ship an all-in-one Linux bundle with `install.sh`, plus per-component archives and installers. Use the all-in-one bundle for a complete Linux installation, or the components for a smaller layout you control. Each install needs only the assets in the table below.

The CLI archive carries every harness-runtime source tree. The CLI executable also embeds the same sources, and when the shell or PowerShell installer installed it, it stages a private copy by itself, so a prebuilt install needs no bhf source checkout. The copy goes to the user's cache, `$XDG_CACHE_HOME/bhf/runtime-<sha256>/` (else `~/.cache/bhf/…`, and `%LOCALAPPDATA%\bhf\…` on Windows), named by the content's digest. It stays there: generated harness Makefiles name it, and every later run of the same release reuses it. Set `BHF_FORCE_EMBEDDED_RUNTIMES=1` to use the embedded copy even when runtime directories sit beside the executable.

### Choose release assets by task

The all-in-one archive is self-contained, and its bundled `install.sh` installs every Linux runtime component. A component installer downloads and installs its own archive, so for each component download either the installer or the archive.

| Task | Required assets | Optional additions |
|---|---|---|
| Complete Linux install with one installer | Full bundle, `.sha256`, and detached `.sig`; verify before extraction, then run `./install.sh --trust-policy /trusted/operator-policy.json` | Independently supplied verifier, publisher key, and trust policy; the CLI, daemon, both shims, runtimes, and signed content are included |
| Windows CLI | `bhf-installer.ps1`, or `bhf-x86_64-pc-windows-msvc.zip` and its sidecar | `bhf-daemon-installer.ps1` or the daemon ZIP only for IDE/JSON-RPC/MCP use |
| Basic Linux CLI, scan, build, and fuzz | `bhf-installer.sh`, or `bhf-x86_64-unknown-linux-gnu.tar.xz` (`bhf-aarch64-unknown-linux-gnu.tar.xz` on 64-bit ARM) and its sidecar | Add the two Linux shims below for full runtime behavior and complex C/C++ build recovery |
| Full Linux `bhf auto` | The Linux CLI plus `bhf_runtrace_shim-installer.sh` (or its archive and sidecar) | Add `bhf_cc_intercept` when testing C/C++ projects with real build systems |
| Complex C/C++ `--probe-build` / `--build-command` recovery | Linux CLI plus `bhf_cc_intercept-installer.sh` (or its archive and sidecar) | Add the runtrace shim for runtime audit/fake-resource coverage too |
| Linux IDE/JSON-RPC/MCP service | The required Linux CLI/shims for the intended workload, plus `bhf-daemon-installer.sh` or its archive | None |
| Source audit or rebuild | `source.tar.gz` and `source.tar.gz.sha256` | The prebuilt runtime assets, only if you also run them |
| Automated component-release processing | `dist-manifest.json`; use `sha256.sum` to verify all archives or the matching `*.sha256` file for one archive | The GitHub Release asset list also includes the separately assembled all-in-one bundle |

What each optional component changes:

- `bhf_runtrace_shim` is Linux-only. It enables runtime environment auditing, the behavioural and taint oracles, and fake files, sockets and environment resources. Without it, bhf scans, builds and fuzzes, and warns that those runtime features are off.
- `bhf_cc_intercept` is Linux-only. It lets C/C++ build recovery observe compilers launched by absolute path or through `posix_spawn`. Most direct harness builds do not need it; complex `--probe-build` and `--build-command` workflows often do.
- `bhf-daemon` provides JSON-RPC and read-only MCP. The CLI does not use or require the daemon for ordinary terminal runs.
- `source.tar.gz`, `dist-manifest.json` and the checksum files are data; keep them out of `PATH`.

The recommended full Linux install is the all-in-one bundle. Its manual equivalent is the CLI plus both shims, with the daemon when you need it. On Windows, install the CLI, and the daemon for IDE or MCP use; the two shims are Linux-only.

### Complete Linux installation with the bundled `install.sh`

Obtain the verifier (`scripts/verify-offline-dist.py`), the publisher's public key and your operator policy through a trusted channel that is independent of the archive. Verification needs Python 3.8 or newer and an OpenSSL with Ed25519 support; on EL7, use an approved newer OpenSSL or a separate verification host. Set `VERSION` to the release you received. The example uses 0.4.0.

```sh
VERSION=0.4.0
BASE="https://github.com/Tarmo-Technologies/bhf/releases/download/${VERSION}"
ARCHIVE="bhf-dist-${VERSION}-x86_64-unknown-linux-gnu.tar.gz"

curl --proto '=https' --tlsv1.2 -fLO "$BASE/$ARCHIVE"
curl --proto '=https' --tlsv1.2 -fLO "$BASE/$ARCHIVE.sha256"
curl --proto '=https' --tlsv1.2 -fLO "$BASE/$ARCHIVE.sig"
sha256sum -c "$ARCHIVE.sha256"
python3 /trusted/verify-offline-dist.py \
  --archive "$ARCHIVE" --signature "$ARCHIVE.sig" \
  --trusted-public-key /trusted/publisher.pub \
  --verified-copy bhf-verified.tar.gz
tar xzf bhf-verified.tar.gz
cd "${ARCHIVE%.tar.gz}"
./install.sh --trust-policy /trusted/operator-policy.json
```

The interactive installer asks which language toolchains, compile targets, fuzzers and optional extras to install. It installs to `/opt/bhf` by default and creates `bhf` and `bhf-daemon` symlinks in `/usr/local/bin`. For automation:

```sh
./install.sh --non-interactive --trust-policy /trusted/operator-policy.json \
  --languages c,cpp,rust \
  --targets native \
  --fuzzers builtin \
  --extras build-recovery,archives
```

On an offline host with the dependencies already staged, add `--no-system-packages --no-rustup`. `./install.sh --help` lists the options for the prefix, seed corpus, content packs, symlinks and smoke test.

### Connected component-installer alternative

```sh
VERSION=<latest release tag>
BASE="https://github.com/Tarmo-Technologies/bhf/releases/download/${VERSION}"

curl --proto '=https' --tlsv1.2 -LsSf "$BASE/bhf-installer.sh" | sh
curl --proto '=https' --tlsv1.2 -LsSf "$BASE/bhf_runtrace_shim-installer.sh" | sh
# Optional, recommended for C/C++ build recovery on real projects:
curl --proto '=https' --tlsv1.2 -LsSf "$BASE/bhf_cc_intercept-installer.sh" | sh
```

Those three installers place `bhf`, `libbhf_runtrace_shim.so`, and `libbhf_cc_intercept.so` together in `$CARGO_HOME/bin` or `$HOME/.cargo/bin`. The daemon has its own optional installer.

### Manual component-archive co-location

Verify each selected archive with its sidecar, extract it, and copy both Linux libraries into the CLI directory. On 64-bit ARM, use the `aarch64-unknown-linux-gnu` archives in place of `x86_64-unknown-linux-gnu`; the shell installers pick the archive for the host's architecture themselves.

```sh
sha256sum -c bhf-x86_64-unknown-linux-gnu.tar.xz.sha256
sha256sum -c bhf_runtrace_shim-x86_64-unknown-linux-gnu.tar.xz.sha256
sha256sum -c bhf_cc_intercept-x86_64-unknown-linux-gnu.tar.xz.sha256

tar xf bhf-x86_64-unknown-linux-gnu.tar.xz
tar xf bhf_runtrace_shim-x86_64-unknown-linux-gnu.tar.xz
tar xf bhf_cc_intercept-x86_64-unknown-linux-gnu.tar.xz

CLI_DIR=bhf-x86_64-unknown-linux-gnu
install -m 0755 \
  bhf_runtrace_shim-x86_64-unknown-linux-gnu/libbhf_runtrace_shim.so \
  "$CLI_DIR/"
install -m 0755 \
  bhf_cc_intercept-x86_64-unknown-linux-gnu/libbhf_cc_intercept.so \
  "$CLI_DIR/"

"./$CLI_DIR/bhf" --version
```

Run it in place, or copy the whole directory to a permanent prefix. If policy keeps the libraries elsewhere, set `BHF_RUNTRACE_SHIM` and `BHF_CC_INTERCEPT` to absolute paths.

A prefix with a space or colon in it (`/opt/Program Files (x86)/bhf`) also works. `LD_PRELOAD` splits paths on those characters, so bhf preloads a copy of the runtrace shim staged in the run's work directory (`<work>/.bhf-runtime/`) or in `$TMPDIR/bhf-shim-<uid>-<hash>/`. It uses only a directory private to the account running bhf (owned by it, mode `0700`), so no other local user can plant the library it preloads. It reuses a staged copy only while its bytes match the shim and replaces any other file there. When no such directory is usable, it warns once and runs without the shim. Every component archive includes an `INSTALL.md` with these commands and the optional daemon and user-local layouts.

## Native Windows release or build

Releases include `bhf-x86_64-pc-windows-msvc.zip`, `bhf-daemon-x86_64-pc-windows-msvc.zip`, their SHA-256 sidecars, and native PowerShell installers. For example:

```powershell
$Version = "0.4.0"
irm "https://github.com/Tarmo-Technologies/bhf/releases/download/$Version/bhf-installer.ps1" | iex
bhf.exe --version
```

The release executables need no Rust toolchain. To compile and fuzz native C and C++ targets you need LLVM, Visual Studio Build Tools and GNU make; see [windows.md](./windows.md).

To build from source instead:

```sh
rustup target add x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc -p bhf
# -> target/x86_64-pc-windows-msvc/release/bhf.exe
```

`bhf.exe` runs the pipeline on Windows: discovery, clang harness builds (edge coverage, CmpLog, ASan and UBSan), coverage-guided fuzzing and crash detection, including Visual Studio solutions (`.sln`, `.vcxproj`) through `--probe-build`. See [windows.md](./windows.md) for the full guide and the native sanitizer matrix.

## macOS (Apple Silicon) from source

Releases include no macOS binaries. bhf builds and fuzzes natively on Apple Silicon (`aarch64-apple-darwin`): CI builds it on a `macos-15` runner and checks that `bhf auto` finds a planted C overflow there. You need Rust and the Xcode Command Line Tools (`xcode-select --install`), whose `clang` and `make` build the C/C++ harnesses with AddressSanitizer, UBSan and SanitizerCoverage:

```sh
git clone https://github.com/Tarmo-Technologies/bhf.git && cd bhf
cargo build --locked --release -p bhf
./target/release/bhf auto path/to/src --work-dir bhf_work --per-target-time 60
```

The runtrace shim is an `LD_PRELOAD` library for Linux, so on macOS native harnesses run without it: bhf runs no behavioural sink oracles there and records no files, environment variables or network use. `run.json` and every finding say so: the target's `behavioral_oracles` is `off`, its `fidelity.runtime_shim` is `not_exercised` with the reason, and the finding's `runtime_mode.shim_armed` is `false`. Coverage, CmpLog, the fork-server and the sanitizers work as on Linux. macOS does not enforce `--rss-limit-mb`. The Linux toolchain lanes, including the shim, run on a Mac through Docker Desktop ([docker.md](./docker.md)).

## Offline / air-gapped install

bhf runs with no network access and never updates itself. To install or update it on a disconnected machine, do one of these, then stage the harness build and fuzz toolchains and the checksum-verified content packs:

- build a binary-only offline tarball (`scripts/package-offline-dist.sh`);
- transfer published or source-built binaries; or
- transfer the source and build on the offline host.

[offline-deployment.md](./offline-deployment.md) is the full guide: the binary-only package flow, the build-or-transfer decision, which artifacts to move, glibc and architecture matching for the runtrace shim, the `cargo vendor` offline build, toolchain staging, staging harness dependencies across the air gap (`--deps-only`, `--install-deps`), and rules, CVE and corpus pack updates.

## Verify the install

Run `auto` on a source tree that ships with the repository. The C example needs `clang` and `make`; the Ada example also needs GNAT and GPRbuild. `--per-target-time` is the **total** fuzz budget per target, in **seconds**.

```sh
# Real C library (miniz)
bhf auto tests/fixtures/build_recovery/fixtures/miniz --work-dir /tmp/bhf-miniz --per-target-time 10

# Ada example (needs the Ada toolchain)
bhf auto examples/swallowed_constraint_error --work-dir /tmp/bhf-ada --per-target-time 10
```

When the sweep finishes, it prints a summary (duration, outcome breakdown, file and language counts, findings, executions, throughput, coverage edges and where each output landed) and writes it to `<work-dir>/auto/summary.txt`. The detailed reports start at `<work-dir>/results/INDEX.md` and `<work-dir>/results/findings.csv`; campaign and coverage details are in `<work-dir>/auto/run.md` and `run.json`.

If the summary has a `⚠ WARNING: N target(s) fuzzed STUB-ONLY` line, those targets ran blind stubs instead of real library code, so a clean result for them is a **false clean**. Check the `stub_execution` block in `run.json` before you rely on it.

See [auto.md](./auto.md) for the full `bhf auto` reference, including scaling to large trees, force-fuzz mode, and static-analysis integration.

### Selected language installations

All sixteen languages are installed by default; the `llm` feature is opt-in at build time. The container's `--languages` selects the toolchains to install, and `bhf auto --languages` selects the languages for one run. For example:

```sh
scripts/build-container-release.sh bhf:java-python --languages java,python
```

For an extracted native bundle:

```sh
./install.sh --non-interactive --no-content --languages java,python
```

See [selection and dependency details](docker.md#installation-selection-versus-run-selection) for aliases, conflicts, shared dependencies, engine opt-outs and the recorded test runs.
