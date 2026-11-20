<!-- SPDX-License-Identifier: Apache-2.0 -->

# Offline / Air-Gapped Deployment & Updates

bhf runs with no network access. This page covers installing and updating
bhf on a disconnected (air-gapped) machine, including the choice between
building on a connected machine and transferring the binaries, or
transferring the source and building on the offline host.

bhf fuzzes sixteen languages (Ada, C, C++, Rust, Java, Python, Perl, Go,
COBOL, Fortran, C#, JavaScript, TypeScript, Ruby, Lua and PHP), and each
needs its own toolchain on the offline host; see
[Toolchains on the offline host](#toolchains-on-the-offline-host).

bhf has no auto-updater and makes no network call of its own. You update it
by transferring a new package yourself. If you build from a private source
checkout and do not want to hand the checkout to the destination user, use
the binary-only distribution flow below.

---

## Decision: build-and-transfer, or transfer-and-build?

| | **Model A: transfer binaries** | **Model B: transfer source, build offline** |
|---|---|---|
| You move | The built `bhf`, `bhf-daemon`, runtrace shim and compiler-interception shim | The repository plus a vendored crate cache |
| Offline host needs Rust? | **No** | **Yes** (the version `rust-toolchain.toml` pins) |
| Binary/host match | You must match OS, CPU architecture and glibc | Exact: built on the host itself |
| Best when | The offline host's OS and architecture are known and match a build host or release target | The offline host's libc or architecture is unusual, hardened or unknown |

Both models also need the build and fuzz toolchains (`clang`, `make`,
optionally GNAT) on the offline host; see
[Toolchains on the offline host](#toolchains-on-the-offline-host). Those
build the generated harnesses, which is separate from building bhf itself.

## Optional LLM assistance in an enclave

The deterministic bhf workflow needs no model and makes no network request.
On a host that must stay air-gapped, do not configure the `openai`,
`anthropic`, `codex` or `claude` providers. If local policy permits model
assistance, transfer approved model weights separately and point
`--provider local --model <id> --base-url <local-openai-compatible-url>` at
an endpoint inside the enclave. bhf's distribution bundles no weights and no
model server.

`bhf-daemon --mcp` can also serve its read-only tools locally. The MCP host
must then itself use an enclave-approved local model, because the MCP
transport does not make a cloud-backed host offline. Review prompts, code,
logs, findings and MCP transcripts as controlled data. See
[LLM Assistance](llm.md) for the provider, agent, memory and privacy
boundaries.

---

## Model A: obtain or build on a connected host, transfer binaries

This is the simplest path and the recommended default.

### A0. Build a binary-only distribution package from source

Use this when you have the source on a build machine but the destination
should receive only an installable package. The package does not include the
bhf application source tree. It does include the harness runtime support
files that generated harnesses and interpreter drivers need at build and run
time.

The package contains:

- `tool/bhf`, `tool/bhf-daemon`, the runtrace shim, the
  compiler-interception shim and `tool/bhf-bug-report`;
- `tool/c_runtime`, `tool/ada_runtime`, `tool/java_runtime`,
  `tool/python_runtime`, `tool/perl_runtime`, `tool/crates/rust_runtime`,
  `tool/csharp_runtime`, `tool/js_runtime`, `tool/ruby_runtime`,
  `tool/lua_runtime` and `tool/php_runtime`;
- `content/packs/current/update-pack.json`, a content pack, signed when
  signing inputs are supplied;
- `content/bhf-policy.json`, content policy metadata (not a publisher trust
  anchor);
- `smoke/c/bhf_smoke.c`, a small post-install `bhf auto` fixture;
- `install.sh`, the interactive and update-safe installer;
- `README.md`, `LICENSE`, `RELEASE_NOTES.md`, `VERSION`, and the guides
  `README-DIST.md`, `INSTALL.md` and `RUN-BHF.md` (install choices and
  running after install), `AUTO-OFFLINE-RUNBOOK.md` and
  `RECOMMENDED-SWEEP.md`.

The content pack carries these pack kinds:

| Pack kind | Files | Purpose |
|---|---|---|
| `rules` | `rules/static.json` | The finding and static-analysis rule catalog, as `bhf rules list --json` exports it |
| `cve` | `cve/sbom-cves.json` | Offline CVE/SCA database for `bhf sbom --vuln-db` |
| `cve` | `cve/binary-cves.json` | Offline binary component and CVE database for binary scanning |
| `corpus` | `corpus/seeds.tar.gz` | Optional shared seed corpus |

CWE IDs and mappings in rule metadata and vulnerability output are built into
bhf and the bundled rule catalog; there is no separate CWE pack.

On the **build machine**:

```sh
# Toolchain bootstrap from the README install section, if not already present:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
sudo apt-get update
sudo apt-get install -y make clang llvm

# Optional, if this build machine also runs the smoke tests:
sudo apt-get install -y gnat gprbuild default-jdk maven gradle python3 perl golang-go afl++ \
  gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 wine64 \
  qemu-user gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
rustup toolchain install nightly

# From the bhf source checkout. Generate a publisher key once, and give its
# public half to receiving hosts through an independent trusted channel.
mkdir -m 700 keys
cargo run --release -p bhf -- pack keygen \
  --private-key keys/publisher.der --public-key keys/publisher.pub
# Omitted CVE DB and seed inputs are generated under dist/content-inputs/.
scripts/package-offline-dist.sh \
  --signing-key keys/publisher.der --key-id publisher-v1 \
  --trusted-public-key keys/publisher.pub

# Transfer the archive, its detached .sig and its .sha256 sidecar:
sha256sum -c dist/bhf-dist-*.tar.gz.sha256
```

The generated input files are:

```text
dist/content-inputs/sbom-cves.json
dist/content-inputs/binary-cves.json
dist/content-inputs/seeds/
```

The generated CVE databases are valid and empty, so the SBOM and binary-CVE
workflows run but report no CVE matches. For CVE matching in the packaged
content, replace those files with your real feed data and rerun
`scripts/package-offline-dist.sh` with the same signing inputs.

Keep the private key outside the distribution output. For a deliberate
checksum-only package, pass `--legacy-integrity-only`. Such a package does
not authenticate the publisher, and the destination must opt in to it
explicitly.

On the **destination machine**:

```sh
# A checksum sidecar from the same channel does not authenticate the
# publisher. Authenticate the whole tarball, with an installer and verifier
# obtained out of band, before running any bundle code. Separately provision
# operator-policy.json with update_packs.require_signature=true and a
# trusted_public_keys map.
sha256sum -c bhf-dist-*.tar.gz.sha256
bash /trusted/verify-offline-dist.sh \
  --archive bhf-dist-<version>-<triple>.tar.gz \
  --signature bhf-dist-<version>-<triple>.tar.gz.sig \
  --trusted-public-key /trusted/publisher.pub
tar xzf bhf-dist-*.tar.gz
cd bhf-dist-*

# Interactive arrow-key install:
./install.sh --trust-policy /trusted/operator-policy.json

# Or install or update everything non-interactively:
./install.sh --non-interactive --trust-policy /trusted/operator-policy.json \
  --languages all \
  --targets native,windows,aarch64 \
  --fuzzers builtin,afl \
  --extras build-recovery,sandbox,archives
```

The installer defaults to `/opt/bhf` and symlinks `bhf` into
`/usr/local/bin`. It backs up an existing install to
`/opt/bhf.backup.<timestamp>`, keeps the existing `packs/` and `corpora/`,
authenticates the content pack against the external policy, and installs it
under `/opt/bhf/packs/<pack_id>`. It then runs a small C `bhf auto` smoke
test on the bundled `smoke/c` fixture to check discovery, harness
generation, build, fuzz execution and reporting. Run `./install.sh --help`
for `--prefix`, `--bin-dir`, `--package-manager`, `--no-system-packages`,
`--no-rustup`, `--no-content`, `--install-seeds`, `--no-smoke` and the other
automation controls.

On a fully air-gapped destination, stage the apt/dnf and rustup toolchains
through your normal offline mirror first, then run the installer with
`--no-system-packages` and/or `--no-rustup`. The older `--no-apt` spelling
is a compatibility alias of `--no-system-packages`.

### A1. Use the published all-in-one bundle (preferred)

The release publishes `bhf-dist-<version>-x86_64-unknown-linux-gnu.tar.gz`
with its detached `.sig` and `.sha256` sidecars. The bundle is x86_64 only;
for a 64-bit ARM host, use the component archives below. It contains
`install.sh`, the CLI, the daemon, the runtrace shim, the
compiler-interception shim, the harness runtimes, the content pack and the
smoke fixture. No source checkout or component assembly is needed.

On the **connected** host:

```sh
gh release download vX.Y.Z --repo Tarmo-Technologies/bhf \
  --pattern 'bhf-dist-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz*'

# Authenticate the complete archive with a verifier from a trusted channel.
sha256sum -c bhf-dist-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz.sha256
bash /trusted/verify-offline-dist.sh \
  --archive bhf-dist-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz \
  --signature bhf-dist-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz.sig \
  --trusted-public-key /trusted/publisher.pub
```

Transfer the archive and its sidecars, then on the **offline** host:

```sh
sha256sum -c bhf-dist-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz.sha256
bash /trusted/verify-offline-dist.sh \
  --archive bhf-dist-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz \
  --signature bhf-dist-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz.sig \
  --trusted-public-key /trusted/publisher.pub
tar xzf bhf-dist-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz
cd bhf-dist-vX.Y.Z-x86_64-unknown-linux-gnu

./install.sh --non-interactive --trust-policy /trusted/operator-policy.json \
  --languages all \
  --targets native \
  --fuzzers builtin \
  --extras build-recovery,archives \
  --no-system-packages \
  --no-rustup
```

On a connected destination, leave out `--no-system-packages` and
`--no-rustup` if the installer should prepare those dependencies. The
content pack is inside the bundle and is installed unless you pass
`--no-content`. An older checksum-only bundle needs
`--allow-legacy-integrity-only` instead of `--trust-policy`; that mode does
not authenticate the publisher.

### A2. Manually co-locate published component archives

The release job (`dist`) attaches each app to the GitHub Release for its tag
as a separate archive with a `.sha256` sidecar:

- `bhf-*`: the CLI;
- `bhf-daemon-*`: the JSON-RPC and read-only MCP daemon (only for IDE or MCP
  use);
- `bhf_runtrace_shim-*`: the `LD_PRELOAD` shim `bhf auto` uses for runtime
  virtualisation on Linux. It is loaded into native C/C++, Ada, Rust, Go,
  COBOL and Fortran harnesses and into the Python, Perl, Ruby, Lua and PHP
  interpreters; Java, C#, JavaScript, TypeScript and cross-compiled or
  emulated targets run without it;
- `bhf_cc_intercept-*`: the `LD_PRELOAD` shim C/C++ build recovery uses to
  capture compiler invocations made by absolute path or through
  `posix_spawn`.

Use this path when policy or storage limits require individually selected
files. For the usual full Linux `bhf auto` deployment, transfer the CLI,
runtrace shim and compiler-interception shim archives with their three
sidecars. Transfer the daemon only for IDE, JSON-RPC or MCP clients. Leave
the component shell installers behind: they download archives from the
network, which the disconnected side cannot reach.

On the **connected** host:

```sh
# Download the archives and checksums for the host's Linux target
# (use aarch64-unknown-linux-gnu in these names for a 64-bit ARM host).
gh release download vX.Y.Z --repo Tarmo-Technologies/bhf \
  --pattern 'bhf-x86_64-unknown-linux-gnu.tar.xz*' \
  --pattern 'bhf_runtrace_shim-x86_64-unknown-linux-gnu.tar.xz*' \
  --pattern 'bhf_cc_intercept-x86_64-unknown-linux-gnu.tar.xz*'

# Only if the disconnected host will serve JSON-RPC or MCP:
gh release download vX.Y.Z --repo Tarmo-Technologies/bhf \
  --pattern 'bhf-daemon-x86_64-unknown-linux-gnu.tar.xz*'

# Check integrity (re-runnable offline: the sidecar travels with the file).
sha256sum -c bhf-x86_64-unknown-linux-gnu.tar.xz.sha256
sha256sum -c bhf_runtrace_shim-*.tar.xz.sha256
sha256sum -c bhf_cc_intercept-*.tar.xz.sha256
# If downloaded:
sha256sum -c bhf-daemon-x86_64-unknown-linux-gnu.tar.xz.sha256
```

The component archives carry SHA-256 sidecars, and the release publishes no
GitHub Artifact Attestations for them. `sha256sum -c` works offline and is
your archive-integrity check on the air-gapped side, so copy the `.sha256`
sidecars across with the archives. A sidecar detects a changed file; it does
not authenticate the publisher. The installer also checks content-pack
digests before installing a pack.

Transfer the archives (for example on approved removable media), then on the
**offline** host:

```sh
sha256sum -c bhf-x86_64-unknown-linux-gnu.tar.xz.sha256 # re-check after transfer
tar xf bhf-x86_64-unknown-linux-gnu.tar.xz
tar xf bhf_runtrace_shim-*.tar.xz
tar xf bhf_cc_intercept-*.tar.xz
# Only if transferred for JSON-RPC or MCP:
tar xf bhf-daemon-x86_64-unknown-linux-gnu.tar.xz

CLI_DIR=bhf-x86_64-unknown-linux-gnu
install -m 0755 \
  bhf_runtrace_shim-x86_64-unknown-linux-gnu/libbhf_runtrace_shim.so \
  "$CLI_DIR/"
install -m 0755 \
  bhf_cc_intercept-x86_64-unknown-linux-gnu/libbhf_cc_intercept.so \
  "$CLI_DIR/"

"./$CLI_DIR/bhf" --help
```

Put both libraries beside the CLI: bhf finds them there. bhf also finds the
runtrace shim in a sibling archive directory, but it does not search for the
compiler-interception shim that way. If policy requires separate library
directories, set absolute paths:

```sh
export BHF_RUNTRACE_SHIM=/absolute/path/libbhf_runtrace_shim.so
export BHF_CC_INTERCEPT=/absolute/path/libbhf_cc_intercept.so
```

Every component archive includes an `INSTALL.md` with the same co-location
commands, an optional-daemon example, and a user-local permanent prefix.

### A3. Build from source on a connected host, transfer the needed components

Use this when you need a tag or commit that has no published archive, or a
target triple the release job does not build.

On the **connected** host, build against a glibc no newer than the offline
host's. For RHEL 7 through 10, use the pinned manylinux2014 image and ABI
check from `.github/workflows/release.yml`; a normal build on a current
Ubuntu host does not run on EL7:

```sh
cargo build --release --workspace
```

Transfer the CLI and the Linux components the planned workload needs, and
keep the selected shims next to the CLI:

```
target/release/bhf
target/release/libbhf_runtrace_shim.so # recommended: runtime audit and fake resources
target/release/libbhf_cc_intercept.so  # optional: complex C/C++ build recovery
target/release/bhf-daemon              # optional: IDE JSON-RPC or MCP
```

> **Match the runtime, not just the CPU.** The runtrace shim is
> `LD_PRELOAD`-ed into the harness processes bhf compiles on the offline
> host, so it must be built against the same libc that the offline host's
> `clang` links against. Build on a host whose glibc is the same as, or
> older than, the offline host's. A newer glibc shows up as
> `version 'GLIBC_2.xx' not found` when a harness runs. When in doubt, use
> Model B.

The published Linux release is checked against a glibc 2.17 ceiling and is
the preferred Model A artifact for RHEL 7, 8, 9 and 10. The stock EL7 linker
cannot link the current preload shim from source, so rebuild for EL7 in the
pinned manylinux2014 build image rather than with stock binutils.

---

## Model B: transfer the source and build on the offline host

This gives a binary that matches the offline host exactly. It needs a Rust
toolchain on the offline host and a one-time crate vendor step on the
connected host (bhf pins every dependency version in `Cargo.lock`).

On the **connected** host, from a clean checkout of the desired tag:

```sh
# Copy every crate the lockfile references into a local directory and print
# the cargo config that redirects builds to it.
cargo vendor vendor-offline > offline-cargo-config.toml
```

`cargo vendor` writes the full dependency set (about 470 MB) into
`vendor-offline/` and prints a `[source.*]` block. Transfer the whole
repository together with `vendor-offline/`, `Cargo.lock` and the printed
config.

On the **offline** host:

```sh
# Point builds at the vendored crates (paths are relative to the repo root)
mkdir -p .cargo
cp offline-cargo-config.toml .cargo/config.toml      # check that `directory =` is "vendor-offline"

# Install the pinned toolchain offline if rustup is not already provisioned.
# (rust-toolchain.toml pins the Rust version, with rustfmt and clippy.)

cargo build --release --workspace --offline
```

`--offline` makes cargo use only the vendored crates and never touch the
network; the build fails with an error if anything is missing. The resulting
`target/release/` binaries are laid out as in Model A.

---

## Toolchains on the offline host

bhf discovers, ranks and recovers source with no external tools. To build
and fuzz the generated harnesses, it runs compilers that must already be
installed on the offline host:

| Lane | Required | Provides |
|---|---|---|
| C / C++ | `clang`, `clang++` (ASan/UBSan and SanitizerCoverage), `make` | harness build and fuzz |
| Ada | FSF `gnat`, `gprbuild` (and `alr` for dependency resolution, only under `--run-untrusted`) | harness build and fuzz |
| Rust | `cargo`, `rustc` (nightly, for SanitizerCoverage and ASan), `clang` to link the fork-server driver | harness build and fuzz |
| Java | `javac`, `java` (JDK 8+), optionally `maven`/`gradle` (coverage from the bundled ASM bytecode agent) | harness build and fuzz |
| Python | `python3` (3.12+ for `sys.monitoring` edge coverage; `sys.settrace` fallback) | harness build (`py_compile` and an import smoke test) and fuzz |
| Perl | `perl` (per-statement edge coverage from the bundled `-d:BhfCov` debugger) | harness build (`perl -c` and a `require` smoke test) and fuzz |
| Go | `go` (`-cover -covermode=atomic` block feedback; black-box fallback) | harness build and fuzz |
| COBOL | `cobc`, `clang`, `make` | GnuCOBOL-to-C harness build and coverage-guided fuzz |
| Fortran | `gfortran`, `clang`, `make` | ASan and `trace-pc`/`trace-cmp` harness build and fuzz |
| C# | .NET SDK plus `SharpFuzz.CommandLine` | IL instrumentation, warm-CLR harness and fuzz |
| JavaScript | `node` | syntax check, V8 block coverage and warm-process fuzz |
| TypeScript | `node`, `esbuild` | transpile and bundle, V8 block coverage and warm-process fuzz |
| Ruby | Ruby 2.0+ | `TracePoint` coverage and interpreter fuzz |
| Lua | Lua 5.3+ (`lua`/`luac`) | line-hook coverage and interpreter fuzz |
| PHP | PHP 8.0+; `pcov` recommended | syntax check and interpreter fuzz (`pcov` coverage or black-box fallback) |
| AFL++ engine (optional) | `afl-fuzz`, `afl-clang-fast` | second fuzz engine for native C/C++, COBOL, Fortran, Rust and Ada targets |

Stage these from your distribution's offline package mirror or a
pre-downloaded `.deb`/`.rpm` bundle (for example
`apt-get install --download-only` on a connected mirror, transfer,
`dpkg -i`). Without them, `bhf auto` still runs discovery and build recovery.
Ada, C and C++ targets then report as unbuildable, and the targets of every
lane whose compiler or interpreter is absent are skipped without an error or
finding (for example Rust without nightly, or Go without `go`).

The binary installer maps both Debian/Ubuntu (`apt-get`) and RHEL-family
(`dnf`/`yum`) package names. On RHEL it filters the selected set through the
enabled repositories before installing, so an unavailable supplemental
package does not block the core tools that are available. The C# lane needs
an explicitly staged .NET 8 SDK and the global `SharpFuzz.CommandLine` tool.
TypeScript needs `esbuild` on `PATH` or already in the target project, so
that `npx --no-install esbuild` succeeds. A C# harness also restores its
SharpFuzz NuGet package: pre-populate the NuGet cache, or configure an
approved offline package source, before moving into the enclave (see
[C#: staging the NuGet packages offline](csharp.md#staging-the-nuget-packages-offline)).

On RHEL 7, point `yum` at an active subscription or an organization mirror
before running the installer. A CentOS 7 compatibility lab needs an archive
mirror, because the retired default mirrorlist no longer supplies
dependencies.

> **License note.** GNAT and GPRbuild are GPL. bhf runs them as subprocesses
> and never links them. Keep that in mind when you stage toolchains for an
> air-gapped Ada deployment; see [Licensing](licensing.md).

---

## Staging harness dependencies across the air gap

The toolchains build the harnesses, but the harnesses also need the
project's own dependency headers, libraries and Ada units. A legacy tree that
`#include`s a vendored SDK or `with`s an external Ada library does not build
offline until those are staged. bhf lists everything missing in one scan, so
you stage it in one trip.

| Flag | Network | What it does |
|---|---|---|
| `--deps-only` | offline | Discovers and builds each target as far as possible (stubbing what is missing), writes the missing-dependency manifest, and skips fuzzing. The fast "what does this tree need?" pass. |
| `--install-deps` | **online** | After the sweep, fetches the still-blocking dependencies with the package managers present (`apt-get` for headers and libraries, `alr get` for Ada units). The only part of `auto` that uses the network; run it on the connected host. |
| `--ada-deps <DIR>` | offline | Adds a local directory of Ada dependency source to the build path, for vendored units a project `with`s. Repeatable. |
| `--extra-include <DIR>` | offline | Adds a C/C++ include directory for dependency headers outside the swept tree (a vendored SDK's `include/`). Read from disk only. Repeatable. |
| `--probe-build` | offline | Recovers the project's real compile wiring (`-I`, `-D`, `-std`, generated headers) by running its own build once. Executes the project's untrusted build scripts, in bwrap or firejail when one is available. |
| `--run-untrusted` | offline | Consent for materializing generated dependencies: implies `--probe-build`, plus an Ada `alr build` / `gprbuild` probe. Off by default. Executes untrusted code, as `--probe-build` does. |

The recommended air-gapped flow:

```sh
# On the OFFLINE host: find everything the tree needs, without fuzzing.
bhf auto path/to/src --work-dir bhf_work --deps-only
#   → writes bhf_work/auto/missing-deps.txt (human-readable list)
#           bhf_work/auto/missing-deps.json (machine-readable)

# Carry missing-deps.txt to the CONNECTED host and fetch there: run
# `auto --install-deps` (the only network path), or stage the headers,
# libraries and Ada units by hand. Then transfer them back across the gap.

# Back on the OFFLINE host: point auto at the staged dependencies and fuzz.
bhf auto path/to/src --work-dir bhf_work \
  --extra-include /opt/staged/sdk/include \
  --ada-deps /opt/staged/ada-units
```

Both files exist before the first target build and are checkpointed
atomically after every completed target. Start with their first section,
`Required toolchains, runtimes, generated and vendor source`. Each row names
its evidence as declared, observed or inferred, and `missing-deps.json` also
records whether the checkpoint is final. If the parent process is OOM-killed,
everything learned before the target that was running is kept.

`--run-untrusted` and `--probe-build` are needed only when a dependency is
generated by the project's own build (CMake or configure code generation,
Alire config). They run that build offline, so use them only when you accept
executing the project's scripts. Without them, bhf stubs the generated
dependencies and records them in the manifest, and runs nothing.

The [offline auto runbook](offline-auto-runbook.md) (shipped in the bundle
as `AUTO-OFFLINE-RUNBOOK.md`) walks through a full Ada, C and C++ campaign on
an offline host.

---

## Updating the bhf tool in place (data-safe)

Running `install.sh` from a newer package updates an existing install; you
do not uninstall first. It is idempotent, so it is safe to run repeatedly
and over the same version, and it keeps your data.

Verify the new package with the independently trusted verifier and
publisher key before unpacking it, then reuse the operator policy from the
first install. Set `ARCHIVE` to the new file name and keep the existing
install prefix:

```sh
ARCHIVE='bhf-dist-<version>-x86_64-unknown-linux-gnu.tar.gz'
sha256sum -c "$ARCHIVE.sha256"
python3 /trusted/verify-offline-dist.py \
  --archive "$ARCHIVE" --signature "$ARCHIVE.sig" \
  --trusted-public-key /trusted/publisher.pub \
  --verified-copy bhf-update-verified.tar.gz
tar xzf bhf-update-verified.tar.gz
cd "${ARCHIVE%.tar.gz}"
./install.sh --trust-policy /trusted/operator-policy.json
# or, non-interactively, with your earlier selections:
./install.sh --non-interactive --trust-policy /trusted/operator-policy.json \
  --languages all --targets native --fuzzers builtin
```

The update stages the new install in `<prefix>.new.$$` and then swaps it in:

| Action | Items |
|---|---|
| **Replaced** with the new version | `bhf`, `bhf-daemon`, the `libbhf_runtrace*.so` and `libbhf_cc_intercept.so` shims, and every `*_runtime/` tree. They are reinstalled even when unchanged, so a rerun is a clean overwrite. |
| **Kept** (copied forward from the old install) | `<prefix>/packs/` (rules and CVE database content) and `<prefix>/corpora/` (seed corpus). |
| **Backed up** (full rollback) | The previous install moves to `<prefix>.backup.<timestamp>` before the swap. Roll back with `mv <prefix>.backup.<ts> <prefix>`. |
| **Not touched** | Your run outputs (findings, reports, harnesses and corpora under any `--work-dir` you pass at run time) live outside the prefix, and the installer does not read them. |

On the same offline machine you can drop in a newer package and run
`./install.sh`: it replaces the binaries and runtimes and keeps your content
packs, seed corpora and all earlier run data. `bhf --version` (or
`cat <prefix>/VERSION`) confirms the new build. If the old and new
selections differ, pass the same `--languages`, `--targets` and `--fuzzers`
flags you used before, or use interactive mode, which pre-fills them.

---

## When bhf itself errors: `--debug` and `bug-report.json`

If bhf itself fails on your tree (an internal panic, or a harness whose
generated code bhf left broken), it records the failure in a bug report.
Findings are bugs in your target, and `missing-deps.txt` lists dependencies
your environment lacks; the bug report lists bhf's own defects, with what a
maintainer needs to fix them offline.

- A bhf-internal panic while parsing or fuzzing one file is caught at that
  file or target boundary: the sweep records it and continues.
- Whenever a run hits an internal defect, bhf writes
  `<work-dir>/auto/bug-report.json` and `bug-report.md` and prints a
  one-line pointer to them. A clean run writes neither.

Add `--debug` to capture a backtrace for each panic (it sets
`RUST_BACKTRACE` for you), which pins the exact source line:

```sh
bhf auto --debug <source-tree> --work-dir bhf_work
# → bhf_work/auto/bug-report.md   (send an entry to the maintainer)
```

`bug-report.md` lists each issue with its category (`PANIC` or `codegen`),
the source file and target it happened on, the language, the bhf version and
commit, and, under `--debug`, the backtrace. Send that file, or one entry
from it, to get the defect fixed. For a scrubbed archive you can review
before sharing, run `bhf bug-report <work-dir> --preview`, then `--bundle`.

---

## Updating offline content: rules, CVE DB, corpora

Updating the tool (above) is separate from updating the content it reads:
static-analysis rules, the CVE/SCA database and seed corpora. Content ships
as checksum-verified update packs: local JSON manifests with deterministic
hashes and optional Ed25519 publisher signatures, so content can cross the
air gap independently of a bhf release.

The binary-only package flow in
[A0](#a0-build-a-binary-only-distribution-package-from-source) creates and
installs this pack for you. Run `bhf pack create` directly only to publish a
content-only update.

On the **connected** host:

```sh
bhf pack keygen --private-key keys/offline-root.der --public-key keys/offline-root.pub
bhf pack create --root packs/current \
  --pack-id rules-2026-06 --version 2026.06 \
  --item rules:rules/static.json \
  --item cve:cve/sbom-cves.json \
  --item cve:cve/binary-cves.json \
  --item corpus:corpus/seeds.tar.gz \
  --signing-key keys/offline-root.der --key-id offline-root \
  --out packs/current/update-pack.json
```

Keep the private key outside the transferred pack. Configure the offline
host's policy independently, with `update_packs.require_signature: true` and
`update_packs.trusted_public_keys: {"offline-root": "<contents of keys/offline-root.pub>"}`.
An optional `revoked_keys` array denies retired key IDs even if they are
still in the trust map. The deprecated `--sign-key` is only an unkeyed digest
label and cannot satisfy an authentication policy.

Transfer `packs/current/`, then verify it on the **offline** host before use:

```sh
bhf pack verify packs/current/update-pack.json \
  --root packs/current --policy bhf-policy.json --require-authenticated
```

See [Release Packaging: Air-Gapped Packs](release-packaging.md#air-gapped-packs)
for the full pack format.

---

## Post-update smoke test

After any update, check the install on the offline host before relying on
it. From the extracted bundle directory:

```sh
bhf --help                                  # the CLI resolves
bhf auto smoke/c \
  --work-dir /tmp/bhf-smoke --per-target-time 5 --verbose
```

`--per-target-time` is each target's total fuzz wall-clock budget in seconds
(default 60), split evenly across the empty, rng and fuzz-driven passes
under one shared deadline, so a target takes about this long whatever the
pass count. To bound the whole run across all targets, use
`--campaign-time <secs>`. To stop a target once it has produced N distinct
crash signatures, use `--per-target-finding-count N` (`1` matches libFuzzer's
stop on first crash).

A healthy run prints per-target fuzz lines with non-zero `execs=` and lists
at least one `built+fuzzed` target (given a C target and `clang`). If the
summary shows `built+fuzzed (N STUB-ONLY)` or a `STUB-ONLY` warning, the
harness fuzzed blind stubs, not real library code, and a clean result there
is a false clean. If you see `libbhf_runtrace_shim.so not found`, check the
shim location (`BHF_RUNTRACE_SHIM`); if every target reports a build
failure, check the [toolchains](#toolchains-on-the-offline-host).
