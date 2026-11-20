<!-- SPDX-License-Identifier: Apache-2.0 -->

# Release Packaging

BHF uses `dist` 0.31.0 (formerly `cargo-dist`) to plan and publish binary
release artifacts from GitHub Actions. This page covers how a release is
built and verified, including the offline binary-distribution tarball
(`scripts/package-offline-dist.sh`). The site page
[Release Packaging](./site/release-packaging.md) has the full artifact table
and the archive-install layout.

The releasable applications are:

- `bhf`: the command-line interface from `crates/cli`
- `bhf-daemon`: the JSON-RPC and read-only MCP daemon from `crates/daemon`
- `bhf_runtrace_shim`: the `cdylib` loaded by `bhf auto` for runtime
  virtualisation on Linux
- `bhf_cc_intercept`: the build-time compiler-interception `cdylib` used by
  C/C++ `--probe-build` / `--build-command` recovery

## Asset Selection for Release Consumers

A release provides an all-in-one Linux bundle and separate components. Pick
one delivery style; you do not need every file:

| Consumer scenario | Assets to use |
|---|---|
| Complete Linux install | Full bundle, checksum, and detached signature; verify with an independently trusted verifier/key, then run `./install.sh --trust-policy /trusted/operator-policy.json` |
| Windows CLI | `bhf-installer.ps1`, or the Windows CLI ZIP and its checksum—not both |
| Basic Linux CLI | `bhf-installer.sh`, or the Linux CLI archive and its checksum—not both |
| Full Linux `bhf auto` | The CLI, runtrace shim, and compiler-interception shim; choose the three installers or the three archives/checksums |
| IDE/JSON-RPC/MCP | Add the platform's `bhf-daemon` installer/archive; it is not required by the CLI |
| Manual/offline install | Download only the matching platform archives and their `.sha256` sidecars; do not also download installers |
| Source audit/rebuild | `source.tar.gz` and its checksum |
| Release automation | `dist-manifest.json`, individual sidecars, and/or the aggregate `sha256.sum` |

The runtrace and compiler-interception shims are Linux-only. The runtrace shim
adds runtime audit, behavioral and taint oracles, and fake resources. The
compiler-interception shim is used for C/C++ build recovery
(`--probe-build`, `--build-command`). [Choose release assets by
task](./site/install.md#choose-release-assets-by-task) gives the decision
guide and the exact commands.

The workspace defaults every package to `dist = false`; the two app packages
and both Linux preload-shim packages opt back in. The app packages also list
their distributed binaries, which leaves test and legacy compatibility
binaries such as `cli`, `daemon`, and fixture harnesses out of the release
archives.
The CLI package explicitly includes all eleven harness-runtime trees. The CLI
also embeds those tracked runtime sources and securely stages them on first use,
which keeps shell/PowerShell installer deployments functional even though dist
installers place only the executable in `CARGO_HOME/bin`.

The runtrace shim package opts in with `package-libraries = ["cdylib"]` and
`install-libraries = ["cdylib"]` so dist publishes a shim archive and
installer containing `libbhf_runtrace_shim`. The runtime preload libraries are
Linux-only. The generated workflow publishes the CLI and daemon for
`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` and
`x86_64-pc-windows-msvc`, while publishing the two preload libraries only for
the two Linux targets. Each Linux target is built natively, on a runner of its
architecture, in a pinned manylinux2014 / CentOS 7 container and checked for a
maximum glibc 2.17 ABI, so the binaries run on Ubuntu 22.04/24.04/26.04 LTS
and RHEL 7 through RHEL 10. Installer metadata explicitly uses that glibc 2.17
floor. The same gate verifies the runtrace shim's required interposition
exports. For manual component installs, copy `libbhf_runtrace_shim.so` and
`libbhf_cc_intercept.so` into the extracted `bhf-*` CLI directory, or set
`BHF_RUNTRACE_SHIM` and `BHF_CC_INTERCEPT` to absolute paths. The runtrace
shim is also found in a sibling dist directory; the compiler-interception shim
is not, so put both directly beside `bhf`. Every component archive includes
`INSTALL.md`. For component-installer installs, run the CLI and each required
shim installer so all files land beside one another. The CLI also accepts the
renamed `libbhf_runtrace.so` produced by source builds.

After `dist` generates the main Unix installer, the release workflow runs
`scripts/augment-release-installer.py`. On an EL7-family host the resulting
installer explains, before downloading the CLI, that it does not enable system
repositories or install toolchains/shims; it prints the exact RHSCL LLVM 7
packages and the separate runtrace/compiler-interception installer commands.
The augmentation is idempotent and the release workflow rejects an installer
that does not contain the guidance marker.

`scripts/fix-dist-shell-installer.py` adds an explicit `xz` dependency check to
all four Unix installers. Cargo-dist already checks for `tar`, but its `.tar.xz`
archives also require the external `xz` helper on minimal RHEL installations.
The release gate rejects any Unix installer without this check.

The workflow also runs `scripts/fix-dist-library-installer.py` over both Linux
preload-library installers. This corrects cargo-dist 0.31's temporary-directory
`chmod` path before publication; a release gate rejects either installer if the
fixed path is absent.

`scripts/fix-dist-powershell-installer.py` makes both Windows installers usable
from local PowerShell and non-interactive Windows OpenSSH sessions by disabling
`Expand-Archive` console progress in the extraction scope. This avoids the
Server 2019 `ReadConsoleOutput` access-denied failure while leaving installation
output and errors visible.

## Binary-Only Distribution Package

Use `scripts/package-offline-dist.sh` when a connected build machine has the
source checkout but the destination machine should receive an installable
tarball instead of the BHF application source tree:

```sh
scripts/package-offline-dist.sh \
  --signing-key keys/publisher.der --key-id publisher-v1 \
  --trusted-public-key keys/publisher.pub
```

When CVE DBs or seeds are not provided, the script creates and packages:

```text
dist/content-inputs/sbom-cves.json
dist/content-inputs/binary-cves.json
dist/content-inputs/seeds/
```

Those generated CVE DBs are valid empty defaults. Replace them with real feed
data and rerun the same command when you need SBOM or binary-CVE matching.

The script runs `cargo build --release --workspace`, stages the release binaries,
both Linux shims, harness runtime support files, a tiny `bhf auto` smoke
fixture, and an authenticated content pack, then produces
`dist/bhf-dist-<version>-<triple>.tar.gz` plus a `.sha256` sidecar and detached
`.tar.gz.sig` signature. Every tagged release publishes this full bundle
alongside the component artifacts.

The tarball includes `install.sh`, `bhf-bug-report`, `INSTALL.md`, `LICENSE`,
`README.md`, `RELEASE_NOTES.md`, `README-DIST.md`, `RUN-BHF.md`,
`RECOMMENDED-SWEEP.md` (this repository's
[`docs/recommended-sweep.md`](recommended-sweep.md)) and
`AUTO-OFFLINE-RUNBOOK.md` (from
[`docs/site/offline-auto-runbook.md`](site/offline-auto-runbook.md)).
`bhf-bug-report` writes a size-capped diagnostic summary from the live
per-target checkpoints; it leaves out source and corpus content and replaces
project paths and identifiers. `INSTALL.md` documents both the bundled
installer and the manual component-archive co-location layout. The release
workflow extracts every full bundle and fails before publication if
`install.sh`, `INSTALL.md`, `LICENSE`, `README.md` or `RELEASE_NOTES.md` is
missing.

The runtime trees cover C/C++, Ada, Rust, Java, Python, Perl, C#,
JavaScript/TypeScript, Ruby, Lua, and PHP. COBOL, Fortran, and Go use their
system toolchains plus the shared C runtime. `--languages all` selects installer
dependencies for all sixteen lanes and is the default for both interactive
and non-interactive installation. Use an explicit subset to install fewer
toolchains.

`install.sh` installs or updates interactively, with an arrow-key terminal
checklist, or non-interactively:

```sh
./install.sh --non-interactive --trust-policy /trusted/operator-policy.json \
  --languages all \
  --targets native,windows,aarch64 \
  --fuzzers builtin,afl \
  --extras build-recovery,sandbox,archives
```

Provision the trust policy and public key independently of the bundle, and
verify the detached archive signature with a separately trusted OpenSSL-based
verifier before you extract or run anything (see [Verifying
Releases](#verifying-releases)). The release workflow fails when the protected
signing inputs are absent. `--legacy-integrity-only` is an explicit
unauthenticated compatibility mode, never used for a release.

The installer runs the smoke fixture against the staged install before it
activates it; the smoke needs `clang` and `make`. Use `--no-smoke` only on a
host without a C toolchain.

The generated release workflow also produces this all-in-one package from the
same EL7-baseline binaries used by the component archives, installs it into a
temporary prefix, runs its smoke fixture, and publishes the tarball and checksum
as first-class release assets.

## Targets

The generated release workflow builds these target triples:

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu` (component archives and installers; the
  all-in-one signed bundle is built for x86_64 only)
- `x86_64-pc-windows-msvc` (`bhf` and `bhf-daemon` only)

Each archive has a SHA-256 checksum sidecar. The Linux binaries are built in the
pinned manylinux2014 container of their architecture
(`manylinux2014_x86_64` on an x86_64 runner, `manylinux2014_aarch64` on an
`ubuntu-24.04-arm` runner) for Ubuntu 22.04/24.04/26.04 LTS and RHEL 7
through 10. The aarch64 archives are unpacked and smoke-tested on the ARM64
runner before upload, and CI's `arm64-release-build` job, which the release's
CI gate requires, builds them the same way, installs them through the
generated installers and runs the same smoke on every change that runs the
full CI. Windows binaries are built and smoke-tested on Windows Server 2022,
then the same binaries are exercised on Server 2025; Server 2019, Windows 11
Enterprise 25H2, and Windows 11 Enterprise LTSC 2024 are covered by the platform
VM validation. PowerShell installers are published alongside the Unix shell
installers. The runtime and
compiler-interception preload shims remain Linux-only assets. No macOS or
Windows-on-Arm artifacts are published. CI's `macos-build` job,
which CI acceptance requires, builds the workspace natively for
`aarch64-apple-darwin` on a `macos-15` runner (the preload shim crates build
empty libraries there and no shim is staged beside `bhf`), runs the shim-gating
and shared-map unit tests, and runs `scripts/ci/macos-auto-smoke.sh`: `bhf
auto` finds a planted C overflow, and the target, the campaign rollup and the
finding record the shim-unavailable fidelity (`fidelity.runtime_shim`).

GitHub Artifact Attestations are disabled in the generated workflow
(`github-attestations = false` in `[workspace.metadata.dist]`). Release
assets carry SHA-256 sidecars, and the offline distribution checks its
content-pack digests during package creation and install. SHA-256 sidecars
and content-pack digests detect a changed file but do not authenticate its
publisher. Publisher authentication comes from the detached Ed25519 signature
of the full bundle and the content pack's Ed25519 signature; see
[Authenticated offline update packs](enterprise-pack-authentication.md).

To enable attestations, set `github-attestations = true` and add
`github-attestations-phase = "host"` in `[workspace.metadata.dist]`,
regenerate the release workflow with `dist generate --mode ci`, and add the
attestation verification command to this page.

## Verifying Releases

Download the release asset and its checksum sidecar from the GitHub Release,
then verify the checksum first:

```sh
sha256sum -c <asset>.sha256
```

For the full Linux bundle, also verify the detached signature before you
extract it. Use a copy of `scripts/verify-offline-dist.sh` and the publisher's
public key (64 lowercase hex characters) that you obtained through a trusted
channel, not from the release being checked:

```sh
verify-offline-dist.sh --archive bhf-dist-<version>-<triple>.tar.gz \
  --signature bhf-dist-<version>-<triple>.tar.gz.sig \
  --trusted-public-key /trusted/publisher.pub
```

After extraction, the installer verifies the content pack against your trust
policy. To verify it by hand:

```sh
./tool/bhf pack verify \
  ./content/packs/current/update-pack.json \
  --root ./content/packs/current \
  --policy /trusted/operator-policy.json --require-authenticated
```

References:

- [dist GitHub Attestations](https://axodotdev.github.io/cargo-dist/book/supplychain-security/attestations/github.html)

## Release Flow

Pull requests run the generated `Release / plan` check. Pushing a tag that
contains a semantic version (this repository's tags look like `0.3.0`) runs
the full release workflow. Before you push the tag, set
`[workspace.package].version` in `Cargo.toml` to the exact release version and
refresh `Cargo.lock`. The workflow then:

1. plans the artifacts (`dist host --steps=create --tag=<tag>`);
2. builds the platform archives and checksums against the RHEL 7 ABI (x86_64
   and aarch64) and on native Windows, and smoke-tests the aarch64 archives on
   the ARM64 runner;
3. checks every CLI archive for every required harness runtime;
4. generates the Unix shell and Windows PowerShell installers;
5. uploads the artifacts to a GitHub Release.

To see the plan locally before you open a release-packaging change or push a
tag, run the plan job's command:

```sh
dist host --steps=create --tag=X.Y.Z
```
