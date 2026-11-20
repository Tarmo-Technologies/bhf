<!-- SPDX-License-Identifier: Apache-2.0 -->

# Release Packaging

bhf uses `dist` (cargo-dist 0.31.0) to publish binary archives for four
components:

- the `bhf` CLI;
- `bhf-daemon`, the JSON-RPC and read-only MCP service;
- the `bhf_runtrace_shim` library that `bhf auto` preloads on Linux for
  runtime virtualisation;
- the `bhf_cc_intercept` library that C/C++ build recovery preloads to
  observe compilers started by absolute path or through `posix_spawn`.

The CLI archives hold the complete Ada, C/C++, C#, Java, JavaScript, Lua,
Perl, PHP, Python, Ruby and Rust harness-runtime trees. The executable also
embeds those sources for installs made with the shell or PowerShell
installer, so neither install style needs a source checkout or a CI build
path.

## Artifacts

The CLI and daemon archives are built for `x86_64-unknown-linux-gnu`,
`aarch64-unknown-linux-gnu` and `x86_64-pc-windows-msvc`.

- **Linux.** Each GNU/Linux build runs natively in a pinned manylinux2014
  (CentOS 7) container for its architecture, and the aarch64 archives are
  smoke-tested on an ARM64 runner. A release gate rejects a binary that
  needs a glibc newer than 2.17 or lacks a preload-hook export. That fixes
  the release ABI for Ubuntu 22.04, 24.04 and 26.04 LTS and RHEL 7 to 10,
  independent of the build runner's glibc. The release binaries are scan,
  build and fuzz tested across that Linux matrix.
- **Windows.** The Windows build runs on Windows Server 2022, and the same
  binary is smoke-tested on Server 2025. The platform VM validation covers
  Windows Server 2019, Windows 11 Enterprise 25H2 and Windows 11 Enterprise
  LTSC 2024.
- **Preload libraries.** The two shims are Linux-only and are published as
  Linux libraries only.
- **All-in-one bundle.** `bhf-dist-*` is published for x86_64. On aarch64,
  use the component archives or installers.
- **macOS.** Releases include no macOS or Windows-on-Arm artifacts. CI's
  `macos-build` job builds bhf natively for `aarch64-apple-darwin` on a
  `macos-15` runner, without the Linux preload libraries, and runs a
  `bhf auto` smoke test there.

A GitHub Release contains the all-in-one Linux bundle with its `install.sh`,
per-component archives for each platform, Unix shell installers, and
PowerShell installers for the Windows components. For each component, pick
one form: run its installer on a connected host, or download its archive
and checksum for a manual or offline install. The installer downloads the
archive itself.

| Scenario | Assets to use |
|---|---|
| Linux, complete one-package install | `bhf-dist-<version>-x86_64-unknown-linux-gnu.tar.gz` and its sidecar; extract it and run the bundled `install.sh` |
| Windows terminal or CI | `bhf-installer.ps1`, or the `bhf-*.zip` and its `.sha256` sidecar |
| Linux terminal or CI, basic features | `bhf-installer.sh`, or the Linux `bhf-*.tar.xz` and its sidecar |
| Linux, full `bhf auto` on real projects | the Linux CLI plus `bhf_runtrace_shim` and `bhf_cc_intercept`, as three installers or three archives with sidecars |
| IDE, JSON-RPC or read-only MCP | add the `bhf-daemon` installer or archive for your OS |
| Source audit or rebuild | `source.tar.gz` and `source.tar.gz.sha256` |
| Release automation | `dist-manifest.json` plus the checksum sidecars, or `sha256.sum` for the full archive set |

The CLI works without the daemon. On Windows, skip the two Linux preload
shims. Without the runtrace shim, scan, build and fuzz work, and the
runtime audit, the behavioural and taint oracles and the fake resources are
off. The compiler-interception shim matters only for C/C++ build recovery
that has to observe compilers started by absolute path or through
`posix_spawn`.

| Component prefix | Purpose | Needed for |
|---|---|---|
| `bhf-dist-*` | All-in-one Linux bundle: `install.sh`, CLI, daemon, both shims, runtimes, content pack and smoke fixture | a complete Linux or air-gapped install, after you verify its signature |
| `bhf-*` | Main CLI | every CLI workflow |
| `bhf_runtrace_shim-*` | Runtime virtualisation `LD_PRELOAD` shim | full `bhf auto` runtime audit and fake resources |
| `bhf_cc_intercept-*` | Build-time compiler interception `LD_PRELOAD` shim | C/C++ `--probe-build` and `--build-command` recovery when builds start compilers by absolute path or through `posix_spawn` |
| `bhf-daemon-*` | JSON-RPC and read-only MCP daemon | IDE, editor, MCP and agent integrations |
| `source.tar.gz` | Release source snapshot | source audit or rebuild |
| `dist-manifest.json`, `sha256.sum`, `*.sha256` | dist metadata and checksums | automation and integrity checks |

For a manual component install, copy `libbhf_runtrace_shim.so` and `libbhf_cc_intercept.so` into the extracted `bhf-*` CLI directory, or set `BHF_RUNTRACE_SHIM` and `BHF_CC_INTERCEPT` to their absolute paths. bhf also finds the runtrace shim in a sibling `bhf_runtrace_shim-*` archive directory; the compiler-interception shim must sit beside the CLI or be set explicitly. Every component archive includes an `INSTALL.md` with the exact commands. Every component archive also carries the documentation beside `README.md` (`docs/`, `examples/`, `schemas/`, `benchmarks/` and the pages `README.md` links), and the release workflow checks that the links of `README.md`, `INSTALL.md` and `docs/site/index.md` resolve inside each Linux archive. With the component installers, run each one you need; the `bhf` installer installs the CLI.

Each archive has a SHA-256 checksum sidecar. A sidecar detects changes to
the file; it does not identify the publisher. The all-in-one bundle carries
a content pack whose SHA-256 digests and Ed25519 publisher signature are
checked when the pack is built, and again at install when you supply an
external trust policy.

### Installer adjustments

The release workflow edits the generated installers after `dist` creates
them:

- `bhf-installer.sh` prints, before it runs, the repository,
  compiler-package and preload-shim commands that RHEL and CentOS 7 need.
  The generated installer stays reproducible.
- All four Unix installers check for `xz` before they download a `.tar.xz`
  archive, so a minimal RHEL host gets a clear missing-command message
  instead of failing during extraction.
- Both Linux preload-library installers get a corrected temporary-directory
  `chmod` path for cargo-dist 0.31, and a release gate checks that
  correction.
- The CLI and daemon PowerShell installers stop `Expand-Archive` from
  reading the console progress buffer, which fails in non-interactive
  Windows OpenSSH sessions.

## Binary-Only Distribution Package

When the build host has the source and the destination host should receive
only an installable package, as in an enclave, run:

```sh
scripts/package-offline-dist.sh \
  --signing-key keys/publisher.der --key-id publisher-v1 \
  --trusted-public-key keys/publisher.pub
```

When you supply no CVE databases or seeds, the script creates and packages:

```text
dist/content-inputs/sbom-cves.json
dist/content-inputs/binary-cves.json
dist/content-inputs/seeds/
```

The generated CVE databases are valid and empty. For SBOM or binary CVE
matching, replace them with real feed data (`--sbom-cve-db`,
`--binary-cve-db`) and run the same command again.

The script runs `cargo build --release --workspace` and stages:

- the CLI, the daemon, the runtrace shim and the compiler-interception shim;
- the harness runtime support files needed to compile generated harnesses
  on the destination;
- a small `bhf auto` smoke fixture;
- the `bhf-bug-report` support collector, which scrubs private data;
- an Ed25519-signed content pack and `install.sh`;
- documentation: `README.md`, `INSTALL.md`, `RELEASE_NOTES.md`, `LICENSE`,
  `README-DIST.md` (package context), `RUN-BHF.md` (running bhf after
  install) and the offline runbooks (`scripts/package-offline-dist.sh
  --help` lists the current set).

It writes `dist/bhf-dist-<version>-<triple>.tar.gz` with a SHA-256 sidecar
and a detached `.tar.gz.sig` Ed25519 signature. The package holds no bhf
application source.

The staged runtime trees cover C/C++, Ada, Rust, Java, Python, Perl, C#,
JavaScript and TypeScript, Ruby, Lua and PHP. COBOL, Fortran and Go use
their system toolchains and the shared C runtime. The installer selects all
sixteen language dependency profiles by default, interactively or not; pass
`--languages c,cpp` or another subset to install fewer.

The bundled `install.sh` shows a terminal checklist for languages, compile
targets, fuzzers and extras. Up and Down move through the options and the
OK and Cancel rows, Space toggles an option, and Enter accepts. A
non-interactive install of every feature:

```sh
./install.sh --non-interactive --trust-policy /trusted/operator-policy.json \
  --languages all \
  --targets native,windows,aarch64 \
  --fuzzers builtin,afl \
  --extras build-recovery,sandbox,archives
```

The installer needs a policy, provisioned independently, that pins the
publisher's public key. Authenticate the archive, the verifier and the key
out of band before you extract or run anything: a checksum sidecar from the
same channel cannot establish who published it. Check the detached
signature with a separately trusted `scripts/verify-offline-dist.sh` and the
publisher's public key before extraction. A pack built as checksum-only
(`--legacy-integrity-only`) is unauthenticated and installs only with
`--allow-legacy-integrity-only`.

After installing, the installer runs the bundled smoke fixture. Pass
`--no-smoke` to skip it, for example on a host without a C toolchain.

For every tagged release, the release workflow runs the same packager on
the EL7-baseline prebuilt binaries. It verifies the archive checksum and the
required payload, extracts the bundle, checks that `install.sh`,
`INSTALL.md`, `LICENSE`, `README.md` and `RELEASE_NOTES.md` are present, runs
the installer into a temporary prefix, and publishes the tarball and its
sidecar. The all-in-one bundle is therefore on the same glibc 2.17 baseline
as the component archives.

## Verification

```sh
sha256sum -c <asset>.sha256
```

GitHub Artifact Attestations are turned off (`github-attestations = false`
in `Cargo.toml`). To turn them on, set it to `true`, regenerate the
workflow and restore the `gh attestation verify` step.

## Release Flow

Before you push a release tag, set `[workspace.package].version` in
`Cargo.toml` to the tag's version, refresh `Cargo.lock`, and check dist's
local release plan:

```sh
dist host --steps=create --tag=X.Y.Z
```

Pushing a tag that matches a semantic version, such as `0.3.0`, runs the
release workflow. It plans the artifacts, builds the EL7-compatible Linux
archives and the Windows MSVC archives with their checksums, checks that
every harness runtime is inside each CLI archive, generates the Unix shell
and PowerShell installers, and uploads the verified artifacts to the GitHub
Release.

## Air-Gapped Packs

Update packs are local JSON manifests for rules, CVE databases, corpora and
other offline content. Create one with deterministic hashes and an Ed25519
publisher signature:

```sh
bhf pack keygen --private-key keys/offline-root.der --public-key keys/offline-root.pub
bhf pack create --root packs/current \
  --pack-id rules-2026-06 \
  --version 2026.06 \
  --item rules:rules/static.json \
  --item cve:cve/sbom-cves.json \
  --item cve:cve/binary-cves.json \
  --item corpus:corpus/seeds.tar.gz \
  --signing-key keys/offline-root.der --key-id offline-root \
  --out packs/current/update-pack.json

bhf pack verify packs/current/update-pack.json \
  --root packs/current \
  --policy bhf-policy.json
```

The legacy `--sign-key` option only labels an unkeyed digest; it does not
authenticate the pack. The verifying host must configure, independently,
`update_packs.trusted_public_keys: {"offline-root": "<64-character public key hex>"}`
and `require_signature: true`. Keep the private key on the signing host;
never transfer it with the pack.
[docs/enterprise-pack-authentication.md](../enterprise-pack-authentication.md)
specifies the canonical bytes, key rotation, revocation and legacy
behaviour.
