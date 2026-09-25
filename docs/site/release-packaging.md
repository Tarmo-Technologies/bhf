<!-- SPDX-License-Identifier: Apache-2.0 -->

# Release Packaging

BHF uses `dist` to publish binary archives for the `bhf` CLI, the
`bhf-daemon` JSON-RPC/read-only-MCP service, the `bhf_runtrace_shim` cdylib that
`bhf auto` loads for runtime virtualisation on Linux, and the
`bhf_cc_intercept` cdylib that C/C++ build recovery uses to observe
absolute-path and `posix_spawn` compiler invocations.

The CLI archives include the complete Ada, C/C++, C#, Java, JavaScript,
Lua, Perl, PHP, Python, Ruby, and Rust harness-runtime trees. The executable
also embeds those sources as a fallback for shell/PowerShell installer installs,
so neither install style depends on a source checkout or a CI build path.

## Artifacts

The CLI and daemon archives are built for `x86_64-unknown-linux-gnu` and
`x86_64-pc-windows-msvc`. The GNU/Linux build runs in a pinned manylinux2014 /
CentOS 7 container. An automated gate rejects GLIBC requirements newer than
2.17 and missing preload-hook exports, fixing the release ABI for Ubuntu
22.04/24.04/26.04 LTS and RHEL 7 through RHEL 10 instead of inheriting a newer
Ubuntu runner's glibc. Release binaries are scan/build/fuzz tested across that
Linux matrix. The Windows build runs on Windows Server 2022 and the same binary
is smoke-tested on Server 2025; Windows Server 2019, Windows 11 Enterprise 25H2,
and Windows 11 Enterprise LTSC 2024 are covered by the platform VM validation.
The runtime
preload libraries are Linux-only and use package-local targets, so they remain
separate Linux cdylib assets rather than empty Windows artifacts. macOS,
Linux/aarch64, and Windows-on-Arm artifacts are not currently published.

The GitHub Release contains the all-in-one Linux `install.sh` bundle,
per-component platform archives, Unix shell installers, and PowerShell
installers for the portable Windows components:

Choose one delivery form per component: run its installer on a connected host,
or download its archive and checksum for a manual/offline install. The installer
already downloads the archive, so keeping both is unnecessary.

| Consumer scenario | Assets to use |
|---|---|
| Linux, complete one-package install | `bhf-dist-<version>-x86_64-unknown-linux-gnu.tar.gz` and its sidecar; extract and run the bundled `install.sh` |
| Windows terminal/CI | `bhf-installer.ps1`, or the `bhf-*.zip` and its `.sha256` sidecar—not both |
| Linux terminal/CI, basic features | `bhf-installer.sh`, or the Linux `bhf-*.tar.xz` and sidecar—not both |
| Linux, full `bhf auto` on real projects | The Linux CLI plus `bhf_runtrace_shim` and `bhf_cc_intercept`; use either all three installers or all three archives/sidecars |
| IDE, JSON-RPC, or read-only MCP | Add the OS-appropriate `bhf-daemon` installer/archive to the components needed for the workload |
| Source audit/rebuild | `source.tar.gz` and `source.tar.gz.sha256`; no binary asset is required merely to inspect source |
| Release automation | `dist-manifest.json` plus the relevant checksum sidecars, or `sha256.sum` for the full archive set |

The daemon is never required by the normal CLI. The two preload shims are
Linux-only; Windows users should ignore them. Omitting the runtrace shim keeps
ordinary scan/build/fuzz functionality but removes runtime audit, behavioral/
taint oracles, and fake-resource support. Omitting the compiler-interception
shim affects only complex C/C++ build recovery that must observe absolute-path
or `posix_spawn` compiler launches.

| Component prefix | Purpose | Required for |
|---|---|---|
| `bhf-dist-*` | All-in-one Linux bundle with `install.sh`, CLI, daemon, both shims, runtimes, content pack, and smoke fixture | Complete Linux or air-gapped install after external signature verification |
| `bhf-*` | Main CLI | All CLI workflows |
| `bhf_runtrace_shim-*` | Runtime virtualisation `LD_PRELOAD` shim | Full `bhf auto` runtime audit/fake-resource support |
| `bhf_cc_intercept-*` | Build-time compiler interception `LD_PRELOAD` shim | C/C++ `--probe-build` / `--build-command` recovery when builds invoke compilers by absolute path or via `posix_spawn` |
| `bhf-daemon-*` | JSON-RPC and read-only MCP daemon | IDE/editor or MCP/agent integrations |
| `source.tar.gz` | Release source snapshot | Source audit or rebuilds |
| `dist-manifest.json`, `sha256.sum`, `*.sha256` | dist metadata and checksums | Automation and integrity verification |

For manual component installs, copy `libbhf_runtrace_shim.so` and
`libbhf_cc_intercept.so` into the extracted `bhf-*` CLI directory, or
set `BHF_RUNTRACE_SHIM` / `BHF_CC_INTERCEPT` to absolute extracted
paths. Only the runtrace shim has sibling-archive-directory discovery; the
compiler-interception shim must be directly beside the CLI or explicitly
configured. Every component archive includes `INSTALL.md` with exact commands.
For component-installer installs, run each installer you need; installing
`bhf` alone installs only the CLI. Each archive has a SHA-256 checksum
sidecar, and the all-in-one distribution carries a content pack whose SHA-256
digests and Ed25519 publisher signature are checked during package creation
and install when the operator supplies an external trust policy. The checksum
sidecars alone do not authenticate a publisher.

The release workflow post-processes the main Unix `bhf-installer.sh` so
RHEL and CentOS 7 users see the required repository, compiler-package, and
separate preload-shim installation commands before the installer runs. This
keeps the generated cargo-dist installer reproducible while making its scope
and the complete EL7 setup explicit.

All four Unix installers are also post-processed to require `xz` before they
download a `.tar.xz` archive. This gives minimal RHEL installations an immediate
missing-command diagnostic instead of failing partway through extraction.

It also post-processes both Linux preload-library installers to correct
cargo-dist 0.31's temporary-directory `chmod` path. A release gate checks the
corrected path so a shim installer cannot be published with the known failure.
The CLI and daemon PowerShell installers are post-processed as well so
`Expand-Archive` does not access a console progress buffer in non-interactive
Windows OpenSSH sessions.

## Binary-Only Distribution Package

For customer or enclave installs where the build host has source but the
destination host should receive only an installable package, use:

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

The script builds `cargo build --release --workspace`, stages the CLI, daemon,
runtrace shim, compiler-interception shim, harness runtime support files, a tiny
`bhf auto` smoke fixture, the `bhf-bug-report` privacy-scrubbing support
collector, an Ed25519-signed content pack, and `install.sh`, then writes
`dist/bhf-dist-<version>-<triple>.tar.gz` plus a SHA-256 sidecar and detached
`.tar.gz.sig` Ed25519 signature. The
package does not include the BHF application source tree; it does include
runtime support files needed to compile generated harnesses on the destination.
It also includes `README-DIST.md` for package context, `INSTALL.md` for both the
installer and manual co-location choices, and `RUN-BHF.md` for post-install
operation.

The staged runtime trees cover C/C++, Ada, Rust, Java, Python, Perl, C#,
JavaScript/TypeScript, Ruby, Lua, and PHP. COBOL, Fortran, and Go use their
system toolchains plus the shared C runtime and do not have separate runtime
trees. `--languages all` selects all sixteen installer dependency profiles;
the interactive/default profile remains the original eight core lanes so new
toolchains are opt-in.

The bundled `install.sh` prompts with an arrow-key terminal checklist for
languages, compile targets, fuzzers, and extras. Up/Down moves through options
and the OK/Cancel rows, Space toggles options, and Enter accepts the highlighted
action. Non-interactive all-features install:

```sh
./install.sh --non-interactive --trust-policy /trusted/operator-policy.json \
  --languages all \
  --targets native,windows,aarch64 \
  --fuzzers builtin,afl \
  --extras build-recovery,sandbox,archives
```

The installer requires an independently provisioned policy pinning the
publisher public key. The archive, verifier, and key must themselves be
authenticated out of band before extraction or execution; a same-channel
checksum sidecar alone cannot establish publisher identity. Check the detached
signature with a separately trusted `scripts/verify-offline-dist.sh` and the
publisher public key before extraction. An explicitly produced checksum-only
pack requires `--allow-legacy-integrity-only` instead; it is not authenticated.

The installer runs the bundled smoke fixture by default after install; pass
`--no-smoke` only for constrained installs where the C toolchain is intentionally
absent.

The release workflow invokes the same packager with the EL7-baseline prebuilt
release directory for every tagged release, verifies the archive checksum and
required payload, extracts the bundle, requires `install.sh`, `INSTALL.md`,
`LICENSE`, `README.md`, and `RELEASE_NOTES.md`, runs the installer into a
temporary prefix, and publishes both the tarball and sidecar. This keeps the
one-package artifact on the same glibc 2.17 baseline as the component archives.

## Verification

```sh
sha256sum -c <asset>.sha256
```

GitHub Artifact Attestations are disabled in the generated workflow because
GitHub currently rejects attestation persistence for this private
Tarmo-Technologies organization/repository plan. When repository support is
available, re-enable `github-attestations = true`, regenerate the workflow, and
restore the connected `gh attestation verify` step.

## Release Flow

Before cutting a release tag, bump `[workspace.package].version` in `Cargo.toml`
to the exact tag version, refresh `Cargo.lock`, and validate dist's local
release plan:

```sh
dist host --steps=create --tag=vX.Y.Z
```

Tag pushes matching semantic versions, such as `v0.2.19`, run the generated
release workflow. The workflow plans artifacts, builds the EL7-compatible Linux
and Windows MSVC archives and checksums, verifies that every harness runtime is
inside both CLI archives, generates Unix shell and PowerShell installers, and
uploads the verified artifacts to the GitHub Release.

## Air-Gapped Packs

Update packs are local JSON manifests for rules, CVE databases, corpora, and
other offline content. Create one with deterministic hashes and an Ed25519
publisher signature. The legacy `--sign-key` option labels an unkeyed digest
and does not authenticate the pack:

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

The verifying host must independently configure
`update_packs.trusted_public_keys: {"offline-root": "<64-character public key hex>"}`
and `require_signature: true`. The private key must not be transferred with
the pack. The source-tree document `docs/enterprise-pack-authentication.md`
specifies canonical bytes, rotation, revocation, and legacy behavior.
