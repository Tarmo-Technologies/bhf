<!-- SPDX-License-Identifier: Apache-2.0 -->

# Release checklist

The full distribution archive (`bhf-dist-<version>-x86_64-unknown-linux-gnu.tar.gz`)
is the standard release shape. Every release must ship it, its `.sha256`,
detached `.sig`, and `.sig.sha256` files. The archive must contain
`install.sh`, `INSTALL.md`, `LICENSE`, `README.md`, and `RELEASE_NOTES.md` at its
root alongside the CLI, daemon, both Linux preload shims, and the harness
runtimes. This checklist is mandatory for every version.

## Automated gates (enforced by `.github/workflows/release.yml`)

The full CI called by the release workflow also builds real cargo-dist component
archives and exercises their generated installers. Linux checks cover the CLI,
daemon, and both shims on the EL7 ABI. Windows Server 2022 and 2025 each exercise
the CLI and daemon installers under Windows PowerShell and PowerShell Core.
The checks use local artifact URLs, temporary install prefixes, archive and
installed-binary hash comparisons, and exact source/version identity. They do
not publish a release or authenticate a publisher.

The `x86_64-unknown-linux-gnu` installer metadata requires glibc 2.17, matching
the manylinux2014 build and ABI gate. This explicit cargo-dist setting prevents
global installer generation on a newer host from raising the advertised floor.

- [ ] `build-local-artifacts` transfers the raw Linux binaries to the protected
      `sign-linux-bundle` job. That job builds the full distribution archive with
      `scripts/package-offline-dist.sh`, authenticates it with the publisher key,
      and emits the archive/signature checksum sidecars.
- [ ] The archive-content gate fails the release if any mandatory root file is
      missing: `install.sh` (executable), `INSTALL.md`, `LICENSE`, `README.md`,
      `RELEASE_NOTES.md`.
- [ ] The gate authenticates a private copy before extraction and runs
      `install.sh --non-interactive --trust-policy <external-policy>` in a
      clean directory, then verifies the installed `bhf`, `bhf-bug-report`,
      and both shims — proving an offline install from the archive works.
- [ ] `cargo test -p bhf --test release_bundle_manifest` passes (the packaging
      manifest and the workflow gate both list every mandatory root file).

## Manual verification

- [ ] `RELEASE_NOTES.md` documents the major changes and the resume guarantees,
      including the build-context invalidation rules.
- [ ] The `README.md` resume section shows the stop → reboot → resume commands
      against the same `--work-dir`, and they work locally with `--resume`.
- [ ] Build-context invalidation is documented (GPR, `compile_commands.json`,
      IDL, `--project`, and the harness-affecting options).
- [ ] `RELEASE_NOTES.md` documents the default work-directory/corpus ceilings,
      non-destructive compaction, and the root-level `FINDINGS.md` handoff.
- [ ] A smoke `auto` run leaves no private Rust Cargo `target/` tree, preserves
      finding evidence through `bhf clean <work> --compact`, and writes both
      root-level finding indexes.
- [ ] No secrets or absolute host paths appear in the archive.

## Post-release

- [ ] The GitHub Release contains the full distribution archive and its `.sha256`
      sidecar, detached `.sig`, and `.sig.sha256` sidecar as assets.
- [ ] The release announcement names the full distribution archive as the primary
      offline / air-gapped installation method.
