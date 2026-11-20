<!-- SPDX-License-Identifier: Apache-2.0 -->

# Release checklist

Work through this checklist for every version. The standard release shape is
the full distribution archive,
`bhf-dist-<version>-x86_64-unknown-linux-gnu.tar.gz`. Every release ships it
with its `.sha256`, detached `.sig` and `.sig.sha256` files. The archive has
`install.sh`, `INSTALL.md`, `LICENSE`, `README.md` and `RELEASE_NOTES.md` at
its root, alongside the CLI, the daemon, both Linux preload shims and the
harness runtimes.

## Automated gates (enforced by `.github/workflows/release.yml`)

The full CI that the release workflow calls also builds real cargo-dist
component archives and runs their generated installers. The Linux checks
cover the CLI, the daemon and both shims on the EL7 ABI, for x86_64 and, on
an ARM64 runner, aarch64. Windows Server 2022 and 2025 each run the CLI and
daemon installers under Windows PowerShell and PowerShell Core. These checks
use local artifact URLs, temporary install prefixes, archive and
installed-binary hash comparisons, and the exact source and version
identity; they run before anything is published, and publisher signing
happens later, in `sign-linux-bundle`.

The `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` installer
metadata require glibc 2.17, matching the manylinux2014 builds and the ABI
gate. This explicit cargo-dist setting keeps a global installer generated on
a newer host from raising the advertised floor.

- [ ] `build-local-artifacts` passes the raw Linux binaries to the protected
      `sign-linux-bundle` job. That job builds the full distribution archive
      with `scripts/package-offline-dist.sh`, signs it with the publisher
      key, and writes the archive and signature checksum sidecars.
- [ ] The archive-content gate fails the release if a mandatory root file is
      missing: `install.sh` (executable), `INSTALL.md`, `LICENSE`,
      `README.md` or `RELEASE_NOTES.md`.
- [ ] The gate authenticates a private copy before extraction and runs
      `install.sh --non-interactive --trust-policy <external-policy>` in a
      clean directory, then checks the installed `bhf`, `bhf-bug-report`
      and both shims, so an offline install from the archive is known to
      work.
- [ ] `cargo test -p bhf --test release_bundle_manifest` passes: the
      packaging script and the workflow gate both list every mandatory root
      file.

## Manual verification

- [ ] `RELEASE_NOTES.md` documents the major changes and the resume
      guarantees, including the build-context invalidation rules.
- [ ] The `README.md` resume section shows the stop, reboot and resume
      commands against the same `--work-dir`, and they work locally with
      `--resume`.
- [ ] Build-context invalidation is documented (GPR, `compile_commands.json`,
      IDL, `--project`, and the options that affect the harness).
- [ ] `RELEASE_NOTES.md` documents the default work-directory and corpus
      ceilings, non-destructive compaction, and the `results/INDEX.md`
      handoff.
- [ ] A smoke `auto` run leaves no private Rust Cargo `target/` tree, keeps
      finding evidence through `bhf clean <work> --compact`, and writes
      `results/findings.json` and `results/findings.csv`.
- [ ] No secrets or absolute host paths appear in the archive.

## Post-release

- [ ] The GitHub Release has the full distribution archive, its `.sha256`
      sidecar, the detached `.sig` and the `.sig.sha256` sidecar as assets.
- [ ] The release announcement names the full distribution archive as the
      primary offline and air-gapped installation method.

See [Release Packaging](release-packaging.md) for the artifacts and the
release flow, and [Offline Deployment](offline-deployment.md) for how
operators install the archive.
