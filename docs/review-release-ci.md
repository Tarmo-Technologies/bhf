<!-- SPDX-License-Identifier: Apache-2.0 -->

# Release and CI fixes (baseline `5528a41`)

This page records the defects found at commit `5528a41` in the Linux
all-in-one bundle and installer (`scripts/package-offline-dist.sh`,
`scripts/install-dist.sh`), the release and CI workflows, and the declared
minimum Rust version, and what each one does now. [Release
packaging](release-packaging.md), [CI acceptance](ci-acceptance.md) and
[Authenticated offline update packs](enterprise-pack-authentication.md)
describe the current behavior.

## Defects and fixes

1. **Rust minimum.** The workspace and README declared Rust 1.83, but the
   lockfile needed newer compilers: locked `icu_* 2.2.0` and
   `idna_adapter 1.2.2` require Rust 1.86, `tera 2.4.0` fails to build on
   1.86 with let-chain errors (E0658) although its metadata declares no
   higher minimum, and the source used `usize::is_multiple_of` (stable since
   1.87). The declared minimum and its CI check are now Rust 1.88.0
   (`rust-version` in `Cargo.toml`); `rust-toolchain.toml` pins the
   toolchain CI builds with.
2. **Install updates could delete a previous backup.** Backups were named
   with a one-second timestamp, and an existing backup of that name was
   removed first, so two updates in one second lost the first backup. Each
   backup now gets a unique name (`<prefix>.backup.<timestamp>[.<n>]`).
3. **Pack verification ran after activation.** A malformed or untrusted pack
   failed the install with the new binaries already active. Pack
   verification and installation now run against the staged prefix, and a
   failure leaves the installed prefix and its symlinks unchanged.
4. **The installer deleted the caller's smoke work directory.** It ran
   `rm -rf` on `--smoke-work-dir`. It now uses that directory only as the
   smoke run's output.
5. **Unsafe distribution name.** The packager sanitized `--name` but accepted
   `.` and `..` before running `rm -rf "$OUT_ROOT/$NAME"`. An empty, `.` or
   `..` name is now rejected before any cleanup.
6. **An unauthenticated content pack was reported as signed.**
   `sha256-items-v1` packs carried a digest of public item metadata and a
   caller-chosen `key_id`, and verification reported a matching digest with
   a trusted label as `verified`/`trusted`. The legacy digest is now reported
   as `integrity_only` with `authenticated: false` and `trusted: false`, is
   rejected whenever the policy requires a signature or lists trusted keys,
   and a digest mismatch is rejected under every policy. `--sign-key` is a
   deprecated label that signs nothing. Publisher authentication now uses
   `ed25519-json-v1` signatures; see [Authenticated offline update
   packs](enterprise-pack-authentication.md).
7. **The staging path could delete a sibling.** The stage directory
   `<prefix>.new.<pid>` was removed recursively before staging. The installer
   now refuses an occupied stage path, creates a fresh empty directory, and
   rejects broad or relative install prefixes before any side effect. Pack
   installation and the smoke run use the staged prefix, so a failure leaves
   the old prefix, content and symlinks intact. If the final stage-to-prefix
   move fails after the old prefix was backed up, the installer restores the
   old prefix and keeps the staged tree for diagnosis. Symlinks are updated
   last. `install.json` records the final pack directory
   (`--reported-install-dir`), not the stage.
8. **The Docs Site workflow failed on its page manifest.** `docs/site/ato.md`
   and `docs/site/docker.md` were missing from `PAGES` in
   `scripts/docs/build-site.py`, so `validate_manifest` stopped the build.
   Both pages now have routes, and the builder maps the `docker.md` link to
   the root README (`../../README.md#resource-requirements`) to its
   repository URL.
9. **Release regression tests asserted stale claims.** `m19_signed_releases`
   asserted that the release docs call the digest pack signed and that the
   Windows install docs pin `v0.2.19`. The tests now assert that the docs
   describe SHA-256 integrity without publisher authentication, and derive the
   Windows example version from `[workspace.package].version` while checking
   the CI smoke and release workflow version sources. The OS matrix checks are
   unchanged.

## Installer limits

- Existing-prefix symlinks and canonical broad roots are rejected; other
  mount points or path aliases you supply are not checked.
- A failure while updating symlinks after activation can leave a partly
  updated bin directory. The previous prefix stays in its backup for manual
  recovery.
- Between the two prefix renames the public prefix briefly does not exist;
  an interruption at that moment needs manual recovery from the backup.
- Concurrent installer runs are not serialized. Use an external lock if more
  than one install can run at a time.

## Tests

- `cargo test --locked --offline -p bhf --test offline_dist_scripts` runs
  the packager and installer against temporary bundles with mocked binaries.
  It covers backup retention, failed pack verification, preserving the smoke
  work directory, unsafe distribution names, a forged trusted key, legacy
  digest packs under an integrity-only policy, and injected failures in pack
  install, smoke, and the final activation move. Successful updates keep
  packs, corpora and a working prefix symlink.
- `cargo test --locked --offline -p bhf --test m19_signed_releases` checks
  the release documentation and workflow contracts.
- The release workflow's manylinux2014 build, Ubuntu/RHEL/Windows smoke
  matrix, cargo-dist assembly and upload run only on hosted runners, as does
  the Docs Site workflow.
