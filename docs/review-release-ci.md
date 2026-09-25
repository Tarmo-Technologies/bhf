<!-- SPDX-License-Identifier: Apache-2.0 -->

# Release and CI readiness review (PR-02)

Baseline: `5528a41`. This review covers the Linux all-in-one bundle and installer,
release/CI workflows, and the declared source-build Rust minimum.

## Confirmed findings before fixes

1. **Incorrect Rust minimum.** The workspace and README claim Rust 1.83, but
   `cargo metadata --locked --offline --format-version 1` reports locked
   `icu_* 2.2.0` and `idna_adapter 1.2.2` packages requiring Rust 1.86. Several
   other locked dependencies require 1.85. The `rust-toolchain.toml` channel is
   `stable`, not a pin to 1.83. A 1.83 source build cannot satisfy this lockfile.
   An actual `cargo +1.86.0 check --locked --offline --workspace --all-targets`
   failed in locked `tera 2.4.0`: ten E0658 let-chain errors (Tera does not
   declare the higher minimum in its metadata). The source also used
   `usize::is_multiple_of`, which local Rust 1.94 docs mark stable since 1.87.
   The declared floor and CI check are now Rust 1.88.0. A separate
   `CARGO_TARGET_DIR=/tmp/bhf-msrv188-target.T8lYox cargo +1.88.0 check
   --locked --offline --workspace --all-targets` passed locally.
2. **Install updates can destroy a previous backup.** `install-dist.sh` names
   backups with second-resolution timestamps and removes an existing backup at
   that name before moving the installed prefix. Two updates in one second can
   erase the first backup. Acceptance: each update preserves every prior backup.
3. **Pack integrity is checked after activating the new installation.** The
   installer moves the old prefix to a backup and activates the new prefix before
   `pack verify`. A malformed or untrusted bundled pack fails the installer with
   the new binaries active. Acceptance: pack verification failure leaves the
   installed prefix and symlinks untouched.
4. **User-specified smoke work is deleted.** The installer runs `rm -rf` on
   `--smoke-work-dir`, although the option names a caller-owned path. Acceptance:
   the installer never deletes a caller's work directory; the smoke command may
   use that path as its output destination.
5. **Unsafe distribution name.** The packager sanitizes `--name`, but accepts
   `.` and `..`; its staging cleanup then runs `rm -rf "$OUT_ROOT/$NAME"`.
   Acceptance: these names and empty sanitized names fail before any cleanup.
6. **Unauthenticated content pack is presented as signed (PR-07).**
   `create_update_pack_file` emits `algorithm: sha256-items-v1` with a digest of
   public item metadata and a caller-provided `key_id`; no private key is used.
   `update_pack_signature_summary` accepts a matching digest and `key_id` from
   `trusted_keys` as `verified`/`trusted`, so anyone able to replace the pack can
   forge the key label and recompute the digest. The bundle policy currently
   sets `require_signature: true` and trusts its own label. Acceptance for this
   bounded migration: report the legacy digest as `integrity_only` with
   `authenticated: false` and `trusted: false`; reject it whenever policy
   requires a signature or lists trusted keys; reject digest mismatches under
   all policies. Migrate bundled policy to checksum integrity only and correct
   release/offline text. `--sign-key` remains accepted as a deprecated label for
   compatibility, but does not sign anything. Real publisher authentication
   remains a future release gate requiring public-key verification and managed
   key distribution; existing strict-auth policies will now fail closed.
   The legacy digest covers item metadata only, not `pack_id` or `version`;
   manifest-level integrity and trusted distribution also remain future work.
7. **Installer staging path can delete a sibling.** `NEW_PREFIX` uses the
   process ID and is removed recursively before staging. A pre-existing path at
   that predictable name is deleted. Acceptance: refuse an occupied stage path
   and create a fresh empty directory; reject broad/relative install prefixes
   before any package or filesystem side effect. The post-activation failure
   boundary was also confirmed: pack installation or smoke failure could leave
   a failed new install active. Both now run against the owned staged prefix;
   failure leaves the old prefix, content, and symlinks intact. If the final
   stage-to-prefix move fails after backing up the old prefix, the installer
   restores the old prefix and retains the staged tree for diagnosis. Symlinks
   are updated last.
   The pack command records its stage `install_dir` in `install.json`; no code
   reads that field today, but making this metadata location-independent is a
   later compatibility cleanup outside this shell-only change.
   Existing-prefix symlinks and canonical broad roots are rejected, but this
   bounded guard does not prove safety for every possible user-supplied mount
   or path alias. A failure while updating symlinks after activation can still
   leave a partially updated bin directory; the prior prefix is preserved in
   the backup for manual recovery. The two prefix renames have a brief interval
   when the public prefix is absent, and a process interruption in that interval
   requires manual recovery from the backup. Concurrent installer runs are not
   serialized and need an external lock before claiming fully transactional
   updates.
8. **Docs Site workflow fails on its page manifest (PR-11).** The existing
   `docs/site/ato.md` and `docs/site/docker.md` are not listed in `PAGES` in
   `scripts/docs/build-site.py`. Its `validate_manifest` rejects the omission,
   so the workflow's build command fails before rendering any pages. Acceptance:
   give both pages unique routes in the navigation and successfully render all
   configured pages with generated relative links valid. Once routed, the
   existing `docker.md` link to `../../README.md#resource-requirements` is also
   exposed as a broken site-local link; the builder must map that root README
   reference to its repository URL. Both routes and that link are fixed.
9. **Release regression tests encode stale claims.** The baseline
   `m19_signed_releases` target asserts that release docs call the unkeyed
   content pack signed and that Windows installation docs pin `v0.2.19`. The
   first conflicts with the corrected integrity-only behavior; the second
   predates the current `0.2.32` workspace version. Acceptance: assert the
   docs explain SHA-256 integrity without publisher authentication, and derive
   the Windows example version from `[workspace.package].version` while checking
   the CI smoke and release workflow version sources. Keep all OS matrix gates.
   The assertions now enforce those contracts.

## Verification and release gates

- Use installer integration tests with temporary bundles for backup retention,
  failed pack verification, and smoke work directory preservation.
- Reject unsafe distribution names in a shell invocation test.
- Prove a forged trusted key cannot meet authentication policy and a matching
  legacy digest still verifies and installs under integrity-only policy.
- Validate shell syntax and the focused `offline_dist_scripts` test target.
- Focused installer tests passed: 22/22, including injected pack-install,
  smoke, and final activation-move failures. Successful update coverage checks
  preserved packs/corpora and a working prefix symlink. These use temporary
  mocked bundle binaries and do not replace the hosted full release-package
  smoke gate.
- Minimum-Rust CI must pass on a hosted runner; the local 1.88.0 workspace
  all-targets check passed.
- Release CI still needs an actual GitHub run for the manylinux2014 build,
  Ubuntu/RHEL/Windows smoke matrix, cargo-dist artifact assembly, and upload.
  Local inspection and tests cannot substitute for those hosted runners.
- Docs Site workflow must pass on a hosted PR run; local generation into an
  owned temporary directory succeeded at `/tmp/bhf-docs-site.n54Y9z/site`:
  41 pages rendered, both new routes exist, the root README link was rewritten,
  and `validate_generated_links` passed.
- `cargo test --locked --offline -p bhf --test m19_signed_releases` passed
  11/11 after replacing the stale integrity and Windows example assertions;
  its Linux/Windows release matrix checks remain active.
