<!-- SPDX-License-Identifier: Apache-2.0 -->
# Production Readiness Review, 2026-09-24

Baseline: `5528a41` (workspace version 0.2.32), branch `dockerize`.

This review checked the implementation against the documented behavior, ran
the available checks, and recorded the fixes and the release gates that
remained. It is a dated record of that pass. Later work is tracked in the
[Enterprise readiness program](enterprise-readiness-program.md), and the
current plan is in [DEVELOPMENT_PLAN.md](../DEVELOPMENT_PLAN.md).

## Review areas

| Area | Scope | Detail |
|---|---|---|
| PR-01 | Daemon and editor trust boundaries, request handling, process lifecycle | [Daemon and editor review](review-daemon-editors.md) |
| PR-02 | Distribution, CI, declared Rust support, installation correctness | [Release and CI review](review-release-ci.md) |
| PR-03 | Feature completeness, optional engines, documented gaps, remaining work | [Feature completeness review](review-feature-completeness.md) |

Workspace validation, the core CLI checks, this summary and the SPDX manifest
were covered by the review itself. Each fix recorded its evidence and
acceptance check first and stayed within its area; broader redesigns went to
the backlog.

## Findings and corrections

- **PR-04 (high, PR-03 area).** Cleanup checked the leaf with
  `symlink_metadata` but followed intermediate symlinked directories in
  `auto/storage.rs::compact_build_caches` and in `clean.rs`'s removal of
  `auto/findings.csv`. Acceptance: temporary external sentinels survive
  symlinked `auto`, `harnesses`, harness and `incrate`/`rust_harness`
  ancestors, and normal cleanup and unlinking of leaf symlinks still work.
- **PR-05 (high, PR-01 area).** `capsule.rs::build_capsule` put the untrusted
  finding ID into a path passed to `remove_dir_all` without validating it.
  `ScratchDir::new` used a predictable PID directory and deleted any existing
  contents. Acceptance: traversal, absolute and separator-bearing IDs are
  rejected before any write, external sentinel directories survive,
  temporary directories are securely unique, and a requested packaging
  failure exits nonzero.
- **PR-06 (low).** `cargo fmt --all -- --check` reported three formatting
  differences in `auto/build_probe.rs` and `generate_harness.rs`. Acceptance:
  the formatting check passes.
- **PR-07 (high, PR-02 area).** Legacy pack "signatures" were public, unkeyed
  hashes and could not authenticate a publisher. They are now rejected under
  an authentication-required policy, and the integrity-only distribution
  policy is explicit. Public-key signing followed as separate work (see
  [Pack authentication](enterprise-pack-authentication.md)).
- **PR-08 (medium, PR-03 area).** A report test used `/tmp` as its source root
  and picked up unrelated generated-header fixtures; one CLI unit test failed
  on the baseline. The test now uses an isolated temporary project, with its
  assertions unchanged.
- **PR-09 (medium).** The generated SPDX manifest was missing four Docker and
  ATO documentation and configuration files, as well as the new review
  documents. It was regenerated and the headers checked.
- **PR-10 (medium, PR-03 area).** Version stamping watched `.git/HEAD` but not
  the current loose branch ref, so a rebuilt binary could report an old
  commit. Git's paths are now resolved, worktrees and packed-only refs
  included, and the branch ref is watched. The rebuilt binary reported
  `0.2.32-15-g5528a41-dirty`.
- **PR-11 (medium, PR-02 area).** Docs-site generation failed because its page
  manifest omitted `ato.md` and `docker.md`. Both pages are registered and the
  Docker page's link to the repository README is rewritten; all 41 pages
  generate and pass the builder's link validation.
- **PR-12 (medium, PR-02 area).** Two release-test assertions were stale: they
  expected signing language that was false, and Windows installation docs
  pinned to `v0.2.19`. The tests now require integrity-only wording and take
  the expected example version from the workspace manifest, keeping the OS
  matrix checks. The release test target passes.

PR-04 to PR-12 were implemented in the working tree; no commit or release was
made in this pass. The three area reviews also cover installer backup
retention and activation order, scheduler IDs and atomic persistence,
replay-command injection, protocol bounds, and Nyx fallback behavior.

## Release gates after this review

Supported workflows are distinguished from optional scaffolding and from the
target classes bhf reports as unsupported; the feature completeness review
links each limit to its implementation and measured examples. Release
acceptance needed:

1. CI on the proposed commit for the workspace and editor tests, Clippy,
   formatting, license checks and the new regression tests.
2. Hosted Windows, RHEL and Ubuntu ABI, packaging and installation jobs on
   these changes, including a passing Rust-minimum job.
3. A new run of the sixteen-language container sweep on a freshly built
   image. [The earlier 32-project record](validation/2026-09-24-docker-sweep.md)
   predates these changes; its four replaced projects and its low- and
   zero-coverage lanes still apply. The sweep was later re-run (see
   [Container validation](enterprise-container-validation.md)).
4. Public-key authentication and trusted-key distribution before signed
   update packs are advertised or used where an authenticated publisher is
   required.
5. Further lane-specific harness work from [Measured gaps](expected-gaps.md),
   prioritized by confirmed target classes, with representative fixtures and
   measured built-and-fuzzed gains for each.

## Open tasks at the end of the review

| Priority and status | Task and files | Acceptance |
|---|---|---|
| P1; bounded fix done, further failure modes open | The installer validates pack installation, seeds, help and a smoke test in staging before activation, restores the previous prefix if activation fails, and updates command links last; mocked installer tests pass | Test interruption between renames, simultaneous installers and a partial symlink update. `install.json` records the staging path used during installation; relocation metadata needs a follow-up. A smoke test of the real release package is still required |
| P1; implemented, Windows validation pending | VS Code runs replay as `ProcessExecution(executable, args)` in visible tasks; stored replay strings and terminal shell execution are removed; the editor tests pass | Run a native Windows extension-host smoke test with spaces, quotes and shell operators as literal arguments, and check the visible output and exit status |
| P2 | Bound daemon response production, give GNAT Studio requests a deadline, review scheduler shutdown of running jobs | An oversized finding fails with a controlled diagnostic; a silent daemon or a hung fuzz child cannot block the editor or shutdown; cleanup reaps owned children. Since implemented: [Daemon reliability](enterprise-daemon-reliability.md) |
| P2 | Public-key content-pack verification and trusted-key distribution in `governance`, the pack CLI and the distribution tooling | Tampered metadata and payloads, unknown keys and forged labels fail; valid signed packs verify offline; key rotation and compatibility have tests; the fail-closed behavior stays. Since implemented: [Pack authentication](enterprise-pack-authentication.md) |
| P2 | The measured harness gaps from the feature review, one target class and fixture per change | More real-code targets built and fuzzed within the same budget, with confidence and stub provenance and the unsupported classifications kept |
| P3 | Profile the repeated full work-directory traversals in `auto/storage.rs` (`compact_work_dir` runs nested before-and-after accounting) | Report the traversal count, wall time and peak memory on a large fixture before proposing shared accounting or incremental counters; keep quota and reclaimed-byte accounting correct |

The static symlink checks reject redirected descendants that already exist.
Concurrent swaps of an ancestor in an attacker-writable directory need
directory-handle-based operations or an enforced private work-directory
boundary, and a dedicated security review.

## Validation record

- Linux x86_64, Rust/Cargo 1.94.0; the baseline working tree was clean.
- `cargo deny --locked check`: advisories, bans, licenses and sources passed.
- `python3 -m unittest discover -s scripts/validation -p 'test_*.py'`: passed.
- `target/debug/spdx_check check` and `generate`: passed; manifest updated.
- `cargo clippy --workspace --all-targets --locked`: passed. Raising the Rust
  minimum enables advisory `manual_is_multiple_of` warnings in existing code;
  they are warnings, not build failures.
- `cargo fmt --all -- --check`: passed after the formatting fixes.
- VS Code and GNAT Studio test suites: passed.
- Targeted daemon, scheduler, capsule, cleanup, storage, report, installer and
  pack-policy regression tests: passed; the commands are in the area reviews.
- Installer failure injection: passed, including pack-install failure, smoke
  failure, and activation failure that preserves or restores the prior
  install.
- Optional LibAFL feature tests: passed. The optional GNAT probe feature
  compiled under `BHF_PROFILE=external-tools` (no tests run).
- Nyx adapter (since removed with the other unused crates): its default and
  `nyx-engine` tests passed; they checked the explicit unsupported behavior.
- Rebuilt CLI scan and C fuzz smoke test: one target built and fuzzed,
  32 executions, target entry observed, 10 coverage edges. Artifacts in
  `/tmp/bhf-production-smoke.ZEKfj5` (local, temporary).
- Docs-site build: 41 pages, Docker and ATO/RMF included; the generated-link
  validation passed.
- Rust minimum: compiling with 1.86 hit Tera let-chain usage that its
  `rust-version` metadata does not declare.
  `cargo +1.88.0 check --locked --offline --workspace --all-targets` passed in
  an isolated target directory. The supported minimum and the CI gate became
  1.88.
- The
  [latest completed CI run](https://github.com/Tarmo-Technologies/bhf/actions/runs/35672265412)
  at the time passed for `60f640b440505491b0e0ebb6b9b57ce79ba9165d`, an
  earlier commit than this branch.
- `cargo test --workspace --no-fail-fast`: **5,541 passed, 2 failed,
  4 ignored**, exit status 101. Both failures were in `m19_signed_releases`
  (PR-12). After the PR-12 fix,
  `cargo test --locked --offline -p bhf --test m19_signed_releases` passed;
  the full workspace run was not repeated for that test-only change.
- The four ignored tests are the engine-parity cold-solve sweep, the slow
  RedQueen discriminator, and two harness-generator documentation examples.
  Some integration tests return early when a toolchain is missing, so the
  pass count covers the toolchains installed on this host.
- Full-suite log: `/tmp/bhf-production-final-tests.log` (local, temporary).
  The 32-project container matrix and the hosted release and platform runs
  were not re-run in this review.
