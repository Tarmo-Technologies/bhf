<!-- SPDX-License-Identifier: Apache-2.0 -->
# Production readiness review — 2026-09-24

Baseline: `5528a41` (workspace version 0.2.32), branch `dockerize`.
Initial review and delegated fix pass completed. Continued enterprise-readiness
work is tracked in [the active program](enterprise-readiness-program.md); counts
and open states below describe the initial pass, not a final release signoff.
Substantial working functionality is
validated below, but remaining feature and release gates prevent a blanket
"all features complete / production ready" conclusion.

This review checks implementation against documented behavior, executes available
checks, and records concrete fixes and remaining release gates. A passing local
suite does not prove every platform, optional engine, or language toolchain works.

## Delegated work packages

Each owner must record evidence and acceptance checks in the linked handoff before
implementing a confirmed issue, keep changes within its scope, and report exact
validation results. Speculative improvements and broad redesigns belong in the
backlog, not unreviewed implementation changes.

| Package | Scope | Assigned model | Handoff |
|---|---|---|---|
| PR-01 | Daemon and editor trust boundaries, request handling, process lifecycle | GPT-6 Sol | [Handoff](review-daemon-editors.md) |
| PR-02 | Distribution, CI, declared Rust support, installation correctness | GPT-6 Sol | [Handoff](review-release-ci.md) |
| PR-03 | Feature completeness, optional engines, documented gaps, actionable remaining work | GPT-6 Luna | [Handoff](review-feature-completeness.md) |

The coordinating review owns workspace validation, core CLI checks, integration
review, this summary, and the SPDX manifest. The lower-cost agents implemented
the bounded fixes after recording their evidence and acceptance checks.

## Additional core findings and implemented corrections

- PR-04 (high, delegated to PR-03 owner): cleanup checks the leaf with
  `symlink_metadata` but follows intermediate symlink directories in
  `auto/storage.rs::compact_build_caches` and `clean.rs`'s
  `auto/findings.csv` removal. Acceptance: temporary external sentinels survive
  symlinked `auto`, `harnesses`, harness and `incrate`/`rust_harness` ancestors;
  normal cleanup and unlinking leaf symlinks still work.
- PR-05 (high, delegated to PR-01 owner): `capsule.rs::build_capsule` interpolates
  the untrusted finding ID into a path passed to `remove_dir_all` without validating
  it. `ScratchDir::new` uses a predictable PID directory and deletes any existing
  contents. Acceptance: reject traversal/absolute/separator-bearing IDs before
  writes, retain external sentinel directories, use securely unique temporary
  directories, and propagate requested packaging failures to a nonzero exit.
- PR-06 (low): baseline `cargo fmt --all -- --check` reports three formatting
  discrepancies in `auto/build_probe.rs` and `generate_harness.rs`. Acceptance:
  formatting check passes after focused formatting.
- PR-07 (high, delegated to PR-02 owner): legacy pack "signatures" are public,
  unkeyed hashes and cannot authenticate the claimed publisher. Reject them under
  authentication-required policy and make the integrity-only distribution policy
  explicit. Real cryptographic signing remains a separate implementation project.
- PR-08 (medium, delegated to PR-03 owner): a report test uses `/tmp` as its
  source root and discovers unrelated generated-header fixtures. Baseline workspace
  validation reproduced the failure with 1,680 CLI unit tests passing and one
  failing. Use an isolated temporary project without weakening assertions.
- PR-09 (medium, coordinating review): the generated SPDX manifest was missing
  four existing Docker/ATO documentation and configuration files in addition to
  the new review documents. Regenerate it and check headers before handoff.
- PR-10 (medium, delegated to PR-03 owner): version stamping watched `.git/HEAD`
  but not the current loose branch ref. Rebuilt binaries could advertise an old
  commit. Resolve Git's paths (including worktrees and packed-only refs) and watch
  the branch. The rebuilt binary now reports `0.2.32-15-g5528a41-dirty`.
- PR-11 (medium, delegated to PR-02 owner): docs-site generation failed because
  its page manifest omitted `ato.md` and `docker.md`. Register both pages and
  correctly rewrite the Docker page's repository README link; all 41 pages now
  generate and pass the builder's link validation.
- PR-12 (medium, delegated to PR-02 owner): the full sweep exposed two stale
  release-test assertions: false signing language and Windows installation docs
  pinned to `v0.2.19`. Tests now require honest integrity-only semantics and derive
  the expected example version from the workspace manifest, retaining OS matrix
  checks. The entire 11-test release target passes on rerun.

PR-04 through PR-12 have implementations in the working tree. The three detailed
handoffs also cover installer backup retention and activation order, scheduler
IDs and atomic persistence, replay-command injection, protocol bounds, and Nyx
fallback behavior. No commits or release publication were performed.

## Production acceptance boundaries

The review cannot certify "no issues" or universal feature completeness. Supported
workflows must be distinguished from optional scaffolding and target classes the
tool intentionally reports as unsupported. The detailed feature handoff links
those limits to implementation and measured examples.

Release acceptance still requires:

1. CI on the proposed commit confirming workspace/editor tests, Clippy,
   formatting, license checks, and the new targeted regressions. Local results
   and the precise full-sweep/rerun distinction are recorded below.
2. Hosted Windows, RHEL/Ubuntu ABI, packaging and installation jobs on these exact
   changes. Adding a Rust-minimum CI job is not evidence that it has passed.
3. Re-running the sixteen-language container sweep against a newly built image.
   [The existing 32-project record](validation/2026-09-24-docker-sweep.md) is useful
   historical evidence, not validation of changes in this review. Its four
   replaced projects and low/zero-coverage lanes remain relevant limitations.
4. Public-key authentication and trust/key distribution before advertising signed
   update packs or using them where authenticated publishers are required.
5. Further lane-specific harness work from [expected gaps](expected-gaps.md),
   prioritized by confirmed target classes. Fixing those requires representative
   fixtures and measured built-and-fuzzed improvements, not simply removing skips.

## Remaining implementation handoffs

Open tasks and validation gates are listed below. Two initially open P1 tasks
were handed back to the Sol agents while broad validation ran; their current
status is explicit. Each task is scoped for a separate reviewable change.

| Priority / next owner | Task and files | Acceptance |
|---|---|---|
| P1 / bounded fix complete; further failure modes open | Installer validates pack installation, seeds, help and smoke in staging before activation, restores the previous prefix if activation fails, and updates command links last. 22 mocked installer tests pass. | Still test interruption between renames, simultaneous installers, and partial symlink-update failure. `install.json` records the staging path used during installation; relocation metadata needs a follow-up. Real release-package smoke remains required. |
| P1 / implementation complete; Windows validation pending | VS Code now uses `ProcessExecution(executable, args)` in visible tasks. Stored replay strings and terminal shell execution are removed; 18 editor tests pass. | Run a native Windows extension-host smoke test with spaces, quotes and shell operators as literal arguments; verify visible output and exit status. |
| P2 / GPT-6 Sol | Bound daemon response production and give GNAT Studio requests a deadline; review scheduler shutdown of running jobs. | Oversized findings fail with a controlled diagnostic; a nonresponding daemon and hung fuzz child cannot block editor/shutdown indefinitely; cleanup reaps owned children. |
| P2 / GPT-6 Sol, reviewed by security owner | Add actual public-key content-pack verification and trusted-key distribution in `governance`, pack CLI and distribution tooling. | Tampered metadata/payloads, unknown keys and forged labels fail; valid signed packs verify offline; key rotation and compatibility have explicit tests. Do not relax the new fail-closed behavior. |
| P2 / lane-specific GPT-6 Sol tasks | Work through the measured harness gaps linked in the feature handoff. Start with one target class and fixture per change. | Demonstrate additional real-code targets built and fuzzed within the same budget, preserving confidence/stub provenance and unsupported classifications. |
| P3 / GPT-6 Luna measurement task | Profile repeated full workdir traversals in `auto/storage.rs` (`compact_work_dir` invokes nested before/after accounting). | Report traversal count, wall time and peak memory on a large fixture before proposing shared accounting or incremental counters; preserve quota and reclaimed-byte correctness. |

Static symlink checks prevent existing redirected descendants, but do not close
concurrent ancestor-swap races in attacker-writable directories. Stronger
multi-principal filesystem isolation requires directory-handle-based operations
or an enforced private work-directory boundary and a dedicated security review.

## Validation record

- Linux x86_64, Rust/Cargo 1.94.0; baseline working tree was clean.
- `cargo deny --locked check`: passed advisories, bans, licenses, and sources.
- `python3 -m unittest discover -s scripts/validation -p 'test_*.py'`: 14 passed.
- `target/debug/spdx_check check` and `generate`: passed; manifest updated.
- Baseline workspace run: stopped on PR-08; the broad run used `--no-fail-fast`
  to expose failures in later crates and integration targets as well.
- `cargo clippy --workspace --all-targets --locked`: passed. Raising the Rust
  minimum enables five advisory `manual_is_multiple_of` warnings in existing
  code; these are not build failures or correctness findings.
- `cargo fmt --all -- --check`: passed after formatting corrections.
- VS Code: 18 tests passed; GNAT Studio: 14 tests passed.
- Targeted daemon/scheduler/capsule, cleanup/storage/report, installer and pack
  policy regressions: passed; exact commands/counts are in the owner handoffs.
- Installer failure injection: 22 tests passed, including pack-install failure,
  smoke failure and activation failure preserving/restoring the prior install.
- Optional LibAFL feature: 5 tests passed. Optional GNAT probe feature compiled
  under `BHF_PROFILE=external-tools` (zero tests; not runtime validation).
- Nyx adapter: 6 default-feature tests and 3 `nyx-engine` tests passed; the latter
  checks explicit unsupported behavior, not real Nyx fuzzing.
- Rebuilt CLI scan + C fuzz smoke: 1 target built and fuzzed, 32 executions,
  target entry observed, 10 coverage edges. Artifacts:
  `/tmp/bhf-production-smoke.ZEKfj5` (local, temporary).
- Docs-site build: 41 generated pages, including Docker and ATO/RMF, with
  generated-link validation passing.
- Rust minimum: actual 1.86 compilation found Tera let-chain usage absent from
  dependency `rust-version` metadata. `cargo +1.88.0 check --locked --offline
  --workspace --all-targets` passed in an isolated target directory. The supported
  minimum and CI gate are now 1.88.
- Read-only GitHub CI lookup: [latest completed CI run](https://github.com/Tarmo-Technologies/bhf/actions/runs/35672265412)
  passed for `60f640b440505491b0e0ebb6b9b57ce79ba9165d`, not this local
  `dockerize` branch at `5528a41` or these uncommitted changes. It is not a
  substitute for final platform validation.
- Broad run, `cargo test --workspace --no-fail-fast`: completed 331 test-result
  summaries with **5,541 passed, 2 failed, 4 ignored**. Its exit status was 101;
  the sole failing target was `m19_signed_releases` (PR-12).
- After fixing those assertions, `cargo test --locked --offline -p bhf --test
  m19_signed_releases` passed **11/11**. No other broad-run target failed.
  The long workspace sweep was not repeated for these test-only assertion
  corrections. Changed components also have the targeted runs listed above.
- Four explicit ignores remain: the engine-parity cold-solve sweep, the slow
  Redqueen discriminator, and two harness-generator documentation examples.
  Some integration tests also return early when a toolchain is absent; a passing
  count alone does not establish complete sixteen-language or platform coverage.
- Full-suite logs are local temporary evidence in
  `/tmp/bhf-production-final-tests.log`. The 32-project container matrix and
  hosted release/platform runs were not re-executed in this review.
