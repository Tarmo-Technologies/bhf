<!-- SPDX-License-Identifier: Apache-2.0 -->
# CI acceptance and release-evidence boundaries

## What the check establishes

The `CI acceptance` job in `.github/workflows/ci.yml` aggregates the **same
workflow run's** job results and records the exact checked-out commit in
`ci-acceptance.json`. The receipt is uploaded even when the gate rejects a run.
It is not an accreditation, benchmark result, artifact signature, or claim of
enterprise readiness.

| Decision | Meaning | Full CI evidence? |
| --- | --- | --- |
| `PASS_FULL_CI` | The classifier, policy tests, and every required build/test/platform job succeeded. | Yes, for the recorded commit and this workflow's scope only. |
| `PASS_DOCS_ONLY` | Classification explicitly permitted documentation-only skips; mandatory policy checks and the release and docs contract tests (`doc-contracts`) succeeded and no listed job failed or was cancelled. | No. |
| `BLOCKED` | A required result is missing, unsuccessful, malformed, or incompatible with the selected scope. | No. |

A successful job label, an empty result set, or an unrelated earlier commit
cannot stand in for a complete run. Documentation-only success must not be used
as release-candidate build evidence. A manual `workflow_dispatch` invocation
always selects full CI and the aggregator refuses a documentation exemption.

## Required coverage and regression safeguards

The aggregator includes the minimum-Rust check, workspace build/tests (including
the existing optional-feature steps), RHEL 7 build, RHEL-family and Ubuntu
release compatibility matrices, Windows build/tests, and Windows Server 2025
compatibility. It also requires the path classifier and CI policy tests.

The workflow-contract tests ensure that every job declared in `ci.yml` is in the
aggregation policy and in the gate's `needs` list. A new job requires a policy
update; do not silently drop it from acceptance. Matrix job success is consumed
as GitHub's aggregate result for that job, not inferred from one matrix entry.

Path classification now treats crate, fixture, benchmark, and vendor Markdown
as potentially executable/test-relevant input. Unknown files select full CI.
A failed or partial `git diff` also selects full CI. Documentation and website
exemptions remain narrowly enumerated in `should-run-heavy-ci.sh`.

The release and docs contract tests (the `m19_*`, `offline_dist_scripts` and
`release_bundle_manifest` binaries, and the tests that check a guide against
the code) read `README.md`, `INSTALL.md` and `docs/site/*.md` and take
seconds. `build-test` runs them on every code change. A documentation-only
change, which skips the heavy jobs, runs them in the `doc-contracts` job, and
`PASS_DOCS_ONLY` requires that job to pass; a full run may skip it.

Each Windows native test command is immediately followed by an exit-code check,
so a later successful test cannot conceal an earlier failed command. CI Cargo
commands use `--locked`, runner jobs have time limits, and checkouts do not
persist credentials.

## Container image vulnerability gate

The `container-core` and `container-full` jobs scan the image they built with
grype and review the scan with `scripts/ci/review-image-scan.py`. Critical,
High and unknown-severity matches, and Medium matches that have a fix, are
blockers. On pull requests and branch pushes the review is **report-only**: it
writes `release-review.json` with `"enforcement": "report-only"`, annotates the
blockers in the job log and summary, and exits 0, so a CVE published upstream
after a change does not turn `CI acceptance` red for that change. Tag runs,
`release` events, and runs of `release.yml` or `container-release.yml`
(including the CI run they call) **enforce** the gate and fail on any blocker,
whatever mode was requested; so does a manual or scheduled run, and any run
outside GitHub Actions. `--mode` (or `BHF_IMAGE_SCAN_MODE`) selects `auto`, the
default, `enforce` or `report-only`. A scan that did not run, or ran against an
invalid database or one built more than seven days earlier, fails in every
mode.

`.github/workflows/image-scan.yml` scans the core, Ada and full images daily.
When it finds blockers it opens one issue labelled `image-scan`, or updates the
open one, and comments on it when the blocker list changes. A manual run with
`seed_blocker` adds a synthetic blocker named `SEEDED-IMAGE-SCAN-BLOCKER`, to
check that a first run opens the issue and a second run updates it; close the
issue afterwards.

## Nightly integration suite

`.github/workflows/integration-nightly.yml` runs every bhf integration test in
13 shards, and a 14th, `ignored`, runs the `#[ignore]`d tests the PR suites
leave out because they need minutes of fuzzing or a quiet machine: the Lua
line-hook cost benchmark (`auto_lua_hook`), the RedQueen/cmplog cold-solve
discriminators (`redqueen_cmplog`, including `cold_gate_needs_redqueen`, which
solves the integer gate in 2000 executions at a fixed seed with RedQueen and
not with `BHF_DISABLE_REDQUEEN=1`) and the engine-parity cold-solve sweep
(`engine_parity`). Its gate (`scripts/ci/nightly-gate.py`) skips a scheduled run only
when an earlier run at the same commit ran every shard and all of them passed;
a skipped run, which GitHub records as a success, does not count. A nightly
that failed therefore runs again each day while the commit is unchanged, and a
manual dispatch always runs. A failed or timed-out shard opens one issue
labelled `integration-nightly` for the branch, or updates the open one, and
comments on it when a new commit fails; close it once a nightly passes.

A `build` job compiles every test binary once, with line tables only, into
one nextest archive (`cargo nextest archive --profile ci`) that also carries
the runtrace shim and the compiler intercept, which bhf preloads from beside
itself, and the release bhf (`.config/nextest.toml` `archive.include`); every
shard downloads it and runs `cargo nextest run --archive-file ... --extract-to
.`, so the binaries sit where they were built and no shard compiles. The heavy
tests that ran `cargo run --release` inside the test run the prebuilt bhf that
`BHF_TEST_BIN` names instead (set it locally to a release bhf to skip that
build too); the support helpers then never invoke cargo.

Each shard installs the interpreter, JVM,
TypeScript, Rust-nightly, C# and Cortex-M emulator toolchains (Lua 5.4, PHP
with pcov, Ruby, Perl, JDK 21, Node 24 with esbuild, a nightly Rust, the
SharpFuzz tool, `qemu-system-arm` with `gcc-arm-none-eabi`, gdb, lldb and LLVM)
and runs its tests with `BHF_REQUIRE_TOOLS=1`. A test that finds its tool
missing prints a skip line (one starting with `skip`, `skipping`, `skipped` or
`SKIP`) and passes; `scripts/ci/check-no-skips.py` reads those lines from the
JUnit report and fails the shard on any that `scripts/ci/allowed-skips.txt`
does not allow. The allowlist names the lanes the nightly does not install yet
(Ada, AFL++, COBOL, Wine and AArch64) and the few tests another workflow runs;
each entry gives its reason.

## Test reports, retries and hangs

CI's nextest runs (`build-test`, `doc-contracts` and every nightly shard) use
the `ci` profile in `.config/nextest.toml`. A failing test is retried once; a
test that then passes is reported FLAKY, listed in the job summary by
`scripts/ci/junit-summary.py` and annotated as a warning, rather than hidden. A
test still running after 16 minutes (8 slow-timeout periods of 120 s; 50
minutes for `build_recovery_scenarios`) is killed and reported as a TIMEOUT
failure. Each job uploads its JUnit report (`junit-*` artifacts, from
`target/nextest/<profile>/junit.xml`), which keeps every test's captured
stdout and stderr, passing tests included, even when the job fails. Run
`cargo nextest run --profile ci ...` to reproduce a CI run's behavior locally.

## Running and consuming the checks

Run the complete policy and shell-behavior regression suite on Linux without
Rust or network access (Python 3.10+, Bash, tar, and OpenSSL with Ed25519
support are required for the combined policy/distribution suite):

```sh
python3 -m unittest discover -s scripts/ci/tests -v
```

The shell/workflow fixtures model the Ubuntu CI jobs and use POSIX paths and
mock executables; they are not Windows/WSL integration tests. The standalone
acceptance-policy tests can also be run with native Windows Python:

```sh
python -m unittest discover -s scripts/ci/tests -p test_ci_acceptance.py -v
```

For an exported **same-run** `needs` observation, the policy can be evaluated
without executing builds:

```sh
python3 scripts/ci/check-ci-acceptance.py \
  --commit "$EVALUATED_COMMIT_SHA" --event push \
  --needs-file needs.json --require-full --output ci-acceptance.json
```

This CLI does **not** fetch or authenticate the observation, verify that its
claimed SHA exists, rerun tests, or validate a downloadable release. User-written
JSON can claim anything. For real acceptance evidence, retain the GitHub run,
its evaluated SHA, logs, and receipt together. On pull requests, the checked-out
SHA is normally GitHub's test-merge commit, not the source branch head.

Inputs are size/depth bounded and duplicate JSON keys are rejected. The tool
returns nonzero on failed or malformed observations; a failed evaluation
replaces an earlier success receipt rather than leaving stale success behind.

The workflow runs for pushes to `main` and `rtos-radar-fuzzing`, and for pull
requests. Manual workflow dispatch becomes available when the dispatcher-enabled
workflow is present on the default branch. This change does not dispatch a
release or merge the development branch.

## Administrative enforcement and remaining blockers

A repository administrator should make **`CI acceptance`** a required status
check, retaining any other independently required workflows. Merely defining
the job does not change branch protection. Repository rules remain an
administrative setting. The release workflow now calls CI with full validation
forced and requires an exact-revision, same-run acceptance export before
release creation, signing, or publishing. The Linux installation smoke test
extracts a separately authenticated archive copy. See
[enterprise release controls](enterprise-release-controls.md) for the workflow,
trust boundaries, retry behavior, and distinction between source validation
and authentication of a rebuilt release artifact.

Historical scope of the initial CI-only change: at its inspected base
`e3ccadbea4c9e1b2ebc63dc9e5d36c0d3f8a803b`, the installer directly called
`libc::renameat2` in `crates/governance/src/lib.rs`. Commit `30ee685` did not
correct that compatibility issue.

The subsequent portability repair removes that glibc wrapper dependency while
retaining atomic no-overwrite behavior, adds production-helper regressions, and
runs the governance tests in the permanent EL7 build lane. See
[the dated portability validation record](portability-hardening-2026-09-25.md)
for the observed native results and the limits of container-based ABI evidence.
This is not a claim that the whole release matrix has passed.

This gate deliberately does not assess separate workflows, held-out harness
quality, comparative engine effectiveness, long-duration operation, publisher
key custody, physical hardware validation, or deployment authorization. Passing
it is one release-engineering condition, not evidence for universal embedded
compatibility or a best-in-class claim.

## Initial validation record: 2026-09-25

The initial CI-only change set's 50 stdlib regression tests passed locally on
Python 3.13.5. They include executions of the actual Bash classifier step with
failed/partial diffs, missing refs, NUL-delimited filenames, and manual-run
selection. Both modified workflow files also parsed as YAML in that environment.

That editing environment had no Rust toolchain and could not clone the repository
over its network connection. No native workspace, RHEL ABI, Windows execution,
or hardware success is claimed from that local run. Subsequent hosted validation
is recorded separately in the dated portability record; full CI results must
still be checked for the exact published commit.
