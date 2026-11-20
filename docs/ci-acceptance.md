<!-- SPDX-License-Identifier: Apache-2.0 -->
# CI acceptance and release evidence

This page describes how bhf's CI decides that a commit passed: the
`CI acceptance` gate, the container image scan, the nightly integration suite,
and how to run the policy checks yourself.

## The acceptance decision

The `CI acceptance` job (`ci-acceptance`) in `.github/workflows/ci.yml`
aggregates the job results of the **same workflow run** and records the exact
checked-out commit in `ci-acceptance.json`. The receipt is uploaded even when
the gate rejects a run. It records which jobs of this workflow passed for
that commit.

| Decision | Meaning | Full CI evidence? |
| --- | --- | --- |
| `PASS_FULL_CI` | The classifier, policy tests, and every required build, test and platform job succeeded. | Yes, for the recorded commit and the jobs of this workflow. |
| `PASS_DOCS_ONLY` | Classification explicitly permitted documentation-only skips; mandatory policy checks and the release and docs contract tests (`doc-contracts`) succeeded and no listed job failed or was cancelled. | No. |
| `BLOCKED` | A required result is missing, unsuccessful, malformed, or incompatible with the selected scope. | No. |

A successful job label, an empty result set, or an earlier commit's result
does not count as a complete run. A documentation-only pass is not
release-candidate build evidence. A manual `workflow_dispatch` run always
selects full CI, and the aggregator then refuses a documentation exemption.

## Required coverage and regression safeguards

The gate requires the minimum-Rust check, the workspace build and tests
(including the optional-feature steps), the RHEL 7 build, the RHEL-family and
Ubuntu release compatibility matrices, the Windows build and tests, Windows
Server 2025 compatibility, the path classifier, and the CI policy tests.

The workflow-contract tests check that every job declared in `ci.yml` is in
the aggregation policy and in the gate's `needs` list, so adding a job
without a policy update fails those tests. A matrix job counts through GitHub's
aggregate result for the whole job, never one matrix entry.

The path classifier (`scripts/ci/should-run-heavy-ci.sh`) treats Markdown
under crates, fixtures, benchmarks and `vendor/` as test input. Unknown files,
and a failed or partial `git diff`, select full CI. The documentation and
website exemptions are listed one by one in the script.

The release and docs contract tests (the `m19_*`, `offline_dist_scripts` and `release_bundle_manifest` binaries, and the tests that check a guide against the code) read `README.md`, `INSTALL.md` and `docs/site/*.md` and take seconds. `build-test` runs the library tests and those three groups of binaries on every code change. A documentation-only change, which skips the heavy jobs, runs the `doc-contracts` job instead: it runs every test that reads a documentation page (a file under `docs/` or a Markdown page at the repository root), in the `bhf`, `bhf-daemon` and `lang_profile` crates, and the help-text contracts `command_help_cli` and `the_config_help_lists_every_config_key`, with GNAT installed so `cli_md_common_flow` runs the Ada pipeline in `docs/site/cli.md`. It also runs `license_audit_subcommand_exits_zero_for_current_repo`, which audits the repository and so reads `THIRD_PARTY.md`. `scripts/ci/tests/test_doc_contracts.py` finds those tests by scanning the Rust sources, lists the tests that read a page through library code, and fails when the job's filter misses one. `PASS_DOCS_ONLY` requires that job to pass; a full run may skip it.

Each Windows native test command is followed by an exit-code check, so a
later successful test cannot hide an earlier failed command. CI Cargo
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

`.github/workflows/integration-nightly.yml` runs daily and runs every bhf
integration test in 13 shards (12 hash shards and one for
`build_recovery_scenarios`). A 14th shard, `ignored`, runs the `#[ignore]`d
tests the PR suites leave out because they need minutes of fuzzing or a quiet
machine: the Lua line-hook cost benchmark (`auto_lua_hook`), the
RedQueen/cmplog cold-solve discriminators (`redqueen_cmplog`, including
`cold_gate_needs_redqueen`, which solves the integer gate in 2000 executions
at a fixed seed with RedQueen and not with `BHF_DISABLE_REDQUEEN=1`) and the
engine-parity cold-solve sweep (`engine_parity`). Its gate
(`scripts/ci/nightly-gate.py`) skips a scheduled run only when an earlier run
at the same commit ran every shard and all of them passed; a skipped run,
which GitHub records as a success, does not count. A nightly that failed
therefore runs again each day while the commit is unchanged, and a manual
dispatch always runs. A failed or timed-out shard opens one issue labelled
`integration-nightly` for the branch, or updates the open one, and comments on
it when a new commit fails; close it once a nightly passes.

A `build` job compiles every test binary once, with line tables only, into
one nextest archive (`cargo nextest archive --profile ci`). The archive also
carries the runtrace shim and the compiler intercept, which bhf preloads from
beside itself, and the release bhf (`archive.include` in
`.config/nextest.toml`). Every shard downloads it and runs `cargo nextest run
--archive-file ... --extract-to .`, so the binaries sit where they were built
and no shard compiles. The heavy tests run the prebuilt bhf that
`BHF_TEST_BIN` names instead of `cargo run --release`; set it locally to a
release bhf to skip that build too.

Each shard installs these toolchains: Lua 5.4, PHP with pcov, Ruby, Perl, JDK
21, Node 24 with esbuild, a nightly Rust, the SharpFuzz tool, GNAT 13 with
GPRbuild, AFL++, GnuCOBOL 3, Wine with the MinGW-w64 cross compilers,
qemu-user with the AArch64 cross compilers, `qemu-system-arm` with
`gcc-arm-none-eabi`, gdb, lldb, LLVM, and SymCC (built by
`scripts/ci/install-symcc.sh`). It runs its tests with `BHF_REQUIRE_TOOLS=1`,
so a test's tool check (`support::require_tool`) fails the test when its tool
is missing. A test that skips for another reason prints a skip line (starting
with `skip`, `skipping`, `skipped` or `SKIP`) and passes;
`scripts/ci/check-no-skips.py` reads those lines from the JUnit report and
fails the shard on any that `scripts/ci/allowed-skips.txt` does not allow.
Each allowlist entry names a test another workflow runs and gives the
reason.

## Test reports, retries and hangs

CI's nextest runs (`build-test`, `doc-contracts` and every nightly shard) use
the `ci` profile in `.config/nextest.toml`. A failing test is retried once; a
test that then passes is reported FLAKY, listed in the job summary by
`scripts/ci/junit-summary.py`, and annotated as a warning. A test still
running after 10 minutes (5 slow-timeout periods of 120 s) is killed and
reported as a TIMEOUT failure. `build_recovery_scenarios` gets 50 minutes and
the `ignored` shard's tests (`auto_lua_hook`, `redqueen_cmplog`,
`engine_parity`) get 25 minutes each, both with no retry. Each job uploads its
JUnit report (`junit-*` artifacts, from `target/nextest/<profile>/junit.xml`),
which keeps every test's captured stdout and stderr, passing tests included,
even when the job fails. Run `cargo nextest run --profile ci ...` to reproduce
a CI run's behavior locally.

## Running and consuming the checks

Run the complete policy and shell-behavior regression suite on Linux. It
needs Python 3.10 or newer, Bash, tar, and OpenSSL with Ed25519 support, and
no Rust or network access:

```sh
python3 -m unittest discover -s scripts/ci/tests -v
```

The shell and workflow fixtures model the Ubuntu CI jobs with POSIX paths and
mock executables, so run them on Linux. The acceptance-policy tests alone also
run with native Windows Python:

```sh
python -m unittest discover -s scripts/ci/tests -p test_ci_acceptance.py -v
```

To evaluate the policy on an exported `needs` observation from one run,
without running builds:

```sh
python3 scripts/ci/check-ci-acceptance.py \
  --commit "$EVALUATED_COMMIT_SHA" --event push \
  --needs-file needs.json --require-full --output ci-acceptance.json
```

The script evaluates the JSON you give it: it does not fetch or authenticate
the observation, check that the SHA exists, rerun tests, or validate a
release download. As acceptance evidence, keep the GitHub run, its evaluated
SHA, its logs and the receipt together. On a pull request the checked-out SHA
is usually GitHub's test-merge commit, not the branch head.

Inputs are bounded in size and depth, and duplicate JSON keys are rejected.
The script exits nonzero on a failed or malformed observation, and a failed
evaluation replaces an earlier success receipt.

The workflow runs on pushes to `main` and `rtos-radar-fuzzing`, on pull
requests, and on manual dispatch.

## Branch protection and releases

Make **`CI acceptance`** a required status check in the repository settings,
alongside any other required workflows; defining the job does not change
branch protection. The release workflow calls CI with full validation forced
and requires an exact-revision, same-run acceptance export before it creates,
signs or publishes a release. The Linux installation smoke test extracts a
separately authenticated archive copy. [Enterprise release
controls](enterprise-release-controls.md) covers the workflow, its trust
boundaries, retry behavior, and the difference between source validation and
authenticating a rebuilt release artifact.

The gate covers the jobs of `ci.yml`. Other workflows (the nightly suite, the
image scan, the release workflow) report separately.

## History

The first version of the acceptance gate was checked locally with the
standard-library policy tests on Python 3.13.5, including runs of the Bash
classifier step against failed and partial diffs, missing refs, NUL-delimited
file names and manual-run selection. At its base commit
(`e3ccadbea4c9e1b2ebc63dc9e5d36c0d3f8a803b`) the installer called
`libc::renameat2` directly in `crates/governance/src/lib.rs`, which needs a
newer glibc than RHEL 7 has; the [portability repair of
2026-09-25](portability-hardening-2026-09-25.md) replaced that call and added
the governance tests to the EL7 build job.
