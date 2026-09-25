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
| `PASS_DOCS_ONLY` | Classification explicitly permitted documentation-only skips; mandatory policy checks succeeded and no listed job failed or was cancelled. | No. |
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

Each Windows native test command is immediately followed by an exit-code check,
so a later successful test cannot conceal an earlier failed command. CI Cargo
commands use `--locked`, runner jobs have time limits, and checkouts do not
persist credentials.

## Running and consuming the checks

Run the policy and shell-behavior regression suite without Rust or network
access (Python 3.10+ and Bash are required):

```sh
python3 -m unittest discover -s scripts/ci/tests -v
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
the job does not change branch protection. This change set does not alter
repository rules, and it does not wire this policy into the separate release
publishing workflow. Release publication still needs its own exact-revision and
artifact-verification acceptance controls.

At the inspected base `e3ccadbea4c9e1b2ebc63dc9e5d36c0d3f8a803b`, the installer
still directly calls `libc::renameat2` in `crates/governance/src/lib.rs`. That
legacy-Linux compatibility issue is **not fixed by this change set**. Its
resolution must preserve atomic no-overwrite behavior and pass the real legacy
ABI build; weakening installer safety or skipping the failed lane is not an
acceptable substitute.

This gate deliberately does not assess separate workflows, held-out harness
quality, comparative engine effectiveness, long-duration operation, publisher
key custody, physical hardware validation, or deployment authorization. Passing
it is one release-engineering condition, not evidence for universal embedded
compatibility or a best-in-class claim.

## Validation record: 2026-09-25

The change set's 50 stdlib regression tests passed locally on Python 3.13.5.
They include executions of the actual Bash classifier step with failed/partial
diffs, missing refs, NUL-delimited filenames, and manual-run selection. Both
modified workflow files also parsed as YAML in the editing environment.

The editing environment had no Rust toolchain and could not clone the repository
over its network connection. No native workspace, RHEL ABI, Windows execution,
or hardware success is claimed from that local run. Hosted CI results must be
checked separately for the published commit.
