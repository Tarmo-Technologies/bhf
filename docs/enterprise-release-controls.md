<!-- SPDX-License-Identifier: Apache-2.0 -->
# Enterprise release controls

## Scope

This increment connects the CI acceptance policy to the release workflow and
uses the existing verified-copy utility in the actual Linux installation smoke
path. It changes release engineering, not fuzzing engines or embedded targets.
It is based on `87151dbf26220b7fb10215af4a6c09ee0b7954ba` and preserves the
committed scheduler, VEX, EL7 prerequisite, and independent-verifier changes.

A local passing policy test is not a hosted release validation. The source
changes require application and hosted acceptance before they can be relied on
in a published release. No tag, release, merge to main, signing-key update, or
branch-protection change accompanies this implementation.

## Release path

A version-tag push calls the local `.github/workflows/ci.yml` with
`force_full: true`. The local reusable workflow resolves at the caller's source
revision. Both the path classifier and the final CI aggregator enforce full
validation. A documentation-only exemption cannot authorize a release.

The CI aggregator exports only its accepted decision, checked-out commit, run
ID, and producer attempt. The release gate requires the reusable workflow to
have succeeded and all four exports to be present and consistent with the
release context. It produces `PASS_RELEASE_CI` or `BLOCKED` in
`release-ci-acceptance.json`; failed observations replace stale success files.

Only after that gate succeeds can `release-plan` run the pre-existing
`dist host --steps=create` operation. Signing and publication also explicitly
depend on the gate. An `always()` condition allows the rejection receipt to be
produced after upstream failure; it does not override the policy decision.

The gate consumes the current workflow's `needs` outputs, not a user-supplied
artifact ZIP or the most recent green run on a different commit. The standalone
Python CLI does not authenticate arbitrary input JSON; outside Actions that
JSON is just an assertion. It does not query GitHub, modify repository rules,
verify archive signatures, or grant deployment authorization.

## Privileges and source identity

The release workflow defaults to `contents: read`. Pull-request planning stays
read-only and runs `dist plan`, not release creation. Only the gated tag-planning
and publishing jobs request `contents: write`. The reusable CI call receives no
inherited publisher secrets. The existing signing job retains its
`production-release` environment and scoped signing-key access.

Release checkouts explicitly select `github.sha` and do not persist credentials.
Tag arguments pass through quoted shell arguments. Runner jobs are time bounded.
The release concurrency group does not cancel an in-progress publishing run and
is distinct from the nested CI group, avoiding caller self-cancellation.

These source controls do not configure environment approvals, independently
trusted public keys, protected branches/tags, or reviewer requirements. A
maintainer who can change trusted workflow source can change this policy; the
repository's administrative controls remain part of the trust boundary.

## Verified-copy installation smoke

The existing Bash detached verifier remains in the signing path. Before
extraction, the Python verifier streams, hashes, authenticates, and publishes a
private copy under a fresh temporary directory. `tar` extracts that accepted
copy instead of reopening the original archive pathname. The original archive
is still the release upload candidate; the receipt identifies the authenticated
SHA-256 and the installation smoke's accepted copy.

`linux-bundle-verification.json` accompanies the signed Linux bundle workflow
artifact. This JSON is an unsigned workflow observation, not an additional
publisher signature or deployment approval. The existing detached signature
format is unchanged. Neither independent verifier's product source is modified
by this increment.

This narrows a verification-to-use race for the smoke installation. It does not
make output files immutable, validate an arbitrary archive's extraction safety,
or prove that a rebuilt artifact is bit-identical to an earlier CI binary.
The runner and its private temporary directories remain trusted. No signature,
revocation, anti-rollback, key-distribution, or crypto-policy requirement is
silently relaxed.

## Retry behavior

When validation fails, repair the source and start a new candidate validation;
do not turn skipped jobs into success. A release gate export from another run
or producer attempt is rejected. For a clean validation retry, choose **re-run
all jobs**, not just the release gate.

The attempt field identifies the acceptance-producing job. GitHub may retain
successful upstream jobs when only failed jobs are rerun; the receipt alone
therefore does not prove that every upstream job executed again in that attempt.
The retained full-CI logs and platform artifacts must accompany release review.
Already-created releases and partial publish retries retain cargo-dist/GitHub's
existing semantics; this change does not make publication transactionally
idempotent.

## Validation and reproduction

On a Linux host with Python 3.10+, Bash, tar, and OpenSSL supporting Ed25519:

```sh
python3 -m unittest discover -s scripts/ci/tests -v
```

The integrated suite contains 181 tests: 103 previously committed tests,
64 release policy/workflow tests carried forward from the earlier unlanded
proposal, and 14 new gate-to-extraction integration tests. All 181 passed locally
with zero failures or skips on Python 3.13.5 / OpenSSL 3.5.5. Existing source
copies used for local validation were checked against GitHub's Git blob hashes.

The integration tests execute both policy CLIs and the workflow's shell
fragments. They reject failure/cancellation/skipping of every required CI job,
missing results, documentation-only passes, wrong checkouts, and stale exports.
The archive tests use real temporary Ed25519 signatures, copying, and tar
extraction. Replacing the original archive immediately before tar still yields
the authenticated payload; tampering before verification stops before tar.
GitHub event/job observations and the crypto-unavailable condition are fixtures.

Two early combined integration runs hit their outer execution time limits during
local interpreter startup. The stdlib-only integration subprocesses now use
Python `-S` to exclude local site/customization hooks. No production command,
resource limit, gate requirement, or assertion was weakened. The final combined
run completed in approximately 24 seconds in that local environment; this is
not a service performance benchmark.

All three edited workflow files passed a duplicate-key-aware YAML parse and
local job-graph checks; 47 embedded Bash blocks passed static parsing. This is
not actionlint or hosted Actions validation. The editing environment could not
clone GitHub or run Rust. No native workspace, Windows/EL7 execution of this
patch, paid infrastructure, hardware, release publication, or accreditation
result is asserted.

## Relationship to earlier handoffs

Do not apply the older complete `BHF_enterprise_controls_2026-09-25` package on
top of this increment. Its release-control portion is integrated here against
the newer branch. Its proposed EL7 bootstrap and Bash verifier replacement are
not copied: the committed OpenSSL/bootstrap and independent verification work
supersede those overlapping pieces. Current scheduler regression steps and the
entire existing platform matrix are preserved.

For administrative enforcement, require `CI acceptance` in branch protection
and retain any separately required checks. Confirm a hosted run of the final
candidate, protected release environment configuration, and the actual published
artifact separately. Passing this release gate establishes none of the broader
best-in-class, multi-tenant, embedded-platform, or deployment-authorization claims.

## Reference semantics

GitHub's documented reusable-workflow output, caller-context, permissions, and
concurrency behavior informs this implementation:
https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations
https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax
