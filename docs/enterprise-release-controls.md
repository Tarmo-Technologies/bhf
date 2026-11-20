<!-- SPDX-License-Identifier: Apache-2.0 -->
# Release Controls

This page describes how `.github/workflows/release.yml` ties a release to a
full CI run of the same commit, which privileges each job has, and how the
Linux installation smoke test installs only the bytes it verified. The CI
acceptance policy itself is described in [CI acceptance](ci-acceptance.md).

## Release path

1. A version-tag push calls the local `.github/workflows/ci.yml` as a reusable
   workflow (`validate-release-ci`) with `force_full: true`. A local reusable
   workflow resolves at the caller's commit. Both the path classifier and the
   final CI aggregator then require full validation, so a documentation-only
   exemption cannot authorize a release.
2. The CI aggregator (`CI acceptance`) exports four values: its decision, the
   checked-out commit, the run ID and the run attempt.
3. The `release-acceptance` job runs `scripts/ci/check-release-acceptance.py`
   on those exports. It requires the reusable workflow to have succeeded and
   all four exports to be present and to match the tag's commit, run and
   attempt. It writes `release-ci-acceptance.json` with the decision
   `PASS_RELEASE_CI` or `BLOCKED`. A failed check overwrites any earlier
   success file. The job runs under `always()`, so it uploads a rejection
   receipt even after an upstream failure; the receipt's decision still
   governs.
4. Only after `release-acceptance` succeeds does `release-plan` run
   `dist host --steps=create`. The signing job (`sign-linux-bundle`) and
   publication also require that success.

The gate reads the `needs` outputs of the current workflow run. A downloaded
artifact ZIP or a green run on another commit cannot satisfy it. Run outside
GitHub Actions, `check-release-acceptance.py` checks only the JSON it is
given: it does not query GitHub, change repository rules, verify archive
signatures or grant deployment authorization.

## Privileges and source identity

| Job or setting | Control |
|---|---|
| Workflow default | `contents: read` |
| Pull-request planning (`pull-request-plan`) | Read-only; runs `dist plan`, never creates a release |
| `release-plan` and the publishing jobs | `contents: write`, only behind the gate |
| Reusable CI call | `contents: read`; no inherited publisher secrets |
| Signing (`sign-linux-bundle`) | `production-release` environment and its scoped signing key |
| Checkouts | `ref: ${{ github.sha }}`, `persist-credentials: false` |
| Tag arguments | Passed as quoted shell arguments |
| Jobs | Each has a `timeout-minutes` bound |
| Concurrency | Group `release-<ref>`, `cancel-in-progress: false`, separate from the CI workflow's group so the call cannot cancel its caller |

Environment approvals, trusted public keys, protected branches and tags, and
reviewer requirements are repository settings outside the workflow source. A
maintainer who can change the trusted workflow source can change this policy,
so the repository's administrative controls are part of the trust boundary.
For enforcement, make `CI acceptance` a required check in branch protection,
next to any other required checks.

## Verified-copy installation smoke

The signing job builds the offline Linux bundle with
`scripts/package-offline-dist.sh` and checks its SHA-256 files and 64-byte
detached signature. The Bash verifier `scripts/verify-offline-dist.sh` then
verifies the archive.

Before extraction, the Python verifier `scripts/verify-offline-dist.py
--verified-copy` streams, hashes and authenticates the archive and writes a
private copy into a fresh temporary directory. `tar` extracts that copy; the
original archive path is not reopened. The install smoke test then runs the
bundle's `install.sh` with the C lane, the builtin fuzzer, no system packages
and no rustup, and checks the installed `bhf`, `bhf-bug-report`, both shims
and the content pack.

The original archive remains the file uploaded for release.
`linux-bundle-verification.json`, uploaded next to it, records the
authenticated SHA-256 and the accepted copy. That JSON is an unsigned
workflow record; the detached signature format is unchanged.

The verified copy closes the window between verification and use for the
smoke installation. The runner and its private temporary directories are
trusted. See [Verified distribution handoff](verified-distribution-handoff.md)
for the verifier's checks and the bundle layout.

## Retrying a failed release

- Fix the source and start a new candidate validation. A skipped job never
  counts as a success.
- The gate rejects exports from another run or another attempt. For a clean
  retry, choose **Re-run all jobs**, not only the release gate.
- The attempt field identifies the job that produced the acceptance. When
  only failed jobs are re-run, GitHub can keep earlier successful upstream
  jobs, so keep the full CI logs and platform artifacts with the release
  review.
- A release that already exists and a partly published retry follow
  cargo-dist's and GitHub's own behavior; publication is not transactional.

## Tests

On a Linux host with Python 3.10 or later, Bash, tar, and OpenSSL with
Ed25519 support:

```sh
python3 -m unittest discover -s scripts/ci/tests -v
```

The integration tests run both policy CLIs and the workflow's shell
fragments. They reject a failed, cancelled or skipped required CI job, a
missing result, a documentation-only pass, a wrong checkout and a stale
export. The archive tests use real temporary Ed25519 signatures, copying and
`tar` extraction: replacing the original archive right before `tar` still
yields the authenticated payload, and tampering before verification stops
before `tar`. GitHub event and job observations, and the case where the
crypto library is unavailable, are fixtures. The integration subprocesses run
Python with `-S`, so local site-customization hooks do not run in them.

Before relying on a release, also confirm a hosted run of the final
candidate, the protected release environment settings and the published
artifact.

## References

GitHub's documentation of reusable-workflow outputs, caller context,
permissions and concurrency:

- <https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations>
- <https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax>
