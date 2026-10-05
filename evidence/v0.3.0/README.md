# BHF 0.3.0 release qualification evidence

This branch retains evidence separately from the published release. Version
`0.3.0` was published on October 5, 2026 at 17:16:14 America/Chicago from
`acc63b9951d23411300b188710ad0643dd1a6241`. All required release gates passed.
The downloaded signed Linux bundle was independently authenticated before
extraction, and its binary reported that exact version and full commit.

`bhf-v0.3.0-release-qualification.json` binds the campaign to the final release.
Final CI receipts, release logs, production approval, and independent published
signature/version observations are retained alongside the campaign archive.
The campaign archive contains the original RC binary for audit, not installation;
use the release's signed `bhf-dist-0.3.0-x86_64-unknown-linux-gnu.tar.gz` to install.

`bhf-v0.3.0-100-project-evidence.tar.gz` contains 229 checksum-bound evidence
files and their `SHA256SUMS`. It includes the exact original candidate binary,
project manifest, per-project JSON, campaign logs, aggregates, correction patch,
and exact regression reruns. Extract it into a fresh directory and run
`sha256sum --check SHA256SUMS` there. The archive has its own SHA-256 sidecar.

The original candidate was PR #92 source `da750fa`, merge
`229a638386d69967a8ab2916a466ae4d5483756b`, Actions run `37341335272`.
The original campaign measured 98 of 100 projects; two timed out. The correction
landed in `2469411f6cbb86b9194282ef2aca7d534c0ca449`. Exact reruns of the two
affected projects completed successfully. The composite evidence therefore has
100 measured projects, zero campaign problems, and 176 built-and-fuzzed targets.
It is not a claim that all 100 projects were rerun on the final release binary.

The initial unpublished `0.3.0` tag targeted main commit
`ba912e7c7a832e7dab82d18219bea727257aee47`. Release run `37361148060`
could not publish: hosted-runner assignment failures cancelled validation gates,
and the Linux packaging shell expanded an empty array under Bash 4.2 nounset.
Its logs are retained alongside this evidence.

PR #93 (`8c6bd2ee663ef02570cc8a3eb0691574910f491a`) repairs packaging by
requiring accepted, matching tag-plan outputs before any packaging work and
passing a mandatory quoted tag without the empty-array expansion. All 247 CI
policy tests passed both locally and in hosted CI attempt 2 of run `37370500540`.
The hosted policy-test log and unsuccessful CI attempt 1 logs are also retained.

GitHub reported an active Actions/hosted-runner incident on October 5, 2026.
No failed or skipped validation gate was changed into a passing release decision.
No branch protection, environment protection, or signing key was altered.
