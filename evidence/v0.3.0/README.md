# BHF 0.3.0 release qualification evidence

This branch retains evidence, not a published release. Publication still requires
the protected CI and release workflow gates.

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
