<!-- SPDX-License-Identifier: Apache-2.0 -->
# BHF 0.3.0 release qualification evidence

This directory holds the qualification evidence for the 0.3.0 release, kept apart from the published release assets. Version `0.3.0` was published on October 5, 2026 at 17:16:14 America/Chicago (22:16:14 UTC) from commit `acc63b9951d23411300b188710ad0643dd1a6241`, with all required release gates passed. The downloaded signed Linux bundle was verified against its Ed25519 signature with the key in `bhf-v0.3.0-trusted-public-key.hex` before extraction (`signature-verification.json`, `bhf-verify-published-0.3.0.sh`), and its binary reported that version and full commit (`version.txt`).

## Install from the release, not from this directory

Install with the release's signed `bhf-dist-0.3.0-x86_64-unknown-linux-gnu.tar.gz`. The campaign archive here contains the original release-candidate binary, kept for audit.

## Files

| File | Contents |
|---|---|
| `bhf-v0.3.0-release-qualification.json` | Binds the qualification campaign to the final release |
| `bhf-v0.3.0-100-project-evidence.tar.gz` (+ `.sha256`) | The 100-project campaign: 229 checksum-bound evidence files and their `SHA256SUMS` |
| `bhf-v0.3.0-production-release-approval.json` | The production release approval |
| `ci-acceptance.json`, `release-ci-acceptance.json` | CI and release acceptance decisions |
| `release-api.json`, `tag-object.json`, `tag-ref.json` | The published release and tag as GitHub reported them |
| `signature-verification.json`, `bhf-verify-published-0.3.0.sh`, `bhf-v0.3.0-trusted-public-key.hex` | Signature check of the published bundle |
| `version.txt` | `bhf --version` of the published binary |
| `bhf-v0.3.0-*-logs.zip`, `bhf-v0.3.0-packaging-policy-tests.log` | Release and CI logs (see below) |
| `bhf-check-packaging-bash42.py` | Checks that the release workflow's packaging commands guard the tag and run under Bash 4.2 |

## The 100-project campaign

The evidence archive holds the original candidate binary, the project manifest, per-project JSON, campaign logs, aggregates, the correction patch and the reruns of the affected projects. To check it, extract it into a fresh directory and run `sha256sum --check SHA256SUMS` there; the archive itself has a SHA-256 sidecar.

The original candidate was PR #92 source `da750fa`, merge `229a638386d69967a8ab2916a466ae4d5483756b`, Actions run `37341335272`. That campaign measured 98 of 100 projects; two timed out. The correction landed in `2469411f6cbb86b9194282ef2aca7d534c0ca449`, and reruns of the two affected projects completed. The combined evidence has 100 measured projects, zero campaign problems and 176 built-and-fuzzed targets: 98 projects from the original candidate binary and 2 from the reruns after the correction.

## Release runs

The first `0.3.0` tag targeted main commit `ba912e7c7a832e7dab82d18219bea727257aee47` and was not published. Its release run, `37361148060`, stopped because hosted-runner assignment failures cancelled validation gates and the Linux packaging shell expanded an empty array under Bash 4.2 `nounset`. Its logs are in `bhf-v0.3.0-original-release-run-37361148060-logs.zip`.

PR #93 (`8c6bd2ee663ef02570cc8a3eb0691574910f491a`) fixed packaging: it requires accepted, matching tag-plan outputs before any packaging work and passes a mandatory quoted tag without the empty-array expansion. The CI policy tests passed in hosted CI attempt 2 of run `37370500540`. The policy test log and the logs of both CI attempts are kept here.

GitHub reported an active Actions and hosted-runner incident on October 5,
2026. The release decision used only gates that passed, and branch protection, environment protection and the signing key were unchanged.
