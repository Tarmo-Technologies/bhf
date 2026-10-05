<!-- SPDX-License-Identifier: Apache-2.0 -->
# Contractor qualification checkpoint

Decision: **NOT_READY**. This record distinguishes executed packaging/functional
checks from the requested third-party vulnerability-discovery campaign, which
is not executed in this work. No release or publisher signature is authorized.

Live baseline: PR #91 remains open at
`37582ed1849d18b11e5d6438b049ee6ed5034b69`; main is
`2e9ea97def2a71e66bf00b5d50d4c5f5a9112bd6`. Version remains 0.2.35.
Latest published release is 0.2.34; prior releases are preserved.
Read-only protection lookup: strict `CI acceptance`, admin enforcement enabled,
force pushes/deletions disabled. No required-review entry appeared in the
protection response. The listed Copilot ruleset is disabled; no settings changed.
PR #91 had no submitted reviews. Earlier-head CI is not acceptance of this work.

Available local runner: 6 CPUs, 13 GiB RAM, 8 GiB swap, 179 GiB free disk;
Docker 29.1.3, unprivileged workload support. No new paid resources authorized.
Build concurrency: one image, two Cargo jobs. Functional containers: disconnected,
read-only root, at most 4 GiB RAM, 512 PIDs, two CPUs, disposable work/tmp space.
No external projects or credentials are mounted into these functional checks.

## Audit to action

| Area | Action and evidence status |
|---|---|
| Language selection | Implement shared canonical/alias/dependency resolver; build actual subset images; run selection properties and negative cases. Pending. |
| Native installation | Reuse installer, package resolver with it, reject malformed selections before side effects; test disposable installs. Pending. |
| Default no AI | Inspect selected compiled graph and run existing CLI/daemon dummy-provider controls. Pending. |
| Functional controls | Prefer public `bhf auto` on BHF-owned benign fixtures; manual assistance must be labeled. Pending. |
| Artifact sizes | Compare baseline image/config IDs, package counts, compressed exports and layers. Pending. |
| Inventory and signing | Reuse existing inventory/scan gate and independent verifier tests; no publisher key creation or release publication. Pending. |
| 100 upstream projects | No frozen verified 100-project manifest or scored trials produced. Unrun; no success rate claimed. |
| Release support | Sixteen-language target-entry, exact-head CI, offline native/platform install matrix, license/source completeness and human risk review remain blockers until executed. |
| Optional limits | Physical boards, arbitrary RTOS fidelity, Windows ETW and broad private-resource Rust remain scoped capability limitations. |

The 100-project qualification budget is up to 50 CPU-hours of requested target
execution alone (100 × 3 × 5 × 120 seconds), before preparation and builds.
Nothing in this checkpoint claims that compiler smoke or a short owned fixture
satisfies that preset. No failed project is removed from a scored denominator.

## Resumed packaging and owned-control work

The interrupted `ccdb343` matrix was continued from a detached checkout of that
exact source, preserving its first four rows and interrupted Java log. It
completed all twenty selections: nineteen compiler/lifecycle rows passed; the
Ruby-only build failed because the patched zlib gem needed development headers.
This older matrix did not include the stronger automatic controls added below.

The native installer regression expected the removed `none` language selector.
Its assertion and the packaged help were brought into agreement with the
nonempty-selection contract; all thirty installer tests passed, including
temporary-key authenticated installation, tamper rejection, upgrade preservation,
and rollback. Provider opt-in mocks passed 19/19. CI policy/inventory/resumption
tests passed 239/239; independent offline verifier tests passed 8/8. The selected
default CLI/daemon graph excludes `llm_harness_gen`.

The dependency-bearing BHF-owned Java control now uses public `bhf auto` on a
disposable source copy with spaces in its path, staged Maven dependencies,
network disabled, and a read-only root/original checkout. Cold and warm runs
each produced one entered target, 96 executions, 57 measured edges, and no
findings. An independent marker in the owned target confirms body entry.
Missing consent and an empty offline cache both produced zero entered targets
and exit status 1. Original source integrity was checked. JSON checkpoints and
artifact hashes survive disposable-volume cleanup even on assertion failure.

Additional clean packet/checksum fixtures exercise all sixteen lanes through
`bhf auto`; they are fixtures, not upstream-project slots. Initial runs exposed
Go replacement-path quoting on spaced paths and missing PHP `pcov` feedback.
The Go correction passed its 25 builder tests and all four integration tests,
including real target coverage with spaced source/work directories. The Ruby
dependency closure and PHP coverage extension are corrected for the next image
snapshot. The first scalar-only Fortran fixture was ineligible by design; the
character-input replacement entered successfully and the initial failure remains
in local evidence. C/C++ spaced paths remain explicitly unsupported by strict
Makefile input validation. Ordinary-path controls passed for those lanes.

The matrix now supports source/hash-checked resumption, preserves interrupted
attempt logs, checks ecosystem exclusions, and can require owned automatic
controls. An explicitly requested workflow matrix gates candidate packaging.
These changes and their final images still require their own executed matrix;
the earlier twenty-image results do not certify the corrected implementation.

Whole-image inventory of the older all-language image
`sha256:6f7c175dff3751da9c7195219f5810481dfacd0fb13ca1c254ed47fa70cc78d4`
used checksum-verified Syft 1.46.0 and Grype 0.115.0 with a valid database built
2026-10-04T08:11:47Z. Its policy result was
`REQUIRES_PROTECTED_REVIEW: 0 blockers, 829 residual matches` (678 Medium,
141 Low, 10 Negligible). Residual matches are untriaged; no risk was accepted.
This inventory predates the new PHP extension and must be repeated on the final
image. Global Rust formatting also reports pre-existing differences outside the
changed files; changed Rust files pass their scoped formatting check.

Raw execution evidence is retained locally under
`/tmp/bhf-qualification-20261005`; this is a workspace location, not a contractor
download link. Compact committed results and fresh-image dispositions will
follow. The 100-project sweep, exact-final-source platform acceptance, complete
redistribution materials, and publisher-authenticated handoff remain unrun or
incomplete. Decision remains **NOT_READY**.
