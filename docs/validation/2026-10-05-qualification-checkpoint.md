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
