<!-- SPDX-License-Identifier: Apache-2.0 -->
# Enterprise Readiness Program

Goal: bring bhf to production readiness as an enterprise fuzzing tool, with evidence that places it against AFL++ and Mayhem.

Status: open. The current plan and the latest checkpoint are in [DEVELOPMENT_PLAN.md](../DEVELOPMENT_PLAN.md). This page holds the acceptance matrix that defines completion.

## Evidence and comparison requirements

Competitor capability is broader than a command count. AFL++ documents several instrumentation backends, persistent execution, comparison feedback, mutation strategies and corpus tools ([overview](https://aflplus.plus/), [features](https://aflplus.plus/features/)). Mayhem documents code testing, hybrid fuzzing with symbolic execution, target support, coverage and CI integrations ([technology](https://docs.mayhem.security/code-testing/reference/mayhem-technology/), [support matrix](https://docs.mayhem.security/code-testing/reference/support-matrix/), [documentation](https://docs.mayhem.security/)). The requirements below are drawn from these sources.

A comparison must:

- identify target versions, engines, compilers, hardware, harness semantics, build and setup effort, seeds, time and resource limits, and independent trials;
- measure coverage with a common offline replay when the engines' own counters differ;
- keep failed trials and censored no-solve trials in the results;
- move from the small gate fixtures, which serve as regression tests, toward real-code benchmarks and the [FuzzBench](https://github.com/google/fuzzbench) methodology.

A Mayhem comparison needs a licensed, identified Mayhem version and reproducible results. [Engine Comparison Benchmarks](enterprise-engine-benchmark.md) describes the runners and the results so far.

## Acceptance matrix

| Requirement | Evidence needed before completion | Current state |
|---|---|---|
| Secure artifacts and updates | Real public-key verification; tampered, unknown and revoked keys and downgrades rejected; offline trust management and rotation; transactional install and recovery; published artifacts verified against their source | Pack and archive signing and independent verification implemented and tested locally ([pack authentication](enterprise-pack-authentication.md), [verified handoff](verified-distribution-handoff.md)); the mutable-source and install lifecycle and the protected release-operation gates are open |
| Service and editor reliability | Bounded inputs, responses, jobs and subprocess trees; deadlines; controlled overload; restart, cancel, shutdown and isolation tests; no lost acknowledged jobs | Bounded responses and finding loading, editor deadlines, scheduler deadlines, durability and queue and history limits implemented ([daemon reliability](enterprise-daemon-reliability.md)); whole-scheduler shutdown and tenant isolation are open ([soak plan](enterprise-service-soak-plan.md)) |
| Fuzzing effectiveness | Equal-budget repeated real-code comparison with AFL++ and libFuzzer: reproduced bugs, common coverage, confidence intervals and censoring, throughput and setup cost; gates neither weakened nor hand-picked | Four-engine trade study on the controlled fixtures (2026-09-27, with a bhf rerun on 2026-09-28); the repeated real-code comparison is open |
| Target breadth and harness quality | Current sixteen-language image sweep, expert-harness comparison, representative legacy, opaque and stateful target gaps fixed with measured reach and real execution | 32 of 32 projects passed the container sweep on the 2026-09-25 image ([container validation](enterprise-container-validation.md)); generated and expert harnesses compared on 30 projects (2026-08-14); lane gaps listed in [expected gaps](expected-gaps.md) |
| Operational durability and scale | Long-running multi-worker campaigns with bounded CPU, RSS and disk; reliable cancellation, resume, corpus exchange, reproducible replay and minimization, audit retention and recovery under injected failures | Needs adversarial and soak validation beyond unit tests |
| Enterprise workflow and access | Threat model and deployment boundaries; tested authorization and project isolation, auditability, policy gates, CI artifacts and automation; documented comparison with managed-service and API capability | Governance and daemon features exist and need end-to-end validation |
| Platform and supply-chain release | Locked reproducible builds, verified minimum Rust version, clean dependency and security policy, Linux ABI and native Windows checks, full final-tree tests, release installation smoke test | Minimum Rust 1.88 (`rust-version`) verified locally; hosted and final-artifact gates are open ([release controls](enterprise-release-controls.md)) |
| Accurate supported surface | Every public command and feature matched to its implementation, unsupported cases stated, no panicking optional paths, docs and examples validated, migration documented | Ongoing; see [production readiness review](production-readiness-review.md) |

New findings refine the implementation work; the matrix defines success. A missing competitor license or hosted runner blocks only its own evidence gate. Any missing capability or evidence in the matrix blocks completion.

## Workstreams and their records

| ID | Workstream | Record |
|---|---|---|
| E1 | Ed25519 offline pack creation and verification, trusted public-key policy, key handling, independent verification, tamper, rotation, revocation and downgrade tests | [enterprise-pack-authentication.md](enterprise-pack-authentication.md) |
| E2 | Bounded response production, GNAT Studio request deadlines, scheduler process-tree shutdown and restart, adversarial regression tests | [enterprise-daemon-reliability.md](enterprise-daemon-reliability.md) |
| E3 | Ignored cold-solve gates run, controlled repeated engine comparison with raw results | [enterprise-engine-benchmark.md](enterprise-engine-benchmark.md) |
| E4 | Container build and sweep failure semantics, a fresh source-snapshot image and its pinned language matrix | [enterprise-container-validation.md](enterprise-container-validation.md) |

## Remaining work

- real-code performance and harness gaps;
- operational soak and fault-injection testing;
- full installation recovery;
- platform releases;
- competitive capability gaps.

Rules for this program:

- Label evidence from older builds as historical.
- Local development and testing never publish a release or sign with production credentials.
- Check [DEVELOPMENT_PLAN.md](../DEVELOPMENT_PLAN.md) before acting on an older task listed here.
