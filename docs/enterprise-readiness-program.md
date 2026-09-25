<!-- SPDX-License-Identifier: Apache-2.0 -->
# Enterprise readiness program

Objective: keep working until BHF is production-ready and could be considered
an enterprise-level tool comparable to, or better than, AFL++ and Mayhem.
Status: resumed at the user's request on 2026-09-24; completion is unproven.
The consolidated plan, interrupted worktree history and resumed checkpoint are in
[DEVELOPMENT_PLAN.md](../DEVELOPMENT_PLAN.md).
The preceding review made concrete
progress (security/reliability fixes and broad validation), not a completion
claim. This program preserves the full objective across implementation waves.

## Evidence and comparison requirements

Competitor capability is broader than command count. AFL++ documents multiple
instrumentation backends, persistent execution, comparison feedback, mutation
strategies and corpus tools ([overview](https://aflplus.plus/),
[features](https://aflplus.plus/features/)). Mayhem documents code testing,
hybrid fuzzing/symbolic execution, target support, coverage and CI integrations
([technology](https://docs.mayhem.security/code-testing/reference/mayhem-technology/),
[support matrix](https://docs.mayhem.security/code-testing/reference/support-matrix/),
[documentation](https://docs.mayhem.security/)). These primary sources inform the
requirements; they do not establish BHF performance or feature parity.

Comparisons must identify target versions, engines, compilers, hardware, harness
semantics, build/setup effort, seeds, time/resource limits and independent trials.
Use common offline replay/coverage measurement when coverage counters differ.
Preserve failures and censored no-solve trials. Toy gates are regression tests,
not proof of broad superiority. Extend toward real-code benchmarks and the
methodology of [FuzzBench](https://github.com/google/fuzzbench). Direct Mayhem
claims require access to a licensed, identified version and reproducible results;
documentation alone cannot satisfy that gate.

## Acceptance matrix

| Requirement | Evidence needed before completion | Current state |
|---|---|---|
| Secure artifacts and updates | Real public-key verification; tampering/unknown/revoked keys and downgrade rejected; offline trust management and rotation; transactional install/recovery; published artifacts verified against their source | Pack/archive signing and independent verification implemented and locally tested; mutable-source/install lifecycle and protected release-operation gates remain |
| Service and editor reliability | Bounded inputs, responses, jobs and subprocess trees; deadlines; controlled overload; restart/cancel/shutdown and isolation tests; no lost acknowledged jobs | Bounded response/reader, editor deadline and scheduler durability/deadline controls implemented; queue/history, whole shutdown and isolation gates remain |
| Fuzzing effectiveness | Equal-budget repeated real-code comparison with AFL++/libFuzzer, reproduced bugs, common coverage, confidence/censoring, throughput and setup costs; no weakened or hand-picked-only gates | Historical small gates and sweeps exist; current competitive baseline needed |
| Target breadth and harness quality | Current sixteen-language image sweep, expert-harness comparison, representative legacy/opaque/stateful target gaps fixed with measured reach and real execution | Prior container evidence is not evidence for the changed source; lane gaps remain |
| Operational durability and scale | Long-running multiworker campaigns with bounded CPU/RSS/disk; reliable cancellation, resume, corpus exchange, reproducible replay/minimization, audit retention and recovery under injected failures | Requires adversarial and soak validation beyond unit tests |
| Enterprise workflow and access | Threat model and deployment boundaries; tested authorization and project isolation, auditability, policy gates, CI artifacts and automation; documented managed-service/API capability comparison | Existing governance and daemon features require end-to-end validation, not checkbox inference |
| Platform and supply-chain release | Locked reproducible builds, verified Rust minimum, clean dependency/security policy, Linux ABI and native Windows checks, full final-tree tests, release installation smoke | Rust 1.88 verified locally; hosted and final-artifact gates remain |
| Honest supported surface | Every public command/feature matched to implementation, accepted unsupported cases explicit, no panicking optional paths, docs/examples validated and migration documented | Initial review corrected multiple claims; continuing requirement |

New findings refine implementation work, not the definition of success. A missing
competitor license or hosted runner may block its particular evidence gate but
does not block independent engineering progress when work is authorized to run.
Missing required capability or evidence prevents completion. The earlier user
pause ended with the 2026-09-24 resumption instruction.

## Delegated work before the pause

| ID | Owner/model | Deliverable and acceptance |
|---|---|---|
| E1 | release_ci / GPT-6 Sol | Ed25519 offline pack creation/verification and trusted public-key policy; secure key handling; independent verification and tamper/rotation/revocation/downgrade tests; `enterprise-pack-authentication.md` |
| E2 | daemon_editors / GPT-6 Sol | Bounded response production, GNAT request deadlines, scheduler process-tree shutdown/restart; adversarial regressions; `enterprise-daemon-reliability.md` |
| E3 | feature_completeness / GPT-6 Luna | Run ignored cold-solve gates, implement controlled repeated engine comparison with raw results and honest limits; `enterprise-engine-benchmark.md` |
| E4 | coordinating agent | Harden container build/sweep failure semantics, build a fresh source snapshot image and run its pinned language matrix; integrate/review agent changes and maintain evidence |

Subsequent waves must cover the remaining matrix: real-code performance and
harness gaps, operational soak/fault injection, full installation recovery,
platform releases and competitive capability gaps. Evidence from older builds
must stay labeled historical. No release publication or signing with production
credentials is implicit in local development/testing.

All delegated implementation was stopped for the historical model handoff.
See the root development plan before acting on any older task assignment here.
