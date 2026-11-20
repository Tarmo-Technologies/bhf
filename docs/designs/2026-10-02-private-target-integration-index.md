<!-- SPDX-License-Identifier: Apache-2.0 -->
# Private-target integration program — design index (#56/#57/#58/#60/#61)

These five issues form one program: fuzzing private, source-unavailable, policy-bound targets with bhf. They build on three shipped features: #47 (runner and target args), #59 (runtime sink oracles in manual and binary fuzz), and #55 (user postcondition oracles and fixture hooks).

All five are implemented. Each design's status line names its commits, the follow-up issues that completed it, and the user guide:

| Design | Initial commit | Follow-ups delivered | User guide |
|---|---|---|---|
| #56 external project profiles | 0b76dd0 | [#334](https://github.com/Tarmo-Technologies/bhf/issues/334) (`bhf project import-ossfuzz`) | [External Project Profiles](../site/cli.md#external-project-profiles) |
| #57 extension protocol | 1efe037 | [#373](https://github.com/Tarmo-Technologies/bhf/issues/373), [#314](https://github.com/Tarmo-Technologies/bhf/issues/314), [#374](https://github.com/Tarmo-Technologies/bhf/issues/374), [#313](https://github.com/Tarmo-Technologies/bhf/issues/313), [#228](https://github.com/Tarmo-Technologies/bhf/issues/228) | [Out-of-Process Extensions](../site/cli.md#out-of-process-extensions), [extension protocol](../site/extension-protocol.md) |
| #58 stateful protocol sessions | c8c8fd0 | [#363](https://github.com/Tarmo-Technologies/bhf/issues/363), [#364](https://github.com/Tarmo-Technologies/bhf/issues/364), [#260](https://github.com/Tarmo-Technologies/bhf/issues/260), [#258](https://github.com/Tarmo-Technologies/bhf/issues/258), [#262](https://github.com/Tarmo-Technologies/bhf/issues/262), [#261](https://github.com/Tarmo-Technologies/bhf/issues/261), [#315](https://github.com/Tarmo-Technologies/bhf/issues/315), [#257](https://github.com/Tarmo-Technologies/bhf/issues/257) | [Stateful protocol sessions](../site/cli.md#stateful-protocol-sessions) |
| #60 runtime-event collector | 85e4781 | [#76](https://github.com/Tarmo-Technologies/bhf/issues/76), [#246](https://github.com/Tarmo-Technologies/bhf/issues/246), [#247](https://github.com/Tarmo-Technologies/bhf/issues/247), [#278](https://github.com/Tarmo-Technologies/bhf/issues/278) | [Runtime Oracles, Collectors and Postconditions](../site/cli.md#runtime-oracles-collectors-and-postconditions) |
| #61 relational policy fuzzing | 92d99c1 | none | [Coverage-Guided Relational Policy Fuzzing](../site/cli.md#coverage-guided-relational-policy-fuzzing) |

| Spec | Issue | Size | Depends on |
|---|---|---|---|
| [External project profiles](./2026-10-02-external-project-profiles.md) | #56 | L | — (composes #47/#55/#59) |
| [Extension protocol](./2026-10-02-extension-protocol.md) | #57 | XL | #56 (to declare trusted extensions) |
| [Stateful protocol sessions](./2026-10-02-stateful-protocol-sessions.md) | #58 | L–XL | HDF-7 pieces; optionally #57 `scenario.*` |
| [Runtime-event collector + Windows provider](./2026-10-02-runtime-event-collector.md) | #60 | XL | #55 (classification); needs a Windows runner |
| [Relational policy fuzzing](./2026-10-02-relational-policy-fuzzing.md) | #61 | XL | #55 + #60 |

## Planned sequencing

1. **#56 external project profiles:** pure, no execution risk, and the composition surface the others plug into. Do it first.
2. **#58 stateful sessions:** independent of the others (builds on HDF-7); a pure crate plus a TCP vertical slice.
3. **#60 collector:** land the platform-neutral crate and a Linux adapter first (Linux-only), then the Windows provider on a Windows runner.
4. **#55-dependent work:** **#61 relational** needs #55 (done) and #60; sequence it after #60's Linux side.
5. **#57 extension protocol:** the largest; land the host and `oracle.evaluate` slice first, then codec/mutator/scenario.

All five follow one principle: reuse the existing engines and the #47/#55/#59 execution surface; add pure, unit-testable crates first; and gate anything that spawns an external process or needs a non-Linux runner behind an explicit, trusted, separately validated phase.
