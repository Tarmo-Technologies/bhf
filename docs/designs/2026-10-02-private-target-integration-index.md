<!-- SPDX-License-Identifier: Apache-2.0 -->
# Private-target integration program — design index (#56/#57/#58/#60/#61)

These five issues form one program: making bhf a first-class fuzzer for private,
source-unavailable, policy-bound targets. The shipped features #47 (runner /
target args), #59 (runtime sink oracles in manual + binary fuzz), and #55 (user
postcondition oracles + fixture hooks) are the foundation these build on.

Each spec is a **design for review** — no implementation has started. They are
written so each can be prioritised and approved independently before any build.

| Spec | Issue | Size | Depends on |
|---|---|---|---|
| [External project profiles](./2026-10-02-external-project-profiles.md) | #56 | L | — (composes #47/#55/#59) |
| [Extension protocol](./2026-10-02-extension-protocol.md) | #57 | XL | #56 (to declare trusted extensions) |
| [Stateful protocol sessions](./2026-10-02-stateful-protocol-sessions.md) | #58 | L–XL | HDF-7 pieces; optionally #57 `scenario.*` |
| [Runtime-event collector + Windows provider](./2026-10-02-runtime-event-collector.md) | #60 | XL | #55 (classification); needs a Windows runner |
| [Relational policy fuzzing](./2026-10-02-relational-policy-fuzzing.md) | #61 | XL | #55 + #60 |

## Suggested sequencing

1. **#56 external project profiles** — pure, no execution risk, immediately
   useful, and the composition surface the others plug into. Best first.
2. **#58 stateful sessions** — independent of the others (builds on HDF-7); a
   pure crate + a TCP vertical slice.
3. **#60 collector** — land the platform-neutral crate + a Linux adapter first
   (Linux-only), then the Windows provider on a Windows runner.
4. **#55-dependent work**: **#61 relational** needs #55 (done) + #60; sequence
   after #60's Linux side.
5. **#57 extension protocol** — the largest; land the host + `oracle.evaluate`
   slice, defer codec/mutator/scenario.

Common principle across all five: reuse the existing engines and the
#47/#55/#59 execution surface; add crates that are pure/unit-testable first, and
gate anything that spawns an external process or needs a non-Linux runner behind
an explicit, trusted, separately-validated phase.
