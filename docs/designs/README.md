<!-- SPDX-License-Identifier: Apache-2.0 -->

# Design notes

Each page here is the design written before a feature was built: the
problem, the goals, the design and the phased plan. A note's status line
names the commits that built it and the user guide that now describes it.
For how a feature behaves today, read that guide.

| Design | What it designs | User guide |
|---|---|---|
| [Private-target integration program](2026-10-02-private-target-integration-index.md) | The index of the five designs below, their order and what each delivered | |
| [External project profiles](2026-10-02-external-project-profiles.md) | `bhf project`: a checked-in profile for a hand-written harness and its build | [External project profiles](../site/cli.md#external-project-profiles) |
| [Extension protocol](2026-10-02-extension-protocol.md) | `bhf extension`: codecs, mutators, oracles and lifecycle hooks in a separate process, over the `bhf.extension.v1` protocol | [Extension protocol](../site/extension-protocol.md) |
| [Stateful protocol sessions](2026-10-02-stateful-protocol-sessions.md) | `bhf fuzz --protocol-profile`: multi-message sessions whose next message depends on the target's reply | [Stateful protocol sessions](../site/cli.md#stateful-protocol-sessions) |
| [Runtime-event collector](2026-10-02-runtime-event-collector.md) | A platform-neutral runtime event stream, with a native Windows provider | [Runtime oracles, collectors and postconditions](../site/cli.md#runtime-oracles-collectors-and-postconditions) |
| [Relational policy fuzzing](2026-10-02-relational-policy-fuzzing.md) | `bhf relational`: one testcase run under several named profiles, with the observed behaviour checked against policy predicates | [Relational policy fuzzing](../site/cli.md#coverage-guided-relational-policy-fuzzing) |
| [Ada static rules](2026-10-16-ada-static-rules.md) | The Ada rules of `bhf static-scan`, and their measured hits | [Static CWE coverage](../site/static-cwe-coverage.md) |
