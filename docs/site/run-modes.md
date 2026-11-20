<!-- SPDX-License-Identifier: Apache-2.0 -->

# Run Modes (Reporting vs Attacking)

`bhf auto` and `bhf fuzz` both take `--mode reporting|attacking`. The default is `reporting`.

```sh
bhf auto path/to/src --mode attacking
```

The mode sets which targets `bhf auto` fuzzes first and which findings the report puts first. Verdicts come from the collected evidence in both modes (see below). Every finding's actionability record carries the mode, so other tools can group runs by it.

## Verdicts Are the Same in Both Modes

In either mode, bhf classifies each finding from its evidence into one verdict:

- `real_reachable`: reproduced, with a source fix location, on an attacker-reachable entry point. A candidate vulnerability.
- `likely_reachable`: a real failure on a plausible entry point whose reachability bhf could not fully prove.
- `lab_only`: the path depends on generated stubs, fake resources, injected environment values or mocks. It reproduces in the lab, and reachability through the public API is unproven. bhf also assigns `lab_only` when the fuzzed entry point is known to be outside the attacker's control, such as an internal helper or an output serializer that the harness called directly.
- `blocked`: a real resource was missing and had no substitute, so the target could not run.
- `unknown`: reachability was not assessed, for example for Ada targets, which are ranked by structure, or for findings from older runs.

The mode never moves a finding between these verdicts, and neither does model output. Optional agent or model assistance can explain or prioritise the evidence; the verdict comes only from the deterministic run, reachability, replay, stub and fake, and oracle fields.

## Reporting Mode (default)

Reporting mode serves the developer workflow. Findings come with replay commands, minimized inputs when available, source fix locations, patch guidance and clear labels for lab-only paths. Use it to triage your own code and fix what comes back.

## Attacking Mode

Attacking mode puts the externally reachable, security-relevant findings first: the attacker's view. It changes two things:

- **Target scheduling (`bhf auto` only).** bhf re-sorts the candidate queue so that attacker-reachable targets and targets near dangerous sinks are fuzzed first. To each candidate's base rank it adds `+50` when the target name contains a reachable-surface keyword (`parse`, `decode`, `read`, `open`, `connect`, `spawn`, `query`, `sql`, `load`), and `+100` for each dangerous-API oracle whose API appears in the source text. Under a target cap or time budget (`--max-targets`, `--campaign-time`) this decides which targets run before the budget runs out. On a full sweep with no cap it changes only the order. `bhf fuzz` drives a single harness, so for it the mode changes only the actionability profile.
- **Report emphasis.** Externally reachable, security-relevant findings come first. Findings that depend on stubs, fakes, injected environment values or mocks are still recorded, stay classified `lab_only`, and are left out of the real-reachable counts.

## Gating CI on Actionability

`bhf ci` gates on the verdict, whatever the run mode:

```sh
bhf ci . --fail-on-actionability likely --min-actionability-confidence medium
```

| `--fail-on-actionability` | Fails the build on |
|---|---|
| `real` | attacker-reachable findings only (strict) |
| `likely` | reachable findings, including strong static entry and sink evidence |
| `lab` | lab-only findings as well |
| `any` | every recorded finding |

`--min-actionability-confidence` (`high`, `medium` or `low`, default `low`) sets the lowest verdict confidence that counts.

## When To Use Which

- **Reporting** for routine development and your own triage, with the fix workflow in front.
- **Attacking** for an audit under a budget: it schedules the reachable, dangerous surface first and puts first the findings an external attacker could reach. It has the most effect with `--max-targets` or `--campaign-time` on a large tree.

## See Also

- [Auto](auto.md): `--mode` in the full option table and the actionability section.
- [CLI](cli.md): actionability modes and the `bhf ci` gates.
