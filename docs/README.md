<!-- SPDX-License-Identifier: Apache-2.0 -->

# The docs folder

The user guides are in [`site/`](site/index.md); start at the
[documentation index](site/index.md). This page lists the other pages under
`docs/`: reference notes the guides link to, release and CI notes,
measurements, plans, and dated records.

## Reference

| Page | What it covers |
|---|---|
| [The recommended sweep](recommended-sweep.md) | The `bhf auto` command to start with, and how to size each flag |
| [Results reference](finding-report-fields.md) | The `results/` directory, the `bhf.findings.v1` and `bhf.finding.v1` formats, and the CSV columns |
| [Campaign comparison and triage](report-comparison.md) | `bhf report --baseline`, carried-forward triage decisions, and the offline HTML view |
| [Differential fuzzing](differential-fuzzing.md) | `bhf differential` and `bhf fuzz --differential-harness` |
| [Symbolic seed generation](symbolic-seed-generation.md) | `bhf fuzz --symbolic-seed-source`: seeds mined from the guards of an Ada file |
| [libFuzzer adapter](libfuzzer-adapter.md) | The libFuzzer-compatible binaries a generated harness builds |
| [Builtin harness protocol resolution](enterprise-harness-protocol.md) | How the built-in engine decides how a harness binary takes its input |
| [Typed Go data parameters](enterprise-harness-gap-plan.md) | Go targets whose parameters are plain data structs, slices and maps |
| [Ada cross-compilation and probe backends](cross-compilation.md) | GNAT/GPRbuild cross builds, the embedded probe backends, and qemu-user replay of an Ada harness |
| [Hardware-in-the-loop bring-up](hil-bringup.md) | Fuzzing a physical ARM board over gdb-remote; the board profiles are in [`hil-boards/`](hil-boards/) |
| [Daemon JSON-RPC](daemon-json-rpc.md) | `bhf-daemon`'s wire format and methods |
| [Daemon reliability](enterprise-daemon-reliability.md) | How the daemon, the continuous scheduler and the GNAT Studio client bound their memory and child processes |
| [Scheduler reliability](scheduler-reliability.md) | The continuous scheduler's storage, job state, health reports and shutdown |
| [VS Code thin client](vscode-thin-client.md), [GNAT Studio plugin](gnatstudio-plugin.md), [IDE parity](ide-parity.md) | The editor integrations |
| [Authenticated offline update packs](enterprise-pack-authentication.md) | The content-pack signature format and how packs are verified |
| [Verified distribution handoff](verified-distribution-handoff.md) | `scripts/verify-offline-dist.py`: checking a bundle's signature and handing over the verified bytes |

## Release and CI

| Page | What it covers |
|---|---|
| [Release packaging](release-packaging.md) | How a release is built and verified, including the offline Linux bundle |
| [CI acceptance](ci-acceptance.md) | How CI decides a commit passed, and how to run the policy checks yourself |
| [Release controls](enterprise-release-controls.md) | How the release workflow ties a release to a full CI run of the same commit |
| [Container validation sweep](enterprise-container-validation.md) | `bhf auto` in the Docker image over 32 public projects, two per language |

## Measurements

| Page | What it covers |
|---|---|
| [Engine comparison benchmarks](enterprise-engine-benchmark.md) | The two effectiveness experiments; their [methodology](../benchmarks/engine-comparison/METHODOLOGY.md) has the schemas and offline run steps |
| [Measured gaps](expected-gaps.md) | Each class of target bhf skipped or failed to fuzz in the 500-project sweep, with its size and cause |
| [Discovery cost](open-defects-discovery-cost.md) | What one very large C++ file cost discovery, and the fix |
| [`--force` reach](open-defects-force-and-reach.md) | `bhf auto --force` over 126 projects: what was fixed and what still blocks fuzzing |

## Plans and research

| Page | What it covers |
|---|---|
| [Enterprise readiness program](enterprise-readiness-program.md) | The acceptance matrix for production readiness |
| [Service durability and soak plan](enterprise-service-soak-plan.md) | The scheduler and daemon lifecycle, open items, and the soak a release should run |
| [High-demand fuzzing roadmap](high-demand-fuzzing-roadmap.md) | The plan for RTOS, radar and other embedded targets |
| [Fuzzing landscape, 2026-05-20](fuzzing-landscape-2026-05-20.md) | A dated memo on fuzzing tools, user pain points and the backlog bhf drew from them, with a status map |

## Dated records

These pages record one review or repair at the commit they name. The guides
describe current behaviour.

| Page | What it records |
|---|---|
| [Production readiness review, 2026-09-24](production-readiness-review.md) | Documented behaviour checked against the implementation, with the fixes and release gates |
| [Feature completeness review, 2026-09-24](review-feature-completeness.md) | Feature promises, residual gaps and the optional engine adapters |
| [Daemon and editor hardening, 2026-09-24](review-daemon-editors.md) | Defects found in the daemon and editor integrations, and what bhf does now |
| [Release and CI fixes](review-release-ci.md) | Defects found in the Linux bundle, installer and release workflows, and what each does now |
| [Portability and daemon-framing repair, 2026-09-25](portability-hardening-2026-09-25.md) | Installer, portability and daemon-framing fixes, with the JSON test record |

Two more indexes list dated files, one per topic:

- [Validation records](validation/README.md): validation runs, named
  `YYYY-MM-DD-topic.md`.
- [Design notes](designs/README.md): the designs written before a feature
  was built, each linked to the guide that now describes it.

## Elsewhere in the repository

| Page | What it covers |
|---|---|
| [Benchmarks](../benchmarks/README.md) | Every benchmark study: what it measures, its results and how to re-run it |
| [Docker files](../docker/README.md) | The files that build the image, the Compose files, the validation sweep and the compliance notices |
| [Changelog](../CHANGELOG.md) | Every change, release by release |
| [Enterprise-readiness plan](../DEVELOPMENT_PLAN.md) | Phases P0 to P7: what each has delivered and what is still open |
