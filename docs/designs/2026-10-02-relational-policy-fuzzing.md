<!-- SPDX-License-Identifier: Apache-2.0 -->
# Design: Coverage-guided relational policy fuzzing (#61)

> Status: **design for review** — no implementation yet. Depends on #55
> (postcondition/semantic predicates) and #60 (runtime-event collector); builds
> on the existing `bhf differential`.

## Problem

Authorization and entitlement bugs are **relational**: the same action must be
exercised under different principals/roles/tenants/sessions/licenses/sandbox
profiles and compared against an explicit policy. Today `bhf differential` is
replay-only — it consumes an existing input dir, runs two harness binaries,
compares stdout/exit/timeout, does not mutate or gather coverage, has no per-side
session profile, and compares neither runtime effects nor semantic-oracle
results. Critically it can report a *difference* but an auth bug can also be an
unexpected *equivalence*: a privileged and an unprivileged run may both return 0
and identical output even though the low-privilege run created a forbidden child
process — output differential cannot see that.

## Goals

- A coverage-guided **relational** campaign mode that executes the same generated
  testcase across N named launch/session profiles and evaluates declarative
  relational predicates over each profile's observed behaviour.
- Per-profile collection of code coverage, normalised response/status, runtime
  events (#60 collector), and semantic/postcondition results (#55), plus optional
  product authorization-decision events.
- Catch both unexpected divergence AND unexpected equivalence against policy.

## Non-goals

- Inventing a new engine: reuse the builtin coverage-guided mutator; relational
  mode is a scheduler/oracle layer over it.
- Credential management: profiles reference local-lab secrets by indirection with
  redaction; bhf never stores secrets.

## Proposed design

### Profiles + predicates

A relational config names profiles and predicates (illustrative):

```toml
schema = "bhf.relational.v1"

[[profile]]
name = "admin"
runner = "..."; args = ["--role", "admin"]
env = { TOKEN_REF = "lab:admin" }          # indirection, redacted in provenance
collector = "auto"                          # #60
[[profile]]
name = "viewer"
args = ["--role", "viewer"]

[[predicate]]
# unexpected-equivalence and unexpected-divergence, over observed effects
rule = "action allowed in admin must remain denied in viewer"
when = "admin.status == allowed"
require = "viewer.status == denied"

[[predicate]]
rule = "observed process targets must be a subset of the profile allowlist"
require = "subset(viewer.spawned_processes, viewer.allowlist)"
```

Predicates operate over a per-profile observation record: `{status, coverage,
events[], semantic_hits[], auth_decisions[]}`.

### Architecture

- New crate `relational` (pure): the profile+predicate schema, the per-profile
  `Observation` model, and a predicate evaluator producing relational findings
  (`unexpected_allow`, `unexpected_equivalence`, `allowlist_escape`, ...) with a
  stable signature.
- A relational campaign driver: one generated testcase is run once per profile
  (each profile = a launch/session config reusing #47 runner/args + #60 collector
  + #55 hooks); coverage is the UNION across profiles so the mutator is guided
  toward inputs that reach new code in ANY profile; after each multi-profile
  execution the predicate evaluator runs and emits relational findings.
- Reuses, not replaces: the builtin mutator/corpus/coverage machinery drives
  input generation; #60 supplies the effect events; #55 supplies per-profile
  semantic verdicts; the finding pipeline persists results. `bhf differential`'s
  output-comparison becomes one predicate kind among several.
- Replay/minimize: a relational finding records all profiles + the triggering
  input; replay re-runs every profile and re-checks the predicate; minimize
  reduces the input while the predicate still fails.

### Integration points

- `bhf differential` (crates/cli/src/differential.rs) is the closest existing
  surface; relational mode is either a new `--relational <config>` on it or a new
  `bhf relational` subcommand. It already uses the executable-oracle registry for
  output divergence — relational predicates extend that.
- Coverage: the builtin engine's bitmap, unioned across profiles per input.
- Collector (#60) + postconditions (#55) are the per-profile observation sources.

## Risks / open questions

- Highest-dependency issue: needs #55 and #60 landed first (semantic verdicts +
  portable effect events). Sequence it last.
- Predicate language scope: start with a small fixed set (status relation,
  allowlist-subset, equivalence) rather than a general expression language;
  extend later (possibly via a #57 extension oracle).
- Union-coverage guidance can bias toward one profile's code; bucket per-profile
  novelty so no profile is starved.
- Secret handling: references + redaction only; provenance must never capture the
  resolved secret.

## Phased plan

1. `relational` crate: profile+predicate schema, `Observation` model, predicate
   evaluator + finding mapping. Pure, unit-tested against synthetic observations.
2. Multi-profile driver reusing #47 launch config; per-profile status/coverage
   collection; union-coverage feedback. (Works before #60/#55 using
   status/coverage-only predicates.)
3. Wire #55 semantic verdicts and #60 collector events into `Observation`;
   enable effect-based predicates (allowlist-subset, forbidden-spawn).
4. Replay/minimize for relational findings; docs; an auth-bug fixture
   (admin-allows / viewer-must-deny).

Phase 1–2 are implementable now (status+coverage predicates); phases 3–4 gate on
#55/#60.
