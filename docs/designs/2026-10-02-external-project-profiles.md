<!-- SPDX-License-Identifier: Apache-2.0 -->
# Design: First-class external project profiles (#56)

> Status: **design for review** — no implementation yet. One of five specs for the
> private-target-integration program (#56/#57/#58/#60/#61). Author: bhf maintainers.

## Problem

bhf can run a private, hand-written harness, but only through an implicit
filesystem convention: the operator materialises an executable at one of
`<work>/build/<id>/main[_afl]`, `<work>/harnesses/<id>/main`, or
`<work>/auto/<id>/main`, then supplies assets piecemeal (`--seed-input`,
`--seed-file`, `--grammar`, a `dictionary.txt` copied into a lookup path, and
build/runner/reset behaviour kept in external scripts). `.bhf.toml` describes
campaign budgets and a few `auto` knobs and **rejects unknown keys**, so it
cannot describe an external harness. The result works for one experiment but is
weak for a long-lived private research program: bhf never discovers, validates,
versions, hashes, composes, or reports the private harness + corpus + dictionary
+ grammar + launch profile as one coherent target.

## Goals

- A versioned, explicitly-loaded manifest describing one or more external targets
  and their assets, kept OUTSIDE the bhf repo and never auto-loaded from an
  untrusted tree.
- Deterministic validation, provenance (hashes of every referenced asset), and
  reporting of the composed target.
- Reuse the existing engines (`bhf fuzz`, `bhf binary fuzz`) and the new
  runner/runtime-oracle/postcondition features (#47/#59/#55) rather than
  re-implementing execution.

## Non-goals

- Automatic discovery of private harnesses (explicit manifest only).
- The extension protocol (#57) and collector (#60) are referenced but specified
  separately.

## Proposed design

A new subcommand group `bhf project` reading a `bhf.project.v1` TOML manifest
passed with `--manifest` (never auto-discovered):

```text
bhf project validate --manifest /private/acme/bhf-project.toml
bhf project list     --manifest /private/acme/bhf-project.toml
bhf project run      --manifest /private/acme/bhf-project.toml --target acme.channel.parser
```

Manifest shape:

```toml
schema = "bhf.project.v1"
id = "acme-client-research"
version = "2026.10.1"
requires-bhf = ">=0.2.34"

[[target]]
id = "acme.channel.parser"
engine = "binary"                 # "binary" | "builtin" | "afl++"
binary = "./harnesses/parser"     # resolved relative to the manifest dir
input-mode = "file"               # maps to bhf binary fuzz
runner = "wine"                   # #47
runner-args = ["--mode", "fuzz"]
target-args = ["@@"]
env = { ACME_LICENSE = "lab" }
seeds = ["corpus/"]               # dirs and files
dictionary = "dicts/channel.txt"
grammar = "grammars/channel.g"
runtime-oracles = "auto"          # #59
[target.postcondition]            # #55
setup-command = "./prepare-case"
oracle-command = "./check-postcondition"
reset-command = "./reset-case"
```

### Architecture

- New crate `project_profile` (pure): parse + validate the manifest, resolve all
  asset paths against the manifest dir, hash every referenced file, and lower a
  `[[target]]` into the existing `FuzzArgs` / `BinaryFuzzArgs` plus a resolved
  asset set. Pure so it is unit-testable without running a campaign.
- `bhf project run` builds the args struct for the target's engine and calls the
  existing `fuzz::run` / `binary_fuzz::run` entry points — no new execution path.
- `bhf project validate` is `run` minus execution: resolve, hash, type-check, and
  report every asset and the effective launch, exiting non-zero on any problem.
- Provenance: a `project.json` in the work dir records the manifest hash, each
  target's resolved args, and every asset's path+sha256. Findings reference the
  target id and manifest version.

### Integration points

- `FuzzArgs`/`BinaryFuzzArgs` are already the composition surface — `project run`
  just populates them. `--runner`/`--target-arg` (#47), `--runtime-oracles`
  (#59), and the postcondition hooks (#55) are the fields a profile sets.
- Dictionary/grammar/seed loading already exists on the fuzz path; the profile
  resolver points them at the manifest-relative assets.
- Trust: the manifest is loaded only via explicit `--manifest`; the untrusted
  auto-load rules of `.bhf.toml` are unchanged.

## Risks / open questions

- Overlap with `.bhf.toml`: keep them separate (campaign config vs. external
  target description) rather than extending the strict `.bhf.toml` schema.
- Path safety: asset paths must stay under the manifest dir (reject `..`
  escapes) unless an explicit `allow-external-paths` is set.
- Versioning: `requires-bhf` gate so a profile pinned to a feature fails closed
  on an older bhf.

## Phased plan

1. `project_profile` crate: schema, parse, validate, asset resolution + hashing,
   lowering to args. Unit tests only (no execution).
2. `bhf project validate` + `list` (read-only; CI-friendly).
3. `bhf project run` dispatching to the existing engines; `project.json`
   provenance; one e2e against a fixture profile.
4. Documentation + a worked example profile.

Each phase is independently shippable; phase 1–2 add no execution risk.
