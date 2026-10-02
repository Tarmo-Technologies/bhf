<!-- SPDX-License-Identifier: Apache-2.0 -->
# Design: Versioned out-of-process extension protocol (#57)

> Status: **design for review** — no implementation yet. Largest of the five
> private-target-integration specs; depends conceptually on #56 (profiles) to
> declare which extensions a target trusts.

## Problem

bhf's "plugins" are compile-time Rust registries: `BugOracle`s linked into
`ORACLE_REGISTRY`/`ORACLE_MANIFEST`, fake-resource plugins compiled into the
runtrace shim, and internal structured-mutator/sequence types. Adding a private
codec, protocol-repair pass, semantic oracle, or lifecycle adapter means
modifying and rebuilding bhf — unsuitable for proprietary targets and coupling
the bhf release cycle to every internal research project. A Rust dynamic-library
ABI would be brittle across compiler/bhf versions and would run extension code
in-process. A versioned out-of-process protocol gives isolation, language
independence, explicit resource limits, and reproducible provenance.

## Goals

- A negotiated `bhf.extension.v1` subprocess protocol over length-framed JSON (or
  CBOR) with capability negotiation, so a private extension adds codecs/mutators/
  oracles/lifecycle hooks without recompiling bhf.
- Crash/timeout isolation: an extension fault is an infrastructure result, never
  a target vulnerability.
- Deterministic replay/minimization using the same extension version + config.

## Non-goals

- Shipping any concrete extension. This spec is the protocol + host harness only.
- In-process performance parity (out-of-process has per-call overhead by design;
  mitigate with batching, not by moving in-process).

## Proposed design

### Transport & framing

- The host spawns the extension executable (declared in a #56 profile, explicitly
  trusted) and speaks over its stdin/stdout: `{u32 LE length}{payload}` frames,
  payload JSON by default (CBOR negotiated). stderr is captured for diagnostics.
- Handshake: host sends `hello{protocol:"bhf.extension.v1", requested_caps:[...]}`;
  extension replies `hello{protocol, provided_caps:[...], limits:{...}}`. The host
  **rejects incompatible required capabilities before fuzzing starts**.

### Capabilities (negotiated, subset allowed)

```text
codec.decode    codec.encode    codec.repair
mutator.mutate
scenario.next   scenario.observe-response
oracle.evaluate
lifecycle.setup lifecycle.reset lifecycle.teardown
```

The initial host implementation need not drive all of them; a narrow stable
envelope + negotiation lets capabilities be added without new ad-hoc hooks.

### Envelope (required properties, from the issue)

1. **Version + capability negotiation** — reject incompatible required caps up
   front.
2. **Case identity** — every request/response carries `{campaign, worker,
   testcase}` ids so concurrent events cannot cross-contaminate.
3. **Bounded messages** — enforce max frame size, per-call timeout, and a cap on
   outstanding requests.
4. **Deterministic result classes** — `ok | reject | finding | unsupported |
   infrastructure_error`.
5. **Stable finding identity** — an `oracle.evaluate` finding carries a
   rule/classification, signature inputs, evidence, and an optional minimization
   predicate id.
6. **Crash isolation** — an extension crash/timeout is `infrastructure_error`;
   the host may restart it per an explicit policy (max restarts, backoff).
7. **Replay/minimization** — replay pins the extension version + config;
   minimization preserves codec validity, response bindings, and oracle truth.
8. **Provenance** — record executable+config hashes, negotiated caps, protocol
   version, env redactions, resource limits, and restart/loss events.

### Architecture

- New crate `extension_host`: the framed-codec, handshake/negotiation state
  machine, a typed `ExtensionClient` with one method per capability, the restart
  policy, and provenance accounting. Pure protocol logic is unit-testable with an
  in-memory duplex pipe; a reference mock extension (in-repo, test-only) exercises
  each capability + the crash/timeout/oversize paths.
- Integration is capability-by-capability and opt-in:
  - `oracle.evaluate` plugs into the finding pipeline beside `ORACLE_REGISTRY`
    (its results map to the same finding record, `confirmation: "extension"`).
  - `codec.*` / `mutator.mutate` plug into the builtin engine's structured-input
    path; a decode/repair failure is `reject` (drop the input), not a finding.
  - `lifecycle.*` and `scenario.*` are consumed by #55's case orchestration and
    #58's session scheduler respectively.
- Trust: extensions are named only by an explicitly-loaded #56 profile; bhf never
  auto-starts an extension from an untrusted tree.

## Risks / open questions

- Scope: this is multi-week. Recommend landing the host + negotiation +
  `oracle.evaluate` first (highest value, smallest surface), deferring
  codec/mutator/scenario.
- Format: JSON is debuggable; CBOR is faster for large payloads. Negotiate, start
  JSON-only in the host.
- Determinism: a non-deterministic extension breaks replay; the host records a
  per-case digest of extension I/O and flags divergence on replay rather than
  silently passing.
- Security: resource limits (rlimits/cgroup) and env redaction on the child are
  mandatory, not optional.

## Phased plan

1. `extension_host` crate: framing, handshake/negotiation, result classes,
   bounded-message + restart policy; in-memory-pipe unit tests + a mock extension.
2. `oracle.evaluate` integration into the finding pipeline (one real extension
   example, e.g. a toy policy oracle) + provenance.
3. `codec.decode/encode/repair` + `mutator.mutate` into the builtin structured
   path.
4. `lifecycle.*` (ties to #55) and `scenario.*` (ties to #58).
5. Replay/minimization pinning + divergence detection; docs.

Phases 1–2 are a shippable, self-contained slice; later phases are independent.
