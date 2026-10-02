<!-- SPDX-License-Identifier: Apache-2.0 -->
# Design: Platform-neutral runtime-event collector + native Windows provider (#60)

> Status: **design for review** — no implementation yet. Cross-platform
> (Windows); cannot be fully validated in the current Linux dev/CI environment —
> the Windows provider needs a Windows runner. Feeds the #55 semantic predicates
> and #61 relational policy fuzzing.

## Problem

bhf's behavioural oracles depend on the Linux `LD_PRELOAD` runtrace shim, which
is unavailable on native Windows and under Wine/QEMU/cross-emulation. A large
class of high-impact defects exits successfully and is visible only as a runtime
effect: `CreateProcess*`/`ShellExecute*` launching an attacker-selected target, a
file op resolving outside an allowed root, `LoadLibrary*` from an unsafe location,
a descendant process performing the security-relevant action, or a registry/
network/service effect. #55 gives a place to *classify* an arbitrary
postcondition, but bhf lacks a portable *event feed* that exposes these effects
consistently to built-in or private oracles.

## Goals

- A versioned, platform-neutral **runtime-event collector contract** (a sidecar
  protocol) that any provider can implement, feeding the existing oracle registry
  and the #55 semantic predicates.
- An initial native **Windows provider** observing process/file/module-load
  events (ETW a plausible base), usable from an ordinary user session where the
  OS permits, with explicit fidelity/loss metadata.

## Non-goals

- Replacing the Linux `LD_PRELOAD` shim (it stays; this is the portable
  superset for configs the shim cannot reach).
- A Linux provider beyond a thin adapter over the existing runtrace events
  (optional, to prove the contract is platform-neutral).

## Proposed design

### Collector contract (sidecar protocol)

A provider is a subprocess (or OS tracer) that emits normalised events to a
sink the host reads, keyed by case. Reuse the #57 framed-JSON transport where a
subprocess provider fits; an OS tracer (ETW) writes the same JSON event schema to
the per-case audit stream bhf already models (`BHF_RUNTRACE_LOG`-style).

Event schema (superset of the Linux runtrace vocabulary, so one oracle layer
consumes both):

```jsonc
{ "testcase": "...", "worker": 0, "seq": 12,
  "process": { "pid": 1234, "image": "...", "parent": 1200, "ancestor": 1000,
               "user": "...", "session": 1 },
  "kind": "process_create | shell_execute | file_open | file_write | file_rename
           | file_delete | module_load | network | registry",
  "path": "<normalised/resolved>", "args": [...], "verb": "...",
  "ts": 1696200000.123,
  "fidelity": { "lost": 0, "unsupported_fields": [], "permission_denied": false } }
```

Contract requirements (from the issue): testcase begin/end + worker ids; observed
process identity, parent/ancestor, user/token, session where available;
timestamp/order; normalised process/file/module-load/network/optional-registry
events; raw backend evidence references; event-loss / unsupported-field /
permission-failure / fidelity metadata; and a **bounded post-exit observation
window** for descendant effects.

### Architecture

- New crate `runtime_collector` (pure contract): the event schema, a
  `CollectorSession` reader that merges a provider's event stream for one case,
  normalisation helpers (path canonicalisation, ancestor attribution), and the
  mapping from a collector event to an `OracleRuntimeEvent` (so the existing
  `ORACLE_REGISTRY` and #55 predicates consume it unchanged).
- **Windows provider** (`bhf-collector-win`, a separate binary, built only on
  Windows): an ETW consumer subscribing to process/file/image-load providers,
  attributing events to the testcase's descendant process tree, emitting the JSON
  schema. Runs without admin where the OS permits a user-session ETW session;
  missing visibility is reported as `fidelity.permission_denied`, never silently
  dropped.
- Host integration: `bhf binary fuzz`/`bhf fuzz` gain `--collector <auto|path>`;
  when set, the host starts the provider per case (or attaches the OS tracer),
  waits the bounded post-exit window, then runs oracle + #55 evaluation over the
  collected events exactly as the Linux path already does.

### First Windows provider scope

1. `CreateProcess*` + descendant process creation.
2. `ShellExecute*` target/verb/args + resulting child where observable.
3. File create/open/write/rename/delete with resolved paths where possible.
4. `LoadLibrary*` / image-load.
5. The descendant process tree attributable to the testcase.

## Risks / open questions

- **Validation gap**: no Windows CI runner here. Recommend landing the
  platform-neutral `runtime_collector` crate + schema + a Linux adapter (proving
  the contract against existing runtrace events) FIRST, entirely on Linux, then
  the Windows provider as a separately-validated deliverable on a Windows runner.
- ETW specifics (session setup, non-admin capability, event loss under load) are
  provider-implementation details the contract deliberately does not mandate.
- Ordering/attribution: ancestor attribution needs the process-create tree before
  file/module events can be blamed on the testcase; the post-exit window handles
  late descendant effects.

## Phased plan

1. `runtime_collector` crate: schema, `CollectorSession`, normalisation, event →
   `OracleRuntimeEvent` mapping. Pure, Linux-testable.
2. A Linux adapter that feeds existing runtrace events through the contract
   (proves platform-neutrality; no behaviour change).
3. `--collector` wiring on `bhf fuzz`/`bhf binary fuzz` (host side), bounded
   post-exit window, oracle + #55 evaluation over collected events.
4. **Windows provider** (`bhf-collector-win`, ETW) — built + validated on a
   Windows runner; the five event classes above.
5. Docs + fidelity/loss reporting.

Phases 1–3 are Linux-only and self-contained; phase 4 is the cross-platform piece
that needs a Windows environment to land and test.
