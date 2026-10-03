<!-- SPDX-License-Identifier: Apache-2.0 -->
# The `bhf.extension.v1` out-of-process extension protocol

bhf can drive an **explicitly-trusted, out-of-process extension** so a *private*
semantic oracle can judge whether a clean-exiting input violates a contract a
crash-only fuzzer cannot see — without vendoring that oracle into bhf, and in any
language. This document is the externally-implementable wire contract: an
extension that speaks it interoperates with the host regardless of the language it
is written in. The host names no specific downstream consumer; results are
written for generic importers (SARIF / vulnerability-management tooling).

The authoritative parser is the host's serde envelope
(`crates/extension_host`), which rejects unknown fields; the published JSON
Schemas under [`schemas/`](../schemas/) (`bhf.extension.v1.request.schema.json`,
`bhf.extension.v1.response.schema.json`) describe the same bytes for external
implementers, and the committed golden fixtures under
`crates/extension_host/tests/fixtures/` are validated against **both** so the two
layers can never drift. A complete, dependency-free Python reference extension
lives at `crates/extension_host/tests/fixtures/reference_extension.py`.

## Transport and framing

Every message is a single length-framed frame over the child's stdin/stdout:

```
{u32 little-endian length}{UTF-8 JSON payload}
```

The declared length is checked against a negotiated cap **before** any
allocation, so a malformed oversized length can never drive the host
out-of-memory. A truncated body mid-frame is a protocol error; a clean EOF at a
frame boundary is an orderly shutdown. The host speaks JSON only today; the
handshake negotiates a `format` field so a binary encoding (e.g. CBOR) can be
added later without a wire break.

## Handshake and capability negotiation

Before any case is driven, the host sends a `hello` and the extension replies
with its own. The host rejects an incompatible protocol identifier or any missing
**required** capability up front — no case is ever driven against an extension
that cannot satisfy the campaign.

Host hello:

```json
{
  "protocol": "bhf.extension.v1",
  "required_capabilities": ["oracle.evaluate"],
  "optional_capabilities": [],
  "formats": ["json"],
  "limits": { "max_frame_bytes": 1048576, "call_timeout_ms": 5000 }
}
```

Extension hello:

```json
{
  "protocol": "bhf.extension.v1",
  "provided_capabilities": ["oracle.evaluate"],
  "formats": ["json"],
  "name": "reference_extension.py",
  "version": "0.1.0"
}
```

The negotiated session uses the capability intersection (required ∪ the optional
capabilities the extension also provides) and the element-wise **minimum** of the
two sides' limits.

## Requests and responses

Every request and every response carries the full campaign/worker/testcase
identity, so a response can be matched to its request and two workers can never
mix test-case identity (the host rejects a response whose `case` differs from the
request's).

A request:

```json
{
  "protocol": "bhf.extension.v1",
  "capability": "oracle.evaluate",
  "case": { "campaign": "demo", "worker": "worker-0", "testcase": "tc-000123" },
  "payload": { "input_b64": "Li4vZXRjL3Bhc3N3ZA==" }
}
```

For `oracle.evaluate` the payload carries the raw test input as standard base64
in `input_b64`.

A response declares one deterministic **result class**:

| `result` | Meaning |
|---|---|
| `ok` | The input was evaluated and is benign. |
| `reject` | The extension could not use this input (e.g. undecodable); drop it. |
| `finding` | The input triggered a semantic violation; a `finding` is attached. |
| `unsupported` | The capability is not supported for this input/mode (bounded). |
| `infrastructure_error` | The extension hit an internal error it reports explicitly (bounded). |

`ok`/`reject`/`finding` are target-truth outcomes; `unsupported` and
`infrastructure_error` — along with any crash, per-call timeout, oversized or
malformed frame, or mismatched case identity — are **bounded infrastructure
results** that can never be reported as a target vulnerability.

A `finding` response:

```json
{
  "protocol": "bhf.extension.v1",
  "case": { "campaign": "demo", "worker": "worker-0", "testcase": "tc-000123" },
  "result": "finding",
  "finding": {
    "rule": "oracle.path-escape",
    "classification": "extension_oracle",
    "signature_inputs": ["oracle.path-escape", "../etc/passwd"],
    "evidence": [
      { "key": "path", "value": "../etc/passwd" },
      { "key": "reason", "value": "escapes sandbox root" }
    ],
    "min_predicate": "path-contains-dotdot"
  }
}
```

The host hashes `signature_inputs` **in the order given** into the finding's
stable `signature`, so the same violation reproduces the identical signature on
replay/minimize/re-evaluate regardless of host-side iteration order. The
`min_predicate`, when present, names a minimization predicate the extension
exposes.

## Trust, isolation, and provenance

- **No implicit execution.** An extension is only ever loaded through an explicit
  `--manifest` path (`bhf.extension-manifest.v1`, see `bhf extension --help`);
  there is no auto-discovery. Naming the manifest is the operator's act of trust.
- **Isolation.** The child runs with a cleared, explicitly allow-listed
  environment (only the **names** of passed/dropped variables are ever recorded,
  never the values) and, on unix, `setrlimit(RLIMIT_AS/RLIMIT_CPU)` caps.
- **Crash isolation + restart policy.** A crash or timeout triggers a bounded
  restart policy; an exhausted restart budget is a terminal loss event.
- **Provenance.** Findings and run metadata record the extension executable and
  config SHA-256, the negotiated protocol version and capabilities, the applied
  resource limits, and the restart/loss counts.

## Capability surface

The host drives the full `bhf.extension.v1` capability set. Capability
negotiation advertises every capability as optional on top of the manifest's
`required-capabilities`, so an extension that implements only a subset still
negotiates cleanly — the host drives exactly what both sides agreed on.

| Capability | Request payload | `ok` response `value` |
|---|---|---|
| `oracle.evaluate` | `{ "input_b64": … }` | *(none; result travels in `finding`)* |
| `codec.decode` | `{ "input_b64": … }` | `{ "decoded": <structured> }` |
| `codec.encode` | `{ "decoded": <structured> }` | `{ "output_b64": … }` |
| `codec.repair` | `{ "input_b64": … }` | `{ "output_b64": … }` |
| `mutator.mutate` | `{ "input_b64": …, "seed": <u64> }` | `{ "output_b64": … }` |
| `scenario.next` | `{ "step": <u32>, "seed_b64"? : … }` | `{ "message_b64": …, "label"? : … }` or `{ "done": true }` |
| `scenario.observe-response` | `{ "step": <u32>, "response_b64": … }` | *(ack)* |
| `lifecycle.setup` / `lifecycle.reset` | `{ "root"? : "<path>" }` | *(ack)* |
| `lifecycle.teardown` | `{}` | *(ack)* |

- **`codec.*`** let a private codec decode a raw frame to a structured value,
  encode it back, and **repair** computed fields (length prefixes, checksums)
  after a mutation — so a mutation-corrupted frame reaches the target well-formed.
  A frame the extension does not recognize is `reject`ed and left untouched, so
  the host stays codec-agnostic over arbitrary corpora.
- **`mutator.mutate`** supplies a structure-aware mutation of a decoded input; the
  `seed` makes it reproducible for replay.
- **`scenario.*`** drive a multi-message session: `scenario.next` yields the next
  message, the target's response bytes are fed back via
  `scenario.observe-response`, and the extension binds a response-derived value (a
  handle, a nonce) into a later message. `bhf extension session` composes this
  with `codec.repair`, `mutator.mutate`, and `oracle.evaluate` over a target seam;
  the host owns the transport (the stateful-session TCP transport or an in-process
  target), never the target's wire protocol.
- **`lifecycle.*`** orchestrate per-case state: `setup` before the first case,
  `reset` with a fresh temp root between cases, `teardown` at the end.

CBOR wire encoding remains optional (the handshake already negotiates `format`);
the host speaks JSON only. The same capabilities are also reachable from a
`bhf.project.v1` profile's `[[extension]]` section, which `bhf project run`
materializes as a trusted manifest and loads.
