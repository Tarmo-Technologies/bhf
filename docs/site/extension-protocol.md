<!-- SPDX-License-Identifier: Apache-2.0 -->
# The `bhf.extension.v1` out-of-process extension protocol

bhf can drive an **explicitly trusted extension** that runs as a separate process. The extension holds a private semantic oracle: it judges whether an input that exits cleanly still breaks a contract, a violation that a crash-only fuzzer cannot see. The oracle stays out of bhf's source and can be written in any language. This page is the wire contract an extension implements. Findings are written for generic importers such as SARIF and vulnerability-management tools.

The host's serde envelope (`crates/extension_host`) is the authoritative parser and rejects unknown fields. The JSON Schemas `schemas/bhf.extension.v1.request.schema.json` and `schemas/bhf.extension.v1.response.schema.json` describe the same bytes for other implementations. The golden fixtures in `crates/extension_host/tests/fixtures/` are validated against both the parser and the schemas. A complete Python reference extension with no dependencies is `crates/extension_host/tests/fixtures/reference_extension.py`.

## Commands

| Command | What it does |
|---|---|
| `bhf extension validate --manifest <m>` | starts the extension, negotiates the protocol and capabilities, and prints them with the executable and config SHA-256, without driving a case |
| `bhf extension evaluate --manifest <m> --input <file> --work <dir>` | runs `oracle.evaluate` on one input; a violation becomes a finding under `<dir>/results/findings/` |
| `bhf extension session --manifest <m> --input <file> --work <dir>` | drives a multi-message session (see [Capability surface](#capability-surface)) |
| `bhf extension minimize --manifest <m> --finding <dir>` | shrinks an extension finding's testcase while its signature stays the same |
| `bhf fuzz --extension <m>` | after a campaign, runs the retained corpus through `oracle.evaluate` |

The `bhf extension` subcommands take `--json` for a machine-readable report. Their exit codes:

| Code | Meaning |
|---|---|
| `0` | clean: the input was evaluated and is benign |
| `1` | at least one finding was emitted |
| `2` | manifest, usage or setup error |
| `3` | `session` over `--session-transport`: the target ended the session or its service exited |
| `4` | bounded extension-side infrastructure failure (crash, timeout, oversized or malformed reply, unsupported) |

## Manifest

An extension is loaded only from a `bhf.extension-manifest.v1` TOML file that you name with `--manifest`. The manifest is strict: unknown keys are an error. This manifest sits next to an executable copy of `reference_extension.py`:

```toml
schema = "bhf.extension-manifest.v1"
id = "path-oracle"
executable = "reference_extension.py"
required-capabilities = ["oracle.evaluate"]
env-passthrough = ["LANG"]

[limits]
call-timeout-ms = 5000
max-restarts = 2
```

```sh
bhf extension validate --manifest ./extension.toml
printf '../etc/passwd' > input.bin
bhf extension evaluate --manifest ./extension.toml --input input.bin --work ext_work
```

The second command reports a finding and exits with code `1`.

| Key | Meaning |
|---|---|
| `schema` | must be `bhf.extension-manifest.v1` |
| `executable`, `args` | the program to run, resolved relative to the manifest's directory, and its fixed arguments (relative arguments resolve against your working directory) |
| `allow-external-paths` | allow an absolute executable path or one outside the manifest's directory (default `false`) |
| `required-capabilities`, `optional-capabilities` | capabilities the extension must provide, and ones bhf uses when it does |
| `env`, `env-passthrough` | variables to set on the child, and host variables to forward by name; the child starts with an empty environment |
| `requires-bhf` | a `>=X.Y[.Z]` bound; an older bhf refuses the manifest |
| `id`, `version`, `format` | an identifier, a version string, and the wire format (`json`) |
| `[limits]` | `max-frame-bytes`, `call-timeout-ms`, `max-outstanding`, `address-space-bytes`, `cpu-seconds`, `max-restarts` |

## Transport and framing

Every message is one length-prefixed frame on the child's stdin and stdout:

```
{u32 little-endian length}{UTF-8 JSON payload}
```

The host checks the declared length against the negotiated cap **before** it allocates, so an oversized length cannot exhaust the host's memory. A body cut off mid-frame is a protocol error; a clean EOF at a frame boundary is an orderly shutdown. The host speaks JSON. The handshake negotiates a `format` field, so a binary encoding such as CBOR can be added without changing the frame.

## Handshake and capability negotiation

Before any case, the host sends a `hello` and the extension replies with its own. The host rejects an incompatible protocol identifier or a missing **required** capability before it drives any case.

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
  "version": "0.2.0"
}
```

The session uses the required capabilities plus the optional capabilities the extension also provides, and the element-wise **minimum** of the two sides' limits.

## Requests and responses

Every request and response carries the full campaign, worker and testcase identity. A response is matched to its request by that identity, and the host rejects a response whose `case` differs from the request's, so two workers' test cases cannot mix.

A request:

```json
{
  "protocol": "bhf.extension.v1",
  "capability": "oracle.evaluate",
  "case": { "campaign": "demo", "worker": "worker-0", "testcase": "tc-000123" },
  "payload": { "input_b64": "Li4vZXRjL3Bhc3N3ZA==" }
}
```

For `oracle.evaluate`, the payload carries the raw test input as standard base64 in `input_b64`.

A response declares one deterministic **result class**:

| `result` | Meaning |
|---|---|
| `ok` | The input was evaluated and is benign. |
| `reject` | The extension cannot use this input (for example, it does not decode); drop it. |
| `finding` | The input triggered a semantic violation; a `finding` object is attached. |
| `unsupported` | The capability does not apply to this input or mode (bounded). |
| `infrastructure_error` | The extension reports an internal error (bounded). |

`ok`, `reject` and `finding` describe the target. `unsupported`, `infrastructure_error`, a crash, a per-call timeout, an oversized or malformed frame and a mismatched case identity are **bounded infrastructure results**: bhf records them and never reports them as a target vulnerability.

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

The host hashes `signature_inputs`, **in the order given**, into the finding's stable `signature`. The same violation gives the same signature on replay, minimization and re-evaluation, whatever order the host iterates in. `min_predicate`, when present, names a minimization predicate the extension exposes.

`bhf extension minimize --manifest <m> --finding <dir>` delta-debugs a finding's testcase by re-running `oracle.evaluate`. It accepts a candidate only when it reproduces the **same stable signature**, writes `min_testcase.bin` next to the finding, and leaves the recorded `signature` unchanged.

## Trust, isolation and provenance

- **Explicit loading.** bhf loads an extension only through an explicit `--manifest` path and never discovers one on its own. Naming the manifest is your act of trust.
- **Isolation.** The child runs with a cleared environment that holds only the variables the manifest sets or passes through. Provenance records the **names** of passed and dropped variables, never their values. On Unix, `setrlimit` applies the `RLIMIT_AS` and `RLIMIT_CPU` caps.
- **Crash isolation and restarts.** A crash or timeout triggers a bounded restart policy. When the restart budget runs out, including when a restarted child fails the handshake again, bhf records a terminal loss event and carries on. `bhf extension evaluate` and `session` classify it as infrastructure (exit code `4`) and still write the run's `extension.json` provenance.
- **Provenance.** Findings and run metadata record the SHA-256 of the extension executable and its config, the negotiated protocol version and capabilities, the applied resource limits and the restart and loss counts.

## Capability surface

The host implements the full `bhf.extension.v1` capability set. `bhf extension session` and `bhf fuzz --extension` request every capability below as optional, on top of the manifest's `required-capabilities`, so an extension that provides a subset still negotiates and the host drives the capabilities both sides agreed on. `validate`, `evaluate` and `minimize` request the manifest's required and optional capabilities.

| Capability | Request payload | `ok` response `value` |
|---|---|---|
| `oracle.evaluate` | `{ "input_b64": … }` | *(none; the result travels in `finding`)* |
| `codec.decode` | `{ "input_b64": … }` | `{ "decoded": <structured> }` |
| `codec.encode` | `{ "decoded": <structured> }` | `{ "output_b64": … }` |
| `codec.repair` | `{ "input_b64": … }` | `{ "output_b64": … }` |
| `mutator.mutate` | `{ "input_b64": …, "seed": <u64> }` | `{ "output_b64": … }` |
| `scenario.next` | `{ "step": <u32>, "seed_b64"? : … }` | `{ "message_b64": …, "label"? : … }` or `{ "done": true }` |
| `scenario.observe-response` | `{ "step": <u32>, "response_b64": … }` | *(ack)* |
| `lifecycle.setup` / `lifecycle.reset` | `{ "root"? : "<path>" }` | *(ack)* |
| `lifecycle.teardown` | `{}` | *(ack)* |

- **`codec.*`** lets a private codec decode a raw frame to a structured value, encode it back, and **repair** computed fields (length prefixes, checksums) after a mutation, so a mutated frame reaches the target well formed. The extension `reject`s a frame it does not recognise and leaves it untouched, so the host works with any corpus without knowing the codec.
- **`mutator.mutate`** supplies a structure-aware mutation of a decoded input; the `seed` makes it reproducible for replay.
- **`scenario.*`** drives a multi-message session. `scenario.next` yields the next message, the target's response bytes go back through `scenario.observe-response`, and the extension binds a value from a response (a handle, a nonce) into a later message. `bhf extension session` combines this with `codec.repair`, `mutator.mutate` and `oracle.evaluate`. bhf owns the transport: a built-in test target by default, or a real target over `--session-transport` (`tcp:HOST:PORT`, `udp:HOST:PORT`, `serial:PATH[,baud=N]` or `transport:SPEC`). The extension owns the target's wire protocol.
- **`lifecycle.*`** manages per-case state: `setup` before the first case, `reset` with a fresh temporary root between cases, and `teardown` at the end.

The host speaks JSON; the handshake's `format` field leaves room for a CBOR encoding. A `bhf.project.v1` profile reaches the same capabilities through its `[[extension]]` section, which `bhf project run` turns into a trusted manifest and loads.
