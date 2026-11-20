<!-- SPDX-License-Identifier: Apache-2.0 -->
# Design: Response-dependent structured multi-message sessions (HDF-7, #58)

> Status: **implemented** (c8c8fd0, `bhf fuzz --protocol-profile` over
> TCP, a black-box lane; replay fixes in 16726ec). Follow-ups delivered:
> - code coverage from the session target: 52e5307 ([#363](https://github.com/Tarmo-Technologies/bhf/issues/363));
> - runtime and postcondition oracles per session, with the target under the
>   runtrace shim: 1ebb169 ([#364](https://github.com/Tarmo-Technologies/bhf/issues/364));
> - spawning and restarting the target with `--session-server-cmd`, with its
>   sanitizer crashes: cf31ce8 ([#260](https://github.com/Tarmo-Technologies/bhf/issues/260));
> - transports beyond TCP: UDP 83bd1da ([#258](https://github.com/Tarmo-Technologies/bhf/issues/258)), serial 3e1b26c
>   ([#262](https://github.com/Tarmo-Technologies/bhf/issues/262)), the existing target transports 08f8d27
>   ([#261](https://github.com/Tarmo-Technologies/bhf/issues/261)), GIOP/IIOP through the `iiop` crate 10060d8
>   ([#315](https://github.com/Tarmo-Technologies/bhf/issues/315));
> - framing as a protocol-profile property, raw by default: 44c1ade
>   ([#257](https://github.com/Tarmo-Technologies/bhf/issues/257)).
>
> User guide: [Stateful protocol sessions](../site/cli.md#stateful-protocol-sessions).
> Builds on existing HDF-7 library pieces; can consume #57's `scenario.*`
> capability through `bhf extension session`.

## Problem

bhf has HDF-7 library pieces for computed binary fields and protocol state
graphs, but they are not assembled into a CLI-visible, response-dependent
multi-message campaign:

- `bhf fuzz --grammar` describes a text-style CFG, not a request/response
  session.
- The transport loop sends one opaque input to `run_input`.
- `ProtocolStateGraph` is not connected to the engine scheduler.
- Application **response bytes** are not available to extract a handle / request
  id / nonce / cookie / stream id needed by a later request.
- Replay/minimization has no representation for dependent message sequences.

That leaves a common high-impact class hard to reach: a target accepts message
B only after message A returns a per-session value that B must echo, both
carry computed lengths or checksums, and the security violation exits
successfully.

## Goals

- A versioned **protocol-profile** accepted by `bhf fuzz` (or a dedicated
  subcommand) describing message types, typed fields, byte order/widths/enums,
  bounded variable data, optional fields, computed fields (length,
  CRC/checksum, TLV length, offset, back-reference), legal
  ordering/transitions, response-field extraction, references from later
  requests to captured response values, and setup/teardown/reset + a transport
  binding.
- A testcase is a sequence of structured messages; mutate field values and
  sequence structure, then repair computed fields before execution.
- Schedule on both code coverage and protocol-state/transition novelty.

## Non-goals

- Automatic protocol inference (explicit profile only; inference is future
  work).
- Shipping transport backends beyond what `TargetTransport` already provides.

## Proposed design

### Profile (illustrative)

```toml
schema = "bhf.protocol.v1"
transport = "tcp"                 # harness | socket | queue | TargetTransport id

[[message]]
name = "OPEN"
[[message.field]]
name = "path"; type = "bytes"; max = 256
[[message.field]]
name = "len"; type = "u32"; computed = "length(path)"
[[message.field]]
name = "crc"; type = "u32"; computed = "crc32(path)"
[message.response]                # what to capture from the reply
handle = { at = 0, type = "u32" }

[[message]]
name = "WRITE"
[[message.field]]
name = "handle"; type = "u32"; ref = "OPEN.response.handle"   # back-reference
# ... offset/data/length/crc ...

[[transition]]
from = "start"; send = "OPEN"; to = "opened"
[[transition]]
from = "opened"; send = "WRITE"; to = "opened"
```

### Architecture

- New crate `protocol_session` (builds on the HDF-7 pieces): parse the profile
  into a typed message/field model + a `ProtocolStateGraph`; a
  `SessionTestcase` = an ordered list of `MessageInstance`s with concrete
  field values and captured response bindings.
- **Mutation**: two layers, field-value mutation (bounded by type) and
  sequence structure mutation (insert/drop/reorder a legal transition). After
  mutation, a **repair pass** recomputes `computed` fields
  (length/CRC/TLV/offset) and re-resolves `ref` back-references against the
  latest captured responses, so the message is wire-valid before send.
- **Execution**: a session runner drives the transport. For each message it
  encodes, sends, reads the reply, and extracts the declared response fields
  into the binding table, where later `ref`s can use them. Bind to a harness, a
  socket, or an existing `TargetTransport` backend.
- **Scheduling**: the engine scheduler gets a second novelty signal,
  state/transition coverage over the `ProtocolStateGraph`, alongside edge
  coverage, so a sequence reaching a new transition is retained even at equal
  code coverage.
- **Findings/replay**: a `SessionTestcase` serialises to disk (profile id +
  message sequence + captured-response snapshot) so replay re-drives the exact
  session; minimization reduces the sequence AND field bytes while preserving
  computed-field validity, response bindings, and the finding.

### Integration points

- `TargetTransport` (crates/cli/src/transport_*): the session runner's send/recv
  backend; already models qemu/gdb/socket transports.
- The builtin engine scheduler: add the state-novelty feedback channel next to
  the coverage bitmap.
- Oracles: crash, #59 runtime oracles and #55 postconditions all apply per
  session unchanged (the violation often exits 0, so #55/#59 catch it).

## Risks / open questions

- Scope is large; build a vertical slice first: 2 message types, a length and
  a CRC computed field, one response-to-ref back-reference, TCP transport, over
  the issue's toy OPEN/WRITE service.
- Repair-versus-mutation ordering matters (mutate, then repair): a mutated CRC
  must be recomputed or the target rejects every input.
- State-novelty feedback must not dominate code coverage (weight/bucket it).

## Phased plan

1. `protocol_session` crate: profile schema, typed model, `SessionTestcase`,
   encode/repair of computed fields + back-references. Unit tests against the
   toy OPEN/WRITE profile (no live target).
2. Session runner over `TargetTransport` (TCP first); response extraction +
   binding table; replay of a serialised session.
3. Engine integration: structure and field mutation, and state-novelty
   scheduling.
4. Minimization of sequences; docs + the toy-service e2e the issue describes.

Phase 1 is pure and self-contained; later phases layer on the live engine.
