#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""A portable, out-of-tree reference ``bhf.extension.v1`` extension.

Implemented against the published wire contract using only the Python standard
library -- it imports nothing from bhf. This is the "portable SDK / implemented
once outside the tree" deliverable: the same protocol a Rust host drives, spoken
by a short, language-independent script.

It implements the issue's minimal reproduction for a toy framed protocol::

    [u16 big-endian length][payload][u32 big-endian CRC-32]
    OPEN(path) -> response handle
    WRITE(handle, data)

and the full capability surface over it:

* ``oracle.evaluate`` -- flag a clean-exiting target that "writes outside its
  sandbox root" (a path with a ``..`` component or an absolute path);
* ``codec.decode`` / ``codec.encode`` -- structured view of a frame and back
  (an input that is not a recognized toy frame is ``reject``ed, never decoded);
* ``codec.repair`` -- recompute the length prefix and CRC after a mutation, but
  only for a recognized toy frame -- an unrecognized raw input is ``reject``ed so
  the host evaluates it verbatim and stays codec-agnostic over arbitrary corpora;
* ``mutator.mutate`` -- a structure-aware mutation (grow the data region,
  leaving the computed fields stale for ``codec.repair`` to fix);
* ``scenario.next`` / ``scenario.observe-response`` -- drive OPEN then WRITE,
  binding the handle the OPEN response returns into the WRITE;
* ``lifecycle.setup`` / ``reset`` / ``teardown`` -- reset a temp root per case.

No extension source is copied into the BHF repository and BHF is not rebuilt.

Wire envelope framing: ``{u32 little-endian length}{UTF-8 JSON payload}`` over
stdin/stdout. The toy protocol framing is big-endian and independent of it.
"""
import base64
import json
import struct
import sys
import zlib

PROTOCOL = "bhf.extension.v1"
CAPABILITIES = [
    "oracle.evaluate",
    "codec.decode",
    "codec.encode",
    "codec.repair",
    "mutator.mutate",
    "scenario.next",
    "scenario.observe-response",
    "lifecycle.setup",
    "lifecycle.reset",
    "lifecycle.teardown",
]


# ---- envelope framing: {u32 LE length}{JSON} ------------------------------


def read_frame(stream):
    header = stream.read(4)
    if not header:
        return None
    if len(header) < 4:
        raise EOFError("truncated frame header")
    (length,) = struct.unpack("<I", header)
    body = stream.read(length)
    if len(body) < length:
        raise EOFError("truncated frame body")
    return body


def write_frame(stream, payload):
    stream.write(struct.pack("<I", len(payload)))
    stream.write(payload)
    stream.flush()


# ---- toy protocol framing: [u16 BE len][payload][u32 BE crc32] ------------


def build_frame(payload):
    return struct.pack(">H", len(payload)) + payload + struct.pack(">I", zlib.crc32(payload) & 0xFFFFFFFF)


def parse_frame(frame):
    if len(frame) < 6:
        return None
    (declared_len,) = struct.unpack(">H", frame[:2])
    payload = frame[2:-4]
    (crc,) = struct.unpack(">I", frame[-4:])
    return declared_len, payload, crc


def is_known_op(payload):
    """Whether a frame payload is one this toy protocol recognizes.

    This is the codec-agnostic recognition guard: ``codec.decode`` / ``codec.repair``
    MUST ``reject`` any input that is not a well-formed toy frame so the host
    evaluates an UNRECOGNIZED raw corpus entry VERBATIM instead of silently
    rebuilding arbitrary bytes into a toy frame (matching the in-repo mock's
    ``is_known_op`` and the ``drive_fuzz_extension`` contract)."""
    op = payload.split(b" ", 1)[0]
    return op in (b"OPEN", b"WRITE", b"OPENOK", b"WRITEOK")


# ---- envelope result helpers ---------------------------------------------


def ok(protocol, case, value=None):
    resp = {"protocol": protocol, "case": case, "result": "ok"}
    if value is not None:
        resp["value"] = value
    return resp


def reject(protocol, case, detail):
    return {"protocol": protocol, "case": case, "result": "reject", "detail": detail}


def unsupported(protocol, case, capability):
    return {
        "protocol": protocol,
        "case": case,
        "result": "unsupported",
        "detail": "%s is not supported" % capability,
    }


# ---- capability handlers --------------------------------------------------


def escapes(path):
    return path.startswith("/") or any(seg == ".." for seg in path.split("/"))


def oracle_evaluate(protocol, case, input_bytes):
    path = input_bytes.decode("utf-8", "replace")
    if escapes(path):
        return {
            "protocol": protocol,
            "case": case,
            "result": "finding",
            "finding": {
                "rule": "oracle.path-escape",
                "classification": "extension_oracle",
                "signature_inputs": ["oracle.path-escape", path],
                "evidence": [
                    {"key": "path", "value": path},
                    {"key": "reason", "value": "escapes sandbox root"},
                ],
                "min_predicate": "path-contains-dotdot",
            },
        }
    return ok(protocol, case)


def decode_payload(payload, crc_valid):
    text = payload.decode("utf-8", "replace")
    parts = text.split(" ", 2)
    op = parts[0] if parts else ""
    if op == "OPEN":
        return {
            "op": "OPEN",
            "path": parts[1] if len(parts) > 1 else "",
            "length": len(payload),
            "crc_valid": crc_valid,
        }
    if op == "WRITE":
        return {
            "op": "WRITE",
            "handle": parts[1] if len(parts) > 1 else "",
            "data": parts[2] if len(parts) > 2 else "",
            "length": len(payload),
            "crc_valid": crc_valid,
        }
    return {"op": op, "length": len(payload), "crc_valid": crc_valid}


def encode_payload(decoded):
    op = decoded.get("op")
    if op == "OPEN":
        return ("OPEN %s" % decoded.get("path", "")).encode("utf-8")
    if op == "WRITE":
        return ("WRITE %s %s" % (decoded.get("handle", ""), decoded.get("data", ""))).encode("utf-8")
    return None


def codec_decode(protocol, case, frame):
    parsed = parse_frame(frame)
    if parsed is None or not is_known_op(parsed[1]):
        # An input that is not a well-formed toy frame is rejected, never decoded,
        # so the host stays codec-agnostic over arbitrary corpora.
        return reject(protocol, case, "not a recognized frame")
    declared_len, payload, crc = parsed
    crc_valid = declared_len == len(payload) and crc == (zlib.crc32(payload) & 0xFFFFFFFF)
    return ok(protocol, case, {"decoded": decode_payload(payload, crc_valid)})


def codec_encode(protocol, case, request):
    decoded = request.get("payload", {}).get("decoded")
    payload = encode_payload(decoded) if decoded is not None else None
    if payload is None:
        return reject(protocol, case, "undecodable structured value")
    frame = build_frame(payload)
    return ok(protocol, case, {"output_b64": base64.b64encode(frame).decode("ascii")})


def codec_repair(protocol, case, frame):
    parsed = parse_frame(frame)
    if parsed is None or not is_known_op(parsed[1]):
        # Only a frame recognized as this extension's format is rebuilt; an
        # unrecognized raw corpus entry is rejected and left for the host to
        # evaluate verbatim (never silently rebuilt into a toy frame).
        return reject(protocol, case, "not a recognized frame to repair")
    payload = parsed[1]
    repaired = build_frame(payload)
    return ok(protocol, case, {"output_b64": base64.b64encode(repaired).decode("ascii")})


def mutator_mutate(protocol, case, request):
    frame = base64.b64decode(request.get("payload", {}).get("input_b64", ""))
    seed = int(request.get("payload", {}).get("seed", 0))
    if len(frame) < 6:
        return reject(protocol, case, "frame too short to mutate")
    old_len = frame[:2]
    payload = frame[2:-4]
    old_crc = frame[-4:]
    mutated = old_len + payload + bytes([seed & 0xFF]) + old_crc  # stale len/crc
    return ok(protocol, case, {"output_b64": base64.b64encode(mutated).decode("ascii")})


def scenario_next(protocol, case, request, state):
    step = int(request.get("payload", {}).get("step", 0))
    if step == 0:
        state["path"] = base64.b64decode(request.get("payload", {}).get("seed_b64", ""))
        frame = build_frame(b"OPEN " + state["path"])
        return ok(protocol, case, {"message_b64": base64.b64encode(frame).decode("ascii"), "label": "OPEN"})
    if step == 1:
        handle = state.get("handle", "0")
        payload = ("WRITE %s " % handle).encode("utf-8") + b"data:" + state.get("path", b"")
        frame = build_frame(payload)
        return ok(protocol, case, {"message_b64": base64.b64encode(frame).decode("ascii"), "label": "WRITE"})
    return ok(protocol, case, {"done": True})


def scenario_observe(protocol, case, request, state):
    response = base64.b64decode(request.get("payload", {}).get("response_b64", ""))
    parsed = parse_frame(response)
    if parsed is not None:
        text = parsed[1].decode("utf-8", "replace")
        if text.startswith("OPENOK "):
            state["handle"] = text[len("OPENOK "):].strip()
    return ok(protocol, case)


def lifecycle(protocol, case, request, state, reset):
    if reset:
        state.pop("handle", None)
        state.pop("path", None)
    root = request.get("payload", {}).get("root")
    if root is not None:
        state["root"] = root
    return ok(protocol, case)


def handle(protocol, case, capability, request, state):
    if capability == "oracle.evaluate":
        return oracle_evaluate(protocol, case, base64.b64decode(request.get("payload", {}).get("input_b64", "")))
    if capability == "codec.decode":
        return codec_decode(protocol, case, base64.b64decode(request.get("payload", {}).get("input_b64", "")))
    if capability == "codec.encode":
        return codec_encode(protocol, case, request)
    if capability == "codec.repair":
        return codec_repair(protocol, case, base64.b64decode(request.get("payload", {}).get("input_b64", "")))
    if capability == "mutator.mutate":
        return mutator_mutate(protocol, case, request)
    if capability == "scenario.next":
        return scenario_next(protocol, case, request, state)
    if capability == "scenario.observe-response":
        return scenario_observe(protocol, case, request, state)
    if capability == "lifecycle.setup":
        return lifecycle(protocol, case, request, state, reset=False)
    if capability == "lifecycle.reset":
        return lifecycle(protocol, case, request, state, reset=True)
    if capability == "lifecycle.teardown":
        state.clear()
        return ok(protocol, case)
    return unsupported(protocol, case, capability)


def main():
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer

    hello = read_frame(stdin)
    if hello is None:
        return
    host = json.loads(hello)
    protocol = host.get("protocol", PROTOCOL)

    write_frame(
        stdout,
        json.dumps(
            {
                "protocol": protocol,
                "provided_capabilities": CAPABILITIES,
                "formats": ["json"],
                "name": "reference_extension.py",
                "version": "0.2.0",
            }
        ).encode("utf-8"),
    )

    state = {}
    while True:
        frame = read_frame(stdin)
        if frame is None:
            return
        request = json.loads(frame)
        case = request.get("case")
        capability = request.get("capability", "")
        response = handle(protocol, case, capability, request, state)
        write_frame(stdout, json.dumps(response).encode("utf-8"))


if __name__ == "__main__":
    main()
