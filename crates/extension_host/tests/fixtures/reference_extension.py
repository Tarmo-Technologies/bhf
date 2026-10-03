#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""A portable, out-of-tree reference ``bhf.extension.v1`` extension.

Implemented against the published wire contract using only the Python standard
library -- it imports nothing from bhf. This is the "portable SDK / implemented
once outside the tree" deliverable: the same protocol a Rust host drives, spoken
by a short, language-independent script.

It provides the ``oracle.evaluate`` capability and flags a clean-exiting target
that "writes outside its sandbox root" -- a path containing a ``..`` component or
an absolute path -- as a semantic finding. A crash-only fuzzer cannot see such a
violation; a semantic oracle can.

Wire format: ``{u32 little-endian length}{UTF-8 JSON payload}`` frames over
stdin/stdout.
"""
import base64
import json
import struct
import sys

PROTOCOL = "bhf.extension.v1"


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


def evaluate(protocol, case, input_bytes):
    path = input_bytes.decode("utf-8", "replace")
    escapes = path.startswith("/") or any(seg == ".." for seg in path.split("/"))
    if escapes:
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
    return {"protocol": protocol, "case": case, "result": "ok"}


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
                "provided_capabilities": ["oracle.evaluate"],
                "formats": ["json"],
                "name": "reference_extension.py",
                "version": "0.1.0",
            }
        ).encode("utf-8"),
    )

    while True:
        frame = read_frame(stdin)
        if frame is None:
            return
        request = json.loads(frame)
        case = request.get("case")
        payload = request.get("payload", {})
        input_bytes = base64.b64decode(payload.get("input_b64", ""))
        response = evaluate(protocol, case, input_bytes)
        write_frame(stdout, json.dumps(response).encode("utf-8"))


if __name__ == "__main__":
    main()
