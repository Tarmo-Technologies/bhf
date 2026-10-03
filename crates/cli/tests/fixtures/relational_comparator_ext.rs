// SPDX-License-Identifier: Apache-2.0

//! A test-only reference `bhf.extension.v1` comparator for the relational
//! external-predicate CLI e2e (#61).
//!
//! It links **only `std` + `serde_json`** — no bhf internals — so it also proves
//! the external-comparator contract is implementable against the wire protocol
//! alone. It advertises a single capability, `oracle.evaluate`, whose input is
//! the serialized cross-profile observation bundle the driver sends (a JSON map
//! of `profile -> observation`). Its policy over that bundle:
//!
//! * if any profile's status is `unknown` → `unsupported` (the comparator cannot
//!   decide), which the driver maps to `PolicyUnknown`;
//! * else if the `viewer` profile's effect events reach `administrator-helper`
//!   (a forbidden cross-profile escape) → a `finding`;
//! * else → `ok` (clean / compliant).
//!
//! The bundle it receives is already secret-redacted by the driver, so a resolved
//! secret value can never reach this process.

use std::io::{self, ErrorKind, Read, Write};

use serde_json::{json, Value};

fn main() {
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();

    let hello = match read_frame(&mut stdin).expect("read host hello") {
        Some(frame) => frame,
        None => return,
    };
    let host: Value = serde_json::from_slice(&hello).expect("parse host hello");
    let protocol = host
        .get("protocol")
        .and_then(|p| p.as_str())
        .unwrap_or("bhf.extension.v1")
        .to_string();

    let ext_hello = json!({
        "protocol": protocol,
        "provided_capabilities": ["oracle.evaluate"],
        "formats": ["json"],
        "name": "relational-comparator-ref",
        "version": "0.0.0",
    });
    write_frame(&mut stdout, &serde_json::to_vec(&ext_hello).unwrap()).expect("write ext hello");

    loop {
        let frame = match read_frame(&mut stdin).expect("read request") {
            Some(frame) => frame,
            None => return, // host closed the link: orderly shutdown
        };
        let request: Value = serde_json::from_slice(&frame).expect("parse request");
        let case = request.get("case").cloned().unwrap_or(Value::Null);
        let capability = request
            .get("capability")
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string();

        let response = match capability.as_str() {
            "oracle.evaluate" => {
                let input = decode_input(&request, "input_b64");
                evaluate_bundle(&protocol, &case, &input)
            }
            other => unsupported(&protocol, &case, &format!("{other} is not supported")),
        };
        write_frame(&mut stdout, &serde_json::to_vec(&response).unwrap()).unwrap();
    }
}

fn evaluate_bundle(protocol: &str, case: &Value, input: &[u8]) -> Value {
    let bundle: Value = match serde_json::from_slice(input) {
        Ok(value) => value,
        Err(error) => {
            return unsupported(
                protocol,
                case,
                &format!("cannot decode observation bundle: {error}"),
            );
        }
    };
    let Some(profiles) = bundle.as_object() else {
        return unsupported(protocol, case, "observation bundle was not a JSON object");
    };

    // A profile whose status could not be classified makes the relation
    // undecidable for this comparator.
    if profiles
        .values()
        .any(|obs| obs.get("status").and_then(|s| s.as_str()) == Some("unknown"))
    {
        return unsupported(protocol, case, "undecidable: a profile status is unknown");
    }

    // The forbidden cross-profile escape: viewer reached administrator-helper.
    if let Some(viewer) = profiles.get("viewer") {
        if events_reach(viewer, "administrator-helper") {
            return json!({
                "protocol": protocol,
                "case": case,
                "result": "finding",
                "finding": {
                    "rule": "relational.external/viewer-reached-admin-helper",
                    "classification": "relational_external",
                    "signature_inputs": [
                        "relational.external/viewer-reached-admin-helper",
                        "viewer",
                        "administrator-helper"
                    ],
                    "evidence": [
                        { "key": "profile", "value": "viewer" },
                        { "key": "target", "value": "administrator-helper" },
                        { "key": "reason", "value": "viewer reached a target reserved for administrator" }
                    ]
                }
            });
        }
    }

    // No cross-profile violation observed.
    json!({ "protocol": protocol, "case": case, "result": "ok" })
}

/// Whether `observation`'s effect events include `target`.
fn events_reach(observation: &Value, target: &str) -> bool {
    observation
        .get("events")
        .and_then(|e| e.as_array())
        .map(|events| {
            events
                .iter()
                .any(|e| e.get("target").and_then(|t| t.as_str()) == Some(target))
        })
        .unwrap_or(false)
}

fn unsupported(protocol: &str, case: &Value, detail: &str) -> Value {
    json!({ "protocol": protocol, "case": case, "result": "unsupported", "detail": detail })
}

fn decode_input(request: &Value, field: &str) -> Vec<u8> {
    let b64 = request
        .get("payload")
        .and_then(|p| p.get(field))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    b64_decode(b64).unwrap_or_default()
}

// ---- Framing (re-implemented from the wire contract, no bhf dependency). ----

fn write_frame(out: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    let len = payload.len() as u32;
    out.write_all(&len.to_le_bytes())?;
    out.write_all(payload)?;
    out.flush()
}

fn read_frame(inp: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0u8; 4];
    let mut read = 0;
    while read < 4 {
        match inp.read(&mut header[read..]) {
            Ok(0) if read == 0 => return Ok(None), // clean EOF at boundary
            Ok(0) => return Err(io::Error::from(ErrorKind::UnexpectedEof)),
            Ok(n) => read += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let len = u32::from_le_bytes(header) as usize;
    let mut body = vec![0u8; len];
    inp.read_exact(&mut body)?;
    Ok(Some(body))
}

// ---- Minimal standard base64 decode (RFC 4648), no dependency. -------------

fn b64_decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for block in bytes.chunks(4) {
        let mut vals = [0u8; 4];
        let mut pad = 0;
        for (i, &c) in block.iter().enumerate() {
            if c == b'=' {
                pad += 1;
                vals[i] = 0;
            } else {
                vals[i] = symbol(c)?;
            }
        }
        let n = (u32::from(vals[0]) << 18)
            | (u32::from(vals[1]) << 12)
            | (u32::from(vals[2]) << 6)
            | u32::from(vals[3]);
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

fn symbol(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}
