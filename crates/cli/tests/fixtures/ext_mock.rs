// SPDX-License-Identifier: Apache-2.0

//! A test-only mock `bhf.extension.v1` extension for the CLI integration tests.
//!
//! This binary links **only `std` + `serde_json`** — no bhf internals — so it
//! also proves the protocol is a portable SDK implementable against the wire
//! contract alone. It implements the full capability surface over a toy framed
//! protocol (`[u16 BE length][payload][u32 BE CRC-32]`, `OPEN(path) -> handle`,
//! `WRITE(handle, data)`): `oracle.evaluate`, `codec.decode`/`encode`/`repair`,
//! `mutator.mutate`, `scenario.next`/`observe-response`, and
//! `lifecycle.setup`/`reset`/`teardown`.
//!
//! A `--mode` selects a global misbehaviour so the CLI tests can drive `bhf
//! extension validate/evaluate/session` and `bhf fuzz --extension` through the
//! happy path and every bounded fault (timeout, crash, malformed response,
//! unsupported capability, mismatched case identity).

use std::env;
use std::io::{self, ErrorKind, Read, Write};
use std::process::exit;
use std::time::Duration;

use serde_json::{json, Value};

#[derive(Default)]
struct State {
    root: Option<String>,
    path: Vec<u8>,
    handle: Option<String>,
}

fn main() {
    let mode = parse_mode();

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

    // `no-cap` advertises only a capability the host does not require, so the
    // required `oracle.evaluate` fails negotiation up front. Otherwise advertise
    // the full surface (the host narrows it to what it asked for).
    let provided: Vec<&str> = if mode == "no-cap" {
        vec!["codec.decode"]
    } else {
        vec![
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
    };
    let ext_hello = json!({
        "protocol": protocol,
        "provided_capabilities": provided,
        "formats": ["json"],
        "name": "bhf_ext_mock",
        "version": "0.0.0",
    });
    write_frame(&mut stdout, &serde_json::to_vec(&ext_hello).unwrap()).expect("write ext hello");

    let mut state = State::default();

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

        match mode.as_str() {
            "tamper-case" => {
                let mut tampered = case.clone();
                if let Some(obj) = tampered.as_object_mut() {
                    obj.insert("worker".to_string(), Value::String("EVIL".to_string()));
                }
                let response = handle(&protocol, &tampered, &capability, &request, &mut state);
                write_frame(&mut stdout, &serde_json::to_vec(&response).unwrap()).unwrap();
            }
            "unsupported" => {
                reply(&mut stdout, unsupported(&protocol, &case, &capability));
            }
            "malformed" => {
                write_frame(&mut stdout, b"this is definitely not a json envelope").unwrap();
            }
            "hang" => {
                std::thread::sleep(Duration::from_secs(120));
            }
            "crash" => {
                exit(101);
            }
            _ => {
                let response = handle(&protocol, &case, &capability, &request, &mut state);
                write_frame(&mut stdout, &serde_json::to_vec(&response).unwrap()).unwrap();
            }
        }
    }
}

fn reply(out: &mut impl Write, response: Value) {
    write_frame(out, &serde_json::to_vec(&response).unwrap()).unwrap();
}

fn handle(
    protocol: &str,
    case: &Value,
    capability: &str,
    request: &Value,
    state: &mut State,
) -> Value {
    match capability {
        "oracle.evaluate" => oracle_evaluate(protocol, case, &decode_input(request, "input_b64")),
        "codec.decode" => codec_decode(protocol, case, &decode_input(request, "input_b64")),
        "codec.encode" => codec_encode(protocol, case, request),
        "codec.repair" => codec_repair(protocol, case, &decode_input(request, "input_b64")),
        "mutator.mutate" => mutator_mutate(protocol, case, request),
        "scenario.next" => scenario_next(protocol, case, request, state),
        "scenario.observe-response" => scenario_observe(protocol, case, request, state),
        "lifecycle.setup" => lifecycle(protocol, case, request, state, false),
        "lifecycle.reset" => lifecycle(protocol, case, request, state, true),
        "lifecycle.teardown" => {
            *state = State::default();
            ok(protocol, case, None)
        }
        other => unsupported(protocol, case, other),
    }
}

fn oracle_evaluate(protocol: &str, case: &Value, input: &[u8]) -> Value {
    let path = String::from_utf8_lossy(input).to_string();
    if escapes(&path) {
        json!({
            "protocol": protocol,
            "case": case,
            "result": "finding",
            "finding": {
                "rule": "oracle.path-escape",
                "classification": "extension_oracle",
                "signature_inputs": ["oracle.path-escape", path],
                "evidence": [
                    { "key": "path", "value": path },
                    { "key": "reason", "value": "escapes sandbox root" }
                ],
                "min_predicate": "path-contains-dotdot"
            }
        })
    } else {
        ok(protocol, case, None)
    }
}

fn escapes(path: &str) -> bool {
    path.starts_with('/') || path.split('/').any(|seg| seg == "..")
}

fn codec_decode(protocol: &str, case: &Value, frame: &[u8]) -> Value {
    match parse_frame(frame) {
        Some((declared_len, payload, crc)) if is_known_op(&payload) => {
            let crc_valid = declared_len as usize == payload.len() && crc == crc32(&payload);
            ok(
                protocol,
                case,
                Some(json!({ "decoded": decode_payload(&payload, crc_valid) })),
            )
        }
        _ => reject(protocol, case, "not a recognized frame"),
    }
}

fn codec_encode(protocol: &str, case: &Value, request: &Value) -> Value {
    let decoded = request.get("payload").and_then(|p| p.get("decoded"));
    match decoded.and_then(encode_payload) {
        Some(payload) => {
            let frame = build_frame(&payload);
            ok(
                protocol,
                case,
                Some(json!({ "output_b64": b64_encode(&frame) })),
            )
        }
        None => reject(protocol, case, "undecodable structured value"),
    }
}

/// Repair recomputes length+CRC, but only for a frame recognized as this
/// extension's format (so a non-frame input is `reject`ed and left untouched).
fn codec_repair(protocol: &str, case: &Value, frame: &[u8]) -> Value {
    match parse_frame(frame) {
        Some((_, payload, _)) if is_known_op(&payload) => {
            let repaired = build_frame(&payload);
            ok(
                protocol,
                case,
                Some(json!({ "output_b64": b64_encode(&repaired) })),
            )
        }
        _ => reject(protocol, case, "not a recognized frame to repair"),
    }
}

fn mutator_mutate(protocol: &str, case: &Value, request: &Value) -> Value {
    let frame = decode_input(request, "input_b64");
    let seed = request
        .get("payload")
        .and_then(|p| p.get("seed"))
        .and_then(|s| s.as_u64())
        .unwrap_or(0);
    if frame.len() < 6 {
        return reject(protocol, case, "frame too short to mutate");
    }
    let old_len = &frame[0..2];
    let payload = &frame[2..frame.len() - 4];
    let old_crc = &frame[frame.len() - 4..];
    let mut mutated_payload = payload.to_vec();
    mutated_payload.push((seed & 0xff) as u8);
    let mut out = Vec::with_capacity(frame.len() + 1);
    out.extend_from_slice(old_len);
    out.extend_from_slice(&mutated_payload);
    out.extend_from_slice(old_crc);
    ok(
        protocol,
        case,
        Some(json!({ "output_b64": b64_encode(&out) })),
    )
}

fn scenario_next(protocol: &str, case: &Value, request: &Value, state: &mut State) -> Value {
    let step = request
        .get("payload")
        .and_then(|p| p.get("step"))
        .and_then(|s| s.as_u64())
        .unwrap_or(0);
    if step == 0 {
        state.path = decode_input(request, "seed_b64");
        let mut payload = b"OPEN ".to_vec();
        payload.extend_from_slice(&state.path);
        let frame = build_frame(&payload);
        ok(
            protocol,
            case,
            Some(json!({ "message_b64": b64_encode(&frame), "label": "OPEN" })),
        )
    } else if step == 1 {
        let handle = state.handle.clone().unwrap_or_else(|| "0".to_string());
        let mut payload = format!("WRITE {handle} ").into_bytes();
        payload.extend_from_slice(b"data:");
        payload.extend_from_slice(&state.path);
        let frame = build_frame(&payload);
        ok(
            protocol,
            case,
            Some(json!({ "message_b64": b64_encode(&frame), "label": "WRITE" })),
        )
    } else {
        ok(protocol, case, Some(json!({ "done": true })))
    }
}

fn scenario_observe(protocol: &str, case: &Value, request: &Value, state: &mut State) -> Value {
    let response = decode_input(request, "response_b64");
    if let Some((_, payload, _)) = parse_frame(&response) {
        let text = String::from_utf8_lossy(&payload);
        if let Some(handle) = text.strip_prefix("OPENOK ") {
            state.handle = Some(handle.trim().to_string());
        }
    }
    ok(protocol, case, None)
}

fn lifecycle(
    protocol: &str,
    case: &Value,
    request: &Value,
    state: &mut State,
    reset: bool,
) -> Value {
    let root = request
        .get("payload")
        .and_then(|p| p.get("root"))
        .and_then(|r| r.as_str())
        .map(|s| s.to_string());
    if reset {
        state.handle = None;
        state.path.clear();
    }
    if let Some(root) = root {
        state.root = Some(root);
    }
    ok(protocol, case, None)
}

// ---- toy protocol: [u16 BE len][payload][u32 BE crc32(payload)] -----------

fn build_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 6);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(&crc32(payload).to_be_bytes());
    out
}

fn parse_frame(frame: &[u8]) -> Option<(u16, Vec<u8>, u32)> {
    if frame.len() < 6 {
        return None;
    }
    let declared_len = u16::from_be_bytes([frame[0], frame[1]]);
    let payload = frame[2..frame.len() - 4].to_vec();
    let crc_bytes = &frame[frame.len() - 4..];
    let crc = u32::from_be_bytes([crc_bytes[0], crc_bytes[1], crc_bytes[2], crc_bytes[3]]);
    Some((declared_len, payload, crc))
}

fn is_known_op(payload: &[u8]) -> bool {
    let text = String::from_utf8_lossy(payload);
    let op = text.split(' ').next().unwrap_or("");
    matches!(op, "OPEN" | "WRITE" | "OPENOK" | "WRITEOK")
}

fn decode_payload(payload: &[u8], crc_valid: bool) -> Value {
    let text = String::from_utf8_lossy(payload).to_string();
    let mut parts = text.splitn(3, ' ');
    let op = parts.next().unwrap_or("").to_string();
    match op.as_str() {
        "OPEN" => json!({
            "op": "OPEN",
            "path": parts.next().unwrap_or(""),
            "length": payload.len(),
            "crc_valid": crc_valid,
        }),
        "WRITE" => json!({
            "op": "WRITE",
            "handle": parts.next().unwrap_or(""),
            "data": parts.next().unwrap_or(""),
            "length": payload.len(),
            "crc_valid": crc_valid,
        }),
        _ => json!({ "op": op, "length": payload.len(), "crc_valid": crc_valid }),
    }
}

fn encode_payload(decoded: &Value) -> Option<Vec<u8>> {
    let op = decoded.get("op").and_then(|o| o.as_str())?;
    match op {
        "OPEN" => {
            let path = decoded.get("path").and_then(|p| p.as_str()).unwrap_or("");
            Some(format!("OPEN {path}").into_bytes())
        }
        "WRITE" => {
            let handle = decoded.get("handle").and_then(|h| h.as_str()).unwrap_or("");
            let data = decoded.get("data").and_then(|d| d.as_str()).unwrap_or("");
            Some(format!("WRITE {handle} {data}").into_bytes())
        }
        _ => None,
    }
}

// ---- envelope helpers -----------------------------------------------------

fn ok(protocol: &str, case: &Value, value: Option<Value>) -> Value {
    match value {
        Some(value) => {
            json!({ "protocol": protocol, "case": case, "result": "ok", "value": value })
        }
        None => json!({ "protocol": protocol, "case": case, "result": "ok" }),
    }
}

fn reject(protocol: &str, case: &Value, detail: &str) -> Value {
    json!({ "protocol": protocol, "case": case, "result": "reject", "detail": detail })
}

fn unsupported(protocol: &str, case: &Value, capability: &str) -> Value {
    json!({
        "protocol": protocol,
        "case": case,
        "result": "unsupported",
        "detail": format!("{capability} is not supported"),
    })
}

fn parse_mode() -> String {
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--mode" {
            return args.next().unwrap_or_else(|| "well-behaved".to_string());
        }
        if let Some(value) = arg.strip_prefix("--mode=") {
            return value.to_string();
        }
    }
    "well-behaved".to_string()
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

// ---- CRC-32/ISO-HDLC (zlib). ----------------------------------------------

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

// ---- Minimal standard base64 (RFC 4648), no dependency. -------------------

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 0b11) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(((b1 & 0b1111) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(b2 & 0b111111) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

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
