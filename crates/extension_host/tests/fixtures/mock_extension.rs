// SPDX-License-Identifier: Apache-2.0

//! A test-only mock `bhf.extension.v1` extension.
//!
//! This binary deliberately links **only `std` + `serde_json`** — no
//! `extension_host` internals — so it doubles as living proof that the protocol
//! is a portable SDK that can be implemented against the wire contract alone. It
//! selects a behaviour by `--mode`, letting the subprocess integration tests
//! exercise the happy path and every fault path (timeout, crash, oversize,
//! malformed, unsupported, mismatched case identity, and an explicit
//! extension-reported infrastructure error).
//!
//! It is NOT built by `cargo build -p bhf`.

use std::env;
use std::fs;
use std::io::{self, ErrorKind, Read, Write};
use std::process::exit;
use std::time::Duration;

fn main() {
    let mode = parse_mode();

    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();

    // Handshake: read the host hello, reply with our hello. We always handshake
    // successfully; misbehaviour (if any) happens per evaluate.
    let hello = match read_frame(&mut stdin).expect("read host hello") {
        Some(frame) => frame,
        None => return, // host closed before handshake
    };
    let host: serde_json::Value = serde_json::from_slice(&hello).expect("parse host hello");
    let protocol = host
        .get("protocol")
        .and_then(|p| p.as_str())
        .unwrap_or("bhf.extension.v1")
        .to_string();

    let ext_hello = serde_json::json!({
        "protocol": protocol,
        "provided_capabilities": ["oracle.evaluate"],
        "formats": ["json"],
        "name": "bhf_mock_extension",
        "version": "0.0.0",
    });
    write_frame(&mut stdout, &serde_json::to_vec(&ext_hello).unwrap()).expect("write ext hello");

    // Request loop.
    loop {
        let frame = match read_frame(&mut stdin).expect("read request") {
            Some(frame) => frame,
            None => return, // host closed the link: orderly shutdown
        };
        let request: serde_json::Value = serde_json::from_slice(&frame).expect("parse request");
        let case = request
            .get("case")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let input = decode_input(&request);

        match mode.as_str() {
            "well-behaved" => {
                let response = evaluate(&protocol, &case, &input, false);
                write_frame(&mut stdout, &serde_json::to_vec(&response).unwrap()).unwrap();
            }
            "tamper-case" => {
                // Echo a DIFFERENT case identity to prove the host rejects it.
                let mut tampered = case.clone();
                if let Some(obj) = tampered.as_object_mut() {
                    obj.insert(
                        "worker".to_string(),
                        serde_json::Value::String("EVIL".to_string()),
                    );
                }
                let response = evaluate(&protocol, &tampered, &input, false);
                write_frame(&mut stdout, &serde_json::to_vec(&response).unwrap()).unwrap();
            }
            "unsupported" => {
                let response = serde_json::json!({
                    "protocol": protocol,
                    "case": case,
                    "result": "unsupported",
                    "detail": "oracle.evaluate not supported for this input",
                });
                write_frame(&mut stdout, &serde_json::to_vec(&response).unwrap()).unwrap();
            }
            "infra-error" => {
                let response = serde_json::json!({
                    "protocol": protocol,
                    "case": case,
                    "result": "infrastructure_error",
                    "detail": "internal oracle failure",
                });
                write_frame(&mut stdout, &serde_json::to_vec(&response).unwrap()).unwrap();
            }
            "malformed" => {
                // A well-framed but non-JSON body.
                write_frame(&mut stdout, b"this is definitely not a json envelope").unwrap();
            }
            "oversize" => {
                // Declare an enormous frame; the host rejects it at the header,
                // before allocating, and kills us.
                stdout.write_all(&50_000_000u32.to_le_bytes()).unwrap();
                stdout.write_all(b"partial").unwrap();
                stdout.flush().unwrap();
                exit(0);
            }
            "hang" => {
                // Never respond; the host's per-call deadline fires and kills us.
                std::thread::sleep(Duration::from_secs(120));
            }
            "crash" => {
                // Exit without responding; the host sees the pipe close.
                exit(101);
            }
            "crash-once" => {
                if crashed_before() {
                    let response = evaluate(&protocol, &case, &input, false);
                    write_frame(&mut stdout, &serde_json::to_vec(&response).unwrap()).unwrap();
                } else {
                    mark_crashed();
                    exit(101);
                }
            }
            other => {
                eprintln!("bhf_mock_extension: unknown --mode {other:?}");
                exit(2);
            }
        }
    }
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

fn decode_input(request: &serde_json::Value) -> Vec<u8> {
    let b64 = request
        .get("payload")
        .and_then(|p| p.get("input_b64"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    b64_decode(b64).unwrap_or_default()
}

/// The toy semantic oracle, shared in spirit with the Python reference
/// extension: a (clean-exiting) target that "writes outside its sandbox root" —
/// i.e. a path with a `..` component or an absolute path — is a finding.
fn evaluate(
    protocol: &str,
    case: &serde_json::Value,
    input: &[u8],
    _reset: bool,
) -> serde_json::Value {
    let path = String::from_utf8_lossy(input).to_string();
    let escapes = path.starts_with('/') || path.split('/').any(|segment| segment == "..");
    if escapes {
        serde_json::json!({
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
        serde_json::json!({
            "protocol": protocol,
            "case": case,
            "result": "ok",
        })
    }
}

fn state_file() -> Option<String> {
    env::var("MOCK_STATE_FILE").ok()
}

fn crashed_before() -> bool {
    match state_file() {
        Some(path) => fs::read_to_string(path)
            .map(|s| s.trim() == "crashed")
            .unwrap_or(false),
        None => false,
    }
}

fn mark_crashed() {
    if let Some(path) = state_file() {
        let _ = fs::write(path, "crashed");
    }
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

// ---- Minimal standard base64 decode (RFC 4648), no dependency. ----

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
