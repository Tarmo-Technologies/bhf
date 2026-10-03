// SPDX-License-Identifier: Apache-2.0

//! A test-only mock `bhf.extension.v1` extension.
//!
//! This binary deliberately links **only `std` + `serde_json`** — no
//! `extension_host` internals — so it doubles as living proof that the protocol
//! is a portable SDK that can be implemented against the wire contract alone. It
//! implements the full capability surface over a toy framed protocol
//! (`[u16 BE length][payload][u32 BE CRC-32]`, `OPEN(path) -> handle`,
//! `WRITE(handle, data)`): `oracle.evaluate`, `codec.decode`/`encode`/`repair`,
//! `mutator.mutate`, `scenario.next`/`observe-response`, and
//! `lifecycle.setup`/`reset`/`teardown`.
//!
//! A `--mode` selects a global misbehaviour so the subprocess integration tests
//! can exercise every bounded fault path (timeout, crash, oversize, malformed,
//! unsupported, mismatched case identity, explicit infrastructure error).
//!
//! It is NOT built by `cargo build -p bhf`.

use std::env;
use std::fs;
use std::io::{self, ErrorKind, Read, Write};
use std::process::exit;
use std::time::Duration;

use serde_json::{json, Value};

/// Per-session scenario/lifecycle state (one process == one session).
#[derive(Default)]
struct State {
    /// The sandbox root set by `lifecycle.reset`.
    root: Option<String>,
    /// The OPEN path captured from the session seed.
    path: Vec<u8>,
    /// The handle captured from the OPEN response.
    handle: Option<String>,
}

fn main() {
    let mode = parse_mode();

    // `grandchild-sleeper`: a detached grandchild spawned by `grandchild-holds-stdout`.
    // It inherited the direct child's stdout (fd 1) and keeps that pipe write-end
    // open after the direct child exits, so the host's frame reader sees no EOF. It
    // holds the pipe well past the host's bounded reader-join deadline, then
    // self-terminates so a crashed/failing test cannot leak it forever. It records
    // its own pid (so the test can reap it) and returns BEFORE `log_pid`, so it is
    // never miscounted as a host-spawned extension child.
    if mode == "grandchild-sleeper" {
        if let Ok(path) = env::var("MOCK_GRANDCHILD_PID_FILE") {
            let _ = fs::write(path, std::process::id().to_string());
        }
        std::thread::sleep(Duration::from_secs(120));
        return;
    }

    // Record this child's PID (every spawned child, including a respawn that fails
    // its re-handshake) so a test can assert no child is leaked/left unreaped.
    log_pid();

    // `grandchild-holds-stdout`: before touching the wire, double-fork a grandchild
    // that inherits this child's stdout (fd 1). After this direct child exits (on
    // its first request, below), the grandchild keeps the stdout pipe open, so the
    // host's frame-reader thread blocks on `read` with no EOF — the pathological
    // case the host's bounded reader-join must survive without hanging teardown.
    // The direct child must still be reaped.
    if mode == "grandchild-holds-stdout" {
        spawn_stdout_holding_grandchild();
    }

    // `crash-then-unhandshake`: the FIRST child handshakes then crashes on its
    // first request (marking a cross-process marker); every RESPAWNED child sees
    // the marker and exits BEFORE emitting its hello, so the host's restart-time
    // re-handshake fails persistently. This drives the terminal
    // re-handshake-failure path (a bounded infrastructure result), distinct from
    // `crash-once`, where the respawn recovers.
    if mode == "crash-then-unhandshake" && crashed_before() {
        exit(7);
    }

    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();

    let hello = match read_frame(&mut stdin).expect("read host hello") {
        Some(frame) => frame,
        None => return, // host closed before handshake
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
        "name": "bhf_mock_extension",
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

        // Global fault modes apply to every request regardless of capability.
        match mode.as_str() {
            "tamper-case" => {
                let mut tampered = case.clone();
                if let Some(obj) = tampered.as_object_mut() {
                    obj.insert("worker".to_string(), Value::String("EVIL".to_string()));
                }
                let response = handle(&protocol, &tampered, &capability, &request, &mut state);
                write_frame(&mut stdout, &serde_json::to_vec(&response).unwrap()).unwrap();
                continue;
            }
            "unsupported" => {
                reply(&mut stdout, unsupported(&protocol, &case, &capability));
                continue;
            }
            "infra-error" => {
                reply(
                    &mut stdout,
                    json!({
                        "protocol": protocol,
                        "case": case,
                        "result": "infrastructure_error",
                        "detail": "internal oracle failure",
                    }),
                );
                continue;
            }
            "malformed" => {
                write_frame(&mut stdout, b"this is definitely not a json envelope").unwrap();
                continue;
            }
            "oversize" => {
                stdout.write_all(&50_000_000u32.to_le_bytes()).unwrap();
                stdout.write_all(b"partial").unwrap();
                stdout.flush().unwrap();
                exit(0);
            }
            "hang" => {
                std::thread::sleep(Duration::from_secs(120));
            }
            "crash" => {
                exit(101);
            }
            "grandchild-holds-stdout" => {
                // Vanish on the first request WITHOUT responding, after the
                // handshake already succeeded. The grandchild spawned at startup
                // keeps stdout open, so the host's reader never sees EOF; the host
                // must bound its reader-join on teardown and still reap this direct
                // child.
                exit(0);
            }
            "crash-once" => {
                if crashed_before() {
                    let response = handle(&protocol, &case, &capability, &request, &mut state);
                    write_frame(&mut stdout, &serde_json::to_vec(&response).unwrap()).unwrap();
                } else {
                    mark_crashed();
                    exit(101);
                }
                continue;
            }
            "crash-then-unhandshake" => {
                // The first child reaches a request, marks the marker, then crashes.
                // Every respawn detects the marker and fails its re-handshake (above).
                mark_crashed();
                exit(101);
            }
            // "well-behaved" | "no-cap" fall through to the real handlers.
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

/// Dispatch a well-behaved request by capability.
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

// ---- oracle.evaluate ------------------------------------------------------

/// The toy semantic oracle: a path with a `..` component or an absolute path is a
/// finding (a clean-exiting target would write outside its sandbox root).
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

// ---- codec.* --------------------------------------------------------------

fn codec_decode(protocol: &str, case: &Value, frame: &[u8]) -> Value {
    match parse_frame(frame) {
        Some((declared_len, payload, crc)) => {
            let crc_valid = declared_len as usize == payload.len() && crc == crc32(&payload);
            let decoded = decode_payload(&payload, crc_valid);
            ok(protocol, case, Some(json!({ "decoded": decoded })))
        }
        None => reject(protocol, case, "frame too short to decode"),
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

fn codec_repair(protocol: &str, case: &Value, frame: &[u8]) -> Value {
    if frame.len() < 6 {
        return reject(protocol, case, "frame too short to repair");
    }
    // Recompute the computed fields from the actual payload region.
    let payload = frame[2..frame.len() - 4].to_vec();
    let repaired = build_frame(&payload);
    ok(
        protocol,
        case,
        Some(json!({ "output_b64": b64_encode(&repaired) })),
    )
}

// ---- mutator.mutate -------------------------------------------------------

/// Structure-aware mutation: grow the data region deterministically from `seed`,
/// leaving the (now-stale) length prefix and CRC suffix in place so the frame is
/// malformed until `codec.repair` fixes it — but the opcode/handle survive.
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
    mutated_payload.push((seed & 0xff) as u8); // append one seed-derived byte

    let mut out = Vec::with_capacity(frame.len() + 1);
    out.extend_from_slice(old_len); // STALE length prefix
    out.extend_from_slice(&mutated_payload);
    out.extend_from_slice(old_crc); // STALE CRC suffix
    ok(
        protocol,
        case,
        Some(json!({ "output_b64": b64_encode(&out) })),
    )
}

// ---- scenario.* -----------------------------------------------------------

fn scenario_next(protocol: &str, case: &Value, request: &Value, state: &mut State) -> Value {
    let step = request
        .get("payload")
        .and_then(|p| p.get("step"))
        .and_then(|s| s.as_u64())
        .unwrap_or(0);
    if step == 0 {
        // The session seed is the OPEN path.
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
        // WRITE binds the handle captured from the OPEN response.
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

// ---- lifecycle.* ----------------------------------------------------------

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
        // A fresh root between cases drops any captured handle/path.
        state.handle = None;
        state.path.clear();
    }
    if let Some(root) = root {
        state.root = Some(root);
    }
    ok(protocol, case, None)
}

// ---- toy framed protocol: [u16 BE len][payload][u32 BE crc32(payload)] -----

fn build_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 6);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(&crc32(payload).to_be_bytes());
    out
}

/// Parse a frame into `(declared_len, payload, declared_crc)`.
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

/// Double-fork a detached grandchild (a re-exec of this mock in
/// `grandchild-sleeper` mode) that inherits this process's stdout (fd 1) and so
/// keeps the host's read-pipe write-end open after this process exits. The child
/// handle is intentionally leaked (never waited on): the grandchild is not the
/// host's child, and it self-terminates after a bound. `stdin`/`stderr` are not
/// inherited so the grandchild holds ONLY the stdout pipe open.
fn spawn_stdout_holding_grandchild() {
    use std::process::{Command, Stdio};
    let exe = env::current_exe().expect("current_exe");
    // Intentionally detached: we must NOT wait on the grandchild — this process
    // exits immediately after, and the grandchild outlives it (that is the whole
    // point: it keeps the stdout pipe open). It is reparented to init and
    // self-terminates after a bound, so it never becomes a zombie of this process.
    #[allow(clippy::zombie_processes)]
    let _child = Command::new(exe)
        .arg("--mode")
        .arg("grandchild-sleeper")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit()) // the dup of fd 1 that keeps the pipe open
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn stdout-holding grandchild");
    // `MOCK_GRANDCHILD_PID_FILE` is inherited from this process's environment, so
    // the grandchild records its own pid there for the test to reap.
}

/// Append this process's PID to `MOCK_PID_LOG` (if set), one per line, so a test
/// can enumerate every child the host spawned and assert none was leaked.
fn log_pid() {
    if let Ok(path) = env::var("MOCK_PID_LOG") {
        if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "{}", std::process::id());
        }
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

// ---- CRC-32/ISO-HDLC (zlib), matching Python's zlib.crc32. ----------------

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
