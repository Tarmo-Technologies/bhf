// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for the HDF-7 session-fuzzing lane (`bhf fuzz
//! --protocol-profile`), driven over a real TCP socket against an in-process toy
//! `OPEN`/`WRITE` service.
//!
//! The toy service mirrors the vertical-slice protocol: `OPEN(path)` issues a
//! fresh per-connection handle (a global counter guarantees every connection —
//! hence every replay — sees a DIFFERENT handle); a `WRITE` is accepted only when
//! it echoes the current handle and passes its CRC-32 integrity gate; and a
//! `WRITE` through a handle whose `OPEN` path escaped the sandbox (`..`) returns
//! the boundary status `0xEF` — a security violation that exits cleanly. The
//! checked-in `toy-open-write.toml` profile drives it.
//!
//! The service verifies each frame's CRC with the SAME `crc32` the encoder uses,
//! so a finding is proof that the structured mutate→repair pass recomputed the
//! length/CRC fields and re-resolved the response-derived handle before send.
//!
//! Network hygiene: an ephemeral port (`127.0.0.1:0`) and a bounded per-request
//! socket timeout on the client keep these tests CI-safe.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use fuzz_engine_builtin::crc32;
use protocol_session::{FieldValue, MessageInstance, Profile, ProtocolModel, SessionTestcase};

/// The checked-in profile that drives the toy service (single source of truth,
/// reused from the `protocol_session` crate).
const TOY_PROFILE: &str = include_str!("../../protocol_session/tests/fixtures/toy-open-write.toml");

/// Distinct per-connection handles across the whole test binary, so every
/// connection — and therefore every replay/minimize drive — captures a handle no
/// other connection used.
static HANDLE_COUNTER: AtomicU32 = AtomicU32::new(0x00AB_CD01);

fn toy_profile_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../protocol_session/tests/fixtures/toy-open-write.toml")
}

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("bhf-session-cli-{tag}-{nanos}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ---------------------------------------------------------------------------
// The in-process toy OPEN/WRITE TCP service
// ---------------------------------------------------------------------------

fn be16(buf: &[u8], at: usize) -> Option<usize> {
    let s = buf.get(at..at + 2)?;
    Some(usize::from(u16::from_be_bytes([s[0], s[1]])))
}

fn be32(buf: &[u8], at: usize) -> Option<u32> {
    let s = buf.get(at..at + 4)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// Process one decoded request frame against this connection's session state.
fn handle_frame(req: &[u8], current_handle: &mut Option<u32>, tainted: &mut bool) -> Vec<u8> {
    let reject = vec![0x01u8];
    let Some(&op) = req.first() else {
        return reject;
    };
    match op {
        // OPEN: op(1) mode(1) len(2) path(len) crc(4)
        1 => {
            let Some(len) = be16(req, 2) else {
                return reject;
            };
            let path_end = 4 + len;
            let crc_end = path_end + 4;
            if req.len() < crc_end {
                return reject;
            }
            if be32(req, path_end).unwrap() != crc32(&req[0..path_end]) {
                // Integrity gate failed: hand back an invalid (zero) handle.
                return vec![0, 0, 0, 0];
            }
            *tainted = req[4..path_end].windows(2).any(|w| w == b"..");
            let handle = HANDLE_COUNTER.fetch_add(1, Ordering::SeqCst);
            *current_handle = Some(handle);
            handle.to_be_bytes().to_vec()
        }
        // WRITE: op(1) handle(4) len(2) data(len) crc(4) [flags]
        2 => {
            let Some(handle) = be32(req, 1) else {
                return reject;
            };
            let Some(len) = be16(req, 5) else {
                return reject;
            };
            let data_end = 7 + len;
            let crc_end = data_end + 4;
            if req.len() < crc_end {
                return reject;
            }
            if be32(req, data_end).unwrap() != crc32(&req[0..data_end]) {
                return reject;
            }
            if *current_handle == Some(handle) {
                if *tainted {
                    vec![0xEF] // boundary violation, clean exit
                } else {
                    vec![0x00] // ok
                }
            } else {
                vec![0x01] // stale / guessed handle rejected
            }
        }
        _ => reject,
    }
}

/// Serve one connection: a length-framed (`[u16 BE len][payload]`) request/reply
/// loop until the peer closes.
fn serve_connection(mut stream: TcpStream) {
    // Match the client: no Nagle, so each request/reply round-trip is immediate.
    stream.set_nodelay(true).ok();
    let mut current_handle: Option<u32> = None;
    let mut tainted = false;
    loop {
        let mut len_buf = [0u8; 2];
        if stream.read_exact(&mut len_buf).is_err() {
            return; // peer closed
        }
        let req_len = usize::from(u16::from_be_bytes(len_buf));
        let mut frame = vec![0u8; req_len];
        if stream.read_exact(&mut frame).is_err() {
            return;
        }
        let reply = handle_frame(&frame, &mut current_handle, &mut tainted);
        let reply_len = (reply.len() as u16).to_be_bytes();
        if stream
            .write_all(&reply_len)
            .and_then(|()| stream.write_all(&reply))
            .and_then(|()| stream.flush())
            .is_err()
        {
            return;
        }
    }
}

/// Start the toy service on an ephemeral localhost port; returns the port. The
/// listener thread (and its per-connection handlers) run until the test process
/// exits.
fn start_toy_service() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind toy service");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    thread::spawn(move || serve_connection(stream));
                }
                Err(_) => break,
            }
        }
    });
    port
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn toy_model() -> ProtocolModel {
    ProtocolModel::from_profile(&Profile::from_toml(TOY_PROFILE).expect("parse")).expect("compile")
}

fn find_session_finding(work_dir: &Path) -> Option<PathBuf> {
    let findings = work_dir.join("results").join("findings");
    for entry in std::fs::read_dir(&findings).ok()?.flatten() {
        let dir = entry.path();
        if dir.join("session.json").is_file() {
            return Some(dir);
        }
    }
    None
}

fn read_session(finding_dir: &Path) -> SessionTestcase {
    let json = std::fs::read_to_string(finding_dir.join("session.json")).expect("session.json");
    SessionTestcase::from_json(&json).expect("parse session.json")
}

// ---------------------------------------------------------------------------
// AC1 / AC2: the campaign reaches the boundary over TCP and records evidence
// ---------------------------------------------------------------------------

#[test]
fn session_campaign_over_tcp_reaches_boundary_and_records_evidence() {
    let port = start_toy_service();
    let work_dir = temp_dir("campaign");
    let profile = toy_profile_path();

    let exit = cli::run_from(vec![
        "bhf".to_owned(),
        "fuzz".to_owned(),
        work_dir.to_str().unwrap().to_owned(),
        "--harness".to_owned(),
        "H-session".to_owned(),
        "--protocol-profile".to_owned(),
        profile.to_str().unwrap().to_owned(),
        "--session-transport".to_owned(),
        format!("tcp:127.0.0.1:{port}"),
        // The valid OPEN,WRITE seed plus the `..` dictionary token means a bounded
        // budget provably field-mutates the path to the boundary.
        "--iterations".to_owned(),
        "1500".to_owned(),
    ]);
    assert_eq!(exit, 0, "session fuzz run should succeed");

    let finding_dir =
        find_session_finding(&work_dir).expect("the campaign emitted a session finding");
    let testcase = read_session(&finding_dir);

    // AC2: >= 2 structured messages, a state path, per-step captured replies, and
    // a response-derived handle binding.
    assert!(testcase.messages.len() >= 2, "AC2: >= 2 messages");
    assert!(!testcase.state_path.is_empty(), "AC2: state path");
    assert_eq!(
        testcase.captured_responses.len(),
        testcase.messages.len(),
        "AC2: a captured reply per step"
    );
    assert!(testcase.captured_responses.iter().all(|r| !r.is_empty()));
    assert!(
        testcase.bindings.contains("OPEN.response.handle"),
        "AC2: response-derived handle binding present"
    );
    assert_eq!(testcase.profile_sha256, toy_model().profile_sha256());

    // The discovered OPEN path escaped the sandbox — the boundary the oracle flags.
    let open = &testcase.messages[0];
    let path = match open.get("path") {
        Some(FieldValue::Bytes { value }) => value.clone(),
        other => panic!("expected a bytes path, got {other:?}"),
    };
    assert!(
        path.windows(2).any(|w| w == b".."),
        "the discovered path escaped the sandbox: {path:?}"
    );

    // The finding carries a stamped finding.json so it indexes into results/.
    assert!(finding_dir.join("finding.json").is_file());

    std::fs::remove_dir_all(&work_dir).ok();
}

// ---------------------------------------------------------------------------
// AC3: replay after a fresh reset (a different handle) still reproduces
// ---------------------------------------------------------------------------

#[test]
fn session_replay_cli_reproduces_on_a_fresh_connection() {
    let port = start_toy_service();
    let work_dir = temp_dir("replay");
    let profile = toy_profile_path();

    let exit = cli::run_from(vec![
        "bhf".to_owned(),
        "fuzz".to_owned(),
        work_dir.to_str().unwrap().to_owned(),
        "--harness".to_owned(),
        "H-session".to_owned(),
        "--protocol-profile".to_owned(),
        profile.to_str().unwrap().to_owned(),
        "--session-transport".to_owned(),
        format!("tcp:127.0.0.1:{port}"),
        "--iterations".to_owned(),
        "1500".to_owned(),
    ]);
    assert_eq!(exit, 0);

    let finding_dir = find_session_finding(&work_dir).expect("a session finding");
    let recorded_handle = read_session(&finding_dir)
        .bindings
        .get("OPEN.response.handle")
        .and_then(protocol_session::BoundValue::as_u64)
        .expect("recorded handle");

    // `bhf replay` re-drives the recorded session on a brand-new connection — the
    // global counter guarantees the service hands it a handle no prior connection
    // used, so a MATCH proves the ref was re-resolved from the FRESH reply.
    let exit = cli::run_from(vec![
        "bhf".to_owned(),
        "replay".to_owned(),
        finding_dir.to_str().unwrap().to_owned(),
    ]);
    assert_eq!(exit, 0, "replay should MATCH on a fresh connection");

    // Sanity: the service really does mint a new handle per connection, so the
    // replay could not have reused the recorded one.
    let next_handle = HANDLE_COUNTER.load(Ordering::SeqCst);
    assert!(
        u64::from(next_handle) > recorded_handle,
        "the handle counter advanced past the recorded handle ({recorded_handle:#x})"
    );

    std::fs::remove_dir_all(&work_dir).ok();
}

// ---------------------------------------------------------------------------
// AC4: minimize preserves the smallest valid, still-reproducing sequence
// ---------------------------------------------------------------------------

#[test]
fn session_minimize_cli_shrinks_padded_sequence() {
    let port = start_toy_service();
    let work_dir = temp_dir("minimize");
    let finding_dir = work_dir
        .join("results")
        .join("findings")
        .join("F-0000-session");
    std::fs::create_dir_all(&finding_dir).unwrap();

    let model = toy_model();
    // A padded 4-message session: two OPEN/WRITE pairs; only one pair is needed.
    let mut open_a = MessageInstance::from_seed(model.message("OPEN").unwrap());
    open_a.set(
        "path",
        FieldValue::Bytes {
            value: b"../escaped-a".to_vec(),
        },
    );
    let mut open_b = MessageInstance::from_seed(model.message("OPEN").unwrap());
    open_b.set(
        "path",
        FieldValue::Bytes {
            value: b"../escaped-b".to_vec(),
        },
    );
    let write = MessageInstance::from_seed(model.message("WRITE").unwrap());
    let padded = SessionTestcase::from_messages(
        model.profile_sha256(),
        vec![open_a, write.clone(), open_b, write],
    );
    std::fs::write(
        finding_dir.join("session.json"),
        padded.to_json().unwrap().as_bytes(),
    )
    .unwrap();

    // The self-contained replay/minimize sidecar: the profile inline + the live
    // transport spec.
    let meta = serde_json::json!({
        "schema": "bhf.session-artifact.v1",
        "profile_sha256": model.profile_sha256(),
        "profile_toml": TOY_PROFILE,
        "transport": format!("tcp:127.0.0.1:{port}"),
        "transport_kind": "tcp",
        "reset": "reconnect",
        "reset_fidelity": "tcp;reset=reconnect",
        "rule_id": "HDF7-PATHTRAV",
        "oracle": "path-traversal-write",
    });
    std::fs::write(
        finding_dir.join("session_meta.json"),
        serde_json::to_vec_pretty(&meta).unwrap(),
    )
    .unwrap();
    // A primary testcase kept in step, so the minimizer can update it too.
    std::fs::write(
        finding_dir.join("testcase.bin"),
        padded.to_json().unwrap().as_bytes(),
    )
    .unwrap();

    let exit = cli::run_from(vec![
        "bhf".to_owned(),
        "minimize".to_owned(),
        finding_dir.to_str().unwrap().to_owned(),
    ]);
    assert_eq!(exit, 0, "session minimize should succeed");

    // The minimized session is the smallest valid OPEN,WRITE sequence and still
    // reproduces (its dynamic handle binding re-resolved on a fresh connection).
    let minimized = read_session(&finding_dir);
    assert_eq!(
        minimized.message_names(),
        vec!["OPEN", "WRITE"],
        "minimized to the smallest valid sequence"
    );
    assert!(
        minimized.bindings.contains("OPEN.response.handle"),
        "the dynamic handle binding is maintained"
    );
    // The minimized OPEN path still escapes the sandbox (the finding is preserved).
    let path = match minimized.messages[0].get("path") {
        Some(FieldValue::Bytes { value }) => value.clone(),
        other => panic!("expected a bytes path, got {other:?}"),
    };
    assert!(
        path.windows(2).any(|w| w == b".."),
        "minimized path still escapes: {path:?}"
    );

    // Re-running `bhf replay` on the minimized artifact still MATCHes.
    let exit = cli::run_from(vec![
        "bhf".to_owned(),
        "replay".to_owned(),
        finding_dir.to_str().unwrap().to_owned(),
    ]);
    assert_eq!(exit, 0, "minimized session still reproduces");

    std::fs::remove_dir_all(&work_dir).ok();
}

// ---------------------------------------------------------------------------
// Opt-in regression: the default fuzz path is untouched without --protocol-profile
// ---------------------------------------------------------------------------

#[test]
fn malformed_protocol_profile_exits_with_a_diagnostic() {
    let work_dir = temp_dir("malformed");
    let bad_profile = work_dir.join("bad.toml");
    std::fs::write(&bad_profile, b"schema = \"bhf.protocol.v99\"\n").unwrap();

    // A malformed/unknown-schema profile is a descriptive non-zero exit, never a
    // panic, and never routes into the default host loop.
    let exit = cli::run_from(vec![
        "bhf".to_owned(),
        "fuzz".to_owned(),
        work_dir.to_str().unwrap().to_owned(),
        "--harness".to_owned(),
        "H-session".to_owned(),
        "--protocol-profile".to_owned(),
        bad_profile.to_str().unwrap().to_owned(),
        "--session-transport".to_owned(),
        "tcp:127.0.0.1:1".to_owned(),
    ]);
    assert_ne!(exit, 0, "a malformed profile must fail");

    std::fs::remove_dir_all(&work_dir).ok();
}
