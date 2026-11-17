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

use fuzz_engine_builtin::crc32;
use protocol_session::{FieldValue, MessageInstance, Profile, ProtocolModel, SessionTestcase};

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

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

fn temp_dir(tag: &str) -> TestDir {
    TestDir::new(&format!("session-cli-{tag}"))
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

/// The toy service over UDP: each datagram is one request, unframed, and the
/// reply is one datagram. A client address (its source port) is a session,
/// so a new socket starts with no handle.
fn start_udp_toy_service() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp toy service");
    let port = socket.local_addr().unwrap().port();
    thread::spawn(move || {
        let mut sessions: std::collections::HashMap<std::net::SocketAddr, (Option<u32>, bool)> =
            std::collections::HashMap::new();
        let mut buf = [0u8; 65_536];
        while let Ok((n, peer)) = socket.recv_from(&mut buf) {
            let (handle, tainted) = sessions.entry(peer).or_default();
            let reply = handle_frame(&buf[..n], handle, tainted);
            let _ = socket.send_to(&reply, peer);
        }
    });
    port
}

/// The toy profile with no `[framing]`: raw, so each message is its datagram.
fn raw_toy_profile(dir: &Path) -> PathBuf {
    let framing = "[framing]\nkind = \"length_prefix\"\nwidth = 2\nendian = \"big\"\n";
    assert!(
        TOY_PROFILE.contains(framing),
        "the toy profile's framing table"
    );
    let path = dir.join("toy-open-write-raw.toml");
    std::fs::write(&path, TOY_PROFILE.replace(framing, "")).unwrap();
    path
}

/// The toy service, except that the WRITE through an escaped path, which the
/// toy service answers with the boundary status, kills the session instead:
/// the connection closes with no reply, as a service that crashes on the
/// request does. It goes on accepting new connections.
fn start_aborting_toy_service() -> u16 {
    fn serve(mut stream: TcpStream) {
        stream.set_nodelay(true).ok();
        let mut current_handle: Option<u32> = None;
        let mut tainted = false;
        loop {
            let mut len_buf = [0u8; 2];
            if stream.read_exact(&mut len_buf).is_err() {
                return;
            }
            let mut frame = vec![0u8; usize::from(u16::from_be_bytes(len_buf))];
            if stream.read_exact(&mut frame).is_err() {
                return;
            }
            let reply = handle_frame(&frame, &mut current_handle, &mut tainted);
            if reply == [0xEF] {
                let _ = stream.shutdown(std::net::Shutdown::Both);
                return;
            }
            let reply_len = (reply.len() as u16).to_be_bytes();
            if stream
                .write_all(&reply_len)
                .and_then(|()| stream.write_all(&reply))
                .is_err()
            {
                return;
            }
        }
    }
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind aborting toy service");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || serve(stream));
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

/// #258: the same campaign over UDP. A WRITE is answered only in the
/// `opened` state, through the handle its session's OPEN captured, so the
/// finding proves the campaign reached the second state over datagrams.
#[test]
fn session_campaign_over_udp_reaches_the_second_state_and_the_oracle_fires() {
    let port = start_udp_toy_service();
    let work_dir = temp_dir("udp-campaign");
    std::fs::create_dir_all(&work_dir).unwrap();
    let profile = raw_toy_profile(&work_dir);

    let exit = cli::run_from(vec![
        "bhf".to_owned(),
        "fuzz".to_owned(),
        work_dir.to_str().unwrap().to_owned(),
        "--harness".to_owned(),
        "H-session-udp".to_owned(),
        "--protocol-profile".to_owned(),
        profile.to_str().unwrap().to_owned(),
        "--session-transport".to_owned(),
        format!("udp:127.0.0.1:{port}"),
        "--session-reply-timeout".to_owned(),
        "2s".to_owned(),
        "--iterations".to_owned(),
        "1500".to_owned(),
    ]);
    assert_eq!(exit, 0, "session fuzz run over udp should succeed");

    let finding_dir =
        find_session_finding(&work_dir).expect("the campaign emitted a session finding");
    let testcase = read_session(&finding_dir);
    assert!(
        testcase.state_path.iter().any(|state| state == "opened"),
        "the session reached the second state: {:?}",
        testcase.state_path
    );
    assert!(testcase.bindings.contains("OPEN.response.handle"));
    let finding = std::fs::read_to_string(finding_dir.join("finding.json")).unwrap();
    assert!(finding.contains("HDF7-PATHTRAV"), "{finding}");
    let meta = std::fs::read_to_string(finding_dir.join("session_meta.json")).unwrap();
    assert!(meta.contains("\"udp:127.0.0.1:"), "{meta}");
    assert!(meta.contains("\"reply_timeout_ms\": 2000"), "{meta}");

    std::fs::remove_dir_all(&work_dir).ok();
}

/// A pseudo-terminal: the master end, as a device's side of a UART, and the
/// slave's path, which starts in the default cooked mode as a real tty does.
#[cfg(target_os = "linux")]
fn pty() -> (std::fs::File, String) {
    use std::os::fd::{FromRawFd, OwnedFd};
    // SAFETY: libc calls on a fresh descriptor, each result checked.
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(master >= 0);
        assert_eq!(libc::grantpt(master), 0);
        assert_eq!(libc::unlockpt(master), 0);
        let mut name = [0 as libc::c_char; 128];
        assert_eq!(libc::ptsname_r(master, name.as_mut_ptr(), name.len()), 0);
        (
            std::fs::File::from(OwnedFd::from_raw_fd(master)),
            std::ffi::CStr::from_ptr(name.as_ptr())
                .to_string_lossy()
                .into_owned(),
        )
    }
}

/// The toy service as a serial device on a pty's master: length-framed
/// requests in, replies out, one device for every session.
#[cfg(target_os = "linux")]
fn serve_serial(mut device: std::fs::File) {
    let mut current_handle: Option<u32> = None;
    let mut tainted = false;
    loop {
        let mut len_buf = [0u8; 2];
        if device.read_exact(&mut len_buf).is_err() {
            return;
        }
        let mut req = vec![0u8; u16::from_be_bytes(len_buf) as usize];
        if device.read_exact(&mut req).is_err() {
            return;
        }
        let reply = handle_frame(&req, &mut current_handle, &mut tainted);
        let mut frame = (reply.len() as u16).to_be_bytes().to_vec();
        frame.extend_from_slice(&reply);
        if device.write_all(&frame).is_err() {
            return;
        }
    }
}

/// `--session-transport serial:PATH` (#262): the session lane drives a UART
/// command set. Over a pty the campaign reaches the second state and the
/// boundary oracle, through binary length-prefixed frames with CRCs that a
/// tty left cooked would edit and translate.
#[cfg(target_os = "linux")]
#[test]
fn session_campaign_over_a_serial_pty_reaches_the_second_state_and_the_oracle_fires() {
    let (master, slave) = pty();
    thread::spawn(move || serve_serial(master));
    let work_dir = temp_dir("serial-campaign");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("fuzz")
        .arg(work_dir.path())
        .args(["--harness", "H-session-serial", "--protocol-profile"])
        .arg(toy_profile_path())
        .args([
            "--session-transport",
            &format!("serial:{slave},baud=115200"),
        ])
        .args(["--session-reset", "none", "--iterations", "1500"])
        .output()
        .expect("run bhf fuzz");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let summary: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(summary["transport"], format!("serial:{slave},baud=115200"));
    assert_eq!(summary["reset_fidelity"], "serial;reset=none");

    let finding_dir =
        find_session_finding(work_dir.path()).expect("the campaign emitted a session finding");
    let testcase = read_session(&finding_dir);
    assert!(
        testcase.state_path.iter().any(|state| state == "opened"),
        "{:?}",
        testcase.state_path
    );
    let finding = std::fs::read_to_string(finding_dir.join("finding.json")).unwrap();
    assert!(finding.contains("HDF7-PATHTRAV"), "{finding}");
}

/// A serial device has no port for `--session-server-cmd` to wait for, and a
/// bad spec says what is wrong.
#[test]
fn a_serial_session_transport_spec_is_checked() {
    let work_dir = temp_dir("serial-spec");
    for (spec, extra, wanted) in [
        ("serial:", &[][..], "the device path is empty"),
        (
            "serial:/dev/ttyUSB0,baud=fast",
            &[][..],
            "baud=fast is not a positive integer",
        ),
        (
            "serial:/dev/ttyUSB0",
            &["--session-server-cmd", "true"][..],
            "needs a tcp: or udp: --session-transport",
        ),
    ] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_bhf"))
            .arg("fuzz")
            .arg(work_dir.path())
            .args(["--harness", "H-session-serial", "--protocol-profile"])
            .arg(toy_profile_path())
            .args(["--session-transport", spec])
            .args(extra)
            .output()
            .expect("run bhf fuzz");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{spec}: {stderr}");
        assert!(stderr.contains(wanted), "{spec}: {stderr}");
    }
}

// ---------------------------------------------------------------------------
// A session the service drops is a crash finding; a service that is gone
// stops the campaign
// ---------------------------------------------------------------------------

#[test]
fn a_session_the_service_drops_is_a_finding_and_the_campaign_goes_on() {
    let port = start_aborting_toy_service();
    let work_dir = temp_dir("disconnect");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("fuzz")
        .arg(work_dir.path())
        .args(["--harness", "H-session", "--protocol-profile"])
        .arg(toy_profile_path())
        .args(["--session-transport", &format!("tcp:127.0.0.1:{port}")])
        .args(["--iterations", "1500"])
        .output()
        .expect("run bhf fuzz");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "the campaign goes on:\n{stderr}");
    let summary: serde_json::Value =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("summary ({e}):\n{stderr}"));
    assert_eq!(summary["executions"], 1500, "{summary:#}");
    assert!(summary["crashes"].as_u64().unwrap() >= 1, "{summary:#}");
    assert_eq!(
        summary["findings"].as_array().unwrap().len(),
        1,
        "{summary:#}"
    );

    let finding = find_session_finding(&work_dir).expect("a session finding");
    let raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(finding.join("finding.json")).unwrap()).unwrap();
    assert_eq!(raw["rule_id"], "BHF-210", "{raw:#}");
    assert_eq!(raw["oracle"]["name"], "session-disconnect");
    assert_eq!(raw["oracle"]["api"], "WRITE");

    // The dropped session replays as one the service drops again.
    let replay = std::process::Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["replay", "--finding"])
        .arg(&finding)
        .output()
        .expect("run bhf replay");
    let shown = String::from_utf8_lossy(&replay.stdout);
    assert!(
        replay.status.success() && shown.starts_with("MATCH"),
        "{shown}\n{}",
        String::from_utf8_lossy(&replay.stderr)
    );
}

#[test]
fn a_service_that_refuses_three_connections_in_a_row_stops_the_campaign() {
    // A port nothing listens on.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let work_dir = temp_dir("refused");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("fuzz")
        .arg(work_dir.path())
        .args(["--harness", "H-session", "--protocol-profile"])
        .arg(toy_profile_path())
        .args(["--session-transport", &format!("tcp:127.0.0.1:{port}")])
        .args(["--iterations", "50"])
        .output()
        .expect("run bhf fuzz");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains("3 connection attempts in a row failed"),
        "{stderr}"
    );
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
