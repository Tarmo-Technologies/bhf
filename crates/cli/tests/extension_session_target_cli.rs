// SPDX-License-Identifier: Apache-2.0

//! `bhf extension session --session-transport` (#313): an extension's scenario
//! drives a real target over the session lane's transport, not only the
//! built-in toy target.
//!
//! The fixture servers speak the `bhf_ext_mock` extension's toy protocol
//! (`[u16 BE len][payload][u32 BE CRC-32]`, `OPEN(path) -> handle`,
//! `WRITE(handle, data)`). A WRITE is answered with the path, relative to the
//! server's root, that the handle resolved to, and the mock in `target-oracle`
//! mode judges THAT reply: its oracle fires only when the target says it wrote
//! outside its root. So a finding here can only come from what the server did,
//! never from the input alone.

#![cfg(unix)]

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use std::thread;

use serde_json::Value;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 6);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(&crc32(payload).to_be_bytes());
    out
}

/// The `path` OPEN named, resolved lexically against the server's root: `.`
/// dropped, `..` popping a component, and a `..` past the root kept, so a path
/// that escapes still says so.
fn resolve(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." if parts.last().is_some_and(|last| *last != "..") => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let joined = parts.join("/");
    if path.starts_with('/') {
        format!("/{joined}")
    } else {
        joined
    }
}

fn escapes(path: &str) -> bool {
    path.starts_with('/') || path.split('/').any(|segment| segment == "..")
}

/// What a fixture server does with a session.
#[derive(Clone, Copy, PartialEq)]
enum Behaviour {
    /// Opens any path and writes wherever it resolves.
    Permissive,
    /// Refuses to open a path that resolves outside its root.
    Sandboxed,
    /// Closes the connection when a WRITE arrives.
    DropOnWrite,
}

/// A frame the server received, as the server saw it.
#[derive(Debug, Clone)]
struct Received {
    payload: String,
    crc_valid: bool,
}

/// The server's answer to one frame, or `None` to drop the connection.
fn answer(
    behaviour: Behaviour,
    message: &[u8],
    handles: &mut Vec<(String, String)>,
    log: &Mutex<Vec<Received>>,
) -> Option<Vec<u8>> {
    if message.len() < 6 {
        return Some(frame(b"ERR badframe"));
    }
    let declared = usize::from(u16::from_be_bytes([message[0], message[1]]));
    let payload = &message[2..message.len() - 4];
    let crc = u32::from_be_bytes(message[message.len() - 4..].try_into().unwrap());
    let crc_valid = declared == payload.len() && crc == crc32(payload);
    let text = String::from_utf8_lossy(payload).into_owned();
    log.lock().unwrap().push(Received {
        payload: text.clone(),
        crc_valid,
    });
    if !crc_valid {
        return Some(frame(b"ERR badcrc"));
    }
    let mut words = text.splitn(3, ' ');
    let reply = match words.next() {
        Some("OPEN") => {
            let resolved = resolve(words.next().unwrap_or(""));
            if behaviour == Behaviour::Sandboxed && escapes(&resolved) {
                "ERR denied".to_owned()
            } else {
                // Handles start at 41, so a WRITE that carries one carries
                // the server's, bound from its OPEN reply.
                let handle = (41 + handles.len()).to_string();
                handles.push((handle.clone(), resolved));
                format!("OPENOK {handle}")
            }
        }
        Some("WRITE") if behaviour == Behaviour::DropOnWrite => return None,
        Some("WRITE") => {
            let handle = words.next().unwrap_or("");
            match handles.iter().find(|(known, _)| known == handle) {
                Some((_, resolved)) => format!("WRITEOK {resolved}"),
                None => "ERR badhandle".to_owned(),
            }
        }
        _ => "ERR unknownop".to_owned(),
    };
    Some(frame(reply.as_bytes()))
}

/// Serve one connection: each message is one write from the host, read up to
/// its declared length.
fn serve(mut stream: TcpStream, behaviour: Behaviour, log: Arc<Mutex<Vec<Received>>>) {
    let mut handles = Vec::new();
    let mut buffered: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        buffered.extend_from_slice(&chunk[..n]);
        while buffered.len() >= 6 {
            let end = usize::from(u16::from_be_bytes([buffered[0], buffered[1]])) + 6;
            if buffered.len() < end {
                break;
            }
            let message: Vec<u8> = buffered.drain(..end).collect();
            match answer(behaviour, &message, &mut handles, &log) {
                Some(reply) => {
                    if stream.write_all(&reply).is_err() {
                        return;
                    }
                }
                None => return,
            }
        }
    }
}

/// A TCP fixture server on a free loopback port, and what it receives.
fn start_tcp_server(behaviour: Behaviour) -> (u16, Arc<Mutex<Vec<Received>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fixture server");
    let port = listener.local_addr().unwrap().port();
    let log = Arc::new(Mutex::new(Vec::new()));
    let served = Arc::clone(&log);
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let log = Arc::clone(&served);
            thread::spawn(move || serve(stream, behaviour, log));
        }
    });
    (port, log)
}

/// A UDP fixture server: one datagram is one message, its reply one datagram.
/// Its handles are per server, as a UDP service has no connection to key on.
fn start_udp_server() -> (u16, Arc<Mutex<Vec<Received>>>) {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind the udp fixture server");
    let port = socket.local_addr().unwrap().port();
    let log = Arc::new(Mutex::new(Vec::new()));
    let served = Arc::clone(&log);
    thread::spawn(move || {
        let mut handles = Vec::new();
        let mut buf = [0u8; 65_536];
        while let Ok((n, peer)) = socket.recv_from(&mut buf) {
            if let Some(reply) = answer(Behaviour::Permissive, &buf[..n], &mut handles, &served) {
                let _ = socket.send_to(&reply, peer);
            }
        }
    });
    (port, log)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A manifest for the mock extension in `mode`.
fn write_manifest(dir: &Path, mode: &str) -> PathBuf {
    let manifest = format!(
        "schema = \"bhf.extension-manifest.v1\"\n\
         id = \"mock-extension\"\n\
         executable = {exe:?}\n\
         args = [\"--mode\", {mode:?}]\n\
         required-capabilities = [\"oracle.evaluate\"]\n\
         allow-external-paths = true\n\
         \n\
         [limits]\n\
         call-timeout-ms = 5000\n",
        exe = env!("CARGO_BIN_EXE_bhf_ext_mock"),
    );
    let path = dir.join("extension.toml");
    fs::write(&path, manifest).unwrap();
    path
}

/// A finished `bhf extension session` run.
struct Run {
    code: i32,
    report: Value,
    stderr: String,
    work: PathBuf,
}

/// Run `bhf extension session --json` over the seed `input` with `extra`
/// arguments, the mock in `mode`.
fn run_session(dir: &Path, mode: &str, input: &[u8], extra: &[&str]) -> Run {
    let manifest = write_manifest(dir, mode);
    let seed = dir.join("input.bin");
    fs::write(&seed, input).unwrap();
    let work = dir.join("work");
    let output: Output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["extension", "session", "--manifest"])
        .arg(&manifest)
        .arg("--input")
        .arg(&seed)
        .arg("--work")
        .arg(&work)
        .arg("--json")
        .args(extra)
        .output()
        .expect("run bhf extension session");
    Run {
        code: output.status.code().unwrap_or(-1),
        report: serde_json::from_slice(&output.stdout).unwrap_or(Value::Null),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        work,
    }
}

/// Every extension finding under `<work>/results/findings/`.
fn extension_findings(work: &Path) -> Vec<Value> {
    let Ok(entries) = fs::read_dir(work.join("results/findings")) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| fs::read(entry.path().join("finding.json")).ok())
        .map(|bytes| serde_json::from_slice::<Value>(&bytes).unwrap())
        .filter(|finding| finding["confirmation"] == "extension")
        .collect()
}

fn evidence<'a>(finding: &'a Value, key: &str) -> Option<&'a str> {
    finding["evidence"]
        .as_array()?
        .iter()
        .find(|item| item["key"] == key)?["value"]
        .as_str()
}

#[test]
fn an_extension_scenario_drives_a_fixture_server_and_its_oracle_fires() {
    let dir = TestDir::new("ext-session-tcp");
    let (port, received) = start_tcp_server(Behaviour::Permissive);
    let spec = format!("tcp:127.0.0.1:{port}");
    let run = run_session(
        &dir,
        "target-oracle",
        b"logs/../../etc/passwd",
        &["--session-transport", &spec],
    );
    assert_eq!(run.code, 1, "{}\n{}", run.report, run.stderr);

    // The server got the scenario: an OPEN of the seed's path, then a WRITE
    // carrying the handle the server issued, both well-formed.
    let received = received.lock().unwrap().clone();
    assert_eq!(received.len(), 2, "{received:?}");
    assert_eq!(received[0].payload, "OPEN logs/../../etc/passwd");
    assert!(
        received[1].payload.starts_with("WRITE 41 "),
        "the WRITE carries the server's handle: {received:?}"
    );
    assert!(received.iter().all(|frame| frame.crc_valid), "{received:?}");

    // The oracle fired on what the server reported: the path it wrote to,
    // which the server resolved, not the seed's spelling of it.
    let findings = extension_findings(&run.work);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0]["rule_id"], "oracle.write-escape");
    assert_eq!(evidence(&findings[0], "target_path"), Some("../etc/passwd"));
    assert_eq!(
        findings[0]["extension"]["protocol_version"],
        "bhf.extension.v1"
    );

    let session = &run.report["session"];
    assert_eq!(run.report["result"], "finding");
    assert_eq!(session["oracle_ran"], true);
    assert_eq!(session["messages_sent"], 2);
    assert_eq!(session["target"]["transport"], spec.as_str());
    assert_eq!(session["target"]["exchanges"], 2);
    assert_eq!(session["target"]["error"], Value::Null);
    let labels: Vec<&str> = session["steps"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|step| step["label"].as_str())
        .collect();
    assert_eq!(labels, ["OPEN", "WRITE"]);
    // The run record on disk is the one printed.
    let on_disk: Value =
        serde_json::from_slice(&fs::read(run.work.join("extension.json")).unwrap()).unwrap();
    assert_eq!(on_disk, run.report);
}

#[test]
fn the_oracle_judges_what_the_server_did_not_the_input() {
    // The same escaping seed against a server that refuses it: the OPEN is
    // denied, the WRITE has no handle to carry, nothing is written outside
    // the root, and the oracle does not fire.
    let dir = TestDir::new("ext-session-sandboxed");
    let (port, received) = start_tcp_server(Behaviour::Sandboxed);
    let run = run_session(
        &dir,
        "target-oracle",
        b"logs/../../etc/passwd",
        &["--session-transport", &format!("tcp:127.0.0.1:{port}")],
    );
    assert_eq!(run.code, 0, "{}\n{}", run.report, run.stderr);
    assert!(extension_findings(&run.work).is_empty());
    assert_eq!(run.report["result"], "ok");
    assert_eq!(run.report["session"]["oracle_ran"], true);

    let received = received.lock().unwrap().clone();
    assert_eq!(received.len(), 2, "{received:?}");
    assert!(
        received[1].payload.starts_with("WRITE 0 "),
        "no handle was bound from the denied OPEN: {received:?}"
    );
}

#[test]
fn a_udp_target_is_driven_one_datagram_per_message() {
    let dir = TestDir::new("ext-session-udp");
    let (port, received) = start_udp_server();
    let spec = format!("udp:127.0.0.1:{port}");
    let run = run_session(
        &dir,
        "target-oracle",
        b"../etc/shadow",
        &["--session-transport", &spec],
    );
    assert_eq!(run.code, 1, "{}\n{}", run.report, run.stderr);
    let findings = extension_findings(&run.work);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(evidence(&findings[0], "target_path"), Some("../etc/shadow"));
    assert_eq!(run.report["session"]["target"]["transport"], spec.as_str());
    assert_eq!(received.lock().unwrap().len(), 2);
}

#[test]
fn a_target_that_drops_the_session_is_the_targets_result_not_the_extensions() {
    let dir = TestDir::new("ext-session-dropped");
    let (port, _received) = start_tcp_server(Behaviour::DropOnWrite);
    let run = run_session(
        &dir,
        "target-oracle",
        b"../etc/passwd",
        &[
            "--session-transport",
            &format!("tcp:127.0.0.1:{port}"),
            "--session-reply-timeout",
            "2s",
        ],
    );
    // Exit 3: the target ended the session. Not 4, an extension fault, and
    // not 1: the oracle never judged a session that did not finish.
    assert_eq!(run.code, 3, "{}\n{}", run.report, run.stderr);
    assert!(extension_findings(&run.work).is_empty());
    let result = run.report["result"].as_str().unwrap_or_default();
    assert!(result.starts_with("target_error: "), "{}", run.report);
    assert!(result.contains("connection closed"), "{}", run.report);
    let session = &run.report["session"];
    assert_eq!(session["oracle_ran"], false);
    assert_eq!(session["messages_sent"], 1, "only the OPEN was answered");
    assert_eq!(session["target"]["exchanges"], 1);
    assert!(session["target"]["error"].is_string(), "{}", run.report);
}

#[test]
fn an_unreachable_target_is_a_setup_error() {
    let dir = TestDir::new("ext-session-unreachable");
    let spec = format!("tcp:127.0.0.1:{}", free_port());
    let run = run_session(
        &dir,
        "target-oracle",
        b"logs/a.txt",
        &["--session-transport", &spec],
    );
    assert_eq!(run.code, 2, "{}", run.stderr);
    assert!(run.stderr.contains(&spec), "{}", run.stderr);
    assert!(extension_findings(&run.work).is_empty());
}

#[test]
fn a_malformed_session_transport_spec_is_a_usage_error() {
    let dir = TestDir::new("ext-session-bad-spec");
    let run = run_session(
        &dir,
        "target-oracle",
        b"logs/a.txt",
        &["--session-transport", "tcp:127.0.0.1"],
    );
    assert_eq!(run.code, 2, "{}", run.stderr);
    assert!(
        run.stderr
            .contains("--session-transport: malformed tcp spec \"tcp:127.0.0.1\""),
        "{}",
        run.stderr
    );
    // Refused before the extension is spawned: no run record.
    assert!(!run.work.join("extension.json").exists());
}

#[test]
fn a_session_server_cmd_needs_a_session_transport() {
    let dir = TestDir::new("ext-session-server-no-transport");
    let run = run_session(
        &dir,
        "target-oracle",
        b"logs/a.txt",
        &["--session-server-cmd", "true"],
    );
    assert_eq!(run.code, 2, "{}", run.stderr);
    assert!(run.stderr.contains("--session-transport"), "{}", run.stderr);
}

// ── a service bhf starts (--session-server-cmd) ─────────────────────────────

/// The toy file service as a process of its own, for `--session-server-cmd`:
/// `toy_server.py PORT [crash]`. With `crash` it exits on a WRITE with a
/// sanitizer report on stderr, as a service built with ASan would.
const TOY_SERVICE: &str = r#"
import socket, struct, sys, zlib

port = int(sys.argv[1])
crash = len(sys.argv) > 2 and sys.argv[2] == "crash"

def frame(payload):
    return struct.pack(">H", len(payload)) + payload + struct.pack(">I", zlib.crc32(payload))

def resolve(path):
    parts = []
    for segment in path.split("/"):
        if segment in ("", "."):
            continue
        if segment == ".." and parts and parts[-1] != "..":
            parts.pop()
        else:
            parts.append(segment)
    return "/".join(parts)

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", port))
server.listen()
while True:
    conn, _ = server.accept()
    handles = {}
    buffered = b""
    while True:
        data = conn.recv(4096)
        if not data:
            break
        buffered += data
        while len(buffered) >= 6:
            end = struct.unpack(">H", buffered[:2])[0] + 6
            if len(buffered) < end:
                break
            payload, buffered = buffered[2:end - 4], buffered[end:]
            words = payload.decode("latin-1").split(" ", 2)
            if words[0] == "OPEN":
                handle = str(41 + len(handles))
                handles[handle] = resolve(words[1] if len(words) > 1 else "")
                reply = "OPENOK " + handle
            elif words[0] == "WRITE" and crash:
                sys.stderr.write(
                    "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address "
                    "0x602000000018 at pc 0x1 bp 0x2 sp 0x3\n"
                    "WRITE of size 8 at 0x602000000018 thread T0\n"
                    "    #0 0x1 in write_file toy_server.c:42\n"
                    "SUMMARY: AddressSanitizer: heap-buffer-overflow toy_server.c:42 in write_file\n"
                )
                sys.stderr.flush()
                sys.exit(1)
            elif words[0] == "WRITE":
                resolved = handles.get(words[1] if len(words) > 1 else "")
                reply = "WRITEOK " + resolved if resolved is not None else "ERR badhandle"
            else:
                reply = "ERR unknownop"
            conn.sendall(frame(reply.encode("latin-1")))
    conn.close()
"#;

/// `python3 <toy_server.py> PORT [crash]`, or `None` with no python3.
fn toy_service_cmd(dir: &Path, port: u16, crash: bool) -> Option<String> {
    let present = Command::new("python3")
        .args(["-c", "1"])
        .status()
        .is_ok_and(|status| status.success());
    if !present {
        return None;
    }
    let script = dir.join("toy_server.py");
    fs::write(&script, TOY_SERVICE).unwrap();
    Some(format!(
        "exec python3 {} {port}{}",
        script.display(),
        if crash { " crash" } else { "" }
    ))
}

#[test]
fn a_service_bhf_starts_is_driven_and_its_oracle_fires() {
    let dir = TestDir::new("ext-session-server");
    let port = free_port();
    let Some(service) = toy_service_cmd(&dir, port, false) else {
        eprintln!("skipping: python3 not found");
        return;
    };
    let run = run_session(
        &dir,
        "target-oracle",
        b"../etc/passwd",
        &[
            "--session-transport",
            &format!("tcp:127.0.0.1:{port}"),
            "--session-server-cmd",
            &service,
        ],
    );
    assert_eq!(run.code, 1, "{}\n{}", run.report, run.stderr);
    let findings = extension_findings(&run.work);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(evidence(&findings[0], "target_path"), Some("../etc/passwd"));
    let server = &run.report["session"]["target"]["server"];
    assert_eq!(server["command"], service.as_str());
    assert_eq!(server["starts"], 1);
    assert_eq!(server["exit"], Value::Null, "{}", run.report);
    // The service is stopped when the session is over.
    assert!(
        TcpStream::connect(("127.0.0.1", port)).is_err(),
        "the service still serves"
    );
}

#[test]
fn a_service_that_exits_during_the_session_is_recorded_with_its_report() {
    let dir = TestDir::new("ext-session-server-crash");
    let port = free_port();
    let Some(service) = toy_service_cmd(&dir, port, true) else {
        eprintln!("skipping: python3 not found");
        return;
    };
    let run = run_session(
        &dir,
        "target-oracle",
        b"../etc/passwd",
        &[
            "--session-transport",
            &format!("tcp:127.0.0.1:{port}"),
            "--session-server-cmd",
            &service,
        ],
    );
    assert_eq!(run.code, 3, "{}\n{}", run.report, run.stderr);
    assert!(extension_findings(&run.work).is_empty());
    assert_eq!(run.report["result"], "target_exited: exit status 1");
    let exit = &run.report["session"]["target"]["server"]["exit"];
    assert_eq!(exit["status"], "exit status 1", "{}", run.report);
    assert_eq!(exit["sanitizer"]["kind"], "heap-buffer-overflow");
    // Its stderr is kept where the record says.
    let log_dir = PathBuf::from(exit["log_dir"].as_str().unwrap());
    let logs: String = fs::read_dir(&log_dir)
        .unwrap()
        .flatten()
        .map(|entry| fs::read_to_string(entry.path()).unwrap_or_default())
        .collect();
    assert!(
        logs.contains("AddressSanitizer: heap-buffer-overflow"),
        "{logs}"
    );
}

#[test]
fn a_service_that_does_not_start_is_a_setup_error_with_its_stderr() {
    let dir = TestDir::new("ext-session-server-fails");
    let run = run_session(
        &dir,
        "target-oracle",
        b"logs/a.txt",
        &[
            "--session-transport",
            &format!("tcp:127.0.0.1:{}", free_port()),
            "--session-server-cmd",
            "echo 'no config file' >&2; exit 4",
        ],
    );
    assert_eq!(run.code, 2, "{}", run.stderr);
    assert!(
        run.stderr.contains("--session-server-cmd"),
        "{}",
        run.stderr
    );
    assert!(run.stderr.contains("exit status 4"), "{}", run.stderr);
    assert!(run.stderr.contains("no config file"), "{}", run.stderr);
}
