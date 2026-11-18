// SPDX-License-Identifier: Apache-2.0

//! The session lane over a `--target-transport` backend (#261):
//! `--session-transport transport:agent:tcp:HOST:PORT` drives a protocol
//! session through the on-target agent, one execution per message. The lane
//! reached only tcp, udp and serial services, so a stateful protocol on a
//! board behind an agent or a debug probe could not be fuzzed as sessions.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::sync::{Arc, Mutex};

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// HELLO, then CMD with up to 32 bytes of data. Over an agent there is no
/// reply channel, so the profile captures nothing.
const PROFILE: &str = r#"
schema = "bhf.protocol.v1"
start = "start"

[framing]
kind = "raw"

[[message]]
name = "HELLO"

[[message.field]]
name = "op"
type = "u8"
value = 1

[[message]]
name = "CMD"

[[message.field]]
name = "op"
type = "u8"
value = 2

[[message.field]]
name = "len"
type = "u8"
computed = "length(data)"

[[message.field]]
name = "data"
type = "bytes"
max = 32
value = "ok"

[[transition]]
from = "start"
send = "HELLO"
to = "armed"

[[transition]]
from = "armed"
send = "CMD"
to = "armed"
"#;

/// A CMD whose data holds a byte past ASCII: the firmware's parser indexes a
/// 128-entry table with it.
fn overflows(input: &[u8]) -> bool {
    input.first() == Some(&2) && input.iter().skip(2).any(|&byte| byte >= 0x80)
}

/// One agent reply: an edge per first byte, and a memory-protection fault
/// when `crash`.
fn reply(input: &[u8], crash: bool) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&u32::from(crash).to_le_bytes()); // status
    out.extend_from_slice(&1u32.to_le_bytes()); // n_edges
    out.extend_from_slice(&(u32::from(input.first().copied().unwrap_or(0)) + 100).to_le_bytes());
    out.extend_from_slice(&u32::from(crash).to_le_bytes()); // fault_present
    if crash {
        out.extend_from_slice(&1u32.to_le_bytes()); // MemoryProtection
        out.extend_from_slice(&0x2000_0ff8u64.to_le_bytes());
        let detail = b"stack smash";
        out.extend_from_slice(&(detail.len() as u32).to_le_bytes());
        out.extend_from_slice(detail);
    }
    out
}

/// A target-side agent on a loopback port; every input it is sent goes into
/// the log, in arrival order.
fn mock_agent() -> (u16, Arc<Mutex<Vec<Vec<u8>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&received);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let log = Arc::clone(&log);
            std::thread::spawn(move || serve(stream, &log));
        }
    });
    (port, received)
}

fn serve(mut stream: TcpStream, log: &Mutex<Vec<Vec<u8>>>) {
    loop {
        let mut len = [0u8; 4];
        if stream.read_exact(&mut len).is_err() {
            return;
        }
        let mut input = vec![0u8; u32::from_le_bytes(len) as usize];
        if stream.read_exact(&mut input).is_err() {
            return;
        }
        let crash = overflows(&input);
        let frame = reply(&input, crash);
        log.lock().unwrap().push(input);
        if stream.write_all(&frame).is_err() {
            return;
        }
    }
}

fn bhf(work: &TestDir, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
        .current_dir(work.path())
        .args(args)
        .output()
        .expect("run bhf")
}

#[test]
fn a_session_over_an_agent_is_delivered_in_order_and_a_fault_is_a_finding() {
    let work = TestDir::new("session-target-transport");
    std::fs::write(work.join("cmd.toml"), PROFILE).unwrap();
    let (port, received) = mock_agent();
    let spec = format!("transport:agent:tcp:127.0.0.1:{port}");
    let out = bhf(
        &work,
        &[
            "fuzz",
            "bhf_work",
            "--harness",
            "H-session-agent",
            "--protocol-profile",
            "cmd.toml",
            "--session-transport",
            &spec,
            "--iterations",
            "300",
            "--rng-seed",
            "5",
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    let summary: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(summary["transport"], spec.as_str(), "{summary:#}");
    assert_eq!(summary["coverage_source"], "target", "{summary:#}");
    assert!(
        summary["coverage_edges"].as_u64().unwrap() > 1,
        "the agent's edges: {summary:#}"
    );
    assert!(
        summary["corpus_new"].as_u64().unwrap() > 0,
        "sessions that reached new edges are kept: {summary:#}"
    );

    // The seed session first: HELLO, then CMD "ok", one execution each.
    let log = received.lock().unwrap().clone();
    assert_eq!(log[..2], [vec![1], b"\x02\x02ok".to_vec()], "{log:?}");

    // The overflow, once, confirmed on a second drive.
    let findings = summary["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{summary:#}");
    let dir = work
        .join("bhf_work/results/findings")
        .join(findings[0].as_str().unwrap());
    let record = std::fs::read_to_string(dir.join("finding.json")).unwrap();
    assert!(
        record.contains("faulted on this message")
            && record.contains("MemoryProtection at 0x20000ff8: stack smash"),
        "{record}"
    );
    let session = std::fs::read_to_string(dir.join("session.json")).unwrap();
    assert!(session.contains("CMD"), "{session}");

    // `bhf replay` drives the recorded session over the agent again.
    let replay = bhf(&work, &["replay", dir.to_str().unwrap()]);
    let replay_out = String::from_utf8_lossy(&replay.stdout);
    assert_eq!(
        replay.status.code(),
        Some(0),
        "{replay_out}\n{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    assert!(
        replay_out.contains("MATCH") && !replay_out.contains("MISMATCH"),
        "{replay_out}"
    );
}

#[test]
fn a_target_transport_session_spec_is_checked_and_takes_the_coverage_map() {
    let work = TestDir::new("session-target-transport-spec");
    std::fs::write(work.join("cmd.toml"), PROFILE).unwrap();
    let run = |extra: &[&str]| {
        let mut args = vec![
            "fuzz",
            "bhf_work",
            "--harness",
            "H-session-agent",
            "--protocol-profile",
            "cmd.toml",
            "--iterations",
            "1",
        ];
        args.extend_from_slice(extra);
        let out = bhf(&work, &args);
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };

    // The backend's own requirements: gdb needs its coverage map.
    let (code, stderr) = run(&["--session-transport", "transport:gdb:127.0.0.1:1"]);
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("--transport-coverage-map"), "{stderr}");

    // The map is the target backend's; a socket session has none.
    let (code, stderr) = run(&[
        "--session-transport",
        "tcp:127.0.0.1:1",
        "--transport-coverage-map",
        "input=0x1,input_cap=8,ring=0x2,write=0x3,wrapped=0x4,cap=8",
    ]);
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("--transport-coverage-map"), "{stderr}");

    // There is no port to wait for a service on.
    let (code, stderr) = run(&[
        "--session-transport",
        "transport:agent:tcp:127.0.0.1:1",
        "--session-server-cmd",
        "true",
    ]);
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("--session-server-cmd"), "{stderr}");
}
