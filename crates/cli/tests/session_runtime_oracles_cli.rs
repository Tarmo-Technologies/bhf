// SPDX-License-Identifier: Apache-2.0

//! The runtime sink oracles over a service the session lane runs (#364). With
//! `--session-server-cmd` and `--runtime-oracles on`, the service runs under
//! the runtrace shim, the shim matches its sinks against the bytes of the
//! session in flight, and each session's events are evaluated as that
//! session's. Sessions had only the profile's response and state oracles.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

const PROFILE: &str = r#"
schema = "bhf.protocol.v1"
start = "start"

[framing]
kind = "length_prefix"

[[message]]
name = "RUN"

[[message.field]]
name = "op"
type = "u8"
value = 1

[[message.field]]
name = "len"
type = "u16"
endian = "big"
computed = "length(data)"

[[message.field]]
name = "data"
type = "bytes"
max = 32
value = "hello"

[message.response]
[[message.response.capture]]
name = "status"
type = "u8"
at = 0

[[transition]]
from = "start"
send = "RUN"
to = "start"
"#;

/// The shell service, with its planted injection or (`clean`) without.
fn build_service(dir: &Path, clean: bool) -> Option<PathBuf> {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/session_server/shell_server.c");
    let binary = dir.join(if clean {
        "clean-service"
    } else {
        "shell-service"
    });
    let mut clang = Command::new("clang");
    clang.args(["-O1", "-o"]).arg(&binary).arg(source);
    if clean {
        clang.arg("-DCLEAN");
    }
    clang
        .status()
        .is_ok_and(|status| status.success())
        .then_some(binary)
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The summary of a campaign against `service` under the runtime oracles.
fn fuzz(root: &Path, name: &str, service: &Path) -> serde_json::Value {
    let profile = root.join("run.toml");
    std::fs::write(&profile, PROFILE).unwrap();
    let port = free_port();
    let startup = root.join(format!("{name}-startup"));
    let mut command = Command::new(env!("CARGO_BIN_EXE_bhf"));
    command
        .arg("fuzz")
        .arg(root.join(name))
        .args(["--harness", "H-session-oracles", "--protocol-profile"])
        .arg(&profile)
        .args(["--session-transport", &format!("tcp:127.0.0.1:{port}")])
        .args([
            "--session-server-cmd",
            &format!("{} {port} {}", service.display(), startup.display()),
        ])
        .args(["--runtime-oracles", "on", "--iterations", "40"]);
    support::configure_runtrace_shim(&mut command);
    let output = command.output().expect("run bhf fuzz");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(startup.is_dir(), "the service started");
    serde_json::from_slice(&output.stdout).unwrap()
}

fn finding(work: &Path, id: &str) -> (PathBuf, serde_json::Value) {
    let dir = work.join("results/findings").join(id);
    let record = serde_json::from_slice(&std::fs::read(dir.join("finding.json")).unwrap()).unwrap();
    (dir, record)
}

#[test]
fn a_command_injection_in_the_service_is_a_finding_of_the_session_that_caused_it() {
    let root = TestDir::new("session-runtime-oracles");
    let Some(shell) = build_service(root.path(), false) else {
        eprintln!("skipping: no clang");
        return;
    };
    let summary = fuzz(root.path(), "shell", &shell);
    let ids: Vec<&str> = summary["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap())
        .collect();
    // The one system() sink, once per rule however many sessions reached it:
    // a controlled command (BHF-431) holding shell syntax (BHF-304).
    let records: Vec<(PathBuf, serde_json::Value)> = ids
        .iter()
        .map(|id| finding(&root.join("shell"), id))
        .collect();
    let mut rules: Vec<&str> = records
        .iter()
        .map(|(_, record)| record["rule_id"].as_str().unwrap())
        .collect();
    rules.sort();
    assert_eq!(rules, ["BHF-304", "BHF-431"], "{summary:#}");
    let (dir, record) = records
        .iter()
        .find(|(_, record)| record["rule_id"] == "BHF-431")
        .unwrap();
    let text = record.to_string();
    assert!(text.contains("CWE-78"), "{record:#}");
    // Attributed to the session: its testcase and its session artifact carry
    // the data that reached system().
    let session = std::fs::read_to_string(dir.join("session.json")).unwrap();
    assert!(session.contains("RUN"), "{session}");
    let meta = std::fs::read_to_string(dir.join("session_meta.json")).unwrap();
    assert!(meta.contains("\"runtime_signature\""), "{meta}");

    // `bhf replay` runs the service under the shim again and sees the sink.
    let mut replay = Command::new(env!("CARGO_BIN_EXE_bhf"));
    replay.arg("replay").arg(dir);
    support::configure_runtrace_shim(&mut replay);
    let replay = replay.output().unwrap();
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
fn a_clean_service_and_its_start_up_give_no_finding() {
    let root = TestDir::new("session-runtime-oracles-clean");
    let Some(clean) = build_service(root.path(), true) else {
        eprintln!("skipping: no clang");
        return;
    };
    // The service's start-up makes a world-writable directory, which the
    // insecure-permissions oracle reports in a session's events: no session
    // made it, so none is reported.
    let summary = fuzz(root.path(), "clean", &clean);
    assert_eq!(summary["findings"], serde_json::json!([]), "{summary:#}");
    // The shim saw it: the start-up is in the service's runtrace.
    let runtrace =
        std::fs::read_to_string(root.join("clean/session_server/service-runtrace.jsonl")).unwrap();
    assert!(runtrace.contains(r#""e":"insecure_mkdir""#), "{runtrace}");
}
