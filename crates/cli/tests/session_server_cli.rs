// SPDX-License-Identifier: Apache-2.0

//! `bhf fuzz --session-server-cmd` (#260): bhf starts the service the session
//! lane fuzzes, watches it, and starts it again after a crash.
//!
//! The session lane drove a service someone else had started, so it saw a
//! crash only as a dropped connection, had no sanitizer report, and stopped
//! once the service was gone. The fixture is a length-framed TCP service
//! built with ASan whose ECHO copies its data into an 8-byte buffer: a
//! session whose data is longer is a heap-buffer-overflow, found from the
//! service's own report, and the campaign goes on against the service
//! started again.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

const PROFILE: &str = r#"
schema = "bhf.protocol.v1"
start = "start"

[framing]
kind = "length_prefix"

[[message]]
name = "ECHO"

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
max = 64
value = "payload"

[message.response]
[[message.response.capture]]
name = "status"
type = "u8"
at = 0

[[transition]]
from = "start"
send = "ECHO"
to = "start"
"#;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The fixture service built with ASan, or `None` with no clang.
fn build_service(dir: &Path) -> Option<PathBuf> {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/session_server/echo_server.c");
    let binary = dir.join("echo_server");
    let built = Command::new("clang")
        .args(["-fsanitize=address", "-g", "-O1", "-o"])
        .arg(&binary)
        .arg(source)
        .status()
        .is_ok_and(|status| status.success());
    built.then_some(binary)
}

fn fuzz(work: &Path, profile: &Path, port: u16, server: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("fuzz")
        .arg(work)
        .args(["--harness", "H-session-server", "--protocol-profile"])
        .arg(profile)
        .args(["--session-transport", &format!("tcp:127.0.0.1:{port}")])
        .args(["--session-server-cmd", server])
        .args(["--iterations", "400"])
        .output()
        .expect("run bhf fuzz")
}

#[test]
fn a_planted_asan_bug_in_the_service_is_found_and_the_campaign_goes_on() {
    let root = TestDir::new("session-server");
    let Some(service) = build_service(root.path()) else {
        eprintln!("skipping: no clang with ASan");
        return;
    };
    let profile = root.join("echo.toml");
    std::fs::write(&profile, PROFILE).unwrap();
    let port = free_port();
    let work = root.join("work");
    let out = fuzz(
        &work,
        &profile,
        port,
        &format!("{} {port}", service.display()),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    let summary: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    // The campaign ran its whole budget against the service started again.
    assert_eq!(summary["executions"], 400, "{summary:#}");
    assert!(
        summary["server_starts"].as_u64().unwrap_or(0) >= 3,
        "started, then again after the crash and after its confirmation: {summary:#}"
    );

    let finding = summary["findings"][0]
        .as_str()
        .unwrap_or_else(|| panic!("a finding: {summary:#}\n{stderr}"));
    let dir = work.join("results/findings").join(finding);
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("finding.json")).unwrap()).unwrap();
    assert!(
        record["exception"]["name"]
            .as_str()
            .is_some_and(|name| name.contains("HEAP_BUFFER_OVERFLOW")),
        "{record:#}"
    );
    assert!(
        std::fs::read_to_string(dir.join("sanitizer.log"))
            .unwrap()
            .contains("AddressSanitizer: heap-buffer-overflow"),
        "the service's report is kept"
    );
    // The session that caused it is recorded, with data past the 8 bytes.
    let session: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("session.json")).unwrap()).unwrap();
    assert!(!session["messages"].as_array().unwrap().is_empty());
    let meta = std::fs::read_to_string(dir.join("session_meta.json")).unwrap();
    assert!(
        meta.contains("\"oracle\": \"session-server-crash\""),
        "{meta}"
    );
    assert!(meta.contains("echo_server"), "{meta}");

    // `bhf replay` starts the service and the session crashes it again.
    let replay = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("replay")
        .arg(&dir)
        .output()
        .unwrap();
    let replay_out = String::from_utf8_lossy(&replay.stdout);
    assert_eq!(
        replay.status.code(),
        Some(0),
        "{replay_out}\n{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    assert!(!replay_out.contains("MISMATCH"), "{replay_out}");
}

#[test]
fn a_service_that_does_not_start_is_exit_2_with_its_stderr() {
    let root = TestDir::new("session-server-fails");
    let profile = root.join("echo.toml");
    std::fs::write(&profile, PROFILE).unwrap();
    let out = fuzz(
        &root.join("work"),
        &profile,
        free_port(),
        "echo 'cannot open the config file' >&2; exit 4",
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("--session-server-cmd"), "{stderr}");
    assert!(stderr.contains("exit status 4"), "{stderr}");
    assert!(stderr.contains("cannot open the config file"), "{stderr}");
}
