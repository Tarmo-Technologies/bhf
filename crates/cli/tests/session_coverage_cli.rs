// SPDX-License-Identifier: Apache-2.0

//! Code coverage of a service the session lane runs (#363). With
//! `--session-server-cmd`, bhf gives the service `BHF_COV_SHM`; built with
//! SanitizerCoverage and `c_runtime/bhf_service_cov.c`, the service fills it,
//! and bhf keeps a session that reached new code. The lane folded an empty
//! edge set, so on a one-state protocol it kept nothing past the seeds.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// One message in one state: the state channel finds nothing past the seed.
const PROFILE: &str = r#"
schema = "bhf.protocol.v1"
start = "start"

[framing]
kind = "length_prefix"

[[message]]
name = "CMD"

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
value = "x"

[message.response]
[[message.response.capture]]
name = "status"
type = "u8"
at = 0

[[transition]]
from = "start"
send = "CMD"
to = "start"
"#;

/// The command service, built with or without the coverage runtime; `None`
/// with no clang.
fn build_service(dir: &Path, instrumented: bool) -> Option<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let binary = dir.join(if instrumented { "covered" } else { "plain" });
    let mut clang = Command::new("clang");
    clang.args(["-O1", "-o"]).arg(&binary);
    clang.arg(root.join("tests/fixtures/session_server/command_server.c"));
    if instrumented {
        clang
            .arg("-fsanitize-coverage=trace-pc-guard")
            .arg(root.join("c_runtime/bhf_service_cov.c"));
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

/// The run summary of `iterations` sessions against `service`.
fn fuzz(root: &Path, name: &str, service: &Path, iterations: u32) -> serde_json::Value {
    let profile = root.join("cmd.toml");
    std::fs::write(&profile, PROFILE).unwrap();
    let port = free_port();
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("fuzz")
        .arg(root.join(name))
        .args(["--harness", "H-session-cov", "--protocol-profile"])
        .arg(&profile)
        .args(["--session-transport", &format!("tcp:127.0.0.1:{port}")])
        .args([
            "--session-server-cmd",
            &format!("{} {port}", service.display()),
        ])
        .args(["--iterations", &iterations.to_string(), "--rng-seed", "3"])
        .output()
        .expect("run bhf fuzz");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn service_coverage_grows_and_a_session_reaching_new_code_is_kept() {
    let root = TestDir::new("session-coverage");
    let Some(covered) = build_service(root.path(), true) else {
        eprintln!("skipping: no clang");
        return;
    };
    let plain = build_service(root.path(), false).unwrap();

    let short = fuzz(root.path(), "short", &covered, 3);
    let long = fuzz(root.path(), "long", &covered, 300);
    assert_eq!(long["coverage_source"], "service", "{long:#}");
    let (few, many) = (
        short["coverage_edges"].as_u64().unwrap(),
        long["coverage_edges"].as_u64().unwrap(),
    );
    assert!(few > 0, "the seed session reaches service code: {short:#}");
    assert!(
        many > few,
        "more sessions reach more code: {few} then {many}"
    );
    // One state: only code novelty keeps a session.
    assert_eq!(long["states_covered"], short["states_covered"]);
    assert!(
        long["corpus_new"].as_u64().unwrap() > 0,
        "sessions that reached new code are kept: {long:#}"
    );

    let blind = fuzz(root.path(), "blind", &plain, 300);
    assert_eq!(
        blind["coverage_source"], "uninstrumented_service",
        "{blind:#}"
    );
    assert_eq!(blind["coverage_edges"], 0);
    assert_eq!(blind["corpus_new"], 0, "{blind:#}");
}
