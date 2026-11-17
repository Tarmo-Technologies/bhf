// SPDX-License-Identifier: Apache-2.0

//! `bhf-daemon --security-config FILE` (#273): the shipped daemon runs with
//! workspace-scoped security. It had no switch, so a shared deployment that
//! followed daemon.md ran the unauthenticated single-user daemon.

#![cfg(unix)]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const TOKEN: &str = "operator-token-0123456789";

fn frame(value: serde_json::Value) -> String {
    let body = serde_json::to_string(&value).unwrap();
    format!("Content-Length: {}\r\n\r\n{body}", body.len())
}

fn parse_frames(bytes: &[u8]) -> Vec<serde_json::Value> {
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    let mut frames = Vec::new();
    let mut rest = text.as_str();
    while !rest.is_empty() {
        let (headers, after) = rest.split_once("\r\n\r\n").unwrap();
        let len: usize = headers
            .lines()
            .find_map(|line| line.strip_prefix("Content-Length: "))
            .unwrap()
            .parse()
            .unwrap();
        let (body, remaining) = after.split_at(len);
        frames.push(serde_json::from_str(body).unwrap());
        rest = remaining;
    }
    frames
}

/// Run the daemon with `args` on `requests`.
fn daemon(args: &[&std::ffi::OsStr], requests: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_bhf-daemon"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // A daemon that refuses its config exits before reading; ignore the pipe.
    let _ = child.stdin.take().unwrap().write_all(requests.as_bytes());
    child.wait_with_output().unwrap()
}

/// A workspace, a token file with `mode`, and a config naming them.
fn deployment(root: &Path, mode: u32) -> (PathBuf, PathBuf) {
    let workspace = root.join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let token = root.join("operator.token");
    std::fs::write(&token, format!("{TOKEN}\n")).unwrap();
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(mode)).unwrap();
    let config = root.join("security.json");
    std::fs::write(
        &config,
        serde_json::to_vec_pretty(&serde_json::json!({
            "mode": "multi_tenant",
            "tenants": [{
                "tenant": "ops",
                "token_file": "operator.token",
                "workspace_root": "workspace",
                "role": "operator"
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    (config, workspace)
}

fn scan(id: &str, path: &Path, auth: Option<serde_json::Value>) -> String {
    let mut request = serde_json::json!({
        "jsonrpc": "2.0", "id": id, "method": "scan", "params": { "path": path }
    });
    if let Some(auth) = auth {
        request["auth"] = auth;
    }
    frame(request)
}

#[test]
fn with_a_security_config_an_unauthenticated_call_is_denied_and_a_token_accepted() {
    let root = tempfile::tempdir().unwrap();
    let (config, workspace) = deployment(root.path(), 0o600);
    let requests = [
        scan("none", &workspace, None),
        scan(
            "wrong",
            &workspace,
            Some(serde_json::json!({ "token": "not-the-token-0000" })),
        ),
        scan(
            "valid",
            &workspace,
            Some(serde_json::json!({ "tenant": "ops", "token": TOKEN })),
        ),
        scan(
            "outside",
            root.path(),
            Some(serde_json::json!({ "token": TOKEN })),
        ),
    ]
    .concat();
    let output = daemon(
        &["--security-config".as_ref(), config.as_os_str()],
        &requests,
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let responses = parse_frames(&output.stdout);
    assert_eq!(responses[0]["error"]["code"], -32001, "{:?}", responses[0]);
    assert_eq!(responses[1]["error"]["code"], -32001, "{:?}", responses[1]);
    assert!(responses[2].get("result").is_some(), "{:?}", responses[2]);
    assert_eq!(responses[2]["bhfAudit"]["tenant"], "ops");
    assert_eq!(responses[2]["bhfAudit"]["role"], "operator");
    // The workspace root bounds what the token reaches.
    assert_eq!(responses[3]["error"]["code"], -32003, "{:?}", responses[3]);
}

#[test]
fn a_world_readable_token_file_is_refused_at_start() {
    let root = tempfile::tempdir().unwrap();
    let (config, workspace) = deployment(root.path(), 0o644);
    let output = daemon(
        &["--security-config".as_ref(), config.as_os_str()],
        &scan("1", &workspace, Some(serde_json::json!({ "token": TOKEN }))),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("operator.token") && stderr.contains("chmod 600"),
        "{stderr}"
    );
    assert!(output.stdout.is_empty(), "nothing is served");
}

#[test]
fn without_the_switch_the_daemon_serves_one_local_user() {
    let root = tempfile::tempdir().unwrap();
    let output = daemon(&[], &scan("1", root.path(), None));
    assert!(output.status.success());
    let responses = parse_frames(&output.stdout);
    assert!(responses[0].get("result").is_some(), "{:?}", responses[0]);
    assert!(responses[0].get("bhfAudit").is_none());

    // MCP has no authentication to apply a config to.
    let (config, _) = deployment(root.path(), 0o600);
    let refused = daemon(
        &[
            "--mcp".as_ref(),
            "--security-config".as_ref(),
            config.as_os_str(),
        ],
        "",
    );
    assert_eq!(refused.status.code(), Some(2));
}
