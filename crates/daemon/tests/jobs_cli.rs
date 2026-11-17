// SPDX-License-Identifier: Apache-2.0

//! `bhf-daemon --jobs-dir DIR` (#271): the continuous fuzzing scheduler behind
//! the daemon's `submitJob`, `listJobs` and `cancelJob` methods. The scheduler
//! was a library with no consumer, so nothing could run it.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

/// A daemon session: write a request, read its response.
struct Session {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl Session {
    fn start(args: &[&std::ffi::OsStr]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_bhf-daemon"))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            stdin,
            stdout,
            next_id: 0,
        }
    }

    fn call(
        &mut self,
        method: &str,
        auth: (&str, &str),
        params: serde_json::Value,
    ) -> serde_json::Value {
        self.next_id += 1;
        let body = serde_json::to_string(&serde_json::json!({
            "jsonrpc": "2.0", "id": self.next_id, "method": method,
            "auth": { "tenant": auth.0, "token": auth.1 },
            "params": params
        }))
        .unwrap();
        let stdin = self.stdin.as_mut().unwrap();
        write!(stdin, "Content-Length: {}\r\n\r\n{body}", body.len()).unwrap();
        stdin.flush().unwrap();
        let mut length = 0;
        loop {
            let mut line = String::new();
            self.stdout.read_line(&mut line).unwrap();
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            if let Some(value) = line.strip_prefix("Content-Length: ") {
                length = value.parse().unwrap();
            }
        }
        let mut body = vec![0; length];
        self.stdout.read_exact(&mut body).unwrap();
        serde_json::from_slice(&body).unwrap()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let _ = self.child.wait();
    }
}

const OPS: (&str, &str) = ("ops", "ops-token-0123456789");
const AUDIT: (&str, &str) = ("audit", "audit-token-0123456789");
const OTHER: (&str, &str) = ("other", "other-token-0123456789");

/// Two workspaces and a config: `ops` (operator) and `audit` (viewer) in the
/// first, `other` (operator) in the second.
fn deployment(root: &Path) -> (PathBuf, PathBuf) {
    let first = root.join("first");
    let second = root.join("second");
    std::fs::create_dir_all(first.join("project")).unwrap();
    std::fs::create_dir_all(&second).unwrap();
    let mut tenants = Vec::new();
    for ((tenant, token), workspace, role) in [
        (OPS, "first", "operator"),
        (AUDIT, "first", "viewer"),
        (OTHER, "second", "operator"),
    ] {
        let file = root.join(format!("{tenant}.token"));
        std::fs::write(&file, token).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        tenants.push(serde_json::json!({
            "tenant": tenant, "token_file": file, "workspace_root": workspace, "role": role
        }));
    }
    let config = root.join("security.json");
    std::fs::write(
        &config,
        serde_json::to_vec(&serde_json::json!({ "mode": "multi_tenant", "tenants": tenants }))
            .unwrap(),
    )
    .unwrap();
    // A `bhf` that marks the job it runs as entered and waits.
    let bhf = root.join("bhf");
    std::fs::write(
        &bhf,
        "#!/bin/sh\ntouch \"$2/entered-$4\"\nwhile [ ! -f \"$2/release\" ]; do sleep 0.05; done\n",
    )
    .unwrap();
    std::fs::set_permissions(&bhf, std::fs::Permissions::from_mode(0o700)).unwrap();
    (config, first.join("project"))
}

fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn jobs_are_submitted_listed_and_cancelled_and_a_viewer_cannot_submit() {
    let root = tempfile::tempdir().unwrap();
    let (config, project) = deployment(root.path());
    let jobs = root.path().join("jobs");
    let bhf = root.path().join("bhf");
    let mut daemon = Session::start(&[
        "--security-config".as_ref(),
        config.as_os_str(),
        "--jobs-dir".as_ref(),
        jobs.as_os_str(),
        "--bhf".as_ref(),
        bhf.as_os_str(),
    ]);
    let submit = |harness: &str| serde_json::json!({ "project_dir": project, "harness_id": harness, "time_budget_secs": 0 });

    let denied = daemon.call("submitJob", AUDIT, submit("viewer"));
    assert_eq!(denied["error"]["code"], -32002, "{denied}");

    let first = daemon.call("submitJob", OPS, submit("first"));
    let first_id = first["result"]["job_id"]
        .as_str()
        .unwrap_or_else(|| panic!("{first}"))
        .to_owned();
    wait_for("the first job to start", || {
        project.join("entered-first").exists()
    });
    let second = daemon.call("submitJob", OPS, submit("second"));
    let second_id = second["result"]["job_id"].as_str().unwrap().to_owned();

    // Another workspace's tenant sees none of them, and cannot cancel one.
    let other = daemon.call("listJobs", OTHER, serde_json::json!({}));
    assert_eq!(other["result"]["total"], 0, "{other}");
    let refused = daemon.call(
        "cancelJob",
        OTHER,
        serde_json::json!({ "job_id": first_id }),
    );
    assert!(
        refused["error"]["message"]
            .as_str()
            .unwrap()
            .contains("no job"),
        "{refused}"
    );

    // A viewer of the workspace lists them.
    let listed = daemon.call("listJobs", AUDIT, serde_json::json!({}));
    assert_eq!(listed["result"]["total"], 2, "{listed}");
    assert_eq!(listed["result"]["jobs"][0]["state"], "running");
    assert_eq!(listed["result"]["jobs"][1]["state"], "queued");

    let cancelled = daemon.call("cancelJob", OPS, serde_json::json!({ "job_id": second_id }));
    assert_eq!(cancelled["result"]["state"], "cancelled", "{cancelled}");
    let stopping = daemon.call("cancelJob", OPS, serde_json::json!({ "job_id": first_id }));
    assert_eq!(stopping["result"]["state"], "running", "{stopping}");
    wait_for("the running job to be cancelled", || {
        daemon.call("listJobs", OPS, serde_json::json!({}))["result"]["jobs"][0]["state"]
            == "cancelled"
    });
    assert!(
        !project.join("entered-second").exists(),
        "a cancelled job never starts"
    );
}

#[test]
fn without_a_jobs_dir_the_job_methods_say_how_to_run_one() {
    let root = tempfile::tempdir().unwrap();
    let (config, project) = deployment(root.path());
    let mut daemon = Session::start(&["--security-config".as_ref(), config.as_os_str()]);
    let response = daemon.call(
        "submitJob",
        OPS,
        serde_json::json!({ "project_dir": project, "harness_id": "h", "time_budget_secs": 1 }),
    );
    assert!(
        response["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--jobs-dir"),
        "{response}"
    );
}
