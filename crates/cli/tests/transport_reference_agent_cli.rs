// SPDX-License-Identifier: Apache-2.0

//! `bhf fuzz --target-transport agent:tcp` against the reference target-side
//! agent (`c_runtime/bhf_agent.c`, #289) rather than a mock: its POSIX
//! example, linked with a SanitizerCoverage-built target whose fault sits
//! behind three one-byte gates. The agent's edges reach the engine, the fault
//! is a finding, and `bhf replay` re-drives it through the agent. (Coverage
//! growing gate by gate is `agent_loopback.rs`'s test.) It needs
//! clang; `BHF_REQUIRE_TOOLS=1` makes a missing one a failure.
#![cfg(unix)]

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn have_clang() -> bool {
    let present = Command::new("clang")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success());
    support::require_tool(present, "clang")
}

fn build_agent(dir: &Path) -> PathBuf {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let runtime = repo.join("c_runtime");
    let target = repo.join("crates/target_transport/tests/agent/target.c");
    let run = |args: Vec<std::ffi::OsString>| {
        let status = Command::new("clang").args(&args).status().unwrap();
        assert!(status.success(), "clang {args:?}");
    };
    let os = |s: &str| std::ffi::OsString::from(s);
    run(vec![
        os("-c"),
        runtime.join("bhf_agent.c").into(),
        os("-o"),
        dir.join("bhf_agent.o").into(),
    ]);
    run(vec![
        os("-I"),
        runtime.clone().into(),
        os("-c"),
        runtime.join("examples/agent_posix.c").into(),
        os("-o"),
        dir.join("agent_posix.o").into(),
    ]);
    run(vec![
        os("-fsanitize-coverage=trace-pc-guard"),
        os("-c"),
        target.into(),
        os("-o"),
        dir.join("target.o").into(),
    ]);
    let agent = dir.join("agent");
    run(vec![
        dir.join("agent_posix.o").into(),
        dir.join("bhf_agent.o").into(),
        dir.join("target.o").into(),
        os("-o"),
        agent.clone().into(),
    ]);
    agent
}

struct Agent(Child);

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn the_reference_agent_is_fuzzed_to_its_fault_and_replayed() {
    if !have_clang() {
        eprintln!("skipping: clang not on PATH");
        return;
    }
    let work = TestDir::new("reference-agent");
    let binary = build_agent(work.path());
    let mut child = Command::new(&binary)
        .arg("0")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut port = String::new();
    std::io::BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut port)
        .unwrap();
    let _agent = Agent(child);
    let spec = format!("agent:tcp:127.0.0.1:{}", port.trim());
    std::fs::write(work.join("bug.dict"), "\"BUG\"\n").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .current_dir(work.path())
        .args(["fuzz", "bhf_work", "--harness", "H-agent"])
        .args(["--target-transport", &spec])
        .args([
            "--seed-input",
            "A",
            "--seed-input",
            "BU",
            "--dict",
            "bug.dict",
        ])
        .args([
            "--iterations",
            "20000",
            "--rng-seed",
            "9",
            "--max-len",
            "64",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    let summary: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        summary["coverage_edges"].as_u64().unwrap_or(0) >= 2,
        "the agent's edges reach the engine: {summary:#}"
    );
    let id = summary["findings"][0]
        .as_str()
        .unwrap_or_else(|| panic!("the fault behind BUG is not found: {summary:#}\n{stderr}"));
    let finding = work.join("bhf_work/results/findings").join(id);
    let testcase = std::fs::read(finding.join("testcase.bin")).unwrap();
    assert!(testcase.starts_with(b"BUG"), "{testcase:?}");
    let record = std::fs::read_to_string(finding.join("finding.json")).unwrap();
    assert!(record.contains("SIGSEGV"), "{record}");

    let replay = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .current_dir(work.path())
        .arg("replay")
        .arg(&finding)
        .output()
        .unwrap();
    let replayed = String::from_utf8_lossy(&replay.stdout);
    assert_eq!(
        replay.status.code(),
        Some(0),
        "{replayed}\n{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    assert!(
        replayed.contains("MATCH") && !replayed.contains("MISMATCH"),
        "{replayed}"
    );
}
