// SPDX-License-Identifier: Apache-2.0

//! `bhf minimize` of an on-target transport finding (#280) rebuilds the
//! transport from the finding's profile, as `bhf replay` does, and
//! delta-debugs its input on the same fault rule and site. It refused
//! transport findings.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// The four bytes the mock firmware faults on, wherever they are.
const TRIGGER: &[u8] = b"BOOM";

/// One agent reply: a memory-protection fault at a fixed site when `crash`.
fn reply(crash: bool) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&u32::from(crash).to_le_bytes()); // status
    out.extend_from_slice(&0u32.to_le_bytes()); // n_edges
    out.extend_from_slice(&u32::from(crash).to_le_bytes()); // fault_present
    if crash {
        out.extend_from_slice(&1u32.to_le_bytes()); // MemoryProtection
        out.extend_from_slice(&0x2000_4000u64.to_le_bytes());
        let detail = b"write to a guard page";
        out.extend_from_slice(&(detail.len() as u32).to_le_bytes());
        out.extend_from_slice(detail);
    }
    out
}

fn serve(mut stream: TcpStream) {
    loop {
        let mut len = [0u8; 4];
        if stream.read_exact(&mut len).is_err() {
            return;
        }
        let mut input = vec![0u8; u32::from_le_bytes(len) as usize];
        if stream.read_exact(&mut input).is_err() {
            return;
        }
        let crash = input.windows(TRIGGER.len()).any(|window| window == TRIGGER);
        if stream.write_all(&reply(crash)).is_err() {
            return;
        }
    }
}

fn mock_agent() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || serve(stream));
        }
    });
    port
}

fn bhf(work: &TestDir, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
        .current_dir(work.path())
        .args(args)
        .output()
        .expect("run bhf")
}

#[test]
fn a_transport_finding_minimizes_to_its_trigger() {
    let work = TestDir::new("transport-minimize");
    let port = mock_agent();
    // 64 bytes, the trigger in the middle.
    let mut seed = vec![b'.'; 30];
    seed.extend_from_slice(TRIGGER);
    seed.extend(std::iter::repeat_n(b'-', 30));
    assert_eq!(seed.len(), 64);
    std::fs::write(work.join("seed.bin"), &seed).unwrap();
    let spec = format!("agent:tcp:127.0.0.1:{port}");
    let fuzz = bhf(
        &work,
        &[
            "fuzz",
            "bhf_work",
            "--harness",
            "H-agent",
            "--target-transport",
            &spec,
            "--seed-file",
            "seed.bin",
            "--iterations",
            "1",
        ],
    );
    let stderr = String::from_utf8_lossy(&fuzz.stderr);
    assert_eq!(fuzz.status.code(), Some(0), "{stderr}");
    let summary: serde_json::Value = serde_json::from_slice(&fuzz.stdout).unwrap();
    let id = summary["findings"][0]
        .as_str()
        .unwrap_or_else(|| panic!("{summary:#}"));
    let finding = work.join("bhf_work/results/findings").join(id);
    assert_eq!(std::fs::read(finding.join("testcase.bin")).unwrap(), seed);

    let minimize = bhf(&work, &["minimize", finding.to_str().unwrap()]);
    let out = String::from_utf8_lossy(&minimize.stdout);
    assert_eq!(
        minimize.status.code(),
        Some(0),
        "{out}\n{}",
        String::from_utf8_lossy(&minimize.stderr)
    );
    assert!(out.contains("original_len=64 minimized_len=4"), "{out}");
    assert_eq!(
        std::fs::read(finding.join("min_testcase.bin")).unwrap(),
        TRIGGER
    );
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(finding.join("finding.json")).unwrap()).unwrap();
    assert_eq!(record["minimal_reproducer"], "min_testcase.bin");
    assert_eq!(record["minimization"]["lane"], "transport", "{record:#}");

    // The typed strategy needs a host harness's argument layout.
    let typed = bhf(
        &work,
        &["minimize", finding.to_str().unwrap(), "--strategy", "typed"],
    );
    let typed_err = String::from_utf8_lossy(&typed.stderr);
    assert_ne!(typed.status.code(), Some(0), "{typed_err}");
    assert!(typed_err.contains("--strategy bytes"), "{typed_err}");
}
