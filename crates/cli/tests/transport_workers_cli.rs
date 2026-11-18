// SPDX-License-Identifier: Apache-2.0

//! `bhf fuzz --target-transport ... --workers N` runs N workers, one target
//! each (#316): the spec names each worker's with `{BASE+worker}` or
//! `{worker}`. The workers share one corpus and one finding set. The lane was
//! single-worker and ignored `--workers`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// An agent reply: an edge per first byte, and a fault on an input with `!`.
fn reply(input: &[u8]) -> Vec<u8> {
    let crash = input.contains(&b'!');
    let mut out = Vec::new();
    out.extend_from_slice(&u32::from(crash).to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(100 + u32::from(input.first().copied().unwrap_or(0))).to_le_bytes());
    out.extend_from_slice(&u32::from(crash).to_le_bytes());
    if crash {
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&0x2000_0100u64.to_le_bytes());
        let detail = b"write past the frame";
        out.extend_from_slice(&(detail.len() as u32).to_le_bytes());
        out.extend_from_slice(detail);
    }
    out
}

fn serve(mut stream: TcpStream, runs: &AtomicUsize) {
    loop {
        let mut len = [0u8; 4];
        if stream.read_exact(&mut len).is_err() {
            return;
        }
        let mut input = vec![0u8; u32::from_le_bytes(len) as usize];
        if stream.read_exact(&mut input).is_err() {
            return;
        }
        runs.fetch_add(1, Ordering::SeqCst);
        if stream.write_all(&reply(&input)).is_err() {
            return;
        }
    }
}

/// `n` mock agents on consecutive ports from the returned base, each
/// counting the inputs it ran.
fn agents(n: usize) -> (u16, Vec<Arc<AtomicUsize>>) {
    for attempt in 0..200u16 {
        let base = 20_000 + (std::process::id() as u16 % 20_000) + attempt * 7;
        let listeners: Vec<TcpListener> = (0..n as u16)
            .filter_map(|offset| TcpListener::bind(("127.0.0.1", base + offset)).ok())
            .collect();
        if listeners.len() < n {
            continue;
        }
        let counts = (0..n)
            .map(|_| Arc::new(AtomicUsize::new(0)))
            .collect::<Vec<_>>();
        for (listener, count) in listeners.into_iter().zip(&counts) {
            let count = Arc::clone(count);
            std::thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    let count = Arc::clone(&count);
                    std::thread::spawn(move || serve(stream, &count));
                }
            });
        }
        return (base, counts);
    }
    panic!("no {n} consecutive free ports");
}

fn bhf(work: &TestDir, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
        .current_dir(work.path())
        .args(["fuzz", "bhf_work", "--harness", "H-agents"])
        .args(args)
        .output()
        .expect("run bhf")
}

#[test]
fn three_agents_share_executions_and_their_findings_merge() {
    let work = TestDir::new("transport-workers");
    std::fs::write(work.join("bang.dict"), "\"!\"\n").unwrap();
    let (base, counts) = agents(3);
    let spec = format!("agent:tcp:127.0.0.1:{{{base}+worker}}");
    let out = bhf(
        &work,
        &[
            "--target-transport",
            &spec,
            "--workers",
            "3",
            "--seed-input",
            "a",
            "--dict",
            "bang.dict",
            "--iterations",
            "900",
            "--rng-seed",
            "4",
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    let summary: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(summary["workers"], 3, "{summary:#}");
    assert_eq!(summary["executions"], 900, "{summary:#}");
    let ran: Vec<usize> = counts
        .iter()
        .map(|count| count.load(Ordering::SeqCst))
        .collect();
    assert_eq!(ran.iter().sum::<usize>(), 900, "{ran:?}");
    assert!(
        ran.iter().all(|&runs| runs > 0),
        "every agent ran inputs: {ran:?}"
    );
    let findings = summary["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "one fault, one finding: {summary:#}");

    // `bhf replay` re-drives it on the agent of the worker that found it.
    let finding = work
        .join("bhf_work/results/findings")
        .join(findings[0].as_str().unwrap());
    let profile: serde_json::Value =
        serde_json::from_slice(&std::fs::read(finding.join("transport_profile.json")).unwrap())
            .unwrap();
    let recorded = profile["spec"].as_str().unwrap().to_owned();
    assert!(!recorded.contains('{'), "{recorded}");
    let replay = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .current_dir(work.path())
        .arg("replay")
        .arg(&finding)
        .output()
        .unwrap();
    let replayed = String::from_utf8_lossy(&replay.stdout);
    assert!(
        replayed.contains("MATCH") && !replayed.contains("MISMATCH"),
        "{replayed}"
    );
}

#[test]
fn workers_without_a_per_worker_spec_are_refused() {
    let work = TestDir::new("transport-workers-refused");
    for workers in ["3", "auto"] {
        let out = bhf(
            &work,
            &[
                "--target-transport",
                "agent:tcp:127.0.0.1:1",
                "--workers",
                workers,
                "--iterations",
                "1",
            ],
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{workers}: {stderr}");
        assert!(stderr.contains("{BASE+worker}"), "{stderr}");
    }
}
