// SPDX-License-Identifier: Apache-2.0

//! The on-target transport lane's mutator gets the operator's `--dict`, the
//! harness's dictionary and `--grammar`. Its dictionary was hard-coded empty,
//! so a firmware magic gate got no help, and `--grammar` was refused.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::sync::{Arc, Mutex};

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// The magic the mock agent faults on when an input holds it anywhere: nine
/// bytes no blind mutation of the seed writes in 5000 inputs.
const MAGIC: &[u8] = b"BHF7MAGIC";

/// One agent reply (`agent.rs`'s frame): status, no edges, and a
/// memory-protection fault when `crash`.
fn reply(crash: bool) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&u32::from(crash).to_le_bytes()); // status: 0 ok, 1 crash
    out.extend_from_slice(&0u32.to_le_bytes()); // n_edges
    out.extend_from_slice(&u32::from(crash).to_le_bytes()); // fault_present
    if crash {
        out.extend_from_slice(&1u32.to_le_bytes()); // MemoryProtection
        out.extend_from_slice(&0x2000_1000u64.to_le_bytes());
        let detail = b"magic gate";
        out.extend_from_slice(&(detail.len() as u32).to_le_bytes());
        out.extend_from_slice(detail);
    }
    out
}

/// A target-side agent on a loopback port: every input it is sent goes into
/// `received`, and `crashes(input)` says whether it faults.
fn mock_agent(crashes: fn(&[u8]) -> bool) -> (u16, Arc<Mutex<Vec<Vec<u8>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&received);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let log = Arc::clone(&log);
            std::thread::spawn(move || serve(stream, crashes, &log));
        }
    });
    (port, received)
}

fn serve(mut stream: TcpStream, crashes: fn(&[u8]) -> bool, log: &Mutex<Vec<Vec<u8>>>) {
    loop {
        let mut len = [0u8; 4];
        if stream.read_exact(&mut len).is_err() {
            return;
        }
        let mut input = vec![0u8; u32::from_le_bytes(len) as usize];
        if stream.read_exact(&mut input).is_err() {
            return;
        }
        let crash = crashes(&input);
        log.lock().unwrap().push(input);
        if stream.write_all(&reply(crash)).is_err() {
            return;
        }
    }
}

fn holds_magic(input: &[u8]) -> bool {
    input.windows(MAGIC.len()).any(|window| window == MAGIC)
}

fn fuzz(work: &TestDir, port: u16, extra: &[&str]) -> (serde_json::Value, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .current_dir(work.path())
        .args(["fuzz", "bhf_work", "--harness", "H-agent"])
        .args(["--target-transport", &format!("agent:tcp:127.0.0.1:{port}")])
        .args(["--rng-seed", "7", "--seed-input", "HELLO-FIRMWARE"])
        .args(extra)
        .output()
        .expect("run bhf fuzz");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    let summary =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("summary ({e}): {stderr}"));
    (summary, stderr)
}

#[test]
fn a_dictionary_magic_gate_is_passed_with_dict_and_not_without() {
    let work = TestDir::new("transport-dict");
    std::fs::write(work.join("magic.dict"), "magic=\"BHF7MAGIC\"\n").unwrap();

    let (port, _) = mock_agent(holds_magic);
    let (without, _) = fuzz(&work, port, &["--iterations", "5000"]);
    assert_eq!(
        without["findings"].as_array().unwrap().len(),
        0,
        "{without:#}"
    );

    let (port, received) = mock_agent(holds_magic);
    let (with, stderr) = fuzz(
        &work,
        port,
        &["--iterations", "5000", "--dict", "magic.dict"],
    );
    assert_eq!(
        with["findings"].as_array().unwrap().len(),
        1,
        "{with:#}\n{stderr}"
    );
    assert!(received
        .lock()
        .unwrap()
        .iter()
        .any(|input| holds_magic(input)));
}

/// `START` derives `CMD` and one or more `a`/`b` arguments.
const GRAMMAR: &str =
    r#"{"START": ["CMD {ARGS}"], "ARGS": ["{ARG}", "{ARG},{ARGS}"], "ARG": ["a", "b"]}"#;

fn is_sentence(input: &[u8]) -> bool {
    let Some(args) = input.strip_prefix(b"CMD ") else {
        return false;
    };
    !args.is_empty()
        && args
            .split(|b| *b == b',')
            .all(|arg| arg == b"a" || arg == b"b")
}

#[test]
fn with_a_grammar_every_input_is_a_sentence_of_it() {
    let work = TestDir::new("transport-grammar");
    std::fs::write(work.join("grammar.json"), GRAMMAR).unwrap();
    let (port, received) = mock_agent(|_| false);
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .current_dir(work.path())
        .args(["fuzz", "bhf_work", "--harness", "H-agent"])
        .args(["--target-transport", &format!("agent:tcp:127.0.0.1:{port}")])
        .args(["--rng-seed", "7", "--iterations", "300", "--max-len", "64"])
        .args(["--grammar", "grammar.json"])
        .output()
        .expect("run bhf fuzz");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    let received = received.lock().unwrap();
    assert_eq!(received.len(), 300, "{stderr}");
    for input in received.iter() {
        assert!(
            is_sentence(input),
            "not a sentence of the grammar: {:?}",
            String::from_utf8_lossy(input)
        );
    }
}
