// SPDX-License-Identifier: Apache-2.0

//! A TCP server's parser bug is found in the fork-server lane (#312).
//!
//! `serve` binds a port, listens, and handles one client per `accept`: it
//! reads a record and hands it to `parse_record`, which trusts the record's
//! length byte and overflows a 16-byte field. Fuzzed as it is, the server
//! would wait in `accept` for a client that never comes. Under the runtrace
//! shim with `BHF_DESOCKET=1` the first `accept` returns a connection that
//! carries the fuzz input, the next one (once the server has closed that
//! connection) ends the run, and the C harness runs each input in a forked
//! child, so the builtin engine's persistent fork-server reaches the
//! overflow. The finding records the mode, so it replays in a clean
//! environment.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

mod support;

const SERVER_C: &str = r#"#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* A record is "R:", a length byte, then that many payload bytes. */
static int parse_record(const unsigned char *msg, size_t n) {
    unsigned char field[16];
    if (n < 3 || msg[0] != 'R' || msg[1] != ':') return -1;
    size_t len = msg[2];
    if (len > n - 3) return -1;
    memcpy(field, msg + 3, len);
    return field[0];
}

int serve(int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)(20000 + (port & 0xfff)));
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr *)&addr, sizeof addr) != 0) return -1;
    if (listen(s, 8) != 0) return -1;
    for (;;) {
        int c = accept(s, NULL, NULL);
        if (c < 0) return -1;
        unsigned char buf[512];
        ssize_t n = recv(c, buf, sizeof buf, 0);
        if (n > 0) {
            int verdict = parse_record(buf, (size_t)n);
            send(c, &verdict, sizeof verdict, 0);
        }
        close(c);
    }
}
"#;

fn bhf() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
}

fn shim() -> Option<PathBuf> {
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"));
    let found = ["debug", "release"]
        .into_iter()
        .map(|profile| target.join(profile).join("libbhf_runtrace_shim.so"))
        .any(|path| path.is_file());
    support::require_tool(found, "the runtrace shim (cargo build --workspace)")
        .then(|| target.join("debug"))
}

fn step(args: &[&std::ffi::OsStr], env: &[(&str, &str)]) -> std::process::Output {
    let out = bhf()
        .args(args)
        .envs(env.iter().copied())
        .output()
        .expect("run bhf");
    assert!(
        out.status.success(),
        "bhf {args:?} failed: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

#[test]
fn a_server_parser_bug_is_found_in_the_fork_server_lane() {
    if Command::new("cc").arg("--version").output().is_err() {
        eprintln!("skipping: no C compiler on PATH");
        return;
    }
    if shim().is_none() {
        eprintln!("skipping: the runtrace shim is not built");
        return;
    }
    let root = TestDir::new("desocket-server");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    let source = src.join("server.c");
    std::fs::write(&source, SERVER_C).unwrap();
    let work = root.join("work");
    let generated = work.join("generated_harnesses");
    step(
        &[
            "generate-harness".as_ref(),
            "--target".as_ref(),
            "serve".as_ref(),
            "--id".as_ref(),
            "H-SERVE".as_ref(),
            "--output".as_ref(),
            generated.as_os_str(),
            source.as_os_str(),
        ],
        &[],
    );
    step(
        &[
            "build".as_ref(),
            work.as_os_str(),
            "--harness".as_ref(),
            "H-SERVE".as_ref(),
        ],
        &[],
    );
    // A well-formed record with room behind it: the fuzzer only has to raise
    // its length byte past the field.
    let seed = root.join("seed.bin");
    let mut record = b"R:\x04abcd".to_vec();
    record.resize(32, b'.');
    std::fs::write(&seed, record).unwrap();
    let fuzz = step(
        &[
            "fuzz".as_ref(),
            work.as_os_str(),
            "--harness".as_ref(),
            "H-SERVE".as_ref(),
            "--runtime-oracles".as_ref(),
            "on".as_ref(),
            "--seed-file".as_ref(),
            seed.as_os_str(),
            "--time".as_ref(),
            "30s".as_ref(),
        ],
        &[("BHF_DESOCKET", "1")],
    );
    let stderr = String::from_utf8_lossy(&fuzz.stderr);

    let findings_dir = work.join("results").join("findings");
    let overflow = std::fs::read_dir(&findings_dir)
        .unwrap_or_else(|e| panic!("{}: {e}\n{stderr}", findings_dir.display()))
        .flatten()
        .map(|entry| entry.path())
        .find(|dir| {
            std::fs::read_to_string(dir.join("finding.json")).is_ok_and(|finding| {
                finding.contains("stack-buffer-overflow") && finding.contains("parse_record")
            })
        })
        .unwrap_or_else(|| {
            panic!(
                "the record parser's overflow is found through the server's accept loop:\n{stderr}"
            )
        });

    // The finding records the mode it ran under, so it replays in a clean
    // environment: without the gate the server would bind a real port and
    // wait in accept until the replay timed out.
    let finding: serde_json::Value =
        serde_json::from_slice(&std::fs::read(overflow.join("finding.json")).unwrap()).unwrap();
    assert_eq!(
        finding["shim_env"],
        serde_json::json!({"BHF_DESOCKET": "1"}),
        "{finding:#}"
    );
    let replay_py = std::fs::read_to_string(overflow.join("replay.py")).unwrap();
    assert!(
        replay_py.contains(r#"EXTRA_ENV = {"BHF_DESOCKET":"1"}"#),
        "{replay_py}"
    );
    let replay = bhf()
        .arg("replay")
        .arg(&overflow)
        .env_remove("BHF_DESOCKET")
        .output()
        .expect("run bhf replay");
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
    // Its capsule carries the mode too: verify-poc replays it under the shim.
    let id = overflow.file_name().unwrap().to_str().unwrap().to_owned();
    let capsules = root.join("capsules");
    let packaged = bhf()
        .args(["capsule", "--work-dir"])
        .arg(&work)
        .args(["--finding-id", &id, "-o"])
        .arg(&capsules)
        .env_remove("BHF_DESOCKET")
        .output()
        .expect("run bhf capsule");
    assert!(
        packaged.status.success(),
        "{}",
        String::from_utf8_lossy(&packaged.stderr)
    );
    let capsule = capsules.join(format!("capsule_{id}"));
    let verified = bhf()
        .arg("verify-poc")
        .arg(&capsule)
        .env_remove("BHF_DESOCKET")
        .output()
        .expect("run bhf verify-poc");
    let verdict = String::from_utf8_lossy(&verified.stdout);
    assert!(
        verified.status.success() && verdict.contains("verify-poc: PASS"),
        "{verdict}\n{}",
        String::from_utf8_lossy(&verified.stderr)
    );

    let run: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work.join("fuzz_runs").join("H-SERVE-latest.json"))
            .unwrap_or_else(|e| panic!("fuzz run record: {e}\n{stderr}")),
    )
    .unwrap();
    assert_eq!(run["execution"]["forkserver"], true, "{run:#}");
    assert_eq!(run["execution"]["persistent"], true, "{run:#}");
}

/// The persistent process outlives each input's end: the harness runs it in
/// a forked child, so the server's second `accept` ends the child and the
/// framed loop answers the next input. Without that the first input's exit
/// would close the sync channel.
#[test]
fn the_framed_harness_survives_each_desocketed_input() {
    use std::io::{Read, Write};
    if Command::new("cc").arg("--version").output().is_err() {
        eprintln!("skipping: no C compiler on PATH");
        return;
    }
    let Some(target) = shim() else {
        eprintln!("skipping: the runtrace shim is not built");
        return;
    };
    let root = TestDir::new("desocket-framed");
    let source = root.join("server.c");
    std::fs::write(&source, SERVER_C).unwrap();
    let work = root.join("work");
    let generated = work.join("generated_harnesses");
    step(
        &[
            "generate-harness".as_ref(),
            "--target".as_ref(),
            "serve".as_ref(),
            "--id".as_ref(),
            "H-FRAMED".as_ref(),
            "--output".as_ref(),
            generated.as_os_str(),
            source.as_os_str(),
        ],
        &[],
    );
    step(
        &[
            "build".as_ref(),
            work.as_os_str(),
            "--harness".as_ref(),
            "H-FRAMED".as_ref(),
        ],
        &[],
    );
    let mut child = Command::new(work.join("build/H-FRAMED/main"))
        .env("BHF_FRAMED", "1")
        .env("BHF_DESOCKET", "1")
        .env("LD_PRELOAD", target.join("libbhf_runtrace_shim.so"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("start the framed harness");
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut byte = [0u8; 1];
    stdout.read_exact(&mut byte).expect("ready byte");
    for record in [&b"R:\x02ok"[..], b"R:\x03yes", b"R:\x01!"] {
        stdin
            .write_all(&(record.len() as u32).to_le_bytes())
            .unwrap();
        stdin.write_all(record).unwrap();
        stdin.flush().unwrap();
        stdout
            .read_exact(&mut byte)
            .unwrap_or_else(|e| panic!("no sync byte after {record:?}: {e}"));
    }
    drop(stdin);
    assert!(child.wait().unwrap().success());
}
