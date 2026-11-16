// SPDX-License-Identifier: Apache-2.0

//! `bhf fuzz --target-transport` and `--protocol-profile` drive their own
//! loops and used to drop host-lane flags without a word: a `--workers 4
//! --grammar g.json` campaign ran one blind mutator, and a `--grammar` that
//! did not exist was accepted. Each flag a lane does not wire is now refused
//! with exit 2, naming it; the flags it does wire still run.

use std::process::{Command, Output};

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// Host-lane flags neither lane wires, each with the arguments that set it.
const HOST_ONLY: &[(&str, &[&str])] = &[
    ("--workers", &["--workers", "2"]),
    ("--grammar", &["--grammar", "/nonexistent/grammar.json"]),
    ("--cmplog-log", &["--cmplog-log", "cmplog.txt"]),
    ("--len-control", &["--len-control", "5"]),
    ("--rss-limit-mb", &["--rss-limit-mb", "128"]),
    ("--fork-server", &["--fork-server"]),
    ("--no-fork-server", &["--no-fork-server"]),
    ("--qemu-user", &["--qemu-user", "qemu-arm"]),
    (
        "--qemu-arg",
        &["--qemu-user", "qemu-arm", "--qemu-arg", "-L"],
    ),
    ("--extension", &["--extension", "ext.toml"]),
    ("--sanitizers", &["--sanitizers", "asan"]),
    (
        "--symbolic-seed-source",
        &["--symbolic-seed-source", "p.adb"],
    ),
    ("--sandbox", &["--sandbox", "none"]),
    (
        "--sandbox-tool",
        &["--sandbox", "firejail", "--sandbox-tool", "fj"],
    ),
    ("--sandbox-strict", &["--sandbox-strict"]),
    ("--runtime-oracles", &["--runtime-oracles", "auto"]),
    ("--structured-inputs", &["--structured-inputs", "json"]),
    ("--print-final-stats", &["--print-final-stats"]),
    ("--collector", &["--collector", "auto"]),
    ("--collector-window-ms", &["--collector-window-ms", "10"]),
];

/// Flags only the session lane does not wire.
const SESSION_ONLY: &[(&str, &[&str])] = &[
    ("--seed-input", &["--seed-input", "A"]),
    ("--seed-file", &["--seed-file", "seed.bin"]),
    ("--max-len", &["--max-len", "32"]),
    ("--timeout", &["--timeout", "1s"]),
    ("--deadline", &["--deadline", "1s"]),
    (
        "--transport-coverage-map",
        &["--transport-coverage-map", "input=1"],
    ),
];

/// Flags only the transport lane does not wire.
const TRANSPORT_ONLY: &[(&str, &[&str])] = &[
    ("--protocol-profile", &["--protocol-profile", "p.toml"]),
    (
        "--session-transport",
        &["--session-transport", "tcp:127.0.0.1:9"],
    ),
    ("--session-reset", &["--session-reset", "none"]),
    ("--max-session-messages", &["--max-session-messages", "3"]),
];

const TRANSPORT: &[&str] = &["--target-transport", "agent:tcp:127.0.0.1:9"];
const SESSION: &[&str] = &["--protocol-profile", "missing-profile.toml"];

fn fuzz(work: &TestDir, lane: &[&str], extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
        .current_dir(work.path())
        .args(["fuzz", "bhf_work", "--harness", "h"])
        .args(lane)
        .args(extra)
        .output()
        .expect("run bhf fuzz")
}

fn assert_refused(lane_name: &str, lane: &[&str], cases: &[(&str, &[&str])]) {
    let work = TestDir::new("lane-flag-conflicts");
    for (flag, args) in cases {
        let out = fuzz(&work, lane, args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{lane_name} {flag}: {stderr}");
        assert!(
            stderr.contains(&format!("{flag},")) || stderr.contains(&format!("{flag} ")),
            "{lane_name} {flag}: the refusal names the flag: {stderr}"
        );
        assert!(stderr.contains("not apply"), "{lane_name} {flag}: {stderr}");
    }
}

#[test]
fn the_transport_lane_refuses_each_flag_it_does_not_wire() {
    assert_refused("--target-transport", TRANSPORT, HOST_ONLY);
    assert_refused("--target-transport", TRANSPORT, TRANSPORT_ONLY);
}

#[test]
fn the_session_lane_refuses_each_flag_it_does_not_wire() {
    assert_refused("--protocol-profile", SESSION, HOST_ONLY);
    assert_refused("--protocol-profile", SESSION, SESSION_ONLY);
}

#[test]
fn several_ignored_flags_are_named_together() {
    let work = TestDir::new("lane-flag-conflicts-many");
    let out = fuzz(
        &work,
        TRANSPORT,
        &[
            "--workers",
            "4",
            "--grammar",
            "g.json",
            "--cmplog-log",
            "c.txt",
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("--workers, --cmplog-log, --grammar")
            || stderr.contains("--workers, --grammar, --cmplog-log"),
        "{stderr}"
    );
}

/// The flags a lane wires get past the check: the run goes on to its own
/// work (and fails there, with no target to reach).
#[test]
fn the_flags_each_lane_wires_still_run() {
    let work = TestDir::new("lane-flag-conflicts-supported");
    let transport = fuzz(
        &work,
        TRANSPORT,
        &[
            "--seed-input",
            "AB",
            "--max-len",
            "32",
            "--timeout",
            "1s",
            "--time",
            "1s",
            "--iterations",
            "4",
            "--rng-seed",
            "7",
        ],
    );
    let session = fuzz(
        &work,
        SESSION,
        &[
            "--session-transport",
            "tcp:127.0.0.1:9",
            "--session-reset",
            "none",
            "--max-session-messages",
            "8",
            "--time",
            "1s",
            "--iterations",
            "4",
        ],
    );
    for (lane, out) in [("transport", transport), ("session", session)] {
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!stderr.contains("not apply"), "{lane}: {stderr}");
    }
}
