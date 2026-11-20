// SPDX-License-Identifier: Apache-2.0

//! `bhf fuzz --frame`: a single-input harness fuzzed through a frame
//! descriptor, driven against the event-log fake harness, whose planted bug
//! sits behind the length and CRC-32 check of a `[u16 BE length][OPEN
//! <path>][u32 BE CRC-32]` frame (`frame.adb`, an OPEN path longer than 8).
//!
//! - with the frame's profile, every mutant's length and CRC are recomputed,
//!   and the bug is reached within a fixed number of executions that plain
//!   byte mutation of the same seed does not reach it in (#328);
//! - a profile the single-input loop cannot apply, and `--frame` with an
//!   engine that would ignore it, are refused before the campaign starts.

#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

const HARNESS: &str = "H-TEST";

/// The executions both campaigns get.
const EXECUTIONS: usize = 300;

/// The fake harness's frame as a `bhf.protocol.v1` profile of one message.
const FRAME_PROFILE: &str = r#"
schema = "bhf.protocol.v1"

[[message]]
name = "open"

[[message.field]]
name = "length"
type = "u16"
endian = "big"
computed = "length(payload)"

[[message.field]]
name = "payload"
type = "bytes"
max = 64
value = "OPEN track"

[[message.field]]
name = "crc"
type = "u32"
endian = "big"
computed = "crc32(payload)"
"#;

/// A work dir with the fake harness installed as `H-TEST`.
fn work_with_harness(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let work = dir.join("bhf_work");
    let target = work.join("build").join(HARNESS).join("obj").join("main");
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_cli_fake_harness"), &target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
    work
}

/// `bhf fuzz` on `H-TEST` for [`EXECUTIONS`] from `seed`, with `extra` flags.
fn fuzz(work: &Path, seed: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("fuzz")
        .arg(work)
        .args(["--harness", HARNESS, "--iterations"])
        .arg(EXECUTIONS.to_string())
        .arg("--seed-file")
        .arg(seed)
        .args(["--rng-seed", "1"])
        .args(extra)
        .output()
        .expect("run bhf fuzz")
}

fn assert_ran(output: &Output) {
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// `[u16 BE length][payload][u32 BE CRC-32]`.
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = (payload.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(payload);
    out.extend_from_slice(&crc32(payload).to_be_bytes());
    out
}

/// The payload of a frame whose length and CRC are right.
fn valid_payload(bytes: &[u8]) -> Option<&[u8]> {
    let crc_at = bytes.len().checked_sub(4)?;
    let payload = bytes.get(2..crc_at)?;
    let declared = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
    let stored = u32::from_be_bytes(bytes[crc_at..].try_into().ok()?);
    (declared == payload.len() && stored == crc32(payload)).then_some(payload)
}

/// The testcases of the planted `frame.adb` bug's findings under `work`.
fn frame_bug_testcases(work: &Path) -> Vec<Vec<u8>> {
    let Ok(entries) = fs::read_dir(work.join("results/findings")) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|entry| {
            fs::read(entry.path().join("finding.json"))
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                .is_some_and(|finding| {
                    finding["exception"]["message"]
                        .as_str()
                        .is_some_and(|message| message.contains("frame.adb"))
                })
        })
        .filter_map(|entry| fs::read(entry.path().join("testcase.bin")).ok())
        .collect()
}

fn executions(work: &Path) -> u64 {
    let path = work
        .join("fuzz_runs")
        .join(format!("{HARNESS}-latest.json"));
    let run: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    run["executions"].as_u64().unwrap()
}

#[test]
fn a_post_crc_bug_is_reached_within_a_fixed_exec_count_only_with_frame() {
    let dir = TestDir::new("fuzz-frame-crc");
    let seed = dir.join("seed");
    fs::write(&seed, frame(b"OPEN track")).unwrap();
    let profile = dir.join("frame.toml");
    fs::write(&profile, FRAME_PROFILE).unwrap();

    let plain = work_with_harness(&dir.join("plain"));
    assert_ran(&fuzz(&plain, &seed, &[]));
    assert_eq!(executions(&plain), EXECUTIONS as u64);
    assert!(
        frame_bug_testcases(&plain).is_empty(),
        "byte mutation of the frame breaks its length or CRC, so the bug stays unreached"
    );

    let framed = work_with_harness(&dir.join("framed"));
    let output = fuzz(&framed, &seed, &["--frame", profile.to_str().unwrap()]);
    assert_ran(&output);
    assert_eq!(executions(&framed), EXECUTIONS as u64);
    let reached = frame_bug_testcases(&framed);
    assert!(
        !reached.is_empty(),
        "with --frame every mutant keeps its length and CRC right, and one lengthens the \
         path past 8 bytes within {EXECUTIONS} executions\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for testcase in &reached {
        let payload = valid_payload(testcase)
            .unwrap_or_else(|| panic!("the reproducer is a valid frame: {testcase:?}"));
        let path = payload
            .strip_prefix(b"OPEN ")
            .unwrap_or_else(|| panic!("an OPEN payload: {payload:?}"));
        assert!(path.len() > 8, "{payload:?}");
        assert!(payload.len() <= 64, "within the payload's max: {payload:?}");
    }
}

#[test]
fn a_profile_the_single_input_loop_cannot_apply_is_refused() {
    let dir = TestDir::new("fuzz-frame-refused");
    let seed = dir.join("seed");
    fs::write(&seed, frame(b"OPEN track")).unwrap();
    let work = work_with_harness(&dir);
    let cases = [
        (
            "two-messages.toml",
            format!("{FRAME_PROFILE}\n[[message]]\nname = \"close\"\n"),
            "declares 2 (open, close)",
        ),
        (
            "optional.toml",
            format!(
                "{FRAME_PROFILE}\n[[message.field]]\nname = \"note\"\ntype = \"bytes\"\n\
                 optional = true\n"
            ),
            "\"note\" is optional",
        ),
        (
            "bad-cover.toml",
            FRAME_PROFILE.replace("crc32(payload)", "crc32(nothing)"),
            "nothing",
        ),
    ];
    for (name, text, expected) in cases {
        let profile = dir.join(name);
        fs::write(&profile, text).unwrap();
        let output = fuzz(&work, &seed, &["--frame", profile.to_str().unwrap()]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{name}: {stderr}");
        assert!(
            stderr.contains("--frame") && stderr.contains(expected),
            "{name}: {stderr}"
        );
    }
    assert!(
        !work.join("fuzz_runs").exists(),
        "no campaign ran for a refused profile"
    );
}

#[test]
fn frame_with_another_engine_is_refused() {
    let dir = TestDir::new("fuzz-frame-engine");
    let seed = dir.join("seed");
    fs::write(&seed, frame(b"OPEN track")).unwrap();
    let profile = dir.join("frame.toml");
    fs::write(&profile, FRAME_PROFILE).unwrap();
    let work = work_with_harness(&dir);
    let output = fuzz(
        &work,
        &seed,
        &[
            "--frame",
            profile.to_str().unwrap(),
            "--engine",
            "libfuzzer",
        ],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("--frame") && stderr.contains("--engine libfuzzer"),
        "{stderr}"
    );
}
