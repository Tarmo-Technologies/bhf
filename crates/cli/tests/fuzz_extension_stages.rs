// SPDX-License-Identifier: Apache-2.0

//! The extension stages of `bhf fuzz --extension`'s builtin loop, driven with
//! the `bhf_ext_mock` sidecar against the event-log fake harness:
//!
//! - an extension's `mutator.mutate` reaches a gate the builtin mutator does
//!   not, and a slow one is cut off while the campaign goes on (#314);
//! - its codec keeps a framed input's length and CRC right through a
//!   mutation, so a bug behind the CRC check is reached only with it, and
//!   its decode errors are counted, not findings (#373).

#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

const HARNESS: &str = "H-TEST";

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

/// A manifest for the mock extension in `mode`, with a per-call timeout.
fn manifest(dir: &Path, mode: &str, call_timeout_ms: u64) -> PathBuf {
    let text = format!(
        "schema = \"bhf.extension-manifest.v1\"\n\
         id = \"mock-extension\"\n\
         executable = {exe:?}\n\
         args = [\"--mode\", {mode:?}]\n\
         required-capabilities = [\"oracle.evaluate\"]\n\
         allow-external-paths = true\n\
         \n\
         [limits]\n\
         call-timeout-ms = {call_timeout_ms}\n",
        exe = env!("CARGO_BIN_EXE_bhf_ext_mock"),
    );
    let path = dir.join(format!("extension-{mode}.toml"));
    fs::write(&path, text).unwrap();
    path
}

/// `bhf fuzz` on `H-TEST` for `iterations` from `seed`, with `extension`.
fn fuzz(work: &Path, iterations: usize, seed: &Path, extension: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bhf"));
    command
        .arg("fuzz")
        .arg(work)
        .args(["--harness", HARNESS, "--iterations"])
        .arg(iterations.to_string())
        .arg("--seed-file")
        .arg(seed)
        .args(["--rng-seed", "1"]);
    if let Some(extension) = extension {
        command.arg("--extension").arg(extension);
    }
    command.output().expect("run bhf fuzz")
}

fn summary(work: &Path) -> Value {
    let path = work
        .join("fuzz_runs")
        .join(format!("{HARNESS}-latest.json"));
    serde_json::from_slice(&fs::read(&path).unwrap()).unwrap()
}

/// The findings of the fake harness's planted bug `marker` (`magic.adb`,
/// `frame.adb`) under `work`: the harness reports a handled exception for
/// any other input, which is a finding too.
fn planted(work: &Path, marker: &str) -> Vec<Value> {
    let Ok(entries) = fs::read_dir(work.join("results/findings")) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| fs::read(entry.path().join("finding.json")).ok())
        .map(|bytes| serde_json::from_slice::<Value>(&bytes).unwrap())
        .filter(|finding| {
            finding["exception"]["message"]
                .as_str()
                .is_some_and(|message| message.contains(marker))
        })
        .collect()
}

fn assert_ran(output: &Output) {
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `[u16 BE length][payload][u32 BE CRC-32]`, the mock's toy frame.
fn frame(payload: &[u8]) -> Vec<u8> {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in payload {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    let mut out = (payload.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(payload);
    out.extend_from_slice(&(!crc).to_be_bytes());
    out
}

#[test]
fn an_extension_mutation_reaches_a_gate_the_builtin_mutator_does_not() {
    let dir = TestDir::new("ext-stage-magic");
    let seed = dir.join("seed");
    fs::write(&seed, b"AAAA").unwrap();

    let plain = work_with_harness(&dir.join("plain"));
    assert_ran(&fuzz(&plain, 200, &seed, None));
    assert!(
        planted(&plain, "magic.adb").is_empty(),
        "200 builtin mutations of AAAA do not spell the magic"
    );

    let work = work_with_harness(&dir.join("extension"));
    let ext = manifest(&dir, "magic-mutator", 5000);
    assert_ran(&fuzz(&work, 200, &seed, Some(&ext)));
    let stages = &summary(&work)["extension"]["stages"];
    assert!(stages["mutated"].as_u64() > Some(0), "{stages:#}");
    assert!(stages["cut_off"].is_null(), "{stages:#}");
    assert!(
        !planted(&work, "magic.adb").is_empty(),
        "the extension's mutation reaches the gated bug: {stages:#}"
    );
}

#[test]
fn a_slow_extension_mutator_is_cut_off_and_the_campaign_goes_on() {
    let dir = TestDir::new("ext-stage-slow");
    let seed = dir.join("seed");
    fs::write(&seed, b"AAAA").unwrap();
    let work = work_with_harness(&dir);
    // The mock's mutator sleeps 30 s; each call may take 300 ms.
    let ext = manifest(&dir, "slow-mutator", 300);
    let started = std::time::Instant::now();
    let output = fuzz(&work, 60, &seed, Some(&ext));
    assert_ran(&output);
    let run = summary(&work);
    let stages = &run["extension"]["stages"];
    assert_eq!(
        stages["calls"], 1,
        "cut off at its first timeout: {stages:#}"
    );
    assert!(
        stages["cut_off"]
            .as_str()
            .is_some_and(|reason| reason.contains("mutator.mutate failed")),
        "{stages:#}"
    );
    assert_eq!(
        run["executions"], 60,
        "the campaign ran every case: {run:#}"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(25),
        "one timeout, not one per child: {:?}",
        started.elapsed()
    );
}

#[test]
fn the_codec_stage_keeps_a_frame_valid_and_reaches_the_bug_behind_its_crc() {
    let dir = TestDir::new("ext-stage-codec");
    let seed = dir.join("seed");
    fs::write(&seed, frame(b"OPEN track")).unwrap();

    let plain = work_with_harness(&dir.join("plain"));
    assert_ran(&fuzz(&plain, 300, &seed, None));
    assert!(
        planted(&plain, "frame.adb").is_empty(),
        "a raw mutation of the frame breaks its CRC"
    );

    let work = work_with_harness(&dir.join("codec"));
    let ext = manifest(&dir, "codec-only", 5000);
    assert_ran(&fuzz(&work, 300, &seed, Some(&ext)));
    let stages = &summary(&work)["extension"]["stages"];
    assert!(stages["encoded"].as_u64() > Some(0), "{stages:#}");
    assert!(
        !planted(&work, "frame.adb").is_empty(),
        "a codec mutation lengthens the path inside a valid frame: {stages:#}"
    );
}

#[test]
fn codec_errors_are_counted_and_are_no_findings() {
    let dir = TestDir::new("ext-stage-codec-errors");
    let seed = dir.join("seed");
    fs::write(&seed, b"not a frame").unwrap();
    let work = work_with_harness(&dir);
    let ext = manifest(&dir, "codec-only", 5000);
    assert_ran(&fuzz(&work, 80, &seed, Some(&ext)));
    let run = summary(&work);
    let stages = &run["extension"]["stages"];
    assert!(stages["codec_errors"].as_u64() > Some(0), "{stages:#}");
    assert_eq!(stages["encoded"], 0, "{stages:#}");
    assert!(
        stages["cut_off"].is_null(),
        "a decode reject is no fault: {stages:#}"
    );
    assert!(planted(&work, "frame.adb").is_empty(), "{run:#}");
}
