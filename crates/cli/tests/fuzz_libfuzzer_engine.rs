// SPDX-License-Identifier: Apache-2.0
//
// #294: `bhf fuzz --engine libfuzzer` runs the harness's libFuzzer build,
// building `main_libfuzzer` with `make libfuzzer` when there is none, and
// records the crash it saves as a finding that `bhf replay` reproduces.
// Needs clang with libFuzzer; `BHF_REQUIRE_TOOLS=1` makes a missing one a
// failure.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// Whether clang links a libFuzzer target.
fn have_libfuzzer(dir: &Path) -> bool {
    let probe = dir.join("probe.c");
    std::fs::write(
        &probe,
        "#include <stddef.h>\n#include <stdint.h>\n\
         int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { (void)d; (void)n; return 0; }\n",
    )
    .unwrap();
    let present = Command::new("clang")
        .arg("-fsanitize=fuzzer")
        .arg(&probe)
        .arg("-o")
        .arg(dir.join("probe"))
        .output()
        .is_ok_and(|out| out.status.success());
    support::require_tool(present, "clang with libFuzzer")
}

fn bhf(args: &[&str]) -> std::process::Output {
    Command::new(PathBuf::from(env!("CARGO_BIN_EXE_bhf")))
        .args(args)
        .output()
        .expect("run bhf")
}

#[test]
fn the_libfuzzer_engine_finds_the_overflow_and_its_finding_replays() {
    let scratch = TestDir::new("libfuzzer-engine");
    if !have_libfuzzer(scratch.path()) {
        eprintln!("SKIP: clang with libFuzzer is not installed");
        return;
    }
    let source = scratch.join("rec.c");
    std::fs::write(
        &source,
        "#include <string.h>\n\
         int parse_rec(const unsigned char *buf, unsigned long len) {\n\
         \x20   char tmp[8];\n\
         \x20   if (len < 2 || buf[0] != 'R')\n\
         \x20       return -1;\n\
         \x20   memcpy(tmp, buf, len);\n\
         \x20   return tmp[1];\n\
         }\n",
    )
    .unwrap();
    let work = scratch.join("work");
    let generated = bhf(&[
        "generate-harness",
        source.to_str().unwrap(),
        "--target",
        "parse_rec",
        "--output",
        work.join("harnesses").to_str().unwrap(),
        "--id",
        "H-LF",
    ]);
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let out = bhf(&[
        "fuzz",
        work.to_str().unwrap(),
        "--harness",
        "H-LF",
        "--engine",
        "libfuzzer",
        "--time",
        "20s",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("make libfuzzer"), "{stderr}");
    let summary: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(summary["engine"], "libfuzzer", "{summary:#}");
    assert!(
        summary["executions"].as_u64().unwrap_or(0) > 0,
        "{summary:#}"
    );
    let id = summary["findings"][0]
        .as_str()
        .unwrap_or_else(|| panic!("no finding: {summary:#}\n{stderr}"))
        .to_owned();
    let finding = work.join("results/findings").join(&id);
    let record = std::fs::read_to_string(finding.join("finding.json")).unwrap();
    assert!(record.contains("found by libFuzzer"), "{record}");
    assert!(record.contains("main_libfuzzer"), "{record}");

    let replay = bhf(&["replay", finding.to_str().unwrap()]);
    let replayed = String::from_utf8_lossy(&replay.stdout);
    assert!(
        replayed.contains("MATCH") && !replayed.contains("MISMATCH"),
        "{replayed}\n{}",
        String::from_utf8_lossy(&replay.stderr)
    );
}

/// #342: libFuzzer times `-timeout` in the harness process, with the clock
/// the runtrace shim fakes under `BHF_FAKE_CLOCK=1`. The engine keeps the
/// real clock for its children, so a hang is still caught at the per-input
/// timeout instead of running until bhf's backstop stops the campaign.
#[test]
fn a_hang_is_found_with_the_libfuzzer_engine_under_the_fake_clock() {
    let scratch = TestDir::new("libfuzzer-fake-clock");
    if !have_libfuzzer(scratch.path()) {
        eprintln!("SKIP: clang with libFuzzer is not installed");
        return;
    }
    let shim = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"))
        .join("debug/libbhf_runtrace_shim.so");
    if !support::require_tool(
        shim.is_file(),
        "the runtrace shim (cargo build --workspace)",
    ) {
        eprintln!("SKIP: the runtrace shim is not built");
        return;
    }
    let source = scratch.join("spin.c");
    std::fs::write(
        &source,
        "static volatile unsigned long spins;\n\
         int spin_on(const unsigned char *buf, unsigned long len) {\n\
         \x20   if (len > 0 && buf[0] == 'H')\n\
         \x20       for (;;) spins++;\n\
         \x20   return 0;\n\
         }\n",
    )
    .unwrap();
    let work = scratch.join("work");
    let generated = bhf(&[
        "generate-harness",
        source.to_str().unwrap(),
        "--target",
        "spin_on",
        "--output",
        work.join("harnesses").to_str().unwrap(),
        "--id",
        "H-SPIN",
    ]);
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let seed = scratch.join("seed.bin");
    std::fs::write(&seed, b"H").unwrap();
    let started = std::time::Instant::now();
    let out = Command::new(PathBuf::from(env!("CARGO_BIN_EXE_bhf")))
        .args(["fuzz", work.to_str().unwrap(), "--harness", "H-SPIN"])
        .args(["--engine", "libfuzzer", "--runtime-oracles", "on"])
        .args(["--seed-file", seed.to_str().unwrap()])
        .args(["--time", "10s", "--timeout", "2"])
        .env("BHF_RUNTRACE_SHIM", &shim)
        .env("BHF_FAKE_CLOCK", "1")
        .output()
        .expect("run bhf");
    let elapsed = started.elapsed();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("BHF_FAKE_CLOCK=1 is ignored with --engine libfuzzer"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("ran past its time budget"),
        "libFuzzer timed the hang out itself: {stderr}"
    );
    let summary: serde_json::Value =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|error| panic!("{error}: {stderr}"));
    let id = summary["findings"][0]
        .as_str()
        .unwrap_or_else(|| panic!("the hang is a finding: {summary:#}\n{stderr}"));
    let record: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work.join("results/findings").join(id).join("finding.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(record["rule_id"], "BHF-230", "{record:#}");
    assert!(
        elapsed < std::time::Duration::from_secs(45),
        "{elapsed:?}: {stderr}"
    );
}

/// `bhf auto` refuses the engine rather than running builtin passes instead.
#[test]
fn bhf_auto_refuses_the_libfuzzer_engine() {
    let scratch = TestDir::new("libfuzzer-engine-auto");
    let out = bhf(&["auto", scratch.to_str().unwrap(), "--engine", "libfuzzer"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("bhf fuzz --engine libfuzzer"), "{stderr}");
}
