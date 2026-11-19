// SPDX-License-Identifier: Apache-2.0

//! `bhf fuzz --differential-harness` (#345): the builtin engine runs every
//! input it executes through a second build of the harness as well, compares
//! the two builds' outcomes and what each observed (the target's return value
//! and the bytes it hands `bhf_diff_observe`), and reports a disagreement it
//! can reproduce in fresh processes as a BHF-301 divergence finding.
#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn clang_runs() -> bool {
    let present = Command::new("clang")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success());
    support::require_tool(present, "clang")
}

/// A record checksum. `VARIANT` selects how the build treats a record whose
/// tag is `Z`: 0 the same as any other, 1 folds one more bit into the
/// checksum it observes, 2 returns a different status, 3 copies a record
/// longer than four bytes past a buffer, 6 takes 1.4 s over the record `Zed`
/// first. Variant 4 observes how many records the process parsed instead,
/// for a record tagged `Q`, and crashes on one of five bytes; 7 does the
/// same without the crash; 5 returns its process id. The checksum goes to `bhf_diff_observe`, which a
/// build without bhf's driver does not have.
const TARGET: &str = r#"
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
extern void bhf_diff_observe(const void *data, size_t len) __attribute__((weak));
__attribute__((noinline)) static void copy_at(char *dst, const uint8_t *src, size_t n) {
    memcpy(dst, src, n);
}
static uint32_t parsed;
int bhf_run_one(const uint8_t *data, size_t size) {
    uint32_t sum = 0;
    for (size_t i = 0; i < size; i++) sum = sum * 31u + data[i];
    int tagged = size > 0 && data[0] == 'Z';
    parsed++;
#if VARIANT == 4 || VARIANT == 7
    if (size > 0 && data[0] == 'Q') {
#if VARIANT == 4
        if (size == 5) {
            volatile char *none = 0;
            *none = 1;
        }
#endif
        if (bhf_diff_observe) bhf_diff_observe(&parsed, sizeof parsed);
    }
    return 0;
#endif
#if VARIANT == 5
    return (int)(getpid() & 0x7fff);
#endif
#if VARIANT == 6
    if (size == 3 && memcmp(data, "Zed", 3) == 0) usleep(1400000);
#endif
#if VARIANT == 1
    if (tagged) sum ^= 1u;
#endif
#if VARIANT == 3
    if (tagged && size > 4) {
        char name[4];
        copy_at(name, data, size);
        sum += (uint32_t)name[0];
    }
#endif
    if (bhf_diff_observe) bhf_diff_observe(&sum, sizeof sum);
#if VARIANT == 2
    return tagged;
#else
    return 0;
#endif
}
"#;

/// Build the target with bhf's driver as `<dir>/<name>`, with `VARIANT`.
fn build(dir: &Path, name: &str, variant: u32) -> PathBuf {
    fs::create_dir_all(dir).unwrap();
    let source = dir.join("target.c");
    fs::write(&source, TARGET).unwrap();
    let driver = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime/bhf_driver.c");
    let out = dir.join(name);
    let built = Command::new("clang")
        .current_dir(dir)
        .args([
            "-O1",
            "-g",
            "-fsanitize=address",
            "-fsanitize-coverage=trace-pc-guard,trace-cmp",
        ])
        .arg(format!("-DVARIANT={variant}"))
        .arg("-o")
        .arg(&out)
        .arg(&source)
        .arg(&driver)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    out
}

/// `bhf fuzz` of harness `H-DIFF` in `work` with `--differential-harness`
/// `peer`, from `seed`, for 300 iterations or as `extra` says.
fn fuzz(work: &Path, peer: &Path, seed: &str, extra: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bhf"));
    command
        .arg("fuzz")
        .arg(work)
        .args(["--harness", "H-DIFF", "--quiet", "--seed-input", seed]);
    if !extra.contains(&"--iterations") {
        command.args(["--iterations", "300"]);
    }
    command
        .args(extra)
        .arg("--differential-harness")
        .arg(peer)
        .output()
        .unwrap()
}

/// `bhf fuzz` of harness `H-DIFF` (variant 0) with `--differential-harness`
/// set to a build of `variant`, from `seed`.
fn fuzz_against(root: &Path, variant: u32, seed: &str) -> (PathBuf, Output) {
    let work = root.join("work");
    build(&work.join("harnesses").join("H-DIFF"), "main", 0);
    let peer = build(&root.join("peer"), "main_b", variant);
    let output = fuzz(&work, &peer, seed, &[]);
    (work, output)
}

/// `bhf fuzz` of harness `H-DIFF`, a build of `variant`, with
/// `--differential-harness` set to a byte-identical copy of it.
fn fuzz_against_a_copy(root: &Path, variant: u32, seed: &str, extra: &[&str]) -> (PathBuf, Output) {
    let work = root.join("work");
    let main = build(&work.join("harnesses").join("H-DIFF"), "main", variant);
    let peer_dir = root.join("peer");
    fs::create_dir_all(&peer_dir).unwrap();
    let peer = peer_dir.join("main_b");
    fs::copy(&main, &peer).unwrap();
    let output = fuzz(&work, &peer, seed, extra);
    (work, output)
}

fn log(output: &Output) -> String {
    format!(
        "status {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// The run's printed summary.
fn summary(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|_| panic!("{}", log(output)))
}

/// Every finding.json under the work dir's findings.
fn findings(work: &Path) -> Vec<(PathBuf, serde_json::Value)> {
    let mut found = Vec::new();
    for entry in fs::read_dir(work.join("results").join("findings"))
        .into_iter()
        .flatten()
        .flatten()
    {
        let path = entry.path().join("finding.json");
        if let Ok(bytes) = fs::read(&path) {
            found.push((entry.path(), serde_json::from_slice(&bytes).unwrap()));
        }
    }
    found
}

fn divergences(work: &Path) -> Vec<(PathBuf, serde_json::Value)> {
    findings(work)
        .into_iter()
        .filter(|(_, record)| record["rule_id"] == "BHF-301")
        .collect()
}

#[test]
fn disagreeing_builds_give_a_divergence_finding() {
    if !clang_runs() {
        eprintln!("skipping: clang unavailable");
        return;
    }
    let root = TestDir::new("fuzz-diff-observed");
    let (work, output) = fuzz_against(&root, 1, "Zed");
    assert!(output.status.success(), "{}", log(&output));
    let found = divergences(&work);
    assert_eq!(found.len(), 1, "{}\n{found:#?}", log(&output));
    let (dir, record) = &found[0];
    assert_eq!(record["oracle"]["name"], "differential-output-runtime");
    assert_eq!(record["harness_id"], "H-DIFF");
    let diff = &record["differential"];
    assert_eq!(diff["mode"], "in_loop", "{record:#}");
    assert_eq!(diff["divergence"], "observation", "{record:#}");
    assert_eq!(diff["outcome_a"], "clean");
    assert_eq!(diff["outcome_b"], "clean");
    assert_ne!(diff["observation_a"]["hash"], diff["observation_b"]["hash"]);
    assert_eq!(diff["observation_a"]["observations"], 1);
    assert!(
        diff["harness_b"].as_str().unwrap().ends_with("main_b"),
        "{diff}"
    );
    let input = fs::read(dir.join("testcase.bin")).unwrap();
    assert_eq!(input.first(), Some(&b'Z'), "{input:?}");

    let summary = summary(&output);
    assert!(
        summary["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|id| *id == record["id"]),
        "{summary:#}"
    );
    let run = &summary["differential"];
    assert!(run["executions"].as_u64().unwrap() > 0, "{run}");
    assert_eq!(run["findings"], 1, "{run}");
    // Every mutant of the seed that keeps its tag diverges; only the first is
    // re-run in fresh processes, since its kind is recorded.
    assert!(run["divergences"].as_u64().unwrap() >= 1, "{run}");
    assert_eq!(run["confirmed"], 1, "{run}");
    // And the results index lists it.
    let index: serde_json::Value =
        serde_json::from_slice(&fs::read(work.join("results/findings.json")).unwrap()).unwrap();
    assert!(
        index["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["id"] == record["id"]),
        "{index:#}"
    );
}

#[test]
fn agreeing_builds_give_no_divergence_finding() {
    if !clang_runs() {
        eprintln!("skipping: clang unavailable");
        return;
    }
    let root = TestDir::new("fuzz-diff-agree");
    let (work, output) = fuzz_against(&root, 0, "Zed");
    assert!(output.status.success(), "{}", log(&output));
    assert_eq!(divergences(&work), Vec::new(), "{}", log(&output));
    let run = &summary(&output)["differential"];
    assert!(run["executions"].as_u64().unwrap() > 0, "{run}");
    assert_eq!(run["divergences"], 0, "{run}");
}

/// The target's return value is part of what the builds are compared on.
#[test]
fn a_build_that_returns_another_status_is_a_divergence() {
    if !clang_runs() {
        eprintln!("skipping: clang unavailable");
        return;
    }
    let root = TestDir::new("fuzz-diff-status");
    let (work, output) = fuzz_against(&root, 2, "Zed");
    assert!(output.status.success(), "{}", log(&output));
    let found = divergences(&work);
    assert_eq!(found.len(), 1, "{}", log(&output));
    assert_eq!(found[0].1["differential"]["divergence"], "observation");
}

/// A build that crashes on an input the other runs clean is a divergence,
/// with that build's sanitizer report.
#[test]
fn a_build_that_crashes_where_the_other_runs_clean_is_a_divergence() {
    if !clang_runs() {
        eprintln!("skipping: clang unavailable");
        return;
    }
    let root = TestDir::new("fuzz-diff-crash");
    let (work, output) = fuzz_against(&root, 3, "Zebra-record");
    assert!(output.status.success(), "{}", log(&output));
    let found = divergences(&work);
    assert_eq!(found.len(), 1, "{}", log(&output));
    let (dir, record) = &found[0];
    let diff = &record["differential"];
    assert_eq!(diff["divergence"], "outcome", "{record:#}");
    assert_eq!(diff["outcome_a"], "clean");
    assert_eq!(diff["outcome_b"], "crash");
    assert_eq!(diff["report_b"]["kind"], "stack-buffer-overflow", "{diff}");
    let log_b = fs::read_to_string(dir.join("sanitizer.log")).unwrap();
    assert!(log_b.contains("AddressSanitizer"), "{log_b}");
    // The primary build ran clean: no crash finding of its own.
    assert!(
        findings(&work)
            .iter()
            .all(|(_, record)| record["rule_id"] == "BHF-301"),
        "{:#?}",
        findings(&work)
    );
}

/// Two copies of one build of a target that keeps state from one input to
/// the next agree on every input: the second build's process runs every
/// input the fuzzed build's process runs, the calibration and CmpLog re-runs
/// too, and both start over when either dies.
#[test]
fn identical_builds_of_a_target_that_keeps_state_agree() {
    if !clang_runs() {
        eprintln!("skipping: clang unavailable");
        return;
    }
    let root = TestDir::new("fuzz-diff-stateful");
    let (work, output) = fuzz_against_a_copy(&root, 4, "QRx", &["--iterations", "800"]);
    assert!(output.status.success(), "{}", log(&output));
    assert_eq!(divergences(&work), Vec::new(), "{}", log(&output));
    let summary = summary(&output);
    let run = &summary["differential"];
    assert!(run["executions"].as_u64().unwrap() > 0, "{run}");
    assert_eq!(run["divergences"], 0, "{summary:#}");
    // The fuzzed build's process died and started over on the crashing
    // records, and new entries were calibrated: both re-ran inputs.
    assert!(
        findings(&work)
            .iter()
            .any(|(_, record)| record["rule_id"] != "BHF-301"),
        "{}",
        log(&output)
    );
}

/// A second build that crashes where the fuzzed build does not, of a target
/// that keeps state, diverges on the crash alone: once its process died, the
/// fuzzed build's starts over too, so that both again hold the same state.
#[test]
fn a_second_build_that_crashes_on_a_target_that_keeps_state_diverges_on_the_crash_alone() {
    if !clang_runs() {
        eprintln!("skipping: clang unavailable");
        return;
    }
    let root = TestDir::new("fuzz-diff-stateful-crash");
    let work = root.join("work");
    build(&work.join("harnesses").join("H-DIFF"), "main", 7);
    let peer = build(&root.join("peer"), "main_b", 4);
    let output = fuzz(&work, &peer, "QRx", &["--iterations", "800"]);
    assert!(output.status.success(), "{}", log(&output));
    let found = divergences(&work);
    assert_eq!(found.len(), 1, "{}", log(&output));
    let diff = &found[0].1["differential"];
    assert_eq!(diff["divergence"], "outcome", "{diff}");
    assert_eq!(diff["outcome_b"], "crash", "{diff}");
    let summary = summary(&output);
    let run = &summary["differential"];
    // No disagreement on what the builds observed was re-run.
    assert_eq!(run["unconfirmed"], 0, "{summary:#}");
    assert_eq!(run["nondeterministic"], 0, "{summary:#}");
    assert!(run["not_rerun"].as_u64().unwrap() >= 1, "{summary:#}");
}

/// A value that changes from one process to the next (here the process id
/// the target returns) is not a divergence between two builds: each build
/// is re-run to check it reproduces its own observation, and a build that
/// does not is counted as nondeterministic. Past a few such re-runs, the
/// loop's disagreements of that kind are counted but not re-run.
#[test]
fn a_result_that_changes_from_process_to_process_is_not_a_divergence() {
    if !clang_runs() {
        eprintln!("skipping: clang unavailable");
        return;
    }
    let root = TestDir::new("fuzz-diff-nondeterministic");
    let (work, output) = fuzz_against_a_copy(&root, 5, "Zed", &[]);
    assert!(output.status.success(), "{}", log(&output));
    assert_eq!(divergences(&work), Vec::new(), "{}", log(&output));
    let summary = summary(&output);
    let run = &summary["differential"];
    assert_eq!(run["findings"], 0, "{run}");
    assert_eq!(run["confirmed"], 0, "{run}");
    let nondeterministic = run["nondeterministic"].as_u64().unwrap();
    assert!(nondeterministic >= 1, "{run}");
    let rerun = nondeterministic + run["unconfirmed"].as_u64().unwrap();
    assert!(run["not_rerun"].as_u64().unwrap() > 0, "{run}");
    assert_eq!(
        rerun + run["not_rerun"].as_u64().unwrap(),
        run["divergences"].as_u64().unwrap(),
        "{run}"
    );
}

/// A second build that is only slower than `--timeout` is judged as the
/// fuzzed build's hangs are: re-run in a fresh process with twice the
/// timeout, it finishes, and that is no divergence.
#[test]
fn a_second_build_that_is_only_slower_than_the_timeout_is_not_a_divergence() {
    if !clang_runs() {
        eprintln!("skipping: clang unavailable");
        return;
    }
    let root = TestDir::new("fuzz-diff-slow");
    let work = root.join("work");
    build(&work.join("harnesses").join("H-DIFF"), "main", 0);
    let peer = build(&root.join("peer"), "main_b", 6);
    let output = fuzz(
        &work,
        &peer,
        "Zed",
        &["--iterations", "40", "--timeout", "1s"],
    );
    assert!(output.status.success(), "{}", log(&output));
    assert_eq!(divergences(&work), Vec::new(), "{}", log(&output));
    let run = &summary(&output)["differential"];
    assert!(run["divergences"].as_u64().unwrap() >= 1, "{run}");
    assert!(run["unconfirmed"].as_u64().unwrap() >= 1, "{run}");
    assert_eq!(run["findings"], 0, "{run}");
}

/// A divergence the work dir already holds a finding for is not recorded
/// again by a later run on it: the run lists that finding in
/// `duplicates_of_existing`, as it does a crash it found before.
#[test]
fn a_divergence_found_again_is_a_duplicate_of_the_existing_finding() {
    if !clang_runs() {
        eprintln!("skipping: clang unavailable");
        return;
    }
    let root = TestDir::new("fuzz-diff-again");
    let (work, first) = fuzz_against(&root, 1, "Zed");
    assert!(first.status.success(), "{}", log(&first));
    let found = divergences(&work);
    assert_eq!(found.len(), 1, "{}", log(&first));
    let id = found[0].1["id"].clone();

    let again = fuzz(&work, &root.join("peer").join("main_b"), "Zed", &[]);
    assert!(again.status.success(), "{}", log(&again));
    assert_eq!(divergences(&work).len(), 1, "{}", log(&again));
    let summary = summary(&again);
    assert!(
        summary["duplicates_of_existing"]
            .as_array()
            .unwrap()
            .contains(&id),
        "{summary:#}"
    );
    assert_eq!(summary["differential"]["findings"], 0, "{summary:#}");
    assert!(
        !summary["findings"].as_array().unwrap().contains(&id),
        "{summary:#}"
    );
}

/// `bhf replay` of an in-loop divergence runs both builds of the input and
/// compares them as the fuzz run did; without the second build it cannot
/// say, and says so.
#[test]
fn replay_runs_both_builds_of_an_in_loop_divergence() {
    if !clang_runs() {
        eprintln!("skipping: clang unavailable");
        return;
    }
    let root = TestDir::new("fuzz-diff-replay");
    let (work, output) = fuzz_against(&root, 1, "Zed");
    assert!(output.status.success(), "{}", log(&output));
    let found = divergences(&work);
    assert_eq!(found.len(), 1, "{}", log(&output));
    let dir = &found[0].0;
    let replay = |dir: &Path| {
        Command::new(env!("CARGO_BIN_EXE_bhf"))
            .arg("replay")
            .arg(dir)
            .arg("--json")
            .output()
            .unwrap()
    };
    let matched = replay(dir);
    assert_eq!(matched.status.code(), Some(0), "{}", log(&matched));
    let result: serde_json::Value = serde_json::from_slice(&matched.stdout).unwrap();
    assert_eq!(result["verdict"], "match", "{result:#}");
    assert_eq!(result["lane"], "differential", "{result:#}");
    let text = result.to_string();
    assert!(text.contains("main_b"), "{result:#}");

    fs::rename(
        root.join("peer").join("main_b"),
        root.join("peer").join("gone"),
    )
    .unwrap();
    let unverified = replay(dir);
    assert_eq!(unverified.status.code(), Some(4), "{}", log(&unverified));
    let result: serde_json::Value = serde_json::from_slice(&unverified.stdout).unwrap();
    assert_eq!(result["verdict"], "unverified", "{result:#}");
    let text = result.to_string();
    assert!(
        text.contains("second build") && text.contains("main_b"),
        "{result:#}"
    );
    // The text summary says so too.
    let plain = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("replay")
        .arg(dir)
        .output()
        .unwrap();
    assert_eq!(plain.status.code(), Some(4), "{}", log(&plain));
    let stderr = String::from_utf8_lossy(&plain.stderr);
    assert!(
        stderr.contains("UNVERIFIED") && stderr.contains("second build"),
        "{stderr}"
    );
}

/// Only the builtin engine's single-worker loop runs the second build.
#[test]
fn the_second_harness_is_refused_where_it_would_be_ignored() {
    let root = TestDir::new("fuzz-diff-refused");
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    for (extra, names) in [
        (&["--engine", "afl++"][..], "--engine afl++"),
        (&["--workers", "2"][..], "--workers"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
            .arg("fuzz")
            .arg(&work)
            .args(["--harness", "H-DIFF", "--differential-harness", "/bin/true"])
            .args(extra)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{extra:?}: {}", log(&output));
        assert!(
            stderr.contains("--differential-harness") && stderr.contains(names),
            "{extra:?}: {stderr}"
        );
    }
}
