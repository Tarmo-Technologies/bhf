// SPDX-License-Identifier: Apache-2.0

//! `bhf fuzz --collector` replays the campaign's retained inputs one by one on
//! the harness (#246). A sidecar was never run against an execution
//! (`harness_sidecar_replay_unsupported`), and on Linux the collector read the
//! campaign's runtrace as one aggregate session, so a finding carried no input.
//! Now each retained input runs under the observer, the observation names that
//! testcase and the PID it ran as, and a finding keeps its input and replays.

#![cfg(target_os = "linux")]

use serde_json::Value;
use std::path::Path;
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

const HARNESS: &str = "H-TOOL";

/// Runs a shell command built from the input, and appends `<pid> <len>` to
/// the file `BHF_TEST_PID_LOG` names, so a test can tell which process ran
/// which input.
const TARGET: &str = "#include <stdio.h>\n#include <stdlib.h>\n#include <stddef.h>\n\
                      #include <unistd.h>\n\
                      int run_tool(const unsigned char *data, size_t len) {\n  \
                      const char *log = getenv(\"BHF_TEST_PID_LOG\");\n  \
                      if (log) { FILE *f = fopen(log, \"a\"); \
                      if (f) { fprintf(f, \"%d %zu\\n\", (int)getpid(), len); fclose(f); } }\n  \
                      char cmd[96];\n  if (len < 2 || len > 40) return 0;\n  \
                      snprintf(cmd, sizeof cmd, \"echo %.*s > /dev/null\", (int)len, data);\n  \
                      return system(cmd);\n}\n";

fn bhf() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
}

fn clang_present() -> bool {
    let present = Command::new("clang")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success());
    support::require_tool(present, "clang")
}

/// Generate and build the tool harness in `work`; returns the seed file.
fn build_tool(work: &Path) -> std::path::PathBuf {
    std::fs::write(work.join("tool.c"), TARGET).unwrap();
    for args in [
        &[
            "generate-harness",
            "tool.c",
            "--target",
            "run_tool",
            "--output",
            "generated_harnesses",
            "--id",
            HARNESS,
        ][..],
        &["build", ".", "--harness", HARNESS][..],
    ] {
        let out = bhf().current_dir(work).args(args).output().unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let seed = work.join("seed");
    std::fs::write(&seed, b"hello world").unwrap();
    seed
}

/// `bhf fuzz` of the tool with `flags`; returns the run summary.
fn fuzz(work: &Path, flags: &[&str], env: &[(&str, &Path)]) -> Value {
    let mut fuzz = bhf();
    support::configure_runtrace_shim(&mut fuzz);
    fuzz.current_dir(work)
        .args([
            "fuzz",
            ".",
            "--harness",
            HARNESS,
            "--engine",
            "builtin",
            "-q",
        ])
        .args([
            "--seed-file",
            "seed",
            "--iterations",
            "400",
            "--rng-seed",
            "3",
        ])
        .args(["--sandbox", "none"])
        .args(flags);
    for (key, value) in env {
        fuzz.env(key, value);
    }
    let out = fuzz.output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("summary ({e}): {stderr}"))
}

fn finding(work: &Path, id: &str) -> Value {
    serde_json::from_slice(
        &std::fs::read(work.join("results/findings").join(id).join("finding.json")).unwrap(),
    )
    .unwrap()
}

fn replays(collector: &Value) -> Vec<Value> {
    collector["replays"]
        .as_array()
        .unwrap_or_else(|| panic!("the replays are listed: {collector:#}"))
        .clone()
}

/// `bhf replay` of a collector finding reproduces it from its evidence.
fn assert_replays(work: &Path, id: &str) {
    let out = bhf()
        .arg("replay")
        .arg(work.join("results/findings").join(id))
        .output()
        .unwrap();
    assert!(
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("MATCH"),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A sidecar observes each retained input as the harness process that ran
/// it: the replay names the testcase, and its PID is the one that harness run
/// recorded for an input of that length.
#[test]
fn a_sidecar_observes_each_retained_input_as_the_process_that_ran_it() {
    if !clang_present() {
        eprintln!("skipping: no clang");
        return;
    }
    let work = TestDir::new("collector-fuzz-sidecar");
    build_tool(work.path());
    let pid_log = work.join("pids.txt");
    let mock = env!("CARGO_BIN_EXE_mock_collector");
    let summary = fuzz(
        work.path(),
        &["--collector", mock, "--collector-window-ms", "200"],
        &[("BHF_TEST_PID_LOG", &pid_log)],
    );
    let collector = &summary["collector"];
    assert_eq!(collector["observed"], true, "{collector:#}");
    assert_eq!(collector["observation"], "replay", "{collector:#}");
    let replays = replays(collector);
    assert!(!replays.is_empty(), "{collector:#}");

    let queue = work.join("corpus").join(HARNESS).join("queue");
    let ran: Vec<(u64, usize)> = std::fs::read_to_string(&pid_log)
        .unwrap()
        .lines()
        .filter_map(|line| {
            let (pid, len) = line.split_once(' ')?;
            Some((pid.parse().ok()?, len.parse().ok()?))
        })
        .collect();
    for replay in &replays {
        let testcase = replay["testcase"].as_str().unwrap();
        let stem = testcase
            .strip_prefix("corpus-")
            .unwrap_or_else(|| panic!("a retained corpus input: {replay}"));
        let input = std::fs::read(queue.join(format!("{stem}.bin"))).unwrap();
        assert_eq!(replay["observed"], true, "{replay}");
        let pid = replay["replayed_pid"].as_u64().expect("the PID it ran as");
        assert!(
            ran.contains(&(pid, input.len())),
            "{testcase} replayed as PID {pid}, which no harness run of {} bytes was: {ran:?}",
            input.len()
        );
    }

    // The mock's effects make findings; the first replay's input is kept.
    let ids: Vec<&str> = collector["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(!ids.is_empty(), "{collector:#}");
    let first = replays[0]["testcase"].as_str().unwrap();
    let first_input =
        std::fs::read(queue.join(format!("{}.bin", first.strip_prefix("corpus-").unwrap())))
            .unwrap();
    for id in &ids {
        let raw = finding(work.path(), id);
        assert_eq!(raw["collector"]["observation"], "replay", "{raw:#}");
        assert_eq!(
            std::fs::read(work.join("results/findings").join(id).join("testcase.bin")).unwrap(),
            first_input,
            "{raw:#}"
        );
    }
    assert_replays(work.path(), ids[0]);
}

/// On Linux the runtrace view replays each retained input under the shim: the
/// fuzzed `system()` is reported from a replay, with the input that reached
/// it, not from the campaign aggregate with a 0-byte input.
#[test]
fn the_runtrace_view_reports_a_sink_with_the_input_whose_replay_reached_it() {
    if !clang_present() {
        eprintln!("skipping: no clang");
        return;
    }
    let work = TestDir::new("collector-fuzz-runtrace");
    build_tool(work.path());
    let summary = fuzz(work.path(), &["--collector", "auto"], &[]);
    let collector = &summary["collector"];
    if collector["active"] != true {
        eprintln!("skipping: no runtrace shim");
        return;
    }
    assert_eq!(collector["observation"], "replay", "{collector:#}");
    assert!(
        replays(collector).iter().all(|r| r["observed"] == true),
        "{collector:#}"
    );
    let process: Vec<Value> = collector["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .map(|id| (id.to_owned(), finding(work.path(), id)))
        .filter(|(_, raw)| raw["rule_id"] == "BHF-431")
        .map(|(id, mut raw)| {
            raw["id"] = Value::from(id);
            raw
        })
        .collect();
    assert_eq!(process.len(), 1, "one sink, one finding: {process:#?}");
    let raw = &process[0];
    assert_eq!(raw["collector"]["observation"], "replay", "{raw:#}");
    let bytes = raw["input"]["bytes"].as_u64().unwrap();
    assert!(
        (2..=40).contains(&bytes),
        "the input that reached system(): {raw:#}"
    );
    assert_replays(work.path(), raw["id"].as_str().unwrap());
}
