// SPDX-License-Identifier: Apache-2.0

//! A pass shorter than the harness's start-up still runs over the
//! fork-server (#432). The harness's fork-server process sleeps before bhf's
//! driver sends its ready byte, for longer than the pass's `--time`: the
//! handshake waits for it, and the pass then fuzzes over the fork-server for
//! its budget instead of starting a fresh process for every input, which on
//! a loaded Windows host costs most of a second each. The handshake waits as
//! long as `--timeout` asks, a campaign's workers are not stopped for the
//! time it takes, and a second build's start-up never holds a pass past its
//! end. A run whose fork-server does not start says how many inputs it ran
//! per second.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// How long the fork-server process takes to start: longer than the pass.
const STARTUP_MS: u32 = 2500;
/// The pass's `--time`, shorter than the start-up.
const PASS: &str = "1s";

fn clang_runs() -> bool {
    let present = Command::new("clang")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success());
    support::require_tool(present, "clang")
}

/// A target whose fork-server process (the one bhf starts with
/// `BHF_FRAMED` set) runs `startup` before `main`, so before the driver
/// sends its ready byte. A fresh process for one input skips it.
fn target(startup: &str) -> String {
    format!(
        "#include <stddef.h>\n#include <stdint.h>\n#include <stdlib.h>\n\
         #ifdef _WIN32\n#include <windows.h>\n#else\n#include <time.h>\n#endif\n\
         __attribute__((constructor)) static void fork_server_start(void) {{\n\
             if (!getenv(\"BHF_FRAMED\")) return;\n\
             {startup}\n\
         }}\n\
         int bhf_run_one(const uint8_t *data, size_t size) {{\n\
             int acc = 0;\n\
             for (size_t i = 0; i < size; i++) acc += data[i] == 'A';\n\
             return acc;\n\
         }}\n"
    )
}

/// A start-up that sleeps `millis` of wall-clock time, as a harness does on
/// a loaded host.
fn sleep_for(millis: u32) -> String {
    format!(
        "#ifdef _WIN32\n    Sleep({millis});\n#else\n\
         struct timespec t = {{ {secs}, {nanos} }};\n    nanosleep(&t, 0);\n#endif",
        secs = millis / 1000,
        nanos = (millis % 1000) * 1_000_000,
    )
}

/// Build `target` with bhf's driver into `<dir>/main`.
fn build_into(dir: &Path, target: &str) {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("target.c"), target).unwrap();
    let driver = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime/bhf_driver.c");
    let built = Command::new("clang")
        .current_dir(dir)
        .args(["-O1", "-g", "-fsanitize-coverage=trace-pc-guard,trace-cmp"])
        .args(["-o", "main", "target.c"])
        .arg(&driver)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
}

/// Build `target` with bhf's driver into `<work>/harnesses/<id>/main`.
fn build_harness(work: &Path, id: &str, target: &str) {
    build_into(&work.join("harnesses").join(id), target);
}

/// `bhf fuzz` of the harness for `--time` `pass`, with `extra` arguments.
fn run_fuzz(work: &Path, id: &str, pass: &str, extra: &[&std::ffi::OsStr]) -> Output {
    let seed = work.join("seed.bin");
    fs::write(&seed, b"AAAA").unwrap();
    Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("fuzz")
        .arg(work)
        .args(["--harness", id, "--engine", "builtin", "--time", pass])
        .arg("--seed-file")
        .arg(&seed)
        .args(extra)
        .output()
        .unwrap()
}

/// The JSON summary a successful `bhf fuzz` printed, and its stderr.
fn summary_of(output: &Output) -> (serde_json::Value, String) {
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");
    let summary = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "the fuzz summary is not JSON ({error}): {}\n{stderr}",
            String::from_utf8_lossy(&output.stdout)
        )
    });
    (summary, stderr)
}

/// `bhf fuzz` one pass of `pass` over the harness: its summary and stderr.
fn fuzz(work: &Path, id: &str, pass: &str, extra: &[&str]) -> (serde_json::Value, String) {
    let extra: Vec<&std::ffi::OsStr> = extra.iter().map(std::ffi::OsStr::new).collect();
    summary_of(&run_fuzz(work, id, pass, &extra))
}

/// The run went over the fork-server and fuzzed after its start-up.
fn assert_ran_over_the_fork_server(summary: &serde_json::Value, stderr: &str) {
    assert_eq!(
        summary["execution"]["forkserver"], true,
        "a start-up longer than the pass must not drop it to a fresh process per input: \
         {summary:#}\n{stderr}"
    );
    assert!(
        !stderr.contains("running a fresh process per input"),
        "{stderr}"
    );
    // The start-up is not charged to the pass: it still fuzzed, at
    // fork-server rates, after the harness was ready.
    let executions = summary["executions"].as_u64().unwrap_or_default();
    assert!(executions > 20, "{executions} executions: {summary:#}");
}

#[test]
fn a_pass_shorter_than_the_start_up_still_runs_over_the_fork_server() {
    if !clang_runs() {
        eprintln!("skipping: needs clang");
        return;
    }
    let work = TestDir::new("fork-server-slow-start");
    build_harness(&work, "H-SLOWREADY", &target(&sleep_for(STARTUP_MS)));
    let (summary, stderr) = fuzz(&work, "H-SLOWREADY", PASS, &[]);
    assert_ran_over_the_fork_server(&summary, &stderr);
}

#[test]
fn a_start_up_past_ten_seconds_gets_the_timeout_it_asks_for_in_a_short_pass() {
    if !clang_runs() {
        eprintln!("skipping: needs clang");
        return;
    }
    let work = TestDir::new("fork-server-slower-start");
    // Past the 10 s every framed harness gets, inside the 20 s `--timeout`.
    build_harness(&work, "H-SLOWERREADY", &target(&sleep_for(11_500)));
    let (summary, stderr) = fuzz(&work, "H-SLOWERREADY", PASS, &["--timeout", "20s"]);
    assert_ran_over_the_fork_server(&summary, &stderr);
}

#[test]
fn the_workers_of_a_campaign_are_not_stopped_for_their_start_up() {
    if !clang_runs() {
        eprintln!("skipping: needs clang");
        return;
    }
    let work = TestDir::new("fork-server-slow-start-workers");
    // Longer than the 5 s a worker may run past the campaign's `--time`.
    build_harness(&work, "H-SLOWWORKERS", &target(&sleep_for(6500)));
    let (summary, stderr) = fuzz(&work, "H-SLOWWORKERS", PASS, &["--workers", "2"]);
    assert_eq!(summary["workers_completed"], 2, "{summary:#}\n{stderr}");
    for worker in summary["per_worker"].as_array().unwrap() {
        assert_eq!(worker["exit_code"], 0, "{summary:#}\n{stderr}");
        assert!(worker.get("stopped_at_deadline").is_none(), "{summary:#}");
        // Each worker waited for its harness and fuzzed over the fork-server.
        let dir = Path::new(worker["work_dir"].as_str().unwrap());
        let own = fs::read(dir.join("worker-stdout.json")).unwrap();
        let own: serde_json::Value = serde_json::from_slice(&own).unwrap();
        let log = fs::read_to_string(dir.join("worker-stderr.log")).unwrap_or_default();
        assert_ran_over_the_fork_server(&own, &log);
    }
}

/// A second build whose fork-server takes longer than the pass to start may
/// not hold the pass for its start-up: the pass ends on time, and that build
/// runs a fresh process per input.
#[cfg(unix)]
#[test]
fn a_second_build_slow_to_start_does_not_hold_the_pass_past_its_end() {
    if !clang_runs() {
        eprintln!("skipping: needs clang");
        return;
    }
    let work = TestDir::new("fork-server-slow-second-build");
    build_harness(&work, "H-QUICK", &target(""));
    let slow = work.join("second-build");
    build_into(&slow, &target(&sleep_for(6000)));
    let peer = slow.join("main");
    let output = run_fuzz(
        &work,
        "H-QUICK",
        PASS,
        &["--differential-harness".as_ref(), peer.as_os_str()],
    );
    let (summary, stderr) = summary_of(&output);
    let elapsed = summary["elapsed_secs"].as_f64().unwrap();
    assert!(
        elapsed < 5.0,
        "a 1 s pass took {elapsed:.1} s waiting for the second build: {summary:#}\n{stderr}"
    );
    assert_eq!(summary["execution"]["forkserver"], true, "{summary:#}");
}

/// `bhf: N input(s) ran in a fresh process each, without the fork-server, in
/// the Ss it was down: R per second` as `(N, S, R)`.
fn fallback_note(stderr: &str) -> (f64, f64, f64) {
    let note = stderr
        .lines()
        .find(|line| line.contains("in a fresh process each, without the fork-server"))
        .unwrap_or_else(|| panic!("no fallback rate on stderr:\n{stderr}"));
    let between = |from: &str, to: &str| -> f64 {
        let rest = &note[note.find(from).unwrap_or_else(|| panic!("{note}")) + from.len()..];
        rest[..rest.find(to).unwrap_or_else(|| panic!("{note}"))]
            .trim()
            .parse()
            .unwrap_or_else(|error| panic!("{error}: {note}"))
    };
    (
        between("bhf: ", " input(s)"),
        between("in the ", "s it was down"),
        between("was down: ", " per second"),
    )
}

#[test]
fn a_run_without_its_fork_server_says_how_many_inputs_it_ran_per_second() {
    if !clang_runs() {
        eprintln!("skipping: needs clang");
        return;
    }
    let work = TestDir::new("fork-server-fallback-rate");
    // The fork-server process ends before it is ready; each fresh process
    // runs its input. A pass of a few seconds always runs some.
    build_harness(&work, "H-NOSERVER", &target("exit(0);"));
    let (summary, stderr) = fuzz(&work, "H-NOSERVER", "3s", &[]);
    assert_eq!(summary["execution"]["forkserver"], false, "{summary:#}");
    let (inputs, down, per_second) = fallback_note(&stderr);
    assert!(inputs >= 1.0, "{stderr}");
    let executions = summary["executions"].as_f64().unwrap();
    assert!(inputs <= executions, "{inputs} of {executions}: {stderr}");
    // The rate is of the fuzzing time the fork-server was down, which here
    // is most of the pass, not of the time spent inside those processes.
    assert!(down >= 1.0, "down {down} s of a 3 s pass: {stderr}");
    let expected = inputs / down;
    assert!(
        (per_second - expected).abs() <= expected * 0.06 + 0.1,
        "{per_second} per second for {inputs} inputs over {down} s: {stderr}"
    );
}
