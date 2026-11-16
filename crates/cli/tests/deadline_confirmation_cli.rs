// SPDX-License-Identifier: Apache-2.0

//! A run that overruns `--deadline` is a response-deadline finding (BHF-555)
//! only when most of its fresh re-runs overrun it too (#209): one slow run on
//! a loaded host is not a finding, and a finding records each re-run's time.

use std::fs;
use std::path::{Path, PathBuf};

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn clang_runs() -> bool {
    std::process::Command::new("clang")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

/// `W...` takes 600 ms on every run; `O...` only on its first, counted in
/// the file `RUN_COUNT` names.
const SLOW_TARGET: &str = "#include <stddef.h>\n#include <stdint.h>\n#include <stdio.h>\n\
     #include <time.h>\n\
     static void pause_ms(long ms) {\n\
         struct timespec t = { ms / 1000, (ms % 1000) * 1000000L };\n\
         nanosleep(&t, 0);\n\
     }\n\
     static int runs_before(void) {\n\
         int runs = 0;\n\
         FILE *f = fopen(RUN_COUNT, \"r\");\n\
         if (f) { if (fscanf(f, \"%d\", &runs) != 1) runs = 0; fclose(f); }\n\
         f = fopen(RUN_COUNT, \"w\");\n\
         if (f) { fprintf(f, \"%d\", runs + 1); fclose(f); }\n\
         return runs;\n\
     }\n\
     int bhf_run_one(const uint8_t *data, size_t size) {\n\
         if (size == 0) return 0;\n\
         if (data[0] == 'W') pause_ms(600);\n\
         if (data[0] == 'O' && runs_before() == 0) pause_ms(600);\n\
         return 0;\n\
     }\n";

fn build_harness(work: &Path, id: &str, run_count: &Path) {
    let dir = work.join("harnesses").join(id);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("target.c"), SLOW_TARGET).unwrap();
    let driver = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime/bhf_driver.c");
    let built = std::process::Command::new("clang")
        .current_dir(&dir)
        .args([
            "-O1",
            "-g",
            "-fsanitize=address",
            "-fsanitize-coverage=trace-pc-guard,trace-cmp",
            "-o",
            "main",
            "target.c",
        ])
        .arg(format!("-DRUN_COUNT=\"{}\"", run_count.display()))
        .arg(&driver)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
}

/// Fuzz one seed, `bytes`, under a 300 ms deadline: the 600 ms run overruns
/// it twice over, and a fast run on a loaded host stays well inside it.
fn fuzz_one(root: &Path, bytes: &[u8]) -> (PathBuf, PathBuf) {
    let work = root.join("work");
    let count = root.join("runs.txt");
    build_harness(&work, "H-SLOW", &count);
    let seed = root.join("seed.bin");
    fs::write(&seed, bytes).unwrap();
    let exit = cli::run_from(
        [
            "bhf",
            "fuzz",
            work.to_str().unwrap(),
            "--harness",
            "H-SLOW",
            "--seed-file",
            seed.to_str().unwrap(),
            "--iterations",
            "1",
            "--no-fork-server",
            "--deadline",
            "300ms",
            "--timeout",
            "5s",
        ]
        .map(str::to_owned)
        .to_vec(),
    );
    assert_eq!(exit, 0, "bhf fuzz exit");
    (work, count)
}

fn deadline_findings(work: &Path) -> Vec<serde_json::Value> {
    fs::read_dir(work.join("results/findings"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            serde_json::from_slice::<serde_json::Value>(
                &fs::read(entry.path().join("finding.json")).ok()?,
            )
            .ok()
        })
        .filter(|finding| finding["rule_id"] == "BHF-555")
        .collect()
}

#[cfg(unix)]
#[test]
fn a_consistently_slow_input_is_one_finding_with_its_timings() {
    if !clang_runs() {
        eprintln!("skipping: clang unavailable");
        return;
    }
    let root = TestDir::new("deadline-slow");
    let (work, _) = fuzz_one(root.path(), b"W1");
    let found = deadline_findings(&work);
    assert_eq!(found.len(), 1, "{found:#?}");
    let check = &found[0]["deadline_confirmation"];
    assert_eq!(check["deadline_ms"], 300, "{check:#}");
    assert_eq!(check["overruns"], 2, "{check:#}");
    let reruns = check["rerun_ms"].as_array().expect("rerun_ms");
    assert_eq!(reruns.len(), 2, "{check:#}");
    assert!(
        reruns
            .iter()
            .all(|ms| ms.as_u64().is_some_and(|ms| ms >= 600)),
        "{check:#}"
    );
}

#[cfg(unix)]
#[test]
fn a_run_slow_only_once_is_not_a_finding() {
    if !clang_runs() {
        eprintln!("skipping: clang unavailable");
        return;
    }
    let root = TestDir::new("deadline-once");
    let (work, count) = fuzz_one(root.path(), b"O1");
    assert!(
        deadline_findings(&work).is_empty(),
        "{:#?}",
        deadline_findings(&work)
    );
    // The slow run and the two re-runs that met the deadline.
    assert_eq!(fs::read_to_string(&count).unwrap(), "3");
}
