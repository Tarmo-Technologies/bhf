// SPDX-License-Identifier: Apache-2.0

//! An input that keeps a C harness running past `--timeout` is a hang finding
//! (BHF-230) once a fresh process given twice the timeout hangs on it too
//! (#207). Two inputs looping in one loop are one finding, keyed on the stack
//! the sanitizer printed when the re-run was stopped, and an execution that
//! was slow once is not a finding.

#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn clang_runs() -> bool {
    let present = {
        std::process::Command::new("clang")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    };
    support::require_tool(present, "clang")
}

/// A TLV walker: a record's length byte moves the cursor, so a zero length
/// never advances it. The volatile store keeps the loop from being assumed
/// to terminate.
const TLV_LOOP: &str = "#include <stddef.h>\n#include <stdint.h>\n\
     static volatile int seen;\n\
     __attribute__((noinline)) int walk_tlv(const uint8_t *d, size_t n) {\n\
         size_t at = 0;\n\
         while (at + 2 <= n) {\n\
             seen += d[at];\n\
             at += d[at + 1];\n\
         }\n\
         return seen;\n\
     }\n\
     int bhf_run_one(const uint8_t *data, size_t size) {\n\
         if (size >= 3 && data[0] == 'T') return walk_tlv(data + 1, size - 1);\n\
         return 0;\n\
     }\n";

/// Slow (5 s) on its first run only: the run count is kept in the file
/// `RUN_COUNT` names.
const SLOW_ONCE: &str = "#include <stddef.h>\n#include <stdint.h>\n#include <stdio.h>\n\
     #include <time.h>\n\
     int bhf_run_one(const uint8_t *data, size_t size) {\n\
         if (size == 0 || data[0] != 'S') return 0;\n\
         int runs = 0;\n\
         FILE *f = fopen(RUN_COUNT, \"r\");\n\
         if (f) { if (fscanf(f, \"%d\", &runs) != 1) runs = 0; fclose(f); }\n\
         f = fopen(RUN_COUNT, \"w\");\n\
         if (f) { fprintf(f, \"%d\", runs + 1); fclose(f); }\n\
         if (runs == 0) { struct timespec t = { 5, 0 }; nanosleep(&t, 0); }\n\
         return 0;\n\
     }\n";

/// Build `target` with bhf's driver and AddressSanitizer into
/// `<work>/harnesses/<id>/main`, with `defines` (`-D`).
fn build_harness(work: &Path, id: &str, target: &str, defines: &[String]) {
    let dir = work.join("harnesses").join(id);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("target.c"), target).unwrap();
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
        .args(defines.iter().map(|define| format!("-D{define}")))
        .arg(&driver)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
}

fn seed(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = root.join(name);
    fs::write(&path, bytes).unwrap();
    path
}

/// Run `bhf fuzz` over `seeds` only, with `--timeout <timeout>`.
fn fuzz(
    work: &Path,
    id: &str,
    seeds: &[PathBuf],
    timeout: &str,
    extra: &[&str],
) -> serde_json::Value {
    let mut argv: Vec<String> = ["bhf", "fuzz", work.to_str().unwrap(), "--harness", id]
        .map(str::to_owned)
        .to_vec();
    for seed in seeds {
        argv.push("--seed-file".to_owned());
        argv.push(seed.to_str().unwrap().to_owned());
    }
    argv.extend(
        [
            "--iterations",
            &seeds.len().to_string(),
            "--timeout",
            timeout,
        ]
        .map(str::to_owned),
    );
    argv.extend(extra.iter().map(|arg| (*arg).to_owned()));
    let exit = cli::run_from(argv);
    assert_eq!(exit, 0, "bhf fuzz exit");
    serde_json::from_slice(
        &fs::read(work.join("fuzz_runs").join(format!("{id}-latest.json"))).unwrap(),
    )
    .unwrap()
}

fn findings(work: &Path) -> Vec<serde_json::Value> {
    fs::read_dir(work.join("results/findings"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            serde_json::from_slice(&fs::read(entry.path().join("finding.json")).ok()?).ok()
        })
        .collect()
}

#[test]
fn two_inputs_hanging_in_one_loop_are_one_hang_finding() {
    if !clang_runs() {
        eprintln!("skipping: clang unavailable");
        return;
    }
    let root = TestDir::new("hang-tlv");
    let work = root.join("work");
    build_harness(&work, "H-TLV", TLV_LOOP, &[]);
    // A zero length at the first record, and at the second.
    let seeds = [
        seed(&root, "first.bin", b"T\x01\x00"),
        seed(&root, "second.bin", b"T\x05\x02\x09\x00"),
    ];
    let summary = fuzz(&work, "H-TLV", &seeds, "200ms", &[]);

    let hangs: Vec<_> = findings(&work)
        .into_iter()
        .filter(|finding| finding["rule_id"] == "BHF-230")
        .collect();
    assert_eq!(hangs.len(), 1, "{hangs:#?}\n{summary:#}");
    // The stack starts at the loop, not at the coverage callback the stop
    // signal interrupted.
    let stack = &hangs[0]["exception"]["stack"];
    assert_eq!(stack[0]["function"], "walk_tlv", "{:#}", hangs[0]);
    assert!(
        stack[0]["file"]
            .as_str()
            .is_some_and(|file| file.ends_with("target.c")),
        "{:#}",
        hangs[0]
    );
    assert_eq!(summary["hangs"]["observed"], 2, "{summary:#}");
    assert_eq!(summary["hangs"]["confirmed"], 2, "{summary:#}");
    assert_eq!(summary["hangs"]["timeout_ms"], 200, "{summary:#}");
}

#[test]
fn an_execution_slow_only_once_is_not_a_hang_finding() {
    if !clang_runs() {
        eprintln!("skipping: clang unavailable");
        return;
    }
    let root = TestDir::new("hang-slow-once");
    let work = root.join("work");
    let count = root.join("runs.txt");
    build_harness(
        &work,
        "H-SLOW",
        SLOW_ONCE,
        &[format!("RUN_COUNT=\"{}\"", count.display())],
    );
    let seeds = [seed(&root, "slow.bin", b"S1")];
    // Its re-run gets 2 s, room for a loaded host.
    let summary = fuzz(&work, "H-SLOW", &seeds, "1s", &["--no-fork-server"]);

    assert!(
        !findings(&work)
            .iter()
            .any(|finding| finding["rule_id"] == "BHF-230"),
        "{:#?}",
        findings(&work)
    );
    assert_eq!(summary["hangs"]["observed"], 1, "{summary:#}");
    assert_eq!(summary["hangs"]["cleared"], 1, "{summary:#}");
    assert_eq!(
        fs::read_to_string(&count).unwrap(),
        "2",
        "one hung run and its re-run"
    );
}
