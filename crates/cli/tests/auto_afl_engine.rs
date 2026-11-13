// SPDX-License-Identifier: Apache-2.0

//! End-to-end coverage for `bhf auto --engine afl++` (#auto-afl). Toolchain-
//! gated: skips (printing why) when `afl-fuzz`/`afl-clang-fast` are not on PATH,
//! per the project's GNAT-less skip convention, so a box without AFL does not
//! hard-fail the suite.

use std::path::Path;
use std::process::Command;

fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(bin).is_file()))
        .unwrap_or(false)
}

fn afl_present() -> bool {
    which("afl-fuzz") && which("afl-clang-fast")
}

/// The bundled miniz fixture. `CARGO_MANIFEST_DIR` is `<repo>/crates/cli`, so the
/// fixture lives two levels up — integration tests run with CWD at the crate root,
/// not the workspace root.
fn miniz_fixture() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/build_recovery/fixtures/miniz")
}

/// Recursively check whether a file named `name` exists anywhere under `root`.
fn walk_for(root: &Path, name: &str) -> bool {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for entry in rd.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.file_name().and_then(|n| n.to_str()) == Some(name) {
                    return true;
                }
            }
        }
    }
    false
}

/// `auto --engine builtin,afl++` against a real C library (miniz) must:
///   1. recover the build and produce the AFL-instrumented `main_afl`, and
///   2. drive AFL, recording an `afl++`-attributed pass in run.json ALONGSIDE
///      the builtin passes.
#[test]
fn auto_engine_both_builds_main_afl_and_attributes_afl_pass() {
    if !afl_present() {
        eprintln!("skipping auto_engine_both: afl-fuzz/afl-clang-fast not on PATH");
        return;
    }
    let bin = env!("CARGO_BIN_EXE_bhf");
    let tmp = tempfile::tempdir().unwrap();
    let work = tmp.path().join("work");
    let status = Command::new(bin)
        .args([
            "auto",
            "--engine",
            "builtin,afl++",
            "--per-target-time",
            "2",
            "--max-targets",
            "1",
            "--work-dir",
            work.to_str().unwrap(),
            miniz_fixture().to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(
        status.success(),
        "auto --engine builtin,afl++ exited non-zero"
    );

    // (1) the afl-instrumented binary was built from the recovered harness
    assert!(
        walk_for(&work, "main_afl"),
        "expected a main_afl under {} (auto should `make afl` the recovered build)",
        work.display()
    );

    // (2) run.json attributes a pass to the afl++ engine, and still carries the
    //     builtin passes (both engines ran for the target)
    let run_json = std::fs::read_to_string(work.join("auto").join("run.json")).unwrap();
    assert!(
        run_json.contains("\"engine\": \"afl++\""),
        "run.json should attribute an afl++ pass"
    );
    assert!(
        run_json.contains("\"engine\": \"builtin\""),
        "run.json should still carry the builtin passes"
    );
}

/// `auto --engine afl++` (AFL only) must skip the builtin cascade and record ONLY
/// an afl++ pass for a native C target.
#[test]
fn auto_engine_afl_only_skips_builtin_cascade() {
    if !afl_present() {
        eprintln!("skipping auto_engine_afl_only: afl-fuzz/afl-clang-fast not on PATH");
        return;
    }
    let bin = env!("CARGO_BIN_EXE_bhf");
    let tmp = tempfile::tempdir().unwrap();
    let work = tmp.path().join("work");
    let status = Command::new(bin)
        .args([
            "auto",
            "--engine",
            "afl++",
            "--per-target-time",
            "2",
            "--max-targets",
            "1",
            "--work-dir",
            work.to_str().unwrap(),
            miniz_fixture().to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "auto --engine afl++ exited non-zero");

    let run_json = std::fs::read_to_string(work.join("auto").join("run.json")).unwrap();
    assert!(
        run_json.contains("\"engine\": \"afl++\""),
        "run.json should attribute the afl++ pass"
    );
    // AFL-only: no builtin empty/rng/fuzz_driven passes were run for this target.
    assert!(
        !run_json.contains("\"engine\": \"builtin\""),
        "AFL-only run must NOT record builtin passes"
    );
}

/// A store to a struct member past a 4-byte heap block, fuzzed by AFL++ alone
/// (the only access through the struct type, so seeds that skip it do not
/// crash: clang's check reports any member access through an undersized block).
/// afl-clang-fast's UBSan object-size check reports the member access before
/// ASan does; the crash ingestion re-runs the input with that check suppressed
/// and reports ASan's heap-buffer-overflow, as the builtin engine does, saying
/// so in the finding.
#[test]
fn an_afl_member_store_past_a_heap_block_is_an_asan_heap_buffer_overflow() {
    if !afl_present() || !which("make") {
        eprintln!("skipping: afl-fuzz/afl-clang-fast or make not on PATH");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("tree/src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("pair.c"),
        "#include <stdlib.h>\n\
         struct pair { int first; int second; };\n\
         int store_pair(const unsigned char *d, size_t n) {\n\
         \x20   int *slot = malloc(sizeof(int));\n\
         \x20   if (!slot) return 0;\n\
         \x20   *slot = 0;\n\
         \x20   if (n > 2 && d[0] == 'P') ((struct pair *)slot)->second = d[1];\n\
         \x20   int r = *slot;\n\
         \x20   free(slot);\n\
         \x20   return r;\n\
         }\n",
    )
    .unwrap();
    let work = tmp.path().join("work");
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(&src)
        .arg("--work-dir")
        .arg(&work)
        .args([
            "--engine",
            "afl++",
            "--per-target-time",
            "8",
            "--max-targets",
            "1",
            "--jobs",
            "1",
            "--no-discovery-cache",
        ])
        .env_remove("CC")
        .env_remove("CXX")
        .output()
        .unwrap();
    let log = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let findings: Vec<serde_json::Value> = std::fs::read_dir(work.join("results/findings"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let text = std::fs::read_to_string(entry.path().join("finding.json")).ok()?;
            serde_json::from_str(&text).ok()
        })
        .collect();
    let overflow = findings
        .iter()
        .find(|finding| finding["exception"]["name"] == "ASAN_HEAP_BUFFER_OVERFLOW")
        .unwrap_or_else(|| panic!("no heap-buffer-overflow: {findings:#?}\n{log}"));
    assert_eq!(overflow["rule_id"], "BHF-201", "{overflow:#}");
    let opinion = &overflow["sanitizer_second_opinion"];
    assert_eq!(opinion["check"], "object-size", "{overflow:#}");
    assert_eq!(opinion["used"], "asan", "{overflow:#}");
    assert!(
        !findings
            .iter()
            .any(|finding| finding["rule_id"] == "BHF-227"),
        "no object-size finding: {findings:#?}"
    );
}
