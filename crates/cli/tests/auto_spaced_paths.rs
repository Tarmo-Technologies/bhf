// SPDX-License-Identifier: Apache-2.0

//! End-to-end regression for paths that contain spaces. Source trees, work
//! directories and SDK include dirs routinely live under such paths
//! (`/home/Dana Smith/...`, `C:/Program Files (x86)/Windows Kits/...`). Every
//! target under one used to be refused before generation, and an
//! `--extra-include` dir with a space was split into two compiler arguments.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bhf_bin() -> PathBuf {
    let mut dir = std::env::current_exe().expect("test exe");
    dir.pop();
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join("bhf")
}

fn tool_available(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

/// `(target name, outcome, harness id)` for every target in `auto/run.json`.
fn outcomes(work: &Path) -> Vec<(String, String, String)> {
    let Ok(bytes) = std::fs::read(work.join("auto/run.json")) else {
        return Vec::new();
    };
    let Ok(run): Result<serde_json::Value, _> = serde_json::from_slice(&bytes) else {
        return Vec::new();
    };
    run["targets"]
        .as_array()
        .map(|targets| {
            targets
                .iter()
                .map(|target| {
                    (
                        target["name"].as_str().unwrap_or_default().to_owned(),
                        target["outcome"]["outcome"]
                            .as_str()
                            .unwrap_or_default()
                            .to_owned(),
                        target["harness_id"].as_str().unwrap_or_default().to_owned(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

fn finding_dirs(work: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(work.join("results/findings"))
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.join("finding.json").is_file())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn auto_builds_and_fuzzes_targets_under_paths_with_spaces() {
    if !tool_available("clang") || !tool_available("clang++") || !tool_available("make") {
        eprintln!("skip: clang/clang++/make unavailable");
        return;
    }
    let bin = bhf_bin();
    if !bin.is_file() {
        eprintln!("skip: bhf binary not built");
        return;
    }

    let tmp = tempfile::tempdir().expect("temp dir");
    let root = tmp.path().join("Dana Smith's files");
    let tree = root.join("My Project (copy)");
    let src = tree.join("src lib");
    let kit = root.join("SDK 10/Include");
    let work = root.join("bhf work dir");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&kit).unwrap();
    std::fs::create_dir_all(&work).unwrap();

    // A header reachable only through the spaced `--extra-include` dir: if that
    // dir is word-split the build fails on the missing header.
    std::fs::write(kit.join("record_limits.h"), "#define RECORD_SLOTS 4\n").unwrap();
    std::fs::write(
        src.join("record.h"),
        "#ifndef RECORD_H\n#define RECORD_H\n\
         #include <stddef.h>\n\
         #include \"record_limits.h\"\n\
         int parse_record(const unsigned char *data, size_t len);\n\
         #endif\n",
    )
    .unwrap();
    // A planted out-of-bounds read, so the run must also produce a finding.
    std::fs::write(
        src.join("record.c"),
        "#include \"record.h\"\n\
         int parse_record(const unsigned char *data, size_t len) {\n\
         \x20   int slots[RECORD_SLOTS] = {0};\n\
         \x20   if (len >= 2 && data[0] == 'R') return slots[data[1]];\n\
         \x20   return len ? data[0] : 0;\n\
         }\n",
    )
    .unwrap();
    std::fs::write(
        src.join("frame.hpp"),
        "#pragma once\n#include <cstddef>\n#include \"record_limits.h\"\n\
         namespace demo {\n\
         int parse_frame(const unsigned char *data, std::size_t len);\n\
         }\n",
    )
    .unwrap();
    std::fs::write(
        src.join("frame.cpp"),
        "#include \"frame.hpp\"\n\
         namespace demo {\n\
         int parse_frame(const unsigned char *data, std::size_t len) {\n\
         \x20   return len > RECORD_SLOTS ? data[RECORD_SLOTS] : 0;\n\
         }\n\
         }\n",
    )
    .unwrap();

    let output = Command::new(&bin)
        .args(["auto"])
        .arg(&tree)
        .arg("--work-dir")
        .arg(&work)
        .arg("--extra-include")
        .arg(&kit)
        .args([
            "--languages",
            "c,cpp",
            "--max-targets",
            "2",
            "--jobs",
            "1",
            "--per-target-time",
            "8",
            "--no-discovery-cache",
        ])
        .output()
        .expect("run bhf auto");
    let log = format!(
        "stderr:\n{}\nstdout:\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );

    let outcomes = outcomes(&work);
    for target in ["parse_record", "parse_frame"] {
        assert!(
            outcomes
                .iter()
                .any(|(name, outcome, _)| name.ends_with(target) && outcome == "built_and_fuzzed"),
            "{target} under a spaced tree and work dir must build and fuzz; got {outcomes:?}\n{log}"
        );
    }
    let record_harness = outcomes
        .iter()
        .find(|(name, _, _)| name == "parse_record")
        .map(|(_, _, harness)| harness.clone())
        .unwrap();
    assert!(
        !log.contains("refusing to generate harness"),
        "a path with spaces must not be refused:\n{log}"
    );

    // The planted bug is found, and its testcase replays against the harness
    // built inside the spaced work dir.
    let findings = finding_dirs(&work);
    let finding = findings
        .iter()
        .find(|dir| {
            std::fs::read_to_string(dir.join("finding.json"))
                .ok()
                .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
                .is_some_and(|finding| finding["harness_id"] == record_harness.as_str())
        })
        .unwrap_or_else(|| panic!("the planted read must be found: {findings:?}\n{log}"));
    let replay = Command::new(&bin)
        .arg("replay")
        .arg(finding)
        .output()
        .expect("run bhf replay");
    assert!(
        String::from_utf8_lossy(&replay.stdout).contains("MATCH"),
        "the finding must replay from the spaced work dir:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&replay.stdout),
        String::from_utf8_lossy(&replay.stderr)
    );
}

/// A compile database's include flags name the tree's own directories, so a
/// tree under a directory with an apostrophe (`/home/Dana's tree/...`) puts the
/// apostrophe inside a compile flag. Single quotes cannot hold it, so the flag
/// is double-quoted; it used to be refused, and every target with it.
#[test]
fn auto_uses_compile_database_flags_under_an_apostrophe_directory() {
    if !tool_available("clang") || !tool_available("make") {
        eprintln!("skip: clang/make unavailable");
        return;
    }
    let bin = bhf_bin();
    if !bin.is_file() {
        eprintln!("skip: bhf binary not built");
        return;
    }

    let tmp = tempfile::tempdir().expect("temp dir");
    let tree = tmp.path().join("Dana's tree").join("proj");
    let src = tree.join("src");
    let cfg = tree.join("cfg");
    let work = tmp.path().join("work");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&cfg).unwrap();
    // Reachable only through the compile database's -I flag.
    std::fs::write(cfg.join("rec_limits.h"), "#define REC_SLOTS 4\n").unwrap();
    std::fs::write(
        src.join("rec.h"),
        "#ifndef REC_H\n#define REC_H\n\
         #include <stddef.h>\n\
         #include \"rec_limits.h\"\n\
         int parse_rec(const unsigned char *data, size_t len);\n\
         #endif\n",
    )
    .unwrap();
    std::fs::write(
        src.join("rec.c"),
        "#include \"rec.h\"\n\
         int parse_rec(const unsigned char *data, size_t len) {\n\
         \x20   int slots[REC_SLOTS] = {0};\n\
         \x20   return len ? slots[data[0] % REC_SLOTS] : 0;\n\
         }\n",
    )
    .unwrap();
    let database = serde_json::json!([{
        "directory": tree.display().to_string(),
        "file": src.join("rec.c").display().to_string(),
        "arguments": [
            "clang",
            format!("-I{}", cfg.display()),
            "-c",
            src.join("rec.c").display().to_string(),
        ],
    }]);
    std::fs::write(
        tree.join("compile_commands.json"),
        serde_json::to_vec_pretty(&database).unwrap(),
    )
    .unwrap();

    let output = Command::new(&bin)
        .args(["auto"])
        .arg(&tree)
        .arg("--work-dir")
        .arg(&work)
        .args([
            "--languages",
            "c",
            "--max-targets",
            "1",
            "--jobs",
            "1",
            "--per-target-time",
            "3",
            "--no-discovery-cache",
        ])
        .output()
        .expect("run bhf auto");
    let log = format!(
        "stderr:\n{}\nstdout:\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        !log.contains("refusing to generate harness"),
        "a compile flag under an apostrophe directory must not be refused:\n{log}"
    );
    let outcomes = outcomes(&work);
    assert!(
        outcomes
            .iter()
            .any(|(name, outcome, _)| name == "parse_rec" && outcome == "built_and_fuzzed"),
        "parse_rec must build with its compile-database flags; got {outcomes:?}\n{log}"
    );
}

/// A tree under a path no quoting makes safe in a build recipe (here a `$`,
/// which make expands) is refused with its own outcome, `unsafe_build_path`,
/// counted on its own in run.json and filed in the bug report as a path to
/// rename, not as an unsupported type.
#[test]
fn an_unquotable_tree_path_is_its_own_outcome() {
    let bin = bhf_bin();
    if !bin.is_file() {
        eprintln!("skip: bhf binary not built");
        return;
    }
    let tmp = tempfile::tempdir().expect("temp dir");
    let tree = tmp.path().join("build$tree");
    let src = tree.join("src");
    let work = tmp.path().join("work");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("record.h"),
        "#include <stddef.h>\nint parse_record(const unsigned char *data, size_t len);\n",
    )
    .unwrap();
    std::fs::write(
        src.join("record.c"),
        "#include \"record.h\"\n\
         int parse_record(const unsigned char *data, size_t len) { return len ? data[0] : 0; }\n",
    )
    .unwrap();
    let output = Command::new(&bin)
        .arg("auto")
        .arg(&tree)
        .arg("--work-dir")
        .arg(&work)
        .args([
            "--languages",
            "c",
            "--max-targets",
            "1",
            "--jobs",
            "1",
            "--per-target-time",
            "2",
            "--no-discovery-cache",
        ])
        .output()
        .expect("run bhf auto");
    let log = format!(
        "stderr:\n{}\nstdout:\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let outcomes = outcomes(&work);
    assert!(
        outcomes
            .iter()
            .any(|(name, outcome, _)| name == "parse_record" && outcome == "unsafe_build_path"),
        "{outcomes:?}\n{log}"
    );
    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
    assert_eq!(
        run["summary"]["unsafe_build_path"], 1,
        "{:#}",
        run["summary"]
    );
    let report = std::fs::read_to_string(work.join("auto/bug-report.md")).unwrap_or_default();
    assert!(report.contains("[unsafe-build-path]"), "{report}\n{log}");
    assert!(!report.contains("[unsupported-type"), "{report}");
    assert!(log.contains("Rename or move that path"), "{log}");
}
