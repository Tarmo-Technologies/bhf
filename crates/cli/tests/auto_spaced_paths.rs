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

/// Hard-link `from` to `to`, or copy it where a link cannot be made.
#[cfg(target_os = "linux")]
fn link_or_copy(from: &Path, to: &Path) {
    if std::fs::hard_link(from, to).is_err() {
        std::fs::copy(from, to).expect("copy into the install dir");
    }
}

/// bhf installed under a directory with spaces (`Program Files (x86)`, a
/// user profile) still preloads its runtrace shim, which `LD_PRELOAD` would
/// split at the space, and the finding says it was armed because the run
/// produced the runtrace log.
#[cfg(target_os = "linux")]
#[test]
fn the_runtrace_shim_loads_when_bhf_is_installed_under_a_spaced_path() {
    if !tool_available("clang") || !tool_available("make") {
        eprintln!("skip: clang/make unavailable");
        return;
    }
    let bin = bhf_bin();
    let Some(shim) = ["libbhf_runtrace.so", "libbhf_runtrace_shim.so"]
        .into_iter()
        .map(|name| bin.with_file_name(name))
        .find(|path| path.is_file())
    else {
        eprintln!("skip: bhf or its runtrace shim is not built");
        return;
    };
    if !bin.is_file() {
        eprintln!("skip: bhf binary not built");
        return;
    }

    let tmp = tempfile::tempdir().expect("temp dir");
    let install = tmp
        .path()
        .join("Program Files (x86)")
        .join("bhf")
        .join("bin");
    std::fs::create_dir_all(&install).unwrap();
    let installed = install.join("bhf");
    link_or_copy(&bin, &installed);
    link_or_copy(&shim, &install.join("libbhf_runtrace.so"));

    let tree = tmp.path().join("proj");
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
         int parse_record(const unsigned char *data, size_t len) {\n\
         \x20   int slots[4] = {0};\n\
         \x20   return len ? slots[data[0]] : 0;\n\
         }\n",
    )
    .unwrap();

    let output = Command::new(&installed)
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
            "6",
            "--no-discovery-cache",
        ])
        .env_remove("BHF_RUNTRACE_SHIM")
        .env_remove("LD_PRELOAD")
        .output()
        .expect("run the installed bhf auto");
    let log = format!(
        "stderr:\n{}\nstdout:\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let outcomes = outcomes(&work);
    let (_, outcome, harness) = outcomes
        .iter()
        .find(|(name, _, _)| name == "parse_record")
        .cloned()
        .unwrap_or_else(|| panic!("parse_record was not attempted: {outcomes:?}\n{log}"));
    assert_eq!(outcome, "built_and_fuzzed", "{log}");
    assert!(!log.contains("cannot be preloaded"), "{log}");
    assert!(
        work.join("harnesses")
            .join(&harness)
            .join("runtrace.jsonl")
            .is_file(),
        "the fuzz pass produced no runtrace log, so the shim was not loaded:\n{log}"
    );

    let finding = finding_dirs(&work)
        .into_iter()
        .find(|dir| {
            std::fs::read_to_string(dir.join("finding.json"))
                .ok()
                .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
                .is_some_and(|finding| finding["harness_id"] == harness.as_str())
        })
        .unwrap_or_else(|| panic!("the planted read must be found:\n{log}"));
    let raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(finding.join("finding.json")).unwrap()).unwrap();
    assert_eq!(raw["runtime_mode"]["shim_armed"], true, "{raw:#}");
    let sanitizer_log = std::fs::read_to_string(finding.join("sanitizer.log")).unwrap_or_default();
    assert!(
        !sanitizer_log.contains("cannot be preloaded"),
        "{sanitizer_log}"
    );
}

/// Every file under `dir`, recursively.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                found.push(path);
            }
        }
    }
    found
}

/// A tree and work dir under a directory with `&` (`R&D/`) build and fuzz:
/// the ampersand is double-quoted wherever a path reaches a recipe. The
/// directory name also spells a command between ampersands, so a path that
/// any recipe emitted unquoted would run it and leave its marker file behind.
#[test]
fn auto_builds_and_fuzzes_targets_under_a_path_with_an_ampersand() {
    if !tool_available("clang") || !tool_available("clang++") || !tool_available("make") {
        eprintln!("skip: clang/clang++/make unavailable");
        return;
    }
    let bin = bhf_bin();
    if !bin.is_file() {
        eprintln!("skip: bhf binary not built");
        return;
    }
    const MARKER: &str = "bhf-ampersand-marker";
    let tmp = tempfile::tempdir().expect("temp dir");
    let root = tmp.path().join(format!("R&D&touch {MARKER}&x"));
    let tree = root.join("proj");
    let src = tree.join("src");
    let work = root.join("work");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("record.h"),
        "#include <stddef.h>\nint parse_record(const unsigned char *data, size_t len);\n",
    )
    .unwrap();
    std::fs::write(
        src.join("record.c"),
        "#include \"record.h\"\n\
         int parse_record(const unsigned char *data, size_t len) {\n\
         \x20   int slots[4] = {0};\n\
         \x20   return len ? slots[data[0]] : 0;\n\
         }\n",
    )
    .unwrap();
    std::fs::write(
        src.join("frame.hpp"),
        "#pragma once\n#include <cstddef>\n\
         namespace demo {\nint parse_frame(const unsigned char *data, std::size_t len);\n}\n",
    )
    .unwrap();
    std::fs::write(
        src.join("frame.cpp"),
        "#include \"frame.hpp\"\n\
         namespace demo {\n\
         int parse_frame(const unsigned char *data, std::size_t len) {\n\
         \x20   return len > 4 ? data[4] : 0;\n\
         }\n\
         }\n",
    )
    .unwrap();

    let output = Command::new(&bin)
        .arg("auto")
        .arg(&tree)
        .arg("--work-dir")
        .arg(&work)
        .args([
            "--languages",
            "c,cpp",
            "--max-targets",
            "2",
            "--jobs",
            "1",
            "--per-target-time",
            "6",
            "--no-discovery-cache",
        ])
        .output()
        .expect("run bhf auto");
    let log = format!(
        "stderr:\n{}\nstdout:\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(!log.contains("refusing to generate harness"), "{log}");
    let outcomes = outcomes(&work);
    for target in ["parse_record", "parse_frame"] {
        assert!(
            outcomes
                .iter()
                .any(|(name, outcome, _)| name.ends_with(target) && outcome == "built_and_fuzzed"),
            "{target} under an `&` path must build and fuzz; got {outcomes:?}\n{log}"
        );
    }
    assert!(
        !finding_dirs(&work).is_empty(),
        "the planted read must be found:\n{log}"
    );
    let injected: Vec<PathBuf> = files_under(tmp.path())
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|name| name == MARKER))
        .collect();
    assert!(
        injected.is_empty(),
        "an unquoted path ran the command in its name: {injected:?}"
    );
}
