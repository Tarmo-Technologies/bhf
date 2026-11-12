// SPDX-License-Identifier: Apache-2.0

//! End-to-end checks of what the runtrace shim observes through stdio: a file
//! opened with `fopen` and closed with `fclose` is no resource leak, the event
//! log bhf hands an Ada harness is bhf's own, and a sanitized target's
//! `printf` format strings reach the runtrace log and `bhf explain`.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

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

/// Whether bhf and its runtrace shim are built side by side.
fn bhf_with_shim() -> Option<PathBuf> {
    let bin = bhf_bin();
    let shim = ["libbhf_runtrace.so", "libbhf_runtrace_shim.so"]
        .into_iter()
        .any(|name| bin.with_file_name(name).is_file());
    (bin.is_file() && shim).then_some(bin)
}

fn auto(bin: &Path, tree: &Path, work: &Path, languages: &str, seconds: &str) -> Output {
    Command::new(bin)
        .arg("auto")
        .arg(tree)
        .arg("--work-dir")
        .arg(work)
        .args([
            "--languages",
            languages,
            "--max-targets",
            "1",
            "--jobs",
            "1",
            "--per-target-time",
            seconds,
            "--no-discovery-cache",
        ])
        .env_remove("BHF_RUNTRACE_SHIM")
        .output()
        .expect("run bhf auto")
}

fn log_of(output: &Output) -> String {
    format!(
        "stderr:\n{}\nstdout:\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    )
}

/// Every `finding.json` of the work dir, parsed.
fn findings(work: &Path) -> Vec<(PathBuf, serde_json::Value)> {
    std::fs::read_dir(work.join("results/findings"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let dir = entry.path();
            let text = std::fs::read_to_string(dir.join("finding.json")).ok()?;
            Some((dir, serde_json::from_str(&text).ok()?))
        })
        .collect()
}

fn resource_leaks(work: &Path) -> Vec<String> {
    findings(work)
        .into_iter()
        .filter(|(_, finding)| finding.to_string().contains("BHF-306"))
        .map(|(dir, finding)| format!("{}: {finding}", dir.display()))
        .collect()
}

/// The fuzz pass ran: the target was built and fuzzed.
fn assert_fuzzed(work: &Path, log: &str) {
    let run: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work.join("auto/run.json")).unwrap_or_else(|_| panic!("no run.json\n{log}")),
    )
    .unwrap();
    assert!(
        run["targets"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|target| target["outcome"]["outcome"] == "built_and_fuzzed"),
        "no target was built and fuzzed:\n{log}"
    );
}

/// A target that reads a file with `fopen` and closes it with `fclose`
/// releases it: glibc closes the descriptor inside `fclose`, which the shim
/// now records, so no BHF-306 "unreleased resource" finding is raised.
#[test]
fn a_file_read_with_fopen_and_fclose_is_not_a_resource_leak() {
    if !tool_available("clang++") || !tool_available("make") {
        eprintln!("skip: clang++/make unavailable");
        return;
    }
    let Some(bin) = bhf_with_shim() else {
        eprintln!("skip: bhf and its runtrace shim are not built");
        return;
    };
    let tmp = tempfile::tempdir().expect("temp dir");
    let tree = tmp.path().join("proj");
    let work = tmp.path().join("work");
    std::fs::create_dir_all(tree.join("src")).unwrap();
    let config = tmp.path().join("widget.cfg");
    std::fs::write(&config, "slots=4\n").unwrap();
    std::fs::write(
        tree.join("src/widget.hpp"),
        "#pragma once\n#include <cstddef>\n\
         namespace demo {\nint read_widget(const unsigned char *data, std::size_t len);\n}\n",
    )
    .unwrap();
    std::fs::write(
        tree.join("src/widget.cpp"),
        format!(
            "#include \"widget.hpp\"\n#include <cstdio>\n\
             namespace demo {{\n\
             int read_widget(const unsigned char *data, std::size_t len) {{\n\
             \x20   std::FILE *f = std::fopen(\"{}\", \"r\");\n\
             \x20   if (!f) return -1;\n\
             \x20   int c = std::fgetc(f);\n\
             \x20   std::fclose(f);\n\
             \x20   return len ? c + data[0] : c;\n\
             }}\n}}\n",
            config.display()
        ),
    )
    .unwrap();
    let output = auto(&bin, &tree, &work, "cpp", "4");
    let log = log_of(&output);
    assert_fuzzed(&work, &log);
    let leaks = resource_leaks(&work);
    assert!(
        leaks.is_empty(),
        "an fclose()d file was reported as leaked: {leaks:#?}\n{log}"
    );
}

/// The event log bhf hands every Ada harness (`<work>/events/fuzz-events-*`)
/// is opened by the harness's runtime and closed by its exit: bhf's own
/// plumbing, never the target's leak.
#[test]
fn the_ada_harness_event_log_is_not_a_resource_leak() {
    if which::which("gnatmake").is_err() || which::which("gprbuild").is_err() {
        eprintln!("skip: the Ada toolchain is not installed");
        return;
    }
    let Some(bin) = bhf_with_shim() else {
        eprintln!("skip: bhf and its runtrace shim are not built");
        return;
    };
    let tmp = tempfile::tempdir().expect("temp dir");
    let tree = tmp.path().join("proj");
    let work = tmp.path().join("work");
    std::fs::create_dir_all(&tree).unwrap();
    // A target with no I/O of its own: every file the run opens is bhf's.
    std::fs::write(
        tree.join("records.ads"),
        "package Records is\n   function Checksum (Data : String) return Natural;\nend Records;\n",
    )
    .unwrap();
    std::fs::write(
        tree.join("records.adb"),
        "package body Records is\n\
         \x20  function Checksum (Data : String) return Natural is\n\
         \x20     Sum : Natural := 0;\n\
         \x20  begin\n\
         \x20     for C of Data loop\n\
         \x20        Sum := (Sum + Character'Pos (C)) mod 65_521;\n\
         \x20     end loop;\n\
         \x20     return Sum;\n\
         \x20  end Checksum;\n\
         end Records;\n",
    )
    .unwrap();
    let output = auto(&bin, &tree, &work, "ada", "4");
    let log = log_of(&output);
    assert_fuzzed(&work, &log);
    let leaks = resource_leaks(&work);
    assert!(
        leaks.is_empty(),
        "bhf's own event log was reported as a target leak: {leaks:#?}\n{log}"
    );
}

/// A target built with AddressSanitizer whose only contact with the
/// environment is `printf`: the sanitizer's `printf` interceptor forwards to
/// `vprintf`, which the shim hooks, so the format string is in the runtrace
/// log and `bhf explain` lists it under FAKED ENVIRONMENT instead of saying
/// the run touched nothing.
#[test]
fn a_sanitized_targets_printf_format_reaches_explain() {
    if !tool_available("clang") || !tool_available("make") {
        eprintln!("skip: clang/make unavailable");
        return;
    }
    let Some(bin) = bhf_with_shim() else {
        eprintln!("skip: bhf and its runtrace shim are not built");
        return;
    };
    let tmp = tempfile::tempdir().expect("temp dir");
    let tree = tmp.path().join("proj");
    let work = tmp.path().join("work");
    std::fs::create_dir_all(tree.join("src")).unwrap();
    std::fs::write(
        tree.join("src/record.h"),
        "#include <stddef.h>\nint parse_record(const unsigned char *data, size_t len);\n",
    )
    .unwrap();
    std::fs::write(
        tree.join("src/record.c"),
        "#include \"record.h\"\n#include <stdio.h>\n\
         int parse_record(const unsigned char *data, size_t len) {\n\
         \x20   int slots[4] = {0};\n\
         \x20   printf(\"parse_record len=%zu\\n\", len);\n\
         \x20   return len ? slots[data[0]] : 0;\n\
         }\n",
    )
    .unwrap();
    let output = auto(&bin, &tree, &work, "c", "6");
    let log = log_of(&output);
    assert_fuzzed(&work, &log);
    let (finding, _) = findings(&work)
        .into_iter()
        .find(|(_, finding)| {
            finding["exception"]["name"]
                .as_str()
                .is_some_and(|name| name.starts_with("UBSAN_") || name.starts_with("ASAN_"))
        })
        .unwrap_or_else(|| panic!("the planted read must be found:\n{log}"));
    let id = finding.file_name().expect("finding id").to_owned();
    let explain = Command::new(&bin)
        .arg("explain")
        .arg("--work-dir")
        .arg(&work)
        .arg("--finding-id")
        .arg(&id)
        .env_remove("BHF_RUNTRACE_SHIM")
        .output()
        .expect("run bhf explain");
    let text = String::from_utf8_lossy(&explain.stdout);
    let section = text
        .split("FAKED ENVIRONMENT")
        .nth(1)
        .unwrap_or_else(|| panic!("no FAKED ENVIRONMENT section:\n{text}"));
    assert!(
        section.contains("format string: parse_record len=%zu"),
        "the printf format is missing from explain's environment:\n{text}"
    );
    assert!(!section.contains("touched no external resource"), "{text}");
}
