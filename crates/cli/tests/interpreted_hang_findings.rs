// SPDX-License-Identifier: Apache-2.0

//! Hangs in the interpreted lanes are findings located in the target (#382).
//! An input that outlived `--timeout` was re-run with twice that and, when it
//! hung again, reported without a stack: the interpreter answered no signal,
//! so a Python `while True` gave a finding with no location and every hang of
//! a target was one finding. The re-run now asks the lane's driver for the
//! frames its target is running (`BHF_HANG_REPORT_MS`), and a Lua recursion
//! that outlives the timeout under the coverage hook is re-run without it,
//! where it overflows the stack in the target.

#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn have(program: &str, version_flag: &str) -> bool {
    let present = {
        Command::new(program)
            .arg(version_flag)
            .output()
            .is_ok_and(|output| output.status.success())
    };
    support::require_tool(present, program)
}

/// `bhf auto` over `src` with a short timeout and `seeds`; its findings.
fn auto_findings(src: &Path, work: &Path, seeds: &[&[u8]]) -> Vec<serde_json::Value> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bhf"));
    command
        .arg("auto")
        .arg(src)
        .arg("--work-dir")
        .arg(work)
        .args([
            "--timeout",
            "500ms",
            "--per-target-time",
            "20",
            "--max-targets",
            "1",
        ]);
    for (index, seed) in seeds.iter().enumerate() {
        let path = work.with_extension(format!("seed{index}"));
        fs::write(&path, seed).unwrap();
        command.arg("--seed-file").arg(path);
    }
    let output = command.output().unwrap();
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "{log}");
    fs::read_dir(work.join("results/findings"))
        .unwrap_or_else(|error| panic!("no findings dir ({error}):\n{log}"))
        .flatten()
        .filter_map(|entry| {
            serde_json::from_slice(&fs::read(entry.path().join("finding.json")).ok()?).ok()
        })
        .collect()
}

/// The first frame of `finding` and the file it is in.
fn top_frame(finding: &serde_json::Value) -> (String, PathBuf) {
    let frame = &finding["exception"]["stack"][0];
    (
        frame["function"].as_str().unwrap_or_default().to_owned(),
        PathBuf::from(frame["file"].as_str().unwrap_or_default()),
    )
}

fn hangs(findings: &[serde_json::Value]) -> Vec<&serde_json::Value> {
    findings
        .iter()
        .filter(|finding| finding["rule_id"] == "BHF-230")
        .collect()
}

#[test]
fn a_python_while_true_is_one_hang_finding_in_the_target_file() {
    if !have("python3", "--version") {
        eprintln!("skipping: python3 unavailable");
        return;
    }
    let root = TestDir::new("hang-python");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("spin.py"),
        "def parse_frame(data):\n\
         \x20   \"\"\"Count the frame's records.\"\"\"\n\
         \x20   if len(data) > 0 and data[0] == 0x51:\n\
         \x20       n = 0\n\
         \x20       while True:\n\
         \x20           n += 1\n\
         \x20   return len(data)\n",
    )
    .unwrap();
    let found = auto_findings(&src, &root.join("work"), &[b"Q"]);
    let hung = hangs(&found);
    assert_eq!(hung.len(), 1, "{found:#?}");
    let (function, file) = top_frame(hung[0]);
    assert_eq!(function, "parse_frame", "{:#}", hung[0]);
    assert_eq!(file.file_name().unwrap(), "spin.py", "{:#}", hung[0]);
}

/// `bhf auto` over the one-file tree `name` = `source`, seeded with `Q`; its one
/// hang finding is in `name`, in `function`.
fn one_hang_in(lane: &str, name: &str, source: &str, function: &str) {
    let root = TestDir::new(&format!("hang-{lane}"));
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join(name), source).unwrap();
    let found = auto_findings(&src, &root.join("work"), &[b"Q"]);
    let hung = hangs(&found);
    assert_eq!(hung.len(), 1, "{found:#?}");
    let (top, file) = top_frame(hung[0]);
    assert!(top.ends_with(function), "{:#}", hung[0]);
    assert_eq!(file.file_name().unwrap(), name, "{:#}", hung[0]);
}

#[test]
fn a_ruby_loop_is_one_hang_finding_in_the_target_file() {
    if !have("ruby", "--version") {
        eprintln!("skipping: ruby unavailable");
        return;
    }
    one_hang_in(
        "ruby",
        "record_spin.rb",
        "module RecordSpin\n\
         \x20 def self.parse_frame(text)\n\
         \x20   return 0 unless text.bytesize.positive? && text.getbyte(0) == 0x51\n\
         \x20   n = 0\n\
         \x20   loop { n += 1 }\n\
         \x20 end\n\
         end\n",
        "parse_frame",
    );
}

#[test]
fn a_perl_loop_is_one_hang_finding_in_the_target_file() {
    if !have("perl", "-v") {
        eprintln!("skipping: perl unavailable");
        return;
    }
    one_hang_in(
        "perl",
        "RecordSpin.pm",
        "package RecordSpin;\nuse strict;\nuse warnings;\n\n\
         sub parse_frame {\n\
         \x20   my ($data) = @_;\n\
         \x20   return 0 unless length($data) && ord($data) == 0x51;\n\
         \x20   my $n = 0;\n\
         \x20   while (1) { $n++ }\n\
         }\n\n1;\n",
        "parse_frame",
    );
}

#[test]
fn a_php_loop_is_one_hang_finding_in_the_target_file() {
    if !have("php", "--version") {
        eprintln!("skipping: php unavailable");
        return;
    }
    one_hang_in(
        "php",
        "spin.php",
        "<?php\nnamespace Demo;\nclass Spin {\n\
         \x20   public static function parse_frame(string $text): int {\n\
         \x20       if (strlen($text) === 0 || ord($text[0]) !== 0x51) return 0;\n\
         \x20       $n = 0;\n\
         \x20       while (true) { $n++; }\n\
         \x20   }\n}\n",
        "parse_frame",
    );
}

#[test]
fn a_lua_recursion_that_outlives_the_timeout_is_found_in_the_target_file() {
    if !have("lua5.4", "-v") && !have("lua", "-v") {
        eprintln!("skipping: lua unavailable");
        return;
    }
    let root = TestDir::new("hang-lua");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    // Deep enough to overflow Lua's stack; under the coverage hook each call
    // costs enough that it outlives the timeout first.
    fs::write(
        src.join("walk.lua"),
        "local M = {}\n\
         local function down(n)\n\
         \x20 if n == 0 then return 0 end\n\
         \x20 return down(n - 1) + 1\n\
         end\n\
         function M.walk(data)\n\
         \x20 if #data > 0 and data:byte(1) == 81 then return down(#data * 400000) end\n\
         \x20 return 0\n\
         end\n\
         return M\n",
    )
    .unwrap();
    let found = auto_findings(&src, &root.join("work"), &[b"QQQQQQQQ"]);
    let located: Vec<_> = found
        .iter()
        .filter(|finding| {
            top_frame(finding)
                .1
                .file_name()
                .is_some_and(|name| name == "walk.lua")
        })
        .collect();
    assert!(!located.is_empty(), "{found:#?}");
    assert!(
        located.iter().any(|finding| top_frame(finding).0 == "down"),
        "{located:#?}"
    );
}

#[test]
fn two_inputs_hanging_in_one_js_loop_are_one_finding() {
    if !have("node", "--version") {
        eprintln!("skipping: node unavailable");
        return;
    }
    let root = TestDir::new("hang-js");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    // A record's length byte moves the cursor, so a zero length never
    // advances it.
    fs::write(
        src.join("records.js"),
        "'use strict';\n\
         function walkRecords(buf) {\n\
         \x20 let at = 0;\n\
         \x20 while (at + 2 <= buf.length) {\n\
         \x20   at += buf[at + 1];\n\
         \x20 }\n\
         \x20 return at;\n\
         }\n\
         function parseRecords(data) {\n\
         \x20 if (data.length > 2 && data[0] === 0x54) return walkRecords(data.subarray(1));\n\
         \x20 return 0;\n\
         }\n\
         module.exports = { parseRecords };\n",
    )
    .unwrap();
    fs::write(
        src.join("package.json"),
        "{\"name\": \"records\", \"main\": \"records.js\"}\n",
    )
    .unwrap();
    // A zero length at the first record, and at the second.
    let found = auto_findings(
        &src,
        &root.join("work"),
        &[b"T\x01\x00", b"T\x05\x02\x09\x00"],
    );
    let hung = hangs(&found);
    assert_eq!(hung.len(), 1, "{found:#?}");
    let (function, file) = top_frame(hung[0]);
    assert_eq!(function, "walkRecords", "{:#}", hung[0]);
    assert_eq!(file.file_name().unwrap(), "records.js", "{:#}", hung[0]);
}
