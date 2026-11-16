// SPDX-License-Identifier: Apache-2.0

//! The Ruby, Lua and PHP lanes have no CmpLog, so the dictionary mined from
//! the target's source is what gets the fuzzer past a comparison. It held only
//! string literals, so a byte check against a number (`getbyte(3) - 48`) was
//! left to blind mutation. Each lane's fixture divides by zero when an `RT`
//! record's fourth byte is `'0'`; mining `48` (and the `0` byte it stands for)
//! finds it.

use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn have(interpreter: &[&str], probe: &[&str]) -> bool {
    let present = {
        interpreter.iter().any(|bin| {
            Command::new(bin)
                .args(probe)
                .output()
                .is_ok_and(|o| o.status.success())
        })
    };
    support::require_tool(present, &interpreter.join(" "))
}

/// `bhf auto` over `file` = `source` fuzzing `tlv_ratio` for 20000 inputs at
/// the default seed; whether results/findings.json reports a CWE-369 in it.
fn finds_the_division(lang: &str, file: &str, source: &str) -> (bool, String) {
    let root = TestDir::new(&format!("numeric-dict-{lang}"));
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join(file), source).unwrap();
    let work = root.join("work");
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["auto", "--work-dir", work.to_str().unwrap()])
        .args(["--languages", lang, "--target", "tlv_ratio", "--jobs", "1"])
        .args(["--single-pass", "--iterations", "20000"])
        .args(["--per-target-time", "120"])
        .arg(&src)
        .output()
        .expect("run bhf auto");
    let findings = std::fs::read_to_string(work.join("results/findings.json")).unwrap_or_default();
    let doc: serde_json::Value = serde_json::from_str(&findings).unwrap_or_default();
    let found = doc["findings"].as_array().into_iter().flatten().any(|f| {
        f["cwe"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|c| c.as_u64() == Some(369))
    });
    let dictionary = std::fs::read_dir(work.join("harnesses"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|h| std::fs::read_to_string(h.path().join("dictionary.txt")).unwrap_or_default())
        .collect::<String>();
    let log = format!(
        "findings:\n{findings}\ndictionary:\n{dictionary}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    (found, log)
}

#[test]
#[cfg_attr(
    windows,
    ignore = "Ruby runs under WSL on Windows; see docs/site/windows.md"
)]
fn ruby_finds_a_division_behind_a_numeric_byte_check() {
    if !have(&["ruby"], &["-e", "1"]) {
        eprintln!("skipping: no ruby on PATH");
        return;
    }
    let (found, log) = finds_the_division(
        "ruby",
        "tlv.rb",
        "def tlv_ratio(data)\n  \
         return 0 unless data.start_with?(\"RT\")\n  \
         return 1 if data.bytesize < 4\n  \
         100 / (data.getbyte(3) - 48)\nend\n",
    );
    assert!(found, "{log}");
}

#[test]
#[cfg_attr(
    windows,
    ignore = "Lua runs under WSL on Windows; see docs/site/windows.md"
)]
fn lua_finds_a_division_behind_a_numeric_byte_check() {
    if !have(&["lua", "lua5.4"], &["-e", "assert(math.type)"]) {
        eprintln!("skipping: no lua 5.3+ on PATH");
        return;
    }
    let (found, log) = finds_the_division(
        "lua",
        "tlv.lua",
        "local M = {}\nfunction M.tlv_ratio(data)\n  \
         if data:sub(1, 2) ~= \"RT\" or #data < 4 then return 0 end\n  \
         return 100 // (data:byte(4) - 48)\nend\nreturn M\n",
    );
    assert!(found, "{log}");
}

#[test]
#[cfg_attr(
    windows,
    ignore = "PHP runs under WSL on Windows; see docs/site/windows.md"
)]
fn php_finds_a_division_behind_a_numeric_byte_check() {
    if !have(&["php"], &["-r", "echo 1;"]) {
        eprintln!("skipping: no php on PATH");
        return;
    }
    let (found, log) = finds_the_division(
        "php",
        "tlv.php",
        "<?php\nfunction tlv_ratio(string $data): int {\n    \
         if (substr($data, 0, 2) !== \"RT\" || strlen($data) < 4) {\n        \
         return 0;\n    }\n    \
         return intdiv(100, ord($data[3]) - 48);\n}\n",
    );
    assert!(found, "{log}");
}
