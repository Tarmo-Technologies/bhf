// SPDX-License-Identifier: Apache-2.0

//! The PHP lane's coverage is the lines that ran. pcov lists every executable
//! line of a loaded file and marks the ones that did not run with -1; folding
//! those in made coverage constant from the first input, so the lane never
//! saw progress through a gate, and every harness's `covered-lines.txt`
//! claimed the whole file, sibling functions included.

use std::path::Path;
use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// `tlv_ratio` (lines 10-19) divides by zero past two string gates, which
/// the fuzzer passes one at a time only when it sees the first one open;
/// `tlv_sum` (lines 2-8) runs none of it.
const TARGET: &str = "<?php
function tlv_sum(string $data): int {
    $total = 0;
    for ($i = 0; $i < strlen($data); $i++) {
        $total += ord($data[$i]);
    }
    return $total;
}

function tlv_ratio(string $data): int {
    if (substr($data, 0, 2) !== \"RT\") {
        return 0;
    }
    if (substr($data, 2, 4) !== \"cmd:\") {
        return 1;
    }
    $body = substr($data, 6);
    return intdiv(strlen($body), substr_count($body, \",\"));
}
";

fn have_php_with_pcov() -> bool {
    Command::new("php")
        .args([
            "-d",
            "pcov.enabled=1",
            "-r",
            "exit(function_exists('\\\\pcov\\\\start') ? 0 : 1);",
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// `bhf auto` over a tree holding only the fixture, fuzzing `target`.
fn auto(root: &TestDir, target: &str, extra: &[&str]) -> (std::path::PathBuf, String) {
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("tlv.php"), TARGET).unwrap();
    let work = root.join("work");
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["auto", "--work-dir", work.to_str().unwrap()])
        .args(["--languages", "php", "--target", target, "--jobs", "1"])
        .args(["--single-pass"])
        .args(extra)
        .arg(&src)
        .output()
        .expect("run bhf auto");
    let log = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (work, log)
}

/// The `tlv.php` line numbers every harness's `covered-lines.txt` lists.
fn covered_fixture_lines(work: &Path) -> Vec<u32> {
    let mut lines = Vec::new();
    for harness in std::fs::read_dir(work.join("harnesses")).unwrap().flatten() {
        let text =
            std::fs::read_to_string(harness.path().join("covered-lines.txt")).unwrap_or_default();
        lines.extend(text.lines().filter_map(|entry| {
            let (file, line) = entry.rsplit_once(':')?;
            file.ends_with("tlv.php")
                .then(|| line.parse::<u32>().ok())
                .flatten()
        }));
    }
    lines.sort_unstable();
    lines
}

#[test]
#[cfg_attr(
    windows,
    ignore = "PHP runs under WSL on Windows; see docs/site/windows.md"
)]
fn fuzzing_one_function_marks_none_of_its_siblings_lines() {
    if !have_php_with_pcov() {
        eprintln!("skipping: no php with pcov on PATH");
        return;
    }
    let root = TestDir::new("php-coverage-sibling");
    let (work, log) = auto(&root, "tlv_sum", &["--per-target-time", "3"]);

    let lines = covered_fixture_lines(&work);
    assert!(
        lines.iter().any(|line| (2..=8).contains(line)),
        "tlv_sum's own lines must be covered: {lines:?}\n{log}"
    );
    assert!(
        !lines.iter().any(|line| (10..=19).contains(line)),
        "tlv_ratio never ran, so none of its lines are covered: {lines:?}\n{log}"
    );
}

#[test]
#[cfg_attr(
    windows,
    ignore = "PHP runs under WSL on Windows; see docs/site/windows.md"
)]
fn a_string_gated_division_by_zero_is_found_within_twenty_thousand_inputs() {
    if !have_php_with_pcov() {
        eprintln!("skipping: no php with pcov on PATH");
        return;
    }
    let root = TestDir::new("php-coverage-gated");
    let (work, log) = auto(
        &root,
        "tlv_ratio",
        &["--iterations", "20000", "--per-target-time", "120"],
    );

    let findings = std::fs::read_to_string(work.join("results/findings.json")).unwrap_or_default();
    assert!(
        findings.contains("tlv_ratio") && findings.contains("DivisionByZeroError"),
        "coverage through the RT and cmd: gates must reach the division:\n{findings}\n{log}"
    );
}
