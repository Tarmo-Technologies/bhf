// SPDX-License-Identifier: Apache-2.0
//! Python 2 source is discovered via the tolerant line-based extractor (the
//! bundled tree-sitter-python grammar is Python 3 only and fails on `print`
//! statements / `except E, e:`) and tagged with the Python 2 dialect. Where a
//! `python2` interpreter exists `bhf auto` fuzzes it with the same runtime
//! (#285); without one it takes the report-only path (discover + statically
//! analyze, not fuzzed).

use cli::auto::candidate::Lang;
use cli::auto::discovery::discover;
use std::fs;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::process::Command;

#[cfg(unix)]
mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn tmp(tag: &str) -> TestDir {
    TestDir::new(tag)
}

#[test]
fn python2_file_is_discovered_with_python2_dialect() {
    let dir = tmp("py2-disc");
    // A genuine Python 2 module: `print` statement + `except E, e:` comma bind.
    fs::write(
        dir.join("legacy.py"),
        "def parse_record(data):\n\
         \x20   print 'parsing', data\n\
         \x20   try:\n\
         \x20       return int(data)\n\
         \x20   except ValueError, e:\n\
         \x20       return None\n",
    )
    .unwrap();

    let candidates = discover(&dir).expect("discover py2 tree");
    let py = candidates
        .iter()
        .find(|c| c.lang == Lang::Python && c.name == "parse_record")
        .expect("the Python 2 function must be discovered by the tolerant extractor");
    assert_eq!(
        py.dialect.map(|d| d.as_str()),
        Some("python2"),
        "discovered Python 2 target must carry the Python 2 dialect"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn modern_python3_file_keeps_python3_dialect_and_tree_sitter_path() {
    let dir = tmp("py3-disc");
    fs::write(
        dir.join("modern.py"),
        "def decode(data: bytes) -> dict:\n\
         \x20   print(data)\n\
         \x20   return {}\n",
    )
    .unwrap();

    let candidates = discover(&dir).expect("discover py3 tree");
    let py = candidates
        .iter()
        .find(|c| c.lang == Lang::Python && c.name == "decode")
        .expect("the Python 3 function must be discovered");
    assert_eq!(py.dialect.map(|d| d.as_str()), Some("python3"));

    let _ = fs::remove_dir_all(&dir);
}

/// #285: a Python 2 module fuzzes under `python2`, and its planted IndexError
/// is found. Python 2 was report-only, and the runtime did not import under
/// Python 2. Needs `python2` (enforced with `BHF_REQUIRE_TOOLS=1`).
#[cfg(unix)]
#[test]
fn auto_fuzzes_a_python2_module_under_python2_and_finds_its_index_error() {
    let python2 = which::which("python2").is_ok() || which::which("python2.7").is_ok();
    if !support::require_tool(python2, "python2") {
        eprintln!("SKIP: no python2 interpreter on PATH");
        return;
    }
    let src = tmp("py2-auto-src");
    fs::write(
        src.join("legacy_records.py"),
        "def parse_record(data):\n\
         \x20   print \"parsing %d bytes\" % len(data)\n\
         \x20   if len(data) < 2 or data[0] != \"R\":\n\
         \x20       return None\n\
         \x20   fields = data.split(\",\")\n\
         \x20   return fields[3]\n",
    )
    .unwrap();
    let work = tmp("py2-auto-work");
    let out = Command::new(PathBuf::from(env!("CARGO_BIN_EXE_bhf")))
        .args(["auto", src.to_str().unwrap(), "--target", "parse_record"])
        .args([
            "--per-target-time",
            "10",
            "--max-targets",
            "1",
            "--jobs",
            "1",
        ])
        .args(["--work-dir", work.to_str().unwrap()])
        .output()
        .expect("run bhf auto");
    let log = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(log.contains("1 built+fuzzed"), "{log}");
    let findings: serde_json::Value =
        serde_json::from_slice(&fs::read(work.join("results/findings.json")).unwrap()).unwrap();
    let found = findings["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| {
            finding["title"]
                .as_str()
                .unwrap_or("")
                .contains("parse_record")
                && finding["cwe"]
                    .as_array()
                    .is_some_and(|cwe| cwe.contains(&125.into()))
        });
    assert!(
        found,
        "no out-of-bounds read in parse_record: {findings:#}\n{log}"
    );
}
