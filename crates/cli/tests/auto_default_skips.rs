// SPDX-License-Identifier: Apache-2.0

//! `bhf auto` names the directories its default non-library filter skips, and
//! `bhf list targets`, which lists them, marks the rows auto leaves out.

use std::path::Path;
use std::process::{Command, Output};

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

const DIRS: &[&str] = &[
    "src",
    "latest",
    "attestation",
    "tests",
    "test",
    "examples",
    "demo",
    "bench",
    "fuzz",
    "tools",
    "cli",
    "app",
    "vendor",
    "third_party",
    "docs",
    "contrib",
];

fn bhf(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(args)
        .env("RAYON_NUM_THREADS", "1")
        .output()
        .expect("run bhf")
}

fn fixture() -> TestDir {
    let dir = TestDir::new("default-skips");
    for name in DIRS {
        let sub = dir.join("tree").join(name);
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(
            sub.join("lib.c"),
            format!(
                "int parse_{}(const unsigned char *d, unsigned long n) {{ return n ? d[0] : 0; }}\n",
                name.replace('-', "_")
            ),
        )
        .unwrap();
    }
    dir
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn auto_names_the_dirs_it_skips_by_default() {
    let dir = fixture();
    let tree = dir.join("tree");
    let work = dir.join("work");
    let output = bhf(&[
        "auto",
        &tree.to_string_lossy(),
        "--work-dir",
        &work.to_string_lossy(),
        "--list-targets",
    ]);
    let out = text(&output);
    assert!(output.status.success(), "{out}");
    let summary = out
        .lines()
        .find(|line| line.contains("skipped as non-library code by default"))
        .unwrap_or_else(|| panic!("no skip summary: {out}"));
    for skipped in &DIRS[3..] {
        assert!(
            summary.contains(&format!("{skipped}/ (1 file)")),
            "{skipped} not named: {summary}"
        );
    }
    assert!(summary.contains("tests/ (1 file)"), "{summary}");
    assert!(summary.contains("--include-dir"), "{summary}");
    for kept in ["parse_src", "parse_latest", "parse_attestation"] {
        assert!(out.contains(kept), "{kept} missing: {out}");
    }
    assert!(!out.contains("parse_tools"), "{out}");

    // --include-dir brings one back, and the summary no longer names it.
    let output = bhf(&[
        "auto",
        &tree.to_string_lossy(),
        "--work-dir",
        &work.to_string_lossy(),
        "--list-targets",
        "--include-dir",
        "tools",
    ]);
    let out = text(&output);
    assert!(out.contains("parse_tools"), "{out}");
    assert!(!out.contains("tools/ (1 file)"), "{out}");
}

#[test]
fn list_targets_marks_the_rows_auto_skips() {
    let dir = fixture();
    let tree = dir.join("tree");
    let output = bhf(&["list", "targets", &tree.to_string_lossy(), "--top", "50"]);
    let out = text(&output);
    assert!(output.status.success(), "{out}");
    let row = |name: &str| {
        out.lines()
            .find(|line| {
                line.contains(&format!("parse_{name} ")) || line.ends_with(&format!("parse_{name}"))
            })
            .unwrap_or_else(|| panic!("no row for {name}: {out}"))
            .to_owned()
    };
    assert!(
        row("tools").contains("(bhf auto skips: in tools/)"),
        "{out}"
    );
    assert!(
        row("vendor").contains("(bhf auto skips: in vendor/)"),
        "{out}"
    );
    assert!(!row("src").contains("bhf auto skips"), "{out}");
    assert!(!row("latest").contains("bhf auto skips"), "{out}");

    let json = bhf(&[
        "list",
        "targets",
        &tree.to_string_lossy(),
        "--top",
        "50",
        "--format",
        "json",
    ]);
    let rows: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    let skipped: Vec<&str> = rows
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["target"]["auto_skips"].is_string())
        .map(|row| row["target"]["name"].as_str().unwrap())
        .collect();
    assert_eq!(skipped.len(), DIRS.len() - 3, "{skipped:?}");
    assert!(Path::new(&tree).is_dir());
}
