// SPDX-License-Identifier: Apache-2.0

//! The exit codes `bhf auto` documents in auto.md and cli.md are the ones it
//! uses. The docs listed three, said a missing source path exits 2 (it exited
//! 1), and had no code for harnesses that built but whose sanitizer runtime
//! cannot start.

use std::path::Path;
use std::process::Command;

fn docs(name: &str) -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/site")
            .join(name),
    )
    .unwrap()
}

const CODES: [(i32, &str); 4] = [
    (cli::auto::cli::EXIT_RAN, "built and ran"),
    (cli::auto::cli::EXIT_NONE_BUILT, "none built"),
    (
        cli::auto::cli::EXIT_NO_CANDIDATES,
        "No candidates discovered",
    ),
    (
        cli::auto::cli::EXIT_SANITIZER_RUNTIME,
        "sanitizer runtime does not start",
    ),
];

#[test]
fn the_exit_tables_match_the_cli() {
    let auto = docs("auto.md");
    let table = auto
        .split("## Exit Codes")
        .nth(1)
        .and_then(|rest| rest.split("\n## ").next())
        .expect("auto.md has an Exit Codes section");
    let rows: Vec<(i32, &str)> = table
        .lines()
        .filter_map(|line| {
            let mut cells = line.trim().trim_matches('|').split('|').map(str::trim);
            let code = cells.next()?.parse().ok()?;
            Some((code, cells.next()?))
        })
        .collect();
    assert_eq!(rows.len(), CODES.len(), "{table}");
    for (code, meaning) in CODES {
        assert!(
            rows.iter()
                .any(|(row, text)| *row == code && text.contains(meaning)),
            "auto.md has no row {code} ({meaning}): {table}"
        );
    }
    let cli = docs("cli.md");
    let sentence = cli
        .split("Exit codes: `0` at least one target built and ran")
        .nth(1)
        .and_then(|rest| rest.split("\n\n").next())
        .expect("cli.md states auto's exit codes");
    for code in [1, 2, 3] {
        assert!(
            sentence.contains(&format!("`{code}`")),
            "cli.md lacks `{code}`: {sentence}"
        );
    }
}

#[test]
fn a_source_path_that_does_not_exist_exits_2() {
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["auto", "/nonexistent/bhf-tree"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(cli::auto::cli::EXIT_NO_CANDIDATES),
        "{stderr}"
    );
    assert!(stderr.contains("does not exist"), "{stderr}");
}
