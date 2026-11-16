// SPDX-License-Identifier: Apache-2.0

//! auto.md documents every `bhf auto` flag (#225). `--max-attempts`,
//! `--sbom`, the WinAFL flags, the decoder bounds and others appeared nowhere
//! in the docs, and the `--max-targets` row described a top-N prefilter where
//! the flag caps the targets that fuzz and backfills past nonviable ones.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

fn help(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(args)
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The long flags `--help` lists as options (`  -j, --jobs <N>`).
fn flags(help: &str) -> BTreeSet<String> {
    help.lines()
        .filter_map(|line| {
            let option = line.trim_start();
            let option = option
                .strip_prefix('-')
                .filter(|rest| rest.len() > 2 && rest.as_bytes()[1] == b',')
                .map_or(option, |rest| rest[2..].trim_start());
            let name = option.strip_prefix("--")?;
            let end = name
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
                .unwrap_or(name.len());
            (line.starts_with("  ") && end > 0).then(|| format!("--{}", &name[..end]))
        })
        .collect()
}

fn auto_md() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/site/auto.md"))
        .unwrap()
}

#[test]
fn auto_md_documents_every_auto_flag() {
    let globals = flags(&help(&[]));
    let auto = flags(&help(&["auto"]));
    assert!(
        auto.len() > 50 && auto.contains("--max-attempts") && globals.contains("--profile"),
        "{auto:?} {globals:?}"
    );
    let doc = auto_md();
    let missing: Vec<String> = auto
        .into_iter()
        .filter(|flag| !globals.contains(flag) && flag != "--help")
        .filter(|flag| !doc.contains(&format!("`{flag}")))
        .collect();
    assert!(missing.is_empty(), "auto.md does not document {missing:?}");
}

/// The table row for `flag`.
fn row<'a>(doc: &'a str, flag: &str) -> &'a str {
    doc.lines()
        .find(|line| line.starts_with(&format!("| `{flag}")))
        .unwrap_or_else(|| panic!("auto.md has no {flag} row"))
}

#[test]
fn the_max_targets_row_is_a_fuzz_cap_with_backfill_and_max_attempts_has_one() {
    let help = help(&["auto"]);
    assert!(help.contains("reach the FUZZ phase"), "{help}");
    assert!(help.contains("backfilled"), "{help}");
    let doc = auto_md();
    let max_targets = row(&doc, "--max-targets");
    for words in [
        "reach the **fuzz** phase",
        "backfilled",
        "not on the candidates inspected",
    ] {
        assert!(max_targets.contains(words), "{max_targets}");
    }
    assert!(
        !max_targets.contains("Keep only the top-N"),
        "{max_targets}"
    );
    let max_attempts = row(&doc, "--max-attempts");
    assert!(max_attempts.contains("**inspected**"), "{max_attempts}");
}
