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
        .env("COLUMNS", "100")
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
    assert!(help.contains("reach the fuzz phase"), "{help}");
    assert!(help.contains("backfilled"), "{help}");
    let doc = auto_md();
    let max_targets = row(&doc, "--max-targets").replace("**", "");
    assert!(max_targets.contains("fuzz phase"), "{max_targets}");
    // Targets that do not build do not use up the cap: others take their place.
    assert!(
        ["backfill", "fill their places", "take their places"]
            .iter()
            .any(|words| max_targets.contains(words)),
        "{max_targets}"
    );
    assert!(
        !max_targets.contains("Keep only the top-N"),
        "{max_targets}"
    );
    let max_attempts = row(&doc, "--max-attempts");
    assert!(max_attempts.contains("inspect"), "{max_attempts}");
}

/// The table's cells for `flag`: its default and its purpose, with `\|`
/// kept inside a cell.
fn cells(doc: &str, flag: &str) -> (String, String) {
    let line = row(doc, flag).replace("\\|", "\u{1}");
    let cells: Vec<String> = line
        .split('|')
        .map(|cell| cell.trim().replace('\u{1}', "|"))
        .collect();
    (cells[2].clone(), cells[3].clone())
}

/// `--flag` -> its `[default: V]` in `help`.
fn help_defaults(help: &str) -> Vec<(String, String)> {
    let mut current = None;
    let mut defaults = Vec::new();
    for line in help.lines() {
        let trimmed = line.trim_start();
        if line.starts_with("  ") && trimmed.starts_with('-') {
            current = flags(line).into_iter().next();
        }
        if let (Some(flag), Some((_, rest))) = (&current, line.split_once("[default: ")) {
            let value = rest.split(']').next().unwrap_or("").to_owned();
            defaults.push((flag.clone(), value));
        }
    }
    defaults
}

#[test]
fn the_table_defaults_match_the_help() {
    let globals = flags(&help(&[]));
    let doc = auto_md();
    let defaults = help_defaults(&help(&["auto"]));
    assert!(
        defaults.iter().any(|(flag, _)| flag == "--per-target-time"),
        "{defaults:?}"
    );
    let mut wrong = Vec::new();
    for (flag, value) in &defaults {
        if globals.contains(flag) {
            continue;
        }
        let (default, _) = cells(&doc, flag);
        // Computed from the host: the table gives the rule, not a number.
        let rules: &[&str] = match flag.as_str() {
            "--jobs" => &["half the host's cores"],
            "--rss-limit-mb" => &["dynamic", "a quarter of"],
            _ => &[],
        };
        let documented = if rules.is_empty() {
            default.contains(value.as_str())
        } else {
            rules.iter().any(|rule| default.contains(rule))
        };
        if !documented {
            wrong.push(format!("{flag}: help {value:?}, auto.md {default:?}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    // Defaults the help states in prose.
    let (sanitizers, _) = cells(&doc, "--sanitizers");
    assert!(sanitizers.contains("address,undefined"), "{sanitizers}");
    let (_, static_dynamic) = cells(&doc, "--static-dynamic");
    assert!(
        static_dynamic.starts_with("Deprecated, no effect"),
        "{static_dynamic}"
    );
}

/// Rust and C# targets need `--run-untrusted`, and the row says how a run
/// without it reports them (#241).
#[test]
fn the_run_untrusted_row_names_rust_csharp_and_consent_required() {
    let doc = auto_md();
    let (_, purpose) = cells(&doc, "--run-untrusted");
    for words in ["Rust", "C#", "`consent_required`", "needs --run-untrusted"] {
        assert!(purpose.contains(words), "{purpose}");
    }
}
