// SPDX-License-Identifier: Apache-2.0

//! The help of `report`, `model`, `snippet` and `license-audit` says what the
//! commands do (#227). `--sarif`/`--csv` and `bhf model` were hidden,
//! snippet's help listed eight of its sixteen languages, and `bhf
//! license-audit`, which checks bhf's own Cargo dependencies, read as a
//! license check of the scanned project. The top-level area guide names every
//! visible command.

use std::process::Command;

fn help(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(args)
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success(), "{args:?}");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn report_help() {
    let text = help(&["report"]);
    for flag in ["--sarif", "--csv", "--junit", "--model", "--baseline"] {
        assert!(text.contains(flag), "{flag}:\n{text}");
    }
    assert!(text.contains("it takes no path"), "{text}");
    assert!(text.contains("results/findings.sarif"), "{text}");
}

#[test]
fn model_help() {
    let top = help(&[]);
    assert!(top.contains("  model "), "bhf model is listed:\n{top}");
    let train = help(&["model", "train"]);
    for words in [
        "true_positive",
        "false_positive",
        "low_value",
        "finding_path",
    ] {
        assert!(train.contains(words), "{words}:\n{train}");
    }
}

#[test]
fn snippet_help() {
    let text = help(&["snippet"]);
    // The values come from the language enum, all sixteen of them.
    for language in [
        "ada",
        "c",
        "cpp",
        "rust",
        "java",
        "python",
        "perl",
        "go",
        "cobol",
        "fortran",
        "csharp",
        "javascript",
        "typescript",
        "ruby",
        "lua",
        "php",
    ] {
        assert!(text.contains(language), "{language}:\n{text}");
    }
    assert!(!text.contains("One of: ada, c, cpp"), "{text}");
}

#[test]
fn license_audit_help() {
    let text = help(&["license-audit"]);
    assert!(text.contains("bhf's own Cargo dependencies"), "{text}");
    assert!(
        text.contains("To list a scanned tree's dependencies and their licenses, use `bhf sbom`"),
        "{text}"
    );
    let top = help(&[]);
    assert!(
        top.contains("Check the licenses of bhf's own Cargo dependencies"),
        "{top}"
    );
}

/// Every command `bhf --help` lists is in its "COMMANDS BY AREA" guide.
#[test]
fn the_area_guide_names_every_visible_command() {
    let top = help(&[]);
    let guide = top
        .split("COMMANDS BY AREA")
        .nth(1)
        .and_then(|rest| rest.split("\n\n").next())
        .expect("the area guide");
    let commands = top
        .split("\nCommands:\n")
        .nth(1)
        .and_then(|rest| rest.split("\n\n").next())
        .expect("the command list");
    for command in commands
        .lines()
        .filter_map(|line| line.strip_prefix("  ")?.split_whitespace().next())
        .filter(|command| *command != "help")
    {
        assert!(
            guide
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
                .any(|word| word == command),
            "the area guide does not name `{command}`:\n{guide}"
        );
    }
}
