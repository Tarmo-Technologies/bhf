// SPDX-License-Identifier: Apache-2.0

//! The help of `report`, `model`, `snippet` and `license-audit` says what the
//! commands do (#227). `--sarif`/`--csv` and `bhf model` were hidden,
//! snippet's help listed eight of its sixteen languages, and `bhf
//! license-audit`, which checks bhf's own Cargo dependencies, read as a
//! license check of the scanned project. The top-level area guide names every
//! visible command.

use std::process::Command;

/// The terminal width the help tests print at, so their text is the same on
/// every host.
const COLUMNS: usize = 100;

/// `bhf <args> <flag>` (`-h` or `--help`) on a terminal `columns` wide. The
/// output is a pipe, so bhf takes the width from `COLUMNS`.
fn help_page(args: &[&str], flag: &str, columns: usize) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(args)
        .arg(flag)
        .env("COLUMNS", columns.to_string())
        .output()
        .unwrap();
    assert!(output.status.success(), "{args:?}");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// `bhf <args> --help` on a terminal `columns` wide.
fn help_at(args: &[&str], columns: usize) -> String {
    help_page(args, "--help", columns)
}

fn help(args: &[&str]) -> String {
    help_at(args, COLUMNS)
}

/// `text` with each run of whitespace made one space, so a phrase matches
/// wherever the help wrapped it.
fn flat(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The width of the widest line of `text` that clap can wrap: not a single
/// word wider than the terminal, an option's name and value on a line of
/// their own, or the usage line, which clap never wraps.
fn widest_wrappable_line(text: &str) -> usize {
    text.lines()
        .filter(|line| {
            let text = line.trim_start();
            text.split_whitespace().count() > 1
                && !(text.starts_with('-') && !text.contains("  "))
                && !line.starts_with("Usage: ")
        })
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(0)
}

/// `bhf --help` and each command's help, short and long, wrap to the
/// terminal's width, and list the global options after the command's own.
/// `ci` has the widest options and `auto` the longest help.
#[test]
fn help_wraps_to_the_terminal_width_with_the_global_options_last() {
    for args in [
        &[][..],
        &["auto"],
        &["ci"],
        &["fuzz"],
        &["binary", "fuzz"],
        &["kernel"],
    ] {
        for flag in ["-h", "--help"] {
            for columns in [40, 60] {
                let narrow = help_page(args, flag, columns);
                let widest = widest_wrappable_line(&narrow);
                assert!(
                    widest <= columns,
                    "{args:?} {flag} at {columns} ({widest}):\n{narrow}"
                );
            }
            let wide = help_page(args, flag, 160);
            let widest = widest_wrappable_line(&wide);
            // Long help has paragraphs long enough to fill a wide terminal.
            assert!(
                widest <= 160 && (flag == "-h" || widest > 100),
                "{args:?} {flag} ({widest}):\n{wide}"
            );
            let global = wide.find("\nGlobal Options:\n").expect(&wide);
            let own = wide.find("\nOptions:\n").expect(&wide);
            assert!(own < global, "{args:?} {flag}:\n{wide}");
            assert!(wide[global..].contains("  --profile <PROFILE>"), "{wide}");
            assert!(!wide[..global].contains("  --profile <PROFILE>"), "{wide}");
        }
    }
}

/// The command to copy from `bhf --help` and `bhf auto --help` prints whole
/// on a terminal 60 columns wide, and the paragraph after it wraps as one:
/// no line of it but the last is short.
#[test]
fn the_first_run_command_prints_whole_at_60_columns() {
    for (args, heading) in [(&[][..], "START HERE:\n"), (&["auto"][..], "FIRST RUN:\n")] {
        let help = help_at(args, 60);
        let start = help.split(heading).nth(1).expect(&help);
        assert!(
            start.starts_with(
                "  bhf auto /path/to/source --work-dir /path/to/bhf_work \\\n    \
                 --jobs 1 --max-targets 1 --per-target-time 10\n\n"
            ),
            "{args:?}:\n{help}"
        );
        let paragraph = help
            .split("\n\n")
            .find(|paragraph| paragraph.starts_with("Keep the work directory"))
            .expect(&help);
        let lines = paragraph.lines().collect::<Vec<_>>();
        assert!(lines.len() > 1, "{args:?}:\n{paragraph}");
        for line in &lines[..lines.len() - 1] {
            assert!(
                (45..=60).contains(&line.chars().count()),
                "{args:?}: {line:?} in\n{paragraph}"
            );
        }
    }
}

#[test]
fn report_help() {
    let text = flat(&help(&["report"]));
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
    assert!(!flat(&text).contains("One of: ada, c, cpp"), "{text}");
}

#[test]
fn license_audit_help() {
    let text = flat(&help(&["license-audit"]));
    assert!(text.contains("bhf's own Cargo dependencies"), "{text}");
    assert!(
        text.contains("To list a scanned tree's dependencies and their licenses, use `bhf sbom`"),
        "{text}"
    );
    let top = flat(&help(&[]));
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
        .filter_map(|line| {
            line.strip_prefix("  ")
                .filter(|rest| !rest.starts_with(' '))?
                .split_whitespace()
                .next()
        })
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
