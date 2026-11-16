// SPDX-License-Identifier: Apache-2.0

//! The Common Flow blocks in `docs/site/cli.md` run as written (#229). The
//! manual Ada pipeline there used `--target Pkg.Parse` and the harness id
//! `H-PKG-PARSE` without `--id`, and replayed `findings/F-0001` through
//! `build/H-PKG-PARSE/main`, none of which existed. A `--finding` that names
//! no finding was reported as an Ada stdin harness problem.

#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// The `sh` blocks of cli.md's Common Flow section, one command per line.
fn common_flow_blocks() -> Vec<Vec<String>> {
    let cli_md = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/site/cli.md");
    let text = fs::read_to_string(&cli_md).unwrap();
    let section = text
        .split("\n## Common Flow\n")
        .nth(1)
        .and_then(|rest| rest.split("\n## ").next())
        .expect("cli.md has a Common Flow section");
    section
        .split("```sh\n")
        .skip(1)
        .map(|block| {
            block
                .split("```")
                .next()
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect()
        })
        .collect()
}

struct Outcome {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Run one documented line in `dir`, with `<finding-id>` replaced by
/// `finding_id`. The lines are plain words: no quoting or expansion to honour.
fn run_line(dir: &Path, line: &str, finding_id: Option<&str>) -> Outcome {
    assert!(
        !line
            .replace("<finding-id>", "")
            .contains(['"', '\'', '$', '\\', '|', '<', '>']),
        "a shell construct in {line:?}"
    );
    let mut words = line.split_whitespace();
    assert_eq!(words.next(), Some("bhf"), "{line:?}");
    let args: Vec<String> = words
        .map(|word| match (word.contains("<finding-id>"), finding_id) {
            (true, Some(id)) => word.replace("<finding-id>", id),
            (true, None) => panic!("{line:?} runs before a finding exists"),
            (false, _) => word.to_owned(),
        })
        .collect();
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(&args)
        .current_dir(dir)
        .output()
        .unwrap();
    Outcome {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn copy_example(to: &Path) {
    let example =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/swallowed_constraint_error");
    fs::create_dir_all(to).unwrap();
    for file in ["pkg.adb", "pkg.ads"] {
        fs::copy(example.join(file), to.join(file)).unwrap();
    }
}

fn finding_ids(dir: &Path) -> Vec<String> {
    let mut ids: Vec<String> = fs::read_dir(dir.join("bhf_work/results/findings"))
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| entry.path().join("finding.json").is_file())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    ids.sort();
    ids
}

fn have_ada_toolchain() -> bool {
    let present = which::which("gnatmake").is_ok() && which::which("gprbuild").is_ok();
    support::require_tool(present, "ada toolchain")
}

#[test]
fn the_common_flow_runs_as_written() {
    if !have_ada_toolchain() {
        eprintln!("SKIP: gnatmake/gprbuild not installed — Ada lane unavailable");
        return;
    }
    let blocks = common_flow_blocks();
    assert_eq!(blocks.len(), 2, "{blocks:#?}");
    let temp = TestDir::new("cli-md-common-flow");
    let dir = temp.path();
    copy_example(&dir.join("path/to"));

    let mut finding_id: Option<String> = None;
    for line in &blocks[0] {
        let run = run_line(dir, line, finding_id.as_deref());
        let log = format!("{line}\nstdout:\n{}\nstderr:\n{}", run.stdout, run.stderr);
        assert_eq!(run.code, 0, "{log}");
        if line.starts_with("bhf fuzz ") {
            let ids = finding_ids(dir);
            assert_eq!(ids.len(), 1, "{ids:?}\n{log}");
            finding_id = ids.into_iter().next();
        } else if line.starts_with("bhf replay ") {
            assert!(run.stdout.contains("MATCH"), "{log}");
        } else if line.starts_with("bhf minimize ") {
            assert!(run.stdout.contains("MINIMIZED"), "{log}");
        }
    }
    assert!(finding_id.is_some(), "the Ada block runs bhf fuzz");
    assert!(dir.join("bhf_work/reports/run-last.md").is_file());

    // The second block's source tree and binaries: the example and the
    // harness the first block built.
    copy_example(&dir.join("path/to/src"));
    let harness: PathBuf = dir.join("bhf_work/build/H-PKG-PARSE/obj/main");
    for name in ["bin", "bin-or-firmware"] {
        fs::copy(&harness, dir.join("path/to").join(name)).unwrap();
    }
    let have_rizin = which::which("rizin").is_ok();
    for line in &blocks[1] {
        let run = run_line(dir, line, None);
        let log = format!("{line}\nstdout:\n{}\nstderr:\n{}", run.stdout, run.stderr);
        if line.contains("--adapter rizin") && !have_rizin {
            assert_eq!(run.code, 1, "{log}");
            assert!(run.stderr.contains("rizin was not found"), "{log}");
        } else {
            assert_eq!(run.code, 0, "{log}");
        }
    }
}

/// `bhf replay` and `bhf minimize` with a `--finding` that names nothing say
/// which path they looked at, and run no harness.
#[test]
fn a_missing_finding_names_the_path() {
    let temp = TestDir::new("cli-md-missing-finding");
    let dir = temp.path();
    for line in [
        "bhf replay --finding findings/F-0001 --harness build/H-PKG-PARSE/main",
        "bhf minimize --finding findings/F-0001",
        "bhf replay --finding F-0001",
    ] {
        let run = run_line(dir, line, None);
        let log = format!("{line}\nstdout:\n{}\nstderr:\n{}", run.stdout, run.stderr);
        assert_eq!(run.code, 1, "{log}");
        let path = if line.contains("findings/") {
            "findings/F-0001"
        } else {
            "F-0001"
        };
        assert!(
            run.stderr
                .contains(&format!("no finding at {path}: {path} does not exist")),
            "{log}"
        );
        assert!(!run.stderr.contains("Ada stdin harness"), "{log}");
    }
}
