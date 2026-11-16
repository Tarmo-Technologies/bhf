// SPDX-License-Identifier: Apache-2.0

//! Harness ids do not depend on how the root is spelled, an id `bhf list
//! targets` prints selects that target in `bhf auto`, and a `--target`,
//! `--harness-id` or `--target-file` selection that matches nothing exits 2
//! naming the closest targets, in both commands.

use std::path::Path;
use std::process::{Command, Output};

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn bhf(cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
        .current_dir(cwd)
        .args(args)
        .env("RAYON_NUM_THREADS", "1")
        .output()
        .expect("run bhf")
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn listed_ids(cwd: &Path, root: &str) -> Vec<String> {
    let output = bhf(cwd, &["list", "targets", root, "--format", "json"]);
    assert!(output.status.success(), "{}", text(&output));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let mut ids: Vec<String> = json
        .as_array()
        .or_else(|| json["targets"].as_array())
        .expect("a target array")
        .iter()
        .map(|entry| entry["target"]["harness_id"].as_str().unwrap().to_owned())
        .collect();
    ids.sort();
    ids
}

fn fixture() -> TestDir {
    let dir = TestDir::new("target-selection");
    std::fs::create_dir_all(dir.join("fx/cbug")).unwrap();
    std::fs::write(
        dir.join("fx/cbug/parse.c"),
        "int parse_record(const unsigned char *d, unsigned long n) { return n > 4 ? d[4] : 0; }\n\
         int table_store(const unsigned char *d, unsigned long n) { return n > 2 ? d[2] : 0; }\n",
    )
    .unwrap();
    dir
}

#[test]
fn ids_are_the_same_however_the_root_is_spelled_and_select_in_auto() {
    let dir = fixture();
    let relative = listed_ids(&dir, "fx/cbug");
    let absolute = listed_ids(&dir, &dir.join("fx/cbug").to_string_lossy());
    let dot = listed_ids(&dir.join("fx/cbug"), ".");
    assert_eq!(relative.len(), 2, "{relative:?}");
    assert_eq!(relative, absolute);
    assert_eq!(relative, dot);

    let work = dir.join("work");
    let output = bhf(
        &dir,
        &[
            "auto",
            "fx/cbug",
            "--work-dir",
            &work.to_string_lossy(),
            "--harness-id",
            &relative[0],
            "--dry-run",
        ],
    );
    let out = text(&output);
    assert_eq!(output.status.code(), Some(0), "{out}");
    assert!(!out.contains("matched no target"), "{out}");
}

#[test]
fn a_selection_that_matches_nothing_exits_2_naming_the_closest() {
    let dir = fixture();
    let work = dir.join("work");
    let work = work.to_string_lossy();
    for (flag, value, closest) in [
        ("--harness-id", "H-C0001-DEADBEEF", "H-C0001-"),
        ("--target-file", "pars.c", "parse.c"),
        ("--target", "parse_recrd", "parse_record"),
    ] {
        for dry_run in [true, false] {
            let mut args = vec!["auto", "fx/cbug", "--work-dir", &*work, flag, value];
            args.extend(["--per-target-time", "1"]);
            if dry_run {
                args.push("--dry-run");
            }
            let output = bhf(&dir, &args);
            let out = text(&output);
            assert_eq!(output.status.code(), Some(2), "auto {args:?}: {out}");
            assert!(
                out.contains(&format!(
                    "{flag} '{value}' matched no target; closest: {closest}"
                )),
                "auto {args:?}: {out}"
            );
        }
        let output = bhf(&dir, &["list", "targets", "fx/cbug", flag, value]);
        let out = text(&output);
        assert_eq!(output.status.code(), Some(2), "list targets {flag}: {out}");
        assert!(
            out.contains(&format!(
                "{flag} '{value}' matched no target; closest: {closest}"
            )),
            "list targets {flag}: {out}"
        );
    }
}
