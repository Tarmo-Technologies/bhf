// SPDX-License-Identifier: Apache-2.0

//! The Rust, Fortran and COBOL lanes record a harness's generation metadata
//! (#234), as the C, C++ and Ada generators do: its language,
//! `harness_format_version` and target. Without `generation-metadata.json` a
//! finding of theirs carried no harness format, so a later format change
//! could not be told when it was replayed, and `bhf explain` could only say
//! the harness was built "by an earlier bhf or some other way".

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn runs(program: &str, args: &[&str]) -> bool {
    let present = {
        Command::new(program)
            .args(args)
            .output()
            .is_ok_and(|output| output.status.success())
    };
    support::require_tool(present, program)
}

/// `bhf auto` over `src` for one `language` target; the generation metadata of
/// each harness it built.
fn metadata_of_built_harnesses(
    src: &Path,
    work: &Path,
    language: &str,
    extra: &[&str],
) -> Vec<serde_json::Value> {
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(src)
        .arg("--work-dir")
        .arg(work)
        .args(["--languages", language, "--max-targets", "1", "--jobs", "1"])
        .args(["--per-target-time", "2", "--no-discovery-cache"])
        .args(extra)
        .output()
        .unwrap();
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let harnesses: Vec<PathBuf> = std::fs::read_dir(work.join("harnesses"))
        .unwrap_or_else(|error| panic!("no harnesses ({error}):\n{log}"))
        .flatten()
        .map(|entry| entry.path())
        .filter(|dir| dir.join("main").is_file())
        .collect();
    assert!(!harnesses.is_empty(), "nothing built:\n{log}");
    harnesses
        .iter()
        .map(|dir| {
            let text = std::fs::read_to_string(dir.join("generation-metadata.json"))
                .unwrap_or_else(|error| panic!("{}: {error}\n{log}", dir.display()));
            serde_json::from_str(&text).unwrap()
        })
        .collect()
}

fn assert_recorded(metadata: &[serde_json::Value], language: &str, target: &str) {
    for record in metadata {
        assert_eq!(record["language"], language, "{record:#}");
        assert!(
            record["harness_format_version"]
                .as_u64()
                .is_some_and(|v| v > 0),
            "{record:#}"
        );
        assert!(
            record["target_function"]
                .as_str()
                .is_some_and(|name| name.eq_ignore_ascii_case(target)),
            "{record:#}"
        );
    }
}

#[test]
fn a_fortran_harness_records_its_generation() {
    if !runs("gfortran", &["--version"]) || !runs("clang", &["--version"]) {
        eprintln!("skipping: gfortran or clang unavailable");
        return;
    }
    let root = TestDir::new("lane-metadata-fortran");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("parse.f90"),
        "subroutine parse_record(data)\n  implicit none\n  character(len=*), intent(in) :: data\n  \
         integer :: total\n  total = len(data)\n  if (total > 3) total = total - 1\n\
         end subroutine parse_record\n",
    )
    .unwrap();
    let metadata = metadata_of_built_harnesses(&src, &root.join("work"), "fortran", &[]);
    assert_recorded(&metadata, "fortran", "parse_record");
}

#[test]
fn a_cobol_harness_records_its_generation() {
    if !runs("cobc", &["--version"]) || !runs("clang", &["--version"]) {
        eprintln!("skipping: cobc or clang unavailable");
        return;
    }
    let root = TestDir::new("lane-metadata-cobol");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("parseit.cob"),
        "       IDENTIFICATION DIVISION.\n\
         \x20      PROGRAM-ID. PARSEIT.\n\
         \x20      DATA DIVISION.\n\
         \x20      LINKAGE SECTION.\n\
         \x20      01 BUF PIC X(8).\n\
         \x20      PROCEDURE DIVISION USING BUF.\n\
         \x20          GOBACK.\n",
    )
    .unwrap();
    let metadata = metadata_of_built_harnesses(&src, &root.join("work"), "cobol", &[]);
    assert_recorded(&metadata, "cobol", "PARSEIT");
}

#[test]
fn a_rust_harness_records_its_generation() {
    if !runs("cargo", &["+nightly", "--version"]) {
        eprintln!("skipping: no cargo nightly");
        return;
    }
    let root = TestDir::new("lane-metadata-rust");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/rust_fuzz");
    let metadata = metadata_of_built_harnesses(
        &fixture.canonicalize().unwrap(),
        &root.join("work"),
        "rust",
        &["--run-untrusted"],
    );
    for record in &metadata {
        assert_eq!(record["language"], "rust", "{record:#}");
        assert!(
            record["harness_format_version"]
                .as_u64()
                .is_some_and(|v| v > 0),
            "{record:#}"
        );
        assert!(record["target_function"].is_string(), "{record:#}");
    }
}
