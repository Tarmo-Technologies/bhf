// SPDX-License-Identifier: Apache-2.0

//! `bhf corpus minimize` keeps the inputs whose replay adds coverage: the
//! edges the harness's driver writes to its coverage map, in every lane
//! (#282), and an Ada harness's event log. It read only the event log, so a
//! C or Python harness kept nothing. A harness that records neither still
//! has every input copied through, and the command exits 2.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn bhf(work: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
        .current_dir(work)
        .args(args)
        .output()
        .unwrap()
}

fn ok(work: &Path, args: &[&str]) {
    let out = bhf(work, args);
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A corpus of `inputs`, named `a`, `b`, ... in order.
fn corpus(work: &Path, inputs: &[&[u8]]) -> PathBuf {
    let dir = work.join("corpus");
    std::fs::create_dir_all(&dir).unwrap();
    for (name, bytes) in ["a", "b", "c", "d", "e", "f"].into_iter().zip(inputs) {
        std::fs::write(dir.join(name), bytes).unwrap();
    }
    dir
}

/// Six inputs over four paths of the targets below: `b` ("AA") takes the
/// path of `a` ("A") and `f` ("Bx") the path of `c` ("B").
const SIX: [&[u8]; 6] = [b"A", b"AA", b"B", b"C", b"CD", b"Bx"];

fn minimize(work: &Path, harness: &str) -> (Option<i32>, String, String) {
    let out = bhf(
        work,
        &[
            "corpus",
            "minimize",
            "--harness",
            harness,
            "--in",
            "corpus",
            "--out",
            "out",
        ],
    );
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn a_c_harness_minimizes_on_its_coverage_map() {
    if Command::new("clang").arg("--version").output().is_err() {
        eprintln!("skipping: no clang");
        return;
    }
    let work = TestDir::new("corpus-minimize-c");
    std::fs::write(
        work.join("tool.c"),
        "#include <stddef.h>\nint parse(const unsigned char *d, size_t n) {\n  \
         if (n == 0) return 0;\n  \
         if (d[0] == 'A') return 1;\n  \
         if (d[0] == 'B') return 2;\n  \
         if (d[0] == 'C') {\n    \
           if (n > 1 && d[1] == 'D') return 4;\n    \
           return 3;\n  \
         }\n  \
         return 5;\n}\n",
    )
    .unwrap();
    ok(
        work.path(),
        &[
            "generate-harness",
            "tool.c",
            "--target",
            "parse",
            "--output",
            "generated_harnesses",
            "--id",
            "H-TOOL",
        ],
    );
    ok(work.path(), &["build", ".", "--harness", "H-TOOL"]);
    corpus(work.path(), &SIX);
    let (code, stdout, stderr) = minimize(work.path(), "build/H-TOOL/main");
    assert_eq!(code, Some(0), "{stderr}");
    assert!(
        stdout.contains("minimized 6 inputs -> 4"),
        "{stdout}{stderr}"
    );
    assert_eq!(names(&work.join("out")), ["a", "c", "d", "e"]);
}

#[test]
fn a_python_harness_minimizes_on_its_coverage_map() {
    let python = Command::new("python3").arg("--version").output();
    if !python.is_ok_and(|out| out.status.success()) {
        eprintln!("skipping: no python3");
        return;
    }
    let work = TestDir::new("corpus-minimize-py");
    let package = work.join("tree/tool");
    std::fs::create_dir_all(&package).unwrap();
    std::fs::write(package.join("__init__.py"), "").unwrap();
    std::fs::write(
        package.join("parse.py"),
        "def parse(data: bytes) -> int:\n\
         \x20   if not data:\n\
         \x20       return 0\n\
         \x20   if data[0:1] == b'A':\n\
         \x20       return 1\n\
         \x20   if data[0:1] == b'B':\n\
         \x20       return 2\n\
         \x20   if data[0:1] == b'C':\n\
         \x20       if data[1:2] == b'D':\n\
         \x20           return 4\n\
         \x20       return 3\n\
         \x20   return 5\n",
    )
    .unwrap();
    let auto = bhf(
        work.path(),
        &[
            "auto",
            "tree",
            "--work-dir",
            "work",
            "--per-target-time",
            "1",
            "--max-targets",
            "1",
            "--jobs",
            "1",
            "--no-discovery-cache",
        ],
    );
    let auto_log = String::from_utf8_lossy(&auto.stderr);
    let harness = std::fs::read_dir(work.join("work/harnesses"))
        .unwrap()
        .flatten()
        .map(|entry| entry.path().join("main"))
        .find(|main| main.is_file())
        .unwrap_or_else(|| panic!("no Python harness: {auto_log}"));
    corpus(work.path(), &SIX);
    let (code, stdout, stderr) = minimize(work.path(), harness.to_str().unwrap());
    assert_eq!(code, Some(0), "{stderr}");
    assert!(
        stdout.contains("minimized 6 inputs -> 4"),
        "{stdout}{stderr}"
    );
    assert_eq!(names(&work.join("out")), ["a", "c", "d", "e"]);
}

/// A harness that writes no coverage map and no event log cannot be
/// minimized: every input is copied through, and it exits 2.
#[cfg(unix)]
#[test]
fn a_harness_with_no_coverage_keeps_every_input_and_exits_2() {
    use std::os::unix::fs::PermissionsExt;
    let work = TestDir::new("corpus-minimize-none");
    let harness = work.join("build/H-SH/main");
    std::fs::create_dir_all(harness.parent().unwrap()).unwrap();
    std::fs::write(&harness, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&harness, std::fs::Permissions::from_mode(0o755)).unwrap();
    corpus(work.path(), &[b"XYZ", b"XYZ", b"abc"]);
    let (code, _, stderr) = minimize(work.path(), "build/H-SH/main");
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("records no coverage"), "{stderr}");
    assert!(stderr.contains("copied all 3 inputs"), "{stderr}");
    assert_eq!(names(&work.join("out")), ["a", "b", "c"]);
}

#[test]
fn an_ada_harness_still_minimizes() {
    if Command::new("gprbuild").arg("--version").output().is_err() {
        eprintln!("skipping: no gprbuild");
        return;
    }
    let work = TestDir::new("corpus-minimize-ada");
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/swallowed_constraint_error");
    let instrumented = work.join("bhf_work/src_instrumented");
    ok(
        work.path(),
        &[
            "instrument",
            fixture.join("pkg.adb").to_str().unwrap(),
            "--output",
            instrumented.to_str().unwrap(),
        ],
    );
    std::fs::copy(fixture.join("pkg.ads"), instrumented.join("pkg.ads")).unwrap();
    ok(
        work.path(),
        &[
            "generate-harness",
            instrumented.join("pkg.adb").to_str().unwrap(),
            "--target",
            "Parse",
            "--output",
            "bhf_work/generated_harnesses",
            "--id",
            "H-ADA-MIN",
        ],
    );
    ok(
        work.path(),
        &["build", "bhf_work", "--harness", "H-ADA-MIN"],
    );
    let build = work.join("bhf_work/build/H-ADA-MIN");
    let harness = [build.join("obj/main"), build.join("main")]
        .into_iter()
        .find(|path| path.is_file())
        .expect("the built Ada harness");
    corpus(work.path(), &[b"12", b"12", b"not-an-integer"]);
    let out = bhf(
        work.path(),
        &[
            "corpus",
            "minimize",
            "--harness",
            harness.to_str().unwrap(),
            "--in",
            "corpus",
            "--out",
            "out",
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    let kept = names(&work.join("out"));
    assert!(
        !kept.is_empty() && kept.len() < 3,
        "{kept:?}: {}{stderr}",
        String::from_utf8_lossy(&out.stdout)
    );
}
