// SPDX-License-Identifier: Apache-2.0

//! `bhf corpus minimize` keeps the inputs whose replay adds corpus coverage,
//! which only an Ada harness records. For any other harness it kept none,
//! wrote an empty `--out` and exited 0. It now copies every input through,
//! names the harness's lane and exits 2; an Ada harness still minimizes.

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

/// A corpus of three inputs, two of them the same bytes.
fn corpus(work: &Path, inputs: [&[u8]; 3]) -> PathBuf {
    let dir = work.join("corpus");
    std::fs::create_dir_all(&dir).unwrap();
    for (name, bytes) in ["a", "b", "c"].into_iter().zip(inputs) {
        std::fs::write(dir.join(name), bytes).unwrap();
    }
    dir
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
fn a_c_harness_keeps_every_input_and_exits_2() {
    if Command::new("clang").arg("--version").output().is_err() {
        eprintln!("skipping: no clang");
        return;
    }
    let work = TestDir::new("corpus-minimize-c");
    std::fs::write(
        work.join("tool.c"),
        "#include <stddef.h>\nint parse(const unsigned char *d, size_t n) {\n  \
         return n > 2 && d[0] == 'X';\n}\n",
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
    corpus(work.path(), [b"XYZ", b"XYZ", b"abc"]);
    let out = bhf(
        work.path(),
        &[
            "corpus",
            "minimize",
            "--harness",
            "build/H-TOOL/main",
            "--in",
            "corpus",
            "--out",
            "out",
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("the C harness records no corpus coverage"),
        "{stderr}"
    );
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
    corpus(work.path(), [b"12", b"12", b"not-an-integer"]);
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
