// SPDX-License-Identifier: Apache-2.0

//! The documented Ada flow on `examples/swallowed_constraint_error`:
//! `instrument` the body, `generate-harness --target Pkg.Parse`, `build`.
//! `generate-harness` refused the package-qualified name ("subprogram
//! 'Pkg.Parse' not found") and `instrument` copied only the body, so the
//! build failed on the missing `pkg.ads` (#214).

use std::fs;
use std::path::{Path, PathBuf};

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn run(args: &[&str]) -> i32 {
    cli::run_from(
        std::iter::once("bhf")
            .chain(args.iter().copied())
            .map(str::to_owned)
            .collect::<Vec<_>>(),
    )
}

fn path(p: &Path) -> &str {
    p.to_str().expect("utf-8 path")
}

/// Every file under `dir`, relative, with its text.
fn tree(dir: &Path) -> Vec<(PathBuf, String)> {
    let mut files = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in fs::read_dir(&next).unwrap().flatten() {
            let entry_path = entry.path();
            if entry_path.is_dir() {
                pending.push(entry_path);
            } else {
                let text = String::from_utf8_lossy(&fs::read(&entry_path).unwrap()).into_owned();
                files.push((entry_path.strip_prefix(dir).unwrap().to_path_buf(), text));
            }
        }
    }
    files.sort();
    files
}

#[test]
fn a_package_qualified_target_instruments_generates_and_builds() {
    let example =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/swallowed_constraint_error");
    let temp = TestDir::new("ada-qualified-target");
    let work = temp.join("bhf_work");
    let instrumented = work.join("src_instrumented");
    let harnesses = work.join("generated_harnesses");

    assert_eq!(
        run(&[
            "instrument",
            path(&example.join("pkg.adb")),
            "--output",
            path(&instrumented),
        ]),
        0
    );
    assert_eq!(
        fs::read(instrumented.join("pkg.ads")).expect("the spec is copied beside the body"),
        fs::read(example.join("pkg.ads")).unwrap()
    );

    let body = instrumented.join("pkg.adb");
    for (target, id) in [("Pkg.Parse", "H-QUALIFIED"), ("Parse", "H-BARE")] {
        let out = temp.join(id);
        assert_eq!(
            run(&[
                "generate-harness",
                path(&body),
                "--target",
                target,
                "--output",
                path(&out),
                "--id",
                "H-PKG-PARSE",
            ]),
            0,
            "--target {target}"
        );
    }
    assert_eq!(
        tree(&temp.join("H-QUALIFIED")),
        tree(&temp.join("H-BARE")),
        "Pkg.Parse and Parse generate the same harness"
    );

    if which::which("gprbuild").is_err() && which::which("gnatmake").is_err() {
        eprintln!("skipping the build: no Ada compiler on PATH");
        return;
    }
    assert_eq!(
        run(&[
            "generate-harness",
            path(&body),
            "--target",
            "Pkg.Parse",
            "--output",
            path(&harnesses),
            "--id",
            "H-PKG-PARSE",
        ]),
        0
    );
    assert_eq!(run(&["build", path(&work), "--harness", "H-PKG-PARSE"]), 0);
    assert!(work.join("build/H-PKG-PARSE/obj/main").exists());
}
