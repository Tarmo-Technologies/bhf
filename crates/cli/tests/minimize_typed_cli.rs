// SPDX-License-Identifier: Apache-2.0

//! `bhf minimize --strategy typed` on a generated C/C++ harness (#279)
//! reduces each argument it decodes, by its `arg-layout.json`: an integer to
//! the boundary its crash starts at. It refused every harness but Ada's with
//! a fixed "C/C++" message; a lane without an argument layout is now refused
//! by name.

use std::path::Path;
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

fn ok(work: &Path, args: &[&str]) -> Output {
    let out = bhf(work, args);
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

/// The one finding under `work`.
fn only_finding(work: &Path) -> std::path::PathBuf {
    let mut dirs: Vec<_> = std::fs::read_dir(work.join("results/findings"))
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.join("finding.json").is_file())
        .collect();
    assert!(!dirs.is_empty(), "no finding under {}", work.display());
    dirs.sort();
    dirs.remove(0)
}

#[test]
fn an_integer_argument_is_minimized_to_its_boundary() {
    if Command::new("clang").arg("--version").output().is_err() {
        eprintln!("skipping: no clang");
        return;
    }
    let work = TestDir::new("minimize-typed-c");
    std::fs::write(
        work.join("pick.c"),
        "#include <stdlib.h>\n\
         int pick(int idx) {\n\
         \x20   if (idx > 100) {\n\
         \x20       char *slot = malloc(4);\n\
         \x20       if (!slot) return 0;\n\
         \x20       slot[4] = 1;\n\
         \x20       free(slot);\n\
         \x20       return 1;\n\
         \x20   }\n\
         \x20   return 0;\n\
         }\n",
    )
    .unwrap();
    ok(
        work.path(),
        &[
            "generate-harness",
            "pick.c",
            "--target",
            "pick",
            "--output",
            "generated_harnesses",
            "--id",
            "H-PICK",
        ],
    );
    ok(work.path(), &["build", ".", "--harness", "H-PICK"]);
    std::fs::write(work.join("seed.bin"), 5000_i32.to_le_bytes()).unwrap();
    ok(
        work.path(),
        &[
            "fuzz",
            ".",
            "--harness",
            "H-PICK",
            "--seed-file",
            "seed.bin",
            "--iterations",
            "1",
        ],
    );
    let finding = only_finding(work.path());
    let out = ok(
        work.path(),
        &["minimize", finding.to_str().unwrap(), "--strategy", "typed"],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("strategy=typed"), "{stdout}");
    let minimized = std::fs::read(finding.join("min_testcase.bin")).unwrap();
    assert!(minimized.len() >= 4, "{minimized:?}");
    assert_eq!(
        i32::from_le_bytes(minimized[0..4].try_into().unwrap()),
        101,
        "{minimized:?}"
    );
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(finding.join("finding.json")).unwrap()).unwrap();
    assert_eq!(record["minimization"]["strategy"], "typed", "{record:#}");
    assert!(
        record["minimization"]["typed"]["values_kept"]
            .as_u64()
            .is_some_and(|kept| kept >= 1),
        "{record:#}"
    );
}

#[test]
fn the_typed_refusal_names_the_python_lane() {
    let python = Command::new("python3").arg("--version").output();
    if !python.is_ok_and(|out| out.status.success()) {
        eprintln!("skipping: no python3");
        return;
    }
    let work = TestDir::new("minimize-typed-py");
    let package = work.join("tree/tool");
    std::fs::create_dir_all(&package).unwrap();
    std::fs::write(package.join("__init__.py"), "").unwrap();
    std::fs::write(
        package.join("check.py"),
        "def check(data: bytes) -> int:\n\
         \x20   if len(data) > 1:\n\
         \x20       raise ZeroDivisionError('checked')\n\
         \x20   return 0\n",
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
            "3",
            "--max-targets",
            "1",
            "--jobs",
            "1",
            "--no-discovery-cache",
        ],
    );
    let auto_log = String::from_utf8_lossy(&auto.stderr).into_owned();
    let findings = work.join("work/results/findings");
    let finding = std::fs::read_dir(&findings)
        .unwrap_or_else(|error| panic!("{error}: {auto_log}"))
        .flatten()
        .map(|entry| entry.path())
        .find(|path| path.join("finding.json").is_file())
        .unwrap_or_else(|| panic!("no Python finding: {auto_log}"));
    let out = bhf(
        work.path(),
        &["minimize", finding.to_str().unwrap(), "--strategy", "typed"],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_ne!(out.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("the Python harness"), "{stderr}");
    assert!(!stderr.contains("C/C++ harnesses"), "{stderr}");
    assert!(stderr.contains("--strategy bytes"), "{stderr}");
}
