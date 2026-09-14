// SPDX-License-Identifier: Apache-2.0
//
// A Java class in the default package cannot be referenced from a named package.
// This end-to-end test verifies that `bhf auto` emits its harness in the default
// package too, then compiles and executes the target.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/java_default_package")
        .canonicalize()
        .expect("canonicalize java_default_package fixture")
}

fn bhf_bin() -> PathBuf {
    let mut dir = std::env::current_exe().expect("test exe path");
    dir.pop();
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join("bhf")
}

fn has_jdk() -> bool {
    Command::new("javac").arg("-version").output().is_ok()
        && Command::new("java").arg("-version").output().is_ok()
}

#[test]
fn default_package_java_target_builds_and_executes() {
    let bin = bhf_bin();
    if !bin.exists() {
        eprintln!("skip: bhf binary not built at {}", bin.display());
        return;
    }
    if !has_jdk() {
        eprintln!("skip: no JDK (native Java lane needs javac/java)");
        return;
    }

    let tmp = std::env::temp_dir().join(format!("bhf-java-default-package-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let work = tmp.join("work");
    let seed = tmp.join("trigger");
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::write(&seed, b"G").unwrap();

    let output = Command::new(&bin)
        .args([
            "auto",
            fixture().to_str().unwrap(),
            "--target",
            "parse",
            "--per-target-time",
            "20",
            "--max-targets",
            "1",
            "--seed-file",
            seed.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
        ])
        .output()
        .expect("run bhf auto on default-package Java fixture");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        combined.contains("built+fuzzed"),
        "default-package Java target should build and fuzz, got:\n{combined}"
    );
    let generated = std::fs::read_to_string(
        std::fs::read_dir(work.join("harnesses"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path()
            .join("harness-src/BhfHarness.java"),
    )
    .expect("read default-package generated harness");
    assert!(!generated.contains("package bhfgen;"), "{generated}");
    assert!(
        generated.contains("DefaultPackageParser.parse(a0);"),
        "{generated}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
