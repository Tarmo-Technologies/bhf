// SPDX-License-Identifier: Apache-2.0
//
// JVM cmplog/RedQueen parity: bhf's own JVM coverage agent captures the
// operands of String/byte comparisons into BHF_CMP_SHM, and the engine splices
// them — solving a multi-byte STRING magic gate that pure coverage-guided
// byte-flipping cannot, exactly like the C/Rust lanes solve magic via
// trace-compares. This is what brings Java fuzzing to the same level.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/java_cmplog")
        .canonicalize()
        .expect("canonicalize java_cmplog fixture")
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
fn jvm_cmplog_solves_a_string_magic_gate_without_a_seed() {
    let bin = bhf_bin();
    if !bin.exists() {
        eprintln!("skip: bhf binary not built at {}", bin.display());
        return;
    }
    if !has_jdk() {
        eprintln!("skip: no JDK (native Java lane needs javac/java)");
        return;
    }

    let tmp = std::env::temp_dir().join(format!("bhf-java-cmplog-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let work = tmp.join("work");

    // NO seed: cmplog must splice the 13-byte "BHF_MAGIC" operand it captures
    // from String.startsWith. A generous budget keeps it robust on slow CI; in
    // practice it solves in a couple hundred execs.
    let output = Command::new(&bin)
        .args([
            "auto",
            fixture().to_str().unwrap(),
            "--per-target-time",
            "25",
            "--max-targets",
            "1",
            "--work-dir",
            work.to_str().unwrap(),
        ])
        .output()
        .expect("run bhf auto on java_cmplog fixture");
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("built+fuzzed"),
        "Java cmplog target should build + fuzz, got:\n{combined}"
    );

    // The crashing input must carry the spliced magic — proof cmplog (not luck)
    // solved the gate.
    let findings = work.join("findings");
    let mut solved = false;
    if let Ok(entries) = std::fs::read_dir(&findings) {
        for entry in entries.flatten() {
            if let Ok(tc) = std::fs::read(entry.path().join("testcase.bin")) {
                if tc.windows(b"BHF_MAGIC".len()).any(|w| w == b"BHF_MAGIC") {
                    solved = true;
                }
            }
        }
    }
    assert!(
        solved,
        "cmplog should splice BHF_MAGIC into a crashing input (no-seed), output:\n{combined}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
