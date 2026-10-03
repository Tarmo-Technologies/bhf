// SPDX-License-Identifier: Apache-2.0

//! End-to-end check that `bhf auto --list-fakes` prints the
//! manifest as a table, and that the info and plan modes leave no
//! results index behind.

use std::process::Command;

fn bhf_bin() -> std::path::PathBuf {
    let path = env!("CARGO_BIN_EXE_bhf");
    std::path::PathBuf::from(path)
}

#[test]
fn bhf_auto_list_fakes_prints_known_plugins() {
    let output = Command::new(bhf_bin())
        .args(["auto", ".", "--list-fakes"])
        .output()
        .expect("spawn bhf auto --list-fakes");
    assert!(
        output.status.success(),
        "bhf auto --list-fakes exit={:?} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    for name in ["env", "net", "fs", "dl", "dlsym", "identity"] {
        assert!(
            stdout.contains(name),
            "missing {name} in --list-fakes output: {stdout}"
        );
    }
    assert!(stdout.contains("BHF_FAKE_IDENTITY"));
    assert!(stdout.contains("env-gated"));
    assert!(stdout.contains("always-on"));
}

/// Info and plan modes (`--list-fakes`, `--list-targets`, `--dry-run`) produce
/// no findings, so they must neither record a producer nor create `results/`.
#[test]
fn info_and_plan_modes_do_not_create_results() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("a.c"),
        "int process(const char *d, unsigned long n){ return n>0?d[0]:0; }\n",
    )
    .unwrap();
    for flag in ["--list-fakes", "--list-targets", "--dry-run"] {
        let work = tmp.path().join(format!("work{flag}"));
        let output = Command::new(bhf_bin())
            .arg("auto")
            .arg(&src)
            .arg(flag)
            .arg("--work-dir")
            .arg(&work)
            .output()
            .unwrap_or_else(|e| panic!("spawn bhf auto {flag}: {e}"));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(0),
            "bhf auto {flag} exit; stderr={stderr}"
        );
        assert!(
            !work.join("results").exists(),
            "bhf auto {flag} must not create results/; stderr={stderr}"
        );
        assert!(
            !stderr.contains("Results:"),
            "bhf auto {flag} must not rebuild the results index; stderr={stderr}"
        );
    }
}
