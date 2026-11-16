// SPDX-License-Identifier: Apache-2.0
//! A shell the target runs (`popen`, `system`) inherited `LD_PRELOAD` and
//! `BHF_CMPLOG`, so most of a run's comparison records were the shell's own,
//! and its keywords became dictionary tokens. With `BHF_TARGET_EXE` naming
//! the harness, only processes running that image record: the target and a
//! child it forks, as a fork server's are. Each comparison is recorded once
//! per process.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn target_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("CARGO_TARGET_DIR") {
        return PathBuf::from(dir);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root above crates/bhf_runtrace_shim")
        .join("target")
}

/// The shim cdylib, when it is newer than the code these tests cover.
fn shim_so() -> Option<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let newest_source = ["src/hooks/cmplog.rs", "src/jsonl.rs"]
        .iter()
        .filter_map(|source| manifest.join(source).metadata().ok()?.modified().ok())
        .max()?;
    ["debug", "release"].into_iter().find_map(|profile| {
        let shim = target_dir().join(profile).join("libbhf_runtrace_shim.so");
        let built = shim.metadata().ok()?.modified().ok()?;
        (built >= newest_source).then_some(shim)
    })
}

fn cc() -> Option<&'static str> {
    ["cc", "gcc", "clang"].into_iter().find(|c| {
        Command::new(c)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    })
}

/// Compares its argument with a key, a hundred times; runs a shell through
/// `popen`; forks a child that compares it with another key.
const PROGRAM: &str = r#"
    #include <stdio.h>
    #include <string.h>
    #include <unistd.h>
    #include <sys/wait.h>
    int main(int argc, char **argv) {
        const char *in = argc > 1 ? argv[1] : "x";
        volatile int r = 0;
        int i, status;
        pid_t child;
        FILE *shell;
        char line[64];
        for (i = 0; i < 100; i++) r += strcmp(in, "TARGETKEY");
        shell = popen("for w in alpha beta; do case $w in alpha) echo $w ;; *) : ;; esac; done", "r");
        if (shell) {
            while (fgets(line, sizeof line, shell)) {}
            pclose(shell);
        }
        child = fork();
        if (child == 0) {
            r += strcmp(in, "CHILDKEY");
            _exit(0);
        }
        waitpid(child, &status, 0);
        return r == 12345;
    }
"#;

fn hex(text: &str) -> String {
    text.bytes().map(|b| format!("{b:02x}")).collect()
}

/// The comparison records of a run of `bin`, each as its (a, b) hex pair.
fn records(
    bin: &Path,
    shim: &Path,
    log: &Path,
    target_exe: Option<&Path>,
) -> Vec<(String, String)> {
    let _ = std::fs::remove_file(log);
    let mut command = Command::new(bin);
    command
        .arg("probe-input")
        .env("LD_PRELOAD", shim)
        .env("BHF_RUNTRACE_LOG", log)
        .env("BHF_CMPLOG", "1")
        .env_remove("BHF_TARGET_EXE")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(target) = target_exe {
        command.env("BHF_TARGET_EXE", target);
    }
    assert!(command.status().unwrap().success());
    std::fs::read_to_string(log)
        .unwrap()
        .lines()
        .filter(|line| line.starts_with("{\"e\":\"cmplog\""))
        .map(|line| (field(line, "a"), field(line, "b")))
        .collect()
}

/// The string value of `key` in a record the shim wrote.
fn field(record: &str, key: &str) -> String {
    let open = format!("\"{key}\":\"");
    let start = record
        .find(&open)
        .unwrap_or_else(|| panic!("no {key} in {record}"))
        + open.len();
    let len = record[start..].find('"').expect("a closing quote");
    record[start..start + len].to_owned()
}

#[test]
fn only_the_target_image_records_comparisons() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built (cargo build -p bhf_runtrace_shim)");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let dir = tempfile::Builder::new()
        .prefix("bhf-")
        .tempdir()
        .expect("create test dir");
    let src = dir.path().join("probe.c");
    std::fs::write(&src, PROGRAM).unwrap();
    let bin = dir.path().join("probe");
    let built = Command::new(cc)
        .args(["-O0", "-fno-builtin"])
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(built.success(), "probe failed to compile");
    let log = dir.path().join("rt.jsonl");
    let input = hex("probe-input");
    let target = (input.clone(), hex("TARGETKEY"));
    let child = (input.clone(), hex("CHILDKEY"));
    let from_target = |record: &(String, String)| *record == target || *record == child;

    // Without BHF_TARGET_EXE the shell's own comparisons are recorded.
    let all = records(&bin, &shim, &log, None);
    assert!(
        all.iter().any(|record| !from_target(record)),
        "the shell recorded nothing, so this test shows nothing: {all:?}"
    );

    // A symlink to the harness names the same image.
    let link = dir.path().join("probe-link");
    std::os::unix::fs::symlink(&bin, &link).unwrap();
    for target_exe in [&bin, &link] {
        let gated = records(&bin, &shim, &log, Some(target_exe));
        assert!(
            gated.iter().all(from_target),
            "a record from another image: {gated:?}"
        );
        // A hundred equal comparisons are one record, and the forked child
        // records its own.
        assert_eq!(
            gated.iter().filter(|record| **record == target).count(),
            1,
            "{gated:?}"
        );
        assert_eq!(
            gated.iter().filter(|record| **record == child).count(),
            1,
            "{gated:?}"
        );
    }

    // A file no process runs named: nothing records.
    let other = records(&bin, &shim, &log, Some(&src));
    assert!(other.is_empty(), "{other:?}");
}
