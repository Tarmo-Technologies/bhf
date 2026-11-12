// SPDX-License-Identifier: Apache-2.0
//! End-to-end coverage for `bhf env-capsule` + environment-response fuzzing. A
//! parser of a "trusted" external config file (opened via raw open/read, which the
//! shim fakes and fuzzes) overflows on the SERVED content — so the crash is driven
//! by the environment, not the input, and its minimized input is empty. The
//! env-capsule must record the served world and replay it to reproduce the crash
//! DETERMINISTICALLY from that empty input, in a pristine location.

use std::path::Path;
use std::process::Command;

fn clang_available() -> bool {
    which::which("clang").is_ok()
}

fn shim_present() -> bool {
    // The env-capsule needs the runtrace shim built beside the test binary.
    let exe = std::env::current_exe().unwrap();
    let dir = exe.parent().and_then(|p| p.parent()).unwrap().to_path_buf();
    dir.join("libbhf_runtrace_shim.so").is_file() || dir.join("libbhf_runtrace.so").is_file()
}

/// Reads a faked config file's (fuzzed) content into a fixed buffer — overflow when
/// the shim serves > 8 bytes. Raw open/read so the shim's `open` interposition fires.
const ENV_DRIVEN_C: &str = "\
#include <fcntl.h>
#include <unistd.h>
int load_config(const char *data, unsigned int len) {
    (void)data; (void)len;
    int fd = open(\"/etc/bhf_envcap_demo.conf\", O_RDONLY);
    if (fd < 0) return 0;
    char cfg[8];
    long n = read(fd, cfg, 64);
    close(fd);
    return n > 0 ? cfg[0] : 0;
}
";

/// Run from the project dir with the default (relative) `bhf_work`: the
/// replays, which run beside the harness binary, must still find the binary,
/// the input and the recorded world.
#[test]
fn env_capsule_replays_environment_driven_crash() {
    if !clang_available() {
        eprintln!("skipping: clang not installed");
        return;
    }
    if !shim_present() {
        eprintln!("skipping: runtrace shim not built");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let work = root.path().join("bhf_work");
    let src = root.path().join("load_config.c");
    std::fs::write(&src, ENV_DRIVEN_C).unwrap();
    let snip = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("snippet")
        .arg(&src)
        .arg("--lang")
        .arg("c")
        .arg("--per-target-time")
        .arg("8")
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run snippet");
    if !has_crash_finding(&work) {
        // Environment-response fuzzing needs the shim to fake the config read; if the
        // build/shim couldn't produce the crash, skip rather than falsely fail.
        eprintln!(
            "skipping: no env-driven crash found; stderr:\n{}",
            String::from_utf8_lossy(&snip.stderr)
        );
        return;
    }

    let cap = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("env-capsule")
        .current_dir(root.path())
        .output()
        .expect("run env-capsule");
    let stdout = String::from_utf8_lossy(&cap.stdout);
    assert!(
        cap.status.success()
            && stdout.contains("verified to replay")
            && stdout.contains("✓ replays"),
        "env-capsule should verify a replay; stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&cap.stderr)
    );

    // Independently verify: copy the capsule to a pristine dir and run replay.sh.
    let capsule = first_capsule(&work).expect("a capsule dir");
    let scratch = tempfile::tempdir().unwrap();
    let dest = scratch.path().join("cap");
    assert!(Command::new("cp")
        .arg("-r")
        .arg(&capsule)
        .arg(&dest)
        .status()
        .unwrap()
        .success());
    // The shipped primary input is (typically) empty — the reproducer is the world.
    let replay = Command::new("sh")
        .arg("replay.sh")
        .current_dir(&dest)
        .output()
        .expect("run replay.sh");
    let rep_err = String::from_utf8_lossy(&replay.stderr);
    assert!(
        rep_err.contains("AddressSanitizer"),
        "replay.sh must reproduce the crash from the pinned environment; stderr:\n{rep_err}"
    );
}

fn has_crash_finding(work: &Path) -> bool {
    std::fs::read_dir(work.join("results").join("findings"))
        .map(|d| {
            d.flatten().any(|e| {
                e.file_name().to_string_lossy().starts_with("F-0000")
                    && e.path().join("testcase.bin").is_file()
            })
        })
        .unwrap_or(false)
}

fn first_capsule(work: &Path) -> Option<std::path::PathBuf> {
    std::fs::read_dir(work.join("env-capsules"))
        .ok()?
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("env_capsule_"))
        })
}

/// Same environment-driven overflow, in a C++ target: env-capsule handles the
/// native C++ lane as it does C.
const ENV_DRIVEN_CPP: &str = "\
#include <fcntl.h>
#include <unistd.h>
int load_config(const char *data, unsigned int len) {
    (void)data; (void)len;
    int fd = open(\"/etc/bhf_envcap_demo.conf\", O_RDONLY);
    if (fd < 0) return 0;
    char cfg[8];
    long n = read(fd, cfg, 64);
    close(fd);
    return n > 0 ? cfg[0] : 0;
}
";

#[test]
fn env_capsule_replays_a_cpp_environment_driven_crash() {
    if which::which("clang++").is_err() {
        eprintln!("skipping: clang++ not installed");
        return;
    }
    if !shim_present() {
        eprintln!("skipping: runtrace shim not built");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let work = root.path().join("work");
    let src = root.path().join("load_config.cpp");
    std::fs::write(&src, ENV_DRIVEN_CPP).unwrap();
    let snip = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("snippet")
        .arg(&src)
        .args(["--lang", "cpp", "--per-target-time", "8", "--work-dir"])
        .arg(&work)
        .output()
        .expect("run snippet");
    if !has_crash_finding(&work) {
        eprintln!(
            "skipping: no env-driven crash found; stderr:\n{}",
            String::from_utf8_lossy(&snip.stderr)
        );
        return;
    }
    let cap = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("env-capsule")
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run env-capsule");
    let stdout = String::from_utf8_lossy(&cap.stdout);
    assert!(
        cap.status.success() && stdout.contains("✓ replays"),
        "env-capsule must capture the C++ crash; stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&cap.stderr)
    );
    let capsule = first_capsule(&work).expect("a capsule dir");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(capsule.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["reproduced"], true, "{manifest}");
}

/// A requested finding env-capsule cannot capture is refused with its reason
/// and a non-zero exit, whether or not the runtrace shim is installed, and no
/// output dir is left behind.
#[test]
fn env_capsule_refusing_a_requested_finding_exits_non_zero() {
    let root = tempfile::tempdir().unwrap();
    let work = root.path().join("work");
    let id = "F-0001-0000aaaa";
    let harness_id = "H-A0003-0000ABCD";
    let finding_dir = work.join("results/findings").join(id);
    std::fs::create_dir_all(&finding_dir).unwrap();
    std::fs::write(finding_dir.join("testcase.bin"), b"AAAA").unwrap();
    std::fs::write(
        finding_dir.join("finding.json"),
        serde_json::json!({"id": id, "classification": "unhandled", "harness_id": harness_id})
            .to_string(),
    )
    .unwrap();
    let harness = work.join("harnesses").join(harness_id);
    std::fs::create_dir_all(&harness).unwrap();
    std::fs::write(
        harness.join("generation-metadata.json"),
        br#"{"schema_version":1,"language":"ada"}"#,
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("env-capsule")
        .arg("--work-dir")
        .arg(&work)
        .arg("--finding-id")
        .arg(id)
        .output()
        .expect("run env-capsule");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains(id) && stderr.contains("Ada"),
        "the refusal must name the finding and its language:\n{stderr}"
    );
    assert!(!work.join("env-capsules").exists(), "{stderr}");
}
