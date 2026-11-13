// SPDX-License-Identifier: Apache-2.0

//! Findings of a cross sweep: harnesses built for another architecture and
//! fuzzed under its emulator. Each test drives the real binary and skips (with
//! a notice) when the cross compiler or the emulator is not installed.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bhf() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
}

fn have(program: &str) -> bool {
    which::which(program).is_ok()
}

fn cross_tools() -> bool {
    let ok = have("aarch64-linux-gnu-gcc") && have("qemu-aarch64") && have("make");
    if !ok {
        eprintln!("skip: aarch64-linux-gnu-gcc/qemu-aarch64/make unavailable");
    }
    ok
}

fn text(output: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Run an aarch64 cross sweep of `src` fuzzing up to `targets` targets.
fn cross_sweep(src: &Path, work: &Path, targets: usize) -> String {
    let targets = targets.to_string();
    let output = bhf()
        .arg("auto")
        .arg(src)
        .arg("--work-dir")
        .arg(work)
        .args([
            "--max-targets",
            &targets,
            "--jobs",
            "1",
            "--no-discovery-cache",
            "--languages",
            "c",
            "--per-target-time",
            "8",
            "--target-triple",
            "aarch64-linux-gnu",
            "--runner",
            "qemu-aarch64",
        ])
        .env_remove("CC")
        .env_remove("CXX")
        .output()
        .unwrap();
    text(&output)
}

/// Every `finding.json` under `<work>/results/findings`, with its directory.
fn findings(work: &Path) -> Vec<(PathBuf, serde_json::Value)> {
    let mut found: Vec<(PathBuf, serde_json::Value)> =
        std::fs::read_dir(work.join("results/findings"))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| {
                let bytes = std::fs::read(entry.path().join("finding.json")).ok()?;
                Some((entry.path(), serde_json::from_slice(&bytes).ok()?))
            })
            .collect();
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found
}

/// Two functions that each fault without a sanitizer report, at different
/// sites: a store through a null pointer and a load from a small address.
fn write_two_faults(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("records.c"),
        "#include <stddef.h>\n#include <stdint.h>\n\
         int copy_at(const unsigned char *data, size_t size) {\n\
             if (size > 0 && data[0] != 0x7f) {\n\
                 volatile unsigned char *out = (volatile unsigned char *)(uintptr_t)0;\n\
                 out[0] = data[0];\n\
             }\n\
             return 0;\n\
         }\n\
         int bit_index(const unsigned char *data, size_t size) {\n\
             if (size > 0 && data[0] != 0x7f) {\n\
                 const volatile int *word = (const volatile int *)(uintptr_t)8;\n\
                 return *word >> 3;\n\
             }\n\
             return 0;\n\
         }\n",
    )
    .unwrap();
}

/// A cross sweep's harnesses run without a sanitizer runtime, so their
/// crashes have no frames. Two harnesses that fault at different sites are
/// two root-cause groups, not one.
#[test]
fn frameless_crashes_of_two_cross_harnesses_are_two_root_cause_groups() {
    if !cross_tools() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    write_two_faults(&src);
    let work = tmp.path().join("work");
    let out = cross_sweep(&src, &work, 2);
    let found = findings(&work);
    let segv: Vec<&serde_json::Value> = found
        .iter()
        .map(|(_, finding)| finding)
        .filter(|finding| finding["rule_id"] == "BHF-210")
        .collect();
    let harnesses: std::collections::BTreeSet<&str> = segv
        .iter()
        .filter_map(|finding| finding["harness_id"].as_str())
        .collect();
    assert_eq!(harnesses.len(), 2, "both harnesses crash:\n{out}");
    let groups: std::collections::BTreeSet<&str> = segv
        .iter()
        .filter_map(|finding| finding["cluster_key_full"].as_str())
        .collect();
    assert_eq!(groups.len(), segv.len(), "one group per crash: {segv:#?}");
    assert!(
        segv.iter()
            .all(|finding| finding["exception"]["pc_offset"].is_string()),
        "the driver's fault line gives each crash its pc: {segv:#?}"
    );
    let index = std::fs::read_to_string(work.join("results/INDEX.md")).unwrap_or_default();
    assert!(
        index.contains(&format!("in {} root-cause groups", segv.len())),
        "{index}"
    );
}

/// An AArch64 trap (`__builtin_trap`, or a bounds check built to trap) raises
/// SIGTRAP: it is a finding, not a rejected input. A cross finding replays
/// under the emulator recorded beside its harness, with no `--qemu-user`, and
/// its fidelity record names the target and the emulator, and no sanitizer.
#[test]
fn a_cross_sweep_reports_traps_replays_under_the_recorded_runner_and_labels_fidelity() {
    if !cross_tools() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("records.c"),
        "#include <stddef.h>\n\
         int check_magic(const unsigned char *data, size_t size) {\n\
             if (size > 0 && data[0] != 0x7f) __builtin_trap();\n\
             return 0;\n\
         }\n",
    )
    .unwrap();
    let work = tmp.path().join("work");
    let out = cross_sweep(&src, &work, 1);
    let found = findings(&work);
    let (dir, trap) = found
        .iter()
        .find(|(_, finding)| finding["exception"]["signal"] == "SIGTRAP")
        .unwrap_or_else(|| panic!("the trap is a finding: {found:#?}\n{out}"));
    assert_eq!(trap["rule_id"], "BHF-210", "{trap}");
    assert_eq!(
        found
            .iter()
            .filter(|(_, finding)| finding["exception"]["signal"] == "SIGTRAP")
            .count(),
        1,
        "one finding for the one trap: {found:#?}"
    );

    let fidelity = &trap["fidelity"];
    let arch = fidelity["arch"]["reason"].as_str().unwrap_or_default();
    assert!(
        arch.contains("aarch64-linux-gnu") && arch.contains("qemu-aarch64"),
        "{fidelity:#}"
    );
    assert!(!arch.contains("host"), "{fidelity:#}");
    let endianness = fidelity["endianness"]["reason"]
        .as_str()
        .unwrap_or_default();
    assert!(!endianness.contains("host"), "{fidelity:#}");
    assert_eq!(
        fidelity["sanitizers"]["status"], "not_exercised",
        "{fidelity:#}"
    );

    let started = std::time::Instant::now();
    let replay = bhf().arg("replay").arg(dir).output().unwrap();
    let replay_text = text(&replay);
    assert_eq!(replay.status.code(), Some(0), "{replay_text}");
    assert!(
        String::from_utf8_lossy(&replay.stdout).starts_with("MATCH"),
        "{replay_text}"
    );
    assert!(
        replay_text.contains("under the recorded runner qemu-aarch64"),
        "{replay_text}"
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
}

/// A sanitized AArch64 harness replayed under qemu-user: its report ends the
/// run without an abort (which makes the emulator spend minutes on its own
/// address space), so the replay finishes well inside the replay timeout and
/// matches.
#[test]
fn an_emulated_sanitized_replay_finishes_quickly_and_matches() {
    if !cross_tools() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let work = tmp.path().join("work");
    let harness_dir = work.join("harnesses/H-ASAN");
    std::fs::create_dir_all(&harness_dir).unwrap();
    std::fs::write(
        harness_dir.join("target.c"),
        "#include <stdint.h>\n#include <stddef.h>\n#include <stdlib.h>\n\
         __attribute__((noinline)) void copy_at(char *out, size_t n) { out[n] = 1; }\n\
         int bhf_run_one(const uint8_t *data, size_t size) {\n\
             char *out = malloc(4);\n\
             if (size > 0 && data[0] == 'W') copy_at(out, 4);\n\
             free(out);\n\
             return 0;\n\
         }\n",
    )
    .unwrap();
    let driver = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime/bhf_driver.c");
    let built = Command::new("aarch64-linux-gnu-gcc")
        .current_dir(&harness_dir)
        .args([
            "-O1",
            "-g",
            "-fsanitize=address",
            "-static-libasan",
            "-o",
            "main",
            "target.c",
        ])
        .arg(&driver)
        .output()
        .unwrap();
    if !built.status.success() {
        eprintln!(
            "skip: the cross compiler has no AddressSanitizer: {}",
            String::from_utf8_lossy(&built.stderr)
        );
        return;
    }
    let harness = harness_dir.join("main");
    let input = tmp.path().join("input.bin");
    std::fs::write(&input, b"W").unwrap();
    let run = Command::new("qemu-aarch64")
        .args(["-L", "/usr/aarch64-linux-gnu"])
        .arg(&harness)
        .arg(&input)
        .env("ASAN_OPTIONS", "abort_on_error=0:detect_leaks=0")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&run.stderr).into_owned();
    let Some(report) = corpus::parse_sanitizer_report(&stderr) else {
        eprintln!("skip: no sanitizer report under the emulator: {stderr}");
        return;
    };
    let sha256 = {
        use sha2::{Digest, Sha256};
        format!("{:x}", Sha256::digest(std::fs::read(&harness).unwrap()))
    };
    let id = corpus::FindingEmitter::with_metadata(
        work.clone(),
        "H-ASAN".to_owned(),
        "c".to_owned(),
        harness.display().to_string(),
    )
    .with_build_binary(serde_json::json!({"sha256": sha256}))
    .emit_sanitizer_crash_with_log(b"W", &report, Some(stderr.as_bytes()))
    .unwrap();
    let finding = corpus::layout::findings_dir(&work).join(id.0);

    let started = std::time::Instant::now();
    let replay = bhf()
        .arg("replay")
        .arg(&finding)
        .args([
            "--qemu-user",
            "qemu-aarch64",
            "--qemu-arg=-L",
            "--qemu-arg=/usr/aarch64-linux-gnu",
            "--sandbox",
            "none",
        ])
        .output()
        .unwrap();
    let elapsed = started.elapsed();
    let replay_text = text(&replay);
    assert_eq!(replay.status.code(), Some(0), "{replay_text}");
    assert!(!replay_text.contains("timed out"), "{replay_text}");
    assert!(
        elapsed < std::time::Duration::from_secs(8),
        "the replay took {elapsed:?}: {replay_text}"
    );

    // The generated replay.py runs the harness under the emulator recorded
    // beside it, with the same options: the report ends the run without an
    // abort, so the script finishes quickly too.
    if !have("python3") {
        eprintln!("skip: python3 unavailable for replay.py");
        return;
    }
    std::fs::write(
        harness_dir.join("bhf_runner.json"),
        serde_json::json!({
            "schema": "bhf.harness_runner.v1",
            "program": "qemu-aarch64",
            "args": ["-L", "/usr/aarch64-linux-gnu"],
        })
        .to_string(),
    )
    .unwrap();
    let report = bhf()
        .arg("report")
        .arg("--work-dir")
        .arg(&work)
        .output()
        .unwrap();
    assert!(report.status.success(), "{}", text(&report));
    let script = finding.join("replay.py");
    assert!(script.is_file(), "{}", text(&report));
    let log = tmp.path().join("replay-py.log");
    let started = std::time::Instant::now();
    let mut command = Command::new("python3");
    command
        .arg(&script)
        .env("ASAN_OPTIONS", "abort_on_error=1")
        .env_remove("BHF_REPLAY_RUNNER")
        .stdout(std::fs::File::create(&log).unwrap())
        .stderr(std::process::Stdio::null());
    // Its own process group, so a run that hangs is killed with the emulator
    // it started.
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    let mut child = command.spawn().unwrap();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > std::time::Duration::from_secs(40) {
            #[cfg(unix)]
            let _ = Command::new("kill")
                .arg("-KILL")
                .arg(format!("-{}", child.id()))
                .status();
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "replay.py still running after {:?}: {}",
                started.elapsed(),
                std::fs::read_to_string(&log).unwrap_or_default()
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let elapsed = started.elapsed();
    let output = std::fs::read_to_string(&log).unwrap();
    assert!(
        output.contains("qemu-aarch64 -L /usr/aarch64-linux-gnu"),
        "{output}"
    );
    assert!(output.contains("ERROR: AddressSanitizer"), "{output}");
    assert!(
        status.code().is_some_and(|code| code != 0 && code != 134),
        "{status:?}: {output}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(15),
        "replay.py took {elapsed:?}: {output}"
    );
}
