// SPDX-License-Identifier: Apache-2.0

use serde_json::json;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
#[test]
fn binary_fuzz_finds_replayable_stdin_and_file_crashes() {
    let root = temp_dir("stdin-file");
    let stdin_bin = root.join("crash-stdin.sh");
    write_executable(
        &stdin_bin,
        "#!/bin/sh\ninput=$(cat)\nif [ \"$input\" = \"CRASH\" ]; then echo binary-crash >&2; exit 42; fi\nexit 0\n",
    );
    let file_bin = root.join("crash-file.sh");
    write_executable(
        &file_bin,
        "#!/bin/sh\nif [ -n \"$1\" ] && grep -q CRASH \"$1\"; then echo file-crash >&2; exit 43; fi\nexit 0\n",
    );

    let work = root.join("work");
    assert_success(
        Command::new(bhf_bin())
            .args([
                "binary-fuzz",
                stdin_bin.to_str().unwrap(),
                "--work-dir",
                work.to_str().unwrap(),
                "--input-mode",
                "stdin",
                "--seed-input",
                "CRASH",
                "--env",
                "BHF_TEST_ENV=1",
                "--timeout-ms",
                "1000",
            ])
            .output()
            .unwrap(),
    );
    let stdin_finding_dir = work.join("results/findings/BF-0001");
    let stdin_finding = read_json(&stdin_finding_dir.join("finding.json"));
    assert_eq!(stdin_finding["kind"], "binary_crash");
    assert_eq!(stdin_finding["finding_kind"], "binary");
    assert_eq!(stdin_finding["input"]["mode"], "stdin");
    assert_eq!(stdin_finding["crash"]["exit_code"], 42);
    assert_eq!(stdin_finding["env"]["BHF_TEST_ENV"], "1");
    assert_eq!(
        stdin_finding["binary"]["sha256"].as_str().unwrap().len(),
        64
    );

    assert_success(
        Command::new(bhf_bin())
            .args([
                "replay",
                stdin_finding_dir.to_str().unwrap(),
                "--harness",
                stdin_bin.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );
    assert_success(
        Command::new(bhf_bin())
            .args([
                "minimize",
                stdin_finding_dir.to_str().unwrap(),
                "--harness",
                stdin_bin.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );
    let minimized = read_json(&stdin_finding_dir.join("finding.json"));
    assert_eq!(minimized["minimal_reproducer"], "min_testcase.bin");
    // `replay` stamped last_seen (one history entry) before `minimize` ran, so
    // minimize is the latest history entry rather than the first.
    let history = minimized["history"].as_array().expect("history array");
    assert_eq!(history.last().unwrap()["command"], "minimize");
    assert!(
        history.iter().any(|h| h["command"] == "replay"),
        "replay should have recorded last_seen in history: {history:?}"
    );

    assert_success(
        Command::new(bhf_bin())
            .args([
                "binary-fuzz",
                file_bin.to_str().unwrap(),
                "--work-dir",
                work.to_str().unwrap(),
                "--input-mode",
                "file",
                "--seed-input",
                "CRASH",
                "--timeout-ms",
                "1000",
            ])
            .output()
            .unwrap(),
    );
    let file_finding = read_json(&work.join("results/findings/BF-0002/finding.json"));
    assert_eq!(file_finding["input"]["mode"], "file");
    assert_eq!(file_finding["crash"]["exit_code"], 43);
}

/// The seed-replay engine runs the operator's seeds as they are: a crash's
/// lineage is that user seed, 0 generations down, named by its file when it
/// was read from one, and the empty input bhf runs when given none is
/// generated.
#[cfg(unix)]
#[test]
fn a_seed_replay_crash_names_the_seed_it_ran_as_a_user_seed() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let target = root.join("crash-file.sh");
    write_executable(
        &target,
        "#!/bin/sh\nif [ ! -s \"$1\" ] || grep -q CRASH \"$1\"; then echo file-crash >&2; exit 43; fi\nexit 0\n",
    );
    let seed = root.join("seeds").join("crash.txt");
    fs::create_dir_all(seed.parent().unwrap()).unwrap();
    fs::write(&seed, b"CRASH").unwrap();
    let run = |work: &Path, seeds: &[&str]| {
        let mut args = vec![
            "binary-fuzz",
            target.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
            "--input-mode",
            "file",
            "--timeout-ms",
            "1000",
        ];
        args.extend_from_slice(seeds);
        assert_success(Command::new(bhf_bin()).args(&args).output().unwrap());
        read_json(&work.join("results/findings/BF-0001/finding.json"))["lineage"].clone()
    };

    let from_file = run(
        &root.join("work-file"),
        &[
            "--seed-input",
            "fine",
            "--seed-file",
            seed.to_str().unwrap(),
        ],
    );
    assert_eq!(from_file["origin"], "user_seed", "{from_file}");
    assert_eq!(from_file["root_path"], seed.to_str().unwrap());
    assert_eq!(from_file["depth"], 0);
    assert_eq!(
        from_file["root_sha256"].as_str().unwrap().len(),
        64,
        "{from_file}"
    );

    let literal = run(&root.join("work-literal"), &["--seed-input", "CRASH"]);
    assert_eq!(literal["origin"], "user_seed", "{literal}");
    assert!(literal.get("root_path").is_none(), "{literal}");
    assert_eq!(literal["depth"], 0);

    let none = run(&root.join("work-none"), &[]);
    assert_eq!(none["origin"], "generated", "{none}");
    assert_eq!(none["depth"], 0);
}

#[test]
fn ci_fails_on_binary_crash_findings() {
    let root = temp_dir("ci");
    let work = root.join("work");
    let finding = work.join("results/findings/BF-0001");
    fs::create_dir_all(&finding).unwrap();
    fs::write(
        finding.join("finding.json"),
        serde_json::to_vec_pretty(&json!({
            "id": "BF-0001",
            "kind": "binary_crash",
            "severity": "high",
            "rule_id": "BHF-501"
        }))
        .unwrap(),
    )
    .unwrap();

    let output = Command::new(bhf_bin())
        .args([
            "ci",
            root.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
            "--per-target-time",
            "1",
            "--fail-on",
            "high",
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
fn write_executable(path: &Path, source: &str) {
    fs::write(path, source).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

#[cfg(unix)]
fn assert_success(output: std::process::Output) {
    assert!(
        output.status.success(),
        "exit={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn bhf_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bhf"))
}

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("bhf-binary-fuzz-{name}-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}
