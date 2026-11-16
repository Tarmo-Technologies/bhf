// SPDX-License-Identifier: Apache-2.0
//! End-to-end coverage for `bhf explain`: after fuzzing a crash that is gated
//! behind a magic value AND reads an env var (faked by the shim), the offline,
//! deterministic explanation must join every evidence source — the sink + CWE, the
//! minimized input, the comparisons that input reached (recorded by the harness's
//! driver while it ran), the environment the runtrace shim observed for that
//! input, and the reproduce commands — with no LLM.

use std::path::Path;
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn clang_available() -> bool {
    which::which("clang").is_ok()
}

fn bhf() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bhf"));
    support::configure_runtrace_shim(&mut command);
    command
}

/// Overflow gated behind the magic bytes "BOOM"; also reads env var APP_MODE.
const GATED_C: &str = "\
#include <string.h>
#include <stdlib.h>
int handle(const char *data, unsigned int len) {
    if (len < 4) return 0;
    if (data[0]=='B' && data[1]=='O' && data[2]=='O' && data[3]=='M') {
        char *cfg = getenv(\"APP_MODE\");
        char buf[8];
        memcpy(buf, data, len);
        return buf[0] + (cfg ? cfg[0] : 0);
    }
    return 1;
}
";

#[test]
fn explain_joins_input_gates_faked_env_and_dataflow() {
    if !clang_available() {
        eprintln!("skipping: clang not installed");
        return;
    }
    let work_guard = TestDir::new("explain");
    let work = work_guard.join("work");
    let src = work.with_extension("src.c");
    std::fs::write(&src, GATED_C).unwrap();
    let out = bhf()
        .arg("snippet")
        .arg(&src)
        .arg("--lang")
        .arg("c")
        .arg("--per-target-time")
        .arg("10")
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run bhf snippet");
    let _ = std::fs::remove_file(&src);
    assert!(
        finding_dir_nonempty(&work),
        "snippet produced no crash: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let explain = bhf()
        .arg("explain")
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run bhf explain");
    let text = String::from_utf8_lossy(&explain.stdout);

    // The narrative must be deterministic and self-contained.
    assert!(text.contains("WHAT HAPPENED"), "missing section:\n{text}");
    assert!(
        text.contains("CWE-121") || text.contains("Buffer Overflow"),
        "missing CWE/class:\n{text}"
    );
    assert!(
        text.contains("THE INPUT THAT TRIGGERS IT  (min_testcase.bin,"),
        "the minimized input is shown and named:\n{text}"
    );
    // The "BOOM" gate: the comparisons that read the input's magic bytes were
    // recorded while this input ran, with their offsets — not a dictionary
    // substring match.
    let words = text.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        words.contains("Comparison evidence for this input (min_testcase.bin, recorded when the finding was saved):")
            && (words.contains("reaches cmp") || words.contains("reach cmp")),
        "missing recorded comparison evidence:\n{text}"
    );
    assert!(
        !text.contains("matched recovered constant") && !text.contains("solved"),
        "no heuristic presented as solved gates:\n{text}"
    );
    // The minimized crash: a slow run can also save, and minimize, a finding
    // of another class (an out-of-memory input), whose comparisons the
    // capture pass does not record.
    let record: serde_json::Value = std::fs::read_dir(work.join("results/findings"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.join("min_testcase.bin").is_file())
        .map(|p| {
            serde_json::from_slice::<serde_json::Value>(
                &std::fs::read(p.join("finding.json")).unwrap(),
            )
            .unwrap()
        })
        .find(|record| record["classification"] == "unhandled")
        .expect("a minimized crash");
    let gates = record["gates"].as_array().expect("finding.json gates");
    assert!(
        gates.iter().any(|g| g["operand_hex"]
            .as_str()
            .is_some_and(|h| h.starts_with("42"))),
        "the 'B' of BOOM reached a comparison: {gates:?}"
    );
    // The environment: the shim served getenv APP_MODE to this input's own
    // replay. The runtrace shim is an LD_PRELOAD library, so elsewhere explain
    // says the environment was not observed.
    if cfg!(target_os = "linux") {
        assert!(
            text.contains(
                "FAKED ENVIRONMENT  (observed while replaying min_testcase.bin with the runtrace shim)"
            ) && text.contains("APP_MODE"),
            "missing faked-env timeline:\n{text}"
        );
    } else {
        assert!(
            text.contains(
                "FAKED ENVIRONMENT\n  environment not observed (runtrace shim not loaded)"
            ),
            "the environment must be said unobserved:\n{text}"
        );
    }
    // Reproduce hooks wire into the capsule feature.
    assert!(
        text.contains("bhf verify-poc"),
        "missing reproduce commands:\n{text}"
    );
    // The crash depends only on the input: its replay was served no faked
    // bytes (an environment variable is no faked resource), so env-capsule,
    // which needs a served world, is not suggested.
    let reproduce = text.split("REPRODUCE OFFLINE").nth(1).unwrap_or_default();
    assert!(!reproduce.contains("bhf env-capsule"), "{text}");
    assert!(
        !reproduce.contains("replays without the faked environment"),
        "{text}"
    );
    if cfg!(target_os = "linux") {
        assert_eq!(
            record["gate_capture"]["served_resources"],
            serde_json::json!([]),
            "{record:#}"
        );
    }

    // Determinism: a second run yields identical text.
    let explain2 = bhf()
        .arg("explain")
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run bhf explain again");
    assert_eq!(
        text,
        String::from_utf8_lossy(&explain2.stdout),
        "explain must be deterministic across runs"
    );
    let _ = std::fs::remove_dir_all(&work);
}

fn finding_dir_nonempty(work: &Path) -> bool {
    std::fs::read_dir(work.join("results").join("findings"))
        .map(|mut d| d.next().is_some())
        .unwrap_or(false)
}

/// explain offers `bhf capsule` / `bhf verify-poc` only for a finding capsule
/// can package. For any other finding it names why and prints a command that
/// does reproduce it.
#[test]
fn explain_suggests_only_reproduce_commands_that_apply() {
    let root = tempfile::tempdir().unwrap();
    let work = root.path().join("work");
    let id = "F-0001-0000aaaa";
    let harness_id = "H-A0003-0000ABCD";
    let finding_dir = work.join("results").join("findings").join(id);
    std::fs::create_dir_all(&finding_dir).unwrap();
    std::fs::write(finding_dir.join("testcase.bin"), b"AAAA").unwrap();
    std::fs::write(finding_dir.join("replay.py"), b"print('replay')\n").unwrap();
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
    let reproduce = || {
        let explain = bhf()
            .arg("explain")
            .arg("--work-dir")
            .arg(&work)
            .output()
            .expect("run bhf explain");
        let text = String::from_utf8_lossy(&explain.stdout).into_owned();
        text.split("REPRODUCE OFFLINE")
            .nth(1)
            .unwrap_or_else(|| panic!("missing REPRODUCE OFFLINE:\n{text}"))
            .to_owned()
    };

    // No harness was built, so replay.py would have nothing to run.
    let unbuilt = reproduce();
    assert!(!unbuilt.contains("bhf capsule --work-dir"), "{unbuilt}");
    assert!(!unbuilt.contains("replay.py"), "{unbuilt}");

    std::fs::write(harness.join("main"), b"\x7fELF").unwrap();
    let reproduce = reproduce();
    assert!(!reproduce.contains("bhf capsule --work-dir"), "{reproduce}");
    assert!(!reproduce.contains("bhf verify-poc"), "{reproduce}");
    assert!(reproduce.contains("Ada"), "says why: {reproduce}");
    // In the host shell's own spelling: PowerShell quotes the path, and the
    // Windows interpreter is `python`.
    let replay = finding_dir.join("replay.py");
    let command = if cfg!(windows) {
        format!("python '{}'", replay.display())
    } else {
        format!("python3 {}", replay.display())
    };
    assert!(
        reproduce.contains(&command),
        "a working alternative: {reproduce}"
    );
}

/// replay.py runs the harness a relative `fixture_path` names in the work dir
/// that holds the finding, so explain offers it (or not) the same way from any
/// current directory.
#[test]
fn explain_offers_replay_py_by_the_work_dir_not_the_current_dir() {
    let root = tempfile::tempdir().unwrap();
    let work = root.path().join("work");
    let id = "F-0001-0000aaaa";
    let harness_id = "H-A0003-0000ABCD";
    let finding_dir = work.join("results/findings").join(id);
    std::fs::create_dir_all(&finding_dir).unwrap();
    std::fs::write(finding_dir.join("testcase.bin"), b"AAAA").unwrap();
    std::fs::write(finding_dir.join("replay.py"), b"print('replay')\n").unwrap();
    let harness = work.join("harnesses").join(harness_id);
    std::fs::create_dir_all(&harness).unwrap();
    std::fs::write(
        harness.join("generation-metadata.json"),
        br#"{"schema_version":1,"language":"ada"}"#,
    )
    .unwrap();
    // The harness binary lives only where the relative fixture_path names it
    // from the work dir; `root/elsewhere/main` is what it names from `root`.
    std::fs::create_dir_all(work.join("custom")).unwrap();
    std::fs::write(work.join("custom/main"), b"\x7fELF").unwrap();
    std::fs::create_dir_all(root.path().join("elsewhere")).unwrap();
    std::fs::write(root.path().join("elsewhere/main"), b"\x7fELF").unwrap();
    let replay_lines = |fixture: &str, cwd: &Path| {
        std::fs::write(
            finding_dir.join("finding.json"),
            serde_json::json!({"id": id, "classification": "unhandled",
                               "harness_id": harness_id, "fixture_path": fixture})
            .to_string(),
        )
        .unwrap();
        let explain = bhf()
            .current_dir(cwd)
            .arg("explain")
            .arg("--work-dir")
            .arg(&work)
            .output()
            .expect("run bhf explain");
        let text = String::from_utf8_lossy(&explain.stdout).into_owned();
        let reproduce = text
            .split("REPRODUCE OFFLINE")
            .nth(1)
            .unwrap_or_else(|| panic!("missing REPRODUCE OFFLINE:\n{text}"))
            .to_owned();
        reproduce
            .lines()
            .filter(|line| line.contains("replay.py"))
            .count()
    };
    for cwd in [root.path(), work.as_path(), Path::new("/")] {
        assert_eq!(
            replay_lines("custom/main", cwd),
            1,
            "from {}",
            cwd.display()
        );
        assert_eq!(
            replay_lines("elsewhere/main", cwd),
            0,
            "from {}",
            cwd.display()
        );
    }
}

/// An overflow behind the magic bytes "BOOM".
#[cfg(windows)]
const OVERFLOW_C: &str = "\
#include <string.h>
int handle(const char *data, unsigned int len) {
    char buf[8];
    if (len < 4 || data[0] != 'B' || data[1] != 'O' || data[2] != 'O' || data[3] != 'M') return 0;
    memcpy(buf, data, len);
    return buf[0];
}
";

/// On Windows a harness binary is `main.exe`, which cmd and PowerShell run by
/// its path (an extensionless `main` starts only through CreateProcess:
/// "is not recognized as an internal or external command"), and the direct
/// run `bhf explain` prints is a PowerShell command that reproduces the crash
/// as printed.
#[cfg(windows)]
#[test]
fn the_printed_direct_run_starts_the_harness_from_powershell_and_cmd() {
    if !clang_available() || which::which("make").is_err() {
        eprintln!("skipping: clang/make not on PATH");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let work = root.path().join("work");
    let src = root.path().join("overflow.c");
    std::fs::write(&src, OVERFLOW_C).unwrap();
    let out = {
        let _guard = support::fuzz_serial_guard();
        bhf()
            .arg("snippet")
            .arg(&src)
            .args(["--lang", "c", "--per-target-time", "20", "--work-dir"])
            .arg(&work)
            .output()
            .expect("run bhf snippet")
    };
    assert!(
        finding_dir_nonempty(&work),
        "snippet produced no crash: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let harnesses: Vec<_> = std::fs::read_dir(work.join("harnesses"))
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .filter(|dir| dir.join("Makefile").is_file())
        .collect();
    assert_eq!(harnesses.len(), 1, "{harnesses:?}");
    let binary = harnesses[0].join("main.exe");
    assert!(
        binary.is_file(),
        "no main.exe in {}",
        harnesses[0].display()
    );
    assert!(
        !harnesses[0].join("main").exists(),
        "an extensionless binary beside main.exe"
    );

    let explain = bhf()
        .arg("explain")
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run bhf explain");
    let text = String::from_utf8_lossy(&explain.stdout).into_owned();
    let mut lines = text
        .lines()
        .skip_while(|line| !line.contains("To run the harness binary directly in PowerShell"))
        .skip(1);
    let mut script = Vec::new();
    for line in lines.by_ref() {
        let line = line.trim();
        script.push(line.to_owned());
        if line.contains("& '") {
            break;
        }
    }
    let call = script.last().cloned().unwrap_or_default();
    let harness_id = harnesses[0]
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert!(
        call.contains(&format!("{harness_id}\\main.exe' '")),
        "the direct run names main.exe: {script:?}\n{text}"
    );
    let ran = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command"])
        .arg(script.join("; "))
        .output()
        .expect("run powershell");
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
    assert!(
        output.contains("AddressSanitizer"),
        "the printed PowerShell run did not reproduce: {script:?}\n{output}"
    );

    // cmd runs it by its path too; bhf put the ASan runtime DLL beside it.
    let input = call
        .rsplit(" '")
        .next()
        .and_then(|word| word.strip_suffix('\''))
        .expect("the input word")
        .replace("''", "'");
    let ran = Command::new("cmd")
        .arg("/c")
        .arg(&binary)
        .arg(&input)
        .output()
        .expect("run cmd");
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
    assert!(
        output.contains("AddressSanitizer"),
        "cmd /c {} {input} did not run the harness:\n{output}",
        binary.display()
    );
}

/// Write `raw` as the `finding.json` of finding `id` in `work`.
fn write_finding(work: &Path, id: &str, raw: serde_json::Value) {
    let dir = work.join("results/findings").join(id);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("finding.json"), raw.to_string()).unwrap();
    std::fs::write(dir.join("testcase.bin"), b"AAAA").unwrap();
}

/// `bhf explain --finding-id` for a finding it cannot explain exits 1 with
/// the reason, as `bhf capsule` does; without an id an oracle-only work dir
/// is explained.
#[test]
fn explain_refuses_a_finding_id_it_cannot_explain() {
    let tmp = tempfile::tempdir().unwrap();
    let work = tmp.path().join("work");
    write_finding(
        &work,
        "F-0001-0a0b0c0d",
        serde_json::json!({
            "id": "F-0001-0a0b0c0d", "rule_id": "BHF-201", "harness_id": "H-C0001",
            "classification": "unhandled",
            "exception": {"name": "ASAN_HEAP_BUFFER_OVERFLOW", "sanitizer": "asan",
                "message": "AddressSanitizer: heap-buffer-overflow", "stack": []}
        }),
    );
    write_finding(
        &work,
        "F-0002-0a0b0c0d",
        serde_json::json!({
            "id": "F-0002-0a0b0c0d", "rule_id": "BHF-401", "classification": "static_scan"
        }),
    );
    let explain = |id: Option<&str>, work: &Path| {
        let mut command = bhf();
        command.arg("explain").arg("--work-dir").arg(work);
        if let Some(id) = id {
            command.arg("--finding-id").arg(id);
        }
        command.output().expect("run bhf explain")
    };
    let findings_dir = work.join("results").join("findings");
    for (id, reason) in [
        (
            "F-9999-deadbeef",
            format!(
                "no finding with id F-9999-deadbeef in {}",
                findings_dir.display()
            ),
        ),
        (
            "F-0002-0a0b0c0d",
            "its classification is `static_scan`, not a runtime crash or oracle finding; bhf \
             report lists it"
                .to_owned(),
        ),
    ] {
        let output = explain(Some(id), &work);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{id}: {stderr}");
        assert!(
            stderr.contains(&format!("bhf explain: cannot explain {id}: {reason}")),
            "{id}: {stderr}"
        );
    }
    // A directory by that name without a readable finding.json.
    std::fs::create_dir_all(findings_dir.join("F-0003-0a0b0c0d")).unwrap();
    std::fs::write(findings_dir.join("F-0003-0a0b0c0d/finding.json"), "{").unwrap();
    let output = explain(Some("F-0003-0a0b0c0d"), &work);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("cannot explain F-0003-0a0b0c0d:")
            && stderr.contains("is missing or is not valid JSON"),
        "{stderr}"
    );
    let output = explain(Some("F-0001-0a0b0c0d"), &work);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("F-0001-0a0b0c0d"));

    // An oracle finding alone is explained without an id.
    let oracle_work = tmp.path().join("oracle-work");
    write_finding(
        &oracle_work,
        "F-0004-0a0b0c0d",
        serde_json::json!({
            "id": "F-0004-0a0b0c0d", "rule_id": "BHF-408", "harness_id": "H-C0001",
            "classification": "oracle_hit", "confirmation": "runtime",
            "oracle": {"name": "format-string-runtime", "category": "injection", "api": "printf",
                "message": "a fuzz-controlled printf format contains a conversion",
                "evidence": [{"key": "format", "value": "%n"}]},
            "exception": {"name": "ORACLE_FORMAT_STRING_RUNTIME",
                "message": "a fuzz-controlled printf format contains a conversion"}
        }),
    );
    let output = explain(None, &oracle_work);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert!(
        stdout.contains("Oracle: format-string-runtime on printf"),
        "{stdout}"
    );
}
