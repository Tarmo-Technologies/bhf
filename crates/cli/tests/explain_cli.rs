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
    let work = std::env::temp_dir().join(format!("bhf-explain-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
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
    let finding = std::fs::read_dir(work.join("results/findings"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.join("min_testcase.bin").is_file())
        .expect("a minimized finding");
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(finding.join("finding.json")).unwrap()).unwrap();
    let gates = record["gates"].as_array().expect("finding.json gates");
    assert!(
        gates.iter().any(|g| g["operand_hex"]
            .as_str()
            .is_some_and(|h| h.starts_with("42"))),
        "the 'B' of BOOM reached a comparison: {gates:?}"
    );
    // The environment: the shim served getenv APP_MODE to this input's own replay.
    assert!(
        text.contains(
            "FAKED ENVIRONMENT  (observed while replaying min_testcase.bin with the runtrace shim)"
        ) && text.contains("APP_MODE"),
        "missing faked-env timeline:\n{text}"
    );
    // Reproduce hooks wire into the capsule feature.
    assert!(
        text.contains("bhf verify-poc"),
        "missing reproduce commands:\n{text}"
    );

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
    let finding_dir = work.join("results/findings").join(id);
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

    let explain = bhf()
        .arg("explain")
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run bhf explain");
    let text = String::from_utf8_lossy(&explain.stdout);
    let reproduce = text
        .split("REPRODUCE OFFLINE")
        .nth(1)
        .unwrap_or_else(|| panic!("missing REPRODUCE OFFLINE:\n{text}"));
    assert!(!reproduce.contains("bhf capsule --work-dir"), "{reproduce}");
    assert!(!reproduce.contains("bhf verify-poc"), "{reproduce}");
    assert!(reproduce.contains("Ada"), "says why: {reproduce}");
    assert!(
        reproduce.contains(&format!(
            "python3 {}",
            finding_dir.join("replay.py").display()
        )),
        "a working alternative: {reproduce}"
    );
}
