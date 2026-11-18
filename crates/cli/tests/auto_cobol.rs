// SPDX-License-Identifier: Apache-2.0
//! End-to-end: `bhf auto` fuzzes a COBOL program and catches a runtime bug.
//!
//! The fixture is a subprogram with a `LINKAGE` `PIC X(8)` buffer whose
//! reference-modification offset goes out of bounds when the input starts with
//! `Z` — a libcob `EC-BOUND-REF-MOD` failure the harness surfaces as a crash. The
//! trigger byte is seeded so the run is fast + deterministic. Gated on
//! cobc + clang + make; skipped otherwise.

use std::path::Path;
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn have(tool: &str) -> bool {
    let present = {
        Command::new(tool)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };
    support::require_tool(present, tool)
}

fn tempdir(name: &str) -> TestDir {
    TestDir::new(&format!("cobol-e2e-{name}"))
}

fn read_findings(work: &Path) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(work.join("results").join("findings")) else {
        return out;
    };
    for entry in entries.flatten() {
        if let Ok(bytes) = std::fs::read(entry.path().join("finding.json")) {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                out.push(v);
            }
        }
    }
    out
}

/// The ref-mod fixture: `BUF(IDX:1)` with `IDX` = 200 when the input starts
/// with `Z`, at line 11 of `parseit.cob`.
const PARSEIT: &str = "       IDENTIFICATION DIVISION.\n\
     \x20      PROGRAM-ID. PARSEIT.\n\
     \x20      DATA DIVISION.\n\
     \x20      WORKING-STORAGE SECTION.\n\
     \x20      01 IDX PIC 9(4).\n\
     \x20      LINKAGE SECTION.\n\
     \x20      01 BUF PIC X(8).\n\
     \x20      PROCEDURE DIVISION USING BUF.\n\
     \x20          IF BUF(1:1) = \"Z\"\n\
     \x20              MOVE 200 TO IDX\n\
     \x20              DISPLAY BUF(IDX:1)\n\
     \x20          END-IF\n\
     \x20          GOBACK.\n";

#[test]
fn auto_cobol_discovers_and_crashes_on_ref_mod_oob() {
    if !have("cobc") || !have("clang") || !have("make") {
        eprintln!("skip: needs cobc (GnuCOBOL) + clang + make");
        return;
    }
    let src = tempdir("src");
    std::fs::write(src.join("parseit.cob"), PARSEIT).unwrap();

    let seed = tempdir("seed");
    std::fs::write(seed.join("z.bin"), b"Z").unwrap();

    let work = tempdir("work");
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["auto", src.to_str().unwrap()])
        .args(["--languages", "cobol"])
        .args(["--per-target-time", "10"])
        .arg("--no-discovery-cache")
        .arg("--seed-dir")
        .arg(&seed)
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("spawn bhf");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);

    // The COBOL program was discovered and built+fuzzed via the C harness path.
    assert!(
        stdout.contains("PARSEIT") || stderr.contains("PARSEIT"),
        "expected COBOL PROGRAM-ID PARSEIT to be discovered.\n{stdout}\n{stderr}"
    );
    // The out-of-bounds reference-modification is caught as a crash finding.
    let findings = read_findings(&work);
    assert!(
        findings.iter().any(|f| f["rule_id"] == "BHF-210"),
        "expected a BHF-210 reachable-crash finding from the ref-mod OOB.\n{stdout}\n{stderr}"
    );
    // #424: the report places it at the COBOL line libcob named.
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("results/findings.json")).unwrap())
            .unwrap();
    let location = &doc["findings"][0]["location"];
    assert_eq!(location["file"], "parseit.cob", "{doc:#}");
    assert_eq!(location["line"], 11, "{doc:#}");
}

/// A COBOL finding is recorded as libcob's runtime error, not the SIGSEGV the
/// harness dies by. Replaying it gives the replayed crash the same attribution,
/// so `bhf replay` matches it, and the auto minimize pass, which compares the
/// same way, minimizes it instead of refusing it as another crash.
#[test]
fn auto_cobol_finding_replays_as_a_match_and_is_minimized() {
    if !have("cobc") || !have("clang") || !have("make") {
        eprintln!("skip: needs cobc (GnuCOBOL) + clang + make");
        return;
    }
    let src = tempdir("replay-src");
    std::fs::write(src.join("parseit.cob"), PARSEIT).unwrap();
    // Seven bytes after the trigger for the minimize pass to remove.
    let seed = tempdir("replay-seed");
    std::fs::write(seed.join("z.bin"), b"Zpadding").unwrap();

    let work = tempdir("replay-work");
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["auto", src.to_str().unwrap()])
        .args(["--languages", "cobol"])
        .args(["--per-target-time", "10"])
        .arg("--no-discovery-cache")
        .arg("--seed-dir")
        .arg(&seed)
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("spawn bhf");
    let auto_log = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let findings_dir = work.join("results").join("findings");
    let finding = std::fs::read_dir(&findings_dir)
        .unwrap_or_else(|error| panic!("no findings dir ({error}).\n{auto_log}"))
        .flatten()
        .map(|entry| entry.path())
        .find(|dir| {
            std::fs::read(dir.join("finding.json"))
                .ok()
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                .is_some_and(|f| f["exception"]["name"] == "COBOL_RUNTIME_ERROR")
        })
        .unwrap_or_else(|| panic!("expected a COBOL_RUNTIME_ERROR finding.\n{auto_log}"));
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(finding.join("finding.json")).unwrap()).unwrap();

    // The auto minimize pass reduced the testcase to its trigger byte.
    let testcase = std::fs::read(finding.join("testcase.bin")).unwrap();
    let minimized = std::fs::read(finding.join("min_testcase.bin")).unwrap_or_else(|error| {
        panic!(
            "the auto minimize pass must minimize the COBOL finding ({error}); record: \
             {record:#}\n{auto_log}"
        )
    });
    assert!(testcase.len() > 1, "{testcase:?}");
    assert_eq!(minimized, b"Z", "minimized from {testcase:?}");
    assert_eq!(record["minimization"]["reduced"], true, "{record:#}");

    // `bhf replay` reproduces it as the recorded crash: the same runtime
    // error at the same COBOL line, by the same signal.
    let replay = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["replay", "--finding"])
        .arg(&finding)
        .output()
        .expect("spawn bhf replay");
    let stdout = String::from_utf8_lossy(&replay.stdout);
    let stderr = String::from_utf8_lossy(&replay.stderr);
    assert_eq!(
        replay.status.code(),
        Some(0),
        "bhf replay of a COBOL finding must MATCH.\n{stdout}\n{stderr}"
    );
    assert!(stdout.starts_with("MATCH"), "{stdout}\n{stderr}");
    let compared = stdout
        .lines()
        .find(|line| line.trim_start().starts_with("compared"))
        .unwrap_or_default();
    // The location is the COBOL source line libcob named: a `site`, or a
    // `sink` naming the program when the finding records its target.
    let site = format!(
        "{}/parseit.cob:11",
        src.file_name().unwrap().to_string_lossy()
    );
    for field in ["kind cobol-runtime-error", "signal SIGSEGV", site.as_str()] {
        assert!(compared.contains(field), "{field}: {stdout}");
    }
    for dir in [&src, &seed, &work] {
        let _ = std::fs::remove_dir_all(dir);
    }
}
