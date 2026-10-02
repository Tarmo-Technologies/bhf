// SPDX-License-Identifier: Apache-2.0
//! `auto --static`: run a whole-tree static scan IN ADDITION to fuzzing (not only
//! as a fallback when a target can't be fuzzed). The scan's findings
//! (classification `static_scan`, `F-STATIC-*`) merge into the unified report next
//! to the fuzz findings — so a target that built+fuzzed still gets static coverage.
//!
//! Gated on the C toolchain being installed; skipped (with a notice) otherwise.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize repo root")
}

#[test]
fn static_flag_runs_tree_scan_and_merges_findings() {
    if which::which("clang").is_err() || which::which("make").is_err() {
        eprintln!("SKIP: clang/make not installed — C lane unavailable");
        return;
    }

    let tmp = tempfile::Builder::new()
        .prefix("bhf-static-scan-")
        .tempdir()
        .expect("tempdir");
    let srcroot = tmp.path().join("srcroot");
    std::fs::create_dir_all(&srcroot).expect("mkdir srcroot");
    std::fs::copy(
        repo_root().join("tests/fixtures/static_scan/weak.c"),
        srcroot.join("weak.c"),
    )
    .expect("copy fixture");

    let work_dir = srcroot.join("bhf_work");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg("--static")
        .arg(&srcroot)
        .arg("--work-dir")
        .arg(&work_dir)
        .arg("--per-target-time")
        .arg("1")
        .output()
        .expect("spawn bhf auto --static");

    // The static scan must have produced at least one F-STATIC finding, written
    // straight into the findings dir alongside any fuzz findings.
    let findings_dir = work_dir.join("results").join("findings");
    let static_findings: Vec<_> = std::fs::read_dir(&findings_dir)
        .expect("findings dir exists")
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("F-STATIC-"))
        .collect();
    assert!(
        !static_findings.is_empty(),
        "--static must write at least one F-STATIC finding; stderr=\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Each static finding is tagged classification `static_scan` and carries a CWE.
    let first = static_findings[0].path().join("finding.json");
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&first).expect("read finding.json"))
            .expect("parse finding.json");
    assert_eq!(record["classification"].as_str(), Some("static_scan"));
    assert_eq!(record["finding_kind"], "static");
    // The v1 envelope's birth timestamp is valid RFC 3339.
    assert!(
        chrono::DateTime::parse_from_rfc3339(record["created_at"].as_str().unwrap()).is_ok(),
        "created_at must be RFC 3339: {}",
        record["created_at"]
    );
    assert!(
        record["actionability"]["cwe"]
            .as_array()
            .is_some_and(|c| !c.is_empty()),
        "static finding must carry a CWE: {record}"
    );
    assert!(
        record["static_fingerprint"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "static finding must carry its static-scan fingerprint: {record}"
    );

    // #484 (fuzz-confirmation join): the `strcpy(buf, name)` at weak.c:9 is a
    // static CWE-120 finding AND a trivially fuzz-reachable stack overflow. The
    // fuzzer crashes ASan at the SAME line the static rule flagged, so the join
    // must (a) upgrade the static finding to `fuzz_confirmed` on disk, and (b)
    // CLUSTER it with the crash so the report renders ONE issue row (the crash as
    // representative, the static finding a member) — not two orphaned rows.
    let static_id = static_findings[0]
        .file_name()
        .to_string_lossy()
        .into_owned();
    let confirmed: serde_json::Value = serde_json::from_slice(
        &std::fs::read(static_findings[0].path().join("finding.json")).expect("read finding.json"),
    )
    .expect("parse confirmed finding.json");
    assert_eq!(confirmed["confirmation"].as_str(), Some("fuzz_confirmed"));
    assert!(
        confirmed["confirmed_by"]
            .as_array()
            .is_some_and(|a| !a.is_empty()),
        "confirmed finding must name its confirming runtime finding(s): {confirmed}"
    );

    // The confirmed static finding is listed in results/findings.json at weak.c
    // with level `static_confirmed`, and clusters under its crash. bhf's OWN
    // generated harness under the work-dir must NOT appear as static findings (no
    // `main.c` FP rows). The legacy top-level FINDINGS.md / findings.csv are gone.
    let results = work_dir.join("results");
    assert!(
        results.join("INDEX.md").is_file(),
        "results/INDEX.md missing"
    );
    assert!(
        !work_dir.join("FINDINGS.md").exists(),
        "legacy FINDINGS.md must not be written"
    );
    assert!(
        !work_dir.join("findings.csv").exists(),
        "legacy findings.csv must not be written"
    );
    let doc: serde_json::Value = serde_json::from_slice(
        &std::fs::read(results.join("findings.json")).expect("findings.json"),
    )
    .expect("parse findings.json");
    let findings = doc["findings"].as_array().expect("findings array");
    assert!(
        !findings.iter().any(|f| f["location"]["file"]
            .as_str()
            .is_some_and(|p| p.contains("harnesses/"))),
        "the work-dir's generated harness must be excluded from --static: {doc}"
    );
    let merged = findings
        .iter()
        .find(|f| f["id"] == static_id.as_str())
        .unwrap_or_else(|| panic!("findings.json must list the confirmed static finding: {doc}"));
    assert_eq!(
        merged["confirmation"]["level"],
        "static_confirmed",
        "the fuzz-reachable static finding must be static_confirmed: {merged}\nstderr=\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        merged["location"]["file"]
            .as_str()
            .is_some_and(|f| f.ends_with("weak.c")),
        "{merged}"
    );
    let crash = findings
        .iter()
        .find(|f| f["kind"] == "fuzz")
        .expect("a fuzz crash");
    let crash_group = crash["group"].clone();
    assert_eq!(
        merged["group"], crash_group,
        "confirmed static finding clusters under its crash"
    );
    // Bounded auto minimization (`--no-minimize` to opt out) runs after the
    // report is written, so the crash's representative gets a small reproducer.
    let crash_id = crash["id"].as_str().expect("crash finding id");
    let crash_dir = findings_dir.join(crash_id);
    assert!(
        crash_dir.join("min_testcase.bin").is_file(),
        "auto must minimize the crash representative: {}",
        crash_dir.display()
    );
    let index = std::fs::read_to_string(results.join("INDEX.md")).unwrap();
    assert!(
        index.contains(&static_id) || index.contains("weak.c"),
        "{index}"
    );

    let run_json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work_dir.join("auto/run.json")).expect("read run.json"),
    )
    .expect("parse run.json");
    assert!(
        run_json["summary"]["fuzz_confirmed"].as_u64().unwrap_or(0) >= 1,
        "run.json summary must count the confirmed finding: {}",
        run_json["summary"]
    );
}

/// `--static-dynamic` is accepted for compatibility; `results/findings.csv`
/// always carries a `kind` column (`static` / `fuzz`).
#[test]
fn static_dynamic_flag_is_accepted_and_kind_column_is_always_present() {
    if which::which("clang").is_err() || which::which("make").is_err() {
        eprintln!("SKIP: clang/make not installed — C lane unavailable");
        return;
    }
    let tmp = tempfile::Builder::new()
        .prefix("bhf-scan-type-")
        .tempdir()
        .expect("tempdir");
    let srcroot = tmp.path().join("srcroot");
    std::fs::create_dir_all(&srcroot).expect("mkdir srcroot");
    std::fs::copy(
        repo_root().join("tests/fixtures/static_scan/weak.c"),
        srcroot.join("weak.c"),
    )
    .expect("copy fixture");
    let work_dir = srcroot.join("bhf_work");
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["auto", "--static", "--static-dynamic"])
        .arg(&srcroot)
        .arg("--work-dir")
        .arg(&work_dir)
        .args(["--per-target-time", "1"])
        .status()
        .expect("spawn bhf auto --static --static-dynamic");
    assert!(status.success());
    let csv =
        std::fs::read_to_string(work_dir.join("results/findings.csv")).expect("read findings.csv");
    let header: Vec<&str> = csv.lines().next().expect("header").split(',').collect();
    let kind = header
        .iter()
        .position(|c| *c == "kind")
        .expect("kind column");
    let kinds: std::collections::BTreeSet<&str> = csv
        .lines()
        .skip(1)
        .filter_map(|row| row.split(',').nth(kind))
        .collect();
    assert!(kinds.contains("static"), "{csv}");
}
