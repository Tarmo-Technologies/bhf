// SPDX-License-Identifier: Apache-2.0
//! One work dir, three producers (auto --static on a crashing C fixture, sbom,
//! static-scan), one results/ index that holds all of them. Gated on clang/make.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn bhf(cwd: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
        .current_dir(cwd)
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn one_results_dir_for_every_producer() {
    if which::which("clang").is_err() || which::which("make").is_err() {
        eprintln!("SKIP: clang/make not installed — C lane unavailable");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::copy(
        repo_root().join("tests/fixtures/static_scan/weak.c"),
        src.join("weak.c"),
    )
    .unwrap();
    std::fs::write(src.join("component.json"), r#"{"name":"example","version":"2.4.2","ecosystem":"npm","type":"library","purl":"pkg:npm/example@2.4.2"}"#).unwrap();
    let db = tmp.path().join("advisories.json");
    std::fs::write(&db, r#"{"vulnerabilities":[{"id":"CVE-2026-TEST","severity":"high","summary":"t","package":{"ecosystem":"npm","name":"example"},"affected_versions":["2.4.2"],"fixed_versions":["2.4.3"]}]}"#).unwrap();

    // Defaults everywhere: cwd = tmp so bhf_work resolves to tmp/bhf_work.
    let auto = bhf(
        tmp.path(),
        &["auto", "--static", "src", "--per-target-time", "1"],
    );
    assert!(
        matches!(auto.status.code(), Some(0..=2)),
        "{}",
        String::from_utf8_lossy(&auto.stderr)
    );
    let sbom = bhf(
        tmp.path(),
        &["sbom", "src", "--vuln-db", db.to_str().unwrap()],
    );
    assert!(
        sbom.status.success(),
        "{}",
        String::from_utf8_lossy(&sbom.stderr)
    );
    let scan = bhf(tmp.path(), &["static-scan", "src"]);
    assert!(
        scan.status.success(),
        "{}",
        String::from_utf8_lossy(&scan.stderr)
    );
    let report = bhf(tmp.path(), &["report"]);
    assert!(
        report.status.success(),
        "{}",
        String::from_utf8_lossy(&report.stderr)
    );

    let results = tmp.path().join("bhf_work/results");
    let doc: results::model::FindingsDocument =
        serde_json::from_slice(&std::fs::read(results.join("findings.json")).unwrap())
            .expect("strict v1 parse");
    let kinds: std::collections::BTreeSet<_> =
        doc.findings.iter().map(|f| f.kind.as_str()).collect();
    for want in ["fuzz", "static", "sca"] {
        assert!(kinds.contains(want), "missing {want}: {kinds:?}");
    }
    let commands: Vec<_> = doc.producers.iter().map(|p| p.command.as_str()).collect();
    assert_eq!(
        commands,
        ["auto", "sbom", "static-scan"],
        "report is not a producer"
    );
    let index = std::fs::read_to_string(results.join("INDEX.md")).unwrap();
    assert!(index.contains("By kind:") && index.contains("sca"));
    let fuzz = doc
        .findings
        .iter()
        .find(|f| f.kind == results::model::Kind::Fuzz)
        .unwrap();
    let roles: Vec<_> = fuzz
        .evidence
        .as_ref()
        .unwrap()
        .files
        .iter()
        .map(|f| f.role.as_str())
        .collect();
    for role in ["finding", "testcase", "sanitizer_log", "replay_script"] {
        assert!(roles.contains(&role), "{role} missing: {roles:?}");
    }
    assert!(!tmp.path().join("bhf_work/FINDINGS.md").exists());
    for f in [
        "findings.csv",
        "findings.sarif",
        "attestation.json",
        "manifest.json",
    ] {
        assert!(results.join(f).is_file(), "{f}");
    }
}
