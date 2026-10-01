// SPDX-License-Identifier: Apache-2.0
//! Builds a synthetic work dir with one finding of every kind, rebuilds it, and
//! compares (or with BHF_UPDATE_GOLDEN=1, rewrites) tests/fixtures/golden_results.
//! Importers can use that directory as a reference fixture for the contract.
//! Titles, CWEs and remediation text come from the rule catalog, so editing a
//! rule drifts the fixture by design: review the diff, then regenerate with
//! `BHF_UPDATE_GOLDEN=1`.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// The tool version the fixture is stamped with, independent of the crate
/// version the SARIF driver block is built from.
const GOLDEN_VERSION: &str = "0.3.0";

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn put(path: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

fn put_json(path: &Path, value: Value) {
    put(path, &serde_json::to_vec_pretty(&value).unwrap());
}

fn build(work: &Path) {
    let f = work.join("results/findings");
    put_json(
        &work.join("auto/run.json"),
        json!({"schema_version": 1, "source_root": "/src/demo", "partial": false, "summary": {"discovered": 3}}),
    );
    put_json(
        &f.join("F-0000-1a2b3c4d/finding.json"),
        json!({
            "schema_version": "bhf.finding.v1", "finding_kind": "fuzz", "created_at": "2026-10-01T11:20:00Z",
            "id": "F-0000-1a2b3c4d", "signature": "aa11bb22", "cluster_key": "c0ffee00", "cluster_key_full": "c0ffee00c0ffee00",
            "cluster_normalized_frames": ["parse_header"], "cluster_fallback": false,
            "rule_id": "BHF-201", "classification": "unhandled", "harness_id": "H-C-parse", "dialect": "c11",
            "exception": {"name": "ASAN_HEAP_BUFFER_OVERFLOW", "message": "heap-buffer-overflow on address 0x602000000010",
                          "sanitizer": "asan", "stack": [{"function": "parse_header", "file": "/src/demo/src/parse.c", "line": 42}]},
            "build": {"binary": {"sha256": "2222222222222222222222222222222222222222222222222222222222222222", "build_id": "abcdef01"}}
        }),
    );
    put(&f.join("F-0000-1a2b3c4d/testcase.bin"), b"AAAA");
    put(&f.join("F-0000-1a2b3c4d/min_testcase.bin"), b"A");
    put(
        &f.join("F-0000-1a2b3c4d/sanitizer.log"),
        b"==1==ERROR: AddressSanitizer: heap-buffer-overflow\n",
    );
    put_json(
        &f.join("F-TSAN-0000/finding.json"),
        json!({
            "schema_version": "bhf.finding.v1", "finding_kind": "runtime", "created_at": "2026-10-01T11:30:00Z",
            "id": "F-TSAN-0000", "rule_id": "BHF-556", "classification": "unhandled", "harness_id": "H-C-parse",
            "exception": {"name": "TSAN_DATA_RACE", "sanitizer": "tsan", "message": "data race"}
        }),
    );
    put(&f.join("F-TSAN-0000/testcase.bin"), b"B");
    put_json(
        &f.join("F-DIFF-0000/finding.json"),
        json!({
            "schema_version": "bhf.finding.v1", "finding_kind": "differential", "created_at": "2026-10-01T11:40:00Z",
            "id": "F-DIFF-0000", "signature": "dd", "rule_id": "BHF-301", "classification": "divergence",
            "exception": {"name": "OUTPUT_DIVERGENCE", "message": "stdout bytes differ"}
        }),
    );
    put(&f.join("F-DIFF-0000/testcase.bin"), b"C");
    put_json(
        &f.join("BF-0001/finding.json"),
        json!({
            "schema_version": "bhf.finding.v1", "finding_kind": "binary", "created_at": "2026-10-01T11:50:00Z",
            "id": "BF-0001", "kind": "binary_crash", "rule_id": "BHF-501", "severity": "high", "confidence": "high",
            "message": "Binary crashed under BHF binary-fuzz",
            "binary": {"path": "/bin/demo", "sha256": "3333333333333333333333333333333333333333333333333333333333333333"},
            "crash": {"exit_code": null, "timeout": false, "signature": "signal:11:x"}
        }),
    );
    put(&f.join("BF-0001/testcase.bin"), b"D");
    // An auto static row in the pre-0.3 shape: no sink, location only in target/oracle evidence,
    // no static_fingerprint. Exercises the location fallback and the rule:file:line primary.
    put_json(
        &f.join("F-RO-BHF-401-0000ABCD/finding.json"),
        json!({
            "schema_version": "bhf.finding.v1", "finding_kind": "static", "created_at": "2026-10-01T11:10:00Z",
            "id": "F-RO-BHF-401-0000ABCD", "rule_id": "BHF-401", "classification": "static_scan", "confirmation": "static",
            "severity": "high", "report_only": true,
            "exception": {"message": "Unbounded string copy (strcpy/strcat/gets) with no length limit", "source_file": "", "source_line": ""},
            "oracle": {"evidence": [{"key": "source", "value": "/src/demo/lib/parse.c:6:copy_name"}]},
            "target": {"line": 6, "location": {"line": 6, "path": "/src/demo/lib/parse.c"}, "name": "parse.c", "source_path": "/src/demo/lib/parse.c"}
        }),
    );
    put_json(
        &work.join("results/static/static-report.json"),
        json!({
            "schema_version": "bhf.static.v1", "root": "/src/demo",
            "findings": [{
                "id": "S-0001", "rule_id": "BHF-401", "rule_slug": "bhf.static/unsafe-string-copy", "cwe": "CWE-120",
                "remediation": "Use a bounded copy.", "language": "c", "severity": "high", "confidence": "medium",
                "baseline_status": "new", "message": "strcpy into fixed buffer",
                "location": {"path": "/src/demo/weak.c", "line": 9, "column": 5}, "fingerprint": "fp-weak-9", "identity": "id-weak",
                "evidence": [{"kind": "sink", "detail": "strcpy", "snippet": "strcpy(buf, name);"}],
                "analysis": {"engine": "taint", "enclosing_function": "greet",
                             "trace": [{"kind": "source", "path": "/src/demo/weak.c", "line": 3, "caller": "main", "callee": "greet", "snippet": ""}]},
                "triage": {"state": "open", "note": ""}
            }],
            "issues": [{"issue_key": "issue-weak", "finding_ids": ["S-0001"]}]
        }),
    );
    // static-scan's own SARIF (the static_analysis emitter's shape): its results
    // carry no bhfFindingId, and are merged into the one results run.
    put_json(
        &work.join("results/static/static-report.sarif"),
        json!({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "BHF", "version": "0.3.0", "semanticVersion": "0.3.0",
                                    "informationUri": "https://github.com/Tarmo-Technologies/bhf",
                                    "rules": [{"id": "BHF-401", "name": "bhf.static/unsafe-string-copy",
                                               "shortDescription": {"text": "Unsafe string copy call in source"}}]}},
                "results": [{
                    "ruleId": "BHF-401", "kind": "fail", "level": "error",
                    "message": {"text": "strcpy into fixed buffer"}, "help": {"text": "Use a bounded copy."},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "weak.c", "uriBaseId": "SRCROOT"},
                        "region": {"startLine": 9, "startColumn": 5}}}],
                    "partialFingerprints": {"bhfStaticFingerprint": "fp-weak-9"},
                    "properties": {"findingKind": "static", "cwe": "CWE-120", "fingerprint": "fp-weak-9",
                                   "baselineStatus": "new", "confidence": "medium", "language": "c"}
                }],
                "properties": {"bhfStaticSchemaVersion": "bhf.static.v1", "findingKind": "static"},
                "originalUriBaseIds": {"SRCROOT": {"uri": "file:///src/demo/"}}
            }]
        }),
    );
    put_json(
        &work.join("results/sbom/vulnerabilities.json"),
        json!({
            "matches": [{
                "id": "CVE-2026-0001", "severity": "high", "summary": "test advisory",
                "component": {"name": "example", "version": "2.4.2", "ecosystem": "npm", "purl": "pkg:npm/example@2.4.2", "cpe": null},
                "match_confidence": "high", "matching_method": "purl", "cwe": ["CWE-1395"],
                "reachability": {"status": "not_observed", "source": "auto_run"},
                "vex": {"advisory_fixed_versions": ["2.4.3"]}
            }]
        }),
    );
}

/// Paths under results/ that the golden comparison covers (stable, no timestamps).
const COMPARED: [&str; 4] = [
    "findings.json",
    "findings.csv",
    "INDEX.md",
    "findings.sarif",
];

/// The SARIF driver block carries the report crate's `CARGO_PKG_VERSION`;
/// pin it so a release bump does not drift the fixture.
fn normalize_sarif(text: &str) -> String {
    let mut sarif: Value = serde_json::from_str(text).unwrap();
    for run in sarif["runs"].as_array_mut().into_iter().flatten() {
        let driver = &mut run["tool"]["driver"];
        for key in ["version", "semanticVersion"] {
            if driver.get(key).is_some() {
                driver[key] = json!(GOLDEN_VERSION);
            }
        }
    }
    let mut out = serde_json::to_string_pretty(&sarif).unwrap();
    out.push('\n');
    out
}

fn options() -> results::RebuildOptions {
    results::RebuildOptions {
        tool: results::model::ToolInfo {
            name: "bhf".into(),
            version: GOLDEN_VERSION.into(),
            build: GOLDEN_VERSION.into(),
        },
        now: Some("2026-10-01T12:00:00Z".into()),
        generate_reproducers: false,
        lock_timeout: std::time::Duration::from_secs(5),
    }
}

#[test]
fn golden_results_match() {
    let tmp = tempfile::tempdir().unwrap();
    build(tmp.path());
    let options = options();
    results::rebuild(tmp.path(), &options).unwrap();

    let golden = repo().join("tests/fixtures/golden_results");
    let produced = tmp.path().join("results");
    if std::env::var_os("BHF_UPDATE_GOLDEN").is_some() {
        // Pin the SARIF version first, then re-attest, so the fixture's
        // attestation digests match the files shipped next to it.
        let sarif = produced.join("findings.sarif");
        let pinned = normalize_sarif(&std::fs::read_to_string(&sarif).unwrap());
        results::rebuild::write_atomic(&sarif, pinned.as_bytes()).unwrap();
        let attestation = results::rebuild::attestation(&produced, &options.tool).unwrap();
        let mut bytes = serde_json::to_vec_pretty(&attestation).unwrap();
        bytes.push(b'\n');
        results::rebuild::write_atomic(&produced.join("attestation.json"), &bytes).unwrap();

        let _ = std::fs::remove_dir_all(&golden);
        copy_tree(&produced, &golden.join("results"));
        put(
            &golden.join("auto/run.json"),
            &std::fs::read(tmp.path().join("auto/run.json")).unwrap(),
        );
        return;
    }
    for name in COMPARED {
        let want = std::fs::read_to_string(golden.join("results").join(name))
            .unwrap_or_else(|_| panic!("missing golden {name}; run with BHF_UPDATE_GOLDEN=1"));
        let got = std::fs::read_to_string(produced.join(name)).unwrap();
        let (got, want) = if name == "findings.sarif" {
            (normalize_sarif(&got), normalize_sarif(&want))
        } else {
            (got, want)
        };
        assert_eq!(
            got, want,
            "{name} drifted; review and regenerate with BHF_UPDATE_GOLDEN=1"
        );
    }
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap().flatten() {
        let name = entry.file_name();
        if name.to_string_lossy().starts_with('.') {
            continue; // .lock and any stray temp file
        }
        let dest = to.join(&name);
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &dest);
        } else {
            std::fs::copy(entry.path(), dest).unwrap();
        }
    }
}
