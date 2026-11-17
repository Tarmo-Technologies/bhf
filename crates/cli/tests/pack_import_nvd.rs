// SPDX-License-Identifier: Apache-2.0

//! `bhf pack import-nvd` (#387): NVD CVE records become advisory database
//! records that match a native component by its CPE and version range. A C
//! or C++ library an SBOM or `bhf binary scan` names is identified by CPE,
//! which only NVD data carries.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/nvd")
}

fn bhf(args: &[&str], cwd: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
        .current_dir(cwd)
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn an_nvd_record_matches_a_component_by_cpe_and_version_range() {
    let root = TestDir::new("pack-import-nvd");
    let db = root.join("cve-db.json");
    let out = bhf(
        &["pack", "import-nvd", fixtures().to_str().unwrap()],
        root.path(),
    );
    assert_eq!(out.status.code(), Some(2), "--out is required");
    let out = bhf(
        &[
            "pack",
            "import-nvd",
            fixtures().to_str().unwrap(),
            "--out",
            db.to_str().unwrap(),
        ],
        root.path(),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    let summary: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(summary["format"], "nvd");
    assert_eq!(summary["files"], 2, "{summary:#}");
    assert_eq!(summary["feed_records"], 5, "{summary:#}");
    assert_eq!(summary["records_written"], 3, "{summary:#}");
    assert_eq!(summary["without_versions"], 0, "{summary:#}");
    let malformed: Vec<String> = summary["malformed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| format!("{} {}", entry["source"], entry["reason"]))
        .collect();
    for expected in [
        "truncated.json\" \"not JSON",
        "\" \"a CVE record without an id",
        "(CVE-2026-90104)\" \"configurations[0]: a CPE match without criteria",
        "(CVE-2026-90104)\" \"configurations[0]: criteria `openssl 1.0.2` is not a CPE 2.3 string",
    ] {
        assert!(
            malformed.iter().any(|line| line.contains(expected)),
            "{expected}: {malformed:#?}"
        );
    }
    assert_eq!(malformed.len(), 4, "{malformed:#?}");
    assert_eq!(
        stderr.matches("bhf pack import-nvd: skipped ").count(),
        4,
        "{stderr}"
    );

    let database: Value = serde_json::from_slice(&std::fs::read(&db).unwrap()).unwrap();
    let first = &database["vulnerabilities"][0];
    assert_eq!(first["id"], "CVE-2026-90101");
    assert_eq!(
        first["package"]["cpe"],
        "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"
    );
    assert_eq!(first["severity"], "high");
    assert_eq!(
        first["affected_ranges"],
        serde_json::json!([{"start_including": "1.0.2", "end_excluding": "1.0.2u"}])
    );
    assert_eq!(database["vulnerabilities"][1]["severity"], "medium");

    // A vendored openssl 1.0.2t, identified by CPE: in the first range, not
    // the 1.1.1 record, and past the range that ends at 1.0.2a.
    let src = root.join("src/vendor/openssl");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("bhf-component.json"),
        serde_json::to_vec(&serde_json::json!({
            "name": "openssl",
            "version": "1.0.2t",
            "cpe": "cpe:2.3:a:openssl:openssl:1.0.2t:*:*:*:*:*:*:*",
        }))
        .unwrap(),
    )
    .unwrap();
    let sbom = root.join("sbom");
    let out = bhf(
        &[
            "sbom",
            root.join("src").to_str().unwrap(),
            "--out",
            sbom.to_str().unwrap(),
            "--vuln-db",
            db.to_str().unwrap(),
        ],
        root.path(),
    );
    assert!(
        out.status.code().is_some_and(|code| code <= 1),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: Value =
        serde_json::from_slice(&std::fs::read(sbom.join("vulnerabilities.json")).unwrap()).unwrap();
    let matched: Vec<(&str, &str)> = report["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            (
                m["id"].as_str().unwrap_or_default(),
                m["matching_method"].as_str().unwrap_or_default(),
            )
        })
        .collect();
    assert_eq!(matched, [("CVE-2026-90101", "cpe")], "{report:#}");
}
