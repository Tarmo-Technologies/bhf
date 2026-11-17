// SPDX-License-Identifier: Apache-2.0

//! `bhf pack import-osv` (#223): OSV records become an advisory database
//! that `bhf sbom --vuln-db` matches. No command built one from a public feed,
//! so an offline user could not gate on real advisories.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/osv")
}

fn bhf(args: &[&str], cwd: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
        .current_dir(cwd)
        .args(args)
        .output()
        .unwrap()
}

/// A Cargo project locked to openssl 0.10.0.
fn openssl_project(root: &Path) -> PathBuf {
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nopenssl = \"=0.10.0\"\n",
    )
    .unwrap();
    std::fs::write(
        src.join("Cargo.lock"),
        "version = 3\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\
         dependencies = [\"openssl\"]\n\n[[package]]\nname = \"openssl\"\nversion = \"0.10.0\"\n\
         source = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
    )
    .unwrap();
    src
}

#[test]
fn osv_records_become_a_database_that_matches_openssl_0_10_0() {
    let root = TestDir::new("pack-import-osv");
    let db = root.join("cve-db.json");
    let out = bhf(
        &[
            "pack",
            "import-osv",
            fixtures().to_str().unwrap(),
            "--out",
            db.to_str().unwrap(),
        ],
        root.path(),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    let summary: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(summary["files"], 4, "{summary:#}");
    assert_eq!(summary["feed_records"], 6, "{summary:#}");
    assert_eq!(summary["records_written"], 3, "{summary:#}");
    assert_eq!(
        summary["unsupported_ecosystems"]["Debian"], 1,
        "{summary:#}"
    );
    assert_eq!(summary["without_versions"], 1, "{summary:#}");

    // Each malformed record or file is reported, on stderr and in the
    // summary, and skipped.
    let malformed: Vec<String> = summary["malformed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| format!("{} {}", entry["source"], entry["reason"]))
        .collect();
    assert_eq!(malformed.len(), 4, "{malformed:#?}");
    for expected in [
        "truncated.json\" \"not JSON",
        "batch.json\" \"an OSV record without an id",
        "(TEST-2026-0004)\" \"affected[0] names no package ecosystem and name",
        "(TEST-2026-0004)\" \"affected[1]: unknown range event `broken`",
    ] {
        assert!(
            malformed.iter().any(|line| line.contains(expected)),
            "{expected}: {malformed:#?}"
        );
    }
    assert_eq!(
        stderr.matches("bhf pack import-osv: skipped ").count(),
        4,
        "{stderr}"
    );

    let database: Value = serde_json::from_slice(&std::fs::read(&db).unwrap()).unwrap();
    assert_eq!(database["schema_version"], "bhf.cve_db.v1");
    let first = &database["vulnerabilities"][0];
    assert_eq!(first["id"], "TEST-2026-0001");
    assert_eq!(first["package"]["ecosystem"], "cargo");
    assert_eq!(first["severity"], "high");
    assert_eq!(first["aliases"][0], "CVE-2026-90001");
    assert_eq!(
        first["affected_ranges"][0],
        serde_json::json!({"start_including": "0.10.0", "end_excluding": "0.10.38"})
    );

    // The range record and the explicit-version record match openssl
    // 0.10.0; the one fixed in 0.9.10 does not.
    let src = openssl_project(root.path());
    let sbom = root.join("sbom");
    let out = bhf(
        &[
            "sbom",
            src.to_str().unwrap(),
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
    let matched: Vec<(String, String)> = report["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| {
            (
                m["id"].as_str().unwrap_or_default().to_owned(),
                m["severity"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        matched,
        [
            ("TEST-2026-0001".to_owned(), "high".to_owned()),
            ("TEST-2026-0002".to_owned(), "critical".to_owned()),
        ],
        "{report:#}"
    );
    assert_eq!(report["advisory_db"]["entries"], 3);
}

/// Input made only of malformed records imports nothing and fails.
#[test]
fn a_feed_of_only_malformed_records_fails() {
    let root = TestDir::new("pack-import-osv-bad");
    let db = root.join("cve-db.json");
    let out = bhf(
        &[
            "pack",
            "import-osv",
            fixtures().join("other/truncated.json").to_str().unwrap(),
            "--out",
            db.to_str().unwrap(),
        ],
        root.path(),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not JSON"));
}
