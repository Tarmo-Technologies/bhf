// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for `bhf project <validate|list|run>` (issue #56).
//!
//! These drive the real `bhf` binary (`CARGO_BIN_EXE_bhf`) against a committed
//! two-target fixture staged into a tempdir OUTSIDE the repo working tree, with
//! the harness binary supplied by the prebuilt `cli_fake_harness` bin (no C
//! toolchain, no committed binary). They exercise: listing, validation of the
//! happy path and each error class, manifest-root-relative path resolution,
//! trusted build-command execution (and `--skip-build`), work-dir
//! materialization + provenance, finding provenance stamping, and secret
//! redaction.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn bhf() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/project_min")
}

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("bhf-project-cli-{name}-{nonce}"));
    fs::create_dir_all(&dir).expect("temp dir is created");
    dir
}

fn copy_tree(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("dst dir");
    for entry in fs::read_dir(src).expect("read fixture dir") {
        let entry = entry.expect("fixture entry");
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_tree(&from, &to);
        } else {
            fs::copy(&from, &to).expect("copy fixture file");
        }
    }
}

/// Stage the committed fixture into a fresh project dir outside the repo tree and
/// drop the prebuilt harness at the manifest-relative `prebuilt/harness`.
fn stage(name: &str) -> (PathBuf, PathBuf) {
    let root = temp_dir(name);
    let project = root.join("project");
    copy_tree(&fixture_root(), &project);
    let harness_src = PathBuf::from(env!("CARGO_BIN_EXE_cli_fake_harness"));
    let harness_dst = project.join("prebuilt/harness");
    fs::create_dir_all(harness_dst.parent().unwrap()).expect("prebuilt dir");
    fs::copy(&harness_src, &harness_dst).expect("stage prebuilt harness");
    make_executable(&harness_dst);
    (root, project)
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path).expect("metadata").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).expect("chmod +x");
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}

fn json(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).expect("valid JSON on stdout")
}

#[test]
fn project_list_shows_two_targets() {
    let (_root, project) = stage("list");
    let out = bhf()
        .args(["project", "list", "--manifest"])
        .arg(project.join("manifest.toml"))
        .output()
        .expect("run bhf project list");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("alpha"), "missing alpha: {stdout}");
    assert!(stdout.contains("beta"), "missing beta: {stdout}");

    // --json lists exactly the two declared targets with their engine.
    let out = bhf()
        .args(["project", "list", "--json", "--manifest"])
        .arg(project.join("manifest.toml"))
        .output()
        .expect("run bhf project list --json");
    assert!(out.status.success());
    let v = json(&out.stdout);
    let targets = v["targets"].as_array().expect("targets array");
    assert_eq!(targets.len(), 2);
    assert_eq!(v["project"]["id"], "demo-fuzz");
    assert_eq!(targets[0]["id"], "alpha");
    assert_eq!(targets[0]["engine"], "builtin");
    assert_eq!(targets[0]["dictionaries"], 2);
    assert_eq!(targets[0]["grammar"], true);
}

#[test]
fn project_validate_valid_fixture_exits_zero_with_provenance_and_never_builds() {
    let (_root, project) = stage("validate-ok");
    let out = bhf()
        .args(["project", "validate", "--json", "--manifest"])
        .arg(project.join("manifest.toml"))
        .output()
        .expect("run bhf project validate");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let v = json(&out.stdout);
    assert_eq!(v["ok"], true);
    let targets = v["targets"].as_array().expect("targets");
    assert_eq!(targets.len(), 2);
    // Every target carries a 64-hex manifest hash and at least the harness asset.
    for t in targets {
        assert_eq!(t["manifest_sha256"].as_str().unwrap().len(), 64);
        assert!(t["assets"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["kind"] == "harness"));
    }
    // validate resolves + hashes but NEVER runs the build command.
    assert!(
        !project.join(".build-sentinel").exists(),
        "validate must not run the build command"
    );
}

#[test]
fn project_validate_reports_missing_asset() {
    let dir = temp_dir("validate-missing");
    // A manifest that references a seed dir that does not exist. The binary is
    // present so the FIRST failure is the missing seed, not the binary.
    fs::write(dir.join("harness"), b"#!/bin/sh\nexit 0\n").unwrap();
    make_executable(&dir.join("harness"));
    fs::write(
        dir.join("manifest.toml"),
        r#"schema = "bhf.project.v1"
[project]
id = "p"
version = "1"
[[target]]
id = "a"
engine = "builtin"
binary = "harness"
seeds = ["corpus/ghost"]
"#,
    )
    .unwrap();
    let out = bhf()
        .args(["project", "validate", "--manifest"])
        .arg(dir.join("manifest.toml"))
        .output()
        .expect("run validate");
    assert!(
        !out.status.success(),
        "a missing asset must fail validation"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("asset not found"), "stderr: {stderr}");
}

#[test]
fn project_validate_rejects_parent_escape_path() {
    let dir = temp_dir("validate-escape");
    fs::write(dir.join("harness"), b"bin").unwrap();
    fs::write(
        dir.join("manifest.toml"),
        r#"schema = "bhf.project.v1"
[project]
id = "p"
version = "1"
[[target]]
id = "a"
engine = "builtin"
binary = "../escape.bin"
"#,
    )
    .unwrap();
    let out = bhf()
        .args(["project", "validate", "--manifest"])
        .arg(dir.join("manifest.toml"))
        .output()
        .expect("run validate");
    assert!(
        !out.status.success(),
        "a `..` escape must be rejected by default"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("escapes the manifest directory"),
        "stderr: {stderr}"
    );
}

#[test]
fn project_validate_resolves_manifest_root_relative_paths_from_other_cwd() {
    let (root, project) = stage("relative-cwd");
    // Run from an unrelated cwd, with an absolute manifest path. Every asset is
    // declared relative to the manifest dir, so resolution must succeed anyway.
    let elsewhere = root.join("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    let out = bhf()
        .current_dir(&elsewhere)
        .args(["project", "validate", "--target", "alpha", "--manifest"])
        .arg(project.join("manifest.toml"))
        .output()
        .expect("run validate from other cwd");
    assert!(
        out.status.success(),
        "manifest-root-relative resolution failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn project_run_builtin_materializes_and_fuzzes() {
    let (root, project) = stage("run-builtin");
    let work = root.join("work");
    let out = bhf()
        .args(["project", "run", "--target", "alpha", "--manifest"])
        .arg(project.join("manifest.toml"))
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run bhf project run");
    assert!(
        out.status.success(),
        "project run failed: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // The trusted build command ran (explicit load = trusted).
    assert!(
        project.join(".build-sentinel").exists(),
        "build command did not run"
    );

    // The harness was materialized where the engine probes first; the operator
    // copied nothing under build/harnesses/auto.
    assert!(
        work.join("build/alpha/main").is_file(),
        "harness not materialized"
    );

    // The merged, de-duplicated dictionary was written where the engine looks,
    // with both layers in declared order.
    let dict = fs::read_to_string(work.join("build/alpha/dictionary.txt"))
        .expect("merged dictionary materialized");
    assert_eq!(
        dict, "\"alpha\"\n\"beta\"\n\"gamma\"\n",
        "merged dict: {dict:?}"
    );

    // A native run summary exists.
    assert!(
        work.join("fuzz_runs/alpha-latest.json").is_file(),
        "no run summary"
    );

    // Authoritative provenance records the manifest hash and every asset hash.
    let prov: serde_json::Value =
        serde_json::from_slice(&fs::read(work.join("results/project.json")).unwrap()).unwrap();
    assert_eq!(prov["project_id"], "demo-fuzz");
    assert_eq!(prov["target_id"], "alpha");
    assert_eq!(prov["schema"], "bhf.project.v1");
    assert_eq!(prov["manifest_sha256"].as_str().unwrap().len(), 64);
    let assets = prov["assets"].as_array().unwrap();
    assert!(assets
        .iter()
        .all(|a| a["sha256"].as_str().unwrap().len() == 64));
    assert!(assets.iter().any(|a| a["kind"] == "merged-dictionary"));

    // The crash seed produced a finding, and it was stamped with provenance.
    let findings_dir = work.join("results/findings");
    let finding = fs::read_dir(&findings_dir)
        .expect("findings dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.is_dir())
        .expect("at least one finding dir");
    let sidecar: serde_json::Value =
        serde_json::from_slice(&fs::read(finding.join("project-provenance.json")).unwrap())
            .expect("finding carries project-provenance.json");
    assert_eq!(sidecar["project_id"], "demo-fuzz");
    assert_eq!(sidecar["target_id"], "alpha");
    assert_eq!(sidecar["manifest_sha256"], prov["manifest_sha256"]);
}

#[test]
fn project_run_skip_build_does_not_run_build_command() {
    let (root, project) = stage("run-skip-build");
    let work = root.join("work");
    let out = bhf()
        .args([
            "project",
            "run",
            "--skip-build",
            "--target",
            "beta",
            "--manifest",
        ])
        .arg(project.join("manifest.toml"))
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run bhf project run --skip-build");
    assert!(
        out.status.success(),
        "skip-build run failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The build command was skipped: no sentinel.
    assert!(
        !project.join(".build-sentinel").exists(),
        "--skip-build must not run the build command"
    );
    // The run still started and recorded provenance from the prebuilt binary.
    assert!(
        work.join("results/project.json").is_file(),
        "no provenance written"
    );
    assert!(
        work.join("build/beta/main").is_file(),
        "prebuilt harness not materialized"
    );
}

#[test]
fn project_validate_redacts_secret_values() {
    let (_root, project) = stage("secret");
    // Add a manifest whose target carries a secret-handle env value. Resolution
    // reads the secret from BHF_SECRET_API_TOKEN but must record only the handle.
    fs::write(
        project.join("manifest-secret.toml"),
        r#"schema = "bhf.project.v1"
[project]
id = "demo-fuzz"
version = "1.0.0"
[[target]]
id = "sec"
engine = "builtin"
binary = "prebuilt/harness"
seeds = ["corpus/beta"]
[target.env]
PROFILE = "release"
TOKEN = "${secret:API_TOKEN}"
"#,
    )
    .unwrap();

    let out = bhf()
        .env("BHF_SECRET_API_TOKEN", "s3cr3t-value")
        .args([
            "project",
            "validate",
            "--target",
            "sec",
            "--json",
            "--manifest",
        ])
        .arg(project.join("manifest-secret.toml"))
        .output()
        .expect("run validate with a secret");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The handle is recorded; the resolved value never appears anywhere.
    assert!(
        stdout.contains("${secret:API_TOKEN}"),
        "handle missing: {stdout}"
    );
    assert!(
        !stdout.contains("s3cr3t-value"),
        "secret value leaked: {stdout}"
    );
    // The public literal passes through.
    assert!(stdout.contains("release"), "literal env missing: {stdout}");
}
