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

// ── [[extension]] convergence (#57): bhf project run loads a trusted extension ──

#[cfg(unix)]
#[test]
fn project_run_loads_declared_extension_and_emits_finding() {
    let root = temp_dir("run-extension");
    let project = root.join("project");
    fs::create_dir_all(project.join("corpus/alpha")).unwrap();

    // Harness (prebuilt) + the trusted extension executable, both staged into the
    // project tree so they resolve manifest-relative (no --allow-external-paths).
    let harness = PathBuf::from(env!("CARGO_BIN_EXE_cli_fake_harness"));
    fs::create_dir_all(project.join("prebuilt")).unwrap();
    fs::copy(&harness, project.join("prebuilt/harness")).unwrap();
    make_executable(&project.join("prebuilt/harness"));

    let ext = PathBuf::from(env!("CARGO_BIN_EXE_bhf_ext_mock"));
    fs::create_dir_all(project.join("ext")).unwrap();
    fs::copy(&ext, project.join("ext/mock")).unwrap();
    make_executable(&project.join("ext/mock"));

    // A clean-exit semantic violation the extension oracle flags (the fake harness
    // does not crash on it).
    fs::write(project.join("corpus/alpha/seed0"), b"../etc/passwd").unwrap();

    let manifest = project.join("manifest.toml");
    fs::write(
        &manifest,
        r#"
schema = "bhf.project.v1"

[project]
id = "ext-demo"
version = "1.0.0"

[[target]]
id = "alpha"
engine = "builtin"
binary = "prebuilt/harness"
seeds = ["corpus/alpha"]
time = "2s"

[[extension]]
id = "mock"
executable = "ext/mock"
args = ["--mode", "well-behaved"]
required-capabilities = ["oracle.evaluate"]
optional-capabilities = ["codec.repair"]
"#,
    )
    .unwrap();

    let work = root.join("work");
    let out = bhf()
        .args(["project", "run", "--target", "alpha", "--manifest"])
        .arg(&manifest)
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run bhf project run with extension");
    assert!(
        out.status.success(),
        "project run failed: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // The project-level [[extension]] was materialized as a trusted
    // bhf.extension-manifest.v1 in the work dir and loaded by the run.
    let materialized = work.join("extension.toml");
    assert!(
        materialized.is_file(),
        "extension manifest not materialized"
    );
    let mtext = fs::read_to_string(&materialized).unwrap();
    assert!(mtext.contains("bhf.extension-manifest.v1"), "{mtext}");
    assert!(mtext.contains("allow-external-paths = true"), "{mtext}");

    // Provenance hashed the extension executable.
    let prov: serde_json::Value =
        serde_json::from_slice(&fs::read(work.join("results/project.json")).unwrap()).unwrap();
    assert!(
        prov["assets"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["kind"] == "extension"),
        "project.json records no extension asset: {prov}"
    );

    // The run summary carries the additive extension block (the extension was
    // actually driven over the retained corpus).
    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(work.join("fuzz_runs/alpha-latest.json")).unwrap())
            .unwrap();
    assert_eq!(summary["extension"]["active"], true, "{summary}");
    assert_eq!(summary["extension"]["protocol_version"], "bhf.extension.v1");

    // The loaded extension flagged the clean-exit escape as an extension finding.
    let ext_finding = fs::read_dir(work.join("results/findings"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let f = e.path().join("finding.json");
            f.is_file().then(|| {
                serde_json::from_slice::<serde_json::Value>(&fs::read(f).unwrap()).unwrap()
            })
        })
        .find(|f| f["confirmation"] == "extension");
    let ext_finding = ext_finding.expect("an extension finding from the loaded extension");
    assert_eq!(ext_finding["rule_id"], "oracle.path-escape");
}

// ── Composition (#47/#59/#55): `bhf project run` drives a runner + fixed argv +
//    postcondition hooks + runtime oracles on the binary lane ──────────────────

#[cfg(unix)]
#[test]
fn project_run_binary_wires_runner_target_args_and_postcondition() {
    let root = temp_dir("run-composition");
    let project = root.join("project");
    fs::create_dir_all(project.join("corpus")).unwrap();

    // A clean-exiting target: the user postcondition — not a crash — produces the
    // finding, proving the oracle hooks ran.
    let target = project.join("target.sh");
    fs::write(&target, "#!/bin/sh\nexit 0\n").unwrap();
    make_executable(&target);
    fs::write(project.join("corpus/seed0"), b"seed").unwrap();

    // A binary target composing #47 (runner via `env` + fixed `@@` argv), #59
    // (runtime oracles), and #55 (setup/oracle/reset postcondition). The oracle
    // always reports a violation so a binary_postcondition finding lands even on a
    // clean target exit. The hooks are self-contained (they run in a per-case
    // dir, not the project dir).
    let manifest = project.join("manifest.toml");
    fs::write(
        &manifest,
        r#"schema = "bhf.project.v1"
[project]
id = "composed"
version = "1.0.0"
[[target]]
id = "acme"
engine = "binary"
binary = "target.sh"
input-mode = "file"
runner = "env"
target-args = ["@@"]
runtime-oracles = "auto"
[target.postcondition]
setup-command = "true"
oracle-command = "echo policy-violation; exit 1"
reset-command = "true"
"#,
    )
    .unwrap();

    let work = root.join("work");
    let out = bhf()
        .args(["project", "run", "--target", "acme", "--manifest"])
        .arg(&manifest)
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run bhf project run (composed binary target)");
    assert!(
        out.status.success(),
        "composed project run failed: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // The user postcondition produced a BHF-502 finding on a clean target exit,
    // and it records the runner + fixed argv (#47) and the hook commands (#55) —
    // proving `bhf project run` wired every composition field end to end.
    let finding = fs::read_dir(work.join("results/findings"))
        .expect("findings dir")
        .flatten()
        .filter_map(|e| {
            let f = e.path().join("finding.json");
            f.is_file().then(|| {
                serde_json::from_slice::<serde_json::Value>(&fs::read(f).unwrap()).unwrap()
            })
        })
        .find(|f| f["kind"] == "binary_postcondition")
        .expect("a binary_postcondition finding from the wired oracle");

    assert_eq!(finding["rule_id"], "BHF-502");
    assert_eq!(finding["command"]["runner"], "env");
    assert_eq!(finding["command"]["target_args"][0], "@@");
    assert_eq!(finding["postcondition"]["setup_command"], "true");
    assert_eq!(
        finding["postcondition"]["oracle_command"],
        "echo policy-violation; exit 1"
    );
    assert_eq!(finding["postcondition"]["reset_command"], "true");
    assert_eq!(finding["postcondition"]["signature"], "policy-violation");

    // Provenance was written for the composed run.
    assert!(
        work.join("results/project.json").is_file(),
        "no provenance written"
    );
}

// ── Secret redaction (#56): a resolved `${secret:NAME}` value must NOT leak into
//    a binary-lane finding; replay re-resolves it from the environment ──────────

#[cfg(unix)]
#[test]
fn project_run_binary_redacts_secret_env_from_finding_and_replays_from_env() {
    let root = temp_dir("run-secret-redact");
    let project = root.join("project");
    fs::create_dir_all(&project).unwrap();

    // A target whose crash is GATED on the secret value actually reaching the
    // child: it exits non-zero (a crash to the binary engine) only when
    // `$TOKEN` equals the resolved secret. This makes the test prove two things
    // at once — the secret reaches the spawned process, yet never lands in the
    // finding (replay must recover it from the environment, not the record).
    let target = project.join("target.sh");
    fs::write(
        &target,
        "#!/bin/sh\nif [ \"$TOKEN\" = \"s3cr3t\" ]; then echo secret-gated-crash >&2; exit 139; fi\nexit 0\n",
    )
    .unwrap();
    make_executable(&target);

    let manifest = project.join("manifest.toml");
    fs::write(
        &manifest,
        r#"schema = "bhf.project.v1"
[project]
id = "secret-redact"
version = "1.0.0"
[[target]]
id = "sec"
engine = "binary"
binary = "target.sh"
input-mode = "stdin"
[target.env]
PROFILE = "release"
TOKEN = "${secret:API}"
"#,
    )
    .unwrap();

    let work = root.join("work");
    let out = bhf()
        .env("BHF_SECRET_API", "s3cr3t")
        .args(["project", "run", "--target", "sec", "--manifest"])
        .arg(&manifest)
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run bhf project run (secret-gated binary target)");
    assert!(
        out.status.success(),
        "secret-gated project run failed: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // Locate the binary_crash finding the secret-gated exit produced.
    let findings_dir = work.join("results/findings");
    let finding_dir = fs::read_dir(&findings_dir)
        .expect("findings dir exists")
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            let f = p.join("finding.json");
            f.is_file()
                && serde_json::from_slice::<serde_json::Value>(&fs::read(&f).unwrap())
                    .map(|v| v["kind"] == "binary_crash")
                    .unwrap_or(false)
        })
        .expect("a binary_crash finding gated on the secret value");

    // 1) The RAW finding bytes must not contain the secret value anywhere, and the
    //    env must record the handle (never the value), with the key marked for
    //    re-resolution. The public literal still passes through verbatim.
    let finding_bytes = fs::read(finding_dir.join("finding.json")).unwrap();
    assert!(
        !String::from_utf8_lossy(&finding_bytes).contains("s3cr3t"),
        "secret value leaked into finding.json: {}",
        String::from_utf8_lossy(&finding_bytes)
    );
    let finding: serde_json::Value = serde_json::from_slice(&finding_bytes).unwrap();
    assert_eq!(finding["env"]["TOKEN"], "${secret:API}", "{finding}");
    assert_eq!(finding["env"]["PROFILE"], "release", "{finding}");
    let redacted: Vec<&str> = finding["redacted_env_keys"]
        .as_array()
        .expect("redacted_env_keys array")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(redacted, vec!["TOKEN"], "{finding}");

    // 2) Replay re-resolves the secret from the environment and reproduces.
    let replay_ok = bhf()
        .env("BHF_SECRET_API", "s3cr3t")
        .args(["replay"])
        .arg(&finding_dir)
        .arg("--harness")
        .arg(&target)
        .output()
        .expect("run bhf replay with the secret present");
    assert!(
        replay_ok.status.success(),
        "replay with the secret must reproduce: {}\n{}",
        String::from_utf8_lossy(&replay_ok.stdout),
        String::from_utf8_lossy(&replay_ok.stderr)
    );
    assert!(
        String::from_utf8_lossy(&replay_ok.stdout).contains("MATCH"),
        "replay did not report MATCH: {}",
        String::from_utf8_lossy(&replay_ok.stdout)
    );

    // 3) Without the secret in the environment, replay cannot recover it from the
    //    stored finding — proving the value is not persisted. It must FAIL loudly,
    //    not silently reproduce (which would mean the value had been stored).
    let replay_missing = bhf()
        .env_remove("BHF_SECRET_API")
        .args(["replay"])
        .arg(&finding_dir)
        .arg("--harness")
        .arg(&target)
        .output()
        .expect("run bhf replay without the secret");
    assert!(
        !replay_missing.status.success(),
        "replay without the secret must fail, not silently reproduce: {}\n{}",
        String::from_utf8_lossy(&replay_missing.stdout),
        String::from_utf8_lossy(&replay_missing.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&replay_missing.stdout).contains("MATCH"),
        "replay without the secret must not MATCH: {}",
        String::from_utf8_lossy(&replay_missing.stdout)
    );
}
