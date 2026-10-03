// SPDX-License-Identifier: Apache-2.0

//! Crate-level integration tests: schema parse/gate and end-to-end resolution
//! against a tempdir fixture. These exercise the public API exactly as the CLI
//! (a separate crate) will.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use project_profile::{
    load, resolve, validate, AssetKind, EnvSource, LoweredLaunch, ProjectError, ResolveOptions,
    RunContext,
};
use tempfile::tempdir;

const CURRENT_BHF: &str = "0.2.34";

struct MapEnv(HashMap<String, String>);
impl EnvSource for MapEnv {
    fn get(&self, key: &str) -> Option<String> {
        self.0.get(key).cloned()
    }
}
fn env(pairs: &[(&str, &str)]) -> MapEnv {
    MapEnv(
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    )
}

const TWO_TARGET: &str = r#"
schema = "bhf.project.v1"

[project]
id = "demo"
version = "1.2.3"
requires-bhf = ">=0.2.0"

[[target]]
id = "alpha"
engine = "builtin"
binary = "prebuilt/harness"
seeds = ["corpus/alpha"]
dictionaries = ["dict/base.dict", "dict/overlay.dict"]
grammar = "grammar/a.json"

[target.env]
PROFILE = "release"
TOKEN = "${secret:API_TOKEN}"

[[target]]
id = "beta"
engine = "binary"
binary = "prebuilt/harness"
input-mode = "file"
seeds = ["corpus/beta"]
"#;

#[test]
fn parses_minimal_valid_manifest() {
    let m = load(TWO_TARGET).unwrap();
    assert_eq!(m.schema, "bhf.project.v1");
    assert_eq!(m.project.id, "demo");
    assert_eq!(m.targets.len(), 2);
    assert_eq!(m.targets[0].id, "alpha");
    assert_eq!(m.targets[1].id, "beta");
}

#[test]
fn rejects_unknown_key() {
    // `seedz` is a genuine typo — deny_unknown_fields must reject it at parse.
    let text = r#"
schema = "bhf.project.v1"
[project]
id = "demo"
version = "1.0.0"
[[target]]
id = "a"
engine = "builtin"
binary = "h"
seedz = ["x"]
"#;
    let err = load(text).unwrap_err();
    assert!(matches!(err, ProjectError::Parse(_)), "{err:?}");
}

#[test]
fn composition_fields_validate_and_lower() {
    // runner (#47), target-args, runtime-oracles (#59), and a postcondition (#55)
    // are the composition knobs a profile sets. They parse, validate, and lower
    // into a usable binary launch (no longer rejected).
    let text = r#"
schema = "bhf.project.v1"
[project]
id = "demo"
version = "1.0.0"
[[target]]
id = "a"
engine = "binary"
binary = "h"
input-mode = "file"
runner = "wine"
runner-args = ["--mode", "fuzz"]
target-args = ["@@"]
runtime-oracles = "auto"
[target.postcondition]
setup-command = "./prepare-case"
oracle-command = "./check-postcondition"
reset-command = "./reset-case"
"#;
    let m = load(text).expect("manifest with composition fields parses");
    validate(&m, CURRENT_BHF).expect("composition fields validate");

    let (launch, _warnings) = project_profile::lower_target(&m.targets[0]).unwrap();
    match launch {
        LoweredLaunch::Binary(b) => {
            assert_eq!(b.runner.as_deref(), Some("wine"));
            assert_eq!(b.runner_args, vec!["--mode".to_owned(), "fuzz".to_owned()]);
            assert_eq!(b.target_args, vec!["@@".to_owned()]);
            assert_eq!(b.runtime_oracles, project_profile::RuntimeOraclesMode::Auto);
            assert_eq!(b.oracle_command.as_deref(), Some("./check-postcondition"));
            assert_eq!(b.engine, project_profile::BinaryEngine::Builtin);
        }
        LoweredLaunch::Native(_) => panic!("expected binary launch, got native"),
    }
}

#[test]
fn postcondition_without_oracle_is_rejected_by_validate() {
    // Well-formedness: a [target.postcondition] with no oracle-command asserts
    // nothing and is rejected with a target-attributed diagnostic.
    let text = r#"
schema = "bhf.project.v1"
[project]
id = "demo"
version = "1.0.0"
[[target]]
id = "a"
engine = "binary"
binary = "h"
[target.postcondition]
setup-command = "./prepare-case"
"#;
    let m = load(text).expect("parses");
    let err = validate(&m, CURRENT_BHF).unwrap_err();
    assert!(
        matches!(
            err,
            ProjectError::MissingField {
                field: "postcondition.oracle-command",
                ..
            }
        ),
        "{err:?}"
    );
}

#[test]
fn invalid_runtime_oracles_mode_is_rejected_by_validate() {
    let text = r#"
schema = "bhf.project.v1"
[project]
id = "demo"
version = "1.0.0"
[[target]]
id = "a"
engine = "builtin"
binary = "h"
runtime-oracles = "asan"
"#;
    let m = load(text).expect("parses");
    let err = validate(&m, CURRENT_BHF).unwrap_err();
    assert!(
        matches!(
            err,
            ProjectError::InvalidFieldValue {
                field: "runtime-oracles",
                ..
            }
        ),
        "{err:?}"
    );
}

#[test]
fn rejects_wrong_schema_string() {
    let text = r#"
schema = "bhf.project.v2"
[project]
id = "demo"
version = "1.0.0"
"#;
    let err = load(text).unwrap_err();
    assert!(
        matches!(err, ProjectError::UnsupportedSchema { ref found, .. } if found == "bhf.project.v2"),
        "{err:?}"
    );
}

fn write(root: &Path, rel: &str, body: &[u8]) {
    let p = root.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, body).unwrap();
}

fn stage_fixture(root: &Path) {
    write(root, "manifest.toml", TWO_TARGET.as_bytes());
    write(root, "prebuilt/harness", b"#!/bin/sh\nexit 0\n");
    write(root, "corpus/alpha/seed0", b"alpha-seed");
    write(root, "corpus/beta/seed0", b"beta-seed");
    write(root, "dict/base.dict", b"\"alpha\"\n\"beta\"\n");
    write(root, "dict/overlay.dict", b"\"beta\"\n\"gamma\"\n");
    write(root, "grammar/a.json", b"{\"root\":\"S\"}");
}

#[test]
fn resolve_native_target_produces_full_provenance() {
    let dir = tempdir().unwrap();
    stage_fixture(dir.path());
    let m = load(TWO_TARGET).unwrap();
    let e = env(&[("BHF_SECRET_API_TOKEN", "s3cr3t-value")]);
    let ctx = RunContext {
        bhf_version: CURRENT_BHF,
        toolchain: Some("x86_64-unknown-linux-gnu"),
    };

    let resolved = resolve(
        &m,
        TWO_TARGET,
        dir.path(),
        "alpha",
        &ResolveOptions::default(),
        &ctx,
        &e,
    )
    .unwrap();

    // Native launch.
    assert!(matches!(resolved.launch, LoweredLaunch::Native(_)));

    // Manifest hash matches the verbatim bytes.
    assert_eq!(
        resolved.provenance.manifest_sha256,
        project_profile::sha256_bytes(TWO_TARGET.as_bytes())
    );

    // Layered dictionary merged in order with dedupe.
    assert_eq!(
        resolved.merged_dictionary.tokens,
        vec![b"alpha".to_vec(), b"beta".to_vec(), b"gamma".to_vec()]
    );

    // Provenance records every asset class with a 64-hex sha256.
    let kinds: Vec<AssetKind> = resolved.provenance.assets.iter().map(|a| a.kind).collect();
    assert!(kinds.contains(&AssetKind::Harness));
    assert!(kinds.contains(&AssetKind::Seed));
    assert_eq!(
        kinds
            .iter()
            .filter(|k| **k == AssetKind::Dictionary)
            .count(),
        2
    );
    assert!(kinds.contains(&AssetKind::MergedDictionary));
    assert!(kinds.contains(&AssetKind::Grammar));
    for a in &resolved.provenance.assets {
        if a.kind != AssetKind::MergedDictionary {
            // Declared (manifest-relative) path is recorded, not an abs path.
            // The message stays static: asset paths are manifest-derived and
            // CodeQL conservatively taints them, so never format one into a sink.
            assert!(
                !a.path.starts_with('/'),
                "a provenance asset path must be manifest-relative, not absolute"
            );
        }
        assert_eq!(a.sha256.len(), 64);
    }

    // Env: the real secret value is available for the launch...
    let token = resolved
        .resolved_env
        .iter()
        .find(|(k, _)| k == "TOKEN")
        .unwrap();
    assert_eq!(token.1, "s3cr3t-value");
    let profile = resolved
        .resolved_env
        .iter()
        .find(|(k, _)| k == "PROFILE")
        .unwrap();
    assert_eq!(profile.1, "release");

    // ...but provenance only keeps the handle, and the secret never serializes.
    assert_eq!(
        resolved.provenance.redacted_env.get("TOKEN").unwrap(),
        "${secret:API_TOKEN}"
    );
    let json = serde_json::to_string(&resolved.provenance).unwrap();
    assert!(!json.contains("s3cr3t-value"));
    assert!(json.contains("${secret:API_TOKEN}"));
    assert_eq!(resolved.provenance.bhf_version, "0.2.34");

    // The redaction map names ONLY the handle-backed key (so the binary lane
    // records the handle, not the value), and never the public literal.
    assert_eq!(
        resolved.env_redaction.get("TOKEN").map(String::as_str),
        Some("${secret:API_TOKEN}")
    );
    // Static message: the redaction map pairs env names with `${secret:...}` /
    // `${env:...}` handles, which CodeQL taints — never format it into a sink.
    assert!(
        !resolved.env_redaction.contains_key("PROFILE"),
        "a public literal must not appear in the redaction map"
    );
    assert!(resolved.env_redaction.values().all(|v| v != "s3cr3t-value"));
}

#[test]
fn reresolve_env_handle_recovers_secret_without_storing_it() {
    use project_profile::reresolve_env_handle;

    // Replay recovers a secret value from the environment via the recorded handle
    // — the same BHF_SECRET_<NAME> mechanism `resolve` uses — so a finding never
    // needs to store it. A literal passes through unchanged.
    let e = env(&[
        ("BHF_SECRET_API_TOKEN", "s3cr3t-value"),
        ("BUILD_PROFILE", "release"),
    ]);
    assert_eq!(
        reresolve_env_handle("${secret:API_TOKEN}", &e).unwrap(),
        "s3cr3t-value"
    );
    assert_eq!(
        reresolve_env_handle("${env:BUILD_PROFILE}", &e).unwrap(),
        "release"
    );
    assert_eq!(
        reresolve_env_handle("plain-literal", &e).unwrap(),
        "plain-literal"
    );

    // A missing secret is a hard error at replay, never a silent empty value.
    assert!(reresolve_env_handle("${secret:MISSING}", &env(&[])).is_err());
}

#[test]
fn resolve_binary_target_hashes_binary_and_seeds() {
    let dir = tempdir().unwrap();
    stage_fixture(dir.path());
    let m = load(TWO_TARGET).unwrap();
    let ctx = RunContext {
        bhf_version: CURRENT_BHF,
        toolchain: None,
    };
    let resolved = resolve(
        &m,
        TWO_TARGET,
        dir.path(),
        "beta",
        &ResolveOptions::default(),
        &ctx,
        &env(&[]),
    )
    .unwrap();
    match &resolved.launch {
        LoweredLaunch::Binary(b) => {
            assert_eq!(b.input_mode, project_profile::BinaryInput::File);
        }
        LoweredLaunch::Native(_) => panic!("expected binary launch, got native"),
    }
    assert_eq!(resolved.provenance.engine, "binary");
    assert_eq!(resolved.provenance.input_mode, "file");
    assert!(resolved
        .provenance
        .assets
        .iter()
        .any(|a| a.kind == AssetKind::Binary));
    // No dictionaries/grammar on the binary lane.
    assert!(!resolved
        .provenance
        .assets
        .iter()
        .any(|a| a.kind == AssetKind::Grammar));
}

#[test]
fn resolve_missing_asset_errors() {
    let dir = tempdir().unwrap();
    // Stage everything EXCEPT the grammar the alpha target references.
    write(dir.path(), "prebuilt/harness", b"bin");
    write(dir.path(), "corpus/alpha/seed0", b"x");
    write(dir.path(), "dict/base.dict", b"\"a\"\n");
    write(dir.path(), "dict/overlay.dict", b"\"b\"\n");
    let m = load(TWO_TARGET).unwrap();
    let ctx = RunContext {
        bhf_version: CURRENT_BHF,
        toolchain: None,
    };
    let err = resolve(
        &m,
        TWO_TARGET,
        dir.path(),
        "alpha",
        &ResolveOptions::default(),
        &ctx,
        &env(&[("BHF_SECRET_API_TOKEN", "x")]),
    )
    .unwrap_err();
    assert!(matches!(err, ProjectError::MissingAsset(_)), "{err:?}");
}

#[test]
fn resolve_unknown_target_errors() {
    let dir = tempdir().unwrap();
    stage_fixture(dir.path());
    let m = load(TWO_TARGET).unwrap();
    let ctx = RunContext {
        bhf_version: CURRENT_BHF,
        toolchain: None,
    };
    let err = resolve(
        &m,
        TWO_TARGET,
        dir.path(),
        "does-not-exist",
        &ResolveOptions::default(),
        &ctx,
        &env(&[]),
    )
    .unwrap_err();
    assert!(matches!(err, ProjectError::UnknownTarget(_)), "{err:?}");
}

// ── [[extension]] convergence (#57) ─────────────────────────────────────────

const WITH_EXTENSION: &str = r#"
schema = "bhf.project.v1"

[project]
id = "demo"
version = "1.0.0"

[[target]]
id = "alpha"
engine = "builtin"
binary = "prebuilt/harness"
seeds = ["corpus/alpha"]

[[extension]]
id = "path-oracle"
executable = "ext/path-oracle"
args = ["--serve"]
required-capabilities = ["oracle.evaluate"]
optional-capabilities = ["codec.repair", "scenario.next"]
env-passthrough = ["ACME_MODE"]

[extension.limits]
call-timeout-ms = 5000
max-frame-bytes = 1048576
max-restarts = 1
"#;

fn stage_extension_fixture(root: &Path) {
    write(root, "prebuilt/harness", b"#!/bin/sh\nexit 0\n");
    write(root, "corpus/alpha/seed0", b"alpha-seed");
    write(root, "ext/path-oracle", b"#!/bin/sh\nexit 0\n");
}

#[test]
fn extension_section_parses_and_resolves_with_provenance() {
    let dir = tempdir().unwrap();
    stage_extension_fixture(dir.path());
    let m = load(WITH_EXTENSION).unwrap();
    assert_eq!(m.extensions.len(), 1);
    assert_eq!(
        m.extensions[0].executable.to_str().unwrap(),
        "ext/path-oracle"
    );

    validate(&m, CURRENT_BHF).unwrap();

    let ctx = RunContext {
        bhf_version: CURRENT_BHF,
        toolchain: None,
    };
    let resolved = resolve(
        &m,
        WITH_EXTENSION,
        dir.path(),
        "alpha",
        &ResolveOptions::default(),
        &ctx,
        &env(&[]),
    )
    .unwrap();

    // The resolved extension carries the fields the CLI needs to load it.
    let ext = resolved.resolved_extension.expect("resolved extension");
    assert_eq!(ext.id.as_deref(), Some("path-oracle"));
    assert!(ext.resolved_executable.ends_with("ext/path-oracle"));
    assert_eq!(ext.required_capabilities, vec!["oracle.evaluate"]);
    assert_eq!(
        ext.optional_capabilities,
        vec!["codec.repair".to_string(), "scenario.next".to_string()]
    );
    assert_eq!(ext.env_passthrough, vec!["ACME_MODE"]);
    assert_eq!(ext.limits.unwrap().call_timeout_ms, Some(5000));

    // Provenance hashes the extension executable so a run records exactly which
    // extension it loaded.
    let hashed = resolved
        .provenance
        .assets
        .iter()
        .find(|a| matches!(a.kind, AssetKind::Extension))
        .expect("extension asset hashed");
    assert_eq!(hashed.path, "ext/path-oracle");
    assert_eq!(hashed.sha256.len(), 64);
}

#[test]
fn extension_missing_executable_asset_errors_on_resolve() {
    let dir = tempdir().unwrap();
    write(dir.path(), "prebuilt/harness", b"#!/bin/sh\nexit 0\n");
    write(dir.path(), "corpus/alpha/seed0", b"seed");
    // Note: ext/path-oracle is intentionally NOT staged.
    let m = load(WITH_EXTENSION).unwrap();
    let ctx = RunContext {
        bhf_version: CURRENT_BHF,
        toolchain: None,
    };
    let err = resolve(
        &m,
        WITH_EXTENSION,
        dir.path(),
        "alpha",
        &ResolveOptions::default(),
        &ctx,
        &env(&[]),
    )
    .unwrap_err();
    assert!(matches!(err, ProjectError::MissingAsset(_)), "{err:?}");
}

#[test]
fn extension_unknown_key_is_rejected() {
    let text = WITH_EXTENSION.replace("args = [\"--serve\"]", "surprise = true");
    let err = load(&text).unwrap_err();
    assert!(matches!(err, ProjectError::Parse(_)), "{err:?}");
}

#[test]
fn extension_bad_wire_format_is_rejected_by_validate() {
    let text = r#"
schema = "bhf.project.v1"

[project]
id = "demo"
version = "1.0.0"

[[target]]
id = "alpha"
engine = "builtin"
binary = "prebuilt/harness"

[[extension]]
executable = "ext/path-oracle"
format = "cbor"
"#;
    let m = load(text).unwrap();
    let err = validate(&m, CURRENT_BHF).unwrap_err();
    assert!(
        matches!(err, ProjectError::InvalidExtension { .. }),
        "{err:?}"
    );
}
