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
fn gated_field_parses_but_is_not_unknown() {
    // `runner` is a declared (gated) field: it DESERIALIZES, so the error comes
    // from validation ("requires #47"), not a serde unknown-field error.
    let text = r#"
schema = "bhf.project.v1"
[project]
id = "demo"
version = "1.0.0"
[[target]]
id = "a"
engine = "binary"
binary = "h"
runner = "wine"
"#;
    let m = load(text).expect("manifest with a gated field still parses");
    let err = validate(&m, CURRENT_BHF).unwrap_err();
    match err {
        ProjectError::GatedFeature { field, issue, .. } => {
            assert_eq!(field, "runner");
            assert_eq!(issue, "#47");
        }
        other => panic!("expected gated-feature error, got {other:?}"),
    }
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
            assert!(!a.path.starts_with('/'), "abs path leaked: {}", a.path);
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
        other => panic!("expected binary launch, got {other:?}"),
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
