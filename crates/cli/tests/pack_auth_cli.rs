// SPDX-License-Identifier: Apache-2.0

use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(args)
        .output()
        .unwrap()
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

#[test]
fn cli_keygen_sign_verify_install_and_reject_downgrade() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("payload");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("rules.json"), b"rules-v1").unwrap();
    let private = tmp.path().join("private.der");
    let public = tmp.path().join("public.hex");
    let manifest = tmp.path().join("pack.json");
    let policy = tmp.path().join("policy.json");
    let verified = tmp.path().join("verified.json");
    let installed = tmp.path().join("installed");
    let private_str = private.to_str().unwrap();
    let public_str = public.to_str().unwrap();
    let manifest_str = manifest.to_str().unwrap();
    let root_str = root.to_str().unwrap();
    let policy_str = policy.to_str().unwrap();
    let verified_str = verified.to_str().unwrap();
    let installed_str = installed.to_str().unwrap();

    let output = run(&[
        "pack",
        "keygen",
        "--private-key",
        private_str,
        "--public-key",
        public_str,
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let public_hex = fs::read_to_string(&public).unwrap();
    assert_eq!(public_hex.trim().len(), 64);
    assert!(!String::from_utf8_lossy(&output.stdout).contains(private_str));
    assert!(!run(&[
        "pack",
        "keygen",
        "--private-key",
        private_str,
        "--public-key",
        public_str
    ])
    .status
    .success());

    let output = run(&[
        "pack",
        "create",
        "--root",
        root_str,
        "--pack-id",
        "publisher-pack",
        "--version",
        "1",
        "--item",
        "rules:rules.json",
        "--license",
        "Apache-2.0",
        "--signing-key",
        private_str,
        "--key-id",
        "publisher-v1",
        "--out",
        manifest_str,
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        read_json(&manifest)["signature"]["algorithm"],
        "ed25519-json-v1"
    );
    fs::write(
        &policy,
        serde_json::to_vec(&json!({"update_packs": {
            "require_signature": true,
            "trusted_public_keys": {"publisher-v1": public_hex.trim()},
            "revoked_keys": []
        }}))
        .unwrap(),
    )
    .unwrap();
    let output = run(&[
        "pack",
        "verify",
        manifest_str,
        "--root",
        root_str,
        "--policy",
        policy_str,
        "--out",
        verified_str,
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(read_json(&verified)["signature"]["authenticated"], true);
    let output = run(&[
        "pack",
        "install",
        manifest_str,
        "--root",
        root_str,
        "--policy",
        policy_str,
        "--install-dir",
        installed_str,
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        read_json(&installed.join("publisher-pack/install.json"))["publisher_authentication"]
            ["key_id"],
        "publisher-v1"
    );

    let original = read_json(&manifest);
    let mut tampered = original.clone();
    tampered["items"][0]["license"] = json!("changed");
    fs::write(&manifest, serde_json::to_vec(&tampered).unwrap()).unwrap();
    assert!(!run(&[
        "pack",
        "verify",
        manifest_str,
        "--root",
        root_str,
        "--policy",
        policy_str
    ])
    .status
    .success());
    fs::write(&manifest, serde_json::to_vec(&original).unwrap()).unwrap();
    fs::write(
        &policy,
        serde_json::to_vec(&json!({"update_packs": {
            "require_signature": true,
            "trusted_public_keys": {"publisher-v1": public_hex.trim()},
            "revoked_keys": ["publisher-v1"]
        }}))
        .unwrap(),
    )
    .unwrap();
    assert!(!run(&[
        "pack",
        "install",
        manifest_str,
        "--root",
        root_str,
        "--policy",
        policy_str,
        "--install-dir",
        tmp.path().join("revoked").to_str().unwrap()
    ])
    .status
    .success());
    assert!(!tmp.path().join("revoked").exists());
}
