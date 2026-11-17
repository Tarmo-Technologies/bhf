// SPDX-License-Identifier: Apache-2.0
//
// A static method of a trait impl whose trait is not the crate's own is
// harnessed (#338). Such a method is callable only by UFCS, and the lane
// resolved the trait only among the crate's own traits and `FromStr` /
// `TryFrom`, so `impl wiredep::Decode for Record { fn decode(&[u8]) }` and
// `impl From<&[u8]> for Packet` were refused. The trait is now resolved
// through the impl file's `use` declarations or its full spelling, and the
// external harness crate depends on the trait's crate with the target's
// spec; `From<&[u8]>` joins the standard conversions. A decoder on a generic
// type and a `Default::default` are refused, each saying why.

use std::path::{Path, PathBuf};
use std::process::Command;

mod support;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/rust_ext_trait/app")
        .canonicalize()
        .expect("canonicalize rust_ext_trait fixture")
}

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn has_cargo_nightly() -> bool {
    let present = Command::new("cargo")
        .args(["+nightly", "--version"])
        .output()
        .is_ok_and(|o| o.status.success());
    support::require_tool(present, "cargo nightly")
}

#[test]
#[cfg_attr(
    windows,
    ignore = "the Rust lane builds its harness as a Unix static archive (lib*.a, linked with \
              libpthread and libdl) and runs under WSL on Windows; see docs/site/windows.md"
)]
fn static_methods_of_dependency_and_std_trait_impls_build_and_their_bugs_are_found() {
    if !has_cargo_nightly() {
        eprintln!("skip: no `cargo +nightly` toolchain (native Rust lane needs it)");
        return;
    }
    let root = TestDir::new("rust-ext-trait");
    let work = root.join("work");
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args([
            "auto",
            "--run-untrusted",
            "--per-target-time",
            "10",
            "--jobs",
            "1",
        ])
        .args([
            "--target", "decode", "--target", "from", "--target", "default",
        ])
        .arg(fixture())
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run bhf auto");
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
    let targets = run["targets"].as_array().unwrap();
    let mut fuzzed = Vec::new();
    let mut refused = Vec::new();
    for target in targets {
        let name = target["name"].as_str().unwrap_or_default();
        if target["outcome"]["outcome"] == "unsupported_params" {
            refused.push(
                target["outcome"]["reason"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            );
            continue;
        }
        assert!(
            target["outcome"]["passes"]
                .as_array()
                .is_some_and(|passes| !passes.is_empty()),
            "{name} did not build and fuzz: {target:#}\n{log}"
        );
        let findings: usize = target["outcome"]["passes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pass| pass["findings"].as_array().map_or(0, Vec::len))
            .sum();
        assert!(
            findings > 0,
            "the planted bug behind {name} is found:\n{log}"
        );
        fuzzed.push(name.to_owned());
    }
    fuzzed.sort();
    assert_eq!(fuzzed, ["decode", "decode", "from"], "{log}");
    refused.sort();
    assert_eq!(refused.len(), 2, "{refused:#?}\n{log}");
    assert!(
        refused[0].contains("'decode' is a static method of a trait impl on a generic type"),
        "{refused:#?}"
    );
    assert!(
        refused[1].contains("'default' is a trait-impl method that takes no input"),
        "{refused:#?}"
    );

    // The harness names the dependency's trait, so its crate depends on it.
    let decode = targets
        .iter()
        .find(|target| target["name"] == "decode")
        .unwrap();
    let harness = work
        .join("harnesses")
        .join(decode["harness_id"].as_str().unwrap())
        .join("rust_harness");
    let manifest = std::fs::read_to_string(harness.join("Cargo.toml")).unwrap();
    assert!(manifest.contains("wiredep = { path = "), "{manifest}");
    let source = std::fs::read_to_string(harness.join("src/lib.rs")).unwrap();
    assert!(
        source.contains("as ::wiredep::Decode>::decode("),
        "{source}"
    );
}
