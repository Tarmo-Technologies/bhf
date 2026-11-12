// SPDX-License-Identifier: Apache-2.0

//! The Rust lane.
//!
//! A Rust harness is a generated `staticlib` crate (`rust_harness/`) that
//! path-depends on the target crate and on bhf's dependency-free decode
//! runtime (`rust_runtime`), built by `cargo +nightly` with SanitizerCoverage
//! and ASan, and linked by clang with bhf's C driver (`main.c`) into a native
//! `main` that speaks the framed protocol (one input file as `argv[1]`
//! outside the fuzz loop). A capsule ships the harness crate, the driver, the
//! runtime crate, the scanned tree and, when the lock file names registry or
//! git packages, a `vendor/` dir made by `cargo vendor --offline` from the
//! local cargo cache. A package the local cache does not hold is refused: it
//! cannot be vendored without the network. The crash oracle is the panic (or
//! the ASan report) the harness prints.

use super::relocate::{self, Contents, Mount, Relocator};
use super::{
    refuse, report_signature, CapsulePlan, GeneratedFile, HarnessContext, Lane, ReplayOutput, Tool,
    Toolchain, CARTOGRAPHY_GAP,
};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

pub(crate) struct RustLane;

pub(crate) static RUST_LANE: RustLane = RustLane;

/// The cargo variable is `BHF_CARGO`, not `CARGO`: cargo sets `CARGO` to its
/// own toolchain binary for everything it runs, which is not the rustup proxy
/// that `+nightly` needs.
const RUST_TOOLS: &[Toolchain] = &[
    Toolchain::new(
        "BHF_CARGO",
        "cargo",
        "builds the harness crate (with the rustup nightly toolchain: `cargo +nightly`)",
    ),
    Toolchain::new("CC", "clang", "links the harness with bhf's driver"),
];

/// The flags bhf builds the harness crate with (`rust_build::sancov_rustflags`).
const RUSTFLAGS: &str = "-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 \
                         -Cllvm-args=-sanitizer-coverage-trace-pc-guard \
                         -Cllvm-args=-sanitizer-coverage-trace-compares -Zsanitizer=address";

impl Lane for RustLane {
    fn tag(&self) -> &'static str {
        "rust"
    }

    fn name(&self) -> &'static str {
        "Rust"
    }

    fn tools(&self) -> &'static [Toolchain] {
        RUST_TOOLS
    }

    fn recognizes(&self, harness_dir: &Path) -> bool {
        harness_dir.join("rust_harness/Cargo.toml").is_file()
            && harness_dir.join("main.c").is_file()
    }

    fn harness_problem(&self, harness: &HarnessContext) -> Option<String> {
        let dir = &harness.harness_dir;
        if !dir.join("main.c").is_file() {
            return Some("it has no main.c (bhf's driver)".to_owned());
        }
        let Ok(manifest) = std::fs::read_to_string(dir.join("rust_harness/Cargo.toml")) else {
            return Some("it has no rust_harness/Cargo.toml".to_owned());
        };
        if path_dependencies(&manifest).is_empty() {
            return Some("its harness crate path-depends on no target crate".to_owned());
        }
        None
    }

    fn plan_capsule(&self, harness: &HarnessContext) -> anyhow::Result<CapsulePlan> {
        let dir = &harness.harness_dir;
        let manifest = std::fs::read_to_string(dir.join("rust_harness/Cargo.toml"))?;
        let mut runtime = None;
        let mut targets = Vec::new();
        for path in path_dependencies(&manifest) {
            let is_runtime = std::fs::read_to_string(path.join("Cargo.toml"))
                .is_ok_and(|text| text.contains("name = \"rust_runtime\""));
            if is_runtime {
                runtime = Some(path);
            } else {
                targets.push(path);
            }
        }
        let tree = super::recorded_source_root(&harness.work_dir)
            .filter(|root| targets.iter().all(|crate_dir| crate_dir.starts_with(root)))
            .or_else(|| targets.first().cloned())
            .ok_or_else(|| refuse("its harness crate path-depends on no target crate"))?;
        if let Some(outside) = targets
            .iter()
            .find(|crate_dir| !crate_dir.starts_with(&tree))
        {
            return Err(refuse(format!(
                "its harness crate path-depends on {}, which is outside the scanned tree {}",
                outside.display(),
                tree.display()
            )));
        }
        let vendor = vendored_packages(dir)?;
        let mut relocator = Relocator {
            mounts: vec![
                Mount::rendered(
                    dir,
                    "harness",
                    Contents::Tree {
                        skip: not_harness_crate,
                    },
                ),
                Mount::in_place(
                    &tree,
                    "sources",
                    Contents::Tree {
                        skip: relocate::is_tree_noise,
                    },
                ),
            ],
            tools: Vec::new(),
            protected: vec![harness.work_dir.clone(), tree.clone()],
            exclude: vec![harness.work_dir.clone()],
        };
        if let Some(runtime) = &runtime {
            relocator.mounts.push(Mount::in_place(
                runtime,
                "runtime/rust_runtime",
                Contents::Tree {
                    skip: relocate::is_tree_noise,
                },
            ));
        }
        let mut relocated = relocator.relocate()?;
        if let Some((scratch, config)) = &vendor {
            // Vendored files ship byte for byte: cargo checks their checksums.
            for rel in walk_all(&scratch.path().join("vendor")) {
                let from = scratch.path().join("vendor").join(&rel);
                relocated.generated.push(GeneratedFile {
                    to: format!("vendor/{}", rel.to_string_lossy().replace('\\', "/")),
                    bytes: std::fs::read(&from)?,
                    executable: false,
                });
            }
            relocated.generated.push(GeneratedFile {
                to: ".cargo/config.toml".to_owned(),
                bytes: config.clone().into_bytes(),
                executable: false,
            });
        }
        let mut script = String::from(
            "#!/bin/sh\n\
             # Rebuild this bhf PoC offline. Needs cargo with the rustup nightly toolchain\n\
             # (or $BHF_CARGO; $BHF_RUST_NIGHTLY names another nightly), clang (or $CC)\n\
             # and a shell.\n\
             set -e\n\
             cd \"$(dirname \"$0\")\"\n",
        );
        script.push_str(&relocate::resolve_tool("TOOL_CARGO", &RUST_TOOLS[0]));
        script.push_str(&relocate::resolve_tool("TOOL_CC", &RUST_TOOLS[1]));
        script.push_str(&relocator.render_script(&relocated));
        script.push_str(&format!(
            "CHANNEL=\"+${{BHF_RUST_NIGHTLY:-nightly}}\"\n\
             HOST=$(\"$TOOL_CARGO\" \"$CHANNEL\" -vV | sed -n 's/^host: //p')\n\
             RUSTFLAGS=\"{RUSTFLAGS}\" \"$TOOL_CARGO\" \"$CHANNEL\" build --offline \\\n\
             \x20 --manifest-path build/harness/rust_harness/Cargo.toml \\\n\
             \x20 --target-dir build/cargo --target \"$HOST\"\n\
             LIB=$(ls build/cargo/\"$HOST\"/debug/libbhf_rust_harness*.a | head -n 1)\n\
             \"$TOOL_CC\" -O1 -g -fsanitize=address -fsanitize-coverage=trace-pc-guard,trace-cmp \\\n\
             \x20 -o poc build/harness/main.c \"$LIB\" -lpthread -ldl -lm -lrt\n"
        ));
        let requires: Vec<_> = RUST_TOOLS.iter().map(Toolchain::requirement).collect();
        let mut layout = vec![
            (
                "harness/rust_harness/".to_owned(),
                "the generated harness crate (decodes the input, calls the target)".to_owned(),
            ),
            (
                "harness/main.c".to_owned(),
                "bhf's driver the crate links with".to_owned(),
            ),
            (
                "sources/".to_owned(),
                "the scanned tree holding the target crate".to_owned(),
            ),
        ];
        if runtime.is_some() {
            layout.push((
                "runtime/rust_runtime/".to_owned(),
                "bhf's decode runtime crate".to_owned(),
            ));
        }
        if vendor.is_some() {
            layout.push((
                "vendor/".to_owned(),
                "the crates.io and git packages the lock file names, vendored offline".to_owned(),
            ));
        }
        Ok(CapsulePlan {
            files: relocated.files,
            generated: relocated.generated,
            build_script: script,
            build_summary: "cargo +nightly build the harness, link ./poc (ASan)".to_owned(),
            build_facts: json!({
                "rustflags": RUSTFLAGS,
                "nightly_channel_env": "BHF_RUST_NIGHTLY",
                "vendored": vendor.is_some(),
                "relocated_files": relocated.templates,
            }),
            requires,
            layout,
            build_outputs: vec!["poc", "build"],
            warnings: relocated.warnings,
            windows: None,
        })
    }

    fn crash_signature(&self, replay: &ReplayOutput) -> Option<String> {
        report_signature(&replay.stderr, &replay.status)
    }

    fn tool_gap(&self, tool: Tool) -> Option<&'static str> {
        match tool {
            Tool::Cartography => Some(CARTOGRAPHY_GAP),
            Tool::Capsule | Tool::EnvCapsule => None,
        }
    }
}

/// What a Rust harness dir holds that is not the harness crate or the driver.
fn not_harness_crate(rel: &Path, is_dir: bool) -> bool {
    let parts: Vec<&str> = rel
        .components()
        .filter_map(|part| part.as_os_str().to_str())
        .collect();
    match parts.as_slice() {
        [name] if is_dir => *name != "rust_harness",
        [name] => *name != "main.c",
        ["rust_harness", name, ..] => matches!(*name, "target" | "target-libfuzzer"),
        _ => false,
    }
}

/// The `path = "..."` dependencies of a Cargo manifest.
pub(crate) fn path_dependencies(manifest: &str) -> Vec<PathBuf> {
    manifest
        .lines()
        .filter_map(|line| {
            let at = line.find("path = \"")? + "path = \"".len();
            let end = line[at..].find('"')?;
            let path = PathBuf::from(&line[at..at + end]);
            path.is_absolute().then_some(path)
        })
        .collect()
}

/// A scratch `vendor/` dir and the cargo config that points at it, when the
/// harness lock file names packages from crates.io or git; `None` when every
/// package is a path dependency. A refusal when the local cargo cache cannot
/// provide them.
fn vendored_packages(harness_dir: &Path) -> anyhow::Result<Option<(tempfile::TempDir, String)>> {
    let lock =
        std::fs::read_to_string(harness_dir.join("rust_harness/Cargo.lock")).unwrap_or_default();
    if !lock
        .lines()
        .any(|line| line.trim_start().starts_with("source = \""))
    {
        return Ok(None);
    }
    let scratch = tempfile::Builder::new()
        .prefix("bhf-cargo-vendor-")
        .tempdir()?;
    let mut vendor = Command::new(RUST_TOOLS[0].compiler());
    vendor
        .args(["vendor", "--offline", "--versioned-dirs", "--manifest-path"])
        .arg(harness_dir.join("rust_harness/Cargo.toml"))
        .arg(scratch.path().join("vendor"));
    let output = crate::command_output::output_with_timeout(&mut vendor, Duration::from_secs(600))
        .map_err(|error| anyhow::anyhow!("cannot run cargo vendor: {error}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let reason = stderr
            .lines()
            .map(str::trim)
            .find(|line| line.starts_with("error"))
            .or_else(|| stderr.lines().map(str::trim).find(|line| !line.is_empty()))
            .unwrap_or("no output")
            .to_owned();
        return Err(refuse(format!(
            "the harness crate needs packages that are not in the local cargo cache, so \
             they cannot be vendored for an offline rebuild: {reason}"
        )));
    }
    let printed = String::from_utf8_lossy(&output.stdout);
    let vendor_dir = scratch.path().join("vendor");
    let config = printed.replace(&vendor_dir.to_string_lossy().into_owned(), "vendor");
    Ok(Some((scratch, config)))
}

/// Every file under `root`, relative.
fn walk_all(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![PathBuf::new()];
    while let Some(rel) = stack.pop() {
        for entry in std::fs::read_dir(root.join(&rel))
            .into_iter()
            .flatten()
            .flatten()
        {
            let child = rel.join(entry.file_name());
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => stack.push(child),
                Ok(_) => out.push(child),
                Err(_) => {}
            }
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_dependencies_are_read_from_the_manifest() {
        let manifest = "[dependencies]\n\
                        widget = { path = \"/t/my src\" }\n\
                        rust_runtime = { path = \"/bhf/crates/rust_runtime\" }\n\
                        serde = \"1\"\n";
        assert_eq!(
            path_dependencies(manifest),
            vec![
                PathBuf::from("/t/my src"),
                PathBuf::from("/bhf/crates/rust_runtime")
            ]
        );
    }

    #[test]
    fn only_the_harness_crate_and_driver_ship() {
        assert!(!not_harness_crate(Path::new("main.c"), false));
        assert!(!not_harness_crate(Path::new("rust_harness"), true));
        assert!(!not_harness_crate(
            Path::new("rust_harness/src/lib.rs"),
            false
        ));
        assert!(not_harness_crate(Path::new("rust_harness/target"), true));
        assert!(not_harness_crate(Path::new("main"), false));
        assert!(not_harness_crate(Path::new("bhf_libfuzzer.c"), false));
        assert!(not_harness_crate(Path::new("repairs"), true));
    }

    /// A lock file naming a registry package the local cargo cache does not
    /// hold is refused: it cannot be vendored offline.
    #[test]
    fn a_package_missing_from_the_cargo_cache_is_refused() {
        if which::which("cargo").is_err() {
            eprintln!("skipping: cargo not installed");
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let crate_dir = temp.path().join("harness/rust_harness");
        std::fs::create_dir_all(crate_dir.join("src")).unwrap();
        std::fs::write(crate_dir.join("src/lib.rs"), "").unwrap();
        std::fs::write(
            crate_dir.join("Cargo.toml"),
            "[package]\nname = \"bhf_rust_harness\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
             [workspace]\n[dependencies]\nbhf-test-absent-crate-zz = \"=9.9.9\"\n",
        )
        .unwrap();
        std::fs::write(
            crate_dir.join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"bhf-test-absent-crate-zz\"\nversion = \"9.9.9\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
        )
        .unwrap();
        let error = vendored_packages(&temp.path().join("harness"))
            .expect_err("an uncached package is refused");
        let refusal = error
            .downcast_ref::<super::super::PlanRefusal>()
            .expect("a refusal, not a failure");
        assert!(refusal.0.contains("cannot be vendored"), "{refusal}");
    }
}
