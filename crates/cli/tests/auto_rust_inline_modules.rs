// SPDX-License-Identifier: Apache-2.0

//! Rust functions inside inline modules (`mod codec { ... }`) are called by
//! their full path: a public or nested one builds against the crate, and one
//! behind a private module builds in-crate (`crate::hidden::checksum`), with
//! the in-crate lane's flag or without it.

use std::path::Path;
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

const LIB_RS: &str = r#"pub mod codec {
    pub fn decode_record(data: &[u8]) -> usize {
        if data.len() > 3 && data[0] == b'W' {
            return data[3] as usize;
        }
        data.len()
    }

    pub mod inner {
        pub fn parse_frame(data: &[u8]) -> usize {
            if data.len() > 2 && data[0] == b'F' {
                return data[2] as usize;
            }
            data.len()
        }
    }
}

mod hidden {
    pub fn checksum(data: &[u8]) -> u32 {
        data.iter().map(|byte| *byte as u32).sum()
    }
}

pub fn digest(data: &[u8]) -> u32 {
    hidden::checksum(data)
}
"#;

fn cargo_available() -> bool {
    let present = {
        Command::new(support::rustup_cargo())
            .args(["+nightly", "--version"])
            .output()
            .is_ok_and(|output| output.status.success())
    };
    support::require_tool(present, "cargo")
}

fn crate_in(dir: &Path) -> std::path::PathBuf {
    let root = dir.join("widget");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"widget\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n",
    )
    .unwrap();
    std::fs::write(root.join("src/lib.rs"), LIB_RS).unwrap();
    root
}

fn run_auto(root: &Path, work: &Path, incrate_private: bool) -> (String, serde_json::Value) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bhf"));
    command
        .args(["auto", "--run-untrusted"])
        .arg(root)
        .args(["--per-target-time", "3", "--jobs", "1", "--work-dir"])
        .arg(work)
        .env("RAYON_NUM_THREADS", "1");
    if incrate_private {
        command.env("BHF_RUST_INCRATE_PRIVATE", "1");
    } else {
        command.env_remove("BHF_RUST_INCRATE_PRIVATE");
    }
    let output = command.output().expect("run bhf auto");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let run: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work.join("auto/run.json"))
            .unwrap_or_else(|e| panic!("run.json: {e}\n{text}")),
    )
    .unwrap();
    (text, run)
}

fn attempt<'a>(run: &'a serde_json::Value, name: &str) -> Option<&'a serde_json::Value> {
    run.get("targets")
        .or_else(|| run.get("attempts"))
        .and_then(|value| value.as_array())
        .expect("run.json lists its targets")
        .iter()
        .find(|attempt| attempt["name"].as_str() == Some(name))
}

/// The target built and was fuzzed (its passes ran), not `failed_build`.
fn assert_built(run: &serde_json::Value, name: &str, text: &str) {
    let found = attempt(run, name).unwrap_or_else(|| panic!("{name} not attempted: {text}"));
    assert!(
        found["outcome"]["passes"]
            .as_array()
            .is_some_and(|passes| !passes.is_empty()),
        "{name} did not build and fuzz: {found}\n{text}"
    );
}

#[test]
fn public_and_nested_inline_module_functions_build_by_their_full_path() {
    if !cargo_available() {
        eprintln!("skipping: cargo +nightly not installed");
        return;
    }
    let dir = TestDir::new("rust-inline-mods");
    let root = crate_in(&dir);
    let (text, run) = run_auto(&root, &dir.join("work"), false);
    assert_built(&run, "decode_record", &text);
    assert_built(&run, "parse_frame", &text);
    assert!(!text.contains("E0425"), "{text}");
    // Behind a private module: built in-crate by its `crate::` path.
    assert_built(&run, "checksum", &text);
}

#[test]
fn a_private_inline_module_function_builds_in_the_in_crate_lane() {
    if !cargo_available() {
        eprintln!("skipping: cargo +nightly not installed");
        return;
    }
    let dir = TestDir::new("rust-inline-private");
    let root = crate_in(&dir);
    let (text, run) = run_auto(&root, &dir.join("work"), true);
    assert_built(&run, "checksum", &text);
    assert!(!text.contains("E0425"), "{text}");
}

/// A private function behind a crate feature: the in-crate lane builds the
/// copied crate with the feature its `#[cfg]` needs, as the dependency lane
/// enables it (#215). Without it the function did not exist in the build
/// (E0425) and the target was a `failed_build`.
#[test]
fn a_feature_gated_private_function_builds_with_its_feature() {
    if !cargo_available() {
        eprintln!("skipping: cargo +nightly not installed");
        return;
    }
    let dir = TestDir::new("rust-gated-private");
    let root = dir.join("framed");
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"framed\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
         [features]\nframes = []\n\n[lib]\npath = \"src/lib.rs\"\n",
    )
    .unwrap();
    std::fs::write(
        root.join("src/lib.rs"),
        r#"mod hidden {
    #[cfg(feature = "frames")]
    pub fn frame_len(data: &[u8]) -> usize {
        if data.len() > 2 && data[0] == b'F' {
            return data[2] as usize;
        }
        data.len()
    }
}

#[cfg(feature = "frames")]
pub fn total(data: &[u8]) -> usize {
    hidden::frame_len(data)
}
"#,
    )
    .unwrap();
    let (text, run) = run_auto(&root, &dir.join("work"), false);
    assert_built(&run, "frame_len", &text);
    assert!(!text.contains("E0425"), "{text}");
}
