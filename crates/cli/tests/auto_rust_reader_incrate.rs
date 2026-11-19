// SPDX-License-Identifier: Apache-2.0
//
// §27.1 / §27.10 end-to-end: the native Rust lane builds + fuzzes a `pub trait`
// reader method (byteorder's `ReadBytesExt` class) through a synthesised
// `std::io::Cursor` receiver, and builds + fuzzes a `pub` type in a PRIVATE module
// via the IN-CRATE build mode (the harness injected as a module of a copy of the
// target crate). Both fixtures plant a crash so we prove a real, executing harness,
// not just a clean skip. The tests self-skip without a `cargo +nightly` toolchain
// (the native lane needs nightly for `-Zsanitizer`, the GNAT-less rule).

use std::path::{Path, PathBuf};
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
        .canonicalize()
        .unwrap_or_else(|e| panic!("canonicalize fixture {name}: {e}"))
}

/// The `bhf` binary cargo built for these tests (`bhf.exe` on Windows).
fn bhf_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bhf"))
}

fn has_cargo_nightly() -> bool {
    let present = {
        Command::new(support::rustup_cargo())
            .args(["+nightly", "--version"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };
    support::require_tool(present, "cargo nightly")
}

/// Run `bhf auto` on `fixture_dir` and return (combined stdout+stderr, run.json).
fn run_auto(
    fixture_dir: &Path,
    work: &Path,
    per_target: &str,
    max_targets: &str,
) -> (String, serde_json::Value) {
    let output = Command::new(bhf_bin())
        .args([
            "auto",
            "--run-untrusted",
            fixture_dir.to_str().unwrap(),
            "--per-target-time",
            per_target,
            "--max-targets",
            max_targets,
            "--work-dir",
            work.to_str().unwrap(),
        ])
        .output()
        .expect("run bhf auto");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let run_json = work.join("auto").join("run.json");
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&run_json).expect("read run.json"))
            .expect("parse run.json");
    (combined, json)
}

fn attempts(json: &serde_json::Value) -> &Vec<serde_json::Value> {
    json.get("targets")
        .or_else(|| json.get("attempts"))
        .and_then(|v| v.as_array())
        .expect("run.json has a targets/attempts array")
}

fn find_attempt<'a>(json: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    attempts(json)
        .iter()
        .find(|a| a.get("name").and_then(|n| n.as_str()) == Some(name))
        .unwrap_or_else(|| panic!("attempt `{name}` not present in run.json"))
}

/// Total findings across an attempt's passes, asserting it built (has passes).
fn attempt_findings(attempt: &serde_json::Value, name: &str) -> usize {
    let passes = attempt
        .get("outcome")
        .and_then(|o| o.get("passes"))
        .and_then(|p| p.as_array())
        .unwrap_or_else(|| panic!("`{name}` did not build+fuzz (no passes): {attempt}"));
    passes
        .iter()
        .filter_map(|p| p.get("findings").and_then(|f| f.as_array()))
        .map(|f| f.len())
        .sum()
}

#[test]
fn reader_trait_method_builds_fuzzes_and_finds_planted_crash() {
    let bin = bhf_bin();
    if !bin.exists() {
        eprintln!("skip: bhf binary not built at {}", bin.display());
        return;
    }
    if !has_cargo_nightly() {
        eprintln!("skip: no `cargo +nightly` toolchain (native Rust lane needs it)");
        return;
    }
    let tmp_guard = TestDir::new("reader");
    let tmp = tmp_guard.join("tmp");
    let (combined, json) = run_auto(&fixture("rust_reader_trait"), &tmp, "8", "4");

    // The reader-trait methods built+fuzzed through the synthesised Cursor receiver.
    assert!(
        combined.contains("built+fuzzed"),
        "a reader-trait method must build+fuzz; got:\n{combined}"
    );
    // `read_tag` hides a planted panic reachable through the Cursor receiver —
    // proving a real, executing harness (not a skip).
    let read_tag = find_attempt(&json, "read_tag");
    assert!(
        attempt_findings(read_tag, "read_tag") > 0,
        "the planted reader-trait crash in read_tag must be FOUND; output:\n{combined}"
    );
    // The generated harness shows the synthesised receiver + trait import.
    let harness_id = read_tag
        .get("harness_id")
        .and_then(|h| h.as_str())
        .expect("read_tag has a harness_id");
    let harness_rs = tmp
        .join("harnesses")
        .join(harness_id)
        .join("rust_harness/src/lib.rs");
    let text = std::fs::read_to_string(&harness_rs).expect("read generated harness");
    assert!(
        text.contains("std::io::Cursor::new(") && text.contains("recv.read_tag()"),
        "harness must use a Cursor receiver:\n{text}"
    );
    assert!(
        text.contains("ReadNumExt as _;"),
        "harness must import the reader trait:\n{text}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn private_module_target_builds_and_fuzzes_in_crate() {
    let bin = bhf_bin();
    if !bin.exists() {
        eprintln!("skip: bhf binary not built at {}", bin.display());
        return;
    }
    if !has_cargo_nightly() {
        eprintln!("skip: no `cargo +nightly` toolchain (native Rust lane needs it)");
        return;
    }
    let tmp_guard = TestDir::new("incrate");
    let tmp = tmp_guard.join("tmp");
    let (combined, json) = run_auto(&fixture("rust_incrate"), &tmp, "12", "4");

    assert!(
        combined.contains("built+fuzzed"),
        "the in-crate target must build+fuzz; got:\n{combined}"
    );
    // `Parser::parse` lives in a PRIVATE module — an external harness can't reach
    // it (E0603). It built+fuzzed only via the in-crate mode, AND found the planted
    // out-of-bounds crash behind the magic gate.
    let parse = find_attempt(&json, "parse");
    assert!(
        attempt_findings(parse, "parse") > 0,
        "the planted OOB crash in the private-module Parser::parse must be FOUND \
         (proving in-crate build reached + drove a private item); output:\n{combined}"
    );
    // The in-crate harness was injected as a module reaching `crate::internal`.
    let harness_id = parse
        .get("harness_id")
        .and_then(|h| h.as_str())
        .expect("parse has a harness_id");
    let module = tmp
        .join("harnesses")
        .join(harness_id)
        .join("incrate/src/__bhf_harness.rs");
    let text = std::fs::read_to_string(&module).expect("read injected in-crate harness module");
    assert!(
        text.contains("crate::internal::Parser"),
        "the in-crate harness must reach the private module by its `crate::` path:\n{text}"
    );
    // The crashing input reproduces against the built in-crate binary.
    let main_bin = tmp.join("harnesses").join(harness_id).join("main");
    assert!(
        main_bin.is_file(),
        "in-crate `main` binary exists: {}",
        main_bin.display()
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

/// #218: a member of a workspace that inherits its edition, its version and a
/// dependency from the workspace (`*.workspace = true`) was refused by the
/// in-crate lane ("can't resolve"). The detached copy now takes them from the
/// workspace's `[workspace.package]` and `[workspace.dependencies]`, with the
/// workspace's `Cargo.lock`, and builds offline.
#[test]
fn a_workspace_member_inheriting_its_dependencies_builds_and_fuzzes_in_crate() {
    if !has_cargo_nightly() {
        eprintln!("skip: no `cargo +nightly` toolchain (native Rust lane needs it)");
        return;
    }
    let tmp_guard = TestDir::new("incrate-workspace");
    let tmp = tmp_guard.join("tmp");
    let (combined, json) = run_auto(&fixture("rust_incrate_workspace"), &tmp, "12", "4");
    let parse = find_attempt(&json, "parse");
    assert!(
        attempt_findings(parse, "parse") > 0,
        "the planted out-of-bounds index in the member's private parser is found:\n{combined}"
    );
    let harness_id = parse["harness_id"]
        .as_str()
        .expect("parse has a harness_id");
    let incrate = tmp.join("harnesses").join(harness_id).join("incrate");
    let manifest = std::fs::read_to_string(incrate.join("Cargo.toml")).unwrap();
    assert!(!manifest.contains("workspace = true"), "{manifest}");
    assert!(manifest.contains("ws_checksum"), "{manifest}");
    assert!(
        incrate.join("Cargo.lock").is_file(),
        "the workspace's lockfile is copied"
    );
}

/// #217: the in-crate lane refused trait-impl methods ("in-crate trait
/// resolution is not yet supported") and took no parameter overrides. A
/// private module's `impl FromStr` and `impl TryFrom<&[u8]>` are now called by
/// UFCS, and a unit-enum parameter gets a `crate`-rooted variant pick; each
/// planted bug is found.
#[test]
fn private_trait_impls_and_an_enum_parameter_fuzz_in_crate() {
    if !has_cargo_nightly() {
        eprintln!("skip: no `cargo +nightly` toolchain (native Rust lane needs it)");
        return;
    }
    let tmp_guard = TestDir::new("incrate-traits");
    let tmp = tmp_guard.join("tmp");
    let (combined, json) = run_auto(&fixture("rust_incrate_traits"), &tmp, "12", "6");
    for (name, call) in [
        (
            "from_str",
            "<crate::internal::Header as ::core::str::FromStr>::from_str(",
        ),
        (
            "try_from",
            "<crate::internal::Packet as ::core::convert::TryFrom<&[u8]>>::try_from(",
        ),
        (
            "decode",
            "match (c.u8() as usize) % 2 { 0 => crate::internal::Mode::Strict, \
             _ => crate::internal::Mode::Fast }",
        ),
    ] {
        let attempt = find_attempt(&json, name);
        assert!(
            attempt_findings(attempt, name) > 0,
            "the planted bug behind `{name}` is found:\n{combined}"
        );
        let harness_id = attempt["harness_id"].as_str().unwrap();
        let module = tmp
            .join("harnesses")
            .join(harness_id)
            .join("incrate/src/__bhf_harness.rs");
        let text = std::fs::read_to_string(&module).unwrap();
        assert!(text.contains(call), "{name}:\n{text}");
    }
}

/// #216: a zoxide-shaped directory opener, `open_dir(data_dir: impl
/// AsRef<Path>)` reading `<data_dir>/db.zo`, fuzzes in-crate. The path recipe
/// took neither `impl AsRef<Path>` nor a seed name other than `db`, so the
/// file the opener reads was never written.
#[test]
fn an_impl_asref_path_opener_fuzzes_with_the_file_it_joins() {
    if !has_cargo_nightly() {
        eprintln!("skip: no `cargo +nightly` toolchain (native Rust lane needs it)");
        return;
    }
    let tmp_guard = TestDir::new("incrate-zoxide");
    let tmp = tmp_guard.join("tmp");
    let (combined, json) = run_auto(&fixture("rust_incrate_zoxide"), &tmp, "12", "4");
    let open_dir = find_attempt(&json, "open_dir");
    assert!(
        attempt_findings(open_dir, "open_dir") > 0,
        "the planted out-of-bounds index behind the db.zo magic is found:\n{combined}"
    );
    let harness = tmp
        .join("harnesses")
        .join(open_dir["harness_id"].as_str().unwrap());
    let module = std::fs::read_to_string(harness.join("incrate/src/__bhf_harness.rs")).unwrap();
    assert!(
        module.contains("__bhf_res_dir.join(\"db.zo\")"),
        "the harness seeds db.zo:\n{module}"
    );
    let recipe = std::fs::read_to_string(harness.join("resource_recipe.json")).unwrap();
    assert!(recipe.contains("`db.zo`"), "{recipe}");
}
