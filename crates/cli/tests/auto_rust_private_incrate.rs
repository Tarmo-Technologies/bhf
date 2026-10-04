// SPDX-License-Identifier: Apache-2.0
//
// §27.10 / #83 end-to-end: the opt-in IN-CRATE PRIVATE harness lane reaches a
// NON-PUBLIC method (`pub(crate) Database::open_dir(dir: &Path)`) on a crate-root
// public type by injecting the harness as a module of a COPY of the target crate,
// and materializes a bounded, path-backed resource (a temp dir seeded with the fuzz
// input) to pass to the path opener. The fixture plants an out-of-bounds crash
// behind a magic gate IN THE FILE the opener reads, so we prove a real, executing
// harness that drove attacker bytes through the resource — not a clean skip.
//
// Default (flag OFF) MUST NOT discover the non-pub method at all, so the default
// Rust auto path stays byte-identical. The tests self-skip without a
// `cargo +nightly` toolchain (the native lane needs it — the GNAT-less rule).

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
        .canonicalize()
        .unwrap_or_else(|e| panic!("canonicalize fixture {name}: {e}"))
}

fn bhf_bin() -> PathBuf {
    let mut dir = std::env::current_exe().expect("test exe path");
    dir.pop(); // deps/
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join("bhf")
}

fn has_cargo_nightly() -> bool {
    Command::new("cargo")
        .args(["+nightly", "--version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run `bhf auto` on `fixture_dir`. When `incrate_private` is set, the opt-in
/// `BHF_RUST_INCRATE_PRIVATE=1` lane is enabled. Returns (combined output, run.json).
fn run_auto(
    fixture_dir: &Path,
    work: &Path,
    per_target: &str,
    max_targets: &str,
    incrate_private: bool,
) -> (String, serde_json::Value) {
    let mut cmd = Command::new(bhf_bin());
    cmd.args([
        "auto",
        fixture_dir.to_str().unwrap(),
        "--per-target-time",
        per_target,
        "--max-targets",
        max_targets,
        "--work-dir",
        work.to_str().unwrap(),
    ]);
    if incrate_private {
        cmd.env("BHF_RUST_INCRATE_PRIVATE", "1");
    } else {
        // Ensure the ambient env never leaks the flag into the default-path test.
        cmd.env_remove("BHF_RUST_INCRATE_PRIVATE");
    }
    let output = cmd.output().expect("run bhf auto");
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

fn find_attempt<'a>(json: &'a serde_json::Value, name: &str) -> Option<&'a serde_json::Value> {
    attempts(json)
        .iter()
        .find(|a| a.get("name").and_then(|n| n.as_str()) == Some(name))
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

/// Recursively hash the fixture source tree (relative path + bytes) so we can prove
/// the opt-in in-crate build left the user's checkout UNCHANGED.
fn snapshot(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    fn walk(base: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            // The fixture ships no target/ — never traverse one if a stray build left it.
            if p.is_dir() {
                if p.file_name().and_then(|n| n.to_str()) == Some("target") {
                    continue;
                }
                walk(base, &p, out);
            } else {
                let rel = p.strip_prefix(base).unwrap().to_string_lossy().into_owned();
                out.push((rel, std::fs::read(&p).unwrap_or_default()));
            }
        }
    }
    walk(dir, dir, &mut out);
    out.sort();
    out
}

#[test]
fn private_path_opener_builds_fuzzes_and_finds_planted_crash_in_crate() {
    let bin = bhf_bin();
    if !bin.exists() {
        eprintln!("skip: bhf binary not built at {}", bin.display());
        return;
    }
    if !has_cargo_nightly() {
        eprintln!("skip: no `cargo +nightly` toolchain (native Rust lane needs it)");
        return;
    }
    let fixture_dir = fixture("rust_incrate_private");
    let before = snapshot(&fixture_dir);

    let tmp = std::env::temp_dir().join(format!("bhf-incrate-private-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let (combined, json) = run_auto(&fixture_dir, &tmp, "20", "6", true);

    assert!(
        combined.contains("built+fuzzed"),
        "the in-crate private path-opener must build+fuzz; got:\n{combined}"
    );

    // `Database::open_dir` is `pub(crate)` AND takes a `&Path` — unreachable by the
    // default external lane twice over. With the opt-in flag it built+fuzzed via the
    // in-crate mode, drove a materialized temp-dir resource, and FOUND the planted
    // out-of-bounds crash behind the in-file magic gate.
    let open_dir =
        find_attempt(&json, "open_dir").expect("open_dir attempt present under the opt-in flag");
    assert!(
        attempt_findings(open_dir, "open_dir") > 0,
        "the planted OOB crash in the private-method path opener must be FOUND \
         (proving the in-crate harness drove attacker bytes through a materialized \
         path resource); output:\n{combined}"
    );

    let harness_id = open_dir
        .get("harness_id")
        .and_then(|h| h.as_str())
        .expect("open_dir has a harness_id");
    let harness_root = tmp.join("harnesses").join(harness_id);

    // The in-crate harness reaches the NON-PUBLIC method by its `crate::` path and
    // materializes + seeds a path-backed resource (not a fuzzed path).
    let module = harness_root.join("incrate/src/__bhf_harness.rs");
    let text = std::fs::read_to_string(&module).expect("read injected in-crate harness module");
    // The harness reaches the crate-root type by its `crate::` path (the receiver
    // ctor) and calls the NON-PUBLIC method on it — unreachable from an external
    // dependent crate (E0603). Together these prove the in-crate private reach.
    assert!(
        text.contains("crate::Database::new()") && text.contains("recv.open_dir("),
        "the in-crate harness must reach the crate-root type by its `crate::` path and \
         drive the non-pub method:\n{text}"
    );
    assert!(
        text.contains("std::fs::write(__bhf_res_dir.join(\"db\")")
            && text.contains("c.rest_bytes()"),
        "the harness must materialize + SEED a path-backed resource with the fuzz input:\n{text}"
    );
    assert!(
        text.contains("remove_dir_all"),
        "the resource must be RAII-cleaned:\n{text}"
    );

    // The resource assumption is recorded as a retained artifact beside the harness.
    let recipe_json = harness_root.join("resource_recipe.json");
    assert!(
        recipe_json.is_file(),
        "a retained resource-recipe artifact must be written: {}",
        recipe_json.display()
    );
    let recipe = std::fs::read_to_string(&recipe_json).unwrap();
    assert!(
        recipe.contains("bhf.resource_recipe.v1") && recipe.contains("open_dir"),
        "the recipe artifact must record the target + assumption:\n{recipe}"
    );

    // The built binary exists and the transient in-crate Cargo cache was cleaned.
    assert!(
        harness_root.join("main").is_file(),
        "in-crate `main` binary exists: {}",
        harness_root.display()
    );
    assert!(
        !harness_root.join("incrate/target").exists(),
        "in-crate Rust Cargo cache must be cleaned: {}",
        harness_root.display()
    );

    // The user's source checkout is UNCHANGED (the copy is isolated under work-dir).
    let after = snapshot(&fixture_dir);
    assert_eq!(
        before, after,
        "the opt-in in-crate build must not mutate the source checkout"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn default_path_does_not_discover_the_non_pub_method() {
    let bin = bhf_bin();
    if !bin.exists() {
        eprintln!("skip: bhf binary not built at {}", bin.display());
        return;
    }
    // This test does NOT need a toolchain — it asserts a DISCOVERY property (the
    // non-pub method is never ranked without the opt-in flag), so it runs anywhere.
    let tmp = std::env::temp_dir().join(format!("bhf-incrate-default-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let (_combined, json) = run_auto(&fixture("rust_incrate_private"), &tmp, "2", "6", false);

    assert!(
        find_attempt(&json, "open_dir").is_none(),
        "without BHF_RUST_INCRATE_PRIVATE the pub(crate) `open_dir` must NOT be \
         discovered (default Rust auto path byte-identical): run.json:\n{json}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn discovery_cache_tracks_the_incrate_private_flag_toggle() {
    // #83 item 3: the discovery-cache identity includes the opt-in flag, so a warm
    // cache on the SAME work directory does not leak the previous run's candidate
    // set across a flag toggle. Discovery-only property (checks run.json attempts),
    // so it runs without a toolchain — no `cargo +nightly` gate.
    let bin = bhf_bin();
    if !bin.exists() {
        eprintln!("skip: bhf binary not built at {}", bin.display());
        return;
    }
    let fx = fixture("rust_incrate_private");

    // off -> on, ONE work directory: the stale flag-off cache must NOT suppress the
    // private target once the flag is enabled.
    let w1 = std::env::temp_dir().join(format!("bhf-incrate-cache-onoff-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&w1);
    let (_c1, off) = run_auto(&fx, &w1, "2", "6", false);
    assert!(
        find_attempt(&off, "open_dir").is_none(),
        "flag OFF must not discover open_dir:\n{off}"
    );
    let (_c2, on) = run_auto(&fx, &w1, "2", "6", true);
    assert!(
        find_attempt(&on, "open_dir").is_some(),
        "flag ON on the SAME work dir must re-discover open_dir — the stale flag-off \
         cache must not suppress it:\n{on}"
    );
    let _ = std::fs::remove_dir_all(&w1);

    // on -> off, ONE work directory: a warm flag-on cache must NOT retain the
    // private target once the flag is disabled.
    let w2 = std::env::temp_dir().join(format!("bhf-incrate-cache-offon-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&w2);
    let (_c3, on2) = run_auto(&fx, &w2, "2", "6", true);
    assert!(
        find_attempt(&on2, "open_dir").is_some(),
        "flag ON must discover open_dir:\n{on2}"
    );
    let (_c4, off2) = run_auto(&fx, &w2, "2", "6", false);
    assert!(
        find_attempt(&off2, "open_dir").is_none(),
        "flag OFF on the SAME work dir must drop open_dir — a warm flag-on cache must \
         not retain it:\n{off2}"
    );
    let _ = std::fs::remove_dir_all(&w2);
}
