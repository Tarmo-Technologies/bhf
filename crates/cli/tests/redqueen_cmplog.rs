// SPDX-License-Identifier: Apache-2.0

//! Cold-solve gate for the input-to-state (RedQueen) cmplog mutator (#400).
//!
//! Runs the built-in engine cold (no trigger seed) on the `redqueen_int` fixture,
//! whose only crash is gated behind an INTEGER comparison against a per-input,
//! len-derived magic. That gate is reachable only by capturing the comparison
//! operand via SanitizerCoverage trace-cmp and splicing it into the input at the
//! offset it was compared — #400's contribution. Every pre-existing path (the
//! mem/str-only LD_PRELOAD shim cmplog, the static dictionary, uniform fill,
//! arithmetic, blind mutation, repetition/structured mutators) cannot reach it.
//!
//! The test is the discriminator the issue asked for: with per-input capture ON
//! the bug is solved cold; with it disabled (`BHF_DISABLE_REDQUEEN=1`, the
//! dictionary-only path) it is NOT — within the same budget. `#[ignore]` because
//! it is slow and needs clang+make; run it on demand / nightly.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

mod support;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/engine_parity/redqueen_int/redqueen_int.c")
}

fn tmpdir(tag: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let p = std::env::temp_dir().join(format!("bhf-rq-cold-{tag}-{n}"));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Count findings that are real crashes (sanitizer/unhandled faults), excluding
/// oracle hits — only a genuine memory-safety crash means the gate was cleared.
fn count_crash_findings(work: &std::path::Path) -> usize {
    let findings_dir = work.join("bhf_work/findings");
    let Ok(entries) = std::fs::read_dir(&findings_dir) else {
        return 0;
    };
    let mut crashes = 0;
    for entry in entries.flatten() {
        let finding = entry.path().join("finding.json");
        let Ok(bytes) = std::fs::read(&finding) else {
            continue;
        };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        // Oracle hits (insecure-temp-file, TOCTOU, …) are not the gate crash; the
        // planted OOB surfaces as a sanitizer/"unhandled" classification.
        if value["classification"].as_str() != Some("oracle_hit") {
            crashes += 1;
        }
    }
    crashes
}

/// Run `auto` on the fixture cold and return the number of crash findings.
/// `redqueen` selects per-input cmplog capture (true) or the dictionary-only
/// baseline (false, via `BHF_DISABLE_REDQUEEN=1`).
fn run(tag: &str, redqueen: bool, budget_secs: &str) -> usize {
    let work = tmpdir(tag);
    std::fs::copy(fixture(), work.join("redqueen_int.c")).unwrap();
    let mut cmd = support::bhf_cargo_command();
    cmd.current_dir(&work)
        .args(["auto", ".", "--per-target-time", budget_secs]);
    if !redqueen {
        cmd.env("BHF_DISABLE_REDQUEEN", "1");
    }
    let status = cmd.status().expect("run bhf auto");
    assert!(
        status.success() || status.code() == Some(1),
        "bhf auto crashed unexpectedly ({:?})",
        status.code()
    );
    count_crash_findings(&work)
}

/// Count crash findings under a raw `bhf fuzz` work dir (`<work>/findings/*`),
/// excluding oracle hits — only a genuine memory-safety crash clears the gate.
fn count_fuzz_crash_findings(work: &std::path::Path) -> usize {
    let findings_dir = work.join("findings");
    let Ok(entries) = std::fs::read_dir(&findings_dir) else {
        return 0;
    };
    let mut crashes = 0;
    for entry in entries.flatten() {
        let finding = entry.path().join("finding.json");
        let Ok(bytes) = std::fs::read(&finding) else {
            continue;
        };
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        if value["classification"].as_str() != Some("oracle_hit") {
            crashes += 1;
        }
    }
    crashes
}

/// Run the raw `bhf fuzz` path (generate-harness -> build -> fuzz) cold on the
/// `redqueen_int` fixture and return the number of crash findings. This is the
/// exact entry point the engine trade study drives — distinct from the `auto`
/// orchestration exercised above. `redqueen` selects the default in-campaign
/// cmplog channels vs. the `BHF_DISABLE_REDQUEEN=1` kill-switch.
fn run_fuzz(tag: &str, redqueen: bool, budget_secs: &str) -> usize {
    let work = tmpdir(tag);
    std::fs::copy(fixture(), work.join("redqueen_int.c")).unwrap();
    let seed = work.join("seed-zero-8");
    std::fs::write(&seed, [0u8; 8]).unwrap();
    let id = "H-RQ-FUZZ";
    let generated = work.join("generated_harnesses");

    let gen_ok = support::bhf_cargo_command()
        .current_dir(&work)
        .args([
            "generate-harness",
            "redqueen_int.c",
            "--target",
            "redqueen_int",
            "--output",
        ])
        .arg(&generated)
        .args(["--id", id])
        .status()
        .expect("run bhf generate-harness")
        .success();
    assert!(gen_ok, "generate-harness failed");

    let build_ok = support::bhf_cargo_command()
        .current_dir(&work)
        .args(["build", "."])
        .args(["--harness", id])
        .status()
        .expect("run bhf build")
        .success();
    assert!(build_ok, "build failed");

    let mut cmd = support::bhf_cargo_command();
    cmd.current_dir(&work)
        .args(["fuzz", "."])
        .args(["--harness", id])
        .args(["--engine", "builtin"])
        .args(["--time", &format!("{budget_secs}s")])
        .arg("--seed-file")
        .arg(&seed)
        .args(["--rng-seed", "1000"])
        .args(["--max-len", "64"])
        .args(["--len-control", "0"])
        .args(["--timeout", "1s"])
        .args(["--sandbox", "none"]);
    if !redqueen {
        cmd.env("BHF_DISABLE_REDQUEEN", "1");
    }
    let status = cmd.status().expect("run bhf fuzz");
    assert!(
        status.success() || status.code() == Some(1),
        "bhf fuzz crashed unexpectedly ({:?})",
        status.code()
    );
    count_fuzz_crash_findings(&work)
}

/// Best-in-class parity: the DEFAULT `bhf fuzz` run must solve the integer gate
/// cold, matching `bhf auto` (and AFL++ cmplog / libFuzzer value-profile). The
/// raw engine formerly ran blind here because it never armed the in-campaign
/// `BHF_CMP_SHM` / `BHF_VP_SHM` channels the `auto` path wires — the regression
/// this locks in.
#[test]
#[ignore = "slow cold-solve discriminator; needs clang+make — run on demand / nightly"]
fn redqueen_int_gate_solved_by_default_via_bhf_fuzz() {
    if !support::libfuzzer_toolchain_available("redqueen-fuzz") {
        eprintln!("skipping: clang+make toolchain unavailable");
        return;
    }
    let budget = std::env::var("BHF_RQ_SECS").unwrap_or_else(|_| "25".to_owned());

    // Kill-switch baseline: with per-input capture disabled the raw engine must
    // NOT solve the integer gate in the budget (proves the solve is the cmplog
    // channel, not incidental mutation).
    let baseline = run_fuzz("fuzz-off", false, &budget);
    assert_eq!(
        baseline, 0,
        "BHF_DISABLE_REDQUEEN=1 path unexpectedly solved the integer gate \
         ({baseline} crashes) — discriminator no longer isolates in-campaign cmplog"
    );

    // Default path must solve it cold. Retry once to absorb a transient blip.
    let mut solved = run_fuzz("fuzz-on", true, &budget);
    if solved == 0 {
        solved = run_fuzz("fuzz-on-retry", true, &budget);
    }
    assert!(
        solved > 0,
        "default `bhf fuzz` failed to solve the integer gate cold within {budget}s — \
         in-campaign RedQueen/value-profile not armed by default"
    );
}

#[test]
#[ignore = "slow cold-solve discriminator; needs clang+make — run on demand / nightly"]
fn redqueen_int_gate_solved_only_with_per_input_cmplog() {
    if !support::libfuzzer_toolchain_available("redqueen") {
        eprintln!("skipping: clang+make toolchain unavailable");
        return;
    }
    let budget = std::env::var("BHF_RQ_SECS").unwrap_or_else(|_| "15".to_owned());

    // Dictionary-only baseline must NOT solve the integer gate in the budget.
    let baseline = run("off", false, &budget);
    assert_eq!(
        baseline, 0,
        "dictionary-only path unexpectedly solved the integer gate ({baseline} crashes) — \
         the discriminator no longer isolates per-input cmplog"
    );

    // Per-input cmplog must solve it cold. Retry once to absorb a transient
    // build/run blip (the existing parity sweep does the same).
    let mut solved = run("on", true, &budget);
    if solved == 0 {
        solved = run("on-retry", true, &budget);
    }
    assert!(
        solved > 0,
        "per-input cmplog (#400) failed to solve the integer gate cold within {budget}s — \
         RedQueen capture/splice regression"
    );
}
