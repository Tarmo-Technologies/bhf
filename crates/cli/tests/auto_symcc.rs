// SPDX-License-Identifier: Apache-2.0

//! `bhf auto --symcc`: the SymCC lane of a C/C++ harness (#324) and the
//! solver loop that runs a plateaued pass's corpus entries through it
//! (#331). These need SymCC's `symcc` (C) and `sym++` (C++), which
//! `scripts/ci/install-symcc.sh` builds; `BHF_REQUIRE_TOOLS=1` makes a
//! missing one a failure. The strict-permissive profile's refusal needs only
//! clang and make.

use std::path::{Path, PathBuf};
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn on_path(bin: &str) -> bool {
    let present = std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(bin).is_file()))
        .unwrap_or(false);
    support::require_tool(present, bin)
}

fn symcc_installed() -> bool {
    on_path("symcc") && on_path("sym++") && on_path("make")
}

/// A record whose tag, the four bytes after the first four, passes the
/// check only when `tag * 0x9E3779B1 + 0x7F4A7C15 == 0x2545F491` (mod 2^32):
/// the input holds the tag, never the value it is compared against. The
/// passing record then overflows a four-byte copy.
const GATE: &str = "#include <stddef.h>
#include <stdint.h>
#include <string.h>

int parse_record(const uint8_t *data, size_t size) {
    uint32_t tag;
    if (size < 8) {
        return 0;
    }
    memcpy(&tag, data + 4, sizeof tag);
    if (tag * 0x9E3779B1u + 0x7F4A7C15u == 0x2545F491u) {
        char copy[4];
        memcpy(copy, data, size);
        return copy[3];
    }
    return 0;
}
";

fn passes_the_gate(input: &[u8]) -> bool {
    input.len() >= 8
        && u32::from_le_bytes(input[4..8].try_into().unwrap())
            .wrapping_mul(0x9E37_79B1)
            .wrapping_add(0x7F4A_7C15)
            == 0x2545_F491
}

/// `bhf auto <src> --symcc` with `env`, returning the run's one target from
/// run.json, its stderr and the target's harness dir.
fn auto_symcc(
    root: &TestDir,
    src: &Path,
    env: &[(&str, &str)],
) -> (serde_json::Value, String, PathBuf) {
    auto(
        &root.join("work"),
        src,
        &["--per-target-time", "2", "--symcc"],
        env,
    )
}

/// `bhf auto <src>` into `work` with `args` and `env`, as [`auto_symcc`].
fn auto(
    work: &Path,
    src: &Path,
    args: &[&str],
    env: &[(&str, &str)],
) -> (serde_json::Value, String, PathBuf) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bhf"));
    cmd.arg("auto")
        .arg(src)
        .arg("--work-dir")
        .arg(work)
        .args(["--jobs", "1"])
        .args(args)
        .arg("--no-discovery-cache")
        .env_remove("BHF_PROFILE")
        .env_remove("BHF_SYMCC");
    for (key, value) in env {
        cmd.env(key, value);
    }
    let output = cmd.output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{stderr}");
    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
    let target = run["targets"][0].clone();
    let harness = work
        .join("harnesses")
        .join(target["harness_id"].as_str().unwrap());
    (target, stderr, harness)
}

/// Run `main_symcc` once on `input` as the solver loop does, returning the
/// inputs SymCC wrote.
fn solve(harness: &Path, root: &TestDir, input: &[u8]) -> Vec<Vec<u8>> {
    let file = root.join("input.bin");
    std::fs::write(&file, input).unwrap();
    let out = root.join("symcc-out");
    std::fs::create_dir_all(&out).unwrap();
    let run = Command::new(harness.join("main_symcc"))
        .arg(&file)
        .env("SYMCC_INPUT_FILE", &file)
        .env("SYMCC_OUTPUT_DIR", &out)
        .output()
        .unwrap();
    assert!(run.status.success(), "{run:?}");
    std::fs::read_dir(&out)
        .unwrap()
        .flatten()
        .map(|entry| std::fs::read(entry.path()).unwrap())
        .collect()
}

#[test]
fn the_symcc_lane_of_a_c_harness_builds_and_generates_an_input() {
    if !symcc_installed() {
        eprintln!("skipping: needs SymCC's symcc and sym++, and make");
        return;
    }
    let root = TestDir::new("symcc-c");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("gate.c"), GATE).unwrap();
    let (target, stderr, harness) = auto_symcc(&root, &src, &[]);
    assert_eq!(
        target["lanes"]["symcc"]["built"], true,
        "{target:#}\n{stderr}"
    );
    assert!(
        stderr.contains("SymCC lane on (license profile `external-tools`)"),
        "{stderr}"
    );
    let solved = solve(&harness, &root, b"AAAAAAAA");
    assert!(
        solved.iter().any(|input| passes_the_gate(input)),
        "SymCC wrote no input past the gate: {solved:?}"
    );
}

#[test]
fn the_symcc_lane_of_a_cpp_harness_builds_and_generates_an_input() {
    if !symcc_installed() {
        eprintln!("skipping: needs SymCC's symcc and sym++, and make");
        return;
    }
    let root = TestDir::new("symcc-cpp");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("gate.cpp"), GATE).unwrap();
    let (target, stderr, harness) = auto_symcc(&root, &src, &[]);
    assert_eq!(
        target["lanes"]["symcc"]["built"], true,
        "{target:#}\n{stderr}"
    );
    let solved = solve(&harness, &root, b"AAAAAAAA");
    assert!(
        solved.iter().any(|input| passes_the_gate(input)),
        "SymCC wrote no input past the gate: {solved:?}"
    );
}

/// A C++ target with a compile-database row: the row's own object is
/// compiled for the lane too, by sym++ told which C++ library to take.
#[test]
fn the_symcc_lane_of_a_cpp_harness_with_a_compile_database_builds() {
    if !symcc_installed() {
        eprintln!("skipping: needs SymCC's symcc and sym++, and make");
        return;
    }
    let root = TestDir::new("symcc-cpp-db");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    let gate = src.join("gate.cpp");
    std::fs::write(&gate, GATE).unwrap();
    let dir = src.display().to_string();
    let file = gate.display().to_string();
    std::fs::write(
        src.join("compile_commands.json"),
        serde_json::to_vec_pretty(&serde_json::json!([{
            "directory": dir,
            "file": file,
            "arguments": ["clang++", "-DWIDGET=1", "-std=c++17", "-c", file],
        }]))
        .unwrap(),
    )
    .unwrap();
    let (target, stderr, harness) = auto_symcc(&root, &src, &[]);
    assert!(
        harness.join("build_context_objects.mk").is_file(),
        "the compile database was not used: {target:#}\n{stderr}"
    );
    assert_eq!(
        target["lanes"]["symcc"]["built"], true,
        "{target:#}\n{stderr}"
    );
    let solved = solve(&harness, &root, b"AAAAAAAA");
    assert!(
        solved.iter().any(|input| passes_the_gate(input)),
        "SymCC wrote no input past the gate: {solved:?}"
    );
}

/// A C target that builds only at an older C dialect (implicit `int`, which
/// clang rejects from C99 on): the lane builds at the dialect `main` did.
#[test]
fn the_symcc_lane_of_a_legacy_c_harness_builds_at_its_dialect() {
    if !symcc_installed() {
        eprintln!("skipping: needs SymCC's symcc and sym++, and make");
        return;
    }
    let root = TestDir::new("symcc-legacy");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("old.c"),
        "#include <stddef.h>\n#include <stdint.h>\n\n\
         static total;\n\n\
         int parse_record(const uint8_t *data, size_t size) {\n\
         \x20   register count = (int)size;\n\
         \x20   if (size < 1) {\n\
         \x20       return 0;\n\
         \x20   }\n\
         \x20   total += count;\n\
         \x20   return data[0] == 'W' ? count : 0;\n\
         }\n",
    )
    .unwrap();
    let (target, stderr, harness) = auto_symcc(&root, &src, &[]);
    let recipe: serde_json::Value =
        serde_json::from_slice(&std::fs::read(harness.join("coverage-build-recipe.json")).unwrap())
            .unwrap();
    assert!(
        recipe["standard"]
            .as_str()
            .is_some_and(|standard| standard.contains("89") || standard.contains("90")),
        "main built without a dialect rung: {recipe:#}"
    );
    assert_eq!(
        target["lanes"]["symcc"]["built"], true,
        "{target:#}\n{stderr}"
    );
    assert!(harness.join("main_symcc").is_file());
}

/// The strict-permissive profile never runs SymCC: `--symcc` says why, and
/// no harness gets the lane.
#[test]
fn the_strict_permissive_profile_refuses_the_symcc_lane() {
    if !on_path("clang") || !on_path("make") {
        eprintln!("skipping: needs clang and make");
        return;
    }
    let root = TestDir::new("symcc-strict");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("gate.c"), GATE).unwrap();
    let (target, stderr, harness) =
        auto_symcc(&root, &src, &[("BHF_PROFILE", "strict-permissive")]);
    assert!(
        stderr.contains(
            "--symcc: the `strict-permissive` license profile does not allow SymCC \
             (GPL-3.0) to run"
        ),
        "{stderr}"
    );
    assert!(target["lanes"].get("symcc").is_none(), "{target:#}");
    assert!(harness.join("main").is_file(), "{target:#}");
    assert!(!harness.join("main_symcc").exists());
}

/// The testcases of the findings `bhf auto` wrote into `work`.
fn finding_testcases(work: &Path) -> Vec<Vec<u8>> {
    std::fs::read_dir(work.join("results/findings"))
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|entry| std::fs::read(entry.path().join("testcase.bin")).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// #331: the modular-arithmetic gate is passed only with the solver loop.
/// `bhf auto` alone finds nothing behind it in the budget; with `--symcc`, a
/// pass whose corpus stops growing runs its newest entries through SymCC,
/// and the input SymCC solves reaches the overflow behind the gate.
#[test]
fn only_the_solver_loop_passes_a_modular_arithmetic_gate() {
    if !symcc_installed() {
        eprintln!("skipping: needs SymCC's symcc and sym++, and make");
        return;
    }
    let root = TestDir::new("symcc-loop");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("gate.c"), GATE).unwrap();
    let budget = ["--per-target-time", "9"];

    let plain = root.join("plain");
    let (target, stderr, _) = auto(&plain, &src, &budget, &[]);
    assert!(target["lanes"].get("symcc").is_none(), "{target:#}");
    let found = finding_testcases(&plain);
    assert!(
        found.is_empty(),
        "the builtin engine alone passed the gate: {found:?}\n{stderr}"
    );

    let solved = root.join("symcc");
    let mut args = budget.to_vec();
    args.push("--symcc");
    let (target, stderr, _) = auto(&solved, &src, &args, &[("BHF_SYMCC_PLATEAU_MS", "500")]);
    assert_eq!(
        target["lanes"]["symcc"]["built"], true,
        "{target:#}\n{stderr}"
    );
    assert!(stderr.contains("SymCC ran"), "{stderr}");
    let found = finding_testcases(&solved);
    assert!(
        found.iter().any(|input| passes_the_gate(input)),
        "no finding past the gate: {found:?}\n{stderr}"
    );
    let imports = std::fs::read_to_string(solved.join("symcc-import.log")).unwrap();
    assert!(!imports.trim().is_empty());
}

/// #332 with #331: on two workers per target the solver loop runs in each
/// worker, and what it gave is the parent's once the workers' trees are
/// gone: `<work>/symcc-import.log` lists the inputs, and the pass's `symcc`
/// block names the target's own `main_symcc`.
#[test]
fn the_solver_loop_on_two_workers_logs_into_the_target_work_dir() {
    if !symcc_installed() {
        eprintln!("skipping: needs SymCC's symcc and sym++, and make");
        return;
    }
    let root = TestDir::new("symcc-workers");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("gate.c"), GATE).unwrap();
    let work = root.join("work");
    let (target, stderr, harness) = auto(
        &work,
        &src,
        &[
            "--per-target-time",
            "9",
            "--symcc",
            "--workers-per-target",
            "2",
        ],
        &[("BHF_SYMCC_PLATEAU_MS", "500")],
    );
    assert_eq!(
        target["lanes"]["symcc"]["built"], true,
        "{target:#}\n{stderr}"
    );
    assert!(stderr.contains("SymCC ran"), "{stderr}");
    let imports = std::fs::read_to_string(work.join("symcc-import.log"))
        .unwrap_or_else(|error| panic!("no symcc-import.log: {error}\n{stderr}"));
    assert!(!imports.trim().is_empty(), "{stderr}");
    let id = target["harness_id"].as_str().unwrap();
    let pass: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work.join(format!("fuzz_runs/{id}-latest.json"))).unwrap(),
    )
    .unwrap();
    assert_eq!(pass["workers"]["completed"], 2, "{pass:#}");
    let binary = PathBuf::from(pass["symcc"]["binary"].as_str().unwrap());
    assert!(binary.is_file(), "{}: {pass:#}", binary.display());
    assert_eq!(binary.parent(), Some(harness.as_path()), "{pass:#}");
    assert!(
        !stderr.contains("left in worker dirs"),
        "the merge names worker dirs it removes: {stderr}"
    );
}
