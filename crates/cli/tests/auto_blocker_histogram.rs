// SPDX-License-Identifier: Apache-2.0

//! A sweep must report WHY the targets it could not fuzz were blocked, per
//! language and ordered by how many targets share each cause. Totals alone
//! ("60 unsupported_params") name no lever; the grouped cause does.

use std::fs;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn tmpdir(prefix: &str) -> TestDir {
    TestDir::new(&format!("blockers-{prefix}"))
}

#[test]
fn a_blocked_target_is_reported_with_its_cause_and_language() {
    if !support::libfuzzer_toolchain_available("blockers") {
        eprintln!("skipping: clang+libfuzzer unavailable");
        return;
    }

    let root = tmpdir("root");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    // `struct opaque_thing` is declared but never defined, so the generated
    // harness has no way to produce a value for the parameter. The function
    // itself compiles fine — a pointer to an incomplete type is legal C — so
    // this is a harness-generation blocker, not a broken fixture.
    fs::write(
        src.join("opaque.c"),
        "struct opaque_thing;\n\
         int process_thing(struct opaque_thing *t) { return t ? 1 : 0; }\n",
    )
    .unwrap();
    let work = root.join("work");

    let output = support::bhf_cargo_command()
        .current_dir(&root)
        .args([
            "auto",
            "--work-dir",
            work.to_str().unwrap(),
            "--per-target-time",
            "0",
            src.to_str().unwrap(),
        ])
        .output()
        .expect("run bhf auto");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    let blockers_path = work.join("auto").join("blockers.json");
    assert!(
        blockers_path.is_file(),
        "a sweep with a blocked target must write {}; stderr=\n{stderr}",
        blockers_path.display()
    );

    let rows: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&blockers_path).unwrap())
            .expect("blockers.json is valid JSON");
    let rows = rows.as_array().expect("blockers.json is an array");
    assert!(
        !rows.is_empty(),
        "the blocked target must appear as a row; stderr=\n{stderr}"
    );

    let row = &rows[0];
    assert_eq!(
        row["language"], "c",
        "the row must name the language it belongs to: {row}"
    );
    assert!(
        row["count"].as_u64().is_some_and(|count| count >= 1),
        "every row carries the number of targets sharing the cause: {row}"
    );
    assert!(
        row["detail"]
            .as_str()
            .is_some_and(|detail| !detail.trim().is_empty()),
        "a row with an empty cause names no lever: {row}"
    );
    assert!(
        row["category"]
            .as_str()
            .is_some_and(|category| category != "built_and_fuzzed"),
        "a fuzzed target is not a blocker: {row}"
    );

    assert!(
        stderr.contains("residual blockers"),
        "the histogram belongs on the console too, not only on disk; stderr=\n{stderr}"
    );
}

#[test]
fn a_sweep_with_nothing_blocked_writes_no_histogram() {
    if !support::libfuzzer_toolchain_available("blockers-clean") {
        eprintln!("skipping: clang+libfuzzer unavailable");
        return;
    }

    let root = tmpdir("clean");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("probe.c"),
        "int parse_input(const unsigned char *d, unsigned long n) { return (int)(n + (d ? 0 : 0)); }\n",
    )
    .unwrap();
    let work = root.join("work");

    // A real fuzz budget: `--per-target-time 0` leaves the target no wall clock
    // at all, so it trips the absolute per-target cap and is itself a blocker —
    // which would make this test assert the opposite of what it means to.
    let output = support::bhf_cargo_command()
        .current_dir(&root)
        .args([
            "auto",
            "--work-dir",
            work.to_str().unwrap(),
            "--per-target-time",
            "2",
            "--max-targets",
            "1",
            src.to_str().unwrap(),
        ])
        .output()
        .expect("run bhf auto");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        stderr.contains("1 built+fuzzed"),
        "fixture must actually fuzz for this test to mean anything; stderr=\n{stderr}"
    );

    // Nothing was blocked, so there is no histogram to show. An empty section
    // would be noise on every clean run.
    assert!(
        !work.join("auto").join("blockers.json").exists(),
        "a clean sweep should not leave an empty blockers.json; stderr=\n{stderr}"
    );
}

/// A TypeScript target on a host with Node.js but without esbuild is blocked
/// by a missing toolchain, and is reported as one. bhf used to fall back to
/// `npx --no-install esbuild`, which on npm 7+ looks the package up in the
/// registry and refuses to install it; the target was then filed under
/// `unsupported_params` with npm's refusal as its cause, and the next steps
/// offered `--force`, which cannot install a transpiler. bhf must never start
/// `npx` at all: a stand-in records any call.
#[cfg(unix)]
#[test]
fn a_typescript_target_without_esbuild_is_blocked_by_a_missing_toolchain() {
    use std::os::unix::fs::PermissionsExt;
    let Ok(node) = which::which("node") else {
        eprintln!("skipping: node unavailable");
        return;
    };
    let root = tmpdir("ts-no-esbuild");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("parser.ts"),
        "export function parseRecord(data: Uint8Array): number {\n  \
         return data.length > 0 ? data[0] : 0;\n}\n",
    )
    .unwrap();
    // node and a recording npx first, then every inherited dir that holds no
    // esbuild.
    let bin = root.join("bin");
    fs::create_dir_all(&bin).unwrap();
    std::os::unix::fs::symlink(&node, bin.join("node")).unwrap();
    let npx_calls = root.join("npx-calls");
    fs::write(
        bin.join("npx"),
        format!(
            "#!/bin/sh\necho \"$@\" >> '{}'\nexit 1\n",
            npx_calls.display()
        ),
    )
    .unwrap();
    fs::set_permissions(bin.join("npx"), fs::Permissions::from_mode(0o755)).unwrap();
    let inherited = std::env::var_os("PATH").unwrap_or_default();
    let path = std::env::join_paths(
        std::iter::once(bin.clone())
            .chain(std::env::split_paths(&inherited).filter(|dir| !dir.join("esbuild").exists())),
    )
    .unwrap();
    let work = root.join("work");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bhf"))
        .current_dir(&root)
        .args(["auto", "--work-dir", work.to_str().unwrap()])
        .args([
            "--languages",
            "typescript",
            "--max-targets",
            "1",
            "--jobs",
            "1",
        ])
        .args(["--per-target-time", "1", "--no-discovery-cache"])
        .arg(&src)
        .env("PATH", &path)
        .output()
        .expect("run bhf auto");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    assert!(
        !npx_calls.exists(),
        "bhf must not run npx: {:?}\n{stderr}",
        fs::read_to_string(&npx_calls).unwrap_or_default()
    );
    let run: serde_json::Value =
        serde_json::from_slice(&fs::read(work.join("auto/run.json")).unwrap()).unwrap();
    let outcome = &run["targets"][0]["outcome"];
    assert_eq!(
        outcome["outcome"], "missing_toolchain",
        "{outcome}\n{stderr}"
    );
    assert!(
        outcome["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("esbuild")),
        "the reason names the missing tool: {outcome}"
    );
    let rows: serde_json::Value =
        serde_json::from_slice(&fs::read(work.join("auto/blockers.json")).unwrap()).unwrap();
    assert_eq!(rows[0]["category"], "missing_toolchain", "{rows}");
    assert_eq!(rows[0]["language"], "typescript", "{rows}");
    assert!(
        stderr.contains("Install missing toolchains"),
        "the next steps name the install: {stderr}"
    );
    assert!(
        !stderr.contains("a parameter couldn't be driven"),
        "a missing toolchain is not an undrivable parameter: {stderr}"
    );
    let _ = fs::remove_dir_all(&root);
}
