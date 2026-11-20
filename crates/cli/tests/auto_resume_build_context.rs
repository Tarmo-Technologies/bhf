// SPDX-License-Identifier: Apache-2.0

//! #101: `--resume` reuses completed-target results only when BOTH the source
//! identity (discovery cache) AND the build context (compile databases, GPRs,
//! IDLs, harness-affecting options) are unchanged. A build-context change
//! re-attempts affected targets even when the source is unchanged; a docs change
//! does not.

use std::path::Path;
use std::process::{Command, Output};

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn run_auto(root: &Path, work: &Path, extra: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bhf"));
    command
        .arg("auto")
        .arg(root)
        .arg("--work-dir")
        .arg(work)
        .arg("--per-target-time")
        .arg("1")
        .arg("--single-pass");
    command.args(extra);
    command.output().expect("spawn bhf auto")
}

fn tmpdir(tag: &str) -> TestDir {
    TestDir::new(&format!("resume-bctx-{tag}"))
}

fn have_c_compiler() -> bool {
    let present = { which::which("clang").is_ok() || which::which("cc").is_ok() };
    support::require_tool(present, "c compiler")
}

#[test]
fn resume_reuses_on_unchanged_context_but_reattempts_on_build_context_change() {
    if !have_c_compiler() {
        eprintln!("SKIP: no C compiler on PATH");
        return;
    }
    let root = tmpdir("src");
    std::fs::write(
        root.join("lib.c"),
        "#include <stddef.h>\n#include <stdint.h>\nint decode(const uint8_t*d,size_t n){return n&&d[0]=='Z';}\n",
    )
    .unwrap();
    let work = tmpdir("work");

    // First run establishes the checkpoint + writes the build-context fingerprint.
    let first = run_auto(&root, &work, &[]);
    assert!(
        work.join("auto/build-context.fingerprint").is_file(),
        "first run must record the build-context fingerprint; stderr:\n{}",
        String::from_utf8_lossy(&first.stderr)
    );

    // A docs-only change must NOT invalidate: --resume reloads the completed target.
    std::fs::write(root.join("NOTES.md"), "docs only\n").unwrap();
    let resumed = run_auto(&root, &work, &["--resume"]);
    let resumed_err = String::from_utf8_lossy(&resumed.stderr);
    assert!(
        resumed_err.contains("reloaded") || resumed_err.contains("no completed targets"),
        "a docs-only change must allow resume, not re-attempt on a build-context change; stderr:\n{resumed_err}"
    );
    assert!(
        !resumed_err.contains("build context changed"),
        "docs change must not report a build-context change; stderr:\n{resumed_err}"
    );

    // Adding a compile database changes the build context (source is unchanged), so
    // --resume must re-attempt rather than trust the prior results.
    std::fs::write(root.join("compile_commands.json"), "[]\n").unwrap();
    let changed = run_auto(&root, &work, &["--resume"]);
    let changed_err = String::from_utf8_lossy(&changed.stderr);
    assert!(
        changed_err.contains("build context changed"),
        "adding compile_commands.json must invalidate the build context; stderr:\n{changed_err}"
    );

    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&work);
}

/// The `result.json` modification time of the harness for each target name.
fn result_times(work: &Path) -> std::collections::BTreeMap<String, std::time::SystemTime> {
    let mut times = std::collections::BTreeMap::new();
    for entry in std::fs::read_dir(work.join("harnesses")).unwrap().flatten() {
        let result = entry.path().join("result.json");
        let Ok(bytes) = std::fs::read(&result) else {
            continue;
        };
        let record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let name = record["name"].as_str().unwrap().to_owned();
        let modified = std::fs::metadata(&result).unwrap().modified().unwrap();
        times.insert(name, modified);
    }
    times
}

/// #449: `--no-discovery-cache` reads and writes no discovery cache, but a
/// resumed run still re-attempts the targets whose source file changed and
/// reloads the others, as a run with the cache does.
#[test]
fn resume_without_the_discovery_cache_reattempts_only_the_changed_file() {
    if !have_c_compiler() {
        eprintln!("SKIP: no C compiler on PATH");
        return;
    }
    let root = tmpdir("nocache-src");
    let header = "#include <stddef.h>\n#include <stdint.h>\n";
    std::fs::write(
        root.join("alpha.c"),
        format!("{header}int decode_alpha(const uint8_t*d,size_t n){{return n&&d[0]=='A';}}\n"),
    )
    .unwrap();
    std::fs::write(
        root.join("beta.c"),
        format!("{header}int decode_beta(const uint8_t*d,size_t n){{return n&&d[0]=='B';}}\n"),
    )
    .unwrap();
    let work = tmpdir("nocache-work");

    let first = run_auto(&root, &work, &["--no-discovery-cache"]);
    let first_err = String::from_utf8_lossy(&first.stderr);
    let before = result_times(&work);
    assert_eq!(
        before.keys().map(String::as_str).collect::<Vec<_>>(),
        ["decode_alpha", "decode_beta"],
        "both targets must complete; stderr:\n{first_err}"
    );
    assert!(
        !work.join("discovery-cache.json").exists(),
        "--no-discovery-cache must write no discovery cache"
    );

    // Change only alpha.c.
    std::fs::write(
        root.join("alpha.c"),
        format!("{header}int decode_alpha(const uint8_t*d,size_t n){{return n>1&&d[1]=='A';}}\n"),
    )
    .unwrap();
    let resumed = run_auto(&root, &work, &["--resume", "--no-discovery-cache"]);
    let resumed_err = String::from_utf8_lossy(&resumed.stderr);
    assert!(
        resumed_err.contains("1 source file(s) changed since the last run")
            && resumed_err.contains("reloaded 1 completed target(s); re-running 1 remaining"),
        "only the changed file's target is re-attempted; stderr:\n{resumed_err}"
    );
    let after = result_times(&work);
    assert_ne!(
        after["decode_alpha"], before["decode_alpha"],
        "the changed file's target must run again; stderr:\n{resumed_err}"
    );
    assert_eq!(
        after["decode_beta"], before["decode_beta"],
        "the unchanged file's target must be reloaded; stderr:\n{resumed_err}"
    );
    assert!(!work.join("discovery-cache.json").exists());
}
