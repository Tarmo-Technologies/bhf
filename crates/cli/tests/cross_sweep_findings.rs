// SPDX-License-Identifier: Apache-2.0

//! Findings of a cross sweep: harnesses built for another architecture and
//! fuzzed under its emulator. Each test drives the real binary and skips (with
//! a notice) when the cross compiler or the emulator is not installed.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bhf() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
}

fn have(program: &str) -> bool {
    which::which(program).is_ok()
}

fn cross_tools() -> bool {
    let ok = have("aarch64-linux-gnu-gcc") && have("qemu-aarch64") && have("make");
    if !ok {
        eprintln!("skip: aarch64-linux-gnu-gcc/qemu-aarch64/make unavailable");
    }
    ok
}

fn text(output: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Run an aarch64 cross sweep of `src` fuzzing up to `targets` targets.
fn cross_sweep(src: &Path, work: &Path, targets: usize) -> String {
    let targets = targets.to_string();
    let output = bhf()
        .arg("auto")
        .arg(src)
        .arg("--work-dir")
        .arg(work)
        .args([
            "--max-targets",
            &targets,
            "--jobs",
            "1",
            "--no-discovery-cache",
            "--languages",
            "c",
            "--per-target-time",
            "8",
            "--target-triple",
            "aarch64-linux-gnu",
            "--runner",
            "qemu-aarch64",
        ])
        .env_remove("CC")
        .env_remove("CXX")
        .output()
        .unwrap();
    text(&output)
}

/// Every `finding.json` under `<work>/results/findings`, with its directory.
fn findings(work: &Path) -> Vec<(PathBuf, serde_json::Value)> {
    let mut found: Vec<(PathBuf, serde_json::Value)> =
        std::fs::read_dir(work.join("results/findings"))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| {
                let bytes = std::fs::read(entry.path().join("finding.json")).ok()?;
                Some((entry.path(), serde_json::from_slice(&bytes).ok()?))
            })
            .collect();
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found
}

/// Two functions that each fault without a sanitizer report, at different
/// sites: a store through a null pointer and a load from a small address.
fn write_two_faults(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("records.c"),
        "#include <stddef.h>\n#include <stdint.h>\n\
         int copy_at(const unsigned char *data, size_t size) {\n\
             if (size > 0 && data[0] != 0x7f) {\n\
                 volatile unsigned char *out = (volatile unsigned char *)(uintptr_t)0;\n\
                 out[0] = data[0];\n\
             }\n\
             return 0;\n\
         }\n\
         int bit_index(const unsigned char *data, size_t size) {\n\
             if (size > 0 && data[0] != 0x7f) {\n\
                 const volatile int *word = (const volatile int *)(uintptr_t)8;\n\
                 return *word >> 3;\n\
             }\n\
             return 0;\n\
         }\n",
    )
    .unwrap();
}

/// A cross sweep's harnesses run without a sanitizer runtime, so their
/// crashes have no frames. Two harnesses that fault at different sites are
/// two root-cause groups, not one.
#[test]
fn frameless_crashes_of_two_cross_harnesses_are_two_root_cause_groups() {
    if !cross_tools() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    write_two_faults(&src);
    let work = tmp.path().join("work");
    let out = cross_sweep(&src, &work, 2);
    let found = findings(&work);
    let segv: Vec<&serde_json::Value> = found
        .iter()
        .map(|(_, finding)| finding)
        .filter(|finding| finding["rule_id"] == "BHF-210")
        .collect();
    let harnesses: std::collections::BTreeSet<&str> = segv
        .iter()
        .filter_map(|finding| finding["harness_id"].as_str())
        .collect();
    assert_eq!(harnesses.len(), 2, "both harnesses crash:\n{out}");
    let groups: std::collections::BTreeSet<&str> = segv
        .iter()
        .filter_map(|finding| finding["cluster_key_full"].as_str())
        .collect();
    assert_eq!(groups.len(), segv.len(), "one group per crash: {segv:#?}");
    assert!(
        segv.iter()
            .all(|finding| finding["exception"]["pc_offset"].is_string()),
        "the driver's fault line gives each crash its pc: {segv:#?}"
    );
    let index = std::fs::read_to_string(work.join("results/INDEX.md")).unwrap_or_default();
    assert!(
        index.contains(&format!("in {} root-cause groups", segv.len())),
        "{index}"
    );
}
