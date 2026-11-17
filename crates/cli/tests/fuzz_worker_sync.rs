// SPDX-License-Identifier: Apache-2.0

//! The workers of a `bhf fuzz --workers` campaign share their corpus as they
//! run (#277). Each writes the entries its pool keeps to the campaign's
//! `sync/worker-<id>/` and runs the ones its peers wrote, every
//! `BHF_SYNC_INTERVAL_MS`. The workers merged their queues only after all of
//! them had exited. A C target built by `bhf auto` gives the workers coverage
//! to keep entries by; it skips without clang and make, which
//! `BHF_REQUIRE_TOOLS=1` requires.

#![cfg(unix)]

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

mod support;

fn on_path(bin: &str) -> bool {
    let present = std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(bin).is_file()))
        .unwrap_or(false);
    support::require_tool(present, bin)
}

fn entries(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.ends_with(".bin"))
        .collect()
}

#[test]
fn workers_import_each_others_new_entries_while_the_campaign_runs() {
    if !on_path("clang") || !on_path("make") {
        eprintln!("skipping: clang or make not on PATH");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("tree/src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("gates.c"),
        "#include <stddef.h>\n\
         int gates(const unsigned char *d, size_t n) {\n\
         \x20   int r = 0;\n\
         \x20   for (size_t i = 0; i < n && i < 16; i++) {\n\
         \x20       switch (d[i]) {\n\
         \x20       case 'a': r += 1; break;\n\
         \x20       case 'b': r += 2; break;\n\
         \x20       case 'c': r += 3; break;\n\
         \x20       case 'd': r += 4; break;\n\
         \x20       case 'e': r += 5; break;\n\
         \x20       case 'f': r += 6; break;\n\
         \x20       case 'g': r += 7; break;\n\
         \x20       case 'h': r += 8; break;\n\
         \x20       default: break;\n\
         \x20       }\n\
         \x20   }\n\
         \x20   return r;\n\
         }\n",
    )
    .unwrap();
    let work = tmp.path().join("work");
    let built = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(&src)
        .arg("--work-dir")
        .arg(&work)
        .args([
            "--per-target-time",
            "1",
            "--max-targets",
            "1",
            "--jobs",
            "1",
        ])
        .arg("--no-discovery-cache")
        .env_remove("CC")
        .env_remove("CXX")
        .output()
        .unwrap();
    let auto_log = String::from_utf8_lossy(&built.stderr).into_owned();
    let harness = std::fs::read_dir(work.join("harnesses"))
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().into_string().unwrap())
        .find(|name| name.starts_with("H-"))
        .unwrap_or_else(|| panic!("no harness: {auto_log}"));

    let budget_secs = 8;
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("fuzz")
        .arg(&work)
        .args(["--harness", &harness, "--workers", "2"])
        .args(["--time", &format!("{budget_secs}s")])
        .env("BHF_SYNC_INTERVAL_MS", "1000")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");

    let sync = work.join("fuzz_campaigns").join(&harness).join("sync");
    let exported: Vec<(String, HashSet<String>)> = ["worker-0", "worker-1"]
        .iter()
        .map(|worker| {
            let names = entries(&sync.join(worker));
            (
                (*worker).to_owned(),
                names
                    .iter()
                    .map(|name| name.trim_end_matches(".bin").to_owned())
                    .collect(),
            )
        })
        .collect();
    // Each hash is in the sync directory once, under the worker that found
    // it: an imported entry is not exported again.
    let (a, b) = (&exported[0].1, &exported[1].1);
    assert!(
        a.is_disjoint(b),
        "a hash under both workers: {:?}",
        a.intersection(b).collect::<Vec<_>>()
    );

    let worker_dirs: Vec<PathBuf> = std::fs::read_dir(&work)
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("worker-"))
        })
        .collect();
    let mut imports = Vec::new();
    for dir in &worker_dirs {
        let log = std::fs::read_to_string(dir.join("sync-import.log")).unwrap_or_default();
        for line in log.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            assert_eq!(fields.len(), 3, "{line}");
            imports.push((
                fields[0].parse::<u64>().unwrap(),
                fields[1].to_owned(),
                fields[2].to_owned(),
            ));
        }
    }
    // A worker ran an entry its peer found, during the campaign.
    let (at_ms, peer, hash) = imports
        .iter()
        .find(|(_, peer, hash)| {
            exported
                .iter()
                .any(|(worker, hashes)| worker == peer && hashes.contains(hash))
        })
        .unwrap_or_else(|| {
            panic!("no worker imported a peer's entry: {imports:?}\n{exported:?}\n{stderr}")
        });
    assert!(
        *at_ms < budget_secs * 1000,
        "{peer}'s {hash} was imported at {at_ms} ms, after the campaign"
    );
}
