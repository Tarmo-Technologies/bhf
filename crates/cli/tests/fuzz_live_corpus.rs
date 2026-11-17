// SPDX-License-Identifier: Apache-2.0

//! `BHF_LIVE_CORPUS_DIR` (#256): the built-in loop writes each input it keeps
//! into the dir as it keeps it, named as the queue names it, so an observer
//! (the engine trade study's coverage-over-time snapshots) sees the corpus
//! grow during the campaign. bhf writes its queue only when the pass ends.

#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::path::Path;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

const TARGET: &str = "#include <stddef.h>\n\
    static volatile unsigned sink;\n\
    int count_up(const unsigned char *data, size_t len) {\n\
    \x20   if (len < 1) return 0;\n\
    \x20   for (unsigned i = 0; i < data[0]; i++) sink += i;\n\
    \x20   return 1;\n\
    }\n";

fn names(dir: &Path) -> BTreeSet<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect()
}

#[test]
fn each_kept_input_reaches_the_live_corpus_dir() {
    if !support::libfuzzer_toolchain_available("live-corpus") {
        eprintln!("skipping: clang+make toolchain unavailable");
        return;
    }
    let work = TestDir::new("live-corpus");
    std::fs::write(work.join("loop.c"), TARGET).unwrap();
    let id = "H-LIVE";
    let run = |args: &[&str]| {
        let mut cmd = support::bhf_cargo_command();
        cmd.current_dir(work.path()).args(args);
        cmd
    };
    assert!(run(&["generate-harness", "loop.c", "--target", "count_up"])
        .args(["--output", "generated_harnesses", "--id", id])
        .status()
        .unwrap()
        .success());
    assert!(run(&["build", ".", "--harness", id])
        .status()
        .unwrap()
        .success());
    let live = work.join("live");
    let status = run(&["fuzz", ".", "--harness", id])
        .args([
            "--iterations",
            "2000",
            "--rng-seed",
            "1",
            "--seed-input",
            "A",
        ])
        .args(["--sandbox", "none", "-q"])
        .env("BHF_LIVE_CORPUS_DIR", &live)
        .status()
        .unwrap();
    assert!(status.success() || status.code() == Some(1));

    // The kept inputs, by the names the queue gives them when the pass ends.
    let live_names = names(&live);
    let queue_names = names(&work.join(format!("corpus/{id}/queue")));
    assert!(live_names.len() >= 4, "{live_names:?}");
    assert!(
        live_names.is_subset(&queue_names),
        "{live_names:?} vs {queue_names:?}"
    );
}
