// SPDX-License-Identifier: Apache-2.0

//! Hit-count buckets in `bhf fuzz` (#401).
//!
//! `count_up` loops `data[0]` times, so every input past the first runs the
//! same edges: only the loop edge's hit count tells a longer loop from a
//! shorter one. `bhf auto` armed the driver's per-exec hit-count map and
//! `bhf fuzz` did not, so `bhf fuzz` kept no input that only looped longer.
//! With the map, an input whose loop count reaches a new AFL bucket (1, 2, 3,
//! 4-7, 8-15, 16-31, 32-127, 128+) joins the corpus.

#![cfg(target_os = "linux")]

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

/// The AFL bucket of a loop run `count` times.
fn bucket(count: u8) -> u8 {
    match count {
        0..=3 => count,
        4..=7 => 4,
        8..=15 => 5,
        16..=31 => 6,
        32..=127 => 7,
        128.. => 8,
    }
}

fn bhf(work: &Path, args: &[&str]) -> std::process::Command {
    let mut cmd = support::bhf_cargo_command();
    cmd.current_dir(work).args(args);
    cmd
}

#[test]
fn an_input_that_only_loops_longer_joins_the_corpus() {
    if !support::libfuzzer_toolchain_available("hit-count-buckets") {
        eprintln!("skipping: clang+make toolchain unavailable");
        return;
    }
    let work = TestDir::new("hit-count-buckets");
    std::fs::write(work.join("loop.c"), TARGET).unwrap();
    let id = "H-LOOP";
    let generated = bhf(
        work.path(),
        &["generate-harness", "loop.c", "--target", "count_up"],
    )
    .args(["--output", "generated_harnesses", "--id", id])
    .status()
    .unwrap();
    assert!(generated.success(), "generate-harness failed");
    let built = bhf(work.path(), &["build", ".", "--harness", id])
        .status()
        .unwrap();
    assert!(built.success(), "build failed");
    let out = bhf(work.path(), &["fuzz", ".", "--harness", id])
        .args([
            "--engine",
            "builtin",
            "--iterations",
            "2000",
            "--rng-seed",
            "1",
        ])
        .args(["--seed-input", "A", "--sandbox", "none", "-q"])
        .output()
        .unwrap();
    assert!(
        out.status.success() || out.status.code() == Some(1),
        "bhf fuzz: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut buckets: Vec<u8> = std::fs::read_dir(work.join(format!("corpus/{id}/queue")))
        .expect("the run's corpus queue")
        .flatten()
        .filter_map(|entry| std::fs::read(entry.path()).ok())
        .filter_map(|input| input.first().copied())
        .map(bucket)
        .collect();
    buckets.sort_unstable();
    buckets.dedup();
    assert!(
        buckets.len() >= 5,
        "the kept inputs' loop counts reach the buckets {buckets:?} only"
    );
}
