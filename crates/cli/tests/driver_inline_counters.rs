// SPDX-License-Identifier: Apache-2.0
//! The C driver's inline 8-bit counter coverage (the SanitizerCoverage form
//! MSVC implements, and the one the MSVC harness lane builds with): the counter
//! array a module registers is folded into the shared edge and hit-count maps
//! after every input. Exercised here with clang, whose
//! `-fsanitize-coverage=inline-8bit-counters` calls the same
//! `__sanitizer_cov_8bit_counters_init` the MSVC start-up code does.

use std::path::PathBuf;
use std::process::Command;

#[test]
fn inline_counters_reach_the_edge_and_hit_count_maps() {
    if Command::new("clang").arg("--version").output().is_err() {
        eprintln!("skipping: clang unavailable");
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    let target = dir.join("target.c");
    std::fs::write(
        &target,
        "#include <stddef.h>\n#include <stdint.h>\n\
         int bhf_run_one(const uint8_t *data, size_t size) {\n\
           int score = 0;\n\
           for (size_t i = 0; i < size; i++) { if (data[i] == 'W') score += 2; else score++; }\n\
           return score > 3 ? 1 : 0;\n\
         }\n",
    )
    .unwrap();
    let driver = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime/bhf_driver.c");
    let binary = dir.join("harness");
    let output = Command::new("clang")
        .args(["-O1", "-g", "-c", "-o"])
        .arg(dir.join("driver.o"))
        .arg(&driver)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new("clang")
        .args([
            "-O1",
            "-g",
            "-fsanitize-coverage=inline-8bit-counters,trace-cmp",
            "-o",
        ])
        .arg(&binary)
        .arg(&target)
        .arg(dir.join("driver.o"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let input = dir.join("input.bin");
    std::fs::write(&input, b"WWWWxyz").unwrap();
    let edges = dir.join("cov.shm");
    let counts = dir.join("cnt.shm");
    let status = Command::new(&binary)
        .arg(&input)
        .env("BHF_COV_SHM", &edges)
        .env("BHF_COV_CNT_SHM", &counts)
        .status()
        .unwrap();
    assert!(status.success());
    let edge_map = std::fs::read(&edges).unwrap();
    let count_map = std::fs::read(&counts).unwrap();
    assert_eq!(edge_map.len(), 1 << 16);
    let covered = edge_map.iter().filter(|&&bit| bit != 0).count();
    assert!(covered >= 3, "the run's edges are in the map: {covered}");
    assert!(
        count_map.iter().any(|&hits| hits >= 4),
        "the loop body's hit count (7 iterations) is recorded: max {}",
        count_map.iter().max().unwrap()
    );
    for (bit, hits) in edge_map.iter().zip(&count_map) {
        assert_eq!(*bit != 0, *hits != 0, "an edge is in both maps or neither");
    }
}
