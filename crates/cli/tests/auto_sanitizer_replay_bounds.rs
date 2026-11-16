// SPDX-License-Identifier: Apache-2.0
// Linux only: the MSan and TSan corpus replays build with clang's sanitizers.
#![cfg(target_os = "linux")]

//! The post-fuzz MSan and TSan corpus replays ran each input up to 30 s and
//! retried a timed-out run up to four times, whatever `--timeout` said. With
//! `--timeout 1s` a hanging input now runs once, for the timeout, under the
//! first replay, and the other replay skips it. The per-input timings come
//! from `auto/sanitizer-replay.jsonl`, not the wall clock.

use std::collections::BTreeMap;
use std::fs;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// Spins on an input starting with `S`, only in an MSan or TSan build: the
/// ASan fuzz run keeps that input in its corpus, and each replay hangs on it.
const SPIN: &str = "#include <stddef.h>\n\
                    #if defined(__has_feature)\n\
                    #if __has_feature(memory_sanitizer) || __has_feature(thread_sanitizer)\n\
                    #define SPIN_IN_REPLAY 1\n\
                    #endif\n\
                    #endif\n\
                    int parse_spin(const unsigned char *d, size_t n) {\n\
                        if (n > 0 && d[0] == 'S') {\n\
                    #ifdef SPIN_IN_REPLAY\n\
                            volatile int spinning = 1;\n\
                            while (spinning) {}\n\
                    #endif\n\
                            return 1;\n\
                        }\n\
                        return 0;\n\
                    }\n";

#[test]
fn a_hanging_input_runs_once_for_the_timeout_under_the_sanitizer_replays() {
    if !support::libfuzzer_toolchain_available("sanitizer-replay-bounds") {
        eprintln!("skipping: clang+libfuzzer toolchain unavailable");
        return;
    }
    let root = TestDir::new("auto-sanitizer-replay");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("spin.c"), SPIN).unwrap();
    let work = root.join("work");
    let out = support::bhf_cargo_command()
        .current_dir(root.path())
        .args(["auto", "--work-dir", work.to_str().unwrap()])
        .args(["--timeout", "1s", "--per-target-time", "4"])
        .arg(src.to_str().unwrap())
        .output()
        .expect("run bhf auto");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() || out.status.code() == Some(1),
        "{stderr}"
    );
    let log = fs::read_to_string(work.join("auto/sanitizer-replay.jsonl"))
        .unwrap_or_else(|error| panic!("no replay log ({error}): {stderr}"));
    let runs: Vec<serde_json::Value> = log
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let spins: Vec<String> = fs::read_dir(work.join("corpus"))
        .unwrap()
        .flatten()
        .flat_map(|harness| {
            fs::read_dir(harness.path().join("queue"))
                .into_iter()
                .flatten()
        })
        .flatten()
        .filter(|input| fs::read(input.path()).is_ok_and(|bytes| bytes.first() == Some(&b'S')))
        .map(|input| input.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        !spins.is_empty(),
        "the fuzz run kept no `S` input: {stderr}"
    );

    let mut timeouts = 0;
    for input in &spins {
        let mut by_sanitizer: BTreeMap<&str, Vec<&serde_json::Value>> = BTreeMap::new();
        for run in runs.iter().filter(|run| run["input"] == input.as_str()) {
            by_sanitizer
                .entry(run["sanitizer"].as_str().unwrap())
                .or_default()
                .push(run);
        }
        for (sanitizer, runs) in &by_sanitizer {
            // One run, never a retry.
            assert_eq!(runs.len(), 1, "{sanitizer} {input}: {log}");
            let run = runs[0];
            match run["outcome"].as_str() {
                Some("timeout") => {
                    timeouts += 1;
                    assert_eq!(run["timeout_ms"], 1000, "{log}");
                    let elapsed = run["elapsed_ms"].as_u64().unwrap();
                    assert!(
                        (1000..4000).contains(&elapsed),
                        "{sanitizer} {input}: {log}"
                    );
                }
                // Hung under the replay before this one.
                Some("skipped_known_hang") => {}
                other => panic!("{sanitizer} {input}: {other:?}: {log}"),
            }
        }
    }
    assert!(
        timeouts >= 1,
        "no replay ran a hanging input: {log}\n{stderr}"
    );
}
