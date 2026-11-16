// SPDX-License-Identifier: Apache-2.0

//! `bhf auto --deadline` arms the timing oracle for every fuzzed target, and
//! run.md and run.json count the executions killed at the per-input timeout
//! (#208): the deadline oracle was reachable from auto only through an
//! undocumented environment variable, and auto never reported hangs.

use std::fs;
use std::path::Path;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn auto(root: &Path, src: &Path, args: &[&str]) -> std::process::Output {
    support::bhf_cargo_command()
        .current_dir(root)
        .env_remove("BHF_DEADLINE_MS")
        .env_remove("BHF_EXEC_TIMEOUT")
        .args(["auto", "--work-dir", root.join("work").to_str().unwrap()])
        .args(args)
        .arg(src)
        .output()
        .expect("run bhf auto")
}

fn findings(work: &Path) -> Vec<serde_json::Value> {
    fs::read_dir(work.join("results/findings"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            serde_json::from_slice(&fs::read(entry.path().join("finding.json")).ok()?).ok()
        })
        .collect()
}

#[test]
fn auto_deadline_reports_a_slow_target() {
    if !support::libfuzzer_toolchain_available("auto-deadline") {
        eprintln!("skipping: clang+libfuzzer toolchain unavailable");
        return;
    }
    let root = TestDir::new("auto-deadline");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("slow.c"),
        "#include <stddef.h>\n#include <time.h>\n\
         int answer_slowly(const unsigned char *data, size_t len) {\n\
             struct timespec t = { 0, 200000000L };\n\
             nanosleep(&t, 0);\n\
             return len > 0 ? data[0] : 0;\n\
         }\n",
    )
    .unwrap();
    let out = auto(
        root.path(),
        &src,
        &["--deadline", "50ms", "--per-target-time", "4"],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let work = root.join("work");
    let slow: Vec<_> = findings(&work)
        .into_iter()
        .filter(|finding| finding["rule_id"] == "BHF-555")
        .collect();
    assert_eq!(slow.len(), 1, "{slow:#?}\n{stderr}");
    assert_eq!(
        slow[0]["deadline_confirmation"]["deadline_ms"], 50,
        "{:#}",
        slow[0]
    );
}

#[test]
fn auto_refuses_a_deadline_not_shorter_than_the_timeout() {
    let root = TestDir::new("auto-deadline-refused");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("a.c"),
        "int f(const char *p, unsigned n) { return n; }\n",
    )
    .unwrap();
    for args in [
        &["--deadline", "2s", "--timeout", "1s", "--dry-run"][..],
        &["--deadline", "0", "--dry-run"][..],
    ] {
        let out = auto(root.path(), &src, args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {stderr}");
        assert!(stderr.contains("--deadline must be"), "{args:?}: {stderr}");
    }
}

#[test]
fn run_md_and_run_json_count_a_target_s_hangs() {
    if !support::libfuzzer_toolchain_available("auto-hangs") {
        eprintln!("skipping: clang+libfuzzer toolchain unavailable");
        return;
    }
    let root = TestDir::new("auto-hangs");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    // A record's length byte moves the cursor: a zero never advances it.
    fs::write(
        src.join("tlv.c"),
        "#include <stddef.h>\n\
         static volatile int seen;\n\
         int walk_records(const unsigned char *d, size_t n) {\n\
             size_t at = 0;\n\
             while (at + 2 <= n) {\n\
                 seen += d[at];\n\
                 at += d[at + 1];\n\
             }\n\
             return seen;\n\
         }\n",
    )
    .unwrap();
    let seed = root.join("hang.bin");
    fs::write(&seed, b"\x07\x00\x01").unwrap();
    let out = auto(
        root.path(),
        &src,
        &[
            "--timeout",
            "300ms",
            "--per-target-time",
            "6",
            "--seed-file",
            seed.to_str().unwrap(),
        ],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let work = root.join("work");
    assert!(
        findings(&work)
            .iter()
            .any(|finding| finding["rule_id"] == "BHF-230"),
        "{stderr}"
    );

    let run_md = fs::read_to_string(work.join("auto/run.md")).unwrap();
    let header = run_md
        .lines()
        .find(|line| line.starts_with("Hangs:"))
        .unwrap_or_else(|| panic!("run.md has no Hangs line:\n{run_md}"));
    assert!(
        header.contains("killed at the per-input timeout"),
        "{header}"
    );
    let target = run_md
        .lines()
        .find(|line| line.contains("walk_records"))
        .unwrap_or_else(|| panic!("{run_md}"));
    assert!(target.contains(" hangs="), "{target}");

    let run_json: serde_json::Value =
        serde_json::from_slice(&fs::read(work.join("auto/run.json")).unwrap()).unwrap();
    let hangs: Vec<&serde_json::Value> = run_json["targets"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|target| target["outcome"]["passes"].as_array().into_iter().flatten())
        .filter_map(|pass| pass.get("hangs"))
        .collect();
    assert!(
        hangs
            .iter()
            .any(|hangs| hangs["confirmed"].as_u64().is_some_and(|n| n >= 1)
                && hangs["timeout_ms"] == 300),
        "{hangs:#?}"
    );
}
