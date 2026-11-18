// SPDX-License-Identifier: Apache-2.0

//! End-to-end coverage for `bhf auto --engine afl++` (#auto-afl). Toolchain-
//! gated: skips (printing why) when `afl-fuzz`/`afl-clang-fast` are not on PATH,
//! per the project's GNAT-less skip convention, so a box without AFL does not
//! hard-fail the suite.

use std::path::Path;
use std::process::Command;

mod support;

fn which(bin: &str) -> bool {
    let present = {
        std::env::var_os("PATH")
            .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(bin).is_file()))
            .unwrap_or(false)
    };
    support::require_tool(present, bin)
}

fn afl_present() -> bool {
    which("afl-fuzz") && which("afl-clang-fast")
}

/// The bundled miniz fixture. `CARGO_MANIFEST_DIR` is `<repo>/crates/cli`, so the
/// fixture lives two levels up — integration tests run with CWD at the crate root,
/// not the workspace root.
fn miniz_fixture() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/build_recovery/fixtures/miniz")
}

/// Recursively check whether a file named `name` exists anywhere under `root`.
fn walk_for(root: &Path, name: &str) -> bool {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for entry in rd.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.file_name().and_then(|n| n.to_str()) == Some(name) {
                    return true;
                }
            }
        }
    }
    false
}

/// `auto --engine builtin,afl++` against a real C library (miniz) must:
///   1. recover the build and produce the AFL-instrumented `main_afl`, and
///   2. drive AFL, recording an `afl++`-attributed pass in run.json ALONGSIDE
///      the builtin passes.
#[test]
fn auto_engine_both_builds_main_afl_and_attributes_afl_pass() {
    if !afl_present() {
        eprintln!("skipping auto_engine_both: afl-fuzz/afl-clang-fast not on PATH");
        return;
    }
    let bin = env!("CARGO_BIN_EXE_bhf");
    let tmp = tempfile::tempdir().unwrap();
    let work = tmp.path().join("work");
    let status = Command::new(bin)
        .args([
            "auto",
            "--engine",
            "builtin,afl++",
            "--per-target-time",
            "2",
            "--max-targets",
            "1",
            "--work-dir",
            work.to_str().unwrap(),
            miniz_fixture().to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(
        status.success(),
        "auto --engine builtin,afl++ exited non-zero"
    );

    // (1) the afl-instrumented binary was built from the recovered harness
    assert!(
        walk_for(&work, "main_afl"),
        "expected a main_afl under {} (auto should `make afl` the recovered build)",
        work.display()
    );

    // (2) run.json attributes a pass to the afl++ engine, and still carries the
    //     builtin passes (both engines ran for the target)
    let run_json = std::fs::read_to_string(work.join("auto").join("run.json")).unwrap();
    assert!(
        run_json.contains("\"engine\": \"afl++\""),
        "run.json should attribute an afl++ pass"
    );
    assert!(
        run_json.contains("\"engine\": \"builtin\""),
        "run.json should still carry the builtin passes"
    );
}

/// `auto --engine afl++` (AFL only) must skip the builtin cascade and record ONLY
/// an afl++ pass for a native C target.
#[test]
fn auto_engine_afl_only_skips_builtin_cascade() {
    if !afl_present() {
        eprintln!("skipping auto_engine_afl_only: afl-fuzz/afl-clang-fast not on PATH");
        return;
    }
    let bin = env!("CARGO_BIN_EXE_bhf");
    let tmp = tempfile::tempdir().unwrap();
    let work = tmp.path().join("work");
    let status = Command::new(bin)
        .args([
            "auto",
            "--engine",
            "afl++",
            "--per-target-time",
            "2",
            "--max-targets",
            "1",
            "--work-dir",
            work.to_str().unwrap(),
            miniz_fixture().to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "auto --engine afl++ exited non-zero");

    let run_json = std::fs::read_to_string(work.join("auto").join("run.json")).unwrap();
    assert!(
        run_json.contains("\"engine\": \"afl++\""),
        "run.json should attribute the afl++ pass"
    );
    // AFL-only: no builtin empty/rng/fuzz_driven passes were run for this target.
    assert!(
        !run_json.contains("\"engine\": \"builtin\""),
        "AFL-only run must NOT record builtin passes"
    );
}

/// A store to a struct member past a 4-byte heap block, fuzzed by AFL++ alone
/// (the only access through the struct type, so seeds that skip it do not
/// crash: clang's check reports any member access through an undersized block).
/// afl-clang-fast's UBSan object-size check reports the member access before
/// ASan does; the crash ingestion re-runs the input with that check suppressed
/// and reports ASan's heap-buffer-overflow, as the builtin engine does, saying
/// so in the finding.
#[test]
fn an_afl_member_store_past_a_heap_block_is_an_asan_heap_buffer_overflow() {
    if !afl_present() || !which("make") {
        eprintln!("skipping: afl-fuzz/afl-clang-fast or make not on PATH");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("tree/src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("pair.c"),
        "#include <stdlib.h>\n\
         struct pair { int first; int second; };\n\
         int store_pair(const unsigned char *d, size_t n) {\n\
         \x20   int *slot = malloc(sizeof(int));\n\
         \x20   if (!slot) return 0;\n\
         \x20   *slot = 0;\n\
         \x20   if (n > 2 && d[0] == 'P') ((struct pair *)slot)->second = d[1];\n\
         \x20   int r = *slot;\n\
         \x20   free(slot);\n\
         \x20   return r;\n\
         }\n",
    )
    .unwrap();
    let work = tmp.path().join("work");
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(&src)
        .arg("--work-dir")
        .arg(&work)
        .args([
            "--engine",
            "afl++",
            "--per-target-time",
            "8",
            "--max-targets",
            "1",
            "--jobs",
            "1",
            "--no-discovery-cache",
        ])
        .env_remove("CC")
        .env_remove("CXX")
        .output()
        .unwrap();
    let log = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let findings: Vec<serde_json::Value> = std::fs::read_dir(work.join("results/findings"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let text = std::fs::read_to_string(entry.path().join("finding.json")).ok()?;
            serde_json::from_str(&text).ok()
        })
        .collect();
    let overflow = findings
        .iter()
        .find(|finding| finding["exception"]["name"] == "ASAN_HEAP_BUFFER_OVERFLOW")
        .unwrap_or_else(|| panic!("no heap-buffer-overflow: {findings:#?}\n{log}"));
    assert_eq!(overflow["rule_id"], "BHF-201", "{overflow:#}");
    let opinion = &overflow["sanitizer_second_opinion"];
    assert_eq!(opinion["check"], "object-size", "{overflow:#}");
    assert_eq!(opinion["used"], "asan", "{overflow:#}");
    assert!(
        !findings
            .iter()
            .any(|finding| finding["rule_id"] == "BHF-227"),
        "no object-size finding: {findings:#?}"
    );
}

/// A heap read past a 4-byte block behind two one-byte checks, fuzzed by
/// AFL++ alone. AFL++ fuzzes `main_afl`, which has no bhf driver; the
/// finding's comparison evidence is recorded by replaying its input through
/// the driver build `main` beside it, so `finding.json` carries the gates
/// the input passed and the results index carries them as input-to-state
/// evidence.
#[test]
fn an_afl_finding_records_the_comparison_evidence_of_its_input() {
    if !afl_present() || !which("make") || !which("clang") {
        eprintln!("skipping: afl-fuzz/afl-clang-fast, clang or make not on PATH");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("tree/src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("tag.c"),
        "#include <stdlib.h>\n\
         #include <string.h>\n\
         int parse_tag(const unsigned char *d, size_t n) {\n\
         \x20   char *slot;\n\
         \x20   int r;\n\
         \x20   if (n < 3 || d[0] != 'T' || d[1] != 'G') return 0;\n\
         \x20   slot = malloc(4);\n\
         \x20   if (!slot) return 0;\n\
         \x20   memset(slot, 0, 4);\n\
         \x20   r = slot[d[2] & 0x0f];\n\
         \x20   free(slot);\n\
         \x20   return r;\n\
         }\n",
    )
    .unwrap();
    let work = tmp.path().join("work");
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(&src)
        .arg("--work-dir")
        .arg(&work)
        .args([
            "--engine",
            "afl++",
            "--per-target-time",
            "20",
            "--max-targets",
            "1",
            "--jobs",
            "1",
            "--no-discovery-cache",
        ])
        .env_remove("CC")
        .env_remove("CXX")
        .output()
        .unwrap();
    let log = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let findings: Vec<serde_json::Value> = std::fs::read_dir(work.join("results/findings"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let text = std::fs::read_to_string(entry.path().join("finding.json")).ok()?;
            serde_json::from_str(&text).ok()
        })
        .collect();
    let finding = findings
        .iter()
        .find(|finding| finding["exception"]["name"] == "ASAN_HEAP_BUFFER_OVERFLOW")
        .unwrap_or_else(|| panic!("no heap-buffer-overflow: {findings:#?}\n{log}"));
    assert!(
        finding["fixture_path"]
            .as_str()
            .is_some_and(|path| path.ends_with("main_afl")),
        "an AFL++ finding: {finding:#}"
    );
    let capture = &finding["gate_capture"];
    assert_eq!(capture["status"], "recorded", "{finding:#}\n{log}");
    assert_eq!(capture["harness"], "main", "{finding:#}");
    let gates = finding["gates"].as_array().expect("gates recorded");
    for (offset, constant) in [(0, "54"), (1, "47")] {
        assert!(
            gates.iter().any(|gate| gate["offset"] == offset
                && gate["len"] == 1
                && gate["compared_with_hex"] == constant),
            "no gate at byte {offset} compared with {constant}: {finding:#}"
        );
    }
    let index: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(work.join("results/findings.json")).unwrap())
            .unwrap();
    let id = finding["id"].as_str().unwrap();
    let indexed = index["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == id)
        .unwrap_or_else(|| panic!("{id} is not in the results index: {index:#}"));
    assert!(
        indexed["fuzz"]["input_to_state"]
            .as_array()
            .is_some_and(|evidence| !evidence.is_empty()),
        "{indexed:#}"
    );
    let csv = std::fs::read_to_string(work.join("results/findings.csv")).unwrap();
    let row = csv
        .lines()
        .find(|line| line.starts_with(&format!("{id},")))
        .unwrap_or_else(|| panic!("{id} is not in findings.csv: {csv}"));
    assert!(row.contains("0:1:cmp:54"), "{row}");
    let sarif: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(work.join("results/findings.sarif")).unwrap(),
    )
    .unwrap();
    let result = sarif["runs"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|run| run["results"].as_array().cloned().unwrap_or_default())
        .find(|result| result["properties"]["bhfFindingId"] == id)
        .unwrap_or_else(|| panic!("{id} is not in findings.sarif"));
    assert!(
        result["properties"]["bhfInputToState"]
            .as_array()
            .is_some_and(|evidence| !evidence.is_empty()),
        "{result:#}"
    );
}

/// A read one past the input is the same AddressSanitizer heap-buffer-overflow
/// whichever engine finds it. The AFL++ lane ran the target on AFL++'s 1 MiB
/// testcase buffer with the bytes past the input poisoned, so there it was a
/// `use-after-poison` (#213); it now copies each input into a heap block of
/// exactly its size, as the builtin lane passes it. AFL++ is required under
/// `BHF_REQUIRE_TOOLS=1`, as the nightly runs this.
#[test]
fn an_over_read_of_the_input_is_a_heap_buffer_overflow_in_both_engines() {
    if !afl_present() || !which("make") {
        assert!(
            std::env::var_os("BHF_REQUIRE_TOOLS").is_none_or(|value| value != "1"),
            "BHF_REQUIRE_TOOLS=1 and afl-fuzz/afl-clang-fast or make is not on PATH"
        );
        eprintln!("skipping: afl-fuzz/afl-clang-fast or make not on PATH");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("tree/src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("tag.c"),
        "#include <stddef.h>\n\
         int read_tag(const unsigned char *d, size_t n) {\n\
         \x20   if (n >= 4 && d[0] == 'T' && d[1] == 'G') return d[n];\n\
         \x20   return 0;\n\
         }\n",
    )
    .unwrap();
    let seed = tmp.path().join("seed.bin");
    std::fs::write(&seed, b"TGab").unwrap();
    for engine in ["afl++", "builtin"] {
        let work = tmp.path().join(format!("work-{engine}"));
        let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
            .arg("auto")
            .arg(&src)
            .arg("--work-dir")
            .arg(&work)
            .args(["--engine", engine, "--per-target-time", "6"])
            .args(["--max-targets", "1", "--jobs", "1", "--no-discovery-cache"])
            .arg("--seed-file")
            .arg(&seed)
            .env_remove("CC")
            .env_remove("CXX")
            .output()
            .unwrap();
        let log = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let findings: Vec<serde_json::Value> = std::fs::read_dir(work.join("results/findings"))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| {
                let text = std::fs::read_to_string(entry.path().join("finding.json")).ok()?;
                serde_json::from_str(&text).ok()
            })
            .collect();
        let names: Vec<&str> = findings
            .iter()
            .filter_map(|finding| finding["exception"]["name"].as_str())
            .collect();
        assert!(
            names.contains(&"ASAN_HEAP_BUFFER_OVERFLOW"),
            "{engine}: {names:?}\n{log}"
        );
        assert!(
            !names.iter().any(|name| name.contains("POISON")),
            "{engine}: {names:?}"
        );
    }
}

/// The findings `bhf auto` wrote under `work`.
fn findings_under(work: &Path) -> Vec<serde_json::Value> {
    std::fs::read_dir(work.join("results/findings"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let text = std::fs::read_to_string(entry.path().join("finding.json")).ok()?;
            serde_json::from_str(&text).ok()
        })
        .collect()
}

/// The `fuzzer_stats` of every afl-fuzz instance under `work`.
fn afl_fuzzer_stats(work: &Path) -> Vec<String> {
    let mut stats = Vec::new();
    for harness in std::fs::read_dir(work.join("afl_out"))
        .into_iter()
        .flatten()
        .flatten()
    {
        for instance in std::fs::read_dir(harness.path().join("out"))
            .into_iter()
            .flatten()
            .flatten()
        {
            if let Ok(text) = std::fs::read_to_string(instance.path().join("fuzzer_stats")) {
                stats.push(text);
            }
        }
    }
    stats
}

/// #274: the AFL++ lane builds `main_afl_cmplog` and runs afl-fuzz with
/// `-c` on it, so AFL++'s input-to-state stage solves a 32-bit magic no
/// dictionary holds: the constant is combined with a volatile at run time.
/// Without CmpLog, AFL++ guesses 32 bits blind. AFL++ is required under
/// `BHF_REQUIRE_TOOLS=1`.
#[test]
fn the_afl_lane_runs_cmplog_and_solves_a_magic_no_dictionary_holds() {
    if !afl_present() || !which("make") {
        eprintln!("skipping: afl-fuzz/afl-clang-fast or make not on PATH");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("tree/src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("magic.c"),
        "#include <stdint.h>\n\
         #include <stdlib.h>\n\
         #include <string.h>\n\
         static volatile uint32_t key = 0x5a5a5a5au;\n\
         int check_magic(const unsigned char *d, size_t n) {\n\
         \x20   uint32_t v;\n\
         \x20   char *slot;\n\
         \x20   if (n < 4) return 0;\n\
         \x20   memcpy(&v, d, 4);\n\
         \x20   if (v != (0x13579bdfu ^ key)) return 0;\n\
         \x20   slot = malloc(4);\n\
         \x20   if (!slot) return 0;\n\
         \x20   slot[4 + (n & 3)] = 1;\n\
         \x20   free(slot);\n\
         \x20   return 1;\n\
         }\n",
    )
    .unwrap();
    let work = tmp.path().join("work");
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(&src)
        .arg("--work-dir")
        .arg(&work)
        .args(["--engine", "afl++", "--per-target-time", "30"])
        .args(["--max-targets", "1", "--jobs", "1", "--no-discovery-cache"])
        .env_remove("CC")
        .env_remove("CXX")
        .output()
        .unwrap();
    let log = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(walk_for(&work, "main_afl_cmplog"), "{log}");
    let stats = afl_fuzzer_stats(&work);
    let command_line = stats
        .iter()
        .flat_map(|text| text.lines())
        .find(|line| line.starts_with("command_line"))
        .unwrap_or_else(|| panic!("no fuzzer_stats: {log}"));
    assert!(
        command_line.contains(" -c ")
            && command_line.contains("main_afl_cmplog")
            && command_line.contains("-l 2AT"),
        "{command_line}"
    );
    let findings = findings_under(&work);
    assert!(
        findings
            .iter()
            .any(|finding| finding["exception"]["name"] == "ASAN_HEAP_BUFFER_OVERFLOW"),
        "the magic was not solved: {findings:#?}\n{log}"
    );
}

/// The `key : value` field of an afl-fuzz `fuzzer_stats` file.
fn stats_field<'a>(stats: &'a str, key: &str) -> Option<&'a str> {
    stats.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        (name.trim() == key).then(|| value.trim())
    })
}

/// #412: afl-fuzz runs its whole budget past the first crash. bhf set
/// `AFL_BENCH_UNTIL_CRASH=0`, and AFL++ stops at its first crash when the
/// variable is set at all, so a run found one crash and quit; one the caller
/// sets is removed too. AFL++ is required under `BHF_REQUIRE_TOOLS=1`.
#[test]
fn afl_fuzz_runs_its_budget_past_the_first_crash() {
    if !afl_present() || !which("make") {
        eprintln!("skipping: afl-fuzz/afl-clang-fast or make not on PATH");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("tree/src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("easy.c"),
        "#include <stdlib.h>\n\
         int easy_crash(const unsigned char *d, size_t n) {\n\
         \x20   char *slot;\n\
         \x20   if (n < 2 || d[0] != 'A') return 0;\n\
         \x20   slot = malloc(4);\n\
         \x20   if (!slot) return 0;\n\
         \x20   slot[4 + (n & 3)] = 1;\n\
         \x20   free(slot);\n\
         \x20   return 1;\n\
         }\n",
    )
    .unwrap();
    let work = tmp.path().join("work");
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(&src)
        .arg("--work-dir")
        .arg(&work)
        .args(["--engine", "afl++", "--per-target-time", "10"])
        .args(["--max-targets", "1", "--jobs", "1", "--no-discovery-cache"])
        .env("AFL_BENCH_UNTIL_CRASH", "1")
        .env_remove("CC")
        .env_remove("CXX")
        .output()
        .unwrap();
    let log = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stats = afl_fuzzer_stats(&work);
    let stats = stats
        .first()
        .unwrap_or_else(|| panic!("no fuzzer_stats: {log}"));
    let crashes: u64 = stats_field(stats, "saved_crashes")
        .or_else(|| stats_field(stats, "unique_crashes"))
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    assert!(crashes > 0, "{stats}");
    let run_time: u64 = stats_field(stats, "run_time")
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("no run_time: {stats}"));
    assert!(
        run_time >= 5,
        "afl-fuzz stopped after {run_time}s of its budget: {stats}"
    );
}

/// `bhf auto --engine afl++` over `src` into `work`, for `secs` per target.
fn auto_afl(src: &Path, work: &Path, secs: &str, extra: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(src)
        .arg("--work-dir")
        .arg(work)
        .args(["--engine", "afl++", "--per-target-time", secs])
        .args(["--max-targets", "1", "--jobs", "1", "--no-discovery-cache"])
        .args(extra)
        .env_remove("CC")
        .env_remove("CXX")
        .output()
        .unwrap();
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// The one AFL++ harness directory under `work/afl_out`.
fn afl_harness_dir(work: &Path) -> std::path::PathBuf {
    let mut dirs: Vec<_> = std::fs::read_dir(work.join("afl_out"))
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .collect();
    assert_eq!(dirs.len(), 1, "{dirs:?}");
    dirs.remove(0)
}

fn files_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    names.sort();
    names
}

/// #275: the AFL++ session is kept between runs. The first run's queue is
/// taken into the bhf corpus, and a second run resumes the session (its
/// queue, not a fresh one from the seeds). AFL++ is required under
/// `BHF_REQUIRE_TOOLS=1`.
#[test]
fn a_second_afl_run_resumes_the_session_and_its_queue_is_in_the_corpus() {
    if !afl_present() || !which("make") {
        eprintln!("skipping: afl-fuzz/afl-clang-fast or make not on PATH");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("tree/src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("branches.c"),
        "#include <stddef.h>\n\
         int branches(const unsigned char *d, size_t n) {\n\
         \x20   int r = 0;\n\
         \x20   if (n > 0 && d[0] == 'a') r += 1;\n\
         \x20   if (n > 1 && d[1] == 'b') r += 2;\n\
         \x20   if (n > 2 && d[2] == 'c') r += 4;\n\
         \x20   if (n > 3 && d[3] == 'd') r += 8;\n\
         \x20   return r;\n\
         }\n",
    )
    .unwrap();
    let work = tmp.path().join("work");
    let first = auto_afl(&src, &work, "6", &[]);
    let harness = afl_harness_dir(&work);
    let id = harness.file_name().unwrap().to_str().unwrap().to_owned();
    let queue = harness.join("out/default/queue");
    let after_first: Vec<String> = files_in(&queue)
        .into_iter()
        .filter(|name| name.starts_with("id:"))
        .collect();
    assert!(after_first.len() > 1, "{after_first:?}\n{first}");
    let corpus = work.join("corpus").join(&id).join("queue");
    let imported = files_in(&corpus);
    assert!(
        imported.len() >= after_first.len().min(2),
        "the queue is in the corpus: {imported:?}\n{first}"
    );

    let second = auto_afl(&src, &work, "4", &[]);
    let log = std::fs::read_to_string(harness.join("afl-fuzz.log")).unwrap();
    // Resumed: the inputs come from the session's own queue, not the seeds.
    assert!(
        log.contains("Resuming") && log.contains("_resume"),
        "{log}\n{second}"
    );
    let after_second = files_in(&queue)
        .into_iter()
        .filter(|name| name.starts_with("id:"))
        .count();
    assert!(
        after_second >= after_first.len(),
        "the resumed queue keeps the first run's {} entries: {after_second}",
        after_first.len()
    );
    // The seeds were given once: none is added to the queue again.
    let offered = std::fs::read_to_string(harness.join("offered-seeds.txt")).unwrap();
    assert!(!offered.trim().is_empty(), "{offered}");
    // The second run's seeds (the first's, and its queue from the corpus)
    // are all in the session already.
    let given_again: Vec<String> = files_in(&queue)
        .into_iter()
        .filter(|name| name.contains("orig:bhf-seed-"))
        .collect();
    assert!(given_again.is_empty(), "{given_again:?}");

    // A session afl-fuzz cannot resume (a file it did not write in its queue
    // fails its clean-up) is started over, its queue kept in the corpus.
    std::fs::write(queue.join("stray"), b"zz").unwrap();
    let third = auto_afl(&src, &work, "4", &[]);
    assert!(third.contains("could not resume the session"), "{third}");
    assert!(
        files_in(&queue).iter().any(|name| name.starts_with("id:")),
        "{third}"
    );
    assert!(files_in(&corpus).len() >= imported.len(), "{third}");
}

/// #275: an input afl-fuzz saves as a hang (an infinite loop behind a
/// one-byte check) is re-run with twice afl-fuzz's limit and, hanging again,
/// is a BHF-230 finding. The AFL++ lane did not look at `hangs/`. AFL++ is
/// required under `BHF_REQUIRE_TOOLS=1`.
#[test]
fn an_afl_hang_is_a_confirmed_hang_finding() {
    if !afl_present() || !which("make") {
        eprintln!("skipping: afl-fuzz/afl-clang-fast or make not on PATH");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("tree/src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("spin.c"),
        "#include <stddef.h>\n\
         static volatile unsigned long spins;\n\
         int spin(const unsigned char *d, size_t n) {\n\
         \x20   if (n > 1 && d[0] == 'L') {\n\
         \x20       for (;;) spins++;\n\
         \x20   }\n\
         \x20   return 0;\n\
         }\n",
    )
    .unwrap();
    let work = tmp.path().join("work");
    let log = auto_afl(&src, &work, "12", &[]);
    let findings = findings_under(&work);
    let hang = findings
        .iter()
        .find(|finding| finding["rule_id"] == "BHF-230")
        .unwrap_or_else(|| panic!("no hang finding: {findings:#?}\n{log}"));
    assert!(
        hang["fixture_path"]
            .as_str()
            .is_some_and(|path| path.ends_with("main_afl")),
        "{hang:#}"
    );
    let text = hang.to_string();
    assert!(text.contains("spin"), "the stack names the loop: {hang:#}");
}

/// #276: `bhf fuzz --engine afl++ --workers 2` runs one `-M main` and one
/// `-S sec1` afl-fuzz in one output directory, which sync each other's
/// queues, and both queues are taken into the bhf corpus. It ran two bhf
/// workers with an afl-fuzz each, in their own directories, never synced.
/// AFL++ is required under `BHF_REQUIRE_TOOLS=1`.
#[test]
fn afl_workers_are_synced_main_and_secondary_instances() {
    if !afl_present() || !which("make") {
        eprintln!("skipping: afl-fuzz/afl-clang-fast or make not on PATH");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("tree/src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("branches.c"),
        "#include <stddef.h>\n\
         int branches(const unsigned char *d, size_t n) {\n\
         \x20   int r = 0;\n\
         \x20   if (n > 0 && d[0] == 'a') r += 1;\n\
         \x20   if (n > 1 && d[1] == 'b') r += 2;\n\
         \x20   if (n > 2 && d[2] == 'c') r += 4;\n\
         \x20   return r;\n\
         }\n",
    )
    .unwrap();
    let work = tmp.path().join("work");
    let built = auto_afl(&src, &work, "2", &[]);
    let id = afl_harness_dir(&work)
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("fuzz")
        .arg(&work)
        .args(["--harness", &id, "--engine", "afl++", "--workers", "2"])
        .args(["--time", "8"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}\n{built}");
    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| panic!("{error}: {stderr}"));
    assert_eq!(
        summary["afl"]["instances"],
        serde_json::json!(["main", "sec1"]),
        "{summary:#}"
    );
    let out = work.join("afl_out").join(&id).join("out");
    for (instance, role, peer) in [("main", "-M main", "sec1"), ("sec1", "-S sec1", "main")] {
        let stats = std::fs::read_to_string(out.join(instance).join("fuzzer_stats"))
            .unwrap_or_else(|error| panic!("{instance}: {error}\n{stderr}"));
        let command_line = stats_field(&stats, "command_line").unwrap();
        assert!(command_line.contains(role), "{command_line}");
        assert!(
            out.join(instance).join(".synced").join(peer).exists(),
            "{instance} synced {peer}'s queue"
        );
    }
    // CmpLog runs on the main instance only.
    assert!(
        stats_field(
            &std::fs::read_to_string(out.join("sec1/fuzzer_stats")).unwrap(),
            "command_line"
        )
        .is_some_and(|line| !line.contains(" -c ")),
        "{summary:#}"
    );
    assert!(
        summary["corpus_persisted"].as_u64().is_some(),
        "{summary:#}"
    );
    let corpus = files_in(&work.join("corpus").join(&id).join("queue"));
    assert!(!corpus.is_empty(), "both queues are in the corpus");
}
