// SPDX-License-Identifier: Apache-2.0

//! The GCC lane of `bhf auto` (CC=gcc, CXX=g++) reports what the clang lane
//! does. GCC's static AddressSanitizer runtime opens the vDSO by its link-map
//! name while it symbolizes a report, and the runtrace shim used to fake that
//! open in its faking passes, which crashed the report: every defect came back
//! a second time without a stack, with a fake-descriptor "leak" and the vDSO
//! listed as a missing dependency. Ubuntu's gcc also defines
//! `_FORTIFY_SOURCE`, whose own abort pre-empted AddressSanitizer on an
//! overflowing `strcpy`/`memcpy`.

#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

mod support;

fn bhf() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
}

fn have(program: &str) -> bool {
    let present = { which::which(program).is_ok() };
    support::require_tool(present, program)
}

/// Whether `compiler` links a program with its static AddressSanitizer
/// runtime (`-static-libasan`), which the GCC lane uses.
fn links_static_asan(compiler: &str, language: &str) -> bool {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join(format!("probe.{language}"));
    std::fs::write(&source, "int main(void) { return 0; }\n").unwrap();
    Command::new(compiler)
        .args(["-fsanitize=address", "-static-libasan", "-o"])
        .arg(dir.path().join("probe"))
        .arg(&source)
        .output()
        .is_ok_and(|output| output.status.success())
}

fn text(output: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn auto(tree: &Path, work: &Path, compilers: &[(&str, &str)], targets: &str) -> Output {
    let mut command = bhf();
    command
        .arg("auto")
        .arg(tree)
        .arg("--work-dir")
        .arg(work)
        .args([
            "--max-targets",
            targets,
            "--jobs",
            "1",
            "--per-target-time",
            "6",
            "--no-discovery-cache",
        ])
        .env_remove("CC")
        .env_remove("CXX")
        .env_remove("CFLAGS")
        .env_remove("CXXFLAGS");
    for (key, value) in compilers {
        command.env(key, value);
    }
    command.output().expect("run bhf auto")
}

/// Every `finding.json` of the work dir.
fn findings(work: &Path) -> Vec<serde_json::Value> {
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

/// A sanitizer finding's rule and site (source file name and line of its top
/// frame, or of the report's location).
fn site(finding: &serde_json::Value) -> Option<(String, String, u64)> {
    let exception = &finding["exception"];
    let frame = exception["stack"]
        .as_array()
        .and_then(|stack| stack.iter().find(|frame| frame["line"].is_u64()))
        .unwrap_or(&exception["location"]);
    let file = frame["file"].as_str()?;
    let name = Path::new(file).file_name()?.to_string_lossy().into_owned();
    Some((
        finding["rule_id"].as_str()?.to_owned(),
        name,
        frame["line"].as_u64()?,
    ))
}

fn is_sanitizer_finding(finding: &serde_json::Value) -> bool {
    finding["exception"]["name"]
        .as_str()
        .is_some_and(|name| name.starts_with("ASAN_") || name.starts_with("UBSAN_"))
}

fn write_two_bug_tree(tree: &Path) -> PathBuf {
    let src = tree.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("records.hpp"),
        "#pragma once\n#include <cstddef>\n\
         namespace demo {\n\
         int parse_header(const unsigned char *data, std::size_t len);\n\
         int parse_body(const unsigned char *data, std::size_t len);\n\
         }\n",
    )
    .unwrap();
    std::fs::write(
        src.join("records.cpp"),
        "#include \"records.hpp\"\n\
         #include <cstring>\n\
         namespace demo {\n\
         int parse_header(const unsigned char *data, std::size_t len) {\n\
         \x20   char name[8];\n\
         \x20   if (len > 1 && data[0] == 'H') {\n\
         \x20       std::memcpy(name, data, len);\n\
         \x20       return name[1];\n\
         \x20   }\n\
         \x20   return 0;\n\
         }\n\
         int parse_body(const unsigned char *data, std::size_t len) {\n\
         \x20   unsigned char *slots = new unsigned char[4]();\n\
         \x20   if (len > 2 && data[0] == 'B') std::memcpy(slots, data, len);\n\
         \x20   int value = slots[0];\n\
         \x20   delete[] slots;\n\
         \x20   return value;\n\
         }\n\
         }\n",
    )
    .unwrap();
    src
}

#[test]
fn the_gcc_lane_reports_the_clang_lanes_findings_once_with_their_stacks() {
    if !have("make")
        || !have("clang++")
        || !have("g++")
        || !have("gcc")
        || !links_static_asan("g++", "cpp")
    {
        eprintln!("skip: make, clang++ or g++ with a static libasan unavailable");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let tree = tmp.path().join("tree");
    write_two_bug_tree(&tree);

    let clang_work = tmp.path().join("work-clang");
    let clang_run = auto(&tree, &clang_work, &[], "2");
    let gcc_work = tmp.path().join("work-gcc");
    let gcc_run = auto(&tree, &gcc_work, &[("CC", "gcc"), ("CXX", "g++")], "2");
    let log = format!("clang:\n{}\ngcc:\n{}", text(&clang_run), text(&gcc_run));

    let clang: Vec<serde_json::Value> = findings(&clang_work)
        .into_iter()
        .filter(is_sanitizer_finding)
        .collect();
    let gcc: Vec<serde_json::Value> = findings(&gcc_work)
        .into_iter()
        .filter(is_sanitizer_finding)
        .collect();
    let clang_sites: BTreeSet<_> = clang.iter().filter_map(site).collect();
    let gcc_sites: BTreeSet<_> = gcc.iter().filter_map(site).collect();
    assert_eq!(
        clang_sites.len(),
        2,
        "both planted bugs, clang: {clang_sites:?}\n{log}"
    );
    assert_eq!(gcc_sites, clang_sites, "{log}");
    // Each defect once, each with its stack.
    assert_eq!(gcc.len(), gcc_sites.len(), "{gcc:#?}");
    for finding in &gcc {
        assert!(
            finding["exception"]["stack"]
                .as_array()
                .is_some_and(|stack| !stack.is_empty()),
            "a stackless duplicate: {finding:#}"
        );
    }
    let all = findings(&gcc_work);
    assert!(
        !all.iter().any(|finding| finding["rule_id"] == "BHF-306"),
        "no fake-descriptor leak: {all:#?}"
    );
    let missing =
        std::fs::read_to_string(gcc_work.join("auto/missing-deps.txt")).unwrap_or_default();
    assert!(
        !missing.contains("linux-vdso") && !missing.contains(".debug"),
        "{missing}"
    );
}

/// An overflowing `strcpy` under gcc: with glibc's fortification off on the
/// sanitized lane, AddressSanitizer reports a stack-buffer-overflow at the
/// source line, not a fortify abort without a sanitizer report.
#[test]
fn a_gcc_strcpy_overflow_is_an_asan_stack_buffer_overflow_at_its_line() {
    if !have("make") || !have("gcc") || !links_static_asan("gcc", "c") {
        eprintln!("skip: make or gcc with a static libasan unavailable");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("tree/src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("name.c"),
        "#include <string.h>\n\
         int copy_name(const char *name) {\n\
         \x20   char buf[8];\n\
         \x20   strcpy(buf, name);\n\
         \x20   return buf[0];\n\
         }\n",
    )
    .unwrap();
    let work = tmp.path().join("work");
    let run = auto(&src, &work, &[("CC", "gcc"), ("CXX", "g++")], "1");
    let log = text(&run);
    let all = findings(&work);
    let overflow = all
        .iter()
        .find(|finding| finding["exception"]["name"] == "ASAN_STACK_BUFFER_OVERFLOW")
        .unwrap_or_else(|| panic!("no stack-buffer-overflow: {all:#?}\n{log}"));
    assert_eq!(overflow["rule_id"], "BHF-203", "{overflow:#}");
    assert_eq!(
        site(overflow).map(|(_, file, line)| (file, line)),
        Some(("name.c".to_owned(), 4)),
        "{overflow:#}"
    );
    assert!(
        !all.iter().any(|finding| finding["rule_id"] == "BHF-210"),
        "no sanitizer-less abort: {all:#?}"
    );
}

/// A loop that stores past a 4-byte heap block, built by gcc. gcc's UBSan
/// object-size check sees the store too and reports it first, as a BHF-227
/// insufficient-object-size error; bhf re-runs the input with that check
/// suppressed, and reports the heap-buffer-overflow ASan then reports, as
/// clang does.
#[test]
fn a_gcc_direct_heap_store_overflow_is_an_asan_heap_buffer_overflow() {
    if !have("make") || !have("gcc") || !links_static_asan("gcc", "c") {
        eprintln!("skip: make or gcc with a static libasan unavailable");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("tree/src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("fill.c"), HEAP_STORE_C).unwrap();
    let work = tmp.path().join("work");
    let run = auto(&src, &work, &[("CC", "gcc"), ("CXX", "g++")], "1");
    let log = text(&run);
    let all = findings(&work);
    let overflow = all
        .iter()
        .find(|finding| finding["exception"]["name"] == "ASAN_HEAP_BUFFER_OVERFLOW")
        .unwrap_or_else(|| panic!("no heap-buffer-overflow: {all:#?}\n{log}"));
    assert_eq!(overflow["rule_id"], "BHF-201", "{overflow:#}");
    assert_eq!(
        site(overflow).map(|(_, file, line)| (file, line)),
        Some(("fill.c".to_owned(), HEAP_STORE_LINE)),
        "{overflow:#}"
    );
    assert!(
        !all.iter().any(|finding| finding["rule_id"] == "BHF-227"),
        "no object-size finding: {all:#?}"
    );
    // The finding says which report it carries, and why.
    let opinion = &overflow["sanitizer_second_opinion"];
    assert_eq!(opinion["check"], "object-size", "{overflow:#}");
    assert_eq!(opinion["used"], "asan", "{overflow:#}");
    assert!(
        opinion["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("heap-buffer-overflow")),
        "{overflow:#}"
    );
    assert!(
        opinion["replaced_cluster_key"]
            .as_str()
            .is_some_and(|key| !key.is_empty() && overflow["cluster_key_full"] != key),
        "{overflow:#}"
    );
    // The gcc binary keeps its object-size check, which still reports the
    // store first on a replay: the same overflow, so it reproduces.
    let finding_dir = work
        .join("results/findings")
        .join(overflow["id"].as_str().unwrap());
    let replay = bhf()
        .arg("replay")
        .arg(&finding_dir)
        .output()
        .expect("run bhf replay");
    let replayed = text(&replay);
    assert!(
        replay.status.success() && !replayed.contains("MISMATCH"),
        "{replayed}"
    );
    // So does its capsule, rebuilt with gcc as the harness was.
    let capsule = bhf()
        .args(["capsule", "--work-dir"])
        .arg(&work)
        .args(["--finding-id", overflow["id"].as_str().unwrap()])
        .output()
        .expect("run bhf capsule");
    let packaged = text(&capsule);
    assert!(
        capsule.status.success() && packaged.contains("1 verified to reproduce"),
        "{packaged}"
    );
}

/// A store loop that runs past an 8-byte chunk of a pool allocator declared
/// `alloc_size`, built by gcc. ASan has no redzone inside the pool's static
/// arena, so gcc's UBSan object-size check is the only one that sees the
/// overflow: the gcc lane keeps it next to ASan, and reports BHF-227 at the
/// store.
#[test]
fn a_gcc_pool_chunk_overflow_is_found_by_the_object_size_check() {
    if !have("make") || !have("gcc") || !links_static_asan("gcc", "c") {
        eprintln!("skip: make or gcc with a static libasan unavailable");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("tree/src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("pool.c"), POOL_STORE_C).unwrap();
    let work = tmp.path().join("work");
    let run = auto(&src, &work, &[("CC", "gcc"), ("CXX", "g++")], "1");
    let log = text(&run);
    let all = findings(&work);
    let overflow = all
        .iter()
        .find(|finding| finding["rule_id"] == "BHF-227")
        .unwrap_or_else(|| panic!("no object-size finding: {all:#?}\n{log}"));
    assert_eq!(
        overflow["exception"]["name"], "UBSAN_INSUFFICIENT_OBJECT_SIZE",
        "{overflow:#}"
    );
    assert_eq!(
        site(overflow).map(|(_, file, line)| (file, line)),
        Some(("pool.c".to_owned(), POOL_STORE_LINE)),
        "{overflow:#}"
    );
    // The re-run with the check suppressed was clean: UBSan's report stands,
    // and the finding says so.
    let opinion = &overflow["sanitizer_second_opinion"];
    assert_eq!(opinion["check"], "object-size", "{overflow:#}");
    assert_eq!(opinion["used"], "ubsan", "{overflow:#}");
    assert!(
        opinion["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("no error")),
        "{overflow:#}"
    );
    assert!(
        opinion.get("replaced_cluster_key").is_none(),
        "{overflow:#}"
    );
}

/// A pool allocator over a static arena, declared `alloc_size` as allocators
/// such as PHP's are, and a loop storing up to 64 input bytes into an 8-byte
/// chunk of it at [`POOL_STORE_LINE`] (never past the arena, where ASan would
/// see it).
const POOL_STORE_C: &str = "\
#include <stddef.h>
static unsigned char arena[256];
__attribute__((noinline, malloc, alloc_size(1))) static void *pool_alloc(size_t n) {
    return n <= sizeof arena ? arena : NULL;
}
int fill(const unsigned char *d, size_t n) {
    char *p = pool_alloc(8);
    if (!p) return 0;
    for (size_t i = 0; i < n && i < 64; i++) p[i] = (char)d[i];
    return p[0];
}
";
const POOL_STORE_LINE: u64 = 9;

/// A loop storing every input byte into a 4-byte heap block, at
/// [`HEAP_STORE_LINE`].
const HEAP_STORE_C: &str = "\
#include <stdlib.h>
int fill(const unsigned char *d, size_t n) {
    char *p = malloc(4);
    if (!p) return 0;
    for (size_t i = 0; i < n; i++) p[i] = (char)d[i];
    int r = p[0];
    free(p);
    return r;
}
";
const HEAP_STORE_LINE: u64 = 5;

/// A build context that defines `_FORTIFY_SOURCE` itself, in either spelling
/// (`-D_FORTIFY_SOURCE=2`, or the `-Wp,-D_FORTIFY_SOURCE=2` of Fedora's
/// build flags): the gcc lane's harness, and the finding's capsule rebuilt
/// with gcc, still turn it off and report AddressSanitizer's
/// stack-buffer-overflow, not a fortify abort.
#[test]
fn a_build_context_that_fortifies_still_gets_an_asan_report_and_a_matching_capsule() {
    if !have("make") || !have("gcc") || !links_static_asan("gcc", "c") {
        eprintln!("skip: make or gcc with a static libasan unavailable");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("tree/src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("name.c"),
        "#include <string.h>\n\
         int copy_name(const char *name) {\n\
         \x20   char buf[8];\n\
         \x20   strcpy(buf, name);\n\
         \x20   return buf[0];\n\
         }\n",
    )
    .unwrap();
    std::fs::write(
        src.join("compile_commands.json"),
        serde_json::json!([{
            "directory": src,
            "file": src.join("name.c"),
            "arguments": [
                "gcc", "-O2", "-g", "-pipe", "-Wall", "-Wp,-D_FORTIFY_SOURCE=2",
                "-D_FORTIFY_SOURCE=2", "-c", "name.c", "-o", "name.o"
            ]
        }])
        .to_string(),
    )
    .unwrap();
    let work = tmp.path().join("work");
    let run = auto(&src, &work, &[("CC", "gcc"), ("CXX", "g++")], "1");
    let log = text(&run);
    let all = findings(&work);
    let overflow = all
        .iter()
        .find(|finding| finding["exception"]["name"] == "ASAN_STACK_BUFFER_OVERFLOW")
        .unwrap_or_else(|| panic!("no stack-buffer-overflow: {all:#?}\n{log}"));
    assert!(
        !all.iter().any(|finding| finding["rule_id"] == "BHF-210"),
        "no sanitizer-less abort: {all:#?}"
    );
    // The harness was built with the context's fortifying flags.
    let harness = work.join("harnesses").join(
        overflow["harness_id"]
            .as_str()
            .unwrap_or_else(|| panic!("{overflow:#}")),
    );
    let makefile = std::fs::read_to_string(harness.join("Makefile")).unwrap();
    assert!(
        makefile
            .lines()
            .any(|line| line.starts_with("COMPILE_DB_FLAGS =")
                && line.contains("-Wp,-D_FORTIFY_SOURCE=2")),
        "{makefile}"
    );

    // The capsule rebuilt with gcc reproduces the same report.
    let id = overflow["id"].as_str().unwrap();
    let packaged = bhf()
        .arg("capsule")
        .arg("--work-dir")
        .arg(&work)
        .args(["--finding-id", id])
        .output()
        .unwrap();
    assert!(packaged.status.success(), "{}", text(&packaged));
    let capsule = work.join("capsules").join(format!("capsule_{id}"));
    let build = Command::new("sh")
        .arg("build.sh")
        .current_dir(&capsule)
        .env("CC", "gcc")
        .env_remove("CFLAGS")
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", text(&build));
    let poc = Command::new(capsule.join("poc"))
        .arg("input/testcase.bin")
        .current_dir(&capsule)
        .output()
        .unwrap();
    let report = String::from_utf8_lossy(&poc.stderr);
    assert!(
        report.contains("AddressSanitizer: stack-buffer-overflow")
            && !report.contains("buffer overflow detected"),
        "{report}"
    );
}

/// A target that defines AddressSanitizer's `__asan_on_error` itself (to dump
/// its state on a report) cannot link with the driver's own definition, which
/// has to be strong to win over the static runtime's; built with
/// `-DBHF_NO_ASAN_ON_ERROR`, the driver leaves the hook to the target, whose
/// hook then runs.
#[test]
fn a_target_with_its_own_asan_error_hook_links_with_the_driver_opt_out() {
    if !have("gcc") || !links_static_asan("gcc", "c") {
        eprintln!("skip: gcc with a static libasan unavailable");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let target = dir.join("widget.c");
    std::fs::write(
        &target,
        "#include <stddef.h>\n#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n\
         void __asan_on_error(void) { fputs(\"widget state dump\\n\", stderr); }\n\
         int bhf_run_one(const uint8_t *data, size_t size) {\n\
         \x20   char buf[4];\n\
         \x20   memcpy(buf, data, size);\n\
         \x20   return buf[0];\n\
         }\n",
    )
    .unwrap();
    let driver = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime/bhf_driver.c");
    let build = |defines: &[&str]| {
        let object = dir.join("driver.o");
        let compiled = Command::new("gcc")
            .args(["-O1", "-g", "-fsanitize=address"])
            .args(defines)
            .arg("-c")
            .arg("-o")
            .arg(&object)
            .arg(&driver)
            .output()
            .unwrap();
        assert!(compiled.status.success(), "{}", text(&compiled));
        Command::new("gcc")
            .args(["-O1", "-g", "-fsanitize=address", "-static-libasan", "-o"])
            .arg(dir.join("harness"))
            .arg(&target)
            .arg(&object)
            .output()
            .unwrap()
    };
    let clash = build(&[]);
    assert!(
        !clash.status.success() && text(&clash).contains("__asan_on_error"),
        "{}",
        text(&clash)
    );
    let linked = build(&["-DBHF_NO_ASAN_ON_ERROR"]);
    assert!(linked.status.success(), "{}", text(&linked));
    let input = dir.join("input.bin");
    std::fs::write(&input, b"WIDGETWIDGET").unwrap();
    let run = Command::new(dir.join("harness"))
        .arg(&input)
        .output()
        .unwrap();
    let report = String::from_utf8_lossy(&run.stderr);
    assert!(
        report.contains("widget state dump") && report.contains("stack-buffer-overflow"),
        "{report}"
    );
}
