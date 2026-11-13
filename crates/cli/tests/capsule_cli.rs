// SPDX-License-Identifier: Apache-2.0
//! End-to-end coverage for `bhf capsule` + `bhf verify-poc`: a crash found
//! on a stub-stitched (un-buildable) tree is packaged into a portable capsule that
//! rebuilds and reproduces OFFLINE with only clang + a shell — no bhf, no
//! original work dir. Exercises both a self-contained crash and a stub-dependent
//! one (the recovered stubs must ship in the capsule).

use std::path::Path;
use std::process::Command;

fn clang_available() -> bool {
    which::which("clang").is_ok()
}

fn bhf() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
}

/// Self-contained stack overflow.
const OVERFLOW_C: &str = "\
#include <string.h>
int parse_header(const char *data, unsigned int len) {
    char buf[16];
    memcpy(buf, data, len);
    return buf[0];
}
";

/// NULL deref via a stubbed (undefined) external — the capsule must ship the stub.
const STUB_DEP_C: &str = "\
#include <string.h>
extern char *acquire_scratch(void);
int process(const char *data, unsigned int len) {
    char *dst = acquire_scratch();
    memcpy(dst, data, len);
    return dst[0];
}
";

fn snippet_into(src: &str, work: &Path) {
    let tmp = work.with_extension("src.c");
    std::fs::write(&tmp, src).unwrap();
    let out = bhf()
        .arg("snippet")
        .arg(&tmp)
        .arg("--lang")
        .arg("c")
        .arg("--per-target-time")
        .arg("6")
        .arg("--work-dir")
        .arg(work)
        .output()
        .expect("run bhf snippet");
    let _ = std::fs::remove_file(&tmp);
    assert!(
        work.join("results").join("findings").is_dir(),
        "snippet produced no findings: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn build_capsule(work: &Path, tar: bool) -> String {
    let mut cmd = bhf();
    cmd.arg("capsule")
        .arg("--work-dir")
        .arg(work)
        .arg("--verbose");
    if tar {
        cmd.arg("--tar");
    }
    let out = cmd.output().expect("run bhf capsule");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Verify a capsule from a PRISTINE location — no bhf work dir nearby. The
/// work dir the capsule came from (`<work>/capsules/capsule_<id>`) and the
/// tree it scanned (its `auto/run.json` `source_root`) are moved away while
/// verify-poc runs, so nothing the capsule did not ship can be reached, and
/// put back afterwards for the tests that reuse them.
fn verify_from_scratch(capsule_src: &Path, tag: &str) -> (bool, String) {
    let scratch =
        std::env::temp_dir().join(format!("bhf-cap-scratch-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).unwrap();
    let dest = scratch.join(capsule_src.file_name().unwrap());
    // Copy the capsule tree into the scratch area.
    copy_tree(capsule_src, &dest);
    let work = capsule_src
        .parent()
        .filter(|dir| dir.file_name().is_some_and(|name| name == "capsules"))
        .and_then(Path::parent)
        .map(Path::to_path_buf);
    let tree = work
        .as_ref()
        .and_then(|work| std::fs::read(work.join("auto/run.json")).ok())
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|run| run["source_root"].as_str().map(std::path::PathBuf::from))
        .filter(|tree| tree.is_dir());
    let hidden: Vec<(std::path::PathBuf, std::path::PathBuf)> = tree
        .into_iter()
        .chain(work)
        .map(|dir| {
            let moved = dir.with_extension("hidden-for-verify");
            (dir, moved)
        })
        .collect();
    for (dir, moved) in &hidden {
        std::fs::rename(dir, moved).unwrap();
    }
    let out = bhf().arg("verify-poc").arg(&dest).output();
    for (dir, moved) in hidden.iter().rev() {
        std::fs::rename(moved, dir).unwrap();
    }
    let out = out.expect("run bhf verify-poc");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let pass = out.status.success() && stdout.contains("PASS");
    let _ = std::fs::remove_dir_all(&scratch);
    (pass, stdout)
}

/// Copy the directory tree `src` to `dst`, as `cp -r` would, on any host.
fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap().flatten() {
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).unwrap();
        }
    }
}

/// `path` as bhf writes it into a generated Makefile: forward slashes and no
/// `\\?\` prefix on Windows, unchanged elsewhere.
fn make_path(path: &Path) -> String {
    harness_gen::build_safety::make_path(path)
}

fn only_capsule(work: &Path) -> std::path::PathBuf {
    let caps = work.join("capsules");
    std::fs::read_dir(&caps)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            p.is_dir()
                && p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("capsule_")
        })
        .expect("a capsule dir")
}

#[test]
fn self_contained_crash_capsule_reproduces_offline() {
    if !clang_available() {
        eprintln!("skipping: clang not installed");
        return;
    }
    let work = std::env::temp_dir().join(format!("bhf-cap-plain-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    snippet_into(OVERFLOW_C, &work);
    let stdout = build_capsule(&work, false);
    assert!(
        stdout.contains("verified to reproduce"),
        "capsule stdout:\n{stdout}"
    );
    let cap = only_capsule(&work);
    // The capsule ships a build.sh + input + harness + manifest.
    for f in [
        "build.sh",
        "manifest.json",
        "input/testcase.bin",
        "harness/main.c",
    ] {
        assert!(cap.join(f).is_file(), "capsule missing {f}");
    }
    let (pass, out) = verify_from_scratch(&cap, "plain");
    assert!(pass, "verify-poc should PASS offline; got:\n{out}");
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn stub_dependent_crash_capsule_ships_stubs_and_reproduces() {
    if !clang_available() {
        eprintln!("skipping: clang not installed");
        return;
    }
    let work = std::env::temp_dir().join(format!("bhf-cap-stub-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    snippet_into(STUB_DEP_C, &work);
    let stdout = build_capsule(&work, false);
    assert!(
        stdout.contains("verified to reproduce"),
        "capsule stdout:\n{stdout}"
    );
    let cap = only_capsule(&work);
    // The recovered stub for the undefined external must be packaged, and the
    // provenance-poisoned copy must NOT be. On Windows the work dir may be
    // spelled with an 8.3 short name (`C:\Users\ADMINI~1`) that the recorded
    // build recipe does not use, and the stub then ships with the other
    // recorded sources rather than under stubs/; either home rebuilds it.
    let shipped = files_under(&cap);
    assert!(
        cap.join("stubs/auto_stubs.c").is_file()
            || (cfg!(windows)
                && shipped
                    .iter()
                    .any(|f| f.starts_with("sources/") && f.ends_with("/repairs/auto_stubs.c"))),
        "capsule must ship the stub: {shipped:?}"
    );
    assert!(
        !shipped.iter().any(|f| f.ends_with("auto_stubs_prov.c")),
        "the provenance-poisoned stub is internal and must not ship: {shipped:?}"
    );
    let (pass, out) = verify_from_scratch(&cap, "stub");
    assert!(
        pass,
        "stub-dependent capsule should reproduce offline; got:\n{out}"
    );
    let _ = std::fs::remove_dir_all(&work);
}

/// A target source whose FILE name has a space (`rec ord.c`) is copied into the
/// capsule under that name; `build.sh` must hand it to the compiler as one
/// argument, or the capsule cannot rebuild and is reported as not reproducing.
#[test]
fn capsule_of_a_source_file_named_with_a_space_reproduces_offline() {
    if !clang_available() {
        eprintln!("skipping: clang not installed");
        return;
    }
    let root = std::env::temp_dir().join(format!("bhf-cap-spaced-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let tree = root.join("proj");
    let work = root.join("work");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("rec ord.c"), OVERFLOW_C).unwrap();
    let out = bhf()
        .arg("auto")
        .arg(&tree)
        .arg("--work-dir")
        .arg(&work)
        .args([
            "--languages",
            "c",
            "--max-targets",
            "1",
            "--jobs",
            "1",
            "--per-target-time",
            "6",
            "--no-discovery-cache",
        ])
        .output()
        .expect("run bhf auto");
    assert!(
        work.join("results").join("findings").is_dir(),
        "auto produced no findings: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = build_capsule(&work, false);
    assert!(
        stdout.contains("verified to reproduce"),
        "capsule stdout:\n{stdout}"
    );
    let cap = only_capsule(&work);
    assert!(
        cap.join("sources").join("rec ord.c").is_file(),
        "the spaced source must ship under its own name"
    );
    let (pass, verify) = verify_from_scratch(&cap, "spaced");
    assert!(pass, "verify-poc should PASS offline; got:\n{verify}");
    let _ = std::fs::remove_dir_all(&root);
}

fn clangxx_available() -> bool {
    which::which("clang++").is_ok()
}

/// The finding dirs under `work`, as `(id, dir, finding.json)`.
fn findings(work: &Path) -> Vec<(String, std::path::PathBuf, serde_json::Value)> {
    let Ok(entries) = std::fs::read_dir(work.join("results").join("findings")) else {
        return Vec::new();
    };
    let mut out: Vec<_> = entries
        .flatten()
        .filter_map(|entry| {
            let raw: serde_json::Value =
                serde_json::from_slice(&std::fs::read(entry.path().join("finding.json")).ok()?)
                    .ok()?;
            let id = raw.get("id")?.as_str()?.to_owned();
            Some((id, entry.path(), raw))
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// The first runtime crash finding with a crash input whose harness id
/// satisfies `harness`.
fn crash_finding(
    work: &Path,
    harness: impl Fn(&str) -> bool,
) -> Option<(String, std::path::PathBuf)> {
    findings(work).into_iter().find_map(|(id, dir, raw)| {
        let unhandled = raw["classification"] == "unhandled";
        let matches = raw["harness_id"].as_str().is_some_and(&harness);
        (unhandled && matches && dir.join("testcase.bin").is_file()).then_some((id, dir))
    })
}

fn capsule_for(work: &Path, id: &str) -> std::process::Output {
    bhf()
        .arg("capsule")
        .arg("--work-dir")
        .arg(work)
        .arg("--finding-id")
        .arg(id)
        .arg("--verbose")
        .output()
        .expect("run bhf capsule")
}

/// Every file under `dir`, relative to it, with `/` separators.
fn files_under(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        for entry in std::fs::read_dir(&next).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(rel) = path.strip_prefix(dir) {
                out.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    out.sort();
    out
}

const WIDGET_H: &str = "\
#pragma once
#include <cstddef>
class Widget {
public:
    Widget() {}
    int copy_at(const char *data, std::size_t len);
};
";

/// Heap overflow in a C++ method. Both this source and the generated harness
/// include the class header through a subdirectory (`include/widget.h`).
const WIDGET_CPP: &str = "\
#include \"include/widget.h\"
#include <cstdlib>
#include <cstring>
int Widget::copy_at(const char *data, std::size_t len) {
    if (len < 1) return 0;
    char *buf = static_cast<char *>(std::malloc(4));
    std::memcpy(buf, data, len);
    int r = buf[0];
    std::free(buf);
    return r;
}
";

/// A C++ finding packages into a capsule that ships the C++ driver, keeps the
/// header's subdirectory, ships the minimized input, and rebuilds and
/// reproduces from a clean directory with no work dir nearby.
#[test]
fn cpp_finding_capsule_round_trips_through_verify_poc_offline() {
    if !clangxx_available() {
        eprintln!("skipping: clang++ not installed");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let tree = root.path().join("proj");
    let work = root.path().join("work");
    std::fs::create_dir_all(tree.join("include")).unwrap();
    std::fs::write(tree.join("include/widget.h"), WIDGET_H).unwrap();
    std::fs::write(tree.join("widget.cpp"), WIDGET_CPP).unwrap();
    let out = bhf()
        .arg("auto")
        .arg(&tree)
        .arg("--work-dir")
        .arg(&work)
        .args([
            "--languages",
            "cpp",
            "--max-targets",
            "1",
            "--jobs",
            "1",
            "--per-target-time",
            "6",
            "--no-discovery-cache",
        ])
        .output()
        .expect("run bhf auto");
    let (id, finding_dir) = crash_finding(&work, |h| h.starts_with("H-X")).unwrap_or_else(|| {
        panic!(
            "auto produced no C++ crash finding: {}",
            String::from_utf8_lossy(&out.stderr)
        )
    });

    let packaged = capsule_for(&work, &id);
    let stdout = String::from_utf8_lossy(&packaged.stdout);
    assert!(
        packaged.status.success() && stdout.contains("1 verified to reproduce"),
        "capsule must package and reproduce the C++ finding; stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&packaged.stderr)
    );
    let cap = work.join("capsules").join(format!("capsule_{id}"));
    let files = files_under(&cap);
    assert!(
        files.iter().any(|f| f == "harness/main.cpp"),
        "C++ driver missing: {files:?}"
    );
    assert!(
        files.iter().any(|f| f.ends_with("/include/widget.h")),
        "the header must keep its include/ subdirectory: {files:?}"
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(cap.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["lang"], "cpp", "{manifest}");
    assert_eq!(manifest["reproduced"], true, "{manifest}");
    // The minimized input ships (as input/testcase.bin, the path capsules
    // have always used), and the manifest says which one it is.
    assert_eq!(manifest["input"], "input/testcase.bin", "{manifest}");
    let inputs: Vec<&String> = files.iter().filter(|f| f.starts_with("input/")).collect();
    assert_eq!(inputs, ["input/testcase.bin"], "one input ships: {files:?}");
    let shipped = std::fs::read(cap.join("input/testcase.bin")).unwrap();
    if finding_dir.join("min_testcase.bin").is_file() {
        assert_eq!(manifest["input_source"], "min_testcase.bin", "{manifest}");
        assert_eq!(manifest["input_minimized"], true, "{manifest}");
        assert_eq!(
            shipped,
            std::fs::read(finding_dir.join("min_testcase.bin")).unwrap()
        );
    } else {
        assert_eq!(manifest["input_source"], "testcase.bin", "{manifest}");
    }
    // The Windows build ships too: bhf's driver, which it links, and
    // build.ps1 in the family the harness was built with.
    for shipped in ["build.ps1", "runtime/bhf_driver.c"] {
        assert!(
            files.iter().any(|f| f == shipped),
            "the Windows build must ship {shipped}: {files:?}"
        );
    }
    assert_eq!(
        manifest["build_windows"], "powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1",
        "{manifest}"
    );
    assert_eq!(
        manifest["run_windows"], ".\\poc.exe input/testcase.bin",
        "{manifest}"
    );
    assert_eq!(manifest["requires_windows"][0]["env"], "CXX", "{manifest}");
    assert_eq!(
        manifest["build_recipe"]["windows_compiler_dialect"], "clang",
        "a clang-built harness rebuilds with clang on Windows: {manifest}"
    );
    let script = std::fs::read_to_string(cap.join("build.ps1")).unwrap();
    assert!(script.contains("$Recorded = 'clang'"), "{script}");
    assert!(script.contains("'/fsanitize=address'"), "{script}");
    let (pass, verify) = verify_from_scratch(&cap, "cpp");
    assert!(pass, "verify-poc should PASS offline; got:\n{verify}");

    // The manifest records the harness's input format and the finding's, and
    // a finding recorded against another format is flagged.
    let current = harness_gen::HARNESS_FORMAT_VERSION;
    assert_eq!(manifest["harness_format_version"], current, "{manifest}");
    assert_eq!(
        manifest["finding_harness_format_version"], current,
        "{manifest}"
    );
    assert!(manifest.get("harness_format_note").is_none(), "{manifest}");
    let record_path = finding_dir.join("finding.json");
    let mut record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&record_path).unwrap()).unwrap();
    // Readers take the format from `harness` first.
    record["harness"]["format_version"] = serde_json::json!(2);
    std::fs::write(&record_path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
    let packaged = capsule_for(&work, &id);
    let stderr = String::from_utf8_lossy(&packaged.stderr);
    assert!(
        stderr.contains("recorded against harness input format 2"),
        "the format difference must be flagged:\n{stderr}"
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(cap.join("manifest.json")).unwrap()).unwrap();
    assert!(
        manifest["harness_format_note"]
            .as_str()
            .is_some_and(|note| note.contains(&format!("decodes format {current}"))),
        "{manifest}"
    );
}

const DEFS_H: &str = "#define RECORD_CAP 4\n";

/// Heap overflow in a C target that includes a header by subdirectory.
const PARSE_RECORD_C: &str = "\
#include <stdlib.h>
#include <string.h>
#include \"inc/defs.h\"
int parse_record(const char *data, unsigned int len) {
    char *buf = malloc(RECORD_CAP);
    if (!buf) return 0;
    memcpy(buf, data, len);
    int r = len ? buf[0] : 0;
    free(buf);
    return r;
}
";

/// `generate-harness --id <harness_id>`, `build` and `fuzz` for `target` in
/// `source`; the id of the crash finding the fuzz run recorded.
fn manual_workflow(work: &Path, source: &Path, target: &str, harness_id: &str) -> String {
    let step = |args: &[&std::ffi::OsStr]| {
        let out = bhf().args(args).output().expect("run bhf");
        assert!(
            out.status.success(),
            "bhf {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    let generated = work.join("generated_harnesses");
    step(&[
        "generate-harness".as_ref(),
        "--target".as_ref(),
        target.as_ref(),
        "--id".as_ref(),
        harness_id.as_ref(),
        "--output".as_ref(),
        generated.as_os_str(),
        source.as_os_str(),
    ]);
    step(&[
        "build".as_ref(),
        work.as_os_str(),
        "--harness".as_ref(),
        harness_id.as_ref(),
    ]);
    let fuzz = bhf()
        .arg("fuzz")
        .arg(work)
        .args(["--harness", harness_id, "--time", "4s"])
        .output()
        .expect("run bhf fuzz");
    crash_finding(work, |h| h == harness_id)
        .unwrap_or_else(|| {
            panic!(
                "fuzz produced no finding: {}",
                String::from_utf8_lossy(&fuzz.stderr)
            )
        })
        .0
}

/// A C harness made by hand with a custom `--id` (generate-harness, build,
/// fuzz) lives in `generated_harnesses/` and `build/`, not `harnesses/`: its
/// finding still packages, keeps the `inc/defs.h` include working, and
/// verifies offline.
#[test]
fn custom_id_c_harness_from_the_manual_workflow_round_trips() {
    if !clang_available() {
        eprintln!("skipping: clang not installed");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let src = root.path().join("proj/src");
    let work = root.path().join("work");
    std::fs::create_dir_all(src.join("inc")).unwrap();
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(src.join("inc/defs.h"), DEFS_H).unwrap();
    std::fs::write(src.join("parse.c"), PARSE_RECORD_C).unwrap();
    let id = manual_workflow(&work, &src.join("parse.c"), "parse_record", "parseRecord");
    let packaged = capsule_for(&work, &id);
    let stdout = String::from_utf8_lossy(&packaged.stdout);
    assert!(
        packaged.status.success() && stdout.contains("1 verified to reproduce"),
        "capsule must package the custom-id harness; stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&packaged.stderr)
    );
    let cap = work.join("capsules").join(format!("capsule_{id}"));
    let files = files_under(&cap);
    assert!(
        files.iter().any(|f| f.ends_with("/inc/defs.h")),
        "the header must keep its inc/ subdirectory: {files:?}"
    );
    let (pass, verify) = verify_from_scratch(&cap, "custom-id");
    assert!(pass, "verify-poc should PASS offline; got:\n{verify}");
}

/// A crash finding whose harness cannot be packaged: an Ada harness that was
/// never built (no `build/<id>/bhf_build.gpr`).
fn write_unsupported_lane_finding(work: &Path, id: &str) {
    let harness_id = "H-A0003-0000ABCD";
    let finding_dir = work.join("results/findings").join(id);
    std::fs::create_dir_all(&finding_dir).unwrap();
    std::fs::write(finding_dir.join("testcase.bin"), b"AAAA").unwrap();
    std::fs::write(finding_dir.join("replay.py"), b"print('replay')\n").unwrap();
    std::fs::write(
        finding_dir.join("finding.json"),
        serde_json::json!({
            "id": id,
            "classification": "unhandled",
            "harness_id": harness_id,
        })
        .to_string(),
    )
    .unwrap();
    let harness = work.join("harnesses").join(harness_id);
    std::fs::create_dir_all(&harness).unwrap();
    std::fs::write(
        harness.join("generation-metadata.json"),
        br#"{"schema_version":1,"language":"ada"}"#,
    )
    .unwrap();
}

/// A requested finding the capsule cannot package is refused with its own
/// reason and a command that does reproduce it, exits non-zero, and leaves no
/// output behind; a mistyped id is reported as not found; a run over a work
/// dir with nothing it can package exits non-zero too.
#[test]
fn a_refused_finding_exits_non_zero_with_its_reason() {
    let root = tempfile::tempdir().unwrap();
    let work = root.path().join("work");
    write_unsupported_lane_finding(&work, "F-0001-0000aaaa");

    let refused = capsule_for(&work, "F-0001-0000aaaa");
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(!refused.status.success(), "{stderr}");
    assert!(
        stderr.contains("F-0001-0000aaaa")
            && stderr.contains("H-A0003-0000ABCD")
            && stderr.contains("Ada"),
        "the refusal must name the finding, its harness and its language:\n{stderr}"
    );
    // replay.py would find no harness to run: it is not offered.
    assert!(
        !stderr.contains("replay.py"),
        "replay.py cannot run a harness that was never built:\n{stderr}"
    );
    assert!(
        !work.join("capsules").exists(),
        "a refused run must not leave an output dir behind"
    );
    // With a built harness replay.py runs it: it is offered.
    std::fs::write(work.join("harnesses/H-A0003-0000ABCD/main"), b"\x7fELF").unwrap();
    let refused = capsule_for(&work, "F-0001-0000aaaa");
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(!refused.status.success(), "{stderr}");
    assert!(
        stderr.contains("replay.py"),
        "the refusal must offer a working alternative:\n{stderr}"
    );
    std::fs::remove_file(work.join("harnesses/H-A0003-0000ABCD/main")).unwrap();

    let typo = capsule_for(&work, "F-0001-0000aaab");
    let stderr = String::from_utf8_lossy(&typo.stderr);
    assert!(!typo.status.success(), "{stderr}");
    assert!(
        stderr.contains("no finding with id F-0001-0000aaab"),
        "an unknown id is not an eligibility problem:\n{stderr}"
    );

    let everything = bhf()
        .arg("capsule")
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run bhf capsule");
    let stderr = String::from_utf8_lossy(&everything.stderr);
    assert!(
        !everything.status.success(),
        "packaging nothing from a work dir with crash findings must fail:\n{stderr}"
    );
    assert!(stderr.contains("F-0001-0000aaaa"), "{stderr}");
    assert!(!work.join("capsules").exists());
}

/// `verify-poc` on a path that does not exist says so, and how to make one,
/// instead of reporting a format problem.
#[test]
fn verify_poc_on_a_missing_capsule_says_it_does_not_exist() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("work/capsules/capsule_F-0002-0000bbbb");
    let out = bhf()
        .arg("verify-poc")
        .arg(&missing)
        .output()
        .expect("run bhf verify-poc");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains("no capsule at"), "{stderr}");
    assert!(
        stderr.contains("bhf capsule --work-dir") && stderr.contains("F-0002-0000bbbb"),
        "the error must say how to make the capsule:\n{stderr}"
    );
}

/// The Makefile `bhf build`/`bhf auto` generate for a C harness, cut to the
/// `main` rule: target sources sit between `main.c` and the first make variable.
fn c_harness_makefile(runtime: &Path, src_dir: &Path, target: &Path) -> String {
    format!(
        "C_STD ?=\n\
         C_STD_FLAG := $(if $(C_STD),-std=$(C_STD),)\n\
         CFLAGS ?= -O1 -g -fsanitize=address,undefined\n\
         INCLUDES = -I . -I {runtime} -iquote {src} -idirafter {src}\n\
         COMPILE_DB_FLAGS = \n\
         main: main.c\n\
         \t$(CC) $(CFLAGS) $(COMPILE_DB_FLAGS) $(C_STD_FLAG) $(INCLUDES) $(AUTO_EXTRA_INCLUDES) -DBHF_EXTERNAL_DRIVER -o $@ main.c {target} $(AUTO_EXTRA_SOURCES) $(AUTO_EXTRA_LDFLAGS)\n",
        runtime = make_path(runtime),
        src = make_path(src_dir),
        target = make_path(target),
    )
}

/// A standalone driver: reads `argv[1]` and calls the target.
const DRIVER_C: &str = "\
#include <stdio.h>
int parse_record(const char *data, unsigned int len);
int main(int argc, char **argv) {
    char buf[64];
    FILE *f = argc > 1 ? fopen(argv[1], \"rb\") : NULL;
    if (!f) return 0;
    unsigned int n = (unsigned int)fread(buf, 1, sizeof buf, f);
    fclose(f);
    return parse_record(buf, n);
}
";

/// Builds only as C89 (an undeclared call) and links only with `helper.c`.
const LEGACY_TARGET_C: &str = "\
#include <stdlib.h>
#include <string.h>
int parse_record(const char *data, unsigned int len) {
    char *buf = malloc(record_cap());
    memcpy(buf, data, len);
    return buf[0];
}
";

const HELPER_C: &str = "int record_cap(void) { return 4; }\n";

/// The language standard and the extra sources bhf recorded for a harness
/// build (`coverage-build-recipe.json`) are not in its Makefile; a capsule
/// that ignored them could not rebuild the crash.
#[test]
fn capsule_applies_the_recorded_build_recipe() {
    if !clang_available() {
        eprintln!("skipping: clang not installed");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let src = root.path().join("proj");
    let work = root.path().join("work");
    let harness_id = "H-C0001-0000C0DE";
    let harness = work.join("harnesses").join(harness_id);
    std::fs::create_dir_all(src.join("extra")).unwrap();
    std::fs::create_dir_all(&harness).unwrap();
    std::fs::write(src.join("legacy.c"), LEGACY_TARGET_C).unwrap();
    std::fs::write(src.join("extra/helper.c"), HELPER_C).unwrap();
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime");
    std::fs::write(
        harness.join("Makefile"),
        c_harness_makefile(&runtime, &src, &src.join("legacy.c")),
    )
    .unwrap();
    std::fs::write(harness.join("main.c"), DRIVER_C).unwrap();
    std::fs::write(
        harness.join("generation-metadata.json"),
        br#"{"schema_version":1,"language":"c"}"#,
    )
    .unwrap();
    std::fs::write(
        harness.join("coverage-build-recipe.json"),
        serde_json::json!({
            "schema_version": 1,
            "native": true,
            "extra_sources": [src.join("extra/helper.c")],
            "extra_includes": [],
            "standard": "gnu89",
        })
        .to_string(),
    )
    .unwrap();
    let id = "F-0003-0000cccc";
    let finding_dir = work.join("results/findings").join(id);
    std::fs::create_dir_all(&finding_dir).unwrap();
    std::fs::write(finding_dir.join("testcase.bin"), b"0123456789abcdef").unwrap();
    std::fs::write(
        finding_dir.join("finding.json"),
        serde_json::json!({"id": id, "classification": "unhandled", "harness_id": harness_id})
            .to_string(),
    )
    .unwrap();

    let packaged = capsule_for(&work, id);
    let stdout = String::from_utf8_lossy(&packaged.stdout);
    assert!(
        packaged.status.success() && stdout.contains("1 verified to reproduce"),
        "the recorded recipe must be applied; stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&packaged.stderr)
    );
    let cap = work.join("capsules").join(format!("capsule_{id}"));
    let build = std::fs::read_to_string(cap.join("build.sh")).unwrap();
    assert!(build.contains("-std=gnu89"), "{build}");
    assert!(build.contains("helper.c"), "{build}");
    let (pass, verify) = verify_from_scratch(&cap, "recipe");
    assert!(pass, "verify-poc should PASS offline; got:\n{verify}");
    // The finding recorded no sanitizer report: the capsule says why it has no
    // identity to compare, and verify-poc does not call it an older capsule.
    let manifest_path = cap.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    assert_eq!(
        manifest["identity_comparison"]["verdict"], "none",
        "{manifest}"
    );
    assert!(!verify.contains("older bhf"), "{verify}");
    assert!(verify.contains("recorded no sanitizer report"), "{verify}");
    // A capsule packaged before the field existed is noted as such.
    manifest
        .as_object_mut()
        .unwrap()
        .remove("identity_comparison");
    std::fs::write(&manifest_path, manifest.to_string()).unwrap();
    let (pass, verify) = verify_from_scratch(&cap, "recipe-older");
    assert!(pass, "verify-poc should PASS offline; got:\n{verify}");
    assert!(verify.contains("older bhf"), "{verify}");

    // A run over every finding packages what it can, names what it skipped,
    // and succeeds.
    write_unsupported_lane_finding(&work, "F-0004-0000dddd");
    let all = bhf()
        .arg("capsule")
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run bhf capsule");
    let stdout = String::from_utf8_lossy(&all.stdout);
    let stderr = String::from_utf8_lossy(&all.stderr);
    assert!(all.status.success(), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("1 capsule(s) written") && stdout.contains("1 finding(s) skipped"),
        "{stdout}"
    );
    assert!(
        stderr.contains("F-0004-0000dddd skipped: Ada harness H-A0003-0000ABCD")
            && stderr.contains("never built"),
        "{stderr}"
    );
}

/// Needs `RECORD_CAP` from the build: the compile database supplies it.
const NEEDS_DEFINE_H: &str = "\
#ifndef RECORD_CAP
#error RECORD_CAP comes from the build
#endif
";

/// A target with an exact compile-database row is compiled as its own
/// translation unit with that row's flags, outside the Makefile's `main`
/// sources. The capsule must compile and link that unit the same way.
#[test]
fn capsule_links_per_translation_unit_objects() {
    if !clang_available() {
        eprintln!("skipping: clang not installed");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let proj = root.path().join("proj");
    let work = root.path().join("work");
    std::fs::create_dir_all(proj.join("src/inc")).unwrap();
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(proj.join("src/inc/defs.h"), NEEDS_DEFINE_H).unwrap();
    std::fs::write(proj.join("src/parse.c"), PARSE_RECORD_C).unwrap();
    std::fs::write(
        proj.join("compile_commands.json"),
        serde_json::json!([{
            "directory": proj,
            "file": proj.join("src/parse.c"),
            "arguments": ["clang", "-DRECORD_CAP=4", "-c", "src/parse.c", "-o", "parse.o"],
        }])
        .to_string(),
    )
    .unwrap();
    let id = manual_workflow(
        &work,
        &proj.join("src/parse.c"),
        "parse_record",
        "unitParse",
    );
    assert!(
        work.join("generated_harnesses/unitParse/build_context_objects.mk")
            .is_file(),
        "the fixture must exercise a per-translation-unit build"
    );

    let packaged = capsule_for(&work, &id);
    let stdout = String::from_utf8_lossy(&packaged.stdout);
    assert!(
        packaged.status.success() && stdout.contains("1 verified to reproduce"),
        "capsule must link the per-TU object; stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&packaged.stderr)
    );
    let cap = work.join("capsules").join(format!("capsule_{id}"));
    let build = std::fs::read_to_string(cap.join("build.sh")).unwrap();
    assert!(
        build.contains("-c sources/parse.c -o obj/unit_0.o"),
        "{build}"
    );
    assert!(!cap.join("obj").exists(), "build outputs are not shipped");
    let (pass, verify) = verify_from_scratch(&cap, "per-tu");
    assert!(pass, "verify-poc should PASS offline; got:\n{verify}");
}

/// Falls off the end of a value-returning function on an empty input only, so
/// every crash input it records is 0 bytes and the crash is UBSan's.
const CLASSIFY_CPP: &str = "\
#include <cstddef>
int classify_record(const char *data, std::size_t len) {
    if (len > 0) return data[0];
}
";

/// A C++ UndefinedBehaviorSanitizer finding whose crash input is empty
/// packages, ships the 0-byte input, and verifies offline.
#[test]
fn cpp_ubsan_finding_with_an_empty_input_round_trips_offline() {
    if !clangxx_available() {
        eprintln!("skipping: clang++ not installed");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let tree = root.path().join("proj");
    let work = root.path().join("work");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("classify.cpp"), CLASSIFY_CPP).unwrap();
    let out = bhf()
        .arg("auto")
        .arg(&tree)
        .arg("--work-dir")
        .arg(&work)
        .args([
            "--languages",
            "cpp",
            "--max-targets",
            "1",
            "--jobs",
            "1",
            "--per-target-time",
            "6",
            "--no-discovery-cache",
        ])
        .output()
        .expect("run bhf auto");
    let (id, finding_dir) = crash_finding(&work, |h| h.starts_with("H-X")).unwrap_or_else(|| {
        panic!(
            "auto produced no C++ crash finding: {}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    let finding: serde_json::Value =
        serde_json::from_slice(&std::fs::read(finding_dir.join("finding.json")).unwrap()).unwrap();
    assert_eq!(finding["exception"]["sanitizer"], "ubsan", "{finding}");
    assert_eq!(
        std::fs::metadata(finding_dir.join("testcase.bin"))
            .unwrap()
            .len(),
        0,
        "the fixture must record an empty crash input"
    );

    let packaged = capsule_for(&work, &id);
    let stdout = String::from_utf8_lossy(&packaged.stdout);
    assert!(
        packaged.status.success()
            && stdout.contains("1 verified to reproduce")
            && stdout.contains("UndefinedBehaviorSanitizer"),
        "capsule must reproduce the UBSan finding; stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&packaged.stderr)
    );
    let cap = work.join("capsules").join(format!("capsule_{id}"));
    assert_eq!(
        std::fs::metadata(cap.join("input/testcase.bin"))
            .unwrap()
            .len(),
        0
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(cap.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["lang"], "cpp", "{manifest}");
    assert_eq!(
        manifest["expected_signature"], "UndefinedBehaviorSanitizer:runtime-error",
        "{manifest}"
    );
    let (pass, verify) = verify_from_scratch(&cap, "cpp-ubsan");
    assert!(pass, "verify-poc should PASS offline; got:\n{verify}");
}

/// An executable shell script at `path`.
fn write_script(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

/// A crash finding of `harness_id` with `input` as its crash input.
fn write_crash_finding(work: &Path, id: &str, harness_id: &str, input: &[u8]) {
    let finding_dir = work.join("results/findings").join(id);
    std::fs::create_dir_all(&finding_dir).unwrap();
    std::fs::write(finding_dir.join("testcase.bin"), input).unwrap();
    std::fs::write(
        finding_dir.join("finding.json"),
        serde_json::json!({"id": id, "classification": "unhandled", "harness_id": harness_id})
            .to_string(),
    )
    .unwrap();
}

/// Heap overflow in `lib/parse.c`, which reaches its header through `..`.
const PARSE_RECORD_PARENT_C: &str = "\
#include <stdlib.h>
#include <string.h>
#include \"../common/defs.h\"
int parse_record(const char *data, unsigned int len) {
    char *buf = malloc(RECORD_CAP);
    if (!buf) return 0;
    memcpy(buf, data, len);
    int r = len ? buf[0] : 0;
    free(buf);
    return r;
}
";

/// When the compiler cannot list a build's includes, the fallback still
/// ships a header a source reaches through `..`, outside every include root,
/// and the capsule keeps the tree's layout.
#[test]
fn a_header_reached_through_a_parent_dir_ships_without_compiler_dependency_output() {
    if !clang_available() {
        eprintln!("skipping: clang not installed");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let proj = root.path().join("proj");
    let work = root.path().join("work");
    let harness_id = "H-C0001-0000D00D";
    let harness = work.join("harnesses").join(harness_id);
    std::fs::create_dir_all(proj.join("lib")).unwrap();
    std::fs::create_dir_all(proj.join("common")).unwrap();
    std::fs::create_dir_all(&harness).unwrap();
    std::fs::write(proj.join("common/defs.h"), DEFS_H).unwrap();
    std::fs::write(proj.join("lib/parse.c"), PARSE_RECORD_PARENT_C).unwrap();
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime");
    std::fs::write(
        harness.join("Makefile"),
        c_harness_makefile(&runtime, &proj.join("lib"), &proj.join("lib/parse.c")),
    )
    .unwrap();
    std::fs::write(harness.join("main.c"), DRIVER_C).unwrap();
    std::fs::write(
        harness.join("generation-metadata.json"),
        br#"{"schema_version":1,"language":"c"}"#,
    )
    .unwrap();
    let id = "F-0007-0000eeee";
    write_crash_finding(&work, id, harness_id, b"0123456789");
    // A compiler that builds but cannot print dependency rules.
    let cc = root.path().join("cc-no-deps");
    write_script(
        &cc,
        "#!/bin/sh\nfor arg in \"$@\"; do [ \"$arg\" = -M ] && exit 1; done\nexec clang \"$@\"\n",
    );

    let packaged = bhf()
        .arg("capsule")
        .arg("--work-dir")
        .arg(&work)
        .args(["--finding-id", id, "--verbose"])
        .env("CC", &cc)
        .output()
        .expect("run bhf capsule");
    let stdout = String::from_utf8_lossy(&packaged.stdout);
    assert!(
        packaged.status.success() && stdout.contains("1 verified to reproduce"),
        "the fallback must ship ../common/defs.h; stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&packaged.stderr)
    );
    let cap = work.join("capsules").join(format!("capsule_{id}"));
    let files = files_under(&cap);
    assert!(
        files.iter().any(|f| f == "sources/common/defs.h")
            && files.iter().any(|f| f == "sources/lib/parse.c"),
        "{files:?}"
    );
    let (pass, verify) = verify_from_scratch(&cap, "parent-header");
    assert!(pass, "verify-poc should PASS offline; got:\n{verify}");
}

/// A C++ harness Makefile cut to the `main` rule.
fn cpp_harness_makefile(src_dir: &Path, target: &Path) -> String {
    format!(
        "CXX_STD ?= c++17\n\
         CXXFLAGS ?= -O1 -g -fsanitize=address,undefined -std=$(CXX_STD)\n\
         INCLUDES = -I . -iquote {src}\n\
         COMPILE_DB_FLAGS = \n\
         main: main.cpp\n\
         \t$(CXX) $(CXXFLAGS) $(COMPILE_DB_FLAGS) $(INCLUDES) $(AUTO_EXTRA_INCLUDES) -o $@ main.cpp {target} $(AUTO_EXTRA_SOURCES) $(AUTO_EXTRA_LDFLAGS)\n",
        src = make_path(src_dir),
        target = make_path(target),
    )
}

/// A standalone C++ driver: reads `argv[1]` and calls the method.
const DRIVER_CPP: &str = "\
#include <cstdio>
#include <string>
#include \"include/widget.h\"
int main(int argc, char **argv) {
    if (argc < 2) return 0;
    std::FILE *f = std::fopen(argv[1], \"rb\");
    if (!f) return 0;
    char buf[64];
    std::size_t n = std::fread(buf, 1, sizeof buf, f);
    std::fclose(f);
    std::string bytes(buf, n);
    Widget w;
    return w.copy_at(bytes.data(), bytes.size());
}
";

/// Where clang++ cannot find the C++ standard headers on its own (it picked a
/// GCC install without them), bhf's builds add the installed libstdc++
/// headers; the capsule's dependency scan and its build.sh do the same.
#[test]
fn cpp_capsule_rebuilds_where_the_compiler_misses_the_standard_headers() {
    if !clangxx_available() {
        eprintln!("skipping: clang++ not installed");
        return;
    }
    let has_libstdcxx = std::fs::read_dir("/usr/include/c++")
        .into_iter()
        .flatten()
        .flatten()
        .any(|entry| entry.path().join("string").is_file());
    if !has_libstdcxx {
        eprintln!("skipping: no libstdc++ headers under /usr/include/c++");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let proj = root.path().join("proj");
    let work = root.path().join("work");
    let harness_id = "H-X0001-0000F00D";
    let harness = work.join("harnesses").join(harness_id);
    std::fs::create_dir_all(proj.join("include")).unwrap();
    std::fs::create_dir_all(&harness).unwrap();
    std::fs::write(proj.join("include/widget.h"), WIDGET_H).unwrap();
    std::fs::write(proj.join("widget.cpp"), WIDGET_CPP).unwrap();
    std::fs::write(
        harness.join("Makefile"),
        cpp_harness_makefile(&proj, &proj.join("widget.cpp")),
    )
    .unwrap();
    std::fs::write(harness.join("main.cpp"), DRIVER_CPP).unwrap();
    std::fs::write(
        harness.join("generation-metadata.json"),
        br#"{"schema_version":1,"language":"cpp"}"#,
    )
    .unwrap();
    let id = "F-0006-0000ffff";
    write_crash_finding(&work, id, harness_id, b"0123456789");
    // clang++ that does not search its C++ standard-library dirs.
    let cxx = root.path().join("cxx-no-stdlib");
    write_script(&cxx, "#!/bin/sh\nexec clang++ -nostdinc++ \"$@\"\n");

    let packaged = bhf()
        .arg("capsule")
        .arg("--work-dir")
        .arg(&work)
        .args(["--finding-id", id, "--verbose"])
        .env("CXX", &cxx)
        .output()
        .expect("run bhf capsule");
    let stdout = String::from_utf8_lossy(&packaged.stdout);
    let stderr = String::from_utf8_lossy(&packaged.stderr);
    assert!(
        packaged.status.success() && stdout.contains("1 verified to reproduce"),
        "the capsule must recover the standard headers; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !stdout.contains("could not list the build's includes"),
        "the dependency scan must use the recovered headers too:\n{stdout}"
    );
    let cap = work.join("capsules").join(format!("capsule_{id}"));
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(cap.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(
        manifest["build_recipe"]["stdlib_include_fallback"], true,
        "{manifest}"
    );

    // The shipped build.sh recovers them on its own, offline.
    let scratch = tempfile::tempdir().unwrap();
    let dest = scratch.path().join("cap");
    copy_tree(&cap, &dest);
    let verify = bhf()
        .arg("verify-poc")
        .arg(&dest)
        .env("CXX", &cxx)
        .output()
        .expect("run bhf verify-poc");
    let verify_out = String::from_utf8_lossy(&verify.stdout);
    assert!(
        verify.status.success() && verify_out.contains("PASS"),
        "verify-poc should PASS with the same compiler; stdout:\n{verify_out}\nstderr:\n{}",
        String::from_utf8_lossy(&verify.stderr)
    );
}

/// A C harness bhf built with gcc packages into a capsule that rebuilds with
/// gcc and gcc's sanitizer flags, whether or not `$CC` is set when it is
/// packaged or verified (the compiler is read off the harness binary).
#[test]
#[cfg_attr(
    windows,
    ignore = "gcc has no sanitizer runtime on Windows, where C harnesses build with clang or \
              cl; see docs/site/windows.md"
)]
fn a_gcc_built_harness_capsule_rebuilds_with_gcc() {
    if which::which("gcc").is_err() {
        eprintln!("skipping: gcc not installed");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let tree = root.path().join("proj");
    let work = root.path().join("work");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("parse_header.c"), OVERFLOW_C).unwrap();
    let out = bhf()
        .arg("auto")
        .arg(&tree)
        .arg("--work-dir")
        .arg(&work)
        .args(["--languages", "c", "--max-targets", "1", "--jobs", "1"])
        .args(["--per-target-time", "6", "--no-discovery-cache"])
        .env("CC", "gcc")
        .output()
        .expect("run bhf auto");
    let Some((id, _)) = crash_finding(&work, |_| true) else {
        panic!(
            "bhf auto (CC=gcc) found no crash: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    let packaged = bhf()
        .arg("capsule")
        .arg("--work-dir")
        .arg(&work)
        .args(["--finding-id", &id])
        .env_remove("CC")
        .output()
        .expect("run bhf capsule");
    let stdout = String::from_utf8_lossy(&packaged.stdout);
    assert!(
        packaged.status.success() && stdout.contains("1 verified to reproduce"),
        "{stdout}\n{}",
        String::from_utf8_lossy(&packaged.stderr)
    );
    let cap = work.join("capsules").join(format!("capsule_{id}"));
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(cap.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["build_recipe"]["compiler"], "gcc", "{manifest}");
    assert_eq!(
        manifest["build_recipe"]["compiler_family"], "gcc",
        "{manifest}"
    );
    assert_eq!(manifest["requires"][0]["program"], "gcc", "{manifest}");
    let script = std::fs::read_to_string(cap.join("build.sh")).unwrap();
    assert!(script.contains("CC=\"${CC:-gcc}\""), "{script}");
    for cc in [None, Some("gcc")] {
        let scratch = tempfile::tempdir().unwrap();
        let dest = scratch.path().join("cap");
        copy_tree(&cap, &dest);
        let mut verify = bhf();
        verify.arg("verify-poc").arg(&dest);
        match cc {
            Some(cc) => verify.env("CC", cc),
            None => verify.env_remove("CC"),
        };
        let verified = verify.output().expect("run bhf verify-poc");
        let verify_out = String::from_utf8_lossy(&verified.stdout);
        assert!(
            verified.status.success() && verify_out.contains("PASS"),
            "verify-poc with CC={cc:?} must rebuild with gcc's flags; stdout:\n{verify_out}\nstderr:\n{}",
            String::from_utf8_lossy(&verified.stderr)
        );
    }
}

/// On native Windows a C target whose compiler is gcc is refused, naming the
/// compiler and what to use instead: GCC has no sanitizer runtime there, and
/// the build would fail at the link in words that read like a missing header.
#[cfg(windows)]
#[test]
fn a_gcc_compiler_is_refused_for_c_on_native_windows() {
    if which::which("gcc").is_err() {
        eprintln!("skipping: gcc not installed");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let tree = root.path().join("proj");
    let work = root.path().join("work");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("parse_header.c"), OVERFLOW_C).unwrap();
    let out = bhf()
        .arg("auto")
        .arg(&tree)
        .arg("--work-dir")
        .arg(&work)
        .args(["--languages", "c", "--max-targets", "1", "--jobs", "1"])
        .args(["--per-target-time", "2", "--no-discovery-cache"])
        .env("CC", "gcc")
        .output()
        .expect("run bhf auto");
    let report: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work.join("auto/run.json")).unwrap_or_else(|error| {
            panic!(
                "run.json: {error}\n{}",
                String::from_utf8_lossy(&out.stderr)
            )
        }),
    )
    .unwrap();
    let outcome = &report["targets"][0]["outcome"];
    assert_eq!(outcome["outcome"], "report_only", "{outcome}");
    assert_eq!(
        outcome["reason"],
        "CC=gcc is GCC, which ships no AddressSanitizer or UBSan runtime on Windows, and the \
         harness links both: build C and C++ harnesses with clang or cl (`--cc cl`) on native \
         Windows, pass `--sanitizers none` for a crash-only gcc build, or run under WSL (see \
         docs/site/windows.md) — discovered and statically analyzed, not fuzzed",
        "{outcome}"
    );
}

/// A launcher in front of the compiler (`CXX="ccache clang++"`) works for
/// the capsule's include scan and for its build.sh, as it does for make.
// The launcher is a POSIX shell script, which Windows cannot run as a program.
#[cfg(unix)]
#[test]
fn a_cpp_capsule_builds_through_a_compiler_launcher() {
    if !clangxx_available() {
        eprintln!("skipping: clang++ not installed");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let proj = root.path().join("proj");
    let work = root.path().join("work");
    let harness_id = "H-X0001-0000F00E";
    let harness = work.join("harnesses").join(harness_id);
    std::fs::create_dir_all(proj.join("include")).unwrap();
    std::fs::create_dir_all(&harness).unwrap();
    std::fs::write(proj.join("include/widget.h"), WIDGET_H).unwrap();
    std::fs::write(proj.join("widget.cpp"), WIDGET_CPP).unwrap();
    std::fs::write(
        harness.join("Makefile"),
        cpp_harness_makefile(&proj, &proj.join("widget.cpp")),
    )
    .unwrap();
    std::fs::write(harness.join("main.cpp"), DRIVER_CPP).unwrap();
    std::fs::write(
        harness.join("generation-metadata.json"),
        br#"{"schema_version":1,"language":"cpp"}"#,
    )
    .unwrap();
    let id = "F-0007-0000eeee";
    write_crash_finding(&work, id, harness_id, b"0123456789");
    // A compiler launcher in the shape of ccache: it runs the rest of its words.
    let launcher = root.path().join("fake-ccache");
    write_script(&launcher, "#!/bin/sh\nexec \"$@\"\n");
    let cxx = format!("{} clang++", launcher.display());

    let packaged = bhf()
        .arg("capsule")
        .arg("--work-dir")
        .arg(&work)
        .args(["--finding-id", id, "--verbose"])
        .env("CXX", &cxx)
        .output()
        .expect("run bhf capsule");
    let stdout = String::from_utf8_lossy(&packaged.stdout);
    let stderr = String::from_utf8_lossy(&packaged.stderr);
    assert!(
        packaged.status.success() && stdout.contains("1 verified to reproduce"),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("could not list the build's includes"),
        "the include scan must run the launcher-prefixed compiler: {stderr}"
    );
    let cap = work.join("capsules").join(format!("capsule_{id}"));
    let scratch = tempfile::tempdir().unwrap();
    let dest = scratch.path().join("cap");
    copy_tree(&cap, &dest);
    let verified = bhf()
        .arg("verify-poc")
        .arg(&dest)
        .env("CXX", &cxx)
        .output()
        .expect("run bhf verify-poc");
    let verify_out = String::from_utf8_lossy(&verified.stdout);
    assert!(
        verified.status.success() && verify_out.contains("PASS"),
        "stdout:\n{verify_out}\nstderr:\n{}",
        String::from_utf8_lossy(&verified.stderr)
    );
}

/// `verify-poc` takes the capsule path relative to the current dir, the way
/// `bhf explain` and the docs print it (`bhf verify-poc
/// <work>/capsules/capsule_<id>`): the rebuilt PoC is run from the capsule
/// dir, so its path must not be resolved against that dir again.
#[test]
fn a_capsule_verifies_through_a_path_relative_to_the_current_dir() {
    if !clang_available() {
        eprintln!("skipping: clang not installed");
        return;
    }
    let root = tempfile::Builder::new()
        .prefix("bhf-cap-relative-")
        .tempdir()
        .unwrap();
    let work = root.path().join("work");
    snippet_into(OVERFLOW_C, &work);
    let stdout = build_capsule(&work, false);
    assert!(
        stdout.contains("verified to reproduce"),
        "capsule stdout:\n{stdout}"
    );
    let cap = only_capsule(&work);
    let relative = Path::new("work")
        .join("capsules")
        .join(cap.file_name().unwrap());
    let out = bhf()
        .arg("verify-poc")
        .arg(&relative)
        .current_dir(root.path())
        .output()
        .expect("run bhf verify-poc");
    let verify_out = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && verify_out.contains("PASS"),
        "verify-poc {} from {} must PASS; stdout:\n{verify_out}\nstderr:\n{}",
        relative.display(),
        root.path().display(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !cap.join("poc").exists(),
        "verify-poc leaves the capsule as it found it"
    );
}

/// `bhf auto` on `files` (written under `<root>/src`) for `language`, with a
/// seconds-scale budget; the work dir.
#[cfg(unix)]
fn auto_tree(root: &Path, files: &[(&str, &str)], language: &str) -> (std::path::PathBuf, String) {
    let tree = root.join("src");
    for (name, text) in files {
        let path = tree.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    let work = root.join("work");
    let out = bhf()
        .arg("auto")
        .arg(&tree)
        .arg("--work-dir")
        .arg(&work)
        .args(["--languages", language, "--max-targets", "1", "--jobs", "1"])
        .args(["--per-target-time", "6", "--no-discovery-cache"])
        .output()
        .expect("run bhf auto");
    (work, String::from_utf8_lossy(&out.stderr).into_owned())
}

/// The crash finding whose `exception.name` contains `name`.
#[cfg(unix)]
fn finding_named(work: &Path, name: &str) -> Option<(String, std::path::PathBuf)> {
    findings(work).into_iter().find_map(|(id, dir, raw)| {
        let named = raw["exception"]["name"]
            .as_str()
            .is_some_and(|recorded| recorded.contains(name));
        (raw["classification"] == "unhandled" && named && dir.join("testcase.bin").is_file())
            .then_some((id, dir))
    })
}

/// The files under `dir` whose text has an `#include "/..."` of an absolute
/// path.
#[cfg(unix)]
fn absolute_includes_under(dir: &Path) -> Vec<String> {
    files_under(dir)
        .into_iter()
        .filter(|rel| {
            std::fs::read_to_string(dir.join(rel)).is_ok_and(|text| {
                text.lines().any(|line| {
                    let line = line.trim_start();
                    line.starts_with("#include \"/") || line.starts_with("#import \"/")
                })
            })
        })
        .collect()
}

/// A C++ target calling a function its header declares and nothing defines:
/// bhf stubs it in `repairs/auto_stubs.cpp`, which includes the header by
/// its absolute path.
#[cfg(unix)]
const VENDOR_HPP: &str = "\
#pragma once
namespace vendor { int lookup(int key); }
";

#[cfg(unix)]
const LOOKUP_CPP: &str = "\
#include \"include/vendor.h\"
#include <cstdlib>
#include <cstring>
int parse_record(const char *data, unsigned long len) {
    int key = vendor::lookup(static_cast<int>(len));
    char *buf = static_cast<char *>(std::malloc(4));
    std::memcpy(buf, data, len);
    int r = buf[0] + key;
    std::free(buf);
    return r;
}
";

/// A capsule of a stub-dependent C++ target ships the stub with the header's
/// include relative to the capsule, so it rebuilds and reproduces with the
/// scanned tree and the work dir gone, and its manifest names neither.
// The build.sh round trip of a Linux toolchain; build.ps1 has its own.
#[cfg(unix)]
#[test]
fn a_cpp_capsule_with_a_header_backed_stub_rebuilds_without_the_tree() {
    if !clangxx_available() {
        eprintln!("skipping: clang++ not installed");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (work, stderr) = auto_tree(
        root.path(),
        &[("include/vendor.h", VENDOR_HPP), ("parse.cpp", LOOKUP_CPP)],
        "cpp",
    );
    let (id, _) = crash_finding(&work, |h| h.starts_with("H-X"))
        .unwrap_or_else(|| panic!("auto produced no C++ crash finding: {stderr}"));
    let packaged = capsule_for(&work, &id);
    let stdout = String::from_utf8_lossy(&packaged.stdout);
    assert!(
        packaged.status.success() && stdout.contains(&format!("capsule_{id}  (✓)")),
        "stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&packaged.stderr)
    );
    let cap = work.join("capsules").join(format!("capsule_{id}"));
    assert!(
        cap.join("stubs/auto_stubs.cpp").is_file(),
        "{:?}",
        files_under(&cap)
    );
    let absolute = absolute_includes_under(&cap.join("stubs"));
    assert!(
        absolute.is_empty(),
        "stubs keep absolute includes: {absolute:?}"
    );
    let stub = std::fs::read_to_string(cap.join("stubs/auto_stubs.cpp")).unwrap();
    assert!(
        stub.contains("#include \"../sources/include/vendor.h\""),
        "{stub}"
    );
    let manifest = std::fs::read_to_string(cap.join("manifest.json")).unwrap();
    for host in [root.path().join("src"), work.clone()] {
        assert!(
            !manifest.contains(&host.display().to_string()),
            "the manifest names {}:\n{manifest}",
            host.display()
        );
    }
    let manifest: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    assert_eq!(manifest["portable"], true, "{manifest}");
    let (pass, verify) = verify_from_scratch(&cap, "cpp-stub");
    assert!(
        pass,
        "verify-poc should PASS without the tree; got:\n{verify}"
    );
}

/// The C counterpart: a C header declares the function, and the stub that
/// defines it includes that header.
#[cfg(unix)]
const VENDOR_H: &str = "\
#pragma once
int vendor_lookup(int key);
";

#[cfg(unix)]
const LOOKUP_C: &str = "\
#include \"include/vendor.h\"
#include <stdlib.h>
#include <string.h>
int parse_record(const char *data, unsigned int len) {
    int key = vendor_lookup((int)len);
    char *buf = malloc(4);
    if (!buf) return 0;
    memcpy(buf, data, len);
    int r = buf[0] + key;
    free(buf);
    return r;
}
";

// The build.sh round trip of a Linux toolchain; build.ps1 has its own.
#[cfg(unix)]
#[test]
fn a_c_capsule_with_a_header_backed_stub_rebuilds_without_the_tree() {
    if !clang_available() {
        eprintln!("skipping: clang not installed");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (work, stderr) = auto_tree(
        root.path(),
        &[("include/vendor.h", VENDOR_H), ("parse.c", LOOKUP_C)],
        "c",
    );
    let (id, _) = crash_finding(&work, |h| h.starts_with("H-C"))
        .unwrap_or_else(|| panic!("auto produced no C crash finding: {stderr}"));
    let packaged = capsule_for(&work, &id);
    let stdout = String::from_utf8_lossy(&packaged.stdout);
    assert!(
        packaged.status.success() && stdout.contains(&format!("capsule_{id}  (✓)")),
        "stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&packaged.stderr)
    );
    let cap = work.join("capsules").join(format!("capsule_{id}"));
    let stub = std::fs::read_to_string(cap.join("stubs/auto_stubs.c")).unwrap();
    assert!(stub.contains("vendor_lookup"), "{stub}");
    let absolute = absolute_includes_under(&cap.join("stubs"));
    assert!(
        absolute.is_empty(),
        "stubs keep absolute includes: {absolute:?}"
    );
    let (pass, verify) = verify_from_scratch(&cap, "c-stub");
    assert!(
        pass,
        "verify-poc should PASS without the tree; got:\n{verify}"
    );
}

/// Overflows a signed int on any non-empty input, and falls off the end of
/// the function on an empty one.
#[cfg(unix)]
const SCORE_CPP: &str = "\
#include <climits>
#include <cstddef>
int score_record(const char *data, std::size_t len) {
    if (len > 0) {
        int total = INT_MAX - 64;
        for (std::size_t i = 0; i < len; i++) total += data[i];
        return total;
    }
}
";

/// verify-poc compares the crash field by field: a capsule of the overflow
/// finding fed the input that reaches the other check reports a MISMATCH
/// naming what differs, and fails.
// The build.sh round trip of a Linux toolchain; build.ps1 has its own.
#[cfg(unix)]
#[test]
fn verify_poc_reports_another_check_in_the_same_harness_as_a_mismatch() {
    if !clangxx_available() {
        eprintln!("skipping: clang++ not installed");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (work, stderr) = auto_tree(root.path(), &[("score.cpp", SCORE_CPP)], "cpp");
    let (id, _) = finding_named(&work, "SIGNED_INTEGER_OVERFLOW")
        .unwrap_or_else(|| panic!("auto recorded no signed-overflow finding: {stderr}"));
    let packaged = capsule_for(&work, &id);
    let stdout = String::from_utf8_lossy(&packaged.stdout);
    assert!(
        packaged.status.success() && stdout.contains("1 verified to reproduce"),
        "stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&packaged.stderr)
    );
    let cap = work.join("capsules").join(format!("capsule_{id}"));
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(cap.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(
        manifest["finding_identity"]["kind"], "signed-integer-overflow",
        "{manifest}"
    );
    // The same capsule, with the empty input that reaches the missing return.
    let scratch = tempfile::tempdir().unwrap();
    let copy = scratch.path().join("cap");
    assert!(Command::new("cp")
        .arg("-r")
        .arg(&cap)
        .arg(&copy)
        .status()
        .unwrap()
        .success());
    std::fs::write(copy.join("input/testcase.bin"), b"").unwrap();
    let verified = bhf()
        .arg("verify-poc")
        .arg(&copy)
        .output()
        .expect("run bhf verify-poc");
    let out = String::from_utf8_lossy(&verified.stdout);
    assert_eq!(verified.status.code(), Some(1), "{out}");
    assert!(out.contains("verify-poc: MISMATCH"), "{out}");
    assert!(!out.contains("PASS"), "{out}");
    assert!(
        out.contains("differs:  kind: recorded signed-integer-overflow")
            || out.contains("differs:  site:"),
        "the differing field is named:\n{out}"
    );
}

/// Overflows a heap buffer on inputs longer than four bytes, and dereferences
/// NULL on a three-byte input that starts with `Q`.
#[cfg(unix)]
const PARSE_OR_FAULT_C: &str = "\
#include <stdlib.h>
#include <string.h>
int parse_record(const char *data, unsigned int len) {
    if (len == 3 && data[0] == 'Q') {
        volatile char *p = (char *)0;
        return *p;
    }
    char *buf = malloc(4);
    if (!buf) return 0;
    memcpy(buf, data, len);
    int r = len ? buf[0] : 0;
    free(buf);
    return r;
}
";

/// A minimized input that crashes another way (a SEGV for a heap-overflow
/// finding) is not shipped as the finding's reproducer: the capsule ships the
/// recorded input, which reproduces the heap overflow.
// The build.sh round trip of a Linux toolchain; build.ps1 has its own.
#[cfg(unix)]
#[test]
fn a_minimized_input_with_another_crash_is_not_shipped() {
    if !clang_available() {
        eprintln!("skipping: clang not installed");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (work, stderr) = auto_tree(root.path(), &[("parse.c", PARSE_OR_FAULT_C)], "c");
    let (id, finding_dir) = finding_named(&work, "HEAP_BUFFER_OVERFLOW")
        .unwrap_or_else(|| panic!("auto recorded no heap-overflow finding: {stderr}"));
    std::fs::write(finding_dir.join("min_testcase.bin"), b"Qxy").unwrap();
    let packaged = capsule_for(&work, &id);
    let stdout = String::from_utf8_lossy(&packaged.stdout);
    let cap = work.join("capsules").join(format!("capsule_{id}"));
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(cap.join("manifest.json")).unwrap()).unwrap();
    assert!(
        !(stdout.contains("(✓)") && manifest["expected_signature"] == "AddressSanitizer:SEGV"),
        "a SEGV must never pass for the heap overflow:\n{stdout}\n{manifest}"
    );
    assert!(packaged.status.success(), "{stdout}");
    assert!(stdout.contains(&format!("capsule_{id}  (✓)")), "{stdout}");
    assert_eq!(manifest["input_source"], "testcase.bin", "{manifest}");
    assert_eq!(
        manifest["expected_signature"], "AddressSanitizer:heap-buffer-overflow",
        "{manifest}"
    );
    assert_eq!(
        std::fs::read(cap.join("input/testcase.bin")).unwrap(),
        std::fs::read(finding_dir.join("testcase.bin")).unwrap()
    );
}

/// Valid only before C++17: a dynamic exception specification and `register`.
#[cfg(unix)]
const LEGACY_CPP: &str = "\
#include <cstdlib>
#include <cstring>
int parse_record(const char *data, unsigned long len) throw(int) {
    register int first = 0;
    char *buf = static_cast<char *>(std::malloc(4));
    std::memcpy(buf, data, len);
    first = buf[0];
    std::free(buf);
    return first;
}
";

/// The language standard the dialect ladder built a legacy C++ target with
/// is recorded in its build recipe, so the capsule and the coverage replay
/// rebuild it with the same `-std`.
// The build.sh round trip of a Linux toolchain; build.ps1 has its own.
#[cfg(unix)]
#[test]
fn a_legacy_dialect_cpp_target_records_its_standard_for_the_capsule() {
    if !clangxx_available() {
        eprintln!("skipping: clang++ not installed");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (work, stderr) = auto_tree(root.path(), &[("legacy.cpp", LEGACY_CPP)], "cpp");
    let (id, finding_dir) = crash_finding(&work, |h| h.starts_with("H-X"))
        .unwrap_or_else(|| panic!("auto produced no C++ crash finding: {stderr}"));
    let raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(finding_dir.join("finding.json")).unwrap()).unwrap();
    let harness = work
        .join("harnesses")
        .join(raw["harness_id"].as_str().unwrap());
    let recipe: serde_json::Value =
        serde_json::from_slice(&std::fs::read(harness.join("coverage-build-recipe.json")).unwrap())
            .unwrap();
    assert_eq!(recipe["standard"], "gnu++14", "{recipe}");
    assert!(
        !harness.join("coverage-replay-diagnostic.txt").exists(),
        "the coverage build must use the recorded standard: {}",
        std::fs::read_to_string(harness.join("coverage-replay-diagnostic.txt")).unwrap_or_default()
    );
    let packaged = capsule_for(&work, &id);
    let stdout = String::from_utf8_lossy(&packaged.stdout);
    assert!(
        packaged.status.success() && stdout.contains(&format!("capsule_{id}  (✓)")),
        "stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&packaged.stderr)
    );
    let cap = work.join("capsules").join(format!("capsule_{id}"));
    let build = std::fs::read_to_string(cap.join("build.sh")).unwrap();
    assert!(build.contains("-std=gnu++14"), "{build}");
    let (pass, verify) = verify_from_scratch(&cap, "legacy-cpp");
    assert!(pass, "verify-poc should PASS offline; got:\n{verify}");
}

/// A capsule whose rebuild failed when it was packaged says so, with the
/// build's error, and verify-poc blames the build, not the crash's
/// circumstances.
// The build.sh round trip of a Linux toolchain; build.ps1 has its own.
#[cfg(unix)]
#[test]
fn verify_poc_names_the_rebuild_failure_of_a_capsule_that_never_built() {
    if !clang_available() {
        eprintln!("skipping: clang not installed");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let src = root.path().join("proj");
    let work = root.path().join("work");
    let harness_id = "H-C0001-0000B00B";
    let harness = work.join("harnesses").join(harness_id);
    std::fs::create_dir_all(src.join("extra")).unwrap();
    std::fs::create_dir_all(&harness).unwrap();
    std::fs::write(src.join("legacy.c"), LEGACY_TARGET_C).unwrap();
    std::fs::write(src.join("extra/helper.c"), HELPER_C).unwrap();
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime");
    std::fs::write(
        harness.join("Makefile"),
        c_harness_makefile(&runtime, &src, &src.join("legacy.c")),
    )
    .unwrap();
    std::fs::write(harness.join("main.c"), DRIVER_C).unwrap();
    std::fs::write(
        harness.join("generation-metadata.json"),
        br#"{"schema_version":1,"language":"c"}"#,
    )
    .unwrap();
    let id = "F-0009-0000abcd";
    write_crash_finding(&work, id, harness_id, b"0123456789abcdef");
    // A compiler that lists dependencies and answers the family probe, but
    // fails every real compile.
    let cc = root.path().join("cc-breaks");
    write_script(
        &cc,
        "#!/bin/sh\nfor arg in \"$@\"; do\n  case \"$arg\" in -M|-E|-dM|-print-resource-dir|--version) exec clang \"$@\" ;; esac\ndone\necho 'cc-breaks: error: the toolchain refused to compile' >&2\nexit 1\n",
    );
    let packaged = bhf()
        .arg("capsule")
        .arg("--work-dir")
        .arg(&work)
        .args(["--finding-id", id])
        .env("CC", &cc)
        .output()
        .expect("run bhf capsule");
    let stdout = String::from_utf8_lossy(&packaged.stdout);
    assert!(
        stdout.contains("not reproduced: the rebuild failed"),
        "{stdout}"
    );
    let cap = work.join("capsules").join(format!("capsule_{id}"));
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(cap.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["rebuilt"], false, "{manifest}");
    assert!(
        manifest["build_error"]
            .as_str()
            .is_some_and(|error| error.contains("the toolchain refused to compile")),
        "{manifest}"
    );
    let verified = bhf()
        .arg("verify-poc")
        .arg(&cap)
        .env("CC", &cc)
        .output()
        .expect("run bhf verify-poc");
    let out = String::from_utf8_lossy(&verified.stdout);
    assert_eq!(verified.status.code(), Some(1), "{out}");
    assert!(
        out.contains("the capsule's rebuild failed when it was packaged")
            && out.contains("the toolchain refused to compile"),
        "{out}"
    );
    // This run's rebuild failed too, and says how.
    assert!(
        out.contains("observed: the rebuild fails here too: cc-breaks: error: the toolchain refused to compile"),
        "{out}"
    );
    assert!(!out.contains("fork-server"), "{out}");
}

/// In-bounds for the 4-byte record, out of bounds past it.
#[cfg(unix)]
const SHORT_RECORD_C: &str = "\
#include <stdlib.h>
#include <string.h>
int parse_record(const char *data, unsigned int len) {
    char *buf = malloc(4);
    if (!buf) return 0;
    memcpy(buf, data, len);
    int r = len ? buf[0] : 0;
    free(buf);
    return r;
}
";

/// A capsule whose rebuild failed when it was packaged, but that rebuilds
/// where verify-poc runs: an input that then does not crash is not blamed on
/// the build, which works.
// The build.sh round trip of a Linux toolchain; build.ps1 has its own.
#[cfg(unix)]
#[test]
fn verify_poc_does_not_blame_a_packaging_build_failure_once_the_capsule_builds() {
    if !clang_available() {
        eprintln!("skipping: clang not installed");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let src = root.path().join("proj");
    let work = root.path().join("work");
    let harness_id = "H-C0001-0000B00C";
    let harness = work.join("harnesses").join(harness_id);
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&harness).unwrap();
    std::fs::write(src.join("parse.c"), SHORT_RECORD_C).unwrap();
    let runtime = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime");
    std::fs::write(
        harness.join("Makefile"),
        c_harness_makefile(&runtime, &src, &src.join("parse.c")),
    )
    .unwrap();
    std::fs::write(harness.join("main.c"), DRIVER_C).unwrap();
    std::fs::write(
        harness.join("generation-metadata.json"),
        br#"{"schema_version":1,"language":"c"}"#,
    )
    .unwrap();
    let id = "F-0009-0000abce";
    write_crash_finding(&work, id, harness_id, b"0123456789abcdef");
    let cc = root.path().join("cc-breaks");
    write_script(
        &cc,
        "#!/bin/sh\nfor arg in \"$@\"; do\n  case \"$arg\" in -M|-E|-dM|-print-resource-dir|--version) exec clang \"$@\" ;; esac\ndone\necho 'cc-breaks: error: the toolchain refused to compile' >&2\nexit 1\n",
    );
    let packaged = bhf()
        .arg("capsule")
        .arg("--work-dir")
        .arg(&work)
        .args(["--finding-id", id])
        .env("CC", &cc)
        .output()
        .expect("run bhf capsule");
    let stdout = String::from_utf8_lossy(&packaged.stdout);
    assert!(
        stdout.contains("not reproduced: the rebuild failed"),
        "{stdout}"
    );
    let cap = work.join("capsules").join(format!("capsule_{id}"));
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(cap.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["rebuilt"], false, "{manifest}");
    // Here the rebuild works (a compiler that compiles), and this input
    // stays inside the record.
    std::fs::write(cap.join("input/testcase.bin"), b"ab").unwrap();
    let verified = bhf()
        .arg("verify-poc")
        .arg(&cap)
        .env("CC", "clang")
        .output()
        .expect("run bhf verify-poc");
    let out = String::from_utf8_lossy(&verified.stdout);
    assert_eq!(verified.status.code(), Some(1), "{out}");
    assert!(
        out.contains("NOT REPRODUCIBLE — the capsule rebuilds here, but its input did not crash"),
        "{out}"
    );
    assert!(
        out.contains("the toolchain refused to compile"),
        "names the packaging failure: {out}"
    );
    assert!(!out.contains("sh build.sh"), "the build works: {out}");
    assert!(
        !out.contains("NOT REPRODUCIBLE — the capsule's rebuild failed"),
        "{out}"
    );
}

/// Uses `std::cerr` without including `<iostream>`: the compile database
/// force-includes it.
#[cfg(unix)]
const NEEDS_IOSTREAM_CPP: &str = "\
#include <cstdlib>
#include <cstring>
int parse_record(const char *data, unsigned long len) {
    if (len == 0) {
        std::cerr << \"empty record\\n\";
        return 0;
    }
    char *buf = static_cast<char *>(std::malloc(4));
    std::memcpy(buf, data, len);
    int r = buf[0];
    std::free(buf);
    return r;
}
";

/// A compile database's `-include iostream` names a system header the
/// compiler finds itself: the capsule keeps it as written instead of
/// pointing it at a file next to the harness, and rebuilds.
// The build.sh round trip of a Linux toolchain; build.ps1 has its own.
#[cfg(unix)]
#[test]
fn a_forced_system_header_from_the_compile_database_stays_a_bare_name() {
    if !clangxx_available() {
        eprintln!("skipping: clang++ not installed");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let tree = root.path().join("src");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(
        tree.join("compile_commands.json"),
        serde_json::json!([{
            "directory": tree,
            "file": tree.join("widget.cpp"),
            "arguments": ["clang++", "-include", "iostream", "-c", "widget.cpp", "-o", "widget.o"],
        }])
        .to_string(),
    )
    .unwrap();
    let (work, stderr) = auto_tree(root.path(), &[("widget.cpp", NEEDS_IOSTREAM_CPP)], "cpp");
    let (id, _) = crash_finding(&work, |h| h.starts_with("H-X"))
        .unwrap_or_else(|| panic!("auto produced no C++ crash finding: {stderr}"));
    let packaged = capsule_for(&work, &id);
    let stdout = String::from_utf8_lossy(&packaged.stdout);
    assert!(
        packaged.status.success() && stdout.contains("1 verified to reproduce"),
        "stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&packaged.stderr)
    );
    let cap = work.join("capsules").join(format!("capsule_{id}"));
    let build = std::fs::read_to_string(cap.join("build.sh")).unwrap();
    assert!(build.contains("-include iostream "), "{build}");
    assert!(!build.contains("/iostream"), "{build}");
    let (pass, verify) = verify_from_scratch(&cap, "forced-system-header");
    assert!(pass, "verify-poc should PASS offline; got:\n{verify}");
}

/// Declares a member with its own class's qualification, which only MSVC
/// takes by default: clang needs `-fms-extensions`, gcc `-fpermissive`.
#[cfg(unix)]
const QUALIFIED_MEMBER_H: &str = "\
#pragma once
#include <cstddef>
class Widget {
public:
    int Widget::copy_at(const char *data, std::size_t len);
};
";

#[cfg(unix)]
const QUALIFIED_MEMBER_CPP: &str = "\
#include \"widget.h\"
#include <cstdlib>
#include <cstring>
int Widget::copy_at(const char *data, std::size_t len) {
    char *buf = static_cast<char *>(std::malloc(4));
    std::memcpy(buf, data, len);
    int r = len ? buf[0] : 0;
    std::free(buf);
    return r;
}
";

/// The compatibility flag `bhf auto` adds for a member declared with an extra
/// qualification is announced, recorded as a repair and in the build recipe,
/// and applied by the capsule, which rebuilds and reproduces from a clean copy.
// The build.sh round trip of a Linux toolchain; build.ps1 has its own.
#[cfg(unix)]
#[test]
fn the_cpp_compatibility_flag_is_recorded_and_reaches_the_capsule() {
    if !clangxx_available() {
        eprintln!("skipping: clang++ not installed");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (work, stderr) = auto_tree(
        root.path(),
        &[
            ("widget.h", QUALIFIED_MEMBER_H),
            ("widget.cpp", QUALIFIED_MEMBER_CPP),
        ],
        "cpp",
    );
    let (id, finding_dir) = crash_finding(&work, |h| h.starts_with("H-X"))
        .unwrap_or_else(|| panic!("auto produced no C++ crash finding: {stderr}"));
    assert!(
        stderr.contains("building with -fms-extensions (clang) / -fpermissive (gcc)"),
        "the flag is announced:\n{stderr}"
    );
    let raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(finding_dir.join("finding.json")).unwrap()).unwrap();
    let harness_id = raw["harness_id"].as_str().unwrap();
    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
    let target = run["targets"]
        .as_array()
        .and_then(|targets| targets.iter().find(|t| t["harness_id"] == harness_id))
        .unwrap_or_else(|| panic!("no run.json target for {harness_id}: {run}"));
    assert!(
        target["outcome"]["repairs"]
            .as_array()
            .is_some_and(|repairs| repairs.iter().any(|repair| {
                repair["kind"] == "compiler_compat" && repair["clang"][0] == "-fms-extensions"
            })),
        "{target}"
    );
    let recipe: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            work.join("harnesses")
                .join(harness_id)
                .join("coverage-build-recipe.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        recipe["compat_flags"]["clang"][0], "-fms-extensions",
        "{recipe}"
    );
    assert_eq!(recipe["compat_flags"]["gcc"][0], "-fpermissive", "{recipe}");
    let packaged = capsule_for(&work, &id);
    let stdout = String::from_utf8_lossy(&packaged.stdout);
    assert!(
        packaged.status.success() && stdout.contains(&format!("capsule_{id}  (✓)")),
        "stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&packaged.stderr)
    );
    let cap = work.join("capsules").join(format!("capsule_{id}"));
    let build = std::fs::read_to_string(cap.join("build.sh")).unwrap();
    assert!(build.contains("COMPAT=\"-fms-extensions\""), "{build}");
    let (pass, verify) = verify_from_scratch(&cap, "cxx-compat");
    assert!(pass, "verify-poc should PASS offline; got:\n{verify}");
}
