// SPDX-License-Identifier: Apache-2.0
//
// M3.3 native Go lane: the `go_lane` fixture module is discovered + ranked, built
// into a framed harness binary, fuzzed by the builtin engine, and the planted
// index-out-of-range panic surfaces as a CWE-125 finding. The end-to-end portion
// skips cleanly when no `go` toolchain is installed (the GNAT-less rule).

use std::path::{Path, PathBuf};
use std::process::Command;

use cli::auto::candidate::Lang;
use cli::auto::discovery::discover;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/go_lane")
        .canonicalize()
        .expect("canonicalize go_lane fixture")
}

/// The `bhf` binary cargo built for these tests (`bhf.exe` on Windows).
fn bhf_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bhf"))
}

fn have_go() -> bool {
    let present = {
        Command::new("go")
            .arg("version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };
    support::require_tool(present, "go")
}

#[test]
fn discovers_and_ranks_go_functions() {
    let candidates = discover(&fixture()).expect("discover go_lane fixture");
    let names: Vec<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
    assert!(
        candidates.iter().all(|c| c.lang == Lang::Go),
        "every candidate is Lang::Go: {names:?}"
    );
    assert!(
        names.contains(&"ParseRecord"),
        "exported []byte parser discovered: {names:?}"
    );
    let p = candidates
        .iter()
        .find(|c| c.name == "ParseRecord")
        .expect("ParseRecord discovered");
    assert!(
        p.harness_id.starts_with("H-G"),
        "Go id prefix H-G: {}",
        p.harness_id
    );
}

#[test]
fn auto_builds_fuzzes_and_finds_index_oob_cwe125() {
    if !have_go() {
        eprintln!("skipping: no go toolchain on PATH (GNAT-less rule)");
        return;
    }
    // Run from a temp copy of the whole module (go.mod + package) outside the repo.
    let src_guard = TestDir::new("golane_it");
    let src = src_guard.join("src");
    copy_dir(&fixture(), &src).expect("copy go fixture module");
    let work_guard = TestDir::new("golane_w");
    let work = work_guard.join("work");

    let out = Command::new(bhf_bin())
        .args([
            "auto",
            "--per-target-time",
            "8",
            "--work-dir",
            work.to_str().unwrap(),
            src.to_str().unwrap(),
        ])
        .output()
        .expect("run bhf auto");
    assert!(
        out.status.success(),
        "bhf auto exited non-zero: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc = results_doc(&work);
    assert!(
        has_cwe(&doc, 125),
        "expected a CWE-125 index-out-of-bounds finding in results/findings.json:\n{doc:#}"
    );
    assert!(
        doc.to_string().contains("ParseRecord"),
        "the finding should point at ParseRecord:\n{doc:#}"
    );
    let _ = std::fs::remove_dir_all(&src);
    let _ = std::fs::remove_dir_all(&work);
}

/// The Go lane advertises "real edge coverage" of the TARGET. `go build -cover`
/// instruments only the packages being built, which is just the generated
/// harness `main` — the target module arrives as a dependency through the
/// module `replace`, so without `-coverpkg` the lane measures the harness
/// fuzzing itself and reports it as target coverage.
#[test]
fn go_coverage_instruments_the_target_module_not_just_the_harness() {
    if !have_go() {
        eprintln!("skipping: no go toolchain on PATH (GNAT-less rule)");
        return;
    }
    let src_guard = TestDir::new("bhf go lane cov source ");
    let src = src_guard.join("src");
    copy_dir(&fixture(), &src).expect("copy go fixture module");
    let work_guard = TestDir::new("bhf go lane cov work ");
    let work = work_guard.join("work");

    let out = Command::new(bhf_bin())
        .args([
            "auto",
            "--per-target-time",
            "5",
            "--max-targets",
            "1",
            "--single-pass",
            "--work-dir",
            work.to_str().unwrap(),
            src.to_str().unwrap(),
        ])
        .output()
        .expect("run bhf auto");
    assert!(
        out.status.success(),
        "bhf auto exited non-zero: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Go embeds one coverage-meta entry per instrumented source file. The
    // fixture module's own files must be there; if only the harness were
    // instrumented, none would be.
    let mut binaries = Vec::new();
    for entry in std::fs::read_dir(work.join("harnesses")).expect("harnesses dir") {
        let bin = entry.expect("harness entry").path().join("main");
        if bin.is_file() {
            binaries.push(std::fs::read(&bin).expect("read harness binary"));
        }
    }
    assert!(
        !binaries.is_empty(),
        "no built Go harness binary to inspect"
    );
    // The coverage metadata spells each instrumented file as a STANDALONE
    // NUL-delimited string `<import path>/<file>.go`. The bare import path
    // appears in any build (it is the package reference), so the file-suffixed
    // form is what distinguishes instrumented from merely linked.
    let instrumented = binaries.iter().any(|bytes| {
        let needle = b"bhf.example/recordlib/recordparser/parser.go";
        bytes.windows(needle.len()).any(|window| window == needle)
    });
    assert!(
        instrumented,
        "the target module's files are absent from the coverage metadata, so \
         -coverpkg did not reach it and the lane is measuring only the harness"
    );
    let run: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work.join("auto/run.json")).expect("read Go auto run summary"),
    )
    .expect("parse Go auto run summary");
    let edges = run["targets"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|target| target["outcome"]["passes"].as_array().into_iter().flatten())
        .filter_map(|pass| pass["coverage_edges"].as_u64())
        .max()
        .unwrap_or(0);
    assert!(
        edges > 0,
        "instrumented Go run produced no edge feedback: {run}"
    );

    let _ = std::fs::remove_dir_all(&src);
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn auto_structured_go_seed_populates_nested_fields_and_reaches_target() {
    if !have_go() {
        eprintln!("skipping: no go toolchain on PATH");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let src = root.path().join("source");
    let work = root.path().join("work");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("go.mod"),
        "module example.test/structured\n\ngo 1.21\n",
    )
    .unwrap();
    std::fs::write(
        src.join("parser.go"),
        r#"package structured
type Child struct { Code int `json:"code"` }
type Request struct {
    Magic string `json:"magic"`
    Child *Child `json:"child"`
    Values []int `json:"values"`
    Labels map[string]string `json:"labels"`
}
func ParseRequest(req *Request) {
    if req != nil && req.Magic == "A" && req.Child != nil &&
       req.Child.Code == 1 && len(req.Values) == 1 && req.Values[0] == 1 &&
       req.Labels["k"] == "A" {
        panic("planted structured reachability")
    }
}
"#,
    )
    .unwrap();
    let out = Command::new(bhf_bin())
        .args([
            "auto",
            "--per-target-time",
            "8",
            "--max-targets",
            "1",
            "--single-pass",
            "--work-dir",
            work.to_str().unwrap(),
            src.to_str().unwrap(),
        ])
        .output()
        .expect("run bhf auto on structured Go fixture");
    assert!(
        out.status.success(),
        "Go auto failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let seeds: Vec<_> = std::fs::read_dir(work.join("harnesses"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path().join("structured-seeds.json"))
        .filter(|path| path.is_file())
        .collect();
    assert_eq!(seeds.len(), 1, "expected one built structured Go harness");
    let json = std::fs::read_to_string(work.join("results/findings.json")).unwrap_or_default();
    assert!(
        json.contains("ParseRequest") && json.contains("planted structured reachability"),
        "valid JSON seed did not reach the planted branch: {json}"
    );
}

/// A dependency's package `init` panics on this toolchain, so the harness dies
/// before `main` on every input (#398). That is the target's environment, not
/// a defect a fuzzer found: each target, the project's own fuzz test among
/// them, is reported built but not entered, naming the package whose `init`
/// failed, and no finding is written.
#[test]
fn a_dependency_init_panic_is_a_not_entered_target_naming_the_package() {
    if !have_go() {
        eprintln!("skipping: no go toolchain on PATH (GNAT-less rule)");
        return;
    }
    let src_guard = TestDir::new("golane_initpanic");
    let src = src_guard.join("src");
    copy_dir(&fixture_named("go_init_panic"), &src).expect("copy go fixture module");
    let work_guard = TestDir::new("golane_initpanic_w");
    let work = work_guard.join("work");
    let out = Command::new(bhf_bin())
        .args([
            "auto",
            "--per-target-time",
            "4",
            "--single-pass",
            "--jobs",
            "1",
            "--work-dir",
            work.to_str().unwrap(),
            src.to_str().unwrap(),
        ])
        .output()
        .expect("run bhf auto");
    let log = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let run: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work.join("auto/run.json")).unwrap_or_else(|e| panic!("{e}\n{log}")),
    )
    .expect("parse run.json");
    let targets: Vec<&serde_json::Value> =
        run["targets"].as_array().into_iter().flatten().collect();
    let widget = targets
        .iter()
        .find(|target| target["name"] == "ParseWidget")
        .unwrap_or_else(|| panic!("ParseWidget was not attempted: {run:#}\n{log}"));
    assert!(
        targets
            .iter()
            .any(|target| target["name"] == "FuzzParseWidget"),
        "the provided fuzz test was not attempted: {run:#}"
    );
    for target in &targets {
        let outcome = &target["outcome"];
        assert_eq!(outcome["outcome"], "built_not_entered", "{target:#}\n{log}");
        assert_eq!(outcome["entry_miss"], "target_environment", "{target:#}");
        let reason = outcome["reason"].as_str().unwrap_or_default();
        assert!(
            reason.contains("bhf.example/initpanic/legacycodec")
                && reason.contains("init")
                && reason.contains("session state layout doesn't match"),
            "the reason must name the package whose init failed and why: {reason}"
        );
    }
    assert_eq!(
        widget["outcome"]["passes"],
        serde_json::json!([]),
        "{widget:#}"
    );
    let doc = results_doc(&work);
    let findings = doc["findings"].as_array().map_or(0, Vec::len);
    assert_eq!(
        findings, 0,
        "an init panic is not a finding: {doc:#}\n{log}"
    );
    assert!(
        !work.join("results/findings").is_dir()
            || std::fs::read_dir(work.join("results/findings"))
                .unwrap()
                .next()
                .is_none(),
        "no finding directory may be written"
    );
    // Not a row for bhf's maintainer: the target's environment stopped it.
    let bug_report = std::fs::read_to_string(work.join("auto/bug-report.md")).unwrap_or_default();
    assert!(
        !bug_report.contains("legacycodec"),
        "the target's environment is not a bhf issue: {bug_report}"
    );
    // Nothing built and ran, so the run exits 1, as auto.md documents.
    assert_eq!(out.status.code(), Some(1), "{log}");
}

/// A `Must` function panics on input it rejects by contract (#399). The lane
/// ranks `MustParseHash` below `ParseHash`, fuzzes `ParseHash`, and reports
/// neither `MustParseHash`'s documented panic nor `template.Must`'s. A fault in
/// a `Must` function's own body, `MustParseTag`'s slice past the end of a
/// short tag, is still a finding. So is the panic of `regexp.MustCompile`
/// under `MatchFilter`, which is no `Must` function and passes its input on:
/// that breaks MustCompile's contract, and is marked lab-only as a
/// `must_panic`.
#[test]
fn a_must_functions_documented_panic_is_not_a_finding_but_its_own_fault_is() {
    if !have_go() {
        eprintln!("skipping: no go toolchain on PATH (GNAT-less rule)");
        return;
    }
    let src_guard = TestDir::new("golane_must");
    let src = src_guard.join("src");
    copy_dir(&fixture_named("go_must"), &src).expect("copy go fixture module");
    let work_guard = TestDir::new("golane_must_w");
    let work = work_guard.join("work");
    let out = Command::new(bhf_bin())
        .args([
            "auto",
            "--per-target-time",
            "6",
            "--single-pass",
            "--jobs",
            "1",
            "--work-dir",
            work.to_str().unwrap(),
            src.to_str().unwrap(),
        ])
        .output()
        .expect("run bhf auto");
    let log = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let run: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work.join("auto/run.json")).unwrap_or_else(|e| panic!("{e}\n{log}")),
    )
    .expect("parse run.json");
    let target = |name: &str| {
        run["targets"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|target| target["name"] == name)
            .unwrap_or_else(|| panic!("{name} was not attempted: {run:#}\n{log}"))
            .clone()
    };
    let parse = target("ParseHash");
    let must = target("MustParseHash");
    let tag = target("MustParseTag");
    let page = target("RenderPage");
    let filter = target("MatchFilter");
    assert_eq!(
        parse["outcome"]["outcome"], "built_and_fuzzed",
        "{parse:#}\n{log}"
    );
    assert!(
        must["score"].as_i64() < parse["score"].as_i64(),
        "MustParseHash must rank below ParseHash: {must:#}\n{parse:#}"
    );

    let doc = results_doc(&work);
    let findings: Vec<&serde_json::Value> =
        doc["findings"].as_array().into_iter().flatten().collect();
    let of = |target: &serde_json::Value| -> Vec<String> {
        findings
            .iter()
            .filter(|finding| finding["fuzz"]["harness_id"] == target["harness_id"])
            .map(|finding| finding.to_string())
            .collect()
    };
    for (name, target) in [
        ("ParseHash", &parse),
        ("MustParseHash", &must),
        ("RenderPage", &page),
    ] {
        assert_eq!(
            of(target),
            Vec::<String>::new(),
            "{name}: a Must function's documented panic is not a finding\n{log}"
        );
    }
    let tag_findings = of(&tag);
    assert!(
        tag_findings
            .iter()
            .any(|finding| finding.contains("slice bounds out of range")),
        "the fault in MustParseTag's own body must be a finding: {doc:#}\n{log}"
    );
    // A fault is not the function's contract, so it is not demoted as one.
    for finding in findings
        .iter()
        .filter(|finding| finding["fuzz"]["harness_id"] == tag["harness_id"])
    {
        assert_ne!(finding["verdict_reason"], "must_panic", "{finding:#}");
    }
    let filter_findings: Vec<&&serde_json::Value> = findings
        .iter()
        .filter(|finding| finding["fuzz"]["harness_id"] == filter["harness_id"])
        .collect();
    assert!(
        !filter_findings.is_empty()
            && filter_findings
                .iter()
                .all(|finding| finding["verdict_reason"] == "must_panic"),
        "MatchFilter's input reaching regexp.MustCompile must be a must_panic finding: \
         {filter:#}\n{doc:#}\n{log}"
    );
    assert!(
        !tag_findings
            .iter()
            .any(|finding| finding.contains("want a #tag")),
        "MustParseTag's documented panic is not a finding: {tag_findings:#?}"
    );
}

fn fixture_named(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
        .canonicalize()
        .unwrap_or_else(|e| panic!("canonicalize {name} fixture: {e}"))
}

fn copy_dir(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let dest = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &dest)?;
        } else {
            std::fs::copy(entry.path(), &dest)?;
        }
    }
    Ok(())
}

fn results_doc(work: &std::path::Path) -> serde_json::Value {
    let bytes = std::fs::read(work.join("results/findings.json")).unwrap_or_default();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

fn has_cwe(doc: &serde_json::Value, cwe: u64) -> bool {
    doc["findings"].as_array().into_iter().flatten().any(|f| {
        f["cwe"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|c| c.as_u64() == Some(cwe))
    })
}
