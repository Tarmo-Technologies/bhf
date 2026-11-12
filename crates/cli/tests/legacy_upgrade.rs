// SPDX-License-Identifier: Apache-2.0
//! Opening a work dir written by bhf 0.2.x: the migration keeps the legacy
//! reports and says what it did, `bhf auto` sets the old corpus aside,
//! `bhf report --backfill` replays migrated findings for their sanitizer log
//! and frames, and the index warns about inputs the old seed encoding damaged.

#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bhf(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cli"))
        .args(args)
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

const ASAN_REPORT: &str = "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000031 at pc 0x1 bp 0x2 sp 0x3\n\
WRITE of size 1 at 0x602000000031 thread T0\n\
\x20   #0 0x1 in Widget::copy_at(char const*, unsigned long) /src/widget/widget.cc:12:5\n\
\x20   #1 0x2 in parse_record(char const*) /src/widget/parse.cc:40:7\n\
\n\
0x602000000031 is located 0 bytes after 1-byte region [0x602000000030,0x602000000031)\n\
allocated by thread T0 here:\n\
\x20   #0 0x3 in malloc\n\
\x20   #1 0x4 in parse_record(char const*) /src/widget/parse.cc:38:9\n\
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/widget/widget.cc:12:5 in Widget::copy_at\n";

/// A bhf-driver-protocol script harness that prints `report` and aborts.
fn write_harness(path: &Path, report: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        path,
        format!("#!/bin/sh\n# BHF_FRAMED test driver\ncat >&2 <<'REPORT'\n{report}REPORT\nkill -ABRT $$\n"),
    )
    .unwrap();
    make_executable(path);
}

/// A finding the way bhf 0.2.x wrote it: no sanitizer.log, no frames, an
/// absolute fixture_path.
fn write_legacy_finding(work: &Path, id: &str, harness_id: &str, testcase: &[u8]) -> PathBuf {
    let dir = work.join("findings").join(id);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("testcase.bin"), testcase).unwrap();
    let record = serde_json::json!({
        "id": id,
        "signature": "0".repeat(64),
        "rule_id": "BHF-201",
        "classification": "unhandled",
        "harness_id": harness_id,
        "dialect": "cpp",
        "fixture_path": work.join("harnesses").join(harness_id).join("main").display().to_string(),
        "exception": {
            "name": "ASAN_HEAP_BUFFER_OVERFLOW",
            "sanitizer": "asan",
            "message": "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000031",
            "stack": [
                {"function": "Widget::copy_at(char const*, unsigned long)", "file": "/src/widget/widget.cc", "line": 12}
            ],
        },
        "paths": {"testcase": "testcase.bin", "finding": "finding.json"},
    });
    fs::write(
        dir.join("finding.json"),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();
    fs::write(dir.join("replay.py"), "# written by an earlier release\n").unwrap();
    dir
}

/// A 0.2.x work dir: findings/ at the top, the legacy index files, and a
/// corpus queue.
fn legacy_work_dir(root: &Path) -> PathBuf {
    let work = root.join("work");
    write_legacy_finding(&work, "F-0001-aaaaaaaa", "H-1", b"widget-input");
    fs::write(work.join("FINDINGS.md"), "# Findings (0.2.x)\n").unwrap();
    fs::write(work.join("findings.csv"), "id\nF-0001-aaaaaaaa\n").unwrap();
    fs::create_dir_all(work.join("auto")).unwrap();
    fs::write(work.join("auto/findings.csv"), "id\n").unwrap();
    let queue = work.join("corpus/H-1/queue");
    fs::create_dir_all(&queue).unwrap();
    fs::write(queue.join("0001.bin"), b"kept-corpus-entry").unwrap();
    work
}

#[test]
fn migration_keeps_legacy_reports_and_says_what_changed() {
    let root = tempfile::tempdir().unwrap();
    let work = legacy_work_dir(root.path());
    let out = bhf(&["report", "--work-dir", work.to_str().unwrap()]);
    let stderr = text(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    for needle in [
        "migrated legacy work dir",
        "(1 findings)",
        "FINDINGS.md, findings.csv, auto/findings.csv",
        "results/legacy",
        "bhf report --backfill",
        "--reuse-legacy-corpus",
        "one-way",
    ] {
        assert!(stderr.contains(needle), "missing {needle:?} in:\n{stderr}");
    }
    let legacy = work.join("results/legacy");
    assert_eq!(
        fs::read_to_string(legacy.join("FINDINGS.md")).unwrap(),
        "# Findings (0.2.x)\n"
    );
    assert!(legacy.join("findings.csv").is_file());
    assert!(legacy.join("auto/findings.csv").is_file());
    assert!(legacy.join("findings/F-0001-aaaaaaaa/replay.py").is_file());
    assert!(legacy.join("migration.json").is_file());
    assert!(work
        .join("results/findings/F-0001-aaaaaaaa/finding.json")
        .is_file());
}

/// `bhf auto` on a migrated work dir keeps the old corpus but does not reseed
/// it; `--reuse-legacy-corpus` keeps using it.
#[test]
fn auto_sets_the_legacy_corpus_aside_unless_asked_to_reuse_it() {
    for reuse in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let work = legacy_work_dir(root.path());
        let src = root.path().join("src");
        fs::create_dir_all(&src).unwrap();
        let mut args = vec![
            "auto",
            src.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
        ];
        if reuse {
            args.push("--reuse-legacy-corpus");
        }
        let out = bhf(&args);
        let stderr = text(&out.stderr);
        assert!(
            !stderr.contains("unexpected argument"),
            "reuse={reuse}: {stderr}"
        );
        if reuse {
            assert!(
                work.join("corpus/H-1/queue/0001.bin").is_file(),
                "reused corpus left in place: {stderr}"
            );
            assert!(!work.join("corpus-legacy").exists(), "{stderr}");
        } else {
            assert!(
                !work.join("corpus/H-1/queue/0001.bin").exists(),
                "legacy corpus must not stay where auto reseeds from: {stderr}"
            );
            assert_eq!(
                fs::read(work.join("corpus-legacy/H-1/queue/0001.bin")).unwrap(),
                b"kept-corpus-entry"
            );
            assert!(stderr.contains("corpus-legacy"), "{stderr}");
            // The decision is made once: a later run leaves the new corpus alone.
            let queue = work.join("corpus/H-2/queue");
            fs::create_dir_all(&queue).unwrap();
            fs::write(queue.join("new.bin"), b"new").unwrap();
            let _ = bhf(&args);
            assert!(queue.join("new.bin").is_file());
        }
    }
}

/// A plan-only run fuzzes nothing and leaves the corpus decision alone.
#[test]
fn auto_dry_run_leaves_the_legacy_corpus_alone() {
    let root = tempfile::tempdir().unwrap();
    let work = legacy_work_dir(root.path());
    let src = root.path().join("src");
    fs::create_dir_all(&src).unwrap();
    let out = bhf(&[
        "auto",
        src.to_str().unwrap(),
        "--work-dir",
        work.to_str().unwrap(),
        "--dry-run",
    ]);
    let stderr = text(&out.stderr);
    assert!(work.join("corpus/H-1/queue/0001.bin").is_file(), "{stderr}");
    assert!(!work.join("auto/legacy-corpus.json").exists(), "{stderr}");
}

/// `bhf report --backfill` replays a migrated finding against its harness and
/// records the sanitizer log and frames; a finding without a harness, or one
/// whose harness now crashes elsewhere, is left as it was and said so.
#[test]
fn report_backfill_replays_migrated_findings() {
    let root = tempfile::tempdir().unwrap();
    let work = legacy_work_dir(root.path());
    write_harness(&work.join("harnesses/H-1/main"), ASAN_REPORT);
    write_legacy_finding(&work, "F-0002-bbbbbbbb", "H-GONE", b"other-input");
    write_legacy_finding(&work, "F-0003-cccccccc", "H-3", b"third-input");
    write_harness(
        &work.join("harnesses/H-3/main"),
        &ASAN_REPORT.replace("Widget::copy_at", "Widget::other"),
    );

    let out = bhf(&["report", "--backfill", "--work-dir", work.to_str().unwrap()]);
    let stderr = text(&out.stderr);
    assert!(out.status.success(), "{stderr}");

    let findings = work.join("results/findings");
    let done = findings.join("F-0001-aaaaaaaa");
    let log = fs::read_to_string(done.join("sanitizer.log")).expect("sanitizer.log backfilled");
    assert!(log.contains("heap-buffer-overflow"), "{log}");
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(done.join("finding.json")).unwrap()).unwrap();
    assert_eq!(record["paths"]["sanitizer_log"], "sanitizer.log");
    assert!(record["exception"]["stack"].as_array().unwrap().len() >= 2);
    assert_eq!(record["exception"]["access"]["region"]["size"], 1);
    assert_eq!(record["id"], "F-0001-aaaaaaaa", "identity unchanged");
    assert!(record["history"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["command"] == "report --backfill"));

    for (id, reason) in [("F-0002-bbbbbbbb", "harness"), ("F-0003-cccccccc", "sink")] {
        assert!(
            !findings.join(id).join("sanitizer.log").exists(),
            "{id} must not get another crash's log"
        );
        let line = stderr
            .lines()
            .find(|line| line.contains(id))
            .unwrap_or_else(|| panic!("no backfill line for {id}:\n{stderr}"));
        assert!(line.contains(reason), "{line}");
    }
    assert!(stderr.contains("1 updated"), "{stderr}");

    // The rebuild ran after the backfill: the index lists the new log.
    let index: serde_json::Value =
        serde_json::from_slice(&fs::read(work.join("results/findings.json")).unwrap()).unwrap();
    let files = index["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == "F-0001-aaaaaaaa")
        .unwrap()["evidence"]["files"]
        .to_string();
    assert!(files.contains("sanitizer.log"), "{files}");
}

/// A migrated finding has no decoded.json; when its harness has the argument
/// trace, `report --backfill` runs it once with the trace on and writes the
/// decoded arguments, into decoded.json and finding.json.
#[test]
fn report_backfill_records_the_decoded_arguments_of_a_tracing_harness() {
    let root = tempfile::tempdir().unwrap();
    let work = legacy_work_dir(root.path());
    let harness = work.join("harnesses/H-1/main");
    fs::create_dir_all(harness.parent().unwrap()).unwrap();
    fs::write(
        &harness,
        format!(
            "#!/bin/sh\n# BHF_FRAMED test driver\n\
             if [ \"$BHF_TRACE_ARGS\" = 1 ]; then\n\
             >&2 echo 'BHF_ARG {{\"call\":\"target\",\"i\":0,\"role\":\"param\",\"name\":\"buffer\",\"type\":\"const char *\",\"decoder\":\"bhf_c_string(4096)\",\"span\":[0,2],\"ptr\":\"0x602000000030\",\"alloc_size\":1,\"len\":0,\"preview_hex\":\"\"}}'\n\
             fi\n\
             cat >&2 <<'REPORT'\n{ASAN_REPORT}REPORT\nkill -ABRT $$\n"
        ),
    )
    .unwrap();
    make_executable(&harness);

    let out = bhf(&["report", "--backfill", "--work-dir", work.to_str().unwrap()]);
    let stderr = text(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let done = work.join("results/findings/F-0001-aaaaaaaa");
    let decoded: serde_json::Value =
        serde_json::from_slice(&fs::read(done.join("decoded.json")).expect("decoded.json"))
            .unwrap();
    assert!(decoded.to_string().contains("buffer"), "{decoded}");
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(done.join("finding.json")).unwrap()).unwrap();
    assert_eq!(record["decoded_args"][0]["name"], "buffer", "{record}");
    assert!(stderr.contains("decoded argument"), "{stderr}");
    assert!(
        stderr.contains("1 with decoded arguments"),
        "the summary counts it: {stderr}"
    );
}

/// Inputs carrying runs of EF BF BD in a work dir from an earlier release are
/// flagged in INDEX.md and by `bhf report` as likely damaged.
#[test]
fn report_and_index_warn_about_inputs_the_old_seed_encoding_damaged() {
    let root = tempfile::tempdir().unwrap();
    let work = root.path().join("work");
    write_legacy_finding(
        &work,
        "F-0001-aaaaaaaa",
        "H-1",
        b"\x89PNG\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbdIHDR",
    );
    write_legacy_finding(&work, "F-0002-bbbbbbbb", "H-1", b"plain-input");
    let queue = work.join("corpus/H-1/queue");
    fs::create_dir_all(&queue).unwrap();
    fs::write(queue.join("a.bin"), b"\x00\xef\xbf\xbd\xef\xbf\xbd\x01").unwrap();
    fs::write(queue.join("b.bin"), b"clean").unwrap();

    let out = bhf(&["report", "--work-dir", work.to_str().unwrap()]);
    let stderr = text(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(
        stderr.contains("warning: 2 inputs") && stderr.contains("EF BF BD"),
        "{stderr}"
    );
    let index = fs::read_to_string(work.join("results/INDEX.md")).unwrap();
    assert!(index.contains("EF BF BD"), "{index}");
    assert!(index.contains("F-0001-aaaaaaaa"), "{index}");
    assert!(index.contains("1 corpus entry"), "{index}");
    let warning = index
        .split("EF BF BD")
        .nth(1)
        .unwrap_or_default()
        .split("\n## ")
        .next()
        .unwrap_or_default();
    assert!(!warning.contains("F-0002-bbbbbbbb"), "{index}");
}

/// A work dir this release created gets no such warning.
#[test]
fn a_new_work_dir_gets_no_damaged_input_warning() {
    let root = tempfile::tempdir().unwrap();
    let work = root.path().join("work");
    let dir = work.join("results/findings/F-0001-aaaaaaaa");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("testcase.bin"), b"\xef\xbf\xbd\xef\xbf\xbd").unwrap();
    fs::write(
        dir.join("finding.json"),
        r#"{"id":"F-0001-aaaaaaaa","rule_id":"BHF-201","classification":"unhandled"}"#,
    )
    .unwrap();
    let out = bhf(&["report", "--work-dir", work.to_str().unwrap()]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(!text(&out.stderr).contains("EF BF BD"));
    let index = fs::read_to_string(work.join("results/INDEX.md")).unwrap();
    assert!(!index.contains("EF BF BD"), "{index}");
}

/// A `bhf auto` of this release that finds nothing to fuzz writes
/// `auto/run.json` but no seed list; the work dir is still not taken for an
/// earlier release's, so its inputs get no damaged-input warning.
#[test]
fn a_new_work_dir_auto_left_without_a_seed_list_gets_no_damaged_input_warning() {
    let root = tempfile::tempdir().unwrap();
    let work = root.path().join("work");
    let src = root.path().join("src");
    fs::create_dir_all(&src).unwrap();
    let out = bhf(&[
        "auto",
        src.to_str().unwrap(),
        "--work-dir",
        work.to_str().unwrap(),
    ]);
    let stderr = text(&out.stderr);
    assert!(work.join("auto/run.json").is_file(), "{stderr}");
    assert!(!work.join("auto/seeds.json").exists(), "{stderr}");
    let dir = work.join("results/findings/F-0001-aaaaaaaa");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("testcase.bin"), b"\xef\xbf\xbd\xef\xbf\xbd").unwrap();
    fs::write(
        dir.join("finding.json"),
        r#"{"id":"F-0001-aaaaaaaa","rule_id":"BHF-201","classification":"unhandled"}"#,
    )
    .unwrap();
    let out = bhf(&["report", "--work-dir", work.to_str().unwrap()]);
    let stderr = text(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(!stderr.contains("EF BF BD"), "{stderr}");
    assert!(!stderr.contains("earlier bhf release"), "{stderr}");
}

/// A work dir an earlier release already moved to the results layout (or
/// created there) has no migration record, but its corpus came from that
/// release's seed encoding: the first `bhf auto` run sets it aside too.
#[test]
fn auto_sets_aside_the_corpus_of_an_earlier_release_already_on_the_results_layout() {
    let root = tempfile::tempdir().unwrap();
    let work = root.path().join("work");
    let dir = work.join("results/findings/F-0001-aaaaaaaa");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("testcase.bin"),
        b"\x89PNG\xef\xbf\xbd\xef\xbf\xbdIHDR",
    )
    .unwrap();
    fs::write(
        dir.join("finding.json"),
        r#"{"id":"F-0001-aaaaaaaa","rule_id":"BHF-201","classification":"unhandled"}"#,
    )
    .unwrap();
    // What an earlier `bhf auto` left: its state files and a corpus queue.
    fs::create_dir_all(work.join("auto")).unwrap();
    fs::write(work.join("auto/run.json"), "{}").unwrap();
    fs::write(
        work.join("auto/work-state.json"),
        r#"{"schema_version":1,"producer_version":"0.3.0"}"#,
    )
    .unwrap();
    let queue = work.join("corpus/H-1/queue");
    fs::create_dir_all(&queue).unwrap();
    fs::write(queue.join("0001.bin"), b"kept-corpus-entry").unwrap();
    assert!(!work.join("results/legacy/migration.json").exists());

    let src = root.path().join("src");
    fs::create_dir_all(&src).unwrap();
    let out = bhf(&[
        "auto",
        src.to_str().unwrap(),
        "--work-dir",
        work.to_str().unwrap(),
    ]);
    let stderr = text(&out.stderr);
    assert!(
        !work.join("corpus/H-1/queue/0001.bin").exists(),
        "an earlier release's corpus must not stay where auto reseeds from: {stderr}"
    );
    assert_eq!(
        fs::read(work.join("corpus-legacy/H-1/queue/0001.bin")).unwrap(),
        b"kept-corpus-entry"
    );
    assert!(stderr.contains("corpus-legacy"), "{stderr}");
    // The finding the earlier release wrote is still flagged.
    let out = bhf(&["report", "--work-dir", work.to_str().unwrap()]);
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("warning: 1 input") && stderr.contains("EF BF BD"),
        "{stderr}"
    );
}

/// A backfill replay without a symbolizer gives no frames and cannot show
/// where the crash is: the finding is left as it was, and the reason given.
#[test]
fn report_backfill_skips_an_unsymbolized_replay() {
    let root = tempfile::tempdir().unwrap();
    let work = legacy_work_dir(root.path());
    write_harness(
        &work.join("harnesses/H-1/main"),
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000031 at pc 0x1 bp 0x2 sp 0x3\n\
         WRITE of size 1 at 0x602000000031 thread T0\n\
         \x20   #0 0x4f5a2b  (/w/harnesses/H-1/main+0x4f5a2b)\n\
         \n\
         SUMMARY: AddressSanitizer: heap-buffer-overflow (/w/harnesses/H-1/main+0x4f5a2b)\n",
    );
    let out = bhf(&["report", "--backfill", "--work-dir", work.to_str().unwrap()]);
    let stderr = text(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let finding = work.join("results/findings/F-0001-aaaaaaaa");
    assert!(!finding.join("sanitizer.log").exists(), "{stderr}");
    let line = stderr
        .lines()
        .find(|line| line.contains("F-0001-aaaaaaaa"))
        .unwrap_or_else(|| panic!("no backfill line:\n{stderr}"));
    assert!(line.contains("unsymbolized"), "{line}");
}
