// SPDX-License-Identifier: Apache-2.0

use cli::run_from;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn fuzz_builtin_writes_replayable_finding() {
    let temp = temp_dir("builtin-replay");
    let work_dir = temp.join("bhf_work");
    let harness_id = "H-TEST";
    let harness = install_fake_harness(&work_dir, harness_id);

    let fuzz_exit = run_from(vec![
        OsString::from("bhf"),
        OsString::from("fuzz"),
        work_dir.clone().into_os_string(),
        OsString::from("--harness"),
        OsString::from(harness_id),
        OsString::from("--iterations"),
        OsString::from("1"),
        OsString::from("--seed-input"),
        OsString::from("crash"),
    ]);

    assert_eq!(fuzz_exit, 0);
    assert!(work_dir.join("corpus/H-TEST/queue").is_dir());
    let run_summary: serde_json::Value =
        serde_json::from_slice(&fs::read(work_dir.join("fuzz_runs/H-TEST-latest.json")).unwrap())
            .unwrap();
    assert_eq!(run_summary["sandbox"]["mode"], "none");
    let finding_dir = only_finding_dir(&work_dir);
    let finding_json: serde_json::Value =
        serde_json::from_slice(&fs::read(finding_dir.join("finding.json")).unwrap()).unwrap();
    assert_eq!(finding_json["sandbox"]["mode"], "none");
    assert_eq!(finding_json["build"]["sandbox"]["mode"], "none");
    assert_eq!(
        fs::read(finding_dir.join("testcase.bin")).expect("testcase is readable"),
        b"crash"
    );

    let replay_exit = run_from(vec![
        OsString::from("bhf"),
        OsString::from("replay"),
        OsString::from("--finding"),
        finding_dir.into_os_string(),
        OsString::from("--harness"),
        harness.into_os_string(),
    ]);

    assert_eq!(replay_exit, 0);
}

#[test]
fn fuzz_builtin_returns_three_when_harness_executable_missing() {
    let temp = temp_dir("missing-harness");
    let work_dir = temp.join("bhf_work");
    fs::create_dir_all(work_dir.join("build/H-MISSING")).expect("build directory is created");

    let exit = run_from(vec![
        OsString::from("bhf"),
        OsString::from("fuzz"),
        work_dir.into_os_string(),
        OsString::from("--harness"),
        OsString::from("H-MISSING"),
        OsString::from("--iterations"),
        OsString::from("1"),
    ]);

    assert_eq!(exit, 3);
}

#[test]
fn fuzz_builtin_uses_symbolic_seed_source_for_first_execution() {
    let temp = temp_dir("symbolic-seed");
    let work_dir = temp.join("bhf_work");
    let harness_id = "H-TEST";
    let _harness = install_fake_harness(&work_dir, harness_id);
    let source_path = temp.join("guarded.adb");
    fs::write(
        &source_path,
        r#"
procedure Guarded (Input : String) is
begin
   if Input = "match" then
      raise Constraint_Error;
   end if;
end Guarded;
"#,
    )
    .expect("guarded source is written");

    let fuzz_exit = run_from(vec![
        OsString::from("bhf"),
        OsString::from("fuzz"),
        work_dir.clone().into_os_string(),
        OsString::from("--harness"),
        OsString::from(harness_id),
        OsString::from("--iterations"),
        OsString::from("1"),
        OsString::from("--symbolic-seed-source"),
        source_path.into_os_string(),
    ]);

    assert_eq!(fuzz_exit, 0);
    let finding_dir = only_finding_dir(&work_dir);
    assert_eq!(
        fs::read(finding_dir.join("testcase.bin")).expect("testcase is readable"),
        b"match"
    );
}

#[test]
fn fuzz_builtin_summary_records_cmplog_sanitizer_and_execution_metadata() {
    let temp = temp_dir("summary-metadata");
    let work_dir = temp.join("bhf_work");
    let harness_id = "H-TEST";
    let _harness = install_fake_harness(&work_dir, harness_id);
    let cmplog_path = temp.join("cmplog.jsonl");
    fs::write(
        &cmplog_path,
        b"{\"e\":\"cmplog\",\"k\":\"memcmp\",\"a\":\"6372617368\",\"b\":\"4d41474943\"}\n",
    )
    .expect("cmplog fixture is written");

    let fuzz_exit = run_from(vec![
        OsString::from("bhf"),
        OsString::from("fuzz"),
        work_dir.clone().into_os_string(),
        OsString::from("--harness"),
        OsString::from(harness_id),
        OsString::from("--iterations"),
        OsString::from("1"),
        OsString::from("--seed-input"),
        OsString::from("crash"),
        OsString::from("--cmplog-log"),
        cmplog_path.into_os_string(),
        OsString::from("--sanitizers"),
        OsString::from("asan"),
    ]);

    assert_eq!(fuzz_exit, 0);
    let run_summary: serde_json::Value =
        serde_json::from_slice(&fs::read(work_dir.join("fuzz_runs/H-TEST-latest.json")).unwrap())
            .unwrap();
    assert_eq!(
        run_summary["execution"]["harness_protocol"],
        "stdin_event_log"
    );
    assert_eq!(run_summary["execution"]["forkserver"], false);
    assert_eq!(run_summary["execution"]["persistent"], false);
    assert_eq!(run_summary["cmplog"]["enabled"], true);
    assert_eq!(run_summary["cmplog"]["entries"], 1);
    assert_eq!(run_summary["cmplog"]["dictionary_tokens"], 2);
    assert_eq!(run_summary["cmplog"]["seed_splice_candidates"], 1);
    assert_eq!(run_summary["sanitizers"]["requested"][0], "asan");
    assert_eq!(
        run_summary["sanitizers"]["active_env"][0]["key"],
        "ASAN_OPTIONS"
    );
    // #405: fuzz_runs/<hid>-*.json carries measured wall + throughput, and the
    // throughput is internally consistent with executions / elapsed_secs.
    let elapsed = run_summary["elapsed_secs"]
        .as_f64()
        .expect("elapsed_secs present");
    let eps = run_summary["executions_per_sec"]
        .as_f64()
        .expect("executions_per_sec present");
    assert!(elapsed >= 0.0, "elapsed_secs {elapsed}");
    assert!(eps >= 0.0, "executions_per_sec {eps}");
    if elapsed > 0.0 {
        let execs = run_summary["executions"].as_f64().unwrap();
        assert!(
            (eps - execs / elapsed).abs() < 1.0,
            "exec/s {eps} should equal executions {execs} / elapsed {elapsed}"
        );
    }
}

#[cfg(unix)]
#[test]
fn fuzz_multicore_cli_writes_campaign_summary() {
    use std::os::unix::fs::PermissionsExt;

    let temp = temp_dir("multicore-cli");
    let work_dir = temp.join("bhf_work");
    // The parent resolves the harness before it starts any worker.
    install_fake_harness(&work_dir, "H-MULTI");
    fs::create_dir_all(work_dir.join("corpus/H-MULTI/queue")).expect("queue is created");
    fs::write(work_dir.join("corpus/H-MULTI/queue/base.bin"), b"base").unwrap();
    let script = temp.join("fake-bhf.sh");
    fs::write(
        &script,
        r#"#!/bin/sh
set -eu
worker_dir="$2"
harness=""
while [ $# -gt 0 ]; do
  case "$1" in
    --harness) harness="$2"; shift 2 ;;
    *) shift ;;
  esac
done
test -f "$BHF_SHARED_CORPUS_DIR/base.bin"
mkdir -p "$worker_dir/corpus/$harness/queue"
printf "cli-worker-%s" "$BHF_WORKER_ID" > "$worker_dir/corpus/$harness/queue/cli-worker-$BHF_WORKER_ID.bin"
"#,
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

    let fuzz_exit = run_from(vec![
        OsString::from("bhf"),
        OsString::from("fuzz"),
        work_dir.clone().into_os_string(),
        OsString::from("--harness"),
        OsString::from("H-MULTI"),
        OsString::from("--iterations"),
        OsString::from("1"),
        OsString::from("--workers"),
        OsString::from("2"),
        OsString::from("--sanitizers"),
        OsString::from("asan,ubsan"),
        OsString::from("--bhf-bin"),
        script.into_os_string(),
    ]);

    assert_eq!(fuzz_exit, 0);
    let campaign_summary_path = work_dir.join("fuzz_campaigns/H-MULTI-latest.json");
    assert!(campaign_summary_path.is_file());
    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(campaign_summary_path).unwrap()).unwrap();
    assert_eq!(summary["workers_started"], 2);
    assert_eq!(summary["workers_completed"], 2);
    assert_eq!(summary["sync"]["seed_inputs_loaded"], 1);
    assert_eq!(summary["sync"]["imported_inputs"], 2);
    assert_eq!(summary["per_worker"][0]["env_keys"][0], "ASAN_OPTIONS");
    assert_eq!(summary["per_worker"][1]["env_keys"][0], "UBSAN_OPTIONS");
}

#[cfg(unix)]
#[test]
fn fuzz_multicore_merges_worker_findings_into_the_parent_index() {
    use std::os::unix::fs::PermissionsExt;

    let temp = temp_dir("multicore-merge");
    let work_dir = temp.join("bhf_work");
    install_fake_harness(&work_dir, "H-MULTI");
    fs::create_dir_all(work_dir.join("corpus/H-MULTI/queue")).unwrap();

    // What each worker "finds": worker 0 crash X; worker 1 crash X again
    // (same cluster, other signature) and crash Y.
    let crash = |signature: &str, cluster: &str, function: &str| {
        serde_json::json!({
            "id": format!("F-0000-{}", &signature[..8]),
            "signature": signature,
            "cluster_key": &cluster[..8],
            "cluster_key_full": cluster,
            "rule_id": "BHF-201",
            "classification": "unhandled",
            "harness_id": "H-MULTI",
            "exception": {
                "name": "ASAN_HEAP_BUFFER_OVERFLOW",
                "message": "heap-buffer-overflow READ of size 4",
                "sanitizer": "asan",
                "stack": [{"function": function, "file": "/src/demo/parse.c", "line": 42}]
            },
            "paths": {"testcase": "testcase.bin", "finding": "finding.json"}
        })
    };
    let templates = temp.join("templates");
    for (worker, name, record) in [
        (
            "0",
            "F-0000-aaaaaaaa",
            crash("aaaaaaaa11", "c1c1c1c1c1c1c1c1", "parse_header"),
        ),
        (
            "1",
            "F-0000-bbbbbbbb",
            crash("bbbbbbbb22", "c1c1c1c1c1c1c1c1", "parse_header"),
        ),
        (
            "1",
            "F-0001-cccccccc",
            crash("cccccccc33", "c2c2c2c2c2c2c2c2", "parse_body"),
        ),
    ] {
        let dir = templates.join(worker).join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("finding.json"),
            serde_json::to_vec_pretty(&record).unwrap(),
        )
        .unwrap();
        fs::write(dir.join("testcase.bin"), name.as_bytes()).unwrap();
    }
    let script = temp.join("fake-bhf.sh");
    fs::write(
        &script,
        "#!/bin/sh\nset -eu\nmkdir -p \"$2/results/findings\"\n\
         cp -R \"$BHF_TEST_TEMPLATES/$BHF_WORKER_ID/.\" \"$2/results/findings/\"\n",
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("fuzz")
        .arg(&work_dir)
        .args([
            "--harness",
            "H-MULTI",
            "--iterations",
            "1",
            "--workers",
            "2",
        ])
        .arg("--bhf-bin")
        .arg(&script)
        .env("BHF_TEST_TEMPLATES", &templates)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");

    let parent = work_dir.join("results/findings");
    let mut ids: Vec<String> = fs::read_dir(&parent)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    ids.sort();
    assert_eq!(ids, ["F-0000-aaaaaaaa", "F-0001-cccccccc"], "{stderr}");
    for id in &ids {
        let record: serde_json::Value =
            serde_json::from_slice(&fs::read(parent.join(id).join("finding.json")).unwrap())
                .unwrap();
        assert_eq!(record["id"], id.as_str(), "id matches the parent dir");
    }
    let index: serde_json::Value =
        serde_json::from_slice(&fs::read(work_dir.join("results/findings.json")).unwrap()).unwrap();
    let indexed: Vec<&str> = index["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap())
        .collect();
    assert!(
        indexed.contains(&"F-0000-aaaaaaaa") && indexed.contains(&"F-0001-cccccccc"),
        "{index}"
    );
    assert!(stderr.contains("(2 findings"), "{stderr}");
}

/// A harness laid out the way `bhf auto` builds it: `harnesses/<id>/main`, with
/// no `build/<id>/` at all.
fn install_auto_layout_harness(work_dir: &Path, harness_id: &str) -> PathBuf {
    let harness = PathBuf::from(env!("CARGO_BIN_EXE_cli_fake_harness"));
    let target = work_dir.join("harnesses").join(harness_id).join("main");
    fs::create_dir_all(target.parent().expect("target has parent"))
        .expect("harness directory is created");
    fs::copy(&harness, &target).expect("fake harness is copied");
    make_executable(&target);
    target
}

fn finding_ids(work_dir: &Path) -> Vec<String> {
    let mut ids: Vec<String> = fs::read_dir(work_dir.join("results/findings"))
        .map(|entries| {
            entries
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect()
        })
        .unwrap_or_default();
    ids.sort();
    ids
}

/// `bhf fuzz` run as its own process (so multicore workers re-exec the real
/// binary), returning `(exit code, stdout JSON, stderr)`.
fn fuzz_process(work_dir: &Path, args: &[&str]) -> (Option<i32>, serde_json::Value, String) {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("fuzz")
        .arg(work_dir)
        .args(args)
        .output()
        .expect("bhf fuzz runs");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json = serde_json::from_str(stdout.trim()).unwrap_or(serde_json::Value::Null);
    (output.status.code(), json, stderr)
}

#[cfg(unix)]
#[test]
fn fuzz_workers_find_an_auto_layout_harness() {
    let temp = temp_dir("multicore-auto-layout");
    let work_dir = temp.join("bhf_work");
    install_auto_layout_harness(&work_dir, "H-AUTO");

    let (code, summary, stderr) = fuzz_process(
        &work_dir,
        &[
            "--harness",
            "H-AUTO",
            "--iterations",
            "1",
            "--seed-input",
            "crash",
            "--workers",
            "2",
        ],
    );

    assert_eq!(code, Some(0), "{stderr}");
    assert_eq!(summary["workers_started"], 2, "{summary}");
    assert_eq!(summary["workers_completed"], 2, "{summary}\n{stderr}");
    assert_eq!(finding_ids(&work_dir).len(), 1, "{stderr}");
}

#[cfg(unix)]
#[test]
fn fuzz_sanitizer_matrix_finds_an_auto_layout_harness() {
    let temp = temp_dir("matrix-auto-layout");
    let work_dir = temp.join("bhf_work");
    install_auto_layout_harness(&work_dir, "H-AUTO");

    let (code, summary, stderr) = fuzz_process(
        &work_dir,
        &[
            "--harness",
            "H-AUTO",
            "--iterations",
            "1",
            "--seed-input",
            "crash",
            "--sanitizers",
            "asan,ubsan",
        ],
    );

    assert_eq!(code, Some(0), "{stderr}");
    assert_eq!(summary["workers_completed"], 2, "{summary}\n{stderr}");
    assert_eq!(summary["per_worker"][0]["env_keys"][0], "ASAN_OPTIONS");
    assert_eq!(summary["per_worker"][1]["env_keys"][0], "UBSAN_OPTIONS");
    assert_eq!(finding_ids(&work_dir).len(), 1, "{stderr}");
}

/// A libFuzzer-style shell harness in `dir` that reports an ASan crash in
/// `function` on every input.
#[cfg(unix)]
fn install_crashing_script_harness(dir: &Path, function: &str) {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("main.c"), "// marker for libFuzzer detection\n").unwrap();
    let main = dir.join("main");
    fs::write(
        &main,
        format!(
            "#!/bin/sh\n\
             >&2 echo 'ERROR: AddressSanitizer: heap-buffer-overflow on address 0x601 at pc 0x333'\n\
             >&2 echo '    #0 0x333 in {function} /src/record.c:15'\n\
             >&2 echo '    #1 0x334 in LLVMFuzzerTestOneInput /src/h.c:20'\n\
             exit 1\n"
        ),
    )
    .unwrap();
    make_executable(&main);
}

#[cfg(unix)]
#[test]
fn fuzz_workers_run_the_harness_the_parent_resolves_after_it_moves() {
    // Campaign 1 fuzzes `build/<id>/main`. The build dir is then removed and the
    // harness rebuilt under `harnesses/<id>/`: campaign 2's workers must run the
    // new binary, not the copy of the old build dir left in their trees.
    let temp = temp_dir("multicore-moved-harness");
    let work_dir = temp.join("bhf_work");
    install_crashing_script_harness(&work_dir.join("build/H-MOVED"), "old_copy_at");
    let args = [
        "--harness",
        "H-MOVED",
        "--iterations",
        "2",
        "--seed-input",
        "x",
        "--workers",
        "2",
    ];
    let (code, _, stderr) = fuzz_process(&work_dir, &args);
    assert_eq!(code, Some(0), "{stderr}");
    let before = finding_ids(&work_dir);
    assert_eq!(before.len(), 1, "{stderr}");

    fs::remove_dir_all(work_dir.join("build/H-MOVED")).unwrap();
    install_crashing_script_harness(&work_dir.join("harnesses/H-MOVED"), "current_copy_at");
    let (code, _, stderr) = fuzz_process(&work_dir, &args);
    assert_eq!(code, Some(0), "{stderr}");
    let new: Vec<String> = finding_ids(&work_dir)
        .into_iter()
        .filter(|id| !before.contains(id))
        .collect();
    assert_eq!(
        new.len(),
        1,
        "the current harness's crash is recorded: {stderr}"
    );
    let record = fs::read_to_string(
        work_dir
            .join("results/findings")
            .join(&new[0])
            .join("finding.json"),
    )
    .unwrap();
    assert!(record.contains("current_copy_at"), "{record}");
    assert!(!record.contains("old_copy_at"), "{record}");
    for worker in 0..2 {
        let tree = work_dir.join(format!("worker-H-MOVED-{worker}"));
        assert!(!tree.join("build/H-MOVED").exists(), "{}", tree.display());
        assert!(tree.join("harnesses/H-MOVED/main").is_file());
    }
}

#[cfg(unix)]
#[test]
fn fuzz_multicore_fails_and_shows_worker_stderr_when_no_worker_completes() {
    let temp = temp_dir("multicore-no-worker");
    let work_dir = temp.join("bhf_work");
    install_auto_layout_harness(&work_dir, "H-AUTO");
    let script = temp.join("broken-bhf.sh");
    fs::write(
        &script,
        "#!/bin/sh\necho 'starting worker' >&2\n\
         echo 'error while loading shared libraries: libwidget.so' >&2\nexit 3\n",
    )
    .unwrap();
    make_executable(&script);

    let (code, summary, stderr) = fuzz_process(
        &work_dir,
        &[
            "--harness",
            "H-AUTO",
            "--iterations",
            "1",
            "--workers",
            "2",
            "--bhf-bin",
            script.to_str().unwrap(),
        ],
    );

    assert_ne!(code, Some(0), "no worker completed: {stderr}");
    assert_eq!(summary["workers_completed"], 0, "{summary}");
    assert!(
        stderr.contains("error while loading shared libraries: libwidget.so"),
        "each failing worker's stderr tail is printed: {stderr}"
    );
    assert!(stderr.contains("worker 1"), "{stderr}");
}

#[cfg(unix)]
#[test]
fn fuzz_workers_do_not_bring_back_a_removed_finding_of_an_old_harness() {
    // Campaign 1's two workers both find the old harness's crash: one copy is
    // merged, the other stays in its worker dir as a duplicate. results/ is then
    // wiped and the harness replaced by one that never crashes. Campaign 2 must
    // neither run the old binary nor merge the old duplicate back.
    let temp = temp_dir("multicore-wiped-results");
    let work_dir = temp.join("bhf_work");
    install_crashing_script_harness(&work_dir.join("build/H-WIPE"), "old_copy_at");
    let args = [
        "--harness",
        "H-WIPE",
        "--iterations",
        "2",
        "--seed-input",
        "x",
        "--workers",
        "2",
    ];
    let (code, _, stderr) = fuzz_process(&work_dir, &args);
    assert_eq!(code, Some(0), "{stderr}");
    assert_eq!(finding_ids(&work_dir).len(), 1, "{stderr}");

    fs::remove_dir_all(work_dir.join("build/H-WIPE")).unwrap();
    fs::remove_dir_all(work_dir.join("results")).unwrap();
    let harness = work_dir.join("harnesses/H-WIPE");
    fs::create_dir_all(&harness).unwrap();
    fs::write(
        harness.join("main.c"),
        "// marker for libFuzzer detection\n",
    )
    .unwrap();
    fs::write(harness.join("main"), "#!/bin/sh\nexit 0\n").unwrap();
    make_executable(&harness.join("main"));
    let (code, _, stderr) = fuzz_process(&work_dir, &args);
    assert_eq!(code, Some(0), "{stderr}");
    assert_eq!(finding_ids(&work_dir), Vec::<String>::new(), "{stderr}");
}

/// A finding dir (`F-0000-aaaaaaaa`) a stand-in worker copies into its
/// results, as a worker that found a crash would leave it.
fn write_worker_finding_template(temp: &Path, harness_id: &str) -> PathBuf {
    let finding = temp.join("template/F-0000-aaaaaaaa");
    fs::create_dir_all(&finding).unwrap();
    let record = serde_json::json!({
        "id": "F-0000-aaaaaaaa",
        "signature": "aaaaaaaa11",
        "cluster_key": "c1c1c1c1",
        "cluster_key_full": "c1c1c1c1c1c1c1c1",
        "rule_id": "BHF-201",
        "classification": "unhandled",
        "harness_id": harness_id,
        "exception": {
            "name": "ASAN_HEAP_BUFFER_OVERFLOW",
            "message": "heap-buffer-overflow READ of size 4",
            "sanitizer": "asan",
            "stack": [{"function": "copy_at", "file": "/src/record.c", "line": 15}]
        },
        "paths": {"testcase": "testcase.bin", "finding": "finding.json"}
    });
    fs::write(
        finding.join("finding.json"),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();
    fs::write(finding.join("testcase.bin"), b"x").unwrap();
    finding
}

#[cfg(unix)]
#[test]
fn fuzz_multicore_workers_that_all_fail_after_finding_something_are_not_called_idle() {
    let temp = temp_dir("multicore-failed-with-findings");
    let work_dir = temp.join("bhf_work");
    install_auto_layout_harness(&work_dir, "H-LATE");
    let finding = write_worker_finding_template(&temp, "H-LATE");
    let script = temp.join("late-failure.sh");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nmkdir -p \"$2/results/findings\"\n\
             cp -R '{}' \"$2/results/findings/\"\necho 'write failed' >&2\nexit 4\n",
            finding.display()
        ),
    )
    .unwrap();
    make_executable(&script);

    let (code, _, stderr) = fuzz_process(
        &work_dir,
        &[
            "--harness",
            "H-LATE",
            "--iterations",
            "1",
            "--workers",
            "2",
            "--bhf-bin",
            script.to_str().unwrap(),
        ],
    );

    assert_eq!(code, Some(4), "every worker failed with 4: {stderr}");
    assert!(
        stderr.contains("recorded before failing were merged"),
        "{stderr}"
    );
    assert!(!stderr.contains("fuzzed nothing"), "{stderr}");
    assert_eq!(finding_ids(&work_dir).len(), 1, "{stderr}");
}

#[cfg(unix)]
#[test]
fn fuzz_multicore_workers_stopped_at_the_time_limit_keep_what_they_found() {
    // Each worker records a finding, then outlives the time limit and is
    // stopped. That campaign fuzzed: it must not fail as one that ran nothing.
    let temp = temp_dir("multicore-stopped");
    let work_dir = temp.join("bhf_work");
    install_auto_layout_harness(&work_dir, "H-SLOW");
    let finding = write_worker_finding_template(&temp, "H-SLOW");
    let script = temp.join("slow-worker.sh");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nmkdir -p \"$2/results/findings\"\n\
             cp -R '{}' \"$2/results/findings/\"\necho 'fuzzing' >&2\nexec sleep 30\n",
            finding.display()
        ),
    )
    .unwrap();
    make_executable(&script);

    let (code, summary, stderr) = fuzz_process(
        &work_dir,
        &[
            "--harness",
            "H-SLOW",
            "--time",
            "1s",
            "--workers",
            "2",
            "--bhf-bin",
            script.to_str().unwrap(),
        ],
    );

    assert_eq!(code, Some(0), "{stderr}");
    assert_eq!(summary["workers_completed"], 0, "{summary}");
    assert_eq!(
        summary["per_worker"][0]["stopped_at_deadline"], true,
        "{summary}"
    );
    assert!(stderr.contains("stopped at the time limit"), "{stderr}");
    assert!(!stderr.contains("fuzzed nothing"), "{stderr}");
    assert_eq!(finding_ids(&work_dir).len(), 1, "{stderr}");
}

#[test]
fn fuzz_reports_crashes_that_match_findings_already_recorded() {
    let temp = temp_dir("duplicate-of-existing");
    let work_dir = temp.join("bhf_work");
    install_fake_harness(&work_dir, "H-TEST");
    let args = [
        "--harness",
        "H-TEST",
        "--iterations",
        "1",
        "--seed-input",
        "crash",
    ];

    let (code, first, stderr) = fuzz_process(&work_dir, &args);
    assert_eq!(code, Some(0), "{stderr}");
    let recorded = first["findings"][0]
        .as_str()
        .expect("first run records it")
        .to_owned();

    let (code, second, stderr) = fuzz_process(&work_dir, &args);
    assert_eq!(code, Some(0), "{stderr}");
    assert_eq!(second["findings"], serde_json::json!([]), "{second}");
    assert_eq!(
        second["duplicates_of_existing"],
        serde_json::json!([recorded]),
        "{second}"
    );
    assert!(
        stderr.contains(&recorded) && stderr.contains("already recorded"),
        "a stderr note names the existing finding: {stderr}"
    );
    assert_eq!(finding_ids(&work_dir), [recorded]);
}

fn install_fake_harness(work_dir: &Path, harness_id: &str) -> PathBuf {
    let harness = PathBuf::from(env!("CARGO_BIN_EXE_cli_fake_harness"));
    let target = work_dir
        .join("build")
        .join(harness_id)
        .join("obj")
        .join("main");
    fs::create_dir_all(target.parent().expect("target has parent"))
        .expect("harness build directory is created");
    fs::copy(&harness, &target).expect("fake harness is copied");
    make_executable(&target);
    target
}

fn only_finding_dir(work_dir: &Path) -> PathBuf {
    let findings_root = work_dir.join("results").join("findings");
    let findings = fs::read_dir(&findings_root)
        .expect("findings directory is readable")
        .map(|entry| entry.expect("finding entry is readable").path())
        .collect::<Vec<_>>();

    assert_eq!(findings.len(), 1);
    findings.into_iter().next().expect("one finding exists")
}

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time is after unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("bhf-fuzz-cli-{name}-{nonce}"));
    fs::create_dir_all(&dir).expect("temporary directory is created");
    dir
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)
        .expect("metadata is readable")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("permissions are updated");
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}
