// SPDX-License-Identifier: Apache-2.0

//! `bhf fuzz --engine honggfuzz` (#295): run honggfuzz in persistent mode on
//! the harness's honggfuzz build (`main_honggfuzz`, the harness Makefile's
//! `honggfuzz` target, compiled by `hfuzz-clang`) for the run's budget, and
//! record the crashes it saves through the external-engine ingest the AFL++
//! and libFuzzer engines use. honggfuzz is found as `BHF_HONGGFUZZ_PATH` (its
//! build directory, with `hfuzz_cc/hfuzz-clang`) or as `honggfuzz` on PATH.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::{
    coverage_from_env, ensure_harness_scratch, find_generated_dictionary, find_learned_dictionary,
    kill_process_group, load_cmplog_for_run, reset_target_entry, sanitizer_summary,
    target_entry_from_env, write_run_summary, ExecutionRunSummary, ExternalIngest, FuzzRunSummary,
    PreparedFuzzRun, TraceInput,
};

/// The honggfuzz build's file name (`.exe` added on Windows).
pub(super) const HONGGFUZZ_BINARY: &str = "main_honggfuzz";

/// Where honggfuzz and its compiler wrapper are.
pub(super) struct Tools {
    honggfuzz: PathBuf,
    hfuzz_cc: Option<PathBuf>,
}

impl Tools {
    /// `BHF_HONGGFUZZ_PATH`'s, else the ones on PATH.
    pub(super) fn find() -> Result<Self, String> {
        if let Some(dir) = std::env::var_os("BHF_HONGGFUZZ_PATH").map(PathBuf::from) {
            let honggfuzz = dir.join("honggfuzz");
            if !honggfuzz.is_file() {
                return Err(format!(
                    "BHF_HONGGFUZZ_PATH names {}, which holds no honggfuzz",
                    dir.display()
                ));
            }
            let hfuzz_cc = [dir.join("hfuzz_cc/hfuzz-clang"), dir.join("hfuzz-clang")]
                .into_iter()
                .find(|path| path.is_file());
            return Ok(Self {
                honggfuzz,
                hfuzz_cc,
            });
        }
        let honggfuzz = which::which("honggfuzz").map_err(|_| {
            "--engine honggfuzz needs honggfuzz: put it on PATH or name its build directory \
             in BHF_HONGGFUZZ_PATH"
                .to_owned()
        })?;
        let hfuzz_cc = which::which("hfuzz-clang").ok().or_else(|| {
            honggfuzz
                .parent()
                .map(|dir| dir.join("hfuzz_cc/hfuzz-clang"))
                .filter(|path| path.is_file())
        });
        Ok(Self {
            honggfuzz,
            hfuzz_cc,
        })
    }
}

/// The harness's honggfuzz build: `main_honggfuzz` in its build or harness
/// directory, or one `make honggfuzz` builds from the harness Makefile with
/// honggfuzz's `hfuzz-clang`.
pub(super) fn ensure_binary(work_dir: &Path, harness_id: &str) -> Result<PathBuf, String> {
    let dirs = [
        work_dir.join("build").join(harness_id),
        crate::auto::layout::harness_dir(work_dir, harness_id),
        crate::auto::layout::legacy_auto_harness_dir(work_dir, harness_id),
        work_dir.join("generated_harnesses").join(harness_id),
    ];
    for dir in &dirs {
        let exe = crate::auto::layout::harness_exe(dir, HONGGFUZZ_BINARY);
        if exe.is_file() {
            return Ok(exe);
        }
    }
    let harness_dir = dirs[1..]
        .iter()
        .find(|dir| dir.join("Makefile").is_file())
        .ok_or_else(|| {
            format!("no {HONGGFUZZ_BINARY} for harness {harness_id}, and no harness Makefile to build one")
        })?;
    let tools = Tools::find()?;
    let hfuzz_cc = tools.hfuzz_cc.ok_or_else(|| {
        format!(
            "building {HONGGFUZZ_BINARY} needs honggfuzz's hfuzz-clang, which is neither on PATH \
             nor beside {}",
            tools.honggfuzz.display()
        )
    })?;
    bhfeprintln!(
        "bhf fuzz: building {HONGGFUZZ_BINARY} with `make honggfuzz` in {}",
        harness_dir.display()
    );
    let mut make = Command::new("make");
    make.current_dir(harness_dir)
        .arg("honggfuzz")
        .arg(format!("HFUZZ_CC={}", hfuzz_cc.display()));
    let force_includes = crate::build::repair_force_includes(harness_dir);
    crate::build::apply_c_family_make_env(&mut make, &[], &[], &force_includes, None);
    let output =
        crate::command_output::output_with_timeout(&mut make, Duration::from_secs(30 * 60))
            .map_err(|error| format!("run `make honggfuzz`: {error}"))?;
    let exe = crate::auto::layout::harness_exe(harness_dir, HONGGFUZZ_BINARY);
    if !output.status.success() || !exe.is_file() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let tail: Vec<&str> = stderr.lines().rev().take(12).collect();
        return Err(format!(
            "`make honggfuzz` did not build {}: {}",
            exe.display(),
            tail.into_iter().rev().collect::<Vec<_>>().join("\n")
        ));
    }
    Ok(exe)
}

/// What honggfuzz's closing `Summary` line reports: the inputs it ran and
/// their rate (`Summary iterations:15093 time:10 speed:1509 ...`).
fn summary_stats(log: &str) -> (Option<u64>, Option<f64>) {
    let Some(line) = log
        .lines()
        .rev()
        .find(|line| line.contains("Summary iterations:"))
    else {
        return (None, None);
    };
    let field = |name: &str| {
        line.split_whitespace()
            .find_map(|word| word.strip_prefix(name))
            .map(str::to_owned)
    };
    (
        field("iterations:").and_then(|value| value.parse().ok()),
        field("speed:").and_then(|value| value.parse().ok()),
    )
}

/// A crash file honggfuzz saved: it names each by its signal and site
/// (`SIGABRT.PC.7ffff7a42e9c.STACK.1a2b3c.CODE.-6.ADDR.0.INSTR.mov.fuzz`).
fn is_crash_file(name: &str) -> bool {
    name.ends_with(".fuzz") && name.starts_with("SIG")
}

/// Run `main_honggfuzz` on `input`, as a file argument, once: libhfuzz runs
/// a single input outside honggfuzz.
fn replay(
    harness: &Path,
    work_dir: &Path,
    input: &[u8],
    env: &[(String, String)],
    timeout: Option<Duration>,
) -> Result<std::process::Output, String> {
    let scratch = ensure_harness_scratch(work_dir)?;
    let file = scratch.join(format!("honggfuzz-replay-{}.bin", std::process::id()));
    fs::write(&file, input).map_err(|error| format!("write '{}': {error}", file.display()))?;
    let mut command = Command::new(harness);
    command
        .arg(&file)
        .current_dir(&scratch)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (key, value) in env {
        command.env(key, value);
    }
    super::apply_runaway_rlimits(&mut command);
    let output = match timeout {
        Some(timeout) => crate::command_output::output_with_timeout(&mut command, timeout),
        None => command.output(),
    }
    .map_err(|error| format!("run '{}': {error}", harness.display()));
    let _ = fs::remove_file(&file);
    output
}

pub(super) fn run(prepared: PreparedFuzzRun) -> Result<FuzzRunSummary, String> {
    let tools = Tools::find()?;
    run_with(prepared, &tools.honggfuzz)
}

/// [`run`] with `honggfuzz` as the honggfuzz to run.
fn run_with(prepared: PreparedFuzzRun, honggfuzz: &Path) -> Result<FuzzRunSummary, String> {
    reset_target_entry(&prepared.extra_env);
    let (_, cmplog_summary) = load_cmplog_for_run(prepared.cmplog_log.as_deref(), &prepared.seeds);
    let root = prepared
        .work_dir
        .join("honggfuzz")
        .join(&prepared.harness_id);
    let corpus = root.join("corpus");
    let workspace = root.join("workspace");
    let crashes = root.join("crashes");
    // This run's workspace and crashes only: the corpus carries on, and this
    // run's seeds join it.
    let _ = fs::remove_dir_all(&workspace);
    let _ = fs::remove_dir_all(&crashes);
    for dir in [&corpus, &workspace, &crashes] {
        fs::create_dir_all(dir).map_err(|error| format!("create '{}': {error}", dir.display()))?;
    }
    for (index, seed) in prepared.seeds.iter().enumerate() {
        let path = corpus.join(format!("seed-{index:04}"));
        fs::write(&path, seed).map_err(|error| format!("write '{}': {error}", path.display()))?;
    }
    let time_budget = prepared.time.unwrap_or_else(|| {
        // As for AFL++: 100 ms per requested iteration, within 1 s and 30 s.
        let ms = (prepared.iterations as u64).saturating_mul(100).min(30_000);
        Duration::from_millis(ms.max(1_000))
    });
    let limit = prepared.per_input_timeout.max(Duration::from_secs(1));
    let log_path = root.join("honggfuzz.log");
    let log_file = fs::File::create(&log_path)
        .map_err(|error| format!("create '{}': {error}", log_path.display()))?;

    let mut command = Command::new(honggfuzz);
    command
        .current_dir(ensure_harness_scratch(&prepared.work_dir)?)
        .arg("--persistent")
        .arg("--input")
        .arg(&corpus)
        .arg("--workspace")
        .arg(&workspace)
        .arg("--crashdir")
        .arg(&crashes)
        .arg("--run_time")
        .arg(time_budget.as_secs().max(1).to_string())
        .arg("--timeout")
        .arg(limit.as_secs().max(1).to_string())
        .arg("--max_file_size")
        .arg(prepared.max_len.max(1).to_string())
        .arg("--rlimit_rss")
        .arg(prepared.rss_limit_mb.to_string())
        .arg("--threads")
        .arg("1")
        .arg("--quiet");
    if prepared.time.is_none() && prepared.iterations != usize::MAX {
        command
            .arg("--iterations")
            .arg(prepared.iterations.to_string());
    }
    if let Some(dictionary) = prepared
        .dict_file
        .clone()
        .or_else(|| find_generated_dictionary(&prepared.work_dir, &prepared.harness_id))
        .or_else(|| find_learned_dictionary(&prepared.work_dir, &prepared.harness_id))
    {
        command.arg("--dict").arg(dictionary);
    }
    command
        .arg("--")
        .arg(&prepared.harness_path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(
            log_file
                .try_clone()
                .map_err(|error| format!("honggfuzz log: {error}"))?,
        ))
        .stderr(Stdio::from(log_file));
    for (key, value) in &prepared.extra_env {
        command.env(key, value);
    }
    replay_min::process::isolate_process_group(&mut command);
    let start = Instant::now();
    let mut child = command
        .spawn()
        .map_err(|error| format!("spawn '{}': {error}", honggfuzz.display()))?;
    // honggfuzz stops itself at --run_time; this is the backstop for a
    // wedged run.
    let hard_deadline = start + time_budget.saturating_mul(2) + Duration::from_secs(30);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() >= hard_deadline => {
                kill_process_group(&mut child);
                let _ = child.wait();
                bhfeprintln!("bhf: warning: honggfuzz ran past its time budget and was stopped");
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(error) => return Err(format!("wait for honggfuzz: {error}")),
        }
    }
    let elapsed = start.elapsed();
    let log = fs::read_to_string(&log_path).unwrap_or_default();
    let (executions, per_sec) = summary_stats(&log);

    let mut ingest = ExternalIngest::new(
        &prepared,
        "honggfuzz",
        "its own corpus",
        TraceInput::ArgvFile,
    )?;
    let mut saved: Vec<PathBuf> = fs::read_dir(&crashes)
        .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
        .unwrap_or_default();
    saved.sort();
    let mut crash_count = 0_usize;
    for path in saved {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("")
            .to_owned();
        if !is_crash_file(&name) {
            continue;
        }
        crash_count += 1;
        let input = fs::read(&path)
            .map_err(|error| format!("read crash file '{}': {error}", path.display()))?;
        ingest.crash(
            &input,
            &format!("crash file {name}"),
            hard_deadline,
            &|input, env, timeout| {
                replay(
                    &prepared.harness_path,
                    &prepared.work_dir,
                    input,
                    env,
                    timeout,
                )
            },
        )?;
    }

    let summary = FuzzRunSummary {
        schema_version: 1,
        harness_id: prepared.harness_id.clone(),
        engine: "honggfuzz".to_owned(),
        mode: prepared.mode,
        harness_path: prepared.harness_path.clone(),
        sandbox: prepared.runner.sandbox_metadata(),
        iterations_requested: prepared.iterations,
        executions: executions.map(|n| n as usize).unwrap_or(crash_count),
        target_entry_observed: target_entry_from_env(&prepared.extra_env),
        corpus_new: crash_count,
        corpus_duplicates: 0,
        corpus_persisted: fs::read_dir(&corpus)
            .map(|entries| entries.count())
            .unwrap_or(0),
        execution: ExecutionRunSummary {
            harness_protocol: "honggfuzz_persistent".to_owned(),
            forkserver: false,
            persistent: true,
            persistent_iterations: None,
        },
        cmplog: cmplog_summary,
        sanitizers: sanitizer_summary(&prepared.sanitizers, &prepared.sanitizer_env, false),
        coverage: coverage_from_env(&prepared.extra_env, &prepared.harness_path),
        findings: ingest.finding_ids.clone(),
        duplicates_of_existing: Vec::new(),
        duplicate_crashes_of_existing: 0,
        elapsed_secs: elapsed.as_secs_f64(),
        executions_per_sec: per_sec.unwrap_or(0.0),
        afl: None,
        winafl: None,
        extension: None,
        duplicate_sanitizer_hits: ingest.dedup.duplicate_hits(),
        unreproduced_sanitizer_hits: ingest.dedup.unreproduced_hits(),
        fresh_reruns: None,
        hangs: None,
        stability: None,
    };
    write_run_summary(&prepared.work_dir, &summary)?;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honggfuzz_crash_files_and_its_summary_are_read() {
        assert!(is_crash_file(
            "SIGABRT.PC.7ffff7a42e9c.STACK.1a2b3c.CODE.-6.ADDR.0.INSTR.mov.fuzz"
        ));
        assert!(is_crash_file(
            "SIGSEGV.PC.555555.STACK.ff.CODE.1.ADDR.0.INSTR.[UNKNOWN].fuzz"
        ));
        assert!(!is_crash_file("HONGGFUZZ.REPORT.TXT"));
        assert!(!is_crash_file("seed-ab12"));
        let log = "Start time:'2026-11-18.04.11.03' bin:'./main_honggfuzz'\n\
                   [2026-11-18T04:11:13+0000][I][1] Summary iterations:15093 time:10 \
                   speed:1509 crashes_count:1 timeout_count:0 new_units_added:12\n";
        assert_eq!(summary_stats(log), (Some(15093), Some(1509.0)));
        assert_eq!(summary_stats("no summary"), (None, None));
    }

    /// The crash files a honggfuzz run saved are replayed through the
    /// harness and recorded as findings: a stand-in honggfuzz saves one, and
    /// a stand-in harness reports it as ASan does.
    #[cfg(unix)]
    #[test]
    fn recorded_honggfuzz_crash_files_are_ingested_as_findings() {
        use std::os::unix::fs::PermissionsExt;
        let root = crate::test_support::TestDir::new("honggfuzz-ingest");
        let work = root.join("work");
        let build = work.join("build").join("H-HF");
        fs::create_dir_all(&build).unwrap();
        let harness = build.join(HONGGFUZZ_BINARY);
        fs::write(
            &harness,
            "#!/bin/sh\n\
             if grep -q 'BHF!' \"$1\"; then\n\
               >&2 echo 'ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602 at pc 0x444'\n\
               >&2 echo 'WRITE of size 64 at 0x602 thread T0'\n\
               >&2 echo '    #0 0x444 in parse_record /src/record.c:21'\n\
               >&2 echo '    #1 0x445 in LLVMFuzzerTestOneInput /src/main.c:30'\n\
               exit 1\n\
             fi\n\
             exit 0\n",
        )
        .unwrap();
        fs::set_permissions(&harness, fs::Permissions::from_mode(0o755)).unwrap();
        let honggfuzz = root.join("honggfuzz");
        fs::write(
            &honggfuzz,
            "#!/bin/sh\n\
             while [ $# -gt 0 ]; do\n\
               case \"$1\" in --crashdir) crashes=\"$2\"; shift;; esac\n\
               shift\n\
             done\n\
             printf 'BHF!AAAAAAAA' > \"$crashes/SIGABRT.PC.7ffff7a4.STACK.1a2b.CODE.-6.ADDR.0.INSTR.mov.fuzz\"\n\
             printf 'clean' > \"$crashes/SIGSEGV.PC.1.STACK.2.CODE.1.ADDR.0.INSTR.x.fuzz\"\n\
             echo 'Summary iterations:2048 time:1 speed:2048 crashes_count:2'\n",
        )
        .unwrap();
        fs::set_permissions(&honggfuzz, fs::Permissions::from_mode(0o755)).unwrap();
        let mut args = super::super::afl_programmatic_args(
            &work,
            "H-HF",
            vec![b"seed".to_vec()],
            Some(Duration::from_secs(2)),
            &[],
            actionability::RunMode::Reporting,
            2048,
            &[],
            4096,
        );
        args.engine = super::super::FuzzEngine::Honggfuzz;
        let prepared = super::super::prepare(args).unwrap();
        let summary = run_with(prepared, &honggfuzz).unwrap();
        assert_eq!(summary.engine, "honggfuzz");
        assert_eq!(summary.executions, 2048);
        // The crash file that does not crash again is not a finding.
        assert_eq!(summary.findings.len(), 1, "{:?}", summary.findings);
        let record = fs::read_to_string(
            work.join("results/findings")
                .join(&summary.findings[0])
                .join("finding.json"),
        )
        .unwrap();
        assert!(record.contains("found by honggfuzz"), "{record}");
        assert!(record.contains("heap-buffer-overflow"), "{record}");
    }
}
