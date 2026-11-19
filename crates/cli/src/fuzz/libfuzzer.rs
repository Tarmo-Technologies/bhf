// SPDX-License-Identifier: Apache-2.0

//! `bhf fuzz --engine libfuzzer` (#294): run the harness's libFuzzer build,
//! `main_libfuzzer` (the harness Makefile's `libfuzzer` target), for the run's
//! budget, and record the crash, out-of-memory, leak and timeout artifacts it
//! saves through the external-engine ingest the AFL++ engine uses.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::{
    confirm_external_hang, coverage_from_env, ensure_harness_scratch, find_generated_dictionary,
    find_learned_dictionary, kill_process_group, load_cmplog_for_run, reset_target_entry,
    sanitizer_summary, target_entry_from_env, write_run_summary, ExecutionRunSummary,
    ExternalIngest, FuzzRunSummary, HangConfirmation, HangRunSummary, PreparedFuzzRun, TraceInput,
};

/// The libFuzzer build's file name (`.exe` added on Windows).
pub(super) const LIBFUZZER_BINARY: &str = "main_libfuzzer";

/// libFuzzer's own per-input limit, as `-timeout=` takes it (whole seconds).
const MIN_TIMEOUT_SECS: u64 = 1;

/// The harness's libFuzzer build: `main_libfuzzer` in its build or harness
/// directory, or one `make libfuzzer` builds from the harness Makefile.
pub(super) fn ensure_binary(work_dir: &Path, harness_id: &str) -> Result<PathBuf, String> {
    let dirs = [
        work_dir.join("build").join(harness_id),
        crate::auto::layout::harness_dir(work_dir, harness_id),
        crate::auto::layout::legacy_auto_harness_dir(work_dir, harness_id),
        work_dir.join("generated_harnesses").join(harness_id),
    ];
    for dir in &dirs {
        let exe = crate::auto::layout::harness_exe(dir, LIBFUZZER_BINARY);
        if exe.is_file() {
            return Ok(exe);
        }
    }
    let harness_dir = dirs[1..]
        .iter()
        .find(|dir| dir.join("Makefile").is_file())
        .ok_or_else(|| {
            format!(
                "no {LIBFUZZER_BINARY} for harness {harness_id}, and no harness Makefile to \
                 build one (looked in {})",
                dirs.iter()
                    .map(|dir| dir.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;
    bhfeprintln!(
        "bhf fuzz: building {LIBFUZZER_BINARY} with `make libfuzzer` in {}",
        harness_dir.display()
    );
    let mut make = Command::new("make");
    make.current_dir(harness_dir).arg("libfuzzer");
    let force_includes = crate::build::repair_force_includes(harness_dir);
    crate::build::apply_c_family_make_env(&mut make, &[], &[], &force_includes, None);
    let output =
        crate::command_output::output_with_timeout(&mut make, Duration::from_secs(30 * 60))
            .map_err(|error| format!("run `make libfuzzer`: {error}"))?;
    let exe = crate::auto::layout::harness_exe(harness_dir, LIBFUZZER_BINARY);
    if !output.status.success() || !exe.is_file() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let tail: Vec<&str> = stderr.lines().rev().take(12).collect();
        return Err(format!(
            "`make libfuzzer` did not build {} (libFuzzer needs clang): {}",
            exe.display(),
            tail.into_iter().rev().collect::<Vec<_>>().join("\n")
        ));
    }
    Ok(exe)
}

/// The run's directories under `<work>/libfuzzer/<harness>/`: libFuzzer's
/// corpus, kept between runs, this run's seeds, and the artifacts it saves.
struct CampaignDirs {
    corpus: PathBuf,
    seeds: PathBuf,
    artifacts: PathBuf,
}

impl CampaignDirs {
    fn create(work_dir: &Path, harness_id: &str) -> Result<Self, String> {
        let root = work_dir.join("libfuzzer").join(harness_id);
        let dirs = Self {
            corpus: root.join("corpus"),
            seeds: root.join("seeds"),
            artifacts: root.join("artifacts"),
        };
        // This run's seeds and artifacts only: the corpus carries on.
        let _ = fs::remove_dir_all(&dirs.seeds);
        let _ = fs::remove_dir_all(&dirs.artifacts);
        for dir in [&dirs.corpus, &dirs.seeds, &dirs.artifacts] {
            fs::create_dir_all(dir)
                .map_err(|error| format!("create '{}': {error}", dir.display()))?;
        }
        Ok(dirs)
    }
}

/// What libFuzzer's `-print_final_stats=1` reports: the inputs it ran and
/// their rate.
fn final_stats(log: &str) -> (Option<u64>, Option<f64>) {
    let stat = |name: &str| {
        log.lines().find_map(|line| {
            line.trim()
                .strip_prefix(name)
                .and_then(|rest| rest.trim().strip_prefix(':'))
                .map(|value| value.trim().to_owned())
        })
    };
    (
        stat("stat::number_of_executed_units").and_then(|value| value.parse().ok()),
        stat("stat::average_exec_per_sec").and_then(|value| value.parse().ok()),
    )
}

/// The kind of saved input an artifact's name says it is: libFuzzer prefixes
/// each with what it found (`crash-<sha1>`, `oom-`, `leak-`, `timeout-`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Artifact {
    Crash,
    Timeout,
}

fn artifact_kind(name: &str) -> Option<Artifact> {
    if name.starts_with("timeout-") {
        Some(Artifact::Timeout)
    } else if ["crash-", "oom-", "leak-"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
    {
        Some(Artifact::Crash)
    } else {
        // `slow-unit-` is a slow input, not a fault.
        None
    }
}

/// Run `main_libfuzzer` on `input`, as a file argument, once.
fn replay(
    harness: &Path,
    work_dir: &Path,
    input: &[u8],
    env: &[(String, String)],
    timeout: Option<Duration>,
) -> Result<std::process::Output, String> {
    let scratch = ensure_harness_scratch(work_dir)?;
    let file = scratch.join(format!("libfuzzer-replay-{}.bin", std::process::id()));
    fs::write(&file, input).map_err(|error| format!("write '{}': {error}", file.display()))?;
    let mut command = Command::new(harness);
    command
        .arg(&file)
        .current_dir(&scratch)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(timeout) = timeout {
        command.arg(format!(
            "-timeout={}",
            timeout.as_secs().max(MIN_TIMEOUT_SECS)
        ));
    }
    for (key, value) in env {
        command.env(key, value);
    }
    super::apply_runaway_rlimits(&mut command);
    let output = match timeout {
        Some(timeout) => crate::command_output::output_with_timeout(
            &mut command,
            timeout.saturating_mul(2) + Duration::from_secs(2),
        ),
        None => command.output(),
    }
    .map_err(|error| format!("run '{}': {error}", harness.display()));
    let _ = fs::remove_file(&file);
    output
}

/// The runtrace shim's virtual-clock gate (#342).
const FAKE_CLOCK: &str = "BHF_FAKE_CLOCK";

/// Whether a child given `extra_env` on top of this process's environment
/// would run with the shim's virtual clock on.
fn fake_clock_on(extra_env: &[(String, String)], inherited: Option<&str>) -> bool {
    extra_env
        .iter()
        .rev()
        .find(|(key, _)| key == FAKE_CLOCK)
        .map(|(_, value)| value.as_str())
        .or(inherited)
        == Some("1")
}

/// libFuzzer runs in the harness's own process and times `-timeout` with the
/// clock the runtrace shim fakes under `BHF_FAKE_CLOCK=1` (#342): the time it
/// reads would advance 1 ms per read, so a hanging input would never time out
/// and the campaign would run on until bhf's backstop stops it. Every child
/// of a libFuzzer campaign keeps the real clock.
fn keep_the_real_clock(extra_env: &mut Vec<(String, String)>, inherited: Option<&str>) -> bool {
    if !fake_clock_on(extra_env, inherited) {
        return false;
    }
    extra_env.push((FAKE_CLOCK.to_owned(), "0".to_owned()));
    true
}

pub(super) fn run(mut prepared: PreparedFuzzRun) -> Result<FuzzRunSummary, String> {
    let inherited = std::env::var(FAKE_CLOCK).ok();
    if keep_the_real_clock(&mut prepared.extra_env, inherited.as_deref()) {
        bhfeprintln!(
            "bhf fuzz: warning: {FAKE_CLOCK}=1 is ignored with --engine libfuzzer: libFuzzer \
             runs in the harness process and times -timeout with the clock it would fake, so \
             a hang would go undetected. Use the builtin or AFL++ engine for a virtual clock."
        );
    }
    reset_target_entry(&prepared.extra_env);
    let (_, cmplog_summary) = load_cmplog_for_run(prepared.cmplog_log.as_deref(), &prepared.seeds);
    let dirs = CampaignDirs::create(&prepared.work_dir, &prepared.harness_id)?;
    for (index, seed) in prepared.seeds.iter().enumerate() {
        let path = dirs.seeds.join(format!("seed-{index:04}"));
        fs::write(&path, seed).map_err(|error| format!("write '{}': {error}", path.display()))?;
    }
    let time_budget = prepared.time.unwrap_or_else(|| {
        // As for AFL++: 100 ms per requested iteration, within 1 s and 30 s.
        let ms = (prepared.iterations as u64).saturating_mul(100).min(30_000);
        Duration::from_millis(ms.max(1_000))
    });
    let limit = prepared
        .per_input_timeout
        .max(Duration::from_secs(MIN_TIMEOUT_SECS));
    let log_path = dirs.artifacts.join("../libfuzzer.log");
    let log_file = fs::File::create(&log_path)
        .map_err(|error| format!("create '{}': {error}", log_path.display()))?;

    let mut command = Command::new(&prepared.harness_path);
    command
        .current_dir(ensure_harness_scratch(&prepared.work_dir)?)
        .arg(format!("-artifact_prefix={}/", dirs.artifacts.display()))
        .arg(format!("-max_total_time={}", time_budget.as_secs().max(1)))
        .arg(format!(
            "-timeout={}",
            limit.as_secs().max(MIN_TIMEOUT_SECS)
        ))
        .arg(format!("-max_len={}", prepared.max_len.max(1)))
        .arg(format!("-rss_limit_mb={}", prepared.rss_limit_mb))
        .arg(format!(
            "-seed={}",
            prepared.rng_seed.max(1) % u64::from(u32::MAX)
        ))
        // In process, libFuzzer stops at its first crash, as it does on its
        // own; the artifact it saved is recorded afterwards.
        .arg("-print_final_stats=1");
    if prepared.time.is_none() && prepared.iterations != usize::MAX {
        command.arg(format!("-runs={}", prepared.iterations));
    }
    if let Some(dictionary) = prepared
        .dict_file
        .clone()
        .or_else(|| find_generated_dictionary(&prepared.work_dir, &prepared.harness_id))
        .or_else(|| find_learned_dictionary(&prepared.work_dir, &prepared.harness_id))
    {
        command.arg(format!("-dict={}", dictionary.display()));
    }
    command
        .arg(&dirs.corpus)
        .arg(&dirs.seeds)
        .stdin(Stdio::null())
        .stdout(Stdio::from(
            log_file
                .try_clone()
                .map_err(|error| format!("libfuzzer log: {error}"))?,
        ))
        .stderr(Stdio::from(log_file));
    for (key, value) in &prepared.extra_env {
        command.env(key, value);
    }
    replay_min::process::isolate_process_group(&mut command);
    let start = Instant::now();
    let mut child = command
        .spawn()
        .map_err(|error| format!("spawn '{}': {error}", prepared.harness_path.display()))?;
    // libFuzzer stops itself at -max_total_time; this is the backstop for a
    // wedged run.
    let hard_deadline = start + time_budget.saturating_mul(2) + Duration::from_secs(30);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() >= hard_deadline => {
                kill_process_group(&mut child);
                let _ = child.wait();
                bhfeprintln!(
                    "bhf: warning: {} ran past its time budget and was stopped",
                    prepared.harness_path.display()
                );
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(error) => return Err(format!("wait for libFuzzer: {error}")),
        }
    }
    let elapsed = start.elapsed();
    let log = fs::read_to_string(&log_path).unwrap_or_default();
    let (executions, per_sec) = final_stats(&log);

    let mut ingest = ExternalIngest::new(
        &prepared,
        "libFuzzer",
        "its own corpus",
        TraceInput::ArgvFile,
    )?;
    let mut hangs = HangRunSummary {
        timeout_ms: u64::try_from(limit.as_millis()).unwrap_or(u64::MAX),
        ..HangRunSummary::default()
    };
    let mut artifacts: Vec<PathBuf> = fs::read_dir(&dirs.artifacts)
        .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
        .unwrap_or_default();
    artifacts.sort();
    let mut crash_count = 0_usize;
    for path in artifacts {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("")
            .to_owned();
        let Some(kind) = artifact_kind(&name) else {
            continue;
        };
        let input = fs::read(&path)
            .map_err(|error| format!("read artifact '{}': {error}", path.display()))?;
        match kind {
            Artifact::Crash => {
                crash_count += 1;
                ingest.crash(
                    &input,
                    &format!("artifact {name}"),
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
            Artifact::Timeout => {
                hangs.observed += 1;
                let (report, log) = match confirm_external_hang(
                    &prepared.harness_path,
                    &prepared.work_dir,
                    &input,
                    &prepared.extra_env,
                    hard_deadline,
                    limit,
                    TraceInput::ArgvFile,
                )? {
                    HangConfirmation::Hung(report, log) => {
                        hangs.confirmed += 1;
                        (report, log)
                    }
                    HangConfirmation::Crashed(report, log) => {
                        hangs.cleared += 1;
                        (report, log)
                    }
                    HangConfirmation::Finished => {
                        hangs.cleared += 1;
                        continue;
                    }
                    HangConfirmation::NotRerun => {
                        hangs.not_rerun += 1;
                        continue;
                    }
                };
                ingest.hang(&input, &report, &log, &format!("artifact {name}"))?;
            }
        }
    }

    let summary = FuzzRunSummary {
        schema_version: 1,
        harness_id: prepared.harness_id.clone(),
        engine: "libfuzzer".to_owned(),
        mode: prepared.mode,
        harness_path: prepared.harness_path.clone(),
        sandbox: prepared.runner.sandbox_metadata(),
        iterations_requested: prepared.iterations,
        executions: executions.map(|n| n as usize).unwrap_or(crash_count),
        target_entry_observed: target_entry_from_env(&prepared.extra_env),
        corpus_new: crash_count,
        corpus_duplicates: 0,
        corpus_persisted: fs::read_dir(&dirs.corpus)
            .map(|entries| entries.count())
            .unwrap_or(0),
        execution: ExecutionRunSummary {
            harness_protocol: "libfuzzer_in_process".to_owned(),
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
        hangs: (hangs.observed > 0).then_some(hangs),
        stability: None,
        symcc: None,
        differential: None,
        workers: None,
    };
    write_run_summary(&prepared.work_dir, &summary)?;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #342: a libFuzzer campaign's children keep the real clock, whether
    /// the gate came from bhf's environment or from the run's own.
    #[test]
    fn a_libfuzzer_campaign_keeps_the_real_clock() {
        let pair = |key: &str, value: &str| (key.to_owned(), value.to_owned());
        let mut env = vec![pair("LD_PRELOAD", "/x/libbhf_runtrace_shim.so")];
        assert!(!keep_the_real_clock(&mut env, None));
        assert!(!keep_the_real_clock(&mut env, Some("0")));
        assert_eq!(env.len(), 1);

        assert!(keep_the_real_clock(&mut env, Some("1")));
        assert_eq!(env.last(), Some(&pair(FAKE_CLOCK, "0")));
        assert!(!fake_clock_on(&env, Some("1")));

        let mut own = vec![pair(FAKE_CLOCK, "1")];
        assert!(keep_the_real_clock(&mut own, None));
        assert!(!fake_clock_on(&own, None));
    }

    #[test]
    fn libfuzzer_artifacts_and_final_stats_are_read() {
        assert_eq!(artifact_kind("crash-0a1b"), Some(Artifact::Crash));
        assert_eq!(artifact_kind("oom-0a1b"), Some(Artifact::Crash));
        assert_eq!(artifact_kind("leak-0a1b"), Some(Artifact::Crash));
        assert_eq!(artifact_kind("timeout-0a1b"), Some(Artifact::Timeout));
        assert_eq!(artifact_kind("slow-unit-0a1b"), None);
        assert_eq!(artifact_kind("libfuzzer.log"), None);
        let log = "#2048\tDONE   cov: 12 ft: 13 corp: 3/9b\n\
                   Done 2048 runs in 1 second(s)\n\
                   stat::number_of_executed_units: 2048\n\
                   stat::average_exec_per_sec:     2048\n\
                   stat::new_units_added:          2\n";
        assert_eq!(final_stats(log), (Some(2048), Some(2048.0)));
        assert_eq!(final_stats("INFO: no stats"), (None, None));
    }
}
