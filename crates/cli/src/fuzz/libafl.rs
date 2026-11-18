// SPDX-License-Identifier: Apache-2.0

//! `bhf fuzz --engine libafl` (#296): a LibAFL campaign over the harness's
//! `main`, in a bhf built with the `libafl-engine` feature. LibAFL schedules
//! and mutates, each input runs in a fresh harness process, the edge bitmap
//! the harness writes is LibAFL's map, and the inputs that crashed it are
//! recorded through the external-engine ingest.

use super::{FuzzRunSummary, PreparedFuzzRun};

#[cfg(not(feature = "libafl-engine"))]
pub(super) fn run(_prepared: PreparedFuzzRun) -> Result<FuzzRunSummary, String> {
    Err(
        "--engine libafl needs a bhf built with the libafl-engine feature: \
         `cargo build --release -p bhf --features libafl-engine`"
            .to_owned(),
    )
}

#[cfg(feature = "libafl-engine")]
pub(super) fn run(prepared: PreparedFuzzRun) -> Result<FuzzRunSummary, String> {
    use std::time::{Duration, Instant};

    use fuzz_engine_libafl_adapter::libafl_engine::{run_campaign, CampaignConfig};

    use super::{
        coverage_from_env, load_cmplog_for_run, reset_target_entry, run_dictionary_tokens,
        sanitizer_summary, target_entry_from_env, write_run_summary, ExecutionRunSummary,
        ExternalIngest, TraceInput,
    };

    reset_target_entry(&prepared.extra_env);
    let (_, cmplog_summary) = load_cmplog_for_run(prepared.cmplog_log.as_deref(), &prepared.seeds);
    let budget = prepared.time.unwrap_or_else(|| {
        // As for AFL++: 100 ms per requested iteration, within 1 s and 30 s.
        let ms = (prepared.iterations as u64).saturating_mul(100).min(30_000);
        Duration::from_millis(ms.max(1_000))
    });
    let start = Instant::now();
    let result = run_campaign(CampaignConfig {
        harness: prepared.harness_path.clone(),
        scratch: prepared.work_dir.join("libafl").join(&prepared.harness_id),
        seeds: prepared.seeds.clone(),
        budget,
        timeout: prepared.per_input_timeout.max(Duration::from_millis(100)),
        max_len: prepared.max_len,
        rng_seed: prepared.rng_seed,
        tokens: run_dictionary_tokens(
            &prepared.work_dir,
            &prepared.harness_id,
            prepared.dict_file.as_deref(),
        )?,
        env: prepared.extra_env.clone(),
    })?;
    let elapsed = start.elapsed();
    let hard_deadline = Instant::now() + budget + Duration::from_secs(30);
    let mut ingest =
        ExternalIngest::new(&prepared, "LibAFL", "its own corpus", TraceInput::ArgvFile)?;
    for (index, input) in result.crashes.iter().enumerate() {
        ingest.crash(
            input,
            &format!("solution {index}"),
            hard_deadline,
            &|input, env, timeout| {
                super::honggfuzz::replay(
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
        engine: "libafl".to_owned(),
        mode: prepared.mode,
        harness_path: prepared.harness_path.clone(),
        sandbox: prepared.runner.sandbox_metadata(),
        iterations_requested: prepared.iterations,
        executions: usize::try_from(result.executions).unwrap_or(usize::MAX),
        target_entry_observed: target_entry_from_env(&prepared.extra_env),
        corpus_new: result.crashes.len(),
        corpus_duplicates: 0,
        corpus_persisted: result.corpus,
        execution: ExecutionRunSummary {
            harness_protocol: "libafl_process_per_input".to_owned(),
            forkserver: false,
            persistent: false,
            persistent_iterations: None,
        },
        cmplog: cmplog_summary,
        sanitizers: sanitizer_summary(&prepared.sanitizers, &prepared.sanitizer_env, false),
        coverage: coverage_from_env(&prepared.extra_env, &prepared.harness_path),
        findings: ingest.finding_ids.clone(),
        duplicates_of_existing: Vec::new(),
        duplicate_crashes_of_existing: 0,
        elapsed_secs: elapsed.as_secs_f64(),
        executions_per_sec: result.executions as f64 / elapsed.as_secs_f64().max(f64::EPSILON),
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
