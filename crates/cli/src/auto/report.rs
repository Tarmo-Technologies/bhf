// SPDX-License-Identifier: Apache-2.0

//! Aggregates per-target [`AttemptResult`]s into `<work>/auto/run.md`
//! and `<work>/auto/run.json` — the human-readable summary + machine
//! ledger the `bhf auto` sweep emits. The `needed_for_build`
//! section deduplicates repairs and missing-library notes across
//! targets so the upstream maintainer sees one entry per missing
//! header / symbol / library with the full list of referencing
//! `harness_id`s.

use crate::auto::attempt::{
    stub_execution_summary, AttemptResult, AttemptTrace, Outcome, PassRun, StubExecution,
};
use crate::auto::candidate::{Candidate, Lang};
use crate::auto::repair::Repair;
use anyhow::Result;
use multicore_fuzz::{Sanitizer, SanitizerSelection};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Serialize)]
struct RunJson<'a> {
    schema_version: u32,
    started_at: String,
    finished_at: String,
    partial: bool,
    mode: actionability::RunMode,
    source_root: &'a Path,
    summary: Summary,
    needed_for_build: NeededForBuild,
    targets: Vec<TargetEntry<'a>>,
}

#[derive(Debug, Default, Serialize)]
struct Summary {
    discovered: usize,
    /// Total ranked candidates discovered BEFORE any `--max-targets` /
    /// `--campaign-time` split cap. Equals `discovered` for an uncapped run;
    /// larger when a cap dropped lower-ranked targets from the sweep (#6 — so a
    /// truncated run is never read as having discovered only the swept count).
    discovered_total: usize,
    /// Candidates dropped from the sweep by `--max-targets` / the campaign-time
    /// split (`discovered_total - discovered`). 0 for an uncapped run.
    #[serde(skip_serializing_if = "is_zero")]
    dropped_by_cap: usize,
    /// The operator ended the run early from the keyboard (`q`). The shortfall
    /// against `discovered_total` then has nothing to do with a cap, and a report
    /// read weeks later must not blame one — it is the difference between "this
    /// tree has 3 unreachable targets" and "somebody stopped watching".
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    stopped_by_operator: bool,
    /// The work-directory retention ceiling stopped target admission. In-flight
    /// targets were allowed to finish, so this is a clean partial campaign, not
    /// an internal error or operator cancellation.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    output_limit_reached: bool,
    /// `--resume`: targets skipped this run because they already completed in a
    /// prior sweep over the same work-dir (their artifacts remain on disk). 0 when
    /// not resuming. Included in `discovered`.
    #[serde(skip_serializing_if = "is_zero")]
    resumed: usize,
    built: usize,
    built_and_fuzzed: usize,
    /// #417: of the `built_and_fuzzed` targets, how many were FALSE CLEANS —
    /// their harness fuzzed only blind stubs, never the real library (see
    /// [`StubExecution::stub_only`]). Surfaced distinctly so a sweep that
    /// "built and fuzzed N" isn't read as N real fuzz campaigns.
    fuzzed_stub_only: usize,
    /// force-fuzz Phase 2: of the swept targets, how many ran on synthesized inputs
    /// — `--force` AND either [`StubExecution::stub_only`] (a forced build that
    /// fuzzed synthesized stub bodies) or a forced synthetic parameter/receiver on a
    /// managed lane ([`Repair::ForcedSyntheticParams`]). Their findings are floored
    /// to Low with the forced note, and this count is surfaced next to
    /// `built_and_fuzzed` so a forced sweep isn't read as N confirmed campaigns.
    /// 0 (omitted) for a non-force run.
    #[serde(skip_serializing_if = "is_zero")]
    forced: usize,
    /// #95: targets whose C/C++/Ada harness built and ran fuzz passes but never
    /// observed the target-entry checkpoint — the run exercised only decoding or
    /// blind stubs, so it is NOT a fuzz success (`built_and_fuzzed`). Surfaced
    /// distinctly so it can never inflate the fuzz-success headline. 0 (omitted)
    /// when every built target genuinely entered.
    #[serde(skip_serializing_if = "is_zero")]
    built_not_entered: usize,
    failed_build: usize,
    unsupported_params: usize,
    unrecoverable_link: usize,
    unrecoverable_runtime: usize,
    /// M22: targets discovered + statically analyzed but not fuzzed (legacy
    /// dialect with no lane yet, absent legacy toolchain, or unrecoverable
    /// build). Surfaced distinctly so they read as triaged, not dropped.
    #[serde(skip_serializing_if = "is_zero")]
    report_only: usize,
    findings: usize,
    /// #484: static findings (from `--static` / report-only) that a fuzz crash or
    /// oracle hit reached at the same source site — upgraded to `fuzz_confirmed`.
    /// The headline number that separates "a scanner flagged it" from "a fuzzer
    /// walked into it". 0 (omitted) when nothing was confirmed.
    #[serde(skip_serializing_if = "is_zero")]
    fuzz_confirmed: usize,
    /// #102: source files DROPPED from discovery because a read/decode/parse
    /// stage failed, grouped by (language, stage, error class). Empty when every
    /// scanned file was read + parsed. Makes a parser regression on a large legacy
    /// tree visible instead of indistinguishable from "no fuzzable endpoints".
    #[serde(skip_serializing_if = "Vec::is_empty")]
    discovery_diagnostics: Vec<DiscoveryDiagnosticRow>,
    /// CC-1: the campaign-level fidelity rollup — which execution dimensions
    /// (arch, endianness, RTOS runtime, hardware, concurrency, sanitizers) were
    /// exercised vs not across the fuzzed targets, plus the derived caveat. So a
    /// sweep that host-stubbed a VxWorks target is never read as target
    /// assurance, and a fully-native sweep carries no caveat.
    fidelity: FidelitySummary,
}

/// CC-1: campaign-level fidelity rollup for `run.json`'s summary. `dimensions`
/// is the worst case per dimension across every fuzzed target, so a single
/// host-stub target flags the run; `caveat` is `None` for a fully-native sweep.
#[derive(Debug, Default, Serialize)]
struct FidelitySummary {
    /// Fuzzed targets whose findings are host-stub evidence, not target
    /// assurance (their platform ISA / RTOS / hardware was faked).
    reduced_fidelity_targets: usize,
    /// The foreign platforms stub-isolated on the host this run (sorted, deduped).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    stubbed_platforms: Vec<String>,
    /// Worst-case per-dimension fidelity across all fuzzed targets. `None` when
    /// nothing was fuzzed.
    #[serde(skip_serializing_if = "Option::is_none")]
    dimensions: Option<actionability::Fidelity>,
    /// The derived human caveat, present iff any fuzzed target was reduced-fidelity.
    #[serde(skip_serializing_if = "Option::is_none")]
    caveat: Option<String>,
}

/// #102: one grouped discovery-drop row for `run.json` — a (language, stage,
/// error class) with the number of files it hit and one bounded, scrubbed sample
/// of the error tail. No paths, filenames, source, or identifiers.
#[derive(Debug, Clone, Serialize)]
struct DiscoveryDiagnosticRow {
    language: String,
    stage: String,
    category: String,
    files: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    sample: Option<String>,
}

/// #102: collect + group the discovery-drop diagnostics recorded during the sweep
/// into deterministic `run.json` rows. Reads the shared bug-report snapshot (the
/// same source `bug-report.json` uses), keeps only `DiscoveryDiagnostic` issues,
/// and sorts by (language, stage, category) so repeated runs are byte-identical.
fn collect_discovery_diagnostics() -> Vec<DiscoveryDiagnosticRow> {
    let mut rows: Vec<DiscoveryDiagnosticRow> = crate::auto::bug_report::snapshot()
        .into_iter()
        .filter(|issue| {
            issue.category == crate::auto::bug_report::IssueCategory::DiscoveryDiagnostic
        })
        .map(|issue| {
            // `summary` is "<language> <stage>: <category>".
            let (lhs, category) = issue
                .summary
                .split_once(": ")
                .unwrap_or((issue.summary.as_str(), ""));
            let (language, stage) = lhs.split_once(' ').unwrap_or((lhs, ""));
            DiscoveryDiagnosticRow {
                language: language.to_owned(),
                stage: stage.to_owned(),
                category: category.to_owned(),
                files: issue.occurrences,
                sample: issue.detail.clone(),
            }
        })
        .collect();
    rows.sort_by(|a, b| {
        (&a.language, &a.stage, &a.category).cmp(&(&b.language, &b.stage, &b.category))
    });
    rows
}

#[derive(Debug, Default, Serialize)]
struct NeededForBuild {
    synthesized_headers: Vec<Aggregated>,
    synthesized_types: Vec<Aggregated>,
    /// Build-config macros `#define`d to a benign value because they were used
    /// but never defined (the project's build system injects them via
    /// generated `config.h` / `-D`). The maintainer must supply real values.
    synthesized_macros: Vec<Aggregated>,
    stubbed_symbols_declared: Vec<Aggregated>,
    stubbed_symbols_blind: Vec<Aggregated>,
    stubbed_ada_units: Vec<Aggregated>,
    stubbed_ada_symbols: Vec<Aggregated>,
    missing_libraries: Vec<Aggregated>,
    missing_gpr_imports: Vec<Aggregated>,
    /// Layer-C: env vars the runtrace shim observed getenv() NULLing
    /// during fuzz. With injection on, these double with the
    /// Repair::EnvVarInjection ledger; with --no-stubs they show
    /// the would-be fakes.
    environment_variables_faked: Vec<Aggregated>,
    /// Layer-C: open/stat/access ENOENT paths.
    missing_files: Vec<Aggregated>,
    /// Layer-C: connect()/getaddrinfo() failures.
    network_endpoints: Vec<Aggregated>,
    /// Layer-C: dlopen() NULL returns.
    dlopen_failures: Vec<Aggregated>,
    /// Ada units the classifier still flagged as missing after auto
    /// repair attempts. Successful Ada stub repairs are reported in
    /// `stubbed_ada_units` / `stubbed_ada_symbols` instead.
    missing_ada_units: Vec<Aggregated>,
    /// Harness / codegen build errors (a malformed generated harness or a parser
    /// recovery artifact — "no member named", "did you mean", a bare `type`
    /// placeholder). These are NOT external dependencies, so they are recorded
    /// here for honesty instead of being framed in the missing-dependency
    /// manifest with an "acquire" hint (#5).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    harness_codegen_errors: Vec<Aggregated>,
}

#[derive(Debug, Serialize)]
struct Aggregated {
    name: String,
    referenced_by_targets: Vec<String>,
}

#[derive(Debug, Serialize)]
struct TargetEntry<'a> {
    harness_id: &'a str,
    source: &'a Path,
    name: &'a str,
    line: u32,
    score: i32,
    outcome: &'a Outcome,
    attempt_trace: AttemptTrace,
    /// #417: stub-vs-real execution summary for fuzzed targets — the field that
    /// distinguishes a real fuzz from a FALSE CLEAN over empty stubs. `None`
    /// (omitted) for outcomes that never fuzzed.
    #[serde(skip_serializing_if = "Option::is_none")]
    stub_execution: Option<StubExecution>,
    /// Whether the fuzzed parameters are an attacker-controlled input channel
    /// (C/C++ only). Surfaced so a crash on a non-attacker-reachable target
    /// (serializer / caller-controlled args) is honestly flagged, not presented
    /// as a vulnerability.
    #[serde(skip_serializing_if = "Option::is_none")]
    input_reachability: Option<target_rank::InputReachability>,
    /// #(c): set when the target was built STUB-ISOLATED for a foreign OS platform
    /// (its platform deps faked so it compiles natively). Names the platform so a
    /// reader knows every finding on this target is REDUCED-FIDELITY — the logic
    /// ran but the platform behavior was stubbed, not real.
    #[serde(skip_serializing_if = "Option::is_none")]
    platform_stub: Option<String>,
    /// CC-1: the structured fidelity record for this target — which execution
    /// dimensions were exercised vs faked/unexplored. `None` (omitted) for a
    /// target that never fuzzed (a failed build has nothing to characterize).
    #[serde(skip_serializing_if = "Option::is_none")]
    fidelity: Option<actionability::Fidelity>,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// CC-1: the sanitizers the run armed for the native/host-stub build lane, as
/// short labels. `Default` bakes ASan+UBSan into the harness Makefile; `None`
/// arms none; `Set` is exactly the operator's selection.
fn effective_sanitizer_names(sel: &SanitizerSelection) -> Vec<String> {
    fn label(s: Sanitizer) -> &'static str {
        match s {
            Sanitizer::Asan => "asan",
            Sanitizer::Msan => "msan",
            Sanitizer::Ubsan => "ubsan",
            Sanitizer::Tsan => "tsan",
            Sanitizer::Lsan => "lsan",
        }
    }
    match sel {
        SanitizerSelection::Default => vec!["asan".to_owned(), "ubsan".to_owned()],
        SanitizerSelection::None => Vec::new(),
        SanitizerSelection::Set(set) => set.iter().map(|s| label(*s).to_owned()).collect(),
    }
}

/// CC-1: whether the ThreadSanitizer corpus-replay lane runs for this selection —
/// mirrors [`crate::auto::cli`]'s replay gate (Default runs the historical
/// matrix; `Set` runs it only when TSan is selected). The replay is C-only, so
/// callers additionally gate on dialect.
fn tsan_replay_runs(sel: &SanitizerSelection) -> bool {
    match sel {
        SanitizerSelection::Default => true,
        SanitizerSelection::None => false,
        SanitizerSelection::Set(set) => set.contains(&Sanitizer::Tsan),
    }
}

/// CC-1: derive a target's structured [`actionability::Fidelity`] from facts the
/// report already holds. `None` for a target that never fuzzed — there is no
/// execution to characterize. The host stub-isolation lane is a NATIVE build (it
/// keeps host sanitizers), so its sanitizer/concurrency facts come from the run
/// selection just like a plain native target; only its platform ISA / RTOS /
/// hardware are faked, which `platform_stub` carries.
fn target_fidelity(
    r: &AttemptResult,
    sanitizers: &SanitizerSelection,
) -> Option<actionability::Fidelity> {
    if !matches!(
        r.outcome,
        Outcome::BuiltAndFuzzed { .. } | Outcome::BuiltNotEntered { .. }
    ) {
        return None;
    }
    let mut facts = actionability::FidelityFacts::host();
    facts.platform_stub = r.outcome.platform_stub();
    // The TSan replay is C-only (the C++ Makefile has no `tsan` target); other
    // dialects never exercise concurrency, so gate on both the run selection and
    // the target dialect.
    let tsan_ran = tsan_replay_runs(sanitizers) && matches!(r.candidate.lang, Lang::C);
    let mut names = effective_sanitizer_names(sanitizers);
    if tsan_ran && !names.iter().any(|n| n == "tsan") {
        names.push("tsan".to_owned());
    }
    facts.sanitizers = names;
    facts.tsan_ran = tsan_ran;
    Some(actionability::Fidelity::from_facts(&facts))
}

/// CC-1: write the per-finding fidelity block onto every `finding.json` on disk.
/// A finding produced by a fuzzed target inherits that target's record (keyed by
/// `harness_id`); a static / no-harness finding gets an all-`NotApplicable`
/// "nothing executed" record so every finding carries the block without claiming
/// a spurious caveat. Best-effort: an unreadable or malformed sidecar is skipped,
/// never aborting the report.
fn annotate_findings_with_fidelity(
    work_dir: &Path,
    results: &[AttemptResult],
    fidelities: &[Option<actionability::Fidelity>],
) {
    let mut by_harness: BTreeMap<&str, &actionability::Fidelity> = BTreeMap::new();
    for (r, fid) in results.iter().zip(fidelities) {
        if let Some(f) = fid {
            by_harness.insert(r.candidate.harness_id.as_str(), f);
        }
    }
    let findings_root = corpus::layout::findings_dir(work_dir);
    let Ok(entries) = std::fs::read_dir(&findings_root) else {
        return;
    };
    let static_record =
        actionability::Fidelity::not_executed("static analysis finding; nothing was executed");
    for entry in entries.flatten() {
        let path = entry.path().join("finding.json");
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(mut raw) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        // Snapshot before mutating: results/ is preserved across runs and resumes,
        // so re-running must not append a redundant history entry or rewrite a file
        // whose fidelity block is already correct.
        let before = raw.clone();
        let Some(obj) = raw.as_object_mut() else {
            continue;
        };
        let harness_id = obj
            .get("harness_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let fidelity = by_harness
            .get(harness_id)
            .copied()
            .unwrap_or(&static_record);
        let Ok(value) = serde_json::to_value(fidelity) else {
            continue;
        };
        obj.insert("fidelity".to_owned(), value);
        // Keep a one-line derived caveat next to the block for tools that read a
        // single string; drop any stale one when the target is full-fidelity.
        match fidelity.caveat() {
            Some(caveat) => {
                obj.insert(
                    "fidelity_caveat".to_owned(),
                    serde_json::Value::String(caveat),
                );
            }
            None => {
                obj.remove("fidelity_caveat");
            }
        }
        if raw == before {
            continue;
        }
        corpus::finding::append_history(&mut raw, "auto", &["fidelity", "fidelity_caveat"]);
        match serde_json::to_vec_pretty(&raw) {
            Ok(serialized) => {
                if let Err(error) = atomic_write(&path, &serialized) {
                    bhfeprintln!(
                        "warning: failed to annotate fidelity on {}: {error}",
                        path.display()
                    );
                }
            }
            Err(error) => {
                bhfeprintln!(
                    "warning: failed to serialize fidelity for {}: {error}",
                    path.display()
                );
            }
        }
    }
}

/// force-fuzz Phase 2, persisted: findings from a forced-and-stub-heavy target
/// carry `forced: true` + the caveat on disk, so every renderer (and importer)
/// floors them the same way instead of only the in-memory CSV path. The note is
/// the single shared [`confidence_model::FORCED_STUB_NOTE`].
///
/// `forced` is a fact fixed at the finding's birth (it was produced by a forced,
/// stub-heavy build). A later non-forced run never clears it: this pass only ever
/// sets it, and only for the harnesses in `forced_harness_ids`.
fn annotate_forced_findings(
    work_dir: &Path,
    forced_harness_ids: &std::collections::BTreeSet<String>,
) {
    if forced_harness_ids.is_empty() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(corpus::layout::findings_dir(work_dir)) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path().join("finding.json");
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(mut raw) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        let harness = raw
            .get("harness_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if !forced_harness_ids.contains(harness) {
            continue;
        }
        // results/ is preserved across runs; skip an already-flagged record so a
        // re-run neither appends a redundant history entry nor rewrites the file.
        let before = raw.clone();
        if let Some(obj) = raw.as_object_mut() {
            obj.insert("forced".to_owned(), serde_json::Value::Bool(true));
            obj.insert(
                "forced_note".to_owned(),
                serde_json::json!(confidence_model::FORCED_STUB_NOTE),
            );
        }
        if raw == before {
            continue;
        }
        corpus::finding::append_history(&mut raw, "auto", &["forced", "forced_note"]);
        match serde_json::to_vec_pretty(&raw) {
            Ok(serialized) => {
                if let Err(error) = atomic_write(&path, &serialized) {
                    bhfeprintln!(
                        "warning: failed to annotate forced floor on {}: {error}",
                        path.display()
                    );
                }
            }
            Err(error) => {
                bhfeprintln!(
                    "warning: failed to serialize forced floor for {}: {error}",
                    path.display()
                );
            }
        }
    }
}

/// A round-trippable persisted copy of one target's full attempt result, written
/// to `<work>/harnesses/<id>/result.json` the moment the attempt finishes. On a
/// `--resume` re-run it is loaded back into a real [`AttemptResult`] so the target
/// is fully re-integrated into the new report (its outcome bucket, repair bags,
/// findings, pass detail) without being re-attempted. `Candidate` isn't itself
/// serde-able (its `Lang`/`InputReachability` are cross-crate enums), so its
/// fields are stored as stable strings here, mirroring the discovery cache.
#[derive(Serialize, Deserialize)]
struct PersistedResult {
    harness_id: String,
    lang: String,
    source_path: String,
    line: u32,
    name: String,
    score: i32,
    is_static: bool,
    #[serde(default)]
    foreign_guard: Option<String>,
    #[serde(default)]
    input_reachability: Option<String>,
    outcome: Outcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attempt_trace: Option<AttemptTrace>,
    harness_dir: String,
    /// Whether this attempt ran with `--force` (a fabricated value for a
    /// parameter bhf could not construct, stubs for whatever the compiler
    /// reported missing). `--resume` needs it to decide whether a prior result is
    /// still the best available answer: an unforced non-success can be RETRIED
    /// with force, while a forced result must not be inherited by an unforced run
    /// whose report would then carry stub-heavy findings it never asked for.
    /// Absent in work dirs written before this field existed — those predate
    /// forcing being a separate phase, so `false` is the correct reading.
    #[serde(default)]
    forced: bool,
}

fn lang_tag(l: Lang) -> &'static str {
    match l {
        Lang::Ada => "ada",
        Lang::C => "c",
        Lang::Cpp => "cpp",
        Lang::Rust => "rust",
        Lang::Java => "java",
        Lang::Python => "python",
        Lang::Perl => "perl",
        Lang::Go => "go",
        Lang::Cobol => "cobol",
        Lang::Fortran => "fortran",
        Lang::CSharp => "csharp",
        Lang::Js => "javascript",
        Lang::Ts => "typescript",
        Lang::Ruby => "ruby",
        Lang::Lua => "lua",
        Lang::Php => "php",
    }
}
fn lang_from_tag(s: &str) -> Option<Lang> {
    Some(match s {
        "ada" => Lang::Ada,
        "c" => Lang::C,
        "cpp" => Lang::Cpp,
        "rust" => Lang::Rust,
        "java" => Lang::Java,
        "python" => Lang::Python,
        "perl" => Lang::Perl,
        "go" => Lang::Go,
        "cobol" => Lang::Cobol,
        "fortran" => Lang::Fortran,
        "csharp" => Lang::CSharp,
        "javascript" => Lang::Js,
        "typescript" => Lang::Ts,
        "ruby" => Lang::Ruby,
        "lua" => Lang::Lua,
        "php" => Lang::Php,
        _ => return None,
    })
}
fn reach_tag(r: target_rank::InputReachability) -> &'static str {
    use target_rank::InputReachability::*;
    match r {
        AttackerReachable => "attacker_reachable",
        OutputSerializer => "output_serializer",
        ReachabilityUnproven => "reachability_unproven",
        IpcChannelReachable => "ipc_channel_reachable",
        RegisteredEntryPoint => "registered_entry_point",
        ChannelConsumer => "channel_consumer",
    }
}
fn reach_from_tag(s: &str) -> Option<target_rank::InputReachability> {
    use target_rank::InputReachability::*;
    Some(match s {
        "attacker_reachable" => AttackerReachable,
        "output_serializer" => OutputSerializer,
        "reachability_unproven" => ReachabilityUnproven,
        "ipc_channel_reachable" => IpcChannelReachable,
        "registered_entry_point" => RegisteredEntryPoint,
        "channel_consumer" => ChannelConsumer,
        _ => return None,
    })
}

/// Persist one target's full result to `<work>/harnesses/<id>/result.json` the moment
/// its attempt finishes, so a `--resume` re-run (or one after a mid-sweep
/// interrupt) reloads it instead of re-attempting. Best-effort: a write failure
/// never aborts the run (resume is an optimization, not a correctness input).
pub fn persist_target_result(work_dir: &Path, result: &AttemptResult, forced: bool) {
    let dir = crate::auto::layout::harness_dir(work_dir, &result.candidate.harness_id);
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let c = &result.candidate;
    let dto = PersistedResult {
        harness_id: c.harness_id.clone(),
        lang: lang_tag(c.lang).to_owned(),
        source_path: c.source_path.to_string_lossy().into_owned(),
        line: c.line,
        name: c.name.clone(),
        score: c.score,
        is_static: c.is_static,
        foreign_guard: c.foreign_guard.clone(),
        input_reachability: c.input_reachability.map(|r| reach_tag(r).to_owned()),
        outcome: result.outcome.clone(),
        attempt_trace: Some(result.attempt_trace()),
        harness_dir: result.harness_dir.to_string_lossy().into_owned(),
        forced,
    };
    if let Ok(bytes) = serde_json::to_vec(&dto) {
        let _ = atomic_write(&dir.join("result.json"), &bytes);
    }
}

/// Replace a file through a same-directory, flushed temporary file. A kill/OOM
/// can leave an unreferenced `.tmp-*`, but never a half-written destination; the
/// next successful checkpoint removes its own temporary file via rename.
pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let leaf = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("checkpoint");
    // Remove only abandoned temporaries for this destination. Multiple bhf
    // processes can legitimately share a work directory, so never remove a
    // temporary owned by a process that is still alive.
    let stale_prefix = format!(".{leaf}.tmp-");
    if let Ok(entries) = std::fs::read_dir(parent) {
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();
            let owner = file_name
                .strip_prefix(&stale_prefix)
                .and_then(|suffix| suffix.split_once('-'))
                .and_then(|(pid, _)| pid.parse::<u32>().ok());
            if owner.is_some_and(|pid| !checkpoint_writer_is_alive(pid)) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    let temp = parent.join(format!(
        ".{leaf}.tmp-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)?;
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

#[cfg(target_os = "linux")]
fn checkpoint_writer_is_alive(pid: u32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

#[cfg(not(target_os = "linux"))]
fn checkpoint_writer_is_alive(_pid: u32) -> bool {
    // Without a portable, race-free process-liveness query, preserve the file.
    // A failed write still removes its own temporary below.
    true
}

/// Whether a target already completed (has a well-formed persisted result), for
/// `--resume`'s skip decision. A missing/corrupt file means "not done" →
/// re-attempt.
pub fn target_already_complete(work_dir: &Path, harness_id: &str) -> bool {
    load_resumed_result(work_dir, harness_id).is_some()
}

/// Load a prior target's persisted result back into a real [`AttemptResult`], so
/// `--resume` re-integrates it fully into the new report. `None` if absent,
/// corrupt, or carrying an unrecognized language tag (treated as "re-attempt").
pub fn load_resumed_result(work_dir: &Path, harness_id: &str) -> Option<(AttemptResult, bool)> {
    let p = [
        crate::auto::layout::harness_dir(work_dir, harness_id),
        crate::auto::layout::legacy_auto_harness_dir(work_dir, harness_id),
    ]
    .into_iter()
    .map(|dir| dir.join("result.json"))
    .find(|path| path.is_file())?;
    let text = std::fs::read_to_string(p).ok()?;
    let dto: PersistedResult = serde_json::from_str(&text).ok()?;
    let forced = dto.forced;
    Some(AttemptResult {
        candidate: Candidate {
            harness_id: dto.harness_id,
            lang: lang_from_tag(&dto.lang)?,
            source_path: PathBuf::from(dto.source_path),
            line: dto.line,
            name: dto.name,
            score: dto.score,
            is_static: dto.is_static,
            foreign_guard: dto.foreign_guard,
            input_reachability: dto.input_reachability.as_deref().and_then(reach_from_tag),
            dialect: None,
        },
        outcome: dto.outcome,
        harness_dir: PathBuf::from(dto.harness_dir),
    })
    .map(|result| (result, forced))
}

/// Collapse the per-target `"<kind> harness cannot initialize parameter '<p>' of
/// target '<t>' with type '<ty>': <rest>"` reason to `"<kind> harness cannot
/// initialize a parameter with type '<ty>': <rest>"`. The parameter name and
/// target name vary per row, but the underlying gap (this type has no
/// synthesizable constructor) is one issue — dropping them lets the
/// `(category, summary)` dedup fold every target sharing an unconstructible type
/// into a single `xN` row. The type is kept so genuinely different types stay
/// distinct, actionable rows.
fn collapse_uninitializable_param_reason(reason: &str) -> String {
    const MARKER: &str = " cannot initialize parameter '";
    if let Some(kind_end) = reason.find(MARKER) {
        if let Some(type_pos) = reason.find(" with type '") {
            if type_pos > kind_end {
                let kind = &reason[..kind_end]; // "<kind> harness"
                let tail = &reason[type_pos..]; // " with type '<ty>': <rest>"
                return format!("{kind} cannot initialize a parameter{tail}");
            }
        }
    }
    reason.to_owned()
}

/// Reconcile in-memory per-pass finding ids against the on-disk `results/findings/`
/// directory, dropping any id whose `finding.json` a post-pass removed. Returns
/// the number of phantom ids dropped.
///
/// Result-linked fuzz findings (`F-NNNN-*`) are emitted to
/// `results/findings/<id>/finding.json` during the cascade and recorded in
/// [`PassRun::findings`]. Post-pass oracles then run and may DELETE a finding
/// they prove false: COBOL crash attribution
/// ([`crate::auto::cobol_oracle::run_cobol_attribution`]) removes a crash whose
/// libcob diagnostic is a harness artifact (a dynamic `CALL` to a sibling
/// program not linked into the single-program harness). Such a removal reaches
/// the `results/` index (derived from disk) but NOT the
/// in-memory pass records that feed `summary.findings`, `run.json` and `run.md`
/// — so the headline count would report a finding with no evidence bundle (a
/// phantom: exactly the two COBOL `built_and_fuzzed` targets whose count read 1
/// while their CSV/`results/findings/` held nothing).
///
/// Called once after every post-pass and immediately before [`write_reports`],
/// this makes the pass records agree with disk: the count, `run.json` and
/// `run.md` reflect exactly the findings that still have an evidence bundle.
/// Disk-folded families ([`DISK_ONLY_PREFIXES`]) live only on disk and never
/// in a pass record, so they are unaffected; the report-only
/// path carries its ids in `Outcome::ReportOnly::finding_ids`, which no post-pass
/// removes, so it is left as-is.
pub(crate) fn reconcile_pass_findings_with_disk(
    results: &mut [AttemptResult],
    work_dir: &Path,
) -> usize {
    let findings_root = corpus::layout::findings_dir(work_dir);
    let mut dropped = 0usize;
    for r in results.iter_mut() {
        let passes = match &mut r.outcome {
            Outcome::BuiltAndFuzzed { passes, .. } | Outcome::BuiltNotEntered { passes, .. } => {
                passes
            }
            _ => continue,
        };
        for pass in passes.iter_mut() {
            let before = pass.findings.len();
            pass.findings
                .retain(|fid| findings_root.join(fid).join("finding.json").is_file());
            dropped += before - pass.findings.len();
        }
    }
    dropped
}

#[allow(clippy::too_many_arguments)]
pub fn write_reports(
    source_root: &Path,
    results: &[AttemptResult],
    work_dir: &Path,
    started_at: &str,
    finished_at: &str,
    partial: bool,
    mode: actionability::RunMode,
    resumed: usize,
    discovered_total: usize,
    static_dynamic: bool,
    force: bool,
    stopped_by_operator: bool,
) -> Result<()> {
    write_reports_with_output_limit(
        source_root,
        results,
        work_dir,
        started_at,
        finished_at,
        partial,
        mode,
        resumed,
        discovered_total,
        static_dynamic,
        force,
        stopped_by_operator,
        false,
        &SanitizerSelection::Default,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn write_reports_with_output_limit(
    source_root: &Path,
    results: &[AttemptResult],
    work_dir: &Path,
    started_at: &str,
    finished_at: &str,
    partial: bool,
    mode: actionability::RunMode,
    resumed: usize,
    discovered_total: usize,
    // Deprecated `--static-dynamic`: no effect, `results/findings.csv` always
    // carries a `kind` column.
    _static_dynamic: bool,
    force: bool,
    stopped_by_operator: bool,
    output_limit_reached: bool,
    // CC-1: the run's sanitizer selection, so each target's fidelity record
    // reports which sanitizers were actually armed and whether a TSan
    // (concurrency) pass ran.
    sanitizers: &SanitizerSelection,
) -> Result<()> {
    let auto_dir = work_dir.join("auto");
    std::fs::create_dir_all(&auto_dir)?;

    // force-fuzz Phase 2: under `--force`, a target whose harness fuzzed only blind
    // stubs (`stub_only`) ran against synthesized bodies, so any crash is likely a
    // stub artifact. The managed lanes (Go, C#) have no stub ledger but reach the
    // same place through a synthesized parameter or receiver, recorded as
    // `ForcedSyntheticParams` — a nil map or zero-valued receiver can panic on its
    // own account. Collect both so their findings are floored to Low with the
    // forced note, and count them for the summary. Empty for a non-force run — the
    // non-force path is completely unchanged.
    let forced_harness_ids: std::collections::BTreeSet<String> = if force {
        results
            .iter()
            .filter_map(|r| match &r.outcome {
                Outcome::BuiltAndFuzzed { repairs, .. }
                    if stub_execution_summary(repairs).stub_only
                        || repairs.iter().any(|repair| {
                            matches!(repair, Repair::ForcedSyntheticParams { .. })
                        }) =>
                {
                    Some(r.candidate.harness_id.clone())
                }
                _ => None,
            })
            .collect()
    } else {
        std::collections::BTreeSet::new()
    };

    let attempted = results.len();
    // #6: `discovered_total` is the pre-cap ranked count threaded from the CLI;
    // clamp to the attempted count so a caller that passes 0 (the report tests,
    // an uncapped run) still reports `discovered_total == discovered`.
    let discovered_total = discovered_total.max(attempted);
    let mut summary = Summary {
        // `results` already includes `--resume`-reloaded targets (re-integrated
        // before the report), so they're counted in `discovered` and their outcome
        // buckets; `resumed` just surfaces how many were carried over, not re-run.
        discovered: attempted,
        discovered_total,
        dropped_by_cap: discovered_total - attempted,
        stopped_by_operator,
        output_limit_reached,
        resumed,
        ..Summary::default()
    };
    let mut needed = NeededForBuild::default();
    let mut bag_headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut bag_types: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut bag_macros: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut bag_declared: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut bag_blind: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut bag_ada_stub_units: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut bag_ada_stub_symbols: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut bag_libs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut bag_gpr_imports: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut bag_env: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut bag_files: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut bag_endpoints: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut bag_dlopen: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut bag_ada_units: BTreeMap<String, Vec<String>> = BTreeMap::new();
    // #5: harness/codegen build errors, kept OUT of the missing-dependency
    // manifest so they are never framed to the user as an external dep to acquire.
    let mut bag_codegen: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut failed_error_text = String::new();
    // Per-failed-target final diagnostics, so the missing-dep manifest can record
    // a still-blocking entry for EVERY unresolved build error — not just the
    // shared-lib / Ada subset the bags above capture. Without this a build that
    // dies on an unresolvable `#include` (a configure-generated header) or any
    // other non-lib error produces an opaque `failed_build` with an empty
    // manifest (#418).
    let mut failed_targets: Vec<(String, Vec<build_classifier::BuildErrorKind>)> = Vec::new();

    for r in results {
        let id = r.candidate.harness_id.clone();
        match &r.outcome {
            Outcome::Built { repairs, .. } => {
                summary.built += 1;
                aggregate_repairs(
                    repairs,
                    &id,
                    &mut bag_headers,
                    &mut bag_types,
                    &mut bag_declared,
                    &mut bag_blind,
                    &mut bag_ada_stub_units,
                    &mut bag_ada_stub_symbols,
                    &mut bag_macros,
                );
            }
            Outcome::BuiltAndFuzzed {
                repairs,
                passes,
                runtrace_events,
                ..
            } => {
                summary.built += 1;
                summary.built_and_fuzzed += 1;
                // #417: count the FALSE-CLEAN subset so a sweep that built+fuzzed
                // N targets doesn't read as N real fuzz campaigns when some only
                // exercised blind stubs.
                if stub_execution_summary(repairs).stub_only {
                    summary.fuzzed_stub_only += 1;
                }
                // force-fuzz Phase 2: a target that ran on synthesized input — stub
                // bodies, or a forced Go/C# parameter — is counted distinctly so N
                // forced targets aren't read as N confirmed campaigns. The set is
                // empty unless `--force`, so a normal run is unchanged.
                if forced_harness_ids.contains(&id) {
                    summary.forced += 1;
                }
                summary.findings += passes.iter().map(|p| p.findings.len()).sum::<usize>();
                aggregate_repairs(
                    repairs,
                    &id,
                    &mut bag_headers,
                    &mut bag_types,
                    &mut bag_declared,
                    &mut bag_blind,
                    &mut bag_ada_stub_units,
                    &mut bag_ada_stub_symbols,
                    &mut bag_macros,
                );
                aggregate_runtrace(
                    runtrace_events,
                    &id,
                    &mut bag_env,
                    &mut bag_files,
                    &mut bag_endpoints,
                    &mut bag_dlopen,
                );
            }
            // #95: built + ran fuzz passes but the entry-instrumented harness
            // never observed target entry. It genuinely built (so it counts as
            // `built`), but it is NOT `built_and_fuzzed` and its passes' findings
            // do NOT count toward the headline (a crash without target entry is a
            // decode/stub artifact). Repairs + runtrace evidence are still
            // aggregated for the manifest.
            Outcome::BuiltNotEntered {
                repairs,
                runtrace_events,
                ..
            } => {
                summary.built += 1;
                summary.built_not_entered += 1;
                aggregate_repairs(
                    repairs,
                    &id,
                    &mut bag_headers,
                    &mut bag_types,
                    &mut bag_declared,
                    &mut bag_blind,
                    &mut bag_ada_stub_units,
                    &mut bag_ada_stub_symbols,
                    &mut bag_macros,
                );
                aggregate_runtrace(
                    runtrace_events,
                    &id,
                    &mut bag_env,
                    &mut bag_files,
                    &mut bag_endpoints,
                    &mut bag_dlopen,
                );
            }
            Outcome::FailedBuild {
                repairs,
                last_errors,
                ..
            } => {
                summary.failed_build += 1;
                aggregate_repairs(
                    repairs,
                    &id,
                    &mut bag_headers,
                    &mut bag_types,
                    &mut bag_declared,
                    &mut bag_blind,
                    &mut bag_ada_stub_units,
                    &mut bag_ada_stub_symbols,
                    &mut bag_macros,
                );
                // Accumulate the error text so a "stubbed" dep that the build still
                // fails on is reported as still-blocking, not "build continued".
                for e in last_errors {
                    failed_error_text.push_str(&format!("{e:?}\n"));
                }
                // Keep the full final diagnostic set for this target so the manifest
                // surfaces a still-blocking entry for every unresolved error (#418).
                failed_targets.push((id.clone(), last_errors.clone()));
                for e in last_errors {
                    // #5: a harness/codegen error is bhf's own (or a project
                    // build-config) problem, not a dependency — record it in its
                    // own bag and keep it out of the missing-dependency paths.
                    if build_classifier::is_codegen_error(e) {
                        bag_codegen
                            .entry(codegen_error_label(e))
                            .or_default()
                            .push(id.clone());
                        continue;
                    }
                    match e {
                        build_classifier::BuildErrorKind::MissingSharedLib { name } => {
                            bag_libs.entry(name.clone()).or_default().push(id.clone());
                        }
                        build_classifier::BuildErrorKind::MissingAdaWith { unit }
                        | build_classifier::BuildErrorKind::MissingAdaPackageBody { unit } => {
                            bag_ada_units
                                .entry(unit.clone())
                                .or_default()
                                .push(id.clone());
                        }
                        build_classifier::BuildErrorKind::MissingAdaSymbol { unit, symbol } => {
                            // GNAT occasionally emits the symbol with
                            // no enclosing unit (regex matched `Foo`
                            // but the unit context was on a prior
                            // line we didn't see). A bare `.Foo` row
                            // has no actionable target for the
                            // maintainer — drop it.
                            if unit.is_empty() {
                                continue;
                            }
                            let key = format!("{unit}.{symbol}");
                            bag_ada_units.entry(key).or_default().push(id.clone());
                        }
                        _ => {}
                    }
                }
            }
            Outcome::UnsupportedParams { .. } => {
                summary.unsupported_params += 1;
            }
            Outcome::UnrecoverableLink { missing, .. } => {
                summary.unrecoverable_link += 1;
                for m in missing {
                    if m.ends_with(".gpr") {
                        bag_gpr_imports
                            .entry(m.clone())
                            .or_default()
                            .push(id.clone());
                    } else {
                        bag_libs.entry(m.clone()).or_default().push(id.clone());
                    }
                }
            }
            Outcome::UnrecoverableRuntime {
                repairs,
                runtrace_events,
                ..
            } => {
                summary.unrecoverable_runtime += 1;
                aggregate_repairs(
                    repairs,
                    &id,
                    &mut bag_headers,
                    &mut bag_types,
                    &mut bag_declared,
                    &mut bag_blind,
                    &mut bag_ada_stub_units,
                    &mut bag_ada_stub_symbols,
                    &mut bag_macros,
                );
                aggregate_runtrace(
                    runtrace_events,
                    &id,
                    &mut bag_env,
                    &mut bag_files,
                    &mut bag_endpoints,
                    &mut bag_dlopen,
                );
            }
            // M22: discovered + statically analyzed but not fuzzed. Counted
            // separately so a sweep that report-only'd N legacy targets does not
            // read as N failed builds or N silent drops. Its CWE-tagged static
            // findings count toward the headline findings total (campaign fix).
            Outcome::ReportOnly {
                static_findings, ..
            } => {
                summary.report_only += 1;
                summary.findings += static_findings;
            }
        }
    }
    // Disk-only findings (`--static` whole-tree scan, sanitizer/profiling replays,
    // capability profiling, external tools, sink oracle, differential) are written
    // straight to the findings dir (not linked to any result), so fold their count
    // in here alongside the result-linked fuzz/report-only findings.
    summary.findings += disk_only_finding_ids(work_dir).len();
    // #484: how many of those static findings a fuzz/oracle hit confirmed (read
    // from disk so a `--resume` reload reports the same number the join set).
    summary.fuzz_confirmed = crate::auto::confirm::count_fuzz_confirmed(work_dir);
    // #102: surface any files dropped from discovery (read/decode/parse failures)
    // so a parser regression is visible in run.json, not just bug-report.json.
    summary.discovery_diagnostics = collect_discovery_diagnostics();

    // CC-1: derive each target's structured fidelity once (reused for the
    // per-target run.json entry, the campaign rollup, and the per-finding block).
    let target_fidelities: Vec<Option<actionability::Fidelity>> = results
        .iter()
        .map(|r| target_fidelity(r, sanitizers))
        .collect();
    // Campaign rollup: worst case per dimension across every fuzzed target, plus
    // the count of reduced-fidelity targets and the platforms stubbed this run.
    {
        let present: Vec<&actionability::Fidelity> = target_fidelities.iter().flatten().collect();
        let dimensions = actionability::Fidelity::rollup(present.iter().copied());
        let reduced_fidelity_targets = present.iter().filter(|f| f.is_reduced_fidelity()).count();
        let mut stubbed_platforms: Vec<String> = results
            .iter()
            .filter(|r| {
                matches!(
                    r.outcome,
                    Outcome::BuiltAndFuzzed { .. } | Outcome::BuiltNotEntered { .. }
                )
            })
            .filter_map(|r| r.outcome.platform_stub())
            .collect();
        stubbed_platforms.sort();
        stubbed_platforms.dedup();
        let caveat = dimensions
            .as_ref()
            .and_then(actionability::Fidelity::caveat);
        summary.fidelity = FidelitySummary {
            reduced_fidelity_targets,
            stubbed_platforms,
            dimensions,
            caveat,
        };
    }

    needed.synthesized_headers = drain_bag(bag_headers);
    needed.synthesized_types = drain_bag(bag_types);
    needed.synthesized_macros = drain_bag(bag_macros);
    needed.stubbed_symbols_declared = drain_bag(bag_declared);
    needed.stubbed_symbols_blind = drain_bag(bag_blind);
    needed.stubbed_ada_units = drain_bag(bag_ada_stub_units);
    needed.stubbed_ada_symbols = drain_bag(bag_ada_stub_symbols);
    needed.missing_libraries = drain_bag(bag_libs);
    needed.missing_gpr_imports = drain_bag(bag_gpr_imports);
    needed.environment_variables_faked = drain_bag(bag_env);
    needed.missing_files = drain_bag(bag_files);
    needed.network_endpoints = drain_bag(bag_endpoints);
    needed.dlopen_failures = drain_bag(bag_dlopen);
    needed.missing_ada_units = drain_bag(bag_ada_units);
    needed.harness_codegen_errors = drain_bag(bag_codegen);

    let targets: Vec<TargetEntry> = results
        .iter()
        .zip(&target_fidelities)
        .map(|(r, fidelity)| TargetEntry {
            harness_id: &r.candidate.harness_id,
            source: &r.candidate.source_path,
            name: &r.candidate.name,
            line: r.candidate.line,
            score: r.candidate.score,
            outcome: &r.outcome,
            attempt_trace: r.attempt_trace(),
            stub_execution: r.outcome.stub_execution(),
            input_reachability: r.candidate.input_reachability,
            platform_stub: r.outcome.platform_stub(),
            fidelity: fidelity.clone(),
        })
        .collect();

    // CC-1: stamp every finding.json with its target's structured fidelity block.
    annotate_findings_with_fidelity(work_dir, results, &target_fidelities);
    // force-fuzz Phase 2: persist the forced floor onto each forced target's
    // findings so every renderer and importer floors them the same way the CSV
    // path does in memory.
    annotate_forced_findings(work_dir, &forced_harness_ids);

    let run_json = RunJson {
        schema_version: 1,
        started_at: started_at.to_owned(),
        finished_at: finished_at.to_owned(),
        partial,
        mode,
        source_root,
        summary,
        needed_for_build: needed,
        targets,
    };
    let json_path = auto_dir.join("run.json");
    std::fs::write(&json_path, serde_json::to_vec_pretty(&run_json)?)?;
    let md_path = auto_dir.join("run.md");
    std::fs::write(&md_path, render_md(&run_json))?;

    // bhf self-diagnostics: consolidate everything bhf could NOT fully
    // handle — internal panics caught during the sweep + codegen artifacts (its own
    // bugs) + per-target outcomes it couldn't fuzz (unsupported types, failed
    // builds, report-only) — into bug-report.{json,md}, deduplicated. Without
    // `--debug` a fully clean run writes nothing; with `--debug` a version-stamped
    // confirmation is always written. Distinct from missing-deps.txt (the user env).
    use crate::auto::bug_report::{InternalIssue, IssueCategory, IssueContext};
    fn strip_target_prefix(reason: &str) -> String {
        for pat in ["C++ target '", "C target '", "Ada target '", "target '"] {
            if let Some(rest) = reason.strip_prefix(pat) {
                if let Some((_, tail)) = rest.split_once("' ") {
                    return tail.trim().to_owned();
                }
            }
        }
        reason.to_owned()
    }
    fn build_error_summary(kind: &build_classifier::BuildErrorKind) -> String {
        use build_classifier::BuildErrorKind as E;
        match kind {
            E::MissingType { name } => format!("undefined type '{name}'"),
            E::IncompleteType { name } => format!("incomplete type '{name}'"),
            E::MissingHeader { path } => format!("missing header '{path}'"),
            E::MissingMacro { name, .. } => format!("undefined macro '{name}'"),
            E::UndefinedSymbol { name } => format!("undefined symbol '{name}'"),
            E::UndeclaredFunction { name, file, line } => {
                format!("undeclared function '{name}' at {file}:{line}")
            }
            E::MalformedFunctionDecl { file, line } => {
                format!("malformed declarator at {file}:{line}")
            }
            E::Other { tail } => first_error_line(tail),
            // Ada/library kinds (MissingSharedLib, MissingAdaWith, …): a Debug
            // rendering carries the name/unit, which is what the maintainer needs.
            other => format!("{other:?}"),
        }
    }
    let mut extra: Vec<InternalIssue> = Vec::new();
    for e in &run_json.needed_for_build.harness_codegen_errors {
        extra.push(InternalIssue {
            category: IssueCategory::CodegenDefect,
            summary: e.name.clone(),
            context: IssueContext {
                phase: "harness-codegen".to_owned(),
                target: (!e.referenced_by_targets.is_empty())
                    .then(|| e.referenced_by_targets.join(", ")),
                ..Default::default()
            },
            detail: None,
            backtrace: None,
            occurrences: e.referenced_by_targets.len().max(1),
        });
    }
    for r in results {
        let file = r
            .candidate
            .source_path
            .strip_prefix(source_root)
            .unwrap_or(&r.candidate.source_path)
            .display()
            .to_string();
        let context = |phase: &str| IssueContext {
            phase: phase.to_owned(),
            file: Some(file.clone()),
            target: Some(r.candidate.name.clone()),
            language: Some(format!("{:?}", r.candidate.lang)),
        };
        let entry = match &r.outcome {
            crate::auto::attempt::Outcome::UnsupportedParams { reason } => Some((
                IssueCategory::UnsupportedType,
                collapse_uninitializable_param_reason(&strip_target_prefix(reason)),
                context("harness-gen"),
            )),
            crate::auto::attempt::Outcome::FailedBuild { last_errors, .. } => Some((
                IssueCategory::FailedBuild,
                last_errors
                    .first()
                    .map(build_error_summary)
                    .unwrap_or_else(|| "build failed".to_owned()),
                context("build"),
            )),
            crate::auto::attempt::Outcome::ReportOnly { reason, .. } => Some((
                IssueCategory::ReportOnly,
                strip_target_prefix(reason),
                context("report-only"),
            )),
            crate::auto::attempt::Outcome::UnrecoverableLink { missing, .. } => Some((
                IssueCategory::FailedBuild,
                format!("unresolved link symbol(s): {}", missing.join(", ")),
                context("link"),
            )),
            crate::auto::attempt::Outcome::UnrecoverableRuntime { reason, .. } => Some((
                IssueCategory::FailedBuild,
                strip_target_prefix(reason),
                context("runtime"),
            )),
            // #95: built + ran but the target was never entered — a coverage gap,
            // surfaced distinctly so a maintainer can tell it apart from a build
            // failure or an unsupported type.
            crate::auto::attempt::Outcome::BuiltNotEntered { reason, .. } => Some((
                IssueCategory::TargetNotReached,
                strip_target_prefix(reason),
                context("fuzz-entry"),
            )),
            _ => None,
        };
        if let Some((category, summary, ctx)) = entry {
            extra.push(InternalIssue {
                category,
                summary,
                context: ctx,
                detail: None,
                backtrace: None,
                occurrences: 1,
            });
        }
    }
    let bug_count = crate::auto::bug_report::write(
        &auto_dir,
        finished_at,
        &extra,
        crate::auto::bug_report::debug_enabled(),
    );
    // Always point at the report under --debug (it's always written then, even
    // with zero issues), so the user sees WHERE it landed at the end of the run.
    if bug_count > 0 || crate::auto::bug_report::debug_enabled() {
        bhfeprintln!(
            "bhf: bug report ({bug_count} issue(s) bhf couldn't fully handle) → {}",
            auto_dir.join("bug-report.md").display()
        );
    }

    // Consolidated missing-dependency manifest for the offline-transfer workflow:
    // every external dependency a target needed but the tree didn't provide, each
    // marked stubbed (build continued) or still-blocking, with an acquisition
    // hint. One trip instead of build-hit-copy-repeat.
    let mut manifest =
        build_dependency_manifest(&run_json.needed_for_build, source_root, &failed_error_text);
    // #418: guarantee no opaque `failed_build`. Fold every failed target's final
    // unresolved diagnostics into the manifest as still-blocking entries (with
    // remediation), and ensure each failed target contributes at least one entry.
    record_failed_build_blockers(&mut manifest, &failed_targets, source_root);
    // Targets that SKIPPED on an opaque IDL type never reached the build, so their
    // missing CORBA stub headers aren't in the ledger. Scan skipped targets'
    // sources for unresolved `*C.h`/`*S.h` includes and record the missing IDL —
    // turning a silent skip into "bring bank.idl".
    add_idl_deps_from_skipped_targets(&mut manifest, source_root, results);
    // Merge the early declaration/toolchain seed and every incrementally
    // checkpointed semantic requirement. The run-start checkpoint overwrites any
    // prior run, so this cannot resurrect stale entries from an older campaign.
    if let Some(checkpoint) = load_dependency_manifest(work_dir) {
        manifest.merge_from(&checkpoint);
    }
    add_semantic_requirements_from_results(&mut manifest, source_root, results);
    manifest.mark_checkpoint(results.len(), true);
    write_dependency_manifest_files(work_dir, &manifest)?;
    if !manifest.is_empty() {
        bhfeprintln!(
            "bhf auto: {} external dependenc{} needed ({} still blocking, {} stubbed) — see {}",
            manifest.entries.len(),
            if manifest.entries.len() == 1 {
                "y"
            } else {
                "ies"
            },
            manifest.blocking_count(),
            manifest.stubbed_count(),
            auto_dir.join("missing-deps.txt").display(),
        );
    }
    Ok(())
}

/// Findings written straight to disk rather than linked to a per-target result:
/// whole-tree static scan, sanitizer/profiling replays, capability profiling,
/// external tools, JS sink oracle, and the differential post-pass.
const DISK_ONLY_PREFIXES: [&str; 8] = [
    "F-STATIC-",
    "F-MSAN-",
    "F-CAP-",
    "F-TSAN-",
    "F-MEM-",
    "F-JSINK-",
    "F-EXT-",
    "F-DIFF-",
];

/// Ids of the [`DISK_ONLY_PREFIXES`] findings in the findings dir. The report
/// reads them from disk to fold them in alongside the result-linked
/// fuzz/report-only findings. Empty when no such dirs exist.
pub(crate) fn disk_only_finding_ids(work_dir: &Path) -> Vec<String> {
    let dir = corpus::layout::findings_dir(work_dir);
    let mut ids: Vec<String> = match std::fs::read_dir(&dir) {
        Ok(entries) => entries
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|name| {
                DISK_ONLY_PREFIXES.iter().any(|p| name.starts_with(p))
                    && dir.join(name).join("finding.json").is_file()
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    ids.sort();
    ids
}

/// Fold the per-category `NeededForBuild` ledger into the one flat dependency
/// manifest, tagging each entry's kind and whether bhf stubbed it (build
/// continued) or it is still blocking (the user must supply the real thing).
fn build_dependency_manifest(
    needed: &NeededForBuild,
    source_root: &Path,
    failed_error_text: &str,
) -> crate::auto::dep_manifest::DependencyManifest {
    use crate::auto::dep_manifest::{DepKind, DependencyManifest};
    let mut m = DependencyManifest::new();
    // A dependency we "stubbed" is only honestly "build continued" if the build
    // didn't keep failing on it. When a stubbed type/symbol name still appears in
    // a FailedBuild target's errors, the stub did NOT unblock it — report it as
    // STILL BLOCKING, not stubbed (ctre `utf8_iterator`).
    let still_blocks = |name: &str| !name.is_empty() && failed_error_text.contains(name);
    let add = |kind: DepKind, items: &[Aggregated], stubbed: bool, m: &mut DependencyManifest| {
        for a in items {
            let stubbed = stubbed && !still_blocks(&a.name);
            m.push(
                kind,
                a.name.clone(),
                a.referenced_by_targets.clone(),
                stubbed,
            );
        }
    };
    // Still-blocking first (insertion order is preserved; render sorts blocking
    // ahead anyway, but this keeps the JSON readable too).
    add(
        DepKind::SharedLibrary,
        &needed.missing_libraries,
        false,
        &mut m,
    );
    add(
        DepKind::GprImport,
        &needed.missing_gpr_imports,
        false,
        &mut m,
    );
    add(DepKind::AdaUnit, &needed.missing_ada_units, false, &mut m);
    // A missing filesystem path is classified more precisely so the user knows
    // what to recreate: a dangling symlink, a path on a network mount (NFS/SMB),
    // or a plain file/dir.
    for a in &needed.missing_files {
        // An llvm-debuginfod client cache file (`~/.cache/llvm-debuginfod/...`) is
        // a transient lookup artifact, not a real build input — the build/fuzz
        // completes without it. Mark it non-blocking (stubbed) so the manifest
        // doesn't mislabel it "still blocking".
        m.push(
            classify_missing_path(&a.name),
            a.name.clone(),
            a.referenced_by_targets.clone(),
            is_debuginfod_cache(&a.name),
        );
    }
    // Build-time env vars the project's GPR requires via `external("VAR")` with
    // no default (gprbuild errors without them) — recorded so they travel with
    // the rest of the missing-dependency set.
    for var in required_gpr_externals(source_root) {
        m.push(
            DepKind::EnvVar,
            var,
            vec!["build (project.gpr external)".to_owned()],
            false,
        );
    }
    // Stubbed (build continued against a fake).
    // A stubbed header that matches the CORBA/IDL generated-stub naming
    // (`bankC.h`/`bankS.h`) is reported as the missing IDL interface (`bank.idl`)
    // — what the user actually needs to bring/regenerate — not a generic header.
    for a in &needed.synthesized_headers {
        let stubbed = !still_blocks(&a.name);
        match crate::auto::dep_manifest::corba_generated_idl(&a.name) {
            Some(idl) => m.push_merge(
                DepKind::IdlInterface,
                idl,
                a.referenced_by_targets.clone(),
                stubbed,
            ),
            // A header bhf stubbed: if a `.in`/`.dist`/`.cmake` template sits
            // beside it in the tree it's configure-generated, so name that template
            // and the configure step instead of a dead-end apt-file hint. When no
            // template is found, push_merge_with_hint falls back to the per-kind
            // default (which still special-cases generated-header *names*).
            None => {
                let hint = configure_template_hint(source_root, &a.name);
                let kind = if hint.is_some()
                    || crate::auto::dep_manifest::is_configure_generated_header(&a.name)
                {
                    DepKind::GeneratedSource
                } else {
                    DepKind::Header
                };
                m.push_merge_with_hint(
                    kind,
                    a.name.clone(),
                    a.referenced_by_targets.clone(),
                    stubbed,
                    hint,
                );
            }
        }
    }
    // ConfigTypeAlias entries are generated-source requirements and are added
    // from the structured Repair ledger below. Do not also mislabel the
    // human-formatted width assumption as an ordinary missing C type.
    let ordinary_types: Vec<Aggregated> = needed
        .synthesized_types
        .iter()
        .filter(|entry| !entry.name.contains("(synthesised config default"))
        .map(|entry| Aggregated {
            name: entry.name.clone(),
            referenced_by_targets: entry.referenced_by_targets.clone(),
        })
        .collect();
    add(DepKind::CType, &ordinary_types, true, &mut m);
    add(DepKind::Macro, &needed.synthesized_macros, true, &mut m);
    add(
        DepKind::Symbol,
        &needed.stubbed_symbols_declared,
        true,
        &mut m,
    );
    add(DepKind::Symbol, &needed.stubbed_symbols_blind, true, &mut m);
    add(DepKind::AdaUnit, &needed.stubbed_ada_units, true, &mut m);
    add(
        DepKind::EnvVar,
        &needed.environment_variables_faked,
        true,
        &mut m,
    );
    add(
        DepKind::NetworkEndpoint,
        &needed.network_endpoints,
        true,
        &mut m,
    );
    add(
        DepKind::DlopenLibrary,
        &needed.dlopen_failures,
        true,
        &mut m,
    );
    m
}

/// Fold every failed target's FINAL unresolved diagnostics into the manifest as
/// still-blocking entries, and guarantee each failed target contributes at least
/// one actionable entry (#418). The per-category `needed_for_build` bags only
/// capture stubbed repairs plus the shared-lib / GPR / Ada subset of unresolved
/// errors, so a build that dies on an unresolvable `#include` (a configure-
/// generated header like c-ares' `ares_build.h`), an undefined type/symbol, or
/// any `Other` diagnostic would otherwise leave an opaque `failed_build` behind
/// an empty manifest. This makes the manifest the single honest record of WHY a
/// target could not be built.
fn record_failed_build_blockers(
    manifest: &mut crate::auto::dep_manifest::DependencyManifest,
    failed_targets: &[(String, Vec<build_classifier::BuildErrorKind>)],
    source_root: &Path,
) {
    use crate::auto::dep_manifest::DepKind;
    use build_classifier::BuildErrorKind as E;
    for (id, errors) in failed_targets {
        // #5: a target whose only unresolved errors are harness/codegen errors
        // is explained by the `harness_codegen_errors` ledger — it must NOT get a
        // generic "build failed → acquire dependency" manifest blocker.
        let mut had_codegen = false;
        for err in errors {
            if build_classifier::is_codegen_error(err) {
                had_codegen = true;
                continue;
            }
            match err {
                E::MissingHeader { path } => {
                    // A configure/cmake-generated header has no distro package; if a
                    // `.in`/`.dist`/`.cmake` template sits in the tree, name it and
                    // point at the configure step. Otherwise the default per-kind
                    // hint (which already special-cases generated-header names)
                    // applies.
                    let hint = configure_template_hint(source_root, path);
                    let kind = if hint.is_some()
                        || crate::auto::dep_manifest::is_configure_generated_header(path)
                    {
                        DepKind::GeneratedSource
                    } else {
                        DepKind::Header
                    };
                    manifest.push_merge_with_hint(
                        kind,
                        path.clone(),
                        vec![id.clone()],
                        false,
                        hint,
                    );
                }
                E::MissingType { name } => manifest.push_merge_with_hint(
                    DepKind::CType,
                    name.clone(),
                    vec![id.clone()],
                    false,
                    Some(format!(
                        "'{name}' is undefined in the scanned tree — supply the header/source that \
                         declares it (often a configure-generated or out-of-tree definition)"
                    )),
                ),
                E::IncompleteType { name } => manifest.push_merge_with_hint(
                    DepKind::CType,
                    name.clone(),
                    vec![id.clone()],
                    false,
                    Some(format!(
                        "'{name}' is forward-declared but never defined in the scanned tree (a pimpl / \
                         private implementation) — supply the source that defines it"
                    )),
                ),
                E::MissingMacro { name, .. } => manifest.push_merge_with_hint(
                    DepKind::Macro,
                    name.clone(),
                    vec![id.clone()],
                    false,
                    Some(format!(
                        "'{name}' is injected by the project's build config (generated config.h / \
                         -D flags) — supply its real definition"
                    )),
                ),
                E::UndefinedSymbol { name } => manifest.push_merge_with_hint(
                    DepKind::Symbol,
                    name.clone(),
                    vec![id.clone()],
                    false,
                    Some(format!(
                        "'{name}' is undefined — link the library/object that defines it, or supply \
                         its source"
                    )),
                ),
                E::UndeclaredFunction { name, file, line } => manifest.push_merge_with_hint(
                    DepKind::Symbol,
                    name.clone(),
                    vec![id.clone()],
                    false,
                    Some(format!(
                        "'{name}' has no declaration visible at {file}:{line} — restore the damaged \
                         header macro/declaration or supply the header that declares it"
                    )),
                ),
                E::MalformedFunctionDecl { file, line } => manifest.push_merge_with_hint(
                    DepKind::Other,
                    format!("{file}:{line} (body-less function declarator from a macro/codegen expansion)"),
                    vec![id.clone()],
                    false,
                    Some(
                        "supply the project's real macro/IDL-codegen definitions for this line, or \
                         run the codegen step (--probe-build)"
                            .to_owned(),
                    ),
                ),
                E::Other { tail } => manifest.push_merge_with_hint(
                    DepKind::Other,
                    first_error_line(tail),
                    vec![id.clone()],
                    false,
                    Some(format!(
                        "unrecognised build error for target {id} — see auto/run.json (this \
                         target's outcome.last_errors) for the full diagnostic"
                    )),
                ),
                // Shared libs / GPR imports / Ada units are already folded into the
                // manifest from the `needed_for_build` bags (and already reference
                // this target), so skip them here to avoid a second, hint-poorer
                // entry.
                E::MissingSharedLib { .. }
                | E::MissingGprImport { .. }
                | E::MissingAdaWith { .. }
                | E::MissingAdaPackageBody { .. }
                | E::MissingAdaSymbol { .. }
                | E::UncompilableAdaBody { .. } => {}
                // A `#error` a build-config guard reached: the project's own build
                // system was meant to define the macro, so the actionable step is
                // to run that configure, not to install anything.
                E::ConfigGuardError {
                    file,
                    line,
                    message,
                } => manifest.push_merge_with_hint(
                    DepKind::GeneratedSource,
                    format!("build configuration for {file}"),
                    vec![id.clone()],
                    false,
                    Some(format!(
                        "the header stops the build at line {line} with `#error {message}`;                          run the project's configure/cmake step so the macro it tests is                          defined, or pass it with --build-command"
                    )),
                ),
            }
        }
        // AC2 safety net: every failed target MUST leave at least one actionable
        // record. If it still has no manifest entry — all errors were folded
        // elsewhere and none referenced this target (e.g. a bare empty-unit
        // Ada-symbol row the bag dropped, or an error-less classification) —
        // record a generic blocker so the failure is never silent. A target whose
        // only errors were harness/codegen ones is already recorded in the
        // `harness_codegen_errors` ledger, so it is not framed as a dependency.
        if manifest_reference_count(manifest, id) == 0 && !had_codegen {
            manifest.push_merge_with_hint(
                DepKind::Other,
                format!("build failed for target {id}"),
                vec![id.clone()],
                false,
                Some(
                    "see auto/run.json (this target's outcome.last_errors) for the compiler \
                     diagnostic"
                        .to_owned(),
                ),
            );
        }
    }
}

/// Number of manifest entries that list `id` among their referencing targets.
/// Used to detect whether a failed target contributed any actionable entry.
fn manifest_reference_count(
    manifest: &crate::auto::dep_manifest::DependencyManifest,
    id: &str,
) -> usize {
    manifest
        .entries
        .iter()
        .filter(|e| e.referenced_by.iter().any(|r| r == id))
        .count()
}

/// A stable display label for a harness/codegen build error (#5), used as the
/// `harness_codegen_errors` bag key. A recovery-artifact `MissingType` names the
/// artifact; an `Other` tail is summarised to its first error line.
fn codegen_error_label(err: &build_classifier::BuildErrorKind) -> String {
    use build_classifier::BuildErrorKind as E;
    match err {
        E::MissingType { name } => {
            format!("codegen: unresolved '{name}' (parser recovery artifact)")
        }
        E::Other { tail } => first_error_line(tail),
        // is_codegen_error only flags the two shapes above; anything else is a
        // defensive fallback that should not occur.
        other => format!("{other:?}"),
    }
}

/// The first non-empty, trimmed line of a multi-line `Other` diagnostic tail,
/// capped so a runaway line can't bloat the manifest. Falls back to a stable
/// label when the tail is empty.
fn first_error_line(tail: &str) -> String {
    let line = tail
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("unclassified build error");
    if line.len() > 200 {
        // Truncate on a UTF-8 char boundary: compiler diagnostics are not ASCII
        // (GCC/G++ quote identifiers with U+2018/U+2019), so a fixed `[..200]`
        // can split a multi-byte char and panic.
        let mut end = 200;
        while end > 0 && !line.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &line[..end])
    } else {
        line.to_owned()
    }
}

/// When a missing configure/cmake-generated header has a generation template in
/// the tree (`<name>.in`, `<name>.dist`, `<name>.cmake`, `<name>.cmake.in`),
/// return a remediation naming that template and the configure step. `None` when
/// no template is found — the caller then falls back to the per-kind default
/// hint (which still special-cases generated-header *names*).
fn configure_template_hint(source_root: &Path, header: &str) -> Option<String> {
    let leaf = header.rsplit(['/', '\\']).next().unwrap_or(header);
    let template = find_generation_template(source_root, leaf)?;
    Some(format!(
        "configure-generated: run the project's configure step (`./configure` / `cmake` / \
         `autoreconf -i && ./configure`) to produce '{leaf}' from '{}', then re-run bhf with \
         --probe-build / --consent-build; or copy the generated '{leaf}' into the tree",
        template.display()
    ))
}

/// Bounded walk for a generation template named after `leaf` (`<leaf>.in`,
/// `<leaf>.dist`, `<leaf>.cmake`, `<leaf>.cmake.in`). Returns the first match
/// relative to `root` when possible.
fn find_generation_template(root: &Path, leaf: &str) -> Option<std::path::PathBuf> {
    let candidates = [
        format!("{leaf}.in"),
        format!("{leaf}.dist"),
        format!("{leaf}.cmake"),
        format!("{leaf}.cmake.in"),
    ];
    let mut stack = vec![root.to_path_buf()];
    let mut seen = 0usize;
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            seen += 1;
            if seen > 200_000 {
                return None;
            }
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if candidates.iter().any(|c| c == name) {
                    return Some(path.strip_prefix(root).unwrap_or(&path).to_path_buf());
                }
            }
        }
    }
    None
}

/// Record missing IDL interfaces for targets that were SKIPPED (e.g. an opaque
/// CORBA type parameter the harness can't construct) — these never reached the
/// build, so their unresolved generated-stub includes (`bankC.h`) aren't in the
/// ledger. Scan each skipped target's source for `#include`s of CORBA-generated
/// headers whose file is absent from the tree, and record the source `.idl` as a
/// still-blocking dependency. A header that IS present (a constructibility issue,
/// not a missing IDL) is not flagged.
fn add_idl_deps_from_skipped_targets(
    manifest: &mut crate::auto::dep_manifest::DependencyManifest,
    source_root: &Path,
    results: &[AttemptResult],
) {
    use crate::auto::dep_manifest::{corba_generated_idl, DepKind};
    let present = header_basenames_present(source_root);
    let mut ordered: Vec<&AttemptResult> = results.iter().collect();
    ordered.sort_by(|a, b| a.candidate.harness_id.cmp(&b.candidate.harness_id));
    for r in ordered {
        if !matches!(r.outcome, Outcome::UnsupportedParams { .. }) {
            continue;
        }
        let Ok(text) = crate::source_text::read_source_text(&r.candidate.source_path) else {
            continue;
        };
        for include in scan_include_targets(&text) {
            let leaf = include.rsplit(['/', '\\']).next().unwrap_or(&include);
            if present.contains(leaf) {
                continue; // header is in the tree — not a missing-IDL case
            }
            if let Some(idl) = corba_generated_idl(leaf) {
                manifest.push_merge(
                    DepKind::IdlInterface,
                    idl,
                    vec![r.candidate.harness_id.clone()],
                    false,
                );
            }
        }
    }
}

/// Atomically persist an in-progress dependency manifest after completed target
/// attempts. `seed` is the pre-target declaration/toolchain scan. Rebuilding the
/// small manifest from completed results makes the checkpoint deterministic and
/// avoids keeping mutable dependency state in worker threads.
pub fn write_dependency_checkpoint(
    source_root: &Path,
    work_dir: &Path,
    seed: &crate::auto::dep_manifest::DependencyManifest,
    results: &[AttemptResult],
) -> Result<crate::auto::dep_manifest::DependencyManifest> {
    let mut manifest = seed.clone();
    manifest.complete = false;
    let mut ordered: Vec<&AttemptResult> = results.iter().collect();
    ordered.sort_by(|a, b| a.candidate.harness_id.cmp(&b.candidate.harness_id));
    for result in ordered {
        add_checkpoint_result(&mut manifest, source_root, result);
    }
    add_idl_deps_from_skipped_targets(&mut manifest, source_root, results);
    manifest.mark_checkpoint(results.len(), false);
    write_dependency_manifest_files(work_dir, &manifest)?;
    Ok(manifest)
}

/// Mark an already-written checkpoint final for an early-success mode such as
/// `--dry-run` or `--list-targets`. These modes have no attempt results and do
/// not call the full report writer, but they still completed all promised work.
pub fn finalize_dependency_checkpoint(
    work_dir: &Path,
    manifest: &mut crate::auto::dep_manifest::DependencyManifest,
) -> Result<()> {
    manifest.mark_checkpoint(manifest.completed_targets, true);
    write_dependency_manifest_files(work_dir, manifest)
}

/// Extend an existing durable checkpoint with one newly completed target. This
/// is the hot sweep path: it avoids rescanning every prior result after each
/// target while preserving the same merge semantics as a reconstructed resume
/// checkpoint.
pub fn checkpoint_dependency_result(
    source_root: &Path,
    work_dir: &Path,
    manifest: &mut crate::auto::dep_manifest::DependencyManifest,
    result: &AttemptResult,
) -> Result<()> {
    add_checkpoint_result(manifest, source_root, result);
    add_idl_deps_from_skipped_targets(manifest, source_root, std::slice::from_ref(result));
    manifest.mark_checkpoint(manifest.completed_targets.saturating_add(1), false);
    write_dependency_manifest_files(work_dir, manifest)
}

/// Write both human and machine manifests through atomic replacement. The human
/// handoff list is committed first because that is the file printed to the
/// operator; if the process dies between renames, both files remain valid and
/// the text list is the newest checkpoint.
fn write_dependency_manifest_files(
    work_dir: &Path,
    manifest: &crate::auto::dep_manifest::DependencyManifest,
) -> Result<()> {
    let auto_dir = work_dir.join("auto");
    std::fs::create_dir_all(&auto_dir)?;
    atomic_write(
        &auto_dir.join("missing-deps.txt"),
        manifest.render_text().as_bytes(),
    )?;
    atomic_write(
        &auto_dir.join("missing-deps.json"),
        manifest.to_json().as_bytes(),
    )?;
    Ok(())
}

pub fn load_dependency_manifest(
    work_dir: &Path,
) -> Option<crate::auto::dep_manifest::DependencyManifest> {
    std::fs::read_to_string(work_dir.join("auto/missing-deps.json"))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
}

/// One stable terminal/summary line. Always names the human file, even when a
/// filesystem error made the JSON count unavailable.
pub fn dependency_manifest_pointer(work_dir: &Path) -> String {
    let path = work_dir.join("auto/missing-deps.txt");
    match load_dependency_manifest(work_dir) {
        Some(manifest) => format!(
            "{} ({} blocking, {} substituted; {} target checkpoint{})",
            path.display(),
            manifest.blocking_count(),
            manifest.stubbed_count(),
            manifest.completed_targets,
            if manifest.complete {
                ", final"
            } else {
                ", in progress"
            }
        ),
        None => format!("{} (manifest unavailable)", path.display()),
    }
}

/// The ecosystem package an interpreted lane reported as unresolvable, from the
/// `missing module \`NAME\`` marker those lanes put in their skip reason.
fn missing_language_package(outcome: &Outcome) -> Option<String> {
    let reason = match outcome {
        Outcome::UnsupportedParams { reason } => reason.as_str(),
        Outcome::FailedBuild { .. }
        | Outcome::BuiltAndFuzzed { .. }
        | Outcome::BuiltNotEntered { .. }
        | Outcome::Built { .. }
        | Outcome::UnrecoverableLink { .. }
        | Outcome::UnrecoverableRuntime { .. }
        | Outcome::ReportOnly { .. } => return None,
    };
    let at = reason.find("missing module `")?;
    let rest = &reason[at + "missing module `".len()..];
    let name = rest.split('`').next()?.trim();
    (!name.is_empty()).then(|| name.to_owned())
}

fn add_checkpoint_result(
    manifest: &mut crate::auto::dep_manifest::DependencyManifest,
    source_root: &Path,
    result: &AttemptResult,
) {
    use crate::auto::dep_manifest::{DepKind, RequirementBasis};
    use crate::auto::repair::Repair;
    let id = result.candidate.harness_id.clone();
    let repairs: &[Repair] = match &result.outcome {
        Outcome::BuiltAndFuzzed { repairs, .. }
        | Outcome::BuiltNotEntered { repairs, .. }
        | Outcome::Built { repairs, .. }
        | Outcome::FailedBuild { repairs, .. }
        | Outcome::UnrecoverableLink { repairs, .. }
        | Outcome::UnrecoverableRuntime { repairs, .. } => repairs,
        Outcome::UnsupportedParams { .. } | Outcome::ReportOnly { .. } => &[],
    };
    // An interpreted target that could not load because a package is not
    // installed is a missing DEPENDENCY, not an unsupported signature. Without
    // this the manifest claimed "no external dependencies were missing" for a
    // tree where every target skipped on an uninstalled gem.
    if let Some(package) = missing_language_package(&result.outcome) {
        manifest.push_merge_detailed(
            DepKind::LanguagePackage,
            package.clone(),
            vec![id.clone()],
            false,
            crate::auto::dep_manifest::acquisition_hint(DepKind::LanguagePackage, &package),
            RequirementBasis::Observed,
            Some(format!(
                "the {:?} target could not be loaded: its runtime could not resolve `{package}`",
                result.candidate.lang,
            )),
        );
    }
    for repair in repairs {
        match repair {
            Repair::HeaderPlaceholder { virtual_path } => {
                add_missing_header_requirement(manifest, source_root, virtual_path, &id, true)
            }
            Repair::ConfigHeaderSynth { virtual_path } => manifest.push_merge_detailed(
                DepKind::GeneratedSource,
                virtual_path.clone(),
                vec![id.clone()],
                true,
                configure_template_hint(source_root, virtual_path),
                RequirementBasis::Observed,
                Some("BHF synthesized a minimal configuration header".to_owned()),
            ),
            Repair::TypePlaceholder { type_name } => {
                if !build_classifier::is_recovery_artifact(type_name)
                    && !crate::auto::repair::is_synthesized_type_report_noise(type_name)
                {
                    manifest.push_merge(
                        DepKind::CType,
                        type_name.clone(),
                        vec![id.clone()],
                        true,
                    );
                }
            }
            Repair::TypeAlias { type_name, .. } => manifest.push_merge(
                DepKind::CType,
                type_name.clone(),
                vec![id.clone()],
                true,
            ),
            Repair::ConfigTypeAlias {
                type_name,
                underlying,
                header_path,
            } => {
                let name = header_path
                    .clone()
                    .unwrap_or_else(|| format!("generated definition for {type_name}"));
                manifest.push_merge_detailed(
                    DepKind::GeneratedSource,
                    name,
                    vec![id.clone()],
                    true,
                    Some(format!(
                        "supply the project's generated definition for '{type_name}' instead of BHF's assumed '{underlying}' default"
                    )),
                    RequirementBasis::Inferred,
                    Some(format!(
                        "BHF substituted default type '{underlying}' for '{type_name}'"
                    )),
                );
            }
            Repair::MacroDefine { name, .. } => manifest.push_merge(
                DepKind::Macro,
                name.clone(),
                vec![id.clone()],
                true,
            ),
            Repair::IncludeStdHeader { symbol, header } => manifest.push_merge(
                DepKind::Macro,
                format!("{symbol} -> <{header}>"),
                vec![id.clone()],
                true,
            ),
            Repair::StubDeclared { symbol, .. } | Repair::StubBlind { symbol } => manifest
                .push_merge(
                    DepKind::Symbol,
                    symbol.clone(),
                    vec![id.clone()],
                    true,
                ),
            Repair::AdaPackageStub { unit, .. } | Repair::AdaPackageBodyStub { unit, .. } => {
                manifest.push_merge(
                    DepKind::AdaUnit,
                    unit.clone(),
                    vec![id.clone()],
                    true,
                )
            }
            Repair::OverrideAdaBodyStub { source, unit, .. } => manifest.push_merge_detailed(
                DepKind::Runtime,
                format!("target-compatible Ada runtime/body for {unit}"),
                vec![id.clone()],
                true,
                Some(format!(
                    "stage the GNAT runtime/toolchain matching '{}' or supply a host-compatible implementation of {}",
                    source.display(),
                    source.display()
                )),
                RequirementBasis::Observed,
                Some(format!(
                    "the host assembler/compiler rejected '{}'; BHF neutralized that body",
                    source.display()
                )),
            ),
            Repair::PlatformStub { platform } => manifest.push_merge_detailed(
                DepKind::Runtime,
                format!("{platform} SDK/runtime"),
                vec![id.clone()],
                true,
                Some(format!(
                    "stage the compatible {platform} SDK/runtime and a runnable target environment to exercise real platform behavior"
                )),
                RequirementBasis::Observed,
                Some("the target built with BHF's platform stub".to_owned()),
            ),
            Repair::StubGprImport { project } => manifest.push_merge_detailed(
                DepKind::AdaUnit,
                format!("external Ada library project '{project}'"),
                vec![id.clone()],
                true,
                Some(format!(
                    "supply the real '{project}' library source (e.g. `alr get {project}` on a connected host, then pass its directory with --ada-deps) for a high-fidelity fuzz"
                )),
                RequirementBasis::Observed,
                Some(format!(
                    "the external `with \"{project}\";` project was absent; under --force BHF synthesized an empty stub project so the build could load and the referenced packages were stubbed — findings are reduced-fidelity"
                )),
            ),
            Repair::HeaderForward { .. }
            | Repair::AddIncludeDir { .. }
            | Repair::IncludeTypeHeader { .. }
            | Repair::DeclareFunction { .. }
            | Repair::AddSource { .. }
            | Repair::EnvVarInjection { .. }
            | Repair::AddAdaSource { .. }
            // A recovered build-config macro is bhf supplying what the project's
            // own build system would have — not a dependency to acquire.
            | Repair::ConfigGuardDefine { .. }
            // A forced synthetic parameter is a BHF limit, not a dependency the
            // operator could stage — keep it out of the missing-dependency manifest
            // (#5's rule for codegen errors). The finding-level forced caveat and the
            // blocker histogram already carry it.
            | Repair::ForcedSyntheticParams { .. }
            | Repair::Win32Pack => {}
        }
    }

    match &result.outcome {
        Outcome::FailedBuild { last_errors, .. } => {
            for error in last_errors {
                match error {
                    build_classifier::BuildErrorKind::MissingSharedLib { name } => manifest
                        .push_merge(
                            DepKind::SharedLibrary,
                            name.clone(),
                            vec![id.clone()],
                            false,
                        ),
                    build_classifier::BuildErrorKind::MissingGprImport { path } => manifest
                        .push_merge(
                            DepKind::GprImport,
                            path.clone(),
                            vec![id.clone()],
                            false,
                        ),
                    build_classifier::BuildErrorKind::MissingAdaWith { unit }
                    | build_classifier::BuildErrorKind::MissingAdaPackageBody { unit } => manifest
                        .push_merge(
                            DepKind::AdaUnit,
                            unit.clone(),
                            vec![id.clone()],
                            false,
                        ),
                    build_classifier::BuildErrorKind::MissingAdaSymbol { unit, symbol }
                        if !unit.is_empty() => manifest.push_merge(
                            DepKind::AdaUnit,
                            format!("{unit}.{symbol}"),
                            vec![id.clone()],
                            false,
                        ),
                    build_classifier::BuildErrorKind::UncompilableAdaBody { source } => manifest
                        .push_merge_detailed(
                            DepKind::Runtime,
                            format!("target-compatible Ada runtime/body for {source}"),
                            vec![id.clone()],
                            false,
                            Some(format!(
                                "stage the matching GNAT target runtime/toolchain or a compatible implementation of '{source}'"
                            )),
                            RequirementBasis::Observed,
                            Some("compiler/assembler rejected target-specific Ada body".to_owned()),
                        ),
                    _ => {}
                }
            }
            record_failed_build_blockers(
                manifest,
                &[(id.clone(), last_errors.clone())],
                source_root,
            );
        }
        Outcome::UnrecoverableLink { missing, .. } => {
            for name in missing {
                let kind = if name.ends_with(".gpr") {
                    DepKind::GprImport
                } else {
                    DepKind::SharedLibrary
                };
                manifest.push_merge(kind, name.clone(), vec![id.clone()], false);
            }
        }
        Outcome::BuiltAndFuzzed {
            runtrace_events, ..
        }
        | Outcome::BuiltNotEntered {
            runtrace_events, ..
        }
        | Outcome::UnrecoverableRuntime {
            runtrace_events, ..
        } => add_runtrace_requirements(manifest, &id, runtrace_events),
        Outcome::ReportOnly { reason, .. } => {
            if reason.contains("external SDK/framework") {
                manifest.push_merge_detailed(
                    DepKind::VendorSource,
                    format!("external SDK/framework source required by {id}"),
                    vec![id],
                    false,
                    Some(
                        "identify the owner of the named unresolved types in the target reason and transfer that SDK's headers and semantic source"
                            .to_owned(),
                    ),
                    RequirementBasis::Inferred,
                    Some(reason.clone()),
                );
            }
        }
        Outcome::Built { .. } | Outcome::UnsupportedParams { .. } => {}
    }
}

fn add_missing_header_requirement(
    manifest: &mut crate::auto::dep_manifest::DependencyManifest,
    source_root: &Path,
    header: &str,
    id: &str,
    stubbed: bool,
) {
    use crate::auto::dep_manifest::{
        corba_generated_idl, is_configure_generated_header, DepKind, RequirementBasis,
    };
    if let Some(idl) = corba_generated_idl(header) {
        manifest.push_merge_detailed(
            DepKind::IdlInterface,
            idl,
            vec![id.to_owned()],
            stubbed,
            None,
            RequirementBasis::Inferred,
            Some(format!("missing generated CORBA header '{header}'")),
        );
        return;
    }
    let generated_hint = configure_template_hint(source_root, header);
    if generated_hint.is_some() || is_configure_generated_header(header) {
        manifest.push_merge_detailed(
            DepKind::GeneratedSource,
            header.to_owned(),
            vec![id.to_owned()],
            stubbed,
            generated_hint,
            RequirementBasis::Observed,
            Some(format!(
                "compiler reported generated/config header '{header}' missing"
            )),
        );
    } else {
        manifest.push_merge(
            DepKind::Header,
            header.to_owned(),
            vec![id.to_owned()],
            stubbed,
        );
    }
}

fn add_runtrace_requirements(
    manifest: &mut crate::auto::dep_manifest::DependencyManifest,
    id: &str,
    events: &[crate::auto::runtrace::RuntraceEvent],
) {
    use crate::auto::dep_manifest::DepKind;
    use crate::auto::runtrace::RuntraceEvent;
    for event in events {
        match event {
            RuntraceEvent::EnvVarMissing { name, .. } => {
                manifest.push_merge(DepKind::EnvVar, name.clone(), vec![id.to_owned()], true)
            }
            RuntraceEvent::FileMissing { path, .. } => manifest.push_merge(
                classify_missing_path(path),
                path.clone(),
                vec![id.to_owned()],
                is_debuginfod_cache(path),
            ),
            RuntraceEvent::NetworkUnreachable { address, .. } if !address.is_empty() => manifest
                .push_merge(
                    DepKind::NetworkEndpoint,
                    address.clone(),
                    vec![id.to_owned()],
                    true,
                ),
            RuntraceEvent::DlopenFailed { library } => manifest.push_merge(
                DepKind::DlopenLibrary,
                library.clone(),
                vec![id.to_owned()],
                true,
            ),
            _ => {}
        }
    }
}

/// Add semantic substitutions that the aggregate `NeededForBuild` ledger cannot
/// represent precisely (target runtimes, generated type definitions, and
/// platform SDK substitutions). Safe to call more than once because entries
/// merge by kind+name.
fn add_semantic_requirements_from_results(
    manifest: &mut crate::auto::dep_manifest::DependencyManifest,
    source_root: &Path,
    results: &[AttemptResult],
) {
    for result in results {
        add_checkpoint_result(manifest, source_root, result);
    }
}

/// Set of header file basenames present anywhere under `root` (bounded walk).
fn header_basenames_present(root: &Path) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    let mut stack = vec![root.to_path_buf()];
    let mut seen = 0usize;
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            seen += 1;
            if seen > 200_000 {
                return out;
            }
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.ends_with(".h") || name.ends_with(".hpp") || name.ends_with(".hxx") {
                    out.insert(name.to_owned());
                }
            }
        }
    }
    out
}

/// Extract the targets of `#include "x"` / `#include <x>` directives from C/C++
/// source text.
fn scan_include_targets(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim_start();
        let Some(rest) = t.strip_prefix("#include") else {
            continue;
        };
        let rest = rest.trim_start();
        let close = match rest.chars().next() {
            Some('"') => '"',
            Some('<') => '>',
            _ => continue,
        };
        if let Some(end) = rest[1..].find(close) {
            let inc = &rest[1..1 + end];
            if !inc.is_empty() {
                out.push(inc.to_owned());
            }
        }
    }
    out
}

/// True for an llvm-debuginfod client cache path (`~/.cache/llvm-debuginfod/...`).
/// These are transient symbol-lookup artifacts touched by the linked binary, not
/// real build inputs — the build/fuzz completes without them, so they should be
/// reported as non-blocking rather than "still blocking".
fn is_debuginfod_cache(path: &str) -> bool {
    path.contains(".cache/llvm-debuginfod")
        || (path.contains(".cache") && path.contains("debuginfod"))
}

/// Classify a missing filesystem path the build/runtime needed. A path that
/// `lstat`s as a symlink but doesn't resolve is a dangling Symlink; one under a
/// network-mount prefix (UNC `//host/share`, or `/mnt`/`/net`/`/media`/`/smb`/
/// `/nfs`) is a NetworkShare; anything else is a plain FilePath.
fn classify_missing_path(path: &str) -> crate::auto::dep_manifest::DepKind {
    use crate::auto::dep_manifest::DepKind;
    if path.starts_with("//") {
        return DepKind::NetworkShare;
    }
    let network_prefixes = ["/mnt/", "/net/", "/media/", "/smb/", "/nfs/", "/cifs/"];
    if network_prefixes.iter().any(|p| path.starts_with(p)) {
        return DepKind::NetworkShare;
    }
    // A dangling symlink: the link node exists, its target doesn't.
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() && std::fs::metadata(path).is_err() {
            return DepKind::Symlink;
        }
    }
    DepKind::FilePath
}

/// Scan the project's GPR file(s) under `source_root` for `external("VAR")`
/// scenario references that have NO default — gprbuild errors ("undefined
/// external") without them, so they are genuinely-needed env vars. References
/// with a default (`external("VAR", "x")`) are fine and not reported. Best-effort
/// + bounded; returns deduped variable names.
fn required_gpr_externals(source_root: &Path) -> Vec<String> {
    use std::collections::BTreeSet;
    let mut out = BTreeSet::new();
    let Ok(entries) = std::fs::read_dir(source_root) else {
        return Vec::new();
    };
    for entry in entries.flatten().take(256) {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("gpr") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let lower = text.to_ascii_lowercase();
        let mut from = 0;
        while let Some(rel) = lower[from..].find("external") {
            let at = from + rel;
            from = at + "external".len();
            let rest = text[from..].trim_start();
            // Must be the `external (...)` function form (not `external_as_list`,
            // not an identifier ending in "external").
            let Some(args) = rest.strip_prefix('(') else {
                continue;
            };
            let Some(close) = args.find(')') else {
                continue;
            };
            let inside = &args[..close];
            // First quoted token is the variable name; a comma after it means a
            // default is supplied (not needed).
            let Some(name) = first_quoted(inside) else {
                continue;
            };
            if !inside[inside
                .find('"')
                .map(|i| i + 1 + name.len() + 1)
                .unwrap_or(inside.len())..]
                .trim_start()
                .starts_with(',')
            {
                out.insert(name);
            }
        }
    }
    out.into_iter().collect()
}

/// The first `"..."` token in `s`, or None.
fn first_quoted(s: &str) -> Option<String> {
    let start = s.find('"')?;
    let end = s[start + 1..].find('"')?;
    Some(s[start + 1..start + 1 + end].to_owned())
}

#[allow(clippy::too_many_arguments)]
fn aggregate_repairs(
    repairs: &[Repair],
    id: &str,
    headers: &mut BTreeMap<String, Vec<String>>,
    types: &mut BTreeMap<String, Vec<String>>,
    declared: &mut BTreeMap<String, Vec<String>>,
    blind: &mut BTreeMap<String, Vec<String>>,
    ada_units: &mut BTreeMap<String, Vec<String>>,
    ada_symbols: &mut BTreeMap<String, Vec<String>>,
    macros: &mut BTreeMap<String, Vec<String>>,
) {
    for r in repairs {
        match r {
            Repair::HeaderPlaceholder { virtual_path } => headers
                .entry(virtual_path.clone())
                .or_default()
                .push(id.to_owned()),
            // A forwarding header references a real in-tree header. It is a
            // build-layout adjustment, not a missing dependency or stub.
            Repair::HeaderForward { .. } => {}
            Repair::IncludeTypeHeader { .. } => {}
            // The manifest classifies this as generated source from the
            // structured repair. Keep the run ledger's original path so it can
            // merge without a second, human-label-suffixed entry.
            Repair::ConfigHeaderSynth { virtual_path } => headers
                .entry(virtual_path.clone())
                .or_default()
                .push(id.to_owned()),
            Repair::MacroDefine { name, .. }
            // A macro recovered from a `#error` guard is the same kind of fact for
            // the reader: a build-config define bhf had to supply itself.
            | Repair::ConfigGuardDefine { name, .. } => {
                macros.entry(name.clone()).or_default().push(id.to_owned())
            }
            // A force-included standard header for an undefined standard symbol —
            // report alongside build-config macros (a build adjustment, not a
            // maintainer-must-ship artifact).
            Repair::IncludeStdHeader { symbol, header } => macros
                .entry(format!("{symbol} -> <{header}>"))
                .or_default()
                .push(id.to_owned()),
            // Prototype-only visibility repair: the real project definition is
            // still linked and executed, so this is not a synthesized dependency
            // or a stub inventory entry.
            Repair::DeclareFunction { .. } => {}
            Repair::TypePlaceholder { type_name } => {
                // A clang recovery-artifact placeholder (`type`/`expression`) is not
                // a real missing type the maintainer must ship — never report it as a
                // synthesized_type dependency (#48). Defense in depth: the planner
                // now refuses to synthesize one, but an older on-disk repair record
                // may still carry it.
                if build_classifier::is_recovery_artifact(type_name) {
                    continue;
                }
                // Skip cross-platform Win32 typedef placeholders on
                // non-Windows hosts — they're harmless internally
                // (lets the `#ifdef _WIN32` branch parse) but they're
                // not a "the maintainer must ship WCHAR" finding.
                if crate::auto::repair::is_synthesized_type_report_noise(type_name) {
                    continue;
                }
                types
                    .entry(type_name.clone())
                    .or_default()
                    .push(id.to_owned());
            }
            Repair::TypeAlias { type_name, .. } => {
                // A real typedef synthesised from the tree-wide index (e.g. an
                // arch-gated `word_t`); report it like a synthesised type.
                types
                    .entry(type_name.clone())
                    .or_default()
                    .push(id.to_owned());
            }
            Repair::ConfigTypeAlias {
                type_name,
                underlying,
                ..
            } => {
                // A DEFAULT-width config alias (the real width is set by absent
                // codegen a non-default deployment can override). Surface it as a
                // synthesised type with an explicit LOWER-CONFIDENCE width
                // annotation so a reviewer sees exactly which widths were assumed
                // and can supply the real *AliasAc.h before promoting any finding.
                types
                    .entry(format!(
                        "{type_name} -> {underlying} (synthesised config default, LOWER-CONFIDENCE width)"
                    ))
                    .or_default()
                    .push(id.to_owned());
            }
            Repair::StubDeclared { symbol, .. } => declared
                .entry(symbol.clone())
                .or_default()
                .push(id.to_owned()),
            Repair::StubBlind { symbol } => {
                blind.entry(symbol.clone()).or_default().push(id.to_owned())
            }
            Repair::AddSource { .. } => {}
            // A build-path adjustment (real in-tree header dir / Ada unit source),
            // not a synthesised artifact the maintainer must ship.
            Repair::AddIncludeDir { .. } => {}
            Repair::AddAdaSource { .. } => {}
            Repair::StubGprImport { .. } => {}
            // Layer-C env-var injections are aggregated separately by
            // the runtrace-event aggregator (Batch B5 / Task 12). No-op
            // here to keep the existing four-bag signature stable.
            Repair::EnvVarInjection { .. } => {}
            Repair::AdaPackageStub { unit, decls, .. } => {
                push_unique_reference(ada_units, unit.clone(), id);
                for decl in decls {
                    push_unique_reference(ada_symbols, format!("{unit}.{decl}"), id);
                }
            }
            Repair::OverrideAdaBodyStub { unit, .. } => {
                push_unique_reference(ada_units, unit.clone(), id);
            }
            Repair::AdaPackageBodyStub { unit, ops, .. } => {
                push_unique_reference(ada_units, unit.clone(), id);
                for op in ops {
                    push_unique_reference(ada_symbols, format!("{unit}.{}", op.name), id);
                }
            }
            // Reduced-fidelity label, surfaced per-target via `platform_stub`
            // (not a missing dependency the maintainer must ship).
            Repair::PlatformStub { .. } => {}
            // Synthesized Win32/MFC platform headers for a stray Win32/MFC name —
            // a build adjustment (real underlying types), not a maintainer-must-
            // ship dependency.
            Repair::Win32Pack => {}
            // Reduced-fidelity label for a forced Go/C# parameter or receiver;
            // surfaced per-finding as the forced caveat, not as a dependency.
            Repair::ForcedSyntheticParams { .. } => {}
        }
    }
}

fn aggregate_runtrace(
    events: &[crate::auto::runtrace::RuntraceEvent],
    id: &str,
    env: &mut BTreeMap<String, Vec<String>>,
    files: &mut BTreeMap<String, Vec<String>>,
    endpoints: &mut BTreeMap<String, Vec<String>>,
    dlopen: &mut BTreeMap<String, Vec<String>>,
) {
    use crate::auto::runtrace::RuntraceEvent;
    for ev in events {
        match ev {
            RuntraceEvent::EnvVarMissing { name, .. } => {
                push_unique_reference(env, name.clone(), id);
            }
            RuntraceEvent::EnvVarAccess { .. } => {}
            RuntraceEvent::FileMissing { path, .. } => {
                push_unique_reference(files, path.clone(), id);
            }
            RuntraceEvent::NetworkUnreachable { address, .. } => {
                if !address.is_empty() {
                    push_unique_reference(endpoints, address.clone(), id);
                }
            }
            RuntraceEvent::DlopenFailed { library } => {
                push_unique_reference(dlopen, library.clone(), id);
            }
            // The taint-sink events are always emitted (tainted or not, so the
            // cross-execution tracker can suppress constants) and are consumed
            // by the sink oracles, not this missing-dependency aggregation.
            RuntraceEvent::FileOpened { .. }
            | RuntraceEvent::FileClosed { .. }
            | RuntraceEvent::FileDeleted { .. }
            | RuntraceEvent::PathChecked { .. }
            | RuntraceEvent::InsecurePermissions { .. }
            | RuntraceEvent::InsecureTempFile { .. }
            | RuntraceEvent::CommandExecuted { .. }
            | RuntraceEvent::ProcessExec { .. }
            | RuntraceEvent::NetworkEgress { .. }
            | RuntraceEvent::LibraryLoad { .. }
            | RuntraceEvent::SqlQuery { .. }
            | RuntraceEvent::DestructiveFsOp { .. }
            | RuntraceEvent::FormatString { .. }
            | RuntraceEvent::RuntimeCheck { .. }
            | RuntraceEvent::Unknown { .. } => {}
        }
    }
}

fn push_unique_reference(bag: &mut BTreeMap<String, Vec<String>>, name: String, id: &str) {
    let refs = bag.entry(name).or_default();
    if !refs.iter().any(|existing| existing == id) {
        refs.push(id.to_owned());
    }
}

fn drain_bag(bag: BTreeMap<String, Vec<String>>) -> Vec<Aggregated> {
    bag.into_iter()
        .map(|(name, referenced_by_targets)| Aggregated {
            name,
            referenced_by_targets,
        })
        .collect()
}

fn render_md(r: &RunJson<'_>) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = writeln!(s, "# BHF auto run — {}", r.finished_at);
    let _ = writeln!(s, "Source: {}", r.source_root.display());
    let _ = writeln!(s, "Mode: {}", r.mode.as_str());
    let _ = writeln!(s);
    let _ = writeln!(s, "## Findings");
    if r.summary.findings > 0 {
        let _ = writeln!(
            s,
            "**{} finding observation(s). Start with [`results/INDEX.md`](../results/INDEX.md).**",
            r.summary.findings
        );
        let _ = writeln!(
            s,
            "Machine-readable: [`results/findings.json`](../results/findings.json) · [`results/findings.csv`](../results/findings.csv). Evidence bundles: [`results/findings/`](../results/findings/)."
        );
    } else {
        let _ = writeln!(
            s,
            "No findings were emitted. Review the target outcomes below before treating the run as clean."
        );
    }
    let _ = writeln!(s);
    let _ = writeln!(s, "## Campaign summary");
    let _ = writeln!(s, "Discovered: {}", r.summary.discovered);
    // #102: a run with zero candidates but parser failures must say WHY, so a
    // parser regression on a large tree is never read as an unexplained clean no-op.
    if r.summary.discovered == 0 && !r.summary.discovery_diagnostics.is_empty() {
        let dropped: usize = r
            .summary
            .discovery_diagnostics
            .iter()
            .map(|d| d.files)
            .sum();
        let langs: std::collections::BTreeSet<&str> = r
            .summary
            .discovery_diagnostics
            .iter()
            .map(|d| d.language.as_str())
            .collect();
        let _ = writeln!(
            s,
            "  No targets discovered. Reason: {dropped} file(s) failed to read/parse ({}). \
             See the Discovery Diagnostics section.",
            langs.into_iter().collect::<Vec<_>>().join(", ")
        );
    }
    if r.summary.dropped_by_cap > 0 {
        let reason = if r.summary.stopped_by_operator {
            "not attempted — the operator stopped the run"
        } else if r.summary.output_limit_reached {
            "not attempted — --max-work-dir-mb reached"
        } else {
            "dropped by --max-targets/--campaign-time cap"
        };
        let _ = writeln!(
            s,
            "  (of {} ranked; {} {reason})",
            r.summary.discovered_total, r.summary.dropped_by_cap
        );
    }
    let _ = writeln!(s, "Built:      {}", r.summary.built);
    let _ = writeln!(s, "Failed:     {}", r.summary.failed_build);
    let _ = writeln!(
        s,
        "Skipped (could not auto-harness): {}",
        r.summary.unsupported_params
    );
    let _ = writeln!(s, "Unrecoverable link: {}", r.summary.unrecoverable_link);
    let _ = writeln!(
        s,
        "Unrecoverable runtime: {}",
        r.summary.unrecoverable_runtime
    );
    let _ = writeln!(s, "Findings:   {}", r.summary.findings);
    // #102: durable, grouped discovery-drop diagnostics (read/decode/parse
    // failures). Each row is one (language, stage, class) with the file count and
    // one bounded, scrubbed sample — no paths, filenames, source, or identifiers.
    if !r.summary.discovery_diagnostics.is_empty() {
        let total: usize = r
            .summary
            .discovery_diagnostics
            .iter()
            .map(|d| d.files)
            .sum();
        let _ = writeln!(s);
        let _ = writeln!(
            s,
            "## Discovery Diagnostics — {total} file(s) dropped (read/parse failures)"
        );
        for d in &r.summary.discovery_diagnostics {
            let _ = writeln!(
                s,
                "  - {} {} {} — {} file(s){}",
                d.language,
                d.stage,
                d.category,
                d.files,
                d.sample
                    .as_deref()
                    .map(|s| format!(": {s}"))
                    .unwrap_or_default()
            );
        }
    }
    // force-fuzz Phase 2: a forced sweep that fuzzed synthesized stubs must not read
    // as N confirmed campaigns — surface the forced-and-stub-heavy count distinctly,
    // right next to the fuzzed total, and note the findings are floored to Low.
    if r.summary.forced > 0 {
        let _ = writeln!(
            s,
            "Forced (stub-heavy): {} of {} fuzzed — findings floored to Low (crash may be a stub artifact)",
            r.summary.forced, r.summary.built_and_fuzzed
        );
    }
    // #417: never let a false clean hide. If any fuzzed target only exercised
    // blind stubs, lead with a loud, structured warning naming every such target
    // so a 0-finding run over millions of stub executions is not read as clean.
    if r.summary.fuzzed_stub_only > 0 {
        let _ = writeln!(s);
        let _ = writeln!(
            s,
            "## ⚠ STUB-ONLY (FALSE CLEAN) — {} of {} fuzzed target(s)",
            r.summary.fuzzed_stub_only, r.summary.built_and_fuzzed
        );
        let _ = writeln!(
            s,
            "These targets fuzzed only blind stubs (invented empty bodies); no real \
             dependency code was linked, so their results do NOT reflect the real library. \
             Provide the missing dependency sources (see Upstream delta / missing-deps) and re-run."
        );
        for t in &r.targets {
            if let Some(se) = &t.stub_execution {
                if se.stub_only {
                    let _ = writeln!(
                        s,
                        "  - {} {} — {}/{} called symbols blind-stubbed ({:.0}%)",
                        t.harness_id,
                        t.name,
                        se.blind_stubbed_symbols,
                        se.resolved_called_symbols,
                        se.blind_stub_fraction * 100.0
                    );
                }
            }
        }
    }
    let _ = writeln!(s);
    // Per-target rows. Each built+fuzzed target prints one segment
    // per pass so the maintainer can see which pass surfaced which
    // findings (e.g. `empty=4123execs/1000exec_s/0f
    // rng=3811execs/2000exec_s/1f fuzz_driven=2901execs/500exec_s/2f`).
    if !r.targets.is_empty() {
        let _ = writeln!(s, "## Targets");
        for t in &r.targets {
            let line = render_target_md_line(t);
            let _ = writeln!(s, "  - {line}");
        }
        let _ = writeln!(s);
    }
    let any_delta = !r.needed_for_build.synthesized_headers.is_empty()
        || !r.needed_for_build.synthesized_types.is_empty()
        || !r.needed_for_build.synthesized_macros.is_empty()
        || !r.needed_for_build.stubbed_symbols_declared.is_empty()
        || !r.needed_for_build.stubbed_symbols_blind.is_empty()
        || !r.needed_for_build.stubbed_ada_units.is_empty()
        || !r.needed_for_build.stubbed_ada_symbols.is_empty()
        || !r.needed_for_build.missing_libraries.is_empty()
        || !r.needed_for_build.missing_gpr_imports.is_empty()
        || !r.needed_for_build.missing_ada_units.is_empty();
    let any_delta_c = !r.needed_for_build.environment_variables_faked.is_empty()
        || !r.needed_for_build.missing_files.is_empty()
        || !r.needed_for_build.network_endpoints.is_empty()
        || !r.needed_for_build.dlopen_failures.is_empty();
    if any_delta || any_delta_c {
        let _ = writeln!(s, "## Upstream delta");
        md_section(
            &mut s,
            "Synthesised headers",
            &r.needed_for_build.synthesized_headers,
        );
        md_section(
            &mut s,
            "Synthesised types",
            &r.needed_for_build.synthesized_types,
        );
        md_section(
            &mut s,
            "Synthesised build-config macros (supply real values)",
            &r.needed_for_build.synthesized_macros,
        );
        md_section(
            &mut s,
            "Stubbed symbols (declared)",
            &r.needed_for_build.stubbed_symbols_declared,
        );
        md_section(
            &mut s,
            "Stubbed symbols (blind)",
            &r.needed_for_build.stubbed_symbols_blind,
        );
        md_section(
            &mut s,
            "Stubbed Ada units",
            &r.needed_for_build.stubbed_ada_units,
        );
        md_section(
            &mut s,
            "Stubbed Ada symbols",
            &r.needed_for_build.stubbed_ada_symbols,
        );
        md_section(
            &mut s,
            "Missing libraries (NOT auto-stubbed)",
            &r.needed_for_build.missing_libraries,
        );
        md_section(
            &mut s,
            "Missing GPR imports (NOT auto-synthesised)",
            &r.needed_for_build.missing_gpr_imports,
        );
        md_section(
            &mut s,
            "Missing Ada units (NOT auto-stubbed)",
            &r.needed_for_build.missing_ada_units,
        );
        if any_delta_c {
            let _ = writeln!(s, "\n### Runtime resources observed during fuzzing");
            md_section(
                &mut s,
                "Environment variables (auto-injected)",
                &r.needed_for_build.environment_variables_faked,
            );
            md_section(&mut s, "Missing files", &r.needed_for_build.missing_files);
            md_section(
                &mut s,
                "Network endpoints unreachable",
                &r.needed_for_build.network_endpoints,
            );
            md_section(
                &mut s,
                "dlopen failures",
                &r.needed_for_build.dlopen_failures,
            );
        }
    }
    // #5: harness/codegen build errors are a distinct category — bhf's own
    // codegen or the project's build config, NOT an external dependency. Rendered
    // separately so they are never read as "bring this dependency".
    if !r.needed_for_build.harness_codegen_errors.is_empty() {
        let _ = writeln!(
            s,
            "\n## Harness / codegen build errors\nThese are malformed generated harnesses or \
             parser recovery artifacts (bhf codegen / the project's own build config) — NOT \
             missing dependencies. Do not acquire a package for them."
        );
        md_section(
            &mut s,
            "Harness/codegen errors",
            &r.needed_for_build.harness_codegen_errors,
        );
    }
    s
}

/// Per-target one-liner for `run.md`. Looks like:
///
/// ```text
/// H-C0042 parse_packet              built+fuzzed  empty=4123execs/1000exec_s/0f rng=3811execs/2000exec_s/1f fuzz_driven=2901execs/500exec_s/2f
/// ```
///
/// For non-fuzzed outcomes the trailing pass segment is empty and
/// only the outcome label is shown. The label is the same one the live
/// progress line prints (`crate::auto::cli::outcome_label`) so the human
/// terminal output and the report never use different words for the same
/// outcome; the machine `run.json` `outcome` tag is unaffected.
fn render_target_md_line(t: &TargetEntry<'_>) -> String {
    let outcome_label = crate::auto::cli::outcome_label(t.outcome);
    // #95: `BuiltNotEntered` carries the same pass metrics as `BuiltAndFuzzed`
    // (it ran, it just never entered the target), so show them too.
    let (passes_line, finding_count) = match t.outcome {
        Outcome::BuiltAndFuzzed { passes, .. } | Outcome::BuiltNotEntered { passes, .. } => (
            passes_summary(passes),
            passes.iter().map(|p| p.findings.len()).sum::<usize>(),
        ),
        _ => (String::new(), 0),
    };
    let mut line = if passes_line.is_empty() {
        format!("{} {} {}", t.harness_id, t.name, outcome_label)
    } else {
        format!(
            "{} {} {} {}",
            t.harness_id, t.name, outcome_label, passes_line
        )
    };
    if passes_line.is_empty() {
        line.push_str(&format!(
            "  [stage={} repairs_attempted={} fallback={}]",
            t.attempt_trace.terminal_stage,
            t.attempt_trace.repairs_attempted,
            t.attempt_trace.fallback_chain.join("->")
        ));
    }
    // #417: mark a false-clean target inline so the per-target row itself carries
    // the warning, not just the header block — the outcome_label already reads
    // "built+fuzzed (STUB-ONLY)" but spell out the symbol ratio here too.
    if let Some(se) = &t.stub_execution {
        if se.stub_only {
            line.push_str(&format!(
                "  [!] STUB-ONLY: {}/{} called symbols blind-stubbed — not a real fuzz",
                se.blind_stubbed_symbols, se.resolved_called_symbols
            ));
        }
    }
    // When a target produced findings but its fuzzed parameters are NOT an
    // attacker-controlled input channel, flag every finding as reachability-
    // unproven so an artifact (a serializer overrun, a caller-controlled arg)
    // is never mistaken for a vulnerability.
    if finding_count > 0 {
        if let Some(reach) = t.input_reachability {
            if !reach.is_attacker_reachable() {
                line.push_str(&format!("  [!] {}", reach.report_note()));
            }
        }
    }
    // CC-1: the reduced-fidelity caveat, DERIVED from the structured record so it
    // can never disagree with it. A fully-native target returns `None` here, so it
    // carries no spurious caveat.
    if let Some(caveat) = t
        .fidelity
        .as_ref()
        .and_then(actionability::Fidelity::caveat)
    {
        line.push_str(&format!("  [!] {caveat}"));
    }
    line
}

/// Format a `Vec<PassRun>` as space-separated `pass=Nexecs/Rexec_s/Mf`
/// segments, in the order the cascade ran them. The `Rexec_s` throughput
/// figure (#405) is the measured per-pass executions/sec, for parity with
/// libFuzzer/AFL output.
fn passes_summary(passes: &[PassRun]) -> String {
    let parts: Vec<String> = passes
        .iter()
        .map(|pr| {
            format!(
                "{}={}execs/{:.0}exec_s/{}f",
                pr.pass.as_str(),
                pr.executions,
                pr.executions_per_sec,
                pr.findings.len()
            )
        })
        .collect();
    let mut line = parts.join(" ");
    // Edge coverage accumulates across passes, so the last/largest value is the
    // total the target reached (#385). Only shown when a coverage runtime ran.
    let cov = passes.iter().map(|p| p.coverage_edges).max().unwrap_or(0);
    if cov > 0 {
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(&format!("cov={cov}edges"));
    }
    line
}

fn md_section(s: &mut String, title: &str, bag: &[Aggregated]) {
    use std::fmt::Write;
    if bag.is_empty() {
        return;
    }
    let _ = writeln!(s, "\n### {title}");
    for entry in bag {
        let _ = writeln!(
            s,
            "  - {}    used by {} target(s)",
            entry.name,
            entry.referenced_by_targets.len()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auto::candidate::{Candidate, Lang};
    use crate::auto::dep_manifest::DepKind;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Rebuild `results/` the way the command's results bracket does after
    /// `write_reports`, and return `results/findings.json`.
    fn rebuild_results(work: &Path) -> serde_json::Value {
        let options = results::RebuildOptions {
            generate_reproducers: false,
            ..Default::default()
        };
        results::rebuild(work, &options).expect("rebuild results/");
        serde_json::from_slice(&std::fs::read(work.join("results/findings.json")).unwrap())
            .expect("parse findings.json")
    }

    #[test]
    fn annotate_forced_findings_floors_only_forced_harnesses() {
        let work = tempfile::tempdir().unwrap();
        let findings = corpus::layout::findings_dir(work.path());
        for (id, harness) in [("F-0001", "H1"), ("F-0002", "H2")] {
            let dir = findings.join(id);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("finding.json"),
                serde_json::to_vec_pretty(&serde_json::json!({
                    "id": id,
                    "harness_id": harness,
                }))
                .unwrap(),
            )
            .unwrap();
        }
        let forced: std::collections::BTreeSet<String> = ["H1".to_owned()].into_iter().collect();
        annotate_forced_findings(work.path(), &forced);
        // Second run (results/ is preserved): must not append a second history entry.
        annotate_forced_findings(work.path(), &forced);

        let read = |id: &str| -> serde_json::Value {
            serde_json::from_slice(&std::fs::read(findings.join(id).join("finding.json")).unwrap())
                .unwrap()
        };
        let forced_record = read("F-0001");
        assert_eq!(forced_record["forced"], serde_json::Value::Bool(true));
        assert_eq!(
            forced_record["forced_note"],
            confidence_model::FORCED_STUB_NOTE
        );
        let history = forced_record["history"].as_array().expect("history");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0]["command"], "auto");
        assert_eq!(history[0]["fields"][0], "forced");

        let unforced_record = read("F-0002");
        assert!(unforced_record.get("forced").is_none());
        assert!(unforced_record.get("history").is_none());
    }

    #[test]
    fn annotate_findings_with_fidelity_is_idempotent() {
        let work = tempfile::tempdir().unwrap();
        let findings = corpus::layout::findings_dir(work.path());
        let dir = findings.join("F-0001");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("finding.json"),
            serde_json::to_vec_pretty(&serde_json::json!({ "id": "F-0001", "harness_id": "H1" }))
                .unwrap(),
        )
        .unwrap();
        // Empty results -> every finding gets the "nothing executed" fidelity record.
        annotate_findings_with_fidelity(work.path(), &[], &[]);
        annotate_findings_with_fidelity(work.path(), &[], &[]);
        let raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("finding.json")).unwrap()).unwrap();
        assert!(raw.get("fidelity").is_some());
        let history = raw["history"].as_array().expect("history");
        assert_eq!(history.len(), 1, "fidelity annotation must be idempotent");
        assert_eq!(history[0]["command"], "auto");
        assert_eq!(history[0]["fields"][0], "fidelity");
    }

    #[test]
    fn disk_only_finding_ids_lists_every_disk_family() {
        let tmp = std::env::temp_dir().join(format!(
            "bhf-tsf-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let findings = tmp.join("results").join("findings");
        for id in [
            "F-STATIC-0000",
            "F-STATIC-0001",
            "F-MSAN-0000",
            "F-CAP-0000",
            "F-TSAN-0000",
            "F-MEM-0000",
            "F-JSINK-0000",
            "F-EXT-0000",
            "F-DIFF-0000",
            "F-0000-abcd",
            "F-RO-H1-000",
        ] {
            std::fs::create_dir_all(findings.join(id)).unwrap();
            std::fs::write(findings.join(id).join("finding.json"), b"{}").unwrap();
        }
        // A F-STATIC dir with no finding.json must be ignored (incomplete write).
        std::fs::create_dir_all(findings.join("F-STATIC-9999")).unwrap();

        // Disk-folded finding families: --static (F-STATIC-*), MSan/TSan replay
        // (F-MSAN-* / F-TSAN-*), memory profiling (F-MEM-*), capability profiling
        // (F-CAP-*), the JVM sink oracle (F-JSINK-*), external tools (F-EXT-*) and
        // the differential post-pass (F-DIFF-*). Result-linked fuzz (F-0000-*) and
        // report-only (F-RO-*) findings are NOT re-read here.
        let ids = disk_only_finding_ids(&tmp);
        assert_eq!(
            ids,
            vec![
                "F-CAP-0000",
                "F-DIFF-0000",
                "F-EXT-0000",
                "F-JSINK-0000",
                "F-MEM-0000",
                "F-MSAN-0000",
                "F-STATIC-0000",
                "F-STATIC-0001",
                "F-TSAN-0000",
            ]
        );
        // No findings dir at all -> empty, not a panic.
        assert!(disk_only_finding_ids(tmp.parent().unwrap().join("nope").as_path()).is_empty());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn stubbed_dep_still_in_failed_build_errors_is_reported_blocking() {
        // ctre: `utf8_iterator` was "stubbed" but 22 builds still failed on it —
        // it must be reported STILL BLOCKING, not "stubbed (build continued)".
        let needed = NeededForBuild {
            synthesized_types: vec![
                Aggregated {
                    name: "utf8_iterator".to_owned(),
                    referenced_by_targets: vec!["H-X".to_owned()],
                },
                Aggregated {
                    name: "harmless_t".to_owned(),
                    referenced_by_targets: vec!["H-Y".to_owned()],
                },
            ],
            ..Default::default()
        };
        let failed = "MissingType { name: \"utf8_iterator\" }\n";
        let m = build_dependency_manifest(&needed, &PathBuf::from("/tmp"), failed);
        let entry = |n: &str| m.entries.iter().find(|e| e.name == n).unwrap();
        assert!(
            !entry("utf8_iterator").stubbed,
            "a stubbed type the build still fails on is STILL BLOCKING"
        );
        assert!(
            entry("harmless_t").stubbed,
            "a stubbed type absent from the errors stays stubbed (build continued)"
        );
    }

    #[test]
    fn failed_build_records_unresolved_configure_header_with_remediation() {
        // #418: a c-ares-style failure on a configure-generated header that has no
        // source in the tree must surface in the manifest as a STILL-BLOCKING
        // header with a configure-oriented remediation — not vanish behind an
        // opaque `failed_build`.
        use build_classifier::BuildErrorKind;
        let temp = tempfile::tempdir().unwrap();
        let needed = NeededForBuild::default();
        let project_root = temp.path();
        let mut m = build_dependency_manifest(&needed, project_root, "");
        let failed = vec![(
            "H-CARES".to_owned(),
            vec![BuildErrorKind::MissingHeader {
                path: "ares_build.h".to_owned(),
            }],
        )];
        record_failed_build_blockers(&mut m, &failed, project_root);
        let e = m
            .entries
            .iter()
            .find(|e| e.name == "ares_build.h")
            .expect("ares_build.h must be recorded");
        assert_eq!(e.kind, DepKind::GeneratedSource);
        assert!(!e.stubbed, "an unresolved header is STILL BLOCKING");
        assert!(e.referenced_by.contains(&"H-CARES".to_owned()));
        let hint = e.acquisition_hint.as_deref().unwrap_or("");
        // The remediation for a generated header names the generator that
        // produces it (configure/cmake/autogen) — generalised from the older
        // literal "configure" wording — and points at a trusted build host.
        assert!(
            hint.contains("project generator") && hint.contains("build host"),
            "remediation names the generator + build host: {hint}"
        );
        assert!(!hint.contains("apt-file"), "no dead-end apt hint: {hint}");
        assert!(!m.is_empty());
        assert_eq!(m.blocking_count(), 1);
    }

    #[test]
    fn every_failed_build_yields_at_least_one_manifest_entry() {
        // #418 AC2 (the general guard): a failed_build must never be opaque — even
        // when the diagnostic is NOT a missing header. An `Other` compiler error,
        // an undefined symbol, and an (edge-case) error-less target each leave a
        // referencing manifest entry.
        use build_classifier::BuildErrorKind;
        // A shared-lib blocker is folded by build_dependency_manifest from the
        // `missing_libraries` bag, so the lib-only failed target below is already
        // covered and must NOT also get a redundant generic "build failed" entry.
        let needed = NeededForBuild {
            missing_libraries: vec![Aggregated {
                name: "hiredis".to_owned(),
                referenced_by_targets: vec!["H-LIB".to_owned()],
            }],
            ..Default::default()
        };
        let mut m = build_dependency_manifest(&needed, &PathBuf::from("/tmp"), "");
        let failed = vec![
            (
                "H-OTHER".to_owned(),
                vec![BuildErrorKind::Other {
                    tail: "t.c:9:1: error: something the classifier does not know\nmore noise"
                        .to_owned(),
                }],
            ),
            (
                "H-SYM".to_owned(),
                vec![BuildErrorKind::UndefinedSymbol {
                    name: "vendor_decode".to_owned(),
                }],
            ),
            // Already covered by the missing_libraries fold — no extra entry.
            (
                "H-LIB".to_owned(),
                vec![BuildErrorKind::MissingSharedLib {
                    name: "hiredis".to_owned(),
                }],
            ),
            // Defensive: a target that somehow surfaced no classified error at all
            // still must not be silent.
            ("H-EMPTY".to_owned(), vec![]),
        ];
        record_failed_build_blockers(&mut m, &failed, &PathBuf::from("/tmp"));
        for id in ["H-OTHER", "H-SYM", "H-LIB", "H-EMPTY"] {
            assert!(
                manifest_reference_count(&m, id) >= 1,
                "failed target {id} must contribute >= 1 manifest entry; manifest: {}",
                m.render_text()
            );
        }
        // The Other tail is summarised to its first error line, not dropped.
        assert!(
            m.entries
                .iter()
                .any(|e| e.name.contains("something the classifier does not know")),
            "Other diagnostic must surface: {}",
            m.render_text()
        );
        // The undefined symbol is named with link/supply remediation.
        let sym = m
            .entries
            .iter()
            .find(|e| e.name == "vendor_decode")
            .unwrap();
        assert_eq!(sym.kind, DepKind::Symbol);
        assert!(!sym.stubbed);
        // H-LIB is covered by its shared-library entry only — no redundant generic
        // "build failed for target" row.
        assert_eq!(
            manifest_reference_count(&m, "H-LIB"),
            1,
            "lib-only failure must not get a duplicate generic entry: {}",
            m.render_text()
        );
        assert!(
            !m.entries
                .iter()
                .any(|e| e.name == "build failed for target H-LIB"),
            "no redundant safety-net entry for a lib-only failure"
        );
    }

    #[test]
    fn codegen_only_failure_is_not_framed_as_a_missing_dependency() {
        // #5: a target whose only unresolved error is a harness/codegen error
        // ("no member named" / a bare `type` recovery artifact) must NOT appear in
        // the missing-dependency manifest with an acquire hint.
        use build_classifier::BuildErrorKind;
        let needed = NeededForBuild::default();
        let mut m = build_dependency_manifest(&needed, &PathBuf::from("/tmp"), "");
        let failed = vec![
            (
                "H-YAML".to_owned(),
                vec![BuildErrorKind::Other {
                    tail: "n.cpp:9:7: error: no member named 'as' in 'YAML::Node'".to_owned(),
                }],
            ),
            (
                "H-ADAURL".to_owned(),
                vec![BuildErrorKind::MissingType {
                    name: "type".to_owned(),
                }],
            ),
        ];
        record_failed_build_blockers(&mut m, &failed, &PathBuf::from("/tmp"));
        assert_eq!(
            manifest_reference_count(&m, "H-YAML"),
            0,
            "codegen-only failure must not be a dependency: {}",
            m.render_text()
        );
        assert_eq!(
            manifest_reference_count(&m, "H-ADAURL"),
            0,
            "recovery-artifact failure must not be a dependency: {}",
            m.render_text()
        );
        assert!(
            !m.entries.iter().any(|e| e.name == "type"),
            "the bare 'type' recovery artifact must not be a CType dep"
        );
    }

    #[test]
    fn uninitializable_param_reasons_collapse_by_type_not_target() {
        // Two different targets/params sharing one unconstructible type must
        // normalize to the SAME summary so the bug-report dedups them to one row.
        let a = "direct-call harness cannot initialize parameter 'Command' of \
                 target 'Proc_A' with type 'Sys.Bounded_9.Bounded_String': named type \
                 Sys.Bounded_9.Bounded_String is not declared in the parsed source set \
                 and has no synthesizable constructor. Add a public constructor.";
        let b = "direct-call harness cannot initialize parameter 'Arg' of \
                 target 'Proc_B' with type 'Sys.Bounded_9.Bounded_String': named type \
                 Sys.Bounded_9.Bounded_String is not declared in the parsed source set \
                 and has no synthesizable constructor. Add a public constructor.";
        let na = collapse_uninitializable_param_reason(a);
        assert_eq!(na, collapse_uninitializable_param_reason(b));
        assert!(na.starts_with("direct-call harness cannot initialize a parameter with type "));
        assert!(na.contains("Sys.Bounded_9.Bounded_String"));
        assert!(!na.contains("Proc_A") && !na.contains("'Command'"));
        // A different type stays a distinct row.
        let c = a.replace("Bounded_9", "Bounded_42");
        assert_ne!(na, collapse_uninitializable_param_reason(&c));
        // A reason not of this shape passes through unchanged.
        let other = "C++ parameter 'x' of type 'BOOL' has no byte-buffer decoder";
        assert_eq!(collapse_uninitializable_param_reason(other), other);
    }

    #[test]
    fn first_error_line_picks_first_nonempty_and_caps() {
        assert_eq!(
            first_error_line("\n\n  real error here \nmore"),
            "real error here"
        );
        assert_eq!(first_error_line(""), "unclassified build error");
        let long = "x".repeat(500);
        assert!(first_error_line(&long).ends_with('…'));
        assert!(first_error_line(&long).chars().count() <= 201);
        // A non-ASCII diagnostic (GCC/G++ quote with U+2018/U+2019) whose
        // multi-byte char straddles the 200-byte cap must truncate on a char
        // boundary, not panic. Pad with 198 ASCII bytes so the 2-byte 'é' spans
        // bytes 198-199 and the cut at 200 would otherwise split a later char.
        let unicode = format!("{}{}", "a".repeat(198), "é".repeat(50));
        let capped = first_error_line(&unicode); // must not panic
        assert!(capped.ends_with('…'));
    }

    #[test]
    fn configure_template_hint_names_in_tree_template() {
        let dir = std::env::temp_dir().join(format!(
            "bhf-tmpl-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("ares_build.h.in"), "/* template */\n").unwrap();
        let hint = configure_template_hint(&dir, "ares_build.h").expect("template found");
        assert!(hint.contains("ares_build.h.in"), "{hint}");
        assert!(hint.contains("configure"), "{hint}");
        // No template -> fall back to the per-kind default (None here).
        assert!(configure_template_hint(&dir, "totally_unrelated.h").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn debuginfod_cache_paths_are_non_blocking() {
        assert!(is_debuginfod_cache(
            "/home/user/.cache/llvm-debuginfod/client/abc123"
        ));
        assert!(is_debuginfod_cache(
            "/root/.cache/debuginfod_client/deadbeef"
        ));
        // A real missing build input is NOT a debuginfod cache file.
        assert!(!is_debuginfod_cache("/usr/include/zlib.h"));
        assert!(!is_debuginfod_cache("/tmp/proj/libfoo.so"));
    }

    #[test]
    fn classify_missing_path_distinguishes_network_share_and_symlink() {
        assert_eq!(
            classify_missing_path("//fileserver/share/x.h"),
            DepKind::NetworkShare
        );
        assert_eq!(
            classify_missing_path("/mnt/nfs/proj/lib.a"),
            DepKind::NetworkShare
        );
        assert_eq!(
            classify_missing_path("/net/host/inc/foo.h"),
            DepKind::NetworkShare
        );
        assert_eq!(
            classify_missing_path("/usr/include/missing.h"),
            DepKind::FilePath
        );

        // A real dangling symlink classifies as Symlink.
        let dir = std::env::temp_dir().join(format!(
            "bhf-symtest-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let link = dir.join("dangling.h");
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.join("nonexistent-target.h"), &link).unwrap();
        #[cfg(unix)]
        assert_eq!(
            classify_missing_path(link.to_str().unwrap()),
            DepKind::Symlink
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn required_gpr_externals_reports_only_no_default_vars() {
        let dir = std::env::temp_dir().join(format!(
            "bhf-gprext-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("p.gpr"),
            "project P is\n\
             \x20  Arch : T := external (\"ARCH\", \"generic\");\n\
             \x20  Root : String := external (\"ACE_ROOT\");\n\
             end P;\n",
        )
        .unwrap();
        let vars = required_gpr_externals(&dir);
        assert!(
            vars.contains(&"ACE_ROOT".to_owned()),
            "no-default external is needed: {vars:?}"
        );
        assert!(
            !vars.contains(&"ARCH".to_owned()),
            "defaulted external is not needed: {vars:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn cand(id: &str) -> Candidate {
        Candidate {
            harness_id: id.to_owned(),
            lang: Lang::C,
            source_path: PathBuf::from("/tmp/a.c"),
            line: 1,
            name: "f".to_owned(),
            score: 60,
            is_static: false,
            foreign_guard: None,
            input_reachability: None,
            dialect: None,
        }
    }

    /// CC-1: a fuzzed target's structured fidelity must land on both `run.json`
    /// (per-target + campaign rollup) and every one of that target's
    /// `finding.json` sidecars — a stubbed target's findings read as host-stub
    /// evidence (arch/RTOS/hardware `not_exercised` + a derived caveat), while a
    /// native target's carry no spurious caveat.
    #[test]
    fn fidelity_lands_on_run_json_and_each_finding_json() {
        use crate::auto::attempt::{AttemptResult, Outcome, PassRun};
        use crate::auto::pass::Pass;
        use crate::auto::repair::Repair;

        let work = std::env::temp_dir().join(format!(
            "bhf-report-fidelity-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(work.join("results").join("findings")).unwrap();

        // One finding from a host-stubbed VxWorks target, one from a plain native
        // target, each written to disk exactly as the cascade would.
        let write_finding = |id: &str, harness: &str| {
            let dir = work.join("results").join("findings").join(id);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("finding.json"),
                serde_json::to_vec(&serde_json::json!({
                    "id": id,
                    "harness_id": harness,
                    "rule_id": "BHF-210",
                    "classification": "runtime_crash",
                }))
                .unwrap(),
            )
            .unwrap();
        };
        write_finding("F-0000-stub", "H-STUB-VX");
        write_finding("F-0001-native", "H-NATIVE");

        let built = |harness: &str, finding: &str, repairs: Vec<Repair>| {
            let mut c = cand(harness);
            c.name = harness.to_owned();
            AttemptResult {
                candidate: c,
                outcome: Outcome::BuiltAndFuzzed {
                    repairs,
                    retries: 0,
                    per_pass_budget_secs: 60,
                    total_wall_budget_secs: 60,
                    executions_per_sec: 9.0,
                    passes: vec![PassRun {
                        pass: Pass::Empty,
                        engine: "builtin".to_owned(),
                        executions: 9,
                        target_entry_observed: true,
                        coverage_edges: 80,
                        elapsed_secs: 1.0,
                        executions_per_sec: 9.0,
                        findings: vec![finding.to_owned()],
                    }],
                    runtrace_events: vec![],
                },
                harness_dir: work.join("harnesses").join(harness),
            }
        };

        let results = vec![
            built(
                "H-STUB-VX",
                "F-0000-stub",
                vec![Repair::PlatformStub {
                    platform: "vxworks".to_owned(),
                }],
            ),
            built("H-NATIVE", "F-0001-native", vec![]),
        ];

        write_reports(
            std::path::Path::new("/tmp"),
            &results,
            &work,
            "T0",
            "T1",
            false,
            actionability::RunMode::Reporting,
            0,
            0,
            false,
            false,
            false,
        )
        .unwrap();

        // --- per-finding blocks on disk ---
        let read_finding = |id: &str| -> serde_json::Value {
            serde_json::from_slice(
                &std::fs::read(
                    work.join("results")
                        .join("findings")
                        .join(id)
                        .join("finding.json"),
                )
                .unwrap(),
            )
            .unwrap()
        };
        let stub = read_finding("F-0000-stub");
        assert_eq!(
            stub["fidelity"]["arch"]["status"], "not_exercised",
            "stub finding arch must be not_exercised: {stub}"
        );
        assert_eq!(stub["fidelity"]["rtos_runtime"]["status"], "not_exercised");
        assert_eq!(
            stub["fidelity"]["hardware_peripherals"]["status"],
            "not_exercised"
        );
        assert!(
            stub["fidelity_caveat"]
                .as_str()
                .unwrap_or_default()
                .contains("not target assurance"),
            "stub finding must carry a derived caveat: {stub}"
        );

        let native = read_finding("F-0001-native");
        assert_eq!(
            native["fidelity"]["arch"]["status"], "exercised",
            "native finding arch must be exercised: {native}"
        );
        assert_eq!(
            native["fidelity"]["rtos_runtime"]["status"],
            "not_applicable"
        );
        assert!(
            native.get("fidelity_caveat").is_none(),
            "native finding must NOT carry a spurious caveat: {native}"
        );

        // --- campaign rollup on run.json ---
        let run: serde_json::Value =
            serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
        let sf = &run["summary"]["fidelity"];
        assert_eq!(sf["reduced_fidelity_targets"], 1, "run={run}");
        assert_eq!(sf["stubbed_platforms"], serde_json::json!(["vxworks"]));
        assert_eq!(sf["dimensions"]["arch"]["status"], "not_exercised");
        assert!(sf["caveat"].as_str().unwrap_or_default().contains("arch"));

        std::fs::remove_dir_all(&work).ok();
    }

    /// Regression: a finding a post-pass DELETED from disk (COBOL crash
    /// attribution dropping a harness-artifact crash) must also leave the
    /// in-memory pass record, so the headline count, run.json and the results/
    /// index all agree with the evidence on disk. Before the reconcile the two
    /// COBOL targets read `findings: 1` while their index / `findings/` held nothing.
    #[test]
    fn phantom_finding_removed_by_post_pass_is_reconciled_out_of_count() {
        use crate::auto::attempt::{AttemptResult, Outcome, PassRun};
        use crate::auto::pass::Pass;

        let work = std::env::temp_dir().join(format!(
            "bhf-report-phantom-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(work.join("results").join("findings")).unwrap();

        // The empty pass emitted two crashes; attribution proved F-0000-dead a
        // harness artifact and removed its dir, leaving only F-0001-live on disk.
        let survivor = "F-0001-live";
        let phantom = "F-0000-dead";
        let survivor_dir = work.join("results").join("findings").join(survivor);
        std::fs::create_dir_all(&survivor_dir).unwrap();
        std::fs::write(
            survivor_dir.join("finding.json"),
            serde_json::to_vec(&serde_json::json!({
                "id": survivor,
                "harness_id": "H-B0014",
                "rule_id": "BHF-210",
                "classification": "runtime_crash",
            }))
            .unwrap(),
        )
        .unwrap();

        let outcome = Outcome::BuiltAndFuzzed {
            repairs: vec![],
            retries: 0,
            per_pass_budget_secs: 60,
            total_wall_budget_secs: 60,
            executions_per_sec: 9.0,
            passes: vec![PassRun {
                pass: Pass::Empty,
                engine: "builtin".to_owned(),
                executions: 9,
                target_entry_observed: true,
                coverage_edges: 80,
                elapsed_secs: 1.0,
                executions_per_sec: 9.0,
                // Order matters: the phantom precedes the survivor.
                findings: vec![phantom.to_owned(), survivor.to_owned()],
            }],
            runtrace_events: vec![],
        };
        let mut results = vec![AttemptResult {
            candidate: cand("H-B0014"),
            outcome,
            harness_dir: work.join("harnesses/H-B0014"),
        }];

        let dropped = reconcile_pass_findings_with_disk(&mut results, &work);
        assert_eq!(dropped, 1, "exactly the phantom id should be dropped");

        write_reports(
            std::path::Path::new("/tmp"),
            &results,
            &work,
            "T0",
            "T1",
            false,
            actionability::RunMode::Reporting,
            0,
            0,
            false,
            false,
            false,
        )
        .unwrap();

        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
        // Headline count now equals the single on-disk evidence bundle.
        assert_eq!(json["summary"]["findings"], 1, "{json}");
        // run.json's pass no longer serializes the phantom id.
        assert_eq!(
            json["targets"][0]["outcome"]["passes"][0]["findings"],
            serde_json::json!([survivor]),
            "{json}"
        );
        // The results/ index carries exactly the one surviving finding — count and
        // evidence agree, the invariant the COBOL reconciliation gate requires.
        let doc = rebuild_results(&work);
        let ids: Vec<&str> = doc["findings"]
            .as_array()
            .expect("findings array")
            .iter()
            .filter_map(|f| f["id"].as_str())
            .collect();
        assert_eq!(ids, vec![survivor], "{doc}");

        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn dependency_checkpoint_survives_before_final_report_and_is_atomic() {
        let work = std::env::temp_dir().join(format!(
            "bhf-dep-checkpoint-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let source = work.join("src");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("generated.h.in"), "#define X 1\n").unwrap();

        let mut seed = crate::auto::dep_manifest::DependencyManifest::new();
        seed.push(
            DepKind::Toolchain,
            "missing-cc",
            vec!["preflight: C".to_owned()],
            false,
        );
        let mut durable = write_dependency_checkpoint(&source, &work, &seed, &[]).unwrap();
        let initial = load_dependency_manifest(&work).expect("initial checkpoint");
        assert_eq!(initial.completed_targets, 0);
        assert!(!initial.complete);

        let result = AttemptResult {
            candidate: cand("H-C-CHECKPOINT"),
            outcome: Outcome::Built {
                repairs: vec![Repair::HeaderPlaceholder {
                    virtual_path: "generated.h".to_owned(),
                }],
                retries: 1,
            },
            harness_dir: work.join("harnesses/H-C-CHECKPOINT"),
        };
        checkpoint_dependency_result(&source, &work, &mut durable, &result).unwrap();
        let checkpoint = load_dependency_manifest(&work).expect("target checkpoint");
        assert_eq!(checkpoint.completed_targets, 1);
        assert!(
            !checkpoint.complete,
            "only final reporting marks it complete"
        );
        assert!(checkpoint.has(DepKind::Toolchain, "missing-cc"));
        assert!(checkpoint.has(DepKind::GeneratedSource, "generated.h"));
        let text = std::fs::read_to_string(work.join("auto/missing-deps.txt")).unwrap();
        assert!(text.contains("run still in progress"), "{text}");
        assert!(text.contains("Required toolchains"), "{text}");

        finalize_dependency_checkpoint(&work, &mut durable).unwrap();
        let final_checkpoint = load_dependency_manifest(&work).expect("final checkpoint");
        assert!(final_checkpoint.complete);
        assert_eq!(final_checkpoint.completed_targets, 1);
        let final_text = std::fs::read_to_string(work.join("auto/missing-deps.txt")).unwrap();
        assert!(final_text.contains("final."), "{final_text}");
        assert!(
            !final_text.contains("run still in progress"),
            "{final_text}"
        );
        assert!(std::fs::read_dir(work.join("auto"))
            .unwrap()
            .flatten()
            .all(|entry| !entry.file_name().to_string_lossy().contains(".tmp-")));
        let _ = std::fs::remove_dir_all(work);
    }

    #[test]
    fn atomic_write_preserves_another_live_writers_temporary() {
        let dir = std::env::temp_dir().join(format!(
            "bhf-atomic-writer-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let destination = dir.join("missing-deps.txt");
        let live_temp = dir.join(format!(
            ".missing-deps.txt.tmp-{}-999999",
            std::process::id()
        ));
        std::fs::write(&live_temp, b"other writer").unwrap();

        atomic_write(&destination, b"checkpoint").unwrap();

        assert_eq!(std::fs::read(&destination).unwrap(), b"checkpoint");
        assert_eq!(std::fs::read(&live_temp).unwrap(), b"other writer");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn resume_result_round_trips_full_outcome_for_reintegration() {
        let work = std::env::temp_dir().join(format!(
            "bhf-resume-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&work).unwrap();

        // Before any attempt: not complete, nothing to reload.
        assert!(!target_already_complete(&work, "H-C0009"));
        assert!(load_resumed_result(&work, "H-C0009").is_none());

        // Persist a full result (with repairs + reachability, so the round-trip
        // carries the detail the report aggregates — not just an outcome tag).
        let result = AttemptResult {
            candidate: Candidate {
                input_reachability: Some(target_rank::InputReachability::AttackerReachable),
                ..cand("H-C0009")
            },
            outcome: Outcome::FailedBuild {
                repairs: vec![Repair::StubBlind {
                    symbol: "foo".into(),
                }],
                retries: 2,
                last_errors: vec![],
            },
            harness_dir: PathBuf::from("/work/harnesses/H-C0009"),
        };
        persist_target_result(&work, &result, false);
        assert!(target_already_complete(&work, "H-C0009"));
        let persisted: serde_json::Value = serde_json::from_slice(
            &std::fs::read(work.join("harnesses/H-C0009/result.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(persisted["attempt_trace"]["terminal_stage"], "build");
        assert_eq!(persisted["attempt_trace"]["repairs_attempted"], true);
        assert_eq!(persisted["attempt_trace"]["repair_count"], 1);

        // Reload reconstructs a real AttemptResult, full fidelity.
        let (back, back_forced) = load_resumed_result(&work, "H-C0009").expect("reload");
        assert!(!back_forced, "this attempt was not forced");
        assert_eq!(back.candidate.harness_id, "H-C0009");
        assert_eq!(back.candidate.lang, Lang::C);
        assert_eq!(
            back.candidate.input_reachability,
            Some(target_rank::InputReachability::AttackerReachable)
        );
        match back.outcome {
            Outcome::FailedBuild {
                retries, repairs, ..
            } => {
                assert_eq!(retries, 2);
                assert_eq!(repairs.len(), 1);
            }
            other => panic!("outcome not round-tripped: {other:?}"),
        }

        // Unrelated target unaffected; a corrupt file reads as not-complete.
        assert!(!target_already_complete(&work, "H-C0010"));
        std::fs::write(work.join("harnesses/H-C0009/result.json"), b"{ not json").unwrap();
        assert!(!target_already_complete(&work, "H-C0009"));

        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn aggregates_repairs_across_targets() {
        let r1 = AttemptResult {
            candidate: cand("H-C0001"),
            outcome: Outcome::Built {
                repairs: vec![
                    Repair::HeaderPlaceholder {
                        virtual_path: "x.h".into(),
                    },
                    Repair::StubBlind {
                        symbol: "foo".into(),
                    },
                ],
                retries: 1,
            },
            harness_dir: PathBuf::from("/tmp"),
        };
        let r2 = AttemptResult {
            candidate: cand("H-C0002"),
            outcome: Outcome::Built {
                repairs: vec![Repair::HeaderPlaceholder {
                    virtual_path: "x.h".into(),
                }],
                retries: 1,
            },
            harness_dir: PathBuf::from("/tmp"),
        };
        let work = std::env::temp_dir().join(format!(
            "bhf-report-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&work).unwrap();
        write_reports(
            std::path::Path::new("/tmp"),
            &[r1, r2],
            &work,
            "T0",
            "T1",
            false,
            actionability::RunMode::Reporting,
            0,
            0,
            false,
            false,
            false,
        )
        .unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
        let headers = &json["needed_for_build"]["synthesized_headers"];
        assert_eq!(headers[0]["name"], "x.h");
        assert_eq!(
            headers[0]["referenced_by_targets"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(json["summary"]["built"], 2);
    }

    #[test]
    fn capped_run_reports_discovered_total_and_dropped_by_cap() {
        // #6: a --max-targets / campaign cap drops lower-ranked targets from the
        // sweep. The report must surface the pre-cap total and the dropped delta
        // instead of silently reporting only the swept count.
        let r1 = AttemptResult {
            candidate: cand("H-C0001"),
            outcome: Outcome::Built {
                repairs: vec![],
                retries: 0,
            },
            harness_dir: PathBuf::from("/tmp"),
        };
        let r2 = AttemptResult {
            candidate: cand("H-C0002"),
            outcome: Outcome::Built {
                repairs: vec![],
                retries: 0,
            },
            harness_dir: PathBuf::from("/tmp"),
        };
        let work = std::env::temp_dir().join(format!(
            "bhf-report-cap-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&work).unwrap();
        // 5 ranked discovered, only 2 swept.
        write_reports(
            std::path::Path::new("/tmp"),
            &[r1, r2],
            &work,
            "T0",
            "T1",
            false,
            actionability::RunMode::Reporting,
            0,
            5,
            false,
            false,
            false,
        )
        .unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
        assert_eq!(json["summary"]["discovered"], 2);
        assert_eq!(json["summary"]["discovered_total"], 5);
        assert_eq!(json["summary"]["dropped_by_cap"], 3);
        assert!(
            json["summary"]["discovered_total"].as_u64().unwrap()
                > json["summary"]["discovered"].as_u64().unwrap()
        );
        let md = std::fs::read_to_string(work.join("auto/run.md")).unwrap();
        assert!(md.contains("dropped by --max-targets"), "{md}");
        // An uncapped, un-stopped run must not carry the operator flag at all.
        assert!(json["summary"].get("stopped_by_operator").is_none());
        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn an_operator_stopped_run_does_not_blame_a_cap_for_the_shortfall() {
        // Pressing `q` leaves exactly the shortfall a cap would. Reporting it as
        // "dropped by cap" would tell a reader weeks later that flags they never
        // passed truncated the sweep.
        let r1 = AttemptResult {
            candidate: cand("H-C0001"),
            outcome: Outcome::Built {
                repairs: vec![],
                retries: 0,
            },
            harness_dir: PathBuf::from("/h"),
        };
        let work = std::env::temp_dir().join(format!(
            "bhf-report-operator-stop-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        write_reports(
            Path::new("/src"),
            std::slice::from_ref(&r1),
            &work,
            "T0",
            "T1",
            false,
            actionability::RunMode::Reporting,
            0,
            4,
            false,
            false,
            true,
        )
        .unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
        assert_eq!(json["summary"]["dropped_by_cap"], 3);
        assert_eq!(json["summary"]["stopped_by_operator"], true);
        let md = std::fs::read_to_string(work.join("auto/run.md")).unwrap();
        assert!(
            md.contains("3 not attempted — the operator stopped the run"),
            "{md}"
        );
        assert!(!md.contains("dropped by --max-targets"), "{md}");
        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn output_ceiling_is_durable_and_names_the_right_stop_reason() {
        let result = AttemptResult {
            candidate: cand("H-C0001"),
            outcome: Outcome::Built {
                repairs: vec![],
                retries: 0,
            },
            harness_dir: PathBuf::from("/h"),
        };
        let work = std::env::temp_dir().join(format!(
            "bhf-report-output-cap-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        write_reports_with_output_limit(
            Path::new("/src"),
            std::slice::from_ref(&result),
            &work,
            "T0",
            "T1",
            false,
            actionability::RunMode::Reporting,
            0,
            4,
            false,
            false,
            false,
            true,
            &SanitizerSelection::Default,
        )
        .unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
        assert_eq!(json["summary"]["output_limit_reached"], true);
        assert_eq!(json["summary"]["dropped_by_cap"], 3);
        let md = std::fs::read_to_string(work.join("auto/run.md")).unwrap();
        assert!(
            md.contains("3 not attempted — --max-work-dir-mb reached"),
            "{md}"
        );
        assert!(!md.contains("dropped by --max-targets"), "{md}");
        let _ = std::fs::remove_dir_all(&work);
    }

    #[test]
    fn missing_ada_symbol_with_empty_unit_is_dropped() {
        // GNAT occasionally emits the symbol with no enclosing unit
        // context (regex captured "Harness" alone). The aggregator
        // used to join those as `.Harness` — useless to the upstream
        // maintainer. Today they're dropped; real `Pkg.Foo` rows
        // still land in the bag.
        let r1 = AttemptResult {
            candidate: cand("H-A0001"),
            outcome: Outcome::FailedBuild {
                repairs: vec![],
                retries: 0,
                last_errors: vec![
                    build_classifier::BuildErrorKind::MissingAdaSymbol {
                        unit: String::new(),
                        symbol: "Harness".into(),
                    },
                    build_classifier::BuildErrorKind::MissingAdaSymbol {
                        unit: "Aux_Pkg".into(),
                        symbol: "Frob".into(),
                    },
                ],
            },
            harness_dir: PathBuf::from("/tmp"),
        };
        let work = std::env::temp_dir().join(format!(
            "bhf-report-ada-bare-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&work).unwrap();
        write_reports(
            std::path::Path::new("/tmp"),
            std::slice::from_ref(&r1),
            &work,
            "T0",
            "T1",
            false,
            actionability::RunMode::Reporting,
            0,
            0,
            false,
            false,
            false,
        )
        .unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
        let units = json["needed_for_build"]["missing_ada_units"]
            .as_array()
            .unwrap();
        let names: Vec<&str> = units.iter().filter_map(|u| u["name"].as_str()).collect();
        assert!(
            !names.iter().any(|n| n.starts_with('.')),
            "leading-dot entries should be filtered: {names:?}"
        );
        assert!(
            names.contains(&"Aux_Pkg.Frob"),
            "qualified entries should still surface: {names:?}"
        );
    }

    #[test]
    #[cfg(not(windows))]
    fn win32_type_placeholders_are_hidden_from_synthesized_types_on_linux() {
        // The miniz fixture references WCHAR inside a #ifdef _WIN32
        // block. On non-Windows hosts we still synthesise the typedef
        // so the preprocessor branch parses, but the report row is
        // noise — a Linux maintainer shouldn't be asked to ship WCHAR.
        let r1 = AttemptResult {
            candidate: cand("H-C0001"),
            outcome: Outcome::Built {
                repairs: vec![
                    Repair::TypePlaceholder {
                        type_name: "WCHAR".into(),
                    },
                    Repair::TypePlaceholder {
                        type_name: "my_widget_t".into(),
                    },
                ],
                retries: 1,
            },
            harness_dir: PathBuf::from("/tmp"),
        };
        let work = std::env::temp_dir().join(format!(
            "bhf-report-win32-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&work).unwrap();
        write_reports(
            std::path::Path::new("/tmp"),
            std::slice::from_ref(&r1),
            &work,
            "T0",
            "T1",
            false,
            actionability::RunMode::Reporting,
            0,
            0,
            false,
            false,
            false,
        )
        .unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
        let types = json["needed_for_build"]["synthesized_types"]
            .as_array()
            .unwrap();
        let names: Vec<&str> = types.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(
            !names.contains(&"WCHAR"),
            "WCHAR should be filtered on non-Windows hosts: {names:?}"
        );
        assert!(
            names.contains(&"my_widget_t"),
            "real placeholder should still surface: {names:?}"
        );
    }

    #[test]
    fn aggregates_ada_stub_repairs_separately_from_missing_ada_units() {
        let r1 = AttemptResult {
            candidate: cand("H-A0002"),
            outcome: Outcome::Built {
                repairs: vec![
                    Repair::AdaPackageStub {
                        unit: "Aux_Pkg".into(),
                        decls: vec!["Score".into()],
                        ops: Vec::new(),
                        synthesize_body: true,
                        provenance: "test".into(),
                    },
                    Repair::AdaPackageBodyStub {
                        unit: "Aux_Pkg".into(),
                        ops: vec![stub_gen::StubOp {
                            name: "Score".into(),
                            kind: stub_gen::StubOpKind::Function,
                            return_type: Some("Integer".into()),
                            params: Vec::new(),
                        }],
                        provenance: "test".into(),
                    },
                ],
                retries: 1,
            },
            harness_dir: PathBuf::from("/tmp"),
        };
        let work = std::env::temp_dir().join(format!(
            "bhf-report-ada-stubs-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&work).unwrap();
        write_reports(
            std::path::Path::new("/tmp"),
            std::slice::from_ref(&r1),
            &work,
            "T0",
            "T1",
            false,
            actionability::RunMode::Reporting,
            0,
            0,
            false,
            false,
            false,
        )
        .unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
        let units = json["needed_for_build"]["stubbed_ada_units"]
            .as_array()
            .expect("stubbed_ada_units should be an array");
        let symbols = json["needed_for_build"]["stubbed_ada_symbols"]
            .as_array()
            .expect("stubbed_ada_symbols should be an array");
        assert_eq!(units[0]["name"], "Aux_Pkg");
        assert_eq!(symbols[0]["name"], "Aux_Pkg.Score");
        assert!(
            json["needed_for_build"]["missing_ada_units"]
                .as_array()
                .unwrap()
                .is_empty(),
            "repaired Ada stubs should not also surface as missing units"
        );
    }

    #[test]
    fn aggregates_runtrace_events_across_targets() {
        use crate::auto::runtrace::RuntraceEvent;
        let mut env = BTreeMap::new();
        let mut files = BTreeMap::new();
        let mut endpoints = BTreeMap::new();
        let mut dlopen = BTreeMap::new();
        aggregate_runtrace(
            &[
                RuntraceEvent::EnvVarMissing {
                    api: "getenv".to_owned(),
                    name: "ACME".to_owned(),
                },
                RuntraceEvent::EnvVarMissing {
                    api: "getenv".to_owned(),
                    name: "ACME".to_owned(),
                },
                RuntraceEvent::FileMissing {
                    syscall: "open".to_owned(),
                    path: "/etc/x.conf".to_owned(),
                    taint_offset: None,
                },
            ],
            "H-C0001",
            &mut env,
            &mut files,
            &mut endpoints,
            &mut dlopen,
        );
        aggregate_runtrace(
            &[RuntraceEvent::EnvVarMissing {
                api: "getenv".to_owned(),
                name: "ACME".to_owned(),
            }],
            "H-C0002",
            &mut env,
            &mut files,
            &mut endpoints,
            &mut dlopen,
        );
        assert_eq!(
            env.get("ACME").unwrap(),
            &vec!["H-C0001".to_owned(), "H-C0002".to_owned()]
        );
        assert_eq!(files.get("/etc/x.conf").unwrap().len(), 1);
    }

    #[test]
    fn markdown_renders_runtime_resources_section_when_layer_c_non_empty() {
        let needed = NeededForBuild {
            environment_variables_faked: vec![Aggregated {
                name: "ACME_CONFIG".to_owned(),
                referenced_by_targets: vec!["H-C0001".to_owned()],
            }],
            ..NeededForBuild::default()
        };
        let r = RunJson {
            schema_version: 1,
            started_at: "T0".to_owned(),
            finished_at: "T1".to_owned(),
            partial: false,
            mode: actionability::RunMode::Reporting,
            source_root: std::path::Path::new("/x"),
            summary: Summary::default(),
            needed_for_build: needed,
            targets: vec![],
        };
        let md = render_md(&r);
        assert!(md.contains("## Upstream delta"), "md: {md}");
        assert!(
            md.contains("### Runtime resources observed during fuzzing"),
            "md: {md}"
        );
        assert!(
            md.contains("Environment variables (auto-injected)"),
            "md: {md}"
        );
        assert!(md.contains("ACME_CONFIG"), "md: {md}");
    }

    #[test]
    fn markdown_skips_runtime_resources_when_layer_c_empty() {
        let r = RunJson {
            schema_version: 1,
            started_at: "T0".to_owned(),
            finished_at: "T1".to_owned(),
            partial: false,
            mode: actionability::RunMode::Reporting,
            source_root: std::path::Path::new("/x"),
            summary: Summary::default(),
            needed_for_build: NeededForBuild::default(),
            targets: vec![],
        };
        let md = render_md(&r);
        assert!(
            !md.contains("Runtime resources observed during fuzzing"),
            "md: {md}"
        );
        assert!(!md.contains("## Upstream delta"), "md: {md}");
    }

    #[test]
    fn target_entry_renders_passes_array() {
        use crate::auto::attempt::PassRun;
        use crate::auto::pass::Pass;
        // #405: per-pass elapsed/throughput chosen so each rate is exact
        // (executions / elapsed_secs lands on a round number) — empty 1000/s,
        // rng 2000/s, fuzz_driven 500/s — keeping the run.md assertion stable.
        let passes = vec![
            PassRun {
                pass: Pass::Empty,
                engine: "builtin".to_owned(),
                executions: 4123,
                target_entry_observed: false,
                coverage_edges: 180,
                elapsed_secs: 4.123,
                executions_per_sec: 1000.0,
                findings: vec![],
            },
            PassRun {
                pass: Pass::Rng,
                engine: "builtin".to_owned(),
                executions: 3811,
                target_entry_observed: false,
                coverage_edges: 240,
                elapsed_secs: 1.9055,
                executions_per_sec: 2000.0,
                findings: vec!["F-0001".to_owned()],
            },
            PassRun {
                pass: Pass::FuzzDriven,
                engine: "builtin".to_owned(),
                executions: 2901,
                target_entry_observed: false,
                coverage_edges: 252,
                elapsed_secs: 5.802,
                executions_per_sec: 500.0,
                findings: vec!["F-0002".to_owned(), "F-0003".to_owned()],
            },
        ];
        let executions_per_sec = crate::auto::attempt::aggregate_executions_per_sec(&passes);
        let result = AttemptResult {
            candidate: cand("H-C0042"),
            outcome: Outcome::BuiltAndFuzzed {
                repairs: vec![],
                retries: 0,
                per_pass_budget_secs: 60,
                total_wall_budget_secs: 180,
                passes,
                executions_per_sec,
                runtrace_events: vec![],
            },
            harness_dir: PathBuf::from("/tmp"),
        };
        let work = std::env::temp_dir().join(format!(
            "bhf-report-passes-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&work).unwrap();
        write_reports(
            std::path::Path::new("/tmp"),
            std::slice::from_ref(&result),
            &work,
            "T0",
            "T1",
            false,
            actionability::RunMode::Reporting,
            0,
            0,
            false,
            false,
            false,
        )
        .unwrap();

        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
        let target = &json["targets"][0];
        assert_eq!(target["harness_id"], "H-C0042");
        let passes = target["outcome"]["passes"]
            .as_array()
            .expect("passes array");
        let names: Vec<&str> = passes.iter().filter_map(|p| p["pass"].as_str()).collect();
        assert_eq!(names, vec!["empty", "rng", "fuzz_driven"]);
        assert_eq!(passes[0]["executions"], 4123);
        assert_eq!(passes[1]["findings"][0], "F-0001");
        assert_eq!(passes[2]["findings"].as_array().unwrap().len(), 2);

        // #405: per-pass throughput surfaces in run.json (additive — the
        // existing `executions` field above is unchanged).
        assert_eq!(passes[0]["executions_per_sec"], 1000.0);
        assert_eq!(passes[1]["executions_per_sec"], 2000.0);
        assert_eq!(passes[0]["elapsed_secs"], 4.123);
        // ...and the target-level aggregate (Σexecs / Σelapsed, time-weighted).
        let agg = target["outcome"]["executions_per_sec"].as_f64().unwrap();
        let expect_agg = (4123.0 + 3811.0 + 2901.0) / (4.123 + 1.9055 + 5.802);
        assert!(
            (agg - expect_agg).abs() < 1e-6,
            "aggregate exec/s {agg} != {expect_agg}"
        );

        // Summary totals = sum across passes.
        assert_eq!(json["summary"]["findings"], 3);
        assert_eq!(json["summary"]["built_and_fuzzed"], 1);

        // run.md surfaces a per-target row with one segment per pass, now
        // including the measured exec/s (#405).
        let md = std::fs::read_to_string(work.join("auto/run.md")).unwrap();
        assert!(md.contains("## Targets"), "md: {md}");
        assert!(
            md.contains(
                "empty=4123execs/1000exec_s/0f rng=3811execs/2000exec_s/1f \
                 fuzz_driven=2901execs/500exec_s/2f"
            ),
            "md: {md}"
        );
    }

    /// The per-target stub accounting must carry the real counts. A crash reached
    /// through fabricated values is a different claim from a crash in real library
    /// code. `stub_blind` is the one that matters most — an invented body with no
    /// declaration behind it is the most likely to manufacture a crash.
    #[test]
    fn stub_execution_summary_counts_blind_declared_and_real_symbols() {
        use crate::auto::attempt::stub_execution_summary;
        use crate::auto::repair::Repair;

        // Two blind stubs, one declared stub, one real linked source.
        let repairs = vec![
            Repair::StubBlind {
                symbol: "vendor_open".to_owned(),
            },
            Repair::StubBlind {
                symbol: "vendor_close".to_owned(),
            },
            Repair::StubDeclared {
                symbol: "parse_header".to_owned(),
                return_type: "int".to_owned(),
                provenance: "declared in tree".to_owned(),
            },
            Repair::AddSource {
                symbol: "util_helper".to_owned(),
                source_path: std::path::PathBuf::from("/proj/util.c"),
            },
        ];
        let stub = stub_execution_summary(&repairs);
        assert_eq!(stub.blind_stubbed_symbols, 2, "two invented bodies");
        assert_eq!(stub.declared_stubbed_symbols, 1);
        assert_eq!(stub.real_linked_symbols, 1);
        assert_eq!(stub.resolved_called_symbols, 4, "the denominator");
    }

    /// The legacy work-dir indexes are retired: `results/` (rebuilt by the
    /// command's results bracket) is the only findings index.
    #[test]
    fn write_reports_writes_no_legacy_findings_index() {
        let work = std::env::temp_dir().join(format!(
            "bhf-report-no-legacy-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&work).unwrap();
        write_reports(
            std::path::Path::new("/tmp"),
            &[],
            &work,
            "T0",
            "T1",
            false,
            actionability::RunMode::Reporting,
            0,
            0,
            false,
            false,
            false,
        )
        .unwrap();
        assert!(work.join("auto/run.json").is_file());
        for legacy in [
            "FINDINGS.md",
            "findings.csv",
            "auto/findings.csv",
            "auto/attestation.json",
        ] {
            assert!(!work.join(legacy).exists(), "{legacy} must not be written");
        }
        let md = std::fs::read_to_string(work.join("auto/run.md")).unwrap();
        assert!(md.contains("No findings were emitted"), "{md}");
        std::fs::remove_dir_all(&work).ok();
    }

    /// #484: a `--static` finding that the fuzz-confirmation join upgraded to
    /// `fuzz_confirmed` on disk must count in the run.json `fuzz_confirmed`
    /// summary and index as `static_confirmed` in results/findings.json. A
    /// sibling static finding with no runtime match stays `static`.
    #[test]
    fn write_reports_surfaces_fuzz_confirmed_static_finding() {
        let work = std::env::temp_dir().join(format!(
            "bhf-report-confirm-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        // A confirmed static finding (as the join would have rewritten it) and a
        // plain static finding, both written straight to the findings dir the way
        // `emit_tree_static_findings` does (picked up via `disk_only_finding_ids`).
        let confirmed = serde_json::json!({
            "id": "F-STATIC-0000",
            "rule_id": "BHF-420",
            "classification": "static_scan",
            "confirmation": "fuzz_confirmed",
            "confirmed_by": ["F-0000-abcd"],
            "harness_id": "static-scan",
            "target": { "name": "cmd.c", "source_path": "/p/cmd.c", "line": 8,
                        "location": { "path": "/p/cmd.c", "line": 8 } },
            "oracle": { "evidence": [ { "key": "source", "value": "/p/cmd.c:8" } ] },
            "exception": { "message": "code injection" },
            "actionability": { "mode": "reporting", "verdict": "likely_reachable",
                               "impact": "high", "confidence": "high",
                               "prosthetics": { "used": false }, "cwe": ["CWE-94"] },
        });
        let plain = serde_json::json!({
            "id": "F-STATIC-0001",
            "rule_id": "BHF-420",
            "classification": "static_scan",
            "confirmation": "static",
            "harness_id": "static-scan",
            "target": { "name": "util.c", "source_path": "/p/util.c", "line": 3,
                        "location": { "path": "/p/util.c", "line": 3 } },
            "oracle": { "evidence": [ { "key": "source", "value": "/p/util.c:3" } ] },
            "exception": { "message": "code injection" },
            "actionability": { "cwe": ["CWE-94"], "verdict": "static_only", "confidence": "medium" },
        });
        for f in [&confirmed, &plain] {
            let id = f["id"].as_str().unwrap();
            let dir = work.join("results").join("findings").join(id);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("finding.json"),
                serde_json::to_vec_pretty(f).unwrap(),
            )
            .unwrap();
        }

        write_reports(
            std::path::Path::new("/p"),
            &[],
            &work,
            "T0",
            "T1",
            false,
            actionability::RunMode::Reporting,
            0,
            0,
            false,
            false,
            false,
        )
        .unwrap();

        let doc = rebuild_results(&work);
        let level = |id: &str| -> String {
            doc["findings"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|f| f["id"] == id)
                .and_then(|f| f["confirmation"]["level"].as_str())
                .unwrap_or_default()
                .to_owned()
        };
        assert_eq!(level("F-STATIC-0000"), "static_confirmed", "{doc}");
        assert_eq!(level("F-STATIC-0001"), "static", "{doc}");

        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(work.join("auto/run.json")).unwrap())
                .unwrap();
        assert_eq!(json["summary"]["fuzz_confirmed"], 1);
        assert_eq!(json["summary"]["findings"], 2);

        std::fs::remove_dir_all(&work).ok();
    }

    /// #417 regression — the FALSE-CLEAN bug. A harness whose every external
    /// called symbol was satisfied by a *blind* stub (an invented empty body),
    /// with no real dependency source linked, must NOT be reported as a plain
    /// clean `built_and_fuzzed`: run.json must carry a `stub_execution` field
    /// flagging `stub_only`, the summary must count it under `fuzzed_stub_only`,
    /// and run.md must surface a STUB-ONLY warning. Otherwise a 0-finding result
    /// over millions of executions of empty stubs reads as "library is clean".
    #[test]
    fn stub_only_run_is_flagged_not_reported_as_plain_clean() {
        use crate::auto::attempt::{Outcome, PassRun};
        use crate::auto::pass::Pass;
        use crate::auto::repair::Repair;

        // libyaml-shaped: every entry point the harness calls is blind-stubbed,
        // zero findings over ~8M execs, harness-only coverage.
        let blind_all = Outcome::BuiltAndFuzzed {
            repairs: vec![
                Repair::StubBlind {
                    symbol: "yaml_parser_initialize".to_owned(),
                },
                Repair::StubBlind {
                    symbol: "yaml_parser_set_input_string".to_owned(),
                },
                Repair::StubBlind {
                    symbol: "yaml_parser_parse".to_owned(),
                },
                Repair::StubBlind {
                    symbol: "yaml_parser_delete".to_owned(),
                },
            ],
            retries: 2,
            per_pass_budget_secs: 60,
            total_wall_budget_secs: 180,
            executions_per_sec: 800_000.0,
            passes: vec![PassRun {
                pass: Pass::FuzzDriven,
                engine: "builtin".to_owned(),
                executions: 8_000_000,
                target_entry_observed: false,
                coverage_edges: 16,
                elapsed_secs: 10.0,
                executions_per_sec: 800_000.0,
                findings: vec![],
            }],
            runtrace_events: vec![],
        };
        // Contrast: a genuine fuzz that linked real dependency source. Even with
        // one blind-stubbed leaf helper it is NOT stub-only — real code ran.
        let real_linked = Outcome::BuiltAndFuzzed {
            repairs: vec![
                Repair::AddSource {
                    symbol: "real_decode".to_owned(),
                    source_path: PathBuf::from("/s/decode.c"),
                },
                Repair::StubBlind {
                    symbol: "leaf_helper".to_owned(),
                },
            ],
            retries: 1,
            per_pass_budget_secs: 60,
            total_wall_budget_secs: 180,
            executions_per_sec: 1000.0,
            passes: vec![PassRun {
                pass: Pass::FuzzDriven,
                engine: "builtin".to_owned(),
                executions: 1000,
                target_entry_observed: true,
                coverage_edges: 1400,
                elapsed_secs: 1.0,
                executions_per_sec: 1000.0,
                findings: vec![],
            }],
            runtrace_events: vec![],
        };

        let results = vec![
            AttemptResult {
                candidate: cand("H-STUB"),
                outcome: blind_all,
                harness_dir: PathBuf::from("/tmp"),
            },
            AttemptResult {
                candidate: cand("H-REAL"),
                outcome: real_linked,
                harness_dir: PathBuf::from("/tmp"),
            },
        ];

        let work = std::env::temp_dir().join(format!(
            "bhf-report-stubonly-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&work).unwrap();
        write_reports(
            std::path::Path::new("/tmp"),
            &results,
            &work,
            "T0",
            "T1",
            false,
            actionability::RunMode::Reporting,
            0,
            0,
            false,
            false,
            false,
        )
        .unwrap();

        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();

        // AC2: per-target field distinguishing real vs blind-stubbed execution.
        let stub = &json["targets"][0]["stub_execution"];
        assert_eq!(stub["stub_only"], serde_json::Value::Bool(true), "{json}");
        assert_eq!(stub["blind_stubbed_symbols"], 4);
        assert_eq!(stub["real_linked_symbols"], 0);
        assert_eq!(stub["resolved_called_symbols"], 4);
        assert_eq!(stub["blind_stub_fraction"], 1.0);

        // The real-linked target is NOT flagged stub-only.
        let real = &json["targets"][1]["stub_execution"];
        assert_eq!(real["stub_only"], serde_json::Value::Bool(false), "{json}");
        assert_eq!(real["real_linked_symbols"], 1);

        // AC1: the summary counts the false-clean target distinctly; it is NOT
        // silently folded into a plain clean built_and_fuzzed total.
        assert_eq!(json["summary"]["fuzzed_stub_only"], 1, "{json}");
        assert_eq!(json["summary"]["built_and_fuzzed"], 2);

        // AC1: run.md loudly surfaces the stub-only target.
        let md = std::fs::read_to_string(work.join("auto/run.md")).unwrap();
        assert!(
            md.contains("STUB-ONLY"),
            "md missing stub-only warning: {md}"
        );
        assert!(md.contains("H-STUB"), "md: {md}");
    }

    /// force-fuzz Phase 2: a finding from a target that ran forced-and-stub-heavy
    /// (`--force` + a stub-only build) must be honestly LOW confidence: the summary
    /// counts it under `forced`, run.md surfaces the forced/stub caveat, and the
    /// finding indexes as forced with `low` severity and confidence and the
    /// stub-artifact caveat — so a forced crash is never read as a confirmed bug.
    #[test]
    fn forced_stub_heavy_target_floors_findings_to_low_and_counts_forced() {
        use crate::auto::attempt::{Outcome, PassRun};
        use crate::auto::pass::Pass;
        use crate::auto::repair::Repair;

        let work = std::env::temp_dir().join(format!(
            "bhf-report-forced-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let fid = "F-FORCED-0001";
        let finding_dir = work.join("results").join("findings").join(fid);
        std::fs::create_dir_all(&finding_dir).unwrap();
        // A finding whose EMITTED confidence is high — the forced flooring must
        // override it, not merely leave a low value alone.
        std::fs::write(
            finding_dir.join("finding.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "id": fid,
                "signature": "deadbeefcafef00d",
                "rule_id": "BHF-208",
                "classification": "unhandled",
                "harness_id": "H-FORCED",
                "exception": {
                    "name": "SEGV",
                    "message": "AddressSanitizer: SEGV on unknown address",
                    "sanitizer": "asan",
                    "stack": [
                        { "function": "opaque_target", "file": "/src/opaque.c", "line": 12 }
                    ]
                },
                "actionability": { "confidence": "high", "impact": "high" }
            }))
            .unwrap(),
        )
        .unwrap();

        // Blind-stubbed BuiltAndFuzzed → stub_only, so under --force it is
        // forced-and-stub-heavy.
        let outcome = Outcome::BuiltAndFuzzed {
            repairs: vec![Repair::StubBlind {
                symbol: "opaque_dep".to_owned(),
            }],
            retries: 0,
            per_pass_budget_secs: 60,
            total_wall_budget_secs: 180,
            executions_per_sec: 1000.0,
            passes: vec![PassRun {
                pass: Pass::FuzzDriven,
                engine: "builtin".to_owned(),
                executions: 1000,
                target_entry_observed: false,
                coverage_edges: 4,
                elapsed_secs: 1.0,
                executions_per_sec: 1000.0,
                findings: vec![fid.to_owned()],
            }],
            runtrace_events: vec![],
        };
        let result = AttemptResult {
            candidate: cand("H-FORCED"),
            outcome,
            harness_dir: PathBuf::from("/tmp"),
        };

        std::fs::create_dir_all(&work).unwrap();
        write_reports(
            std::path::Path::new("/tmp"),
            std::slice::from_ref(&result),
            &work,
            "T0",
            "T1",
            false,
            actionability::RunMode::Reporting,
            0,
            0,
            false,
            true, // force,
            false,
        )
        .unwrap();

        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
        // Summary counts the forced-and-stub-heavy target.
        assert_eq!(json["summary"]["forced"], 1, "{json}");
        assert_eq!(json["summary"]["fuzzed_stub_only"], 1, "{json}");
        assert_eq!(json["summary"]["built_and_fuzzed"], 1);

        // run.md surfaces the forced/stub caveat distinctly.
        let md = std::fs::read_to_string(work.join("auto/run.md")).unwrap();
        assert!(
            md.contains("Forced (stub-heavy)"),
            "md missing forced summary: {md}"
        );

        // The forced floor is persisted on the finding, so the results/ index
        // reads it from disk: forced, `low` severity and confidence, plus the
        // stub-artifact caveat.
        let doc = rebuild_results(&work);
        let finding = doc["findings"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|f| f["id"] == fid)
            .unwrap_or_else(|| panic!("indexed forced finding: {doc}"));
        assert_eq!(finding["fidelity"]["forced"], true, "{finding}");
        assert_eq!(finding["severity"], "low", "{finding}");
        assert_eq!(finding["confidence"]["level"], "low", "{finding}");
        assert!(
            finding["fidelity"]["caveats"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|c| c.as_str().is_some_and(|c| c.contains("stub artifact"))),
            "forced caveat missing: {finding}"
        );

        std::fs::remove_dir_all(&work).ok();
    }
}
