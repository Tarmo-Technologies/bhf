// SPDX-License-Identifier: Apache-2.0

//! `bhf ci` subcommand — wraps `bhf auto`, walks the
//! findings directory after the run, optionally writes a Markdown
//! summary to `$GITHUB_STEP_SUMMARY` (or `--summary-file`), and
//! exits non-zero based on a configurable severity threshold.

use crate::auto::cli::{run as run_auto, AutoArgs};
use anyhow::Context;
use clap::ValueEnum;
use finding_rules::Severity;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, clap::Args)]
pub struct CiArgs {
    /// Source root to sweep.
    pub path: PathBuf,

    /// The clap ids of the flags the command line gave (filled by `run_from`).
    #[arg(skip)]
    pub(crate) given: std::collections::BTreeSet<String>,

    /// Work directory.
    #[arg(long, default_value = "bhf_work")]
    pub work_dir: PathBuf,

    /// A directory of stored findings (finding directories, as
    /// `results/findings/` holds them) to replay against this run's build
    /// before it is judged: one that still reproduces fails the gate, one that
    /// no longer does is fixed. The work dir's own `regressions/`, which keeps
    /// a restored work dir's last findings, is always replayed. Repeatable.
    #[arg(long = "regressions", value_name = "DIR")]
    pub regressions: Vec<PathBuf>,

    /// Fuzzing time per target, in seconds, split across its passes. Passed
    /// to `bhf auto`.
    #[arg(long, default_value_t = 60)]
    pub per_target_time: u64,

    /// Stop a target once it has N distinct findings (crash signatures), or
    /// when its per-target time is spent, whichever comes first. `1` stops at
    /// the first crash, as libFuzzer does. Passed to `bhf auto`.
    #[arg(long = "per-target-finding-count", value_name = "N")]
    pub per_target_finding_count: Option<usize>,

    /// Time limit of the whole run, in seconds; with `--min-target-time` it
    /// is divided across the targets instead. Passed to `bhf auto`.
    #[arg(long = "campaign-time", value_name = "SECS")]
    pub campaign_time: Option<u64>,

    /// With `--campaign-time`: the least fuzzing time, in seconds, each
    /// attempted target gets when the campaign time is divided. Passed to
    /// `bhf auto`.
    #[arg(
        long = "min-target-time",
        value_name = "SECS",
        requires = "campaign_time"
    )]
    pub min_target_time: Option<u64>,

    /// Do not generate stubs for missing symbols: a target that does not build
    /// as it is fails, with its build diagnostics. Passed to `bhf auto`.
    #[arg(long)]
    pub no_stubs: bool,

    /// File to append the Markdown summary to. Default: the file the
    /// `GITHUB_STEP_SUMMARY` environment variable names.
    #[arg(long, value_name = "PATH")]
    pub summary_file: Option<PathBuf>,

    /// Exit non-zero when a finding of this severity or higher is present;
    /// `any` fails on every finding. With `--policy`, applies only when given.
    #[arg(long, value_enum, default_value_t = FailOn::Any)]
    pub fail_on: FailOn,

    /// Actionability profile (`reporting` or `attacking`), passed to
    /// `bhf auto --mode`.
    #[arg(long, default_value_t = actionability::RunMode::Reporting)]
    pub mode: actionability::RunMode,

    /// Fuzz only these languages, comma-separated, from the sixteen listed
    /// under "possible values" below (`c++`, `rs`, `py` and other common
    /// spellings work). Passed to `bhf auto`. Default: every language found.
    #[arg(
        long = "languages",
        visible_alias = "lang",
        value_enum,
        value_delimiter = ',',
        ignore_case = true,
        value_name = "LIST"
    )]
    pub languages: Vec<crate::auto::candidate::LangSelector>,

    /// Pull-request mode: build and fuzz only the targets in files changed
    /// since this git ref, from `git merge-base <ref> HEAD`, so a branch
    /// behind its base does not fuzz the base's own changes. Discovery still
    /// walks the whole tree, and its cache is reused across runs. Add
    /// `--campaign-time` to bound a pull-request run.
    #[arg(long = "changed-since", value_name = "GIT_REF")]
    pub changed_since: Option<String>,

    /// Read the changed files from this file, one per line (relative to the
    /// repository root, or absolute), in place of asking git; for a CI system
    /// that has already computed the pull request's diff. Overrides
    /// `--changed-since`.
    #[arg(long = "changed-paths-from", value_name = "PATH")]
    pub changed_paths_from: Option<PathBuf>,

    /// Write a SARIF 2.1.0 report to this path. The GitHub Action uploads it
    /// to code scanning, which annotates the pull request.
    #[arg(long, value_name = "PATH")]
    pub sarif: Option<PathBuf>,

    /// Write a GitLab SAST security report (format 15.2.1) of the run's
    /// findings to this path, for a GitLab job's `artifacts:reports:sast`
    /// (`gl-sast-report.json`).
    #[arg(long = "gitlab-sast", value_name = "PATH")]
    pub gitlab_sast: Option<PathBuf>,

    /// Write a short CI result JSON to this path: finding counts by severity
    /// and verdict, the confirmed count, the scoped file count and the exit
    /// code. The GitHub Action builds its pull-request comment from it.
    #[arg(long = "ci-json", value_name = "PATH")]
    pub ci_json: Option<PathBuf>,

    /// Pull-request gate. `confirmed` exits non-zero only when a
    /// fuzz-confirmed finding (verdict real or likely) is present; `all` fails
    /// on any finding; `never` never fails, and only annotates; `off`
    /// (default) leaves the decision to `--fail-on` or
    /// `--fail-on-actionability`.
    #[arg(long = "pr-gate", value_enum, default_value_t = PrGate::Off)]
    pub pr_gate: PrGate,

    /// Exit non-zero when a finding has this actionability verdict or a
    /// stronger one. Without it, `--fail-on` decides.
    #[arg(long, value_enum)]
    pub fail_on_actionability: Option<FailOnActionability>,

    /// Lowest verdict confidence that counts for --fail-on-actionability.
    #[arg(long, value_enum, default_value_t = MinActionabilityConfidence::Low)]
    pub min_actionability_confidence: MinActionabilityConfidence,

    /// Policy file whose CI gate also decides the exit status: the run fails
    /// when the policy or any gate above fails. Its `fail_on_severity` takes
    /// the place of the default `--fail-on any`. --dashboard-out reports its
    /// decisions too.
    #[arg(long)]
    pub policy: Option<PathBuf>,

    /// Runner assignment plan (from `bhf runners plan`) that the policy gate
    /// and --dashboard-out take into account.
    #[arg(long)]
    pub runner_plan: Option<PathBuf>,

    /// Write the CI result, with policy and runner decisions, as dashboard
    /// JSON to this path.
    #[arg(long)]
    pub dashboard_out: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FailOn {
    Any,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FailOnActionability {
    Real,
    Likely,
    Lab,
    Any,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PrGate {
    Off,
    Confirmed,
    All,
    Never,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MinActionabilityConfidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ActionabilityBuckets {
    pub by_verdict: BTreeMap<String, usize>,
    pub by_verdict_and_confidence: BTreeMap<(String, String), usize>,
}

impl FailOn {
    fn rank(self) -> u8 {
        match self {
            FailOn::Any => 0,
            FailOn::Low => 1,
            FailOn::Medium => 2,
            FailOn::High => 3,
            FailOn::Critical => 4,
        }
    }
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

/// Build the `auto` argument set that `bhf ci` drives. Extracted so flag
/// forwarding (notably the budget knobs `--per-target-time` /
/// `--per-target-finding-count` / `--campaign-time` / `--min-target-time`) is
/// unit-testable without running the whole pipeline.
fn auto_args_from_ci(args: &CiArgs, scoped_files: &[PathBuf]) -> AutoArgs {
    AutoArgs {
        path: args.path.clone(),
        work_dir: args.work_dir.clone(),
        max_work_dir_mb: crate::auto::storage::DEFAULT_MAX_WORK_DIR_MIB,
        max_corpus_mb: 64,
        discovery_cache: None,
        config: None,
        config_toolchain: None,
        config_cross: None,
        // The one flag `bhf ci` forwards that a config key can also set.
        given: args
            .given
            .iter()
            .filter(|id| *id == "per_target_time")
            .cloned()
            .collect(),
        from_config: Default::default(),
        toolchain: Default::default(),
        project: None,
        grammar_file: None,
        max_len: "auto".to_owned(),
        timeout: None,
        deadline: None,
        collector: crate::collector_run::CollectorSpec::Off,
        collector_window_ms: crate::collector_run::DEFAULT_WINDOW_MS,
        cxx_expected_exceptions: Vec::new(),
        cxx_std: None,
        unsafe_search_and_run_build_commands: false,
        dry_run: false,
        per_target_time: args.per_target_time,
        total_time: None,
        per_target_finding_count: args.per_target_finding_count,
        campaign_time: args.campaign_time,
        min_target_time: args.min_target_time,
        max_targets: None,
        max_attempts: None,
        max_repair_rounds: crate::auto::attempt::DEFAULT_MAX_REPAIR_ROUNDS,
        passes: None,
        single_pass: false,
        jobs: 1,
        // PR-native mode reuses the discovery cache so repeat runs skip the
        // full-tree re-parse; the changed-file scope is applied as `target_files`.
        reuse_discovery: !scoped_files.is_empty(),
        no_discovery_cache: false,
        fresh_discovery: false,
        resume: false,
        iterations: None,
        rss_limit_mb: crate::auto::cli::default_auto_rss_limit_mb(),
        no_stubs: args.no_stubs,
        list_fakes: false,
        targets: Vec::new(),
        harness_ids: Vec::new(),
        target_files: scoped_files.to_vec(),
        exclude_paths: Vec::new(),
        exclude: Vec::new(),
        languages: args.languages.clone(),
        ada_deps: Vec::new(),
        seed_files: Vec::new(),
        seed_dirs: Vec::new(),
        no_seed_mining: false,
        reuse_legacy_corpus: false,
        mode: args.mode,
        engine: "builtin".to_owned(),
        winafl_path: None,
        dynamorio_path: None,
        winafl_instrumentation: crate::fuzz::WinaflInstrumentation::Dynamorio,
        winafl_iterations: None,
        winafl_coverage_modules: Vec::new(),
        winafl_page_heap: false,
        verbose: false,
        probe_build: false,
        msbuild_solution: None,
        msbuild_config: None,
        no_msbuild_import: false,
        msbuild_evaluate: false,
        deps_only: false,
        list_targets: false,
        exclude_dir: Vec::new(),
        include_dir: Vec::new(),
        preprocess: crate::auto::discovery::PreprocessMode::Auto,
        install_deps: false,
        run_untrusted: false,
        build_command: None,
        extra_includes: Vec::new(),
        extra_sources: Vec::new(),
        comparison_progress: false,
        sanitizers: Default::default(),
        nonblocking: Vec::new(),
        sbom: false,
        static_scan: false,
        external_tools: false,
        symcc: false,
        workers_per_target: 1,
        sloc: None,
        static_dynamic: false,
        no_minimize: false,
        decoder_limits: Default::default(),
        force: false,
        rust_private: false,
        differential: None,
    }
}

pub fn run(args: CiArgs) -> i32 {
    let work_dir = args.work_dir.clone();
    if let Err(error) = crate::workdir::prepare(&work_dir) {
        bhfeprintln!("error: {error:#}");
        return 1;
    }

    // PR-native scoping. Resolve the changed-file list (from a file, or via
    // git merge-base) and keep only fuzzable sources under the sweep root. An
    // explicitly-requested scope that matches nothing means "no relevant
    // changes" — write a friendly summary and pass, rather than fuzzing the
    // whole tree.
    let scoped_files = match resolve_changed_scope(&args) {
        Ok(scope) => scope,
        Err(error) => {
            bhfeprintln!("error: could not compute changed-file scope: {error:#}");
            return 1;
        }
    };
    let scoping_requested = args.changed_since.is_some() || args.changed_paths_from.is_some();
    if scoping_requested && scoped_files.is_empty() {
        return report_nothing_to_do(&args);
    }

    // Stored findings (#318): a restored work dir's last ones move to
    // `regressions/`, and every one's minimized input seeds the run, so the
    // engines run them first; each is replayed once this run has built its
    // harness again.
    let regressions = crate::ci_regression::collect(&work_dir, &args.regressions);
    if !regressions.is_empty() {
        bhfeprintln!(
            "bhf ci: {} stored finding(s) to replay as regressions",
            regressions.len()
        );
    }
    let mut auto_args = auto_args_from_ci(&args, &scoped_files);
    auto_args.seed_files.extend(
        regressions
            .iter()
            .map(|regression| regression.input.clone()),
    );
    // auto::cli::run returns 0 for success, 2 when no candidates,
    // 1 for hard errors. We treat 1 here as failure regardless of
    // findings; 0/2 mean the auto loop completed normally.
    let auto_exit = run_auto(auto_args);
    if auto_exit != 0 && auto_exit != 2 {
        return auto_exit;
    }
    let regression_outcome = crate::ci_regression::replay(&regressions);
    crate::ci_regression::keep_unverified(&work_dir, &regressions, &regression_outcome);

    // Fail closed: if the findings directory cannot be enumerated, the
    // gate must error out (exit 1), never report zero findings and pass.
    let findings = match bucket_findings(&work_dir) {
        Ok(findings) => findings,
        Err(error) => {
            bhfeprintln!("error: CI gate could not read findings: {error:#}");
            return 1;
        }
    };
    let total: usize = findings.values().sum();

    // Actionability feeds the PR gate, the summary, and the CI JSON, so compute
    // it once. It is gate-critical when `--fail-on-actionability` or `--pr-gate
    // confirmed` is set; in those cases a read failure must fail closed.
    let gate_needs_actionability =
        args.fail_on_actionability.is_some() || args.pr_gate == PrGate::Confirmed;
    let actionability = match bucket_actionability(&work_dir) {
        Ok(actionability) => actionability,
        Err(error) => {
            if gate_needs_actionability {
                bhfeprintln!("error: CI gate could not read findings: {error:#}");
                return 1;
            }
            bhfeprintln!("warning: CI could not read actionability: {error:#}");
            ActionabilityBuckets::default()
        }
    };

    let sarif_path = maybe_emit_sarif(&args, &work_dir);
    if let Some(path) = args.gitlab_sast.as_deref() {
        // From this run's findings: results/ is rebuilt when the command
        // ends, after this.
        let written = match results::rebuild(&work_dir, &results::RebuildOptions::default()) {
            Ok(_) => crate::report::write_gitlab_sast(&work_dir, path),
            Err(error) => Err(format!("rebuild results: {error}")),
        };
        if let Err(error) = written {
            bhfeprintln!(
                "warning: could not write --gitlab-sast {}: {error}",
                path.display()
            );
        }
    }

    // Every gate the run applied counts: the run fails when any one fails, so
    // a passing `--policy` cannot hide a failing `--fail-on`, `--pr-gate` or
    // regression replay.
    let mut gates = finding_gates(&args, &findings, &actionability, &regression_outcome);
    if let Some(policy) = args.policy.as_deref() {
        gates.push(policy_gate(&work_dir, policy, args.runner_plan.as_deref()));
    }
    let exit_code = exit_code_from_gates(&gates);
    bhfeprintln!("bhf ci: {}", format_gates(&gates));

    let summary_target = summary_path_resolution(args.summary_file.as_deref());
    if let Some(path) = summary_target {
        let mut markdown = render_summary(&work_dir, total, &findings);
        markdown.push_str(&render_gates(&gates));
        if regression_outcome.replayed() > 0 {
            markdown.push_str(&format!(
                "\n**Regressions:** {} stored finding(s) replayed: {} still reproduce, {} fixed, \
                 {} not replayed.\n",
                regression_outcome.replayed(),
                regression_outcome.reproduced.len(),
                regression_outcome.fixed.len(),
                regression_outcome.unverified.len()
            ));
        }
        if let Err(error) = append_summary(&path, &markdown) {
            bhfeprintln!(
                "warning: could not write CI summary to {}: {error}",
                path.display()
            );
        }
    }

    if let Some(path) = args.ci_json.as_ref() {
        let mut ci = build_ci_json(
            total,
            &findings,
            &actionability,
            scoped_files.len(),
            sarif_path.as_deref(),
            exit_code,
        );
        ci["regressions"] = regression_outcome.to_json();
        ci["gates"] = gates_json(&gates);
        if let Err(error) = fs::write(path, serde_json::to_vec_pretty(&ci).unwrap_or_default()) {
            bhfeprintln!(
                "warning: could not write --ci-json {}: {error}",
                path.display()
            );
        }
    }
    if let Some(path) = args.dashboard_out {
        let dashboard = governance::ci_dashboard_data(
            &work_dir,
            args.policy.as_deref(),
            args.runner_plan.as_deref(),
            &findings,
            exit_code != 0,
        )
        .map(|mut value| {
            if args.policy.is_some() {
                merge_gates_into_dashboard(&mut value, &gates);
            }
            value
        });
        if let Err(error) = dashboard.and_then(|value| {
            governance::write_json(&path, &value)?;
            Ok(value)
        }) {
            bhfeprintln!("warning: could not write CI dashboard JSON: {error:#}");
        }
    }
    exit_code
}

/// Friendly no-op result when PR scoping matched no fuzzable changed files:
/// write a "nothing to do" summary + CI JSON and pass (exit 0).
fn report_nothing_to_do(args: &CiArgs) -> i32 {
    let summary =
        "### BHF CI\n\n- No fuzzable source files changed in this diff — nothing to do. ✅\n";
    if let Some(path) = summary_path_resolution(args.summary_file.as_deref()) {
        if let Err(error) = append_summary(&path, summary) {
            bhfeprintln!(
                "warning: could not write CI summary to {}: {error}",
                path.display()
            );
        }
    }
    if let Some(path) = args.ci_json.as_ref() {
        let ci = serde_json::json!({
            "total_findings": 0,
            "by_severity": serde_json::Map::new(),
            "by_verdict": serde_json::Map::new(),
            "confirmed_findings": 0,
            "scoped_files": 0,
            "sarif_path": serde_json::Value::Null,
            "exit_code": 0,
            "nothing_to_do": true,
        });
        if let Err(error) = fs::write(path, serde_json::to_vec_pretty(&ci).unwrap_or_default()) {
            bhfeprintln!(
                "warning: could not write --ci-json {}: {error}",
                path.display()
            );
        }
    }
    println!("bhf ci: no changed fuzzable files in scope; passing.");
    0
}

/// Resolve the changed-file scope for PR-native mode. Returns the changed files
/// that live under `args.path` and look like fuzzable source. Empty when no
/// scoping was requested (full-tree sweep) OR nothing relevant changed.
fn resolve_changed_scope(args: &CiArgs) -> anyhow::Result<Vec<PathBuf>> {
    let changed: std::collections::HashSet<PathBuf> =
        if let Some(list_path) = args.changed_paths_from.as_ref() {
            let root = crate::git_diff::repo_root().unwrap_or_else(|_| PathBuf::from("."));
            let text = fs::read_to_string(list_path)
                .with_context(|| format!("read changed-paths file {}", list_path.display()))?;
            crate::git_diff::parse_changed_set(&text, &root)
        } else if let Some(git_ref) = args.changed_since.as_ref() {
            crate::git_diff::compute_changed_set_pr(git_ref)?
        } else {
            return Ok(Vec::new()); // no scoping requested → full-tree sweep
        };

    let root = args
        .path
        .canonicalize()
        .unwrap_or_else(|_| args.path.clone());
    let mut scoped: Vec<PathBuf> = changed
        .into_iter()
        .filter(|p| is_fuzzable_source(p))
        .filter(|p| {
            let cp = p.canonicalize().unwrap_or_else(|_| p.clone());
            cp.starts_with(&root)
        })
        .collect();
    scoped.sort();
    Ok(scoped)
}

/// Extension gate matching the languages bhf discovers. A deleted file no
/// longer exists so it drops out of the in-root check downstream; this is the
/// cheap first cut that also filters docs/config churn out of PR runs.
fn is_fuzzable_source(path: &Path) -> bool {
    const EXTS: &[&str] = &[
        "ada", "adb", "ads", "c", "h", "cc", "cpp", "cxx", "hpp", "hh", "rs", "java", "py", "pl",
        "pm", "go",
    ];
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| EXTS.contains(&e.to_ascii_lowercase().as_str()))
        .unwrap_or(false)
}

/// Count of fuzz-confirmed findings — verdict `real_reachable` or
/// `likely_reachable`. Used by the `--pr-gate confirmed` policy and CI JSON.
fn confirmed_count(actionability: &ActionabilityBuckets) -> usize {
    actionability
        .by_verdict
        .iter()
        .filter(|(verdict, _)| matches!(verdict.as_str(), "real_reachable" | "likely_reachable"))
        .map(|(_, count)| *count)
        .sum()
}

/// A gate a `bhf ci` run applied, and what it came to.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Gate {
    kind: GateKind,
    /// The gate's setting: the `--fail-on`, `--fail-on-actionability` or
    /// `--pr-gate` value, or the policy file.
    setting: Option<String>,
    failed: bool,
    /// Why the gate failed, when it gives reasons (the policy's).
    reasons: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateKind {
    FailOn,
    FailOnActionability,
    PrGate,
    Regressions,
    Policy,
}

impl GateKind {
    /// The gate's id in the CI JSON.
    fn id(self) -> &'static str {
        match self {
            GateKind::FailOn => "fail_on",
            GateKind::FailOnActionability => "fail_on_actionability",
            GateKind::PrGate => "pr_gate",
            GateKind::Regressions => "regressions",
            GateKind::Policy => "policy",
        }
    }

    /// The reason the dashboard lists when the gate fails.
    fn reason(self) -> &'static str {
        match self {
            GateKind::Regressions => "regression_reproduced",
            other => other.id(),
        }
    }
}

impl Gate {
    fn new(kind: GateKind, setting: Option<String>, failed: bool) -> Self {
        Self {
            kind,
            setting,
            failed,
            reasons: Vec::new(),
        }
    }

    /// How the summary names the gate.
    fn label(&self) -> String {
        let flag = match self.kind {
            GateKind::FailOn => "--fail-on",
            GateKind::FailOnActionability => "--fail-on-actionability",
            GateKind::PrGate => "--pr-gate",
            GateKind::Regressions => return "regression replay".to_owned(),
            GateKind::Policy => return "`--policy`".to_owned(),
        };
        match &self.setting {
            Some(setting) => format!("`{flag} {setting}`"),
            None => format!("`{flag}`"),
        }
    }

    fn result(&self) -> String {
        if !self.failed {
            return "passed".to_owned();
        }
        if self.reasons.is_empty() {
            "**failed**".to_owned()
        } else {
            format!("**failed** ({})", self.reasons.join(", "))
        }
    }
}

fn value_name(value: impl ValueEnum) -> Option<String> {
    value
        .to_possible_value()
        .map(|value| value.get_name().to_owned())
}

/// The gates on this run's findings and on the stored findings it replayed:
/// `--pr-gate`, else `--fail-on-actionability`, else `--fail-on`, and the
/// regression replay unless `--pr-gate never`. Beside `--policy`, whose
/// `fail_on_severity` takes the place of the default `--fail-on any`,
/// `--fail-on` applies only when the command line gives it.
fn finding_gates(
    args: &CiArgs,
    findings: &BTreeMap<String, usize>,
    actionability: &ActionabilityBuckets,
    regressions: &crate::ci_regression::Outcome,
) -> Vec<Gate> {
    let total: usize = findings.values().sum();
    let mut gates = Vec::new();
    match args.pr_gate {
        PrGate::Off => {
            if let Some(level) = args.fail_on_actionability {
                gates.push(Gate::new(
                    GateKind::FailOnActionability,
                    value_name(level),
                    exit_code_from_actionability(
                        actionability,
                        level,
                        args.min_actionability_confidence,
                    ) != 0,
                ));
            } else if args.policy.is_none() || args.given.contains("fail_on") {
                gates.push(Gate::new(
                    GateKind::FailOn,
                    value_name(args.fail_on),
                    exit_code_from_buckets(findings, args.fail_on) != 0,
                ));
            }
        }
        gate => {
            let failed = match gate {
                PrGate::All => total > 0,
                PrGate::Confirmed => confirmed_count(actionability) > 0,
                PrGate::Off | PrGate::Never => false,
            };
            gates.push(Gate::new(GateKind::PrGate, value_name(gate), failed));
        }
    }
    // A stored finding that still reproduces is a regression: it fails any
    // gate that can fail.
    if regressions.replayed() > 0 && args.pr_gate != PrGate::Never {
        gates.push(Gate::new(
            GateKind::Regressions,
            None,
            !regressions.reproduced.is_empty(),
        ));
    }
    gates
}

/// The `--policy` file's CI gate. One that cannot be evaluated fails.
fn policy_gate(work_dir: &Path, policy: &Path, runner_plan: Option<&Path>) -> Gate {
    let setting = Some(policy.display().to_string());
    match governance::ci_policy_gate_with_runner_plan(work_dir, policy, runner_plan) {
        Ok(result) => {
            let mut gate = Gate::new(
                GateKind::Policy,
                setting,
                result
                    .pointer("/gate/failed")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
            );
            gate.reasons = result
                .pointer("/gate/reasons")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|reason| reason.as_str().map(str::to_owned))
                .collect();
            gate
        }
        Err(error) => {
            bhfeprintln!("warning: could not evaluate CI policy gate: {error:#}");
            let mut gate = Gate::new(GateKind::Policy, setting, true);
            gate.reasons.push("not evaluated".to_owned());
            gate
        }
    }
}

/// `1` when any gate failed, else `0`.
fn exit_code_from_gates(gates: &[Gate]) -> i32 {
    i32::from(gates.iter().any(|gate| gate.failed))
}

/// One line naming each gate's result, for the log.
fn format_gates(gates: &[Gate]) -> String {
    let parts: Vec<String> = gates
        .iter()
        .map(|gate| {
            let result = if gate.failed { "failed" } else { "passed" };
            format!("{} {result}", gate.label().replace('`', ""))
        })
        .collect();
    format!("gates: {}", parts.join(", "))
}

/// The summary's list item for each gate.
fn render_gates(gates: &[Gate]) -> String {
    gates
        .iter()
        .map(|gate| format!("- Gate {}: {}\n", gate.label(), gate.result()))
        .collect()
}

/// The CI JSON's `gates` array: each gate's id, setting, result and reasons.
fn gates_json(gates: &[Gate]) -> serde_json::Value {
    gates
        .iter()
        .map(|gate| {
            serde_json::json!({
                "gate": gate.kind.id(),
                "setting": gate.setting,
                "failed": gate.failed,
                "reasons": gate.reasons,
            })
        })
        .collect()
}

/// Fold the gates beside the policy into the dashboard's `gate`, which
/// `governance` fills from the policy alone, so its `failed` is the run's
/// result.
fn merge_gates_into_dashboard(dashboard: &mut serde_json::Value, gates: &[Gate]) {
    let Some(gate) = dashboard
        .get_mut("gate")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };
    let mut reasons: Vec<serde_json::Value> = gate
        .get("reasons")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    for failed in gates
        .iter()
        .filter(|g| g.failed && g.kind != GateKind::Policy)
    {
        let reason = serde_json::Value::from(failed.kind.reason());
        if !reasons.contains(&reason) {
            reasons.push(reason);
        }
    }
    let reason = match reasons.as_slice() {
        [] => serde_json::Value::from("none"),
        [single] => single.clone(),
        _ => serde_json::Value::from("multiple"),
    };
    gate.insert(
        "failed".to_owned(),
        serde_json::Value::from(exit_code_from_gates(gates) != 0),
    );
    gate.insert("reason".to_owned(), reason);
    gate.insert("reasons".to_owned(), serde_json::Value::from(reasons));
    gate.insert("gates".to_owned(), gates_json(gates));
}

/// Compact machine-readable CI result the GitHub Action consumes to render the
/// PR summary comment.
fn build_ci_json(
    total: usize,
    by_severity: &BTreeMap<String, usize>,
    actionability: &ActionabilityBuckets,
    scoped_files: usize,
    sarif_path: Option<&str>,
    exit_code: i32,
) -> serde_json::Value {
    serde_json::json!({
        "total_findings": total,
        "by_severity": by_severity,
        "by_verdict": actionability.by_verdict,
        "confirmed_findings": confirmed_count(actionability),
        "scoped_files": scoped_files,
        "sarif_path": sarif_path,
        "exit_code": exit_code,
    })
}

/// Emit a SARIF 2.1.0 report to `--sarif` when requested, reusing the report
/// crate. Returns the final SARIF path string (for the CI JSON) or `None`.
fn maybe_emit_sarif(args: &CiArgs, work_dir: &Path) -> Option<String> {
    let requested = args.sarif.as_ref()?;
    if let Err(error) = results::rebuild(work_dir, &results::RebuildOptions::default()) {
        bhfeprintln!("warning: could not rebuild results for SARIF: {error}");
        return None;
    }
    let produced = corpus::layout::results_dir(work_dir).join("findings.sarif");
    if let Some(parent) = requested.parent() {
        let _ = fs::create_dir_all(parent);
    }
    match fs::copy(&produced, requested) {
        Ok(_) => Some(requested.to_string_lossy().into_owned()),
        Err(error) => {
            bhfeprintln!(
                "warning: could not copy SARIF to {}: {error}",
                requested.display()
            );
            Some(produced.to_string_lossy().into_owned())
        }
    }
}

fn summary_path_resolution(flag: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = flag {
        return Some(p.to_path_buf());
    }
    std::env::var_os("GITHUB_STEP_SUMMARY").map(PathBuf::from)
}

fn bucket_findings(work_dir: &Path) -> anyhow::Result<BTreeMap<String, usize>> {
    let findings_dir = corpus::layout::findings_dir(work_dir);
    let mut buckets: BTreeMap<String, usize> = BTreeMap::new();
    if !findings_dir.is_dir() {
        return Ok(buckets);
    }
    // A failure to enumerate an *existing* findings directory is a hard
    // error: the gate must fail closed, never silently report zero.
    let entries = fs::read_dir(&findings_dir)
        .with_context(|| format!("read findings directory {}", findings_dir.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| {
            format!(
                "read findings directory entry in {}",
                findings_dir.display()
            )
        })?;
        match entry.file_type() {
            Ok(ft) if ft.is_dir() => {}
            // A single unreadable/non-dir entry is skipped, not fatal,
            // but it must never make a real finding disappear — so we
            // only `continue` here, not for parse failures below.
            _ => continue,
        }
        let finding_json = entry.path().join("finding.json");
        if !finding_json.is_file() {
            continue;
        }
        // A finding directory exists, so a finding exists. If its
        // finding.json is unreadable or malformed we count it as an
        // `unknown`-severity finding (visible to the gate) instead of
        // dropping it — a corrupt/partial record must never turn the
        // security gate green.
        let severity = match fs::read(&finding_json)
            .ok()
            .and_then(|raw| serde_json::from_slice::<serde_json::Value>(&raw).ok())
        {
            Some(value) => finding_severity(&value),
            None => {
                bhfeprintln!(
                    "warning: unreadable/malformed {}; counting as an unknown-severity finding",
                    finding_json.display()
                );
                "unknown".to_owned()
            }
        };
        *buckets.entry(severity).or_insert(0) += 1;
    }
    Ok(buckets)
}

pub fn bucket_actionability_for_test(work_dir: &Path) -> anyhow::Result<ActionabilityBuckets> {
    bucket_actionability(work_dir)
}

pub fn exit_code_from_actionability_for_test(
    buckets: &ActionabilityBuckets,
    fail_on: FailOnActionability,
    min_confidence: MinActionabilityConfidence,
) -> i32 {
    exit_code_from_actionability(buckets, fail_on, min_confidence)
}

fn bucket_actionability(work_dir: &Path) -> anyhow::Result<ActionabilityBuckets> {
    let findings_dir = corpus::layout::findings_dir(work_dir);
    let mut buckets = ActionabilityBuckets::default();
    if !findings_dir.is_dir() {
        return Ok(buckets);
    }
    let entries = fs::read_dir(&findings_dir)
        .with_context(|| format!("read findings directory {}", findings_dir.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| {
            format!(
                "read findings directory entry in {}",
                findings_dir.display()
            )
        })?;
        match entry.file_type() {
            Ok(ft) if ft.is_dir() => {}
            _ => continue,
        }
        let finding_json = entry.path().join("finding.json");
        if !finding_json.is_file() {
            continue;
        }
        // A malformed finding.json still counts as a finding, with an
        // "unknown" verdict at "unknown" confidence, so the
        // actionability gate cannot be defeated by a corrupt record.
        let (verdict, confidence) = match fs::read(&finding_json)
            .ok()
            .and_then(|raw| serde_json::from_slice::<serde_json::Value>(&raw).ok())
        {
            Some(value) => {
                let record = actionability::existing_actionability_or_backfill(
                    actionability::RunMode::Reporting,
                    &value,
                    Some(&finding_json),
                );
                (
                    record.verdict.as_str().to_owned(),
                    record.confidence.as_str().to_owned(),
                )
            }
            None => {
                bhfeprintln!(
                    "warning: unreadable/malformed {}; counting as an unknown-verdict finding",
                    finding_json.display()
                );
                ("unknown".to_owned(), "unknown".to_owned())
            }
        };
        *buckets.by_verdict.entry(verdict.clone()).or_insert(0) += 1;
        *buckets
            .by_verdict_and_confidence
            .entry((verdict, confidence))
            .or_insert(0) += 1;
    }
    Ok(buckets)
}

fn finding_severity(value: &serde_json::Value) -> String {
    // The single resolver every renderer, importer and this gate share:
    // actionability impact outranks the record's own severity, which outranks
    // the rule catalog default.
    results::severity::resolve_raw(value, None)
        .as_str()
        .to_owned()
}

fn render_summary(work_dir: &Path, total: usize, buckets: &BTreeMap<String, usize>) -> String {
    let mut out = String::new();
    out.push_str("### BHF CI\n\n");
    out.push_str(&format!(
        "- Findings: **{total}** ({})\n",
        format_buckets(buckets)
    ));
    let actionability = bucket_actionability(work_dir).unwrap_or_default();
    if !actionability.by_verdict.is_empty() {
        out.push_str(&format!(
            "- Actionability: {}\n",
            format_actionability_buckets(&actionability.by_verdict)
        ));
    }
    out.push_str(&format!("- Work dir: `{}`\n", work_dir.display()));
    out.push_str(&format!(
        "- Results: `{}/results/INDEX.md`\n",
        work_dir.display()
    ));
    out
}

fn format_actionability_buckets(buckets: &BTreeMap<String, usize>) -> String {
    const ORDER: &[&str] = &[
        "real_reachable",
        "likely_reachable",
        "lab_only",
        "blocked",
        "unknown",
    ];
    format_buckets_with_order(buckets, ORDER)
}

fn format_buckets(buckets: &BTreeMap<String, usize>) -> String {
    const ORDER: &[&str] = &["critical", "high", "medium", "low", "info"];
    format_buckets_with_order(buckets, ORDER)
}

fn format_buckets_with_order(buckets: &BTreeMap<String, usize>, order: &[&str]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for key in order {
        if let Some(count) = buckets.get(*key) {
            if *count > 0 {
                parts.push(format!("{key} {count}"));
            }
        }
    }
    for (key, count) in buckets {
        if !order.contains(&key.as_str()) && *count > 0 {
            parts.push(format!("{key} {count}"));
        }
    }
    if parts.is_empty() {
        "none".to_owned()
    } else {
        parts.join(", ")
    }
}

fn append_summary(path: &Path, markdown: &str) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    file.write_all(markdown.as_bytes())?;
    Ok(())
}

fn exit_code_from_buckets(buckets: &BTreeMap<String, usize>, fail_on: FailOn) -> i32 {
    let threshold = fail_on.rank();
    for (severity, count) in buckets {
        if *count == 0 {
            continue;
        }
        let rank = severity_for_name(severity).map(severity_rank).unwrap_or(0);
        if rank >= threshold {
            return 1;
        }
    }
    0
}

fn exit_code_from_actionability(
    buckets: &ActionabilityBuckets,
    fail_on: FailOnActionability,
    min_confidence: MinActionabilityConfidence,
) -> i32 {
    for ((verdict, confidence), count) in &buckets.by_verdict_and_confidence {
        if *count == 0 {
            continue;
        }
        if verdict_matches_threshold(verdict, fail_on)
            && confidence_meets_min(confidence, min_confidence)
        {
            return 1;
        }
    }
    0
}

fn verdict_matches_threshold(verdict: &str, fail_on: FailOnActionability) -> bool {
    match fail_on {
        FailOnActionability::Real => verdict == "real_reachable",
        FailOnActionability::Likely => {
            matches!(verdict, "real_reachable" | "likely_reachable")
        }
        FailOnActionability::Lab => {
            matches!(verdict, "real_reachable" | "likely_reachable" | "lab_only")
        }
        FailOnActionability::Any => matches!(
            verdict,
            "real_reachable" | "likely_reachable" | "lab_only" | "blocked" | "unknown"
        ),
    }
}

fn confidence_meets_min(confidence: &str, min: MinActionabilityConfidence) -> bool {
    confidence_rank_name(confidence) >= confidence_rank_min(min)
}

fn confidence_rank_name(confidence: &str) -> u8 {
    match confidence {
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn confidence_rank_min(min: MinActionabilityConfidence) -> u8 {
    match min {
        MinActionabilityConfidence::High => 3,
        MinActionabilityConfidence::Medium => 2,
        MinActionabilityConfidence::Low => 1,
    }
}

fn severity_for_name(name: &str) -> Option<Severity> {
    match name.to_ascii_lowercase().as_str() {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        "info" => Some(Severity::Info),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(name: &str) -> crate::test_support::TestDir {
        crate::test_support::TestDir::new(&format!("ci-{name}"))
    }

    fn write_finding(work_dir: &Path, id: &str, rule_id: &str, severity: &str) {
        let dir = work_dir.join("results").join("findings").join(id);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("finding.json"),
            serde_json::to_vec(&serde_json::json!({
                "id": id,
                "rule_id": rule_id,
                "severity": severity,
            }))
            .unwrap(),
        )
        .unwrap();
    }

    /// A `--per-target-time` the `bhf ci` command line gives counts as given
    /// to the sweep, so a tree's `.bhf.toml` cannot replace it, even when it
    /// has the default value; one it leaves out the config may fill.
    #[test]
    fn a_per_target_time_given_to_ci_wins_over_the_tree_config() {
        use clap::{CommandFactory, FromArgMatches, Parser};
        #[derive(Parser)]
        struct TestCli {
            #[command(flatten)]
            ci: CiArgs,
        }
        let tree = tempfile::tempdir().unwrap();
        std::fs::write(
            tree.path().join(crate::auto::config::CONFIG_FILE_NAME),
            "per-target-time = 10\n",
        )
        .unwrap();
        let swept = |argv: &[&str]| {
            let matches = TestCli::command().try_get_matches_from(argv).unwrap();
            let mut cli = TestCli::from_arg_matches(&matches).unwrap();
            cli.ci.given = crate::auto::cli::given_arg_ids(&matches);
            let mut auto = auto_args_from_ci(&cli.ci, &[]);
            crate::auto::config::apply(&mut auto, tree.path()).unwrap();
            auto.per_target_time
        };
        assert_eq!(swept(&["bhf", "src", "--per-target-time", "60"]), 60);
        assert_eq!(swept(&["bhf", "src", "--per-target-time", "5"]), 5);
        assert_eq!(swept(&["bhf", "src"]), 10);
    }

    #[test]
    fn ci_parses_and_forwards_new_budget_flags() {
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct TestCli {
            #[command(flatten)]
            ci: CiArgs,
        }
        // Defaults: the new budget knobs are unset.
        let def = TestCli::try_parse_from(["bhf", "src"]).expect("parses");
        assert_eq!(def.ci.per_target_finding_count, None);
        assert_eq!(def.ci.campaign_time, None);
        assert_eq!(def.ci.min_target_time, None);
        // ...and they forward to auto as unset.
        let def_auto = auto_args_from_ci(&def.ci, &[]);
        assert_eq!(def_auto.per_target_finding_count, None);
        assert_eq!(def_auto.campaign_time, None);
        assert_eq!(def_auto.min_target_time, None);

        // Explicit values parse on `bhf ci` and forward into the AutoArgs.
        let set = TestCli::try_parse_from([
            "bhf",
            "src",
            "--per-target-finding-count",
            "2",
            "--campaign-time",
            "120",
            "--min-target-time",
            "10",
        ])
        .expect("parses");
        let auto = auto_args_from_ci(&set.ci, &[]);
        assert_eq!(auto.per_target_finding_count, Some(2));
        assert_eq!(auto.campaign_time, Some(120));
        assert_eq!(auto.min_target_time, Some(10));
        // The deprecated alias is never set from CI.
        assert_eq!(auto.total_time, None);

        // --min-target-time requires --campaign-time, same rule as `bhf auto`.
        assert!(
            TestCli::try_parse_from(["bhf", "src", "--min-target-time", "10"]).is_err(),
            "--min-target-time without --campaign-time must error"
        );
    }

    #[test]
    fn ci_languages_flag_parses_and_forwards_to_auto() {
        use crate::auto::candidate::LangSelector;
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct TestCli {
            #[command(flatten)]
            ci: CiArgs,
        }
        // Default: no language filter forwarded (fuzz every language found).
        let def = TestCli::try_parse_from(["bhf", "src"]).expect("parses");
        assert!(def.ci.languages.is_empty());
        assert!(auto_args_from_ci(&def.ci, &[]).languages.is_empty());

        // Explicit (with aliases + the `--lang` flag alias) forwards verbatim.
        let set = TestCli::try_parse_from(["bhf", "src", "--lang", "py,go"]).expect("parses");
        assert_eq!(
            auto_args_from_ci(&set.ci, &[]).languages,
            vec![LangSelector::Python, LangSelector::Go]
        );
    }

    // Serialize the two env-var-dependent tests so they don't
    // race on the shared GITHUB_STEP_SUMMARY slot when cargo runs
    // them on parallel threads.
    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn summary_path_resolution_flag_wins_over_env() {
        let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let original = std::env::var_os("GITHUB_STEP_SUMMARY");
        std::env::set_var("GITHUB_STEP_SUMMARY", "/tmp/from_env");
        let flag_path = PathBuf::from("/tmp/from_flag");
        let resolved = summary_path_resolution(Some(&flag_path));
        assert_eq!(resolved, Some(PathBuf::from("/tmp/from_flag")));
        if let Some(prev) = original {
            std::env::set_var("GITHUB_STEP_SUMMARY", prev);
        } else {
            std::env::remove_var("GITHUB_STEP_SUMMARY");
        }
    }

    #[test]
    fn summary_path_resolution_uses_env_when_flag_omitted() {
        let _guard = ENV_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let original = std::env::var_os("GITHUB_STEP_SUMMARY");
        std::env::set_var("GITHUB_STEP_SUMMARY", "/tmp/from_env_only");
        let resolved = summary_path_resolution(None);
        assert_eq!(resolved, Some(PathBuf::from("/tmp/from_env_only")));
        if let Some(prev) = original {
            std::env::set_var("GITHUB_STEP_SUMMARY", prev);
        } else {
            std::env::remove_var("GITHUB_STEP_SUMMARY");
        }
    }

    #[test]
    fn bucket_findings_groups_by_severity() {
        let work = tempdir("bucket");
        write_finding(&work, "F-0001-aaaa", "BHF-201", "high");
        write_finding(&work, "F-0002-bbbb", "BHF-101", "medium");
        write_finding(&work, "F-0003-cccc", "BHF-101", "medium");
        let buckets = bucket_findings(&work).unwrap();
        assert_eq!(buckets.get("high"), Some(&1));
        assert_eq!(buckets.get("medium"), Some(&2));
    }

    #[test]
    fn malformed_finding_json_counts_as_unknown_not_dropped() {
        // Regression: a truncated/corrupt finding.json must not make
        // the whole gate report zero findings and pass.
        let work = tempdir("malformed");
        write_finding(&work, "F-0001-aaaa", "BHF-201", "high");
        let bad = work.join("results/findings/F-0002-bbbb");
        fs::create_dir_all(&bad).unwrap();
        fs::write(bad.join("finding.json"), b"{ this is not json").unwrap();

        let buckets = bucket_findings(&work).unwrap();
        let total: usize = buckets.values().sum();
        assert_eq!(total, 2, "the valid + the malformed finding both count");
        assert_eq!(buckets.get("high"), Some(&1));
        assert_eq!(
            buckets.get("unknown"),
            Some(&1),
            "malformed record is visible as unknown severity"
        );
        // The gate must be able to fail on it.
        assert_eq!(exit_code_from_buckets(&buckets, FailOn::Any), 1);
    }

    #[test]
    fn bucket_findings_uses_rule_default_severity_when_field_missing() {
        let work = tempdir("rule-default");
        let dir = work.join("results/findings/F-0001");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("finding.json"),
            serde_json::to_vec(&serde_json::json!({ "id": "F-0001", "rule_id": "BHF-208" }))
                .unwrap(),
        )
        .unwrap();
        let buckets = bucket_findings(&work).unwrap();
        // BHF-208 default_severity is Low (per finding_rules).
        assert_eq!(buckets.get("low"), Some(&1));
    }

    #[test]
    fn exit_code_from_buckets_returns_one_when_above_threshold() {
        let mut buckets = BTreeMap::new();
        buckets.insert("high".to_owned(), 1);
        assert_eq!(exit_code_from_buckets(&buckets, FailOn::High), 1);
    }

    #[test]
    fn exit_code_from_buckets_returns_zero_below_threshold() {
        let mut buckets = BTreeMap::new();
        buckets.insert("low".to_owned(), 1);
        assert_eq!(exit_code_from_buckets(&buckets, FailOn::High), 0);
    }

    #[test]
    fn exit_code_from_buckets_any_threshold_treats_any_finding_as_failure() {
        let mut buckets = BTreeMap::new();
        buckets.insert("info".to_owned(), 1);
        assert_eq!(exit_code_from_buckets(&buckets, FailOn::Any), 1);
    }

    #[test]
    fn render_summary_includes_counts() {
        let mut buckets = BTreeMap::new();
        buckets.insert("critical".to_owned(), 1);
        buckets.insert("medium".to_owned(), 4);
        let summary = render_summary(Path::new("/tmp/work"), 5, &buckets);
        assert!(summary.contains("Findings: **5**"));
        assert!(summary.contains("critical 1"));
        assert!(summary.contains("medium 4"));
        assert!(summary.contains("/tmp/work"));
    }

    #[test]
    fn render_summary_includes_actionability_counts_when_present() {
        let work = tempdir("summary-actionability");
        let dir = work.join("results/findings/F-0001");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("finding.json"),
            serde_json::to_vec(&serde_json::json!({
                "id": "F-0001",
                "severity": "high",
                "actionability": {
                    "mode": "attacking",
                    "verdict": "real_reachable",
                    "impact": "high",
                    "confidence": "high",
                    "prosthetics": { "used": false, "items": [] }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let mut buckets = BTreeMap::new();
        buckets.insert("high".to_owned(), 1);
        let summary = render_summary(&work, 1, &buckets);

        assert!(summary.contains("Actionability: real_reachable 1"));
    }

    #[test]
    fn ci_severity_uses_the_unified_resolver() {
        // impact (from actionability) outranks the record's own severity
        let raw = serde_json::json!({
            "rule_id": "BHF-201", "severity": "low",
            "actionability": {"mode": "reporting", "verdict": "real_reachable", "impact": "critical",
                              "confidence": "high", "cwe": ["CWE-122"], "prosthetics": {"used": false}}
        });
        assert_eq!(finding_severity(&raw), "critical");
    }

    #[test]
    fn ci_summary_points_at_results_index() {
        let tmp = tempdir("summary-results-index");
        let summary = render_summary(&tmp, 0, &Default::default());
        assert!(summary.contains("results/INDEX.md"), "{summary}");
        assert!(!summary.contains("reports/run-last.md"));
    }

    #[test]
    fn format_buckets_zero_findings_renders_none() {
        let buckets = BTreeMap::new();
        assert_eq!(format_buckets(&buckets), "none");
    }

    #[test]
    fn new_pr_flags_parse_and_default_off() {
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct T {
            #[command(flatten)]
            ci: CiArgs,
        }
        let t = T::try_parse_from([
            "bhf",
            "src",
            "--changed-since",
            "origin/main",
            "--sarif",
            "out.sarif",
            "--ci-json",
            "ci.json",
            "--pr-gate",
            "confirmed",
        ])
        .expect("parses");
        assert_eq!(t.ci.changed_since.as_deref(), Some("origin/main"));
        assert_eq!(t.ci.sarif, Some(PathBuf::from("out.sarif")));
        assert_eq!(t.ci.ci_json, Some(PathBuf::from("ci.json")));
        assert_eq!(t.ci.pr_gate, PrGate::Confirmed);

        let d = T::try_parse_from(["bhf", "src"]).expect("parses");
        assert_eq!(d.ci.changed_since, None);
        assert_eq!(d.ci.pr_gate, PrGate::Off);
        // The default full-tree run passes no scope to auto.
        assert!(auto_args_from_ci(&d.ci, &[]).target_files.is_empty());
    }

    #[test]
    fn scoped_files_forward_to_auto_target_files_and_reuse_discovery() {
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct T {
            #[command(flatten)]
            ci: CiArgs,
        }
        let t = T::try_parse_from(["bhf", "src"]).expect("parses");
        let scoped = vec![PathBuf::from("/x/a.c"), PathBuf::from("/x/b.c")];
        let auto = auto_args_from_ci(&t.ci, &scoped);
        assert_eq!(auto.target_files, scoped);
        assert!(auto.reuse_discovery, "PR scope reuses the discovery cache");
    }

    #[test]
    fn is_fuzzable_source_matches_known_extensions_only() {
        assert!(is_fuzzable_source(Path::new("a/b/c.rs")));
        assert!(is_fuzzable_source(Path::new("x.ADB")), "case-insensitive");
        assert!(is_fuzzable_source(Path::new("pkg/mod.go")));
        assert!(!is_fuzzable_source(Path::new("README.md")));
        assert!(!is_fuzzable_source(Path::new("Cargo.toml")));
        assert!(!is_fuzzable_source(Path::new("no_extension")));
    }

    #[test]
    fn confirmed_count_counts_real_and_likely_only() {
        let mut a = ActionabilityBuckets::default();
        a.by_verdict.insert("real_reachable".to_owned(), 2);
        a.by_verdict.insert("likely_reachable".to_owned(), 1);
        a.by_verdict.insert("lab_only".to_owned(), 5);
        a.by_verdict.insert("unknown".to_owned(), 3);
        assert_eq!(confirmed_count(&a), 3);
    }

    #[test]
    fn build_ci_json_reports_confirmed_and_scope() {
        let mut sev = BTreeMap::new();
        sev.insert("high".to_owned(), 1);
        let mut a = ActionabilityBuckets::default();
        a.by_verdict.insert("real_reachable".to_owned(), 1);
        a.by_verdict.insert("lab_only".to_owned(), 4);
        let json = build_ci_json(5, &sev, &a, 7, Some("/tmp/x.sarif"), 1);
        assert_eq!(json["total_findings"], 5);
        assert_eq!(json["confirmed_findings"], 1);
        assert_eq!(json["scoped_files"], 7);
        assert_eq!(json["sarif_path"], "/tmp/x.sarif");
        assert_eq!(json["exit_code"], 1);
        assert_eq!(json["by_severity"]["high"], 1);
    }

    #[test]
    fn resolve_changed_scope_from_file_keeps_only_in_root_sources() {
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct T {
            #[command(flatten)]
            ci: CiArgs,
        }
        let work = tempdir("scope");
        let root = work.join("proj");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/a.c"), b"int main(){}").unwrap();
        fs::write(root.join("src/readme.md"), b"# doc").unwrap();
        let list = work.join("changed.txt");
        fs::write(
            &list,
            format!(
                "{}\n{}\n/tmp/outside_{}.c\n",
                root.join("src/a.c").display(),
                root.join("src/readme.md").display(),
                std::process::id(),
            ),
        )
        .unwrap();
        let t = T::try_parse_from([
            "bhf",
            root.to_str().unwrap(),
            "--changed-paths-from",
            list.to_str().unwrap(),
        ])
        .expect("parses");
        let scoped = resolve_changed_scope(&t.ci).unwrap();
        assert_eq!(scoped, vec![root.join("src/a.c")]);
    }

    /// `CiArgs` as the command line `argv` gives them, with the given flags
    /// recorded as `run_from` records them.
    fn ci_args(argv: &[&str]) -> CiArgs {
        use clap::{CommandFactory, FromArgMatches, Parser};
        #[derive(Parser)]
        struct T {
            #[command(flatten)]
            ci: CiArgs,
        }
        let matches = T::command().try_get_matches_from(argv).unwrap();
        let mut parsed = T::from_arg_matches(&matches).unwrap();
        parsed.ci.given = crate::auto::cli::given_arg_ids(&matches);
        parsed.ci
    }

    fn one_finding(severity: &str) -> BTreeMap<String, usize> {
        BTreeMap::from([(severity.to_owned(), 1)])
    }

    fn reproduced(id: &str) -> crate::ci_regression::Outcome {
        crate::ci_regression::Outcome {
            reproduced: vec![id.to_owned()],
            ..Default::default()
        }
    }

    fn fixed(id: &str) -> crate::ci_regression::Outcome {
        crate::ci_regression::Outcome {
            fixed: vec![id.to_owned()],
            ..Default::default()
        }
    }

    fn policy_result(failed: bool) -> Gate {
        let mut gate = Gate::new(GateKind::Policy, Some("p.json".to_owned()), failed);
        if failed {
            gate.reasons.push("policy_threshold".to_owned());
        }
        gate
    }

    #[test]
    fn a_failing_fail_on_fails_the_run_beside_a_passing_policy() {
        let args = ci_args(&["bhf", "src", "--policy", "p.json", "--fail-on", "low"]);
        let mut gates = finding_gates(
            &args,
            &one_finding("medium"),
            &ActionabilityBuckets::default(),
            &Default::default(),
        );
        assert_eq!(
            gates,
            vec![Gate::new(GateKind::FailOn, Some("low".to_owned()), true)]
        );
        gates.push(policy_result(false));
        assert_eq!(exit_code_from_gates(&gates), 1);
    }

    #[test]
    fn every_gate_passing_passes_the_run() {
        let args = ci_args(&["bhf", "src", "--policy", "p.json", "--fail-on", "high"]);
        let mut gates = finding_gates(
            &args,
            &one_finding("medium"),
            &ActionabilityBuckets::default(),
            &fixed("F-1"),
        );
        gates.push(policy_result(false));
        assert_eq!(
            gates.iter().map(|g| (g.kind, g.failed)).collect::<Vec<_>>(),
            vec![
                (GateKind::FailOn, false),
                (GateKind::Regressions, false),
                (GateKind::Policy, false)
            ]
        );
        assert_eq!(exit_code_from_gates(&gates), 0);
    }

    #[test]
    fn a_failing_policy_fails_the_run_beside_passing_gates() {
        let args = ci_args(&["bhf", "src", "--policy", "p.json", "--pr-gate", "confirmed"]);
        let mut gates = finding_gates(
            &args,
            &one_finding("medium"),
            &ActionabilityBuckets::default(),
            &Default::default(),
        );
        assert_eq!(
            gates,
            vec![Gate::new(
                GateKind::PrGate,
                Some("confirmed".to_owned()),
                false
            )]
        );
        gates.push(policy_result(true));
        assert_eq!(exit_code_from_gates(&gates), 1);
    }

    #[test]
    fn a_reproduced_regression_and_a_failing_pr_gate_fail_beside_a_policy() {
        let args = ci_args(&["bhf", "src", "--policy", "p.json"]);
        let gates = finding_gates(
            &args,
            &one_finding("critical"),
            &ActionabilityBuckets::default(),
            &reproduced("F-1"),
        );
        // The policy's `fail_on_severity` replaces the default `--fail-on any`.
        assert_eq!(gates, vec![Gate::new(GateKind::Regressions, None, true)]);

        let args = ci_args(&["bhf", "src", "--policy", "p.json", "--pr-gate", "all"]);
        let gates = finding_gates(
            &args,
            &one_finding("low"),
            &ActionabilityBuckets::default(),
            &Default::default(),
        );
        assert_eq!(
            gates,
            vec![Gate::new(GateKind::PrGate, Some("all".to_owned()), true)]
        );
    }

    #[test]
    fn a_fail_on_actionability_given_beside_a_policy_is_applied() {
        let args = ci_args(&[
            "bhf",
            "src",
            "--policy",
            "p.json",
            "--fail-on-actionability",
            "likely",
        ]);
        let mut actionability = ActionabilityBuckets::default();
        actionability
            .by_verdict_and_confidence
            .insert(("likely_reachable".to_owned(), "high".to_owned()), 1);
        let gates = finding_gates(
            &args,
            &one_finding("low"),
            &actionability,
            &Default::default(),
        );
        assert_eq!(
            gates,
            vec![Gate::new(
                GateKind::FailOnActionability,
                Some("likely".to_owned()),
                true
            )]
        );
    }

    #[test]
    fn without_a_policy_the_default_fail_on_and_never_gate_still_apply() {
        let gates = finding_gates(
            &ci_args(&["bhf", "src"]),
            &one_finding("info"),
            &ActionabilityBuckets::default(),
            &reproduced("F-1"),
        );
        assert_eq!(
            gates.iter().map(|g| (g.kind, g.failed)).collect::<Vec<_>>(),
            vec![(GateKind::FailOn, true), (GateKind::Regressions, true)]
        );
        // `never` only annotates: no finding and no regression fails it.
        let gates = finding_gates(
            &ci_args(&["bhf", "src", "--pr-gate", "never"]),
            &one_finding("critical"),
            &ActionabilityBuckets::default(),
            &reproduced("F-1"),
        );
        assert_eq!(
            gates,
            vec![Gate::new(GateKind::PrGate, Some("never".to_owned()), false)]
        );
        assert_eq!(exit_code_from_gates(&gates), 0);
    }

    #[test]
    fn the_summary_and_ci_json_name_each_gates_result() {
        let gates = vec![
            Gate::new(GateKind::FailOn, Some("any".to_owned()), true),
            Gate::new(GateKind::Regressions, None, false),
            policy_result(true),
        ];
        assert_eq!(
            render_gates(&gates),
            "- Gate `--fail-on any`: **failed**\n\
             - Gate regression replay: passed\n\
             - Gate `--policy`: **failed** (policy_threshold)\n"
        );
        assert_eq!(
            format_gates(&gates),
            "gates: --fail-on any failed, regression replay passed, --policy failed"
        );
        let json = gates_json(&gates);
        assert_eq!(json[0]["gate"], "fail_on");
        assert_eq!(json[0]["setting"], "any");
        assert_eq!(json[0]["failed"], true);
        assert_eq!(json[1]["gate"], "regressions");
        assert_eq!(json[1]["failed"], false);
        assert_eq!(json[2]["gate"], "policy");
        assert_eq!(json[2]["reasons"][0], "policy_threshold");
    }

    #[test]
    fn the_dashboard_gate_fails_when_a_gate_beside_the_policy_fails() {
        let mut dashboard = serde_json::json!({
            "gate": { "failed": false, "reason": "none", "reasons": [] }
        });
        let gates = vec![
            Gate::new(GateKind::FailOn, Some("any".to_owned()), true),
            Gate::new(GateKind::Regressions, None, true),
            policy_result(false),
        ];
        merge_gates_into_dashboard(&mut dashboard, &gates);
        assert_eq!(dashboard["gate"]["failed"], true);
        assert_eq!(dashboard["gate"]["reason"], "multiple");
        assert_eq!(
            dashboard["gate"]["reasons"],
            serde_json::json!(["fail_on", "regression_reproduced"])
        );
        assert_eq!(dashboard["gate"]["gates"][2]["gate"], "policy");

        let mut dashboard = serde_json::json!({
            "gate": { "failed": true, "reason": "policy_threshold", "reasons": ["policy_threshold"] }
        });
        merge_gates_into_dashboard(
            &mut dashboard,
            &[
                Gate::new(GateKind::FailOn, Some("high".to_owned()), false),
                policy_result(true),
            ],
        );
        assert_eq!(dashboard["gate"]["failed"], true);
        assert_eq!(dashboard["gate"]["reason"], "policy_threshold");
    }

    #[test]
    fn resolve_changed_scope_empty_when_no_scoping_requested() {
        use clap::Parser as _;
        #[derive(clap::Parser)]
        struct T {
            #[command(flatten)]
            ci: CiArgs,
        }
        let t = T::try_parse_from(["bhf", "src"]).expect("parses");
        assert!(resolve_changed_scope(&t.ci).unwrap().is_empty());
    }
}
