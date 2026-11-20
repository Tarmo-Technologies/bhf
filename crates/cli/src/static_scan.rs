// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

#[derive(Debug, clap::Args)]
pub struct StaticScanArgs {
    /// Source or project root to scan.
    pub path: PathBuf,

    /// Work directory; without --out, output goes to <work-dir>/results/static
    /// and results/ is rebuilt.
    #[arg(long = "work-dir", default_value = "bhf_work")]
    pub work_dir: PathBuf,

    /// Write native reports here instead, and do not update results/.
    #[arg(long)]
    pub out: Option<PathBuf>,

    /// JSON suppression file: each entry suppresses one rule at one path and
    /// line.
    #[arg(long)]
    pub suppressions: Option<PathBuf>,

    /// Prior static-report.json baseline to compare against.
    #[arg(long)]
    pub baseline: Option<PathBuf>,

    /// Policy-as-code JSON file; its enabled and disabled rules apply.
    #[arg(long)]
    pub policy: Option<PathBuf>,

    /// Report only this rule id. Repeatable.
    #[arg(long = "enable-rule")]
    pub enabled_rules: Vec<String>,

    /// Suppress this rule id before the baseline comparison. Repeatable.
    #[arg(long = "disable-rule")]
    pub disabled_rules: Vec<String>,

    /// Also write static-report.sarif.
    #[arg(long)]
    pub sarif: bool,

    /// Write a per-language line count (LANGUAGE, FILES, TOTAL, COMMENTS,
    /// BLANKS, SLOC). A relative path lands in the `--out` report
    /// directory, beside static-report.json; an absolute path is written as given.
    /// A `.json` extension emits JSON; anything else emits an aligned text table.
    /// It skips the same dependency and build trees as the scan and strips
    /// comments per language, so vendored, `node_modules` and `.venv` code is
    /// not counted.
    #[arg(long)]
    pub sloc: Option<PathBuf>,

    /// Exit non-zero when an active finding meets or exceeds this severity.
    #[arg(long, value_enum)]
    pub fail_on: Option<FailOnSeverity>,

    /// Incremental scan: analyze only the files changed since this git
    /// revision (a tag, branch or SHA).
    #[arg(long)]
    pub since: Option<String>,

    /// Most resident memory for bhf's static-analysis process, in MiB. When it
    /// is reached, the scanner takes on no more files or interprocedural work
    /// and records an analysis gap, so the host does not run out of memory.
    /// Default: the smaller of 80% of the host's available memory and 70% of
    /// the cgroup memory limit.
    #[arg(long = "max-memory-mb", value_name = "MB")]
    pub max_memory_mb: Option<u64>,

    /// Parallel static-analysis workers. Lower it on a host short of memory:
    /// each worker can hold a source file and its parsed copy at once.
    #[arg(long, value_name = "N")]
    pub jobs: Option<usize>,

    /// Also run the external analyzers that are installed and that the license
    /// profile allows (gosec, Bandit, semgrep, GNATcheck), as subprocesses, and
    /// write their findings, such as XSS, CSRF and framework rules that bhf's
    /// own rules do not cover, to `<out>/external-findings.json`. The profile
    /// comes from BHF_PROFILE and is `external-tools` when that is unset; bhf
    /// links none of these tools.
    #[arg(long)]
    pub external_tools: bool,
}

impl StaticScanArgs {
    /// (output dir, whether this run feeds results/)
    pub fn output_target(&self) -> (PathBuf, bool) {
        match &self.out {
            Some(out) => (out.clone(), false),
            None => (corpus::layout::static_dir(&self.work_dir), true),
        }
    }
}

pub fn run(args: StaticScanArgs) -> i32 {
    let (out_dir, into_results) = args.output_target();
    if !into_results {
        bhfeprintln!("note: --out given; results/ was not updated");
    }
    let fail_on = args.fail_on;
    // Plumb the incremental `--since <rev>` scope to the engine (which restricts
    // the file walk to the git diff). Env-carried to avoid threading it through
    // every StaticScanOptions construction site.
    if let Some(rev) = &args.since {
        std::env::set_var("BHF_SINCE_REV", rev);
    }
    if let Some(mb) = args.max_memory_mb {
        std::env::set_var("BHF_MAX_MEMORY_KB", mb.saturating_mul(1024).to_string());
    }
    if let Some(jobs) = args.jobs {
        std::env::set_var("BHF_STATIC_JOBS", jobs.max(1).to_string());
    }
    if let Some(sloc_path) = &args.sloc {
        // A relative path lands in the report output dir (`--out`), beside
        // static-report.json — not the caller's CWD; an absolute path is honored.
        let resolved = if sloc_path.is_absolute() {
            sloc_path.clone()
        } else {
            out_dir.join(sloc_path)
        };
        if let Err(code) = write_sloc_report(&args.path, &resolved) {
            return code;
        }
    }
    let external_tools = args.external_tools;
    let external_root = args.path.clone();
    let external_out = out_dir.clone();
    let options = static_analysis::StaticScanOptions {
        root: args.path,
        out_dir,
        suppressions_path: args.suppressions,
        baseline_path: args.baseline,
        policy_path: args.policy,
        enabled_rules: args.enabled_rules.into_iter().collect(),
        disabled_rules: args.disabled_rules.into_iter().collect(),
        // In results mode SARIF always feeds the aggregated results/ SARIF.
        emit_sarif: args.sarif || into_results,
    };

    match static_analysis::write_static_scan(&options) {
        Ok(summary) => {
            println!(
                "static scan: {} findings, {} suppressed, {} resolved",
                summary.findings_count, summary.suppressed_count, summary.resolved_count
            );
            println!("json: {}", summary.json_path.display());
            println!("markdown: {}", summary.markdown_path.display());
            if let Some(path) = summary.sarif_path {
                println!("sarif: {}", path.display());
            }
            let mut external_gate_trips = false;
            if external_tools {
                external_gate_trips = run_external_tools(&external_root, &external_out, fail_on);
            }
            if let Some(threshold) = fail_on {
                if severity_gate_trips(&summary.by_severity, threshold) || external_gate_trips {
                    return 1;
                }
            }
            0
        }
        Err(error) => {
            bhfeprintln!("{error:#}");
            1
        }
    }
}

/// Compute the per-language SLOC breakdown for `root` and write it to `out`.
/// `.json` extension → JSON; otherwise an aligned text table. Returns `Err(code)`
/// on failure so the caller can exit non-zero.
pub(crate) fn write_sloc_report(root: &std::path::Path, out: &std::path::Path) -> Result<(), i32> {
    let report = static_analysis::sloc_report(root).map_err(|error| {
        bhfeprintln!("sloc: {error:#}");
        1
    })?;
    let is_json = out
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"));
    let body = if is_json {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => format!("{json}\n"),
            Err(error) => {
                bhfeprintln!("sloc: {error}");
                return Err(1);
            }
        }
    } else {
        static_analysis::render_sloc_table(&report)
    };
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    if let Err(error) = std::fs::write(out, body) {
        bhfeprintln!("sloc: cannot write {}: {error}", out.display());
        return Err(1);
    }
    println!(
        "sloc: {} language(s), {} code line(s) → {}",
        report.languages.len(),
        report.total.code_lines,
        out.display()
    );
    Ok(())
}

/// Run the profile-allowed external analyzers over `root` and write their findings
/// to `<out>/external-findings.json` — breadth (XSS/CSRF and framework rules) with
/// no fuzzing. Returns whether the findings trip the `--fail-on` severity gate.
fn run_external_tools(
    root: &std::path::Path,
    out: &std::path::Path,
    fail_on: Option<FailOnSeverity>,
) -> bool {
    let profile = resolve_external_profile();
    let findings = crate::auto::external_tools::collect_external_findings(root, profile);
    if profile == config::Profile::StrictPermissive {
        bhfeprintln!(
            "external tools: profile 'strict-permissive' allows no analyzers — set BHF_PROFILE=external-tools"
        );
    }
    let mut by_tool: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    let mut with_cwe = 0usize;
    let mut gate = false;
    let json: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            *by_tool.entry(f.tool.as_str()).or_default() += 1;
            if f.cwe.is_some() {
                with_cwe += 1;
            }
            if let Some(threshold) = fail_on {
                if severity_rank(&f.severity) >= severity_threshold_rank(threshold) {
                    gate = true;
                }
            }
            serde_json::json!({
                "tool": f.tool,
                "rule": f.rule,
                "cwe": f.cwe,
                "severity": f.severity,
                "path": f.path,
                "line": f.line,
                "message": f.message,
            })
        })
        .collect();
    let path = out.join("external-findings.json");
    let _ = std::fs::create_dir_all(out);
    if let Ok(bytes) = serde_json::to_vec_pretty(&serde_json::json!({
        "schema": "bhf.external-findings.v1",
        "profile": profile.as_str(),
        "findings": json,
    })) {
        let _ = std::fs::write(&path, bytes);
    }
    let summary: Vec<String> = by_tool.iter().map(|(t, n)| format!("{t}:{n}")).collect();
    println!(
        "external tools ({}): {} finding(s) [{}], {} with CWE — {}",
        profile.as_str(),
        findings.len(),
        summary.join(" "),
        with_cwe,
        path.display(),
    );
    gate
}

/// The license profile for `--external-tools`: an explicit `BHF_PROFILE` wins;
/// otherwise the flag itself opts into `external-tools` (the permissive analyzers),
/// mirroring `auto` while making the flag do something useful by default.
fn resolve_external_profile() -> config::Profile {
    std::env::var("BHF_PROFILE")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(config::Profile::ExternalTools)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum FailOnSeverity {
    Low,
    Medium,
    High,
    Critical,
}

fn severity_gate_trips(
    buckets: &std::collections::BTreeMap<String, usize>,
    threshold: FailOnSeverity,
) -> bool {
    buckets.iter().any(|(severity, count)| {
        *count > 0 && severity_rank(severity) >= severity_threshold_rank(threshold)
    })
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn severity_threshold_rank(threshold: FailOnSeverity) -> u8 {
    match threshold {
        FailOnSeverity::Low => 1,
        FailOnSeverity::Medium => 2,
        FailOnSeverity::High => 3,
        FailOnSeverity::Critical => 4,
    }
}
