// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

#[path = "report_comparison.rs"]
mod comparison;

#[derive(Debug, clap::Args)]
pub struct ReportArgs {
    /// Run name used in the output file names.
    #[arg(long, default_value = "last")]
    pub run: String,

    /// Work directory whose results/ to rebuild (work-dir mode, the default).
    #[arg(long = "work-dir", default_value = "bhf_work", conflicts_with_all = ["findings", "out"])]
    pub work_dir: PathBuf,

    /// Explicit mode: a findings directory with one subdirectory per finding.
    #[arg(long)]
    pub findings: Option<PathBuf>,

    /// Explicit mode: report output directory.
    #[arg(long)]
    pub out: Option<PathBuf>,

    /// Confidence model from `bhf model train`, used to score the findings.
    #[arg(long)]
    pub model: Option<PathBuf>,

    /// Explicit mode: also write a SARIF 2.1.0 report (`<run>.sarif` in
    /// `--out`). Work-dir mode always writes `results/findings.sarif`.
    #[arg(long)]
    pub sarif: bool,

    /// Also write a JUnit XML report (`<run>.junit.xml`, in `--out`, or in
    /// `results/report/` in work-dir mode). A switch: it takes no path.
    #[arg(long)]
    pub junit: bool,

    /// Explicit mode: also write a CSV report (`<run>.csv` in `--out`).
    /// Work-dir mode always writes `results/findings.csv`.
    #[arg(long)]
    pub csv: bool,

    /// Work-dir mode: also write a GitLab SAST security report
    /// (`results/gl-sast-report.json`, format 15.2.1), for a GitLab job's
    /// `artifacts:reports:sast`. A switch: it takes no path.
    #[arg(long = "gitlab-sast")]
    pub gitlab_sast: bool,

    /// In the Markdown report, list each cluster's other findings under its
    /// representative finding.
    #[arg(long)]
    pub collapse_clusters: bool,

    /// Compare with a saved bhf.report.v2 JSON report, and write JSON, Markdown
    /// and a self-contained HTML page of the new, persistent and no longer
    /// observed findings.
    #[arg(long)]
    pub baseline: Option<PathBuf>,

    /// Show the triage decisions of a bhf.triage.v1 JSON file in the
    /// comparison. Every finding and its security verdict stay as they are.
    #[arg(long, requires = "baseline")]
    pub triage: Option<PathBuf>,

    /// Work-dir mode only: before rebuilding results/, replay each C/C++
    /// sanitizer finding that has no sanitizer.log (such as findings migrated
    /// from a bhf 0.2.x work dir) against its harness, and when the replay is
    /// the recorded crash, write its sanitizer.log, crash frames and memory
    /// access into the finding. Findings whose harness is gone, that now
    /// crash elsewhere, or whose replay is unsymbolized, are listed and left
    /// as they were. Runtime findings whose harness records comparisons also
    /// get the comparison evidence of their input (`gates` in finding.json).
    #[arg(long, conflicts_with_all = ["findings", "out"])]
    pub backfill: bool,
}

pub fn run(args: ReportArgs) -> i32 {
    match (args.findings.clone(), args.out.clone()) {
        (None, None) => run_work_dir(args),
        (findings, out) => run_explicit(
            args,
            findings.unwrap_or_else(|| PathBuf::from("findings")),
            out.unwrap_or_else(|| PathBuf::from("reports")),
        ),
    }
}

/// Default mode. The dispatcher has already rebuilt results/ before calling
/// this, so here we only add the optional legacy artifacts: the
/// bhf.report.v2 snapshot (needed by --baseline workflows), JUnit, and the
/// comparison, all under results/report/.
fn run_work_dir(args: ReportArgs) -> i32 {
    if args.gitlab_sast {
        let dest = corpus::layout::results_dir(&args.work_dir).join(GITLAB_SAST_REPORT);
        match write_gitlab_sast(&args.work_dir, &dest) {
            Ok(()) => println!("GITLAB_SAST {}", dest.display()),
            Err(error) => {
                bhfeprintln!("error: {error}");
                return 1;
            }
        }
    }
    if !(args.junit || args.baseline.is_some() || args.model.is_some()) {
        return 0;
    }
    let findings = corpus::layout::findings_dir(&args.work_dir);
    let out = corpus::layout::results_dir(&args.work_dir).join("report");
    // `ReportOptions::new` errors with `MissingFindingsDir` on a missing
    // findings root; in work-dir mode an empty findings set is valid.
    let _ = std::fs::create_dir_all(&findings);
    run_explicit(args, findings, out)
}

/// The GitLab SAST report's file name, as GitLab's analyzers write it.
pub(crate) const GITLAB_SAST_REPORT: &str = "gl-sast-report.json";

/// Write the GitLab SAST report (#320) of `work_dir`'s rebuilt
/// `results/findings.json` to `dest`. The scan's times are the run's, from
/// `auto/run.json`, else the document's.
pub(crate) fn write_gitlab_sast(work_dir: &Path, dest: &Path) -> Result<(), String> {
    let path = corpus::layout::results_dir(work_dir).join("findings.json");
    let doc: results::model::FindingsDocument = serde_json::from_slice(
        &std::fs::read(&path).map_err(|error| format!("read {}: {error}", path.display()))?,
    )
    .map_err(|error| format!("parse {}: {error}", path.display()))?;
    let run: Option<serde_json::Value> = std::fs::read(work_dir.join("auto").join("run.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok());
    let time = |key: &str| {
        run.as_ref()
            .and_then(|run| run.get(key))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| doc.generated_at.clone())
    };
    let report = results::render::gitlab::render_gitlab_sast(
        &doc,
        &time("started_at"),
        &time("finished_at"),
    );
    if let Some(parent) = dest.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(dest, serde_json::to_vec_pretty(&report).unwrap_or_default())
        .map_err(|error| format!("write {}: {error}", dest.display()))
}

fn run_explicit(args: ReportArgs, findings: PathBuf, out: PathBuf) -> i32 {
    // Read the baseline before writing the current report: a rolling "last"
    // report may intentionally use the same output pathname.
    let baseline = match args
        .baseline
        .as_deref()
        .map(comparison::load_snapshot)
        .transpose()
    {
        Ok(value) => value,
        Err(error) => {
            bhfeprintln!("error: {error}");
            return 1;
        }
    };
    if args.triage.is_some() && baseline.is_none() {
        bhfeprintln!("error: --triage requires --baseline");
        return 1;
    }
    let decisions = match comparison::load_triage(args.triage.as_deref()) {
        Ok(value) => value,
        Err(error) => {
            bhfeprintln!("error: {error}");
            return 1;
        }
    };
    let options = bhf_report::ReportOptions::new(findings, out)
        .with_run_id(args.run)
        .with_sarif(args.sarif)
        .with_junit(args.junit)
        .with_csv(args.csv)
        .with_collapse_clusters(args.collapse_clusters);
    let options = if let Some(model) = args.model {
        options.with_confidence_model_path(model)
    } else {
        options
    };
    match bhf_report::write_reports(options) {
        Ok(summary) => {
            if let Some(baseline) = baseline {
                let result = comparison::load_snapshot(&summary.json_path).and_then(|current| {
                    comparison::write(
                        &comparison::compare(&baseline, &current, &decisions),
                        &summary.json_path,
                    )
                });
                match result {
                    Ok(paths) => {
                        for path in paths {
                            println!("COMPARISON {}", path.display());
                        }
                    }
                    Err(error) => {
                        bhfeprintln!("error: reports generated but comparison failed: {error}");
                        return 1;
                    }
                }
            }
            println!(
                "REPORT run={} findings={} json={} markdown={}",
                summary.run_id,
                summary.findings_count,
                summary.json_path.display(),
                summary.markdown_path.display()
            );
            if let Some(path) = summary.sarif_path {
                println!("SARIF {}", path.display());
            }
            if let Some(path) = summary.junit_path {
                println!("JUNIT {}", path.display());
            }
            if let Some(path) = summary.csv_path {
                println!("CSV {}", path.display());
            }
            0
        }
        Err(error) => {
            bhfeprintln!("error: {error}");
            1
        }
    }
}
