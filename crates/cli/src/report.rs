// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

#[path = "report_comparison.rs"]
mod comparison;

#[derive(Debug, clap::Args)]
pub struct ReportArgs {
    /// Run identifier used for output file names.
    #[arg(long, default_value = "last")]
    pub run: String,

    /// Work directory whose results/ to rebuild (the default mode).
    #[arg(long = "work-dir", default_value = "bhf_work", conflicts_with_all = ["findings", "out"])]
    pub work_dir: PathBuf,

    /// Explicit mode: findings root containing one subdirectory per finding.
    #[arg(long)]
    pub findings: Option<PathBuf>,

    /// Explicit mode: report output directory.
    #[arg(long)]
    pub out: Option<PathBuf>,

    /// Learned confidence model produced by bhf model train.
    #[arg(long)]
    pub model: Option<PathBuf>,

    /// Explicit mode only; work-dir mode always writes results/findings.{sarif,csv}.
    #[arg(long, hide = true)]
    pub sarif: bool,

    /// Also emit a JUnit-style XML report.
    #[arg(long)]
    pub junit: bool,

    /// Explicit mode only; work-dir mode always writes results/findings.{sarif,csv}.
    #[arg(long, hide = true)]
    pub csv: bool,

    /// Collapse non-representative findings inside each cluster under
    /// their representative in the Markdown report.
    #[arg(long)]
    pub collapse_clusters: bool,

    /// Compare against a saved bhf.report.v2 JSON report; emit JSON, Markdown,
    /// and standalone offline HTML showing new, persistent, and unobserved issues.
    #[arg(long)]
    pub baseline: Option<PathBuf>,

    /// Carry operator decisions from a bhf.triage.v1 JSON file into the comparison.
    /// Never suppresses findings or changes their security verdicts.
    #[arg(long, requires = "baseline")]
    pub triage: Option<PathBuf>,
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
