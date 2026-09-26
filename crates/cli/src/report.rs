// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

#[path = "report_comparison.rs"]
mod comparison;

#[derive(Debug, clap::Args)]
pub struct ReportArgs {
    /// Run identifier used for output file names.
    #[arg(long, default_value = "last")]
    pub run: String,

    /// Findings root containing one subdirectory per finding.
    #[arg(long, default_value = "findings")]
    pub findings: PathBuf,

    /// Report output directory.
    #[arg(long, default_value = "reports")]
    pub out: PathBuf,

    /// Learned confidence model produced by bhf model train.
    #[arg(long)]
    pub model: Option<PathBuf>,

    /// Also emit a SARIF 2.1.0 report.
    #[arg(long)]
    pub sarif: bool,

    /// Also emit a JUnit-style XML report.
    #[arg(long)]
    pub junit: bool,

    /// Also emit a CSV report (one row per finding) for spreadsheets / SCA.
    #[arg(long)]
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
    // Read the baseline before writing the current report: a rolling "last"
    // report may intentionally use the same output pathname.
    let baseline = match args.baseline.as_deref().map(comparison::load_snapshot).transpose() {
        Ok(value) => value,
        Err(error) => { bhfeprintln!("error: {error}"); return 1; }
    };
    if args.triage.is_some() && baseline.is_none() {
        bhfeprintln!("error: --triage requires --baseline");
        return 1;
    }
    let decisions = match comparison::load_triage(args.triage.as_deref()) {
        Ok(value) => value,
        Err(error) => { bhfeprintln!("error: {error}"); return 1; }
    };
    let options = bhf_report::ReportOptions::new(args.findings, args.out)
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
                    comparison::write(&comparison::compare(&baseline, &current, &decisions), &summary.json_path)
                });
                match result {
                    Ok(paths) => for path in paths { println!("COMPARISON {}", path.display()); },
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
            if let Some(path) = summary.sarif_path { println!("SARIF {}", path.display()); }
            if let Some(path) = summary.junit_path { println!("JUNIT {}", path.display()); }
            if let Some(path) = summary.csv_path { println!("CSV {}", path.display()); }
            0
        }
        Err(error) => {
            bhfeprintln!("error: {error}");
            1
        }
    }
}
