// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

#[derive(Debug, clap::Args)]
#[command(args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
pub struct ExportArgs {
    /// `bhf export regression`: the work dir's harnesses, corpora and
    /// findings as a standalone regression suite.
    #[command(subcommand)]
    pub command: Option<ExportCommand>,

    /// Work directory to inventory: its results/ indexes, reports, SBOM and
    /// static reports, auto/run.json, and each finding's record, inputs and
    /// sanitizer log.
    #[arg(long, default_value = "bhf_work")]
    pub work_dir: PathBuf,

    /// Where to write the manifest JSON (each artifact's kind, path, size and
    /// SHA-256).
    #[arg(long, required = true)]
    pub out: Option<PathBuf>,

    /// Also copy every listed artifact into this directory, with the manifest
    /// as `export-manifest.json`, ready to carry to an air-gapped host.
    #[arg(long)]
    pub bundle_dir: Option<PathBuf>,

    /// Policy file to include in the bundle manifest.
    #[arg(long)]
    pub policy: Option<PathBuf>,

    /// Update pack manifest to include. Repeat for multiple packs.
    #[arg(long = "update-pack")]
    pub update_packs: Vec<PathBuf>,

    /// Audit JSONL log to include.
    #[arg(long)]
    pub audit_log: Option<PathBuf>,

    /// Runner manifest to include.
    #[arg(long)]
    pub runner_manifest: Option<PathBuf>,

    /// Runner assignment plan to include.
    #[arg(long)]
    pub runner_plan: Option<PathBuf>,

    /// An artifact kind the export must contain, such as `sarif` or
    /// `findings_json`; bhf exits 1 when one is missing. Repeatable.
    #[arg(long = "require-artifact")]
    pub required_artifacts: Vec<String>,
}

#[derive(Debug, clap::Subcommand)]
pub enum ExportCommand {
    /// Write a standalone regression suite of a work directory's harnesses
    ///
    /// The suite holds each harness's sources and build context, its corpus
    /// and its findings' minimized inputs, and a `run.sh` that builds the
    /// harnesses against the scanned tree and fails when an input crashes.
    Regression(crate::export_regression::RegressionArgs),
}

pub fn run(args: ExportArgs) -> i32 {
    if let Some(ExportCommand::Regression(regression)) = args.command {
        return crate::export_regression::run(regression);
    }
    let Some(out) = args.out else {
        bhfeprintln!("error: bhf export needs --out (or a subcommand: regression)");
        return 2;
    };
    let options = governance::ExportOptions {
        work_dir: args.work_dir,
        out,
        bundle_dir: args.bundle_dir,
        policy: args.policy,
        update_packs: args.update_packs,
        audit_log: args.audit_log,
        runner_manifest: args.runner_manifest,
        runner_plan: args.runner_plan,
        required_artifacts: args.required_artifacts,
    };

    match governance::write_export_manifest(&options) {
        Ok(manifest) => {
            let artifacts = manifest
                .pointer("/counts/artifacts")
                .and_then(|value| value.as_u64())
                .unwrap_or(0);
            println!("export manifest: {artifacts} artifacts");
            if manifest
                .pointer("/required_artifacts/missing")
                .and_then(|value| value.as_array())
                .is_some_and(|missing| !missing.is_empty())
            {
                1
            } else {
                0
            }
        }
        Err(error) => {
            bhfeprintln!("{error:#}");
            1
        }
    }
}
