// SPDX-License-Identifier: Apache-2.0

use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub command: PolicyCommand,
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Print a policy's decisions and its SHA-256 hash
    ///
    /// The decisions are its disabled rules, denied external tools, allowed
    /// runners, sandbox requirement and CI gates.
    Explain(ExplainArgs),
    /// Apply a policy to one finding record and print the decision
    ///
    /// The decision includes any waiver that matches the finding. No scan
    /// runs.
    DryRun(DryRunArgs),
    /// Check a policy-as-code JSON file and print a validation summary.
    Validate(ValidateArgs),
}

#[derive(Debug, Args)]
pub struct ExplainArgs {
    /// Policy JSON file.
    pub path: PathBuf,
    /// Write the JSON summary to this path instead of stdout.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct DryRunArgs {
    /// Policy JSON file.
    pub path: PathBuf,
    /// The finding record (JSON) to judge.
    #[arg(long)]
    pub finding: PathBuf,
    /// Write the JSON decision to this path instead of stdout.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ValidateArgs {
    /// Policy JSON file.
    pub path: PathBuf,

    /// Write the JSON validation summary to this path instead of stdout.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

pub fn run(args: PolicyArgs) -> i32 {
    match args.command {
        PolicyCommand::Explain(args) => {
            write_summary(governance::explain_policy_file(&args.path), args.out)
        }
        PolicyCommand::DryRun(args) => write_summary(
            governance::policy_dry_run_file(&args.path, &args.finding),
            args.out,
        ),
        PolicyCommand::Validate(args) => validate(args),
    }
}

fn validate(args: ValidateArgs) -> i32 {
    match governance::validate_policy_file(&args.path) {
        Ok(summary) => {
            if let Some(out) = args.out {
                if let Err(error) = governance::write_json(&out, &summary) {
                    bhfeprintln!("{error:#}");
                    return 1;
                }
            } else {
                match serde_json::to_string_pretty(&summary) {
                    Ok(json) => println!("{json}"),
                    Err(error) => {
                        bhfeprintln!("serialize policy validation: {error}");
                        return 1;
                    }
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

fn write_summary(
    summary: Result<serde_json::Value, governance::GovernanceError>,
    out: Option<PathBuf>,
) -> i32 {
    match summary {
        Ok(summary) => {
            if let Some(out) = out {
                if let Err(error) = governance::write_json(&out, &summary) {
                    bhfeprintln!("{error:#}");
                    return 1;
                }
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&summary).unwrap_or_default()
                );
            }
            0
        }
        Err(error) => {
            bhfeprintln!("{error:#}");
            1
        }
    }
}
