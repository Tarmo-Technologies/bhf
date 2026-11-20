// SPDX-License-Identifier: Apache-2.0

use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub command: AuditCommand,
}

#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// Append one event to a JSONL audit log
    ///
    /// The log is created if missing. bhf prints the record it appended, which
    /// carries the next sequence number.
    Append(AppendArgs),
    /// Read a JSONL audit log and print its events and their count.
    Read(ReadArgs),
}

#[derive(Debug, Args)]
pub struct AppendArgs {
    /// The JSONL audit log to append to.
    #[arg(long)]
    pub log: PathBuf,
    /// The event name to record.
    #[arg(long)]
    pub event: String,
    /// Who did it.
    #[arg(long)]
    pub actor: String,
    /// The actor's role.
    #[arg(long)]
    pub role: String,
    /// The project the event belongs to.
    #[arg(long)]
    pub project: Option<String>,
    /// Write the appended record as JSON to this path instead of stdout.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ReadArgs {
    /// The JSONL audit log to read.
    #[arg(long)]
    pub log: PathBuf,
    /// Write the JSON summary to this path instead of stdout.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

pub fn run(args: AuditArgs) -> i32 {
    match args.command {
        AuditCommand::Append(args) => {
            let event = governance::append_audit_event(
                &args.log,
                &args.event,
                &args.actor,
                &args.role,
                args.project.as_deref(),
            );
            write_summary(event, args.out)
        }
        AuditCommand::Read(args) => write_summary(governance::read_audit_log(&args.log), args.out),
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
