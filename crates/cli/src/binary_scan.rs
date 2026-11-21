// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Debug, clap::Args)]
pub struct BinaryScanArgs {
    /// Binary file, firmware blob, or directory tree to inventory.
    pub path: PathBuf,

    /// Output directory for binary-inventory.json.
    #[arg(long, default_value = "bhf_work/binary")]
    pub out: PathBuf,

    /// Skip files and archive members larger than this many bytes.
    #[arg(long)]
    pub max_bytes: Option<u64>,

    /// Offline CVE database to match the inventoried components against.
    #[arg(long)]
    pub cve_db: Option<PathBuf>,

    /// A `bhf binary adapter` report of one of the scanned binaries:
    /// its inventory entry gets an `adapter` object with the functions ranked
    /// as fuzz entry points, the dictionary tokens and the candidate
    /// persistent address. The report is matched by the binary's SHA-256.
    #[arg(long)]
    pub adapter_report: Option<PathBuf>,
}

pub fn run(args: BinaryScanArgs) -> i32 {
    let hints = match args.adapter_report.as_deref() {
        Some(report) => match crate::binary_adapter::hints::load(report) {
            Ok(hints) => Some((report.to_path_buf(), hints)),
            Err(error) => {
                bhfeprintln!("--adapter-report: {error}");
                return 1;
            }
        },
        None => None,
    };
    let options = binary_analysis::BinaryScanOptions {
        root: args.path,
        out_dir: args.out,
        max_bytes: args.max_bytes,
        cve_db_path: args.cve_db,
    };
    match binary_analysis::write_inventory(&options) {
        Ok(summary) => {
            println!(
                "binary scan: {} files inventoried, {} skipped, {} containers",
                summary.files, summary.skipped, summary.containers,
            );
            if summary.secret_count > 0 {
                println!(
                    "  ! {} hardcoded secret(s) across {} binaries",
                    summary.secret_count, summary.binaries_with_secrets,
                );
            }
            if summary.malware_indicator_count > 0 {
                println!(
                    "  !! {} malware indicator(s) (credential-store / exfiltration strings)",
                    summary.malware_indicator_count,
                );
            }
            if summary.high_priority > 0 {
                println!(
                    "  ! {} high-priority binaries (secrets / risky imports / CVEs)",
                    summary.high_priority,
                );
            }
            if let Some((report, hints)) = &hints {
                match attach_adapter_hints(&summary.json_path, report, hints) {
                    Ok(binary) => println!(
                        "  adapter report: {} ranked function(s) in {binary}{}",
                        hints.ranking.len(),
                        hints
                            .ranking
                            .first()
                            .map(|top| format!(", first {} at {}", top.name, top.address))
                            .unwrap_or_default(),
                    ),
                    Err(error) => {
                        bhfeprintln!("--adapter-report: {error}");
                        return 1;
                    }
                }
            }
            println!("json: {}", summary.json_path.display());
            0
        }
        Err(error) => {
            bhfeprintln!("{error:#}");
            1
        }
    }
}

/// Add the adapter report's hints to the inventory entry of the binary it
/// analyzed, found by the report's `target_sha256`; that binary's path.
fn attach_adapter_hints(
    inventory: &Path,
    report: &Path,
    hints: &crate::binary_adapter::hints::AdapterHints,
) -> Result<String, String> {
    let read = |path: &Path| -> Result<Value, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {e}", path.display()))
    };
    let digest = read(report)?["target_sha256"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("{} records no target_sha256", report.display()))?;
    let mut value = read(inventory)?;
    let entry = value["binaries"]
        .as_array_mut()
        .and_then(|binaries| {
            binaries
                .iter_mut()
                .find(|binary| binary["sha256"].as_str() == Some(digest.as_str()))
        })
        .ok_or_else(|| {
            format!(
                "{} is of a binary with SHA-256 {digest}, which this scan did not inventory",
                report.display()
            )
        })?;
    entry["adapter"] = hints.provenance(report);
    let binary = entry["path"].as_str().unwrap_or_default().to_owned();
    std::fs::write(
        inventory,
        serde_json::to_vec_pretty(&value).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("write {}: {e}", inventory.display()))?;
    Ok(binary)
}
