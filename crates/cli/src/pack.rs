// SPDX-License-Identifier: Apache-2.0

use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct PackArgs {
    #[command(subcommand)]
    pub command: PackCommand,
}

#[derive(Debug, Subcommand)]
pub enum PackCommand {
    /// Write an update pack manifest that lists each item with its SHA-256
    ///
    /// With --signing-key the manifest is signed with Ed25519. The same inputs
    /// give the same manifest.
    Create(CreateArgs),
    /// Print an update pack manifest's contents without installing it.
    Inspect(InspectArgs),
    /// Verify an update pack, then copy its items into a local directory.
    Install(InstallArgs),
    /// Check an update pack's item hashes and signature, and a policy's limits
    /// on it.
    Verify(VerifyArgs),
    /// Generate an Ed25519 signing key pair: the private key as PKCS#8 DER,
    /// the public key as raw hex.
    Keygen(KeygenArgs),
    /// Sign a distribution archive with an Ed25519 key, for checking with OpenSSL
    ///
    /// Prints the archive's SHA-256.
    SignArchive(SignArchiveArgs),
    /// Build an advisory database for `bhf sbom --vuln-db` from OSV records
    ///
    /// Takes an OSV ecosystem export (unzipped) or single record files.
    /// Malformed records are reported and skipped.
    ImportOsv(ImportFeedArgs),
    /// Build an advisory database for `bhf sbom --vuln-db` from NVD CVE JSON 2.0 files
    ///
    /// Takes yearly feeds or API responses, and records each vulnerable CPE
    /// match with its version range. Malformed records are reported and
    /// skipped.
    ImportNvd(ImportFeedArgs),
}

#[derive(Debug, Args)]
pub struct ImportFeedArgs {
    /// Feed files, or directories searched for `.json` files.
    #[arg(required = true)]
    pub inputs: Vec<PathBuf>,
    /// The advisory database to write.
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Debug, Args)]
pub struct SignArchiveArgs {
    /// The archive to sign, exactly as it will be distributed.
    #[arg(long)]
    pub archive: PathBuf,
    /// Ed25519 PKCS#8 v2 DER private key file (from `bhf pack keygen`).
    #[arg(long)]
    pub signing_key: PathBuf,
    /// Where to write the signature.
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Debug, Args)]
pub struct KeygenArgs {
    /// Where to write the private key (PKCS#8 DER).
    #[arg(long)]
    pub private_key: PathBuf,
    /// Where to write the public key (raw hex).
    #[arg(long)]
    pub public_key: PathBuf,
}

#[derive(Debug, Args)]
pub struct CreateArgs {
    /// Directory the item paths are relative to.
    #[arg(long, default_value = ".")]
    pub root: PathBuf,
    /// The pack's identifier.
    #[arg(long)]
    pub pack_id: String,
    /// The pack's version.
    #[arg(long)]
    pub version: Option<String>,
    /// Pack item in kind:path form. Repeat for each item.
    #[arg(long = "item")]
    pub items: Vec<String>,
    /// License of the pack's content, recorded in the manifest.
    #[arg(long)]
    pub license: Option<String>,
    /// External tool required by every item in this pack. Repeatable.
    #[arg(long = "required-tool")]
    pub required_tools: Vec<String>,
    /// Deprecated digest label for sha256-items-v1; does not sign or authenticate.
    #[arg(long = "sign-key", conflicts_with = "signing_key")]
    pub sign_key: Option<String>,
    /// Ed25519 PKCS#8 v2 DER private key file (owner-only permissions).
    #[arg(long, requires = "key_id")]
    pub signing_key: Option<PathBuf>,
    /// Publisher key ID for --signing-key, as the verifying policy names it.
    #[arg(long, requires = "signing_key")]
    pub key_id: Option<String>,
    /// Where to write the manifest JSON.
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Debug, Args)]
pub struct InspectArgs {
    /// Update pack manifest JSON file.
    pub manifest: PathBuf,
    /// Write the JSON summary to this path instead of stdout.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct InstallArgs {
    /// Update pack manifest JSON file.
    pub manifest: PathBuf,
    /// Directory the manifest's item paths are relative to.
    #[arg(long, default_value = ".")]
    pub root: PathBuf,
    /// Directory to install the items into (created if missing).
    #[arg(long)]
    pub install_dir: PathBuf,
    /// Policy file that can deny pack kinds, licenses or required tools.
    #[arg(long)]
    pub policy: Option<PathBuf>,
    /// Reject unless the pack has a verified signature from an explicitly trusted public key.
    #[arg(long)]
    pub require_authenticated: bool,
    /// Final destination path reported in install.json when installing into a staged prefix.
    #[arg(long)]
    pub reported_install_dir: Option<PathBuf>,
    /// Write the JSON install summary to this path instead of stdout.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Update pack manifest JSON file.
    pub manifest: PathBuf,

    /// Root directory used to resolve manifest item paths.
    #[arg(long, default_value = ".")]
    pub root: PathBuf,

    /// Write the JSON verification summary to this path instead of stdout.
    #[arg(long)]
    pub out: Option<PathBuf>,

    /// Policy file that can deny pack kinds, licenses or required tools.
    #[arg(long)]
    pub policy: Option<PathBuf>,
    /// Reject unless the pack has a verified signature from an explicitly trusted public key.
    #[arg(long)]
    pub require_authenticated: bool,
}

pub fn run(args: PackArgs) -> i32 {
    match args.command {
        PackCommand::Create(args) => create(args),
        PackCommand::Inspect(args) => write_summary(
            governance::inspect_update_pack_file(&args.manifest),
            args.out,
        ),
        PackCommand::Install(args) => {
            let summary = governance::install_update_pack_file_with_options(
                &args.manifest,
                &args.root,
                &args.install_dir,
                args.policy.as_deref(),
                args.require_authenticated,
                args.reported_install_dir.as_deref(),
            );
            write_summary(summary, args.out)
        }
        PackCommand::Verify(args) => verify(args),
        PackCommand::Keygen(args) => {
            match governance::generate_update_pack_keypair(&args.private_key, &args.public_key) {
                Ok(public_hex) => {
                    println!("Ed25519 public key (raw hex): {public_hex}");
                    0
                }
                Err(error) => {
                    bhfeprintln!("{error:#}");
                    1
                }
            }
        }
        PackCommand::ImportOsv(args) => import_feed(
            "osv",
            governance::advisories::import_osv(&args.inputs),
            &args,
        ),
        PackCommand::ImportNvd(args) => import_feed(
            "nvd",
            governance::advisories::import_nvd(&args.inputs),
            &args,
        ),
        PackCommand::SignArchive(args) => {
            match governance::sign_distribution_archive(&args.archive, &args.signing_key, &args.out)
            {
                Ok(digest) => {
                    println!("distribution archive sha256: {digest}");
                    0
                }
                Err(error) => {
                    bhfeprintln!("{error:#}");
                    1
                }
            }
        }
    }
}

fn create(args: CreateArgs) -> i32 {
    let result = if let (Some(signing_key), Some(key_id)) =
        (args.signing_key.as_deref(), args.key_id.as_deref())
    {
        governance::create_authenticated_update_pack_file(
            &args.root,
            &args.pack_id,
            args.version.as_deref(),
            &args.items,
            args.license.as_deref(),
            &args.required_tools,
            signing_key,
            key_id,
            &args.out,
        )
    } else {
        governance::create_update_pack_file(
            &args.root,
            &args.pack_id,
            args.version.as_deref(),
            &args.items,
            args.license.as_deref(),
            &args.required_tools,
            args.sign_key.as_deref(),
            &args.out,
        )
    };
    match result {
        Ok(manifest) => {
            let items = manifest
                .get("items")
                .and_then(|value| value.as_array())
                .map_or(0, Vec::len);
            println!("update pack manifest: {items} items");
            0
        }
        Err(error) => {
            bhfeprintln!("{error:#}");
            1
        }
    }
}

fn verify(args: VerifyArgs) -> i32 {
    match governance::verify_update_pack_file_with_policy(
        &args.manifest,
        &args.root,
        args.policy.as_deref(),
    ) {
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
                        bhfeprintln!("serialize update pack verification: {error}");
                        return 1;
                    }
                }
            }
            if summary.get("valid").and_then(|value| value.as_bool()) == Some(true)
                && (!args.require_authenticated
                    || summary
                        .pointer("/signature/authenticated")
                        .and_then(|value| value.as_bool())
                        == Some(true))
            {
                0
            } else {
                1
            }
        }
        Err(error) => {
            bhfeprintln!("{error:#}");
            1
        }
    }
}

/// Write the database an importer built, print its summary, and report each
/// malformed record it skipped. Exit 1 when nothing could be imported from
/// malformed input, else 0.
fn import_feed(
    format: &str,
    import: Result<governance::advisories::AdvisoryImport, governance::GovernanceError>,
    args: &ImportFeedArgs,
) -> i32 {
    let import = match import {
        Ok(import) => import,
        Err(error) => {
            bhfeprintln!("bhf pack import-{format}: {error:#}");
            return 2;
        }
    };
    for (source, reason) in &import.malformed {
        bhfeprintln!(
            "bhf pack import-{}: skipped {source}: {reason}",
            import.format
        );
    }
    match governance::advisories::write_advisory_db(&import, &args.inputs, &args.out) {
        Ok(summary) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&summary).unwrap_or_default()
            );
            i32::from(import.records.is_empty() && !import.malformed.is_empty())
        }
        Err(error) => {
            bhfeprintln!("bhf pack import-{}: {error:#}", import.format);
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
            if summary
                .get("valid")
                .and_then(|value| value.as_bool())
                .unwrap_or(true)
            {
                0
            } else {
                1
            }
        }
        Err(error) => {
            bhfeprintln!("{error:#}");
            1
        }
    }
}
