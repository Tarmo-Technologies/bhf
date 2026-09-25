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
    /// Create a deterministic air-gapped update pack manifest.
    Create(CreateArgs),
    /// Inspect an air-gapped update pack manifest without installing it.
    Inspect(InspectArgs),
    /// Install a verified update pack into a local offline directory.
    Install(InstallArgs),
    /// Verify an air-gapped update pack manifest.
    Verify(VerifyArgs),
    /// Generate an Ed25519 signing keypair (private PKCS#8 DER; public raw hex).
    Keygen(KeygenArgs),
    /// Sign the exact compressed distribution archive for external OpenSSL verification.
    SignArchive(SignArchiveArgs),
}

#[derive(Debug, Args)]
pub struct SignArchiveArgs {
    #[arg(long)]
    pub archive: PathBuf,
    #[arg(long)]
    pub signing_key: PathBuf,
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Debug, Args)]
pub struct KeygenArgs {
    #[arg(long)]
    pub private_key: PathBuf,
    #[arg(long)]
    pub public_key: PathBuf,
}

#[derive(Debug, Args)]
pub struct CreateArgs {
    #[arg(long, default_value = ".")]
    pub root: PathBuf,
    #[arg(long)]
    pub pack_id: String,
    #[arg(long)]
    pub version: Option<String>,
    /// Pack item in kind:path form. Repeat for each item.
    #[arg(long = "item")]
    pub items: Vec<String>,
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
    /// Policy-controlled publisher key ID for --signing-key.
    #[arg(long, requires = "signing_key")]
    pub key_id: Option<String>,
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Debug, Args)]
pub struct InspectArgs {
    pub manifest: PathBuf,
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct InstallArgs {
    pub manifest: PathBuf,
    #[arg(long, default_value = ".")]
    pub root: PathBuf,
    #[arg(long)]
    pub install_dir: PathBuf,
    #[arg(long)]
    pub policy: Option<PathBuf>,
    /// Reject unless the pack has a verified signature from an explicitly trusted public key.
    #[arg(long)]
    pub require_authenticated: bool,
    /// Final destination path reported in install.json when installing into a staged prefix.
    #[arg(long)]
    pub reported_install_dir: Option<PathBuf>,
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

    /// Write verification summary JSON to this path.
    #[arg(long)]
    pub out: Option<PathBuf>,

    /// Optional policy file used to deny pack kinds, licenses, or required tools.
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
