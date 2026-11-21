// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, clap::Args, PartialEq)]
pub struct InstrumentArgs {
    /// Ada source file to instrument. A body's spec beside it (`pkg.ads` for
    /// `pkg.adb`) is copied to the output directory with it.
    pub source: PathBuf,

    /// Output directory for the instrumented source and breadcrumbs.json.
    #[arg(long, default_value = "bhf_work/src_instrumented")]
    pub output: PathBuf,
}

pub fn run(args: InstrumentArgs) -> Result<()> {
    let source = crate::source_text::read_source_text(&args.source)
        .with_context(|| format!("read Ada source {}", args.source.display()))?;
    let ast = ada_parser::reconcile::build_structural_ast(&source, None, &args.source)
        .with_context(|| format!("scan Ada source {}", args.source.display()))?;
    let result = instrumenter::instrument_unit(instrumenter::InstrumentArgs {
        source: &source,
        ast: &ast,
        source_path: &args.source,
    })?;

    std::fs::create_dir_all(&args.output)
        .with_context(|| format!("create output directory {}", args.output.display()))?;
    let basename = args.source.file_name().ok_or_else(|| {
        anyhow::anyhow!("source path has no file name: {}", args.source.display())
    })?;
    let dest = args.output.join(basename);
    std::fs::write(&dest, &result.rewritten_source)
        .with_context(|| format!("write instrumented source {}", dest.display()))?;
    let sidecar = args.output.join("breadcrumbs.json");
    std::fs::write(
        &sidecar,
        instrumenter::breadcrumbs_sidecar_json(&result.breadcrumbs)?,
    )
    .with_context(|| format!("write breadcrumb sidecar {}", sidecar.display()))?;

    println!("Instrumented: {}", dest.display());
    println!("Sidecar:      {}", sidecar.display());
    // A package body compiles against its spec: copy the spec beside the
    // instrumented body, so the output directory builds on its own.
    if let Some(spec) = companion_spec(&args.source) {
        let spec_dest = args.output.join(spec.file_name().unwrap_or_default());
        let same_file = matches!(
            (spec.canonicalize(), spec_dest.canonicalize()),
            (Ok(from), Ok(to)) if from == to
        );
        if !same_file {
            std::fs::copy(&spec, &spec_dest).with_context(|| {
                format!(
                    "copy Ada spec {} to {}",
                    spec.display(),
                    spec_dest.display()
                )
            })?;
        }
        println!("Spec:         {}", spec_dest.display());
    }

    Ok(())
}

/// The spec beside an Ada body (`pkg.ads` for `pkg.adb`), when there is one.
fn companion_spec(body: &Path) -> Option<PathBuf> {
    let extension = body.extension()?.to_str()?;
    if !extension.eq_ignore_ascii_case("adb") {
        return None;
    }
    let spec_extension = if extension == "ADB" { "ADS" } else { "ads" };
    let spec = body.with_extension(spec_extension);
    spec.is_file().then_some(spec)
}

#[cfg(test)]
mod tests {
    use super::{run, InstrumentArgs};
    use clap::Parser;
    use std::fs;
    use std::path::{Path, PathBuf};

    #[derive(Debug, Parser)]
    struct InstrumentOnly {
        #[command(flatten)]
        args: InstrumentArgs,
    }

    #[test]
    fn instrument_subcommand_writes_to_default_output_dir() {
        let temp = temp_dir("default-output");
        let source = write_source(&temp);
        let cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&temp).unwrap();

        let args = InstrumentOnly::try_parse_from(["instrument", source.to_str().unwrap()])
            .unwrap()
            .args;
        run(args).unwrap();

        assert!(temp.join("bhf_work/src_instrumented/src.adb").is_file());
        std::env::set_current_dir(cwd).unwrap();
    }

    #[test]
    fn instrument_subcommand_writes_to_custom_output_dir() {
        let temp = temp_dir("custom-output");
        let source = write_source(&temp);
        let output = temp.join("out");

        run(InstrumentArgs {
            source,
            output: output.clone(),
        })
        .unwrap();

        assert!(output.join("src.adb").is_file());
    }

    #[test]
    fn instrument_subcommand_creates_output_dir_if_missing() {
        let temp = temp_dir("creates-output");
        let source = write_source(&temp);
        let output = temp.join("missing/nested");

        run(InstrumentArgs {
            source,
            output: output.clone(),
        })
        .unwrap();

        assert!(output.is_dir());
    }

    #[test]
    fn instrument_subcommand_writes_breadcrumbs_json_sidecar() {
        let temp = temp_dir("sidecar");
        let source = write_source(&temp);
        let output = temp.join("out");

        run(InstrumentArgs {
            source,
            output: output.clone(),
        })
        .unwrap();

        let sidecar = fs::read_to_string(output.join("breadcrumbs.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&sidecar).unwrap();
        assert!(value.get("1").is_some());
    }

    fn write_source(dir: &Path) -> PathBuf {
        let source = dir.join("src.adb");
        fs::write(&source, "procedure P is begin A; end P;").unwrap();
        source
    }

    fn temp_dir(name: &str) -> crate::test_support::TestDir {
        crate::test_support::TestDir::new(&format!("cli-instrument-{name}"))
    }
}
