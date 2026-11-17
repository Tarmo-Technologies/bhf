// SPDX-License-Identifier: Apache-2.0

//! `bhf corpus` subcommand: import/export/merge corpora across
//! AFL, libFuzzer, Honggfuzz, and bhf directory layouts.

use corpus::bridge::{
    detect_format, export_dir, import_dir, merge_dirs, BridgeError, Format, ImportSummary,
};
use corpus::compute_signature;
use event_log::Testcase;
use fuzz_engine_builtin::{CoverageInput, CoverageProxy, CoverageSignature};
use std::path::PathBuf;

#[derive(Debug, clap::Args)]
pub struct CorpusArgs {
    #[command(subcommand)]
    pub command: CorpusCommand,
}

#[derive(Debug, clap::Subcommand)]
pub enum CorpusCommand {
    /// Import a foreign corpus into a bhf-layout directory.
    Import(ImportArgs),
    /// Export a bhf corpus to another fuzzer's layout.
    Export(ExportArgs),
    /// Merge multiple corpus directories, deduplicating by content.
    Merge(MergeArgs),
    /// Produce a coverage-minimal corpus: replay each input through a harness
    /// and keep only those that add new coverage (libFuzzer `-merge=1`).
    Minimize(MinimizeCorpusArgs),
}

#[derive(Debug, clap::Args)]
pub struct ImportArgs {
    /// Source format. `auto` (default) detects from filename
    /// patterns; pass an explicit value for mixed-format dirs.
    #[arg(long, default_value = "auto")]
    pub from: String,

    /// Source directory.
    #[arg(long = "in", value_name = "DIR")]
    pub input: PathBuf,

    /// Target directory (created if missing).
    #[arg(long = "out", value_name = "DIR")]
    pub output: PathBuf,
}

#[derive(Debug, clap::Args)]
pub struct ExportArgs {
    /// Target format. `afl` names entries `id:000000,sig:...`, or
    /// `id_000000,sig_...` on Windows, which allows no `:` in a file name
    /// (import reads both).
    #[arg(long, default_value = "libfuzzer")]
    pub to: String,

    /// Source directory.
    #[arg(long = "in", value_name = "DIR")]
    pub input: PathBuf,

    /// Target directory (created if missing).
    #[arg(long = "out", value_name = "DIR")]
    pub output: PathBuf,
}

#[derive(Debug, clap::Args)]
pub struct MergeArgs {
    /// Output directory (created if missing).
    #[arg(long = "out", value_name = "DIR")]
    pub output: PathBuf,

    /// One or more input directories to merge.
    #[arg(required = true, num_args = 1..)]
    pub inputs: Vec<PathBuf>,
}

#[derive(Debug, clap::Args)]
pub struct MinimizeCorpusArgs {
    /// Harness binary to replay corpus inputs through.
    #[arg(long)]
    pub harness: PathBuf,

    /// Input corpus directory.
    #[arg(long = "in", value_name = "DIR")]
    pub input: PathBuf,

    /// Output directory for the coverage-minimal corpus (created if missing).
    #[arg(long = "out", value_name = "DIR")]
    pub output: PathBuf,
}

pub fn run(args: CorpusArgs) -> i32 {
    match args.command {
        CorpusCommand::Import(import_args) => run_import(import_args),
        CorpusCommand::Export(export_args) => run_export(export_args),
        CorpusCommand::Merge(merge_args) => run_merge(merge_args),
        CorpusCommand::Minimize(minimize_args) => run_minimize(minimize_args),
    }
}

fn run_import(args: ImportArgs) -> i32 {
    let from_explicit = Format::parse(&args.from);
    let source_format = match from_explicit {
        Some(Format::Unknown) | None => match detect_format(&args.input) {
            Ok(format) => format,
            Err(error) => return fail(error),
        },
        Some(explicit) => explicit,
    };
    match import_dir(&args.input, &args.output, source_format) {
        Ok(summary) => {
            print_summary("imported", &summary);
            0
        }
        Err(error) => fail(error),
    }
}

fn run_export(args: ExportArgs) -> i32 {
    let Some(target) = Format::parse(&args.to) else {
        bhfeprintln!("error: unknown target format: {}", args.to);
        return 2;
    };
    if matches!(target, Format::Unknown) {
        bhfeprintln!("error: target format must be one of bhf, libfuzzer, afl, honggfuzz");
        return 2;
    }
    match export_dir(&args.input, &args.output, target) {
        Ok(summary) => {
            print_summary("exported", &summary);
            0
        }
        Err(error) => fail(error),
    }
}

fn run_merge(args: MergeArgs) -> i32 {
    match merge_dirs(&args.inputs, &args.output) {
        Ok(summary) => {
            print_summary("merged", &summary);
            0
        }
        Err(error) => fail(error),
    }
}

fn run_minimize(args: MinimizeCorpusArgs) -> i32 {
    let inputs = match read_corpus_inputs(&args.input) {
        Ok(inputs) => inputs,
        Err(error) => {
            bhfeprintln!("error: {error}");
            return 1;
        }
    };
    if inputs.is_empty() {
        bhfeprintln!("error: no corpus files found in {}", args.input.display());
        return 1;
    }

    // The replays run in a scratch directory: a relative harness path is
    // resolved here first.
    let harness = std::path::absolute(&args.harness).unwrap_or_else(|_| args.harness.clone());
    // A cross-built harness runs under the emulator recorded beside it.
    let runner = match crate::runner::harness_runner_for(
        harness,
        None,
        Vec::new(),
        crate::runner::SandboxModeArg::Auto,
        None,
        false,
    ) {
        Ok(runner) => runner,
        Err(error) => {
            bhfeprintln!("error: {error}");
            return 1;
        }
    };
    let work_dir = match scratch_work_dir() {
        Ok(dir) => dir,
        Err(error) => {
            bhfeprintln!("error: {error}");
            return 1;
        }
    };

    // #282: an input's coverage is the edges its harness's driver writes to
    // the coverage map, in every lane, and an Ada harness's event log.
    let map = match crate::fuzz::ReplayCoverageMap::create(work_dir.path()) {
        Ok(map) => map,
        Err(error) => {
            bhfeprintln!("error: {error}");
            return 1;
        }
    };
    // A map whose edges differ between two runs of one input (a driver that
    // hashes addresses a fresh process moves) cannot tell inputs apart.
    let stable_edges = match (
        map.replay(&runner, work_dir.path(), &inputs[0].1),
        map.replay(&runner, work_dir.path(), &inputs[0].1),
    ) {
        (Ok((_, first)), Ok((_, second))) => {
            if first != second {
                bhfeprintln!(
                    "note: the harness's coverage map differs between two runs of one input, \
                     so its edges are not used to tell the inputs apart"
                );
            }
            first == second
        }
        _ => true,
    };
    let mut saw_coverage = false;
    let total = inputs.len();
    let selection = select_coverage_minimal(&inputs, |bytes| {
        match map.replay(&runner, work_dir.path(), bytes) {
            Ok((testcases, edges)) => {
                let edges = if stable_edges { edges } else { Vec::new() };
                if !testcases.is_empty() || !edges.is_empty() {
                    saw_coverage = true;
                }
                Ok((testcases, edges))
            }
            // One unreplayable input must not abort the whole minimize: warn,
            // treat it as contributing no coverage, and keep going.
            Err(error) => {
                bhfeprintln!("warning: skipping input (replay failed): {error}");
                Ok((Vec::new(), Vec::new()))
            }
        }
    });
    drop(map);
    drop(work_dir);

    let kept = match selection {
        Ok(kept) => kept,
        Err(error) => {
            bhfeprintln!("error: {error}");
            return 1;
        }
    };

    if !saw_coverage {
        // Nothing told the inputs apart: keep every one, and say this harness
        // cannot be minimized rather than report an empty minimal corpus.
        let all: Vec<String> = inputs.iter().map(|(name, _)| name.clone()).collect();
        if let Err(error) = copy_selected(&args.input, &args.output, &all) {
            bhfeprintln!("error: {error}");
            return 1;
        }
        bhfeprintln!(
            "error: {} records no coverage when it replays an input (no edges in its \
             coverage map, no event log), so `bhf corpus minimize` cannot tell its inputs \
             apart; copied all {total} inputs to {} unchanged. `bhf corpus merge` drops \
             inputs with duplicate content",
            harness_lane(&args.harness),
            args.output.display()
        );
        return 2;
    }

    if let Err(error) = copy_selected(&args.input, &args.output, &kept) {
        bhfeprintln!("error: {error}");
        return 1;
    }

    println!(
        "minimized {total} inputs -> {} coverage-minimal ({} dropped)",
        kept.len(),
        total - kept.len(),
    );
    0
}

/// "the C harness", "the Java harness": the lane of the harness executable
/// `harness`, read from its harness dir (`<dir>/main`, or `<dir>/obj/main` for
/// an Ada build), else "the harness".
fn harness_lane(harness: &std::path::Path) -> String {
    let mut dir = harness.parent();
    if dir
        .and_then(|dir| dir.file_name())
        .is_some_and(|name| name == "obj")
    {
        dir = dir.and_then(std::path::Path::parent);
    }
    let Some(dir) = dir else {
        return "the harness".to_owned();
    };
    let id = dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    // `bhf build` stages `<work>/build/<id>/main`; the generated harness dir
    // beside it says what it is.
    let mut dirs = vec![dir.to_path_buf()];
    if let Some(work_dir) = dir
        .parent()
        .filter(|build| build.file_name().is_some_and(|name| name == "build"))
        .and_then(std::path::Path::parent)
    {
        dirs.extend(crate::auto::layout::harness_dir_candidates(work_dir, id));
    }
    crate::repro_lane::harness_language(&dirs, id)
        .and_then(|tag| crate::auto::report::lang_from_tag(&tag))
        .map_or_else(
            || "the harness".to_owned(),
            |lang| format!("the {} harness", crate::auto::candidate::lang_name(lang)),
        )
}

/// Read every regular file in `dir` as `(file_name, bytes)`, sorted by file
/// name so the coverage-minimal selection is deterministic across runs.
fn read_corpus_inputs(dir: &std::path::Path) -> Result<Vec<(String, Vec<u8>)>, String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("read {}: {e}", dir.display()))?;
    let mut inputs = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry in {}: {e}", dir.display()))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()).map(str::to_owned) else {
            continue;
        };
        let bytes = std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        inputs.push((name, bytes));
    }
    inputs.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(inputs)
}

fn copy_selected(
    input: &std::path::Path,
    output: &std::path::Path,
    kept: &[String],
) -> Result<(), String> {
    std::fs::create_dir_all(output).map_err(|e| format!("create {}: {e}", output.display()))?;
    for name in kept {
        let src = input.join(name);
        let dst = output.join(name);
        std::fs::copy(&src, &dst)
            .map_err(|e| format!("copy {} -> {}: {e}", src.display(), dst.display()))?;
    }
    Ok(())
}

/// A scratch dir for the replays, removed when it drops, a panic included.
fn scratch_work_dir() -> Result<tempfile::TempDir, String> {
    tempfile::Builder::new()
        .prefix("bhf-corpus-minimize-")
        .tempdir()
        .map_err(|e| format!("create work dir in {}: {e}", std::env::temp_dir().display()))
}

fn print_summary(verb: &str, summary: &ImportSummary) {
    println!(
        "{verb} {} unique files, {} duplicates skipped ({} -> {})",
        summary.unique,
        summary.duplicates,
        summary.source_format.as_str(),
        summary.target_format.as_str(),
    );
}

fn fail(error: BridgeError) -> i32 {
    bhfeprintln!("error: {error}");
    1
}

/// Exception-handler coverage signatures for a single replayed testcase, in
/// the same form the built-in engine feeds its `CoverageProxy`.
fn testcase_signatures(testcase: &Testcase) -> Vec<CoverageSignature> {
    testcase
        .handlers
        .iter()
        .map(|handler| CoverageSignature::from_bytes(compute_signature(testcase, handler).0))
        .collect()
}

/// Greedily select a coverage-minimal subset of `inputs` (libFuzzer `-merge`
/// semantics): replay each input in order through `replay`, which gives its
/// event-log testcases and the edges of its coverage map, and keep an input
/// only when it reaches an edge no earlier one did (#282) or contributes a new
/// event-log feature (breadcrumb, handler, raise, top-level, return class,
/// mock call, or exception signature). Inputs that reproduce only
/// already-seen coverage — or no coverage at all — are dropped.
fn select_coverage_minimal<F>(
    inputs: &[(String, Vec<u8>)],
    mut replay: F,
) -> Result<Vec<String>, String>
where
    F: FnMut(&[u8]) -> Result<(Vec<Testcase>, Vec<u32>), String>,
{
    let mut proxy = CoverageProxy::default();
    let mut edges_seen = std::collections::HashSet::new();
    let mut kept = Vec::new();
    for (name, input) in inputs {
        let (testcases, edges) = replay(input)?;
        let mut added = false;
        for edge in edges {
            added |= edges_seen.insert(edge);
        }
        for testcase in &testcases {
            let signatures = testcase_signatures(testcase);
            if !proxy
                .record(CoverageInput::new(testcase, &signatures))
                .is_empty()
            {
                added = true;
            }
        }
        if added {
            kept.push(name.clone());
        }
    }
    Ok(kept)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_minimize_scratch_dir_is_named_for_bhf_and_removed_on_drop() {
        let dir = scratch_work_dir().unwrap();
        let path = dir.path().to_path_buf();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("bhf-corpus-minimize-"), "{name}");
        assert!(path.is_dir());
        std::fs::write(path.join("replay.bin"), b"x").unwrap();
        drop(dir);
        assert!(!path.exists(), "{}", path.display());
    }

    fn testcase_with_crumbs(crumbs: Vec<u32>) -> Testcase {
        Testcase {
            testcase_id: 1,
            target_id: 0x42,
            target_entered: false,
            crumbs,
            handlers: Vec::new(),
            raises: Vec::new(),
            top_level: None,
            end: None,
            mocks: Vec::new(),
        }
    }

    #[test]
    fn select_coverage_minimal_keeps_only_coverage_adding_inputs() {
        let inputs = vec![
            ("a".to_owned(), b"a".to_vec()),
            ("b".to_owned(), b"b".to_vec()),
            ("c".to_owned(), b"c".to_vec()),
            ("d".to_owned(), b"d".to_vec()),
        ];

        let kept = select_coverage_minimal(&inputs, |input| {
            Ok((
                match input {
                    // distinct breadcrumb -> novel coverage
                    b"a" => vec![testcase_with_crumbs(vec![1])],
                    // same breadcrumb as "a" -> no new coverage
                    b"b" => vec![testcase_with_crumbs(vec![1])],
                    // fresh breadcrumb -> novel coverage
                    b"c" => vec![testcase_with_crumbs(vec![2])],
                    // no events at all -> nothing to add
                    _ => Vec::new(),
                },
                Vec::new(),
            ))
        })
        .unwrap();

        assert_eq!(kept, vec!["a".to_owned(), "c".to_owned()]);
    }

    /// #282: the coverage map's edges tell inputs apart in a lane with no
    /// event log: an input is kept when it reaches an edge no earlier one did.
    #[test]
    fn select_coverage_minimal_keeps_inputs_that_reach_new_edges() {
        let inputs: Vec<(String, Vec<u8>)> = ["a", "b", "c", "d", "e", "f"]
            .iter()
            .map(|name| ((*name).to_owned(), name.as_bytes().to_vec()))
            .collect();
        let kept = select_coverage_minimal(&inputs, |input| {
            let edges = match input {
                b"a" => vec![1, 2],
                b"b" => vec![1, 2],
                b"c" => vec![1, 3],
                b"d" => vec![3],
                b"e" => vec![4, 5],
                _ => vec![1, 6],
            };
            Ok((Vec::new(), edges))
        })
        .unwrap();
        assert_eq!(kept, ["a", "c", "e", "f"]);
    }
}
