// SPDX-License-Identifier: Apache-2.0

//! Provided harnesses: the fuzz entry points a project already ships, which
//! `bhf auto` fuzzes beside the harnesses it generates.
//!
//! A provided harness is the project's own statement of how its code is to be
//! fuzzed, so it is found where generated targets are not looked for (`_test.go`
//! files, `fuzz/` and test directories), ranked ahead of every generated target,
//! and run with what came with it:
//!
//! - a Go native fuzz test (`func FuzzXxx(f *testing.F)` in a `_test.go` file),
//!   built by [`crate::auto::go_build`] against a stand-in for the `testing`
//!   package, with its `f.Add` seeds and its `testdata/fuzz/<Name>` corpus;
//! - an Atheris harness (the function a Python file registers with
//!   `atheris.Setup`, `TestOneInput` by convention), run by
//!   [`crate::auto::python_build`] with a stand-in for `atheris`, with the
//!   `<name>.dict` beside it; every exception it lets escape is a finding;
//! - a fuzzer `bhf project import-ossfuzz` built from the project's OSS-Fuzz
//!   `build.sh` and registered in the work dir ([`discover_imported`]): its
//!   binary is the harness, staged by [`stage_imported_fuzzer`] with the seed
//!   corpus, dictionaries and `.options` the import took for it.
//!
//! The build of each kind leaves [`RECORD_FILE`] in the harness dir, which
//! `run.json` reports as the target's `provided_harness`, and the starting
//! inputs in [`SEEDS_DIR`], which the fuzz passes start from.

use crate::auto::candidate::{Candidate, Lang};
use crate::auto::discovery::DirFilter;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// What a provided harness's build records in its harness dir.
pub(crate) const RECORD_FILE: &str = "provided-harness.json";

/// The provided harness's starting inputs, one file each, in its harness dir.
pub(crate) const SEEDS_DIR: &str = "provided-seeds";

/// A provided harness ranks ahead of every generated target: it is the
/// project's own entry point, so a `--max-targets` cap keeps it first.
const PROVIDED_SCORE: i32 = 1_000_000;

/// Most starting inputs one provided harness loads, how large each may be, and
/// how much they may hold together.
const MAX_SEEDS: usize = 4096;
const MAX_SEED_BYTES: u64 = 1024 * 1024;
const MAX_SEEDS_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

/// Most directory entries the walk for provided harnesses visits.
const WALK_BUDGET: usize = 200_000;

/// Where a provided harness came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Origin {
    /// A Go native fuzz test (`func FuzzXxx(f *testing.F)`).
    GoFuzzTest,
    /// An Atheris harness (`atheris.Setup(sys.argv, TestOneInput)`).
    Atheris,
    /// A fuzzer `bhf project import-ossfuzz` registered in the work dir.
    OssfuzzImport,
}

impl Origin {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Origin::GoFuzzTest => "go-fuzz-test",
            Origin::Atheris => "atheris",
            Origin::OssfuzzImport => "ossfuzz-import",
        }
    }

    /// How a person names one.
    fn describe(self) -> &'static str {
        match self {
            Origin::GoFuzzTest => "Go native fuzz test",
            Origin::Atheris => "Atheris harness",
            Origin::OssfuzzImport => "imported OSS-Fuzz fuzzer",
        }
    }
}

/// A provided harness as `run.json` reports it (`targets[].provided_harness`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProvidedRecord {
    pub origin: Origin,
    /// The entry point: the fuzz test's name, or the function registered
    /// with `atheris.Setup`.
    pub entry: String,
    /// The file that defines it.
    pub source: PathBuf,
    /// How many starting inputs came with it.
    #[serde(default)]
    pub seeds: usize,
    /// Where they came from (the `f.Add` calls are counted, not named).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub seed_sources: Vec<PathBuf>,
    /// The dictionaries that came with it, merged into its harness's
    /// `dictionary.txt`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dictionaries: Vec<PathBuf>,
    /// How many tokens they hold.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub dictionary_tokens: usize,
    /// The fuzz options that came with it, which its fuzz passes use in
    /// place of the run's (an imported fuzzer's `.options`).
    #[serde(default, skip_serializing_if = "FuzzOptions::is_empty")]
    pub options: FuzzOptions,
    /// What came with it that could not be used, and why.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// The `[libfuzzer]` options of an OSS-Fuzz `.options` file bhf applies, as
/// `bhf project import-ossfuzz` read them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FuzzOptions {
    /// `max_len`: the longest input, in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_len: Option<u64>,
    /// `timeout`: the per-input timeout, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
    /// `rss_limit_mb`: the memory limit, in MiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rss_limit_mb: Option<u64>,
}

impl FuzzOptions {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Set the fuzz pass's limits these options name.
    pub(crate) fn apply(
        &self,
        max_len: &mut usize,
        timeout: &mut Option<std::time::Duration>,
        rss_limit_mb: &mut usize,
    ) {
        if let Some(len) = self.max_len.filter(|&len| len > 0) {
            *max_len = usize::try_from(len).unwrap_or(usize::MAX);
        }
        if let Some(secs) = self.timeout_secs.filter(|&secs| secs > 0) {
            *timeout = Some(std::time::Duration::from_secs(secs));
        }
        if let Some(mb) = self.rss_limit_mb {
            *rss_limit_mb = usize::try_from(mb).unwrap_or(usize::MAX);
        }
    }
}

/// The fuzz options a provided harness came with, for the fuzz passes of
/// the harness `harness_id` in `work_dir`; `None` for any other harness.
pub(crate) fn fuzz_options(work_dir: &Path, harness_id: &str) -> Option<FuzzOptions> {
    read_record(&crate::auto::layout::harness_dir(work_dir, harness_id))
        .map(|record| record.options)
        .filter(|options| !options.is_empty())
}

impl ProvidedRecord {
    /// A record of `origin`'s `entry` in `source`, with nothing that came with it.
    pub(crate) fn new(origin: Origin, entry: &str, source: &Path) -> Self {
        Self {
            origin,
            entry: entry.to_owned(),
            source: source.to_path_buf(),
            seeds: 0,
            seed_sources: Vec::new(),
            dictionaries: Vec::new(),
            dictionary_tokens: 0,
            options: FuzzOptions::default(),
            notes: Vec::new(),
        }
    }
}

/// Record `record` in `harness_dir`.
pub(crate) fn write_record(harness_dir: &Path, record: &ProvidedRecord) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(record).map_err(std::io::Error::other)?;
    std::fs::write(harness_dir.join(RECORD_FILE), bytes)
}

/// The record a provided harness's build left in `harness_dir`.
pub(crate) fn read_record(harness_dir: &Path) -> Option<ProvidedRecord> {
    let bytes = std::fs::read(harness_dir.join(RECORD_FILE)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Remove what an earlier build of a provided harness left in `harness_dir`,
/// so a build that fails now cannot be reported with the last one's seeds.
pub(crate) fn clear(harness_dir: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(harness_dir.join(RECORD_FILE)) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    match std::fs::remove_dir_all(harness_dir.join(SEEDS_DIR)) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// The provided harness's starting inputs, in file-name order: at most
/// [`MAX_SEEDS`] files of at most [`MAX_SEED_BYTES`] each and
/// [`MAX_SEEDS_TOTAL_BYTES`] together. Empty for any other harness.
pub(crate) fn load_seeds(harness_dir: &Path) -> Vec<Vec<u8>> {
    let Ok(entries) = std::fs::read_dir(harness_dir.join(SEEDS_DIR)) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .map(|entry| entry.path())
        .collect();
    files.sort();
    let mut seeds = Vec::new();
    let mut total = 0u64;
    for file in files {
        if seeds.len() >= MAX_SEEDS {
            break;
        }
        let Ok(meta) = std::fs::metadata(&file) else {
            continue;
        };
        if meta.len() > MAX_SEED_BYTES || total + meta.len() > MAX_SEEDS_TOTAL_BYTES {
            continue;
        }
        if let Ok(bytes) = std::fs::read(&file) {
            total += bytes.len() as u64;
            seeds.push(bytes);
        }
    }
    seeds
}

/// Copy the starting inputs in `sources` into `harness_dir`'s [`SEEDS_DIR`],
/// as they are: each regular file of a source directory (walked in name
/// order, its subdirectories included) or a source file, within the bounds
/// [`load_seeds`] reads them in. A symlink is not followed, since it could
/// name a file outside the corpus. Returns how many files were copied and
/// how many were left out.
pub(crate) fn copy_seed_files(
    harness_dir: &Path,
    sources: &[PathBuf],
) -> std::io::Result<(usize, usize)> {
    fn collect(path: &Path, depth: usize, files: &mut Vec<PathBuf>, budget: &mut usize) {
        let Ok(meta) = std::fs::symlink_metadata(path) else {
            return;
        };
        if meta.is_file() {
            files.push(path.to_path_buf());
        } else if meta.is_dir() && depth < 16 {
            let Ok(entries) = std::fs::read_dir(path) else {
                return;
            };
            let mut entries: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
            entries.sort();
            for entry in entries {
                if *budget == 0 {
                    return;
                }
                *budget -= 1;
                collect(&entry, depth + 1, files, budget);
            }
        } else {
            files.push(path.to_path_buf());
        }
    }
    let mut files = Vec::new();
    let mut budget = WALK_BUDGET;
    for source in sources {
        collect(source, 0, &mut files, &mut budget);
    }
    let dest = harness_dir.join(SEEDS_DIR);
    std::fs::create_dir_all(&dest)?;
    let (mut copied, mut skipped, mut total) = (0usize, 0usize, 0u64);
    for file in files {
        let fits = std::fs::symlink_metadata(&file).is_ok_and(|meta| {
            meta.is_file()
                && copied < MAX_SEEDS
                && meta.len() <= MAX_SEED_BYTES
                && total + meta.len() <= MAX_SEEDS_TOTAL_BYTES
        });
        if !fits {
            skipped += 1;
            continue;
        }
        let name: String = file
            .file_name()
            .map(|name| name.to_string_lossy())
            .unwrap_or_default()
            .chars()
            .take(64)
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        total += std::fs::copy(&file, dest.join(format!("seed-{copied:04}-{name}")))?;
        copied += 1;
    }
    Ok((copied, skipped))
}

/// Whether `candidate` is a Go native fuzz test. Discovery never takes a
/// generated target from a `_test.go` file, so a Go candidate from one is a
/// fuzz test [`discover`] found.
pub(crate) fn is_go_fuzz_test(candidate: &Candidate) -> bool {
    candidate.lang == Lang::Go
        && candidate
            .source_path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with("_test.go"))
}

/// The Atheris entry point `candidate` is, when its file registers it with
/// `atheris.Setup`.
pub(crate) fn atheris_entry(candidate: &Candidate) -> Option<python_parser::AtherisEntry> {
    if candidate.lang != Lang::Python {
        return None;
    }
    let source = crate::source_text::read_source_text(&candidate.source_path).ok()?;
    if !source.contains("atheris") {
        return None;
    }
    python_parser::find_atheris_entry_points(&source)
        .ok()?
        .into_iter()
        .find(|entry| entry.callback == candidate.name)
}

/// Where `candidate` came from, when it is a provided harness.
pub(crate) fn origin(candidate: &Candidate) -> Option<Origin> {
    if is_go_fuzz_test(candidate) {
        return Some(Origin::GoFuzzTest);
    }
    atheris_entry(candidate).map(|_| Origin::Atheris)
}

/// What `run.json` reports for `candidate`: the record its build left, or,
/// for a provided harness that did not build, its origin and entry point.
/// An imported fuzzer is known by the record its staging left.
pub(crate) fn target_record(candidate: &Candidate, harness_dir: &Path) -> Option<ProvidedRecord> {
    let Some(origin) = origin(candidate) else {
        return read_record(harness_dir).filter(|record| {
            record.origin == Origin::OssfuzzImport && record.entry == candidate.name
        });
    };
    Some(
        read_record(harness_dir)
            .filter(|record| record.origin == origin)
            .unwrap_or_else(|| {
                ProvidedRecord::new(origin, &candidate.name, &candidate.source_path)
            }),
    )
}

/// Merge the dictionaries that came with a provided harness, in order, into
/// its harness's `dictionary.txt` (after the tokens bhf mined, each token
/// once), and return how many tokens they hold.
pub(crate) fn append_dictionaries(
    harness_dir: &Path,
    dictionaries: &[PathBuf],
) -> Result<usize, String> {
    if dictionaries.is_empty() {
        return Ok(0);
    }
    let merged =
        project_profile::merge_dictionaries(dictionaries).map_err(|error| error.to_string())?;
    let path = harness_dir.join("dictionary.txt");
    let mut contents = std::fs::read_to_string(&path).unwrap_or_default();
    for line in merged.to_afl_format().lines() {
        if !contents.lines().any(|existing| existing.trim() == line) {
            if !contents.is_empty() && !contents.ends_with('\n') {
                contents.push('\n');
            }
            contents.push_str(line);
            contents.push('\n');
        }
    }
    std::fs::write(&path, contents)
        .map_err(|error| format!("write {}: {error}", path.display()))?;
    Ok(merged.tokens.len())
}

/// The provided harnesses under `root` (a directory, or one file): every Go
/// native fuzz test and Atheris harness. The walk looks in test and fuzz directories, which
/// discovery of generated targets skips, but not in the work dir, build output,
/// a vendored dependency, `testdata/` or a directory `--exclude-dir` names,
/// nor for Go in a directory whose name starts with `_`, which the go tool
/// ignores.
pub fn discover(root: &Path, filter: &DirFilter) -> Vec<Candidate> {
    let mut out = Vec::new();
    if root.is_file() {
        visit_file(root, true, &mut out);
        return out;
    }
    // Each directory, and whether the go tool builds what it holds.
    let mut stack = vec![(root.to_path_buf(), true)];
    let mut seen = 0usize;
    while let Some((dir, go_builds)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            seen += 1;
            if seen > WALK_BUDGET {
                break;
            }
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                if !crate::auto::discovery::is_excluded_provided_harness_dir(&path, filter) {
                    let go_ignored = entry.file_name().to_string_lossy().starts_with('_');
                    stack.push((path, go_builds && !go_ignored));
                }
            } else if kind.is_file() {
                visit_file(&path, go_builds, &mut out);
            }
        }
    }
    out.sort_by(|a, b| a.source_path.cmp(&b.source_path).then(a.line.cmp(&b.line)));
    out
}

/// The provided harnesses `path` defines; its Go fuzz tests only when the go
/// tool builds its directory (`go_builds`).
fn visit_file(path: &Path, go_builds: bool, out: &mut Vec<Candidate>) {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return;
    };
    if go_builds && name.ends_with("_test.go") {
        go_fuzz_tests(path, out);
    } else if name.ends_with(".py") {
        atheris_harnesses(path, out);
    }
}

fn atheris_harnesses(path: &Path, out: &mut Vec<Candidate>) {
    let Ok(source) = crate::source_text::read_source_text(path) else {
        return;
    };
    if !source.contains("atheris") {
        return;
    }
    let Ok(entries) = python_parser::find_atheris_entry_points(&source) else {
        return;
    };
    for entry in entries {
        out.push(provided_candidate(
            "H-P",
            Lang::Python,
            path,
            entry.line,
            entry.callback,
        ));
    }
}

fn go_fuzz_tests(path: &Path, out: &mut Vec<Candidate>) {
    let Ok(source) = crate::source_text::read_source_text(path) else {
        return;
    };
    if !source.contains("func Fuzz") || !source.contains("testing") {
        return;
    }
    let Ok(tests) = go_parser::parse_go_fuzz_tests(&source) else {
        return;
    };
    for test in tests {
        out.push(provided_candidate(
            "H-G",
            Lang::Go,
            path,
            test.line,
            test.name,
        ));
    }
}

fn provided_candidate(prefix: &str, lang: Lang, path: &Path, line: u32, name: String) -> Candidate {
    Candidate {
        harness_id: crate::auto::discovery::stable_harness_id(prefix, path, line, &name),
        lang,
        source_path: path.to_path_buf(),
        line,
        name,
        score: PROVIDED_SCORE,
        is_static: false,
        foreign_guard: None,
        // The project's own fuzz entry point: its input is the input the
        // project fuzzes the code with.
        input_reachability: Some(target_rank::InputReachability::AttackerReachable),
        input_reachability_basis: None,
        dialect: None,
    }
}

/// The import record `bhf project import-ossfuzz` writes in the work dir.
const IMPORT_RECORD: &str = "ossfuzz/import.json";

/// What `bhf auto` reads of an OSS-Fuzz import's record.
#[derive(Debug, Deserialize)]
struct ImportRecord {
    schema: String,
    /// The source tree the project's `build.sh` built.
    source: PathBuf,
    #[serde(default)]
    fuzzers: Vec<ImportedFuzzer>,
}

/// A fuzzer an OSS-Fuzz import registered, as its record lists it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct ImportedFuzzer {
    pub name: String,
    /// The fuzzer the build left in `$OUT`, `<work>/ossfuzz/out/<name>`.
    pub binary: PathBuf,
    /// The registered harness, `<work>/build/<name>/main`.
    pub harness: PathBuf,
    /// `builtin` for a fuzzer linked with bhf's driver, `binary` otherwise.
    pub engine: String,
    #[serde(default)]
    pub seeds: Option<ImportedSeeds>,
    /// The dictionaries the import merged into the registered harness's
    /// `dictionary.txt` (in `$OUT`).
    #[serde(default)]
    pub dictionaries: Vec<PathBuf>,
    #[serde(default)]
    pub dictionary_tokens: usize,
    #[serde(default)]
    pub options: FuzzOptions,
    /// What the import did not apply, and why.
    #[serde(default)]
    pub notes: Vec<String>,
}

/// The seed corpus an import unpacked for a fuzzer.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct ImportedSeeds {
    pub dir: PathBuf,
}

/// The OSS-Fuzz import recorded in `work_dir`, if any.
fn read_import(work_dir: &Path) -> Result<Option<ImportRecord>, String> {
    let path = work_dir.join(IMPORT_RECORD);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("could not read {}: {error}", path.display())),
    };
    let record: ImportRecord = serde_json::from_slice(&bytes)
        .map_err(|error| format!("{} could not be read: {error}", path.display()))?;
    if record.schema != crate::ossfuzz_import::IMPORT_SCHEMA {
        return Err(format!(
            "{} is a `{}` record, not `{}`",
            path.display(),
            record.schema,
            crate::ossfuzz_import::IMPORT_SCHEMA
        ));
    }
    Ok(Some(record))
}

/// The harness id of an imported fuzzer: it names the registered harness,
/// so the same fuzzer of the same work dir keeps it from run to run.
fn imported_harness_id(lang: Lang, fuzzer: &ImportedFuzzer) -> String {
    let prefix = if lang == Lang::C { "H-C" } else { "H-X" };
    crate::auto::discovery::stable_harness_id(prefix, &fuzzer.harness, 0, &fuzzer.name)
}

/// The fuzzers a `bhf project import-ossfuzz` of `tree` (or of a tree that
/// holds it, or that it holds) registered in `work_dir`, as provided
/// harnesses, and a note for each import that is not taken. Each is a
/// target named after the fuzzer, in the C or C++ source that defines its
/// `LLVMFuzzerTestOneInput` (OSS-Fuzz names a fuzzer after that file), or
/// at its registered binary when no such source is found.
pub fn discover_imported(
    work_dir: &Path,
    tree: &Path,
    filter: &DirFilter,
) -> (Vec<Candidate>, Vec<String>) {
    let record = match read_import(work_dir) {
        Ok(Some(record)) => record,
        Ok(None) => return (Vec::new(), Vec::new()),
        Err(error) => {
            return (
                Vec::new(),
                vec![format!(
                    "  OSS-Fuzz import: {error}; its fuzzers are not fuzzed (run `bhf project \
                     import-ossfuzz` again)"
                )],
            )
        }
    };
    let tree = crate::workdir::plain_canonical(tree);
    let source = crate::workdir::plain_canonical(&record.source);
    if !(tree.starts_with(&source) || source.starts_with(&tree)) {
        return (
            Vec::new(),
            vec![format!(
                "  OSS-Fuzz import in {}: it is of {}, not of {}, so its fuzzers are not fuzzed",
                work_dir.join("ossfuzz").display(),
                source.display(),
                tree.display()
            )],
        );
    }
    let names: Vec<&str> = record.fuzzers.iter().map(|f| f.name.as_str()).collect();
    let sources = fuzzer_sources(&source, &names, filter);
    let candidates = record
        .fuzzers
        .iter()
        .map(|fuzzer| {
            let (path, line, lang) = sources
                .get(&fuzzer.name)
                .cloned()
                .unwrap_or_else(|| (fuzzer.harness.clone(), 1, Lang::Cpp));
            let mut candidate = provided_candidate("H-X", lang, &path, line, fuzzer.name.clone());
            candidate.harness_id = imported_harness_id(lang, fuzzer);
            candidate
        })
        .collect();
    (candidates, Vec::new())
}

/// For each of `names`, the C or C++ file under `root` named after it that
/// defines `LLVMFuzzerTestOneInput`, with that line and its language.
fn fuzzer_sources(
    root: &Path,
    names: &[&str],
    filter: &DirFilter,
) -> std::collections::HashMap<String, (PathBuf, u32, Lang)> {
    const MARKER: &str = "LLVMFuzzerTestOneInput";
    let mut found = std::collections::HashMap::new();
    let mut stack = vec![root.to_path_buf()];
    let mut seen = 0usize;
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            seen += 1;
            if seen > WALK_BUDGET {
                return found;
            }
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                if !crate::auto::discovery::is_excluded_provided_harness_dir(&path, filter) {
                    stack.push(path);
                }
                continue;
            }
            let (Some(stem), Some(ext)) = (
                path.file_stem().and_then(|stem| stem.to_str()),
                path.extension().and_then(|ext| ext.to_str()),
            ) else {
                continue;
            };
            let lang = match ext {
                "c" => Lang::C,
                "cc" | "cpp" | "cxx" | "c++" | "C" => Lang::Cpp,
                _ => continue,
            };
            if !kind.is_file() || !names.contains(&stem) || found.contains_key(stem) {
                continue;
            }
            let Ok(text) = crate::source_text::read_source_text(&path) else {
                continue;
            };
            if let Some(index) = text.lines().position(|line| line.contains(MARKER)) {
                found.insert(stem.to_owned(), (path, index as u32 + 1, lang));
            }
        }
    }
    found
}

/// The imported fuzzer `candidate` is, when an OSS-Fuzz import registered it
/// in `work_dir`.
pub(crate) fn imported_fuzzer(work_dir: &Path, candidate: &Candidate) -> Option<ImportedFuzzer> {
    if !matches!(candidate.lang, Lang::C | Lang::Cpp) {
        return None;
    }
    read_import(work_dir)
        .ok()
        .flatten()?
        .fuzzers
        .into_iter()
        .find(|fuzzer| {
            fuzzer.name == candidate.name
                && imported_harness_id(candidate.lang, fuzzer) == candidate.harness_id
        })
}

/// The directories under `<work>/build/` an OSS-Fuzz import in `work_dir`
/// registered its fuzzers in, by name: they are the import's, so a fresh
/// `bhf auto` run in the work dir keeps them for `bhf fuzz --harness`.
pub(crate) fn imported_registrations(work_dir: &Path) -> Vec<std::ffi::OsString> {
    let Ok(Some(record)) = read_import(work_dir) else {
        return Vec::new();
    };
    record
        .fuzzers
        .iter()
        .filter_map(|fuzzer| {
            let dir = fuzzer.harness.parent()?;
            let in_build = dir
                .parent()
                .and_then(Path::file_name)
                .is_some_and(|name| name == "build");
            in_build.then(|| dir.file_name().map(ToOwned::to_owned))?
        })
        .collect()
}

/// Whether `harness_dir` holds an imported fuzzer [`stage_imported_fuzzer`]
/// staged, which is built already.
pub(crate) fn is_staged_import(harness_dir: &Path) -> bool {
    read_record(harness_dir).is_some_and(|record| record.origin == Origin::OssfuzzImport)
}

/// Stage the imported `fuzzer` as `candidate`'s harness in `harness_dir`
/// from what the import keeps under `<work>/ossfuzz/`: the binary the build
/// left in `$OUT` as `main`, declared framed as its registration is, the
/// dictionaries it took for it merged into `dictionary.txt`, and the files
/// of its unpacked seed corpus, with a record of what came with it (its
/// `.options` included, which its fuzz passes use).
/// A fuzzer linked without bhf's driver is recorded and skipped: bhf's
/// engine cannot drive it, and `bhf project run` runs it. The error says
/// whether the target is skipped (`true`) or failed to build.
pub(crate) fn stage_imported_fuzzer(
    fuzzer: &ImportedFuzzer,
    candidate: &Candidate,
    harness_dir: &Path,
) -> Result<(), (String, bool)> {
    let io = |what: &str, error: std::io::Error| (format!("{what}: {error}"), false);
    std::fs::create_dir_all(harness_dir)
        .map_err(|e| io(&format!("create {}", harness_dir.display()), e))?;
    clear(harness_dir).map_err(|e| io(&format!("clear {}", harness_dir.display()), e))?;
    let mut record =
        ProvidedRecord::new(Origin::OssfuzzImport, &fuzzer.name, &candidate.source_path);
    record.options = fuzzer.options.clone();
    record.notes = fuzzer.notes.clone();
    let refused = if fuzzer.engine != "builtin" {
        Some((
            format!(
                "`{}` was linked without bhf's driver (`-fsanitize=fuzzer` in place of \
                 `$LIB_FUZZING_ENGINE`), so bhf's engine cannot drive it; `bhf project run \
                 --target {}` on the import's manifest runs it one input file per process",
                fuzzer.name, fuzzer.name
            ),
            true,
        ))
    } else if !fuzzer.binary.is_file() {
        Some((
            format!(
                "the imported fuzzer {} is missing; run `bhf project import-ossfuzz` again",
                fuzzer.binary.display()
            ),
            false,
        ))
    } else {
        None
    };
    if let Some(refused) = refused {
        write_record(harness_dir, &record).map_err(|e| io("record the imported fuzzer", e))?;
        return Err(refused);
    }
    let main = harness_dir.join(crate::auto::layout::harness_exe_name("main"));
    std::fs::copy(&fuzzer.binary, &main)
        .map_err(|e| io(&format!("copy {}", fuzzer.binary.display()), e))?;
    crate::protocol_detect::write_declared_input_mode(
        harness_dir,
        "framed",
        "OSS-Fuzz build.sh linked with bhf's driver (bhf project import-ossfuzz)",
    )
    .map_err(|e| (format!("record the fuzzer's input mode: {e}"), false))?;
    let dictionary = harness_dir.join("dictionary.txt");
    match std::fs::remove_file(&dictionary) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            return Err(io(&format!("remove {}", dictionary.display()), error));
        }
        _ => {}
    }
    record.dictionary_tokens =
        append_dictionaries(harness_dir, &fuzzer.dictionaries).map_err(|e| (e, false))?;
    record.dictionaries = fuzzer.dictionaries.clone();
    if let Some(seeds) = &fuzzer.seeds {
        let (copied, skipped) = copy_seed_files(harness_dir, std::slice::from_ref(&seeds.dir))
            .map_err(|e| io("copy the imported seeds", e))?;
        record.seeds = copied;
        record.seed_sources = vec![seeds.dir.clone()];
        if skipped > 0 {
            record.notes.push(format!(
                "{skipped} seed file(s) were left out: past the seed count or size limits"
            ));
        }
    }
    write_record(harness_dir, &record).map_err(|e| io("record the imported fuzzer", e))
}

/// Put the `provided` harnesses ahead of the discovered `candidates`, each
/// once, and drop a discovered candidate that is one of them or is defined
/// in a provided harness's file: that file is harness glue, not library code.
pub fn merge_into(candidates: &mut Vec<Candidate>, provided: Vec<Candidate>) {
    if provided.is_empty() {
        return;
    }
    let ids: std::collections::HashSet<String> =
        provided.iter().map(|c| c.harness_id.clone()).collect();
    let files: std::collections::HashSet<PathBuf> =
        provided.iter().map(|c| c.source_path.clone()).collect();
    let mut merged = Vec::with_capacity(candidates.len() + provided.len());
    let mut taken = std::collections::HashSet::new();
    for candidate in provided {
        if taken.insert(candidate.harness_id.clone()) {
            merged.push(candidate);
        }
    }
    merged.extend(std::mem::take(candidates).into_iter().filter(|candidate| {
        !ids.contains(&candidate.harness_id) && !files.contains(&candidate.source_path)
    }));
    *candidates = merged;
}

/// One line naming how many provided harnesses of each kind `candidates`
/// holds, `imported` of them fuzzers an OSS-Fuzz import registered, or
/// `None` when it holds none.
pub(crate) fn discovered_note(candidates: &[Candidate], imported: usize) -> Option<String> {
    let mut counts = std::collections::BTreeMap::new();
    for candidate in candidates {
        if let Some(origin) = origin(candidate) {
            *counts.entry(origin).or_insert(0usize) += 1;
        }
    }
    if imported > 0 {
        counts.insert(Origin::OssfuzzImport, imported);
    }
    let total: usize = counts.values().sum();
    (total > 0).then(|| {
        let kinds: Vec<String> = counts
            .iter()
            .map(|(origin, n)| format!("{n} {}(s)", origin.describe()))
            .collect();
        format!(
            "  provided harnesses: {total} the project ships ({}), fuzzed first",
            kinds.join(", ")
        )
    })
}

/// The run summary's provided-harness block: each provided harness the run
/// attempted, with its outcome and the seeds it started from. Empty when the
/// run had none.
pub(crate) fn render_summary(results: &[crate::auto::attempt::AttemptResult]) -> String {
    use std::fmt::Write;
    let rows: Vec<_> = results
        .iter()
        .filter_map(|r| Some((r, target_record(&r.candidate, &r.harness_dir)?)))
        .collect();
    if rows.is_empty() {
        return String::new();
    }
    let mut s = String::new();
    let _ = writeln!(s);
    let _ = writeln!(s, "Provided harnesses ({})", rows.len());
    for (r, record) in rows {
        let _ = writeln!(
            s,
            "  {} {} [{}]: {}, {} seed(s)",
            r.candidate.harness_id,
            record.entry,
            record.origin.as_str(),
            crate::auto::cli::outcome_label(&r.outcome),
            record.seeds
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    const FUZZ_TEST: &str = "package widget\n\nimport \"testing\"\n\n\
        func FuzzParseRecord(f *testing.F) {\n\
        \tf.Fuzz(func(t *testing.T, data []byte) { ParseRecord(data) })\n}\n\n\
        func TestParseRecord(t *testing.T) {}\n";

    #[test]
    fn go_fuzz_tests_are_found_in_test_and_fuzz_dirs_but_not_in_vendored_code() {
        let root = crate::test_support::TestDir::new("provided-go");
        write(
            &root.join("widget/widget.go"),
            "package widget\nfunc ParseRecord(b []byte) {}\n",
        );
        write(&root.join("widget/widget_test.go"), FUZZ_TEST);
        write(&root.join("fuzz/more_test.go"), FUZZ_TEST);
        write(&root.join("vendor/other/x_test.go"), FUZZ_TEST);
        write(&root.join(".hidden/x_test.go"), FUZZ_TEST);
        // The go tool ignores `testdata/` and `_`-prefixed directories: a
        // fuzz test there is sample input, not one of the project's.
        write(
            &root.join("widget/testdata/sample/sample_test.go"),
            FUZZ_TEST,
        );
        write(&root.join("_scratch/old_test.go"), FUZZ_TEST);
        write(&root.join("widget/_drafts/nested/draft_test.go"), FUZZ_TEST);
        // Not a test file, so not a fuzz test.
        write(&root.join("widget/notatest.go"), FUZZ_TEST);
        let found = discover(&root, &DirFilter::default());
        let rows: Vec<(String, u32, &str)> = found
            .iter()
            .map(|c| {
                (
                    c.source_path
                        .strip_prefix(&*root)
                        .unwrap()
                        .display()
                        .to_string(),
                    c.line,
                    c.name.as_str(),
                )
            })
            .collect();
        assert_eq!(
            rows,
            [
                ("fuzz/more_test.go".to_owned(), 5, "FuzzParseRecord"),
                ("widget/widget_test.go".to_owned(), 5, "FuzzParseRecord"),
            ]
        );
        assert!(found.iter().all(|c| c.lang == Lang::Go
            && c.harness_id.starts_with("H-G")
            && c.score == PROVIDED_SCORE
            && origin(c) == Some(Origin::GoFuzzTest)));
        // `--exclude-dir fuzz` keeps it out.
        let excluded = discover(&root, &DirFilter::new(&["fuzz".to_owned()], &[]));
        assert_eq!(excluded.len(), 1, "{excluded:?}");
    }

    const ATHERIS_HARNESS: &str = "import sys\nimport atheris\n\n\
        def TestOneInput(data):\n    pass\n\n\
        def helper(data):\n    return data\n\n\
        if __name__ == \"__main__\":\n    atheris.Setup(sys.argv, TestOneInput)\n    atheris.Fuzz()\n";

    #[test]
    fn atheris_harnesses_are_found_in_fuzz_dirs_and_their_files_are_not_targets() {
        let root = crate::test_support::TestDir::new("provided-atheris");
        write(&root.join("fuzz/fuzz_widget.py"), ATHERIS_HARNESS);
        // An `_`-prefixed package is still Python's, but `testdata/` is not
        // the project's own code.
        write(&root.join("_fuzzers/fuzz_more.py"), ATHERIS_HARNESS);
        write(&root.join("tests/testdata/fuzz_sample.py"), ATHERIS_HARNESS);
        write(
            &root.join("widget/__init__.py"),
            "def parse_record(data):\n    return data\n",
        );
        let mut found = discover(&root, &DirFilter::default());
        let files: Vec<PathBuf> = found
            .iter()
            .map(|c| c.source_path.strip_prefix(&*root).unwrap().to_path_buf())
            .collect();
        assert_eq!(
            files,
            [
                Path::new("_fuzzers/fuzz_more.py"),
                Path::new("fuzz/fuzz_widget.py")
            ]
        );
        found.remove(0);
        let harness = &found[0];
        assert_eq!(
            (harness.name.as_str(), harness.line, harness.lang),
            ("TestOneInput", 4, Lang::Python)
        );
        assert!(harness.harness_id.starts_with("H-P"));
        assert_eq!(origin(harness), Some(Origin::Atheris));
        let entry = atheris_entry(harness).expect("an Atheris entry point");
        assert_eq!(entry.callback, "TestOneInput");
        // The harness file's other functions are glue, not targets.
        let mut glue = harness.clone();
        glue.harness_id = "H-P0007-00000000".to_owned();
        glue.name = "helper".to_owned();
        assert!(origin(&glue).is_none());
        let mut candidates = vec![glue, candidate("H-P1", "parse_record")];
        merge_into(&mut candidates, found);
        let names: Vec<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["TestOneInput", "parse_record"]);
    }

    #[cfg(unix)]
    #[test]
    fn seed_corpus_files_are_copied_as_they_are_but_not_through_a_symlink() {
        let dir = crate::test_support::TestDir::new("provided-copy-seeds");
        write(&dir.join("corpus/b record"), "second");
        write(&dir.join("corpus/a/nested"), "first");
        write(&dir.join("one.bin"), "third");
        write(&dir.join("outside"), "host file");
        std::os::unix::fs::symlink(dir.join("outside"), dir.join("corpus/link")).unwrap();
        std::fs::write(
            dir.join("corpus/c-too-large"),
            vec![0u8; MAX_SEED_BYTES as usize + 1],
        )
        .unwrap();
        let harness = dir.join("harness");
        let counts = copy_seed_files(&harness, &[dir.join("corpus"), dir.join("one.bin")]).unwrap();
        assert_eq!(
            counts,
            (3, 2),
            "the symlink and the oversized file are left out"
        );
        let mut names: Vec<String> = std::fs::read_dir(harness.join(SEEDS_DIR))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                "seed-0000-nested",
                "seed-0001-b_record",
                "seed-0002-one.bin"
            ]
        );
        assert_eq!(
            load_seeds(&harness),
            [b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
        );
    }

    /// A work dir with an OSS-Fuzz import of `tree`: `parse_record_fuzzer`
    /// (linked with bhf's driver, with seeds, dictionaries and options) and
    /// `raw_fuzzer` (a libFuzzer binary without it), as the import keeps
    /// them under `ossfuzz/`. Their registrations under `build/` are not
    /// needed: a fresh `bhf auto` run refreshes that directory.
    fn imported_work_dir(root: &Path, tree: &Path) -> PathBuf {
        let work = root.join("work");
        let out = work.join("ossfuzz/out");
        write(
            &out.join("parse_record_fuzzer"),
            "#!/bin/sh\n# BHF_FRAMED\n",
        );
        write(&out.join("parse_record_fuzzer.dict"), "magic=\"REC1\"\n");
        write(&out.join("raw_fuzzer"), "#!/bin/sh\n");
        let registered = work.join("build/parse_record_fuzzer");
        let seeds = work.join("ossfuzz/seeds/parse_record_fuzzer");
        write(&seeds.join("short_record"), "REC1\x01A");
        write(&seeds.join("nested/full_record"), "REC1\x02AB");
        let record = serde_json::json!({
            "schema": crate::ossfuzz_import::IMPORT_SCHEMA,
            "project": "records",
            "source": tree,
            "fuzzers": [
                {
                    "name": "parse_record_fuzzer",
                    "binary": out.join("parse_record_fuzzer"),
                    "harness": registered.join("main"),
                    "engine": "builtin",
                    "seeds": { "dir": seeds, "files": 2 },
                    "dictionaries": [out.join("parse_record_fuzzer.dict")],
                    "dictionary_tokens": 1,
                    "options": { "max_len": 64, "timeout_secs": 5, "rss_limit_mb": null },
                    "notes": ["[asan] detect_leaks = 0 is not applied: bhf has no equivalent"],
                },
                {
                    "name": "raw_fuzzer",
                    "binary": out.join("raw_fuzzer"),
                    "harness": work.join("build/raw_fuzzer/main"),
                    "engine": "binary",
                    "seeds": null,
                    "dictionaries": [],
                    "dictionary_tokens": 0,
                    "options": { "max_len": null, "timeout_secs": null, "rss_limit_mb": null },
                    "notes": [],
                },
            ],
        });
        write(
            &work.join(IMPORT_RECORD),
            &serde_json::to_string_pretty(&record).unwrap(),
        );
        work
    }

    const FUZZER_SOURCE: &str = "#include <stdint.h>\n#include \"record.h\"\n\n\
        extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n\
        \x20   return 0;\n}\n";

    #[test]
    fn imported_fuzzers_are_provided_harnesses_at_the_source_that_defines_them() {
        let root = crate::test_support::TestDir::new("provided-imported");
        let tree = crate::workdir::plain_canonical(&root.join("tree"));
        write(&tree.join("fuzz/parse_record_fuzzer.cc"), FUZZER_SOURCE);
        // Named after the fuzzer but not one: not its source.
        write(
            &tree.join("tools/raw_fuzzer.c"),
            "int main(void) { return 0; }\n",
        );
        let work = imported_work_dir(&root, &tree);
        let (found, notes) = discover_imported(&work, &tree, &DirFilter::default());
        assert!(notes.is_empty(), "{notes:?}");
        let rows: Vec<(&str, Lang, &Path, u32)> = found
            .iter()
            .map(|c| (c.name.as_str(), c.lang, c.source_path.as_path(), c.line))
            .collect();
        let raw_harness = work.join("build/raw_fuzzer/main");
        assert_eq!(
            rows,
            [
                (
                    "parse_record_fuzzer",
                    Lang::Cpp,
                    tree.join("fuzz/parse_record_fuzzer.cc").as_path(),
                    4
                ),
                ("raw_fuzzer", Lang::Cpp, raw_harness.as_path(), 1),
            ]
        );
        assert!(found
            .iter()
            .all(|c| c.harness_id.starts_with("H-X0000-") && c.score == PROVIDED_SCORE));
        // Each is the imported fuzzer it names, and a generated target of
        // the same name is not.
        let fuzzer = imported_fuzzer(&work, &found[0]).expect("an imported fuzzer");
        assert_eq!(fuzzer.name, "parse_record_fuzzer");
        assert_eq!(fuzzer.options.max_len, Some(64));
        let mut generated = found[0].clone();
        generated.harness_id = "H-X0004-0BADF00D".to_owned();
        assert!(imported_fuzzer(&work, &generated).is_none());
        assert_eq!(
            discovered_note(&found, found.len()).as_deref(),
            Some(
                "  provided harnesses: 2 the project ships (2 imported OSS-Fuzz fuzzer(s)), \
                 fuzzed first"
            )
        );

        // An import of another tree is not taken, and says so.
        let other = root.join("other");
        std::fs::create_dir_all(&other).unwrap();
        let (found, notes) = discover_imported(&work, &other, &DirFilter::default());
        assert!(found.is_empty());
        assert!(
            notes[0].contains("so its fuzzers are not fuzzed"),
            "{notes:?}"
        );
        // Nor is a record of another schema.
        write(
            &work.join(IMPORT_RECORD),
            "{\"schema\":\"bhf.ossfuzz-import.v9\",\"source\":\"/\"}",
        );
        let (found, notes) = discover_imported(&work, &tree, &DirFilter::default());
        assert!(found.is_empty());
        assert!(notes[0].contains("bhf.ossfuzz-import.v9"), "{notes:?}");
        // A work dir with no import has nothing to say.
        let (found, notes) = discover_imported(&root, &tree, &DirFilter::default());
        assert!(found.is_empty() && notes.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn an_imported_fuzzer_is_staged_with_what_came_with_it_or_skipped_without_bhfs_driver() {
        let root = crate::test_support::TestDir::new("provided-stage");
        let tree = crate::workdir::plain_canonical(&root.join("tree"));
        write(&tree.join("fuzz/parse_record_fuzzer.cc"), FUZZER_SOURCE);
        let work = imported_work_dir(&root, &tree);
        let (found, _) = discover_imported(&work, &tree, &DirFilter::default());
        let harness = crate::auto::layout::harness_dir(&work, &found[0].harness_id);
        // What an earlier run left is replaced.
        write(&harness.join(SEEDS_DIR).join("stale"), "stale");
        let fuzzer = imported_fuzzer(&work, &found[0]).unwrap();
        stage_imported_fuzzer(&fuzzer, &found[0], &harness).unwrap();
        assert!(is_staged_import(&harness));
        assert_eq!(
            std::fs::read(harness.join("main")).unwrap(),
            std::fs::read(&fuzzer.binary).unwrap()
        );
        assert!(
            std::fs::read_to_string(harness.join(crate::protocol_detect::PROTOCOL_SIDECAR))
                .unwrap()
                .contains("\"framed\"")
        );
        assert_eq!(
            std::fs::read_to_string(harness.join("dictionary.txt")).unwrap(),
            "\"REC1\"\n"
        );
        assert_eq!(
            load_seeds(&harness),
            [b"REC1\x02AB".to_vec(), b"REC1\x01A".to_vec()]
        );
        let record = target_record(&found[0], &harness).expect("reported as provided");
        assert_eq!(record.origin, Origin::OssfuzzImport);
        assert_eq!(record.entry, "parse_record_fuzzer");
        assert_eq!(record.source, tree.join("fuzz/parse_record_fuzzer.cc"));
        assert_eq!(record.seeds, 2);
        assert_eq!(
            record.seed_sources,
            [work.join("ossfuzz/seeds/parse_record_fuzzer")]
        );
        assert_eq!(record.dictionary_tokens, 1);
        assert_eq!(record.notes.len(), 1, "{:?}", record.notes);
        // Its `.options` are its fuzz passes' limits.
        let options = fuzz_options(&work, &found[0].harness_id).expect("its options");
        let (mut max_len, mut timeout, mut rss) = (4096, None, 2048);
        options.apply(&mut max_len, &mut timeout, &mut rss);
        assert_eq!(
            (max_len, timeout, rss),
            (64, Some(std::time::Duration::from_secs(5)), 2048)
        );
        assert!(fuzz_options(&work, "H-C0001-00000000").is_none());
        assert_eq!(
            imported_registrations(&work),
            ["parse_record_fuzzer", "raw_fuzzer"]
        );

        // A fuzzer linked without bhf's driver is skipped, and still
        // reported as provided.
        let raw = imported_fuzzer(&work, &found[1]).unwrap();
        let raw_dir = crate::auto::layout::harness_dir(&work, &found[1].harness_id);
        let (reason, skip) = stage_imported_fuzzer(&raw, &found[1], &raw_dir).unwrap_err();
        assert!(skip && reason.contains("without bhf's driver"), "{reason}");
        assert!(!raw_dir.join("main").exists());
        assert_eq!(
            target_record(&found[1], &raw_dir).map(|r| r.origin),
            Some(Origin::OssfuzzImport)
        );
    }

    /// A generated target in an imported fuzzer's source (the passthrough
    /// harness of its `LLVMFuzzerTestOneInput`) is the same fuzzer: it is
    /// not fuzzed twice.
    #[test]
    fn a_generated_target_in_an_imported_fuzzers_source_is_dropped() {
        let mut imported = candidate("H-X0000-00000001", "parse_record_fuzzer");
        imported.source_path = PathBuf::from("fuzz/parse_record_fuzzer.cc");
        let mut driver = candidate("H-X0004-00000002", "LLVMFuzzerTestOneInput");
        driver.source_path = imported.source_path.clone();
        let mut candidates = vec![candidate("H-C0001-00000003", "record_parse"), driver];
        merge_into(&mut candidates, vec![imported]);
        let names: Vec<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["parse_record_fuzzer", "record_parse"]);
    }

    #[test]
    fn a_provided_harnesss_dictionaries_join_the_mined_tokens_once() {
        let dir = crate::test_support::TestDir::new("provided-dict");
        write(&dir.join("dictionary.txt"), "# mined\n\"BHF\"\n");
        write(&dir.join("widget.dict"), "magic=\"BHF\"\nkind=\"\\x07\"\n");
        let tokens = append_dictionaries(&dir, &[dir.join("widget.dict")]).unwrap();
        assert_eq!(tokens, 2);
        assert_eq!(
            std::fs::read_to_string(dir.join("dictionary.txt")).unwrap(),
            "# mined\n\"BHF\"\n\"\\x07\"\n"
        );
        assert_eq!(append_dictionaries(&dir, &[]).unwrap(), 0);
    }

    fn candidate(id: &str, name: &str) -> Candidate {
        Candidate {
            harness_id: id.to_owned(),
            lang: Lang::Go,
            source_path: PathBuf::from(format!("{name}.go")),
            line: 1,
            name: name.to_owned(),
            score: 10,
            is_static: false,
            foreign_guard: None,
            input_reachability: None,
            input_reachability_basis: None,
            dialect: None,
        }
    }

    #[test]
    fn provided_harnesses_go_first_and_replace_the_same_discovered_target() {
        let mut candidates = vec![candidate("H-G1", "ParseRecord"), candidate("H-G2", "Copy")];
        merge_into(
            &mut candidates,
            vec![candidate("H-G2", "Copy"), candidate("H-G9", "FuzzCopy")],
        );
        let ids: Vec<&str> = candidates.iter().map(|c| c.harness_id.as_str()).collect();
        assert_eq!(ids, ["H-G2", "H-G9", "H-G1"]);
    }

    #[test]
    fn seeds_load_in_name_order_within_their_bounds() {
        let dir = crate::test_support::TestDir::new("provided-seeds");
        write(&dir.join(SEEDS_DIR).join("b"), "second");
        write(&dir.join(SEEDS_DIR).join("a"), "first");
        std::fs::write(
            dir.join(SEEDS_DIR).join("c-too-large"),
            vec![0u8; MAX_SEED_BYTES as usize + 1],
        )
        .unwrap();
        assert_eq!(load_seeds(&dir), [b"first".to_vec(), b"second".to_vec()]);
        clear(&dir).unwrap();
        assert!(load_seeds(&dir).is_empty());
    }

    #[test]
    fn a_provided_harness_that_did_not_build_is_still_reported_as_provided() {
        let dir = crate::test_support::TestDir::new("provided-record");
        let mut fuzz_test = candidate("H-G3", "FuzzParseRecord");
        fuzz_test.source_path = PathBuf::from("widget/widget_test.go");
        let record = target_record(&fuzz_test, &dir).expect("a fuzz test is provided");
        assert_eq!(record.origin, Origin::GoFuzzTest);
        assert_eq!(record.entry, "FuzzParseRecord");
        assert_eq!(record.seeds, 0);
        let built = ProvidedRecord {
            seeds: 3,
            seed_sources: vec![PathBuf::from("widget/testdata/fuzz/FuzzParseRecord")],
            ..record
        };
        write_record(&dir, &built).unwrap();
        assert_eq!(target_record(&fuzz_test, &dir), Some(built));
        assert!(target_record(&candidate("H-G4", "ParseRecord"), &dir).is_none());
    }
}
