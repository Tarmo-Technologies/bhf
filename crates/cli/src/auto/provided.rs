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
//!   package, with its `f.Add` seeds and its `testdata/fuzz/<Name>` corpus.
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
}

impl Origin {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Origin::GoFuzzTest => "go-fuzz-test",
        }
    }

    /// How a person names one.
    fn describe(self) -> &'static str {
        match self {
            Origin::GoFuzzTest => "Go native fuzz test",
        }
    }
}

/// A provided harness as `run.json` reports it (`targets[].provided_harness`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProvidedRecord {
    pub origin: Origin,
    /// The entry point: the fuzz test's name.
    pub entry: String,
    /// The file that defines it.
    pub source: PathBuf,
    /// How many starting inputs came with it.
    #[serde(default)]
    pub seeds: usize,
    /// Where they came from (the `f.Add` calls are counted, not named).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub seed_sources: Vec<PathBuf>,
    /// Starting inputs it came with that could not be used, and why.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
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

/// Where `candidate` came from, when it is a provided harness.
pub(crate) fn origin(candidate: &Candidate) -> Option<Origin> {
    is_go_fuzz_test(candidate).then_some(Origin::GoFuzzTest)
}

/// What `run.json` reports for `candidate`: the record its build left, or,
/// for a provided harness that did not build, its origin and entry point.
pub(crate) fn target_record(candidate: &Candidate, harness_dir: &Path) -> Option<ProvidedRecord> {
    let origin = origin(candidate)?;
    Some(
        read_record(harness_dir)
            .filter(|record| record.origin == origin)
            .unwrap_or_else(|| ProvidedRecord {
                origin,
                entry: candidate.name.clone(),
                source: candidate.source_path.clone(),
                seeds: 0,
                seed_sources: Vec::new(),
                notes: Vec::new(),
            }),
    )
}

/// The provided harnesses under `root` (a directory, or one file): every Go
/// native fuzz test. The walk looks in test and fuzz directories, which
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

/// Put the `provided` harnesses ahead of the discovered `candidates`, each
/// once, and drop a discovered candidate that is one of them.
pub fn merge_into(candidates: &mut Vec<Candidate>, provided: Vec<Candidate>) {
    if provided.is_empty() {
        return;
    }
    let ids: std::collections::HashSet<String> =
        provided.iter().map(|c| c.harness_id.clone()).collect();
    let mut merged = Vec::with_capacity(candidates.len() + provided.len());
    let mut taken = std::collections::HashSet::new();
    for candidate in provided {
        if taken.insert(candidate.harness_id.clone()) {
            merged.push(candidate);
        }
    }
    merged.extend(
        std::mem::take(candidates)
            .into_iter()
            .filter(|candidate| !ids.contains(&candidate.harness_id)),
    );
    *candidates = merged;
}

/// One line naming how many provided harnesses of each kind `candidates`
/// holds, or `None` when it holds none.
pub(crate) fn discovered_note(candidates: &[Candidate]) -> Option<String> {
    let mut counts = std::collections::BTreeMap::new();
    for candidate in candidates {
        if let Some(origin) = origin(candidate) {
            *counts.entry(origin).or_insert(0usize) += 1;
        }
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
