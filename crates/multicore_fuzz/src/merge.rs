// SPDX-License-Identifier: Apache-2.0

//! Fold worker findings into the campaign's own `results/findings`, so the
//! parent `bhf fuzz` indexes what its workers found. A worker finding moves to
//! a fresh parent id unless a finding of the same harness already there, or
//! one met earlier in the merge, shares any of its
//! [`corpus::finding::dedupe_keys`]; duplicates stay in the worker dir. A
//! record with no key always moves. Symlinks under a worker dir are never
//! followed or moved.
//!
//! `finding.json` is the commit point, so neither a crash nor an I/O error
//! leaves a half-moved finding the results loader would index:
//! 1. reserve the parent dir with `create_dir`;
//! 2. atomically rewrite the worker's `finding.json` to carry that parent id
//!    (and a history entry): the intent log;
//! 3. move every other file, subdirectories included (across devices: copy to
//!    `<name>.partial`, then rename);
//! 4. move `finding.json` last.
//!
//! A later merge that meets a worker record whose parent dir exists without a
//! `finding.json` resumes into that dir. A finding that fails is counted in
//! [`MergeReport::failed`] and the merge goes on with the next one.

use crate::MulticoreError;
use corpus::layout::FamilyAllocator;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// Directory entries read per findings dir; the rest count as one failure.
pub const MAX_FINDING_ENTRIES: usize = 100_000;
/// Size cap of one `finding.json`, as the results loader's; a larger one is
/// unreadable.
pub const MAX_FINDING_RECORD_BYTES: u64 = 8 * 1024 * 1024;
/// Failures [`MergeReport::errors`] keeps.
const MAX_REPORTED_ERRORS: usize = 5;
const RECORD: &str = "finding.json";
/// The temp file of the atomic intent rewrite, next to the worker's record.
const RECORD_TMP: &str = "finding.json.tmp";
/// The history entry that marks a worker record's `id` as its parent id.
const INTENT_COMMAND: &str = "fuzz";
const INTENT_FIELDS: [&str; 1] = ["id"];

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergeReport {
    /// Parent ids the merged findings received, in merge order.
    pub merged: Vec<String>,
    /// Worker findings the parent already held under another id.
    pub duplicates: usize,
    /// Worker finding dirs whose `finding.json` is not a readable record (bad
    /// JSON, too large, a symlink), left in place.
    pub unreadable: usize,
    /// Worker findings that could not be moved. They stay in their worker
    /// dir, and the next merge resumes them.
    #[serde(default)]
    pub failed: usize,
    /// The first few failures, each naming its source and target.
    #[serde(default)]
    pub errors: Vec<String>,
}

impl MergeReport {
    fn fail(&mut self, error: String) {
        self.failed += 1;
        if self.errors.len() < MAX_REPORTED_ERRORS {
            self.errors.push(error);
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Limits {
    entries: usize,
    record_bytes: u64,
}

const LIMITS: Limits = Limits {
    entries: MAX_FINDING_ENTRIES,
    record_bytes: MAX_FINDING_RECORD_BYTES,
};

/// Points in one finding's merge where the tests inject faults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// The parent dir is reserved and the intent logged; nothing moved yet.
    Reserved,
    /// Everything but `finding.json` has moved.
    Moved,
}

type Fault<'a> = &'a mut dyn FnMut(Stage, &Path) -> io::Result<()>;

/// Merge every finding under each `worker_dirs[i]/results/findings` into
/// `work_dir/results/findings`, in worker order, then finding-name order.
/// Only a parent `results/` or `results/findings` that is a symlink or not a
/// directory, or an unreadable parent findings dir, fails the whole merge.
pub fn merge_worker_findings(
    work_dir: &Path,
    worker_dirs: &[PathBuf],
) -> Result<MergeReport, MulticoreError> {
    merge_with(work_dir, worker_dirs, LIMITS, &mut |_, _| Ok(()))
}

fn merge_with(
    work_dir: &Path,
    worker_dirs: &[PathBuf],
    limits: Limits,
    fault: Fault<'_>,
) -> Result<MergeReport, MulticoreError> {
    refuse_unsafe_parent(work_dir)?;
    let parent = corpus::layout::findings_dir(work_dir);
    let mut seen = Seen::default();
    for dir in real_subdirs(&parent, limits.entries)?.dirs {
        if let Ok(Some(record)) = read_record(&dir, limits.record_bytes) {
            seen.insert(Seen::keys(&record));
        }
    }
    let mut ids = FamilyAllocator::new(&parent, "F-")?;
    let mut report = MergeReport::default();
    for worker in worker_dirs {
        let findings = corpus::layout::findings_dir(worker);
        let listing = match worker_finding_dirs(worker, limits.entries) {
            Ok(listing) => listing,
            Err(error) => {
                report.fail(format!("{}: {error}", findings.display()));
                continue;
            }
        };
        if listing.truncated {
            report.fail(format!(
                "{}: more than {} entries; the rest were not merged",
                findings.display(),
                limits.entries
            ));
        }
        for source in listing.dirs {
            let record = match read_record(&source, limits.record_bytes) {
                Ok(Some(record)) => record,
                // Merged before: only a symlink or special file stayed behind.
                Ok(None) => continue,
                Err(_) => {
                    report.unreadable += 1;
                    continue;
                }
            };
            let keys = Seen::keys(&record);
            let resume = resumable(&ids, &record);
            if resume.is_none() && seen.holds(&keys) {
                seen.insert(keys);
                report.duplicates += 1;
                continue;
            }
            match merge_one(&source, record, resume, &mut ids, &parent, fault) {
                Ok(id) => {
                    seen.insert(keys);
                    report.merged.push(id);
                }
                Err(error) => report.fail(error),
            }
        }
    }
    Ok(report)
}

/// Distinct crashes across `worker_dirs`, by the merge's rule: a finding
/// counts unless an earlier one of its harness shares one of its keys. Equals
/// what [`merge_worker_findings`] merges into an empty parent.
pub(crate) fn count_unique<'a>(worker_dirs: impl IntoIterator<Item = &'a Path>) -> usize {
    let mut seen = Seen::default();
    let mut unique = 0;
    for worker in worker_dirs {
        let Ok(listing) = worker_finding_dirs(worker, LIMITS.entries) else {
            continue;
        };
        for dir in listing.dirs {
            let Ok(Some(record)) = read_record(&dir, LIMITS.record_bytes) else {
                continue;
            };
            let keys = Seen::keys(&record);
            if !seen.holds(&keys) {
                unique += 1;
            }
            seen.insert(keys);
        }
    }
    unique
}

/// Crash keys already held, each scoped by its record's `harness_id`.
#[derive(Default)]
struct Seen(HashSet<(String, String)>);

impl Seen {
    fn keys(record: &Value) -> Vec<(String, String)> {
        let harness = record
            .get("harness_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        corpus::finding::dedupe_keys(record)
            .into_iter()
            .map(|key| (harness.to_owned(), key))
            .collect()
    }

    /// Whether any of `keys` is held; a keyless record never is.
    fn holds(&self, keys: &[(String, String)]) -> bool {
        keys.iter().any(|key| self.0.contains(key))
    }

    fn insert(&mut self, keys: Vec<(String, String)>) {
        self.0.extend(keys);
    }
}

/// The parent's `results/` and `results/findings` must each be missing or a
/// real directory: through a symlink the merge would write outside the work
/// dir.
fn refuse_unsafe_parent(work_dir: &Path) -> Result<(), MulticoreError> {
    for path in [
        corpus::layout::results_dir(work_dir),
        corpus::layout::findings_dir(work_dir),
    ] {
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_dir() => {}
            Ok(meta) => {
                let reason = if meta.file_type().is_symlink() {
                    "a symlink"
                } else {
                    "not a directory"
                };
                return Err(MulticoreError::UnsafeFindingsDir { path, reason });
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[derive(Default)]
struct Listing {
    /// Real subdirectories, sorted.
    dirs: Vec<PathBuf>,
    /// The dir held more than the entry cap; `dirs` covers only part of it.
    truncated: bool,
}

/// `<worker>/results/findings/*`, only when every level is a real directory.
fn worker_finding_dirs(worker: &Path, max_entries: usize) -> io::Result<Listing> {
    let results = corpus::layout::results_dir(worker);
    if [worker, results.as_path()]
        .iter()
        .all(|dir| is_real_dir(dir))
    {
        real_subdirs(&corpus::layout::findings_dir(worker), max_entries)
    } else {
        Ok(Listing::default())
    }
}

/// The subdirectories among `dir`'s first `max_entries` entries (none when
/// `dir` is missing or a symlink), skipping symlinks.
fn real_subdirs(dir: &Path, max_entries: usize) -> io::Result<Listing> {
    let mut listing = Listing::default();
    if !is_real_dir(dir) {
        return Ok(listing);
    }
    for (index, entry) in std::fs::read_dir(dir)?.enumerate() {
        if index >= max_entries {
            listing.truncated = true;
            break;
        }
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            listing.dirs.push(entry.path());
        }
    }
    listing.dirs.sort();
    Ok(listing)
}

fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|meta| meta.is_dir())
}

/// `dir/finding.json` as a JSON object, read as the results loader reads it:
/// never through a symlink, at most `max_bytes`. `None` when there is none.
fn read_record(dir: &Path, max_bytes: u64) -> Result<Option<Value>, String> {
    let file = match open_record(dir) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!("{RECORD} exceeds {max_bytes} bytes"));
    }
    let record: Value = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if record.is_object() {
        Ok(Some(record))
    } else {
        Err(format!("{RECORD} is not a JSON object"))
    }
}

/// Open `dir/finding.json` refusing a symlink at either level, and anything
/// but a regular file.
#[cfg(unix)]
fn open_record(dir: &Path) -> io::Result<std::fs::File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::OpenOptionsExt;

    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)?;
    let name = CString::new(RECORD).expect("literal has no NUL");
    // SAFETY: `directory` is an open directory and `name` a NUL-terminated
    // relative path; the returned descriptor is checked below.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just opened here and nothing else owns it.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{RECORD} is not a regular file"),
        ));
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_record(dir: &Path) -> io::Result<std::fs::File> {
    let path = dir.join(RECORD);
    if std::fs::symlink_metadata(&path)?.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{RECORD} is a symlink; not followed"),
        ));
    }
    let file = std::fs::File::open(&path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{RECORD} is not a regular file"),
        ));
    }
    Ok(file)
}

/// Whether the record's last history entry is the merge's intent: its `id`
/// then names the parent dir an earlier merge reserved for it.
fn carries_intent(record: &Value) -> bool {
    record
        .get("history")
        .and_then(Value::as_array)
        .and_then(|history| history.last())
        .is_some_and(|entry| {
            entry.get("command") == Some(&json!(INTENT_COMMAND))
                && entry.get("fields") == Some(&json!(INTENT_FIELDS))
        })
}

/// The parent dir an interrupted merge reserved for `record`, while it has
/// no `finding.json` yet.
fn resumable(ids: &FamilyAllocator, record: &Value) -> Option<(String, PathBuf)> {
    if !carries_intent(record) {
        return None;
    }
    let id = record.get("id")?.as_str()?;
    let dir = ids.reserved_dir(id)?;
    let committed = std::fs::symlink_metadata(dir.join(RECORD)).is_ok();
    (!committed).then(|| (id.to_owned(), dir))
}

/// Move one worker finding into the parent (see the module docs) and return
/// its parent id. Errors name the source and the target.
fn merge_one(
    source: &Path,
    mut record: Value,
    resume: Option<(String, PathBuf)>,
    ids: &mut FamilyAllocator,
    parent: &Path,
    fault: Fault<'_>,
) -> Result<String, String> {
    let (id, target) = match resume {
        Some(reserved) => reserved,
        None => {
            let (id, target) = ids
                .create_with_suffix(&id_suffix(&record, source))
                .map_err(|error| path_error(source, parent, &error))?;
            if let Err(error) = log_intent(source, &mut record, &id) {
                let _ = std::fs::remove_dir(&target);
                return Err(path_error(&source.join(RECORD), &target, &error));
            }
            (id, target)
        }
    };
    fault(Stage::Reserved, &target).map_err(|error| path_error(source, &target, &error))?;
    move_contents(source, &target, true)?;
    fault(Stage::Moved, &target).map_err(|error| path_error(source, &target, &error))?;
    let committed = target.join(RECORD);
    if let Err(error) = move_file(&source.join(RECORD), &committed) {
        // A cross-device commit can land and still fail to drop the source.
        if !committed.is_file() {
            return Err(error);
        }
    }
    let _ = std::fs::remove_dir(source);
    Ok(id)
}

fn path_error(from: &Path, to: &Path, error: &io::Error) -> String {
    format!("{} -> {}: {error}", from.display(), to.display())
}

/// Point the worker's record at its parent `id`, atomically. A stale intent
/// whose reservation is gone is replaced, not stacked.
fn log_intent(source: &Path, record: &mut Value, id: &str) -> io::Result<()> {
    if carries_intent(record) {
        if let Some(history) = record["history"].as_array_mut() {
            history.pop();
        }
    }
    record["id"] = Value::from(id);
    corpus::finding::append_history(record, INTENT_COMMAND, &INTENT_FIELDS);
    replace_atomically(&source.join(RECORD), &serde_json::to_vec_pretty(record)?)
}

/// Write `bytes` to a fresh temp file beside `path`, then rename it over
/// `path`. The temp name is never opened through an existing entry.
fn replace_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_file_name(RECORD_TMP);
    let _ = std::fs::remove_file(&tmp);
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        })
        .and_then(|()| std::fs::rename(&tmp, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

/// The emitter's 8-char signature suffix, else the worker id's own suffix.
fn id_suffix(record: &Value, source: &Path) -> String {
    let from_signature = record
        .get("signature")
        .and_then(Value::as_str)
        .map(|signature| signature.chars().take(8).collect::<String>());
    let from_name = source
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("F-")?.split_once('-'))
        .map(|(_, suffix)| suffix.to_owned());
    [from_signature, from_name]
        .into_iter()
        .flatten()
        .find(|suffix| !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_alphanumeric()))
        .unwrap_or_else(|| "merged".to_owned())
}

/// Move `src`'s regular files and directories into `dst`, recursing into
/// subdirectories; a directory a resumed merge already made is reused. At the
/// top level `finding.json` stays for the caller and a stale intent temp file
/// is dropped. Symlinks and special files stay behind.
fn move_contents(src: &Path, dst: &Path, top: bool) -> Result<(), String> {
    let entries = std::fs::read_dir(src).map_err(|error| path_error(src, dst, &error))?;
    for entry in entries {
        let entry = entry.map_err(|error| path_error(src, dst, &error))?;
        let name = entry.file_name();
        let from = entry.path();
        if top && name == RECORD_TMP {
            let _ = std::fs::remove_file(&from);
            continue;
        }
        if top && name == RECORD {
            continue;
        }
        let to = dst.join(&name);
        let file_type = entry
            .file_type()
            .map_err(|error| path_error(&from, &to, &error))?;
        if file_type.is_dir() {
            match std::fs::create_dir(&to) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists && is_real_dir(&to) => {}
                Err(error) => return Err(path_error(&from, &to, &error)),
            }
            move_contents(&from, &to, false)?;
            let _ = std::fs::remove_dir(&from);
        } else if file_type.is_file() {
            move_file(&from, &to)?;
        }
    }
    Ok(())
}

fn move_file(from: &Path, to: &Path) -> Result<(), String> {
    match std::fs::rename(from, to) {
        Err(error) if error.kind() == io::ErrorKind::CrossesDevices => copy_across(from, to),
        moved => moved,
    }
    .map_err(|error| path_error(from, to, &error))
}

/// A rename across devices: copy to `<to>.partial`, rename that into place,
/// then drop the source. A failed copy or rename leaves no partial behind.
fn copy_across(from: &Path, to: &Path) -> io::Result<()> {
    let mut partial = to.as_os_str().to_owned();
    partial.push(".partial");
    let partial = PathBuf::from(partial);
    let _ = std::fs::remove_file(&partial);
    if let Err(error) = std::fs::copy(from, &partial).and_then(|_| std::fs::rename(&partial, to)) {
        let _ = std::fs::remove_file(&partial);
        return Err(error);
    }
    std::fs::remove_file(from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn record(id: &str, signature: &str, cluster: Option<&str>) -> Value {
        let mut record = json!({
            "id": id,
            "signature": signature,
            "rule_id": "BHF-201",
            "classification": "unhandled",
            "harness_id": "H-MULTI",
            "exception": {"name": "ASAN_HEAP_BUFFER_OVERFLOW", "message": "boom", "stack": []},
        });
        if let Some(cluster) = cluster {
            record["cluster_key_full"] = json!(cluster);
        }
        record
    }

    fn put(findings: &Path, id: &str, record: &Value) -> PathBuf {
        let dir = findings.join(id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("finding.json"),
            serde_json::to_vec(record).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.join("testcase.bin"), id.as_bytes()).unwrap();
        dir
    }

    fn read(dir: &Path) -> Value {
        serde_json::from_slice(&std::fs::read(dir.join("finding.json")).unwrap()).unwrap()
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    const SIG_X: &str = "aaaaaaaa11111111";
    const SIG_X2: &str = "bbbbbbbb22222222";
    const SIG_Y: &str = "cccccccc33333333";
    const SIG_Z: &str = "dddddddd44444444";

    #[test]
    fn worker_findings_move_to_fresh_parent_ids_once_per_crash() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path();
        let parent = corpus::layout::findings_dir(work);
        put(
            &parent,
            "F-0000-dddddddd",
            &record("F-0000-dddddddd", SIG_Z, Some("Z")),
        );
        std::fs::create_dir_all(parent.join("F-DIFF-0000")).unwrap();

        let w0 = work.join("worker-H-0");
        let w1 = work.join("worker-H-1");
        let w0_findings = corpus::layout::findings_dir(&w0);
        let w1_findings = corpus::layout::findings_dir(&w1);
        put(
            &w0_findings,
            "F-0000-aaaaaaaa",
            &record("F-0000-aaaaaaaa", SIG_X, Some("X")),
        );
        // Same crash as the parent's existing finding.
        put(
            &w0_findings,
            "F-0001-dddddddd",
            &record("F-0001-dddddddd", SIG_Z, Some("Z")),
        );
        // Same cluster as worker 0's first finding, different signature.
        put(
            &w1_findings,
            "F-0000-bbbbbbbb",
            &record("F-0000-bbbbbbbb", SIG_X2, Some("X")),
        );
        // No cluster key: deduped by signature, and unique.
        put(
            &w1_findings,
            "F-0001-cccccccc",
            &record("F-0001-cccccccc", SIG_Y, None),
        );

        let report = merge_worker_findings(work, &[w0.clone(), w1.clone()]).unwrap();
        assert_eq!(report.merged, ["F-0001-aaaaaaaa", "F-0002-cccccccc"]);
        assert_eq!((report.duplicates, report.unreadable), (2, 0));
        assert_eq!(
            names(&parent),
            [
                "F-0000-dddddddd",
                "F-0001-aaaaaaaa",
                "F-0002-cccccccc",
                "F-DIFF-0000"
            ]
        );

        let merged = parent.join("F-0001-aaaaaaaa");
        let record = read(&merged);
        assert_eq!(
            record["id"], "F-0001-aaaaaaaa",
            "id rewritten to the new dir"
        );
        let history = record["history"].as_array().unwrap();
        assert_eq!(history.last().unwrap()["command"], "fuzz");
        assert_eq!(history.last().unwrap()["fields"], json!(["id"]));
        assert_eq!(
            std::fs::read(merged.join("testcase.bin")).unwrap(),
            b"F-0000-aaaaaaaa"
        );
        assert!(
            !w0_findings.join("F-0000-aaaaaaaa").exists(),
            "moved, not copied"
        );
        assert!(!w1_findings.join("F-0001-cccccccc").exists());

        // Duplicates stay where the worker left them.
        assert!(w0_findings.join("F-0001-dddddddd/finding.json").is_file());
        assert!(w1_findings.join("F-0000-bbbbbbbb/finding.json").is_file());

        // A second merge finds nothing new.
        let again = merge_worker_findings(work, &[w0, w1]).unwrap();
        assert!(again.merged.is_empty());
        assert_eq!(again.duplicates, 2);
    }

    #[test]
    fn unreadable_worker_findings_stay_put() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path();
        let w0 = work.join("worker-H-0");
        let broken = corpus::layout::findings_dir(&w0).join("F-0000-broken00");
        std::fs::create_dir_all(&broken).unwrap();
        std::fs::write(broken.join("finding.json"), "not json").unwrap();
        let report = merge_worker_findings(work, &[w0]).unwrap();
        assert_eq!((report.merged.len(), report.unreadable), (0, 1));
        assert!(broken.join("finding.json").is_file());
    }

    #[test]
    fn missing_worker_dirs_merge_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let report = merge_worker_findings(tmp.path(), &[tmp.path().join("worker-H-0")]).unwrap();
        assert_eq!(report, MergeReport::default());
        assert!(!corpus::layout::results_dir(tmp.path()).exists());
    }

    #[test]
    #[cfg(unix)]
    fn symlinks_in_worker_dirs_are_never_followed() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().join("work");
        let outside = tmp.path().join("outside");
        put(
            &outside,
            "F-0000-eeeeeeee",
            &record("F-0000-eeeeeeee", "eeeeeeee55", None),
        );
        std::fs::write(outside.join("secret"), b"secret").unwrap();

        // A worker whose whole findings dir is a symlink.
        let w0 = work.join("worker-H-0");
        std::fs::create_dir_all(corpus::layout::results_dir(&w0)).unwrap();
        symlink(&outside, corpus::layout::findings_dir(&w0)).unwrap();

        // A worker with a symlinked finding dir and a symlink inside a real one.
        let w1 = work.join("worker-H-1");
        let w1_findings = corpus::layout::findings_dir(&w1);
        std::fs::create_dir_all(&w1_findings).unwrap();
        symlink(
            outside.join("F-0000-eeeeeeee"),
            w1_findings.join("F-0000-eeeeeeee"),
        )
        .unwrap();
        let real = put(
            &w1_findings,
            "F-0001-ffffffff",
            &record("F-0001-ffffffff", "ffffffff66", None),
        );
        symlink(outside.join("secret"), real.join("leak")).unwrap();

        let report = merge_worker_findings(&work, &[w0, w1]).unwrap();
        assert_eq!(report.merged, ["F-0000-ffffffff"]);
        let parent = corpus::layout::findings_dir(&work);
        assert_eq!(names(&parent), ["F-0000-ffffffff"]);
        assert!(
            !parent.join("F-0000-ffffffff/leak").exists(),
            "symlink not carried over"
        );
        assert!(
            outside.join("F-0000-eeeeeeee/finding.json").is_file(),
            "outside untouched"
        );
        assert!(outside.join("secret").is_file());
    }

    fn harness_record(id: &str, harness: &str, signature: &str, cluster: Option<&str>) -> Value {
        let mut record = record(id, signature, cluster);
        record["harness_id"] = json!(harness);
        record
    }

    #[test]
    fn a_shared_key_dedupes_only_within_one_harness() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path();
        let parent = corpus::layout::findings_dir(work);
        put(
            &parent,
            "F-0000-aaaaaaaa",
            &harness_record("F-0000-aaaaaaaa", "H-A", SIG_X, Some("K")),
        );
        let w0 = work.join("worker-H-0");
        let w0_findings = corpus::layout::findings_dir(&w0);
        // Another harness, same cluster and signature: a different finding.
        put(
            &w0_findings,
            "F-0000-aaaaaaaa",
            &harness_record("F-0000-aaaaaaaa", "H-B", SIG_X, Some("K")),
        );
        // Same harness, another cluster but the same signature: any shared
        // key makes it a duplicate.
        put(
            &w0_findings,
            "F-0001-aaaaaaaa",
            &harness_record("F-0001-aaaaaaaa", "H-A", SIG_X, Some("K2")),
        );
        // Same harness, same cluster, another signature: a duplicate.
        put(
            &w0_findings,
            "F-0002-bbbbbbbb",
            &harness_record("F-0002-bbbbbbbb", "H-A", SIG_X2, Some("K")),
        );
        let report = merge_worker_findings(work, &[w0]).unwrap();
        assert_eq!(report.merged, ["F-0001-aaaaaaaa"]);
        assert_eq!(read(&parent.join("F-0001-aaaaaaaa"))["harness_id"], "H-B");
        assert_eq!(report.duplicates, 2);
    }

    #[test]
    fn keyless_records_always_merge() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path();
        let keyless = |id: &str| json!({"id": id, "harness_id": "H-A", "rule_id": "BHF-201"});
        let parent = corpus::layout::findings_dir(work);
        put(&parent, "F-0000-keyless0", &keyless("F-0000-keyless0"));
        let w0 = work.join("worker-H-0");
        let w0_findings = corpus::layout::findings_dir(&w0);
        put(&w0_findings, "F-0000-keyless0", &keyless("F-0000-keyless0"));
        put(&w0_findings, "F-0001-keyless0", &keyless("F-0001-keyless0"));
        let report = merge_worker_findings(work, &[w0]).unwrap();
        assert_eq!(report.merged, ["F-0001-keyless0", "F-0002-keyless0"]);
        assert_eq!(report.duplicates, 0);
    }

    #[test]
    #[cfg(unix)]
    fn a_symlinked_parent_findings_dir_is_refused() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().join("work");
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::create_dir_all(corpus::layout::results_dir(&work)).unwrap();
        symlink(&outside, corpus::layout::findings_dir(&work)).unwrap();
        let w0 = work.join("worker-H-0");
        put(
            &corpus::layout::findings_dir(&w0),
            "F-0000-aaaaaaaa",
            &record("F-0000-aaaaaaaa", SIG_X, Some("X")),
        );
        let error = merge_worker_findings(&work, std::slice::from_ref(&w0)).unwrap_err();
        assert!(
            matches!(error, MulticoreError::UnsafeFindingsDir { .. }),
            "{error}"
        );
        assert!(error.to_string().contains("symlink"), "{error}");
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
        assert!(corpus::layout::findings_dir(&w0)
            .join("F-0000-aaaaaaaa/finding.json")
            .is_file());
    }

    #[test]
    #[cfg(unix)]
    fn leftovers_of_a_merged_finding_are_not_reported_unreadable() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path();
        let w0 = work.join("worker-H-0");
        let source = put(
            &corpus::layout::findings_dir(&w0),
            "F-0000-aaaaaaaa",
            &record("F-0000-aaaaaaaa", SIG_X, Some("X")),
        );
        symlink("/nonexistent", source.join("dangling")).unwrap();
        let report = merge_worker_findings(work, std::slice::from_ref(&w0)).unwrap();
        assert_eq!(report.merged, ["F-0000-aaaaaaaa"]);
        assert!(
            source.join("dangling").symlink_metadata().is_ok(),
            "stays behind"
        );
        let again = merge_worker_findings(work, &[w0]).unwrap();
        assert_eq!(again, MergeReport::default());
    }

    #[test]
    fn nested_subdirectories_move_with_their_files() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path();
        let w0 = work.join("worker-H-0");
        let source = put(
            &corpus::layout::findings_dir(&w0),
            "F-0000-aaaaaaaa",
            &record("F-0000-aaaaaaaa", SIG_X, Some("X")),
        );
        std::fs::create_dir_all(source.join("repro/inner")).unwrap();
        std::fs::write(source.join("repro/inner/input.bin"), b"deep").unwrap();
        // Only the top-level finding.json is the record; a nested one is data.
        std::fs::write(source.join("repro/finding.json"), b"nested").unwrap();
        let report = merge_worker_findings(work, &[w0]).unwrap();
        assert_eq!(report.merged, ["F-0000-aaaaaaaa"]);
        let target = corpus::layout::findings_dir(work).join("F-0000-aaaaaaaa");
        assert_eq!(
            std::fs::read(target.join("repro/inner/input.bin")).unwrap(),
            b"deep"
        );
        assert_eq!(
            std::fs::read(target.join("repro/finding.json")).unwrap(),
            b"nested"
        );
        assert_eq!(read(&target)["id"], "F-0000-aaaaaaaa");
        assert!(!source.exists(), "an emptied worker dir is removed");
    }

    /// Whether `dir`'s permission bits stop this process (not when root).
    #[cfg(unix)]
    fn permissions_enforced(dir: &Path) -> bool {
        let probe = dir.join(".probe");
        match std::fs::create_dir(&probe) {
            Ok(()) => {
                std::fs::remove_dir(&probe).unwrap();
                false
            }
            Err(_) => true,
        }
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn a_read_only_parent_fails_each_finding_and_keeps_the_worker_records() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path();
        let parent = corpus::layout::findings_dir(work);
        std::fs::create_dir_all(&parent).unwrap();
        let w0 = work.join("worker-H-0");
        let w0_findings = corpus::layout::findings_dir(&w0);
        let a = put(
            &w0_findings,
            "F-0000-aaaaaaaa",
            &record("F-0000-aaaaaaaa", SIG_X, Some("X")),
        );
        let b = put(
            &w0_findings,
            "F-0001-cccccccc",
            &record("F-0001-cccccccc", SIG_Y, Some("Y")),
        );
        let before = std::fs::read(a.join("finding.json")).unwrap();
        set_mode(&parent, 0o555);
        if !permissions_enforced(&parent) {
            set_mode(&parent, 0o755);
            eprintln!("SKIP: permission bits not enforced (root)");
            return;
        }
        let report = merge_worker_findings(work, std::slice::from_ref(&w0));
        set_mode(&parent, 0o755);
        let report = report.unwrap();
        assert!(report.merged.is_empty());
        assert_eq!(report.failed, 2);
        assert!(
            report.errors[0].contains(&a.display().to_string())
                && report.errors[0].contains(&parent.display().to_string()),
            "{:?}",
            report.errors
        );
        assert_eq!(std::fs::read(a.join("finding.json")).unwrap(), before);
        assert!(b.join("testcase.bin").is_file());

        let again = merge_worker_findings(work, &[w0]).unwrap();
        assert_eq!(again.merged, ["F-0000-aaaaaaaa", "F-0001-cccccccc"]);
        assert_eq!(again.failed, 0);
    }

    #[test]
    #[cfg(unix)]
    fn one_failing_finding_does_not_stop_the_others() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path();
        let w0 = work.join("worker-H-0");
        let w0_findings = corpus::layout::findings_dir(&w0);
        let bad = put(
            &w0_findings,
            "F-0000-aaaaaaaa",
            &record("F-0000-aaaaaaaa", SIG_X, Some("X")),
        );
        put(
            &w0_findings,
            "F-0001-cccccccc",
            &record("F-0001-cccccccc", SIG_Y, Some("Y")),
        );
        let locked = bad.join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::write(locked.join("data"), b"x").unwrap();
        set_mode(&locked, 0o000);
        if !permissions_enforced(&locked) {
            set_mode(&locked, 0o755);
            eprintln!("SKIP: permission bits not enforced (root)");
            return;
        }
        let report = merge_worker_findings(work, &[w0]);
        set_mode(&locked, 0o755);
        let report = report.unwrap();
        assert_eq!(report.merged, ["F-0001-cccccccc"]);
        assert_eq!(report.failed, 1);
        assert!(
            report.errors[0].contains(&locked.display().to_string()),
            "{:?}",
            report.errors
        );
        assert!(bad.join("finding.json").is_file(), "the record stays");
    }

    fn loaded_ids(findings: &Path) -> Vec<String> {
        let (findings, failures) = report::load_findings_tolerant(findings, None, false).unwrap();
        assert!(failures.is_empty(), "{failures:?}");
        let mut ids: Vec<String> = findings.into_iter().map(|finding| finding.id).collect();
        ids.sort();
        ids
    }

    fn intent_entries(record: &Value) -> usize {
        record["history"].as_array().map_or(0, |history| {
            history.iter().filter(|e| e["command"] == "fuzz").count()
        })
    }

    #[test]
    fn an_interrupted_merge_is_invisible_and_resumes_into_its_reserved_id() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path();
        let parent = corpus::layout::findings_dir(work);
        put(
            &parent,
            "F-0000-dddddddd",
            &record("F-0000-dddddddd", SIG_Z, Some("Z")),
        );
        let w0 = work.join("worker-H-0");
        let w0_findings = corpus::layout::findings_dir(&w0);
        let a = put(
            &w0_findings,
            "F-0000-aaaaaaaa",
            &record("F-0000-aaaaaaaa", SIG_X, Some("X")),
        );
        std::fs::create_dir(a.join("repro")).unwrap();
        std::fs::write(a.join("repro/input.bin"), b"deep").unwrap();
        put(
            &w0_findings,
            "F-0001-cccccccc",
            &record("F-0001-cccccccc", SIG_Y, Some("Y")),
        );

        // Crash after the files moved, before finding.json did.
        let report = merge_with(
            work,
            std::slice::from_ref(&w0),
            LIMITS,
            &mut |stage, target| {
                if stage == Stage::Moved && target.ends_with("F-0001-aaaaaaaa") {
                    Err(io::Error::other("injected"))
                } else {
                    Ok(())
                }
            },
        )
        .unwrap();
        assert_eq!(
            report.merged,
            ["F-0002-cccccccc"],
            "the next one still merges"
        );
        assert_eq!(report.failed, 1);
        let reserved = parent.join("F-0001-aaaaaaaa");
        let error = &report.errors[0];
        assert!(
            error.contains(&a.display().to_string())
                && error.contains(&reserved.display().to_string())
                && error.contains("injected"),
            "{error}"
        );
        assert!(
            reserved.join("repro/input.bin").is_file(),
            "moved before the fault"
        );
        assert!(!reserved.join("finding.json").exists());
        assert_eq!(
            loaded_ids(&parent),
            ["F-0000-dddddddd", "F-0002-cccccccc"],
            "the reserved dir is neither indexed nor a load failure"
        );
        let intent = read(&a);
        assert_eq!(
            intent["id"], "F-0001-aaaaaaaa",
            "the worker record names its target"
        );
        assert_eq!(intent_entries(&intent), 1);

        let again = merge_worker_findings(work, &[w0]).unwrap();
        assert_eq!(
            again.merged,
            ["F-0001-aaaaaaaa"],
            "resumed into the same id"
        );
        assert_eq!((again.failed, again.duplicates), (0, 0));
        let merged = read(&reserved);
        assert_eq!(merged["id"], "F-0001-aaaaaaaa");
        assert_eq!(
            intent_entries(&merged),
            1,
            "one history entry, not one per try"
        );
        assert_eq!(
            std::fs::read(reserved.join("repro/input.bin")).unwrap(),
            b"deep"
        );
        assert_eq!(
            std::fs::read(reserved.join("testcase.bin")).unwrap(),
            b"F-0000-aaaaaaaa"
        );
        assert!(!a.exists());
        assert_eq!(
            loaded_ids(&parent),
            ["F-0000-dddddddd", "F-0001-aaaaaaaa", "F-0002-cccccccc"]
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_write_error_mid_move_keeps_the_worker_record_and_resumes() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path();
        let w0 = work.join("worker-H-0");
        let a = put(
            &corpus::layout::findings_dir(&w0),
            "F-0000-aaaaaaaa",
            &record("F-0000-aaaaaaaa", SIG_X, Some("X")),
        );
        let mut enforced = true;
        // The reserved target turns read-only, as a full disk refuses writes.
        let report = merge_with(
            work,
            std::slice::from_ref(&w0),
            LIMITS,
            &mut |stage, target| {
                if stage == Stage::Reserved {
                    set_mode(target, 0o555);
                    enforced = permissions_enforced(target);
                }
                Ok(())
            },
        )
        .unwrap();
        let reserved = corpus::layout::findings_dir(work).join("F-0000-aaaaaaaa");
        set_mode(&reserved, 0o755);
        if !enforced {
            eprintln!("SKIP: permission bits not enforced (root)");
            return;
        }
        assert!(report.merged.is_empty());
        assert_eq!(report.failed, 1);
        assert!(
            report.errors[0].contains("testcase.bin"),
            "{:?}",
            report.errors
        );
        assert_eq!(read(&a)["id"], "F-0000-aaaaaaaa");
        assert_eq!(
            std::fs::read(a.join("testcase.bin")).unwrap(),
            b"F-0000-aaaaaaaa"
        );
        assert!(!reserved.join("finding.json").exists());

        let again = merge_worker_findings(work, &[w0]).unwrap();
        assert_eq!(again.merged, ["F-0000-aaaaaaaa"]);
        assert_eq!(intent_entries(&read(&reserved)), 1);
    }

    #[test]
    fn copy_across_goes_through_a_partial_that_never_outlives_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let from = tmp.path().join("from");
        std::fs::write(&from, b"data").unwrap();
        let to = tmp.path().join("to");
        copy_across(&from, &to).unwrap();
        assert_eq!(std::fs::read(&to).unwrap(), b"data");
        assert!(!from.exists());
        assert!(!tmp.path().join("to.partial").exists());

        // The final rename cannot land on a non-empty directory.
        std::fs::write(&from, b"data").unwrap();
        let blocked = tmp.path().join("blocked");
        std::fs::create_dir(&blocked).unwrap();
        std::fs::write(blocked.join("x"), b"x").unwrap();
        assert!(copy_across(&from, &blocked).is_err());
        assert!(!tmp.path().join("blocked.partial").exists());
        assert!(from.is_file(), "the source stays on error");
    }

    #[test]
    #[cfg(unix)]
    fn oversized_or_symlinked_records_are_unreadable() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path();
        let w0 = work.join("worker-H-0");
        let w0_findings = corpus::layout::findings_dir(&w0);
        put(
            &w0_findings,
            "F-0000-aaaaaaaa",
            &json!({"signature": "aaaa"}),
        );
        put(
            &w0_findings,
            "F-0001-bbbbbbbb",
            &record("F-0001-bbbbbbbb", SIG_X2, None),
        );
        let linked = w0_findings.join("F-0002-cccccccc");
        std::fs::create_dir_all(&linked).unwrap();
        let outside = tmp.path().join("outside.json");
        std::fs::write(&outside, br#"{"signature": "cccc"}"#).unwrap();
        symlink(&outside, linked.join("finding.json")).unwrap();
        let limits = Limits {
            entries: MAX_FINDING_ENTRIES,
            record_bytes: 32,
        };
        let report = merge_with(work, &[w0], limits, &mut |_, _| Ok(())).unwrap();
        assert_eq!(report.merged, ["F-0000-aaaa"]);
        assert_eq!(report.unreadable, 2, "the large record and the symlink");
        assert!(outside.is_file());
    }

    #[test]
    fn the_entry_cap_merges_part_and_reports_the_rest() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path();
        let w0 = work.join("worker-H-0");
        let w0_findings = corpus::layout::findings_dir(&w0);
        for (id, signature) in [
            ("F-0000-aaaaaaaa", SIG_X),
            ("F-0001-bbbbbbbb", SIG_X2),
            ("F-0002-cccccccc", SIG_Y),
        ] {
            put(&w0_findings, id, &record(id, signature, None));
        }
        let limits = Limits {
            entries: 2,
            record_bytes: MAX_FINDING_RECORD_BYTES,
        };
        let report = merge_with(work, &[w0], limits, &mut |_, _| Ok(())).unwrap();
        assert_eq!(report.merged.len(), 2);
        assert_eq!(report.failed, 1);
        assert!(
            report.errors[0].contains("more than 2 entries"),
            "{:?}",
            report.errors
        );
    }
}
