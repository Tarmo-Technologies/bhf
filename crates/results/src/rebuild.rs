// SPDX-License-Identifier: Apache-2.0
//! `rebuild()`: regenerate every derived file under `<work>/results/` from the
//! evidence on disk. `ProducerRun`: the begin/complete bracket each command uses.

use crate::lock::ResultsLock;
use crate::model::{
    Counts, Finding, FindingsDocument, Group, Kind, LoadError, Manifest, ProducerRecord,
    ProducerStatus, ToolInfo, FINDINGS_SCHEMA_VERSION,
};
use crate::normalize::{self, NormalizeContext};
use crate::render::{
    csv::render_csv,
    index_md::{render_index, IndexContext},
    sarif,
};
use crate::{io_err, layout, manifest, ResultsError};
use serde_json::{json, Value};
use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

pub struct RebuildOptions {
    pub tool: ToolInfo,
    /// Fixed `generated_at` (golden tests); `None` = now.
    pub now: Option<String>,
    /// Generate `replay.py` (every finding) and `repro.adb` (findings with a
    /// `testcase.bin`) in each finding directory. A reproducer that already
    /// holds the current content is not rewritten (mode and mtime are left
    /// alone); a missing or outdated one is (re)written.
    pub generate_reproducers: bool,
    pub lock_timeout: Duration,
}

impl Default for RebuildOptions {
    fn default() -> Self {
        Self {
            tool: manifest::tool_info(),
            now: None,
            generate_reproducers: true,
            lock_timeout: Duration::from_secs(120),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebuildSummary {
    pub findings: usize,
    pub errors: usize,
    pub index_path: PathBuf,
}

/// Files under `results/` the attestation never treats as evidence.
const NOT_ATTESTED: [&str; 2] = ["attestation.json", ".lock"];
/// Directory entries the attestation walk examines before it stops and
/// marks the statement `truncated`.
const MAX_ATTESTED_ENTRIES: usize = 1_000_000;
/// Unhashable files the attestation names; past this only the count grows.
const MAX_SKIPPED_LISTED: usize = 100;
/// Fresh temp names `write_atomic` tries before giving up.
const TEMP_ATTEMPTS: u32 = 8;
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);
/// Retries of a rename that hit a Windows sharing violation (a reader, indexer
/// or scanner holding the destination open), [`RENAME_RETRY_DELAY`] apart.
/// `ERROR_ACCESS_DENIED` (5) and `ERROR_SHARING_VIOLATION` (32) are how
/// `MoveFileEx` reports that.
const RENAME_RETRIES: u32 = 3;
const RENAME_RETRY_DELAY: Duration = Duration::from_millis(50);
/// A `write_atomic` temp file older than this was left by a crashed writer.
const STALE_TEMP_AGE: Duration = Duration::from_secs(3600);
/// Producer history kept in manifest.json; the oldest records drop first.
const MAX_MANIFEST_PRODUCERS: usize = 1000;
/// The most recent producers copied into findings.json.
const FINDINGS_PRODUCERS: usize = 50;

pub fn rebuild(work_dir: &Path, options: &RebuildOptions) -> Result<RebuildSummary, ResultsError> {
    let results = layout::results_dir(work_dir);
    std::fs::create_dir_all(&results).map_err(io_err(&results))?;
    let _lock = ResultsLock::acquire(&results, options.lock_timeout)?;
    rebuild_locked(work_dir, &results, options, None)
}

/// The producer that just finished, recorded by [`rebuild_locked`].
struct Pending {
    record: ProducerRecord,
    /// The scanned tree; recorded only if no earlier producer set one.
    source_root: Option<PathBuf>,
}

/// Write order: manifest.json first, since it is the only file here that is
/// not derived (the producer history); a failure after that loses nothing a
/// rerun cannot rebuild. Then findings.csv, findings.sarif and INDEX.md;
/// findings.json, the commit point, after them; the attestation last.
fn rebuild_locked(
    work_dir: &Path,
    results: &Path,
    options: &RebuildOptions,
    pending: Option<Pending>,
) -> Result<RebuildSummary, ResultsError> {
    rebuild_locked_with(
        work_dir,
        results,
        options,
        pending,
        report::validate_sarif_report,
    )
}

/// [`rebuild_locked`] with the fuzz-side SARIF validator passed in, so a
/// test can make it fail.
fn rebuild_locked_with(
    work_dir: &Path,
    results: &Path,
    options: &RebuildOptions,
    pending: Option<Pending>,
    validate: fn(&Value) -> Result<(), report::ReportError>,
) -> Result<RebuildSummary, ResultsError> {
    remove_stale_temps(results, SystemTime::now());
    let mut manifest = manifest::load(results)?;
    if manifest.source.root.is_none() {
        if let Some(root) = pending.as_ref().and_then(|p| p.source_root.as_deref()) {
            manifest.source = manifest::source_info(Some(root));
        }
    }
    let run = run_json(work_dir);
    let source_root = manifest.source.root.clone().or_else(|| {
        run.as_ref()
            .and_then(|v| v.get("source_root")?.as_str().map(str::to_owned))
    });
    if manifest.source.root.is_none() && source_root.is_some() {
        manifest.source = manifest::source_info(source_root.as_deref().map(Path::new));
    }
    let mut tool = options.tool.clone();
    tool.name = "bhf".to_owned();
    manifest.tool = tool.clone();
    let ctx = NormalizeContext {
        source_root: source_root.as_deref().map(Path::new),
        results_dir: results,
    };
    let mut errors: Vec<LoadError> = Vec::new();

    // 1. Evidence directories (dynamic + auto's static dirs).
    let findings_dir = layout::findings_dir(work_dir);
    let (reports, failures) =
        match report::load_findings_tolerant(&findings_dir, None, options.generate_reproducers) {
            Ok(loaded) => loaded,
            Err(e) => {
                // Nothing can be indexed, but the producer did run.
                if pending.is_some() {
                    record_producer(results, &mut manifest, pending, 0)?;
                }
                return Err(e.into());
            }
        };
    errors.extend(failures.into_iter().map(|f| LoadError {
        path: rel(results, &f.path),
        reason: f.reason,
    }));
    let mut rejected: HashSet<String> = HashSet::new();
    let mut findings: Vec<Finding> = Vec::with_capacity(reports.len());
    for r in &reports {
        match normalize::from_finding_report(r, &ctx) {
            Ok(finding) => findings.push(finding),
            Err(reason) => {
                errors.push(LoadError {
                    path: rel(results, Path::new(&r.source_path)),
                    reason,
                });
                rejected.insert(r.id.clone());
            }
        }
    }

    // 2. static-scan native report.
    let static_dir = layout::static_dir(work_dir);
    if let Some(doc) = read_json(&static_dir.join("static-report.json"), results, &mut errors) {
        let keys = normalize::static_issue_keys(&doc);
        for v in doc
            .get("findings")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let key = v
                .get("id")
                .and_then(Value::as_str)
                .and_then(|id| keys.get(id))
                .map(String::as_str);
            match normalize::from_static_value(v, key, &ctx) {
                Some(f) => findings.push(f),
                None => errors.push(LoadError {
                    path: "static/static-report.json".to_owned(),
                    reason: "static finding without id or location skipped".to_owned(),
                }),
            }
        }
    }

    // 3. SBOM vulnerability matches.
    let sbom_dir = layout::sbom_dir(work_dir);
    if let Some(doc) = read_json(&sbom_dir.join("vulnerabilities.json"), results, &mut errors) {
        for m in doc
            .get("matches")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(f) = normalize::from_sca_value(m) {
                findings.push(f);
            }
        }
    }

    let deduped = dedupe(&mut findings, &mut errors);
    let groups = finalize_groups(&mut findings);
    findings.sort_by(|a, b| {
        a.severity
            .rank()
            .cmp(&b.severity.rank())
            .then_with(|| a.id.cmp(&b.id))
    });
    let counts = count(&findings);
    record_producer(results, &mut manifest, pending, counts.total)?;

    // SARIF from the same retained set: a record the normalizer rejected or
    // dedupe removed is not emitted there either.
    let retained: Vec<report::FindingReport> = reports
        .into_iter()
        .filter(|r| !rejected.contains(&r.id) && !deduped.dropped.contains(&r.id))
        .collect();
    let fuzz_doc = report::document_from_findings("last", &findings_dir, retained);
    let static_sarif = read_json(
        &static_dir.join("static-report.sarif"),
        results,
        &mut errors,
    );
    // The report validator checks the fuzz emitter's contract (every result
    // carries `bhfFindingId`/`bhfExceptionSignature`); static-scan results
    // never do, so it runs before the static run is merged in. A failure
    // costs only findings.sarif, never the rest of the index.
    let mut fuzz_sarif = report::render_sarif_report(&fuzz_doc);
    let merged = match validate(&fuzz_sarif) {
        Ok(()) => {
            strip_root_in_fuzz_results(&mut fuzz_sarif, ctx.source_root);
            // static-scan results folded into an auto static record are not emitted twice
            Some(sarif::merge(
                fuzz_sarif,
                static_sarif.as_ref(),
                &severity_index(&findings),
                &deduped.folded_static,
            ))
        }
        Err(e) => {
            errors.push(LoadError {
                path: "findings.sarif".to_owned(),
                reason: format!("not written: {e}"),
            });
            None
        }
    };

    let doc = FindingsDocument {
        schema_version: FINDINGS_SCHEMA_VERSION.to_owned(),
        generated_at: options
            .now
            .clone()
            .unwrap_or_else(corpus::finding::now_rfc3339),
        tool,
        source: manifest.source.clone(),
        producers: manifest.producers
            [manifest.producers.len().saturating_sub(FINDINGS_PRODUCERS)..]
            .to_vec(),
        counts,
        findings,
        groups,
        errors,
    };
    let index_ctx = IndexContext {
        campaign: run.as_ref().map(campaign_line),
        has_static_dir: static_dir.is_dir(),
        has_sbom_dir: sbom_dir.is_dir(),
        unminimized_groups: unminimized_groups(&doc),
    };

    write_atomic(&results.join("findings.csv"), render_csv(&doc).as_bytes())?;
    let sarif_path = results.join("findings.sarif");
    match &merged {
        Some(merged) => write_json(&sarif_path, merged)?,
        // An earlier rebuild's SARIF would no longer match findings.json.
        None => remove_if_present(&sarif_path)?,
    }
    write_atomic(
        &results.join("INDEX.md"),
        render_index(&doc, &index_ctx).as_bytes(),
    )?;
    write_json(&results.join("findings.json"), &doc)?;
    write_json(
        &results.join("attestation.json"),
        &attestation(results, &doc.tool)?,
    )?;

    Ok(RebuildSummary {
        findings: doc.findings.len(),
        errors: doc.errors.len(),
        index_path: results.join("INDEX.md"),
    })
}

/// Append the producer that just finished (if any) with its `findings_total`,
/// keep the last [`MAX_MANIFEST_PRODUCERS`], and save the manifest. Runs
/// before any derived file is written: the producer history is the one thing
/// in results/ a rerun cannot rebuild.
fn record_producer(
    results: &Path,
    manifest: &mut Manifest,
    pending: Option<Pending>,
    findings_total: usize,
) -> Result<(), ResultsError> {
    if let Some(Pending { mut record, .. }) = pending {
        record.findings_total = findings_total;
        manifest.producers.push(record);
    }
    let excess = manifest
        .producers
        .len()
        .saturating_sub(MAX_MANIFEST_PRODUCERS);
    manifest.producers.drain(..excess);
    manifest::save(results, manifest)?;
    sync_dir(results);
    Ok(())
}

/// Root-cause groups whose representative (the finding INDEX.md shows)
/// carries [`crate::UNMINIMIZED_CAVEAT`].
fn unminimized_groups(doc: &FindingsDocument) -> usize {
    let by_id: HashMap<&str, &Finding> = doc.findings.iter().map(|f| (f.id.as_str(), f)).collect();
    doc.groups
        .iter()
        .filter(|g| {
            by_id.get(g.representative.as_str()).is_some_and(|f| {
                f.fidelity
                    .caveats
                    .iter()
                    .any(|c| c == crate::UNMINIMIZED_CAVEAT)
            })
        })
        .count()
}

/// Make each result's `message.text` and every string under its `properties`
/// (actionability fix location, next steps, patch-hint guidance)
/// repo-relative: the absolute root belongs only in `originalUriBaseIds`.
fn strip_root_in_fuzz_results(sarif: &mut Value, root: Option<&Path>) {
    if root.is_none() {
        return;
    }
    let runs = sarif.get_mut("runs").and_then(Value::as_array_mut);
    for run in runs.into_iter().flatten() {
        let results = run.get_mut("results").and_then(Value::as_array_mut);
        for result in results.into_iter().flatten() {
            if let Some(text) = result.pointer_mut("/message/text") {
                normalize::strip_root_in_value(text, root);
            }
            if let Some(properties) = result.get_mut("properties") {
                normalize::strip_root_in_value(properties, root);
            }
        }
    }
}

/// Finding id -> (severity, primary, id) for fuzz results, plus fingerprint
/// -> (severity, primary, id) for static findings, which `sarif::merge`
/// matches by `bhfStaticFingerprint`. `findings` is sorted most severe first, so when two
/// static findings share a fingerprint the more severe one wins; an id entry
/// is never overwritten by a fingerprint entry.
fn severity_index(findings: &[Finding]) -> sarif::SeverityIndex {
    let entry = |f: &Finding| {
        (
            f.severity.as_str().to_owned(),
            f.fingerprint.primary.clone(),
            f.id.clone(),
        )
    };
    let mut index: sarif::SeverityIndex =
        findings.iter().map(|f| (f.id.clone(), entry(f))).collect();
    for f in findings.iter().filter(|f| f.kind == Kind::Static) {
        index
            .entry(f.fingerprint.primary.clone())
            .or_insert_with(|| entry(f));
    }
    index
}

/// What [`dedupe`] removed.
struct Deduped {
    /// ids no longer present anywhere in the document
    dropped: HashSet<String>,
    /// static fingerprints whose static-scan record was folded into an auto record
    folded_static: HashSet<String>,
}

/// Drop duplicates. Same id and same `fingerprint.primary` (an SCA match
/// listed twice): keep the first. Same id with a different primary is a
/// real collision: keep the first and report the other in `errors`.
///
/// An auto static record (`F-STATIC-*`, `F-RO-*`, `F-EXT-*`) and a
/// static-scan record (`S-*`) with the same `fingerprint.primary` are one
/// finding: keep the auto record, whose id, confirmation and root-cause
/// group are already established across runs, and enrich it with the
/// static-scan analysis (trace, snippet, engine, precision, baseline/triage
/// state, reachability).
fn dedupe(findings: &mut Vec<Finding>, errors: &mut Vec<LoadError>) -> Deduped {
    let mut dropped = HashSet::new();
    let mut seen: HashMap<String, String> = HashMap::new();
    findings.retain(|f| match seen.entry(f.id.clone()) {
        Entry::Vacant(slot) => {
            slot.insert(f.fingerprint.primary.clone());
            true
        }
        Entry::Occupied(slot) => {
            if *slot.get() != f.fingerprint.primary {
                errors.push(LoadError {
                    path: f
                        .raw_ref
                        .clone()
                        .unwrap_or_else(|| "findings.json".to_owned()),
                    reason: format!("finding id collision: {}", f.id),
                });
            }
            false
        }
    });
    let is_scan = |f: &Finding| f.kind == Kind::Static && f.id.starts_with("S-");
    let auto_fps: HashSet<String> = findings
        .iter()
        .filter(|f| f.kind == Kind::Static && !is_scan(f))
        .map(|f| f.fingerprint.primary.clone())
        .collect();
    let scan: HashMap<String, Finding> = findings
        .iter()
        .filter(|f| is_scan(f) && auto_fps.contains(&f.fingerprint.primary))
        .map(|f| (f.fingerprint.primary.clone(), f.clone()))
        .collect();
    for f in findings
        .iter_mut()
        .filter(|f| f.kind == Kind::Static && !f.id.starts_with("S-"))
    {
        if let Some(s) = scan.get(&f.fingerprint.primary) {
            if f.trace.is_empty() {
                f.trace = s.trace.clone();
            }
            f.static_ = s.static_.clone();
            f.reachability = f.reachability.take().or_else(|| s.reachability.clone());
            f.remediation = f.remediation.take().or_else(|| s.remediation.clone());
            if f.location
                .as_ref()
                .and_then(|l| l.function.as_ref())
                .is_none()
            {
                if let (Some(loc), Some(sloc)) = (f.location.as_mut(), s.location.as_ref()) {
                    loc.function = sloc.function.clone();
                }
            }
        }
    }
    findings.retain(|f| {
        let shadowed = is_scan(f) && scan.contains_key(&f.fingerprint.primary);
        if shadowed {
            dropped.insert(f.id.clone());
        }
        !shadowed
    });
    Deduped {
        dropped,
        folded_static: scan.into_keys().collect(),
    }
}

/// Group by `group` key; set occurrences and first/last seen across members;
/// representative = most severe, then lowest id. Groups ordered most severe first.
fn finalize_groups(findings: &mut [Finding]) -> Vec<Group> {
    let mut members: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, f) in findings.iter().enumerate() {
        let key = f
            .group
            .clone()
            .unwrap_or_else(|| f.fingerprint.primary.clone());
        members.entry(key).or_default().push(i);
    }
    let mut groups = Vec::with_capacity(members.len());
    for (key, idx) in members {
        let first_seen = idx
            .iter()
            .filter_map(|&i| findings[i].first_seen.clone())
            .min();
        let last_seen = idx
            .iter()
            .filter_map(|&i| findings[i].last_seen.clone())
            .max();
        let rep = *idx
            .iter()
            .min_by(|&&a, &&b| {
                findings[a]
                    .severity
                    .rank()
                    .cmp(&findings[b].severity.rank())
                    .then_with(|| findings[a].id.cmp(&findings[b].id))
            })
            .expect("non-empty group");
        let mut ids: Vec<String> = idx.iter().map(|&i| findings[i].id.clone()).collect();
        ids.sort();
        for &i in &idx {
            let f = &mut findings[i];
            f.group = Some(key.clone());
            f.occurrences = idx.len();
            f.first_seen = first_seen.clone();
            f.last_seen = last_seen.clone();
        }
        groups.push((
            findings[rep].severity.rank(),
            Group {
                key,
                representative: findings[rep].id.clone(),
                members: ids,
            },
        ));
    }
    groups.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.representative.cmp(&b.1.representative))
    });
    groups.into_iter().map(|(_, g)| g).collect()
}

fn count(findings: &[Finding]) -> Counts {
    let mut counts = Counts {
        total: findings.len(),
        ..Counts::default()
    };
    for f in findings {
        *counts
            .by_kind
            .entry(f.kind.as_str().to_owned())
            .or_default() += 1;
        *counts
            .by_severity
            .entry(f.severity.as_str().to_owned())
            .or_default() += 1;
        *counts
            .by_confirmation
            .entry(f.confirmation.level.as_str().to_owned())
            .or_default() += 1;
    }
    counts
}

fn run_json(work_dir: &Path) -> Option<Value> {
    let bytes = std::fs::read(work_dir.join("auto/run.json")).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn campaign_line(run: &Value) -> String {
    let discovered = run
        .pointer("/summary/discovered")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let partial = run.get("partial").and_then(Value::as_bool).unwrap_or(false);
    format!(
        "{discovered} target(s) swept{}",
        if partial { " (partial run)" } else { "" }
    )
}

/// Read an optional JSON input; missing is `None`, unreadable is an `errors[]` entry.
fn read_json(path: &Path, results: &Path, errors: &mut Vec<LoadError>) -> Option<Value> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            errors.push(LoadError {
                path: rel(results, path),
                reason: e.to_string(),
            });
            return None;
        }
    };
    match serde_json::from_slice(&bytes) {
        Ok(v) => Some(v),
        Err(e) => {
            errors.push(LoadError {
                path: rel(results, path),
                reason: e.to_string(),
            });
            None
        }
    }
}

fn rel(results: &Path, path: &Path) -> String {
    path.strip_prefix(results)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<(), ResultsError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|source| ResultsError::Json {
        path: path.to_path_buf(),
        source,
    })?;
    bytes.push(b'\n');
    write_atomic(path, &bytes)
}

fn remove_if_present(path: &Path) -> Result<(), ResultsError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ResultsError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// fsync `dir` so the renames into it survive a crash. Best effort: the
/// rename already happened, and some filesystems refuse to fsync a directory.
fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(handle) = File::open(dir) {
        let _ = handle.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Remove `write_atomic` temp files ([`is_write_atomic_temp`]) in `results` last
/// modified more than [`STALE_TEMP_AGE`] before `now`. Only regular files: a
/// symlink is neither followed nor removed, and directories are left alone.
/// Best effort. The caller holds the results lock, so no rebuild is writing
/// one; the age guard spares any other writer's fresh temp.
fn remove_stale_temps(results: &Path, now: SystemTime) {
    let Ok(entries) = std::fs::read_dir(results) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if !name.to_str().is_some_and(is_write_atomic_temp) {
            continue;
        }
        // `DirEntry::metadata` does not follow symlinks.
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let stale = meta.is_file()
            && meta
                .modified()
                .ok()
                .and_then(|modified| now.duration_since(modified).ok())
                .is_some_and(|age| age > STALE_TEMP_AGE);
        if stale {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// `.<name>.tmp-<pid>-<seq>-<nanos>`, exactly the name [`open_temp`] gives.
fn is_write_atomic_temp(file_name: &str) -> bool {
    let Some((name, suffix)) = file_name
        .strip_prefix('.')
        .and_then(|rest| rest.rsplit_once(".tmp-"))
    else {
        return false;
    };
    let fields: Vec<&str> = suffix.split('-').collect();
    !name.is_empty()
        && fields.len() == 3
        && fields
            .iter()
            .all(|f| !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()))
}

/// Write to a fresh sibling temp file then rename over `path`, so readers
/// never see a torn file and a crash mid-write leaves the previous version in
/// place. The temp file is created exclusively (`O_EXCL`, plus `O_NOFOLLOW`
/// on unix), so nothing planted at its name can redirect the write; the
/// rename replaces a symlink at `path` rather than writing through it.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ResultsError> {
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "out".to_owned());
    let (tmp, mut file) = open_temp(dir, &name)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    if let Err(source) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(ResultsError::Io { path: tmp, source });
    }
    if let Err(source) = retry_sharing_violation(|| std::fs::rename(&tmp, path)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(ResultsError::Io {
            path: path.to_path_buf(),
            source,
        });
    }
    Ok(())
}

/// Run `op`, retrying up to [`RENAME_RETRIES`] times while it fails with a
/// Windows sharing violation. Elsewhere `op` runs once.
fn retry_sharing_violation(op: impl FnMut() -> std::io::Result<()>) -> std::io::Result<()> {
    retry_sharing_violation_on(cfg!(windows), op)
}

/// [`retry_sharing_violation`] with the platform passed in, so the Windows
/// path is testable everywhere.
fn retry_sharing_violation_on(
    windows: bool,
    mut op: impl FnMut() -> std::io::Result<()>,
) -> std::io::Result<()> {
    let mut retries = 0;
    loop {
        match op() {
            Err(e)
                if windows
                    && matches!(e.raw_os_error(), Some(5 | 32))
                    && retries < RENAME_RETRIES =>
            {
                retries += 1;
                std::thread::sleep(RENAME_RETRY_DELAY);
            }
            outcome => return outcome,
        }
    }
}

/// A new `.<name>.tmp-<pid>-<seq>-<nanos>` in `dir`; a name that already
/// exists (a stale temp from a crashed run, or something planted) is never
/// opened, only skipped for the next one.
fn open_temp(dir: &Path, name: &str) -> Result<(PathBuf, File), ResultsError> {
    let mut attempt = 1;
    loop {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = dir.join(format!(".{name}.tmp-{}-{seq}-{nanos}", std::process::id()));
        match create_temp(&tmp) {
            Ok(file) => return Ok((tmp, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && attempt < TEMP_ATTEMPTS => {
                attempt += 1;
            }
            Err(source) => return Err(ResultsError::Io { path: tmp, source }),
        }
    }
}

fn create_temp(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

/// in-toto Statement v1 over every regular file under results/ (except the
/// attestation, the lock and other dotfiles), sorted by name.
pub fn attestation(results: &Path, tool: &ToolInfo) -> Result<Value, ResultsError> {
    attestation_capped(results, tool, MAX_ATTESTED_ENTRIES)
}

/// Symlinks (to files or directories) are neither followed nor attested.
/// The walk stops after `max_entries` directory entries and records that in
/// the predicate, so a runaway tree cannot stall a rebuild. A regular file
/// that cannot be hashed is named under `skipped` instead of a subject.
fn attestation_capped(
    results: &Path,
    tool: &ToolInfo,
    max_entries: usize,
) -> Result<Value, ResultsError> {
    let mut subjects = Vec::new();
    let mut skipped = Skipped::default();
    let mut visited = 0usize;
    let mut truncated = false;
    let mut stack = vec![results.to_path_buf()];
    'walk: while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).map_err(io_err(&dir))? {
            if visited == max_entries {
                truncated = true;
                break 'walk;
            }
            visited += 1;
            let entry = entry.map_err(io_err(&dir))?;
            let path = entry.path();
            // `DirEntry::file_type` does not follow symlinks.
            let file_type = entry.file_type().map_err(io_err(&path))?;
            let name = rel(results, &path);
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file()
                && !NOT_ATTESTED.contains(&name.as_str())
                && !name
                    .rsplit('/')
                    .next()
                    .is_some_and(|leaf| leaf.starts_with('.'))
            {
                match normalize::sha256_file_uncapped(&path) {
                    Some(digest) => {
                        subjects.push(json!({ "name": name, "digest": { "sha256": digest } }))
                    }
                    None => skipped.push(name),
                }
            }
        }
    }
    subjects.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://github.com/Tarmo-Technologies/bhf/results/v1",
        "predicate": {
            "tool": tool,
            "schema_version": FINDINGS_SCHEMA_VERSION,
            "truncated": truncated,
            "max_entries": max_entries,
            "skipped": skipped.names,
            "skipped_total": skipped.total,
        }
    }))
}

/// Files the attestation could not hash: the [`MAX_SKIPPED_LISTED`]
/// lexicographically lowest names (deterministic whatever the walk order)
/// and the total.
#[derive(Default)]
struct Skipped {
    names: BTreeSet<String>,
    total: usize,
}

impl Skipped {
    fn push(&mut self, name: String) {
        self.total += 1;
        self.names.insert(name);
        if self.names.len() > MAX_SKIPPED_LISTED {
            self.names.pop_last();
        }
    }
}

/// Begin/complete bracket for one command invocation.
pub struct ProducerRun {
    work_dir: PathBuf,
    command: String,
    argv: Vec<String>,
    started_at: String,
    source_root: Option<PathBuf>,
}

impl ProducerRun {
    pub fn begin(work_dir: &Path, command: &str, argv: Vec<String>) -> Self {
        Self {
            work_dir: work_dir.to_path_buf(),
            command: command.to_owned(),
            argv: manifest::redact_argv(&argv),
            started_at: corpus::finding::now_rfc3339(),
            source_root: None,
        }
    }

    /// The scanned tree, for commands (`static-scan`, `sbom`) that know it
    /// directly. Recorded in the manifest only if no earlier producer set one.
    pub fn source_root(mut self, root: &Path) -> Self {
        self.source_root = Some(root.to_path_buf());
        self
    }

    /// Append to the manifest and rebuild. Never changes the caller's exit code:
    /// callers print the error as a warning.
    pub fn complete(
        self,
        exit_code: i32,
        status: ProducerStatus,
    ) -> Result<RebuildSummary, ResultsError> {
        self.complete_with(exit_code, status, &RebuildOptions::default())
    }

    pub fn complete_with(
        self,
        exit_code: i32,
        status: ProducerStatus,
        options: &RebuildOptions,
    ) -> Result<RebuildSummary, ResultsError> {
        let results = layout::results_dir(&self.work_dir);
        std::fs::create_dir_all(&results).map_err(io_err(&results))?;
        let _lock = ResultsLock::acquire(&results, options.lock_timeout)?;
        let record = ProducerRecord {
            command: self.command,
            argv: self.argv,
            started_at: self.started_at,
            finished_at: options
                .now
                .clone()
                .unwrap_or_else(corpus::finding::now_rfc3339),
            status,
            exit_code,
            findings_total: 0, // filled by rebuild_locked
        };
        let pending = Pending {
            record,
            source_root: self.source_root,
        };
        rebuild_locked(&self.work_dir, &results, options, Some(pending))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn opts() -> RebuildOptions {
        RebuildOptions {
            tool: crate::model::ToolInfo {
                name: "bhf".into(),
                version: "0.0.0-test".into(),
                build: "test".into(),
            },
            now: Some("2026-10-01T12:00:00Z".into()),
            generate_reproducers: false,
            lock_timeout: Duration::from_secs(5),
        }
    }

    fn write(path: &Path, value: serde_json::Value) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    }

    fn read_doc(work: &Path) -> crate::model::FindingsDocument {
        serde_json::from_slice(&std::fs::read(work.join("results/findings.json")).unwrap()).unwrap()
    }

    fn read_value(path: &Path) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    fn sca_match(id: &str) -> serde_json::Value {
        json!({
            "id": id, "severity": "high", "summary": "s",
            "component": {"name": "example", "version": "1.0.0", "ecosystem": "npm",
                          "purl": "pkg:npm/example@1.0.0"}
        })
    }

    #[test]
    fn findings_json_leads_with_schema_version_for_cheap_detection() {
        let tmp = tempfile::tempdir().unwrap();
        rebuild(tmp.path(), &opts()).unwrap();
        let text = std::fs::read_to_string(tmp.path().join("results/findings.json")).unwrap();
        assert!(
            text.starts_with("{\n  \"schema_version\": \"bhf.findings.v1\",\n  \"generated_at\""),
            "importers sniff the first bytes; keep schema_version first: {}",
            &text[..80.min(text.len())]
        );
    }

    #[test]
    fn empty_work_dir_produces_an_empty_valid_index() {
        let tmp = tempfile::tempdir().unwrap();
        let summary = rebuild(tmp.path(), &opts()).unwrap();
        assert_eq!(summary.findings, 0);
        let doc = read_doc(tmp.path());
        assert!(doc.findings.is_empty());
        for f in [
            "INDEX.md",
            "findings.csv",
            "findings.sarif",
            "attestation.json",
            "manifest.json",
        ] {
            assert!(tmp.path().join("results").join(f).is_file(), "{f}");
        }
    }

    #[test]
    fn corrupt_record_lands_in_errors_and_the_rest_still_index() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("results/findings");
        write(
            &f.join("F-0000-aaaaaaaa/finding.json"),
            json!({"id": "F-0000-aaaaaaaa", "rule_id": "BHF-201", "classification": "unhandled"}),
        );
        std::fs::create_dir_all(f.join("F-0001-bbbbbbbb")).unwrap();
        std::fs::write(f.join("F-0001-bbbbbbbb/finding.json"), "{nope").unwrap();
        let summary = rebuild(tmp.path(), &opts()).unwrap();
        assert_eq!((summary.findings, summary.errors), (1, 1));
        let doc = read_value(&tmp.path().join("results/findings.json"));
        assert_eq!(
            doc["errors"][0]["path"],
            "findings/F-0001-bbbbbbbb/finding.json"
        );
    }

    #[test]
    fn record_the_normalizer_rejects_lands_in_errors_and_stays_out_of_sarif() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("results/findings");
        write(
            &f.join("F-0000-aaaaaaaa/finding.json"),
            json!({"id": "F-0000-aaaaaaaa", "rule_id": "BHF-201", "classification": "unhandled"}),
        );
        write(
            &f.join("F-0000-cccccccc/finding.json"),
            json!({"id": "F-0000-cccccccc", "rule_id": "BHF-201", "finding_kind": "sca"}),
        );
        let summary = rebuild(tmp.path(), &opts()).unwrap();
        assert_eq!((summary.findings, summary.errors), (1, 1));
        let doc = read_value(&tmp.path().join("results/findings.json"));
        assert_eq!(
            doc["errors"][0]["path"],
            "findings/F-0000-cccccccc/finding.json"
        );
        let sarif = read_value(&tmp.path().join("results/findings.sarif"));
        let ids: Vec<_> = sarif["runs"][0]["results"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|r| r.pointer("/properties/bhfFindingId")?.as_str())
            .collect();
        assert_eq!(ids, ["F-0000-aaaaaaaa"]);
    }

    /// The static-scan twin of an auto static record with fingerprint `fp-1`:
    /// `S-0001` in static-report.json (with a trace, remediation and engine
    /// only it supplies) and its result in static-report.sarif, in the
    /// static_analysis emitter's shape.
    fn write_static_scan_twin(w: &Path) {
        write(
            &w.join("results/static/static-report.json"),
            json!({
                "schema_version": "bhf.static.v1", "findings": [{
                    "id": "S-0001", "rule_id": "BHF-201", "cwe": "CWE-120", "severity": "high", "confidence": "high",
                    "message": "m", "location": {"path": "a.c", "line": 3, "column": 1}, "fingerprint": "fp-1",
                    "remediation": "Bound the copy by the destination size.",
                    "analysis": {"engine": "taint", "enclosing_function": "greet",
                                 "trace": [{"kind": "source", "path": "a.c", "line": 1, "caller": "main", "callee": "greet", "snippet": ""}]}
                }], "issues": []
            }),
        );
        write(
            &w.join("results/static/static-report.sarif"),
            json!({
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
                "runs": [{
                    "tool": {"driver": {"name": "BHF", "version": "0.3.0", "semanticVersion": "0.3.0",
                                        "rules": [{"id": "BHF-201", "shortDescription": {"text": "s"}}]}},
                    "results": [{
                        "ruleId": "BHF-201", "kind": "fail", "level": "error",
                        "message": {"text": "m"}, "help": {"text": "Bound the copy by the destination size."},
                        "locations": [{"physicalLocation": {
                            "artifactLocation": {"uri": "a.c", "uriBaseId": "SRCROOT"},
                            "region": {"startLine": 3, "startColumn": 1}}}],
                        "partialFingerprints": {"bhfStaticFingerprint": "fp-1"},
                        "properties": {"findingKind": "static", "cwe": "CWE-120", "fingerprint": "fp-1"}
                    }],
                    "properties": {"bhfStaticSchemaVersion": "bhf.static.v1", "findingKind": "static"},
                    "originalUriBaseIds": {"SRCROOT": {"uri": "file:///src/demo/"}}
                }]
            }),
        );
    }

    /// The fold kept `F-STATIC-0000`, enriched it from `S-0001`, and left the
    /// static-scan result out of findings.sarif.
    fn assert_folded_into_auto_record(w: &Path) -> crate::model::Finding {
        let doc = read_doc(w);
        let ids: Vec<_> = doc.findings.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(
            ids,
            ["F-STATIC-0000"],
            "the auto record keeps its established id"
        );
        let sarif = read_value(&w.join("results/findings.sarif"));
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(
            results.len(),
            1,
            "the folded static-scan result must not be emitted twice: {results:?}"
        );
        assert_eq!(results[0]["properties"]["bhfFindingId"], "F-STATIC-0000");
        let kept = doc.findings[0].clone();
        assert!(kept.static_.is_some(), "static block from S-0001");
        assert_eq!(
            kept.static_.as_ref().and_then(|s| s.engine.as_deref()),
            Some("taint")
        );
        assert_eq!(
            kept.trace,
            [crate::model::TraceStep {
                file: "a.c".into(),
                line: Some(1),
                function: Some("greet".into()),
                note: Some("source".into()),
            }],
            "trace from S-0001"
        );
        assert_eq!(
            kept.remediation.as_deref(),
            Some("Bound the copy by the destination size."),
            "remediation from S-0001"
        );
        kept
    }

    #[test]
    fn auto_static_record_absorbs_the_static_scan_twin() {
        let tmp = tempfile::tempdir().unwrap();
        let w = tmp.path();
        write(
            &w.join("results/findings/F-STATIC-0000/finding.json"),
            json!({
                "id": "F-STATIC-0000", "rule_id": "BHF-201", "classification": "static_scan",
                "confirmation": "static", "static_fingerprint": "fp-1", "finding_kind": "static"
            }),
        );
        write_static_scan_twin(w);
        rebuild(w, &opts()).unwrap();
        assert_folded_into_auto_record(w);
    }

    #[test]
    fn fuzz_confirmation_and_crash_group_survive_static_dedupe() {
        let tmp = tempfile::tempdir().unwrap();
        let w = tmp.path();
        write(
            &w.join("results/findings/F-STATIC-0000/finding.json"),
            json!({
                "id": "F-STATIC-0000", "rule_id": "BHF-201", "classification": "static_scan",
                "confirmation": "fuzz_confirmed", "static_fingerprint": "fp-1", "finding_kind": "static",
                "cluster_key_full": "crash-cluster"
            }),
        );
        write_static_scan_twin(w);
        rebuild(w, &opts()).unwrap();
        let kept = assert_folded_into_auto_record(w);
        assert_eq!(
            kept.confirmation.level,
            crate::model::ConfirmationLevel::StaticConfirmed
        );
        assert_eq!(kept.group.as_deref(), Some("crash-cluster"));
    }

    #[test]
    fn corrupt_static_sarif_lands_in_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let static_dir = tmp.path().join("results/static");
        std::fs::create_dir_all(&static_dir).unwrap();
        std::fs::write(
            static_dir.join("static-report.sarif"),
            r#"{"version": "2.1.0", "runs": [{"res"#,
        )
        .unwrap();
        let summary = rebuild(tmp.path(), &opts()).unwrap();
        assert_eq!(summary.errors, 1);
        let doc = read_doc(tmp.path());
        assert_eq!(doc.errors[0].path, "static/static-report.sarif");
    }

    #[test]
    fn static_scan_sarif_results_take_the_unified_level() {
        let tmp = tempfile::tempdir().unwrap();
        let w = tmp.path();
        write(
            &w.join("results/static/static-report.json"),
            json!({
                "schema_version": "bhf.static.v1", "findings": [{
                    "id": "S-0001", "rule_id": "BHF-201", "severity": "high", "confidence": "high",
                    "message": "m", "location": {"path": "a.c", "line": 3}, "fingerprint": "fp-9"
                }], "issues": []
            }),
        );
        // The shape static-scan emits: no bhfFindingId/bhfExceptionSignature,
        // which the fuzz-side SARIF validator would reject.
        write(
            &w.join("results/static/static-report.sarif"),
            json!({"version": "2.1.0", "runs": [{
                "tool": {"driver": {"name": "BHF", "version": "0.3.0", "rules": [{"id": "BHF-201"}]}},
                "originalUriBaseIds": {"SRCROOT": {"uri": "file:///src/demo/"}},
                "results": [{"ruleId": "BHF-201", "kind": "fail", "level": "note", "message": {"text": "m"},
                             "locations": [{"physicalLocation": {
                                 "artifactLocation": {"uri": "a.c", "uriBaseId": "SRCROOT"},
                                 "region": {"startLine": 3, "startColumn": 1}}}],
                             "partialFingerprints": {"bhfStaticFingerprint": "fp-9"},
                             "properties": {"findingKind": "static", "fingerprint": "fp-9"}}]
            }]}),
        );
        rebuild(w, &opts()).unwrap();
        let sarif = read_value(&w.join("results/findings.sarif"));
        let result = sarif["runs"][0]["results"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| {
                r.pointer("/partialFingerprints/bhfStaticFingerprint") == Some(&json!("fp-9"))
            })
            .expect("static result merged");
        assert_eq!(result["level"], "error", "high resolves to error");
        assert_eq!(result["partialFingerprints"]["bhfPrimary"], "fp-9");
        assert_eq!(result["properties"]["bhfFindingId"], "S-0001");
    }

    #[test]
    fn duplicate_sca_match_is_kept_once_without_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            &tmp.path().join("results/sbom/vulnerabilities.json"),
            json!({"matches": [sca_match("CVE-2026-0001"), sca_match("CVE-2026-0001")]}),
        );
        let summary = rebuild(tmp.path(), &opts()).unwrap();
        assert_eq!((summary.findings, summary.errors), (1, 0));
        assert!(read_doc(tmp.path()).findings[0].id.starts_with("F-SCA-"));
    }

    #[test]
    fn same_id_with_a_different_primary_is_reported_as_a_collision() {
        let first = crate::normalize::from_sca_value(&sca_match("CVE-2026-0001")).unwrap();
        let mut second = first.clone();
        second.fingerprint.primary = "something-else".into();
        let mut findings = vec![first.clone(), second];
        let mut errors = Vec::new();
        let deduped = dedupe(&mut findings, &mut errors);
        assert_eq!(findings, std::slice::from_ref(&first), "keep the first");
        assert!(
            !deduped.dropped.contains(&first.id),
            "the id is still in the document"
        );
        assert_eq!(
            errors,
            [LoadError {
                path: "sbom/vulnerabilities.json".into(),
                reason: format!("finding id collision: {}", first.id),
            }]
        );
    }

    #[test]
    fn index_gap_regression_every_family_is_listed() {
        let tmp = tempfile::tempdir().unwrap();
        let ids = [
            "F-0000-aaaaaaaa",
            "F-RO-BHF-201-0000ABCD",
            "F-STATIC-0000",
            "F-EXT-0000",
            "F-MSAN-0000",
            "F-TSAN-0000",
            "F-MEM-0000",
            "F-JSINK-0000",
            "F-DIFF-0000",
            "F-CAP-0000",
            "BF-0001",
        ];
        for id in ids {
            write(
                &tmp.path()
                    .join("results/findings")
                    .join(id)
                    .join("finding.json"),
                json!({"id": id, "rule_id": "BHF-201", "classification": "unhandled"}),
            );
        }
        let summary = rebuild(tmp.path(), &opts()).unwrap();
        assert_eq!(
            (summary.findings, summary.errors),
            (ids.len(), 0),
            "every family survives the loader"
        );
        let index = std::fs::read_to_string(tmp.path().join("results/INDEX.md")).unwrap();
        let csv = std::fs::read_to_string(tmp.path().join("results/findings.csv")).unwrap();
        for id in ids {
            assert!(csv.contains(&format!("\n{id},")), "{id} missing from CSV");
        }
        // INDEX.md has one section per root-cause group, headed by its
        // representative; every finding is a member of exactly one group.
        let doc = read_doc(tmp.path());
        let members: Vec<&str> = doc
            .groups
            .iter()
            .flat_map(|g| g.members.iter().map(String::as_str))
            .collect();
        let mut sorted_members = members.clone();
        sorted_members.sort_unstable();
        let mut sorted_ids = ids.to_vec();
        sorted_ids.sort_unstable();
        assert_eq!(sorted_members, sorted_ids, "each finding in one group");
        assert_eq!(
            index.matches("\n## ").count(),
            doc.groups.len(),
            "one section per group:\n{index}"
        );
        for group in &doc.groups {
            assert!(
                index.contains(&format!("- Finding: `{}` (", group.representative)),
                "group {} (representative {}) missing from INDEX.md:\n{index}",
                group.key,
                group.representative
            );
        }
    }

    #[test]
    fn producer_run_appends_history_and_rebuilds() {
        let tmp = tempfile::tempdir().unwrap();
        let run = ProducerRun::begin(
            tmp.path(),
            "fuzz",
            vec!["bhf".into(), "fuzz".into(), "--token".into(), "t".into()],
        );
        let summary = run
            .complete_with(0, ProducerStatus::Complete, &opts())
            .unwrap();
        assert_eq!(summary.findings, 0);
        let manifest = crate::manifest::load(&tmp.path().join("results")).unwrap();
        assert_eq!(manifest.producers.len(), 1);
        assert_eq!(
            manifest.producers[0].argv,
            ["bhf", "fuzz", "--token", "<redacted>"]
        );
    }

    #[test]
    fn producer_run_records_exit_code_status_and_findings_total() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            &tmp.path().join("results/sbom/vulnerabilities.json"),
            json!({"matches": [sca_match("CVE-2026-0001")]}),
        );
        ProducerRun::begin(tmp.path(), "sbom", vec!["bhf".into(), "sbom".into()])
            .source_root(Path::new("/src/demo"))
            .complete_with(3, ProducerStatus::Partial, &opts())
            .unwrap();
        let manifest = crate::manifest::load(&tmp.path().join("results")).unwrap();
        let record = &manifest.producers[0];
        assert_eq!(
            (record.exit_code, record.status, record.findings_total),
            (3, ProducerStatus::Partial, 1)
        );
        assert_eq!(manifest.source.root.as_deref(), Some("/src/demo"));
        assert_eq!(read_doc(tmp.path()).producers, manifest.producers);
    }

    fn seed_producers(results: &Path, n: usize) {
        std::fs::create_dir_all(results).unwrap();
        let mut manifest = crate::manifest::load(results).unwrap();
        manifest.producers = (0..n)
            .map(|i| ProducerRecord {
                command: format!("p{i}"),
                argv: vec!["bhf".into()],
                started_at: "2026-10-01T12:00:00Z".into(),
                finished_at: "2026-10-01T12:00:00Z".into(),
                status: ProducerStatus::Complete,
                exit_code: 0,
                findings_total: 0,
            })
            .collect();
        crate::manifest::save(results, &manifest).unwrap();
    }

    #[test]
    fn producer_history_keeps_the_last_1000_and_findings_json_the_last_50() {
        let tmp = tempfile::tempdir().unwrap();
        let results = tmp.path().join("results");
        seed_producers(&results, 1000);
        ProducerRun::begin(tmp.path(), "fuzz", vec!["bhf".into(), "fuzz".into()])
            .complete_with(0, ProducerStatus::Complete, &opts())
            .unwrap();
        let manifest = crate::manifest::load(&results).unwrap();
        assert_eq!(manifest.producers.len(), 1000);
        assert_eq!(manifest.producers[0].command, "p1", "the oldest is dropped");
        assert_eq!(manifest.producers[999].command, "fuzz");
        let doc = read_doc(tmp.path());
        assert_eq!(doc.producers.len(), 50);
        assert_eq!(doc.producers[..], manifest.producers[950..]);
    }

    #[test]
    fn plain_rebuild_trims_an_oversized_producer_history() {
        let tmp = tempfile::tempdir().unwrap();
        let results = tmp.path().join("results");
        seed_producers(&results, 1200);
        rebuild(tmp.path(), &opts()).unwrap();
        let manifest = crate::manifest::load(&results).unwrap();
        assert_eq!(manifest.producers.len(), 1000);
        assert_eq!(manifest.producers[0].command, "p200");
        assert_eq!(read_doc(tmp.path()).producers[49].command, "p1199");
    }

    #[test]
    fn concurrent_producers_on_one_work_dir_all_record() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().to_path_buf();
        write(
            &work.join("results/sbom/vulnerabilities.json"),
            json!({"matches": [sca_match("CVE-2026-0001")]}),
        );
        let threads: Vec<_> =
            (0..8)
                .map(|i| {
                    let work = work.clone();
                    std::thread::spawn(move || {
                        let options = RebuildOptions {
                            lock_timeout: Duration::from_secs(120),
                            ..opts()
                        };
                        ProducerRun::begin(&work, &format!("p{i}"), vec!["bhf".into()])
                            .complete_with(0, ProducerStatus::Complete, &options)
                    })
                })
                .collect();
        for thread in threads {
            thread.join().unwrap().expect("every producer completes");
        }
        let manifest = crate::manifest::load(&work.join("results")).unwrap();
        let mut commands: Vec<&str> = manifest
            .producers
            .iter()
            .map(|p| p.command.as_str())
            .collect();
        commands.sort();
        assert_eq!(commands, ["p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7"]);
        let doc = read_doc(&work);
        assert_eq!(doc.producers.len(), 8);
        assert_eq!(doc.counts.total, 1);
        assert!(manifest.producers.iter().all(|p| p.findings_total == 1));
    }

    #[test]
    fn producer_record_survives_a_failed_derived_write() {
        let tmp = tempfile::tempdir().unwrap();
        let results = tmp.path().join("results");
        // A non-empty directory at findings.csv makes that rename fail.
        std::fs::create_dir_all(results.join("findings.csv/child")).unwrap();
        let outcome = ProducerRun::begin(tmp.path(), "fuzz", vec!["bhf".into(), "fuzz".into()])
            .source_root(Path::new("/src/demo"))
            .complete_with(0, ProducerStatus::Complete, &opts());
        assert!(outcome.is_err(), "the findings.csv write must fail");
        let manifest = crate::manifest::load(&results).unwrap();
        assert_eq!(manifest.producers.len(), 1, "producer record lost");
        assert_eq!(manifest.producers[0].command, "fuzz");
        assert_eq!(manifest.source.root.as_deref(), Some("/src/demo"));
        assert!(
            !results.join("findings.json").exists(),
            "findings.json is the commit point, written after the other derived files"
        );
    }

    #[test]
    fn producer_record_survives_a_hard_loader_error() {
        let tmp = tempfile::tempdir().unwrap();
        let results = tmp.path().join("results");
        std::fs::create_dir_all(&results).unwrap();
        // The tolerant loader refuses a findings root that is not a directory.
        std::fs::write(results.join("findings"), "not a dir").unwrap();
        let outcome = ProducerRun::begin(tmp.path(), "fuzz", vec!["bhf".into(), "fuzz".into()])
            .complete_with(2, ProducerStatus::Complete, &opts());
        assert!(
            matches!(outcome, Err(ResultsError::Report(_))),
            "{outcome:?}"
        );
        let manifest = crate::manifest::load(&results).unwrap();
        assert_eq!(manifest.producers.len(), 1, "producer record lost");
        let record = &manifest.producers[0];
        assert_eq!(
            (
                record.command.as_str(),
                record.exit_code,
                record.findings_total
            ),
            ("fuzz", 2, 0)
        );
        assert!(!results.join("findings.json").exists());
    }

    #[test]
    fn sarif_validation_failure_is_reported_and_the_rest_is_written() {
        let tmp = tempfile::tempdir().unwrap();
        let results = tmp.path().join("results");
        write(
            &results.join("findings/F-0000-aaaaaaaa/finding.json"),
            json!({"id": "F-0000-aaaaaaaa", "rule_id": "BHF-201", "classification": "unhandled"}),
        );
        // A findings.sarif from an earlier rebuild no longer matches findings.json.
        std::fs::write(results.join("findings.sarif"), "{}").unwrap();
        let _lock = ResultsLock::acquire(&results, Duration::from_secs(5)).unwrap();
        let summary = rebuild_locked_with(tmp.path(), &results, &opts(), None, |_| {
            Err(report::ReportError::SarifValidation("injected".to_owned()))
        })
        .unwrap();
        assert_eq!((summary.findings, summary.errors), (1, 1));
        let doc = read_doc(tmp.path());
        assert_eq!(doc.errors.len(), 1);
        assert_eq!(doc.errors[0].path, "findings.sarif");
        assert!(
            doc.errors[0].reason.starts_with("not written: ")
                && doc.errors[0].reason.contains("injected"),
            "{:?}",
            doc.errors[0]
        );
        assert!(!results.join("findings.sarif").exists(), "stale SARIF kept");
        for name in ["findings.csv", "INDEX.md", "attestation.json"] {
            assert!(results.join(name).is_file(), "{name}");
        }
    }

    #[test]
    fn manifest_ends_with_a_newline() {
        let tmp = tempfile::tempdir().unwrap();
        rebuild(tmp.path(), &opts()).unwrap();
        let text = std::fs::read_to_string(tmp.path().join("results/manifest.json")).unwrap();
        assert!(text.ends_with("}\n"), "{text:?}");
    }

    #[test]
    fn unminimized_groups_counts_groups_not_findings() {
        let tmp = tempfile::tempdir().unwrap();
        for id in ["F-0000-aaaaaaaa", "F-0001-bbbbbbbb"] {
            write(
                &tmp.path()
                    .join("results/findings")
                    .join(id)
                    .join("finding.json"),
                json!({
                    "id": id, "rule_id": "BHF-201", "classification": "unhandled",
                    "cluster_key_full": "one-cluster", "fidelity_caveat": crate::UNMINIMIZED_CAVEAT
                }),
            );
        }
        rebuild(tmp.path(), &opts()).unwrap();
        let doc = read_doc(tmp.path());
        assert_eq!(doc.groups.len(), 1, "{:?}", doc.groups);
        let index = std::fs::read_to_string(tmp.path().join("results/INDEX.md")).unwrap();
        assert!(
            index.contains("- ⚠ 1 root-cause group(s) were not minimized"),
            "{index}"
        );
    }

    #[test]
    fn stale_temp_files_are_removed_at_rebuild() {
        let tmp = tempfile::tempdir().unwrap();
        let results = tmp.path().join("results");
        std::fs::create_dir_all(&results).unwrap();
        let two_hours_ago = std::time::SystemTime::now() - Duration::from_secs(2 * 3600);
        let backdate = |path: &Path| {
            std::fs::File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_modified(two_hours_ago)
                .unwrap();
        };
        let stale = results.join(".findings.json.tmp-1-2-3");
        let fresh = results.join(".findings.csv.tmp-1-2-3");
        let other = results.join(".keep-me");
        // Not write_atomic's `.tmp-<pid>-<seq>-<nanos>`: someone's backup.
        let backup = results.join(".foo.tmp-bak");
        for path in [&stale, &fresh, &other, &backup] {
            std::fs::write(path, "x").unwrap();
        }
        backdate(&stale);
        backdate(&other);
        backdate(&backup);
        let stale_dir = results.join(".INDEX.md.tmp-4-5-6");
        std::fs::create_dir_all(stale_dir.join("child")).unwrap();

        rebuild(tmp.path(), &opts()).unwrap();
        assert!(!stale.exists(), "stale temp file kept");
        assert!(fresh.exists(), "a fresh temp may belong to a live writer");
        assert!(other.exists(), "only temp names are removed");
        assert!(
            backup.exists(),
            "only write_atomic's exact temp names are removed"
        );
        assert!(
            stale_dir.join("child").exists(),
            "directories are left alone"
        );
    }

    #[test]
    fn temp_name_matcher_matches_what_open_temp_creates() {
        let tmp = tempfile::tempdir().unwrap();
        let (path, file) = open_temp(tmp.path(), "findings.json").unwrap();
        drop(file);
        let name = path.file_name().unwrap().to_str().unwrap();
        assert!(is_write_atomic_temp(name), "{name}");
        for other in [
            ".foo.tmp-bak",
            ".foo.tmp-1-2",
            ".foo.tmp-1-2-3-4",
            ".foo.tmp-1-x-3",
            ".foo.tmp-1--3",
            "foo.tmp-1-2-3",
            "..tmp-1-2-3",
            ".lock",
        ] {
            assert!(!is_write_atomic_temp(other), "{other}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn stale_temp_cleanup_never_follows_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let results = tmp.path().join("results");
        std::fs::create_dir_all(&results).unwrap();
        let victim = tmp.path().join("victim");
        std::fs::write(&victim, "untouched").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&victim)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - Duration::from_secs(2 * 3600))
            .unwrap();
        let link = results.join(".findings.json.tmp-7-8-9");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        remove_stale_temps(
            &results,
            std::time::SystemTime::now() + Duration::from_secs(3 * 3600),
        );
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched");
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    /// Calls `retry_sharing_violation_on(windows, ..)` makes for an op that
    /// always fails with `error`.
    fn rename_calls(windows: bool, error: fn() -> std::io::Error) -> u32 {
        let mut calls = 0;
        let outcome = retry_sharing_violation_on(windows, || {
            calls += 1;
            Err(error())
        });
        assert!(outcome.is_err());
        calls
    }

    #[test]
    fn sharing_violation_retry_is_bounded_and_windows_only() {
        use std::io::{Error, ErrorKind};
        // ERROR_ACCESS_DENIED and ERROR_SHARING_VIOLATION, as lock.rs matches them.
        for code in [5, 32] {
            let error = match code {
                5 => || Error::from_raw_os_error(5),
                _ => || Error::from_raw_os_error(32),
            };
            assert_eq!(rename_calls(true, error), 1 + RENAME_RETRIES, "{code}");
            assert_eq!(rename_calls(false, error), 1, "{code} off Windows");
        }
        // A PermissionDenied with another (or no) OS code is final.
        assert_eq!(rename_calls(true, || Error::from_raw_os_error(13)), 1);
        assert_eq!(
            rename_calls(true, || Error::from(ErrorKind::PermissionDenied)),
            1
        );
        assert_eq!(rename_calls(true, || Error::from(ErrorKind::NotFound)), 1);

        let mut calls = 0;
        retry_sharing_violation_on(true, || {
            calls += 1;
            if calls == 1 {
                Err(Error::from_raw_os_error(32))
            } else {
                Ok(())
            }
        })
        .unwrap();
        assert_eq!(calls, 2, "succeeds once the holder lets go");
    }

    #[test]
    fn attestation_covers_every_results_file_but_itself() {
        let tmp = tempfile::tempdir().unwrap();
        write(
            &tmp.path()
                .join("results/findings/F-0000-aaaaaaaa/finding.json"),
            json!({"id": "F-0000-aaaaaaaa"}),
        );
        rebuild(tmp.path(), &opts()).unwrap();
        let att = read_value(&tmp.path().join("results/attestation.json"));
        let names: Vec<_> = att["subject"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["name"].as_str().unwrap().to_owned())
            .collect();
        assert!(names.contains(&"findings.json".to_owned()));
        assert!(names.contains(&"findings/F-0000-aaaaaaaa/finding.json".to_owned()));
        assert!(!names
            .iter()
            .any(|n| n == "attestation.json" || n == ".lock"));
        assert_eq!(att["predicate"]["truncated"], false);
    }

    #[test]
    fn attestation_hashes_files_past_the_evidence_cap() {
        let tmp = tempfile::tempdir().unwrap();
        let results = tmp.path();
        let big = results.join("big.bin");
        let file = std::fs::File::create(&big).unwrap();
        file.set_len(64 * 1024 * 1024 + 1).unwrap();
        drop(file);
        let att = attestation(results, &opts().tool).unwrap();
        let subject = att["subject"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == "big.bin")
            .expect("a file over 64 MiB is still attested");
        assert_eq!(
            subject["digest"]["sha256"].as_str().unwrap().len(),
            64,
            "{subject}"
        );
    }

    #[test]
    fn attestation_walk_is_bounded_and_says_so() {
        let tmp = tempfile::tempdir().unwrap();
        for i in 0..5 {
            std::fs::write(tmp.path().join(format!("f{i}.txt")), "x").unwrap();
        }
        let att = attestation_capped(tmp.path(), &opts().tool, 3).unwrap();
        assert_eq!(att["predicate"]["truncated"], true);
        assert_eq!(att["predicate"]["max_entries"], 3);
        assert!(att["subject"].as_array().unwrap().len() <= 3);
    }

    #[cfg(unix)]
    #[test]
    fn attestation_lists_files_it_could_not_hash() {
        use std::os::unix::fs::PermissionsExt;
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("SKIP: root reads a mode-000 file");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("ok.txt"), "x").unwrap();
        let locked = tmp.path().join("locked.txt");
        std::fs::write(&locked, "x").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let att = attestation(tmp.path(), &opts().tool).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o600)).unwrap();
        let names: Vec<_> = att["subject"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["ok.txt"]);
        assert_eq!(att["predicate"]["skipped"], json!(["locked.txt"]));
        assert_eq!(att["predicate"]["skipped_total"], 1);
    }

    #[test]
    fn skipped_list_is_capped_and_keeps_the_lowest_names() {
        let mut skipped = Skipped::default();
        for i in (0..MAX_SKIPPED_LISTED + 5).rev() {
            skipped.push(format!("f{i:04}"));
        }
        assert_eq!(skipped.total, MAX_SKIPPED_LISTED + 5);
        let listed: Vec<_> = skipped.names.iter().cloned().collect();
        assert_eq!(listed.len(), MAX_SKIPPED_LISTED);
        assert_eq!(listed[0], "f0000");
        assert_eq!(
            listed.last().unwrap(),
            &format!("f{:04}", MAX_SKIPPED_LISTED - 1)
        );
    }

    #[cfg(unix)]
    #[test]
    fn attestation_never_follows_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), "s").unwrap();
        let results = tmp.path().join("results");
        std::fs::create_dir_all(&results).unwrap();
        std::fs::write(results.join("real.txt"), "r").unwrap();
        std::os::unix::fs::symlink(outside.join("secret.txt"), results.join("link.txt")).unwrap();
        std::os::unix::fs::symlink(&outside, results.join("linkdir")).unwrap();
        let att = attestation(&results, &opts().tool).unwrap();
        let names: Vec<_> = att["subject"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["real.txt"]);
    }

    #[test]
    fn fuzz_sarif_results_carry_no_host_root() {
        let mut sarif = json!({"runs": [{
            "originalUriBaseIds": {"SRCROOT": {"uri": "file:///src/demo/"}},
            "results": [{
                "message": {"text": "at /src/demo/a.c"},
                "properties": {
                    "actionabilityFixLocation": {"path": "/src/demo/src/parse.c", "line": 42},
                    "actionabilityNextSteps": ["Inspect /src/demo/src/parse.c as the primary fix location."],
                    "actionabilityPatchHints": [{"guidance": "Check `/src/demo/src/parse.c:42`."}],
                    "other": "/opt/src/demo/x.c"
                }
            }]
        }]});
        strip_root_in_fuzz_results(&mut sarif, Some(Path::new("/src/demo")));
        let props = &sarif["runs"][0]["results"][0]["properties"];
        assert_eq!(props["actionabilityFixLocation"]["path"], "src/parse.c");
        assert_eq!(props["actionabilityFixLocation"]["line"], 42);
        assert_eq!(
            props["actionabilityNextSteps"][0],
            "Inspect src/parse.c as the primary fix location."
        );
        assert_eq!(
            props["actionabilityPatchHints"][0]["guidance"],
            "Check `src/parse.c:42`."
        );
        assert_eq!(props["other"], "/opt/src/demo/x.c", "not under the root");
        assert_eq!(
            sarif["runs"][0]["originalUriBaseIds"]["SRCROOT"]["uri"], "file:///src/demo/",
            "SRCROOT is the one legitimate absolute root"
        );
        assert_eq!(sarif["runs"][0]["results"][0]["message"]["text"], "at a.c");
    }

    #[test]
    fn write_atomic_replaces_the_file_and_leaves_no_temp_behind() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("out.json");
        std::fs::write(&dest, "old").unwrap();
        write_atomic(&dest, b"new").unwrap();
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "new");
        let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .filter(|n| n != "out.json")
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn write_atomic_removes_its_temp_file_when_the_rename_fails() {
        let tmp = tempfile::tempdir().unwrap();
        // A non-empty directory at the destination makes rename fail.
        let dest = tmp.path().join("out.json");
        std::fs::create_dir_all(dest.join("child")).unwrap();
        assert!(write_atomic(&dest, b"new").is_err());
        let names: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["out.json"], "temp file left behind");
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_never_writes_through_a_planted_temp_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let victim = tmp.path().join("victim");
        std::fs::write(&victim, "untouched").unwrap();
        let planted = tmp.path().join(".out.json.tmp-planted");
        std::os::unix::fs::symlink(&victim, &planted).unwrap();
        let err = create_temp(&planted).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched");
        assert!(std::fs::symlink_metadata(&planted)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_replaces_a_destination_symlink_instead_of_following_it() {
        let tmp = tempfile::tempdir().unwrap();
        let victim = tmp.path().join("victim");
        std::fs::write(&victim, "untouched").unwrap();
        let dest = tmp.path().join("out.json");
        std::os::unix::fs::symlink(&victim, &dest).unwrap();
        write_atomic(&dest, b"new").unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched");
        assert!(std::fs::symlink_metadata(&dest).unwrap().is_file());
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "new");
    }
}
