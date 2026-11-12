// SPDX-License-Identifier: Apache-2.0

//! Multi-core fuzzing orchestrator.
//!
//! Spawns N parallel `bhf fuzz` worker subprocesses, all
//! pointed at the same work directory. Each worker writes its
//! own slice of the corpus + findings; the orchestrator collates
//! findings across workers and reports an aggregate `MulticoreSummary`.
//!
//! The orchestrator seeds every worker from a central
//! `corpus/<harness>/queue`, gives each worker a private work tree,
//! then imports newly discovered queue entries back into the central
//! queue and writes a sync manifest. That is still lighter than an
//! AFL master/slave protocol, but it gives offline campaigns a real
//! shared-corpus handoff between worker runs and CI invocations.
//!
//! Tracks issue #292.

mod merge;

pub use merge::{merge_worker_findings, MergeReport};

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MulticoreConfig {
    /// Bhf work directory containing build/<harness_id>/.
    pub work_dir: PathBuf,
    pub harness_id: String,
    pub workers: WorkerCount,
    /// Per-worker iteration budget. None = run until time budget
    /// elapses.
    pub per_worker_iterations: Option<u64>,
    /// Wall-clock budget for the whole campaign.
    pub time_budget: Duration,
    /// Path to the bhf binary the orchestrator should spawn.
    /// `which` lookup is the caller's responsibility.
    pub bhf_bin: PathBuf,
    /// Per-worker environment overrides keyed by worker_id (e.g.
    /// `ASAN_OPTIONS` / `MSAN_OPTIONS` / `UBSAN_OPTIONS` for the
    /// sanitizer-composition flow from #296). When the per-worker
    /// map is empty the worker inherits the orchestrator's env.
    pub per_worker_env: Vec<Vec<(String, String)>>,
    /// Extra argv passed through to every `bhf fuzz` worker after
    /// the orchestrator-owned worker budget, seed, and harness args.
    pub extra_worker_args: Vec<String>,
    /// Grace period beyond `time_budget` before the orchestrator
    /// SIGKILLs workers that haven't exited. Only enforced when
    /// `time_budget` is non-zero — the worker is supposed to honour
    /// `--time` on its own and this is a backstop for hangs.
    /// `None` defaults to 5 seconds.
    pub kill_grace: Option<Duration>,
    /// Every work-dir-relative directory a worker's harness lookup reads (for
    /// example `build/<id>` and `harnesses/<id>`), whether or not the parent has
    /// it. Each worker tree gets an exact copy of the ones the parent has and
    /// loses its copy of the ones the parent lacks, so a worker's lookup lands on
    /// the executable the parent resolved, never on a file an earlier campaign
    /// left in the worker tree. Empty means `build/<harness_id>` only.
    pub harness_dirs: Vec<PathBuf>,
    /// Work-dir-relative path of the harness executable the parent resolved.
    /// Every worker tree must hold it once mirrored, or the campaign fails
    /// before that worker starts.
    pub harness_executable: Option<PathBuf>,
}

/// Each worker's stderr, captured inside its own work dir.
pub const WORKER_STDERR_LOG: &str = "worker-stderr.log";
/// How much of a failed worker's stderr [`WorkerReport::stderr_tail`] keeps.
const STDERR_TAIL_BYTES: u64 = 4096;
const STDERR_TAIL_LINES: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerCount {
    /// Use `available_parallelism() - 1` workers, capped at 1+.
    Auto,
    /// Use a fixed count. Must be >= 1.
    Fixed(u32),
}

impl WorkerCount {
    pub fn resolve(self) -> Result<u32, MulticoreError> {
        match self {
            WorkerCount::Auto => {
                let cpus = std::thread::available_parallelism()
                    .map(|n| n.get() as u32)
                    .unwrap_or(1);
                Ok(cpus.saturating_sub(1).max(1))
            }
            WorkerCount::Fixed(0) => Err(MulticoreError::InvalidWorkerCount),
            WorkerCount::Fixed(n) => Ok(n),
        }
    }
}

/// Spawn a worker, retrying the two transient failures that make an `exec` of a
/// FRESHLY WRITTEN executable fail.
///
/// `ExecutableFileBusy` (`ETXTBSY`): the kernel refuses to exec a file that is
/// still open for writing ANYWHERE. bhf builds a harness and then fuzzes it,
/// and a multicore run forks several workers at once — a child forked by one
/// thread inherits a write descriptor another thread has not closed yet, so the
/// exec of that path fails. Load- and filesystem-dependent, which is why it shows
/// up as an intermittent CI failure and never locally.
///
/// `replay` was given this treatment in 0.2.27 (see `replay_min::spawn_harness`);
/// the multicore worker spawn has the same window and was missed, surfacing as
/// `worker 0 failed to spawn: Text file busy` on a loaded runner.
///
/// Matched on `ErrorKind` rather than raw errno so it compiles on every target.
fn spawn_worker(command: &mut Command) -> std::io::Result<std::process::Child> {
    const RETRY_DELAY: Duration = Duration::from_millis(25);
    const RETRIES: usize = 40; // ~1s total, far longer than either window lasts
    for _ in 0..RETRIES {
        match command.spawn() {
            Ok(child) => return Ok(child),
            Err(error) => {
                if !matches!(
                    error.kind(),
                    std::io::ErrorKind::ExecutableFileBusy | std::io::ErrorKind::WouldBlock
                ) {
                    return Err(error);
                }
                std::thread::sleep(RETRY_DELAY);
            }
        }
    }
    command.spawn()
}

#[derive(Debug, thiserror::Error)]
pub enum MulticoreError {
    #[error("work dir does not exist: {0}")]
    WorkDirMissing(PathBuf),
    #[error("worker count must be at least 1")]
    InvalidWorkerCount,
    #[error("bhf binary not found: {0}")]
    BinMissing(PathBuf),
    #[error("worker {worker_id} failed to spawn: {source}")]
    WorkerSpawn {
        worker_id: u32,
        source: std::io::Error,
    },
    #[error("worker {worker_id} exited non-zero ({exit_code:?})")]
    WorkerFailed {
        worker_id: u32,
        exit_code: Option<i32>,
    },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("refusing to merge worker findings into {}: it is {reason}", path.display())]
    UnsafeFindingsDir { path: PathBuf, reason: &'static str },
    #[error(
        "refusing to mirror harness dir '{}' into worker trees: it is not a plain path inside the work dir",
        path.display()
    )]
    UnsafeHarnessDir { path: PathBuf },
    #[error(
        "worker tree {} has no harness executable '{}' after mirroring the harness dirs",
        worker_dir.display(),
        executable.display()
    )]
    HarnessNotMirrored {
        worker_dir: PathBuf,
        executable: PathBuf,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MulticoreSummary {
    pub harness_id: String,
    pub workers_started: u32,
    pub workers_completed: u32,
    pub total_findings: usize,
    pub unique_findings: usize,
    pub campaign_dir: PathBuf,
    pub sync_manifest_path: PathBuf,
    pub sync: CorpusSyncReport,
    pub per_worker: Vec<WorkerReport>,
    /// Duplicates earlier campaigns left in the worker trees whose parent
    /// finding has since been removed, dropped before the workers started.
    #[serde(default)]
    pub dropped_duplicates: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerReport {
    pub worker_id: u32,
    pub work_dir: PathBuf,
    pub exit_code: Option<i32>,
    /// Findings in the worker tree at the end, including duplicates an earlier
    /// campaign left there.
    pub findings_count: usize,
    /// Findings the worker recorded during this campaign.
    #[serde(default)]
    pub new_findings: usize,
    pub env_keys: Vec<String>,
    /// The worker was still running at the time limit (plus the kill grace) and
    /// was stopped. Its `exit_code` is `None`, as for a worker killed by a
    /// signal, but it fuzzed until then.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stopped_at_deadline: bool,
    /// The worker's captured stderr ([`WORKER_STDERR_LOG`] in its work dir).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr_log: Option<PathBuf>,
    /// The last lines of that stderr, kept only for a worker that did not
    /// complete (non-zero exit, or killed at the deadline).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr_tail: Option<String>,
}

impl WorkerReport {
    /// The worker exited zero.
    pub fn completed(&self) -> bool {
        self.exit_code == Some(0)
    }
}

struct RunningWorker {
    worker_id: u32,
    work_dir: PathBuf,
    env_keys: Vec<String>,
    stderr_log: PathBuf,
    /// Findings already in the worker tree when it started.
    findings_before: usize,
    child: std::process::Child,
}

impl RunningWorker {
    fn report(self, exit_code: Option<i32>, stopped_at_deadline: bool) -> WorkerReport {
        let completed = exit_code == Some(0);
        let findings_count = count_findings(&self.work_dir);
        WorkerReport {
            worker_id: self.worker_id,
            findings_count,
            new_findings: findings_count.saturating_sub(self.findings_before),
            work_dir: self.work_dir,
            exit_code,
            env_keys: self.env_keys,
            stopped_at_deadline,
            stderr_tail: (!completed)
                .then(|| stderr_tail(&self.stderr_log))
                .flatten(),
            stderr_log: Some(self.stderr_log),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusSyncReport {
    pub shared_queue: PathBuf,
    pub seed_inputs_loaded: usize,
    pub imported_inputs: usize,
    pub duplicate_inputs: usize,
}

/// Spawn `workers` parallel fuzz subprocesses and wait for all of
/// them to terminate. Each worker gets its own `work_dir`/worker-N/
/// subdirectory (a copy of the base build tree); findings are
/// collated at the end.
pub fn run_multicore(config: &MulticoreConfig) -> Result<MulticoreSummary, MulticoreError> {
    if !config.work_dir.is_dir() {
        return Err(MulticoreError::WorkDirMissing(config.work_dir.clone()));
    }
    if !config.bhf_bin.is_file() {
        return Err(MulticoreError::BinMissing(config.bhf_bin.clone()));
    }
    let workers = config.workers.resolve()?;
    let campaign_dir = config
        .work_dir
        .join("fuzz_campaigns")
        .join(&config.harness_id);
    let shared_queue = config
        .work_dir
        .join("corpus")
        .join(&config.harness_id)
        .join("queue");
    std::fs::create_dir_all(&campaign_dir)?;
    std::fs::create_dir_all(&shared_queue)?;
    let shared_seed_files = queue_seed_files(&shared_queue)?;
    let mut children: Vec<RunningWorker> = Vec::new();
    let worker_namespace = sanitize_worker_namespace(&config.harness_id);
    // Namespace per harness so two campaigns sharing one work_dir (e.g.
    // fuzzing two harnesses at once) don't collide on `worker-N` dirs and
    // cross-contaminate each other's corpus/findings.
    let worker_dirs: Vec<PathBuf> = (0..workers)
        .map(|worker_id| {
            config
                .work_dir
                .join(format!("worker-{worker_namespace}-{worker_id}"))
        })
        .collect();
    let dropped_duplicates = merge::drop_orphaned_duplicates(&config.work_dir, &worker_dirs)?;
    for (worker_id, worker_dir) in (0..workers).zip(worker_dirs) {
        std::fs::create_dir_all(&worker_dir)?;
        mirror_harness_layout(config, &worker_dir)?;
        let findings_before = count_findings(&worker_dir);
        copy_shared_queue_to_worker(&shared_queue, &worker_dir, &config.harness_id)?;
        // A file, not a pipe: nothing drains a pipe while the workers run, so a
        // worker writing more than the pipe buffer would block until killed.
        let stderr_log = worker_dir.join(WORKER_STDERR_LOG);
        let stderr_file = std::fs::File::create(&stderr_log)?;
        let worker_env = env_for_worker(&config.per_worker_env, worker_id);
        let env_keys = worker_env
            .iter()
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();
        let mut cmd = Command::new(&config.bhf_bin);
        cmd.arg("fuzz")
            .arg(&worker_dir)
            .arg("--harness")
            .arg(&config.harness_id)
            .arg("--rng-seed")
            .arg(format!("{}", 0x4756_4655_5a5a_u64 ^ (worker_id as u64)))
            .env("BHF_WORKER_ID", worker_id.to_string())
            .env("BHF_SHARED_CORPUS_DIR", &shared_queue)
            .env("BHF_CAMPAIGN_DIR", &campaign_dir)
            // The orchestrating `bhf fuzz` records the campaign and rebuilds
            // results/ once; workers must not each do it.
            .env(corpus::layout::RESULTS_DEFER_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_file));
        if let Some(iterations) = config.per_worker_iterations {
            cmd.arg("--iterations").arg(iterations.to_string());
        }
        if !config.time_budget.is_zero() {
            cmd.arg("--time")
                .arg(format!("{}s", config.time_budget.as_secs()));
        }
        for seed_file in &shared_seed_files {
            cmd.arg("--seed-file").arg(seed_file);
        }
        for arg in &config.extra_worker_args {
            cmd.arg(arg);
        }
        for (k, v) in &worker_env {
            cmd.env(k, v);
        }
        let child = spawn_worker(&mut cmd)
            .map_err(|source| MulticoreError::WorkerSpawn { worker_id, source })?;
        children.push(RunningWorker {
            worker_id,
            work_dir: worker_dir,
            env_keys,
            stderr_log,
            findings_before,
            child,
        });
    }
    let workers_started = children.len() as u32;
    let mut workers_completed = 0u32;
    let mut per_worker: Vec<WorkerReport> = Vec::new();
    let start = Instant::now();
    let kill_grace = config.kill_grace.unwrap_or(Duration::from_secs(5));
    let enforce_deadline = !config.time_budget.is_zero();
    let mut pending = children;
    while !pending.is_empty() {
        let should_kill =
            enforce_deadline && start.elapsed() > config.time_budget.saturating_add(kill_grace);
        let mut still_pending = Vec::with_capacity(pending.len());
        for mut worker in pending.drain(..) {
            match worker.child.try_wait() {
                Ok(Some(status)) => {
                    if status.success() {
                        workers_completed += 1;
                    }
                    per_worker.push(worker.report(status.code(), false));
                }
                Ok(None) => {
                    if should_kill {
                        let _ = worker.child.kill();
                        let _ = worker.child.wait();
                        per_worker.push(worker.report(None, true));
                    } else {
                        still_pending.push(worker);
                    }
                }
                Err(error) => return Err(MulticoreError::Io(error)),
            }
        }
        pending = still_pending;
        if !pending.is_empty() {
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    // The loop above pushes each report as its worker exits, so the order is
    // whatever the scheduler produced. Sort by worker_id before anything reads
    // it: the campaign summary is a published artifact (diffing two runs must
    // not show phantom churn) and `sync_worker_corpora` imports corpora in this
    // order, so leaving it racy makes the sync accounting order-dependent too.
    per_worker.sort_by_key(|report| report.worker_id);

    let total_findings: usize = per_worker.iter().map(|r| r.findings_count).sum();
    let unique_findings = unique_finding_count(&per_worker);
    let sync = sync_worker_corpora(
        &config.work_dir,
        &config.harness_id,
        &per_worker,
        shared_seed_files.len(),
        &shared_queue,
    )?;
    let sync_manifest_path = config
        .work_dir
        .join("fuzz_campaigns")
        .join(format!("{}-sync-manifest.json", config.harness_id));

    let summary = MulticoreSummary {
        harness_id: config.harness_id.clone(),
        workers_started,
        workers_completed,
        total_findings,
        unique_findings,
        campaign_dir,
        sync_manifest_path,
        sync,
        per_worker,
        dropped_duplicates,
    };
    write_campaign_artifacts(&config.work_dir, &summary)?;
    Ok(summary)
}

fn env_for_worker(envs: &[Vec<(String, String)>], worker_id: u32) -> Vec<(String, String)> {
    if envs.is_empty() {
        Vec::new()
    } else {
        envs[(worker_id as usize) % envs.len()].clone()
    }
}

fn queue_seed_files(shared_queue: &Path) -> Result<Vec<PathBuf>, MulticoreError> {
    let mut files = Vec::new();
    if !shared_queue.is_dir() {
        return Ok(files);
    }
    for entry in std::fs::read_dir(shared_queue)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file() {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn copy_shared_queue_to_worker(
    shared_queue: &Path,
    worker_dir: &Path,
    harness_id: &str,
) -> Result<(), MulticoreError> {
    if !shared_queue.is_dir() {
        return Ok(());
    }
    let worker_queue = worker_dir.join("corpus").join(harness_id).join("queue");
    std::fs::create_dir_all(&worker_queue)?;
    for seed_file in queue_seed_files(shared_queue)? {
        let Some(name) = seed_file.file_name() else {
            continue;
        };
        std::fs::copy(&seed_file, worker_queue.join(name))?;
    }
    Ok(())
}

fn sync_worker_corpora(
    work_dir: &Path,
    harness_id: &str,
    per_worker: &[WorkerReport],
    seed_inputs_loaded: usize,
    shared_queue: &Path,
) -> Result<CorpusSyncReport, MulticoreError> {
    std::fs::create_dir_all(shared_queue)?;
    let mut seen = HashSet::<Vec<u8>>::new();
    for seed_file in queue_seed_files(shared_queue)? {
        if let Ok(bytes) = std::fs::read(seed_file) {
            seen.insert(bytes);
        }
    }

    let mut imported_inputs = 0_usize;
    let mut duplicate_inputs = 0_usize;
    for worker in per_worker {
        let worker_queue = worker
            .work_dir
            .join("corpus")
            .join(harness_id)
            .join("queue");
        for queue_file in queue_seed_files(&worker_queue)? {
            let bytes = std::fs::read(&queue_file)?;
            if !seen.insert(bytes.clone()) {
                duplicate_inputs += 1;
                continue;
            }
            let Some(name) = queue_file.file_name() else {
                continue;
            };
            let mut destination = shared_queue.join(name);
            if destination.exists() {
                destination = shared_queue.join(format!(
                    "worker-{}-{}",
                    worker.worker_id,
                    name.to_string_lossy()
                ));
            }
            std::fs::write(destination, bytes)?;
            imported_inputs += 1;
        }
    }

    Ok(CorpusSyncReport {
        shared_queue: work_dir.join("corpus").join(harness_id).join("queue"),
        seed_inputs_loaded,
        imported_inputs,
        duplicate_inputs,
    })
}

fn write_campaign_artifacts(
    work_dir: &Path,
    summary: &MulticoreSummary,
) -> Result<(), MulticoreError> {
    let runs_dir = work_dir.join("fuzz_campaigns");
    std::fs::create_dir_all(&runs_dir)?;
    let latest = runs_dir.join(format!("{}-latest.json", summary.harness_id));
    std::fs::write(
        &latest,
        format!("{}\n", serde_json::to_string_pretty(summary)?),
    )?;
    let manifest = serde_json::json!({
        "schema_version": 1,
        "harness_id": summary.harness_id,
        "workers_started": summary.workers_started,
        "workers_completed": summary.workers_completed,
        "total_findings": summary.total_findings,
        "unique_findings": summary.unique_findings,
        "campaign_dir": summary.campaign_dir,
        "sync": summary.sync,
        "per_worker": summary.per_worker,
    });
    std::fs::write(
        &summary.sync_manifest_path,
        format!("{}\n", serde_json::to_string_pretty(&manifest)?),
    )?;
    Ok(())
}

/// Make each harness layout dir in a worker tree an exact copy of the parent's,
/// and remove the worker's copy of any dir the parent does not have. A copy an
/// earlier campaign left is reused only while it still matches the parent's
/// dir file for file ([`trees_match`]); otherwise it is replaced. The worker's
/// harness lookup reads only these dirs, so it resolves the executable the
/// parent resolved: not an empty dir a failed attempt left, not a binary rebuilt
/// since, and not one the parent has moved or removed.
fn mirror_harness_layout(config: &MulticoreConfig, dst_work: &Path) -> Result<(), MulticoreError> {
    let legacy = [Path::new("build").join(&config.harness_id)];
    let dirs: &[PathBuf] = if config.harness_dirs.is_empty() {
        &legacy
    } else {
        &config.harness_dirs
    };
    for rel in dirs {
        if !is_plain_relative(rel) {
            return Err(MulticoreError::UnsafeHarnessDir { path: rel.clone() });
        }
        let src = config.work_dir.join(rel);
        let dst = dst_work.join(rel);
        if !src.is_dir() {
            remove_path(&dst)?;
            continue;
        }
        if dst.is_dir() && trees_match(&src, &dst)? {
            continue;
        }
        remove_path(&dst)?;
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        copy_dir_recursive(&src, &dst)?;
    }
    if let Some(executable) = &config.harness_executable {
        if !dst_work.join(executable).is_file() {
            return Err(MulticoreError::HarnessNotMirrored {
                worker_dir: dst_work.to_path_buf(),
                executable: executable.clone(),
            });
        }
    }
    copy_line_map_sidecars(&config.work_dir, dst_work);
    Ok(())
}

/// A non-empty relative path made only of normal components, so joining it to
/// a worker dir can never reach outside that dir.
fn is_plain_relative(path: &Path) -> bool {
    path.components().next().is_some()
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

/// Remove whatever is at `path` (a dir tree, a file or a symlink); nothing
/// there is fine.
fn remove_path(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(path),
        Ok(_) => std::fs::remove_file(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// One entry of a tree as [`copy_dir_recursive`] copies it.
#[derive(Debug, PartialEq, Eq)]
enum TreeEntry {
    Dir,
    File {
        len: u64,
        modified: Option<std::time::SystemTime>,
    },
}

/// Every entry under `root` that [`copy_dir_recursive`] copies, keyed by its
/// path relative to `root`: dirs, regular files and symlinks to regular files
/// (described by their target).
fn tree_listing(root: &Path) -> std::io::Result<std::collections::BTreeMap<PathBuf, TreeEntry>> {
    let mut listing = std::collections::BTreeMap::new();
    let mut pending = vec![PathBuf::new()];
    while let Some(rel) = pending.pop() {
        for entry in std::fs::read_dir(root.join(&rel))? {
            let entry = entry?;
            let rel = rel.join(entry.file_name());
            match copied_kind(&entry)? {
                Some(Copied::Dir) => {
                    listing.insert(rel.clone(), TreeEntry::Dir);
                    pending.push(rel);
                }
                Some(Copied::File(meta)) => {
                    listing.insert(
                        rel,
                        TreeEntry::File {
                            len: meta.len(),
                            modified: meta.modified().ok(),
                        },
                    );
                }
                None => {}
            }
        }
    }
    Ok(listing)
}

/// Whether the worker copy `dst` still matches `src`: the same dirs and files,
/// each file the same size and modification time (the copy carries the
/// source's time over). An extra, missing, resized or rewritten file is a
/// mismatch.
fn trees_match(src: &Path, dst: &Path) -> std::io::Result<bool> {
    Ok(tree_listing(src)? == tree_listing(dst)?)
}

/// The last lines of a worker's stderr log, or `None` when it is empty.
fn stderr_tail(path: &Path) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    let start = len.saturating_sub(STDERR_TAIL_BYTES);
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let mut lines: Vec<&str> = text.lines().collect();
    if start > 0 && lines.len() > 1 {
        lines.remove(0); // cut mid-line by the byte window
    }
    let keep = lines.len().saturating_sub(STDERR_TAIL_LINES);
    let tail = lines[keep..].join("\n");
    (!tail.trim().is_empty()).then_some(tail)
}

/// Map a harness id to a filesystem-safe worker-directory namespace
/// (alphanumeric / `-` / `_` kept; anything else collapsed to `_`).
fn sanitize_worker_namespace(harness_id: &str) -> String {
    let mapped: String = harness_id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if mapped.is_empty() {
        "harness".to_owned()
    } else {
        mapped
    }
}

/// Copy the instrumented→original line-map sidecars into the worker tree so
/// worker-emitted findings remap exception lines to the original source just
/// like the single-process path. Best-effort: absence simply skips remapping.
fn copy_line_map_sidecars(src_work: &Path, dst_work: &Path) {
    let src_dir = src_work.join("src_instrumented");
    let dst_dir = dst_work.join("src_instrumented");
    let Ok(entries) = std::fs::read_dir(&src_dir) else {
        return;
    };
    let _ = std::fs::create_dir_all(&dst_dir);
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name.to_string_lossy().ends_with(".bhf-lines.json") {
            let _ = std::fs::copy(entry.path(), dst_dir.join(&name));
        }
    }
}

enum Copied {
    Dir,
    File(std::fs::Metadata),
}

/// How [`copy_dir_recursive`] treats an entry: a dir is walked, a regular file
/// or a symlink to one is copied as a file, anything else (a symlink to a dir,
/// a dangling link, a socket) is skipped.
fn copied_kind(entry: &std::fs::DirEntry) -> std::io::Result<Option<Copied>> {
    let file_type = entry.file_type()?;
    if file_type.is_dir() {
        return Ok(Some(Copied::Dir));
    }
    if file_type.is_file() {
        return entry.metadata().map(|meta| Some(Copied::File(meta)));
    }
    if file_type.is_symlink() {
        if let Ok(meta) = std::fs::metadata(entry.path()) {
            if meta.is_file() {
                return Ok(Some(Copied::File(meta)));
            }
        }
    }
    Ok(None)
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), MulticoreError> {
    std::fs::create_dir_all(dst).map_err(MulticoreError::Io)?;
    for entry in std::fs::read_dir(src).map_err(MulticoreError::Io)? {
        let entry = entry.map_err(MulticoreError::Io)?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        match copied_kind(&entry)? {
            Some(Copied::Dir) => copy_dir_recursive(&from, &to)?,
            Some(Copied::File(meta)) => copy_file_with_time(&from, &to, &meta)?,
            None => {}
        }
    }
    Ok(())
}

/// Copy a file's bytes and permissions, and carry its modification time over
/// so [`trees_match`] can tell later whether the source changed.
fn copy_file_with_time(
    from: &Path,
    to: &Path,
    meta: &std::fs::Metadata,
) -> Result<(), MulticoreError> {
    let mut reader = std::fs::File::open(from)?;
    let mut writer = std::fs::File::create(to)?;
    std::io::copy(&mut reader, &mut writer)?;
    if let Ok(modified) = meta.modified() {
        // Best effort: a filesystem that cannot set it only makes the next
        // campaign copy this file again.
        let _ = writer.set_modified(modified);
    }
    drop(writer);
    std::fs::set_permissions(to, meta.permissions())?;
    Ok(())
}

/// The `<SAN>_OPTIONS` key for a sanitizer.
pub fn sanitizer_options_key(s: Sanitizer) -> &'static str {
    match s {
        Sanitizer::Asan => "ASAN_OPTIONS",
        Sanitizer::Msan => "MSAN_OPTIONS",
        Sanitizer::Ubsan => "UBSAN_OPTIONS",
        Sanitizer::Tsan => "TSAN_OPTIONS",
        Sanitizer::Lsan => "LSAN_OPTIONS",
    }
}

/// The runtime keys bhf must set on every armed `<SAN>_OPTIONS`:
/// `abort_on_error`/`halt_on_error` turn a sanitizer report into a fault the
/// engine saves as a finding (instead of a printed-and-ignored warning), and
/// `detect_leaks` arms LSan. These MUST win over any operator value.
///
/// `symbolize=0` deliberately does NOT belong here. AFL++ v4 refuses to start
/// when it inherits a custom `ASAN_OPTIONS` without it, so the afl-fuzz
/// invocation sets it on its own child env — but a BUILTIN-engine child must
/// keep symbolizing, because the file and line in a sanitizer report are what
/// join a crash to the static finding at the same line. Setting it globally to
/// appease AFL silently downgraded every fuzz-confirmed static finding to
/// `fuzz_exercised`, which is the one result bhf exists to produce.
const REQUIRED_SANITIZER_OPTIONS: &str = "abort_on_error=1:halt_on_error=1:detect_leaks=1";

/// UBSan keys bhf requires on top of [`REQUIRED_SANITIZER_OPTIONS`]: the stack
/// of each report (`print_stacktrace=1`) and the failed check's name on its
/// `SUMMARY:` line (`report_error_type=1`). Without them a UBSan report is one
/// `file:line:col: runtime error:` line: no function for the sink and no check
/// name to tell one defect from another.
pub const UBSAN_REPORT_OPTIONS: &str = "print_stacktrace=1:report_error_type=1";

/// Merge an operator-provided `<SAN>_OPTIONS` (from the inherited environment)
/// with the keys bhf requires (#435). bhf's keys go LAST so they win on
/// conflict — an operator cannot accidentally disable `abort_on_error`, which is
/// what makes a sanitizer report a saved finding — while every other operator
/// key is preserved. This is how an operator tames the RTOS / partial-build
/// false-positive storm: export e.g.
/// `ASAN_OPTIONS=verify_asan_link_order=0:detect_container_overflow=0:detect_odr_violation=0:allocator_may_return_null=1:suppressions=$PWD/asan.supp`
/// (and `LSAN_OPTIONS=suppressions=$PWD/lsan.supp`) and bhf keeps it. Each
/// sanitizer is merged independently, so per-sanitizer suppressions files land in
/// the right place (an LSan suppressions file never leaks into `ASAN_OPTIONS`).
pub fn merge_sanitizer_options(inherited: Option<&str>, required: &str) -> String {
    match inherited.map(str::trim).filter(|s| !s.is_empty()) {
        Some(prefix) => format!("{prefix}:{required}"),
        None => required.to_owned(),
    }
}

/// Sanitizer composition envs (#296): produce a per-worker env vector that points
/// each worker at one of ASan / MSan / UBSan / TSan / LSan via
/// `<SANITIZER>_OPTIONS`. The harness binary must already be built with the
/// relevant sanitizer flags — this only orchestrates the env-controlled runtime
/// options. Each value MERGES the operator's inherited `<SAN>_OPTIONS` (so
/// suppressions / FP-killer options survive) with bhf's required keys (#435).
pub fn sanitizer_envs(sanitizers: &[Sanitizer]) -> Vec<Vec<(String, String)>> {
    sanitizers
        .iter()
        .map(|s| {
            let key = sanitizer_options_key(*s);
            let required = match s {
                Sanitizer::Ubsan => {
                    format!("{REQUIRED_SANITIZER_OPTIONS}:{UBSAN_REPORT_OPTIONS}")
                }
                _ => REQUIRED_SANITIZER_OPTIONS.to_owned(),
            };
            let value = merge_sanitizer_options(std::env::var(key).ok().as_deref(), &required);
            vec![(key.to_owned(), value)]
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sanitizer {
    Asan,
    Msan,
    Ubsan,
    Tsan,
    Lsan,
}

impl Sanitizer {
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "asan" | "address" => Some(Sanitizer::Asan),
            "msan" | "memory" => Some(Sanitizer::Msan),
            "ubsan" | "undefined" => Some(Sanitizer::Ubsan),
            "tsan" | "thread" => Some(Sanitizer::Tsan),
            "lsan" | "leak" => Some(Sanitizer::Lsan),
            _ => None,
        }
    }
}

/// What `--sanitizers` selected for a build+run (#434). Distinguishes the three
/// meaningful states that a bare `Vec<Sanitizer>` could not:
///
/// * [`SanitizerSelection::Default`] — no `--sanitizers` given. The harness
///   Makefile's baked-in `-fsanitize=address,undefined` stands; build and run
///   env are left byte-identical to the historical behavior.
/// * [`SanitizerSelection::None`] — `--sanitizers none`. The native build keeps
///   the engine's coverage instrumentation but drops the `-fsanitize=` group
///   entirely: native crash-only + coverage fuzzing with **zero** ASan/UBSan
///   false positives (the escape hatch for shared-memory / custom-allocator /
///   RTOS code that FP-storms under ASan). No runtime `<SAN>_OPTIONS`.
/// * [`SanitizerSelection::Set`] — `--sanitizers <set>`. Arm exactly this set on
///   both the build (`-fsanitize=<set>`) and the run env.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SanitizerSelection {
    #[default]
    Default,
    None,
    Set(Vec<Sanitizer>),
}

impl SanitizerSelection {
    /// The sanitizers whose runtime `<SAN>_OPTIONS` must be armed. Empty for
    /// `Default` (the Makefile bakes ASan/UBSan, but we do not override their
    /// run env) and for `None`.
    pub fn runtime_set(&self) -> &[Sanitizer] {
        match self {
            SanitizerSelection::Set(set) => set,
            SanitizerSelection::Default | SanitizerSelection::None => &[],
        }
    }

    /// True when the native build's `-fsanitize=`/coverage flags must be
    /// overridden. `Default` leaves the Makefile flags intact; `None` and `Set`
    /// both replace them.
    pub fn overrides_build(&self) -> bool {
        !matches!(self, SanitizerSelection::Default)
    }
}

fn count_findings(worker_dir: &Path) -> usize {
    let findings_dir = corpus::layout::findings_dir(worker_dir);
    let Ok(entries) = std::fs::read_dir(findings_dir) else {
        return 0;
    };
    entries.filter_map(|e| e.ok()).count()
}

/// Distinct crashes across the workers, by the rule the merge into the parent
/// uses: harness-scoped, any shared dedupe key is the same crash.
fn unique_finding_count(per_worker: &[WorkerReport]) -> usize {
    merge::count_unique(per_worker.iter().map(|report| report.work_dir.as_path()))
}

#[cfg(test)]
mod tests {
    /// The builtin engine and AFL++ want OPPOSITE symbolization, and satisfying
    /// AFL globally is what broke the product's differentiator.
    ///
    /// AFL++ v4 aborts in pre-flight on a custom `ASAN_OPTIONS` without
    /// `symbolize=0`, so the afl-fuzz spawn sets it on that child. Putting it
    /// here instead stripped file:line from every builtin child's sanitizer
    /// report — and file:line is exactly what joins a crash to the static finding
    /// on the same line, so every `fuzz_confirmed` static finding silently
    /// downgraded to `fuzz_exercised`.
    #[test]
    #[cfg(unix)]
    fn worker_spawn_retries_a_freshly_written_executable_that_is_still_open() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        // ETXTBSY: the kernel refuses to exec a file that is still open for
        // WRITING anywhere. Holding the writer open reproduces deterministically
        // what a loaded CI runner hits by accident when one thread is still
        // finishing a write while another forks.
        let dir = std::env::temp_dir().join(format!(
            "bhf-mc-etxtbsy-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("worker.sh");
        let mut writer = std::fs::File::create(&script).unwrap();
        writer.write_all(b"#!/bin/sh\nexit 0\n").unwrap();
        writer.flush().unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        // Still-open writer -> a bare spawn fails.
        let bare = Command::new(&script).spawn();
        let bare_failed_busy = matches!(
            &bare,
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy
        );
        if let Ok(mut child) = bare {
            let _ = child.wait();
        }

        // Release the descriptor from another thread while the retry loop runs,
        // exactly as the real race resolves itself.
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(60));
            drop(writer);
        });
        let mut cmd = Command::new(&script);
        let spawned = spawn_worker(&mut cmd);
        handle.join().unwrap();
        assert!(
            spawned.is_ok(),
            "spawn_worker must ride out ETXTBSY, got {:?}",
            spawned.err()
        );
        let _ = spawned.unwrap().wait();
        // Only meaningful if the platform actually produced the race; say so
        // rather than silently passing a test that proved nothing.
        if !bare_failed_busy {
            eprintln!("note: this filesystem did not produce ETXTBSY for an open writer");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn builtin_children_keep_symbolization_for_the_fuzz_confirmation_join() {
        assert!(
            !REQUIRED_SANITIZER_OPTIONS.contains("symbolize"),
            "a builtin fuzz child must symbolize so a crash carries file:line: \
             {REQUIRED_SANITIZER_OPTIONS}"
        );
        // The keys that make a sanitizer report a saved finding stay required.
        for key in ["abort_on_error=1", "halt_on_error=1", "detect_leaks=1"] {
            assert!(
                REQUIRED_SANITIZER_OPTIONS.contains(key),
                "{key} is required"
            );
        }
        // An operator asking for no symbolization is still honoured — bhf
        // does not force it on — and their other keys survive the merge.
        let merged = merge_sanitizer_options(
            Some("symbolize=0:suppressions=/x.supp"),
            REQUIRED_SANITIZER_OPTIONS,
        );
        assert!(merged.contains("symbolize=0"), "{merged}");
        assert!(
            merged.contains("suppressions=/x.supp"),
            "operator keys survive: {merged}"
        );
        assert!(merged.contains("abort_on_error=1"), "{merged}");
    }

    /// The AFL child's own env is built by merging `symbolize=0` LAST, so it wins
    /// over whatever the builtin path put in `extra_env`. That ordering is the
    /// whole fix: applying `extra_env` after the explicit value silently undid it
    /// and AFL went back to aborting in pre-flight.
    #[test]
    fn the_afl_child_env_forces_symbolize_off_over_an_inherited_value() {
        let builtin = merge_sanitizer_options(None, REQUIRED_SANITIZER_OPTIONS);
        let afl = merge_sanitizer_options(Some(&builtin), "symbolize=0");
        assert!(
            afl.contains("symbolize=0"),
            "AFL++ will not start without it: {afl}"
        );
        assert!(
            afl.contains("abort_on_error=1"),
            "and it must not lose the keys that save a finding: {afl}"
        );
    }

    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn worker_namespace_is_harness_specific_and_path_safe() {
        // Two harnesses yield distinct namespaces (no worker-dir collision when
        // sharing a work_dir); odd chars collapse to '_'.
        assert_eq!(
            sanitize_worker_namespace("H-A0048-0B811272"),
            "H-A0048-0B811272"
        );
        assert_ne!(
            sanitize_worker_namespace("H-A0048-0B811272"),
            sanitize_worker_namespace("H-A004E-E9877A92")
        );
        assert_eq!(sanitize_worker_namespace("a/b c"), "a_b_c");
        assert_eq!(sanitize_worker_namespace(""), "harness");
    }

    fn tempdir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("bhf-multicore-{name}-{nonce}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn worker_count_auto_resolves_at_least_one() {
        let n = WorkerCount::Auto.resolve().unwrap();
        assert!(n >= 1);
    }

    #[test]
    fn worker_count_fixed_zero_is_rejected() {
        assert!(matches!(
            WorkerCount::Fixed(0).resolve(),
            Err(MulticoreError::InvalidWorkerCount)
        ));
    }

    #[test]
    fn worker_count_fixed_n_returns_n() {
        assert_eq!(WorkerCount::Fixed(7).resolve().unwrap(), 7);
    }

    #[test]
    #[cfg(unix)]
    fn per_worker_reports_are_ordered_by_worker_id_not_completion() {
        use std::os::unix::fs::PermissionsExt;

        // The reaping loop polls `try_wait` and pushes each report as the
        // worker exits, so completion order is a race. Stagger it so worker 0
        // is guaranteed to finish last: an unsorted report would lead with
        // worker 1, making both the campaign summary artifact and every
        // consumer that indexes `per_worker[i]` nondeterministic.
        let work = tempdir("worker-order");
        let script = work.join("stagger.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\nif [ \"$BHF_WORKER_ID\" = \"0\" ]; then sleep 1; fi\nexit 0\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let config = MulticoreConfig {
            work_dir: work.clone(),
            harness_id: "H-ORDER".to_owned(),
            workers: WorkerCount::Fixed(2),
            per_worker_iterations: None,
            // Zero disables deadline enforcement, so the loop reaps both
            // workers on their own schedule rather than killing the sleeper.
            time_budget: Duration::from_secs(0),
            bhf_bin: script,
            per_worker_env: Vec::new(),
            extra_worker_args: Vec::new(),
            kill_grace: None,
            harness_dirs: Vec::new(),
            harness_executable: None,
        };

        let summary = run_multicore(&config).expect("staggered campaign completes");
        assert_eq!(summary.workers_started, 2);
        assert_eq!(
            summary
                .per_worker
                .iter()
                .map(|r| r.worker_id)
                .collect::<Vec<_>>(),
            vec![0, 1],
            "per_worker must be ordered by worker_id, not by exit order"
        );
    }

    #[test]
    #[cfg(unix)]
    fn workers_defer_the_results_rebuild_to_the_parent() {
        use std::os::unix::fs::PermissionsExt;

        // argv is `fuzz <worker_dir> ...`; record what the worker saw.
        let work = tempdir("defer");
        let script = work.join("record-env.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\nprintf '%s' \"${BHF_RESULTS_DEFER-unset}\" > \"$2/defer\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let config = MulticoreConfig {
            work_dir: work.clone(),
            harness_id: "H-DEFER".to_owned(),
            workers: WorkerCount::Fixed(1),
            per_worker_iterations: None,
            time_budget: Duration::from_secs(0),
            bhf_bin: script,
            per_worker_env: Vec::new(),
            extra_worker_args: Vec::new(),
            kill_grace: None,
            harness_dirs: Vec::new(),
            harness_executable: None,
        };
        let summary = run_multicore(&config).expect("campaign completes");
        let seen = std::fs::read_to_string(summary.per_worker[0].work_dir.join("defer")).unwrap();
        assert_eq!(seen, "1");
    }

    #[test]
    fn run_multicore_rejects_missing_work_dir() {
        let config = MulticoreConfig {
            work_dir: PathBuf::from("/nonexistent/work"),
            harness_id: "H".to_owned(),
            workers: WorkerCount::Auto,
            per_worker_iterations: None,
            time_budget: Duration::from_secs(1),
            bhf_bin: PathBuf::from("/bin/true"),
            per_worker_env: Vec::new(),
            extra_worker_args: Vec::new(),
            kill_grace: None,
            harness_dirs: Vec::new(),
            harness_executable: None,
        };
        assert!(matches!(
            run_multicore(&config),
            Err(MulticoreError::WorkDirMissing(_))
        ));
    }

    #[test]
    fn run_multicore_rejects_missing_bhf_bin() {
        let work = tempdir("missing-bin");
        let config = MulticoreConfig {
            work_dir: work,
            harness_id: "H".to_owned(),
            workers: WorkerCount::Fixed(1),
            per_worker_iterations: Some(1),
            time_budget: Duration::from_secs(1),
            bhf_bin: PathBuf::from("/nonexistent/bin/bhf"),
            per_worker_env: Vec::new(),
            extra_worker_args: Vec::new(),
            kill_grace: None,
            harness_dirs: Vec::new(),
            harness_executable: None,
        };
        assert!(matches!(
            run_multicore(&config),
            Err(MulticoreError::BinMissing(_))
        ));
    }

    #[test]
    fn run_multicore_rejects_zero_workers() {
        let work = tempdir("zero");
        let config = MulticoreConfig {
            work_dir: work,
            harness_id: "H".to_owned(),
            workers: WorkerCount::Fixed(0),
            per_worker_iterations: None,
            time_budget: Duration::from_secs(1),
            bhf_bin: PathBuf::from("/bin/true"),
            per_worker_env: Vec::new(),
            extra_worker_args: Vec::new(),
            kill_grace: None,
            harness_dirs: Vec::new(),
            harness_executable: None,
        };
        assert!(matches!(
            run_multicore(&config),
            Err(MulticoreError::InvalidWorkerCount)
        ));
    }

    #[test]
    fn count_findings_returns_zero_for_missing_dir() {
        let dir = tempdir("count-zero");
        assert_eq!(count_findings(&dir), 0);
    }

    #[test]
    fn count_findings_counts_finding_subdirectories() {
        let dir = tempdir("count");
        let findings = dir.join("results").join("findings");
        std::fs::create_dir_all(findings.join("F-0001")).unwrap();
        std::fs::create_dir_all(findings.join("F-0002")).unwrap();
        assert_eq!(count_findings(&dir), 2);
    }

    #[test]
    fn unique_finding_count_dedups_across_workers_by_cluster_key() {
        let dir = tempdir("uniq");
        for worker in 0..2 {
            let worker_dir = dir.join(format!("worker-{worker}"));
            let findings_dir = worker_dir.join("results").join("findings");
            let f = findings_dir.join(format!("F-{worker:04}"));
            std::fs::create_dir_all(&f).unwrap();
            std::fs::write(
                f.join("finding.json"),
                serde_json::json!({
                    "cluster_key_full": "shared-cluster-key",
                    "signature": format!("signature-{worker}")
                })
                .to_string(),
            )
            .unwrap();
        }
        let reports = vec![
            WorkerReport {
                worker_id: 0,
                work_dir: dir.join("worker-0"),
                exit_code: Some(0),
                findings_count: 1,
                env_keys: Vec::new(),
                ..WorkerReport::default()
            },
            WorkerReport {
                worker_id: 1,
                work_dir: dir.join("worker-1"),
                exit_code: Some(0),
                findings_count: 1,
                env_keys: Vec::new(),
                ..WorkerReport::default()
            },
        ];
        // Two workers, one shared cluster_key → 1 unique.
        assert_eq!(unique_finding_count(&reports), 1);
    }

    fn report_for(worker_id: u32, work_dir: PathBuf) -> WorkerReport {
        WorkerReport {
            worker_id,
            work_dir,
            exit_code: Some(0),
            ..WorkerReport::default()
        }
    }

    fn put_finding(work_dir: &Path, id: &str, record: serde_json::Value) {
        let dir = corpus::layout::finding_dir(work_dir, id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("finding.json"), record.to_string()).unwrap();
    }

    #[test]
    fn unique_finding_count_agrees_with_the_merge() {
        let tmp = tempfile::tempdir().unwrap();
        let work = tmp.path().to_path_buf();
        let finding = |harness: &str, cluster: Option<&str>, signature: Option<&str>| {
            let mut record = serde_json::json!({"harness_id": harness, "rule_id": "BHF-201"});
            if let Some(cluster) = cluster {
                record["cluster_key_full"] = cluster.into();
            }
            if let Some(signature) = signature {
                record["signature"] = signature.into();
            }
            record
        };
        put_finding(
            &work,
            "F-0000-aaaaaaaa",
            finding("H-A", Some("K1"), Some("aaaaaaaa")),
        );
        let w0 = work.join("worker-H-0");
        let w1 = work.join("worker-H-1");
        // Already in the parent.
        put_finding(
            &w0,
            "F-0000-aaaaaaaa",
            finding("H-A", Some("K1"), Some("aaaaaaaa")),
        );
        put_finding(
            &w0,
            "F-0001-bbbbbbbb",
            finding("H-A", Some("K2"), Some("bbbbbbbb")),
        );
        // Another harness's K1: a finding of its own.
        put_finding(
            &w1,
            "F-0000-aaaaaaaa",
            finding("H-B", Some("K1"), Some("aaaaaaaa")),
        );
        // Worker 0's K2 again, under another signature.
        put_finding(
            &w1,
            "F-0001-cccccccc",
            finding("H-A", Some("K2"), Some("cccccccc")),
        );
        // Worker 1's own K3, matched only by worker 0's signature: a duplicate.
        put_finding(
            &w1,
            "F-0002-bbbbbbbb",
            finding("H-A", Some("K3"), Some("bbbbbbbb")),
        );
        put_finding(&w1, "F-0003-dddddddd", finding("H-A", None, None));
        let workers = [report_for(0, w0.clone()), report_for(1, w1.clone())];
        let with_parent = [
            report_for(0, work.clone()),
            workers[0].clone(),
            workers[1].clone(),
        ];
        let unique_workers = unique_finding_count(&workers);
        let unique_with_parent = unique_finding_count(&with_parent);

        let merge = merge_worker_findings(&work, &[w0, w1]).unwrap();
        assert_eq!(merge.merged.len(), 3, "{merge:?}");
        assert_eq!(merge.duplicates, 3, "{merge:?}");
        assert_eq!(unique_with_parent, 1 + merge.merged.len());
        assert_eq!(
            unique_workers,
            merge.merged.len() + 1,
            "the workers' own count also holds the parent's K1"
        );
    }

    #[test]
    fn sanitizer_parse_accepts_known_aliases() {
        assert_eq!(Sanitizer::parse("asan"), Some(Sanitizer::Asan));
        assert_eq!(Sanitizer::parse("Address"), Some(Sanitizer::Asan));
        assert_eq!(Sanitizer::parse("msan"), Some(Sanitizer::Msan));
        assert_eq!(Sanitizer::parse("memory"), Some(Sanitizer::Msan));
        assert_eq!(Sanitizer::parse("ubsan"), Some(Sanitizer::Ubsan));
        assert_eq!(Sanitizer::parse("tsan"), Some(Sanitizer::Tsan));
        assert_eq!(Sanitizer::parse("lsan"), Some(Sanitizer::Lsan));
        assert_eq!(Sanitizer::parse("garbage"), None);
    }

    #[test]
    fn sanitizer_selection_default_is_passthrough() {
        let sel = SanitizerSelection::default();
        assert_eq!(sel, SanitizerSelection::Default);
        assert!(sel.runtime_set().is_empty());
        assert!(!sel.overrides_build());
    }

    #[test]
    fn sanitizer_selection_none_overrides_build_but_arms_no_env() {
        let sel = SanitizerSelection::None;
        assert!(sel.runtime_set().is_empty());
        assert!(sel.overrides_build());
    }

    #[test]
    fn sanitizer_selection_set_exposes_runtime_set() {
        let sel = SanitizerSelection::Set(vec![Sanitizer::Asan, Sanitizer::Lsan]);
        assert_eq!(sel.runtime_set(), &[Sanitizer::Asan, Sanitizer::Lsan]);
        assert!(sel.overrides_build());
    }

    #[test]
    fn merge_sanitizer_options_without_inherited_is_just_required() {
        assert_eq!(
            merge_sanitizer_options(None, "abort_on_error=1"),
            "abort_on_error=1"
        );
        assert_eq!(
            merge_sanitizer_options(Some("   "), "abort_on_error=1"),
            "abort_on_error=1"
        );
    }

    #[test]
    fn merge_sanitizer_options_preserves_operator_keys_and_required_wins() {
        // Operator's FP-killers / suppressions survive; bhf's required keys
        // come LAST so they override any operator attempt to disable them (#435).
        let merged = merge_sanitizer_options(
            Some("verify_asan_link_order=0:abort_on_error=0:suppressions=/x.supp"),
            "abort_on_error=1:halt_on_error=1:detect_leaks=1",
        );
        assert_eq!(
            merged,
            "verify_asan_link_order=0:abort_on_error=0:suppressions=/x.supp:\
             abort_on_error=1:halt_on_error=1:detect_leaks=1"
        );
        // The required override is the LAST abort_on_error occurrence (ASan: last wins).
        assert!(
            merged.rfind("abort_on_error=1").unwrap() > merged.rfind("abort_on_error=0").unwrap()
        );
    }

    #[test]
    fn sanitizer_envs_one_entry_per_sanitizer() {
        let envs = sanitizer_envs(&[Sanitizer::Asan, Sanitizer::Msan, Sanitizer::Ubsan]);
        assert_eq!(envs.len(), 3);
        assert_eq!(envs[0][0].0, "ASAN_OPTIONS");
        assert_eq!(envs[1][0].0, "MSAN_OPTIONS");
        assert_eq!(envs[2][0].0, "UBSAN_OPTIONS");
        for env in &envs {
            assert!(env[0].1.contains("abort_on_error=1"));
        }
    }

    #[test]
    fn ubsan_envs_print_stack_traces_and_check_names() {
        let envs = sanitizer_envs(&[Sanitizer::Asan, Sanitizer::Ubsan]);
        let ubsan = &envs[1][0].1;
        for key in [
            "print_stacktrace=1",
            "report_error_type=1",
            "halt_on_error=1",
        ] {
            assert!(ubsan.contains(key), "UBSAN_OPTIONS lacks {key}: {ubsan}");
        }
        assert!(
            !envs[0][0].1.contains("print_stacktrace"),
            "a UBSan flag stays out of ASAN_OPTIONS: {}",
            envs[0][0].1
        );
    }

    #[test]
    fn run_multicore_two_workers_with_bin_true_yields_two_started_workers() {
        // /bin/true exits 0 immediately; we just want to verify
        // orchestration scaffolding spawns + reaps the right number.
        let work = tempdir("true-bin");
        let build = work.join("build").join("H-TEST");
        std::fs::create_dir_all(&build).unwrap();
        let config = MulticoreConfig {
            work_dir: work,
            harness_id: "H-TEST".to_owned(),
            workers: WorkerCount::Fixed(2),
            per_worker_iterations: Some(0),
            time_budget: Duration::from_secs(0),
            bhf_bin: PathBuf::from("/bin/true"),
            per_worker_env: Vec::new(),
            extra_worker_args: Vec::new(),
            kill_grace: None,
            harness_dirs: Vec::new(),
            harness_executable: None,
        };
        let summary = run_multicore(&config).expect("run ok");
        assert_eq!(summary.workers_started, 2);
        assert_eq!(summary.workers_completed, 2);
    }

    #[cfg(unix)]
    #[test]
    fn run_multicore_syncs_worker_corpus_and_writes_manifest() {
        use std::os::unix::fs::PermissionsExt;

        let work = tempdir("sync-manifest");
        let build = work.join("build").join("H-SYNC");
        let shared_queue = work.join("corpus").join("H-SYNC").join("queue");
        std::fs::create_dir_all(&build).unwrap();
        std::fs::create_dir_all(&shared_queue).unwrap();
        std::fs::write(shared_queue.join("seed.bin"), b"seed").unwrap();

        let script = work.join("fake-bhf.sh");
        std::fs::write(
            &script,
            r#"#!/bin/sh
set -eu
worker_dir="$2"
harness=""
while [ $# -gt 0 ]; do
  case "$1" in
    --harness) harness="$2"; shift 2 ;;
    *) shift ;;
  esac
done
test -f "$BHF_SHARED_CORPUS_DIR/seed.bin"
mkdir -p "$worker_dir/corpus/$harness/queue"
printf "worker-%s" "$BHF_WORKER_ID" > "$worker_dir/corpus/$harness/queue/worker-$BHF_WORKER_ID.bin"
"#,
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let config = MulticoreConfig {
            work_dir: work.clone(),
            harness_id: "H-SYNC".to_owned(),
            workers: WorkerCount::Fixed(2),
            per_worker_iterations: Some(1),
            time_budget: Duration::ZERO,
            bhf_bin: script,
            per_worker_env: sanitizer_envs(&[Sanitizer::Asan, Sanitizer::Ubsan]),
            extra_worker_args: Vec::new(),
            kill_grace: None,
            harness_dirs: Vec::new(),
            harness_executable: None,
        };

        let summary = run_multicore(&config).expect("run ok");

        assert_eq!(summary.workers_started, 2);
        assert_eq!(summary.workers_completed, 2);
        assert_eq!(summary.sync.seed_inputs_loaded, 1);
        assert_eq!(summary.sync.imported_inputs, 2);
        assert!(summary.sync_manifest_path.is_file());
        assert_eq!(
            std::fs::read(shared_queue.join("worker-0.bin")).unwrap(),
            b"worker-0"
        );
        assert_eq!(
            std::fs::read(shared_queue.join("worker-1.bin")).unwrap(),
            b"worker-1"
        );
        assert_eq!(summary.per_worker[0].env_keys, vec!["ASAN_OPTIONS"]);
        assert_eq!(summary.per_worker[1].env_keys, vec!["UBSAN_OPTIONS"]);

        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&summary.sync_manifest_path).unwrap()).unwrap();
        assert_eq!(manifest["harness_id"], "H-SYNC");
        assert_eq!(manifest["workers_started"], 2);
        assert_eq!(manifest["sync"]["imported_inputs"], 2);
    }

    #[cfg(unix)]
    fn executable_script(path: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_stale_empty_worker_build_dir_is_refreshed() {
        // A failed earlier campaign left the worker's build dir created but
        // empty. Reusing it as-is fails every later retry.
        let work = tempdir("stale-build");
        let build = work.join("build").join("H-STALE");
        std::fs::create_dir_all(&build).unwrap();
        executable_script(&build.join("main"), "#!/bin/sh\nexit 0\n");
        std::fs::create_dir_all(work.join("worker-H-STALE-0/build/H-STALE")).unwrap();
        let script = work.join("needs-harness.sh");
        executable_script(
            &script,
            "#!/bin/sh\ntest -x \"$2/build/H-STALE/main\" || exit 3\n",
        );
        let config = MulticoreConfig {
            work_dir: work.clone(),
            harness_id: "H-STALE".to_owned(),
            workers: WorkerCount::Fixed(1),
            per_worker_iterations: Some(1),
            time_budget: Duration::ZERO,
            bhf_bin: script,
            per_worker_env: Vec::new(),
            extra_worker_args: Vec::new(),
            kill_grace: None,
            harness_dirs: Vec::new(),
            harness_executable: None,
        };
        let summary = run_multicore(&config).expect("campaign runs");
        assert_eq!(
            summary.workers_completed, 1,
            "the stale worker dir must be refreshed: {:?}",
            summary.per_worker
        );
    }

    #[cfg(unix)]
    #[test]
    fn workers_get_the_harness_from_the_layout_dir_the_parent_resolved() {
        // `bhf auto` keeps the binary in `harnesses/<id>/`, not `build/<id>/`.
        let work = tempdir("auto-layout");
        let harness = work.join("harnesses").join("H-AUTO");
        std::fs::create_dir_all(&harness).unwrap();
        executable_script(&harness.join("main"), "#!/bin/sh\nexit 0\n");
        std::fs::write(harness.join("structured_seeds.json"), "[]").unwrap();
        let script = work.join("needs-harness.sh");
        executable_script(
            &script,
            "#!/bin/sh\ntest -x \"$2/harnesses/H-AUTO/main\" || exit 3\n",
        );
        let config = MulticoreConfig {
            work_dir: work.clone(),
            harness_id: "H-AUTO".to_owned(),
            workers: WorkerCount::Fixed(2),
            per_worker_iterations: Some(1),
            time_budget: Duration::ZERO,
            bhf_bin: script,
            per_worker_env: Vec::new(),
            extra_worker_args: Vec::new(),
            kill_grace: None,
            harness_dirs: vec![PathBuf::from("harnesses/H-AUTO")],
            harness_executable: Some(PathBuf::from("harnesses/H-AUTO/main")),
        };
        let summary = run_multicore(&config).expect("campaign runs");
        assert_eq!(summary.workers_completed, 2, "{:?}", summary.per_worker);
        for worker in &summary.per_worker {
            assert!(worker
                .work_dir
                .join("harnesses/H-AUTO/structured_seeds.json")
                .is_file());
            assert!(worker.stderr_tail.is_none(), "{worker:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_worker_copy_of_a_rebuilt_harness_is_replaced() {
        let work = tempdir("rebuilt");
        let harness = work.join("harnesses").join("H-REBUILT");
        std::fs::create_dir_all(&harness).unwrap();
        executable_script(&harness.join("main"), "#!/bin/sh\n# v1\nexit 0\n");
        let script = work.join("needs-v2.sh");
        executable_script(
            &script,
            "#!/bin/sh\ngrep -q v2 \"$2/harnesses/H-REBUILT/main\" || exit 3\n",
        );
        let config = MulticoreConfig {
            work_dir: work.clone(),
            harness_id: "H-REBUILT".to_owned(),
            workers: WorkerCount::Fixed(1),
            per_worker_iterations: Some(1),
            time_budget: Duration::ZERO,
            bhf_bin: script,
            per_worker_env: Vec::new(),
            extra_worker_args: Vec::new(),
            kill_grace: None,
            harness_dirs: vec![PathBuf::from("harnesses/H-REBUILT")],
            harness_executable: Some(PathBuf::from("harnesses/H-REBUILT/main")),
        };
        assert_eq!(run_multicore(&config).unwrap().workers_completed, 0);
        executable_script(&harness.join("main"), "#!/bin/sh\n# v2 rebuilt\nexit 0\n");
        assert_eq!(run_multicore(&config).unwrap().workers_completed, 1);
    }

    /// A stand-in worker that resolves `main` the way `bhf fuzz` does (the
    /// `build/<id>/` copy first, then `harnesses/<id>/`) and runs it, writing its
    /// stdout to `ran.txt` in the worker tree.
    #[cfg(unix)]
    fn lookup_worker(work: &Path, id: &str) -> PathBuf {
        let script = work.join("lookup-worker.sh");
        executable_script(
            &script,
            &format!(
                "#!/bin/sh\nfor exe in \"$2/build/{id}/main\" \"$2/harnesses/{id}/main\"; do\n  \
                 if [ -x \"$exe\" ]; then \"$exe\" > \"$2/ran.txt\"; exit $?; fi\ndone\nexit 3\n"
            ),
        );
        script
    }

    #[cfg(unix)]
    fn moved_harness_config(work: &Path, id: &str, executable: &str) -> MulticoreConfig {
        MulticoreConfig {
            work_dir: work.to_path_buf(),
            harness_id: id.to_owned(),
            workers: WorkerCount::Fixed(2),
            per_worker_iterations: Some(1),
            time_budget: Duration::ZERO,
            bhf_bin: lookup_worker(work, id),
            per_worker_env: Vec::new(),
            extra_worker_args: Vec::new(),
            kill_grace: None,
            harness_dirs: vec![
                Path::new("build").join(id),
                Path::new("harnesses").join(id),
                Path::new("auto").join(id),
                Path::new("generated_harnesses").join(id),
            ],
            harness_executable: Some(PathBuf::from(executable)),
        }
    }

    #[cfg(unix)]
    fn ran(summary: &MulticoreSummary) -> Vec<String> {
        summary
            .per_worker
            .iter()
            .map(|worker| {
                std::fs::read_to_string(worker.work_dir.join("ran.txt"))
                    .unwrap_or_default()
                    .trim()
                    .to_owned()
            })
            .collect()
    }

    #[cfg(unix)]
    #[test]
    fn a_worker_copy_of_a_harness_dir_the_parent_no_longer_has_is_removed() {
        // Campaign 1 ran `build/<id>/main`. The parent's build dir is then
        // removed and the harness lives in `harnesses/<id>/`: the workers'
        // copies of the old build dir must not win their lookup.
        let work = tempdir("moved-harness");
        let id = "H-MOVED";
        let build = work.join("build").join(id);
        std::fs::create_dir_all(&build).unwrap();
        executable_script(&build.join("main"), "#!/bin/sh\necho old-build\n");
        std::fs::write(build.join("main.c"), "// old\n").unwrap();
        let first = run_multicore(&moved_harness_config(&work, id, "build/H-MOVED/main")).unwrap();
        assert_eq!(ran(&first), ["old-build", "old-build"]);

        std::fs::remove_dir_all(&build).unwrap();
        let harness = work.join("harnesses").join(id);
        std::fs::create_dir_all(&harness).unwrap();
        executable_script(&harness.join("main"), "#!/bin/sh\necho current\n");
        let second =
            run_multicore(&moved_harness_config(&work, id, "harnesses/H-MOVED/main")).unwrap();
        assert_eq!(second.workers_completed, 2, "{:?}", second.per_worker);
        assert_eq!(ran(&second), ["current", "current"]);
        for worker in &second.per_worker {
            assert!(
                !worker.work_dir.join("build").join(id).exists(),
                "{worker:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_worker_copy_that_still_holds_an_executable_the_parent_dropped_is_replaced() {
        // The parent's build dir stays (not empty) but loses `main`; the
        // harness the parent resolves is now `harnesses/<id>/main`.
        let work = tempdir("dropped-exe");
        let id = "H-DROPPED";
        let build = work.join("build").join(id);
        std::fs::create_dir_all(&build).unwrap();
        executable_script(&build.join("main"), "#!/bin/sh\necho old-build\n");
        std::fs::write(build.join("main.c"), "// kept\n").unwrap();
        let first =
            run_multicore(&moved_harness_config(&work, id, "build/H-DROPPED/main")).unwrap();
        assert_eq!(ran(&first), ["old-build", "old-build"]);

        std::fs::remove_file(build.join("main")).unwrap();
        let harness = work.join("harnesses").join(id);
        std::fs::create_dir_all(&harness).unwrap();
        executable_script(&harness.join("main"), "#!/bin/sh\necho current\n");
        let second =
            run_multicore(&moved_harness_config(&work, id, "harnesses/H-DROPPED/main")).unwrap();
        assert_eq!(ran(&second), ["current", "current"]);
        for worker in &second.per_worker {
            let copy = worker.work_dir.join("build").join(id);
            assert!(copy.join("main.c").is_file(), "{worker:?}");
            assert!(!copy.join("main").exists(), "{worker:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_harness_executable_reaches_the_worker_as_a_file() {
        let work = tempdir("symlinked-exe");
        let id = "H-LINK";
        let build = work.join("build").join(id);
        std::fs::create_dir_all(&build).unwrap();
        let real = work.join("main.real");
        executable_script(&real, "#!/bin/sh\necho linked\n");
        std::os::unix::fs::symlink(&real, build.join("main")).unwrap();
        let summary = run_multicore(&moved_harness_config(&work, id, "build/H-LINK/main")).unwrap();
        assert_eq!(ran(&summary), ["linked", "linked"]);
    }

    #[test]
    fn a_harness_dir_outside_the_work_dir_is_refused() {
        let work = tempdir("escape");
        let config = MulticoreConfig {
            work_dir: work.clone(),
            harness_id: "H-ESC".to_owned(),
            workers: WorkerCount::Fixed(1),
            per_worker_iterations: Some(1),
            time_budget: Duration::ZERO,
            bhf_bin: std::env::current_exe().unwrap(),
            per_worker_env: Vec::new(),
            extra_worker_args: Vec::new(),
            kill_grace: None,
            harness_dirs: vec![PathBuf::from("build/../../outside")],
            harness_executable: None,
        };
        let error = run_multicore(&config).unwrap_err();
        assert!(
            matches!(error, MulticoreError::UnsafeHarnessDir { .. }),
            "{error}"
        );
    }

    #[test]
    fn a_mirrored_tree_matches_its_source_until_either_side_changes() {
        let work = tempdir("tree-match");
        let src = work.join("src");
        std::fs::create_dir_all(src.join("obj")).unwrap();
        std::fs::write(src.join("main"), b"binary v1").unwrap();
        std::fs::write(src.join("obj").join("unit.o"), b"object").unwrap();
        let dst = work.join("dst");
        copy_dir_recursive(&src, &dst).unwrap();
        assert!(trees_match(&src, &dst).unwrap(), "a fresh copy matches");

        std::fs::write(dst.join("extra"), b"left by a worker").unwrap();
        assert!(!trees_match(&src, &dst).unwrap(), "an extra file differs");
        std::fs::remove_file(dst.join("extra")).unwrap();
        assert!(trees_match(&src, &dst).unwrap());

        // Same size, rewritten later: the timestamp differs.
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(src.join("main"), b"binary v2").unwrap();
        assert!(!trees_match(&src, &dst).unwrap(), "a rebuilt file differs");
    }

    #[cfg(unix)]
    #[test]
    fn a_campaign_starts_without_duplicates_of_removed_findings_and_counts_new_ones() {
        let work = tempdir("orphaned-duplicates");
        let id = "H-ORPHAN";
        let build = work.join("build").join(id);
        std::fs::create_dir_all(&build).unwrap();
        executable_script(&build.join("main"), "#!/bin/sh\nexit 0\n");
        let crash = |finding_id: &str, cluster: &str| {
            serde_json::json!({
                "id": finding_id,
                "signature": format!("{cluster}{cluster}"),
                "harness_id": id,
                "cluster_key_full": cluster,
            })
        };
        let w0 = work.join(format!("worker-{id}-0"));
        let w1 = work.join(format!("worker-{id}-1"));
        // Worker 0 holds a duplicate of a parent finding that was removed since;
        // worker 1 one of a parent finding that is still there.
        put_finding(&w0, "F-0000-orphaned", crash("F-0000-orphaned", "aaaa"));
        put_finding(&w1, "F-0000-heldcopy", crash("F-0000-heldcopy", "bbbb"));
        put_finding(&work, "F-0000-original", crash("F-0000-original", "bbbb"));
        for (worker, name) in [(&w0, "F-0000-orphaned"), (&w1, "F-0000-heldcopy")] {
            let dir = corpus::layout::finding_dir(worker, name);
            std::fs::write(dir.join(merge::DUPLICATE_MARKER), b"").unwrap();
        }
        // Each worker records one crash; worker 0 fails if the orphan is there.
        let script = work.join("records-one.sh");
        executable_script(
            &script,
            "#!/bin/sh\ntest -e \"$2/results/findings/F-0000-orphaned\" && exit 3\n\
             mkdir -p \"$2/results/findings/F-0001-fresh$BHF_WORKER_ID\"\nexit 0\n",
        );
        let config = MulticoreConfig {
            work_dir: work.clone(),
            harness_id: id.to_owned(),
            workers: WorkerCount::Fixed(2),
            per_worker_iterations: Some(1),
            time_budget: Duration::ZERO,
            bhf_bin: script,
            per_worker_env: Vec::new(),
            extra_worker_args: Vec::new(),
            kill_grace: None,
            harness_dirs: Vec::new(),
            harness_executable: None,
        };
        let summary = run_multicore(&config).unwrap();
        assert_eq!(summary.workers_completed, 2, "{:?}", summary.per_worker);
        assert_eq!(summary.dropped_duplicates, 1);
        let counts: Vec<(usize, usize)> = summary
            .per_worker
            .iter()
            .map(|worker| (worker.findings_count, worker.new_findings))
            .collect();
        assert_eq!(counts, [(1, 1), (2, 1)], "the held duplicate is not new");
    }

    #[cfg(unix)]
    #[test]
    fn a_failing_worker_reports_the_tail_of_its_stderr() {
        let work = tempdir("stderr-tail");
        let script = work.join("fails.sh");
        executable_script(
            &script,
            "#!/bin/sh\ni=0\nwhile [ $i -lt 50 ]; do echo \"noise $i\" >&2; i=$((i+1)); done\n\
             echo 'work dir malformed: no built harness executable found' >&2\nexit 3\n",
        );
        let config = MulticoreConfig {
            work_dir: work.clone(),
            harness_id: "H-FAIL".to_owned(),
            workers: WorkerCount::Fixed(1),
            per_worker_iterations: Some(1),
            time_budget: Duration::ZERO,
            bhf_bin: script,
            per_worker_env: Vec::new(),
            extra_worker_args: Vec::new(),
            kill_grace: None,
            harness_dirs: Vec::new(),
            harness_executable: None,
        };
        let summary = run_multicore(&config).expect("campaign runs");
        assert_eq!(summary.workers_completed, 0);
        let worker = &summary.per_worker[0];
        assert_eq!(worker.exit_code, Some(3));
        assert!(!worker.completed());
        let tail = worker.stderr_tail.as_deref().expect("stderr tail");
        assert!(
            tail.ends_with("work dir malformed: no built harness executable found"),
            "{tail}"
        );
        assert!(!tail.contains("noise 0\n"), "only the tail is kept: {tail}");
        assert_eq!(tail.lines().count(), STDERR_TAIL_LINES);
        assert!(worker.stderr_log.as_deref().is_some_and(Path::is_file));
    }

    #[cfg(unix)]
    #[test]
    fn a_worker_writing_lots_of_stderr_is_not_blocked() {
        // Worker stderr used to be an undrained pipe: a worker that wrote more
        // than the pipe buffer blocked until the deadline killed it.
        let work = tempdir("stderr-flood");
        let script = work.join("chatty.sh");
        executable_script(
            &script,
            "#!/bin/sh\ni=0\nwhile [ $i -lt 4000 ]; do\n  \
             echo 'bhf: progress line padded to roughly sixty-four bytes......' >&2\n  \
             i=$((i+1))\ndone\nexit 0\n",
        );
        let config = MulticoreConfig {
            work_dir: work.clone(),
            harness_id: "H-CHATTY".to_owned(),
            workers: WorkerCount::Fixed(1),
            per_worker_iterations: Some(1),
            time_budget: Duration::from_secs(2),
            bhf_bin: script,
            per_worker_env: Vec::new(),
            extra_worker_args: Vec::new(),
            kill_grace: Some(Duration::from_secs(2)),
            harness_dirs: Vec::new(),
            harness_executable: None,
        };
        let summary = run_multicore(&config).expect("campaign runs");
        assert_eq!(summary.workers_completed, 1, "{:?}", summary.per_worker);
    }

    #[cfg(unix)]
    #[test]
    fn run_multicore_kills_workers_after_time_budget_plus_grace() {
        use std::os::unix::fs::PermissionsExt;
        // A shell script that ignores its args and hangs forever.
        // We need this because /bin/sleep would error on our argv,
        // and /bin/true exits before the kill switch can trigger.
        let work = tempdir("hang");
        let build = work.join("build").join("H-HANG");
        std::fs::create_dir_all(&build).unwrap();
        let script = work.join("hang.sh");
        std::fs::write(&script, "#!/bin/sh\nexec sleep 300\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let config = MulticoreConfig {
            work_dir: work,
            harness_id: "H-HANG".to_owned(),
            workers: WorkerCount::Fixed(2),
            per_worker_iterations: None,
            time_budget: Duration::from_millis(200),
            bhf_bin: script,
            per_worker_env: Vec::new(),
            extra_worker_args: Vec::new(),
            kill_grace: Some(Duration::from_millis(300)),
            harness_dirs: Vec::new(),
            harness_executable: None,
        };

        let start = std::time::Instant::now();
        let summary = run_multicore(&config).expect("run ok");
        let elapsed = start.elapsed();

        assert_eq!(summary.workers_started, 2);
        assert_eq!(summary.workers_completed, 0); // killed, not exit 0
        assert!(
            summary.per_worker.iter().all(|r| r.exit_code.is_none()),
            "expected all workers killed (exit_code=None), got {:?}",
            summary.per_worker
        );
        assert!(
            summary.per_worker.iter().all(|r| r.stopped_at_deadline),
            "a worker stopped at the deadline says so: {:?}",
            summary.per_worker
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "orchestrator should have killed hanging workers within ~time_budget+grace, took {elapsed:?}"
        );
    }
}
