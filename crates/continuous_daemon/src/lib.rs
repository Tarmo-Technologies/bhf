// SPDX-License-Identifier: Apache-2.0

//! Continuous-fuzzing on-prem daemon.
//!
//! In-process scheduler that accepts fuzz-job submissions, queues
//! them, and dispatches them to a worker pool that spawns the
//! configured `bhf fuzz` command per job. Jobs are persisted
//! to `<data_dir>/jobs.jsonl` so a daemon restart can recover the
//! known job set (state is reset to Queued for jobs that were
//! Running at shutdown — in-flight work is assumed lost).
//!
//! Tracks issue #303. The HTTP/JSON-RPC front end + web UI from
//! the original issue body are deliberately out of scope for v0.1
//! — the focus here is the scheduler + job model the
//! `crates/daemon` JSON-RPC server (or any other front end) plugs
//! into via the `Scheduler::submit` / `Scheduler::list_jobs`
//! surface.

mod health;
mod storage_lock;

pub use health::{PersistencePhase, SchedulerHealth, StorageFault};

use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_JOB_WALL_GRACE: Duration = Duration::from_secs(30);
const MAX_WEBHOOK_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_CONCURRENT_WORKERS: u32 = 64;

/// Bounds on in-memory history, waiting work, and the persisted JSONL snapshot.
/// Completed jobs are retained; reaching the history cap requires an explicit
/// export/rotation operation rather than silently deleting audit history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulerLimits {
    pub max_jobs: usize,
    pub max_queued_jobs: usize,
    pub max_snapshot_bytes: usize,
    pub max_job_bytes: usize,
    pub max_list_page: usize,
}

impl Default for SchedulerLimits {
    fn default() -> Self {
        Self {
            max_jobs: 10_000,
            max_queued_jobs: 1_024,
            max_snapshot_bytes: 64 * 1024 * 1024,
            max_job_bytes: 64 * 1024,
            max_list_page: 1_000,
        }
    }
}

impl SchedulerLimits {
    fn valid(self) -> bool {
        self.max_jobs > 0
            && self.max_queued_jobs > 0
            && self.max_snapshot_bytes > 0
            && self.max_job_bytes > 0
            && self.max_list_page > 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzJob {
    pub job_id: String,
    pub project_dir: PathBuf,
    pub harness_id: String,
    pub time_budget_secs: u64,
    pub state: JobState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running,
    Complete,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonConfig {
    pub data_dir: PathBuf,
    pub max_concurrent_jobs: u32,
    pub bhf_bin: PathBuf,
    pub webhook_url: Option<String>,
    pub poll_interval: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("data dir does not exist: {0}")]
    DataDirMissing(PathBuf),
    #[error("scheduler data directory is already owned by another instance: {0}")]
    DataDirInUse(PathBuf),
    #[error("bhf binary not found: {0}")]
    BinMissing(PathBuf),
    #[error("scheduler already shut down")]
    Shutdown,
    #[error("job ID space exhausted")]
    IdExhausted,
    #[error("invalid job time budget: {0}")]
    InvalidBudget(String),
    #[error("invalid scheduler limits")]
    InvalidLimits,
    #[error("scheduler capacity exceeded: {0}")]
    Capacity(&'static str),
    #[error("invalid jobs snapshot {} at line {line}: {reason}", path.display())]
    CorruptJobs {
        path: PathBuf,
        line: usize,
        reason: String,
    },
    #[error("durability of job {job_id} is uncertain after replacing jobs snapshot: {source}; restart the scheduler before submitting again")]
    DurabilityUncertain {
        job_id: String,
        #[source]
        source: std::io::Error,
    },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Scheduler handle. Construction spawns a background worker
/// thread that drains the queue. Drop the scheduler to stop the
/// thread (Drop sends a shutdown signal and joins).
pub struct Scheduler {
    state: Arc<SharedState>,
    workers: Vec<JoinHandle<()>>,
    data_dir: PathBuf,
    job_wall_grace: Duration,
    limits: SchedulerLimits,
    // Retained until Drop has joined every worker. The pathname is never removed.
    _storage_lease: storage_lock::StorageLease,
}

struct SharedState {
    inner: Mutex<InnerState>,
    cv: Condvar,
}

struct InnerState {
    queue: VecDeque<FuzzJob>,
    seen: Vec<FuzzJob>,
    shutdown: bool,
    next_id: u64,
    snapshot_bytes_reserved: usize,
    storage_fault: Option<StorageFault>,
}

impl Scheduler {
    pub fn start(config: &DaemonConfig) -> Result<Self, DaemonError> {
        Self::start_with_shutdown_timeout(config, DEFAULT_SHUTDOWN_TIMEOUT)
    }

    /// Start a scheduler with a bound on waiting for an interrupted fuzz child
    /// to exit after its process tree is killed. The normal `start` path uses
    /// a two-second bound.
    pub fn start_with_shutdown_timeout(
        config: &DaemonConfig,
        shutdown_timeout: Duration,
    ) -> Result<Self, DaemonError> {
        Self::start_with_limits(config, shutdown_timeout, DEFAULT_JOB_WALL_GRACE)
    }

    /// As `start_with_shutdown_timeout`, with an explicit allowance beyond a
    /// positive job's requested fuzz time for build/setup and child cleanup.
    /// A zero job budget remains unlimited until shutdown.
    pub fn start_with_limits(
        config: &DaemonConfig,
        shutdown_timeout: Duration,
        job_wall_grace: Duration,
    ) -> Result<Self, DaemonError> {
        Self::start_with_resource_limits(
            config,
            shutdown_timeout,
            job_wall_grace,
            SchedulerLimits::default(),
        )
    }

    pub fn start_with_resource_limits(
        config: &DaemonConfig,
        shutdown_timeout: Duration,
        job_wall_grace: Duration,
        limits: SchedulerLimits,
    ) -> Result<Self, DaemonError> {
        if !limits.valid() {
            return Err(DaemonError::InvalidLimits);
        }
        if config.max_concurrent_jobs > MAX_CONCURRENT_WORKERS {
            return Err(DaemonError::Capacity("worker threads"));
        }
        if config.poll_interval.is_zero() {
            return Err(DaemonError::InvalidLimits);
        }
        if !config.data_dir.is_dir() {
            return Err(DaemonError::DataDirMissing(config.data_dir.clone()));
        }
        if !config.bhf_bin.is_file() {
            return Err(DaemonError::BinMissing(config.bhf_bin.clone()));
        }
        // Lock before inspecting/recovering history, not merely before writing it.
        let storage_lease = storage_lock::acquire(&config.data_dir)?;
        let state = Arc::new(SharedState {
            inner: Mutex::new(InnerState {
                queue: VecDeque::new(),
                seen: Vec::new(),
                shutdown: false,
                next_id: 0,
                snapshot_bytes_reserved: 0,
                storage_fault: None,
            }),
            cv: Condvar::new(),
        });

        // Restore from disk if the previous run persisted any jobs.
        let jobs_path = config.data_dir.join("jobs.jsonl");
        if let Some(snapshot) = storage_lock::open_snapshot(&jobs_path)? {
            let mut bytes = Vec::new();
            snapshot
                .take(limits.max_snapshot_bytes.saturating_add(1) as u64)
                .read_to_end(&mut bytes)?;
            if bytes.len() > limits.max_snapshot_bytes {
                return Err(DaemonError::Capacity("jobs snapshot bytes"));
            }
            let mut guard = state.inner.lock().unwrap_or_else(|p| p.into_inner());
            let mut seen_ids = HashSet::new();
            let line_count = bytes.split(|b| *b == b'\n').count();
            for (index, line) in bytes.split(|b| *b == b'\n').enumerate() {
                if line.is_empty() && index + 1 == line_count {
                    continue;
                }
                let line_number = index + 1;
                let corrupt = |reason: String| DaemonError::CorruptJobs {
                    path: jobs_path.clone(),
                    line: line_number,
                    reason,
                };
                if line.len() > limits.max_job_bytes {
                    return Err(DaemonError::Capacity("job record bytes"));
                }
                if guard.seen.len() >= limits.max_jobs {
                    return Err(DaemonError::Capacity("retained jobs"));
                }
                let mut job = serde_json::from_slice::<FuzzJob>(line)
                    .map_err(|error| corrupt(error.to_string()))?;
                let number = job
                    .job_id
                    .strip_prefix("J-")
                    .filter(|value| {
                        !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
                    })
                    .and_then(|value| value.parse::<u64>().ok())
                    .ok_or_else(|| corrupt(format!("invalid job ID {:?}", job.job_id)))?;
                if !seen_ids.insert(number) {
                    return Err(corrupt(format!(
                        "duplicate numeric job ID {:?}",
                        job.job_id
                    )));
                }
                guard.next_id = guard.next_id.max(number.checked_add(1).ok_or_else(|| {
                    corrupt(format!("job ID {:?} exhausts ID space", job.job_id))
                })?);
                validate_wall_budget(job.time_budget_secs, job_wall_grace)
                    .map_err(|error| corrupt(error.to_string()))?;
                if matches!(job.state, JobState::Running) {
                    job.state = JobState::Queued;
                }
                let needs_requeue = matches!(job.state, JobState::Queued);
                let reserved = reserved_job_bytes(&job)?;
                if reserved > limits.max_job_bytes
                    || guard.snapshot_bytes_reserved.saturating_add(reserved)
                        > limits.max_snapshot_bytes
                {
                    return Err(DaemonError::Capacity("jobs snapshot bytes"));
                }
                if needs_requeue && guard.queue.len() >= limits.max_queued_jobs {
                    return Err(DaemonError::Capacity("queued jobs"));
                }
                guard.snapshot_bytes_reserved += reserved;
                guard.seen.push(job.clone());
                if needs_requeue {
                    guard.queue.push_back(job);
                }
            }
        }

        let mut workers = Vec::new();
        for _ in 0..config.max_concurrent_jobs.max(1) {
            let state_ref = Arc::clone(&state);
            let data_dir = config.data_dir.clone();
            let bin = config.bhf_bin.clone();
            let poll = config.poll_interval;
            let webhook = config.webhook_url.clone();
            let worker = std::thread::Builder::new().spawn(move || {
                worker_loop(
                    state_ref,
                    data_dir,
                    bin,
                    poll,
                    webhook,
                    shutdown_timeout,
                    job_wall_grace,
                );
            });
            match worker {
                Ok(handle) => workers.push(handle),
                Err(error) => {
                    {
                        let mut guard = state.inner.lock().unwrap_or_else(|p| p.into_inner());
                        guard.shutdown = true;
                        state.cv.notify_all();
                    }
                    for handle in workers {
                        let _ = handle.join();
                    }
                    return Err(DaemonError::Io(error));
                }
            }
        }
        Ok(Self {
            state,
            workers,
            data_dir: config.data_dir.clone(),
            job_wall_grace,
            limits,
            _storage_lease: storage_lease,
        })
    }

    /// Queue a fuzz job. Returns the assigned job_id. The job will
    /// be picked up by a worker thread on the next poll cycle.
    pub fn submit(
        &self,
        project_dir: PathBuf,
        harness_id: String,
        time_budget: Duration,
    ) -> Result<String, DaemonError> {
        self.submit_with_persistence(project_dir, harness_id, time_budget, persist_jobs)
    }

    fn submit_with_persistence<F>(
        &self,
        project_dir: PathBuf,
        harness_id: String,
        time_budget: Duration,
        persist: F,
    ) -> Result<String, DaemonError>
    where
        F: FnOnce(&Path, &[FuzzJob]) -> Result<(), PersistFailure>,
    {
        let mut guard = self.state.inner.lock().unwrap_or_else(|p| p.into_inner());
        if guard.shutdown {
            return Err(DaemonError::Shutdown);
        }
        if guard.seen.len() >= self.limits.max_jobs {
            return Err(DaemonError::Capacity("retained jobs"));
        }
        if guard.queue.len() >= self.limits.max_queued_jobs {
            return Err(DaemonError::Capacity("queued jobs"));
        }
        if project_dir
            .as_os_str()
            .len()
            .saturating_add(harness_id.len())
            > self.limits.max_job_bytes
        {
            return Err(DaemonError::Capacity("job record bytes"));
        }
        let budget_secs = rounded_budget_secs(time_budget)?;
        validate_wall_budget(budget_secs, self.job_wall_grace)?;
        let next_id = guard
            .next_id
            .checked_add(1)
            .ok_or(DaemonError::IdExhausted)?;
        let job_id = format!("J-{:06}", guard.next_id);
        let job = FuzzJob {
            job_id: job_id.clone(),
            project_dir,
            harness_id,
            time_budget_secs: budget_secs,
            state: JobState::Queued,
        };
        let reserved = reserved_job_bytes(&job)?;
        if reserved > self.limits.max_job_bytes {
            return Err(DaemonError::Capacity("job record bytes"));
        }
        if guard.snapshot_bytes_reserved.saturating_add(reserved) > self.limits.max_snapshot_bytes {
            return Err(DaemonError::Capacity("jobs snapshot bytes"));
        }
        guard.seen.push(job.clone());
        if let Err(failure) = persist(&self.data_dir, &guard.seen) {
            health::latch_storage_fault(
                &self.state, &mut guard, PersistencePhase::Admission, &job_id, &failure,
            );
            if failure.installed {
                guard.next_id = next_id;
                guard.snapshot_bytes_reserved += reserved;
                return Err(DaemonError::DurabilityUncertain {
                    job_id,
                    source: failure.error,
                });
            }
            guard.seen.pop();
            return Err(DaemonError::Io(failure.error));
        }
        guard.next_id = next_id;
        guard.snapshot_bytes_reserved += reserved;
        guard.queue.push_back(job);
        self.state.cv.notify_one();
        Ok(job_id)
    }

    pub fn list_jobs(&self) -> Result<Vec<FuzzJob>, DaemonError> {
        let guard = self.state.inner.lock().unwrap_or_else(|p| p.into_inner());
        Ok(guard.seen.clone())
    }

    /// Return at most one configured page of retained jobs in submission order.
    pub fn list_jobs_page(&self, offset: usize, limit: usize) -> Result<Vec<FuzzJob>, DaemonError> {
        let guard = self.state.inner.lock().unwrap_or_else(|p| p.into_inner());
        Ok(guard
            .seen
            .iter()
            .skip(offset)
            .take(limit.min(self.limits.max_list_page))
            .cloned()
            .collect())
    }
}

fn reserved_job_bytes(job: &FuzzJob) -> Result<usize, DaemonError> {
    let mut worst = job.clone();
    worst.state = JobState::Complete;
    Ok(serde_json::to_vec(&worst)?.len().saturating_add(1))
}

impl Drop for Scheduler {
    fn drop(&mut self) {
        self.request_shutdown();
        for handle in self.workers.drain(..) {
            let _ = handle.join();
        }
    }
}

fn worker_loop(
    state: Arc<SharedState>,
    data_dir: PathBuf,
    bin: PathBuf,
    poll: Duration,
    webhook: Option<String>,
    shutdown_timeout: Duration,
    job_wall_grace: Duration,
) {
    loop {
        let job = {
            let mut guard = state.inner.lock().unwrap_or_else(|p| p.into_inner());
            loop {
                if guard.shutdown {
                    return;
                }
                if !guard.queue.is_empty() {
                    // Persist Running while holding the state mutex. No worker may
                    // dispatch an uncommitted transition or race its publication.
                    match health::claim_job(&data_dir, &state, &mut guard, persist_jobs) {
                        Some(job) => break job,
                        None => return,
                    }
                }
                guard = match state.cv.wait_timeout(guard, poll) {
                    Ok((g, _)) => g,
                    Err(poisoned) => poisoned.into_inner().0,
                };
            }
        };
        let outcome = run_one_job(&bin, &job, &state, shutdown_timeout, job_wall_grace);
        let final_state = match outcome {
            JobOutcome::Finished(state) => state,
            JobOutcome::Interrupted => JobState::Queued,
        };
        if !health::finish_job(&data_dir, &state, &job.job_id, final_state, persist_jobs) {
            // Do not notify completion, dispatch again, or overwrite the first
            // uncertain snapshot after a storage fault. Recovery is explicit.
            return;
        }
        if matches!(outcome, JobOutcome::Interrupted) {
            return;
        }
        if state
            .inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .shutdown
        {
            return;
        }
        if let Some(url) = &webhook {
            let payload = serde_json::json!({
                "job_id": job.job_id,
                "harness_id": job.harness_id,
                "state": final_state,
            });
            let _ = post_webhook(url, &payload.to_string());
        }
    }
}

#[derive(Clone, Copy)]
enum JobOutcome {
    Finished(JobState),
    Interrupted,
}

fn rounded_budget_secs(budget: Duration) -> Result<u64, DaemonError> {
    budget
        .as_secs()
        .checked_add(u64::from(budget.subsec_nanos() > 0))
        .ok_or_else(|| DaemonError::InvalidBudget("seconds exceed u64 range".to_owned()))
}

fn validate_wall_budget(budget_secs: u64, grace: Duration) -> Result<(), DaemonError> {
    if budget_secs == 0 {
        return Ok(());
    }
    let wall = Duration::from_secs(budget_secs)
        .checked_add(grace)
        .ok_or_else(|| DaemonError::InvalidBudget("budget plus grace overflows".to_owned()))?;
    Instant::now()
        .checked_add(wall)
        .ok_or_else(|| DaemonError::InvalidBudget("monotonic deadline overflows".to_owned()))?;
    Ok(())
}

fn is_shutting_down(state: &SharedState) -> bool {
    state
        .inner
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .shutdown
}

fn run_one_job(
    bin: &Path,
    job: &FuzzJob,
    state: &SharedState,
    shutdown_timeout: Duration,
    job_wall_grace: Duration,
) -> JobOutcome {
    if is_shutting_down(state) {
        return JobOutcome::Interrupted;
    }
    let mut cmd = Command::new(bin);
    cmd.arg("fuzz")
        .arg(&job.project_dir)
        .arg("--harness")
        .arg(&job.harness_id);
    if job.time_budget_secs > 0 {
        cmd.arg("--time").arg(format!("{}s", job.time_budget_secs));
    }
    prepare_owned_child(&mut cmd);
    let Ok(mut child) = cmd.spawn() else {
        return JobOutcome::Finished(JobState::Failed);
    };
    let deadline = if job.time_budget_secs == 0 {
        None
    } else {
        Duration::from_secs(job.time_budget_secs)
            .checked_add(job_wall_grace)
            .and_then(|wall| Instant::now().checked_add(wall))
    };
    if job.time_budget_secs > 0 && deadline.is_none() {
        kill_owned_tree(&mut child, shutdown_timeout);
        reap_after_kill(&mut child, shutdown_timeout);
        return JobOutcome::Finished(JobState::Failed);
    }
    loop {
        if is_shutting_down(state) {
            kill_owned_tree(&mut child, shutdown_timeout);
            reap_after_kill(&mut child, shutdown_timeout);
            return JobOutcome::Interrupted;
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                // The direct child can exit while helpers it spawned remain.
                kill_owned_tree(&mut child, shutdown_timeout);
                return JobOutcome::Finished(if status.success() {
                    JobState::Complete
                } else {
                    JobState::Failed
                });
            }
            Ok(None) => {
                if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    eprintln!(
                        "fuzz job {} exceeded {}s plus {:?} wall grace",
                        job.job_id, job.time_budget_secs, job_wall_grace
                    );
                    kill_owned_tree(&mut child, shutdown_timeout);
                    reap_after_kill(&mut child, shutdown_timeout);
                    return if is_shutting_down(state) {
                        JobOutcome::Interrupted
                    } else {
                        JobOutcome::Finished(JobState::Failed)
                    };
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => {
                eprintln!("wait for fuzz job {}: {error}", job.job_id);
                kill_owned_tree(&mut child, shutdown_timeout);
                reap_after_kill(&mut child, shutdown_timeout);
                return JobOutcome::Finished(JobState::Failed);
            }
        }
    }
}

#[cfg(unix)]
fn prepare_owned_child(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(not(unix))]
fn prepare_owned_child(_command: &mut Command) {}

#[cfg(unix)]
fn kill_owned_tree(child: &mut Child, _timeout: Duration) {
    if let Ok(pid) = i32::try_from(child.id()) {
        unsafe { libc::kill(-pid, libc::SIGKILL) };
    }
    let _ = child.kill();
}

#[cfg(windows)]
fn kill_owned_tree(child: &mut Child, timeout: Duration) {
    use std::process::Stdio;
    if let Ok(mut killer) = Command::new("taskkill")
        .args(["/PID", &child.id().to_string(), "/T", "/F"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        let deadline = Instant::now() + timeout.min(Duration::from_secs(1));
        loop {
            match killer.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                _ => {
                    let _ = killer.kill();
                    let _ = killer.wait();
                    break;
                }
            }
        }
    }
    let _ = child.kill();
}

#[cfg(not(any(unix, windows)))]
fn kill_owned_tree(child: &mut Child, _timeout: Duration) {
    let _ = child.kill();
}

fn reap_after_kill(child: &mut Child, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                eprintln!(
                    "fuzz child {} did not exit within shutdown timeout",
                    child.id()
                );
                return;
            }
            Err(error) => {
                eprintln!("reap fuzz child {}: {error}", child.id());
                return;
            }
        }
    }
}

/// Best-effort webhook POST. Used by the scheduler to notify a
/// configured webhook URL of job state transitions. Returns
/// Ok(()) on 2xx, Err otherwise. The implementation is a hand-rolled
/// minimal HTTP/1.1 client to avoid pulling in a TLS+reqwest stack
/// — the v0.1 audience is on-prem (likely plain HTTP webhook to a
/// chatops bot or local notification proxy).
///
/// Socket work has a 10-second overall deadline and a 64 KiB response cap.
/// Synchronous DNS resolution happens before this deadline and remains an
/// unbounded platform operation for hostnames.
pub fn post_webhook(url: &str, payload: &str) -> Result<(), DaemonError> {
    post_webhook_with_timeout(url, payload, Duration::from_secs(10))
}

/// As [`post_webhook`] but with a caller-supplied overall socket deadline.
/// DNS resolution for a hostname is not covered by this deadline.
pub fn post_webhook_with_timeout(
    url: &str,
    payload: &str,
    timeout: Duration,
) -> Result<(), DaemonError> {
    let parsed = parse_http_url(url).ok_or_else(|| {
        DaemonError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid webhook url: {url}"),
        ))
    })?;
    if parsed.scheme != "http" {
        return Err(DaemonError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "only http:// webhooks are supported in v0.1; use a TLS-terminating proxy for https",
        )));
    }
    use std::io::{Read, Write};
    use std::net::ToSocketAddrs;
    let addrs: Vec<std::net::SocketAddr> = (parsed.host.as_str(), parsed.port)
        .to_socket_addrs()?
        .collect();
    let addr = addrs.first().ok_or_else(|| {
        DaemonError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("could not resolve {}:{}", parsed.host, parsed.port),
        ))
    })?;
    let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
        DaemonError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "webhook deadline overflows",
        ))
    })?;
    let mut stream = std::net::TcpStream::connect_timeout(addr, remaining_webhook_time(deadline)?)?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        parsed.path,
        parsed.host,
        payload.len(),
        payload
    );
    let mut request_bytes = request.as_bytes();
    while !request_bytes.is_empty() {
        stream.set_write_timeout(Some(remaining_webhook_time(deadline)?))?;
        let count = stream.write(request_bytes)?;
        if count == 0 {
            return Err(DaemonError::Io(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "webhook request write returned zero",
            )));
        }
        request_bytes = &request_bytes[count..];
    }
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        stream.set_read_timeout(Some(remaining_webhook_time(deadline)?))?;
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        if buf.len().saturating_add(count) > MAX_WEBHOOK_RESPONSE_BYTES {
            return Err(DaemonError::Capacity("webhook response bytes"));
        }
        buf.extend_from_slice(&chunk[..count]);
    }
    let status = parse_http_status(&buf)
        .ok_or_else(|| DaemonError::Io(std::io::Error::other("malformed webhook response")))?;
    if !(200..300).contains(&status) {
        return Err(DaemonError::Io(std::io::Error::other(format!(
            "webhook returned {status}"
        ))));
    }
    Ok(())
}

fn remaining_webhook_time(deadline: Instant) -> Result<Duration, DaemonError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(DaemonError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "webhook overall deadline exceeded",
        )));
    }
    Ok(remaining)
}

#[derive(Debug)]
struct ParsedUrl {
    scheme: String,
    host: String,
    port: u16,
    path: String,
}

fn parse_http_url(url: &str) -> Option<ParsedUrl> {
    let (scheme, rest) = url.split_once("://")?;
    let (host_port, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (h.to_owned(), p.parse().ok()?),
        None => (
            host_port.to_owned(),
            if scheme == "https" { 443u16 } else { 80u16 },
        ),
    };
    Some(ParsedUrl {
        scheme: scheme.to_owned(),
        host,
        port,
        path: path.to_owned(),
    })
}

fn parse_http_status(response: &[u8]) -> Option<u16> {
    let line = response.split(|b| *b == b'\n').next()?;
    let mut tokens = line.splitn(3, |b| *b == b' ');
    let _http = tokens.next()?;
    let status = std::str::from_utf8(tokens.next()?).ok()?;
    status.trim().parse().ok()
}

struct PersistFailure {
    error: std::io::Error,
    /// The new snapshot replaced the old one, but directory sync failed.
    installed: bool,
}

impl PersistFailure {
    fn before(error: std::io::Error) -> Self {
        Self {
            error,
            installed: false,
        }
    }

    fn after(error: std::io::Error) -> Self {
        Self {
            error,
            installed: true,
        }
    }
}

fn persist_jobs(data_dir: &Path, jobs: &[FuzzJob]) -> Result<(), PersistFailure> {
    persist_jobs_with_sync(data_dir, jobs, sync_parent_directory)
}

fn persist_jobs_with_sync<F>(
    data_dir: &Path,
    jobs: &[FuzzJob],
    sync_directory: F,
) -> Result<(), PersistFailure>
where
    F: FnOnce(&Path) -> std::io::Result<()>,
{
    let mut out = String::new();
    for job in jobs {
        let line = serde_json::to_string(job)
            .map_err(std::io::Error::other)
            .map_err(PersistFailure::before)?;
        out.push_str(&line);
        out.push('\n');
    }
    let mut temp = tempfile::NamedTempFile::new_in(data_dir).map_err(PersistFailure::before)?;
    temp.write_all(out.as_bytes())
        .map_err(PersistFailure::before)?;
    temp.as_file().sync_all().map_err(PersistFailure::before)?;
    temp.persist(data_dir.join("jobs.jsonl"))
        .map_err(|error| PersistFailure::before(error.error))?;
    sync_directory(data_dir).map_err(PersistFailure::after)?;
    Ok(())
}

#[cfg(unix)]
fn sync_parent_directory(data_dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(data_dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_directory(_data_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tempdir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("bhf-cd-{name}-{nonce}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn ok_config(dir: PathBuf, bin: PathBuf) -> DaemonConfig {
        DaemonConfig {
            data_dir: dir,
            max_concurrent_jobs: 2,
            bhf_bin: bin,
            webhook_url: None,
            poll_interval: Duration::from_millis(50),
        }
    }

    #[test]
    fn start_rejects_missing_data_dir() {
        let config = DaemonConfig {
            data_dir: PathBuf::from("/nonexistent"),
            max_concurrent_jobs: 1,
            bhf_bin: PathBuf::from("/bin/true"),
            webhook_url: None,
            poll_interval: Duration::from_millis(50),
        };
        assert!(matches!(
            Scheduler::start(&config),
            Err(DaemonError::DataDirMissing(_))
        ));
    }

    #[test]
    fn start_rejects_missing_bin() {
        let dir = tempdir("missing-bin");
        let config = DaemonConfig {
            data_dir: dir,
            max_concurrent_jobs: 1,
            bhf_bin: PathBuf::from("/nonexistent/bhf"),
            webhook_url: None,
            poll_interval: Duration::from_millis(50),
        };
        assert!(matches!(
            Scheduler::start(&config),
            Err(DaemonError::BinMissing(_))
        ));
    }

    #[test]
    fn start_rejects_excessive_worker_count_and_zero_poll_interval() {
        let dir = tempdir("worker-capacity");
        let mut config = ok_config(dir, PathBuf::from("/bin/true"));
        config.max_concurrent_jobs = MAX_CONCURRENT_WORKERS + 1;
        assert!(matches!(
            Scheduler::start(&config),
            Err(DaemonError::Capacity("worker threads"))
        ));
        config.max_concurrent_jobs = 1;
        config.poll_interval = Duration::ZERO;
        assert!(matches!(
            Scheduler::start(&config),
            Err(DaemonError::InvalidLimits)
        ));
    }

    #[test]
    fn submit_and_list_returns_queued_job() {
        let dir = tempdir("submit");
        let scheduler =
            Scheduler::start(&ok_config(dir.clone(), PathBuf::from("/bin/true"))).unwrap();
        let id = scheduler
            .submit(dir.clone(), "H".to_owned(), Duration::from_secs(0))
            .unwrap();
        assert!(id.starts_with("J-"));
        let jobs = scheduler.list_jobs().unwrap();
        assert!(jobs.iter().any(|j| j.job_id == id));
    }

    #[test]
    fn worker_runs_submitted_job_to_completion_against_bin_true() {
        let dir = tempdir("run-complete");
        let scheduler =
            Scheduler::start(&ok_config(dir.clone(), PathBuf::from("/bin/true"))).unwrap();
        let id = scheduler
            .submit(dir.clone(), "H".to_owned(), Duration::from_secs(0))
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            std::thread::sleep(Duration::from_millis(50));
            let jobs = scheduler.list_jobs().unwrap();
            let job = jobs.iter().find(|j| j.job_id == id).expect("job present");
            if matches!(job.state, JobState::Complete | JobState::Failed) {
                assert_eq!(job.state, JobState::Complete);
                break;
            }
            if std::time::Instant::now() > deadline {
                panic!("job did not finish within 3s: {job:?}");
            }
        }
    }

    #[test]
    fn worker_marks_failure_when_bin_exits_nonzero() {
        let dir = tempdir("run-fail");
        let scheduler =
            Scheduler::start(&ok_config(dir.clone(), PathBuf::from("/bin/false"))).unwrap();
        let id = scheduler
            .submit(dir.clone(), "H".to_owned(), Duration::from_secs(0))
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            std::thread::sleep(Duration::from_millis(50));
            let jobs = scheduler.list_jobs().unwrap();
            let job = jobs.iter().find(|j| j.job_id == id).expect("job present");
            if matches!(job.state, JobState::Complete | JobState::Failed) {
                assert_eq!(job.state, JobState::Failed);
                break;
            }
            if std::time::Instant::now() > deadline {
                panic!("job did not finish within 3s: {job:?}");
            }
        }
    }

    #[test]
    fn parse_http_url_handles_explicit_port() {
        let parsed = super::parse_http_url("http://localhost:9090/notify").unwrap();
        assert_eq!(parsed.scheme, "http");
        assert_eq!(parsed.host, "localhost");
        assert_eq!(parsed.port, 9090);
        assert_eq!(parsed.path, "/notify");
    }

    #[test]
    fn parse_http_url_defaults_port_80() {
        let parsed = super::parse_http_url("http://example.com/").unwrap();
        assert_eq!(parsed.port, 80);
        assert_eq!(parsed.path, "/");
    }

    #[test]
    fn parse_http_url_defaults_port_443_for_https() {
        let parsed = super::parse_http_url("https://example.com/x").unwrap();
        assert_eq!(parsed.port, 443);
    }

    #[test]
    fn parse_http_status_picks_status_code() {
        let response = b"HTTP/1.1 204 No Content\r\nFoo: bar\r\n\r\n";
        assert_eq!(super::parse_http_status(response), Some(204));
    }

    #[test]
    fn post_webhook_rejects_invalid_url() {
        let result = post_webhook("not-a-url", "{}");
        assert!(result.is_err());
    }

    #[test]
    fn post_webhook_rejects_https_v0_1() {
        let result = post_webhook("https://example.com/notify", "{}");
        assert!(result.is_err());
    }

    #[test]
    fn post_webhook_with_timeout_fires_on_silent_server() {
        // Bind a listener that accepts then never responds. The
        // webhook client should give up within ~timeout instead of
        // hanging the worker thread.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let _acceptor = std::thread::spawn(move || {
            // Accept one connection and immediately drop it from
            // this scope — but keep the stream alive in the closure's
            // local so it doesn't close, simulating a server that
            // never writes a response.
            let held: Vec<std::net::TcpStream> =
                listener.incoming().take(1).filter_map(Result::ok).collect();
            std::thread::sleep(std::time::Duration::from_secs(2));
            drop(held);
        });
        let url = format!("http://127.0.0.1:{port}/hook");
        let start = std::time::Instant::now();
        let result = post_webhook_with_timeout(&url, "{}", std::time::Duration::from_millis(250));
        let elapsed = start.elapsed();
        assert!(result.is_err(), "should error on silent server");
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "client should give up within ~timeout, took {elapsed:?}"
        );
    }

    #[test]
    fn webhook_deadline_stops_trickle_and_response_cap_stops_large_body() {
        use std::io::Write as _;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let trickler = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for byte in b"HTTP/1.1 200 OK\r\n\r\n".iter().cycle().take(100) {
                if stream.write_all(&[*byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let started = Instant::now();
        let result = post_webhook_with_timeout(
            &format!("http://127.0.0.1:{port}/hook"),
            "{}",
            Duration::from_millis(150),
        );
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        trickler.join().unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let sender = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let body = vec![b'x'; MAX_WEBHOOK_RESPONSE_BYTES + 1];
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n");
            let _ = stream.write_all(&body);
        });
        assert!(matches!(
            post_webhook_with_timeout(
                &format!("http://127.0.0.1:{port}/hook"),
                "{}",
                Duration::from_secs(1),
            ),
            Err(DaemonError::Capacity("webhook response bytes"))
        ));
        sender.join().unwrap();
    }

    #[test]
    fn webhook_small_success_response_is_accepted() {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let sender = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .unwrap();
        });
        post_webhook_with_timeout(
            &format!("http://127.0.0.1:{port}/hook"),
            "{}",
            Duration::from_secs(1),
        )
        .unwrap();
        sender.join().unwrap();
    }

    #[test]
    fn restart_recovers_queued_jobs_from_disk() {
        let dir = tempdir("restart");
        {
            let scheduler =
                Scheduler::start(&ok_config(dir.clone(), PathBuf::from("/bin/sleep"))).unwrap();
            scheduler
                .submit(dir.clone(), "H".to_owned(), Duration::from_secs(0))
                .unwrap();
            // Drop scheduler — workers may have started but with
            // /bin/sleep + no args sleep exits 1; we don't care
            // about completion here, only that disk persistence ran.
        }
        // Inspect the persisted file directly to confirm something
        // landed; a fresh scheduler should also see at least one job.
        let jobs_file = std::fs::read(dir.join("jobs.jsonl")).unwrap();
        assert!(!jobs_file.is_empty());
        let scheduler = Scheduler::start(&ok_config(dir, PathBuf::from("/bin/true"))).unwrap();
        let jobs = scheduler.list_jobs().unwrap();
        assert!(!jobs.is_empty());
    }

    #[test]
    fn restart_assigns_distinct_id_after_restored_job() {
        let dir = tempdir("restart-id");
        let old = FuzzJob {
            job_id: "J-000007".to_owned(),
            project_dir: dir.clone(),
            harness_id: "old".to_owned(),
            time_budget_secs: 0,
            state: JobState::Complete,
        };
        std::fs::write(
            dir.join("jobs.jsonl"),
            format!("{}\n", serde_json::to_string(&old).unwrap()),
        )
        .unwrap();
        let scheduler =
            Scheduler::start(&ok_config(dir.clone(), PathBuf::from("/bin/true"))).unwrap();
        let id = scheduler
            .submit(dir, "new".to_owned(), Duration::ZERO)
            .unwrap();
        assert_eq!(id, "J-000008");
        assert_eq!(scheduler.list_jobs().unwrap().len(), 2);
    }

    #[test]
    fn startup_rejects_corrupt_or_duplicate_snapshot_without_changing_it() {
        let old = FuzzJob {
            job_id: "J-000007".to_owned(),
            project_dir: PathBuf::from("/tmp/fixture"),
            harness_id: "H".to_owned(),
            time_budget_secs: 0,
            state: JobState::Complete,
        };
        let valid = serde_json::to_string(&old).unwrap();
        let alias = serde_json::to_string(&FuzzJob {
            job_id: "J-7".to_owned(),
            ..old.clone()
        })
        .unwrap();
        let invalid_id = serde_json::to_string(&FuzzJob {
            job_id: "J-not-a-number".to_owned(),
            ..old.clone()
        })
        .unwrap();
        let exhausted_id = serde_json::to_string(&FuzzJob {
            job_id: format!("J-{}", u64::MAX),
            ..old.clone()
        })
        .unwrap();
        let invalid_budget = serde_json::to_string(&FuzzJob {
            time_budget_secs: u64::MAX,
            ..old.clone()
        })
        .unwrap();
        let cases = [
            ("truncated", format!("{valid}\n{{\"job_id\":"), 2, "EOF"),
            ("middle-empty", format!("{valid}\n\n{valid}\n"), 2, "EOF"),
            ("duplicate", format!("{valid}\n{valid}\n"), 2, "duplicate"),
            (
                "numeric-alias",
                format!("{valid}\n{alias}\n"),
                2,
                "duplicate",
            ),
            ("invalid-id", format!("{invalid_id}\n"), 1, "invalid job ID"),
            (
                "id-overflow",
                format!("{exhausted_id}\n"),
                1,
                "exhausts ID space",
            ),
            (
                "budget-overflow",
                format!("{invalid_budget}\n"),
                1,
                "invalid job time budget",
            ),
        ];
        for (name, snapshot, line, reason) in cases {
            let dir = tempdir(name);
            let path = dir.join("jobs.jsonl");
            std::fs::write(&path, snapshot.as_bytes()).unwrap();
            let error = match Scheduler::start(&ok_config(dir, PathBuf::from("/bin/true"))) {
                Ok(_) => panic!("{name} snapshot unexpectedly accepted"),
                Err(error) => error,
            };
            assert!(matches!(error, DaemonError::CorruptJobs { .. }));
            let message = error.to_string();
            assert!(message.contains(&format!("line {line}")), "{message}");
            assert!(message.contains(reason), "{message}");
            assert_eq!(std::fs::read(path).unwrap(), snapshot.as_bytes());
        }
    }

    #[test]
    fn startup_accepts_legacy_unpadded_numeric_id() {
        let dir = tempdir("legacy-id");
        let old = FuzzJob {
            job_id: "J-7".to_owned(),
            project_dir: dir.clone(),
            harness_id: "H".to_owned(),
            time_budget_secs: 0,
            state: JobState::Complete,
        };
        std::fs::write(
            dir.join("jobs.jsonl"),
            format!("{}\n", serde_json::to_string(&old).unwrap()),
        )
        .unwrap();
        let scheduler =
            Scheduler::start(&ok_config(dir.clone(), PathBuf::from("/bin/true"))).unwrap();
        assert_eq!(
            scheduler
                .submit(dir, "next".to_owned(), Duration::ZERO)
                .unwrap(),
            "J-000008"
        );
    }

    #[test]
    fn submit_does_not_acknowledge_job_if_persistence_fails() {
        let dir = tempdir("persist-error");
        let scheduler =
            Scheduler::start(&ok_config(dir.clone(), PathBuf::from("/bin/true"))).unwrap();
        // Corrupt the destination after startup; startup now rejects non-files.
        std::fs::create_dir(dir.join("jobs.jsonl")).unwrap();
        assert!(matches!(
            scheduler.submit(dir, "new".to_owned(), Duration::ZERO),
            Err(DaemonError::Io(_))
        ));
        assert!(scheduler.list_jobs().unwrap().is_empty());
    }

    #[test]
    fn post_replace_sync_failure_preserves_id_and_stops_submissions() {
        let dir = tempdir("dir-sync-failure");
        let scheduler =
            Scheduler::start(&ok_config(dir.clone(), PathBuf::from("/bin/true"))).unwrap();
        let error = scheduler
            .submit_with_persistence(dir.clone(), "H".to_owned(), Duration::ZERO, |dir, jobs| {
                persist_jobs_with_sync(dir, jobs, |_| {
                    Err(std::io::Error::other(
                        "injected parent directory sync error",
                    ))
                })
            })
            .unwrap_err();
        assert!(matches!(error, DaemonError::DurabilityUncertain { .. }));
        assert!(error.to_string().contains("J-000000"));
        assert!(matches!(
            scheduler.submit(dir.clone(), "next".to_owned(), Duration::ZERO),
            Err(DaemonError::Shutdown)
        ));
        let jobs = scheduler.list_jobs().unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].job_id, "J-000000");
        assert_eq!(jobs[0].state, JobState::Queued);
        let saved: FuzzJob =
            serde_json::from_slice(std::fs::read(dir.join("jobs.jsonl")).unwrap().trim_ascii())
                .unwrap();
        assert_eq!(saved.job_id, "J-000000");
        drop(scheduler);
        let restarted =
            Scheduler::start(&ok_config(dir.clone(), PathBuf::from("/bin/true"))).unwrap();
        assert_eq!(
            restarted
                .submit(dir, "new".to_owned(), Duration::ZERO)
                .unwrap(),
            "J-000001"
        );
    }

    #[test]
    fn persistence_keeps_unrelated_temp_name_sentinel() {
        let dir = tempdir("persist-sentinel");
        let sentinel = dir.join(format!(".jobs.jsonl.{}.0.tmp", std::process::id()));
        std::fs::write(&sentinel, b"keep").unwrap();
        let scheduler =
            Scheduler::start(&ok_config(dir.clone(), PathBuf::from("/bin/true"))).unwrap();
        scheduler
            .submit(dir, "new".to_owned(), Duration::ZERO)
            .unwrap();
        assert_eq!(std::fs::read(sentinel).unwrap(), b"keep");
    }

    #[test]
    fn positive_subsecond_budget_rounds_up_and_overflow_is_rejected() {
        assert_eq!(rounded_budget_secs(Duration::from_millis(1)).unwrap(), 1);
        assert_eq!(rounded_budget_secs(Duration::ZERO).unwrap(), 0);
        assert!(matches!(
            rounded_budget_secs(Duration::new(u64::MAX, 1)),
            Err(DaemonError::InvalidBudget(_))
        ));
        assert!(matches!(
            validate_wall_budget(u64::MAX, Duration::from_secs(30)),
            Err(DaemonError::InvalidBudget(_))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ignored_child_time_budget_is_killed_and_persisted_failed() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir("wall-budget-tree");
        let pid_file = dir.join("grandchild.pid");
        let script = dir.join("ignore-time.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\ntrap '' TERM\nsleep 30 &\nprintf '%s' \"$!\" > '{}'\nwait\n",
                pid_file.display()
            ),
        )
        .unwrap();
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();

        let scheduler = Scheduler::start_with_limits(
            &ok_config(dir.clone(), script),
            Duration::from_secs(1),
            Duration::ZERO,
        )
        .unwrap();
        let id = scheduler
            .submit(dir.clone(), "H".to_owned(), Duration::from_millis(1))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(4);
        while !pid_file.is_file() {
            assert!(Instant::now() < deadline, "fuzz child did not start");
            std::thread::sleep(Duration::from_millis(10));
        }
        let grandchild_pid: u32 = std::fs::read_to_string(&pid_file).unwrap().parse().unwrap();
        loop {
            let job = scheduler
                .list_jobs()
                .unwrap()
                .into_iter()
                .find(|job| job.job_id == id)
                .unwrap();
            if job.state == JobState::Failed {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "job did not reach Failed: {job:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(scheduler);
        let saved: FuzzJob =
            serde_json::from_slice(std::fs::read(dir.join("jobs.jsonl")).unwrap().trim_ascii())
                .unwrap();
        assert_eq!(saved.state, JobState::Failed);
        assert_eq!(saved.time_budget_secs, 1);
        let grandchild_status = PathBuf::from(format!("/proc/{grandchild_pid}/stat"));
        let gone_deadline = Instant::now() + Duration::from_secs(1);
        while grandchild_status.is_file() {
            let status = std::fs::read_to_string(&grandchild_status).unwrap();
            if status.split_whitespace().nth(2) == Some("Z") {
                break;
            }
            assert!(
                Instant::now() < gone_deadline,
                "grandchild remained running"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shutdown_kills_owned_process_tree_and_requeues_job_for_restart() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir("shutdown-tree");
        let pid_file = dir.join("grandchild.pid");
        let script = dir.join("ignore-time.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\ntrap '' TERM\nsleep 30 &\nprintf '%s' \"$!\" > '{}'\nwait\n",
                pid_file.display()
            ),
        )
        .unwrap();
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();

        let scheduler = Scheduler::start_with_shutdown_timeout(
            &ok_config(dir.clone(), script),
            Duration::from_secs(1),
        )
        .unwrap();
        let id = scheduler
            .submit(dir.clone(), "H".to_owned(), Duration::from_secs(1))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while !pid_file.is_file() {
            assert!(Instant::now() < deadline, "fuzz child did not start");
            std::thread::sleep(Duration::from_millis(10));
        }
        let grandchild_pid: u32 = std::fs::read_to_string(&pid_file).unwrap().parse().unwrap();

        let started = Instant::now();
        drop(scheduler);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "scheduler shutdown hung"
        );
        let saved: FuzzJob =
            serde_json::from_slice(std::fs::read(dir.join("jobs.jsonl")).unwrap().trim_ascii())
                .unwrap();
        assert_eq!(saved.job_id, id);
        assert_eq!(saved.state, JobState::Queued);

        let grandchild_status = PathBuf::from(format!("/proc/{grandchild_pid}/stat"));
        let deadline = Instant::now() + Duration::from_secs(1);
        while grandchild_status.is_file() {
            let status = std::fs::read_to_string(&grandchild_status).unwrap();
            if status.split_whitespace().nth(2) == Some("Z") {
                break;
            }
            assert!(Instant::now() < deadline, "grandchild remained running");
            std::thread::sleep(Duration::from_millis(10));
        }

        let restarted =
            Scheduler::start(&ok_config(dir.clone(), PathBuf::from("/bin/true"))).unwrap();
        let next = restarted
            .submit(dir, "H-new".to_owned(), Duration::ZERO)
            .unwrap();
        assert_eq!(next, "J-000001");
    }

    #[test]
    fn retained_capacity_rejects_without_changing_acknowledged_snapshot() {
        let dir = tempdir("capacity-retained");
        let limits = SchedulerLimits {
            max_jobs: 1,
            max_list_page: 1,
            ..SchedulerLimits::default()
        };
        let scheduler = Scheduler::start_with_resource_limits(
            &ok_config(dir.clone(), PathBuf::from("/bin/true")),
            Duration::from_secs(1),
            DEFAULT_JOB_WALL_GRACE,
            limits,
        )
        .unwrap();
        assert_eq!(
            scheduler
                .submit(dir.clone(), "H".into(), Duration::ZERO)
                .unwrap(),
            "J-000000"
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while !std::fs::read_to_string(dir.join("jobs.jsonl"))
            .unwrap()
            .contains("\"complete\"")
        {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        let before = std::fs::read(dir.join("jobs.jsonl")).unwrap();
        assert!(matches!(
            scheduler.submit(dir.clone(), "H2".into(), Duration::ZERO),
            Err(DaemonError::Capacity("retained jobs"))
        ));
        assert_eq!(std::fs::read(dir.join("jobs.jsonl")).unwrap(), before);
        assert_eq!(scheduler.list_jobs_page(0, usize::MAX).unwrap().len(), 1);
        assert!(scheduler.list_jobs_page(1, usize::MAX).unwrap().is_empty());
    }

    #[test]
    fn startup_enforces_byte_record_and_job_caps_without_rewriting_input() {
        let dir = tempdir("capacity-recovery");
        let config = ok_config(dir.clone(), PathBuf::from("/bin/true"));
        let path = dir.join("jobs.jsonl");
        let job = FuzzJob {
            job_id: "J-000000".into(),
            project_dir: dir.clone(),
            harness_id: "H".into(),
            time_budget_secs: 0,
            state: JobState::Complete,
        };
        let line = format!("{}\n", serde_json::to_string(&job).unwrap());
        std::fs::write(&path, line.as_bytes()).unwrap();
        for limits in [
            SchedulerLimits {
                max_snapshot_bytes: line.len() - 1,
                ..SchedulerLimits::default()
            },
            SchedulerLimits {
                max_job_bytes: line.len() - 2,
                ..SchedulerLimits::default()
            },
        ] {
            assert!(matches!(
                Scheduler::start_with_resource_limits(
                    &config,
                    Duration::from_secs(1),
                    DEFAULT_JOB_WALL_GRACE,
                    limits,
                ),
                Err(DaemonError::Capacity(_))
            ));
            assert_eq!(std::fs::read(&path).unwrap(), line.as_bytes());
        }
        std::fs::write(&path, format!("{line}{line}")).unwrap();
        let limits = SchedulerLimits {
            max_jobs: 1,
            ..SchedulerLimits::default()
        };
        assert!(matches!(
            Scheduler::start_with_resource_limits(
                &config,
                Duration::from_secs(1),
                DEFAULT_JOB_WALL_GRACE,
                limits,
            ),
            Err(DaemonError::CorruptJobs { .. }) | Err(DaemonError::Capacity(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn queued_capacity_rejects_before_id_or_snapshot_change() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir("capacity-queue");
        let entered = dir.join("entered");
        let release = dir.join("release");
        let script = dir.join("wait.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\ntouch '{}'\nwhile [ ! -e '{}' ]; do sleep 0.01; done\n",
                entered.display(),
                release.display()
            ),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();
        let limits = SchedulerLimits {
            max_queued_jobs: 1,
            ..SchedulerLimits::default()
        };
        let mut config = ok_config(dir.clone(), script);
        config.max_concurrent_jobs = 1;
        let scheduler = Scheduler::start_with_resource_limits(
            &config,
            Duration::from_secs(1),
            DEFAULT_JOB_WALL_GRACE,
            limits,
        )
        .unwrap();
        scheduler
            .submit(dir.clone(), "first".into(), Duration::ZERO)
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !entered.exists() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            scheduler
                .submit(dir.clone(), "waiting".into(), Duration::ZERO)
                .unwrap(),
            "J-000001"
        );
        let before = std::fs::read(dir.join("jobs.jsonl")).unwrap();
        assert!(matches!(
            scheduler.submit(dir.clone(), "rejected".into(), Duration::ZERO),
            Err(DaemonError::Capacity("queued jobs"))
        ));
        assert_eq!(std::fs::read(dir.join("jobs.jsonl")).unwrap(), before);
        std::fs::write(&release, b"").unwrap();
        drop(scheduler);
    }
}
