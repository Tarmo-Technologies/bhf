// SPDX-License-Identifier: Apache-2.0
//! Health observations and serialized fail-closed state transitions.

use super::{FuzzJob, InnerState, JobState, PersistFailure, Scheduler, SharedState};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistencePhase {
    Admission,
    Start,
    Completion,
}

/// First storage error since startup. A snapshot may be installed but not durable.
/// No project paths, harness names, URLs, or raw error messages are included.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageFault {
    pub phase: PersistencePhase,
    pub job_id: String,
    pub snapshot_installed: bool,
    pub io_error_kind: String,
    pub raw_os_error: Option<i32>,
}

/// Point-in-time, in-memory observation, not a readiness or durability certificate.
/// Counts remain available after admission stops. Consult storage_fault before
/// treating an observed terminal job state as durably committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerHealth {
    pub schema_version: u32,
    pub accepting_submissions: bool,
    pub shutdown_requested: bool,
    pub retained_jobs: usize,
    pub queued_jobs: usize,
    pub running_jobs: usize,
    pub complete_jobs: usize,
    pub failed_jobs: usize,
    pub max_jobs: usize,
    pub max_queued_jobs: usize,
    pub snapshot_bytes_reserved: usize,
    pub max_snapshot_bytes: usize,
    pub storage_fault: Option<StorageFault>,
}

impl Scheduler {
    pub fn health(&self) -> SchedulerHealth {
        let guard = self.state.inner.lock().unwrap_or_else(|p| p.into_inner());
        let mut health = SchedulerHealth {
            schema_version: 1,
            accepting_submissions: !guard.shutdown
                && guard.seen.len() < self.limits.max_jobs
                && guard.queue.len() < self.limits.max_queued_jobs
                && guard.snapshot_bytes_reserved < self.limits.max_snapshot_bytes,
            shutdown_requested: guard.shutdown,
            retained_jobs: guard.seen.len(),
            queued_jobs: 0,
            running_jobs: 0,
            complete_jobs: 0,
            failed_jobs: 0,
            max_jobs: self.limits.max_jobs,
            max_queued_jobs: self.limits.max_queued_jobs,
            snapshot_bytes_reserved: guard.snapshot_bytes_reserved,
            max_snapshot_bytes: self.limits.max_snapshot_bytes,
            storage_fault: guard.storage_fault.clone(),
        };
        for job in &guard.seen {
            match job.state {
                JobState::Queued => health.queued_jobs += 1,
                JobState::Running => health.running_jobs += 1,
                JobState::Complete => health.complete_jobs += 1,
                JobState::Failed => health.failed_jobs += 1,
            }
        }
        health
    }

    /// Stop admission and wake workers. Running children are interrupted by the
    /// existing cleanup path; waiting jobs are retained for restart, not cancelled.
    /// This signals shutdown without joining workers; Drop still joins them.
    /// It does not bound filesystem I/O or synchronous webhook DNS.
    pub fn request_shutdown(&self) {
        let mut guard = self.state.inner.lock().unwrap_or_else(|p| p.into_inner());
        guard.shutdown = true;
        self.state.cv.notify_all();
    }
}

pub(super) fn latch_storage_fault(
    shared: &SharedState,
    guard: &mut InnerState,
    phase: PersistencePhase,
    job_id: &str,
    failure: &PersistFailure,
) {
    if guard.storage_fault.is_none() {
        eprintln!(
            "scheduler storage fault: phase={phase:?} job={job_id} installed={} kind={:?}; admission stopped; restart required",
            failure.installed, failure.error.kind(),
        );
        guard.storage_fault = Some(StorageFault {
            phase,
            job_id: job_id.to_owned(),
            snapshot_installed: failure.installed,
            io_error_kind: format!("{:?}", failure.error.kind()),
            raw_os_error: failure.error.raw_os_error(),
        });
    }
    guard.shutdown = true;
    shared.cv.notify_all();
}

/// Called with the scheduler mutex held. Persistence must succeed before dequeue.
pub(super) fn claim_job<F>(
    data_dir: &Path,
    shared: &SharedState,
    guard: &mut InnerState,
    persist: F,
) -> Option<FuzzJob>
where
    F: FnOnce(&Path, &[FuzzJob]) -> Result<(), PersistFailure>,
{
    if guard.shutdown {
        return None;
    }
    let job = guard.queue.front()?.clone();
    let Some(index) = guard.seen.iter().position(|seen| seen.job_id == job.job_id) else {
        let failure = PersistFailure::before(std::io::Error::new(
            std::io::ErrorKind::InvalidData, "queued job missing from scheduler history",
        ));
        latch_storage_fault(shared, guard, PersistencePhase::Start, &job.job_id, &failure);
        return None;
    };
    guard.seen[index].state = JobState::Running;
    if let Err(failure) = persist(data_dir, &guard.seen) {
        // No child was dispatched. Recovery also requeues an installed Running row.
        guard.seen[index].state = JobState::Queued;
        latch_storage_fault(shared, guard, PersistencePhase::Start, &job.job_id, &failure);
        return None;
    }
    guard.queue.pop_front()
}

pub(super) fn finish_job<F>(
    data_dir: &Path,
    shared: &SharedState,
    job_id: &str,
    final_state: JobState,
    persist: F,
) -> bool
where
    F: FnOnce(&Path, &[FuzzJob]) -> Result<(), PersistFailure>,
{
    let mut guard = shared.inner.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(seen) = guard.seen.iter_mut().find(|seen| seen.job_id == job_id) {
        // This is a runtime observation. A storage failure below is exposed by
        // health(), so it is never silently advertised as a durable completion.
        seen.state = final_state;
    }
    if guard.storage_fault.is_some() {
        return false;
    }
    if let Err(failure) = persist(data_dir, &guard.seen) {
        latch_storage_fault(shared, &mut guard, PersistencePhase::Completion, job_id, &failure);
        return false;
    }
    true
}

#[cfg(test)]
#[path = "health_tests.rs"]
mod tests;
