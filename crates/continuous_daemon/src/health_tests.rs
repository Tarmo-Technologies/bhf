// SPDX-License-Identifier: Apache-2.0
//! Filesystem, lifecycle, and fault-injection tests; no external targets.

use super::*;
use crate::{DaemonConfig, DaemonError, SchedulerLimits, DEFAULT_JOB_WALL_GRACE};
use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

fn config(path: &Path) -> DaemonConfig {
    DaemonConfig {
        data_dir: path.to_owned(),
        max_concurrent_jobs: 1,
        // These portable tests do not submit work to the executable.
        bhf_bin: std::env::current_exe().unwrap(),
        webhook_url: None,
        poll_interval: Duration::from_millis(10),
    }
}

fn job(state: JobState) -> FuzzJob {
    FuzzJob {
        job_id: "J-000000".into(),
        project_dir: PathBuf::from("private-project-do-not-export"),
        harness_id: "private-harness-do-not-export".into(),
        time_budget_secs: 1,
        state,
    }
}

fn shared(job: FuzzJob) -> SharedState {
    SharedState {
        inner: Mutex::new(InnerState {
            queue: if job.state == JobState::Queued { VecDeque::from([job.clone()]) } else { VecDeque::new() },
            seen: vec![job],
            shutdown: false,
            next_id: 1,
            snapshot_bytes_reserved: 1024,
            storage_fault: None,
        }),
        cv: Condvar::new(),
    }
}

fn failed(installed: bool) -> PersistFailure {
    PersistFailure {
        error: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "private-path-must-not-leak"),
        installed,
    }
}

fn wait_for(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !predicate() {
        assert!(Instant::now() < deadline, "bounded condition did not become true");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn idle_health_and_explicit_shutdown_are_distinct_from_storage_failure() {
    let dir = tempfile::tempdir().unwrap();
    let scheduler = Scheduler::start(&config(dir.path())).unwrap();
    let health = scheduler.health();
    assert!(health.accepting_submissions);
    assert!(!health.shutdown_requested);
    assert_eq!(health.retained_jobs, 0);
    assert!(health.storage_fault.is_none());
    scheduler.request_shutdown();
    scheduler.request_shutdown();
    assert!(!scheduler.health().accepting_submissions);
    assert!(scheduler.health().shutdown_requested);
    assert!(scheduler.health().storage_fault.is_none());
    assert!(matches!(scheduler.submit(dir.path().to_owned(), "H".into(), Duration::ZERO), Err(DaemonError::Shutdown)));
}

#[test]
fn health_counts_states_without_exposing_project_or_harness_names() {
    let dir = tempfile::tempdir().unwrap();
    let scheduler = Scheduler::start(&config(dir.path())).unwrap();
    {
        let mut guard = scheduler.state.inner.lock().unwrap();
        guard.seen = [JobState::Queued, JobState::Running, JobState::Complete, JobState::Failed]
            .into_iter().enumerate().map(|(index, state)| FuzzJob { job_id: format!("J-{index:06}"), ..job(state) }).collect();
    }
    let health = scheduler.health();
    assert_eq!((health.retained_jobs, health.queued_jobs, health.running_jobs, health.complete_jobs, health.failed_jobs), (4, 1, 1, 1, 1));
    let encoded = serde_json::to_string(&health).unwrap();
    assert!(!encoded.contains("private-"));
    assert_eq!(serde_json::from_str::<SchedulerHealth>(&encoded).unwrap(), health);
}

#[test]
fn health_marks_retained_capacity_without_calling_it_a_storage_fault() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("jobs.jsonl"), format!("{}\n", serde_json::to_string(&job(JobState::Complete)).unwrap())).unwrap();
    let scheduler = Scheduler::start_with_resource_limits(
        &config(dir.path()), Duration::from_secs(1), DEFAULT_JOB_WALL_GRACE,
        SchedulerLimits { max_jobs: 1, ..SchedulerLimits::default() },
    ).unwrap();
    assert!(!scheduler.health().accepting_submissions);
    assert!(!scheduler.health().shutdown_requested);
    assert!(scheduler.health().storage_fault.is_none());
}

#[test]
fn rejected_admission_latches_fault_without_consuming_id_or_record() {
    let dir = tempfile::tempdir().unwrap();
    let scheduler = Scheduler::start(&config(dir.path())).unwrap();
    let result = scheduler.submit_with_persistence(dir.path().to_owned(), "H".into(), Duration::ZERO, |_, _| Err(failed(false)));
    assert!(matches!(result, Err(DaemonError::Io(_))));
    let guard = scheduler.state.inner.lock().unwrap();
    assert_eq!(guard.next_id, 0);
    assert_eq!(guard.snapshot_bytes_reserved, 0);
    assert!(guard.seen.is_empty());
    assert!(guard.queue.is_empty());
    assert_eq!(guard.storage_fault.as_ref().unwrap().phase, PersistencePhase::Admission);
    drop(guard);
    assert!(!scheduler.health().accepting_submissions);
    assert!(matches!(scheduler.submit(dir.path().to_owned(), "next".into(), Duration::ZERO), Err(DaemonError::Shutdown)));
}

#[test]
fn uncertain_admission_reserves_id_and_bytes_and_exposes_installed_flag() {
    let dir = tempfile::tempdir().unwrap();
    let scheduler = Scheduler::start(&config(dir.path())).unwrap();
    let result = scheduler.submit_with_persistence(dir.path().to_owned(), "H".into(), Duration::ZERO, |path, jobs| {
        crate::persist_jobs_with_sync(path, jobs, |_| Err(std::io::Error::other("injected directory sync failure")))
    });
    assert!(matches!(result, Err(DaemonError::DurabilityUncertain { .. })));
    let health = scheduler.health();
    assert_eq!(health.retained_jobs, 1);
    assert!(health.snapshot_bytes_reserved > 0);
    assert!(health.storage_fault.unwrap().snapshot_installed);
    let guard = scheduler.state.inner.lock().unwrap();
    assert_eq!(guard.next_id, 1);
    assert!(guard.queue.is_empty());
}

#[test]
fn start_failure_never_dequeues_or_authorizes_dispatch() {
    let dir = tempfile::tempdir().unwrap();
    for installed in [false, true] {
        let state = shared(job(JobState::Queued));
        let mut guard = state.inner.lock().unwrap();
        let claimed = claim_job(dir.path(), &state, &mut guard, |_, rows| {
            assert_eq!(rows[0].state, JobState::Running);
            Err(failed(installed))
        });
        assert!(claimed.is_none());
        assert_eq!(guard.queue.len(), 1);
        assert_eq!(guard.seen[0].state, JobState::Queued);
        let fault = guard.storage_fault.as_ref().unwrap();
        assert_eq!(fault.phase, PersistencePhase::Start);
        assert_eq!(fault.snapshot_installed, installed);
        assert!(guard.shutdown);
        assert!(claim_job(dir.path(), &state, &mut guard, |_, _| panic!("must not attempt another write")).is_none());
    }
}

#[test]
fn successful_claim_persists_running_before_dequeue() {
    let dir = tempfile::tempdir().unwrap();
    let state = shared(job(JobState::Queued));
    let mut guard = state.inner.lock().unwrap();
    assert!(claim_job(dir.path(), &state, &mut guard, crate::persist_jobs).is_some());
    assert!(guard.queue.is_empty());
    assert_eq!(guard.seen[0].state, JobState::Running);
    let saved: FuzzJob = serde_json::from_slice(fs::read(dir.path().join("jobs.jsonl")).unwrap().trim_ascii()).unwrap();
    assert_eq!(saved.state, JobState::Running);
    assert!(guard.storage_fault.is_none());
}

#[test]
fn completion_failure_blocks_notification_and_further_writes() {
    let dir = tempfile::tempdir().unwrap();
    for installed in [false, true] {
        let state = shared(job(JobState::Running));
        assert!(!finish_job(dir.path(), &state, "J-000000", JobState::Complete, |_, rows| {
            assert_eq!(rows[0].state, JobState::Complete);
            Err(failed(installed))
        }));
        let guard = state.inner.lock().unwrap();
        assert!(guard.shutdown);
        assert_eq!(guard.seen[0].state, JobState::Complete);
        let fault = guard.storage_fault.as_ref().unwrap();
        assert_eq!(fault.phase, PersistencePhase::Completion);
        assert_eq!(fault.snapshot_installed, installed);
        assert!(!serde_json::to_string(fault).unwrap().contains("private-path"));
        drop(guard);
        assert!(!finish_job(dir.path(), &state, "J-000000", JobState::Queued, |_, _| panic!("must not overwrite uncertain snapshot")));
    }
}

#[test]
fn successful_completion_is_durable_and_normal_shutdown_can_requeue() {
    let dir = tempfile::tempdir().unwrap();
    let state = shared(job(JobState::Running));
    assert!(finish_job(dir.path(), &state, "J-000000", JobState::Complete, crate::persist_jobs));
    let saved: FuzzJob = serde_json::from_slice(fs::read(dir.path().join("jobs.jsonl")).unwrap().trim_ascii()).unwrap();
    assert_eq!(saved.state, JobState::Complete);
    state.inner.lock().unwrap().shutdown = true;
    assert!(finish_job(dir.path(), &state, "J-000000", JobState::Queued, crate::persist_jobs));
    let saved: FuzzJob = serde_json::from_slice(fs::read(dir.path().join("jobs.jsonl")).unwrap().trim_ascii()).unwrap();
    assert_eq!(saved.state, JobState::Queued);
}

#[test]
fn first_storage_failure_is_not_overwritten_by_later_failures() {
    let state = shared(job(JobState::Running));
    let mut guard = state.inner.lock().unwrap();
    latch_storage_fault(&state, &mut guard, PersistencePhase::Start, "J-000000", &failed(true));
    let first = guard.storage_fault.clone();
    latch_storage_fault(&state, &mut guard, PersistencePhase::Completion, "J-000001", &failed(false));
    assert_eq!(guard.storage_fault, first);
}

#[test]
fn duplicate_scheduler_is_rejected_even_through_a_path_alias() {
    let dir = tempfile::tempdir().unwrap();
    let scheduler = Scheduler::start(&config(dir.path())).unwrap();
    assert!(matches!(Scheduler::start(&config(dir.path())), Err(DaemonError::DataDirInUse(_))));
    assert!(matches!(Scheduler::start(&config(&dir.path().join("."))), Err(DaemonError::DataDirInUse(_))));
    drop(scheduler);
    assert!(dir.path().join(".bhf-scheduler.lock").is_file());
    let reopened = Scheduler::start(&config(dir.path())).unwrap();
    drop(reopened);
}

#[test]
fn separate_storage_directories_can_be_owned_independently() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let first = Scheduler::start(&config(a.path())).unwrap();
    let second = Scheduler::start(&config(b.path())).unwrap();
    assert!(first.health().accepting_submissions && second.health().accepting_submissions);
}

#[test]
fn preexisting_lock_file_is_not_truncated_or_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(".bhf-scheduler.lock");
    fs::write(&path, b"retained sentinel").unwrap();
    let scheduler = Scheduler::start(&config(dir.path())).unwrap();
    drop(scheduler);
    assert_eq!(fs::read(path).unwrap(), b"retained sentinel");
}

#[test]
fn invalid_snapshot_startup_releases_ownership_without_rewriting_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("jobs.jsonl");
    fs::write(&path, b"not-json\n").unwrap();
    assert!(matches!(Scheduler::start(&config(dir.path())), Err(DaemonError::CorruptJobs { .. })));
    assert_eq!(fs::read(&path).unwrap(), b"not-json\n");
    fs::remove_file(path).unwrap();
    let scheduler = Scheduler::start(&config(dir.path())).unwrap();
    drop(scheduler);
}

#[test]
fn directory_at_snapshot_path_is_not_treated_as_missing_history() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("jobs.jsonl")).unwrap();
    assert!(matches!(Scheduler::start(&config(dir.path())), Err(DaemonError::Io(_))));
}

#[cfg(unix)]
#[test]
fn symlinked_snapshot_and_lock_are_rejected_without_touching_targets() {
    use std::os::unix::fs::symlink;
    for name in ["jobs.jsonl", ".bhf-scheduler.lock"] {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("outside");
        fs::write(&target, b"unchanged").unwrap();
        symlink(&target, dir.path().join(name)).unwrap();
        assert!(matches!(Scheduler::start(&config(dir.path())), Err(DaemonError::Io(_))));
        assert_eq!(fs::read(target).unwrap(), b"unchanged");
    }
}

#[cfg(unix)]
#[test]
fn dangling_snapshot_link_is_not_treated_as_empty_history() {
    let dir = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink("missing", dir.path().join("jobs.jsonl")).unwrap();
    assert!(matches!(Scheduler::start(&config(dir.path())), Err(DaemonError::Io(_))));
    assert!(!dir.path().join("missing").exists());
}

#[cfg(unix)]
#[test]
fn fifo_storage_paths_are_rejected_without_waiting_for_a_writer() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    for name in ["jobs.jsonl", ".bhf-scheduler.lock"] {
        let dir = tempfile::tempdir().unwrap();
        let name = CString::new(dir.path().join(name).as_os_str().as_bytes()).unwrap();
        // SAFETY: name is a valid live NUL-terminated pathname in our temp dir.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let started = Instant::now();
        assert!(matches!(Scheduler::start(&config(dir.path())), Err(DaemonError::Io(_))));
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn lock_child(dir: &Path, mode: &str) -> ChildGuard {
    ChildGuard(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "health::tests::storage_lock_child", "--nocapture"])
        .env("BHF_TEST_STORAGE_CHILD", mode)
        .env("BHF_TEST_STORAGE_DIR", dir)
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
        .spawn().unwrap())
}

#[test]
fn storage_lock_child() {
    let Some(mode) = std::env::var_os("BHF_TEST_STORAGE_CHILD") else { return; };
    let dir = PathBuf::from(std::env::var_os("BHF_TEST_STORAGE_DIR").unwrap());
    if mode == "probe" {
        match Scheduler::start(&config(&dir)) {
            Err(DaemonError::DataDirInUse(_)) => std::process::exit(42),
            Ok(scheduler) => { drop(scheduler); std::process::exit(0); }
            Err(_) => std::process::exit(43),
        }
    }
    assert_eq!(mode, "hold");
    let _scheduler = Scheduler::start(&config(&dir)).unwrap();
    fs::write(dir.join("child-ready"), b"owned").unwrap();
    loop { std::thread::sleep(Duration::from_millis(100)); }
}

#[test]
fn a_second_process_cannot_open_owned_storage() {
    let dir = tempfile::tempdir().unwrap();
    let scheduler = Scheduler::start(&config(dir.path())).unwrap();
    let mut child = lock_child(dir.path(), "probe");
    let mut status = None;
    wait_for(|| { status = child.0.try_wait().unwrap(); status.is_some() });
    assert_eq!(status.unwrap().code(), Some(42));
    drop(scheduler);
}

#[test]
fn process_termination_releases_lock_without_stale_lockfile_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = lock_child(dir.path(), "hold");
    wait_for(|| dir.path().join("child-ready").exists());
    assert!(matches!(Scheduler::start(&config(dir.path())), Err(DaemonError::DataDirInUse(_))));
    child.0.kill().unwrap();
    wait_for(|| child.0.try_wait().unwrap().is_some());
    let scheduler = Scheduler::start(&config(dir.path())).unwrap();
    assert!(scheduler.health().accepting_submissions);
}

#[cfg(unix)]
#[test]
fn real_worker_completion_storage_failure_stops_the_next_job() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("worker.sh");
    // Use the passed project directory rather than interpolating a host pathname.
    fs::write(&script, b"#!/bin/sh\ntouch \"$2/entered-$4\"\nwhile [ ! -f \"$2/release\" ]; do sleep 0.01; done\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let mut cfg = config(dir.path());
    cfg.bhf_bin = script;
    let scheduler = Scheduler::start(&cfg).unwrap();
    scheduler.submit(dir.path().to_owned(), "first".into(), Duration::ZERO).unwrap();
    wait_for(|| dir.path().join("entered-first").exists());
    scheduler.submit(dir.path().to_owned(), "second".into(), Duration::ZERO).unwrap();
    fs::remove_file(dir.path().join("jobs.jsonl")).unwrap();
    fs::create_dir(dir.path().join("jobs.jsonl")).unwrap();
    fs::write(dir.path().join("release"), b"").unwrap();
    wait_for(|| scheduler.health().storage_fault.is_some());
    let health = scheduler.health();
    assert_eq!(health.storage_fault.unwrap().phase, PersistencePhase::Completion);
    assert!(!health.accepting_submissions);
    assert!(!dir.path().join("entered-second").exists());
    assert_eq!(scheduler.list_jobs().unwrap()[1].state, JobState::Queued);
}
