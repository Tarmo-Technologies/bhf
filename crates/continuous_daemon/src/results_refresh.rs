// SPDX-License-Identifier: Apache-2.0

//! Keeps each project's `results/` current while its `bhf fuzz` children run
//! with the rebuild deferred to the daemon. The jobs that finished since a
//! project's last record become one `daemon fuzz` producer record and one
//! rebuild: when the project goes idle (nothing running or queued for it), at
//! most once per [`REBUILD_INTERVAL`]; while it stays busy, at most once per
//! [`BUSY_REBUILD_INTERVAL`], with still-running jobs left for the next
//! record. Whatever is outstanding is recorded at shutdown.
//!
//! The rebuilds run on the scheduler's refresh thread (see
//! [`ResultsRefresh::wait_for_work`]); workers only report jobs, so a slow
//! rebuild never holds up job claiming.
//!
//! Lock order: the scheduler mutex may be held while taking the projects
//! mutex, never the reverse; the signal mutex is a leaf; no rebuild runs under
//! any of them.

use crate::{JobOutcome, JobState};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Minimum spacing of rebuilds for a project that has gone idle.
pub(crate) const REBUILD_INTERVAL: Duration = Duration::from_secs(60);
/// Minimum spacing of rebuilds for a project that never goes idle.
pub(crate) const BUSY_REBUILD_INTERVAL: Duration = Duration::from_secs(300);
const PRODUCER_COMMAND: &str = "daemon fuzz";

#[derive(Default)]
pub(crate) struct ResultsRefresh {
    projects: Mutex<HashMap<PathBuf, Project>>,
    signal: Mutex<Signal>,
    wake: Condvar,
}

#[derive(Default)]
struct Signal {
    job_finished: bool,
    shutdown: bool,
}

/// Invariant: `running > 0` implies `pending.is_some()`.
#[derive(Default)]
struct Project {
    running: usize,
    /// The open bracket: jobs finished since the last record, plus the
    /// running ones the next record will cover.
    pending: Option<Pending>,
    last_rebuild: Option<Instant>,
}

pub(crate) struct Pending {
    run: results::ProducerRun,
    opened: Instant,
    finished: usize,
    failed: bool,
    interrupted: bool,
}

impl Pending {
    fn open(project: &Path, now: Instant) -> Self {
        Self {
            run: results::ProducerRun::begin(project, PRODUCER_COMMAND, std::env::args().collect()),
            opened: now,
            finished: 0,
            failed: false,
            interrupted: false,
        }
    }
}

impl ResultsRefresh {
    pub(crate) fn job_started(&self, project: &Path, now: Instant) {
        let mut projects = self.lock();
        let entry = projects.entry(project.to_path_buf()).or_default();
        entry.running += 1;
        entry
            .pending
            .get_or_insert_with(|| Pending::open(project, now));
    }

    /// Count the job against its project's bracket and wake the refresh thread.
    pub(crate) fn job_finished(&self, project: &Path, outcome: JobOutcome) {
        if let Some(entry) = self.lock().get_mut(project) {
            entry.running = entry.running.saturating_sub(1);
            if let Some(pending) = entry.pending.as_mut() {
                pending.finished += 1;
                match outcome {
                    JobOutcome::Finished(JobState::Complete) => {}
                    JobOutcome::Finished(_) => pending.failed = true,
                    JobOutcome::Interrupted => pending.interrupted = true,
                }
            }
        }
        self.signal().job_finished = true;
        self.wake.notify_one();
    }

    /// Block until a job finishes, `timeout` passes, or shutdown is requested;
    /// `false` once it has been.
    pub(crate) fn wait_for_work(&self, timeout: Duration) -> bool {
        let (mut signal, _) = self
            .wake
            .wait_timeout_while(self.signal(), timeout, |s| !s.job_finished && !s.shutdown)
            .unwrap_or_else(|p| p.into_inner());
        signal.job_finished = false;
        !signal.shutdown
    }

    /// Stop the refresh thread's loop. Call once every worker has stopped.
    pub(crate) fn request_shutdown(&self) {
        self.signal().shutdown = true;
        self.wake.notify_one();
    }

    /// Whether any project has finished jobs not yet recorded.
    pub(crate) fn has_pending(&self) -> bool {
        self.lock()
            .values()
            .any(|project| project.pending.as_ref().is_some_and(|p| p.finished > 0))
    }

    /// Take the bracket of every project with finished jobs to record that is
    /// due at `now`: an idle project (nothing running, nothing in `queued`)
    /// once [`REBUILD_INTERVAL`] has passed since its last rebuild, a busy one
    /// once [`BUSY_REBUILD_INTERVAL`] has. A busy project's running jobs move
    /// to a fresh bracket that opens at `now`. Also reports when the earliest
    /// bracket left behind falls due, should nothing change before then.
    pub(crate) fn take_due(&self, now: Instant, queued: &HashSet<PathBuf>) -> Due {
        let mut projects = self.lock();
        let mut due = Due::default();
        for (dir, project) in projects.iter_mut() {
            let Some(pending) = project.pending.as_ref() else {
                continue;
            };
            if pending.finished == 0 {
                continue;
            }
            let busy = project.running > 0 || queued.contains(dir);
            let due_at = if busy {
                project
                    .last_rebuild
                    .unwrap_or(pending.opened)
                    .checked_add(BUSY_REBUILD_INTERVAL)
            } else {
                project
                    .last_rebuild
                    .map_or(Some(now), |at| at.checked_add(REBUILD_INTERVAL))
            };
            // An interval past the end of the clock never comes due.
            let Some(due_at) = due_at else {
                continue;
            };
            if now < due_at {
                due.next = Some(due.next.map_or(due_at, |next| next.min(due_at)));
                continue;
            }
            let reopened = (project.running > 0).then(|| Pending::open(dir, now));
            if let Some(pending) = std::mem::replace(&mut project.pending, reopened) {
                project.last_rebuild = Some(now);
                due.brackets.push((dir.clone(), pending));
            }
        }
        // Forget a project once nothing is left to record or debounce.
        projects.retain(|_, project| {
            project.running > 0 || project.pending.is_some() || !idle_rested(project, now)
        });
        due
    }

    /// Every bracket with finished jobs, regardless of interval (shutdown).
    pub(crate) fn take_all(&self) -> Vec<(PathBuf, Pending)> {
        self.lock()
            .drain()
            .filter_map(|(dir, project)| Some((dir, project.pending?)))
            .filter(|(_, pending)| pending.finished > 0)
            .collect()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<PathBuf, Project>> {
        self.projects.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn signal(&self) -> MutexGuard<'_, Signal> {
        self.signal.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// What [`ResultsRefresh::take_due`] took, and when to look again.
#[derive(Default)]
pub(crate) struct Due {
    pub(crate) brackets: Vec<(PathBuf, Pending)>,
    /// When the earliest bracket with finished jobs left behind falls due.
    pub(crate) next: Option<Instant>,
}

/// How long the refresh thread sleeps when nothing wakes it: until `next`
/// falls due, at most [`REBUILD_INTERVAL`]. An idle project is then rebuilt
/// at most [`REBUILD_INTERVAL`] after its last rebuild, and a busy one at
/// most [`BUSY_REBUILD_INTERVAL`] after it.
pub(crate) fn refresh_wait(next: Option<Instant>, now: Instant) -> Duration {
    next.map_or(REBUILD_INTERVAL, |at| {
        at.saturating_duration_since(now).min(REBUILD_INTERVAL)
    })
}

/// Rebuild every bracket. A rebuild that panics is logged and the rest still
/// run, so one bad project never stops the refresh thread.
pub(crate) fn rebuild_all(due: Vec<(PathBuf, Pending)>) {
    rebuild_each(due, Pending::rebuild);
}

fn rebuild_each(due: Vec<(PathBuf, Pending)>, rebuild: impl Fn(Pending, &Path)) {
    for (project, pending) in due {
        let rebuilt =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| rebuild(pending, &project)));
        if rebuilt.is_err() {
            eprintln!(
                "results index for {} not rebuilt: the rebuild panicked; run 'bhf report --work-dir {}' to retry",
                project.display(),
                project.display()
            );
        }
    }
}

fn idle_rested(project: &Project, now: Instant) -> bool {
    project
        .last_rebuild
        .is_none_or(|at| now.saturating_duration_since(at) >= REBUILD_INTERVAL)
}

impl Pending {
    /// Append one `daemon fuzz` producer to `project`'s manifest and rebuild
    /// its results/. A project dir that no longer exists is skipped, and a
    /// failed rebuild is a warning.
    pub(crate) fn rebuild(self, project: &Path) {
        if !project.is_dir() {
            return;
        }
        let status = if self.interrupted {
            results::model::ProducerStatus::Partial
        } else {
            results::model::ProducerStatus::Complete
        };
        if let Err(error) = self.run.complete(i32::from(self.failed), status) {
            eprintln!(
                "results index for {} not rebuilt: {error}; run 'bhf report --work-dir {}' to retry",
                project.display(),
                project.display()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn producers(project: &Path) -> Vec<serde_json::Value> {
        let bytes = std::fs::read(project.join("results/manifest.json")).unwrap();
        let manifest: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        manifest["producers"].as_array().unwrap().clone()
    }

    const SECOND: Duration = Duration::from_secs(1);

    #[test]
    fn an_idle_project_is_due_at_once_and_a_busy_one_waits() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().to_path_buf();
        let refresh = ResultsRefresh::default();
        let now = Instant::now();
        assert!(!refresh.has_pending());

        refresh.job_started(&project, now);
        refresh.job_started(&project, now);
        assert!(!refresh.has_pending(), "nothing finished yet");
        refresh.job_finished(&project, JobOutcome::Finished(JobState::Complete));
        assert!(refresh.has_pending());
        assert!(
            refresh.take_due(now, &HashSet::new()).brackets.is_empty(),
            "one still running"
        );

        refresh.job_finished(&project, JobOutcome::Finished(JobState::Complete));
        let queued = HashSet::from([project.clone()]);
        assert!(
            refresh.take_due(now, &queued).brackets.is_empty(),
            "more work is queued"
        );

        let due = refresh.take_due(now, &HashSet::new()).brackets;
        assert_eq!(due.len(), 1, "both jobs share one bracket");
        assert!(!refresh.has_pending());
        rebuild_all(due);
        let records = producers(&project);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["command"], "daemon fuzz");
        assert_eq!(records[0]["exit_code"], 0);
        assert_eq!(records[0]["status"], "complete");
    }

    #[test]
    fn rebuilds_are_at_most_once_per_interval_and_shutdown_takes_the_rest() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().to_path_buf();
        let refresh = ResultsRefresh::default();
        let t0 = Instant::now();
        let none = HashSet::new();

        refresh.job_started(&project, t0);
        refresh.job_finished(&project, JobOutcome::Finished(JobState::Complete));
        assert_eq!(refresh.take_due(t0, &none).brackets.len(), 1);

        refresh.job_started(&project, t0);
        refresh.job_finished(&project, JobOutcome::Finished(JobState::Failed));
        assert!(refresh
            .take_due(t0 + REBUILD_INTERVAL - SECOND, &none)
            .brackets
            .is_empty());
        let later = refresh.take_due(t0 + REBUILD_INTERVAL, &none).brackets;
        assert_eq!(later.len(), 1);
        rebuild_all(later);
        assert_eq!(
            producers(&project)[0]["exit_code"],
            1,
            "a failed job marks the record"
        );

        refresh.job_started(&project, t0 + REBUILD_INTERVAL);
        refresh.job_finished(&project, JobOutcome::Interrupted);
        assert!(refresh
            .take_due(t0 + REBUILD_INTERVAL, &none)
            .brackets
            .is_empty());
        let rest = refresh.take_all();
        assert_eq!(rest.len(), 1);
        rebuild_all(rest);
        let records = producers(&project);
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[1]["status"], "partial",
            "an interrupted job is partial"
        );
        assert!(refresh.take_all().is_empty());
    }

    #[test]
    fn a_busy_project_is_recorded_every_busy_interval_and_running_jobs_carry_over() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().to_path_buf();
        let refresh = ResultsRefresh::default();
        let t0 = Instant::now();
        let none = HashSet::new();

        refresh.job_started(&project, t0); // A
        refresh.job_started(&project, t0); // B, long-running
        refresh.job_finished(&project, JobOutcome::Finished(JobState::Complete)); // A
        assert!(
            refresh
                .take_due(t0 + BUSY_REBUILD_INTERVAL - SECOND, &none)
                .brackets
                .is_empty(),
            "busy, inside the busy interval"
        );
        let t1 = t0 + BUSY_REBUILD_INTERVAL;
        let first = refresh.take_due(t1, &none).brackets;
        assert_eq!(
            first.len(),
            1,
            "a project that stays busy is still recorded"
        );
        rebuild_all(first);
        assert!(
            !refresh.has_pending(),
            "B is running: nothing new to record"
        );

        refresh.job_started(&project, t1 + SECOND); // C
        refresh.job_finished(&project, JobOutcome::Finished(JobState::Complete)); // C
        assert!(
            refresh
                .take_due(t1 + REBUILD_INTERVAL, &none)
                .brackets
                .is_empty(),
            "B still running: the busy interval applies"
        );
        refresh.job_finished(&project, JobOutcome::Finished(JobState::Failed)); // B
        let second = refresh.take_due(t1 + REBUILD_INTERVAL, &none).brackets;
        assert_eq!(second.len(), 1, "idle again: the idle interval applies");
        rebuild_all(second);

        let records = producers(&project);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["exit_code"], 0, "the first record holds A only");
        assert_eq!(
            records[1]["exit_code"], 1,
            "B, running at the first record, lands in the next one"
        );
    }

    #[test]
    fn queued_work_alone_keeps_a_project_busy() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().to_path_buf();
        let refresh = ResultsRefresh::default();
        let t0 = Instant::now();
        let queued = HashSet::from([project.clone()]);

        refresh.job_started(&project, t0);
        refresh.job_finished(&project, JobOutcome::Finished(JobState::Complete));
        assert!(refresh
            .take_due(t0 + REBUILD_INTERVAL, &queued)
            .brackets
            .is_empty());
        assert_eq!(
            refresh
                .take_due(t0 + BUSY_REBUILD_INTERVAL, &queued)
                .brackets
                .len(),
            1
        );
    }

    #[test]
    fn the_refresh_thread_wakes_on_a_finished_job_a_timeout_or_shutdown() {
        let refresh = std::sync::Arc::new(ResultsRefresh::default());
        let project = PathBuf::from("/nonexistent/bhf-project");
        let long = Duration::from_secs(30);

        let waiter = {
            let refresh = std::sync::Arc::clone(&refresh);
            std::thread::spawn(move || {
                let start = Instant::now();
                (refresh.wait_for_work(long), start.elapsed())
            })
        };
        std::thread::sleep(Duration::from_millis(50));
        refresh.job_started(&project, Instant::now());
        refresh.job_finished(&project, JobOutcome::Finished(JobState::Complete));
        let (running, waited) = waiter.join().unwrap();
        assert!(running && waited < long, "a finished job wakes it");

        // The wake-up was consumed: the next wait runs to its timeout.
        let start = Instant::now();
        assert!(refresh.wait_for_work(Duration::from_millis(50)));
        assert!(start.elapsed() >= Duration::from_millis(50));

        refresh.request_shutdown();
        let start = Instant::now();
        assert!(!refresh.wait_for_work(long), "shutdown ends the loop");
        assert!(start.elapsed() < long);
    }

    #[test]
    fn rested_projects_are_forgotten() {
        let refresh = ResultsRefresh::default();
        let project = PathBuf::from("/nonexistent/bhf-project");
        let t0 = Instant::now();
        refresh.job_started(&project, t0);
        refresh.job_finished(&project, JobOutcome::Finished(JobState::Complete));
        let due = refresh.take_due(t0, &HashSet::new()).brackets;
        rebuild_all(due); // a missing project dir is skipped, not created
        assert!(!project.exists());
        assert_eq!(refresh.lock().len(), 1, "kept while debouncing");
        refresh.take_due(t0 + REBUILD_INTERVAL, &HashSet::new());
        assert!(refresh.lock().is_empty());
    }

    #[test]
    fn take_due_reports_when_the_next_bracket_falls_due() {
        let tmp = tempfile::tempdir().unwrap();
        let idle = tmp.path().join("idle");
        let busy = tmp.path().join("busy");
        let refresh = ResultsRefresh::default();
        let t0 = Instant::now();
        let none = HashSet::new();
        assert_eq!(refresh.take_due(t0, &none).next, None, "nothing pending");

        refresh.job_started(&idle, t0);
        refresh.job_finished(&idle, JobOutcome::Finished(JobState::Complete));
        let first = refresh.take_due(t0, &none);
        assert_eq!(first.brackets.len(), 1);
        assert_eq!(first.next, None, "nothing left to record");

        // Debounced: due one idle interval after the last rebuild.
        refresh.job_started(&idle, t0 + 10 * SECOND);
        refresh.job_finished(&idle, JobOutcome::Finished(JobState::Complete));
        let debounced = refresh.take_due(t0 + 10 * SECOND, &none);
        assert!(debounced.brackets.is_empty());
        assert_eq!(debounced.next, Some(t0 + REBUILD_INTERVAL));

        // Busy since t0 + 5 s: due one busy interval after its bracket opened;
        // the idle project is still the earlier one.
        refresh.job_started(&busy, t0 + 5 * SECOND);
        refresh.job_started(&busy, t0 + 5 * SECOND);
        refresh.job_finished(&busy, JobOutcome::Finished(JobState::Complete));
        let both = refresh.take_due(t0 + 20 * SECOND, &none);
        assert!(both.brackets.is_empty());
        assert_eq!(both.next, Some(t0 + REBUILD_INTERVAL));

        let after_idle = refresh.take_due(t0 + REBUILD_INTERVAL, &none);
        assert_eq!(after_idle.brackets.len(), 1);
        assert_eq!(
            after_idle.next,
            Some(t0 + 5 * SECOND + BUSY_REBUILD_INTERVAL)
        );
    }

    #[test]
    fn the_refresh_wait_is_the_time_to_the_next_due_capped_at_the_idle_interval() {
        let now = Instant::now();
        assert_eq!(refresh_wait(None, now), REBUILD_INTERVAL);
        assert_eq!(refresh_wait(Some(now + 10 * SECOND), now), 10 * SECOND);
        assert_eq!(
            refresh_wait(Some(now + BUSY_REBUILD_INTERVAL), now),
            REBUILD_INTERVAL
        );
        assert_eq!(refresh_wait(Some(now), now), Duration::ZERO);
        assert_eq!(
            refresh_wait(Some(now), now + SECOND),
            Duration::ZERO,
            "overdue"
        );
    }

    #[test]
    fn a_panicking_rebuild_does_not_stop_the_others() {
        let tmp = tempfile::tempdir().unwrap();
        let bad = tmp.path().join("bad");
        let good = tmp.path().join("good");
        std::fs::create_dir_all(&bad).unwrap();
        std::fs::create_dir_all(&good).unwrap();
        let refresh = ResultsRefresh::default();
        let t0 = Instant::now();
        for project in [&bad, &good] {
            refresh.job_started(project, t0);
            refresh.job_finished(project, JobOutcome::Finished(JobState::Complete));
        }
        let mut due = refresh.take_due(t0, &HashSet::new()).brackets;
        // The bad project first, so a panic there would skip the good one.
        due.sort_by_key(|(project, _)| project != &bad);
        rebuild_each(due, |pending, project| {
            assert_ne!(project, bad.as_path(), "injected rebuild panic");
            pending.rebuild(project);
        });
        assert_eq!(producers(&good).len(), 1);
        assert!(!bad.join("results/manifest.json").exists());
    }
}
