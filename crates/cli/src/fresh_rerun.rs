// SPDX-License-Identifier: Apache-2.0

//! Fresh-process re-runs of new corpus inputs, off the fuzz loop's critical path.
//!
//! The persistent fork-server cannot see a crash that only a fresh process
//! hits (state the warm process carries, an over-read that stays inside its
//! reused input buffer). So every input the loop is about to keep in its
//! corpus is also run once in a fresh process, and a report from that run
//! becomes a finding. Starting a process costs milliseconds on an idle Linux
//! host but seconds on a loaded one (Windows especially), so the re-runs go
//! to a background worker while the loop keeps fuzzing.
//!
//! The queue is bounded by input count and bytes. When it is full, `submit`
//! waits for the oldest re-runs to finish and returns their results, so
//! nothing is dropped and memory stays bounded. At the end of a pass `finish`
//! waits as long as the caller allows, then stops the re-run still going;
//! whatever it could not check is handed back as unchecked, never dropped.
//! With no worker (the caller asks for none: one usable CPU and a response
//! deadline to judge) each re-run runs inline instead.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// How many re-runs may be outstanding (queued or running) at once.
pub(crate) const MAX_OUTSTANDING_INPUTS: usize = 32;
/// How many input bytes may be outstanding at once.
pub(crate) const MAX_OUTSTANDING_BYTES: usize = 64 * 1024 * 1024;
/// How long `finish` waits, after cancelling, for a worker to stop the
/// re-run it was in.
const WORKER_EXIT_GRACE: Duration = Duration::from_secs(2);

/// Where a re-run ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Placement {
    /// On a background worker, beside the fuzz loop.
    Background,
    /// On the caller's thread, while the loop waits.
    Inline,
}

/// What a re-run job is told about the run it is doing.
pub(crate) struct RerunContext<'a> {
    pub(crate) placement: Placement,
    /// Set once the pass has given up on this re-run: the job should stop
    /// its process and return.
    pub(crate) cancelled: &'a AtomicBool,
    /// Set once the fuzz loop has stopped and only re-runs are left: a job
    /// that lowered its process's priority can raise it back.
    pub(crate) draining: &'a AtomicBool,
}

/// One input and what its fresh-process run returned.
pub(crate) struct Checked<R> {
    pub(crate) input: Vec<u8>,
    pub(crate) result: R,
    pub(crate) placement: Placement,
}

/// What a pass's re-runs came to when the pass ended.
pub(crate) struct Finished<R> {
    /// Re-runs that completed during the final wait.
    pub(crate) checked: Vec<Checked<R>>,
    /// Inputs still queued or running when the wait ran out.
    pub(crate) unchecked: Vec<Vec<u8>>,
}

#[derive(Default)]
struct State {
    queue: VecDeque<(u64, Vec<u8>)>,
    running: HashMap<u64, (Vec<u8>, Instant)>,
    /// No more submissions: workers exit once the queue is empty.
    closed: bool,
    /// Workers still running.
    alive: usize,
}

struct Shared {
    state: Mutex<State>,
    work: Condvar,
    /// The final wait ran out: workers stop what they run and exit.
    cancelled: AtomicBool,
    /// The final wait began: the loop no longer competes with the re-runs.
    draining: AtomicBool,
}

type Job<R> = Arc<dyn Fn(&[u8], &RerunContext<'_>) -> R + Send + Sync>;

pub(crate) struct FreshReruns<R: Send + 'static> {
    shared: Arc<Shared>,
    results: Receiver<(u64, Vec<u8>, R, Duration)>,
    run: Job<R>,
    max_inputs: usize,
    max_bytes: usize,
    next_seq: u64,
    outstanding: HashMap<u64, usize>,
    outstanding_bytes: usize,
    workers: usize,
    submitted: usize,
    /// A running average of how long a background re-run takes.
    typical: Option<Duration>,
}

impl<R: Send + 'static> FreshReruns<R> {
    /// Start `workers` background threads that each run `run` on one input
    /// at a time. With `workers == 0`, or when no thread can be started,
    /// `submit` runs each input inline.
    pub(crate) fn start(
        run: impl Fn(&[u8], &RerunContext<'_>) -> R + Send + Sync + 'static,
        workers: usize,
        max_inputs: usize,
        max_bytes: usize,
    ) -> Self {
        let shared = Arc::new(Shared {
            state: Mutex::new(State::default()),
            work: Condvar::new(),
            cancelled: AtomicBool::new(false),
            draining: AtomicBool::new(false),
        });
        let run: Job<R> = Arc::new(run);
        let (sender, results) = mpsc::channel();
        let mut started = 0;
        for index in 0..workers {
            let (shared, run, sender) = (shared.clone(), run.clone(), sender.clone());
            lock(&shared.state).alive += 1;
            let spawned = std::thread::Builder::new()
                .name(format!("bhf-fresh-rerun-{index}"))
                .spawn({
                    let shared = shared.clone();
                    move || worker(&shared, &*run, &sender)
                });
            match spawned {
                Ok(_) => started += 1,
                Err(_) => lock(&shared.state).alive -= 1,
            }
        }
        Self {
            shared,
            results,
            run,
            max_inputs: max_inputs.max(1),
            max_bytes: max_bytes.max(1),
            next_seq: 0,
            outstanding: HashMap::new(),
            outstanding_bytes: 0,
            workers: started,
            submitted: 0,
            typical: None,
        }
    }

    /// Inputs submitted so far.
    pub(crate) fn submitted(&self) -> usize {
        self.submitted
    }

    /// Run `input` on the caller's thread now, whatever the placement of
    /// the other re-runs.
    pub(crate) fn run_inline(&self, input: &[u8]) -> R {
        let never = AtomicBool::new(false);
        (self.run)(
            input,
            &RerunContext {
                placement: Placement::Inline,
                cancelled: &never,
                draining: &never,
            },
        )
    }

    /// Queue `input` for a fresh-process run. Returns re-runs that finished
    /// meanwhile; when the queue is full this waits for the oldest ones.
    pub(crate) fn submit(&mut self, input: Vec<u8>) -> Vec<Checked<R>> {
        self.submitted += 1;
        if self.workers == 0 {
            let result = self.run_inline(&input);
            return vec![Checked {
                input,
                result,
                placement: Placement::Inline,
            }];
        }
        let mut done = self.take_checked();
        while !self.outstanding.is_empty()
            && (self.outstanding.len() >= self.max_inputs
                || self.outstanding_bytes.saturating_add(input.len()) > self.max_bytes)
        {
            match self.results.recv() {
                Ok(result) => done.push(self.account(result)),
                // Every worker is gone (a panicking re-run): check inline.
                Err(_) => {
                    self.workers = 0;
                    let result = self.run_inline(&input);
                    done.push(Checked {
                        input,
                        result,
                        placement: Placement::Inline,
                    });
                    return done;
                }
            }
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        self.outstanding.insert(seq, input.len());
        self.outstanding_bytes += input.len();
        let mut state = lock(&self.shared.state);
        state.queue.push_back((seq, input));
        drop(state);
        self.shared.work.notify_one();
        done
    }

    /// Re-runs that have finished, without waiting.
    pub(crate) fn take_checked(&mut self) -> Vec<Checked<R>> {
        let mut done = Vec::new();
        while let Ok(result) = self.results.try_recv() {
            done.push(self.account(result));
        }
        done
    }

    /// About how long the outstanding re-runs still need: each one counted
    /// at the typical re-run time so far, or at least as long as the one
    /// running has already taken, and never more than `cap` each.
    pub(crate) fn drain_estimate(&self, cap: Duration) -> Duration {
        if self.outstanding.is_empty() {
            return Duration::ZERO;
        }
        let oldest_running = lock(&self.shared.state)
            .running
            .values()
            .map(|(_, since)| since.elapsed())
            .max()
            .unwrap_or_default();
        let each = self
            .typical
            .unwrap_or_default()
            .max(oldest_running)
            .min(cap);
        each.saturating_mul(u32::try_from(self.outstanding.len()).unwrap_or(u32::MAX))
    }

    /// End of pass: wait at most `within` (`None`: until every re-run is
    /// done) for the outstanding re-runs, then cancel the rest and hand back
    /// every input still queued or running as unchecked. Afterwards only
    /// [`Self::run_inline`] runs anything.
    pub(crate) fn finish(&mut self, within: Option<Duration>) -> Finished<R> {
        self.shared.draining.store(true, Ordering::SeqCst);
        lock(&self.shared.state).closed = true;
        self.shared.work.notify_all();
        let deadline = within.and_then(|within| Instant::now().checked_add(within));
        let mut checked = Vec::new();
        while !self.outstanding.is_empty() {
            let received = match deadline {
                Some(deadline) => self
                    .results
                    .recv_timeout(deadline.saturating_duration_since(Instant::now())),
                None => self
                    .results
                    .recv()
                    .map_err(|_| RecvTimeoutError::Disconnected),
            };
            match received {
                Ok(result) => checked.push(self.account(result)),
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => break,
            }
        }
        let mut state = lock(&self.shared.state);
        self.shared.cancelled.store(true, Ordering::SeqCst);
        let mut unchecked: Vec<(u64, Vec<u8>)> = state.queue.drain(..).collect();
        unchecked.extend(state.running.drain().map(|(seq, (input, _))| (seq, input)));
        // A cancelled job stops its process; give the workers a moment to
        // do that, so no re-run outlives the pass.
        let grace = Instant::now() + WORKER_EXIT_GRACE;
        while state.alive > 0 {
            let left = grace.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            self.shared.work.notify_all();
            state = self
                .shared
                .work
                .wait_timeout(state, left)
                .map_or_else(|poisoned| poisoned.into_inner().0, |(state, _)| state);
        }
        drop(state);
        // A worker that finished before the cancel sent its result already.
        checked.extend(self.take_checked());
        unchecked.sort_by_key(|(seq, _)| *seq);
        Finished {
            checked,
            unchecked: unchecked.into_iter().map(|(_, input)| input).collect(),
        }
    }

    fn account(&mut self, (seq, input, result, took): (u64, Vec<u8>, R, Duration)) -> Checked<R> {
        if let Some(len) = self.outstanding.remove(&seq) {
            self.outstanding_bytes = self.outstanding_bytes.saturating_sub(len);
        }
        self.typical = Some(match self.typical {
            Some(typical) => (typical * 3 + took) / 4,
            None => took,
        });
        Checked {
            input,
            result,
            placement: Placement::Background,
        }
    }
}

impl<R: Send + 'static> Drop for FreshReruns<R> {
    fn drop(&mut self) {
        let mut state = lock(&self.shared.state);
        state.closed = true;
        self.shared.cancelled.store(true, Ordering::SeqCst);
        drop(state);
        self.shared.work.notify_all();
    }
}

fn lock(state: &Mutex<State>) -> std::sync::MutexGuard<'_, State> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn worker<R>(
    shared: &Shared,
    run: &(dyn Fn(&[u8], &RerunContext<'_>) -> R + Send + Sync),
    results: &Sender<(u64, Vec<u8>, R, Duration)>,
) {
    /// Counts the worker out however it leaves, a panicking job included.
    struct Alive<'a>(&'a Shared);
    impl Drop for Alive<'_> {
        fn drop(&mut self) {
            lock(&self.0.state).alive -= 1;
            self.0.work.notify_all();
        }
    }
    let _alive = Alive(shared);
    let context = RerunContext {
        placement: Placement::Background,
        cancelled: &shared.cancelled,
        draining: &shared.draining,
    };
    loop {
        let (seq, input) = {
            let mut state = lock(&shared.state);
            loop {
                if shared.cancelled.load(Ordering::SeqCst) {
                    return;
                }
                if let Some((seq, input)) = state.queue.pop_front() {
                    state.running.insert(seq, (input.clone(), Instant::now()));
                    break (seq, input);
                }
                if state.closed {
                    return;
                }
                state = shared
                    .work
                    .wait(state)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
        };
        let started = Instant::now();
        let result = run(&input, &context);
        let took = started.elapsed();
        // Under the lock, so the final wait sees this input either as running
        // (and counts it unchecked) or as a sent result, never both or neither.
        let mut state = lock(&shared.state);
        if shared.cancelled.load(Ordering::SeqCst) {
            return;
        }
        state.running.remove(&seq);
        if results.send((seq, input, result, took)).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn inputs(checked: &[Checked<usize>]) -> Vec<Vec<u8>> {
        let mut inputs: Vec<Vec<u8>> = checked.iter().map(|c| c.input.clone()).collect();
        inputs.sort();
        inputs
    }

    /// The caller is not held up by a slow re-run: submitting returns at once
    /// and the result arrives later, with its input.
    #[test]
    fn a_slow_rerun_does_not_hold_up_the_caller() {
        let mut reruns = FreshReruns::start(
            |input: &[u8], context: &RerunContext<'_>| {
                assert_eq!(context.placement, Placement::Background);
                std::thread::sleep(Duration::from_millis(300));
                input.len()
            },
            1,
            8,
            1 << 20,
        );
        let started = Instant::now();
        assert!(reruns.submit(b"abc".to_vec()).is_empty());
        assert!(
            started.elapsed() < Duration::from_millis(150),
            "submit waited {:?} for a 300 ms re-run",
            started.elapsed()
        );
        let finished = reruns.finish(Some(Duration::from_secs(10)));
        assert_eq!(finished.checked.len(), 1);
        assert_eq!(finished.checked[0].input, b"abc");
        assert_eq!(finished.checked[0].result, 3);
        assert_eq!(finished.checked[0].placement, Placement::Background);
        assert!(finished.unchecked.is_empty());
    }

    /// Every submitted input comes back exactly once, as checked.
    #[test]
    fn every_input_is_checked_once() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let mut reruns = FreshReruns::start(
            move |input: &[u8], _: &RerunContext<'_>| {
                counted.fetch_add(1, Ordering::SeqCst);
                input.len()
            },
            2,
            4,
            1 << 20,
        );
        let mut checked = Vec::new();
        for n in 0..20u8 {
            checked.extend(reruns.submit(vec![n; usize::from(n)]));
        }
        let finished = reruns.finish(Some(Duration::from_secs(10)));
        checked.extend(finished.checked);
        assert!(finished.unchecked.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 20);
        let expected: Vec<Vec<u8>> = (0..20u8).map(|n| vec![n; usize::from(n)]).collect();
        assert_eq!(inputs(&checked), expected);
        assert!(checked.iter().all(|c| c.result == c.input.len()));
    }

    /// A full queue makes `submit` wait for the oldest re-run and hand its
    /// result back, so the outstanding set never exceeds the bound.
    #[test]
    fn a_full_queue_waits_for_the_oldest_rerun() {
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let (now, high) = (running.clone(), peak.clone());
        let mut reruns = FreshReruns::start(
            move |input: &[u8], _: &RerunContext<'_>| {
                let level = now.fetch_add(1, Ordering::SeqCst) + 1;
                high.fetch_max(level, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(50));
                now.fetch_sub(1, Ordering::SeqCst);
                input.len()
            },
            1,
            2,
            1 << 20,
        );
        let mut early = 0;
        for n in 0..6u8 {
            early += reruns.submit(vec![n]).len();
        }
        assert!(
            early >= 4,
            "only {early} results came back while submitting"
        );
        let finished = reruns.finish(Some(Duration::from_secs(10)));
        assert_eq!(early + finished.checked.len(), 6);
        assert_eq!(peak.load(Ordering::SeqCst), 1);
    }

    /// The byte bound applies too: a second large input waits for the first.
    #[test]
    fn the_byte_bound_holds_back_a_large_input() {
        let mut reruns = FreshReruns::start(
            |input: &[u8], _: &RerunContext<'_>| {
                std::thread::sleep(Duration::from_millis(50));
                input.len()
            },
            1,
            100,
            1000,
        );
        assert!(reruns.submit(vec![0; 800]).is_empty());
        let waited = reruns.submit(vec![1; 800]);
        assert_eq!(waited.len(), 1, "the first input's result came back");
        assert_eq!(waited[0].input.len(), 800);
        let finished = reruns.finish(Some(Duration::from_secs(10)));
        assert_eq!(finished.checked.len(), 1);
    }

    /// The end-of-pass wait is bounded: what is still queued or running when
    /// it runs out is handed back as unchecked, in submission order, and
    /// nothing is lost. The running job is told to stop, and has stopped by
    /// the time `finish` returns.
    #[test]
    fn the_final_wait_is_bounded_and_stops_what_it_could_not_check() {
        let stopped = Arc::new(AtomicBool::new(false));
        let seen_stop = stopped.clone();
        let mut reruns = FreshReruns::start(
            move |input: &[u8], context: &RerunContext<'_>| {
                if input == b"stuck" {
                    let give_up = Instant::now() + Duration::from_secs(30);
                    while !context.cancelled.load(Ordering::SeqCst) && Instant::now() < give_up {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    seen_stop.store(context.cancelled.load(Ordering::SeqCst), Ordering::SeqCst);
                }
                input.len()
            },
            1,
            8,
            1 << 20,
        );
        let mut checked = reruns.submit(b"quick".to_vec());
        for input in [&b"stuck"[..], b"after-1", b"after-2"] {
            checked.extend(reruns.submit(input.to_vec()));
        }
        let started = Instant::now();
        let finished = reruns.finish(Some(Duration::from_millis(300)));
        let waited = started.elapsed();
        assert!(waited >= Duration::from_millis(300), "{waited:?}");
        assert!(waited < Duration::from_secs(5), "{waited:?}");
        assert!(
            stopped.load(Ordering::SeqCst),
            "the running re-run was stopped"
        );
        checked.extend(finished.checked);
        assert_eq!(inputs(&checked), vec![b"quick".to_vec()]);
        assert_eq!(
            finished.unchecked,
            vec![b"stuck".to_vec(), b"after-1".to_vec(), b"after-2".to_vec()]
        );
    }

    /// Once the pass starts its final wait, a running job is told the loop
    /// has stopped.
    #[test]
    fn a_running_rerun_learns_when_the_final_wait_begins() {
        let told = Arc::new(AtomicBool::new(false));
        let seen = told.clone();
        let mut reruns = FreshReruns::start(
            move |input: &[u8], context: &RerunContext<'_>| {
                let give_up = Instant::now() + Duration::from_secs(30);
                while !context.draining.load(Ordering::SeqCst) && Instant::now() < give_up {
                    std::thread::sleep(Duration::from_millis(5));
                }
                seen.store(context.draining.load(Ordering::SeqCst), Ordering::SeqCst);
                input.len()
            },
            1,
            8,
            1 << 20,
        );
        assert!(reruns.submit(b"waits".to_vec()).is_empty());
        std::thread::sleep(Duration::from_millis(100));
        assert!(!told.load(Ordering::SeqCst), "not before the final wait");
        let finished = reruns.finish(Some(Duration::from_secs(10)));
        assert_eq!(finished.checked.len(), 1);
        assert!(told.load(Ordering::SeqCst));
    }

    /// With no bound, the end of a pass waits for every re-run.
    #[test]
    fn an_unbounded_final_wait_checks_everything() {
        let mut reruns = FreshReruns::start(
            |input: &[u8], _: &RerunContext<'_>| {
                std::thread::sleep(Duration::from_millis(100));
                input.len()
            },
            1,
            8,
            1 << 20,
        );
        let mut checked = Vec::new();
        for n in 1..=4u8 {
            checked.extend(reruns.submit(vec![n; usize::from(n)]));
        }
        let finished = reruns.finish(None);
        checked.extend(finished.checked);
        assert!(finished.unchecked.is_empty());
        assert_eq!(checked.len(), 4);
    }

    /// What the outstanding re-runs still need is estimated from how long
    /// re-runs have taken: about one typical re-run per outstanding input.
    #[test]
    fn the_drain_estimate_follows_the_typical_rerun_time() {
        let mut reruns = FreshReruns::start(
            |input: &[u8], _: &RerunContext<'_>| {
                std::thread::sleep(Duration::from_millis(200));
                input.len()
            },
            1,
            8,
            1 << 20,
        );
        assert_eq!(
            reruns.drain_estimate(Duration::from_secs(10)),
            Duration::ZERO
        );
        for n in 0..4u8 {
            assert!(reruns.submit(vec![n]).is_empty());
        }
        // The first re-run is done: three are left, at about 200 ms each.
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut done = Vec::new();
        while done.is_empty() && Instant::now() < deadline {
            done = reruns.take_checked();
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(done.len(), 1);
        let estimate = reruns.drain_estimate(Duration::from_secs(10));
        assert!(
            estimate >= Duration::from_millis(3 * 190) && estimate < Duration::from_secs(3),
            "{estimate:?}"
        );
        // Never more than the cap per input.
        assert_eq!(
            reruns.drain_estimate(Duration::from_millis(50)),
            Duration::from_millis(150)
        );
        let _ = reruns.finish(Some(Duration::from_secs(10)));
    }

    /// Quick re-runs leave a quick estimate whatever the per-input cap: a
    /// short pass that found eight inputs is told it needs about eight quick
    /// re-runs, not eight per-input timeouts, so it stops in time to check
    /// them.
    #[test]
    fn the_drain_estimate_counts_measured_reruns_not_the_timeout() {
        let release = Arc::new(AtomicBool::new(false));
        let held = release.clone();
        let mut reruns = FreshReruns::start(
            move |input: &[u8], _: &RerunContext<'_>| {
                std::thread::sleep(Duration::from_millis(20));
                // Every input after the first waits here, so eight stay out.
                let give_up = Instant::now() + Duration::from_secs(30);
                while input != b"first" && !held.load(Ordering::SeqCst) && Instant::now() < give_up
                {
                    std::thread::sleep(Duration::from_millis(1));
                }
                input.len()
            },
            1,
            16,
            1 << 20,
        );
        assert!(reruns.submit(b"first".to_vec()).is_empty());
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut done = Vec::new();
        while done.is_empty() && Instant::now() < deadline {
            done = reruns.take_checked();
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(done.len(), 1, "the first re-run came back");
        for n in 0..8u8 {
            assert!(reruns.submit(vec![n]).is_empty());
        }
        // `bhf fuzz`'s default --timeout is the cap.
        let estimate = reruns.drain_estimate(Duration::from_secs(10));
        release.store(true, Ordering::SeqCst);
        assert!(
            estimate >= Duration::from_millis(8 * 20) && estimate < Duration::from_secs(1),
            "eight 20 ms re-runs estimated at {estimate:?}"
        );
        let finished = reruns.finish(Some(Duration::from_secs(10)));
        assert_eq!(finished.checked.len(), 8);
        assert!(finished.unchecked.is_empty());
    }

    /// With no worker thread at all, re-runs still happen, inline.
    #[test]
    fn without_a_worker_reruns_run_inline() {
        let mut reruns = FreshReruns::start(
            |input: &[u8], context: &RerunContext<'_>| {
                assert_eq!(context.placement, Placement::Inline);
                input.len()
            },
            0,
            8,
            1 << 20,
        );
        let checked = reruns.submit(b"inline".to_vec());
        assert_eq!(checked.len(), 1);
        assert_eq!(checked[0].result, 6);
        assert_eq!(checked[0].placement, Placement::Inline);
        assert_eq!(reruns.submitted(), 1);
        let finished = reruns.finish(Some(Duration::ZERO));
        assert!(finished.checked.is_empty() && finished.unchecked.is_empty());
    }
}
