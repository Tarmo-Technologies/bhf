// SPDX-License-Identifier: Apache-2.0

//! HDF-8 deliverable 2 + 3: schedule-perturbation exploration and pinned-schedule
//! replay via a deterministic cooperative scheduler.
//!
//! Today `multicore_fuzz` is throughput sharding and the only concurrency
//! capability is TSan corpus replay — observational and nondeterministic. A race
//! that needs a *specific* interleaving is only ever found by luck, because the
//! host OS scheduler runs the target's threads however it pleases and, on a fast
//! host, usually runs each short critical section to completion before switching.
//!
//! This module makes the interleaving a **function of the fuzz input** so it can
//! be searched (coverage-guided) and reproduced (pinned). When `BHF_SCHED=1` is
//! set (opt-in, Linux-only), the shim runs the target's threads under a single
//! cooperative *baton*: exactly one registered thread runs at a time, and at each
//! scheduling point the next runnable thread is chosen from the input. This is a
//! PCT-lite / systematic-concurrency-testing design (Burckhardt et al., PLDI'10;
//! the same family as `rr chaos` and Microsoft's CHESS): it does not enumerate all
//! interleavings (intractable), but it turns "reachable only under one ordering"
//! from a coin flip into an input-addressable, replayable decision.
//!
//! ## Scheduling points
//!
//! * [`bhf_sched_yield`] — an explicit cooperative yield the target (or a
//!   generated harness) calls at an interleaving-relevant point. This is the
//!   robust core: the target names where a context switch may happen, so the
//!   scheduler never has to guess lock dependencies.
//! * [`pthread_create`] — a created thread is registered and parked at an initial
//!   gate until the scheduler grants it the baton, so thread *start ordering* is
//!   the scheduler's choice, not the OS's.
//! * [`pthread_join`] — the joiner releases the baton and blocks (a `Joining`
//!   state that is not schedulable) until the joinee finishes, so a join can never
//!   starve the scheduler or self-deadlock the baton.
//!
//! ## Determinism and replay
//!
//! The next thread is `runnable[schedule_byte % runnable.len()]`. Schedule bytes
//! come from `BHF_SCHED_SEQUENCE` (a hex string, for pinned replay) when set, else
//! from the live fuzz input (so the interleaving is coverage-guided-searchable).
//! Same input + same mode ⇒ same interleaving ⇒ the found race reproduces
//! (deliverable 3). The realized schedule is logged as `sched` runtrace events so
//! a caller can assert which interleaving was reached and pin it for replay.
//!
//! ## Honest limits (documented follow-ups)
//!
//! * The scheduler perturbs at explicit yields, `pthread_create`, and
//!   `pthread_join`; it does NOT yet interpose `pthread_mutex_lock`/`unlock`
//!   automatically. Auto-instrumenting every lock acquisition would give
//!   finer-grained search but risks deadlocking a target that relies on
//!   libc-internal locking under a cooperative scheduler, so it is left as a
//!   follow-up behind its own gate. Until then, a target reaches the finer points
//!   by calling `bhf_sched_yield()` (which `harness_gen` can insert).
//! * At most [`MAX_THREADS`] threads are managed; beyond that, creation falls
//!   through to the OS unmanaged (no perturbation), never failing.
//! * Each gate wait has a [`GATE_TIMEOUT`] backstop under the host's
//!   per-input hang kill: a scheduler-induced deadlock is not masked forever — the
//!   waiter proceeds (logged) and the resulting hang surfaces via the host-side
//!   deadline oracle as a finding, rather than wedging the process silently.
//! * Threads created outside the shim's `pthread_create` (e.g. before `BHF_SCHED`
//!   took effect) are not managed; their `bhf_sched_yield` is a no-op.

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::missing_transmute_annotations)]

use std::cell::Cell;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::dlsym::ResolvedFn;
use crate::jsonl::Builder;
use crate::reentrancy::HookGuard;

/// Hard cap on managed threads. A radar/RTOS partition under host stub-isolation
/// has a handful of worker tasks; 16 is generous and keeps the state a fixed-size,
/// heap-free array (the shim's allocation discipline).
pub const MAX_THREADS: usize = 16;

/// Longest a thread waits at a scheduling gate before the safety valve fires. Well
/// under the host's 10s per-input hang kill, so a real scheduler-induced deadlock
/// still terminates the run (and is reported by the host deadline oracle) rather
/// than being masked, while a merely-slow cooperative step is never cut short.
const GATE_TIMEOUT: Duration = Duration::from_secs(5);

/// Longest recorded pinned schedule (bytes). One byte per scheduling decision;
/// 256 decisions is far more than any 2–4 thread fixture needs.
const SEQ_CAP: usize = 256;

/// Key mixed into the fuzz-input read so schedule bytes draw from a stable window
/// distinct from the target's own resource channels.
const SCHED_INPUT_KEY: u64 = 0x5343_4845_4400_0000; // "SCHED\0\0\0"

static REAL_PTHREAD_CREATE: ResolvedFn = ResolvedFn::new(b"pthread_create\0");
static REAL_PTHREAD_JOIN: ResolvedFn = ResolvedFn::new(b"pthread_join\0");

type StartRoutine = unsafe extern "C" fn(*mut libc::c_void) -> *mut libc::c_void;
type PthreadCreateFn = unsafe extern "C" fn(
    *mut libc::pthread_t,
    *const libc::pthread_attr_t,
    Option<StartRoutine>,
    *mut libc::c_void,
) -> libc::c_int;
type PthreadJoinFn = unsafe extern "C" fn(libc::pthread_t, *mut *mut libc::c_void) -> libc::c_int;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    /// Unused slot.
    Free,
    /// Registered and waiting at a gate to be granted the baton.
    Runnable,
    /// Holds the baton (the one thread currently executing target code).
    Running,
    /// Blocked in `pthread_join`; not schedulable until the joinee finishes.
    Joining,
    /// Thread exited.
    Finished,
}

#[derive(Clone, Copy)]
struct Pending {
    /// Real `start_routine` as usize (0 = none), read by the trampoline.
    start: usize,
    /// Real `arg` as usize, read by the trampoline.
    arg: usize,
}

struct SchedState {
    status: [Status; MAX_THREADS],
    /// `pthread_t` of each managed thread, for join → slot mapping.
    tid: [libc::pthread_t; MAX_THREADS],
    /// For a `Joining` slot, the slot it is waiting on.
    join_target: [isize; MAX_THREADS],
    pending: [Pending; MAX_THREADS],
    /// Slot holding the baton, or -1 when none is running.
    running: isize,
    /// Scheduling-decision counter → offset into the schedule byte source.
    decision: u64,
    /// Slot last granted the baton, so the trace records only real context
    /// switches (not a lone thread re-granting itself).
    last_granted: isize,
    /// Pinned schedule from `BHF_SCHED_SEQUENCE`; empty ⇒ draw from fuzz input.
    seq: [u8; SEQ_CAP],
    seq_len: usize,
    /// `BHF_SCHED_SEQUENCE` parsed exactly once.
    seq_loaded: bool,
}

impl SchedState {
    const fn new() -> Self {
        Self {
            status: [Status::Free; MAX_THREADS],
            tid: [0; MAX_THREADS],
            join_target: [-1; MAX_THREADS],
            pending: [Pending { start: 0, arg: 0 }; MAX_THREADS],
            running: -1,
            decision: 0,
            last_granted: -1,
            seq: [0; SEQ_CAP],
            seq_len: 0,
            seq_loaded: false,
        }
    }
}

static STATE: Mutex<SchedState> = Mutex::new(SchedState::new());
static CV: Condvar = Condvar::new();

thread_local! {
    /// This thread's scheduler slot, or -1 when unregistered.
    static SLOT: Cell<isize> = const { Cell::new(-1) };
    /// Reentrancy guard: true while this thread is inside scheduler logic, so a
    /// pthread hook re-entered from within the scheduler falls through to the OS.
    static IN_SCHED: Cell<bool> = const { Cell::new(false) };
}

const ENV_VAR: &[u8] = b"BHF_SCHED\0";
const SEQ_VAR: &[u8] = b"BHF_SCHED_SEQUENCE\0";

/// Reads `BHF_SCHED` once via libc::getenv (not std::env, which could re-enter the
/// env hook mid-lookup). True iff exactly "1". Cached, like every other env gate.
pub fn active() -> bool {
    static CACHED: AtomicU8 = AtomicU8::new(2); // 0=false, 1=true, 2=uninit
    let cached = CACHED.load(Ordering::Relaxed);
    if cached != 2 {
        return cached == 1;
    }
    let value = unsafe { libc::getenv(ENV_VAR.as_ptr() as *const libc::c_char) };
    let enabled = if value.is_null() {
        false
    } else {
        unsafe { std::ffi::CStr::from_ptr(value) }.to_bytes() == b"1"
    };
    CACHED.store(u8::from(enabled), Ordering::Relaxed);
    enabled
}

/// RAII reentrancy guard for scheduler logic. `None` when already scheduling on
/// this thread (the caller then falls through to the OS primitive).
struct SchedGuard;

impl SchedGuard {
    fn acquire() -> Option<Self> {
        IN_SCHED.with(|f| {
            if f.get() {
                None
            } else {
                f.set(true);
                Some(SchedGuard)
            }
        })
    }
}

impl Drop for SchedGuard {
    fn drop(&mut self) {
        IN_SCHED.with(|f| f.set(false));
    }
}

fn slot_of() -> isize {
    SLOT.with(|s| s.get())
}

fn set_slot(v: isize) {
    SLOT.with(|s| s.set(v));
}

/// Parse a hex nibble, or `None` for a non-hex byte.
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Parse a hex string (ignoring non-hex separators) into `out`, returning the
/// number of bytes written. Odd trailing nibbles are dropped. Pure, so it is unit
/// tested without touching process state.
fn parse_hex_seq(hex: &[u8], out: &mut [u8; SEQ_CAP]) -> usize {
    let mut n = 0usize;
    let mut hi: Option<u8> = None;
    for &b in hex {
        let Some(nib) = hex_nibble(b) else {
            continue;
        };
        match hi.take() {
            None => hi = Some(nib),
            Some(h) => {
                if n >= SEQ_CAP {
                    break;
                }
                out[n] = (h << 4) | nib;
                n += 1;
            }
        }
    }
    n
}

/// The runnable slot to grant, given the decision byte and the number of runnable
/// candidates. Pure; the caller maps the ordinal back to a slot index.
fn pick_ordinal(byte: u8, runnable_count: usize) -> usize {
    debug_assert!(runnable_count > 0);
    (byte as usize) % runnable_count
}

/// Draw the next schedule byte: from the pinned `BHF_SCHED_SEQUENCE` when present,
/// else from the live fuzz input, else a deterministic round-robin fallback so a
/// no-input run still terminates. Advances the decision counter. Called with the
/// state lock held.
fn schedule_byte(state: &mut SchedState) -> u8 {
    if !state.seq_loaded {
        let value = unsafe { libc::getenv(SEQ_VAR.as_ptr() as *const libc::c_char) };
        if !value.is_null() {
            let bytes = unsafe { std::ffi::CStr::from_ptr(value) }.to_bytes();
            state.seq_len = parse_hex_seq(bytes, &mut state.seq);
        }
        state.seq_loaded = true;
    }
    let i = state.decision;
    state.decision = state.decision.wrapping_add(1);
    if state.seq_len > 0 {
        return state.seq[(i as usize) % state.seq_len];
    }
    // Fuzz input: keyed so schedule bytes are a stable window distinct from the
    // target's own resource channels. Fall back to the decision counter (pure
    // round-robin) when there is no live input.
    let mut b = [0u8; 1];
    let got = crate::fakes::fuzz_input::read_keyed(SCHED_INPUT_KEY.wrapping_add(i), &mut b);
    if got == 0 {
        i as u8
    } else {
        b[0]
    }
}

/// Emit a `sched` runtrace event recording a baton grant to `slot`. Logged only on
/// a real context switch. Uses its own `HookGuard` (the scheduler tracks
/// reentrancy separately via `IN_SCHED`, so this acquire succeeds).
fn log_grant(slot: isize, decision: u64) {
    if let Some(_g) = HookGuard::acquire() {
        let mut b = Builder::new(b"sched");
        b.field_i64(b"slot", slot as i64);
        b.field_i64(b"d", decision as i64);
        b.field_i64(b"v", 1);
        b.emit();
    }
}

fn log_event(name: &[u8], slot: isize) {
    if let Some(_g) = HookGuard::acquire() {
        let mut b = Builder::new(name);
        b.field_i64(b"slot", slot as i64);
        b.field_i64(b"v", 1);
        b.emit();
    }
}

/// Find a free slot, or `None` when the managed set is full.
fn find_free(state: &SchedState) -> Option<usize> {
    (0..MAX_THREADS).find(|&i| state.status[i] == Status::Free)
}

/// Register the calling thread if it is not yet known. The FIRST registrant
/// becomes the baton holder (typically the main/harness thread); a later
/// unregistered thread that reaches a scheduling point while another holds the
/// baton is left UNMANAGED (returns false) so the single-baton invariant is never
/// violated by a thread the scheduler did not start.
fn ensure_registered(state: &mut SchedState) -> bool {
    if slot_of() != -1 {
        return true;
    }
    if state.running == -1 {
        let Some(slot) = find_free(state) else {
            return false;
        };
        state.status[slot] = Status::Running;
        state.running = slot as isize;
        state.tid[slot] = unsafe { libc::pthread_self() };
        set_slot(slot as isize);
        true
    } else {
        // Another thread holds the baton and this one was not started by us:
        // do not seize a slot — leave it unmanaged.
        false
    }
}

/// Choose and grant the baton to the next runnable slot, drawing the decision from
/// the schedule source. Sets `running` (or -1 when nothing is runnable) and wakes
/// waiters. Called with the lock held.
fn grant_next(state: &mut SchedState) {
    let mut candidates = [0usize; MAX_THREADS];
    let mut n = 0;
    for (i, st) in state.status.iter().enumerate() {
        if *st == Status::Runnable {
            candidates[n] = i;
            n += 1;
        }
    }
    if n == 0 {
        // Nothing runnable: either the run is finished, or every remaining thread
        // is blocked (a deadlock). Leave the baton unheld; a waiter's GATE_TIMEOUT
        // safety valve breaks any true deadlock.
        state.running = -1;
        CV.notify_all();
        return;
    }
    let byte = schedule_byte(state);
    let chosen = candidates[pick_ordinal(byte, n)];
    state.status[chosen] = Status::Running;
    state.running = chosen as isize;
    if state.last_granted != chosen as isize {
        let decision = state.decision;
        state.last_granted = chosen as isize;
        log_grant(chosen as isize, decision);
    }
    CV.notify_all();
}

/// Block until this thread (`me`) holds the baton, or the safety valve fires.
/// Returns true on a normal grant, false when the GATE_TIMEOUT backstop forced
/// progress (a suspected deadlock). Consumes and returns the guard across waits.
fn wait_for_baton<'a>(
    mut guard: std::sync::MutexGuard<'a, SchedState>,
    me: usize,
) -> (std::sync::MutexGuard<'a, SchedState>, bool) {
    let deadline = Instant::now() + GATE_TIMEOUT;
    loop {
        if guard.running == me as isize {
            return (guard, true);
        }
        let now = Instant::now();
        if now >= deadline {
            // Safety valve: proceed unmanaged rather than wedge forever. The host
            // deadline oracle will still surface the resulting overrun as a finding.
            guard.status[me] = Status::Running;
            guard.running = me as isize;
            drop(guard);
            log_event(b"sched_gate_timeout", me as isize);
            return (STATE.lock().unwrap_or_else(|e| e.into_inner()), false);
        }
        let (g, _timeout) = CV
            .wait_timeout(guard, deadline - now)
            .unwrap_or_else(|e| e.into_inner());
        guard = g;
    }
}

/// A cooperative scheduling point: yield the baton (setting this thread `Runnable`)
/// and block until it is granted again. No-op when scheduling is inactive or the
/// calling thread is unmanaged.
fn schedule_point() {
    let Some(_sg) = SchedGuard::acquire() else {
        return;
    };
    let mut guard = STATE.lock().unwrap_or_else(|e| e.into_inner());
    if !ensure_registered(&mut guard) {
        return;
    }
    let me = slot_of() as usize;
    guard.status[me] = Status::Runnable;
    grant_next(&mut guard);
    let _ = wait_for_baton(guard, me);
}

/// Reset the scheduler at a fuzz-input boundary (persistent harness reuse). Safe
/// to call when inactive. Only clears when no managed thread is mid-run — in a
/// persistent harness `bhf_shim_set_fuzz_input` is called at the top of each
/// iteration, before the target creates its worker threads and after the previous
/// iteration joined them, so the registry is quiescent here.
pub(crate) fn reset_for_input() {
    if !active() {
        return;
    }
    let Some(_sg) = SchedGuard::acquire() else {
        return;
    };
    let mut guard = STATE.lock().unwrap_or_else(|e| e.into_inner());
    for i in 0..MAX_THREADS {
        guard.status[i] = Status::Free;
        guard.tid[i] = 0;
        guard.join_target[i] = -1;
        guard.pending[i] = Pending { start: 0, arg: 0 };
    }
    guard.running = -1;
    guard.decision = 0;
    guard.last_granted = -1;
    // The calling (harness) thread will re-register as the baton holder on its
    // next scheduling interaction; other threads from the prior iteration are done.
    set_slot(-1);
}

/// The trampoline every managed thread runs: register at the pre-allocated slot,
/// wait for the scheduler to grant the baton, run the real start routine, then
/// hand the baton off on exit.
unsafe extern "C" fn sched_trampoline(arg: *mut libc::c_void) -> *mut libc::c_void {
    let slot = arg as usize;
    set_slot(slot as isize);
    // Wait for our initial grant (the creator set us Runnable and kept the baton).
    let (start, real_arg) = {
        let _sg = SchedGuard::acquire();
        let guard = STATE.lock().unwrap_or_else(|e| e.into_inner());
        let (guard, _ok) = wait_for_baton(guard, slot);
        (guard.pending[slot].start, guard.pending[slot].arg)
    };
    let ret = if start != 0 {
        let f: StartRoutine = std::mem::transmute(start);
        f(real_arg as *mut libc::c_void)
    } else {
        std::ptr::null_mut()
    };
    // Exit: mark Finished, unblock any joiner, hand the baton off. This thread does
    // NOT wait afterwards — it is leaving.
    {
        let _sg = SchedGuard::acquire();
        let mut guard = STATE.lock().unwrap_or_else(|e| e.into_inner());
        guard.status[slot] = Status::Finished;
        for t in 0..MAX_THREADS {
            if guard.status[t] == Status::Joining && guard.join_target[t] == slot as isize {
                guard.status[t] = Status::Runnable;
            }
        }
        grant_next(&mut guard);
    }
    ret
}

/// `int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
/// void *(*start_routine)(void *), void *arg)`.
#[no_mangle]
pub unsafe extern "C" fn pthread_create(
    thread: *mut libc::pthread_t,
    attr: *const libc::pthread_attr_t,
    start_routine: Option<StartRoutine>,
    arg: *mut libc::c_void,
) -> libc::c_int {
    let real = REAL_PTHREAD_CREATE.ptr() as *const ();
    let real_is_self = real == pthread_create as *const ();
    // Inactive, unresolved, or reentrant: transparent passthrough (default
    // behavior is byte-for-byte unchanged when BHF_SCHED is unset).
    if !active() || real.is_null() || real_is_self {
        if real.is_null() || real_is_self {
            return libc::EAGAIN;
        }
        let real: PthreadCreateFn = std::mem::transmute(real);
        return real(thread, attr, start_routine, arg);
    }
    let sg = SchedGuard::acquire();
    if sg.is_none() {
        let real: PthreadCreateFn = std::mem::transmute(real);
        return real(thread, attr, start_routine, arg);
    }

    // Reserve a managed slot and stash the real start routine for the trampoline.
    let slot = {
        let mut guard = STATE.lock().unwrap_or_else(|e| e.into_inner());
        ensure_registered(&mut guard); // the creator becomes the baton holder if first
        match find_free(&guard) {
            Some(slot) => {
                guard.status[slot] = Status::Runnable;
                guard.pending[slot] = Pending {
                    start: start_routine.map(|f| f as usize).unwrap_or(0),
                    arg: arg as usize,
                };
                guard.join_target[slot] = -1;
                Some(slot)
            }
            None => None,
        }
    };
    let Some(slot) = slot else {
        // Managed set full: run the thread unmanaged rather than fail.
        let real: PthreadCreateFn = std::mem::transmute(real);
        return real(thread, attr, start_routine, arg);
    };

    // Drop the scheduler guard around the real create so the new OS thread's
    // trampoline (which acquires its own guard) is not blocked by ours.
    drop(sg);
    let real: PthreadCreateFn = std::mem::transmute(real);
    let rc = real(
        thread,
        attr,
        Some(sched_trampoline),
        slot as *mut libc::c_void,
    );
    let mut guard = STATE.lock().unwrap_or_else(|e| e.into_inner());
    if rc == 0 {
        guard.tid[slot] = *thread;
        log_event(b"sched_create", slot as isize);
    } else {
        // Creation failed: the trampoline will never run, so release the slot or a
        // later grant would wait on a thread that does not exist.
        guard.status[slot] = Status::Free;
        guard.pending[slot] = Pending { start: 0, arg: 0 };
    }
    rc
}

/// `int pthread_join(pthread_t thread, void **retval)`.
#[no_mangle]
pub unsafe extern "C" fn pthread_join(
    thread: libc::pthread_t,
    retval: *mut *mut libc::c_void,
) -> libc::c_int {
    let real = REAL_PTHREAD_JOIN.ptr() as *const ();
    let real_is_self = real == pthread_join as *const ();
    if !active() || real.is_null() || real_is_self {
        if real.is_null() || real_is_self {
            return libc::ESRCH;
        }
        let real: PthreadJoinFn = std::mem::transmute(real);
        return real(thread, retval);
    }
    let sg = SchedGuard::acquire();
    if sg.is_none() {
        let real: PthreadJoinFn = std::mem::transmute(real);
        return real(thread, retval);
    }

    let target = {
        let mut guard = STATE.lock().unwrap_or_else(|e| e.into_inner());
        ensure_registered(&mut guard);
        (0..MAX_THREADS).find(|&i| guard.status[i] != Status::Free && guard.tid[i] == thread)
    };
    let Some(target) = target else {
        // Joining a thread the scheduler does not manage: just do the real join.
        drop(sg);
        let real: PthreadJoinFn = std::mem::transmute(real);
        return real(thread, retval);
    };

    // Cooperative join: release the baton (as `Joining`, so we are not schedulable)
    // until the joinee finishes. A `Joining` slot is only made Runnable again by the
    // joinee's exit handoff, so the join can neither starve the scheduler nor be
    // re-granted the baton prematurely.
    let me = slot_of() as usize;
    let mut guard = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let mut guarded_steps = 0usize;
    while guard.status[target] != Status::Finished {
        guard.status[me] = Status::Joining;
        guard.join_target[me] = target as isize;
        grant_next(&mut guard);
        let (g, ok) = wait_for_baton(guard, me);
        guard = g;
        // Safety valve tripped (suspected deadlock) or too many spins: stop
        // cooperating and fall through to a real join.
        guarded_steps += 1;
        if !ok || guarded_steps > MAX_THREADS * 4 {
            break;
        }
    }
    guard.join_target[me] = -1;
    drop(guard);
    drop(sg);

    let real: PthreadJoinFn = std::mem::transmute(real);
    real(thread, retval)
}

/// Explicit cooperative scheduling point for the target / a generated harness.
/// A no-op unless `BHF_SCHED` is active and the calling thread is managed.
#[no_mangle]
pub unsafe extern "C" fn bhf_sched_yield() {
    if !active() {
        return;
    }
    schedule_point();
}

/// `--list-fakes` plugin entry for the cooperative scheduler.
pub struct Sched;

impl crate::sdk::FakeResource for Sched {
    fn name(&self) -> &'static str {
        "sched"
    }
    fn intercepts(&self) -> &'static [&'static [u8]] {
        &[b"pthread_create\0", b"pthread_join\0", b"bhf_sched_yield\0"]
    }
    fn is_enabled(&self) -> bool {
        active()
    }
    fn describe(&self) -> &'static str {
        "cooperative schedule-perturbation: drive thread interleavings from the fuzz input (or a pinned BHF_SCHED_SEQUENCE) via pthread_create/join gates and bhf_sched_yield, so a race reachable only under one ordering is searchable and replayable"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pure scheduling-decision math: no real threads (a live #[no_mangle]
    // pthread_create in the test binary must never be driven with real threads
    // here, since it would intercept the test runner's own threads). The full
    // cooperative run is covered by the clang+pthread integration test in
    // tests/schedule_perturbation.rs.

    #[test]
    fn pick_ordinal_is_input_addressable_and_in_range() {
        // Every candidate is selectable by some byte, and the pick never escapes
        // the runnable set — the core of "the interleaving is a function of input".
        assert_eq!(pick_ordinal(0, 2), 0);
        assert_eq!(pick_ordinal(1, 2), 1);
        assert_eq!(pick_ordinal(2, 2), 0);
        assert_eq!(pick_ordinal(255, 3), 255 % 3);
        for n in 1..=MAX_THREADS {
            for byte in 0u8..=255 {
                assert!(pick_ordinal(byte, n) < n);
            }
        }
    }

    #[test]
    fn parse_hex_seq_decodes_pairs_and_ignores_separators() {
        let mut out = [0u8; SEQ_CAP];
        // The pinned sequence "00 01" selects thread A then thread B in the
        // 2-thread fixture; separators are tolerated for readability.
        let n = parse_hex_seq(b"00:01", &mut out);
        assert_eq!(n, 2);
        assert_eq!(&out[..2], &[0x00, 0x01]);

        let n = parse_hex_seq(b"deadBEEF", &mut out);
        assert_eq!(n, 4);
        assert_eq!(&out[..4], &[0xde, 0xad, 0xbe, 0xef]);

        // A trailing odd nibble is dropped, not misdecoded.
        let n = parse_hex_seq(b"ab c", &mut out);
        assert_eq!(n, 1);
        assert_eq!(out[0], 0xab);
    }

    #[test]
    fn parse_hex_seq_is_bounded_by_capacity() {
        let mut out = [0u8; SEQ_CAP];
        let hex = vec![b'a'; SEQ_CAP * 4]; // far more pairs than fit
        let n = parse_hex_seq(&hex, &mut out);
        assert_eq!(n, SEQ_CAP, "never writes past the fixed buffer");
    }

    #[test]
    fn empty_or_non_hex_sequence_decodes_to_nothing() {
        let mut out = [0u8; SEQ_CAP];
        assert_eq!(parse_hex_seq(b"", &mut out), 0);
        assert_eq!(parse_hex_seq(b"----", &mut out), 0);
    }
}
