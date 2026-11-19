// SPDX-License-Identifier: Apache-2.0

//! Determinism plugin: when `BHF_FAKE_DETERMINISM=1` is set, the randomness
//! sources return a fixed, reproducible stream.
//!
//! Determinism is the premise of the whole replay and env-capsule story — a
//! saved input is a reproducer only if the second run makes the same decisions
//! as the first. Nothing in the shim intercepted randomness, so any target that
//! seeds a hash, salts a table or mints an id from `rand`/`getrandom` could take
//! a different path on replay, and a crash found once might never reproduce.
//!
//! The stream is xorshift64*, reset from the current fuzz input (and mixed with
//! `BHF_RUNTRACE_SEED` when present) at every harness iteration. Resetting is
//! essential for the persistent fork-server: a process-global stream would make
//! input N observe RNG state left by inputs 0..N-1, while standalone replay would
//! observe the initial state and fail to reproduce. `srand` still honours the
//! target's own seed after the per-input reset.
//!
//! The clock has its own gate, `BHF_FAKE_CLOCK=1` (#342). With it,
//! `clock_gettime`, `gettimeofday`, `time`, `clock` and `timespec_get` read a
//! virtual clock: it starts at a fixed instant (2026-01-01T00:00:00Z for the
//! wall clocks, 1000 s for the monotonic ones, 0 for the CPU clocks), every
//! read advances it [`CLOCK_TICK_NS`], and every input the harness publishes
//! starts it over. So an input sees the same times on every run, and a loop
//! waiting for a deadline still reaches it. The shim's own reads (the
//! scheduler's safety valve) keep the real clock. An absolute-deadline wait
//! (`clock_nanosleep` with `TIMER_ABSTIME`, `pthread_cond_timedwait`,
//! `pthread_cond_clockwait`, `sem_timedwait`, `sem_clockwait`) on a deadline
//! taken from the virtual clock waits on the real clock for as long as the
//! deadline was ahead of the virtual time.
//!
//! An earlier clock fake broke targets: its pass-through resolved the real
//! symbols with a lazy `dlsym` inside the hook, which could run under the
//! loader lock, and targets built and were then never entered. These hooks
//! never resolve anything when called. A constructor resolves the real
//! functions eagerly, as the shim loads; a hook called before that (from an
//! earlier library constructor) makes the system call itself. The clock gate
//! is read from `environ`, not through the shim's `getenv` hook, for the same
//! reason. A runtime in the process that reads the clock itself (a
//! sanitizer's allocator) advances it too.
//!
//! Allocation discipline matches the other hook modules: no malloc / Box / Vec
//! / String inside the hooks, and the env gate is read once.

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::missing_transmute_annotations)]

use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicU8, Ordering};

use crate::jsonl::Builder;
use crate::reentrancy::HookGuard;
use crate::sdk::FakeResource;

use crate::dlsym::ResolvedFn;

// Resolved ONCE into statics, like every other hook module. Building a
// `ResolvedFn` as a temporary per call re-resolves on every invocation, and
// nothing then guards against the lookup returning THIS symbol — which is an
// unbounded recursion that kills the harness before it reaches the target.
static REAL_RAND: ResolvedFn = ResolvedFn::new(b"rand\0");
static REAL_RANDOM: ResolvedFn = ResolvedFn::new(b"random\0");
static REAL_SRAND: ResolvedFn = ResolvedFn::new(b"srand\0");
static REAL_GETRANDOM: ResolvedFn = ResolvedFn::new(b"getrandom\0");

/// The real implementation, or null when the lookup found only OURSELVES —
/// calling that would recurse forever.
fn real_of(resolved: &ResolvedFn, hook: *const ()) -> *const () {
    let real = resolved.ptr() as *const ();
    if real.is_null() || real == hook {
        return core::ptr::null();
    }
    real
}

const ENV_VAR: &[u8] = b"BHF_FAKE_DETERMINISM\0";
const SEED_VAR: &[u8] = b"BHF_RUNTRACE_SEED\0";

static RNG_STATE: AtomicU64 = AtomicU64::new(0);

/// Reads `BHF_FAKE_DETERMINISM` once via libc::getenv. True iff exactly "1".
pub fn env_enabled() -> bool {
    static CACHED: AtomicU8 = AtomicU8::new(2); // 0=false, 1=true, 2=uninit
    let cached = CACHED.load(Ordering::Relaxed);
    if cached != 2 {
        return cached == 1;
    }
    let value = unsafe { libc::getenv(ENV_VAR.as_ptr() as *const libc::c_char) };
    let enabled = if value.is_null() {
        false
    } else {
        crate::reentrancy::bytes_eq(unsafe { std::ffi::CStr::from_ptr(value) }.to_bytes(), b"1")
    };
    CACHED.store(u8::from(enabled), Ordering::Relaxed);
    enabled
}

/// xorshift64*, seeded from `BHF_RUNTRACE_SEED` when set. Never returns a
/// zero state, which would make the stream degenerate to all zeroes.
fn next_random() -> u64 {
    let mut state = RNG_STATE.load(Ordering::Relaxed);
    if state == 0 {
        state = seed_from_env();
        if state == 0 {
            state = 0x9E37_79B9_7F4A_7C15;
        }
    }
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    RNG_STATE.store(state, Ordering::Relaxed);
    state.wrapping_mul(0x2545_F491_4F6C_DD1D)
}

fn seed_from_env() -> u64 {
    let value = unsafe { libc::getenv(SEED_VAR.as_ptr() as *const libc::c_char) };
    if value.is_null() {
        return 0;
    }
    let bytes = unsafe { std::ffi::CStr::from_ptr(value) }.to_bytes();
    // Hand-rolled parse: `str::parse` would allocate on error paths in some
    // std configurations, and this runs inside an interposer.
    let mut acc: u64 = 0;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return 0;
        }
        acc = acc.wrapping_mul(10).wrapping_add(u64::from(byte - b'0'));
    }
    acc
}

/// Reset the deterministic stream at an input boundary. FNV-1a is used only as
/// a fast stable mixer, not for security; the goal is that the same testcase
/// observes the same pseudo-random decisions regardless of corpus order or how
/// many earlier iterations ran in the persistent process.
pub(crate) fn reset_for_input(input: &[u8]) {
    if clock_enabled() {
        CLOCK_READS.store(0, Ordering::Relaxed);
    }
    if !env_enabled() {
        return;
    }
    RNG_STATE.store(input_seed(input, seed_from_env()), Ordering::Relaxed);
}

fn input_seed(input: &[u8], campaign_seed: u64) -> u64 {
    let mut state = 0xcbf2_9ce4_8422_2325u64 ^ campaign_seed;
    for byte in input {
        state ^= u64::from(*byte);
        state = state.wrapping_mul(0x0000_0100_0000_01b3);
    }
    // Include length so an empty input and a hypothetical sequence of bytes
    // that returns to the offset basis cannot share the trivial seed.
    state ^= input.len() as u64;
    if state == 0 {
        state = 0x9E37_79B9_7F4A_7C15;
    }
    state
}

fn emit_audit(symbol: &[u8], value: i64) {
    if let Some(_g) = HookGuard::acquire() {
        let mut b = Builder::new(b"determinism");
        b.field_str(b"f", symbol);
        b.field_i64(b"v", value);
        b.emit();
    }
}

pub struct Determinism;

impl FakeResource for Determinism {
    fn name(&self) -> &'static str {
        "determinism"
    }
    fn intercepts(&self) -> &'static [&'static [u8]] {
        &[b"rand\0", b"srand\0", b"random\0", b"getrandom\0"]
    }
    fn is_enabled(&self) -> bool {
        env_enabled()
    }
    fn describe(&self) -> &'static str {
        "deterministic randomness so a saved input replays identically"
    }
}

#[no_mangle]
pub unsafe extern "C" fn rand() -> libc::c_int {
    if !env_enabled() {
        let real = real_of(&REAL_RAND, rand as *const ());
        if real.is_null() {
            return 0;
        }
        let real: unsafe extern "C" fn() -> libc::c_int = std::mem::transmute(real);
        return real();
    }
    // RAND_MAX is 2^31-1 on glibc; keep the result in that range.
    (next_random() >> 33) as libc::c_int
}

#[no_mangle]
pub unsafe extern "C" fn random() -> libc::c_long {
    if !env_enabled() {
        let real = real_of(&REAL_RANDOM, random as *const ());
        if real.is_null() {
            return 0;
        }
        let real: unsafe extern "C" fn() -> libc::c_long = std::mem::transmute(real);
        return real();
    }
    (next_random() >> 33) as libc::c_long
}

#[no_mangle]
pub unsafe extern "C" fn srand(seed: libc::c_uint) {
    if !env_enabled() {
        let real = real_of(&REAL_SRAND, srand as *const ());
        if !real.is_null() {
            let real: unsafe extern "C" fn(libc::c_uint) = std::mem::transmute(real);
            real(seed);
        }
        return;
    }
    // Honour the target's own seeding so a program that seeds deterministically
    // keeps its intended stream; a zero seed would stall xorshift.
    RNG_STATE.store(
        if seed == 0 { 1 } else { u64::from(seed) },
        Ordering::Relaxed,
    );
}

#[no_mangle]
pub unsafe extern "C" fn getrandom(
    buf: *mut libc::c_void,
    buflen: libc::size_t,
    flags: libc::c_uint,
) -> libc::ssize_t {
    if !env_enabled() {
        let real = real_of(&REAL_GETRANDOM, getrandom as *const ());
        if real.is_null() {
            return -1;
        }
        let real: unsafe extern "C" fn(
            *mut libc::c_void,
            libc::size_t,
            libc::c_uint,
        ) -> libc::ssize_t = std::mem::transmute(real);
        return real(buf, buflen, flags);
    }
    if buf.is_null() {
        return -1;
    }
    let out = buf as *mut u8;
    let mut written = 0usize;
    while written < buflen {
        let chunk = next_random().to_le_bytes();
        let take = core::cmp::min(chunk.len(), buflen - written);
        core::ptr::copy_nonoverlapping(chunk.as_ptr(), out.add(written), take);
        written += take;
    }
    emit_audit(b"getrandom", written as i64);
    written as libc::ssize_t
}

// ---------------------------------------------------------------------------
// Virtual clock (#342)
// ---------------------------------------------------------------------------

/// The gate's entry in the environment, up to its value.
const CLOCK_ENV_PREFIX: &[u8] = b"BHF_FAKE_CLOCK=";
/// How far the virtual clock advances per read.
pub const CLOCK_TICK_NS: u64 = 1_000_000;
/// Where the wall clocks start: 2026-01-01T00:00:00Z.
const CLOCK_EPOCH_SECS: u64 = 1_767_225_600;
/// Where the monotonic clocks start.
const CLOCK_BOOT_SECS: u64 = 1_000;
const NANOS_PER_SEC: u64 = 1_000_000_000;

/// Reads of the virtual clock since the current input was published.
static CLOCK_READS: AtomicU64 = AtomicU64::new(0);

extern "C" {
    static environ: *const *const libc::c_char;
}

/// Whether `BHF_FAKE_CLOCK` is exactly "1", read once.
///
/// It reads `environ` itself rather than calling `getenv`: a sanitizer's
/// allocator reads the clock from inside `free`, even inside glibc's
/// `dlerror` bookkeeping, and `getenv` is the shim's own hook, whose first
/// call resolves the real one with `dlvsym` and so re-entered that
/// bookkeeping (a double free). No call here reaches a hook.
pub fn clock_enabled() -> bool {
    static CACHED: AtomicU8 = AtomicU8::new(2); // 0=false, 1=true, 2=uninit
    let cached = CACHED.load(Ordering::Relaxed);
    if cached != 2 {
        return cached == 1;
    }
    // Before libc sets `environ` nothing is known yet: not cached.
    let Some(enabled) = (unsafe { environ_value_is(CLOCK_ENV_PREFIX, b"1") }) else {
        return false;
    };
    CACHED.store(u8::from(enabled), Ordering::Relaxed);
    enabled
}

/// Whether the first `environ` entry starting with `prefix` (`NAME=`) has
/// the value `value`; `None` while `environ` is unset.
unsafe fn environ_value_is(prefix: &[u8], value: &[u8]) -> Option<bool> {
    let mut entry = core::ptr::addr_of!(environ).read();
    if entry.is_null() {
        return None;
    }
    while !(*entry).is_null() {
        let text = *entry as *const u8;
        if (0..prefix.len()).all(|i| *text.add(i) == prefix[i]) {
            let rest = text.add(prefix.len());
            return Some(
                (0..value.len()).all(|i| *rest.add(i) == value[i]) && *rest.add(value.len()) == 0,
            );
        }
        entry = entry.add(1);
    }
    Some(false)
}

/// Set once [`resolve_clock_at_load`] has run: from then on the shim's
/// thread-local state is safe to read from a clock hook.
static CLOCK_LOADED: AtomicBool = AtomicBool::new(false);

/// Whether this read is the target's and the fake serves it: the gate is on
/// and the shim's own code (its scheduler's waits) is not the caller. The
/// gate is read first, so a run without it touches no thread-local state.
fn clock_faked() -> bool {
    clock_enabled() && !(CLOCK_LOADED.load(Ordering::Relaxed) && crate::reentrancy::in_shim())
}

/// Where the virtual `clock` starts, or `None` for a clock the fake does not
/// serve (another process's CPU clock, a POSIX clock from a descriptor).
fn clock_base(clock: libc::clockid_t) -> Option<u64> {
    Some(match clock {
        libc::CLOCK_REALTIME
        | libc::CLOCK_REALTIME_COARSE
        | libc::CLOCK_REALTIME_ALARM
        | libc::CLOCK_TAI => CLOCK_EPOCH_SECS * NANOS_PER_SEC,
        libc::CLOCK_MONOTONIC
        | libc::CLOCK_MONOTONIC_RAW
        | libc::CLOCK_MONOTONIC_COARSE
        | libc::CLOCK_BOOTTIME
        | libc::CLOCK_BOOTTIME_ALARM => CLOCK_BOOT_SECS * NANOS_PER_SEC,
        libc::CLOCK_PROCESS_CPUTIME_ID | libc::CLOCK_THREAD_CPUTIME_ID => 0,
        _ => return None,
    })
}

/// The next virtual reading for `clock`, or `None` for a clock the fake does
/// not serve.
fn virtual_time(clock: libc::clockid_t) -> Option<u64> {
    let base = clock_base(clock)?;
    let read = CLOCK_READS.fetch_add(1, Ordering::Relaxed);
    Some(base + read.wrapping_mul(CLOCK_TICK_NS))
}

/// The virtual reading for `clock` now, without advancing it.
fn virtual_now(clock: libc::clockid_t) -> Option<u64> {
    let base = clock_base(clock)?;
    Some(
        base + CLOCK_READS
            .load(Ordering::Relaxed)
            .wrapping_mul(CLOCK_TICK_NS),
    )
}

fn timespec_of(nanos: u64) -> libc::timespec {
    libc::timespec {
        tv_sec: (nanos / NANOS_PER_SEC) as libc::time_t,
        tv_nsec: (nanos % NANOS_PER_SEC) as libc::c_long,
    }
}

// The real functions, resolved by `resolve_clock_at_load` and never inside a
// hook. Null until then, or when the lookup found only this shim.
static REAL_CLOCK_GETTIME: AtomicPtr<libc::c_void> = AtomicPtr::new(core::ptr::null_mut());
static REAL_GETTIMEOFDAY: AtomicPtr<libc::c_void> = AtomicPtr::new(core::ptr::null_mut());
static REAL_TIME: AtomicPtr<libc::c_void> = AtomicPtr::new(core::ptr::null_mut());
static REAL_CLOCK: AtomicPtr<libc::c_void> = AtomicPtr::new(core::ptr::null_mut());
static REAL_TIMESPEC_GET: AtomicPtr<libc::c_void> = AtomicPtr::new(core::ptr::null_mut());
static REAL_CLOCK_NANOSLEEP: AtomicPtr<libc::c_void> = AtomicPtr::new(core::ptr::null_mut());
static REAL_COND_TIMEDWAIT: AtomicPtr<libc::c_void> = AtomicPtr::new(core::ptr::null_mut());
static REAL_COND_CLOCKWAIT: AtomicPtr<libc::c_void> = AtomicPtr::new(core::ptr::null_mut());
static REAL_SEM_TIMEDWAIT: AtomicPtr<libc::c_void> = AtomicPtr::new(core::ptr::null_mut());
static REAL_SEM_CLOCKWAIT: AtomicPtr<libc::c_void> = AtomicPtr::new(core::ptr::null_mut());

#[used]
#[link_section = ".init_array"]
static RESOLVE_CLOCK_AT_LOAD: extern "C" fn() = resolve_clock_at_load;

extern "C" fn resolve_clock_at_load() {
    clock_enabled();
    let slots: [(&AtomicPtr<libc::c_void>, &core::ffi::CStr, *const ()); 5] = [
        (
            &REAL_CLOCK_GETTIME,
            c"clock_gettime",
            clock_gettime as *const (),
        ),
        (
            &REAL_GETTIMEOFDAY,
            c"gettimeofday",
            gettimeofday as *const (),
        ),
        (&REAL_TIME, c"time", time as *const ()),
        (&REAL_CLOCK, c"clock", clock as *const ()),
        (
            &REAL_TIMESPEC_GET,
            c"timespec_get",
            timespec_get as *const (),
        ),
    ];
    for (slot, name, hook) in slots {
        let real = unsafe { crate::dlsym::bhf_shim_resolve_next(name.as_ptr()) };
        if !real.is_null() && real as *const () != hook {
            slot.store(real, Ordering::Relaxed);
        }
    }
    for wait in WAITS {
        unsafe { wait.real() };
    }
    CLOCK_LOADED.store(true, Ordering::Relaxed);
}

/// A real absolute-deadline wait, resolved as the shim loads (or, for a call
/// from a library constructor that runs first, on that call: unlike a clock
/// read, a wait is never made from inside the loader's or an allocator's
/// bookkeeping).
struct RealWait {
    slot: &'static AtomicPtr<libc::c_void>,
    name: &'static core::ffi::CStr,
    /// The symbol version to bind when the base version is an older,
    /// different implementation (glibc's pre-2.3.2 condition variables).
    version: Option<&'static core::ffi::CStr>,
    hook: fn() -> *const (),
}

impl RealWait {
    unsafe fn real(&self) -> *mut libc::c_void {
        let cached = self.slot.load(Ordering::Relaxed);
        if !cached.is_null() {
            return cached;
        }
        let real = match self.version {
            Some(version) => libc::dlvsym(libc::RTLD_NEXT, self.name.as_ptr(), version.as_ptr()),
            None => crate::dlsym::bhf_shim_resolve_next(self.name.as_ptr()),
        };
        if real.is_null() || real as *const () == (self.hook)() {
            return core::ptr::null_mut();
        }
        self.slot.store(real, Ordering::Relaxed);
        real
    }
}

#[cfg(target_arch = "x86_64")]
const COND_TIMEDWAIT_VERSION: Option<&core::ffi::CStr> = Some(c"GLIBC_2.3.2");
#[cfg(not(target_arch = "x86_64"))]
const COND_TIMEDWAIT_VERSION: Option<&core::ffi::CStr> = None;

static CLOCK_NANOSLEEP_WAIT: RealWait = RealWait {
    slot: &REAL_CLOCK_NANOSLEEP,
    name: c"clock_nanosleep",
    version: None,
    hook: || clock_nanosleep as *const (),
};
static COND_TIMEDWAIT: RealWait = RealWait {
    slot: &REAL_COND_TIMEDWAIT,
    name: c"pthread_cond_timedwait",
    version: COND_TIMEDWAIT_VERSION,
    hook: || pthread_cond_timedwait as *const (),
};
static COND_CLOCKWAIT: RealWait = RealWait {
    slot: &REAL_COND_CLOCKWAIT,
    name: c"pthread_cond_clockwait",
    version: None,
    hook: || pthread_cond_clockwait as *const (),
};
static SEM_TIMEDWAIT: RealWait = RealWait {
    slot: &REAL_SEM_TIMEDWAIT,
    name: c"sem_timedwait",
    version: None,
    hook: || sem_timedwait as *const (),
};
static SEM_CLOCKWAIT: RealWait = RealWait {
    slot: &REAL_SEM_CLOCKWAIT,
    name: c"sem_clockwait",
    version: None,
    hook: || sem_clockwait as *const (),
};
static WAITS: [&RealWait; 5] = [
    &CLOCK_NANOSLEEP_WAIT,
    &COND_TIMEDWAIT,
    &COND_CLOCKWAIT,
    &SEM_TIMEDWAIT,
    &SEM_CLOCKWAIT,
];

/// `clock_gettime` through the kernel, for a read before the real function
/// is resolved.
unsafe fn sys_clock_gettime(clock: libc::clockid_t, tp: *mut libc::timespec) -> libc::c_int {
    libc::syscall(libc::SYS_clock_gettime, clock, tp) as libc::c_int
}

unsafe fn real_clock_gettime(clock: libc::clockid_t, tp: *mut libc::timespec) -> libc::c_int {
    let real = REAL_CLOCK_GETTIME.load(Ordering::Relaxed);
    if real.is_null() {
        return sys_clock_gettime(clock, tp);
    }
    let real: unsafe extern "C" fn(libc::clockid_t, *mut libc::timespec) -> libc::c_int =
        std::mem::transmute(real);
    real(clock, tp)
}

pub struct Clock;

impl FakeResource for Clock {
    fn name(&self) -> &'static str {
        "clock"
    }
    fn intercepts(&self) -> &'static [&'static [u8]] {
        &[
            b"clock_gettime\0",
            b"gettimeofday\0",
            b"time\0",
            b"clock\0",
            b"timespec_get\0",
            b"clock_nanosleep\0",
            b"pthread_cond_timedwait\0",
            b"pthread_cond_clockwait\0",
            b"sem_timedwait\0",
            b"sem_clockwait\0",
        ]
    }
    fn is_enabled(&self) -> bool {
        clock_enabled()
    }
    fn describe(&self) -> &'static str {
        "a virtual clock that each input starts over, so the same input sees the same times"
    }
}

#[no_mangle]
pub unsafe extern "C" fn clock_gettime(
    clock: libc::clockid_t,
    tp: *mut libc::timespec,
) -> libc::c_int {
    if clock_faked() {
        if let Some(nanos) = virtual_time(clock) {
            if tp.is_null() {
                set_errno(libc::EFAULT);
                return -1;
            }
            *tp = timespec_of(nanos);
            return 0;
        }
    }
    real_clock_gettime(clock, tp)
}

#[no_mangle]
pub unsafe extern "C" fn gettimeofday(
    tv: *mut libc::timeval,
    tz: *mut libc::c_void,
) -> libc::c_int {
    if clock_faked() {
        let nanos = virtual_time(libc::CLOCK_REALTIME).unwrap_or_default();
        if !tv.is_null() {
            *tv = libc::timeval {
                tv_sec: (nanos / NANOS_PER_SEC) as libc::time_t,
                tv_usec: ((nanos % NANOS_PER_SEC) / 1_000) as libc::suseconds_t,
            };
        }
        if !tz.is_null() {
            core::ptr::write_bytes(tz as *mut u8, 0, 2 * core::mem::size_of::<libc::c_int>());
        }
        return 0;
    }
    let real = REAL_GETTIMEOFDAY.load(Ordering::Relaxed);
    if real.is_null() {
        return libc::syscall(libc::SYS_gettimeofday, tv, tz) as libc::c_int;
    }
    let real: unsafe extern "C" fn(*mut libc::timeval, *mut libc::c_void) -> libc::c_int =
        std::mem::transmute(real);
    real(tv, tz)
}

#[no_mangle]
pub unsafe extern "C" fn time(out: *mut libc::time_t) -> libc::time_t {
    let now = if clock_faked() {
        (virtual_time(libc::CLOCK_REALTIME).unwrap_or_default() / NANOS_PER_SEC) as libc::time_t
    } else {
        let real = REAL_TIME.load(Ordering::Relaxed);
        if !real.is_null() {
            let real: unsafe extern "C" fn(*mut libc::time_t) -> libc::time_t =
                std::mem::transmute(real);
            return real(out);
        }
        let mut ts = timespec_of(0);
        if sys_clock_gettime(libc::CLOCK_REALTIME, &mut ts) != 0 {
            return -1;
        }
        ts.tv_sec
    };
    if !out.is_null() {
        *out = now;
    }
    now
}

#[no_mangle]
pub unsafe extern "C" fn clock() -> libc::clock_t {
    // POSIX fixes CLOCKS_PER_SEC at one million.
    let nanos = if clock_faked() {
        virtual_time(libc::CLOCK_PROCESS_CPUTIME_ID).unwrap_or_default()
    } else {
        let real = REAL_CLOCK.load(Ordering::Relaxed);
        if !real.is_null() {
            let real: unsafe extern "C" fn() -> libc::clock_t = std::mem::transmute(real);
            return real();
        }
        let mut ts = timespec_of(0);
        if sys_clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut ts) != 0 {
            return -1;
        }
        ts.tv_sec as u64 * NANOS_PER_SEC + ts.tv_nsec as u64
    };
    (nanos / 1_000) as libc::clock_t
}

/// C11 `TIME_UTC`.
const TIME_UTC: libc::c_int = 1;

#[no_mangle]
pub unsafe extern "C" fn timespec_get(ts: *mut libc::timespec, base: libc::c_int) -> libc::c_int {
    if base == TIME_UTC && clock_faked() {
        if ts.is_null() {
            return 0;
        }
        *ts = timespec_of(virtual_time(libc::CLOCK_REALTIME).unwrap_or_default());
        return base;
    }
    let real = REAL_TIMESPEC_GET.load(Ordering::Relaxed);
    if !real.is_null() {
        let real: unsafe extern "C" fn(*mut libc::timespec, libc::c_int) -> libc::c_int =
            std::mem::transmute(real);
        return real(ts, base);
    }
    if base == TIME_UTC && !ts.is_null() && sys_clock_gettime(libc::CLOCK_REALTIME, ts) == 0 {
        return base;
    }
    0
}

// Absolute-deadline waits. A target computes the deadline from the virtual
// clock (a monotonic one starts at 1000 s, the wall clock on 2026-01-01), but
// the kernel compares it with its real clock: on a host up for days the wait
// would end at once, and on one booted less than 1000 s ago it would sleep
// until the real uptime caught up. So a wait on a virtual deadline waits on
// the real clock as long as the deadline is ahead of the virtual time, and
// one already past ends at once, as it would have.

/// `TIMER_ABSTIME` for `clock_nanosleep`.
const TIMER_ABSTIME: libc::c_int = 1;

/// The real deadline on `clock` for `deadline`, which the target computed
/// from the virtual clock; `None` when the wait is not on a virtual deadline
/// (the fake is off, the caller is the shim, the clock is not served, or the
/// deadline is malformed, which the real call reports).
unsafe fn real_deadline(
    clock: libc::clockid_t,
    deadline: *const libc::timespec,
) -> Option<libc::timespec> {
    if deadline.is_null() || !clock_faked() {
        return None;
    }
    let virtual_now = virtual_now(clock)?;
    let deadline = &*deadline;
    if deadline.tv_sec < 0 || !(0..NANOS_PER_SEC as libc::c_long).contains(&deadline.tv_nsec) {
        return None;
    }
    let wanted = (deadline.tv_sec as u64)
        .saturating_mul(NANOS_PER_SEC)
        .saturating_add(deadline.tv_nsec as u64);
    let ahead = wanted.saturating_sub(virtual_now);
    let mut now = timespec_of(0);
    if real_clock_gettime(clock, &mut now) != 0 {
        return None;
    }
    let real_now = now.tv_sec as u64 * NANOS_PER_SEC + now.tv_nsec as u64;
    Some(timespec_of(real_now.saturating_add(ahead)))
}

/// The clock a `pthread_cond_timedwait` deadline was read from. The condition
/// variable's clock (`pthread_condattr_setclock`) is not visible here, but
/// the virtual wall clock and the virtual monotonic one lie decades apart.
fn deadline_clock(deadline: *const libc::timespec) -> libc::clockid_t {
    let wall = !deadline.is_null() && unsafe { (*deadline).tv_sec } as u64 >= CLOCK_EPOCH_SECS / 2;
    if wall {
        libc::CLOCK_REALTIME
    } else {
        libc::CLOCK_MONOTONIC
    }
}

#[no_mangle]
pub unsafe extern "C" fn clock_nanosleep(
    clock: libc::clockid_t,
    flags: libc::c_int,
    request: *const libc::timespec,
    remain: *mut libc::timespec,
) -> libc::c_int {
    let translated = if flags & TIMER_ABSTIME != 0 {
        real_deadline(clock, request)
    } else {
        None
    };
    let request = translated
        .as_ref()
        .map_or(request, |deadline| deadline as *const libc::timespec);
    let real = CLOCK_NANOSLEEP_WAIT.real();
    if real.is_null() {
        let rc = libc::syscall(libc::SYS_clock_nanosleep, clock, flags, request, remain);
        return if rc == 0 {
            0
        } else {
            *libc::__errno_location()
        };
    }
    let real: unsafe extern "C" fn(
        libc::clockid_t,
        libc::c_int,
        *const libc::timespec,
        *mut libc::timespec,
    ) -> libc::c_int = std::mem::transmute(real);
    real(clock, flags, request, remain)
}

#[no_mangle]
pub unsafe extern "C" fn pthread_cond_timedwait(
    cond: *mut libc::pthread_cond_t,
    mutex: *mut libc::pthread_mutex_t,
    deadline: *const libc::timespec,
) -> libc::c_int {
    let translated = real_deadline(deadline_clock(deadline), deadline);
    let deadline = translated
        .as_ref()
        .map_or(deadline, |deadline| deadline as *const libc::timespec);
    let real = COND_TIMEDWAIT.real();
    if real.is_null() {
        return libc::ENOSYS;
    }
    let real: unsafe extern "C" fn(
        *mut libc::pthread_cond_t,
        *mut libc::pthread_mutex_t,
        *const libc::timespec,
    ) -> libc::c_int = std::mem::transmute(real);
    real(cond, mutex, deadline)
}

#[no_mangle]
pub unsafe extern "C" fn pthread_cond_clockwait(
    cond: *mut libc::pthread_cond_t,
    mutex: *mut libc::pthread_mutex_t,
    clock: libc::clockid_t,
    deadline: *const libc::timespec,
) -> libc::c_int {
    let translated = real_deadline(clock, deadline);
    let deadline = translated
        .as_ref()
        .map_or(deadline, |deadline| deadline as *const libc::timespec);
    let real = COND_CLOCKWAIT.real();
    if real.is_null() {
        return libc::ENOSYS;
    }
    let real: unsafe extern "C" fn(
        *mut libc::pthread_cond_t,
        *mut libc::pthread_mutex_t,
        libc::clockid_t,
        *const libc::timespec,
    ) -> libc::c_int = std::mem::transmute(real);
    real(cond, mutex, clock, deadline)
}

#[no_mangle]
pub unsafe extern "C" fn sem_timedwait(
    sem: *mut libc::sem_t,
    deadline: *const libc::timespec,
) -> libc::c_int {
    let translated = real_deadline(libc::CLOCK_REALTIME, deadline);
    let deadline = translated
        .as_ref()
        .map_or(deadline, |deadline| deadline as *const libc::timespec);
    let real = SEM_TIMEDWAIT.real();
    if real.is_null() {
        set_errno(libc::ENOSYS);
        return -1;
    }
    let real: unsafe extern "C" fn(*mut libc::sem_t, *const libc::timespec) -> libc::c_int =
        std::mem::transmute(real);
    real(sem, deadline)
}

#[no_mangle]
pub unsafe extern "C" fn sem_clockwait(
    sem: *mut libc::sem_t,
    clock: libc::clockid_t,
    deadline: *const libc::timespec,
) -> libc::c_int {
    let translated = real_deadline(clock, deadline);
    let deadline = translated
        .as_ref()
        .map_or(deadline, |deadline| deadline as *const libc::timespec);
    let real = SEM_CLOCKWAIT.real();
    if real.is_null() {
        set_errno(libc::ENOSYS);
        return -1;
    }
    let real: unsafe extern "C" fn(
        *mut libc::sem_t,
        libc::clockid_t,
        *const libc::timespec,
    ) -> libc::c_int = std::mem::transmute(real);
    real(sem, clock, deadline)
}

fn set_errno(value: i32) {
    unsafe {
        *libc::__errno_location() = value;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // The production state is intentionally process-global. Serialise tests
    // that overwrite it so Rust's parallel test runner cannot splice two
    // pseudo-random streams together and make the determinism assertions flaky.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn the_random_stream_is_reproducible_from_a_seed() {
        let _guard = TEST_LOCK.lock().unwrap();
        // Determinism is the point: the same seed must give the same bytes, or
        // a saved crash input is not a reproducer.
        RNG_STATE.store(12345, Ordering::Relaxed);
        let first: Vec<u64> = (0..8).map(|_| next_random()).collect();
        RNG_STATE.store(12345, Ordering::Relaxed);
        let second: Vec<u64> = (0..8).map(|_| next_random()).collect();
        assert_eq!(first, second);
        // ...and not a degenerate constant stream.
        assert!(
            first.windows(2).any(|w| w[0] != w[1]),
            "stream must vary: {first:?}"
        );
    }

    #[test]
    fn the_virtual_clock_serves_the_system_clocks_and_leaves_the_others() {
        let _guard = TEST_LOCK.lock().unwrap();
        CLOCK_READS.store(0, Ordering::Relaxed);
        assert_eq!(
            virtual_time(libc::CLOCK_REALTIME),
            Some(CLOCK_EPOCH_SECS * NANOS_PER_SEC)
        );
        assert_eq!(
            virtual_time(libc::CLOCK_BOOTTIME),
            Some(CLOCK_BOOT_SECS * NANOS_PER_SEC + CLOCK_TICK_NS)
        );
        assert_eq!(
            virtual_time(libc::CLOCK_THREAD_CPUTIME_ID),
            Some(2 * CLOCK_TICK_NS)
        );
        // Another process's CPU clock (clock_getcpuclockid) and a descriptor
        // clock are negative ids: the fake leaves them, and they do not tick.
        assert_eq!(virtual_time(-6), None);
        assert_eq!(CLOCK_READS.load(Ordering::Relaxed), 3);
        let at = timespec_of(CLOCK_EPOCH_SECS * NANOS_PER_SEC + 1_500_000_000);
        assert_eq!((at.tv_sec, at.tv_nsec), (1_767_225_601, 500_000_000));
    }

    #[test]
    fn a_zero_state_never_stalls_the_stream() {
        let _guard = TEST_LOCK.lock().unwrap();
        // xorshift is absorbing at zero; a zero seed must be replaced.
        RNG_STATE.store(0, Ordering::Relaxed);
        assert_ne!(next_random(), 0);
    }

    #[test]
    fn persistent_iterations_reset_randomness_from_each_input() {
        let _guard = TEST_LOCK.lock().unwrap();
        // Simulate A, B, A in one persistent process. The second A must see the
        // exact stream the first A did; otherwise a saved A is not a standalone
        // reproducer after B (or any corpus prefix) has run.
        RNG_STATE.store(input_seed(b"same-input", 0), Ordering::Relaxed);
        let first: Vec<u64> = (0..4).map(|_| next_random()).collect();
        RNG_STATE.store(input_seed(b"different-input", 0), Ordering::Relaxed);
        let different: Vec<u64> = (0..4).map(|_| next_random()).collect();
        RNG_STATE.store(input_seed(b"same-input", 0), Ordering::Relaxed);
        let replay: Vec<u64> = (0..4).map(|_| next_random()).collect();
        assert_eq!(first, replay);
        assert_ne!(first, different);
    }
}
