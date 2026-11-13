// SPDX-License-Identifier: Apache-2.0

//! Reader for fuzz-input bytes published by the harness or auto loop.
//!
//! Two channels feed this module:
//!
//! 1. **Live buffer** — the generated harness calls
//!    [`bhf_shim_set_fuzz_input`] at the top of
//!    `LLVMFuzzerTestOneInput` with `(Data, Size)`. The shim caches
//!    those bytes in a `Mutex<Option<Vec<u8>>>` and serves them on
//!    subsequent [`read_into`] calls. This is the per-iteration
//!    channel — `read_into` reflects the EXACT bytes libFuzzer is
//!    about to feed to the target.
//!
//! 2. **Shared memfd fallback** — `BHF_FUZZ_INPUT_FD` +
//!    `BHF_FUZZ_INPUT_LEN` env vars point at a parent-owned
//!    memfd the auto loop populates before exec. The shim mmaps it
//!    once at first use. Used when the harness hasn't published a
//!    live buffer yet (e.g. before the first iteration runs, or for
//!    a harness built without the publish call).
//!
//! `read_into` prefers the live buffer when populated and falls
//! back to the memfd otherwise. The cursor wraps modulo the source
//! length so even a buffer larger than the source gets fully
//! populated.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

struct Shared {
    ptr: *const u8,
    len: usize,
}

// The pointer is only ever dereferenced inside an unsafe block via
// `std::ptr::copy_nonoverlapping`, and the mmap'd region is read-only
// and lives for the full process lifetime. Concurrent reads from
// multiple threads are fine — each gets a unique cursor base via
// `fetch_add`.
unsafe impl Send for Shared {}
unsafe impl Sync for Shared {}

static SHARED: OnceLock<Option<Shared>> = OnceLock::new();
static CURSOR: AtomicUsize = AtomicUsize::new(0);

struct LiveInput {
    bytes: Vec<u8>,
}

static LIVE_INPUT: Mutex<Option<LiveInput>> = Mutex::new(None);

fn load() -> Option<&'static Shared> {
    SHARED
        .get_or_init(|| {
            let fd: i32 = std::env::var_os("BHF_FUZZ_INPUT_FD")
                .and_then(|v| v.to_string_lossy().parse().ok())?;
            let len: usize = std::env::var_os("BHF_FUZZ_INPUT_LEN")
                .and_then(|v| v.to_string_lossy().parse().ok())?;
            if fd < 0 || len == 0 {
                return None;
            }
            unsafe {
                let p = libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ,
                    libc::MAP_SHARED,
                    fd,
                    0,
                );
                if p == libc::MAP_FAILED {
                    return None;
                }
                Some(Shared {
                    ptr: p as *const u8,
                    len,
                })
            }
        })
        .as_ref()
}

/// Called from the generated harness's `LLVMFuzzerTestOneInput` to
/// publish the current iteration's fuzz bytes. The shim's faking
/// path will then serve these bytes back through fake fds / sockets.
///
/// Safe to call with a null pointer or zero size. A null pointer with a
/// non-zero size is ignored; a zero-size publication still resets deterministic
/// per-input state and publishes an explicitly empty fake-resource buffer.
/// Safe to call concurrently with [`read_into`] from other
/// threads; readers see either the old or new buffer, never a
/// partial state.
///
/// # Safety
///
/// `data` must point to at least `size` bytes valid for read for
/// the duration of this call. The shim copies the bytes into an
/// owned buffer before returning, so the caller's buffer does not
/// need to remain valid after `bhf_shim_set_fuzz_input` returns.
#[no_mangle]
pub unsafe extern "C" fn bhf_shim_set_fuzz_input(data: *const u8, size: libc::size_t) {
    if size == 0 {
        // Empty corpus entries are real libFuzzer iterations too. Without this
        // reset, an empty reproducer inherits the RNG stream left by the previous
        // testcase in a persistent process but starts from the seed in standalone
        // replay, violating the determinism contract.
        crate::hooks::determinism::reset_for_input(&[]);
        // HDF-8: a fresh input begins a fresh schedule — clear the cooperative
        // scheduler's per-input registry/decision counter so a persistent-harness
        // iteration explores (and replays) the schedule of THIS input, not one left
        // by the previous testcase. No-op unless BHF_SCHED is active.
        crate::hooks::sched::reset_for_input();
        if let Ok(mut guard) = LIVE_INPUT.lock() {
            *guard = Some(LiveInput { bytes: Vec::new() });
        }
        CURSOR.store(0, Ordering::Relaxed);
        return;
    }
    if data.is_null() {
        return;
    }
    let slice = std::slice::from_raw_parts(data, size);
    // The harness runs many testcases in one persistent process. Reset fake RNG
    // state from THIS input before target execution so a saved testcase replays
    // independently of the corpus prefix that happened to precede it.
    crate::hooks::determinism::reset_for_input(slice);
    crate::hooks::sched::reset_for_input();
    let mut guard = match LIVE_INPUT.lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    *guard = Some(LiveInput {
        bytes: slice.to_vec(),
    });
    CURSOR.store(0, Ordering::Relaxed);
}

pub fn read_into(out: &mut [u8]) -> usize {
    if out.is_empty() {
        return 0;
    }
    // Prefer the live buffer when present. `try_lock`, not `lock`: this can be
    // reached from a hook firing in a signal handler that interrupted the input
    // setter (or another reader) mid-critical-section; a blocking lock would
    // self-deadlock. On contention, fall through to the mmap'd shared buffer.
    if let Ok(guard) = LIVE_INPUT.try_lock() {
        if let Some(live) = guard.as_ref() {
            if live.bytes.is_empty() {
                // Some(empty) is an explicit current testcase, not "no live
                // publication". Never fall through to a stale shared buffer.
                return 0;
            }
            let cursor = CURSOR.fetch_add(out.len(), Ordering::Relaxed);
            let len = live.bytes.len();
            for (i, slot) in out.iter_mut().enumerate() {
                *slot = live.bytes[(cursor + i) % len];
            }
            return out.len();
        }
    }
    // Fallback: mmap'd shared memfd.
    let Some(shared) = load() else {
        return 0;
    };
    let cursor = CURSOR.fetch_add(out.len(), Ordering::Relaxed) % shared.len;
    let mut written = 0;
    while written < out.len() {
        let remaining = shared.len - ((cursor + written) % shared.len);
        let chunk = (out.len() - written).min(remaining);
        unsafe {
            let src = shared.ptr.add((cursor + written) % shared.len);
            std::ptr::copy_nonoverlapping(src, out[written..].as_mut_ptr(), chunk);
        }
        written += chunk;
    }
    out.len()
}

/// Fill `out` with fuzz-input bytes for an INDEPENDENT environment channel keyed
/// by `key` (#7 environment-response fuzzing). Unlike [`read_into`], which advances
/// one global cursor shared by every faked resource — so `/etc/a` and `/etc/b` get
/// identical bytes — this starts at a per-`key` base offset into the input, so each
/// faked resource is driven by a DISTINCT, deterministic window of the corpus. A
/// target that reads two config files (or a file plus a socket) therefore has each
/// external resource fuzzed independently rather than mirrored.
///
/// Deterministic: same input + same key → same bytes (no global cursor mutation),
/// so coverage feedback still learns a stable input-byte → resource mapping. Falls
/// back to [`read_into`] semantics when there is no source.
pub fn read_keyed(key: u64, out: &mut [u8]) -> usize {
    if out.is_empty() {
        return 0;
    }
    // try_lock, not lock: reachable from a signal handler; fall through to the
    // mmap on contention rather than deadlocking (see read_into).
    if let Ok(guard) = LIVE_INPUT.try_lock() {
        if let Some(live) = guard.as_ref() {
            if live.bytes.is_empty() {
                return 0;
            }
            let len = live.bytes.len();
            let base = (key as usize) % len;
            for (i, slot) in out.iter_mut().enumerate() {
                *slot = live.bytes[(base + i) % len];
            }
            return out.len();
        }
    }
    let Some(shared) = load() else {
        return 0;
    };
    let base = (key as usize) % shared.len;
    for (i, slot) in out.iter_mut().enumerate() {
        // SAFETY: base+i is taken modulo shared.len, so the index is in-bounds of
        // the read-only mmap that lives for the whole process.
        unsafe {
            *slot = *shared.ptr.add((base + i) % shared.len);
        }
    }
    out.len()
}

/// HDF-6 deliverable 1: fuzz-driven stub return value.
///
/// A fuzz-driven weak stub (emitted by `c_stub_gen`/`stub_gen` in fuzz-driven
/// mode) calls this to draw its scalar return value from the live fuzz input,
/// keyed by its own symbol name so each stubbed dependency is an INDEPENDENT
/// channel — exactly the per-resource keying the mqueue / file / MMIO fakes use
/// via [`crate::fakes::data::fill_bytes`]. `read_sensor()` and `read_status()`
/// therefore see distinct, deterministic windows of the corpus, and the fuzzer's
/// coverage feedback learns a stable input-byte → return-value mapping.
///
/// Mode dispatch matches every other fake:
/// * Audit / Empty → 0 (so a fuzz-driven-stub binary run under audit is
///   byte-for-byte the constant stub, and a shim-less run — where the weak
///   symbol resolves to NULL and the stub's own `?:` falls back to 0 — matches).
/// * Rng → a per-symbol pseudo-random 64-bit value.
/// * FuzzDriven → the symbol's keyed window of the live fuzz input.
///
/// # Safety
///
/// `symbol` must be NULL or a valid NUL-terminated C string valid for read for
/// the duration of the call. The bytes are copied before returning.
#[no_mangle]
pub unsafe extern "C" fn bhf_shim_fuzz_stub_value(symbol: *const libc::c_char) -> u64 {
    let name: &[u8] = if symbol.is_null() {
        b"stub"
    } else {
        std::ffi::CStr::from_ptr(symbol).to_bytes()
    };
    let mut buf = [0u8; 8];
    // `fill_bytes` returns 0 written for Audit/Empty (buf stays zero -> 0), the
    // per-symbol RNG stream for Rng, and the symbol's keyed fuzz window for
    // FuzzDriven. It also honours env-capsule record/replay, so a fuzz-driven
    // stub's return reproduces deterministically in a pinned world.
    let n = crate::fakes::data::fill_bytes(name, &mut buf);
    if n == 0 {
        return 0;
    }
    u64::from_le_bytes(buf)
}

/// The shortest format string that can count as fuzz-controlled.
pub const FORMAT_TAINT_MIN_LEN: usize = 4;

/// Whether a printf-family `format` came from the fuzz input: the whole
/// format, at least [`FORMAT_TAINT_MIN_LEN`] bytes long, occurs verbatim in
/// the current input ([`taint_span`]), and it does not lie in a loaded
/// object's read-only data. A format only part of which matches the input is
/// not controlled. `format` must be the program's own format bytes (not a
/// copy), since its address is checked.
///
/// The address check removes string literals, which live in `.rodata`
/// whatever their length, although the mined dictionary puts a constant
/// format such as `"%s"` into the input. The floor removes short writable
/// copies of literals (a `std::string` holding `"%s"`). The content check
/// runs first, so the program-header walk runs only for a format that
/// matched.
pub fn format_is_input_controlled(format: &[u8]) -> bool {
    taint_span(format, FORMAT_TAINT_MIN_LEN).is_some()
        && !points_into_read_only_image(format.as_ptr())
}

/// Whether `addr` lies in read-only memory of an object the process has
/// loaded: a `PT_LOAD` segment that is not writable, or a `PT_GNU_RELRO`
/// range. String literals live there; memory built at run time (heap, stack,
/// writable `.data`) does not. Walks the link map in place (no allocation)
/// and returns false when no object holds `addr`.
pub fn points_into_read_only_image(addr: *const u8) -> bool {
    struct Probe {
        addr: usize,
        found: bool,
    }
    unsafe extern "C" fn visit(
        info: *mut libc::dl_phdr_info,
        _size: libc::size_t,
        data: *mut libc::c_void,
    ) -> libc::c_int {
        let probe = &mut *(data as *mut Probe);
        let info = &*info;
        if info.dlpi_phdr.is_null() {
            return 0;
        }
        let headers = std::slice::from_raw_parts(info.dlpi_phdr, usize::from(info.dlpi_phnum));
        for header in headers {
            let read_only = match header.p_type {
                libc::PT_LOAD => header.p_flags & libc::PF_W == 0,
                libc::PT_GNU_RELRO => true,
                _ => false,
            };
            if !read_only {
                continue;
            }
            let start = (info.dlpi_addr as usize).wrapping_add(header.p_vaddr as usize);
            let end = start.wrapping_add(header.p_memsz as usize);
            if (start..end).contains(&probe.addr) {
                probe.found = true;
                return 1;
            }
        }
        0
    }
    if addr.is_null() {
        return false;
    }
    let mut probe = Probe {
        addr: addr as usize,
        found: false,
    };
    unsafe {
        libc::dl_iterate_phdr(Some(visit), (&mut probe as *mut Probe).cast());
    }
    probe.found
}

/// Byte-origin taint check (#422): does the whole of `needle`, at least
/// `min_len` bytes long, occur verbatim in the current fuzz input? Returns the
/// `(offset, len)` of the first such occurrence, which is the *source*
/// end of a fuzz-input→sink taint path the oracles confirm.
///
/// Used by the sink hooks (printf-family format strings, open/openat
/// path arguments) to decide whether the value reaching the sink was
/// derived from the fuzz input. Only the live per-iteration buffer is
/// consulted — the same buffer the harness publishes via
/// [`bhf_shim_set_fuzz_input`] — so the answer reflects the exact
/// bytes libFuzzer fed this iteration, never a stale or wrapped view.
///
/// `min_len` guards against coincidental short matches: a 1–3 byte run
/// appears in almost any input by chance, so callers pass a floor (the
/// shim uses 4) below which a match is not treated as taint. A
/// `needle` shorter than `min_len`, an empty needle, or a needle longer
/// than the input all return `None`. A format string is checked through
/// [`format_is_input_controlled`], which also excludes literals in the
/// program's read-only data.
pub fn taint_span(needle: &[u8], min_len: usize) -> Option<(usize, usize)> {
    if needle.is_empty() || needle.len() < min_len {
        return None;
    }
    // try_lock, not lock: sink hooks call this and may fire from a signal
    // handler; on contention skip the taint tag (None) rather than deadlock.
    let guard = LIVE_INPUT.try_lock().ok()?;
    let live = guard.as_ref()?;
    if needle.len() > live.bytes.len() {
        return None;
    }
    live.bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| (offset, needle.len()))
}

/// Does `haystack` contain a contiguous run of at least `min_len` bytes that
/// also appears contiguously in the current fuzz input? Returns the
/// `(input_offset, run_len)` of the first such run, extended as far forward
/// as the two byte sequences agree — the *source* end of a fuzz-input→sink
/// taint path.
///
/// Unlike [`taint_span`], which requires the *whole* value to be copied from
/// the input, this finds a fuzz-derived *span embedded in a larger value* —
/// the common command-injection shape `system("tool " + input)`, where only
/// part of the executed command comes from the attacker. `min_len` guards
/// against coincidental short runs the same way (the shim uses 4); an
/// occasional coincidental run on one input is harmless because the CLI-side
/// correlator suppresses any command also executed *without* taint.
pub fn input_derived_run(haystack: &[u8], min_len: usize) -> Option<(usize, usize)> {
    if min_len == 0 || haystack.len() < min_len {
        return None;
    }
    // Prefer the live buffer (`bhf_shim_set_fuzz_input`, the per-iteration channel
    // a cooperating harness publishes). try_lock, not lock: reachable from sink
    // hooks in a signal handler; skip rather than deadlock (see taint_span).
    if let Ok(guard) = LIVE_INPUT.try_lock() {
        if let Some(live) = guard.as_ref() {
            // Some(empty) is an explicit empty current input, not "no publication":
            // never fall through to a stale shared buffer (mirrors `read_into`).
            if live.bytes.is_empty() {
                return None;
            }
            return input_run_in(haystack, &live.bytes, min_len);
        }
    }
    // Fallback: the mmap'd shared memfd (`BHF_FUZZ_INPUT_FD`). A black-box target
    // that never calls `bhf_shim_set_fuzz_input` — e.g. one driven by
    // `bhf binary fuzz` — still gets byte-origin taint from the parent-published
    // input, exactly as `read_into` already serves it to faked resources.
    let shared = load()?;
    let input = unsafe { std::slice::from_raw_parts(shared.ptr, shared.len) };
    input_run_in(haystack, input, min_len)
}

/// Find the first `>= min_len` contiguous run of `haystack` that also appears in
/// `input`, extended forward while the two agree; `(input_offset, run_len)`.
fn input_run_in(haystack: &[u8], input: &[u8], min_len: usize) -> Option<(usize, usize)> {
    if input.len() < min_len {
        return None;
    }
    let mut i = 0usize;
    while i + min_len <= haystack.len() {
        let probe = &haystack[i..i + min_len];
        if let Some(pos) = input.windows(min_len).position(|w| w == probe) {
            // Extend the match forward while both sequences agree.
            let mut len = min_len;
            while i + len < haystack.len()
                && pos + len < input.len()
                && haystack[i + len] == input[pos + len]
            {
                len += 1;
            }
            return Some((pos, len));
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Reset module state so tests are independent of each other.
    fn reset() {
        if let Ok(mut g) = LIVE_INPUT.lock() {
            *g = None;
        }
        CURSOR.store(0, Ordering::Relaxed);
    }

    #[test]
    fn live_buffer_serves_published_bytes() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        let payload = b"HELLO";
        unsafe {
            bhf_shim_set_fuzz_input(payload.as_ptr(), payload.len());
        }
        let mut out = [0u8; 10];
        let n = read_into(&mut out);
        assert_eq!(n, out.len());
        // First five bytes are HELLO; next five wrap to HELLO again.
        assert_eq!(&out[..5], b"HELLO");
        assert_eq!(&out[5..], b"HELLO");
        reset();
    }

    #[test]
    fn keyed_reads_give_distinct_windows_per_resource() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        // A 16-byte input; two different resource keys must pull DIFFERENT windows
        // (independent environment channels, #7), and each is deterministic.
        let payload: Vec<u8> = (0..16u8).collect();
        unsafe {
            bhf_shim_set_fuzz_input(payload.as_ptr(), payload.len());
        }
        let mut a1 = [0u8; 8];
        let mut a2 = [0u8; 8];
        let mut b = [0u8; 8];
        read_keyed(1, &mut a1);
        read_keyed(1, &mut a2);
        read_keyed(9, &mut b);
        assert_eq!(a1, a2, "same key + input is deterministic");
        assert_ne!(a1, b, "different keys read different windows");
        reset();
    }

    #[test]
    fn null_nonempty_publish_is_noop() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        unsafe {
            bhf_shim_set_fuzz_input(std::ptr::null(), 8);
        }
        // No env vars set, no live buffer => read_into returns 0.
        let mut out = [0u8; 4];
        assert_eq!(read_into(&mut out), 0);
        reset();
    }

    #[test]
    fn empty_publish_shadows_the_previous_testcase() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        let payload = b"previous";
        unsafe {
            bhf_shim_set_fuzz_input(payload.as_ptr(), payload.len());
            bhf_shim_set_fuzz_input(std::ptr::null(), 0);
        }
        let mut sequential = [0u8; 8];
        let mut keyed = [0u8; 8];
        assert_eq!(read_into(&mut sequential), 0);
        assert_eq!(read_keyed(7, &mut keyed), 0);
        assert!(taint_span(b"previous", 4).is_none());
        reset();
    }

    #[test]
    fn fuzz_stub_value_is_zero_without_a_fuzzing_pass() {
        // HDF-6 D1: in the default (audit) pass, `fill_bytes` writes nothing, so a
        // fuzz-driven stub's return falls back to the constant 0 — the byte-for-byte
        // constant-stub guarantee for a shim-less / audit run. Also exercises the
        // null-symbol path.
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        unsafe {
            assert_eq!(bhf_shim_fuzz_stub_value(std::ptr::null()), 0);
            let sym = c"read_sensor";
            assert_eq!(bhf_shim_fuzz_stub_value(sym.as_ptr()), 0);
        }
        reset();
    }

    #[test]
    fn empty_out_returns_zero() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        let payload = b"X";
        unsafe {
            bhf_shim_set_fuzz_input(payload.as_ptr(), payload.len());
        }
        let mut out: [u8; 0] = [];
        assert_eq!(read_into(&mut out), 0);
        reset();
    }

    #[test]
    fn read_only_images_hold_literals_not_heap_or_writable_data() {
        static mut WRITABLE: [u8; 8] = *b"%x%x%x\0\0";
        let literal: &'static str = "a literal format %d";
        assert!(points_into_read_only_image(literal.as_ptr()));
        let heap = literal.as_bytes().to_vec();
        assert!(!points_into_read_only_image(heap.as_ptr()));
        let writable = (&raw const WRITABLE).cast::<u8>();
        assert!(!points_into_read_only_image(writable));
        let on_stack = [b'%'; 8];
        assert!(!points_into_read_only_image(on_stack.as_ptr()));
        assert!(!points_into_read_only_image(std::ptr::null()));
    }

    #[test]
    fn only_formats_outside_read_only_data_that_match_the_input_are_controlled() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        let payload = b"A%s%x%x%x";
        unsafe {
            bhf_shim_set_fuzz_input(payload.as_ptr(), payload.len());
        }
        // A format copied out of the input into memory the program owns.
        let copied: Vec<u8> = b"%x%x%x".to_vec();
        assert!(format_is_input_controlled(&copied));
        let copied_tail: Vec<u8> = payload[3..].to_vec();
        assert!(format_is_input_controlled(&copied_tail));
        // Too short to tell a copy of the input from a copy of a literal.
        let short: Vec<u8> = b"%s".to_vec();
        assert!(!format_is_input_controlled(&short));
        // Not in the input at all.
        let absent: Vec<u8> = b"%p%n%p".to_vec();
        assert!(!format_is_input_controlled(&absent));
        // Only part of the format occurs in the input: the whole format must.
        let partly: Vec<u8> = b"name=%x%x%x and more text".to_vec();
        assert!(!format_is_input_controlled(&partly));
        // A literal in the program's read-only data, though its bytes also
        // occur in the input (a dictionary token put them there).
        assert!(!format_is_input_controlled(b"%x%x"));
        reset();
    }

    #[test]
    fn taint_span_reports_offset_of_first_match() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        let payload = b"GET /../../etc/passwd HTTP";
        unsafe {
            bhf_shim_set_fuzz_input(payload.as_ptr(), payload.len());
        }
        // The path substring is derived from the input at a known offset.
        let needle = b"/../../etc/passwd";
        let (offset, len) = taint_span(needle, 4).expect("path is tainted");
        assert_eq!(len, needle.len());
        assert_eq!(&payload[offset..offset + len], needle);
        reset();
    }

    #[test]
    fn taint_span_rejects_matches_below_min_len() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        let payload = b"the quick brown fox";
        unsafe {
            bhf_shim_set_fuzz_input(payload.as_ptr(), payload.len());
        }
        // "fox" is present but only 3 bytes — below the floor, so not taint.
        assert!(taint_span(b"fox", 4).is_none());
        // A 4-byte run that is present is taint.
        assert!(taint_span(b"quick", 4).is_some());
        reset();
    }

    #[test]
    fn taint_span_none_when_absent_or_no_input() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        // No live input published yet.
        assert!(taint_span(b"anything", 4).is_none());
        let payload = b"hello world";
        unsafe {
            bhf_shim_set_fuzz_input(payload.as_ptr(), payload.len());
        }
        assert!(taint_span(b"absent-token", 4).is_none());
        reset();
    }

    #[test]
    fn input_derived_run_finds_embedded_span_and_extends() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        // The attacker controls only the filename part of the input.
        let payload = b"AAAA/etc/shadow";
        unsafe {
            bhf_shim_set_fuzz_input(payload.as_ptr(), payload.len());
        }
        // The executed command embeds that run inside a larger string that is
        // NOT wholly present in the input — taint_span misses it, the run does.
        let command = b"cat /etc/shadow > /tmp/x";
        assert!(taint_span(command, 4).is_none());
        let (offset, len) = input_derived_run(command, 4).expect("embedded run is taint");
        assert_eq!(&payload[offset..offset + len], b"/etc/shadow");
        reset();
    }

    #[test]
    fn input_derived_run_rejects_short_and_absent_runs() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset();
        let payload = b"prefix-cat-suffix";
        unsafe {
            bhf_shim_set_fuzz_input(payload.as_ptr(), payload.len());
        }
        // "cat" is shared but flanked differently in the command (spaces vs
        // dashes), so only 3 contiguous bytes overlap — below the floor.
        assert!(input_derived_run(b"the cat sat", 4).is_none());
        // No shared run at all.
        assert!(input_derived_run(b"echo hello", 4).is_none());
        // A >=4-byte embedded run ("prefix-cat") is taint.
        assert!(input_derived_run(b"run prefix-cat now", 4).is_some());
        reset();
    }
}
