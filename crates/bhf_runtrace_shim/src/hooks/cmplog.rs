// SPDX-License-Identifier: Apache-2.0

//! CmpLog intercepts. When `BHF_CMPLOG=1` is set, `strcmp`,
//! `strncmp`, and `memcmp` calls record both operand byte ranges
//! (capped at 64 bytes per side) to the audit log as `c:"cmplog"`
//! events. The builtin engine's mutator consumes the log via
//! `cmplog::ingest_from_jsonl_log` to splice operand values back
//! into inputs at matching offsets — the RedQueen-style
//! magic-byte trick that turns equality guards from a brute-force
//! search into a one-shot transformation.
//!
//! Allocation discipline: same as the other hook modules — no
//! malloc / Box / Vec / String from inside the hooks. Operands
//! are emitted as base64-of-hex pairs via the existing
//! jsonl::Builder fixed-buffer path.
//!
//! Only the target records. A shell or tool it runs (`system`, `popen`, an
//! `exec`) inherits `LD_PRELOAD` and `BHF_CMPLOG`, and its comparisons are
//! not the target's: when `BHF_TARGET_EXE` names the harness, a process
//! whose image is another file records nothing. A forked child, such as a
//! fork server's, runs the same image and records. A process records each
//! distinct comparison once, and none once the log holds
//! [`MAX_CMPLOG_LOG_BYTES`], however many processes write it.

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::missing_transmute_annotations)]

use crate::dlsym::ResolvedFn;
use crate::jsonl::Builder;
use crate::reentrancy::HookGuard;
use crate::sdk::FakeResource;

const ENV_VAR: &[u8] = b"BHF_CMPLOG\0";
const TARGET_EXE_VAR: &[u8] = b"BHF_TARGET_EXE\0";
const MAX_OPERAND_BYTES: usize = 64;

/// Comparisons stop being recorded once the shared log holds this many
/// bytes.
const MAX_CMPLOG_LOG_BYTES: u64 = 8 * 1024 * 1024;
/// Records a process writes between two looks at the log's size.
const SIZE_CHECK_EVERY: u32 = 256;
/// Slots of the per-process table of comparisons already recorded.
const SEEN_SLOTS: usize = 4096;
/// Slots a comparison's hash probes before it is recorded unseen.
const SEEN_PROBES: usize = 8;

static REAL_STRCMP: ResolvedFn = ResolvedFn::new(b"strcmp\0");
static REAL_STRNCMP: ResolvedFn = ResolvedFn::new(b"strncmp\0");
static REAL_MEMCMP: ResolvedFn = ResolvedFn::new(b"memcmp\0");

pub fn env_enabled() -> bool {
    use std::sync::atomic::{AtomicU8, Ordering};
    static CACHED: AtomicU8 = AtomicU8::new(2);
    let cached = CACHED.load(Ordering::Relaxed);
    if cached != 2 {
        return cached == 1;
    }
    let value = unsafe { libc::getenv(ENV_VAR.as_ptr() as *const libc::c_char) };
    let enabled = !value.is_null()
        && crate::reentrancy::bytes_eq(unsafe { std::ffi::CStr::from_ptr(value) }.to_bytes(), b"1")
        && process_is_target();
    CACHED.store(if enabled { 1 } else { 0 }, Ordering::Relaxed);
    enabled
}

/// Whether this process runs the image `BHF_TARGET_EXE` names: the same file
/// (device and inode) as `/proc/self/exe`, so a symlink or a sandbox's bind
/// mount of the harness still matches. True when the variable is unset or
/// either file cannot be looked at.
fn process_is_target() -> bool {
    let target = unsafe { libc::getenv(TARGET_EXE_VAR.as_ptr() as *const libc::c_char) };
    if target.is_null() || unsafe { *target } == 0 {
        return true;
    }
    match (file_id(c"/proc/self/exe".as_ptr()), file_id(target)) {
        (Some(running), Some(target)) => running == target,
        _ => true,
    }
}

/// The device and inode of the file at `path`, through the raw `newfstatat`
/// syscall: the shim hooks `stat`, and a comparison hook must not log one.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn file_id(path: *const libc::c_char) -> Option<(libc::dev_t, libc::ino_t)> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `path` is NUL-terminated and `stat` is a writable `struct stat`,
    // the layout the kernel's newfstatat fills on these architectures.
    let result = unsafe {
        libc::syscall(
            libc::SYS_newfstatat,
            libc::AT_FDCWD,
            path,
            stat.as_mut_ptr(),
            0,
        )
    };
    if result != 0 {
        return None;
    }
    // SAFETY: the syscall succeeded and filled `stat`.
    let stat = unsafe { stat.assume_init() };
    Some((stat.st_dev, stat.st_ino))
}

/// Elsewhere the shim does not tell the target's image apart.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn file_id(_path: *const libc::c_char) -> Option<(libc::dev_t, libc::ino_t)> {
    None
}

/// FNV-1a over a comparison's kind and operands, never 0 (an empty slot).
fn comparison_hash(kind: &[u8], a: &[u8], b: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for part in [kind, a, b] {
        for byte in part {
            hash = (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3);
        }
        // A separator, so moving bytes between operands changes the hash.
        hash = (hash ^ 0xff).wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash.max(1)
}

/// Whether this process has not recorded the comparison with `hash` yet;
/// marks it recorded. A comparison that finds every probed slot taken by
/// others counts as new.
fn first_time(hash: u64) -> bool {
    use std::sync::atomic::{AtomicU64, Ordering};
    #[allow(clippy::declare_interior_mutable_const)]
    const EMPTY: AtomicU64 = AtomicU64::new(0);
    static SEEN: [AtomicU64; SEEN_SLOTS] = [EMPTY; SEEN_SLOTS];
    let start = (hash as usize) % SEEN_SLOTS;
    for probe in 0..SEEN_PROBES {
        let slot = &SEEN[(start + probe) % SEEN_SLOTS];
        match slot.compare_exchange(0, hash, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(held) if held == hash => return false,
            Err(_) => {}
        }
    }
    true
}

/// Records since this process last looked at the log's size; it starts, and
/// a forked child restarts, due for a look.
static SINCE_SIZE_CHECK: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(SIZE_CHECK_EVERY);
static LOG_FULL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether the shared log has room for comparisons: its size, which every
/// process writing it adds to, is looked at on a process's first record and
/// every [`SIZE_CHECK_EVERY`] records after.
fn log_has_room() -> bool {
    use std::sync::atomic::Ordering;
    if LOG_FULL.load(Ordering::Relaxed) {
        return false;
    }
    if SINCE_SIZE_CHECK.fetch_add(1, Ordering::Relaxed) + 1 >= SIZE_CHECK_EVERY {
        SINCE_SIZE_CHECK.store(0, Ordering::Relaxed);
        if crate::jsonl::log_len().is_some_and(|len| len >= MAX_CMPLOG_LOG_BYTES) {
            LOG_FULL.store(true, Ordering::Relaxed);
            return false;
        }
    }
    true
}

/// A forked child looks at the log's size on its first record: a fork
/// server's children each start from the server's count.
extern "C" fn restart_size_checks_in_child() {
    SINCE_SIZE_CHECK.store(SIZE_CHECK_EVERY, std::sync::atomic::Ordering::Relaxed);
}

#[used]
#[link_section = ".init_array"]
static REGISTER_FORK_HANDLER: extern "C" fn() = register_fork_handler;

extern "C" fn register_fork_handler() {
    // SAFETY: registers a handler that only stores to an atomic.
    unsafe {
        libc::pthread_atfork(None, None, Some(restart_size_checks_in_child));
    }
}

pub struct CmpLog;

impl FakeResource for CmpLog {
    fn name(&self) -> &'static str {
        "cmplog"
    }
    fn intercepts(&self) -> &'static [&'static [u8]] {
        &[b"strcmp\0", b"strncmp\0", b"memcmp\0"]
    }
    fn is_enabled(&self) -> bool {
        env_enabled()
    }
    fn describe(&self) -> &'static str {
        "record strcmp/strncmp/memcmp operands so the engine can splice them into inputs"
    }
}

/// Hex-encode up to `MAX_OPERAND_BYTES` bytes into a stack buffer.
/// Returns a slice into the supplied output buffer.
fn hex_into<'a>(input: &[u8], out: &'a mut [u8; MAX_OPERAND_BYTES * 2]) -> &'a [u8] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let n = input.len().min(MAX_OPERAND_BYTES);
    for (i, byte) in input.iter().take(n).enumerate() {
        out[i * 2] = HEX[(byte >> 4) as usize];
        out[i * 2 + 1] = HEX[(byte & 0x0F) as usize];
    }
    &out[..n * 2]
}

/// Whether a comparison reaching these hooks is the target's to record: one
/// the shim makes itself, inside a hook or one of its own checks
/// ([`crate::reentrancy::in_shim`]), is not. Thread-local state is read only
/// once recording is on.
fn records_comparison() -> bool {
    env_enabled() && !crate::reentrancy::in_shim()
}

fn emit_cmp(kind: &[u8], a: &[u8], b_bytes: &[u8]) {
    if let Some(_g) = HookGuard::acquire() {
        if !first_time(comparison_hash(kind, a, b_bytes)) || !log_has_room() {
            return;
        }
        let mut buf_a = [0u8; MAX_OPERAND_BYTES * 2];
        let mut buf_b = [0u8; MAX_OPERAND_BYTES * 2];
        let hex_a = hex_into(a, &mut buf_a);
        let hex_b = hex_into(b_bytes, &mut buf_b);
        let mut b = Builder::new(b"cmplog");
        b.field_str(b"k", kind);
        b.field_str(b"a", hex_a);
        b.field_str(b"b", hex_b);
        b.emit();
    }
}

#[no_mangle]
pub unsafe extern "C" fn strcmp(a: *const libc::c_char, b: *const libc::c_char) -> i32 {
    let real = REAL_STRCMP.ptr() as *const ();
    if real.is_null() {
        // Last-resort: call libc directly; we lose the cmplog
        // event but stay correct.
        return libc::strcmp(a, b);
    }
    let real: unsafe extern "C" fn(*const libc::c_char, *const libc::c_char) -> i32 =
        std::mem::transmute(real);
    if records_comparison() && !a.is_null() && !b.is_null() {
        let len_a = libc::strlen(a).min(MAX_OPERAND_BYTES);
        let len_b = libc::strlen(b).min(MAX_OPERAND_BYTES);
        let slice_a = std::slice::from_raw_parts(a as *const u8, len_a);
        let slice_b = std::slice::from_raw_parts(b as *const u8, len_b);
        emit_cmp(b"strcmp", slice_a, slice_b);
    }
    real(a, b)
}

#[no_mangle]
pub unsafe extern "C" fn strncmp(
    a: *const libc::c_char,
    b: *const libc::c_char,
    n: libc::size_t,
) -> i32 {
    let real = REAL_STRNCMP.ptr() as *const ();
    if real.is_null() {
        return libc::strncmp(a, b, n);
    }
    let real: unsafe extern "C" fn(*const libc::c_char, *const libc::c_char, libc::size_t) -> i32 =
        std::mem::transmute(real);
    if records_comparison() && !a.is_null() && !b.is_null() {
        let (slice_a, slice_b) = strncmp_safe_slices(a, b, n);
        emit_cmp(b"strncmp", slice_a, slice_b);
    }
    real(a, b, n)
}

/// Build read-safe byte slices over the strncmp operands.
///
/// strncmp stops at the first null byte in either operand, so a
/// caller that passes a huge `n` against a short string is perfectly
/// legal. The hook must respect that bound or `from_raw_parts` reads
/// past the buffer (heap OOB / SEGV in the harness). We cap with
/// strnlen on each side, then with `MAX_OPERAND_BYTES`, before handing
/// the slice to the JSON emitter.
///
/// # Safety
///
/// Caller must guarantee `a` and `b` are valid for reads up to
/// `min(n, MAX_OPERAND_BYTES)` bytes or terminate with a null within
/// that range. These are exactly the preconditions a well-formed
/// strncmp caller already supplies.
unsafe fn strncmp_safe_slices<'a>(
    a: *const libc::c_char,
    b: *const libc::c_char,
    n: libc::size_t,
) -> (&'a [u8], &'a [u8]) {
    let cap = n.min(MAX_OPERAND_BYTES);
    let len_a = libc::strnlen(a, cap);
    let len_b = libc::strnlen(b, cap);
    (
        std::slice::from_raw_parts(a as *const u8, len_a),
        std::slice::from_raw_parts(b as *const u8, len_b),
    )
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(
    a: *const libc::c_void,
    b: *const libc::c_void,
    n: libc::size_t,
) -> i32 {
    let real = REAL_MEMCMP.ptr() as *const ();
    if real.is_null() {
        return libc::memcmp(a, b, n);
    }
    let real: unsafe extern "C" fn(*const libc::c_void, *const libc::c_void, libc::size_t) -> i32 =
        std::mem::transmute(real);
    if records_comparison() && !a.is_null() && !b.is_null() {
        let len = n.min(MAX_OPERAND_BYTES);
        let slice_a = std::slice::from_raw_parts(a as *const u8, len);
        let slice_b = std::slice::from_raw_parts(b as *const u8, len);
        emit_cmp(b"memcmp", slice_a, slice_b);
    }
    real(a, b, n)
}

#[cfg(test)]
mod tests {
    use super::CmpLog;
    use crate::sdk::FakeResource;

    #[test]
    fn cmplog_plugin_metadata_matches_manifest() {
        let plugin = CmpLog;
        assert_eq!(plugin.name(), "cmplog");
        assert_eq!(
            plugin.intercepts(),
            &[b"strcmp\0" as &[u8], b"strncmp\0", b"memcmp\0"]
        );
        assert!(plugin.describe().contains("strcmp/strncmp/memcmp"));
    }

    #[test]
    fn hex_into_encodes_bytes_lowercase() {
        let mut buf = [0u8; super::MAX_OPERAND_BYTES * 2];
        let out = super::hex_into(&[0xab, 0x01, 0xff], &mut buf);
        assert_eq!(out, b"ab01ff");
    }

    #[test]
    fn hex_into_caps_at_max_operand_bytes() {
        let input = [0xCDu8; super::MAX_OPERAND_BYTES + 10];
        let mut buf = [0u8; super::MAX_OPERAND_BYTES * 2];
        let out = super::hex_into(&input, &mut buf);
        assert_eq!(out.len(), super::MAX_OPERAND_BYTES * 2);
    }

    #[test]
    fn strncmp_safe_slices_caps_at_null_terminator_when_n_is_huge() {
        use std::ffi::CString;
        let a = CString::new("ab").unwrap();
        let b = CString::new("cd").unwrap();
        // n=1000 but strings are only 2 bytes — must NOT read past null.
        let (sa, sb) = unsafe { super::strncmp_safe_slices(a.as_ptr(), b.as_ptr(), 1000) };
        assert_eq!(sa, b"ab");
        assert_eq!(sb, b"cd");
    }

    #[test]
    fn strncmp_safe_slices_respects_explicit_n_when_smaller_than_string() {
        use std::ffi::CString;
        let a = CString::new("abcdef").unwrap();
        let b = CString::new("ghijkl").unwrap();
        let (sa, sb) = unsafe { super::strncmp_safe_slices(a.as_ptr(), b.as_ptr(), 3) };
        assert_eq!(sa, b"abc");
        assert_eq!(sb, b"ghi");
    }

    #[test]
    fn strncmp_safe_slices_caps_at_max_operand_bytes() {
        use std::ffi::CString;
        let long = "x".repeat(super::MAX_OPERAND_BYTES + 50);
        let a = CString::new(long.clone()).unwrap();
        let b = CString::new(long).unwrap();
        let (sa, sb) = unsafe { super::strncmp_safe_slices(a.as_ptr(), b.as_ptr(), 10_000) };
        assert_eq!(sa.len(), super::MAX_OPERAND_BYTES);
        assert_eq!(sb.len(), super::MAX_OPERAND_BYTES);
    }
}
