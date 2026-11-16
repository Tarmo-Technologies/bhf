// SPDX-License-Identifier: Apache-2.0

//! Fixed-buffer JSONL emitter. Each event is formatted into a 4 KiB
//! stack buffer and emitted via libc::write(2) to a per-process log
//! fd opened on first use. No heap allocations — the host process
//! may be inside its own allocator on the path we're called from.
//!
//! The output fd path comes from the `BHF_RUNTRACE_LOG` env var.
//! When that var is unset (host is not running under bhf auto),
//! every emit() is a no-op.

use std::ffi::CString;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};

/// Sentinel: fd not yet opened. -2 instead of -1 because some
/// system calls genuinely return -1 as a valid (just-failed) fd.
const FD_UNINITIALIZED: i32 = -2;
const FD_DISABLED: i32 = -1;

static LOG_FD: AtomicI32 = AtomicI32::new(FD_UNINITIALIZED);

/// Bytes written to the log so far. Once this exceeds
/// `MAX_LOG_BYTES` the shim stops appending — fuzz campaigns can
/// otherwise produce multi-GiB runtrace files that DoS the parent
/// process trying to parse them. Unique locators are deduplicated
/// at aggregation time, so dropping repeated events past the cap
/// loses no information the report would have used.
static LOG_BYTES: AtomicU64 = AtomicU64::new(0);

const EVENT_BUFFER_SIZE: usize = 4096;

/// Cap each runtrace log at 16 MiB. Anything past that is dropped
/// silently. Sized to hold ~300k events at the average event width.
const MAX_LOG_BYTES: u64 = 16 * 1024 * 1024;

/// Append a pre-formatted JSON line (newline-terminated) to the
/// runtrace log. Silent when no log is configured or the per-log
/// byte cap has been reached.
pub fn emit_raw(line: &[u8]) {
    let fd = ensure_fd();
    if fd < 0 {
        return;
    }
    let new_total = LOG_BYTES.fetch_add(line.len() as u64, Ordering::Relaxed) + line.len() as u64;
    if new_total > MAX_LOG_BYTES {
        return;
    }
    // Atomic write: a single write(2) under PIPE_BUF (4096) is
    // guaranteed atomic vs. other writers on POSIX. The buffer here
    // is exactly EVENT_BUFFER_SIZE, so we never exceed.
    unsafe {
        let _ = libc::write(fd, line.as_ptr().cast(), line.len());
    }
}

/// The size of the runtrace log, which every process writing it adds to:
/// `fstat` of the open log. `None` when no log is open or `fstat` fails.
pub fn log_len() -> Option<u64> {
    let fd = ensure_fd();
    if fd < 0 {
        return None;
    }
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `fd` is the open log and `stat` a writable `struct stat`.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: fstat succeeded and filled `stat`.
    Some(unsafe { stat.assume_init() }.st_size as u64)
}

/// The event of the line the shim starts its writes to a runtrace log with.
pub const SHIM_LOADED_EVENT: &str = "shim_loaded";

/// The whole marker line, `SHIM_LOADED_EVENT` as a runtrace event.
const SHIM_LOADED_LINE: &[u8] = b"{\"e\":\"shim_loaded\"}\n";

/// How far into the log the shim looks for a marker an earlier process wrote.
/// bhf looks for it as far, so a marker the shim finds there is one bhf finds.
const MARKER_SCAN_BYTES: usize = 64 * 1024;

/// Open the runtrace log as soon as the shim is loaded, so a run whose target
/// touches nothing the shim records still gets the load marker that
/// [`ensure_fd`] writes. bhf removes the log before a run and reads that line
/// afterwards as proof that the shim was preloaded; a harness the dynamic
/// loader did not preload the shim into (a path `LD_PRELOAD` splits, a library
/// it refuses to load) leaves none. The log's existence proves nothing: the
/// fuzz driver opens the same path for its comparison records whether or not
/// the shim is loaded.
#[used]
#[link_section = ".init_array"]
static OPEN_LOG_AT_LOAD: extern "C" fn() = open_log_at_load;

extern "C" fn open_log_at_load() {
    // A hook guard, so the `open` of the log (which may bind to the shim's own
    // `open` hook) is not itself recorded.
    if let Some(_guard) = crate::reentrancy::HookGuard::acquire() {
        ensure_fd();
    }
}

/// Whether the log behind `fd` already holds the load marker as a line within
/// its first `MARKER_SCAN_BYTES`, written by another process with the shim (an
/// exec'd child of the target, an earlier run appending to the same log).
/// False when the log cannot be read. One stack buffer and `pread`, no heap.
fn log_holds_marker(fd: i32) -> bool {
    let mut buf = [0u8; EVENT_BUFFER_SIZE];
    // Bytes carried into the next read, so a marker split across two reads is
    // still seen whole, together with the byte before it.
    let carry = SHIM_LOADED_LINE.len();
    let mut held = 0usize;
    let mut buf_starts_file = true;
    let mut offset = 0usize;
    while offset < MARKER_SCAN_BYTES {
        let want = (buf.len() - held).min(MARKER_SCAN_BYTES - offset);
        // SAFETY: the destination is the unused tail of `buf`, at least
        // `want` bytes long.
        let n = unsafe {
            libc::pread(
                fd,
                buf[held..].as_mut_ptr().cast(),
                want,
                offset as libc::off_t,
            )
        };
        if n <= 0 {
            return false;
        }
        offset += n as usize;
        let filled = held + n as usize;
        if holds_marker_line(&buf[..filled], buf_starts_file) {
            return true;
        }
        if filled > carry {
            buf.copy_within(filled - carry..filled, 0);
            held = carry;
            buf_starts_file = false;
        } else {
            held = filled;
        }
    }
    false
}

/// Whether `bytes` holds the marker line at the start of a line: right after a
/// newline, or at index 0 when `bytes` starts the file. A marker at index 0 of
/// a later window lies wholly in the previous one, where it was checked
/// together with the byte before it.
fn holds_marker_line(bytes: &[u8], starts_file: bool) -> bool {
    bytes
        .windows(SHIM_LOADED_LINE.len())
        .enumerate()
        .any(|(at, window)| {
            window == SHIM_LOADED_LINE
                && if at == 0 {
                    starts_file
                } else {
                    bytes[at - 1] == b'\n'
                }
        })
}

/// Open the log with read access too, so [`log_holds_marker`] can look into
/// it; a log that is only writable is opened write-only.
fn open_log(path: &CString) -> i32 {
    let flags = libc::O_APPEND | libc::O_CREAT | libc::O_CLOEXEC;
    // SAFETY: `path` is a NUL-terminated C string.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | flags, 0o644) };
    if fd >= 0 {
        return fd;
    }
    // SAFETY: as above.
    unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | flags, 0o644) }
}

/// The log fd, opened on the first call in this process. That first open
/// writes the load marker, unless the log already holds one, before the event
/// that caused the open: glibc runs the constructors of a program's other
/// libraries, and of any library preloaded after the shim, before the shim's
/// own, with the shim's hooks already bound, so a hooked call there (libgomp
/// and GLib read their settings with `getenv`) can open the log before the
/// shim's constructor runs. A forked child inherits the open fd and writes no
/// second marker; an exec'd one finds the marker already in the log. Two
/// processes starting at the same moment may both write it, which consumers
/// tolerate.
fn ensure_fd() -> i32 {
    let cached = LOG_FD.load(Ordering::Relaxed);
    if cached != FD_UNINITIALIZED {
        return cached;
    }
    // Opening the log and looking into it may fail on the way (a log only
    // writable fails the read-write open and then `pread`, a FIFO fails
    // `pread`), and the caller may be the shim's constructor or a hook that
    // leaves `errno` alone: the program must see the `errno` it had.
    let _errno = ErrnoKept::now();
    // Open the log file. Use libc directly so we don't accidentally
    // wind up inside our own hooked open() (which would recurse).
    let path = match std::env::var_os("BHF_RUNTRACE_LOG") {
        Some(p) => p,
        None => {
            LOG_FD.store(FD_DISABLED, Ordering::Relaxed);
            return FD_DISABLED;
        }
    };
    // Process-scope the shim: a crash makes the statically linked sanitizer
    // spawn an external symbolizer (llvm-symbolizer / addr2line) which inherits
    // our LD_PRELOAD *and* the shared BHF_RUNTRACE_LOG path. Without this
    // gate the symbolizer's own getenv/open probes (OPENSSL_*, LLVM_*,
    // ~/.cache/llvm-debuginfod, ...) would be appended to the TARGET's runtrace
    // and misreported as the target's faked env vars / missing deps. Detected
    // once, at first log-open, so the whole non-target child stays silent — and
    // the very event that triggered detection is dropped (this runs before the
    // write in `emit_raw`).
    if process_is_symbolizer() {
        LOG_FD.store(FD_DISABLED, Ordering::Relaxed);
        return FD_DISABLED;
    }
    let path_cstr = match CString::new(path.as_encoded_bytes()) {
        Ok(c) => c,
        Err(_) => {
            LOG_FD.store(FD_DISABLED, Ordering::Relaxed);
            return FD_DISABLED;
        }
    };
    let fd = open_log(&path_cstr);
    if fd < 0 {
        LOG_FD.store(FD_DISABLED, Ordering::Relaxed);
        return FD_DISABLED;
    }
    // Two threads may both get here first; the one that stores its fd marks
    // the log, the other closes its own and uses the stored one.
    if let Err(stored) =
        LOG_FD.compare_exchange(FD_UNINITIALIZED, fd, Ordering::AcqRel, Ordering::Acquire)
    {
        // SAFETY: `fd` is this call's own, unshared descriptor.
        unsafe {
            libc::close(fd);
        }
        return stored;
    }
    if !log_holds_marker(fd) {
        emit_raw(SHIM_LOADED_LINE);
    }
    fd
}

/// The calling thread's `errno`, put back when this is dropped.
struct ErrnoKept(libc::c_int);

impl ErrnoKept {
    fn now() -> Self {
        // SAFETY: `__errno_location` returns the calling thread's errno slot.
        Self(unsafe { *libc::__errno_location() })
    }
}

impl Drop for ErrnoKept {
    fn drop(&mut self) {
        // SAFETY: as in `now`.
        unsafe { *libc::__errno_location() = self.0 };
    }
}

/// True when THIS process is a crash-symbolizer helper the sanitizer spawned
/// (llvm-symbolizer / addr2line / …), read once from `/proc/self/cmdline`.
/// Signal-safe: a single stack buffer and three raw libc syscalls, no heap.
/// `libc::open` here either binds to our own `open` hook — which short-circuits
/// without logging because a hook is already active when `ensure_fd` runs — or
/// to the real `open`; either way the probe is never itself recorded.
fn process_is_symbolizer() -> bool {
    let fd = unsafe {
        libc::open(
            c"/proc/self/cmdline".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return false;
    }
    let mut buf = [0u8; 256];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    unsafe {
        libc::close(fd);
    }
    if n <= 0 {
        return false;
    }
    let n = n as usize;
    // argv[0] is the first NUL-delimited field of /proc/self/cmdline.
    let arg0 = match buf[..n].iter().position(|&b| b == 0) {
        Some(i) => &buf[..i],
        None => &buf[..n],
    };
    let base = match arg0.iter().rposition(|&b| b == b'/') {
        Some(i) => &arg0[i + 1..],
        None => arg0,
    };
    basename_is_symbolizer(base)
}

/// Whether a process basename is one of the sanitizer's symbolization helpers.
/// Versioned forms (`llvm-symbolizer-17`) match via the `llvm-` prefixes.
fn basename_is_symbolizer(base: &[u8]) -> bool {
    base == b"addr2line"
        || base == b"atos"
        || base.starts_with(b"llvm-symbolizer")
        || base.starts_with(b"llvm-addr2line")
}

/// Stack-allocated JSON line builder. Use `Builder::new(b"open")` to
/// start, then `.field_str` / `.field_i64` / `.field_null`, finally
/// `.emit()` to flush. Truncates silently when the buffer fills.
pub struct Builder {
    buf: [u8; EVENT_BUFFER_SIZE],
    len: usize,
    truncated: bool,
}

impl Builder {
    pub fn new(event_name: &[u8]) -> Self {
        let mut b = Self {
            buf: [0u8; EVENT_BUFFER_SIZE],
            len: 0,
            truncated: false,
        };
        b.write_byte(b'{');
        b.write_kv_open(b"e");
        b.write_str_quoted(event_name);
        b
    }

    /// Add a `"key":"value"` pair.
    pub fn field_str(&mut self, key: &[u8], value: &[u8]) {
        self.write_byte(b',');
        self.write_kv_open(key);
        self.write_str_quoted(value);
    }

    /// Add a `"key":<integer>` pair.
    pub fn field_i64(&mut self, key: &[u8], value: i64) {
        self.write_byte(b',');
        self.write_kv_open(key);
        self.write_i64(value);
    }

    pub fn field_null(&mut self, key: &[u8]) {
        self.write_byte(b',');
        self.write_kv_open(key);
        self.write_bytes(b"null");
    }

    pub fn emit(mut self) {
        self.write_byte(b'}');
        self.write_byte(b'\n');
        emit_raw(&self.buf[..self.len]);
    }

    fn write_byte(&mut self, b: u8) {
        if self.len >= self.buf.len() {
            self.truncated = true;
            return;
        }
        self.buf[self.len] = b;
        self.len += 1;
    }

    fn write_bytes(&mut self, bs: &[u8]) {
        for b in bs {
            self.write_byte(*b);
        }
    }

    fn write_kv_open(&mut self, key: &[u8]) {
        self.write_byte(b'"');
        self.write_bytes(key);
        self.write_bytes(b"\":");
    }

    fn write_str_quoted(&mut self, value: &[u8]) {
        self.write_byte(b'"');
        for &b in value {
            match b {
                b'"' => self.write_bytes(b"\\\""),
                b'\\' => self.write_bytes(b"\\\\"),
                b'\n' => self.write_bytes(b"\\n"),
                b'\r' => self.write_bytes(b"\\r"),
                b'\t' => self.write_bytes(b"\\t"),
                0x20..=0x7e => self.write_byte(b),
                // Non-ASCII / control bytes: render as \uXXXX
                _ => {
                    let hi = (b >> 4) & 0xf;
                    let lo = b & 0xf;
                    self.write_bytes(b"\\u00");
                    self.write_byte(hex_digit(hi));
                    self.write_byte(hex_digit(lo));
                }
            }
        }
        self.write_byte(b'"');
    }

    fn write_i64(&mut self, value: i64) {
        if value == 0 {
            self.write_byte(b'0');
            return;
        }
        let mut tmp = [0u8; 20];
        let mut n = value;
        let mut neg = false;
        if n < 0 {
            neg = true;
            // Avoid overflow on i64::MIN.
            n = n.wrapping_neg();
        }
        let mut idx = tmp.len();
        let mut u = n as u64;
        while u > 0 {
            idx -= 1;
            tmp[idx] = b'0' + (u % 10) as u8;
            u /= 10;
        }
        if neg {
            self.write_byte(b'-');
        }
        self.write_bytes(&tmp[idx..]);
    }
}

fn hex_digit(n: u8) -> u8 {
    if n < 10 {
        b'0' + n
    } else {
        b'a' + n - 10
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_renders_simple_event() {
        let mut b = Builder::new(b"getenv");
        b.field_str(b"n", b"FOO_HOME");
        b.field_null(b"r");
        // We can't directly call emit() in a test because it writes
        // to the log fd. Instead, finalize manually and read buf.
        b.write_byte(b'}');
        let out = std::str::from_utf8(&b.buf[..b.len]).unwrap();
        assert_eq!(out, r#"{"e":"getenv","n":"FOO_HOME","r":null}"#);
    }

    #[test]
    fn builder_renders_integer() {
        let mut b = Builder::new(b"open");
        b.field_str(b"p", b"/etc/foo");
        b.field_i64(b"r", -1);
        b.field_i64(b"n", 2);
        b.write_byte(b'}');
        let out = std::str::from_utf8(&b.buf[..b.len]).unwrap();
        assert_eq!(out, r#"{"e":"open","p":"/etc/foo","r":-1,"n":2}"#);
    }

    #[test]
    fn builder_escapes_quotes_and_backslashes() {
        let mut b = Builder::new(b"open");
        b.field_str(b"p", b"/etc/\"weird\"/path");
        b.write_byte(b'}');
        let out = std::str::from_utf8(&b.buf[..b.len]).unwrap();
        assert!(out.contains(r#"\"weird\""#), "got {out}");
    }

    #[test]
    fn symbolizer_basenames_are_recognized() {
        assert!(basename_is_symbolizer(b"llvm-symbolizer"));
        assert!(basename_is_symbolizer(b"llvm-symbolizer-17"));
        assert!(basename_is_symbolizer(b"addr2line"));
        assert!(basename_is_symbolizer(b"llvm-addr2line"));
        assert!(basename_is_symbolizer(b"atos"));
        // A genuine fuzz target binary is not a symbolizer.
        assert!(!basename_is_symbolizer(b"my_target_fuzzer"));
        assert!(!basename_is_symbolizer(b"parse"));
        assert!(!basename_is_symbolizer(b""));
    }

    /// Whether the shim would find a marker in a log holding `bytes`.
    fn log_with(bytes: &[u8]) -> bool {
        use std::os::fd::AsRawFd;
        // Removed when this scope ends.
        let path_tmp = tempfile::Builder::new()
            .prefix("bhf-")
            .tempdir()
            .expect("create test dir");
        let path = path_tmp.path().join(format!(
            "bhf-shim-marker-scan-{}-{}",
            std::process::id(),
            bytes.len()
        ));
        std::fs::write(&path, bytes).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let found = log_holds_marker(file.as_raw_fd());
        let _ = std::fs::remove_file(&path);
        found
    }

    #[test]
    fn a_marker_is_found_as_a_whole_line_within_the_scanned_window() {
        let mut marker = Builder::new(SHIM_LOADED_EVENT.as_bytes());
        marker.write_byte(b'}');
        marker.write_byte(b'\n');
        assert_eq!(&marker.buf[..marker.len], SHIM_LOADED_LINE);

        let record = b"{\"e\":\"cmplog\",\"a\":\"00\",\"b\":\"01\"}\n";
        assert!(!log_with(b""), "an empty log");
        assert!(!log_with(record), "a log of other records");
        assert!(log_with(SHIM_LOADED_LINE), "a log the marker starts");
        assert!(
            log_with(&[&record[..], SHIM_LOADED_LINE].concat()),
            "a marker after another record"
        );
        assert!(
            !log_with(&[b"{\"x\":1}".as_slice(), SHIM_LOADED_LINE].concat()),
            "the marker's bytes in the middle of a line"
        );
        assert!(
            !log_with(&SHIM_LOADED_LINE[..SHIM_LOADED_LINE.len() - 1]),
            "a marker without its newline"
        );
        // A marker split across two reads, at every offset around the edge.
        for split in 0..=SHIM_LOADED_LINE.len() + 1 {
            let mut log = vec![b' '; EVENT_BUFFER_SIZE - split - 1];
            log.push(b'\n');
            log.extend_from_slice(SHIM_LOADED_LINE);
            assert!(
                log_with(&log),
                "a marker split {split} bytes before a read's end"
            );
        }
        // The scan covers the window bhf reads, and no further.
        let mut last = vec![b' '; MARKER_SCAN_BYTES - SHIM_LOADED_LINE.len() - 1];
        last.push(b'\n');
        last.extend_from_slice(SHIM_LOADED_LINE);
        assert!(log_with(&last), "a marker that ends the window");
        let mut beyond = vec![b' '; MARKER_SCAN_BYTES - SHIM_LOADED_LINE.len()];
        beyond.push(b'\n');
        beyond.extend_from_slice(SHIM_LOADED_LINE);
        assert!(!log_with(&beyond), "a marker past the window");
    }

    #[test]
    fn builder_truncates_at_buffer_size() {
        let big: Vec<u8> = vec![b'a'; EVENT_BUFFER_SIZE * 2];
        let mut b = Builder::new(b"open");
        b.field_str(b"p", &big);
        // No panic, no oob write.
        assert!(b.len <= EVENT_BUFFER_SIZE);
    }
}
