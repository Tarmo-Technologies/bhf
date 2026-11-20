// SPDX-License-Identifier: Apache-2.0

//! connect / getaddrinfo audit hooks. Records every ECONNREFUSED
//! / EAI_NONAME / EAI_AGAIN that points at an off-loopback
//! address. The Slice-C runtime will later substitute these with
//! socketpair() peers; for now we just observe.
//!
//! Also the server side's desocket mode (`BHF_DESOCKET=1`, #312): `bind`,
//! `listen` and `accept` serve a TCP server's first connection from the fuzz
//! input; see the section below.
//!
//! Safety: every #[no_mangle] extern "C" fn here is invoked by the
//! dynamic linker as a libc symbol. Caller-supplied pointers must
//! satisfy the matching libc function's contract — we forward them
//! to the real implementation unchanged.

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::missing_transmute_annotations)]
#![allow(clippy::needless_range_loop)]

use crate::dlsym::ResolvedFn;
use crate::jsonl::Builder;
use crate::policy::should_audit_endpoint;
use crate::reentrancy::HookGuard;
use std::ffi::CStr;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicU8, Ordering};

static REAL_CONNECT: ResolvedFn = ResolvedFn::new(b"connect\0");
static REAL_GETADDRINFO: ResolvedFn = ResolvedFn::new(b"getaddrinfo\0");

fn save_errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

fn restore_errno(saved: i32) {
    unsafe { *libc::__errno_location() = saved };
}

/// Minimum run of fuzz-input-derived bytes a destination must contain before it
/// is treated as taint (#422). Matches the floor the other sink hooks use.
const TAINT_MIN_LEN: usize = 4;

/// Emit a `net_egress` sink event for a network destination reached during a
/// fuzz execution, tagged with byte-origin taint when a contiguous run of the
/// destination came from the current fuzz input. Emitted on every egress to a
/// real endpoint (tainted or not) so the CLI's SSRF sink oracle (BHF-433) can
/// confirm a fuzz-controlled destination and suppress a constant one the
/// auto-dictionary merely echoed into an input.
fn emit_egress(api: &[u8], dest: &[u8]) {
    if dest.is_empty() {
        return;
    }
    let mut b = Builder::new(b"net_egress");
    b.field_str(b"a", api);
    b.field_str(b"d", dest);
    if let Some((offset, _len)) = crate::fakes::fuzz_input::input_derived_run(dest, TAINT_MIN_LEN) {
        b.field_i64(b"u", 1);
        b.field_i64(b"o", offset as i64);
    }
    b.emit();
}

/// Render an unsigned integer into `out[n..]` as decimal ASCII.
/// Returns the new write offset. Width-limited to `max_digits`.
/// No heap allocations.
fn write_uint(out: &mut [u8; 128], mut n: usize, mut v: u32, max_digits: usize) -> usize {
    let mut digits = [0u8; 5];
    let mut count = 0usize;
    if v == 0 {
        digits[0] = b'0';
        count = 1;
    } else {
        while v > 0 && count < max_digits {
            digits[max_digits - 1 - count] = b'0' + (v % 10) as u8;
            v /= 10;
            count += 1;
        }
        // Shift digits to start of array.
        for j in 0..count {
            digits[j] = digits[max_digits - count + j];
        }
    }
    for j in 0..count {
        if n < out.len() {
            out[n] = digits[j];
            n += 1;
        }
    }
    n
}

/// Render a sockaddr to a short printable form so the report can
/// list it. Falls back to "?" on unknown families. No heap allocs.
unsafe fn render_sockaddr(
    addr: *const libc::sockaddr,
    _len: libc::socklen_t,
    out: &mut [u8; 128],
) -> (i32, usize) {
    if addr.is_null() {
        return (0, 0);
    }
    let family = (*addr).sa_family as i32;
    match family {
        f if f == libc::AF_UNIX => {
            // sa_data starts at offset 2. Path is up to 108 bytes.
            let sun = addr as *const libc::sockaddr_un;
            let path_ptr = (*sun).sun_path.as_ptr() as *const u8;
            let path_max = 108_usize.min(out.len());
            let mut n = 0;
            while n < path_max {
                let c = *path_ptr.add(n);
                if c == 0 {
                    break;
                }
                out[n] = c;
                n += 1;
            }
            (f, n)
        }
        f if f == libc::AF_INET => {
            let sin = addr as *const libc::sockaddr_in;
            let s_addr = u32::from_be((*sin).sin_addr.s_addr);
            let port = u16::from_be((*sin).sin_port);
            let octets = [
                ((s_addr >> 24) & 0xff) as u8,
                ((s_addr >> 16) & 0xff) as u8,
                ((s_addr >> 8) & 0xff) as u8,
                (s_addr & 0xff) as u8,
            ];
            let mut n = 0;
            for (i, oct) in octets.iter().enumerate() {
                if i > 0 && n < out.len() {
                    out[n] = b'.';
                    n += 1;
                }
                n = write_uint(out, n, *oct as u32, 3);
            }
            if n < out.len() {
                out[n] = b':';
                n += 1;
            }
            n = write_uint(out, n, port as u32, 5);
            (f, n)
        }
        _ => (family, 0),
    }
}

#[no_mangle]
pub unsafe extern "C" fn connect(
    sockfd: libc::c_int,
    addr: *const libc::sockaddr,
    addrlen: libc::socklen_t,
) -> libc::c_int {
    let real = REAL_CONNECT.ptr() as *const ();
    if real.is_null() {
        return libc::connect(sockfd, addr, addrlen);
    }
    let real: unsafe extern "C" fn(
        libc::c_int,
        *const libc::sockaddr,
        libc::socklen_t,
    ) -> libc::c_int = std::mem::transmute(real);
    let result = real(sockfd, addr, addrlen);
    let saved_errno = save_errno();
    // The shim's own work from here on: the endpoint is classified before a
    // hook guard is held, and those comparisons are not the target's.
    let _own = crate::reentrancy::OwnWork::enter();
    // #422: emit the SSRF sink event for every egress to a real endpoint
    // (regardless of success), so a fuzz-controlled destination is confirmed and
    // a constant one is suppressed by the cross-execution correlator (BHF-433).
    if let Some(_g) = HookGuard::acquire() {
        let mut buf = [0u8; 128];
        let (family, n) = render_sockaddr(addr, addrlen, &mut buf);
        if should_audit_endpoint(family, &buf[..n]) {
            emit_egress(b"connect", &buf[..n]);
        }
    }
    if result < 0 && (saved_errno == libc::ECONNREFUSED || saved_errno == libc::ENOENT) {
        if let Some(_g) = HookGuard::acquire() {
            let mut buf = [0u8; 128];
            let (family, n) = render_sockaddr(addr, addrlen, &mut buf);
            let addr_slice: &'static [u8] = std::mem::transmute(&buf[..n] as &[u8]);
            if should_audit_endpoint(family, addr_slice) {
                let mut b = Builder::new(b"connect");
                b.field_i64(b"f", family as i64);
                b.field_str(b"a", addr_slice);
                b.field_i64(b"r", result as i64);
                b.field_i64(b"n", saved_errno as i64);
                b.emit();
            }
        }
        if crate::fakes::mode::current().is_faking() {
            let mut name_buf = [0u8; 128];
            let (family, name_len) = render_sockaddr(addr, addrlen, &mut name_buf);
            let resource_name: &[u8] = &name_buf[..name_len];
            if crate::policy::should_audit_endpoint(family, resource_name) {
                let (local_fd, peer_fd) =
                    crate::fakes::peer::create_fake_socket_peer(resource_name);
                if local_fd >= 0 {
                    if libc::dup2(local_fd, sockfd) >= 0 {
                        let _ = libc::close(local_fd);
                        let _ = libc::close(peer_fd);
                        *libc::__errno_location() = 0;
                        return 0;
                    }
                    let _ = libc::close(local_fd);
                    let _ = libc::close(peer_fd);
                }
            }
        }
    }
    restore_errno(saved_errno);
    result
}

#[no_mangle]
pub unsafe extern "C" fn getaddrinfo(
    node: *const libc::c_char,
    service: *const libc::c_char,
    hints: *const libc::addrinfo,
    res: *mut *mut libc::addrinfo,
) -> libc::c_int {
    let real = REAL_GETADDRINFO.ptr() as *const ();
    if real.is_null() {
        return libc::getaddrinfo(node, service, hints, res);
    }
    let real: unsafe extern "C" fn(
        *const libc::c_char,
        *const libc::c_char,
        *const libc::addrinfo,
        *mut *mut libc::addrinfo,
    ) -> libc::c_int = std::mem::transmute(real);
    let result = real(node, service, hints, res);
    let saved_errno = save_errno();
    // #422: the hostname is the classic SSRF-controllable value — emit the SSRF
    // sink event for every off-localhost resolution (regardless of success) so a
    // fuzz-controlled hostname is confirmed and a constant one is suppressed
    // (BHF-433).
    if let Some(_g) = HookGuard::acquire() {
        if !node.is_null() {
            let name = CStr::from_ptr(node).to_bytes();
            if !name.starts_with(b"localhost") && name != b"::1" && !name.starts_with(b"127.") {
                emit_egress(b"getaddrinfo", name);
            }
        }
    }
    // getaddrinfo returns EAI_* codes (not errno); EAI_NONAME = -2.
    if result != 0 {
        if let Some(_g) = HookGuard::acquire() {
            if !node.is_null() {
                let name: &'static [u8] = std::mem::transmute(CStr::from_ptr(node).to_bytes());
                if !name.starts_with(b"localhost") && name != b"::1" && !name.starts_with(b"127.") {
                    let mut b = Builder::new(b"getaddrinfo");
                    b.field_str(b"n", name);
                    b.field_i64(b"r", result as i64);
                    b.emit();
                }
            }
        }
    }
    restore_errno(saved_errno);
    result
}

pub struct Net;

impl crate::sdk::FakeResource for Net {
    fn name(&self) -> &'static str {
        "net"
    }
    fn intercepts(&self) -> &'static [&'static [u8]] {
        &[b"connect\0", b"getaddrinfo\0"]
    }
    fn is_enabled(&self) -> bool {
        true
    }
    fn describe(&self) -> &'static str {
        "log connect/getaddrinfo failures and substitute fake socket peers"
    }
}

// ---------------------------------------------------------------------------
// Desocket mode (#312)
// ---------------------------------------------------------------------------
//
// With `BHF_DESOCKET=1` a TCP server runs its main loop on the fuzz input
// instead of the network, as libdesock and preeny's desock do. `bind` of an
// IPv4 or IPv6 stream socket is recorded and succeeds without binding, so no
// port is taken and a privileged one needs no privilege. `listen` succeeds and
// turns the socket into one end of a socketpair with a byte waiting, so a
// server that `poll`s, `select`s or `epoll`s its listener sees it ready. The
// first `accept` returns a pseudo-connection: the other end of a socketpair
// that holds the current input (the one the harness published, else stdin)
// followed by end of file, and keeps the peer end open so the server's
// replies are absorbed. A later `accept` ends the run once the server is done
// with that connection: it flushes stdio and ends the process with status 0.
// Until then the server is not done: a thread-per-connection server's handler
// may not have read the input yet, and an event loop drains its accept queue
// before it reads the connections it got. So until the connection is closed
// (or shut down for writing), a later `accept` on a non-blocking listener
// fails with EAGAIN, and one on a blocking listener waits while another
// thread (or the forked child it was handed to) works on it. When the server
// closes it, a byte arrives on each faked listener, so an edge-triggered
// `epoll` reports the listener again and the server calls `accept`. A
// single-threaded server that accepts again with the connection still open
// can never close it, so its run ends at once. Publishing an input starts the
// count over, and the C harness runs each input in a forked child while the
// mode is on (`bhf_shim_desocket_active`), so the fork-server lane keeps one
// process for the campaign.
//
// Limits: TCP only (a UDP server's `recvfrom` is not faked), a connection
// carries at most what fits in a socket buffer (about 200 KiB), and a server
// that writes more than that in reply blocks.

static REAL_BIND: ResolvedFn = ResolvedFn::new(b"bind\0");
static REAL_LISTEN: ResolvedFn = ResolvedFn::new(b"listen\0");
static REAL_ACCEPT: ResolvedFn = ResolvedFn::new(b"accept\0");
static REAL_ACCEPT4: ResolvedFn = ResolvedFn::new(b"accept4\0");
static REAL_GETSOCKNAME: ResolvedFn = ResolvedFn::new(b"getsockname\0");
static REAL_GETPEERNAME: ResolvedFn = ResolvedFn::new(b"getpeername\0");
static REAL_SETSOCKOPT: ResolvedFn = ResolvedFn::new(b"setsockopt\0");

/// The port a pseudo-connection's peer reports.
const DESOCKET_PEER_PORT: u16 = 40_000;
/// Cap on the input bytes read from stdin for a connection.
const DESOCKET_STDIN_CAP: usize = 1 << 20;
/// Sockets the mode tracks at once.
const DESOCKET_SLOTS: usize = 64;

/// Whether `BHF_DESOCKET` is exactly "1", read once from `environ`.
pub fn desocket_enabled() -> bool {
    static CACHED: AtomicU8 = AtomicU8::new(2); // 0=false, 1=true, 2=uninit
    let cached = CACHED.load(Ordering::Relaxed);
    if cached != 2 {
        return cached == 1;
    }
    let Some(enabled) =
        (unsafe { crate::hooks::determinism::environ_value_is(b"BHF_DESOCKET=", b"1") })
    else {
        return false;
    };
    CACHED.store(u8::from(enabled), Ordering::Relaxed);
    enabled
}

/// Whether the desocket mode is on, for the C harness, which then runs each
/// input in a forked child so the exit a later `accept` makes ends only that
/// child.
#[no_mangle]
pub extern "C" fn bhf_shim_desocket_active() -> libc::c_int {
    libc::c_int::from(desocket_enabled())
}

/// Whether the current input's connection has been handed out.
static SERVED: AtomicBool = AtomicBool::new(false);
/// The served connection: the server's end, and the peer end the shim keeps.
static SERVED_FD: AtomicI32 = AtomicI32::new(-1);
static SERVED_PEER: AtomicI32 = AtomicI32::new(-1);
/// The far ends of the faked listeners' socketpairs: a byte written there
/// makes the listener readable again.
static LISTENER_POKES: [AtomicI32; 8] = [const { AtomicI32::new(-1) }; 8];

/// A new input gets a new connection.
pub(crate) fn reset_for_input() {
    SERVED.store(false, Ordering::Relaxed);
    SERVED_FD.store(-1, Ordering::Relaxed);
    let peer = SERVED_PEER.swap(-1, Ordering::Relaxed);
    if peer >= 0 {
        unsafe { libc::syscall(libc::SYS_close, peer) };
    }
}

/// Read and drop what the server wrote to the served connection, so a long
/// reply never blocks it.
unsafe fn drain(peer: libc::c_int) {
    let mut sink = [0u8; 4096];
    while libc::recv(
        peer,
        sink.as_mut_ptr() as *mut libc::c_void,
        sink.len(),
        libc::MSG_DONTWAIT,
    ) > 0
    {}
}

/// Whether the server is done with the served connection: it closed it (in
/// every process that held it) or shut it down for writing.
unsafe fn served_connection_done(wait: bool) -> bool {
    let peer = SERVED_PEER.load(Ordering::Relaxed);
    if peer < 0 {
        return true;
    }
    loop {
        drain(peer);
        let mut poll = libc::pollfd {
            fd: peer,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = libc::poll(&mut poll, 1, if wait { -1 } else { 0 });
        if ready < 0 && *libc::__errno_location() == libc::EINTR {
            continue;
        }
        if ready < 0 || poll.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            return true;
        }
        if !wait {
            return false;
        }
    }
}

/// The number of threads in this process, from `/proc/self/stat`; 1 when it
/// cannot be read.
unsafe fn thread_count() -> u64 {
    let fd = libc::syscall(
        libc::SYS_openat,
        libc::AT_FDCWD,
        c"/proc/self/stat".as_ptr(),
        libc::O_RDONLY | libc::O_CLOEXEC,
    ) as libc::c_int;
    if fd < 0 {
        return 1;
    }
    let mut buf = [0u8; 1024];
    let n = libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
    libc::syscall(libc::SYS_close, fd);
    if n <= 0 {
        return 1;
    }
    let text = &buf[..n as usize];
    // After the command name: state is field 3, num_threads field 20.
    let Some(close) = text.iter().rposition(|byte| *byte == b')') else {
        return 1;
    };
    text[close + 1..]
        .split(|byte| *byte == b' ')
        .filter(|field| !field.is_empty())
        .nth(17)
        .and_then(|field| core::str::from_utf8(field).ok()?.parse().ok())
        .unwrap_or(1)
}

/// A later `accept` on a faked listener: end the run once the server is done
/// with the served connection, or tell a non-blocking listener to try again.
unsafe fn accept_again(fd: libc::c_int) -> libc::c_int {
    if !served_connection_done(false) {
        let nonblocking = libc::fcntl(fd, libc::F_GETFL) & libc::O_NONBLOCK != 0;
        if nonblocking {
            *libc::__errno_location() = libc::EAGAIN;
            return -1;
        }
        // Another thread, or the process the connection was handed to (this
        // one closed its descriptor), can still finish it.
        let served = SERVED_FD.load(Ordering::Relaxed);
        let held_here =
            served >= 0 && find(served).is_some_and(|faked| faked.kind == Kind::Connection);
        if thread_count() > 1 || !held_here {
            served_connection_done(true);
        }
    }
    // The server is back for another client: its one connection is done.
    libc::fflush(core::ptr::null_mut());
    libc::_exit(0);
}

/// A descriptor the target closed: when it was the served connection and the
/// server is now done with it, make each faked listener readable again, so an
/// edge-triggered event loop calls `accept` (which ends the run).
pub(crate) fn desocket_closed(fd: libc::c_int) {
    if !desocket_enabled() || fd < 0 || SERVED_FD.load(Ordering::Relaxed) != fd {
        return;
    }
    unsafe {
        if !served_connection_done(false) {
            return;
        }
        for poke in &LISTENER_POKES {
            let poke = poke.load(Ordering::Relaxed);
            if poke >= 0 {
                send_all(poke, b"!");
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Bound = 1,
    Listener = 2,
    Connection = 3,
}

#[derive(Clone, Copy)]
struct Faked {
    kind: Kind,
    family: libc::c_int,
    /// Host byte order.
    port: u16,
}

// One slot per faked socket: `occupied | kind << 56 | family << 48 | port <<
// 32 | fd`, and beside it the socket's inode, so a slot whose descriptor was
// closed and reused for another file is recognised as stale.
static SLOTS: [AtomicU64; DESOCKET_SLOTS] = [const { AtomicU64::new(0) }; DESOCKET_SLOTS];
static INODES: [AtomicU64; DESOCKET_SLOTS] = [const { AtomicU64::new(0) }; DESOCKET_SLOTS];
const OCCUPIED: u64 = 1 << 63;

fn inode_of(fd: libc::c_int) -> Option<u64> {
    let mut st: libc::stat = unsafe { core::mem::zeroed() };
    let rc = unsafe { libc::syscall(libc::SYS_fstat, fd, &mut st as *mut libc::stat) };
    (rc == 0).then_some(st.st_ino)
}

fn pack(fd: libc::c_int, faked: Faked) -> u64 {
    OCCUPIED
        | (faked.kind as u64) << 56
        | (faked.family as u64 & 0xff) << 48
        | u64::from(faked.port) << 32
        | u64::from(fd as u32)
}

fn unpack(word: u64) -> Option<(libc::c_int, Faked)> {
    if word & OCCUPIED == 0 {
        return None;
    }
    let kind = match (word >> 56) & 0x3f {
        1 => Kind::Bound,
        2 => Kind::Listener,
        3 => Kind::Connection,
        _ => return None,
    };
    Some((
        word as u32 as libc::c_int,
        Faked {
            kind,
            family: ((word >> 48) & 0xff) as libc::c_int,
            port: (word >> 32) as u16,
        },
    ))
}

/// The faked socket `fd` is, dropping a slot whose descriptor now names
/// another file.
fn find(fd: libc::c_int) -> Option<Faked> {
    for (slot, inode) in SLOTS.iter().zip(&INODES) {
        let Some((slot_fd, faked)) = unpack(slot.load(Ordering::Relaxed)) else {
            continue;
        };
        if slot_fd != fd {
            continue;
        }
        if inode_of(fd) == Some(inode.load(Ordering::Relaxed)) {
            return Some(faked);
        }
        slot.store(0, Ordering::Relaxed);
    }
    None
}

/// Record `fd` as `faked`, replacing an earlier record of it.
fn record(fd: libc::c_int, faked: Faked) {
    let Some(inode) = inode_of(fd) else {
        return;
    };
    let mut free = None;
    for (index, slot) in SLOTS.iter().enumerate() {
        match unpack(slot.load(Ordering::Relaxed)) {
            Some((slot_fd, _)) if slot_fd == fd => {
                free = Some(index);
                break;
            }
            None if free.is_none() => free = Some(index),
            _ => {}
        }
    }
    if let Some(index) = free {
        INODES[index].store(inode, Ordering::Relaxed);
        SLOTS[index].store(pack(fd, faked), Ordering::Relaxed);
    }
}

/// A loopback address of `family` with `port`, written to a caller's
/// `(addr, addrlen)` the way the kernel does: truncated to `*addrlen`, which
/// is then set to the address's full size.
unsafe fn write_address(
    addr: *mut libc::sockaddr,
    addrlen: *mut libc::socklen_t,
    family: libc::c_int,
    port: u16,
) {
    if addr.is_null() || addrlen.is_null() {
        return;
    }
    let mut storage: libc::sockaddr_storage = core::mem::zeroed();
    let size = if family == libc::AF_INET6 {
        let v6 = &mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in6;
        (*v6).sin6_family = libc::AF_INET6 as libc::sa_family_t;
        (*v6).sin6_port = port.to_be();
        (*v6).sin6_addr.s6_addr[15] = 1;
        core::mem::size_of::<libc::sockaddr_in6>()
    } else {
        let v4 = &mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in;
        (*v4).sin_family = libc::AF_INET as libc::sa_family_t;
        (*v4).sin_port = port.to_be();
        (*v4).sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]).to_be();
        core::mem::size_of::<libc::sockaddr_in>()
    };
    let room = (*addrlen as usize).min(size);
    core::ptr::copy_nonoverlapping(
        &storage as *const libc::sockaddr_storage as *const u8,
        addr as *mut u8,
        room,
    );
    *addrlen = size as libc::socklen_t;
}

/// Write `bytes` to `fd` without blocking, as much as the socket takes.
unsafe fn send_all(fd: libc::c_int, bytes: &[u8]) {
    let mut sent = 0;
    while sent < bytes.len() {
        let n = libc::send(
            fd,
            bytes[sent..].as_ptr() as *const libc::c_void,
            bytes.len() - sent,
            libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
        );
        if n <= 0 {
            return;
        }
        sent += n as usize;
    }
}

/// Fill the pseudo-connection's peer end with the current input, else
/// stdin, then end its writes so the server reads end of file after it.
unsafe fn feed(peer: libc::c_int) {
    let size = crate::fakes::fuzz_input::with_current(|bytes| bytes.len()).unwrap_or(0);
    let want = (size.max(64 * 1024) * 2).min(i32::MAX as usize) as libc::c_int;
    libc::setsockopt(
        peer,
        libc::SOL_SOCKET,
        libc::SO_SNDBUF,
        &want as *const libc::c_int as *const libc::c_void,
        core::mem::size_of::<libc::c_int>() as libc::socklen_t,
    );
    let published = crate::fakes::fuzz_input::with_current(|bytes| send_all(peer, bytes)).is_some();
    if !published {
        let mut chunk = [0u8; 4096];
        let mut total = 0;
        while total < DESOCKET_STDIN_CAP {
            let n = libc::read(0, chunk.as_mut_ptr() as *mut libc::c_void, chunk.len());
            if n <= 0 {
                break;
            }
            send_all(peer, &chunk[..n as usize]);
            total += n as usize;
        }
    }
    libc::shutdown(peer, libc::SHUT_WR);
}

/// The pseudo-connection for an `accept` on a faked listener, `None` when
/// `fd` is not one (the real call then runs).
unsafe fn desocket_accept(
    fd: libc::c_int,
    addr: *mut libc::sockaddr,
    addrlen: *mut libc::socklen_t,
    flags: libc::c_int,
) -> Option<libc::c_int> {
    if !desocket_enabled() {
        return None;
    }
    let listener = find(fd).filter(|faked| faked.kind == Kind::Listener)?;
    if SERVED.swap(true, Ordering::Relaxed) {
        return Some(accept_again(fd));
    }
    let mut pair = [0 as libc::c_int; 2];
    let kind = libc::SOCK_STREAM | (flags & (libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC));
    if libc::socketpair(libc::AF_UNIX, kind, 0, pair.as_mut_ptr()) != 0 {
        return Some(-1);
    }
    let (server, peer) = (pair[0], pair[1]);
    feed(peer);
    record(
        server,
        Faked {
            kind: Kind::Connection,
            ..listener
        },
    );
    SERVED_FD.store(server, Ordering::Relaxed);
    SERVED_PEER.store(peer, Ordering::Relaxed);
    write_address(addr, addrlen, listener.family, DESOCKET_PEER_PORT);
    Some(server)
}

#[no_mangle]
pub unsafe extern "C" fn bind(
    fd: libc::c_int,
    addr: *const libc::sockaddr,
    len: libc::socklen_t,
) -> libc::c_int {
    if desocket_enabled() && !addr.is_null() {
        let family = libc::c_int::from((*addr).sa_family);
        let mut socket_type: libc::c_int = 0;
        let mut type_len = core::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let stream = libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut socket_type as *mut libc::c_int as *mut libc::c_void,
            &mut type_len,
        ) == 0
            && socket_type == libc::SOCK_STREAM;
        let port = match family {
            libc::AF_INET if len as usize >= core::mem::size_of::<libc::sockaddr_in>() => {
                Some(u16::from_be((*(addr as *const libc::sockaddr_in)).sin_port))
            }
            libc::AF_INET6 if len as usize >= core::mem::size_of::<libc::sockaddr_in6>() => Some(
                u16::from_be((*(addr as *const libc::sockaddr_in6)).sin6_port),
            ),
            _ => None,
        };
        if let (true, Some(port)) = (stream, port) {
            record(
                fd,
                Faked {
                    kind: Kind::Bound,
                    family,
                    port,
                },
            );
            return 0;
        }
    }
    let real = REAL_BIND.ptr();
    if real.is_null() {
        return -1;
    }
    let real: unsafe extern "C" fn(
        libc::c_int,
        *const libc::sockaddr,
        libc::socklen_t,
    ) -> libc::c_int = std::mem::transmute(real);
    real(fd, addr, len)
}

#[no_mangle]
pub unsafe extern "C" fn listen(fd: libc::c_int, backlog: libc::c_int) -> libc::c_int {
    if desocket_enabled() {
        if let Some(bound) = find(fd).filter(|faked| faked.kind != Kind::Connection) {
            // Swap the socket for one end of a socketpair with a byte waiting,
            // keeping the descriptor's number and flags, so the listener polls
            // readable. The other end stays open to keep that byte there.
            let mut pair = [0 as libc::c_int; 2];
            if libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                pair.as_mut_ptr(),
            ) == 0
            {
                send_all(pair[1], b"!");
                let status = libc::fcntl(fd, libc::F_GETFL);
                let descriptor = libc::fcntl(fd, libc::F_GETFD);
                if libc::dup2(pair[0], fd) == fd {
                    if status >= 0 {
                        libc::fcntl(fd, libc::F_SETFL, status & libc::O_NONBLOCK);
                    }
                    if descriptor >= 0 {
                        libc::fcntl(fd, libc::F_SETFD, descriptor);
                    }
                }
                libc::syscall(libc::SYS_close, pair[0]);
                // The far end stays open: it keeps the byte there, and a
                // byte written to it wakes an edge-triggered listener.
                let _kept = LISTENER_POKES.iter().any(|slot| {
                    slot.compare_exchange(-1, pair[1], Ordering::Relaxed, Ordering::Relaxed)
                        .is_ok()
                });
            }
            record(
                fd,
                Faked {
                    kind: Kind::Listener,
                    ..bound
                },
            );
            return 0;
        }
    }
    let real = REAL_LISTEN.ptr();
    if real.is_null() {
        return -1;
    }
    let real: unsafe extern "C" fn(libc::c_int, libc::c_int) -> libc::c_int =
        std::mem::transmute(real);
    real(fd, backlog)
}

#[no_mangle]
pub unsafe extern "C" fn accept(
    fd: libc::c_int,
    addr: *mut libc::sockaddr,
    addrlen: *mut libc::socklen_t,
) -> libc::c_int {
    if let Some(connection) = desocket_accept(fd, addr, addrlen, 0) {
        return connection;
    }
    let real = REAL_ACCEPT.ptr();
    if real.is_null() {
        return -1;
    }
    let real: unsafe extern "C" fn(
        libc::c_int,
        *mut libc::sockaddr,
        *mut libc::socklen_t,
    ) -> libc::c_int = std::mem::transmute(real);
    real(fd, addr, addrlen)
}

#[no_mangle]
pub unsafe extern "C" fn accept4(
    fd: libc::c_int,
    addr: *mut libc::sockaddr,
    addrlen: *mut libc::socklen_t,
    flags: libc::c_int,
) -> libc::c_int {
    if let Some(connection) = desocket_accept(fd, addr, addrlen, flags) {
        return connection;
    }
    let real = REAL_ACCEPT4.ptr();
    if real.is_null() {
        return -1;
    }
    let real: unsafe extern "C" fn(
        libc::c_int,
        *mut libc::sockaddr,
        *mut libc::socklen_t,
        libc::c_int,
    ) -> libc::c_int = std::mem::transmute(real);
    real(fd, addr, addrlen, flags)
}

#[no_mangle]
pub unsafe extern "C" fn getsockname(
    fd: libc::c_int,
    addr: *mut libc::sockaddr,
    addrlen: *mut libc::socklen_t,
) -> libc::c_int {
    if desocket_enabled() {
        if let Some(faked) = find(fd) {
            write_address(addr, addrlen, faked.family, faked.port);
            return 0;
        }
    }
    let real = REAL_GETSOCKNAME.ptr();
    if real.is_null() {
        return -1;
    }
    let real: unsafe extern "C" fn(
        libc::c_int,
        *mut libc::sockaddr,
        *mut libc::socklen_t,
    ) -> libc::c_int = std::mem::transmute(real);
    real(fd, addr, addrlen)
}

#[no_mangle]
pub unsafe extern "C" fn getpeername(
    fd: libc::c_int,
    addr: *mut libc::sockaddr,
    addrlen: *mut libc::socklen_t,
) -> libc::c_int {
    if desocket_enabled() {
        if let Some(faked) = find(fd) {
            if faked.kind != Kind::Connection {
                *libc::__errno_location() = libc::ENOTCONN;
                return -1;
            }
            write_address(addr, addrlen, faked.family, DESOCKET_PEER_PORT);
            return 0;
        }
    }
    let real = REAL_GETPEERNAME.ptr();
    if real.is_null() {
        return -1;
    }
    let real: unsafe extern "C" fn(
        libc::c_int,
        *mut libc::sockaddr,
        *mut libc::socklen_t,
    ) -> libc::c_int = std::mem::transmute(real);
    real(fd, addr, addrlen)
}

#[no_mangle]
pub unsafe extern "C" fn setsockopt(
    fd: libc::c_int,
    level: libc::c_int,
    name: libc::c_int,
    value: *const libc::c_void,
    len: libc::socklen_t,
) -> libc::c_int {
    let real = REAL_SETSOCKOPT.ptr();
    let call_real = || -> libc::c_int {
        if real.is_null() {
            return -1;
        }
        let real: unsafe extern "C" fn(
            libc::c_int,
            libc::c_int,
            libc::c_int,
            *const libc::c_void,
            libc::socklen_t,
        ) -> libc::c_int = std::mem::transmute(real);
        real(fd, level, name, value, len)
    };
    // A faked listener or connection is a local socketpair: TCP and IP
    // options do not apply to it, so they succeed without effect.
    if desocket_enabled() && find(fd).is_some_and(|faked| faked.kind != Kind::Bound) {
        if level == libc::SOL_SOCKET {
            call_real();
        }
        return 0;
    }
    call_real()
}

pub struct Desocket;

impl crate::sdk::FakeResource for Desocket {
    fn name(&self) -> &'static str {
        "desocket"
    }
    fn intercepts(&self) -> &'static [&'static [u8]] {
        &[
            b"bind\0",
            b"listen\0",
            b"accept\0",
            b"accept4\0",
            b"getsockname\0",
            b"getpeername\0",
            b"setsockopt\0",
            b"bhf_shim_desocket_active\0",
        ]
    }
    fn is_enabled(&self) -> bool {
        desocket_enabled()
    }
    fn describe(&self) -> &'static str {
        "serve a TCP server's first accepted connection from the fuzz input, then end the run"
    }
}
