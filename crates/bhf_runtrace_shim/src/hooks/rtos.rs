// SPDX-License-Identifier: Apache-2.0

//! Vendor-RTOS channel virtualization (HDF-6 deliverable 2 + 3).
//!
//! The POSIX message-queue hooks in [`crate::hooks::mqueue`] deliver the fuzz
//! input to a partition's message loop through `mq_receive`. RTOS/radar code that
//! is fuzzed on the host in BHF's stub-isolation lane rarely uses POSIX `mq_*`
//! directly, though — it calls the vendor primitive its BSP provides: VxWorks
//! `msgQReceive`/`semTake`, FreeRTOS `xQueueReceive`, or cFS `CFE_SB_RcvMsg`.
//! Today those symbols resolve to inert `return 0`/`NULL` stubs (`c_stub_gen`),
//! so a consumer's `while (msgQReceive(...) != ERROR) { handle(msg); }` loop
//! either spins on empty messages or never advances, and the handler the fuzzer
//! wants to reach never runs on fuzz-controlled data.
//!
//! This module makes the vendor consume primitives fuzz-driven channels the exact
//! way `hooks/mqueue.rs` does for POSIX `mq_receive`: during a fuzz pass
//! (`is_faking()`), a receive delivers the current fuzz input as the message body
//! (mode-driven bytes — Empty → no message, Rng → per-channel pseudo-random,
//! FuzzDriven → the live fuzz input keyed per channel), a create returns a private
//! non-null fake handle so the consumer's `if (q == NULL)` check passes, and a
//! send is swallowed. Delivery is bounded per channel ([`DELIVERY_CAP`]) so a
//! `while (1)` receive loop terminates instead of spinning on the wrapping
//! fuzz-input cursor. Audit mode passes through to a real implementation if one
//! is resolvable (there rarely is host-side) and otherwise returns the same inert
//! value the constant stub would, so audit is never less transparent than today.
//!
//! These vendor APIs are NOT libc symbols: the shim can only interpose on them
//! when they resolve to it. A native consumer built host-side must therefore
//! leave them as undefined *weak* references (the auto pipeline stops stubbing a
//! symbol this module owns), which the dynamic linker binds to these strong
//! exports when the shim is `LD_PRELOAD`ed. BHF-authored scaffolding — no vendor
//! headers or code are used or required.
//!
//! This module also hosts the bare-metal MMIO fill helper
//! [`bhf_shim_mmio_fill`] (HDF-6 deliverable 3): a fixed-address `mmap` filled
//! from the fuzz input, for `*(volatile T*)ADDR` register reads the `LD_PRELOAD`
//! path cannot see (they are loads, not syscalls).

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::missing_transmute_annotations)]

use crate::dlsym::ResolvedFn;
use crate::jsonl::Builder;
use crate::reentrancy::HookGuard;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Max fuzz-driven messages delivered per receive channel before it reports
/// "empty". Matches the POSIX `mq_receive` cap: generous for multi-message
/// protocols, bounded so a receive loop cannot spin forever on the wrapping
/// fuzz-input cursor.
const DELIVERY_CAP: usize = 256;

/// Largest message body the shim will fill for one receive, so a bogus
/// `maxNbytes` cannot make the shim write megabytes into the caller's buffer.
/// The caller sized the buffer, so this only bounds our fill, never truncates a
/// buffer the caller believes is larger.
const MSG_FILL_CAP: usize = 64 * 1024;

static MSGQ_DELIVERED: AtomicUsize = AtomicUsize::new(0);
static XQUEUE_DELIVERED: AtomicUsize = AtomicUsize::new(0);
static CFE_DELIVERED: AtomicUsize = AtomicUsize::new(0);

// VxWorks return conventions.
const VX_OK: libc::c_int = 0;
const VX_ERROR: libc::c_int = -1;
// FreeRTOS BaseType_t conventions.
const PD_TRUE: libc::c_int = 1;
const PD_FALSE: libc::c_int = 0;
// cFE Software Bus status conventions (values are the published constants).
const CFE_SUCCESS: i32 = 0;
// A distinct non-success sentinel; a cFE app's receive loop breaks on any
// `!= CFE_SUCCESS`, so the exact value is immaterial (kept small and negative).
const CFE_SB_NO_MESSAGE: i32 = -14;

fn set_errno(value: i32) {
    unsafe {
        *libc::__errno_location() = value;
    }
}

fn log_rtos(event: &[u8], detail: i64) {
    if let Some(_g) = HookGuard::acquire() {
        let mut b = Builder::new(event);
        b.field_i64(b"r", detail);
        b.field_i64(b"v", 1);
        b.emit();
    }
}

/// A stable, non-null opaque handle for a faked create that carries no metadata
/// (VxWorks message queues and semaphores). The address is only ever compared to
/// NULL and handed back to our own receive/give hooks, never dereferenced by us.
fn opaque_handle() -> *mut libc::c_void {
    // The address of a process-lifetime static: non-null, stable, and reading
    // through it (should a caller do so) yields a defined zero byte.
    static SENTINEL: u8 = 0;
    &SENTINEL as *const u8 as *mut libc::c_void
}

/// Deliver a fuzz-controlled message body into `buf`, honouring the current pass
/// mode and the per-channel delivery cap. Returns the number of bytes written, or
/// `None` when the channel is empty / exhausted (the caller maps that to its own
/// error convention).
unsafe fn deliver_body(
    channel: &[u8],
    buf_ptr: *mut u8,
    max_len: usize,
    counter: &AtomicUsize,
) -> Option<usize> {
    // Empty pass: the external world is absent — no message available.
    if crate::fakes::mode::current() == crate::fakes::mode::Mode::Empty {
        return None;
    }
    // Bound the number of delivered messages so a receive loop terminates.
    if counter.fetch_add(1, Ordering::Relaxed) >= DELIVERY_CAP {
        return None;
    }
    if buf_ptr.is_null() || max_len == 0 {
        return Some(0);
    }
    let len = max_len.min(MSG_FILL_CAP);
    let out = std::slice::from_raw_parts_mut(buf_ptr, len);
    Some(crate::fakes::data::fill_bytes(channel, out))
}

// ---------------------------------------------------------------------------
// VxWorks message queues (msgQCreate / msgQReceive / msgQSend / msgQDelete)
// ---------------------------------------------------------------------------

/// `MSG_Q_ID msgQCreate(int maxMsgs, int maxMsgLength, int options)`.
#[no_mangle]
pub unsafe extern "C" fn msgQCreate(
    _max_msgs: libc::c_int,
    _max_msg_length: libc::c_int,
    _options: libc::c_int,
) -> *mut libc::c_void {
    if crate::fakes::mode::current().is_faking() {
        log_rtos(b"msgQCreate", 0);
        return opaque_handle();
    }
    let real = ResolvedFn::new(b"msgQCreate\0").ptr() as *const ();
    if real.is_null() {
        // No real VxWorks kernel host-side: match the inert stub (non-null id so
        // the caller's NULL check passes).
        return opaque_handle();
    }
    let real: unsafe extern "C" fn(libc::c_int, libc::c_int, libc::c_int) -> *mut libc::c_void =
        std::mem::transmute(real);
    real(_max_msgs, _max_msg_length, _options)
}

/// `int msgQReceive(MSG_Q_ID msgQId, char *buffer, UINT maxNbytes, int timeout)`
/// — returns the number of bytes received, or `ERROR` (-1) on timeout / empty.
#[no_mangle]
pub unsafe extern "C" fn msgQReceive(
    msg_q_id: *mut libc::c_void,
    buffer: *mut libc::c_char,
    max_nbytes: libc::c_uint,
    timeout: libc::c_int,
) -> libc::c_int {
    if crate::fakes::mode::current().is_faking() {
        match deliver_body(
            b"msgQReceive",
            buffer as *mut u8,
            max_nbytes as usize,
            &MSGQ_DELIVERED,
        ) {
            Some(n) => {
                log_rtos(b"msgQReceive", n as i64);
                return n as libc::c_int;
            }
            None => {
                // S_objLib_OBJ_TIMEOUT is the VxWorks convention; the caller only
                // ever tests the ERROR return, so a plain errno is enough.
                set_errno(libc::ETIMEDOUT);
                return VX_ERROR;
            }
        }
    }
    let real = ResolvedFn::new(b"msgQReceive\0").ptr() as *const ();
    if real.is_null() {
        set_errno(libc::ENOSYS);
        return VX_ERROR;
    }
    let real: unsafe extern "C" fn(
        *mut libc::c_void,
        *mut libc::c_char,
        libc::c_uint,
        libc::c_int,
    ) -> libc::c_int = std::mem::transmute(real);
    real(msg_q_id, buffer, max_nbytes, timeout)
}

/// `STATUS msgQSend(MSG_Q_ID, char *buffer, UINT nbytes, int timeout, int prio)`.
#[no_mangle]
pub unsafe extern "C" fn msgQSend(
    msg_q_id: *mut libc::c_void,
    buffer: *mut libc::c_char,
    nbytes: libc::c_uint,
    timeout: libc::c_int,
    priority: libc::c_int,
) -> libc::c_int {
    if crate::fakes::mode::current().is_faking() {
        // No peer partition to receive it — swallow like a POSIX mq_send.
        log_rtos(b"msgQSend", 0);
        return VX_OK;
    }
    let real = ResolvedFn::new(b"msgQSend\0").ptr() as *const ();
    if real.is_null() {
        return VX_OK;
    }
    let real: unsafe extern "C" fn(
        *mut libc::c_void,
        *mut libc::c_char,
        libc::c_uint,
        libc::c_int,
        libc::c_int,
    ) -> libc::c_int = std::mem::transmute(real);
    real(msg_q_id, buffer, nbytes, timeout, priority)
}

/// `STATUS msgQDelete(MSG_Q_ID)`.
#[no_mangle]
pub unsafe extern "C" fn msgQDelete(msg_q_id: *mut libc::c_void) -> libc::c_int {
    if crate::fakes::mode::current().is_faking() {
        return VX_OK;
    }
    let real = ResolvedFn::new(b"msgQDelete\0").ptr() as *const ();
    if real.is_null() {
        return VX_OK;
    }
    let real: unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int = std::mem::transmute(real);
    real(msg_q_id)
}

// ---------------------------------------------------------------------------
// VxWorks semaphores (semTake / semGive / sem*Create / semDelete)
// ---------------------------------------------------------------------------
//
// A binary/mutex/counting semaphore carries no attacker data — its role in a
// consumer is to UNBLOCK the handler. During a fuzz pass a take succeeds so the
// guarded section runs (Empty → ERROR, matching "the giver is absent"); give and
// delete are swallowed. This is the RTOS analogue of the mq_open success +
// mq_send swallow, not a data channel.

unsafe fn sem_create() -> *mut libc::c_void {
    if crate::fakes::mode::current().is_faking() {
        log_rtos(b"semCreate", 0);
    }
    opaque_handle()
}

/// `SEM_ID semBCreate(int options, SEM_B_STATE initialState)`.
#[no_mangle]
pub unsafe extern "C" fn semBCreate(
    _options: libc::c_int,
    _initial_state: libc::c_int,
) -> *mut libc::c_void {
    sem_create()
}

/// `SEM_ID semMCreate(int options)`.
#[no_mangle]
pub unsafe extern "C" fn semMCreate(_options: libc::c_int) -> *mut libc::c_void {
    sem_create()
}

/// `SEM_ID semCCreate(int options, int initialCount)`.
#[no_mangle]
pub unsafe extern "C" fn semCCreate(
    _options: libc::c_int,
    _initial_count: libc::c_int,
) -> *mut libc::c_void {
    sem_create()
}

/// `STATUS semTake(SEM_ID semId, int timeout)`.
#[no_mangle]
pub unsafe extern "C" fn semTake(sem_id: *mut libc::c_void, timeout: libc::c_int) -> libc::c_int {
    if crate::fakes::mode::current().is_faking() {
        if crate::fakes::mode::current() == crate::fakes::mode::Mode::Empty {
            // No giver in an empty world: the take times out.
            set_errno(libc::ETIMEDOUT);
            return VX_ERROR;
        }
        log_rtos(b"semTake", 0);
        return VX_OK;
    }
    let real = ResolvedFn::new(b"semTake\0").ptr() as *const ();
    if real.is_null() {
        return VX_OK;
    }
    let real: unsafe extern "C" fn(*mut libc::c_void, libc::c_int) -> libc::c_int =
        std::mem::transmute(real);
    real(sem_id, timeout)
}

/// `STATUS semGive(SEM_ID semId)`.
#[no_mangle]
pub unsafe extern "C" fn semGive(sem_id: *mut libc::c_void) -> libc::c_int {
    if crate::fakes::mode::current().is_faking() {
        return VX_OK;
    }
    let real = ResolvedFn::new(b"semGive\0").ptr() as *const ();
    if real.is_null() {
        return VX_OK;
    }
    let real: unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int = std::mem::transmute(real);
    real(sem_id)
}

/// `STATUS semDelete(SEM_ID semId)`.
#[no_mangle]
pub unsafe extern "C" fn semDelete(sem_id: *mut libc::c_void) -> libc::c_int {
    if crate::fakes::mode::current().is_faking() {
        return VX_OK;
    }
    let real = ResolvedFn::new(b"semDelete\0").ptr() as *const ();
    if real.is_null() {
        return VX_OK;
    }
    let real: unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int = std::mem::transmute(real);
    real(sem_id)
}

// ---------------------------------------------------------------------------
// FreeRTOS queues (xQueueGenericCreate / xQueueReceive / xQueueGenericReceive)
// ---------------------------------------------------------------------------
//
// FreeRTOS copies exactly `uxItemSize` bytes into the caller's `pvBuffer` on a
// receive, and the caller sized `pvBuffer` to that item size — so the shim MUST
// know the item size to avoid overrunning the caller's buffer. `xQueueCreate`
// (a macro over `xQueueGenericCreate`) is intercepted to record the item size
// against the handle it returns; the receive hook fills exactly that many bytes.
// A handle the shim did not create (item size unknown) delivers no data rather
// than guessing a size and risking an overflow.

struct QueueMeta {
    handle: usize,
    item_size: usize,
}

/// Synthetic queue-handle base — high enough not to collide with a real pointer
/// the fast path might return, and used only as an opaque token our own hooks
/// resolve back to an item size.
const XQUEUE_HANDLE_BASE: usize = 0x0B0F_0000;
const XQUEUE_CAP: usize = 256;

/// Item sizes of queues this shim created. `try_lock` throughout: a queue hook
/// can be reentered from a signal handler; on contention the receive falls back
/// to "empty" (safe) rather than deadlocking.
static XQUEUES: Mutex<Vec<QueueMeta>> = Mutex::new(Vec::new());

unsafe fn xqueue_create(item_size: usize) -> *mut libc::c_void {
    if crate::fakes::mode::current().is_faking() {
        if let Ok(mut table) = XQUEUES.try_lock() {
            if table.len() < XQUEUE_CAP {
                let handle = XQUEUE_HANDLE_BASE + table.len();
                table.push(QueueMeta { handle, item_size });
                drop(table);
                log_rtos(b"xQueueCreate", item_size as i64);
                return handle as *mut libc::c_void;
            }
        }
        // Table full / contended: a non-null handle with no tracked size still
        // lets the caller's NULL check pass; its receives deliver no data.
        return opaque_handle();
    }
    opaque_handle()
}

fn xqueue_item_size(handle: *mut libc::c_void) -> Option<usize> {
    let addr = handle as usize;
    let table = XQUEUES.try_lock().ok()?;
    table.iter().find(|q| q.handle == addr).map(|q| q.item_size)
}

/// `QueueHandle_t xQueueGenericCreate(UBaseType_t uxQueueLength,
/// UBaseType_t uxItemSize, uint8_t ucQueueType)`.
#[no_mangle]
pub unsafe extern "C" fn xQueueGenericCreate(
    _ux_queue_length: libc::c_ulong,
    ux_item_size: libc::c_ulong,
    _uc_queue_type: libc::c_int,
) -> *mut libc::c_void {
    xqueue_create(ux_item_size as usize)
}

/// `QueueHandle_t xQueueCreate(UBaseType_t uxQueueLength, UBaseType_t uxItemSize)`
/// — a real symbol in some ports; the macro form resolves to
/// [`xQueueGenericCreate`] above.
#[no_mangle]
pub unsafe extern "C" fn xQueueCreate(
    _ux_queue_length: libc::c_ulong,
    ux_item_size: libc::c_ulong,
) -> *mut libc::c_void {
    xqueue_create(ux_item_size as usize)
}

unsafe fn xqueue_receive(x_queue: *mut libc::c_void, pv_buffer: *mut libc::c_void) -> libc::c_int {
    if crate::fakes::mode::current().is_faking() {
        let Some(item_size) = xqueue_item_size(x_queue) else {
            // Unknown queue (created outside the shim) — cannot size the copy
            // safely, so report empty rather than risk overrunning pvBuffer.
            return PD_FALSE;
        };
        match deliver_body(
            b"xQueueReceive",
            pv_buffer as *mut u8,
            item_size,
            &XQUEUE_DELIVERED,
        ) {
            Some(n) => {
                log_rtos(b"xQueueReceive", n as i64);
                PD_TRUE
            }
            None => PD_FALSE,
        }
    } else {
        PD_FALSE
    }
}

/// `BaseType_t xQueueReceive(QueueHandle_t xQueue, void *pvBuffer,
/// TickType_t xTicksToWait)`.
#[no_mangle]
pub unsafe extern "C" fn xQueueReceive(
    x_queue: *mut libc::c_void,
    pv_buffer: *mut libc::c_void,
    _x_ticks_to_wait: libc::c_ulong,
) -> libc::c_int {
    xqueue_receive(x_queue, pv_buffer)
}

/// `BaseType_t xQueueGenericReceive(QueueHandle_t xQueue, void *pvBuffer,
/// TickType_t xTicksToWait, BaseType_t xJustPeeking)` (FreeRTOS < v9).
#[no_mangle]
pub unsafe extern "C" fn xQueueGenericReceive(
    x_queue: *mut libc::c_void,
    pv_buffer: *mut libc::c_void,
    _x_ticks_to_wait: libc::c_ulong,
    _x_just_peeking: libc::c_int,
) -> libc::c_int {
    xqueue_receive(x_queue, pv_buffer)
}

/// `BaseType_t xQueueGenericSend(QueueHandle_t, const void *, TickType_t, BaseType_t)`.
#[no_mangle]
pub unsafe extern "C" fn xQueueGenericSend(
    _x_queue: *mut libc::c_void,
    _pv_item: *const libc::c_void,
    _x_ticks_to_wait: libc::c_ulong,
    _x_copy_position: libc::c_int,
) -> libc::c_int {
    if crate::fakes::mode::current().is_faking() {
        return PD_TRUE;
    }
    PD_TRUE
}

// ---------------------------------------------------------------------------
// cFS Software Bus (CFE_SB_CreatePipe / CFE_SB_RcvMsg / CFE_SB_ReceiveBuffer)
// ---------------------------------------------------------------------------
//
// Unlike msgQReceive (caller buffer + explicit maxNbytes), the cFE Software Bus
// OWNS the message buffer: RcvMsg sets `*BufPtr` to a bus-owned buffer the app
// then reads. The shim owns a process-lifetime buffer, fuzz-fills it per receive,
// and points `*BufPtr` at it — so the app parses a fuzz-controlled CCSDS message
// (its MsgId, length, and payload are all fuzz-driven). Bounded delivery ends the
// app's receive loop. CreatePipe returns success without writing through the
// pipe-id pointer, whose width (uint8 vs the newer struct) the shim cannot know;
// the id is only ever passed back to RcvMsg, which ignores it.

const CFE_MSG_BUF_LEN: usize = 4096;
/// Address of the process-lifetime, fuzz-filled cFE message buffer, allocated
/// once. Stored as an address so the `static` is `Sync` without wrapping the raw
/// pointer.
static CFE_MSG_BUF: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

fn cfe_msg_buf() -> *mut u8 {
    *CFE_MSG_BUF.get_or_init(|| {
        let boxed = vec![0u8; CFE_MSG_BUF_LEN].into_boxed_slice();
        Box::leak(boxed).as_mut_ptr() as usize
    }) as *mut u8
}

unsafe fn cfe_rcv(buf_ptr: *mut *mut libc::c_void) -> i32 {
    if crate::fakes::mode::current().is_faking() {
        if buf_ptr.is_null() {
            return CFE_SB_NO_MESSAGE;
        }
        let buf = cfe_msg_buf();
        match deliver_body(b"CFE_SB_RcvMsg", buf, CFE_MSG_BUF_LEN, &CFE_DELIVERED) {
            Some(_) => {
                *buf_ptr = buf as *mut libc::c_void;
                log_rtos(b"CFE_SB_RcvMsg", CFE_MSG_BUF_LEN as i64);
                CFE_SUCCESS
            }
            None => CFE_SB_NO_MESSAGE,
        }
    } else {
        CFE_SB_NO_MESSAGE
    }
}

/// `int32 CFE_SB_RcvMsg(CFE_SB_MsgPtr_t *BufPtr, CFE_SB_PipeId_t PipeId,
/// int32 TimeOut)` (classic cFE API).
#[no_mangle]
pub unsafe extern "C" fn CFE_SB_RcvMsg(
    buf_ptr: *mut *mut libc::c_void,
    _pipe_id: libc::c_uint,
    _timeout: i32,
) -> i32 {
    cfe_rcv(buf_ptr)
}

/// `int32 CFE_SB_ReceiveBuffer(CFE_SB_Buffer_t **BufPtr, CFE_SB_PipeId_t PipeId,
/// int32 TimeOut)` (cFE >= 6.7 API).
#[no_mangle]
pub unsafe extern "C" fn CFE_SB_ReceiveBuffer(
    buf_ptr: *mut *mut libc::c_void,
    _pipe_id: libc::c_uint,
    _timeout: i32,
) -> i32 {
    cfe_rcv(buf_ptr)
}

/// `int32 CFE_SB_CreatePipe(CFE_SB_PipeId_t *PipeIdPtr, uint16 Depth,
/// const char *PipeName)`.
#[no_mangle]
pub unsafe extern "C" fn CFE_SB_CreatePipe(
    _pipe_id_ptr: *mut libc::c_void,
    _depth: libc::c_uint,
    _pipe_name: *const libc::c_char,
) -> i32 {
    if crate::fakes::mode::current().is_faking() {
        log_rtos(b"CFE_SB_CreatePipe", 0);
    }
    CFE_SUCCESS
}

// ---------------------------------------------------------------------------
// Bare-metal MMIO fill helper (HDF-6 deliverable 3)
// ---------------------------------------------------------------------------
//
// A bare-metal `*(volatile uint32_t*)ADDR` register read is a load, not a
// syscall, so the LD_PRELOAD path cannot intercept it. The general, robust way
// to make such a fixed-address read fuzz-controlled on the host is to MAP the
// page(s) it lives on and fill them from the fuzz input. `bhf_shim_mmio_fill`
// does exactly that on demand: a generated harness (or a fixture) calls it with
// the device base + span before driving the target, and the subsequent volatile
// loads read fuzz-controlled bytes.
//
// Honest limits (documented for the general-case follow-up): the address must be
// page-mappable in the host process (a low or kernel address will not map);
// MAP_FIXED_NOREPLACE means the call FAILS (returns -1, never silently clobbers)
// if the range is already mapped; and the address must be supplied — automatic
// discovery of literal MMIO addresses in already-compiled target code, and a
// compiler-assisted volatile-load rewrite, remain follow-ups. Where the target
// reads registers through a BSP accessor function instead of a raw literal, the
// harness-side `CEnvironmentModel`/`CPeripheralReader` accessor synthesis (HDF-5,
// wired by HDF-6 deliverable 4) is the cleaner path and needs no fixed mapping.

fn page_size() -> usize {
    let sz = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if sz > 0 {
        sz as usize
    } else {
        4096
    }
}

/// Map fuzz-controlled memory over the page(s) covering `[addr, addr + len)` so a
/// subsequent `*(volatile T*)addr` read returns fuzz bytes. Returns 0 on success
/// and -1 on failure (a descriptive errno is left set), never silently — the
/// caller must check.
///
/// # Safety
///
/// Establishes a new mapping at a fixed address in the calling process. `addr`
/// must not overlap memory the target still needs; `MAP_FIXED_NOREPLACE` makes an
/// overlap fail rather than corrupt an existing mapping.
#[no_mangle]
pub unsafe extern "C" fn bhf_shim_mmio_fill(addr: usize, len: libc::size_t) -> libc::c_int {
    if addr == 0 || len == 0 {
        set_errno(libc::EINVAL);
        return -1;
    }
    let ps = page_size();
    let page_base = addr & !(ps - 1);
    let span = (addr - page_base) + len;
    let map_len = span.div_ceil(ps) * ps;
    let mapped = libc::mmap(
        page_base as *mut libc::c_void,
        map_len,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_FIXED_NOREPLACE | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    if mapped == libc::MAP_FAILED || mapped as usize != page_base {
        // MAP_FIXED_NOREPLACE returns a DIFFERENT address (not the fixed one) or
        // MAP_FAILED when the range is taken; treat either as failure so we never
        // pretend a device page is fuzz-mapped when it is not.
        if mapped != libc::MAP_FAILED && mapped as usize != page_base {
            libc::munmap(mapped, map_len);
            set_errno(libc::EEXIST);
        }
        return -1;
    }
    // Fill the mapped region from the fuzz input, keyed by the base address so two
    // device windows are independent channels (same keying as every other fake).
    let mut key = [0u8; 16];
    let head = format!("mmio:{page_base:#x}");
    let hb = head.as_bytes();
    let n = hb.len().min(key.len());
    key[..n].copy_from_slice(&hb[..n]);
    crate::fakes::memfd::fill_region(&key[..n], page_base as *mut u8, map_len);
    log_rtos(b"mmio_fill", map_len as i64);
    0
}

/// `--list-fakes` plugin entry for the vendor-RTOS channel + MMIO hooks.
pub struct Rtos;

impl crate::sdk::FakeResource for Rtos {
    fn name(&self) -> &'static str {
        "rtos"
    }
    fn intercepts(&self) -> &'static [&'static [u8]] {
        &[
            b"msgQCreate\0",
            b"msgQReceive\0",
            b"msgQSend\0",
            b"msgQDelete\0",
            b"semBCreate\0",
            b"semMCreate\0",
            b"semCCreate\0",
            b"semTake\0",
            b"semGive\0",
            b"semDelete\0",
            b"xQueueCreate\0",
            b"xQueueGenericCreate\0",
            b"xQueueReceive\0",
            b"xQueueGenericReceive\0",
            b"xQueueGenericSend\0",
            b"CFE_SB_CreatePipe\0",
            b"CFE_SB_RcvMsg\0",
            b"CFE_SB_ReceiveBuffer\0",
            b"bhf_shim_mmio_fill\0",
        ]
    }
    fn is_enabled(&self) -> bool {
        true
    }
    fn describe(&self) -> &'static str {
        "deliver fuzz input through vendor-RTOS receive channels (VxWorks msgQReceive/semTake, FreeRTOS xQueueReceive, cFS CFE_SB_RcvMsg) and map fuzz-controlled fixed-address MMIO"
    }
}
