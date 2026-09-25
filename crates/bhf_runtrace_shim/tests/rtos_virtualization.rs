// SPDX-License-Identifier: Apache-2.0
//! HDF-6: vendor-RTOS channel + bare-metal MMIO virtualization.
//!
//! A native consumer built host-side calls its BSP's vendor primitive
//! (`msgQReceive`, `semTake`, `xQueueReceive`, `CFE_SB_RcvMsg`) which is left an
//! undefined *weak* reference — WITHOUT the shim it is NULL, so the consumer
//! cannot receive; WITH the shim preloaded the dynamic linker binds it to the
//! shim's strong export and the consumer receives fuzz-controlled data. These
//! tests mirror `mqueue_virtualization.rs`: they compile a small consumer, run it
//! under the shim, and assert a fuzz-controlled branch is reached and (for the
//! data channels) that delivery is bounded so a receive loop terminates.

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn target_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("CARGO_TARGET_DIR") {
        return PathBuf::from(dir);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root above crates/bhf_runtrace_shim")
        .join("target")
}

fn shim_so() -> Option<PathBuf> {
    let base = target_dir();
    for profile in ["debug", "release"] {
        let p = base.join(profile).join("libbhf_runtrace_shim.so");
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

fn cc() -> Option<&'static str> {
    ["cc", "gcc", "clang"].into_iter().find(|c| {
        Command::new(c)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    })
}

/// Compile `src` to `bin`, returning false if the C compiler rejected it.
fn compile(cc: &str, src: &std::path::Path, bin: &std::path::Path) -> bool {
    Command::new(cc)
        .arg(src)
        .arg("-o")
        .arg(bin)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Run `bin` under the shim in the given mode with a bounded wall clock so a
/// broken (unbounded) delivery fails loudly instead of hanging the suite.
fn run_under_shim(
    bin: &std::path::Path,
    shim: &std::path::Path,
    mode: &str,
    log: &std::path::Path,
) -> Option<i32> {
    let mut child = Command::new(bin)
        .env("LD_PRELOAD", shim)
        .env("BHF_RUNTRACE_LOG", log)
        .env("BHF_RUNTRACE_MODE", mode)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn rtos probe");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(s) = child.try_wait().unwrap() {
            return s.code();
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("rtos virtualization HUNG (delivery not bounded)");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

// A VxWorks-style consumer: create a queue that does not exist, publish a fuzz
// input, receive a first message (must have content), reach a byte-gated branch,
// then drain until ERROR (proving delivery is bounded). Returns 42 iff it saw
// content AND the byte-gated branch AND the loop terminated within a sane bound.
const MSGQ_PROBE: &str = r#"
#include <string.h>
#include <stdint.h>
extern void bhf_shim_set_fuzz_input(const uint8_t *data, size_t size) __attribute__((weak));
extern void *msgQCreate(int a, int b, int c) __attribute__((weak));
extern int msgQReceive(void *q, char *buf, unsigned max, int timeout) __attribute__((weak));
extern int msgQDelete(void *q) __attribute__((weak));
int main(void) {
    if (!msgQReceive || !msgQCreate) return 2;   /* without the shim: no vendor kernel */
    /* Uniform input so the delivered message is 'M' at any keyed window offset. */
    if (bhf_shim_set_fuzz_input) {
        uint8_t in[64]; memset(in, 'M', sizeof in);
        bhf_shim_set_fuzz_input(in, sizeof in);
    }
    void *q = msgQCreate(10, 64, 0);
    if (!q) return 3;
    char buf[64];
    memset(buf, 0, sizeof buf);
    int first = msgQReceive(q, buf, sizeof buf, -1);
    if (first <= 0) return 4;                     /* expected a message with content */
    int gated = (buf[0] == 'M');                  /* branch gated on a fuzz-controlled byte */
    int count = 1, guard = 0;
    while (guard++ < 100000) {
        int n = msgQReceive(q, buf, sizeof buf, -1);
        if (n < 0) break;                         /* ERROR: delivery bounded -> loop ends */
        count++;
    }
    msgQDelete(q);
    if (!(count >= 1 && count <= 1000)) return 5; /* delivery bounded */
    return gated ? 42 : 6;
}
"#;

#[test]
fn msgqreceive_delivers_bounded_fuzz_messages_and_reaches_a_byte_gated_branch() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let dir = std::env::temp_dir().join(format!("bhf-msgq-vtest-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("msgq.c");
    std::fs::write(&src, MSGQ_PROBE).unwrap();
    let bin = dir.join("msgq");
    assert!(compile(cc, &src, &bin), "msgq probe failed to compile");

    // fuzz_driven mode: the published input's first byte 'M' drives the branch.
    let log = dir.join("rt.jsonl");
    let code = run_under_shim(&bin, &shim, "fuzz_driven", &log);
    assert_eq!(
        code,
        Some(42),
        "msgQReceive must deliver a fuzz-controlled message, reach the byte-gated branch, and \
         terminate the receive loop (code {code:?})"
    );
    let text = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        text.lines()
            .any(|l| l.contains("\"e\":\"msgQReceive\"") && l.contains("\"v\":1")),
        "virtualized msgQReceive event missing from runtrace log:\n{text}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// A VxWorks consumer guarded by a semaphore: without the shim semTake is NULL, so
// the guarded section is unreachable; with the shim the take succeeds and the
// section runs on a fuzz-controlled message.
const SEM_PROBE: &str = r#"
#include <string.h>
#include <stdint.h>
extern void bhf_shim_set_fuzz_input(const uint8_t *data, size_t size) __attribute__((weak));
extern void *semBCreate(int options, int state) __attribute__((weak));
extern int semTake(void *s, int timeout) __attribute__((weak));
extern int semGive(void *s) __attribute__((weak));
extern void *msgQCreate(int a, int b, int c) __attribute__((weak));
extern int msgQReceive(void *q, char *buf, unsigned max, int timeout) __attribute__((weak));
int main(void) {
    if (!semTake || !semBCreate) return 2;
    if (bhf_shim_set_fuzz_input) {
        uint8_t in[16]; memset(in, 'G', sizeof in);
        bhf_shim_set_fuzz_input(in, sizeof in);
    }
    void *sem = semBCreate(1, 1);
    if (!sem) return 3;
    if (semTake(sem, -1) != 0) return 4;          /* take must succeed to enter the section */
    void *q = msgQCreate(4, 32, 0);
    char buf[32]; memset(buf, 0, sizeof buf);
    int n = msgQReceive(q, buf, sizeof buf, -1);
    semGive(sem);
    if (n <= 0) return 5;
    return (buf[0] == 'G') ? 42 : 6;              /* fuzz-controlled branch inside the section */
}
"#;

#[test]
fn semtake_unblocks_a_guarded_consumer_section() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let dir = std::env::temp_dir().join(format!("bhf-sem-vtest-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("sem.c");
    std::fs::write(&src, SEM_PROBE).unwrap();
    let bin = dir.join("sem");
    assert!(compile(cc, &src, &bin), "sem probe failed to compile");
    let log = dir.join("rt.jsonl");
    let code = run_under_shim(&bin, &shim, "fuzz_driven", &log);
    assert_eq!(
        code,
        Some(42),
        "semTake must succeed so the guarded section runs on a fuzz message (code {code:?})"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// A FreeRTOS consumer: xQueueCreate records a 4-byte item size, xQueueReceive
// copies exactly that many fuzz bytes into pvBuffer (never overrunning it), and
// the branch is gated on the received word.
const XQUEUE_PROBE: &str = r#"
#include <string.h>
#include <stdint.h>
extern void bhf_shim_set_fuzz_input(const uint8_t *data, size_t size) __attribute__((weak));
extern void *xQueueCreate(unsigned long len, unsigned long item_size) __attribute__((weak));
extern int xQueueReceive(void *q, void *buf, unsigned long ticks) __attribute__((weak));
int main(void) {
    if (!xQueueReceive || !xQueueCreate) return 2;
    /* Uniform 0xCD input so the delivered word is 0xCDCDCDCD at any window offset. */
    if (bhf_shim_set_fuzz_input) {
        uint8_t in[16]; memset(in, 0xCD, sizeof in);
        bhf_shim_set_fuzz_input(in, sizeof in);
    }
    void *q = xQueueCreate(8, sizeof(uint32_t));
    if (!q) return 3;
    /* guard bytes around a 4-byte slot detect any over-copy */
    struct { uint32_t guard0; uint32_t slot; uint32_t guard1; } b;
    b.guard0 = 0xAAAAAAAAu; b.slot = 0; b.guard1 = 0xBBBBBBBBu;
    int ok = xQueueReceive(q, &b.slot, ~0UL);
    if (ok != 1) return 4;                          /* pdTRUE: a message was delivered */
    if (b.guard0 != 0xAAAAAAAAu || b.guard1 != 0xBBBBBBBBu) return 7; /* over-copy! */
    return (b.slot == 0xCDCDCDCDu) ? 42 : 6;        /* fuzz-controlled word gates the branch */
}
"#;

#[test]
fn xqueuereceive_delivers_item_sized_fuzz_data_without_overrun() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let dir = std::env::temp_dir().join(format!("bhf-xq-vtest-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("xq.c");
    std::fs::write(&src, XQUEUE_PROBE).unwrap();
    let bin = dir.join("xq");
    assert!(compile(cc, &src, &bin), "xqueue probe failed to compile");
    let log = dir.join("rt.jsonl");
    let code = run_under_shim(&bin, &shim, "fuzz_driven", &log);
    assert_eq!(
        code,
        Some(42),
        "xQueueReceive must copy exactly the item size of fuzz bytes and gate the branch \
         without overrunning pvBuffer (code {code:?})"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// A cFS app: CFE_SB_RcvMsg sets BufPtr to a bus-owned, fuzz-filled buffer; the
// app reads the message's first word (its MsgId in CCSDS) to gate a branch.
const CFE_PROBE: &str = r#"
#include <string.h>
#include <stdint.h>
extern void bhf_shim_set_fuzz_input(const uint8_t *data, size_t size) __attribute__((weak));
extern int CFE_SB_CreatePipe(void *pipe, unsigned depth, const char *name) __attribute__((weak));
extern int CFE_SB_RcvMsg(void **buf, unsigned pipe, int timeout) __attribute__((weak));
int main(void) {
    if (!CFE_SB_RcvMsg) return 2;
    /* Uniform 0x0D input so the message header word is 0x0D0D at any window offset. */
    if (bhf_shim_set_fuzz_input) {
        uint8_t in[16]; memset(in, 0x0D, sizeof in);
        bhf_shim_set_fuzz_input(in, sizeof in);
    }
    unsigned pipe = 0;
    CFE_SB_CreatePipe(&pipe, 16, "TEST_PIPE");
    void *msg = 0;
    int st = CFE_SB_RcvMsg(&msg, pipe, -1);
    if (st != 0 || msg == 0) return 3;             /* CFE_SUCCESS + a bus-owned buffer */
    uint16_t msgid = *(uint16_t *)msg;             /* fuzz-controlled message header */
    return (msgid == 0x0D0D) ? 42 : 6;
}
"#;

#[test]
fn cfe_sb_rcvmsg_delivers_a_fuzz_owned_message_buffer() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let dir = std::env::temp_dir().join(format!("bhf-cfe-vtest-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("cfe.c");
    std::fs::write(&src, CFE_PROBE).unwrap();
    let bin = dir.join("cfe");
    assert!(compile(cc, &src, &bin), "cfe probe failed to compile");
    let log = dir.join("rt.jsonl");
    let code = run_under_shim(&bin, &shim, "fuzz_driven", &log);
    assert_eq!(
        code,
        Some(42),
        "CFE_SB_RcvMsg must point BufPtr at a fuzz-filled bus buffer whose header gates the \
         branch (code {code:?})"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// Bare-metal MMIO: a fixed device address is mapped fuzz-controlled by
// bhf_shim_mmio_fill, and a `*(volatile uint32_t*)ADDR` read reaches a branch
// gated on the fuzz-controlled register value. WITHOUT the shim the map helper is
// NULL and the address is unmapped (the probe cannot reach the branch).
const MMIO_PROBE: &str = r#"
#include <string.h>
#include <stdint.h>
extern void bhf_shim_set_fuzz_input(const uint8_t *data, size_t size) __attribute__((weak));
extern int bhf_shim_mmio_fill(size_t addr, size_t len) __attribute__((weak));
int main(void) {
    if (!bhf_shim_mmio_fill) return 2;             /* no shim: no MMIO interception */
    /* The device window's fuzz bytes are keyed by "mmio:<base>"; make the whole
     * input a run of 0x5A so the first register reads 0x5A5A5A5A regardless of key. */
    if (bhf_shim_set_fuzz_input) {
        uint8_t in[64]; memset(in, 0x5A, sizeof in);
        bhf_shim_set_fuzz_input(in, sizeof in);
    }
    size_t base = 0x51510000;                      /* a normally-unmapped host page */
    if (bhf_shim_mmio_fill(base, 64) != 0) return 3;
    volatile uint32_t *reg = (volatile uint32_t *)base;
    uint32_t v = reg[0];                            /* a load, not a syscall */
    return (v == 0x5A5A5A5Au) ? 42 : 6;            /* fuzz-controlled register gates the branch */
}
"#;

#[test]
fn mmio_fixed_address_read_is_fuzz_controlled() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let dir = std::env::temp_dir().join(format!("bhf-mmio2-vtest-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("mmio.c");
    std::fs::write(&src, MMIO_PROBE).unwrap();
    let bin = dir.join("mmio");
    assert!(compile(cc, &src, &bin), "mmio probe failed to compile");

    // Without the shim, the helper is a NULL weak symbol: the probe self-reports 2.
    let baseline = Command::new(&bin)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run baseline")
        .code();
    assert_eq!(
        baseline,
        Some(2),
        "without the shim bhf_shim_mmio_fill must be unresolved (code {baseline:?})"
    );

    let log = dir.join("rt.jsonl");
    let code = run_under_shim(&bin, &shim, "fuzz_driven", &log);
    assert_eq!(
        code,
        Some(42),
        "a *(volatile uint32_t*)ADDR read must be fuzz-controlled after bhf_shim_mmio_fill \
         (code {code:?})"
    );
    let text = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        text.lines().any(|l| l.contains("\"e\":\"mmio_fill\"")),
        "mmio_fill event missing from runtrace log:\n{text}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
