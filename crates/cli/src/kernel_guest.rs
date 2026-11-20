// SPDX-License-Identifier: Apache-2.0

//! A Linux kernel in a qemu-system guest, driven by bhf's in-guest executor.
//!
//! `c_runtime/kernel_executor.c` is the guest's `/init`: it mounts the
//! pseudo file systems, loads the modules under test, and serves the host
//! over a virtio-serial port. Each program the host sends (system calls with
//! their arguments, in the format [`decode`] reads) runs in a forked child
//! with KCOV enabled, and the reply carries every call's result and the
//! kernel PCs KCOV recorded while it ran.
//!
//! This module is the host's half:
//!
//! * the program format: [`decode`] (as the executor decodes it, for display
//!   and reproducers) and [`ProgramBuilder`] (to write programs);
//! * the wire protocol: [`ExecutorClient`] over any `Read + Write` channel,
//!   with every message bounded;
//! * the guest: [`build_executor`], [`build_initramfs`] (the executor as
//!   `/init` and the modules, in a newc cpio) and [`Guest`], a qemu-system
//!   process whose serial console is captured and whose executor is the
//!   client's peer, over a Unix socket QEMU connects to;
//! * the campaign ([`fuzz`]): KCOV PCs as the coverage map's edges
//!   ([`coverage_ids`]), comparisons as hints and a CmpLog, and each kernel
//!   report on the console as a finding with its program
//!   (`results::import_syzkaller::record_guest_crash`).

// The guest itself needs a Unix host; the rest is used only by it.
#![cfg_attr(not(unix), allow(dead_code))]

use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The executor's source, built for the guest by [`build_executor`].
pub(crate) const EXECUTOR_SOURCE: &str = include_str!("../../../c_runtime/kernel_executor.c");

// ── Programs ─────────────────────────────────────────────────────────────

/// Most calls in one program.
pub(crate) const MAX_CALLS: usize = 64;
/// Most arguments of one call.
pub(crate) const MAX_ARGS: usize = 6;
/// Most bytes of one data or out argument.
pub(crate) const MAX_ARG_BYTES: usize = 4096;
/// Most bytes of a program the executor takes.
pub(crate) const MAX_PROGRAM: usize = 65536;
/// Where the executor maps the data area, and its size.
pub(crate) const DATA_ADDR: u64 = 0x2000_0000;
pub(crate) const DATA_SIZE: u64 = 0x10_0000;

/// The calls a program names by selector (`selector % 13`), in the
/// executor's order; selector 12 is a raw call by number.
pub(crate) const SYSCALLS: [&str; 12] = [
    "openat", "close", "read", "write", "ioctl", "mmap", "munmap", "pread64", "pwrite64", "lseek",
    "fcntl", "dup",
];
const RAW_SELECTOR: u8 = SYSCALLS.len() as u8;
const TAG_CONST: u8 = 0;
const TAG_DATA: u8 = 1;
const TAG_RESULT: u8 = 2;
const TAG_OUT: u8 = 3;

/// What a call is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CallSys {
    /// One of [`SYSCALLS`].
    Named(usize),
    /// A raw call by number.
    Raw(u16),
}

impl CallSys {
    pub(crate) fn name(self) -> String {
        match self {
            Self::Named(index) => SYSCALLS[index].to_owned(),
            Self::Raw(nr) => format!("syscall_{nr}"),
        }
    }
}

/// An argument, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ArgValue {
    Const(u64),
    /// Bytes copied into the data area at `offset` (`None`: they did not
    /// fit, and the argument is NULL); `bytes` is where they are in the
    /// program.
    Data {
        offset: Option<u64>,
        bytes: Range<usize>,
    },
    /// The result of an earlier call (`None` in the first call: -1).
    Result(Option<usize>),
    /// `len` zeroed bytes at `offset` in the data area.
    Out {
        offset: Option<u64>,
        len: u32,
    },
}

/// An argument, and where its value is in the program: a const's 8 bytes,
/// a result's index byte, a data argument's bytes, an out argument's length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodedArg {
    pub value: ArgValue,
    pub span: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodedCall {
    pub sys: CallSys,
    pub args: Vec<DecodedArg>,
    /// The call's bytes in the program, its selector first.
    pub span: Range<usize>,
}

/// A program, as the executor decodes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Program<'a> {
    pub input: &'a [u8],
    pub calls: Vec<DecodedCall>,
    /// Bytes of the data area its buffers use.
    pub data_used: u64,
}

fn le16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn le64(bytes: &[u8]) -> u64 {
    let mut word = [0u8; 8];
    word.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(word)
}

/// Decode `input` as the executor does: every byte string decodes, a call
/// the input ends inside is dropped, and selectors are taken modulo their
/// range (see `c_runtime/kernel_executor.c`).
pub(crate) fn decode(input: &[u8]) -> Program<'_> {
    let mut program = Program {
        input,
        calls: Vec::new(),
        data_used: 0,
    };
    let len = input.len();
    let mut pos = 0usize;
    // Place `n` bytes in the data area: their offset, or None.
    let place = |used: &mut u64, n: u64| -> Option<u64> {
        let at = (*used + 7) & !7;
        if at > DATA_SIZE || n > DATA_SIZE - at {
            return None;
        }
        *used = at + n;
        Some(at)
    };
    'calls: while program.calls.len() < MAX_CALLS && len - pos >= 2 {
        let saved = program.data_used;
        let start = pos;
        let selector = input[pos] % (RAW_SELECTOR + 1);
        let nargs = usize::from(input[pos + 1]) % (MAX_ARGS + 1);
        pos += 2;
        let sys = if selector == RAW_SELECTOR {
            if len - pos < 2 {
                break;
            }
            let nr = le16(&input[pos..]);
            pos += 2;
            CallSys::Raw(nr)
        } else {
            CallSys::Named(usize::from(selector))
        };
        let mut args = Vec::with_capacity(nargs);
        for _ in 0..nargs {
            if pos >= len {
                program.data_used = saved;
                break 'calls;
            }
            let tag = input[pos] % 4;
            pos += 1;
            let arg = match tag {
                TAG_CONST => {
                    if len - pos < 8 {
                        program.data_used = saved;
                        break 'calls;
                    }
                    let value = le64(&input[pos..]);
                    pos += 8;
                    DecodedArg {
                        value: ArgValue::Const(value),
                        span: pos - 8..pos,
                    }
                }
                TAG_DATA => {
                    if len - pos < 2 {
                        program.data_used = saved;
                        break 'calls;
                    }
                    let n = usize::from(le16(&input[pos..]))
                        .min(MAX_ARG_BYTES)
                        .min(len - pos - 2);
                    pos += 2;
                    let offset = place(&mut program.data_used, n as u64);
                    pos += n;
                    DecodedArg {
                        value: ArgValue::Data {
                            offset,
                            bytes: pos - n..pos,
                        },
                        span: pos - n..pos,
                    }
                }
                TAG_RESULT => {
                    if len - pos < 1 {
                        program.data_used = saved;
                        break 'calls;
                    }
                    let before = program.calls.len();
                    let index = (before > 0).then(|| usize::from(input[pos]) % before);
                    pos += 1;
                    DecodedArg {
                        value: ArgValue::Result(index),
                        span: pos - 1..pos,
                    }
                }
                _ => {
                    if len - pos < 2 {
                        program.data_used = saved;
                        break 'calls;
                    }
                    let n = usize::from(le16(&input[pos..])).min(MAX_ARG_BYTES);
                    pos += 2;
                    let offset = place(&mut program.data_used, n as u64);
                    DecodedArg {
                        value: ArgValue::Out {
                            offset,
                            len: n as u32,
                        },
                        span: pos - 2..pos,
                    }
                }
            };
            args.push(arg);
        }
        program.calls.push(DecodedCall {
            sys,
            args,
            span: start..pos,
        });
    }
    program
}

impl Program<'_> {
    #[cfg(test)]
    /// The program as the executor's `--decode` prints it.
    pub(crate) fn dump(&self) -> String {
        let mut out = format!("calls {} data {:#x}\n", self.calls.len(), self.data_used);
        for (index, call) in self.calls.iter().enumerate() {
            let _ = write!(out, "call {index} ");
            match call.sys {
                CallSys::Named(sys) => out.push_str(SYSCALLS[sys]),
                CallSys::Raw(nr) => {
                    let _ = write!(out, "syscall nr={nr}");
                }
            }
            let _ = writeln!(out, " nargs {}", call.args.len());
            for (at, arg) in call.args.iter().enumerate() {
                let _ = write!(out, " arg {at} ");
                match &arg.value {
                    ArgValue::Const(value) => {
                        let _ = writeln!(out, "const 0x{value:x}");
                    }
                    ArgValue::Result(None) => out.push_str("result none\n"),
                    ArgValue::Result(Some(call)) => {
                        let _ = writeln!(out, "result {call}");
                    }
                    ArgValue::Data { offset, bytes } => {
                        let _ = write!(out, "data {} len {} ", place_text(*offset), bytes.len());
                        for byte in &self.input[bytes.clone()] {
                            let _ = write!(out, "{byte:02x}");
                        }
                        out.push('\n');
                    }
                    ArgValue::Out { offset, len } => {
                        let _ = writeln!(out, "out {} len {len}", place_text(*offset));
                    }
                }
            }
        }
        out
    }

    /// The program for a reader: one call per line, `rN = name(args)`, a
    /// buffer as its address and contents.
    pub(crate) fn text(&self) -> String {
        let mut out = String::new();
        for (index, call) in self.calls.iter().enumerate() {
            let args: Vec<String> = call
                .args
                .iter()
                .map(|arg| match &arg.value {
                    ArgValue::Const(value) => format!("{value:#x}"),
                    ArgValue::Result(Some(call)) => format!("r{call}"),
                    ArgValue::Result(None) => "0xffffffffffffffff".to_owned(),
                    ArgValue::Data {
                        offset: Some(offset),
                        bytes,
                    } => format!(
                        "&({:#x})={}",
                        DATA_ADDR + offset,
                        bytes_text(&self.input[bytes.clone()])
                    ),
                    ArgValue::Data {
                        offset: None,
                        bytes,
                    } => {
                        format!("NULL /* {} bytes did not fit */", bytes.len())
                    }
                    ArgValue::Out {
                        offset: Some(offset),
                        len,
                    } => format!("&({:#x})=out[{len}]", DATA_ADDR + offset),
                    ArgValue::Out { offset: None, len } => {
                        format!("NULL /* out[{len}] did not fit */")
                    }
                })
                .collect();
            let _ = writeln!(out, "r{index} = {}({})", call.sys.name(), args.join(", "));
        }
        out
    }
}

impl Program<'_> {
    /// The program as JSON (`decoded.json` of a finding).
    pub(crate) fn json(&self) -> serde_json::Value {
        let calls: Vec<serde_json::Value> = self
            .calls
            .iter()
            .map(|call| {
                let args: Vec<serde_json::Value> = call
                    .args
                    .iter()
                    .map(|arg| match &arg.value {
                        ArgValue::Const(value) => {
                            serde_json::json!({"const": format!("{value:#x}")})
                        }
                        ArgValue::Result(index) => serde_json::json!({"result": index}),
                        ArgValue::Data { offset, bytes } => serde_json::json!({"data": {
                            "address": offset.map(|offset| format!("{:#x}", DATA_ADDR + offset)),
                            "len": bytes.len(),
                            "hex": self.input[bytes.clone()]
                                .iter()
                                .map(|byte| format!("{byte:02x}"))
                                .collect::<String>(),
                        }}),
                        ArgValue::Out { offset, len } => serde_json::json!({"out": {
                            "address": offset.map(|offset| format!("{:#x}", DATA_ADDR + offset)),
                            "len": len,
                        }}),
                    })
                    .collect();
                let nr = match call.sys {
                    CallSys::Raw(nr) => Some(nr),
                    CallSys::Named(_) => None,
                };
                serde_json::json!({"call": call.sys.name(), "nr": nr, "args": args})
            })
            .collect();
        serde_json::json!({
            "schema": PROGRAM_SCHEMA,
            "data_address": format!("{DATA_ADDR:#x}"),
            "data_size": DATA_SIZE,
            "calls": calls,
        })
    }

    /// The program as C: the data area mapped where the executor maps it,
    /// the buffers copied in, then each call through `syscall(2)` with all
    /// six arguments, as the executor makes it. A raw call the executor
    /// refuses is refused here too.
    pub(crate) fn c_source(&self, title: &str) -> String {
        let title = title.replace("*/", "* /");
        let mut out = format!(
            "/*\n * {title}\n *\n * The program bhf kernel fuzz ran when the guest reported it, as C.\n \
             * Build it statically for the guest and run it there as root, with the\n \
             * modules loaded: cc -static -o repro repro.c && ./repro\n */\n\
             #define _GNU_SOURCE\n#include <stdint.h>\n#include <string.h>\n\
             #include <sys/mman.h>\n#include <sys/syscall.h>\n#include <unistd.h>\n"
        );
        let raw = self
            .calls
            .iter()
            .any(|call| matches!(call.sys, CallSys::Raw(_)));
        if raw {
            out.push_str(DENIED_C);
        }
        let _ = write!(
            out,
            "\nint main(void)\n{{\n\tuint64_t r[{}];\n\tchar *data = mmap((void *){DATA_ADDR:#x}ul, {DATA_SIZE:#x}ul, \
             PROT_READ | PROT_WRITE,\n\t\t\t  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);\n\
             \tif (data == MAP_FAILED)\n\t\treturn 1;\n",
            self.calls.len().max(1)
        );
        for arg in self.calls.iter().flat_map(|call| &call.args) {
            if let ArgValue::Data {
                offset: Some(offset),
                bytes,
            } = &arg.value
            {
                if bytes.is_empty() {
                    continue;
                }
                let literal: String = self.input[bytes.clone()]
                    .iter()
                    .map(|byte| format!("\\x{byte:02x}"))
                    .collect();
                let _ = writeln!(
                    out,
                    "\tmemcpy(data + {offset:#x}, \"{literal}\", {});",
                    bytes.len()
                );
            }
        }
        for (index, call) in self.calls.iter().enumerate() {
            let mut args: Vec<String> =
                call.args
                    .iter()
                    .map(|arg| match &arg.value {
                        ArgValue::Const(value) => format!("{value:#x}ul"),
                        ArgValue::Result(Some(earlier)) => format!("r[{earlier}]"),
                        ArgValue::Result(None) => "0xfffffffffffffffful".to_owned(),
                        ArgValue::Data {
                            offset: Some(offset),
                            ..
                        }
                        | ArgValue::Out {
                            offset: Some(offset),
                            ..
                        } => format!("{:#x}ul", DATA_ADDR + offset),
                        ArgValue::Data { offset: None, .. }
                        | ArgValue::Out { offset: None, .. } => "0ul".to_owned(),
                    })
                    .collect();
            args.resize(MAX_ARGS, "0ul".to_owned());
            let args = args.join(", ");
            match call.sys {
                CallSys::Named(sys) => {
                    let _ = writeln!(
                        out,
                        "\tr[{index}] = (uint64_t)syscall(SYS_{}, {args});",
                        SYSCALLS[sys]
                    );
                }
                CallSys::Raw(nr) => {
                    let _ = writeln!(
                        out,
                        "\tr[{index}] = denied({nr}) ? (uint64_t)-1 : (uint64_t)syscall({nr}, {args});"
                    );
                }
            }
        }
        out.push_str("\t(void)r;\n\treturn 0;\n}\n");
        out
    }
}

/// The schema of a program's JSON.
pub(crate) const PROGRAM_SCHEMA: &str = "bhf.kernel-program.v1";

/// The executor's refusal of raw calls, for a C reproducer.
const DENIED_C: &str = "\n/* The raw calls the executor refuses, as it refuses them. */\n\
static int denied(long nr)\n{\n\tstatic const long list[] = {\n\
\t\t__NR_reboot, __NR_kexec_load, __NR_init_module, __NR_finit_module,\n\
\t\t__NR_delete_module, __NR_mount, __NR_umount2, __NR_pivot_root,\n\
\t\t__NR_chroot, __NR_swapon, __NR_swapoff, __NR_syslog, __NR_ptrace,\n\
\t\t__NR_kill, __NR_tkill, __NR_tgkill,\n\
#ifdef __NR_kexec_file_load\n\t\t__NR_kexec_file_load,\n#endif\n\
#ifdef __NR_iopl\n\t\t__NR_iopl,\n#endif\n\
#ifdef __NR_ioperm\n\t\t__NR_ioperm,\n#endif\n\
#ifdef __NR_umount\n\t\t__NR_umount,\n#endif\n\
#ifdef __NR_move_mount\n\t\t__NR_move_mount, __NR_fsmount, __NR_open_tree,\n#endif\n\
#ifdef __NR_pidfd_send_signal\n\t\t__NR_pidfd_send_signal,\n#endif\n\
#ifdef __NR_process_vm_writev\n\t\t__NR_process_vm_writev,\n#endif\n\
\t};\n\tsize_t i;\n\tfor (i = 0; i < sizeof(list) / sizeof(list[0]); i++)\n\
\t\tif (list[i] == nr)\n\t\t\treturn 1;\n\treturn 0;\n}\n";

#[cfg(test)]
fn place_text(offset: Option<u64>) -> String {
    match offset {
        Some(offset) => format!("0x{offset:x}"),
        None => "null".to_owned(),
    }
}

/// `bytes` as a C string literal when they read as text, else as hex.
fn bytes_text(bytes: &[u8]) -> String {
    let body = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    let printable = !body.is_empty()
        && body
            .iter()
            .all(|b| b.is_ascii_graphic() || *b == b' ' || *b == b'\n' || *b == b'\t');
    if printable {
        let mut text = String::from("\"");
        for byte in bytes {
            match byte {
                b'"' => text.push_str("\\\""),
                b'\\' => text.push_str("\\\\"),
                b'\n' => text.push_str("\\n"),
                b'\t' => text.push_str("\\t"),
                0 => text.push_str("\\x00"),
                b => text.push(char::from(*b)),
            }
        }
        text.push('"');
        text
    } else {
        let mut text = String::from("x\"");
        for byte in bytes {
            let _ = write!(text, "{byte:02x}");
        }
        text.push('"');
        text
    }
}

/// One argument of a program [`ProgramBuilder`] writes.
#[derive(Debug, Clone, Copy)]
pub(crate) enum SeedArg<'a> {
    Const(u64),
    /// At most [`MAX_ARG_BYTES`]; longer is cut.
    Data(&'a [u8]),
    /// The result of call N of the program.
    Result(usize),
    Out(u16),
}

/// Writes programs in the executor's format.
#[derive(Debug, Default, Clone)]
pub(crate) struct ProgramBuilder {
    bytes: Vec<u8>,
    calls: usize,
}

impl ProgramBuilder {
    /// Add a call to `name` (one of [`SYSCALLS`]); its index.
    pub(crate) fn call(&mut self, name: &str, args: &[SeedArg<'_>]) -> anyhow::Result<usize> {
        let selector = SYSCALLS
            .iter()
            .position(|known| *known == name)
            .ok_or_else(|| anyhow::anyhow!("`{name}` is not a call the executor names"))?;
        self.push(selector as u8, None, args)
    }

    /// Add a raw call by number; its index.
    #[cfg(test)]
    pub(crate) fn raw(&mut self, nr: u16, args: &[SeedArg<'_>]) -> anyhow::Result<usize> {
        self.push(RAW_SELECTOR, Some(nr), args)
    }

    fn push(
        &mut self,
        selector: u8,
        nr: Option<u16>,
        args: &[SeedArg<'_>],
    ) -> anyhow::Result<usize> {
        anyhow::ensure!(
            self.calls < MAX_CALLS,
            "a program has at most {MAX_CALLS} calls"
        );
        anyhow::ensure!(
            args.len() <= MAX_ARGS,
            "a call has at most {MAX_ARGS} arguments"
        );
        self.bytes.push(selector);
        self.bytes.push(args.len() as u8);
        if let Some(nr) = nr {
            self.bytes.extend_from_slice(&nr.to_le_bytes());
        }
        for arg in args {
            match *arg {
                SeedArg::Const(value) => {
                    self.bytes.push(TAG_CONST);
                    self.bytes.extend_from_slice(&value.to_le_bytes());
                }
                SeedArg::Data(bytes) => {
                    let bytes = &bytes[..bytes.len().min(MAX_ARG_BYTES)];
                    self.bytes.push(TAG_DATA);
                    self.bytes
                        .extend_from_slice(&(bytes.len() as u16).to_le_bytes());
                    self.bytes.extend_from_slice(bytes);
                }
                SeedArg::Result(call) => {
                    anyhow::ensure!(
                        call < self.calls,
                        "call {} cannot take the result of call {call}",
                        self.calls
                    );
                    self.bytes.push(TAG_RESULT);
                    self.bytes.push(call as u8);
                }
                SeedArg::Out(len) => {
                    self.bytes.push(TAG_OUT);
                    self.bytes.extend_from_slice(&len.to_le_bytes());
                }
            }
        }
        self.calls += 1;
        Ok(self.calls - 1)
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

// ── The wire protocol ────────────────────────────────────────────────────

/// `BKX1`, little-endian.
pub(crate) const MAGIC: u32 = 0x3158_4b42;
pub(crate) const PROTOCOL: u32 = 1;
pub(crate) const MSG_HELLO: u32 = 1;
pub(crate) const MSG_EXEC: u32 = 2;
pub(crate) const MSG_REPLY: u32 = 3;
/// Largest message bhf reads: a reply of 64 calls holds at most 512 Ki PCs
/// (4 MiB).
pub(crate) const MAX_MESSAGE: u32 = 16 << 20;
/// Longest string a HELLO carries.
const MAX_HELLO_STRING: u32 = 64 << 10;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProtocolError {
    #[error("the executor's channel closed")]
    Closed,
    #[error("no message from the executor in time")]
    Timeout,
    #[error("executor channel: {0}")]
    Io(io::Error),
    #[error("not an executor message (magic {0:#010x})")]
    Magic(u32),
    #[error("an executor message of {0} bytes is larger than bhf reads ({MAX_MESSAGE})")]
    TooLarge(u32),
    #[error("expected the executor's {expected}, got a message of type {got}")]
    Unexpected { expected: &'static str, got: u32 },
    #[error("malformed {what}: {reason}")]
    Malformed { what: &'static str, reason: String },
    #[error("the executor speaks protocol {0}; this bhf speaks {PROTOCOL}")]
    Version(u32),
    #[error("the reply to program {got} came while program {expected} ran")]
    Id { expected: u64, got: u64 },
}

impl From<io::Error> for ProtocolError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::UnexpectedEof => Self::Closed,
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Self::Timeout,
            _ => Self::Io(error),
        }
    }
}

/// What the executor says when it starts serving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Hello {
    pub protocol: u32,
    /// `/sys/kernel/debug/kcov` opened and mapped.
    pub kcov: bool,
    /// It runs as the guest's `/init`.
    pub init: bool,
    /// KCOV records comparisons (`CONFIG_KCOV_ENABLE_COMPARISONS`).
    pub comparisons: bool,
    pub cover_entries: u32,
    pub max_program: u32,
    pub max_calls: u32,
    pub data_size: u32,
    pub data_addr: u64,
    /// `uname -m` and `uname -r` of the guest.
    pub machine: String,
    pub release: String,
    /// What setup did: each module loaded, or why not, and KCOV.
    pub notes: String,
}

impl Hello {
    /// The setup notes, a line each.
    pub(crate) fn note_lines(&self) -> Vec<String> {
        self.notes
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect()
    }

    /// The notes that say a module was not loaded: the executor notes
    /// `module <name>: loaded` for each it loaded, and `module <name>: not
    /// loaded: <error>` or `module <name>: open: <error>` for one it did
    /// not.
    pub(crate) fn unloaded_modules(&self) -> Vec<String> {
        self.note_lines()
            .into_iter()
            .filter(|line| {
                line.strip_prefix("module ")
                    .is_some_and(|rest| !rest.ends_with(": loaded"))
            })
            .collect()
    }
}

/// How a program's run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecStatus {
    /// Every call ran.
    Ok,
    /// The executor killed it after the timeout (ms).
    Timeout(u32),
    /// The child died by this signal.
    Signaled(u32),
    /// The child exited (with this status) before its last call: a call
    /// ended the process.
    Exited(u32),
    /// The executor could not set the run up (errno).
    Setup(u32),
    /// A status this bhf does not know, and its detail.
    Other(u32, u32),
}

impl ExecStatus {
    fn from_wire(status: u32, detail: u32) -> Self {
        match status {
            0 => Self::Ok,
            1 => Self::Timeout(detail),
            2 => Self::Signaled(detail),
            3 => Self::Exited(detail),
            4 => Self::Setup(detail),
            _ => Self::Other(status, detail),
        }
    }

    #[cfg(test)]
    fn to_wire(self) -> (u32, u32) {
        match self {
            Self::Ok => (0, 0),
            Self::Timeout(detail) => (1, detail),
            Self::Signaled(detail) => (2, detail),
            Self::Exited(detail) => (3, detail),
            Self::Setup(detail) => (4, detail),
            Self::Other(status, detail) => (status, detail),
        }
    }

    pub(crate) fn describe(self) -> String {
        match self {
            Self::Ok => "ok".to_owned(),
            Self::Timeout(ms) => format!("killed after {ms} ms"),
            Self::Signaled(signal) => format!("the program died by signal {signal}"),
            Self::Exited(code) => format!("a call ended the program (exit status {code})"),
            Self::Setup(errno) => format!("the executor could not set the run up (errno {errno})"),
            Self::Other(status, detail) => format!("status {status} ({detail})"),
        }
    }
}

/// What KCOV records while a program runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Collect {
    /// The PCs of the kernel code each call ran.
    Pcs,
    /// The comparisons that code made, and their operands.
    Comparisons,
}

/// One comparison KCOV recorded (`KCOV_TRACE_CMP`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KcovComparison {
    /// KCOV's type word: bit 0 set when an operand is a constant, bits 1-2
    /// the operands' size (1, 2, 4 or 8 bytes).
    pub kind: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub pc: u64,
}

impl KcovComparison {
    /// The operands' size in bytes.
    pub(crate) fn size(self) -> usize {
        1 << ((self.kind >> 1) & 3)
    }
}

/// One call's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallResult {
    pub index: u32,
    /// The call's errno when it failed, else 0.
    pub errno: u32,
    /// What the call returned (-1 when it failed).
    pub ret: i64,
    /// The kernel PCs KCOV recorded while the call ran, in order.
    pub pcs: Vec<u64>,
    /// The comparisons it recorded, when they were asked for instead.
    pub comparisons: Vec<KcovComparison>,
    /// KCOV's buffer filled, or the program's cap was reached.
    pub truncated: bool,
}

/// The executor's reply to one program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExecReply {
    pub id: u64,
    pub status: ExecStatus,
    /// Calls the program decoded to.
    pub decoded: u32,
    /// KCOV traced the run.
    pub kcov: bool,
    /// Some PCs were left out.
    pub truncated: bool,
    /// The calls that ran.
    pub calls: Vec<CallResult>,
}

impl ExecReply {
    /// Distinct `(previous PC, PC)` pairs of the calls' traces: the KCOV
    /// edges the run took.
    pub(crate) fn edges(&self) -> usize {
        let mut edges = std::collections::HashSet::new();
        for call in &self.calls {
            for pair in call.pcs.windows(2) {
                edges.insert((pair[0], pair[1]));
            }
        }
        edges.len()
    }
}

/// A message's payload, read field by field.
struct Fields<'a> {
    what: &'static str,
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Fields<'a> {
    fn new(what: &'static str, bytes: &'a [u8]) -> Self {
        Self {
            what,
            bytes,
            pos: 0,
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ProtocolError> {
        if self.bytes.len() - self.pos < n {
            return Err(ProtocolError::Malformed {
                what: self.what,
                reason: format!(
                    "it ends at byte {} of a field that needs {n} more",
                    self.bytes.len(),
                ),
            });
        }
        self.pos += n;
        Ok(&self.bytes[self.pos - n..self.pos])
    }

    fn u32(&mut self) -> Result<u32, ProtocolError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self) -> Result<u64, ProtocolError> {
        Ok(le64(self.take(8)?))
    }

    fn string(&mut self, max: u32) -> Result<String, ProtocolError> {
        let len = self.u32()?;
        if len > max {
            return Err(ProtocolError::Malformed {
                what: self.what,
                reason: format!("a string of {len} bytes"),
            });
        }
        Ok(String::from_utf8_lossy(self.take(len as usize)?).into_owned())
    }

    fn finish(self) -> Result<(), ProtocolError> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(ProtocolError::Malformed {
                what: self.what,
                reason: format!("{} bytes past its end", self.bytes.len() - self.pos),
            })
        }
    }
}

/// Read one message: its type and payload.
pub(crate) fn read_message(reader: &mut impl Read) -> Result<(u32, Vec<u8>), ProtocolError> {
    let mut head = [0u8; 12];
    reader.read_exact(&mut head)?;
    let word = |at: usize| u32::from_le_bytes([head[at], head[at + 1], head[at + 2], head[at + 3]]);
    let (magic, kind, len) = (word(0), word(4), word(8));
    if magic != MAGIC {
        return Err(ProtocolError::Magic(magic));
    }
    if len > MAX_MESSAGE {
        return Err(ProtocolError::TooLarge(len));
    }
    let mut payload = Vec::new();
    reader.take(u64::from(len)).read_to_end(&mut payload)?;
    if payload.len() != len as usize {
        return Err(ProtocolError::Closed);
    }
    Ok((kind, payload))
}

/// Write one message.
pub(crate) fn write_message(writer: &mut impl Write, kind: u32, payload: &[u8]) -> io::Result<()> {
    let mut message = Vec::with_capacity(12 + payload.len());
    message.extend_from_slice(&MAGIC.to_le_bytes());
    message.extend_from_slice(&kind.to_le_bytes());
    message.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    message.extend_from_slice(payload);
    writer.write_all(&message)?;
    writer.flush()
}

pub(crate) fn parse_hello(payload: &[u8]) -> Result<Hello, ProtocolError> {
    let mut fields = Fields::new("HELLO", payload);
    let protocol = fields.u32()?;
    if protocol != PROTOCOL {
        return Err(ProtocolError::Version(protocol));
    }
    let flags = fields.u32()?;
    let hello = Hello {
        protocol,
        kcov: flags & 1 != 0,
        init: flags & 2 != 0,
        comparisons: flags & 4 != 0,
        cover_entries: fields.u32()?,
        max_program: fields.u32()?,
        max_calls: fields.u32()?,
        data_size: fields.u32()?,
        data_addr: fields.u64()?,
        machine: fields.string(MAX_HELLO_STRING)?,
        release: fields.string(MAX_HELLO_STRING)?,
        notes: fields.string(MAX_HELLO_STRING)?,
    };
    fields.finish()?;
    Ok(hello)
}

#[cfg(test)]
pub(crate) fn encode_hello(hello: &Hello) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&hello.protocol.to_le_bytes());
    let flags =
        u32::from(hello.kcov) | (u32::from(hello.init) << 1) | (u32::from(hello.comparisons) << 2);
    for word in [
        flags,
        hello.cover_entries,
        hello.max_program,
        hello.max_calls,
        hello.data_size,
    ] {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out.extend_from_slice(&hello.data_addr.to_le_bytes());
    for text in [&hello.machine, &hello.release, &hello.notes] {
        out.extend_from_slice(&(text.len() as u32).to_le_bytes());
        out.extend_from_slice(text.as_bytes());
    }
    out
}

pub(crate) fn encode_exec(id: u64, collect: Collect, timeout_ms: u32, program: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(20 + program.len());
    out.extend_from_slice(&id.to_le_bytes());
    let flags: u32 = match collect {
        Collect::Pcs => 1,
        Collect::Comparisons => 2,
    };
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&timeout_ms.to_le_bytes());
    out.extend_from_slice(&(program.len() as u32).to_le_bytes());
    out.extend_from_slice(program);
    out
}

/// An EXEC payload: `(id, flags, timeout_ms, program)`.
#[cfg(test)]
pub(crate) fn parse_exec(payload: &[u8]) -> Result<(u64, u32, u32, Vec<u8>), ProtocolError> {
    let mut fields = Fields::new("EXEC", payload);
    let id = fields.u64()?;
    let flags = fields.u32()?;
    let timeout = fields.u32()?;
    let len = fields.u32()?;
    let program = fields.take(len as usize)?.to_vec();
    fields.finish()?;
    Ok((id, flags, timeout, program))
}

pub(crate) fn parse_reply(payload: &[u8]) -> Result<ExecReply, ProtocolError> {
    let mut fields = Fields::new("REPLY", payload);
    let id = fields.u64()?;
    let status = fields.u32()?;
    let detail = fields.u32()?;
    let decoded = fields.u32()?;
    let ran = fields.u32()?;
    let flags = fields.u32()?;
    let _reserved = fields.u32()?;
    if ran as usize > MAX_CALLS || ran > decoded {
        return Err(ProtocolError::Malformed {
            what: "REPLY",
            reason: format!("{ran} calls ran of {decoded}"),
        });
    }
    let comparisons = flags & 4 != 0;
    let mut calls = Vec::with_capacity(ran as usize);
    for _ in 0..ran {
        let index = fields.u32()?;
        let errno = fields.u32()?;
        let ret = fields.u64()? as i64;
        let nwords = fields.u32()? as usize;
        let call_flags = fields.u32()?;
        let raw = fields.take(nwords.checked_mul(8).ok_or(ProtocolError::Malformed {
            what: "REPLY",
            reason: format!("{nwords} words"),
        })?)?;
        let words: Vec<u64> = raw
            .as_chunks::<8>()
            .0
            .iter()
            .map(|word| u64::from_le_bytes(*word))
            .collect();
        let (pcs, records) = if comparisons {
            let (records, rest) = words.as_chunks::<4>();
            if !rest.is_empty() {
                return Err(ProtocolError::Malformed {
                    what: "REPLY",
                    reason: format!("{nwords} words are not comparisons of four"),
                });
            }
            let records = records
                .iter()
                .map(|[kind, arg1, arg2, pc]| KcovComparison {
                    kind: *kind,
                    arg1: *arg1,
                    arg2: *arg2,
                    pc: *pc,
                })
                .collect();
            (Vec::new(), records)
        } else {
            (words, Vec::new())
        };
        calls.push(CallResult {
            index,
            errno,
            ret,
            pcs,
            comparisons: records,
            truncated: call_flags & 1 != 0,
        });
    }
    fields.finish()?;
    Ok(ExecReply {
        id,
        status: ExecStatus::from_wire(status, detail),
        decoded,
        kcov: flags & 1 != 0,
        truncated: flags & 2 != 0,
        calls,
    })
}

#[cfg(test)]
pub(crate) fn encode_reply(reply: &ExecReply) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&reply.id.to_le_bytes());
    let (status, detail) = reply.status.to_wire();
    let comparisons = reply.calls.iter().any(|call| !call.comparisons.is_empty());
    let flags =
        u32::from(reply.kcov) | (u32::from(reply.truncated) << 1) | (u32::from(comparisons) << 2);
    for word in [
        status,
        detail,
        reply.decoded,
        reply.calls.len() as u32,
        flags,
        0,
    ] {
        out.extend_from_slice(&word.to_le_bytes());
    }
    for call in &reply.calls {
        out.extend_from_slice(&call.index.to_le_bytes());
        out.extend_from_slice(&call.errno.to_le_bytes());
        out.extend_from_slice(&call.ret.to_le_bytes());
        let words: Vec<u64> = if comparisons {
            call.comparisons
                .iter()
                .flat_map(|cmp| [cmp.kind, cmp.arg1, cmp.arg2, cmp.pc])
                .collect()
        } else {
            call.pcs.clone()
        };
        out.extend_from_slice(&(words.len() as u32).to_le_bytes());
        out.extend_from_slice(&u32::from(call.truncated).to_le_bytes());
        for word in &words {
            out.extend_from_slice(&word.to_le_bytes());
        }
    }
    out
}

/// The host's end of the protocol: one HELLO, then an EXEC and its REPLY
/// per program.
pub(crate) struct ExecutorClient<C> {
    channel: C,
    hello: Hello,
    next_id: u64,
}

impl<C: Read + Write> ExecutorClient<C> {
    /// Wait for the executor's HELLO on `channel`.
    pub(crate) fn handshake(mut channel: C) -> Result<Self, ProtocolError> {
        let (kind, payload) = read_message(&mut channel)?;
        if kind != MSG_HELLO {
            return Err(ProtocolError::Unexpected {
                expected: "HELLO",
                got: kind,
            });
        }
        Ok(Self {
            channel,
            hello: parse_hello(&payload)?,
            next_id: 1,
        })
    }

    pub(crate) fn hello(&self) -> &Hello {
        &self.hello
    }

    pub(crate) fn channel_mut(&mut self) -> &mut C {
        &mut self.channel
    }

    /// Run `program`, KCOV collecting what `collect` says; the executor
    /// kills it after `timeout`.
    pub(crate) fn execute(
        &mut self,
        program: &[u8],
        collect: Collect,
        timeout: Duration,
    ) -> Result<ExecReply, ProtocolError> {
        if program.len() > self.hello.max_program as usize {
            return Err(ProtocolError::Malformed {
                what: "program",
                reason: format!(
                    "{} bytes, more than the executor takes ({})",
                    program.len(),
                    self.hello.max_program
                ),
            });
        }
        let id = self.next_id;
        self.next_id += 1;
        let timeout_ms = u32::try_from(timeout.as_millis())
            .unwrap_or(u32::MAX)
            .max(1);
        write_message(
            &mut self.channel,
            MSG_EXEC,
            &encode_exec(id, collect, timeout_ms, program),
        )?;
        let (kind, payload) = read_message(&mut self.channel)?;
        if kind != MSG_REPLY {
            return Err(ProtocolError::Unexpected {
                expected: "REPLY",
                got: kind,
            });
        }
        let reply = parse_reply(&payload)?;
        if reply.id != id {
            return Err(ProtocolError::Id {
                expected: id,
                got: reply.id,
            });
        }
        Ok(reply)
    }
}

// ── Building the guest's initramfs ───────────────────────────────────────

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Build the executor with `cc` into `dir` (statically linked: the
/// initramfs has no C library), once per source: the path of the binary.
pub(crate) fn build_executor(cc: &str, dir: &Path) -> anyhow::Result<PathBuf> {
    use anyhow::Context;
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    let source = dir.join("kernel_executor.c");
    let binary = dir.join("bhf-kernel-executor");
    let stamp = dir.join("bhf-kernel-executor.source-sha256");
    let digest = format!("{} {cc}", sha256_hex(EXECUTOR_SOURCE.as_bytes()));
    if binary.is_file() && std::fs::read_to_string(&stamp).ok().as_deref() == Some(&digest) {
        return Ok(binary);
    }
    std::fs::write(&source, EXECUTOR_SOURCE)
        .with_context(|| format!("write {}", source.display()))?;
    let output = std::process::Command::new(cc)
        .args(["-O2", "-static", "-o"])
        .arg(&binary)
        .arg(&source)
        .output()
        .with_context(|| format!("run {cc} to build the guest executor"))?;
    if !output.status.success() {
        anyhow::bail!(
            "{cc} could not build the guest executor (it is linked statically: install the \
             C library's static archive, such as glibc's libc.a, or pass --executor):\n{}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    std::fs::write(&stamp, digest).with_context(|| format!("write {}", stamp.display()))?;
    Ok(binary)
}

/// One file of a newc cpio archive.
pub(crate) struct CpioEntry {
    pub name: String,
    pub mode: u32,
    pub data: Vec<u8>,
    /// A device node's `(major, minor)`.
    pub rdev: (u32, u32),
}

const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFCHR: u32 = 0o020000;

/// `entries` as a newc ("070701") cpio archive, as the kernel unpacks an
/// initramfs: no compression, owner root, mtime 0.
pub(crate) fn cpio_newc(entries: &[CpioEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    let pad = |out: &mut Vec<u8>| {
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
    };
    let trailer = CpioEntry {
        name: "TRAILER!!!".to_owned(),
        mode: 0,
        data: Vec::new(),
        rdev: (0, 0),
    };
    for (ino, entry) in entries.iter().chain([&trailer]).enumerate() {
        let name_size = entry.name.len() + 1;
        let fields = [
            ino as u32 + 1,
            entry.mode,
            0,
            0,
            if entry.mode & S_IFDIR != 0 { 2 } else { 1 },
            0,
            entry.data.len() as u32,
            0,
            0,
            entry.rdev.0,
            entry.rdev.1,
            name_size as u32,
            0,
        ];
        out.extend_from_slice(b"070701");
        for field in fields {
            out.extend_from_slice(format!("{field:08x}").as_bytes());
        }
        out.extend_from_slice(entry.name.as_bytes());
        out.push(0);
        pad(&mut out);
        out.extend_from_slice(&entry.data);
        pad(&mut out);
    }
    out
}

/// Write the guest's initramfs to `out`: the executor as `/init`, and each
/// module as `/bhf/modules/NN-<name>`, which it loads in that order.
pub(crate) fn build_initramfs(
    executor: &Path,
    modules: &[PathBuf],
    out: &Path,
) -> anyhow::Result<()> {
    use anyhow::Context;
    let read =
        |path: &Path| std::fs::read(path).with_context(|| format!("read {}", path.display()));
    let dir = |name: &str| CpioEntry {
        name: name.to_owned(),
        mode: S_IFDIR | 0o755,
        data: Vec::new(),
        rdev: (0, 0),
    };
    let mut entries = vec![
        dir("dev"),
        CpioEntry {
            name: "dev/console".to_owned(),
            mode: S_IFCHR | 0o600,
            data: Vec::new(),
            rdev: (5, 1),
        },
        dir("proc"),
        dir("sys"),
        dir("bhf"),
        dir("bhf/modules"),
    ];
    for (index, module) in modules.iter().enumerate() {
        let name = module
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".ko"))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "{}: a kernel module's file name ends in .ko",
                    module.display()
                )
            })?;
        entries.push(CpioEntry {
            name: format!("bhf/modules/{index:02}-{name}"),
            mode: S_IFREG | 0o644,
            data: read(module)?,
            rdev: (0, 0),
        });
    }
    entries.push(CpioEntry {
        name: "init".to_owned(),
        mode: S_IFREG | 0o755,
        data: read(executor)?,
        rdev: (0, 0),
    });
    std::fs::write(out, cpio_newc(&entries)).with_context(|| format!("write {}", out.display()))
}

// ── The guest ────────────────────────────────────────────────────────────

/// The kernel command line bhf boots with, before `--append`: the console
/// on the first serial port, PCs that do not move between boots (the edge
/// ids are PCs), and every report a panic, so the guest stops at the first
/// one and QEMU (`-no-reboot`) exits.
pub(crate) const BASE_APPEND: &str = "console=ttyS0 nokaslr panic_on_warn=1 oops=panic panic=-1 \
                                      rcupdate.rcu_cpu_stall_timeout=100";

/// The name of the executor's virtio-serial port.
pub(crate) const PORT_NAME: &str = "org.bhf.executor";

/// How QEMU runs the guest's CPUs.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Accel {
    /// kvm when `/dev/kvm` can be opened for reading and writing, else tcg.
    Auto,
    Kvm,
    Tcg,
}

impl Accel {
    /// `Auto` decided on this host.
    pub(crate) fn resolve(self) -> Self {
        match self {
            Self::Auto => {
                let usable = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("/dev/kvm")
                    .is_ok();
                if usable {
                    Self::Kvm
                } else {
                    Self::Tcg
                }
            }
            other => other,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Kvm => "kvm",
            Self::Tcg => "tcg",
        }
    }
}

/// The longest the host waits for a guest to boot, or gives a program to
/// run, in seconds: a day. The command line takes no more, and a longer
/// wait is cut to it, so no deadline overflows.
pub(crate) const MAX_WAIT_SECS: u64 = 86_400;
const MAX_WAIT: Duration = Duration::from_secs(MAX_WAIT_SECS);

/// How long the host waits for the reply to a program the executor kills
/// after `timeout`: twice that, and 10 s more.
pub(crate) fn reply_wait(timeout: Duration) -> Duration {
    timeout.min(MAX_WAIT) * 2 + Duration::from_secs(10)
}

/// How to boot a guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GuestSetup {
    pub qemu: PathBuf,
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    pub memory_mb: u32,
    pub smp: u32,
    pub accel: Accel,
    /// Kernel command-line arguments after [`BASE_APPEND`].
    pub append: Option<String>,
    pub qemu_args: Vec<String>,
    /// How long the guest has to boot and its executor to say HELLO.
    pub boot_timeout: Duration,
}

impl GuestSetup {
    /// The kernel command line.
    pub(crate) fn command_line(&self) -> String {
        match self.append.as_deref().map(str::trim) {
            Some(extra) if !extra.is_empty() => format!("{BASE_APPEND} {extra}"),
            _ => BASE_APPEND.to_owned(),
        }
    }

    /// QEMU's arguments, with `accel` resolved and the executor's port on
    /// the Unix socket `socket`.
    pub(crate) fn qemu_command(&self, accel: Accel, socket: &Path) -> Vec<String> {
        let mut args: Vec<String> = [
            "-nodefaults",
            "-no-user-config",
            "-display",
            "none",
            "-no-reboot",
            "-serial",
            "stdio",
            "-accel",
            accel.as_str(),
        ]
        .iter()
        .map(|arg| (*arg).to_owned())
        .collect();
        if accel == Accel::Kvm {
            args.extend(["-cpu".to_owned(), "host".to_owned()]);
        }
        args.extend([
            "-m".to_owned(),
            self.memory_mb.to_string(),
            "-smp".to_owned(),
            self.smp.to_string(),
            "-kernel".to_owned(),
            self.kernel.display().to_string(),
            "-initrd".to_owned(),
            self.initrd.display().to_string(),
            "-append".to_owned(),
            self.command_line(),
            "-device".to_owned(),
            "virtio-serial-pci,id=bhfserial".to_owned(),
            "-chardev".to_owned(),
            format!("socket,id=bhfexec,path={}", socket.display()),
            "-device".to_owned(),
            format!("virtserialport,bus=bhfserial.0,chardev=bhfexec,name={PORT_NAME}"),
        ]);
        args.extend(self.qemu_args.iter().cloned());
        args
    }
}

/// Bytes of console output a [`Console`] keeps in memory; older output is
/// in the log file only.
const CONSOLE_KEEP: usize = 8 << 20;

/// The guest's serial console as it is written, kept for the reports in
/// it and appended to a log file.
#[derive(Default)]
pub(crate) struct Console {
    state: std::sync::Mutex<ConsoleState>,
    changed: std::sync::Condvar,
}

#[derive(Default)]
struct ConsoleState {
    bytes: Vec<u8>,
    /// The offset in the whole output of `bytes[0]`.
    base: u64,
    closed: bool,
    log: Option<std::fs::File>,
}

impl Console {
    fn lock(&self) -> std::sync::MutexGuard<'_, ConsoleState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn with_log(log: Option<std::fs::File>) -> Self {
        let console = Self::default();
        console.lock().log = log;
        console
    }

    pub(crate) fn append(&self, chunk: &[u8]) {
        let mut state = self.lock();
        if let Some(log) = state.log.as_mut() {
            let _ = log.write_all(chunk);
        }
        state.bytes.extend_from_slice(chunk);
        if state.bytes.len() > CONSOLE_KEEP {
            let drop = state.bytes.len() - CONSOLE_KEEP / 2;
            state.bytes.drain(..drop);
            state.base += drop as u64;
        }
        self.changed.notify_all();
    }

    fn close(&self) {
        self.lock().closed = true;
        self.changed.notify_all();
    }

    /// Bytes written so far: a mark for [`Console::since`].
    pub(crate) fn mark(&self) -> u64 {
        let state = self.lock();
        state.base + state.bytes.len() as u64
    }

    /// What was written after `mark` (from what is kept).
    pub(crate) fn since(&self, mark: u64) -> String {
        let state = self.lock();
        let start = mark
            .saturating_sub(state.base)
            .min(state.bytes.len() as u64) as usize;
        String::from_utf8_lossy(&state.bytes[start..]).into_owned()
    }

    /// The last `lines` lines.
    pub(crate) fn tail(&self, lines: usize) -> String {
        let state = self.lock();
        let text = String::from_utf8_lossy(&state.bytes);
        let all: Vec<&str> = text.lines().collect();
        all[all.len().saturating_sub(lines)..].join("\n")
    }

    /// Wait until the guest's output ended (QEMU closed it), at most
    /// `timeout`; whether it did.
    pub(crate) fn wait_closed(&self, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        let mut state = self.lock();
        while !state.closed {
            let now = std::time::Instant::now();
            if now >= deadline {
                return false;
            }
            state = self
                .changed
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .0;
        }
        true
    }
}

/// How a program's run in the guest ended.
#[derive(Debug)]
pub(crate) enum RunEnd {
    Replied(ExecReply),
    /// The guest stopped, or its channel failed, before the reply: why.
    Stopped(String),
    /// No reply came within the host's deadline.
    NoReply,
}

/// One program's run in the guest.
#[derive(Debug)]
pub(crate) struct GuestRun {
    pub end: RunEnd,
    /// The console output from the program's start to its end.
    pub console: String,
    pub elapsed: Duration,
}

/// A booted guest whose executor said HELLO.
#[cfg(unix)]
pub(crate) struct Guest {
    child: std::process::Child,
    client: ExecutorClient<std::os::unix::net::UnixStream>,
    console: std::sync::Arc<Console>,
    readers: Vec<std::thread::JoinHandle<()>>,
    stderr: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    accel: Accel,
    _socket_dir: tempfile::TempDir,
}

/// A directory for the executor's socket whose path fits a Unix socket
/// address (108 bytes): the temp dir, else `/tmp`.
#[cfg(unix)]
fn socket_dir() -> anyhow::Result<tempfile::TempDir> {
    use anyhow::Context;
    let fits = |dir: &Path| dir.join("bhf-kg-XXXXXXXX/executor.sock").as_os_str().len() < 100;
    let base = [std::env::temp_dir(), PathBuf::from("/tmp")]
        .into_iter()
        .find(|dir| fits(dir) && dir.is_dir())
        .ok_or_else(|| {
            anyhow::anyhow!("no directory for the executor's socket: set TMPDIR to a short path")
        })?;
    tempfile::Builder::new()
        .prefix("bhf-kg-")
        .tempdir_in(&base)
        .with_context(|| format!("create a socket directory in {}", base.display()))
}

#[cfg(unix)]
impl Guest {
    /// Boot `setup`, its console appended to `console_log` when given, and
    /// wait for the executor's HELLO.
    pub(crate) fn boot(setup: &GuestSetup, console_log: Option<&Path>) -> anyhow::Result<Self> {
        use anyhow::Context;
        use std::os::unix::net::UnixListener;
        use std::process::{Command, Stdio};
        use std::time::Instant;

        for (what, path) in [("kernel", &setup.kernel), ("initramfs", &setup.initrd)] {
            anyhow::ensure!(
                path.is_file(),
                "the guest {what} {} is not a file",
                path.display()
            );
        }
        let log = match console_log {
            Some(path) => Some(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .with_context(|| format!("open {}", path.display()))?,
            ),
            None => None,
        };
        let socket_dir = socket_dir()?;
        let socket = socket_dir.path().join("executor.sock");
        let listener = UnixListener::bind(&socket)
            .with_context(|| format!("listen on {}", socket.display()))?;
        listener.set_nonblocking(true)?;
        let accel = setup.accel.resolve();
        let mut child = Command::new(&setup.qemu)
            .args(setup.qemu_command(accel, &socket))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("start {}", setup.qemu.display()))?;
        let console = std::sync::Arc::new(Console::with_log(log));
        let stderr = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut readers = Vec::new();
        if let Some(mut out) = child.stdout.take() {
            let console = console.clone();
            readers.push(std::thread::spawn(move || {
                let mut chunk = [0u8; 8192];
                loop {
                    match out.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => console.append(&chunk[..n]),
                    }
                }
                console.close();
            }));
        }
        if let Some(mut err) = child.stderr.take() {
            let stderr = stderr.clone();
            readers.push(std::thread::spawn(move || {
                let mut chunk = [0u8; 4096];
                while let Ok(n) = err.read(&mut chunk) {
                    if n == 0 {
                        break;
                    }
                    let mut kept = stderr.lock().unwrap_or_else(|p| p.into_inner());
                    if kept.len() < 64 << 10 {
                        kept.extend_from_slice(&chunk[..n]);
                    }
                }
            }));
        }
        let mut guest = GuestParts {
            child: Some(child),
            console,
            readers,
            stderr,
        };
        let boot_timeout = setup.boot_timeout.min(MAX_WAIT);
        let deadline = Instant::now() + boot_timeout;
        // QEMU connects as it starts; the executor speaks once the kernel
        // has booted and run it.
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(guest.failure(&format!("accept: {error}"))),
            }
            if let Ok(Some(status)) = guest.child().try_wait() {
                return Err(guest.failure(&format!("qemu exited ({status}) before it connected")));
            }
            if Instant::now() >= deadline {
                return Err(guest.failure("qemu did not connect to the executor's socket"));
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(
            deadline
                .saturating_duration_since(Instant::now())
                .max(Duration::from_millis(1)),
        ))?;
        let client = match ExecutorClient::handshake(stream) {
            Ok(client) => client,
            Err(ProtocolError::Timeout) => {
                return Err(guest.failure(&format!(
                    "the executor did not say HELLO within {}s of the boot",
                    boot_timeout.as_secs()
                )))
            }
            Err(error) => {
                let _ = wait_timeout(guest.child(), Duration::from_secs(5));
                return Err(guest.failure(&format!("the executor's HELLO: {error}")));
            }
        };
        Ok(Self {
            child: guest
                .child
                .take()
                .expect("the child runs until the guest is built"),
            client,
            console: guest.console.clone(),
            readers: std::mem::take(&mut guest.readers),
            stderr: guest.stderr.clone(),
            accel,
            _socket_dir: socket_dir,
        })
    }

    pub(crate) fn hello(&self) -> &Hello {
        self.client.hello()
    }

    pub(crate) fn accel(&self) -> Accel {
        self.accel
    }

    /// Run `program`, which the executor kills after `timeout`; the host
    /// waits a little longer for the reply.
    pub(crate) fn run(&mut self, program: &[u8], timeout: Duration) -> GuestRun {
        self.run_collecting(program, Collect::Pcs, timeout)
    }

    /// [`Guest::run`], KCOV collecting what `collect` says.
    pub(crate) fn run_collecting(
        &mut self,
        program: &[u8],
        collect: Collect,
        timeout: Duration,
    ) -> GuestRun {
        let start = std::time::Instant::now();
        let mark = self.console.mark();
        let wait = reply_wait(timeout);
        let end = match self.client.channel_mut().set_read_timeout(Some(wait)) {
            Err(error) => RunEnd::Stopped(format!("executor channel: {error}")),
            Ok(()) => match self.client.execute(program, collect, timeout) {
                Ok(reply) => RunEnd::Replied(reply),
                Err(ProtocolError::Timeout) => RunEnd::NoReply,
                Err(error) => {
                    // The guest went down: its console holds why.
                    let status = wait_timeout(&mut self.child, Duration::from_secs(30));
                    self.console.wait_closed(Duration::from_secs(5));
                    let mut reason = match status {
                        Some(status) => format!("{error}; qemu exited ({status})"),
                        None => error.to_string(),
                    };
                    let stderr = self.qemu_stderr();
                    if !stderr.trim().is_empty() {
                        let _ = write!(reason, "; qemu: {}", stderr.trim());
                    }
                    RunEnd::Stopped(reason)
                }
            },
        };
        if matches!(end, RunEnd::NoReply) {
            // A report the guest is still printing.
            self.console.wait_closed(Duration::from_secs(2));
        }
        GuestRun {
            end,
            console: self.console.since(mark),
            elapsed: start.elapsed(),
        }
    }

    /// QEMU's stderr so far.
    fn qemu_stderr(&self) -> String {
        String::from_utf8_lossy(&self.stderr.lock().unwrap_or_else(|p| p.into_inner())).into_owned()
    }
}

#[cfg(unix)]
impl Drop for Guest {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
    }
}

/// A QEMU process being booted, killed when dropped before it is a
/// [`Guest`].
#[cfg(unix)]
struct GuestParts {
    child: Option<std::process::Child>,
    console: std::sync::Arc<Console>,
    readers: Vec<std::thread::JoinHandle<()>>,
    stderr: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

#[cfg(unix)]
impl Drop for GuestParts {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
    }
}

#[cfg(unix)]
impl GuestParts {
    /// A boot failure: `what`, QEMU's stderr and the console's last lines.
    fn failure(&mut self, what: &str) -> anyhow::Error {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.console.wait_closed(Duration::from_secs(2));
        let stderr =
            String::from_utf8_lossy(&self.stderr.lock().unwrap_or_else(|p| p.into_inner()))
                .trim()
                .to_owned();
        let mut message = format!("the guest did not start: {what}");
        if !stderr.is_empty() {
            let _ = write!(message, "\nqemu: {stderr}");
        }
        let tail = self.console.tail(30);
        if !tail.trim().is_empty() {
            let _ = write!(message, "\nlast console lines:\n{tail}");
        }
        anyhow::anyhow!(message)
    }

    fn child(&mut self) -> &mut std::process::Child {
        self.child
            .as_mut()
            .expect("the child is taken only by into_guest")
    }
}

/// `child`'s exit status, waiting at most `timeout`.
#[cfg(unix)]
fn wait_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Option<std::process::ExitStatus> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => return None,
        }
    }
}

// ── Coverage ─────────────────────────────────────────────────────────────

/// A kernel PC as an edge-map id: its two halves folded together. The
/// kernel's text and its modules' share the upper half of their addresses
/// (`0xffffffff` on x86_64), so distinct PCs keep distinct ids, and
/// `nokaslr` keeps them where they are on every boot.
pub(crate) fn pc_id(pc: u64) -> u32 {
    (pc as u32) ^ ((pc >> 32) as u32)
}

/// A reply's trace for the coverage map: each call's PCs as edge-map ids,
/// the calls in order. The builtin engine's coverage map counts each id's
/// hits in buckets and each pair of consecutive ids as an edge, as it does
/// a harness's breadcrumbs; the pair across two calls is the return to user
/// space and the next system call's entry.
pub(crate) fn coverage_ids(reply: &ExecReply) -> Vec<u32> {
    reply
        .calls
        .iter()
        .flat_map(|call| call.pcs.iter().map(|pc| pc_id(*pc)))
        .collect()
}

/// Fold `ids` into `coverage`: the bits it had not seen.
pub(crate) fn fold_coverage(
    coverage: &mut fuzz_engine_builtin::CoverageProxy,
    ids: &[u32],
) -> fuzz_engine_builtin::CoverageFeedback {
    let testcase = event_log::Testcase {
        testcase_id: 0,
        target_id: 0,
        target_entered: false,
        crumbs: ids.to_vec(),
        handlers: Vec::new(),
        raises: Vec::new(),
        top_level: None,
        end: None,
        mocks: Vec::new(),
    };
    coverage.record(fuzz_engine_builtin::CoverageInput::new(&testcase, &[]))
}

// ── Mutating programs ────────────────────────────────────────────────────

/// Most comparisons one program's CmpLog keeps.
const MAX_COMPARISONS: usize = 4096;

/// The comparisons a reply recorded, as the CmpLog a mutation of `program`
/// splices from: an operand found in the program is replaced with the value
/// the kernel compared it against (a bound, a magic number, a command).
pub(crate) fn comparison_log(reply: &ExecReply, program: &[u8]) -> cmplog::CmpLog {
    let mut seen = std::collections::HashSet::new();
    let mut log = cmplog::CmpLog::new();
    for comparison in reply.calls.iter().flat_map(|call| &call.comparisons) {
        let size = comparison.size();
        let a = comparison.arg1.to_le_bytes()[..size].to_vec();
        let b = comparison.arg2.to_le_bytes()[..size].to_vec();
        if a == b || !seen.insert((a.clone(), b.clone())) {
            continue;
        }
        log.record(cmplog::CmpEntry {
            site_id: comparison.pc,
            operand_a: a,
            operand_b: b,
            kind: cmplog::CmpKind::IntegerCompare,
        });
    }
    log.retain_spliceable(program);
    log.entries.truncate(MAX_COMPARISONS);
    log
}

/// Bytes of a data buffer whose 4-byte words are typed spans (the fields
/// of the struct an ioctl takes).
const TYPED_DATA_PREFIX: usize = 64;

/// Most hint programs one corpus program yields.
pub(crate) const MAX_HINTS: usize = 128;

/// The programs the comparisons of `reply` suggest, as syzkaller's hints
/// do: wherever an argument of a call (a constant's low bytes, or a word of
/// a data buffer at the operand's alignment) holds one operand of a
/// comparison the kernel made while that call ran, that argument with the
/// other operand. The calls take turns, so each gets its share of the `max`
/// hints; each hint is made once.
pub(crate) fn hint_programs(program: &[u8], reply: &ExecReply, max: usize) -> Vec<Vec<u8>> {
    let decoded = decode(program);
    let mut per_call: Vec<std::collections::VecDeque<Vec<u8>>> = Vec::new();
    let mut made = std::collections::HashSet::new();
    made.insert(program.to_vec());
    for (call, result) in decoded.calls.iter().zip(&reply.calls) {
        let mut pairs = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for comparison in &result.comparisons {
            let size = comparison.size();
            let a = comparison.arg1.to_le_bytes()[..size].to_vec();
            let b = comparison.arg2.to_le_bytes()[..size].to_vec();
            if a != b && seen.insert((a.clone(), b.clone())) {
                pairs.push((a.clone(), b.clone()));
                pairs.push((b, a));
            }
        }
        // Where a value of each size can be replaced: (offset, size).
        let mut places = Vec::new();
        for arg in &call.args {
            match &arg.value {
                ArgValue::Const(_) => {
                    for size in [1, 2, 4, 8] {
                        places.push((arg.span.start, size));
                    }
                }
                ArgValue::Data { bytes, .. } => {
                    for size in [1, 2, 4, 8] {
                        let mut offset = bytes.start;
                        while offset + size <= bytes.end {
                            places.push((offset, size));
                            offset += size;
                        }
                    }
                }
                _ => {}
            }
        }
        let mut hints = std::collections::VecDeque::new();
        for (from, to) in &pairs {
            for &(offset, size) in &places {
                if size != from.len() || program[offset..offset + size] != from[..] {
                    continue;
                }
                let mut hint = program.to_vec();
                hint[offset..offset + size].copy_from_slice(to);
                if made.insert(hint.clone()) {
                    hints.push_back(hint);
                }
            }
        }
        per_call.push(hints);
    }
    let mut hints = Vec::new();
    while hints.len() < max && per_call.iter().any(|call| !call.is_empty()) {
        for call in per_call.iter_mut() {
            if let Some(hint) = call.pop_front() {
                if hints.len() < max {
                    hints.push(hint);
                }
            }
        }
    }
    hints
}

impl Program<'_> {
    /// The spans a typed mutation rewrites: each constant (8 bytes), each
    /// result's index, each out buffer's length, each data buffer, and the
    /// 4-byte words of a buffer's first 64 bytes.
    pub(crate) fn typed_spans(&self) -> Vec<fuzz_engine_builtin::TypedSpan> {
        use fuzz_engine_builtin::{TypedSpan, TypedValueKind};
        let mut spans = Vec::new();
        for arg in self.calls.iter().flat_map(|call| &call.args) {
            match &arg.value {
                ArgValue::Const(_) | ArgValue::Result(_) | ArgValue::Out { .. } => {
                    spans.push(TypedSpan::new(
                        arg.span.clone(),
                        TypedValueKind::UnsignedInteger,
                    ));
                }
                ArgValue::Data { bytes, .. } if !bytes.is_empty() => {
                    spans.push(TypedSpan::new(bytes.clone(), TypedValueKind::Bytes));
                    let words = bytes.len().min(TYPED_DATA_PREFIX) / 4;
                    for word in 0..words {
                        let start = bytes.start + word * 4;
                        spans.push(TypedSpan::new(
                            start..start + 4,
                            TypedValueKind::UnsignedInteger,
                        ));
                    }
                }
                ArgValue::Data { .. } => {}
            }
        }
        spans
    }

    /// The calls as an operation sequence: the mutator swaps two, or
    /// changes one's selector.
    pub(crate) fn operations(&self) -> fuzz_engine_builtin::OperationSequenceLayout {
        use fuzz_engine_builtin::{OperationSequenceLayout, OperationStepSpan};
        let steps = self
            .calls
            .iter()
            .map(|call| {
                OperationStepSpan::new(call.span.clone(), call.span.start..call.span.start + 1)
            })
            .collect();
        OperationSequenceLayout::new(None, 0, MAX_CALLS, SYSCALLS.len() + 1, steps)
    }
}

/// Hint programs waiting to run at most.
const MAX_PENDING_HINTS: usize = 4096;
/// Hint programs remembered as queued, so none is queued twice: past it the
/// memory starts again, and a hint may run twice.
const MAX_HINTED: usize = 1 << 20;
/// Corpus programs whose comparisons are kept for their mutations.
const MAX_CMPLOGS: usize = 256;

/// 128 bits of a program's SHA-256: what remembers it.
fn program_digest(program: &[u8]) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(program);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// The hint programs the comparisons suggested, to run before the next
/// mutation: each queued once (by digest, not by its bytes), at most
/// `max_pending` waiting.
#[derive(Debug)]
pub(crate) struct HintQueue {
    pending: std::collections::VecDeque<Vec<u8>>,
    queued: std::collections::HashSet<[u8; 16]>,
    max_pending: usize,
    max_queued: usize,
}

impl HintQueue {
    pub(crate) fn new(max_pending: usize, max_queued: usize) -> Self {
        Self {
            pending: Default::default(),
            queued: Default::default(),
            max_pending,
            max_queued: max_queued.max(1),
        }
    }

    /// Queue `hint` unless it was queued before or the queue is full:
    /// whether it was.
    pub(crate) fn offer(&mut self, hint: Vec<u8>) -> bool {
        if self.pending.len() >= self.max_pending {
            return false;
        }
        if self.queued.len() >= self.max_queued {
            self.queued.clear();
        }
        if !self.queued.insert(program_digest(&hint)) {
            return false;
        }
        self.pending.push_back(hint);
        true
    }

    pub(crate) fn pop(&mut self) -> Option<Vec<u8>> {
        self.pending.pop_front()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn pending(&self) -> usize {
        self.pending.len()
    }

    #[cfg(test)]
    pub(crate) fn remembered(&self) -> usize {
        self.queued.len()
    }
}

/// The comparisons of at most `capacity` corpus programs, by digest: the
/// one used least recently goes when another comes.
#[derive(Debug)]
pub(crate) struct CmpLogCache {
    logs: std::collections::HashMap<[u8; 16], (u64, std::sync::Arc<cmplog::CmpLog>)>,
    clock: u64,
    capacity: usize,
}

impl CmpLogCache {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            logs: Default::default(),
            clock: 0,
            capacity: capacity.max(1),
        }
    }

    pub(crate) fn insert(&mut self, program: &[u8], log: cmplog::CmpLog) {
        self.clock += 1;
        let key = program_digest(program);
        if !self.logs.contains_key(&key) && self.logs.len() >= self.capacity {
            if let Some(oldest) = self
                .logs
                .iter()
                .min_by_key(|(_, (used, _))| *used)
                .map(|(key, _)| *key)
            {
                self.logs.remove(&oldest);
            }
        }
        self.logs
            .insert(key, (self.clock, std::sync::Arc::new(log)));
    }

    /// `program`'s comparisons, which are then the most recently used.
    pub(crate) fn get(&mut self, program: &[u8]) -> Option<std::sync::Arc<cmplog::CmpLog>> {
        self.clock += 1;
        let clock = self.clock;
        self.logs
            .get_mut(&program_digest(program))
            .map(|(used, log)| {
                *used = clock;
                log.clone()
            })
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.logs.len()
    }
}

// ── The campaign ─────────────────────────────────────────────────────────

/// The seed programs of a campaign, and the tokens its mutations splice in
/// (command numbers, the device's path).
#[derive(Debug, Clone, Default)]
pub(crate) struct SeedSet {
    pub programs: Vec<Vec<u8>>,
    pub dictionary: Vec<Vec<u8>>,
    /// What the seeds were made from, for the summary.
    pub origin: Vec<String>,
}

/// A `bhf kernel fuzz` campaign.
#[derive(Debug, Clone)]
pub(crate) struct FuzzConfig {
    /// The work directory, whose `results/` gets the findings.
    pub work_dir: PathBuf,
    /// `<work>/kernel`: the guest's files, the corpus, the crashes, the
    /// summary.
    pub dir: PathBuf,
    /// How the guest boots, as a finding records it for `bhf kernel
    /// replay`.
    pub guest_record: serde_json::Value,
    /// Stop once this many findings were written or updated.
    pub stop_after_findings: Option<usize>,
    pub setup: GuestSetup,
    /// Executions at most.
    pub iterations: usize,
    pub time_budget: Option<Duration>,
    /// How long one program may run.
    pub timeout: Duration,
    pub rng_seed: u64,
    pub max_len: usize,
}

/// Coverage of the campaign at one point.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub(crate) struct CoverageCount {
    /// Distinct edges (pairs of consecutive PCs).
    pub edges: usize,
    /// Distinct PCs and hit-count buckets.
    pub blocks: usize,
}

impl CoverageCount {
    fn of(coverage: &fuzz_engine_builtin::CoverageProxy) -> Self {
        let snapshot = coverage.snapshot();
        Self {
            edges: snapshot.edge_bits,
            blocks: snapshot.breadcrumb_bits,
        }
    }
}

/// What a campaign did, as `<work>/kernel/fuzz.json` records it.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct FuzzSummary {
    pub schema: &'static str,
    pub kernel: String,
    pub release: String,
    pub machine: String,
    pub accel: &'static str,
    pub kcov: bool,
    /// The executor's setup notes in its HELLO: each module loaded or why
    /// not, KCOV.
    pub notes: Vec<String>,
    pub seeds: usize,
    pub seed_origin: Vec<String>,
    pub executions: usize,
    /// KCOV recorded comparisons: each corpus program ran once more for
    /// them, its mutations splice their operands in, and the programs
    /// their operands suggest (hints) ran.
    pub comparisons: bool,
    pub comparison_runs: usize,
    pub hint_runs: usize,
    /// Programs that reached new coverage and joined the corpus.
    pub corpus_new: usize,
    pub corpus: usize,
    /// Coverage once every seed had run, and at the end.
    pub coverage_after_seeds: CoverageCount,
    pub coverage: CoverageCount,
    /// Runs whose console held a kernel report.
    pub reports: usize,
    /// The findings those reports became (or were counted on), under
    /// `<work>/results/findings/`.
    pub findings: Vec<String>,
    /// Runs of a new report's program alone, in a freshly booted guest.
    pub confirm_runs: usize,
    /// Runs the guest did not survive with no kernel report: it stopped, or
    /// did not answer.
    pub crashes: usize,
    /// Where each such run's program and console are, under `<work>`.
    pub crash_dirs: Vec<String>,
    pub boots: usize,
    /// Why the campaign stopped before its budget.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub halted: Option<String>,
    pub elapsed_secs: f64,
    pub executions_per_sec: f64,
}

/// The schema of `fuzz.json`.
pub(crate) const FUZZ_SUMMARY_SCHEMA: &str = "bhf.kernel-fuzz.v1";

/// A run the guest did not survive, saved for its triage.
#[cfg(unix)]
fn save_crash(dir: &Path, index: usize, program: &[u8], run: &GuestRun) -> anyhow::Result<PathBuf> {
    use anyhow::Context;
    let crash = dir.join("crashes").join(format!("{index:04}"));
    std::fs::create_dir_all(&crash).with_context(|| format!("create {}", crash.display()))?;
    let reason = match &run.end {
        RunEnd::Replied(reply) => format!("replied: {}", reply.status.describe()),
        RunEnd::Stopped(reason) => format!("the guest stopped: {reason}"),
        RunEnd::NoReply => "no reply: the guest hung".to_owned(),
    };
    for (name, bytes) in [
        ("program.bin", program.to_vec()),
        ("program.txt", decode(program).text().into_bytes()),
        ("console.log", run.console.clone().into_bytes()),
        ("reason.txt", format!("{reason}\n").into_bytes()),
    ] {
        std::fs::write(crash.join(name), bytes)
            .with_context(|| format!("write {}", crash.join(name).display()))?;
    }
    Ok(crash)
}

/// The campaign's state between runs.
#[cfg(unix)]
struct Campaign<'a> {
    config: &'a FuzzConfig,
    guest: Option<Guest>,
    hello: Option<Hello>,
    accel: Accel,
    coverage: fuzz_engine_builtin::CoverageProxy,
    scheduler: fuzz_engine_builtin::PowerScheduler,
    executions: usize,
    corpus_new: usize,
    crashes: usize,
    crash_dirs: Vec<String>,
    boots: usize,
    /// The comparisons of the corpus programs scheduled last.
    cmplogs: CmpLogCache,
    comparison_runs: usize,
    hints: HintQueue,
    hint_runs: usize,
    reports: usize,
    findings: Vec<String>,
    confirm_runs: usize,
}

#[cfg(unix)]
impl Campaign<'_> {
    /// Whether the campaign has run its budget.
    fn done(&self, start: std::time::Instant) -> bool {
        self.executions >= self.config.iterations
            || self
                .config
                .time_budget
                .is_some_and(|budget| start.elapsed() >= budget)
            || self
                .config
                .stop_after_findings
                .is_some_and(|count| self.findings.len() >= count)
    }

    /// Look for a kernel report on `run`'s console: when there is one,
    /// write it as a finding with `program`, its first time confirmed by a
    /// run of the program alone in a freshly booted guest, and reset the
    /// guest. Whether there was one.
    ///
    /// The finding is written before that run: when its guest does not
    /// boot, the finding stays unconfirmed, saying why, and the next run
    /// boots again (the campaign stops when that boot fails too).
    fn reported(&mut self, program: &[u8], run: &GuestRun) -> anyhow::Result<bool> {
        use results::import_syzkaller as kernel;
        let Some(report) = kernel::console_report(&run.console) else {
            return Ok(false);
        };
        // The kernel's state is suspect once it reported, and with
        // panic_on_warn it is down.
        self.guest = None;
        self.reports += 1;
        let decoded = decode(program);
        let crash = kernel::GuestCrash {
            report: &report,
            console: &run.console,
            program,
            program_text: &decoded.text(),
            decoded: &decoded.json(),
            c_repro: &decoded.c_source(&report.title),
            guest: &self.config.guest_record,
            reproduced: false,
            unconfirmed: Some(kernel::CONFIRMING),
            release: self.hello.as_ref().map(|hello| hello.release.as_str()),
        };
        // A title found before is counted on its finding.
        let found = kernel::record_guest_crash(&self.config.work_dir, &crash)?;
        if !found.updated {
            let (reproduced, unconfirmed) = match self.reproduces(program, &report.title) {
                Ok(reproduced) => (reproduced, None),
                Err(error) => {
                    let error = format!("{error:#}");
                    let first = error.lines().next().unwrap_or_default();
                    (
                        false,
                        Some(format!("its confirming run could not be made: {first}")),
                    )
                }
            };
            kernel::confirm_guest_crash(
                &self.config.work_dir,
                &found.id,
                reproduced,
                unconfirmed.as_deref(),
            )?;
        }
        if !self.findings.contains(&found.id) {
            self.findings.push(found.id);
        }
        Ok(true)
    }

    /// Whether `program`, run alone in a freshly booted guest, makes the
    /// kernel report `title` again.
    fn reproduces(&mut self, program: &[u8], title: &str) -> anyhow::Result<bool> {
        self.guest = None;
        let timeout = self.config.timeout;
        let run = self.guest()?.run(program, timeout);
        self.executions += 1;
        self.confirm_runs += 1;
        let again = results::import_syzkaller::console_report(&run.console);
        if again.is_some() || !matches!(run.end, RunEnd::Replied(_)) {
            self.guest = None;
        }
        Ok(again.is_some_and(|report| report.title == title))
    }

    /// The guest, booted when there is none (at the start, and after a run
    /// it did not survive).
    fn guest(&mut self) -> anyhow::Result<&mut Guest> {
        if self.guest.is_none() {
            let log = self.config.dir.join("guest").join("console.log");
            let guest = Guest::boot(&self.config.setup, Some(&log))?;
            self.boots += 1;
            self.accel = guest.accel();
            self.hello.get_or_insert_with(|| guest.hello().clone());
            self.guest = Some(guest);
        }
        Ok(self.guest.as_mut().expect("booted above"))
    }

    /// Run `program`; fold its coverage in, and keep it when `seed` or when
    /// it reached new coverage.
    fn run(&mut self, program: &[u8], seed: bool) -> anyhow::Result<()> {
        let timeout = self.config.timeout;
        let run = self.guest()?.run(program, timeout);
        self.executions += 1;
        if self.reported(program, &run)? {
            return Ok(());
        }
        let RunEnd::Replied(reply) = &run.end else {
            return self.crashed(program, &run);
        };
        let feedback = fold_coverage(&mut self.coverage, &coverage_ids(reply));
        let new = feedback.new_bitmap_bits() > 0;
        if !(seed || new) {
            return Ok(());
        }
        self.scheduler
            .insert_with_feedback(program, feedback.to_schedule_feedback());
        if !seed {
            self.corpus_new += 1;
        }
        let corpus = self.config.dir.join("corpus");
        std::fs::create_dir_all(&corpus)?;
        std::fs::write(
            corpus.join(format!("{}.bin", &sha256_hex(program)[..16])),
            program,
        )?;
        if self.hello.as_ref().is_some_and(|hello| hello.comparisons)
            && self.executions < self.config.iterations
        {
            self.learn_comparisons(program)?;
        }
        Ok(())
    }

    /// Run a corpus program again for the comparisons its calls made.
    fn learn_comparisons(&mut self, program: &[u8]) -> anyhow::Result<()> {
        let timeout = self.config.timeout;
        let run = self
            .guest()?
            .run_collecting(program, Collect::Comparisons, timeout);
        self.executions += 1;
        self.comparison_runs += 1;
        if self.reported(program, &run)? {
            return Ok(());
        }
        let RunEnd::Replied(reply) = &run.end else {
            return self.crashed(program, &run);
        };
        for hint in hint_programs(program, reply, MAX_HINTS) {
            self.hints.offer(hint);
        }
        let log = comparison_log(reply, program);
        if !log.entries.is_empty() {
            self.cmplogs.insert(program, log);
        }
        Ok(())
    }

    /// A run the guest did not survive: save it, and boot a fresh guest for
    /// the next.
    fn crashed(&mut self, program: &[u8], run: &GuestRun) -> anyhow::Result<()> {
        let dir = save_crash(&self.config.dir, self.crashes, program, run)?;
        self.crashes += 1;
        self.crash_dirs.push(
            dir.strip_prefix(self.config.dir.parent().unwrap_or(&self.config.dir))
                .unwrap_or(&dir)
                .display()
                .to_string(),
        );
        self.guest = None;
        Ok(())
    }
}

/// Run a campaign: boot the guest, run every seed `seeds` gives for the
/// guest's HELLO, then mutate the corpus, coverage-guided, until the
/// iteration cap, the time budget or the findings wanted. A kernel report
/// on the console becomes a finding with its program, and the next run
/// boots the guest again; a run the guest does not survive without one is
/// saved under `<dir>/crashes/`.
#[cfg(unix)]
pub(crate) fn fuzz(
    config: &FuzzConfig,
    seeds: &dyn Fn(&Hello) -> anyhow::Result<SeedSet>,
) -> anyhow::Result<FuzzSummary> {
    use fuzz_engine_builtin::{
        Dictionary, MutationInput, MutationRng, MutatorConfig, MutatorSuite,
    };
    use std::time::Instant;

    let start = Instant::now();
    let mut campaign = Campaign {
        config,
        guest: None,
        hello: None,
        accel: config.setup.accel,
        coverage: Default::default(),
        scheduler: Default::default(),
        executions: 0,
        corpus_new: 0,
        crashes: 0,
        crash_dirs: Vec::new(),
        boots: 0,
        cmplogs: CmpLogCache::new(MAX_CMPLOGS),
        comparison_runs: 0,
        hints: HintQueue::new(MAX_PENDING_HINTS, MAX_HINTED),
        hint_runs: 0,
        reports: 0,
        findings: Vec::new(),
        confirm_runs: 0,
    };
    campaign.guest()?;
    let hello = campaign.hello.clone().expect("the first boot said HELLO");
    let seed_set = seeds(&hello)?;
    anyhow::ensure!(
        !seed_set.programs.is_empty(),
        "no seed programs: give --seeds, --source or --device"
    );
    // A module under test the guest did not load leaves nothing of it to
    // reach: no program runs.
    let unloaded = hello.unloaded_modules();
    let mut halted = (!unloaded.is_empty()).then(|| {
        format!(
            "the guest did not load every --module, so no program could reach its driver: {}",
            unloaded.join("; ")
        )
    });
    for program in &seed_set.programs {
        if halted.is_some() {
            break;
        }
        if campaign.done(start) {
            break;
        }
        if let Err(error) = campaign.run(program, true) {
            halted = Some(format!("{error:#}"));
            break;
        }
    }
    let coverage_after_seeds = CoverageCount::of(&campaign.coverage);

    let mutator = MutatorSuite::new(MutatorConfig {
        max_len: config.max_len.clamp(1, MAX_PROGRAM),
        structured_records: false,
        structured_json: false,
        structured_xml: false,
        structured_key_value: false,
        structured_url_encoded: false,
        structured_multipart: false,
        structured_csv: false,
        structured_http: false,
        structured_ini: false,
        structured_toml: false,
        structured_yaml: false,
        structured_chunked: false,
        structured_recursive: false,
    });
    let mut rng = MutationRng::new(config.rng_seed);
    let dictionary = Dictionary::from_tokens(seed_set.dictionary.iter().cloned());
    'campaign: while halted.is_none() && !campaign.done(start) {
        // The hints the corpus's comparisons suggest run first.
        if let Some(hint) = campaign.hints.pop() {
            campaign.hint_runs += 1;
            if let Err(error) = campaign.run(&hint, false) {
                halted = Some(format!("{error:#}"));
            }
            continue;
        }
        let Some(scheduled) = campaign.scheduler.select_next() else {
            halted = Some("every seed crashed the guest: nothing to mutate".to_owned());
            break;
        };
        for _ in 0..scheduled.energy.max(1) {
            if campaign.done(start) {
                break 'campaign;
            }
            let program = decode(&scheduled.bytes);
            let spans = program.typed_spans();
            let operations = program.operations();
            let cmplog = campaign.cmplogs.get(&scheduled.bytes);
            let mut input = MutationInput::new(&scheduled.bytes, &dictionary)
                .with_typed_spans(&spans)
                .with_operation_sequence(&operations);
            if let Some(log) = cmplog.as_deref() {
                input = input.with_cmplog(log);
            }
            let mutated = mutator
                .mutate(&input, &mut rng)
                .map(|result| result.bytes)
                .unwrap_or_else(|| scheduled.bytes.clone());
            if let Err(error) = campaign.run(&mutated, false) {
                halted = Some(format!("{error:#}"));
                break 'campaign;
            }
            if !campaign.hints.is_empty() {
                break;
            }
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    let summary = FuzzSummary {
        schema: FUZZ_SUMMARY_SCHEMA,
        kernel: config.setup.kernel.display().to_string(),
        release: hello.release.clone(),
        machine: hello.machine.clone(),
        accel: campaign.accel.as_str(),
        kcov: hello.kcov,
        notes: hello.note_lines(),
        comparisons: hello.comparisons,
        comparison_runs: campaign.comparison_runs,
        hint_runs: campaign.hint_runs,
        seeds: seed_set.programs.len(),
        seed_origin: seed_set.origin.clone(),
        executions: campaign.executions,
        corpus_new: campaign.corpus_new,
        corpus: campaign.scheduler.len(),
        coverage_after_seeds,
        coverage: CoverageCount::of(&campaign.coverage),
        reports: campaign.reports,
        findings: campaign.findings.clone(),
        confirm_runs: campaign.confirm_runs,
        crashes: campaign.crashes,
        crash_dirs: campaign.crash_dirs.clone(),
        boots: campaign.boots,
        halted,
        elapsed_secs: elapsed,
        executions_per_sec: if elapsed > 0.0 {
            campaign.executions as f64 / elapsed
        } else {
            0.0
        },
    };
    let path = config.dir.join("fuzz.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&summary)?)?;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `openat(AT_FDCWD, path, flags, 0)`, then each `(call, args)`.
    fn open_then(path: &[u8], flags: u64) -> ProgramBuilder {
        let mut program = ProgramBuilder::default();
        program
            .call(
                "openat",
                &[
                    SeedArg::Const(-100i64 as u64),
                    SeedArg::Data(path),
                    SeedArg::Const(flags),
                    SeedArg::Const(0),
                ],
            )
            .unwrap();
        program
    }

    #[test]
    fn programs_decode_as_the_format_says() {
        let mut builder = open_then(b"/dev/widget\0", 2);
        builder
            .call(
                "ioctl",
                &[
                    SeedArg::Result(0),
                    SeedArg::Const(0xc028_5703),
                    SeedArg::Data(&[7u8; 40]),
                ],
            )
            .unwrap();
        builder
            .call("read", &[SeedArg::Result(0), SeedArg::Out(16)])
            .unwrap();
        builder.raw(500, &[SeedArg::Const(1)]).unwrap();
        let bytes = builder.finish();
        let program = decode(&bytes);
        assert_eq!(program.calls.len(), 4);
        assert_eq!(program.calls[0].sys, CallSys::Named(0));
        assert_eq!(
            program.calls[0].args[0].value,
            ArgValue::Const(-100i64 as u64)
        );
        // Buffers are placed 8-aligned from the start of the data area.
        assert_eq!(
            program.calls[0].args[1].value,
            ArgValue::Data {
                offset: Some(0),
                bytes: 14..26
            }
        );
        assert_eq!(&bytes[14..26], b"/dev/widget\0");
        assert_eq!(program.calls[1].args[0].value, ArgValue::Result(Some(0)));
        assert!(matches!(
            program.calls[1].args[2].value,
            ArgValue::Data { offset: Some(16), ref bytes } if bytes.len() == 40
        ));
        assert_eq!(
            program.calls[2].args[1].value,
            ArgValue::Out {
                offset: Some(56),
                len: 16
            }
        );
        assert_eq!(program.calls[3].sys, CallSys::Raw(500));
        assert_eq!(program.data_used, 72);
        assert_eq!(
            program.text(),
            "r0 = openat(0xffffffffffffff9c, &(0x20000000)=\"/dev/widget\\x00\", 0x2, 0x0)\n\
             r1 = ioctl(r0, 0xc0285703, &(0x20000010)=x\"07070707070707070707070707070707070707070707070707070707070707070707070707070707\")\n\
             r2 = read(r0, &(0x20000038)=out[16])\n\
             r3 = syscall_500(0x1)\n"
        );

        // A call the input ends inside is dropped, with the data it placed.
        let cut = decode(&bytes[..bytes.len() - 3]);
        assert_eq!(cut.calls.len(), 3);
        assert_eq!(cut.data_used, 72);
        let cut = decode(&bytes[..44]);
        assert_eq!(cut.calls.len(), 1);
        assert_eq!(cut.data_used, 12);
        assert!(decode(&bytes[..43]).calls.is_empty());
    }

    #[test]
    fn every_byte_string_decodes_with_selectors_taken_modulo() {
        // Selector 13 is openat again, 7 arguments are none, tag 5 is data,
        // and a result in the first call is -1.
        let bytes = [13u8, 7, 26, 9, 5, 2, 0, b'a', b'b', 6, 9];
        let program = decode(&bytes);
        assert_eq!(program.calls.len(), 2);
        assert_eq!(program.calls[0].sys, CallSys::Named(0));
        assert!(program.calls[0].args.is_empty());
        assert_eq!(program.calls[1].sys, CallSys::Named(0));
        assert_eq!(program.calls[1].args.len(), 2);
        assert_eq!(
            program.calls[1].args[0].value,
            ArgValue::Data {
                offset: Some(0),
                bytes: 7..9
            }
        );
        // The second call's result names call 9 % 1 = 0.
        assert_eq!(program.calls[1].args[1].value, ArgValue::Result(Some(0)));
        assert_eq!(
            decode(&[2, 1, 2, 4]).calls[0].args[0].value,
            ArgValue::Result(None)
        );
        // A data length past the input takes what is left; past 4096 is cut.
        let program = decode(&[3, 1, 1, 0xff, 0xff, 1, 2, 3]);
        assert_eq!(
            program.calls[0].args[0].value,
            ArgValue::Data {
                offset: Some(0),
                bytes: 5..8
            }
        );
        let program = decode(&[3, 1, 3, 0xff, 0xff]);
        assert_eq!(
            program.calls[0].args[0].value,
            ArgValue::Out {
                offset: Some(0),
                len: 4096
            }
        );
        for len in 0..64 {
            let noise: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            assert!(decode(&noise).calls.len() <= MAX_CALLS);
        }
    }

    #[test]
    fn a_buffer_that_does_not_fit_the_data_area_is_null() {
        let mut builder = ProgramBuilder::default();
        for _ in 0..42 {
            let args = [SeedArg::Out(MAX_ARG_BYTES as u16); MAX_ARGS];
            builder.call("read", &args).unwrap();
        }
        builder
            .call(
                "write",
                &[
                    SeedArg::Out(4096),
                    SeedArg::Out(4096),
                    SeedArg::Out(4096),
                    SeedArg::Out(4096),
                    SeedArg::Data(b"late"),
                ],
            )
            .unwrap();
        let bytes = builder.finish();
        assert!(bytes.len() < MAX_PROGRAM);
        let program = decode(&bytes);
        assert_eq!(program.calls.len(), 43);
        let offsets: Vec<Option<u64>> = program
            .calls
            .iter()
            .flat_map(|call| &call.args)
            .map(|arg| match arg.value {
                ArgValue::Out { offset, .. } | ArgValue::Data { offset, .. } => offset,
                _ => unreachable!(),
            })
            .collect();
        // 256 buffers of 4 KiB fill the 1 MiB area exactly.
        assert_eq!(offsets.len(), 257);
        assert_eq!(offsets[255], Some(DATA_SIZE - 4096));
        assert!(offsets[256].is_none(), "{:?}", &offsets[250..]);
        assert_eq!(program.data_used, DATA_SIZE);
        assert!(program.text().contains("NULL /* 4 bytes did not fit */"));
        // More calls than a program holds are left out.
        let mut many = ProgramBuilder::default();
        for _ in 0..MAX_CALLS {
            many.call("dup", &[SeedArg::Const(0)]).unwrap();
        }
        assert!(many.call("dup", &[SeedArg::Const(0)]).is_err());
        let mut bytes = many.finish();
        bytes.extend_from_slice(&[11, 0]);
        assert_eq!(decode(&bytes).calls.len(), MAX_CALLS);
    }

    /// The executor, built for this host (not statically: the tests do not
    /// need it to run as /init).
    #[cfg(target_os = "linux")]
    fn host_executor(dir: &Path) -> PathBuf {
        let source = dir.join("kernel_executor.c");
        std::fs::write(&source, EXECUTOR_SOURCE).unwrap();
        let binary = dir.join("executor");
        let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_owned());
        let output = std::process::Command::new(&cc)
            .args(["-O1", "-Wall", "-Wextra", "-Werror", "-o"])
            .arg(&binary)
            .arg(&source)
            .output()
            .unwrap_or_else(|error| panic!("run {cc}: {error}"));
        assert!(
            output.status.success(),
            "{cc} kernel_executor.c:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        binary
    }

    #[cfg(target_os = "linux")]
    fn executor_dump(executor: &Path, input: &[u8]) -> String {
        use std::process::{Command, Stdio};
        let mut child = Command::new(executor)
            .arg("--decode")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        // Written while the dump is read: either can fill its pipe.
        let mut stdin = child.stdin.take().unwrap();
        let input = input.to_vec();
        let writer = std::thread::spawn(move || stdin.write_all(&input));
        let output = child.wait_with_output().unwrap();
        writer.join().unwrap().unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap()
    }

    /// The executor's decoder, run on programs bhf writes and on noise,
    /// decodes each as `decode` does.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_executor_decodes_programs_as_bhf_does() {
        let dir = crate::test_support::TestDir::new("kernel-executor-decode");
        let executor = host_executor(&dir);

        let mut builder = open_then(b"/dev/widget\0", 2);
        builder
            .call(
                "ioctl",
                &[
                    SeedArg::Result(0),
                    SeedArg::Const(0x4004_5704),
                    SeedArg::Data(&[1, 0, 0, 0]),
                ],
            )
            .unwrap();
        builder
            .raw(16, &[SeedArg::Result(1), SeedArg::Out(8)])
            .unwrap();
        let bytes = builder.finish();
        assert_eq!(
            executor_dump(&executor, &bytes),
            "calls 3 data 0x20\n\
             call 0 openat nargs 4\n \
             arg 0 const 0xffffffffffffff9c\n \
             arg 1 data 0x0 len 12 2f6465762f77696467657400\n \
             arg 2 const 0x2\n \
             arg 3 const 0x0\n\
             call 1 ioctl nargs 3\n \
             arg 0 result 0\n \
             arg 1 const 0x40045704\n \
             arg 2 data 0x10 len 4 01000000\n\
             call 2 syscall nr=16 nargs 2\n \
             arg 0 result 1\n \
             arg 1 out 0x18 len 8\n"
        );
        assert_eq!(executor_dump(&executor, &bytes), decode(&bytes).dump());

        // Noise of every length, and programs cut at every byte.
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut inputs: Vec<Vec<u8>> = (0..bytes.len()).map(|n| bytes[..n].to_vec()).collect();
        for round in 0..150 {
            let len = (next() % 160) as usize + round % 3;
            // Small selectors and tags, so calls, buffers and results occur.
            inputs.push((0..len).map(|_| (next() % 17) as u8).collect());
            inputs.push((0..len).map(|_| next() as u8).collect());
        }
        // A data area filled, and buffers past it.
        let mut full = ProgramBuilder::default();
        let page = [0x5au8; 1000];
        for _ in 0..50 {
            full.call(
                "write",
                &[
                    SeedArg::Out(4000),
                    SeedArg::Data(&page),
                    SeedArg::Out(4096),
                    SeedArg::Out(4096),
                    SeedArg::Out(4096),
                    SeedArg::Out(4096),
                ],
            )
            .unwrap();
        }
        let full = full.finish();
        assert!(full.len() <= MAX_PROGRAM && decode(&full).data_used > DATA_SIZE - 4096);
        inputs.push(full);
        for input in &inputs {
            assert_eq!(
                executor_dump(&executor, input),
                decode(input).dump(),
                "input {input:02x?}"
            );
        }
    }

    // ── The protocol, against a mock executor ──────────────────────────

    fn hello(kcov: bool) -> Hello {
        Hello {
            protocol: PROTOCOL,
            kcov,
            init: true,
            comparisons: kcov,
            cover_entries: 1 << 18,
            max_program: MAX_PROGRAM as u32,
            max_calls: MAX_CALLS as u32,
            data_size: DATA_SIZE as u32,
            data_addr: DATA_ADDR,
            machine: "x86_64".to_owned(),
            release: "6.12.118".to_owned(),
            notes: "module 00-widget.ko: loaded\nready (kcov on)\n".to_owned(),
        }
    }

    /// An EXEC the mock executor read: `(id, flags, timeout_ms)`.
    type Seen = (u64, u32, u32);

    /// What the mock executor does with an EXEC.
    enum Answer {
        Send(Vec<u8>),
        /// Send these bytes and close its end.
        SendAndClose(Vec<u8>),
        Stop,
    }

    /// A mock executor on the far end of a socket pair: it says `hello`,
    /// then answers each EXEC with `answer(id, program)`.
    #[cfg(unix)]
    fn mock_executor(
        hello: Vec<u8>,
        mut answer: impl FnMut(u64, Vec<u8>) -> Answer + Send + 'static,
    ) -> (
        std::os::unix::net::UnixStream,
        std::thread::JoinHandle<Vec<Seen>>,
    ) {
        let (host, mut guest) = std::os::unix::net::UnixStream::pair().unwrap();
        host.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let handle = std::thread::spawn(move || {
            let mut seen = Vec::new();
            guest.write_all(&hello).unwrap();
            while let Ok((kind, payload)) = read_message(&mut guest) {
                assert_eq!(kind, MSG_EXEC);
                let (id, flags, timeout, program) = parse_exec(&payload).unwrap();
                seen.push((id, flags, timeout));
                match answer(id, program) {
                    Answer::Send(bytes) => guest.write_all(&bytes).unwrap(),
                    Answer::SendAndClose(bytes) => {
                        guest.write_all(&bytes).unwrap();
                        break;
                    }
                    Answer::Stop => break,
                }
            }
            seen
        });
        (host, handle)
    }

    fn message(kind: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_message(&mut out, kind, payload).unwrap();
        out
    }

    fn reply_to(id: u64, pcs: &[&[u64]]) -> ExecReply {
        ExecReply {
            id,
            status: ExecStatus::Ok,
            decoded: pcs.len() as u32,
            kcov: true,
            truncated: false,
            calls: pcs
                .iter()
                .enumerate()
                .map(|(index, pcs)| CallResult {
                    index: index as u32,
                    errno: if index == 1 { 22 } else { 0 },
                    ret: if index == 1 { -1 } else { 4 },
                    pcs: pcs.to_vec(),
                    comparisons: Vec::new(),
                    truncated: false,
                })
                .collect(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_client_runs_programs_against_a_mock_executor() {
        let program = open_then(b"/dev/null\0", 1).finish();
        let expected = program.clone();
        let (host, mock) = mock_executor(
            message(MSG_HELLO, &encode_hello(&hello(true))),
            move |id, got| {
                assert_eq!(got, expected);
                let pcs: &[&[u64]] = &[
                    &[
                        0xffff_ffff_8100_0010,
                        0xffff_ffff_8100_0020,
                        0xffff_ffff_8100_0010,
                        0xffff_ffff_8100_0020,
                    ],
                    &[0xffff_ffff_a000_0040],
                ];
                Answer::Send(message(MSG_REPLY, &encode_reply(&reply_to(id, pcs))))
            },
        );
        let mut client = ExecutorClient::handshake(host).unwrap();
        assert_eq!(client.hello(), &hello(true));
        for expected_id in [1, 2] {
            let reply = client
                .execute(&program, Collect::Pcs, Duration::from_millis(2500))
                .unwrap();
            assert_eq!(reply.id, expected_id);
            assert_eq!(reply.status, ExecStatus::Ok);
            assert_eq!(reply.calls.len(), 2);
            assert_eq!(reply.calls[0].pcs.len(), 4);
            assert_eq!((reply.calls[1].ret, reply.calls[1].errno), (-1, 22));
            // a->b, b->a: the repeated a->b is one edge.
            assert_eq!(reply.edges(), 2);
        }
        drop(client);
        assert_eq!(mock.join().unwrap(), vec![(1, 1, 2500), (2, 1, 2500)]);
    }

    #[cfg(unix)]
    #[test]
    fn a_reply_to_another_program_is_refused() {
        let (host, _mock) =
            mock_executor(message(MSG_HELLO, &encode_hello(&hello(true))), |id, _| {
                Answer::Send(message(MSG_REPLY, &encode_reply(&reply_to(id + 7, &[]))))
            });
        let mut client = ExecutorClient::handshake(host).unwrap();
        let error = client
            .execute(&[], Collect::Pcs, Duration::from_secs(1))
            .unwrap_err();
        assert!(
            matches!(
                error,
                ProtocolError::Id {
                    expected: 1,
                    got: 8
                }
            ),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_handshake_refuses_what_is_not_an_executors_hello() {
        let handshake = |bytes: Vec<u8>| {
            let (host, _mock) = mock_executor(bytes, |_, _| Answer::Stop);
            ExecutorClient::handshake(host).err().unwrap()
        };
        let mut wrong = message(MSG_HELLO, &encode_hello(&hello(false)));
        wrong[0] ^= 0xff;
        assert!(matches!(handshake(wrong), ProtocolError::Magic(_)));
        let mut newer = hello(false);
        newer.protocol = 2;
        assert!(matches!(
            handshake(message(MSG_HELLO, &encode_hello(&newer))),
            ProtocolError::Version(2)
        ));
        assert!(matches!(
            handshake(message(MSG_REPLY, &[])),
            ProtocolError::Unexpected {
                expected: "HELLO",
                got: MSG_REPLY
            }
        ));
        // A length past the bound is refused from the header, unread.
        let mut huge = Vec::new();
        huge.extend_from_slice(&MAGIC.to_le_bytes());
        huge.extend_from_slice(&MSG_HELLO.to_le_bytes());
        huge.extend_from_slice(&(MAX_MESSAGE + 1).to_le_bytes());
        assert!(matches!(handshake(huge), ProtocolError::TooLarge(_)));
        // A string longer than its message.
        let mut cut = encode_hello(&hello(false));
        cut.truncate(cut.len() - 4);
        assert!(matches!(
            handshake(message(MSG_HELLO, &cut)),
            ProtocolError::Malformed { what: "HELLO", .. }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_reply_cut_short_or_never_sent_is_an_error() {
        // The PCs a reply announces must be in it.
        let (host, _mock) =
            mock_executor(message(MSG_HELLO, &encode_hello(&hello(true))), |id, _| {
                let mut payload = encode_reply(&reply_to(id, &[&[1, 2, 3]]));
                payload.truncate(payload.len() - 8);
                Answer::Send(message(MSG_REPLY, &payload))
            });
        let mut client = ExecutorClient::handshake(host).unwrap();
        assert!(matches!(
            client.execute(&[], Collect::Pcs, Duration::from_secs(1)),
            Err(ProtocolError::Malformed { what: "REPLY", .. })
        ));

        // The executor goes away mid-message.
        let (host, _mock) =
            mock_executor(message(MSG_HELLO, &encode_hello(&hello(true))), |id, _| {
                let whole = message(MSG_REPLY, &encode_reply(&reply_to(id, &[&[1, 2, 3]])));
                Answer::SendAndClose(whole[..whole.len() - 5].to_vec())
            });
        let mut client = ExecutorClient::handshake(host).unwrap();
        assert!(matches!(
            client.execute(&[], Collect::Pcs, Duration::from_secs(1)),
            Err(ProtocolError::Closed)
        ));

        // A silent executor: the channel's read timeout ends the wait.
        let (host, mock) =
            mock_executor(message(MSG_HELLO, &encode_hello(&hello(true))), |_, _| {
                std::thread::sleep(Duration::from_millis(600));
                Answer::Stop
            });
        let mut client = ExecutorClient::handshake(host).unwrap();
        client
            .channel_mut()
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        assert!(matches!(
            client.execute(&[], Collect::Pcs, Duration::from_secs(1)),
            Err(ProtocolError::Timeout)
        ));
        drop(client);
        mock.join().unwrap();

        // A program larger than the executor takes is not sent.
        let (host, mock) =
            mock_executor(message(MSG_HELLO, &encode_hello(&hello(true))), |_, _| {
                Answer::Stop
            });
        let mut client = ExecutorClient::handshake(host).unwrap();
        assert!(matches!(
            client.execute(
                &vec![0u8; MAX_PROGRAM + 1],
                Collect::Pcs,
                Duration::from_secs(1)
            ),
            Err(ProtocolError::Malformed {
                what: "program",
                ..
            })
        ));
        drop(client);
        assert!(mock.join().unwrap().is_empty());
    }

    /// The real executor, serving over pipes on this host (`--channel
    /// stdio`: no KCOV, no setup): a program's calls run, a denied raw call
    /// is not made, and a run that outlasts its timeout or ends the process
    /// is reported as such.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn the_executor_serves_the_protocol_over_stdio() {
        use std::process::{Command, Stdio};
        struct Pipes {
            out: std::process::ChildStdout,
            into: std::process::ChildStdin,
        }
        impl Read for Pipes {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.out.read(buf)
            }
        }
        impl Write for Pipes {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.into.write(buf)
            }
            fn flush(&mut self) -> io::Result<()> {
                self.into.flush()
            }
        }
        let dir = crate::test_support::TestDir::new("kernel-executor-stdio");
        let executor = host_executor(&dir);
        let mut child = Command::new(&executor)
            .args(["--channel", "stdio"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let pipes = Pipes {
            out: child.stdout.take().unwrap(),
            into: child.stdin.take().unwrap(),
        };
        let mut client = ExecutorClient::handshake(pipes).unwrap();
        let hello = client.hello().clone();
        assert!(!hello.kcov && !hello.init, "{hello:?}");
        assert_eq!(hello.data_addr, DATA_ADDR);
        assert_eq!(hello.max_program, MAX_PROGRAM as u32);

        #[cfg(target_arch = "x86_64")]
        let (reboot, nanosleep, exit_group) = (169u16, 35u16, 231u16);
        #[cfg(target_arch = "aarch64")]
        let (reboot, nanosleep, exit_group) = (142u16, 101u16, 94u16);

        let mut builder = open_then(b"/dev/null\0", 1);
        builder
            .call(
                "write",
                &[SeedArg::Result(0), SeedArg::Data(b"abc"), SeedArg::Const(3)],
            )
            .unwrap();
        builder.call("close", &[SeedArg::Result(0)]).unwrap();
        // Executed, reboot(0, 0, 0, 0) would fail with EINVAL.
        builder.raw(reboot, &[]).unwrap();
        let reply = client
            .execute(&builder.finish(), Collect::Pcs, Duration::from_secs(5))
            .unwrap();
        assert_eq!(reply.status, ExecStatus::Ok);
        assert!(!reply.kcov);
        assert_eq!(reply.decoded, 4);
        let results: Vec<(i64, u32)> = reply.calls.iter().map(|c| (c.ret, c.errno)).collect();
        assert!(results[0].0 >= 0, "{results:?}");
        assert_eq!(&results[1..], &[(3, 0), (0, 0), (-1, 1)]);

        // nanosleep for 10 s, killed after 200 ms.
        let mut sleep = ProgramBuilder::default();
        let ten_seconds = [10u64.to_le_bytes(), 0u64.to_le_bytes()].concat();
        sleep
            .raw(nanosleep, &[SeedArg::Data(&ten_seconds), SeedArg::Const(0)])
            .unwrap();
        let started = std::time::Instant::now();
        let reply = client
            .execute(&sleep.finish(), Collect::Pcs, Duration::from_millis(200))
            .unwrap();
        assert_eq!(reply.status, ExecStatus::Timeout(200));
        assert!(reply.calls.is_empty());
        assert!(started.elapsed() < Duration::from_secs(5));

        // A call that ends the process ends the run, after the calls before it.
        let mut exit = ProgramBuilder::default();
        exit.call("dup", &[SeedArg::Const(0)]).unwrap();
        exit.raw(exit_group, &[SeedArg::Const(3)]).unwrap();
        exit.call("dup", &[SeedArg::Const(0)]).unwrap();
        let reply = client
            .execute(&exit.finish(), Collect::Pcs, Duration::from_secs(5))
            .unwrap();
        assert_eq!(reply.status, ExecStatus::Exited(3));
        assert_eq!((reply.decoded, reply.calls.len()), (3, 1));

        // The executor goes on serving after each.
        let reply = client
            .execute(&[], Collect::Pcs, Duration::from_secs(5))
            .unwrap();
        assert_eq!((reply.status, reply.decoded), (ExecStatus::Ok, 0));
        drop(client);
        assert!(child.wait().unwrap().success());
    }

    // ── Coverage and mutation ──────────────────────────────────────────

    /// A program and the reply the guest sent for it, recorded in
    /// `tests/fixtures/kernel_guest/replies/`.
    fn recorded(name: &str) -> (Vec<u8>, ExecReply) {
        let dir =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/kernel_guest/replies");
        let program = std::fs::read(dir.join(format!("{name}.prog"))).unwrap();
        let reply = parse_reply(&std::fs::read(dir.join(format!("{name}.reply"))).unwrap())
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        (program, reply)
    }

    /// Where the guest loaded its modules (the module area, without KASLR).
    const MODULES: u64 = 0xffff_ffff_a000_0000;

    /// The ids of the PCs of call `index` that are the driver module's.
    fn module_ids(reply: &ExecReply, index: usize) -> Vec<u32> {
        reply.calls[index]
            .pcs
            .iter()
            .filter(|pc| **pc >= MODULES)
            .map(|pc| pc_id(*pc))
            .collect()
    }

    #[test]
    fn recorded_replies_map_their_kcov_pcs_into_the_coverage_map() {
        let runs: Vec<(Vec<u8>, ExecReply)> =
            ["xfer-slot1", "xfer-slot1-again", "xfer-slot7", "get-stats"]
                .iter()
                .map(|name| recorded(name))
                .collect();
        for (program, reply) in &runs {
            assert_eq!(reply.status, ExecStatus::Ok);
            assert!(reply.kcov);
            assert_eq!((reply.decoded, reply.calls.len()), (2, 2));
            assert_eq!(decode(program).calls.len(), 2);
            // Every PC of every call, in order, as its id.
            let ids = coverage_ids(reply);
            let expected: Vec<u32> = reply
                .calls
                .iter()
                .flat_map(|call| call.pcs.iter().map(|pc| pc_id(*pc)))
                .collect();
            assert_eq!(ids, expected);
            assert_eq!(
                ids.len(),
                reply.calls[0].pcs.len() + reply.calls[1].pcs.len()
            );
        }
        // The kernel's PCs share their upper half, so an id is the low half
        // inverted, and no two PCs share an id.
        assert_eq!(pc_id(0xffff_ffff_8188_ed16), !0x8188_ed16u32);
        let pcs: std::collections::HashSet<u64> = runs
            .iter()
            .flat_map(|(_, reply)| reply.calls.iter().flat_map(|call| call.pcs.iter().copied()))
            .collect();
        let ids: std::collections::HashSet<u32> = pcs.iter().map(|pc| pc_id(*pc)).collect();
        assert!(pcs.len() > 500, "{}", pcs.len());
        assert_eq!(ids.len(), pcs.len());

        // The whole trace: the first program is all new coverage.
        let mut map = fuzz_engine_builtin::CoverageProxy::default();
        let first = fold_coverage(&mut map, &coverage_ids(&runs[0].1));
        let edges: std::collections::HashSet<(u32, u32)> = coverage_ids(&runs[0].1)
            .windows(2)
            .map(|pair| (pair[0], pair[1]))
            .collect();
        assert_eq!(first.new_edge_bits as usize, edges.len());
        assert!(first.new_breadcrumb_bits > 0);

        // The driver's own code: the same program takes the same path
        // through it, and adds nothing; slot 7 takes its EINVAL path and
        // GET_STATS another command's, and each adds edges.
        let mut driver = fuzz_engine_builtin::CoverageProxy::default();
        let slot1 = module_ids(&runs[0].1, 1);
        assert!(slot1.len() > 3, "{slot1:x?}");
        assert!(fold_coverage(&mut driver, &slot1).new_edge_bits > 0);
        assert_eq!(module_ids(&runs[1].1, 1), slot1);
        assert!(fold_coverage(&mut driver, &module_ids(&runs[1].1, 1)).is_empty());
        let slot7 = fold_coverage(&mut driver, &module_ids(&runs[2].1, 1));
        assert!(slot7.new_edge_bits > 0, "{slot7:?}");
        assert_eq!(runs[2].1.calls[1].errno, 22);
        let stats = fold_coverage(&mut driver, &module_ids(&runs[3].1, 1));
        assert!(stats.new_edge_bits > 0, "{stats:?}");
        // And the slot-1 path folded again is still nothing new.
        assert!(fold_coverage(&mut driver, &slot1).is_empty());
    }

    #[test]
    fn a_reply_carries_comparisons_in_fours() {
        let comparison = |kind, arg1, arg2, pc| KcovComparison {
            kind,
            arg1,
            arg2,
            pc,
        };
        let mut reply = reply_to(9, &[&[], &[]]);
        reply.calls[1].comparisons = vec![
            comparison(5, 4, 0, MODULES + 0x32e),
            comparison(6, 0xdead_beef_0000_0001, 7, MODULES + 0x40),
        ];
        let parsed = parse_reply(&encode_reply(&reply)).unwrap();
        assert_eq!(parsed, reply);
        assert_eq!(parsed.calls[1].comparisons[0].size(), 4);
        assert_eq!(parsed.calls[1].comparisons[1].size(), 8);
        assert!(parsed.calls[1].pcs.is_empty());
        // Words that are not whole comparisons are refused.
        let mut payload = encode_reply(&reply);
        let at = payload.len() - 8 * 8 - 8;
        payload[at..at + 4].copy_from_slice(&7u32.to_le_bytes());
        payload.truncate(payload.len() - 8);
        assert!(matches!(
            parse_reply(&payload),
            Err(ProtocolError::Malformed { what: "REPLY", .. })
        ));
    }

    /// `openat(widget)`, then `ioctl(r0, WIDGET_IOC_XFER, zeroed xfer)`.
    fn xfer_program() -> Vec<u8> {
        let mut builder = open_then(b"/dev/widget\0", 2);
        builder
            .call(
                "ioctl",
                &[
                    SeedArg::Result(0),
                    SeedArg::Const(0xc028_5703),
                    SeedArg::Data(&[0u8; 40]),
                ],
            )
            .unwrap();
        builder.finish()
    }

    #[test]
    fn a_comparison_the_kernel_made_suggests_its_other_operand_where_the_call_had_one() {
        let program = xfer_program();
        let decoded = decode(&program);
        let data = match &decoded.calls[1].args[2].value {
            ArgValue::Data { bytes, .. } => bytes.clone(),
            other => panic!("{other:?}"),
        };
        let cmd = decoded.calls[1].args[1].span.clone();
        let mut reply = reply_to(1, &[&[], &[]]);
        let cmp = |kind, arg1, arg2| KcovComparison {
            kind,
            arg1,
            arg2,
            pc: MODULES,
        };
        // openat compared its flags (2) with 0x40; the ioctl compared its
        // command with another, and the slot (0) with the bound 4.
        reply.calls[0].comparisons = vec![cmp(5, 0x40, 2)];
        reply.calls[1].comparisons =
            vec![cmp(5, 0x4004_5704, 0xc028_5703), cmp(5, 4, 0), cmp(5, 9, 9)];
        let hints = hint_programs(&program, &reply, MAX_HINTS);
        let slot4 = hints
            .iter()
            .find(|hint| hint[data.start..data.start + 4] == 4u32.to_le_bytes())
            .expect("the slot takes the bound");
        assert_eq!(slot4[..data.start], program[..data.start]);
        assert_eq!(slot4[data.start + 4..], program[data.start + 4..]);
        assert!(hints
            .iter()
            .any(|hint| hint[cmd.clone()] == 0x4004_5704u64.to_le_bytes()));
        // openat's comparison changes openat's flags, not the ioctl's words.
        let flags = decoded.calls[0].args[2].span.clone();
        let opened = hints
            .iter()
            .filter(|hint| hint[flags.clone()] != program[flags.clone()])
            .collect::<Vec<_>>();
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0][flags.clone()], 0x40u64.to_le_bytes());
        // Each hint is made once, none is the program itself, a comparison
        // of equal operands suggests nothing, and the cap holds.
        let unique: std::collections::HashSet<&Vec<u8>> = hints.iter().collect();
        assert_eq!(unique.len(), hints.len());
        assert!(!hints.contains(&program));
        assert!(hints.iter().all(|hint| hint.len() == program.len()));
        assert_eq!(hint_programs(&program, &reply, 2).len(), 2);
        // Both calls get their turn under a small cap.
        let two = hint_programs(&program, &reply, 2);
        assert!(two
            .iter()
            .any(|hint| hint[flags.clone()] != program[flags.clone()]));

        // The same comparisons as a CmpLog keep only what splices into it.
        let log = comparison_log(&reply, &program);
        assert!(log
            .entries
            .iter()
            .any(|entry| entry.operand_a == 4u32.to_le_bytes() && entry.operand_b == [0; 4]));
        assert!(log
            .entries
            .iter()
            .all(|entry| entry.operand_a != entry.operand_b));
    }

    #[test]
    fn mutations_see_each_argument_and_call() {
        use fuzz_engine_builtin::TypedValueKind;
        let program = xfer_program();
        let decoded = decode(&program);
        let spans = decoded.typed_spans();
        // 3 consts and a 12-byte path (3 words) in openat; a result, a
        // const and 40 bytes (10 words) in the ioctl.
        let integers = spans
            .iter()
            .filter(|span| span.kind == TypedValueKind::UnsignedInteger)
            .count();
        assert_eq!(integers, 3 + 3 + 1 + 1 + 10);
        let data = &decoded.calls[1].args[2].span;
        assert!(spans
            .iter()
            .any(|span| span.kind == TypedValueKind::Bytes && span.range == *data));
        assert!(spans.iter().all(|span| span.valid_for(program.len())));
        let operations = decoded.operations();
        assert_eq!(operations.operation_count, SYSCALLS.len() + 1);
        assert_eq!(operations.steps.len(), 2);
        assert_eq!(operations.steps[0].range, decoded.calls[0].span);
        assert_eq!(operations.steps[1].range.end, program.len());
        assert_eq!(
            operations.steps[1].op_index_range,
            decoded.calls[1].span.start..decoded.calls[1].span.start + 1
        );
        operations.validate_for_input(&program).unwrap();
    }

    #[test]
    fn a_program_as_json_names_each_call_and_argument() {
        let mut builder = ProgramBuilder::default();
        builder
            .call(
                "openat",
                &[
                    SeedArg::Const(-100i64 as u64),
                    SeedArg::Data(b"/dev/widget\0"),
                    SeedArg::Const(2),
                ],
            )
            .unwrap();
        builder
            .call("read", &[SeedArg::Result(0), SeedArg::Out(24)])
            .unwrap();
        builder.raw(500, &[]).unwrap();
        let bytes = builder.finish();
        let json = decode(&bytes).json();
        assert_eq!(json["schema"], PROGRAM_SCHEMA);
        assert_eq!(json["data_address"], "0x20000000");
        assert_eq!(json["calls"][0]["call"], "openat");
        assert_eq!(json["calls"][0]["args"][0]["const"], "0xffffffffffffff9c");
        assert_eq!(
            json["calls"][0]["args"][1]["data"],
            serde_json::json!({"address": "0x20000000", "len": 12, "hex": "2f6465762f77696467657400"})
        );
        assert_eq!(json["calls"][1]["args"][0]["result"], 0);
        assert_eq!(
            json["calls"][1]["args"][1]["out"],
            serde_json::json!({"address": "0x20000010", "len": 24})
        );
        assert_eq!(json["calls"][2]["call"], "syscall_500");
        assert_eq!(json["calls"][2]["nr"], 500);
    }

    /// The C reproducer builds, makes the program's calls with the data the
    /// executor would map, and refuses the raw calls the executor refuses.
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn a_program_as_c_makes_the_same_calls() {
        #[cfg(target_arch = "x86_64")]
        let reboot = 169u16;
        #[cfg(target_arch = "aarch64")]
        let reboot = 142u16;
        let mut builder = open_then(b"/nonexistent/widget\0", 2);
        builder
            .call(
                "ioctl",
                &[
                    SeedArg::Result(0),
                    SeedArg::Const(0xc028_5703),
                    SeedArg::Data(&[4, 0, 0, 0]),
                ],
            )
            .unwrap();
        builder
            .call(
                "read",
                &[SeedArg::Const(0), SeedArg::Out(8), SeedArg::Const(0)],
            )
            .unwrap();
        builder.raw(reboot, &[]).unwrap();
        let bytes = builder.finish();
        let source = decode(&bytes).c_source("KASAN: x */ in y");
        assert!(source.contains("KASAN: x * / in y"), "{source}");
        assert!(
            source.contains("memcpy(data + 0x18, \"\\x04\\x00\\x00\\x00\", 4);"),
            "{source}"
        );
        assert!(
            source.contains(
                "r[1] = (uint64_t)syscall(SYS_ioctl, r[0], 0xc0285703ul, 0x20000018ul, 0ul, 0ul, 0ul);"
            ),
            "{source}"
        );
        assert!(source.contains("0x20000020ul"), "{source}");
        assert!(
            source.contains(&format!("r[3] = denied({reboot}) ? (uint64_t)-1")),
            "{source}"
        );
        let dir = crate::test_support::TestDir::new("kernel-repro-c");
        std::fs::write(dir.join("repro.c"), &source).unwrap();
        let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_owned());
        let built = std::process::Command::new(&cc)
            .args(["-Wall", "-Wextra", "-Werror", "-o"])
            .arg(dir.join("repro"))
            .arg(dir.join("repro.c"))
            .output()
            .unwrap();
        assert!(
            built.status.success(),
            "{}",
            String::from_utf8_lossy(&built.stderr)
        );
        // On the host: the open fails, the ioctl and the read fail on a bad
        // descriptor, and the reboot is never made.
        let ran = std::process::Command::new(dir.join("repro"))
            .status()
            .unwrap();
        assert!(ran.success());
    }

    // ── The initramfs and the guest's command line ─────────────────────

    /// An entry of a newc archive: `(name, mode, rdev, data)`.
    type Entry = (String, u32, (u32, u32), Vec<u8>);

    fn read_cpio(bytes: &[u8]) -> Vec<Entry> {
        let mut entries = Vec::new();
        let mut pos = 0;
        let align = |n: usize| (n + 3) & !3;
        loop {
            assert_eq!(&bytes[pos..pos + 6], b"070701");
            let field = |i: usize| {
                let at = pos + 6 + i * 8;
                u32::from_str_radix(std::str::from_utf8(&bytes[at..at + 8]).unwrap(), 16).unwrap()
            };
            let (mode, size, rdev, name_size) = (
                field(1),
                field(6) as usize,
                (field(9), field(10)),
                field(11) as usize,
            );
            let name_at = pos + 110;
            let name = std::str::from_utf8(&bytes[name_at..name_at + name_size - 1])
                .unwrap()
                .to_owned();
            let data_at = align(name_at + name_size);
            let data = bytes[data_at..data_at + size].to_vec();
            pos = align(data_at + size);
            if name == "TRAILER!!!" {
                assert_eq!(pos, bytes.len());
                return entries;
            }
            entries.push((name, mode, rdev, data));
        }
    }

    #[test]
    fn the_initramfs_holds_the_executor_as_init_and_the_modules_in_order() {
        let dir = crate::test_support::TestDir::new("kernel-initramfs");
        let executor = dir.join("executor");
        std::fs::write(&executor, b"\x7fELF executor").unwrap();
        let first = dir.join("widget.ko");
        let second = dir.join("helper.ko");
        std::fs::write(&first, b"widget").unwrap();
        std::fs::write(&second, b"helper module").unwrap();
        let out = dir.join("initramfs.cpio");
        build_initramfs(&executor, &[first, second], &out).unwrap();
        let entries = read_cpio(&std::fs::read(&out).unwrap());
        let names: Vec<&str> = entries.iter().map(|entry| entry.0.as_str()).collect();
        assert_eq!(
            names,
            [
                "dev",
                "dev/console",
                "proc",
                "sys",
                "bhf",
                "bhf/modules",
                "bhf/modules/00-widget.ko",
                "bhf/modules/01-helper.ko",
                "init"
            ]
        );
        let entry = |name: &str| entries.iter().find(|entry| entry.0 == name).unwrap();
        assert_eq!(entry("init").1, 0o100755);
        assert_eq!(entry("init").3, b"\x7fELF executor");
        assert_eq!(entry("bhf/modules/01-helper.ko").3, b"helper module");
        assert_eq!(entry("dev/console").1, 0o020600);
        assert_eq!(entry("dev/console").2, (5, 1));
        assert_eq!(entry("dev").1, 0o040755);

        let error = build_initramfs(&executor, &[dir.join("widget.o")], &out).unwrap_err();
        assert!(error.to_string().contains("ends in .ko"), "{error}");
    }

    #[test]
    fn the_guest_boots_its_kernel_with_the_executors_port_and_no_reboot() {
        let setup = GuestSetup {
            qemu: PathBuf::from("qemu-system-x86_64"),
            kernel: PathBuf::from("/k/bzImage"),
            initrd: PathBuf::from("/w/initramfs.cpio"),
            memory_mb: 2048,
            smp: 2,
            accel: Accel::Auto,
            append: Some("kasan.fault=report".to_owned()),
            qemu_args: vec!["-machine".to_owned(), "q35".to_owned()],
            boot_timeout: Duration::from_secs(60),
        };
        let args = setup.qemu_command(Accel::Tcg, Path::new("/tmp/bhf-kg-1/executor.sock"));
        let after = |flag: &str| {
            let at = args.iter().position(|arg| arg == flag).unwrap();
            args[at + 1].as_str()
        };
        assert_eq!(after("-kernel"), "/k/bzImage");
        assert_eq!(after("-initrd"), "/w/initramfs.cpio");
        assert_eq!(after("-m"), "2048");
        assert_eq!(after("-smp"), "2");
        assert_eq!(after("-accel"), "tcg");
        assert_eq!(after("-serial"), "stdio");
        assert_eq!(
            after("-append"),
            format!("{BASE_APPEND} kasan.fault=report")
        );
        assert!(args.contains(&"-no-reboot".to_owned()));
        assert!(args.contains(&"socket,id=bhfexec,path=/tmp/bhf-kg-1/executor.sock".to_owned()));
        assert!(args.contains(&format!(
            "virtserialport,bus=bhfserial.0,chardev=bhfexec,name={PORT_NAME}"
        )));
        assert_eq!(&args[args.len() - 2..], ["-machine", "q35"]);
        assert!(!args.contains(&"host".to_owned()));
        let kvm = setup.qemu_command(Accel::Kvm, Path::new("/s"));
        assert_eq!(
            kvm[kvm.iter().position(|a| a == "-cpu").unwrap() + 1],
            "host"
        );
        assert_eq!(
            GuestSetup {
                append: Some("  ".to_owned()),
                ..setup
            }
            .command_line(),
            BASE_APPEND
        );
    }

    #[test]
    fn the_console_keeps_what_was_written_since_a_mark() {
        let console = Console::with_log(None);
        console.append(b"[    0.1] booting\n");
        let mark = console.mark();
        console.append(b"BUG: KASAN: slab-out-of-bounds in f+0x1/0x2\n");
        assert_eq!(
            console.since(mark),
            "BUG: KASAN: slab-out-of-bounds in f+0x1/0x2\n"
        );
        assert_eq!(
            console.tail(1),
            "BUG: KASAN: slab-out-of-bounds in f+0x1/0x2"
        );
        // Past its bound it keeps the newest half, and marks stay absolute.
        let big = vec![b'x'; CONSOLE_KEEP];
        let before = console.mark();
        console.append(&big);
        console.append(b"tail\n");
        assert_eq!(console.mark(), before + CONSOLE_KEEP as u64 + 5);
        assert!(console.since(mark).len() <= CONSOLE_KEEP);
        assert!(console.since(mark).ends_with("xtail\n"));
        assert!(!console.wait_closed(Duration::from_millis(1)));
        console.close();
        assert!(console.wait_closed(Duration::from_secs(1)));
    }

    // ── A stand-in for qemu-system ─────────────────────────────────────

    /// A qemu-system stand-in (a Python script) for the host's half of the
    /// guest: launch `n` takes `steps[n]`, the last step repeating. `fail`
    /// exits 1 at once, as a qemu that cannot start does. `serve` connects
    /// to the executor's socket, says `hello` and reads EXECs until the host
    /// closes the channel. `panic` says `hello` too, then at the first EXEC
    /// prints `console` on the serial console and exits, as a guest whose
    /// kernel panicked does. `None` (the test skips) without python3.
    #[cfg(unix)]
    fn stub_qemu(dir: &Path, hello: &Hello, steps: &[&str], console: &str) -> Option<GuestSetup> {
        use std::os::unix::fs::PermissionsExt;
        let python = std::process::Command::new("python3")
            .args(["-c", "pass"])
            .status()
            .is_ok_and(|status| status.success());
        if !python {
            assert!(
                std::env::var_os("BHF_REQUIRE_TOOLS").is_none_or(|value| value != "1"),
                "BHF_REQUIRE_TOOLS=1 and the test's tool `python3` is not available"
            );
            eprintln!("skipping: no python3 for the qemu stand-in");
            return None;
        }
        const STUB: &str = r#"#!/usr/bin/env python3
import os, socket, sys
state = os.path.dirname(os.path.abspath(sys.argv[0]))
counter = os.path.join(state, "launches")
launch = int(open(counter).read()) if os.path.exists(counter) else 0
with open(counter, "w") as out:
    out.write(str(launch + 1))
steps = open(os.path.join(state, "steps")).read().split()
step = steps[min(launch, len(steps) - 1)]
if step == "fail":
    sys.exit(1)
chardev = next(arg for arg in sys.argv if arg.startswith("socket,id=bhfexec,"))
channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
channel.connect(chardev.split("path=", 1)[1])
channel.sendall(open(os.path.join(state, "hello.bin"), "rb").read())

def take(size):
    data = b""
    while len(data) < size:
        chunk = channel.recv(size - len(data))
        if not chunk:
            sys.exit(0)
        data += chunk
    return data

while True:
    take(int.from_bytes(take(12)[8:12], "little"))
    if step == "panic":
        sys.stdout.write(open(os.path.join(state, "console.log")).read())
        sys.stdout.flush()
        sys.exit(0)
"#;
        let qemu = dir.join("qemu-system-stub");
        std::fs::write(&qemu, STUB).unwrap();
        std::fs::set_permissions(&qemu, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(dir.join("steps"), steps.join("\n")).unwrap();
        std::fs::write(
            dir.join("hello.bin"),
            message(MSG_HELLO, &encode_hello(hello)),
        )
        .unwrap();
        std::fs::write(dir.join("console.log"), console).unwrap();
        for file in ["bzImage", "initramfs.cpio"] {
            std::fs::write(dir.join(file), b"stub").unwrap();
        }
        Some(GuestSetup {
            qemu,
            kernel: dir.join("bzImage"),
            initrd: dir.join("initramfs.cpio"),
            memory_mb: 256,
            smp: 1,
            accel: Accel::Tcg,
            append: None,
            qemu_args: Vec::new(),
            boot_timeout: Duration::from_secs(60),
        })
    }

    /// How many times the stand-in was launched.
    #[cfg(unix)]
    fn stub_launches(dir: &Path) -> usize {
        std::fs::read_to_string(dir.join("launches"))
            .map(|text| text.trim().parse().unwrap())
            .unwrap_or(0)
    }

    /// `--boot-timeout` and `--timeout` take a u64 of seconds: a boot or a
    /// run given the longest a Duration holds ends as any other does,
    /// without the deadline overflowing.
    #[cfg(unix)]
    #[test]
    fn a_boot_or_a_run_given_the_longest_wait_ends_without_overflowing() {
        let dir = tempfile::tempdir().unwrap();
        let Some(setup) = stub_qemu(dir.path(), &hello(true), &["fail", "panic"], "") else {
            return;
        };
        assert_eq!(reply_wait(Duration::from_secs(10)), Duration::from_secs(30));
        assert_eq!(
            reply_wait(Duration::MAX),
            Duration::from_secs(2 * MAX_WAIT_SECS + 10)
        );
        let forever = GuestSetup {
            boot_timeout: Duration::MAX,
            ..setup
        };
        let error = match Guest::boot(&forever, None) {
            Ok(_) => panic!("a qemu that exits at once booted"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("qemu exited"), "{error}");
        let mut guest = match Guest::boot(&forever, None) {
            Ok(guest) => guest,
            Err(error) => panic!("{error:#}"),
        };
        let run = guest.run(&open_then(b"/dev/null\0", 1).finish(), Duration::MAX);
        assert!(matches!(run.end, RunEnd::Stopped(_)), "{:?}", run.end);
        assert_eq!(stub_launches(dir.path()), 2);
    }

    /// A campaign in `dir/work` against the stand-in in `dir/stub`, with one
    /// seed and `iterations` runs at most; `None` without python3.
    #[cfg(unix)]
    fn stub_campaign(
        dir: &Path,
        hello: &Hello,
        steps: &[&str],
        console: &str,
        iterations: usize,
    ) -> Option<FuzzConfig> {
        let stub = dir.join("stub");
        std::fs::create_dir_all(&stub).unwrap();
        let setup = stub_qemu(&stub, hello, steps, console)?;
        let work_dir = dir.join("work");
        // Where `bhf kernel fuzz` builds the guest's files, and its console log goes.
        std::fs::create_dir_all(work_dir.join("kernel").join("guest")).unwrap();
        Some(FuzzConfig {
            dir: work_dir.join("kernel"),
            work_dir,
            guest_record: serde_json::json!({"kernel": "bzImage"}),
            stop_after_findings: None,
            setup,
            iterations,
            time_budget: None,
            timeout: Duration::from_secs(5),
            rng_seed: 7,
            max_len: 4096,
        })
    }

    /// One seed: open /dev/widget.
    #[cfg(unix)]
    fn widget_seed(_: &Hello) -> anyhow::Result<SeedSet> {
        Ok(SeedSet {
            programs: vec![open_then(b"/dev/widget\0", 2).finish()],
            ..SeedSet::default()
        })
    }

    /// A `--module` the guest did not load leaves the campaign nothing of
    /// the driver to reach: it stops before it runs a program, and
    /// fuzz.json keeps the HELLO's notes that say why.
    #[cfg(unix)]
    #[test]
    fn a_module_the_guest_did_not_load_stops_the_campaign_before_it_runs() {
        let dir = tempfile::tempdir().unwrap();
        let mut said = hello(true);
        said.notes = "module 00-broken.ko: not loaded: Exec format error\n\
                      ready (kcov on, comparisons on)\n"
            .to_owned();
        let Some(config) = stub_campaign(dir.path(), &said, &["panic"], "", 8) else {
            return;
        };
        let summary = fuzz(&config, &widget_seed).unwrap();
        let written: serde_json::Value =
            serde_json::from_slice(&std::fs::read(config.dir.join("fuzz.json")).unwrap()).unwrap();
        assert_eq!(written["executions"], 0, "{written:#}");
        assert_eq!(
            written["notes"],
            serde_json::json!([
                "module 00-broken.ko: not loaded: Exec format error",
                "ready (kcov on, comparisons on)"
            ])
        );
        let halted = written["halted"].as_str().unwrap_or_default();
        assert!(
            halted.contains("module 00-broken.ko: not loaded: Exec format error"),
            "{halted}"
        );
        assert_eq!(summary.executions, 0);
        assert_eq!(summary.notes, said.note_lines());
        assert_eq!(stub_launches(&dir.path().join("stub")), 1);
    }

    /// The HELLO's notes name each module the executor could not load, in
    /// the executor's own words.
    #[test]
    fn the_hello_notes_name_each_module_the_guest_did_not_load() {
        let mut said = hello(true);
        said.notes = "mount debugfs on /sys/kernel/debug: No such device\n\
                      module 00-broken.ko: not loaded: Exec format error\n\
                      module 01-widget.ko: loaded\n\
                      module 02-gone.ko: open: No such file or directory\n\
                      \n\
                      kcov: no comparisons (CONFIG_KCOV_ENABLE_COMPARISONS is off)\n"
            .to_owned();
        assert_eq!(
            said.unloaded_modules(),
            [
                "module 00-broken.ko: not loaded: Exec format error",
                "module 02-gone.ko: open: No such file or directory"
            ]
        );
        assert_eq!(said.note_lines().len(), 5);
        assert_eq!(said.note_lines()[2], "module 01-widget.ko: loaded");
        assert!(hello(true).unloaded_modules().is_empty());
    }

    /// The hints queued are remembered by a 16-byte digest, not by their
    /// bytes, and neither the queue nor the memory grows past its bound.
    #[test]
    fn hints_are_queued_once_each_and_their_memory_is_bounded() {
        let hint = |n: u32| {
            let mut bytes = vec![0xa5; 4096];
            bytes[..4].copy_from_slice(&n.to_le_bytes());
            bytes
        };
        let mut queue = HintQueue::new(3, 4);
        assert!(queue.offer(hint(1)));
        assert!(!queue.offer(hint(1)), "a hint queued again");
        assert!(queue.offer(hint(2)));
        assert!(queue.offer(hint(3)));
        assert!(!queue.offer(hint(4)), "past the pending bound");
        assert_eq!(queue.pop(), Some(hint(1)));
        // Run, it is still remembered: not queued again.
        assert!(!queue.offer(hint(1)));
        assert!(queue.offer(hint(5)));
        assert_eq!(queue.pending(), 3);
        // The memory holds at most four digests, then starts again.
        for n in 6..1000 {
            while queue.pop().is_some() {}
            queue.offer(hint(n));
            assert!(queue.remembered() <= 4, "{} remembered", queue.remembered());
        }
        assert!(!queue.is_empty());
    }

    /// The CmpLogs of at most so many programs are kept, the one used
    /// least recently giving way.
    #[test]
    fn the_comparisons_of_the_programs_used_least_recently_give_way() {
        let log = |site: u64| {
            let mut log = cmplog::CmpLog::new();
            log.record(cmplog::CmpEntry {
                site_id: site,
                operand_a: vec![1],
                operand_b: vec![2],
                kind: cmplog::CmpKind::IntegerCompare,
            });
            log
        };
        let site = |cache: &mut CmpLogCache, program: &[u8]| {
            cache.get(program).map(|log| log.entries[0].site_id)
        };
        let mut cache = CmpLogCache::new(2);
        cache.insert(b"a", log(1));
        cache.insert(b"b", log(2));
        assert_eq!(site(&mut cache, b"a"), Some(1));
        // b was used least recently.
        cache.insert(b"c", log(3));
        assert_eq!(cache.len(), 2);
        assert_eq!(site(&mut cache, b"b"), None);
        assert_eq!(site(&mut cache, b"a"), Some(1));
        assert_eq!(site(&mut cache, b"c"), Some(3));
        // Replacing a program's log keeps the others.
        cache.insert(b"c", log(4));
        assert_eq!(cache.len(), 2);
        assert_eq!(site(&mut cache, b"c"), Some(4));
        assert_eq!(site(&mut cache, b"a"), Some(1));
        for n in 0..100u32 {
            cache.insert(&n.to_le_bytes(), log(u64::from(n)));
        }
        assert_eq!(cache.len(), 2);
    }

    /// A guest console with a KASAN report, recorded from the widget fixture.
    #[cfg(unix)]
    fn kasan_console() -> String {
        std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/kernel_guest/console/kasan-slab-out-of-bounds.log"),
        )
        .unwrap()
    }

    /// The finding.json of each finding the campaign in `dir/work` wrote.
    #[cfg(unix)]
    fn written_findings(dir: &Path) -> Vec<(PathBuf, serde_json::Value)> {
        let findings = dir.join("work/results/findings");
        let mut out: Vec<(PathBuf, serde_json::Value)> = std::fs::read_dir(&findings)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.path())
                    .filter(|path| path.join("finding.json").is_file())
                    .map(|path| {
                        let raw = serde_json::from_slice(
                            &std::fs::read(path.join("finding.json")).unwrap(),
                        )
                        .unwrap();
                        (path, raw)
                    })
                    .collect()
            })
            .unwrap_or_default();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// A kernel report's program is confirmed in a freshly booted guest; when
    /// that guest does not boot, the finding is written all the same,
    /// unconfirmed and saying why, and the campaign stops only when the
    /// guest does not boot again.
    #[cfg(unix)]
    #[test]
    fn a_report_whose_confirming_guest_does_not_boot_is_still_a_finding() {
        let dir = tempfile::tempdir().unwrap();
        let Some(config) = stub_campaign(
            dir.path(),
            &hello(true),
            &["panic", "fail"],
            &kasan_console(),
            20,
        ) else {
            return;
        };
        let two_seeds = |_: &Hello| -> anyhow::Result<SeedSet> {
            Ok(SeedSet {
                programs: vec![
                    open_then(b"/dev/widget\0", 2).finish(),
                    open_then(b"/dev/widget\0", 0).finish(),
                ],
                ..SeedSet::default()
            })
        };
        let summary = fuzz(&config, &two_seeds).unwrap();
        let findings = written_findings(dir.path());
        assert_eq!(findings.len(), 1, "{summary:#?}");
        let (finding, raw) = &findings[0];
        assert_eq!(
            raw["kernel"]["title"],
            "KASAN: slab-out-of-bounds Write in widget_ioctl"
        );
        assert_eq!(raw["kernel"]["reproduced"], false);
        assert_eq!(raw["confidence"], "medium");
        let unconfirmed = raw["kernel"]["unconfirmed"].as_str().unwrap_or_default();
        assert!(
            unconfirmed.contains("the guest did not start: qemu exited"),
            "{raw:#}"
        );
        assert_eq!(
            std::fs::read(finding.join("testcase.bin")).unwrap(),
            open_then(b"/dev/widget\0", 2).finish()
        );
        assert_eq!(summary.findings, [raw["id"].as_str().unwrap()]);
        assert_eq!((summary.reports, summary.confirm_runs), (1, 0));
        // The second seed's guest did not boot either: the campaign stopped.
        let halted = summary.halted.as_deref().unwrap_or_default();
        assert!(halted.contains("the guest did not start"), "{halted}");
        assert_eq!(stub_launches(&dir.path().join("stub")), 3);
    }

    /// A report the program alone makes again in a freshly booted guest is
    /// a confirmed finding.
    #[cfg(unix)]
    #[test]
    fn a_report_the_program_makes_again_in_a_fresh_guest_is_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let Some(config) = stub_campaign(dir.path(), &hello(true), &["panic"], &kasan_console(), 2)
        else {
            return;
        };
        let summary = fuzz(&config, &widget_seed).unwrap();
        let findings = written_findings(dir.path());
        assert_eq!(findings.len(), 1, "{summary:#?}");
        let raw = &findings[0].1;
        assert_eq!(raw["kernel"]["reproduced"], true, "{raw:#}");
        assert_eq!(raw["confidence"], "high");
        assert!(raw["kernel"].get("unconfirmed").is_none(), "{raw:#}");
        assert_eq!((summary.reports, summary.confirm_runs), (1, 1));
    }
}
