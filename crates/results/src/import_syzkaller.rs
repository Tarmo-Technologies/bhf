// SPDX-License-Identifier: Apache-2.0
//! syzkaller crash directories -> bhf findings.
//!
//! syz-manager keeps each distinct crash in `<workdir>/crashes/<id>/`: the
//! crash title in `description`, the console output of up to 100
//! occurrences in `log0`..., their symbolized reports in `report0`..., and,
//! once syz-repro found one, the reproducer as a syz program
//! (`repro.prog`) and as C (`repro.cprog`). [`import`] turns each into a
//! finding under `<work>/results/findings/F-KERNEL-*`: the crash class, rule
//! and CWE from the title, the stack and the memory access from the report,
//! and the reproducers as evidence. Re-importing a crash updates its finding
//! in place.
//!
//! The same parser reads the kernel reports `bhf kernel fuzz` finds on its
//! guest's console ([`console_report`]): [`record_guest_crash`] writes each
//! as an `F-KERNEL-*` finding with the program that made it.

use crate::model::Severity;
use crate::ResultsError;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// `kind` of an imported kernel crash in its `finding.json`.
pub const KERNEL_CRASH_KIND: &str = "kernel_crash";
/// The producer findings.json names for one.
pub const PRODUCER: &str = "kernel import";
/// The producer of a crash `bhf kernel fuzz` found in its guest.
pub const GUEST_PRODUCER: &str = "kernel fuzz";
/// `kernel.tool` of such a crash.
pub const GUEST_TOOL: &str = "bhf";
/// Finding id family.
pub const ID_PREFIX: &str = "F-KERNEL-";
/// The schema of a finding's `kernel` block.
pub const KERNEL_BLOCK_SCHEMA: &str = "bhf.kernel-crash.v1";

/// Most bytes read from one crash file (a report, a log, a reproducer); the
/// first MiB holds the report and its stacks.
const MAX_FILE_BYTES: u64 = 1 << 20;
/// Most bytes of a title.
const MAX_TITLE_BYTES: u64 = 4096;
/// Most frames kept of one stack.
const MAX_FRAMES: usize = 64;
/// Most crash directories one import reads under one path.
pub const MAX_CRASH_DIRS: usize = 10_000;

/// Evidence files of an imported crash, in the finding directory.
pub const REPORT_FILE: &str = "sanitizer.log";
pub const CONSOLE_FILE: &str = "console.log";
pub const SYZ_REPRO_FILE: &str = "repro.syz";
pub const C_REPRO_FILE: &str = "repro.c";
/// A guest crash's program, as the executor runs it, decoded, and as text.
pub const TESTCASE_FILE: &str = "testcase.bin";
pub const DECODED_FILE: &str = "decoded.json";
pub const PROGRAM_FILE: &str = "program.txt";

/// Whether a `finding.json` is an imported kernel crash.
pub fn is_kernel_crash(raw: &Value) -> bool {
    raw.get("kind").and_then(Value::as_str) == Some(KERNEL_CRASH_KIND)
}

/// Whether a kernel crash's `finding.json` is one bhf's guest lane found.
pub fn is_guest_crash(raw: &Value) -> bool {
    is_kernel_crash(raw) && raw.pointer("/kernel/tool").and_then(Value::as_str) == Some(GUEST_TOOL)
}

/// The producer of a kernel crash's `finding.json`.
pub fn producer(raw: &Value) -> &'static str {
    if is_guest_crash(raw) {
        GUEST_PRODUCER
    } else {
        PRODUCER
    }
}

/// The command that reproduces an imported crash, relative to `results/`:
/// its C reproducer, compiled and run, else its syz program under
/// syz-execprog with the options syz-repro recorded. Both run in the test VM
/// that runs the kernel. `None` when syzkaller found no reproducer.
pub fn reproduce_command(id: &str, raw: &Value, has_c: bool, has_syz: bool) -> Option<String> {
    // The guest bhf found it in boots again and runs its program.
    if is_guest_crash(raw) {
        return Some(format!("bhf kernel replay findings/{id}"));
    }
    if has_c {
        return Some(format!(
            "gcc -pthread -o repro findings/{id}/{C_REPRO_FILE} && ./repro"
        ));
    }
    if !has_syz {
        return None;
    }
    let options = raw.pointer("/kernel/reproducer/options");
    let procs = options
        .and_then(|o| o.get("procs"))
        .and_then(Value::as_u64)
        .unwrap_or(1);
    let sandbox = options
        .and_then(|o| o.get("sandbox"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric()))
        .unwrap_or("none");
    let repeat = options
        .and_then(|o| o.get("repeat"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    // Repeated that many times, or for ever when 0; once when not repeated.
    let repeat_times = options
        .and_then(|o| o.get("repeat_times"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let threaded = options
        .and_then(|o| o.get("threaded"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let sandbox_arg = options
        .and_then(|o| o.get("sandbox_arg"))
        .and_then(Value::as_i64)
        .filter(|arg| *arg != 0)
        .map(|arg| format!(" -sandbox_arg={arg}"))
        .unwrap_or_default();
    Some(format!(
        "syz-execprog -executor=./syz-executor -repeat={} -procs={procs} -sandbox={sandbox}{sandbox_arg} \
         -threaded={threaded} -cover=0 findings/{id}/{SYZ_REPRO_FILE}",
        if repeat { repeat_times } else { 1 }
    ))
}

/// What an imported crash is, in plain words, from its `finding.json`: the
/// detector and access, where it happened, what such a bug lets an attacker
/// do, and how to reproduce it.
pub fn explanation(raw: &Value) -> Option<String> {
    let kernel = raw.get("kernel")?;
    let class = kernel.get("class").and_then(Value::as_str)?;
    let detector = kernel.get("detector").and_then(Value::as_str);
    let guest = is_guest_crash(raw);
    let whose = if guest {
        "the guest kernel's"
    } else {
        "syzkaller's"
    };
    let mut text = match detector {
        Some(detector) => format!("{whose} {detector} report: {}", class.replace('-', " ")),
        None => format!("{whose} kernel report: {}", class.replace('-', " ")),
    };
    if let Some(access) = raw.pointer("/exception/access") {
        if let Some(direction) = access.get("direction").and_then(Value::as_str) {
            match access.get("size").and_then(Value::as_u64) {
                Some(size) => text.push_str(&format!(", a {direction} of {size} bytes")),
                None => text.push_str(&format!(", a {direction}")),
            }
            if let Some(region) = access.get("region").filter(|r| r.is_object()) {
                let distance = region.get("distance").and_then(Value::as_u64);
                let size = region.get("size").and_then(Value::as_u64);
                let kind = region.get("kind").and_then(Value::as_str).unwrap_or("heap");
                let place = match region.get("relation").and_then(Value::as_str) {
                    Some("after") => "past the end of",
                    Some("before") => "before the start of",
                    _ => "inside",
                };
                if let (Some(distance), Some(size)) = (distance, size) {
                    text.push_str(&format!(
                        " {distance} bytes {place} a {size}-byte {kind} object"
                    ));
                }
            }
        }
    }
    let top = raw.pointer("/exception/stack/0");
    let function = kernel
        .get("function")
        .and_then(Value::as_str)
        .or_else(|| top.and_then(|f| f.get("function")).and_then(Value::as_str));
    if let Some(function) = function {
        text.push_str(&format!(", in `{function}`"));
        let at = top
            .filter(|frame| frame.get("function").and_then(Value::as_str) == Some(function))
            .and_then(|frame| {
                let file = frame.get("file").and_then(Value::as_str)?;
                Some(match frame.get("line").and_then(Value::as_u64) {
                    Some(line) => format!("{file}:{line}"),
                    None => file.to_owned(),
                })
            });
        if let Some(at) = at {
            text.push_str(&format!(" ({at})"));
        }
    }
    text.push_str(if guest {
        ", reached from a system call of the program bhf kernel fuzz ran in its guest. "
    } else {
        ", reached from a system call syzkaller made. "
    });
    text.push_str(match family(class) {
        Family::Memory => {
            "A kernel memory-safety bug that user space can reach can crash the machine, \
             corrupt kernel data, and is often exploitable for privilege escalation."
        }
        Family::Pointer => {
            "A bad pointer dereference in the kernel crashes the machine (denial of service), \
             and worse when user space controls the address."
        }
        Family::Uninit => {
            "Uninitialized kernel memory decided what the kernel did, or was copied to user \
             space, which can leak kernel data."
        }
        Family::Race => {
            "Two threads accessed the same kernel memory without synchronization: a race \
             user space can trigger can corrupt kernel state."
        }
        Family::Hang => {
            "The kernel hung or deadlocked: user space can make the machine unresponsive \
             (denial of service)."
        }
        Family::Leak => {
            "Kernel memory was never freed: repeating the calls exhausts the machine's \
             memory (denial of service)."
        }
        Family::Check => {
            "The kernel hit one of its own consistency checks, on a path user space can \
             reach that the code did not expect; with panic_on_warn it crashes the machine."
        }
    });
    let reproducer = kernel.get("reproducer").filter(|r| r.is_object());
    if guest {
        let repeated = kernel.get("reproduced").and_then(Value::as_bool) == Some(true);
        let unconfirmed = kernel.get("unconfirmed").and_then(Value::as_str);
        let how = match unconfirmed {
            _ if repeated => {
                ", as bhf did once, in a freshly booted guest, when it found the crash".to_owned()
            }
            Some(why) => format!(
                " (bhf could not run it alone in a freshly booted guest when it found the \
                 crash: {why})"
            ),
            None => " (it did not crash a freshly booted guest again when bhf found it: the \
                     crash may depend on what ran before it)"
                .to_owned(),
        };
        text.push_str(&format!(
            " The program is attached ({TESTCASE_FILE}, and as C in {C_REPRO_FILE}); `bhf kernel \
             replay` boots the same guest and runs it{how}."
        ));
        return Some(text);
    }
    match reproducer {
        Some(reproducer) => {
            let files: Vec<&str> = ["c", "syz"]
                .iter()
                .filter_map(|key| reproducer.get(*key).and_then(Value::as_str))
                .collect();
            text.push_str(&format!(
                " syzkaller's reproducer is attached ({}); run it in the test VM.",
                files.join(", ")
            ));
        }
        None => text.push_str(&format!(
            " syzkaller found no reproducer; {CONSOLE_FILE} holds the programs it ran before \
             the crash."
        )),
    }
    Some(text)
}

enum Family {
    Memory,
    Pointer,
    Uninit,
    Race,
    Hang,
    Leak,
    Check,
}

fn family(class: &str) -> Family {
    match class {
        "null-ptr-deref"
        | "general-protection-fault"
        | "paging-request"
        | "wild-memory-access"
        | "user-memory-access"
        | "invalid-access"
        | "invalid" => Family::Pointer,
        "uninit-value" | "kernel-infoleak" | "kernel-usb-infoleak" | "kernel-network-infoleak" => {
            Family::Uninit
        }
        "data-race" | "assert-race" => Family::Race,
        "task-hung"
        | "rcu-stall"
        | "task-cant-die"
        | "soft-lockup"
        | "workqueue-lockup"
        | "possible-deadlock"
        | "inconsistent-lock-state" => Family::Hang,
        "memory-leak" | "netdevice-refcount-leak" => Family::Leak,
        _ if class.contains("out-of-bounds")
            || class.contains("use-after")
            || class.contains("free")
            || matches!(
                class,
                "memory-corruption" | "bad-usercopy" | "corrupted-list"
            ) =>
        {
            Family::Memory
        }
        _ => Family::Check,
    }
}

// ── Crash classes ────────────────────────────────────────────────────────

/// What a crash title says the crash is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashClass {
    /// The crash type, as the kernel or syzkaller names it
    /// (`slab-out-of-bounds`, `use-after-free`, `warning`, `task-hung`).
    pub class: String,
    /// The detector that reported it (`KASAN`, `KMSAN`, `lockdep`), when
    /// one did.
    pub detector: Option<&'static str>,
    /// `read` or `write`, when the title says.
    pub access: Option<&'static str>,
    /// The function the title blames (`... in widget_copy_at`).
    pub function: Option<String>,
    /// The `BHF-NNNN` rule of the bug class, when bhf has one.
    pub rule: Option<&'static str>,
    pub cwe: Vec<u32>,
    /// Set when no rule gives the severity.
    pub severity: Option<Severity>,
    /// The finding's `exception.name`: the class in upper snake case, or
    /// for a UBSAN report `UBSAN_<kind>` with bhf's UBSan kind.
    pub exception: String,
}

/// syzkaller's names for crashes of its own infrastructure, not the kernel.
const NOT_KERNEL_CRASHES: &[&str] = &[
    "SYZFAIL",
    "SYZFATAL",
    "lost connection to test machine",
    "no output from test machine",
    "test machine is not executing programs",
    "suppressed report",
    "executor failed",
];

fn upper_snake(class: &str) -> String {
    class
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn kebab(words: &[&str]) -> String {
    words
        .iter()
        .map(|word| word.trim_end_matches(':').to_ascii_lowercase())
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// The out-of-bounds CWEs: the read or write outcome, CWE-119 when neither
/// is known.
fn out_of_bounds(access: Option<&str>) -> u32 {
    match access {
        Some("write") => 787,
        Some("read") => 125,
        _ => 119,
    }
}

/// The class of a crash with title `title`; `None` for a syzkaller
/// infrastructure crash (a lost VM, an executor failure).
pub fn classify(title: &str) -> Option<CrashClass> {
    let title = title.trim();
    if NOT_KERNEL_CRASHES
        .iter()
        .any(|prefix| title.starts_with(prefix))
    {
        return None;
    }
    let (subject, function) = match title.rsplit_once(" in ") {
        Some((subject, blamed)) => (
            subject,
            blamed
                .split_whitespace()
                .next()
                .map(|f| f.trim_end_matches([',', ':']).to_owned()),
        ),
        None => (title, None),
    };
    let detector = ["KASAN", "KMSAN", "KCSAN", "KFENCE", "UBSAN"]
        .into_iter()
        .find(|d| subject.starts_with(&format!("{d}:")));
    let mut class = CrashClass {
        class: String::new(),
        detector,
        access: None,
        function,
        rule: None,
        cwe: Vec::new(),
        severity: None,
        exception: String::new(),
    };
    match detector {
        Some(name) => {
            let body = subject[name.len() + 1..].trim();
            let mut words: Vec<&str> = body.split_whitespace().collect();
            if let Some(last) = words.last() {
                match last.to_ascii_lowercase().as_str() {
                    "read" => class.access = Some("read"),
                    "write" => class.access = Some("write"),
                    _ => {}
                }
                if class.access.is_some() {
                    words.pop();
                }
            }
            class.class = kebab(&words);
            detector_class(&mut class);
        }
        None => oops_class(&mut class, subject),
    }
    if class.exception.is_empty() {
        class.exception = upper_snake(&class.class);
    }
    Some(class)
}

/// The rule, CWE and severity of a KASAN, KFENCE, KMSAN, KCSAN or UBSAN
/// report's class.
fn detector_class(class: &mut CrashClass) {
    let access = class.access;
    let (rule, cwe, severity): (Option<&'static str>, Vec<u32>, Option<Severity>) =
        match class.class.as_str() {
            "slab-out-of-bounds" | "vmalloc-out-of-bounds" | "out-of-bounds" => {
                let cwe = match access {
                    Some(_) => vec![122, out_of_bounds(access)],
                    None => vec![122],
                };
                (Some("BHF-201"), cwe, None)
            }
            "stack-out-of-bounds" => (Some("BHF-203"), vec![121], None),
            "global-out-of-bounds" => (None, vec![out_of_bounds(access)], Some(Severity::High)),
            "use-after-free" | "slab-use-after-free" => (Some("BHF-202"), vec![416], None),
            "use-after-scope" | "stack-use-after-return" => (None, vec![825], Some(Severity::High)),
            "double-free" => (Some("BHF-204"), vec![415], None),
            "invalid-free" => (None, vec![763], Some(Severity::High)),
            "null-ptr-deref" => (Some("BHF-206"), vec![476], None),
            "wild-memory-access" | "user-memory-access" | "invalid-access" | "invalid" => {
                (Some("BHF-223"), vec![119], None)
            }
            "memory-corruption" => (None, vec![787], Some(Severity::High)),
            "uninit-value" => (Some("BHF-212"), vec![457], None),
            "kernel-infoleak" | "kernel-usb-infoleak" | "kernel-network-infoleak" => {
                (None, vec![908], Some(Severity::High))
            }
            "data-race" | "assert-race" => (Some("BHF-556"), vec![362], None),
            _ if class.detector == Some("UBSAN") => {
                let kind = ubsan_kind(&class.class);
                class.exception = format!("UBSAN_{}", upper_snake(kind));
                let (rule, cwe) = match kind {
                    "out-of-bounds-access" => ("BHF-220", 129),
                    "invalid-shift" => ("BHF-215", 1335),
                    "signed-integer-overflow" | "unsigned-integer-overflow" => ("BHF-205", 190),
                    "division-by-zero" => ("BHF-222", 369),
                    "invalid-value-load" => ("BHF-217", 758),
                    "misaligned-access" => ("BHF-226", 758),
                    "insufficient-object-size" => ("BHF-227", 119),
                    "unreachable" => ("BHF-216", 758),
                    "null-pointer-dereference" => ("BHF-206", 476),
                    _ => ("BHF-213", 758),
                };
                (Some(rule), vec![cwe], None)
            }
            _ => (None, Vec::new(), Some(Severity::High)),
        };
    class.rule = rule;
    class.cwe = cwe;
    class.severity = severity;
}

/// bhf's UBSan kind for the check a kernel UBSAN title names.
fn ubsan_kind(check: &str) -> &'static str {
    match check {
        "array-index-out-of-bounds" | "index-out-of-bounds" => "out-of-bounds-access",
        "shift-out-of-bounds" => "invalid-shift",
        "signed-integer-overflow" | "integer-overflow" => "signed-integer-overflow",
        "unsigned-integer-overflow" => "unsigned-integer-overflow",
        "divide-by-zero" | "division-by-zero" | "division-overflow" => "division-by-zero",
        "invalid-load" | "load-invalid-value" => "invalid-value-load",
        "misaligned-access" | "alignment-assumption" => "misaligned-access",
        "object-size-mismatch" => "insufficient-object-size",
        "unreachable" => "unreachable",
        "null-ptr-deref" => "null-pointer-dereference",
        _ => "undefined-behavior",
    }
}

/// The class of a report no sanitizer named: an oops, a warning, a hang, a
/// lockdep or kmemleak report, from the start of its title.
fn oops_class(class: &mut CrashClass, subject: &str) {
    type Row = (
        &'static str,
        &'static str,
        Option<&'static str>,
        Option<&'static str>,
        u32,
        Option<Severity>,
    );
    // (title prefix, class, detector, rule, CWE, severity when no rule).
    const ROWS: &[Row] = &[
        (
            "general protection fault",
            "general-protection-fault",
            None,
            Some("BHF-223"),
            119,
            None,
        ),
        (
            "BUG: unable to handle kernel NULL pointer dereference",
            "null-ptr-deref",
            None,
            Some("BHF-206"),
            476,
            None,
        ),
        (
            "BUG: kernel NULL pointer dereference",
            "null-ptr-deref",
            None,
            Some("BHF-206"),
            476,
            None,
        ),
        (
            "BUG: unable to handle kernel paging request",
            "paging-request",
            None,
            Some("BHF-223"),
            119,
            None,
        ),
        (
            "BUG: unable to handle page fault",
            "paging-request",
            None,
            Some("BHF-223"),
            119,
            None,
        ),
        (
            "BUG: stack guard page was hit",
            "stack-guard-page",
            None,
            Some("BHF-207"),
            674,
            None,
        ),
        (
            "BUG: soft lockup",
            "soft-lockup",
            None,
            None,
            835,
            Some(Severity::Medium),
        ),
        (
            "BUG: workqueue lockup",
            "workqueue-lockup",
            None,
            None,
            835,
            Some(Severity::Medium),
        ),
        (
            "BUG: sleeping function called from invalid context",
            "sleep-in-atomic",
            None,
            None,
            667,
            Some(Severity::Medium),
        ),
        (
            "BUG: scheduling while atomic",
            "sleep-in-atomic",
            None,
            None,
            667,
            Some(Severity::Medium),
        ),
        (
            "BUG: bad usercopy",
            "bad-usercopy",
            None,
            None,
            119,
            Some(Severity::High),
        ),
        (
            "BUG: corrupted list",
            "corrupted-list",
            None,
            None,
            617,
            Some(Severity::High),
        ),
        (
            "BUG: Bad page state",
            "bad-page-state",
            None,
            None,
            617,
            Some(Severity::Medium),
        ),
        (
            "BUG: Bad rss-counter state",
            "bad-rss-counter",
            None,
            None,
            617,
            Some(Severity::Medium),
        ),
        (
            "BUG: spinlock",
            "spinlock-bug",
            None,
            None,
            667,
            Some(Severity::Medium),
        ),
        (
            "BUG:",
            "kernel-bug",
            None,
            None,
            617,
            Some(Severity::Medium),
        ),
        (
            "kernel BUG",
            "kernel-bug",
            None,
            None,
            617,
            Some(Severity::Medium),
        ),
        (
            "WARNING: refcount bug",
            "refcount-bug",
            None,
            None,
            911,
            Some(Severity::High),
        ),
        (
            "WARNING: locking bug",
            "locking-bug",
            Some("lockdep"),
            None,
            667,
            Some(Severity::Medium),
        ),
        (
            "WARNING: bad unlock balance",
            "bad-unlock-balance",
            Some("lockdep"),
            None,
            667,
            Some(Severity::Medium),
        ),
        (
            "WARNING: held lock freed",
            "held-lock-freed",
            Some("lockdep"),
            None,
            667,
            Some(Severity::Medium),
        ),
        (
            "WARNING: suspicious RCU usage",
            "suspicious-rcu-usage",
            Some("lockdep"),
            None,
            667,
            Some(Severity::Medium),
        ),
        (
            "WARNING: ODEBUG bug",
            "odebug-bug",
            None,
            None,
            617,
            Some(Severity::Medium),
        ),
        (
            "WARNING",
            "warning",
            None,
            None,
            617,
            Some(Severity::Medium),
        ),
        (
            "INFO: task hung",
            "task-hung",
            None,
            None,
            835,
            Some(Severity::Medium),
        ),
        (
            "INFO: rcu detected stall",
            "rcu-stall",
            None,
            None,
            835,
            Some(Severity::Medium),
        ),
        (
            "INFO: task can't die",
            "task-cant-die",
            None,
            None,
            835,
            Some(Severity::Medium),
        ),
        (
            "INFO: trying to register non-static key",
            "non-static-lock-key",
            Some("lockdep"),
            None,
            667,
            Some(Severity::Medium),
        ),
        (
            "possible deadlock",
            "possible-deadlock",
            Some("lockdep"),
            None,
            833,
            Some(Severity::Medium),
        ),
        (
            "inconsistent lock state",
            "inconsistent-lock-state",
            Some("lockdep"),
            None,
            833,
            Some(Severity::Medium),
        ),
        (
            "memory leak",
            "memory-leak",
            Some("kmemleak"),
            Some("BHF-208"),
            401,
            None,
        ),
        (
            "divide error",
            "divide-error",
            None,
            Some("BHF-222"),
            369,
            None,
        ),
        (
            "kernel panic",
            "kernel-panic",
            None,
            None,
            617,
            Some(Severity::Medium),
        ),
        (
            "unregister_netdevice: waiting for",
            "netdevice-refcount-leak",
            None,
            None,
            911,
            Some(Severity::Medium),
        ),
    ];
    match ROWS.iter().find(|(prefix, ..)| subject.starts_with(prefix)) {
        Some((_, name, detector, rule, cwe, severity)) => {
            class.class = (*name).to_owned();
            class.detector = *detector;
            class.rule = *rule;
            class.cwe = vec![*cwe];
            class.severity = *severity;
        }
        None => {
            class.class = "kernel-crash".to_owned();
            class.severity = Some(Severity::Medium);
        }
    }
}

// ── Reports ──────────────────────────────────────────────────────────────

/// One frame of a kernel stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelFrame {
    pub function: String,
    pub file: Option<String>,
    pub line: Option<u64>,
    pub inline: bool,
}

/// What a kernel report says beyond its title.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParsedReport {
    /// The crash stack, the report's own frames (the detector, printk and
    /// syscall entry) left out.
    pub stack: Vec<KernelFrame>,
    /// `read` or `write` and its size, from `Write of size 16 at addr ...`.
    pub access: Option<(&'static str, u64)>,
    pub region: Option<Region>,
    /// The allocation and free stacks of the object it hit, allocator
    /// frames left out.
    pub alloc_stack: Vec<KernelFrame>,
    pub free_stack: Vec<KernelFrame>,
}

/// The object a KASAN report says the access hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Region {
    /// `heap`, `stack` or `global`.
    pub kind: &'static str,
    pub size: Option<u64>,
    /// `after`, `before` or `inside`.
    pub relation: &'static str,
    pub distance: u64,
}

/// Files whose frames are the report's own machinery, not the crash.
const NOISE_FILES: &[&str] = &[
    "mm/kasan/",
    "mm/kmsan/",
    "mm/kfence/",
    "kernel/kcsan/",
    "lib/dump_stack.c",
    "lib/ubsan.c",
    "lib/bug.c",
    "kernel/panic.c",
    "kernel/printk/",
    "arch/x86/entry/",
    "arch/x86/kernel/dumpstack",
    "arch/x86/kernel/traps.c",
    "arch/x86/mm/fault.c",
    "arch/arm64/kernel/entry",
    "arch/arm64/kernel/stacktrace.c",
    "arch/arm64/kernel/traps.c",
    "arch/arm64/mm/fault.c",
    "kernel/entry/common.c",
];

/// Function names of the same, for frames without a file.
const NOISE_NAMES: &[&str] = &["die", "__die", "panic", "do_trap", "print_report"];

/// Function-name prefixes of the same.
const NOISE_FUNCTIONS: &[&str] = &[
    "dump_stack",
    "__dump_stack",
    "show_stack",
    "print_address_description",
    "kasan_",
    "__kasan_",
    "____kasan_",
    "__asan_",
    "check_region_inline",
    "kmsan_",
    "__msan_",
    "kcsan_",
    "__tsan_",
    "kfence_",
    "__ubsan_",
    "ubsan_",
    "__warn",
    "warn_slowpath",
    "report_bug",
    "handle_bug",
    "exc_",
    "asm_exc_",
    "do_error_trap",
    "oops_",
    "page_fault_oops",
    "kernelmode_fixup_or_oops",
    "__bad_area_nosemaphore",
    "do_user_addr_fault",
    "do_syscall_",
    "x64_sys_call",
    "__x64_sys_",
    "__ia32_sys_",
    "__arm64_sys_",
    "__se_sys_",
    "__do_sys_",
    "entry_SYSCALL",
    "el0_",
    "el1_",
    "invoke_syscall",
];

/// Allocator frames at the start of an allocation or free stack.
const ALLOCATOR_FUNCTIONS: &[&str] = &[
    "kmalloc",
    "__kmalloc",
    "kzalloc",
    "kcalloc",
    "kvmalloc",
    "kvzalloc",
    "kmem_cache_",
    "__kmem_cache_",
    "slab_",
    "__slab_",
    "____cache_alloc",
    "kfree",
    "kvfree",
    "vmalloc",
    "vzalloc",
    "__vmalloc",
    "vfree",
    "alloc_pages",
    "__alloc_pages",
    "free_pages",
    "stack_depot_",
    "krealloc",
    "kmemdup",
];

fn starts_with_any(text: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|prefix| text.starts_with(prefix))
}

/// The frame a stack line names: `func+0x1a/0x2b file.c:12 [inline]`, with
/// or without the file, `[<ffffffff8123>]` or `[module]`. A `?` frame (an
/// unreliable guess) and anything else is `None`.
fn parse_frame(line: &str) -> Option<KernelFrame> {
    let mut text = line.trim();
    if let Some(rest) = text.strip_prefix("[<") {
        text = rest.split_once(">]")?.1.trim();
    }
    if text.starts_with('?') {
        return None;
    }
    let mut parts = text.split_whitespace();
    let symbol = parts.next()?;
    let (name, offset) = match symbol.split_once('+') {
        Some((name, offset)) => (name, Some(offset)),
        None => (symbol, None),
    };
    // `widget_ioctl.cold`, `widget_copy.constprop.0`: the function's own.
    let function = name.split('.').next().unwrap_or(name);
    if function.is_empty()
        || !function
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        || function.as_bytes()[0].is_ascii_digit()
    {
        return None;
    }
    let mut frame = KernelFrame {
        function: function.to_owned(),
        file: None,
        line: None,
        inline: false,
    };
    for part in parts {
        if part == "[inline]" {
            frame.inline = true;
        } else if let Some((path, number)) = part.rsplit_once(':') {
            if let Ok(number) = number.parse::<u64>() {
                if !path.is_empty() && !path.contains('(') {
                    frame.file = Some(path.to_owned());
                    frame.line = Some(number);
                }
            }
        }
    }
    // Plain words are not a frame: a frame has an offset or a location.
    let offset_ok = offset.is_some_and(|offset| offset.starts_with("0x"));
    (offset_ok || frame.file.is_some()).then_some(frame)
}

/// Lines that end a stack.
const SECTION_HEADERS: &[&str] = &[
    "Allocated by task",
    "Freed by task",
    "The buggy address",
    "Last potentially related",
    "Second to last potentially related",
    "Modules linked in",
    "---[ end trace",
    "Kernel panic",
    "Kernel Offset",
    "irq event stamp",
    "Uninit was",
    "Local variable",
    "Bytes ",
    "Memory state around",
    "====",
    "CPU:",
    "Hardware name",
    "Reported by",
    "value changed",
];

/// The frames from `lines[start]` on, through marker and register lines,
/// up to an empty line or the next section.
fn frames_from(lines: &[&str], start: usize) -> Vec<KernelFrame> {
    let mut frames = Vec::new();
    for line in &lines[start..] {
        let trimmed = line.trim();
        if trimmed.is_empty() || starts_with_any(trimmed, SECTION_HEADERS) {
            break;
        }
        if let Some(frame) = parse_frame(trimmed) {
            if frames.len() < MAX_FRAMES {
                frames.push(frame);
            }
        }
    }
    frames
}

/// `line` with a console timestamp prefix (`[  112.45][ T5104] `) removed.
fn strip_console_prefix(line: &str) -> &str {
    let mut rest = line;
    while let Some(after) = rest.trim_start().strip_prefix('[') {
        match after.split_once(']') {
            Some((inside, tail))
                if inside
                    .trim()
                    .chars()
                    .all(|c| c.is_ascii_digit() || c == '.' || c == 'T' || c == 'C') =>
            {
                rest = tail.strip_prefix(' ').unwrap_or(tail);
            }
            _ => break,
        }
    }
    rest
}

/// What `report` says: its stack, access, region, and allocation and free
/// stacks.
pub fn parse_report(report: &str) -> ParsedReport {
    let lines: Vec<&str> = report.lines().map(strip_console_prefix).collect();
    let mut parsed = ParsedReport::default();
    let after = |header: &str| -> Option<usize> {
        lines
            .iter()
            .position(|line| line.trim_start().starts_with(header))
            .map(|at| at + 1)
    };
    let raw_stack = ["Call Trace:", "Call trace:", "backtrace:"]
        .iter()
        .find_map(|header| after(header))
        .map(|at| frames_from(&lines, at))
        .filter(|frames| !frames.is_empty())
        .or_else(|| {
            // KMSAN and KCSAN print the stack right after the report's
            // first line, with no header.
            lines
                .iter()
                .position(|line| parse_frame(line).is_some())
                .map(|at| frames_from(&lines, at))
        })
        .unwrap_or_default();
    parsed.stack = raw_stack
        .into_iter()
        .filter(|frame| !is_noise(frame))
        .collect();
    let object_stack = |header: &str| -> Vec<KernelFrame> {
        after(header)
            .map(|at| frames_from(&lines, at))
            .unwrap_or_default()
            .into_iter()
            .filter(|frame| {
                !is_noise(frame) && !starts_with_any(&frame.function, ALLOCATOR_FUNCTIONS)
            })
            .collect()
    };
    parsed.alloc_stack = object_stack("Allocated by task");
    parsed.free_stack = object_stack("Freed by task");
    for line in &lines {
        let trimmed = line.trim();
        for (word, direction) in [("Read of size ", "read"), ("Write of size ", "write")] {
            if let Some(rest) = trimmed.strip_prefix(word) {
                if let Some(size) = rest
                    .split_whitespace()
                    .next()
                    .and_then(|size| size.parse::<u64>().ok())
                {
                    parsed.access.get_or_insert((direction, size));
                }
            }
        }
    }
    parsed.region = region(&lines);
    parsed
}

fn is_noise(frame: &KernelFrame) -> bool {
    frame
        .file
        .as_deref()
        .is_some_and(|file| NOISE_FILES.iter().any(|noise| file.contains(noise)))
        || starts_with_any(&frame.function, NOISE_FUNCTIONS)
        || NOISE_NAMES.contains(&frame.function.as_str())
}

/// The region of `The buggy address is located N bytes to the right of /
/// allocated M-byte region`.
fn region(lines: &[&str]) -> Option<Region> {
    let at = lines.iter().position(|line| {
        line.trim_start()
            .starts_with("The buggy address is located")
    })?;
    let text = format!(
        "{} {}",
        lines[at].trim(),
        lines.get(at + 1).map_or("", |line| line.trim())
    );
    let rest = text.strip_prefix("The buggy address is located ")?;
    let (distance, rest) = rest.split_once(" bytes ")?;
    let distance = distance.trim().parse::<u64>().ok()?;
    let relation = if rest.starts_with("to the right of") {
        "after"
    } else if rest.starts_with("to the left of") {
        "before"
    } else if rest.starts_with("inside of") {
        "inside"
    } else {
        return None;
    };
    let size = rest
        .split_whitespace()
        .find_map(|word| word.strip_suffix("-byte"))
        .and_then(|size| size.parse::<u64>().ok());
    let report = lines.join("\n");
    let kind = if report.contains("belongs to the variable") {
        "global"
    } else if report.contains("stack of task") || report.contains("belongs to stack") {
        "stack"
    } else {
        "heap"
    };
    Some(Region {
        kind,
        size,
        relation,
        distance,
    })
}

// ── Console reports ──────────────────────────────────────────────────────

/// A kernel report found in a console log: the title syzkaller would give
/// it, its class, its text and what it says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleReport {
    pub title: String,
    pub class: CrashClass,
    /// The report's lines, from its first to its last, console timestamps
    /// left as they were.
    pub report: String,
    pub parsed: ParsedReport,
}

/// Most lines of one console report.
const MAX_REPORT_LINES: usize = 1000;

/// A panic of the guest's own `/init` (bhf's executor), not of the kernel.
const NOT_KERNEL_PANICS: &[&str] = &["Attempted to kill init", "No working init found"];

/// Whether a console line (its timestamp removed) starts a kernel report.
fn starts_report(text: &str) -> bool {
    const STARTS: &[&str] = &[
        "BUG: ",
        "watchdog: BUG: ",
        "UBSAN: ",
        "WARNING: ",
        "general protection fault",
        "Oops: general protection fault",
        "Oops: divide error",
        "divide error: ",
        "kernel BUG at ",
        "INFO: task ",
        "INFO: rcu_",
        "rcu: INFO: rcu_",
        "unregister_netdevice: waiting for",
        "Kernel panic - not syncing:",
    ];
    starts_with_any(text, STARTS)
        && !(text.starts_with("INFO: task ") && !text.contains(" blocked for more than "))
        && !((text.starts_with("INFO: rcu_") || text.starts_with("rcu: INFO: rcu_"))
            && !text.contains("detected stall"))
}

/// The function a symbol names: `widget_ioctl+0x46c/0x4a0` is
/// `widget_ioctl`, `f.constprop.0` is `f`.
fn symbol_function(symbol: &str) -> Option<String> {
    let name = symbol.split('+').next()?.split('.').next()?;
    (!name.is_empty()
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !name.as_bytes()[0].is_ascii_digit())
    .then(|| name.to_owned())
}

/// The function the report's kernel-mode `RIP:` (x86) or `pc :` (arm64)
/// line names.
fn faulting_function(lines: &[&str]) -> Option<String> {
    lines.iter().find_map(|line| {
        let text = line.trim();
        let symbol = text
            .strip_prefix("RIP: 0010:")
            .or_else(|| text.strip_prefix("pc : "))?;
        let symbol = symbol.split_whitespace().next()?;
        symbol.contains("+0x").then(|| symbol_function(symbol))?
    })
}

/// The title syzkaller gives the report whose lines are `lines` (its
/// header first), with `first` the first frame of its stack; `None` for a
/// panic of the guest's `/init`.
fn console_title(lines: &[&str], first: Option<&str>) -> Option<String> {
    let header = lines[0].trim();
    let header = header.strip_prefix("watchdog: ").unwrap_or(header);
    let header = header.strip_prefix("Oops: ").unwrap_or(header);
    let rip = faulting_function(lines);
    let blamed = rip.as_deref().or(first);
    let in_blamed = |head: &str| match blamed {
        Some(function) => format!("{head} in {function}"),
        None => head.to_owned(),
    };
    for detector in ["KASAN", "KFENCE", "KMSAN", "KCSAN"] {
        let Some(body) = header.strip_prefix(&format!("BUG: {detector}: ")) else {
            continue;
        };
        let (class, location) = body.split_once(" in ").unwrap_or((body, ""));
        let location = location
            .split(" / ")
            .filter_map(|side| side.split_whitespace().next())
            .filter_map(symbol_function)
            .collect::<Vec<_>>()
            .join(" / ");
        let access = (detector == "KASAN")
            .then(|| {
                lines.iter().find_map(|line| {
                    let text = line.trim();
                    if text.starts_with("Read of size ") {
                        Some("Read")
                    } else if text.starts_with("Write of size ") {
                        Some("Write")
                    } else {
                        None
                    }
                })
            })
            .flatten();
        let head = match access {
            Some(access) => format!("{detector}: {} {access}", class.trim()),
            None => format!("{detector}: {}", class.trim()),
        };
        return Some(if location.is_empty() {
            head
        } else {
            format!("{head} in {location}")
        });
    }
    if let Some(body) = header.strip_prefix("UBSAN: ") {
        let check = body.split(" in ").next().unwrap_or(body).trim();
        return Some(match first {
            Some(function) => format!("UBSAN: {check} in {function}"),
            None => header.to_owned(),
        });
    }
    if let Some(message) = header.strip_prefix("Kernel panic - not syncing: ") {
        if NOT_KERNEL_PANICS
            .iter()
            .any(|prefix| message.starts_with(prefix))
        {
            return None;
        }
        return Some(format!("kernel panic: {}", message.trim()));
    }
    if let Some(rest) = header.strip_prefix("WARNING: CPU: ") {
        // `WARNING: CPU: 0 PID: 51 at FILE:LINE FUNC+0x19b/0x1e0 [module]`.
        let function = rest
            .split_once(" at ")
            .and_then(|(_, at)| at.split_whitespace().nth(1))
            .and_then(symbol_function);
        return Some(match function.as_deref().or(blamed) {
            Some(function) => format!("WARNING in {function}"),
            None => "WARNING".to_owned(),
        });
    }
    if header.starts_with("WARNING: possible circular locking dependency")
        || header.starts_with("WARNING: possible recursive locking")
    {
        return Some(in_blamed("possible deadlock"));
    }
    if let Some(rest) = header.strip_prefix("WARNING: ") {
        let what = rest
            .trim_end_matches('!')
            .trim_end_matches(" detected")
            .trim();
        return Some(in_blamed(&format!("WARNING: {what}")));
    }
    if header.starts_with("INFO: task ") {
        return Some(in_blamed("INFO: task hung"));
    }
    if header.contains("detected stall") {
        return Some(in_blamed("INFO: rcu detected stall"));
    }
    if header.starts_with("general protection fault") {
        return Some(in_blamed("general protection fault"));
    }
    if header.starts_with("divide error") {
        return Some(in_blamed("divide error"));
    }
    if header.starts_with("kernel BUG at ") {
        return Some(in_blamed("kernel BUG"));
    }
    if header.starts_with("unregister_netdevice: ") {
        return Some(header.to_owned());
    }
    // `BUG: kernel NULL pointer dereference, address: 0000000000000008`,
    // `BUG: soft lockup - CPU#0 stuck for 22s! [...]`, `BUG: sleeping
    // function called from invalid context at FILE:LINE`: what it is, in
    // the blamed function.
    let what = header
        .split([',', '!'])
        .next()
        .unwrap_or(header)
        .split(" - ")
        .next()
        .unwrap_or(header);
    let what = what.split(" at ").next().unwrap_or(what);
    let what = match what.split_once(": ") {
        Some(("BUG", rest)) => match rest.split_once(": ") {
            // `BUG: scheduling while atomic: comm/1/0x2`
            Some((kind, _)) => format!("BUG: {kind}"),
            None => format!("BUG: {rest}"),
        },
        _ => what.to_owned(),
    };
    let what = what
        .strip_suffix(" for address")
        .map(str::to_owned)
        .unwrap_or(what);
    Some(in_blamed(what.trim()))
}

/// The first kernel report in `console` (a guest's serial console, or a
/// part of it), as syzkaller's report parser reads one: its title, class,
/// text and stack. `None` when it holds none, or only a panic of the
/// guest's own `/init`.
pub fn console_report(console: &str) -> Option<ConsoleReport> {
    let raw: Vec<&str> = console
        .lines()
        .map(|line| line.trim_end_matches('\r'))
        .collect();
    let lines: Vec<&str> = raw.iter().map(|line| strip_console_prefix(line)).collect();
    let start = lines
        .iter()
        .position(|line| starts_report(line.trim_start()))?;
    let panic = lines[start].trim_start().starts_with("Kernel panic");
    // A sanitizer frames its report with `====` lines; an oops or a warning
    // ends with its trace, or at the panic it causes.
    let framed = start > 0 && lines[start - 1].trim().starts_with("====");
    let mut end = (start + MAX_REPORT_LINES).min(lines.len());
    for (at, line) in lines.iter().enumerate().take(end).skip(start + 1) {
        let text = line.trim();
        if framed && text.starts_with("====") || text.starts_with("---[ end trace") {
            end = at + 1;
            break;
        }
        if (!panic && text.starts_with("Kernel panic - not syncing"))
            || text.starts_with("Kernel Offset:")
            || text.starts_with("Rebooting in")
        {
            end = at;
            break;
        }
    }
    let body = &lines[start..end];
    let text = body.join("\n");
    let mut parsed = parse_report(&text);
    let title = console_title(
        body,
        parsed.stack.first().map(|frame| frame.function.as_str()),
    )?;
    let mut class = classify(&title)?;
    // With KASAN a NULL dereference faults on its shadow address: the
    // report says which it was.
    if class.class == "general-protection-fault" && text.contains("KASAN: null-ptr-deref in range")
    {
        let function = class.function.clone();
        class = classify("BUG: kernel NULL pointer dereference")?;
        class.function = function;
    }
    // The blamed function is the stack's first frame: an oops' RIP, which
    // its call trace leaves out, else the frames above the one the title
    // names are the detector's own.
    match class.function.as_deref() {
        Some(function) if class.detector.is_none() => {
            if parsed.stack.first().map(|frame| frame.function.as_str()) != Some(function) {
                parsed.stack.insert(
                    0,
                    KernelFrame {
                        function: function.to_owned(),
                        file: None,
                        line: None,
                        inline: false,
                    },
                );
                parsed.stack.truncate(MAX_FRAMES);
            }
        }
        Some(function) => {
            if let Some(at) = parsed
                .stack
                .iter()
                .position(|frame| frame.function == function)
            {
                parsed.stack.drain(..at);
            }
        }
        None => {}
    }
    Some(ConsoleReport {
        title,
        class,
        report: raw[start..end].join("\n") + "\n",
        parsed,
    })
}

// ── Crash directories ────────────────────────────────────────────────────

/// One syzkaller crash directory, read.
#[derive(Debug, Clone)]
pub struct KernelCrash {
    pub dir: PathBuf,
    pub title: String,
    pub class: CrashClass,
    /// The report file read (`report0`, `repro.report`), and its text.
    pub report: Option<(String, String)>,
    pub parsed: ParsedReport,
    /// `log0`, the console output of the first occurrence.
    pub console: Option<String>,
    /// Occurrences syz-manager kept (`log0`, `log1`, ...).
    pub occurrences: usize,
    pub syz_repro: Option<String>,
    pub c_repro: Option<String>,
    /// The options line syz-repro wrote atop `repro.prog`.
    pub repro_options: Option<Value>,
    /// `tag0`: the kernel the manager ran.
    pub kernel_tag: Option<String>,
}

/// A regular file's text, at most `cap` bytes; `None` when it is missing
/// or not a regular file (a symlink is not followed).
fn read_capped(path: &Path, cap: u64) -> Option<String> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .ok()?
        .take(cap)
        .read_to_end(&mut bytes)
        .ok()?;
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if meta.len() > cap {
        text.push_str(&format!("\n[truncated {} bytes]\n", meta.len() - cap));
    }
    Some(text)
}

/// The crash directories `path` holds: `path` itself when it is one (it
/// has a `description`), else the crash directories under it or under its
/// `crashes/` (a syz-manager workdir), sorted.
pub fn crash_dirs(path: &Path) -> Result<Vec<PathBuf>, ResultsError> {
    if path.join("description").is_file() {
        return Ok(vec![path.to_path_buf()]);
    }
    let parent = if path.join("crashes").is_dir() {
        path.join("crashes")
    } else {
        path.to_path_buf()
    };
    let entries = fs::read_dir(&parent).map_err(crate::io_err(&parent))?;
    let mut dirs: Vec<PathBuf> = entries
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| entry.path())
        .filter(|dir| dir.join("description").is_file())
        .take(MAX_CRASH_DIRS)
        .collect();
    dirs.sort();
    Ok(dirs)
}

/// The options syz-repro found, from the comment atop its program, as an
/// object keyed as syzkaller's JSON form keys them (`threaded`, `repeat`,
/// `repeat_times`, `procs`, `sandbox`, `sandbox_arg`, ...). syz-manager
/// writes Go's `%+v` of them (`# {Threaded:true Repeat:true ... Procs:4
/// Sandbox:namespace ...}`), older versions with fewer fields; the dashboard
/// serves the JSON form (`#{"threaded":true,...}`).
fn repro_options(program: &str) -> Option<Value> {
    program
        .lines()
        .take_while(|line| line.starts_with('#'))
        .find_map(|line| {
            let options = line[1..].trim();
            serde_json::from_str::<Value>(options)
                .ok()
                .filter(Value::is_object)
                .or_else(|| go_options(options))
        })
}

/// Each csource.Options field Go prints, and the JSON key it has (the
/// names older syz-manager versions printed too).
const GO_OPTION_KEYS: &[(&str, &str)] = &[
    ("Threaded", "threaded"),
    ("Repeat", "repeat"),
    ("RepeatTimes", "repeat_times"),
    ("Procs", "procs"),
    ("Slowdown", "slowdown"),
    ("Sandbox", "sandbox"),
    ("SandboxArg", "sandbox_arg"),
    ("Leak", "leak"),
    ("NetInjection", "tun"),
    ("EnableTun", "tun"),
    ("NetDevices", "netdev"),
    ("NetReset", "resetnet"),
    ("Cgroups", "cgroups"),
    ("EnableCgroups", "cgroups"),
    ("BinfmtMisc", "binfmt_misc"),
    ("CloseFDs", "close_fds"),
    ("KCSAN", "kcsan"),
    ("DevlinkPCI", "devlinkpci"),
    ("NicVF", "nicvf"),
    ("USB", "usb"),
    ("VhciInjection", "vhci"),
    ("Wifi", "wifi"),
    ("IEEE802154", "ieee802154"),
    ("Sysctl", "sysctl"),
    ("Swap", "swap"),
    ("UseTmpDir", "tmpdir"),
    ("HandleSegv", "segv"),
    ("Trace", "trace"),
    ("CallComments", "callcomments"),
    ("Collide", "collide"),
    ("Fault", "fault"),
    ("FaultCall", "fault_call"),
    ("FaultNth", "fault_nth"),
];

/// Go's `%+v` of csource.Options, `{Threaded:true ... Sandbox:namespace
/// ... LegacyOptions:{Collide:false ...}}`, as the JSON form's object; the
/// fields it does not know are left out. `None` unless it is that form
/// with a procs count.
fn go_options(text: &str) -> Option<Value> {
    let inner = text.strip_prefix('{')?.strip_suffix('}')?;
    // The embedded struct prints its own braces; its fields are the
    // options' own.
    let inner = inner.replace("LegacyOptions:{", "").replace('}', "");
    let mut options = serde_json::Map::new();
    for token in inner.split_whitespace() {
        // An empty string prints as nothing: `Sandbox: SandboxArg:0`.
        let (field, value) = token.split_once(':')?;
        let Some((_, key)) = GO_OPTION_KEYS.iter().find(|(name, _)| *name == field) else {
            continue;
        };
        let value = match value {
            "true" => json!(true),
            "false" => json!(false),
            _ => value
                .parse::<i64>()
                .map(|number| json!(number))
                .unwrap_or_else(|_| json!(value)),
        };
        options.insert((*key).to_owned(), value);
    }
    options
        .contains_key("procs")
        .then_some(Value::Object(options))
}

/// Read the crash directory `dir`. Errs, with the reason, when it holds no
/// title or a syzkaller infrastructure crash.
pub fn read_crash_dir(dir: &Path) -> Result<KernelCrash, String> {
    let title = read_capped(&dir.join("description"), MAX_TITLE_BYTES)
        .and_then(|text| text.lines().next().map(|line| line.trim().to_owned()))
        .filter(|title| !title.is_empty())
        .ok_or_else(|| "no crash title (description is missing or empty)".to_owned())?;
    let class = classify(&title).ok_or_else(|| {
        format!("`{title}` is a crash of syzkaller's test machine, not of the kernel")
    })?;
    let report = ["report0", "repro.report"].iter().find_map(|name| {
        read_capped(&dir.join(name), MAX_FILE_BYTES)
            .filter(|text| !text.trim().is_empty())
            .map(|text| ((*name).to_owned(), text))
    });
    let console = read_capped(&dir.join("log0"), MAX_FILE_BYTES);
    let parsed = report
        .as_ref()
        .map(|(_, text)| parse_report(text))
        .or_else(|| console.as_deref().map(parse_report))
        .unwrap_or_default();
    let occurrences = (0..100)
        .take_while(|n| dir.join(format!("log{n}")).is_file())
        .count();
    let syz_repro =
        read_capped(&dir.join("repro.prog"), MAX_FILE_BYTES).filter(|text| !text.trim().is_empty());
    let c_repro = read_capped(&dir.join("repro.cprog"), MAX_FILE_BYTES)
        .filter(|text| !text.trim().is_empty());
    let repro_options = syz_repro.as_deref().and_then(repro_options);
    let kernel_tag = read_capped(&dir.join("tag0"), MAX_TITLE_BYTES)
        .and_then(|text| text.lines().next().map(|line| line.trim().to_owned()))
        .filter(|tag| !tag.is_empty());
    Ok(KernelCrash {
        dir: dir.to_path_buf(),
        title,
        class,
        report,
        parsed,
        console,
        occurrences,
        syz_repro,
        c_repro,
        repro_options,
        kernel_tag,
    })
}

fn frame_json(frame: &KernelFrame) -> Value {
    json!({
        "function": frame.function,
        "file": frame.file,
        "line": frame.line,
        "inline": frame.inline,
    })
}

fn sha256_hex(text: &str) -> String {
    let digest = Sha256::digest(text.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// What a kernel crash's `finding.json` says about the crash itself: its
/// identity, class, rule and CWE, exception, access, location.
fn crash_fields(id: &str, title: &str, class: &CrashClass, parsed: &ParsedReport) -> Value {
    let sanitizer = class.detector.map(str::to_ascii_lowercase);
    let access = parsed
        .access
        .map(|(direction, size)| (direction, Some(size)))
        .or_else(|| class.access.map(|direction| (direction, None)));
    let mut exception = json!({
        "name": class.exception,
        "message": title,
        "sanitizer": sanitizer,
        "stack": parsed.stack.iter().map(frame_json).collect::<Vec<_>>(),
    });
    if let Some((direction, size)) = access {
        let region = parsed.region.as_ref().map(|region| {
            let offset = match region.relation {
                "after" => region
                    .size
                    .and_then(|size| size.checked_add(region.distance))
                    .and_then(|offset| i64::try_from(offset).ok()),
                "before" => i64::try_from(region.distance).ok().map(|d| -d),
                _ => i64::try_from(region.distance).ok(),
            };
            json!({
                "kind": region.kind,
                "size": region.size,
                "offset": offset,
                "relation": region.relation,
                "distance": region.distance,
            })
        });
        exception["access"] = json!({
            "direction": direction,
            "size": size,
            "region": region,
            "alloc_stack": parsed.alloc_stack.iter().map(frame_json).collect::<Vec<_>>(),
            "free_stack": parsed.free_stack.iter().map(frame_json).collect::<Vec<_>>(),
        });
    }
    let key = sha256_hex(&format!("syzkaller:{title}"));
    let mut record = json!({
        "id": id,
        "kind": KERNEL_CRASH_KIND,
        "classification": "unhandled",
        "message": title,
        "signature": &key[..16],
        "cluster_key": &key[..16],
        "cluster_key_full": key,
        "cluster_normalized_frames": parsed
            .stack
            .iter()
            .take(3)
            .map(|frame| frame.function.clone())
            .collect::<Vec<_>>(),
        "cluster_fallback": false,
        "cwe": class.cwe.iter().map(|cwe| format!("CWE-{cwe}")).collect::<Vec<_>>(),
        "exception": exception,
    });
    if let Some(rule) = class.rule {
        record["rule_id"] = json!(rule);
    }
    if let Some(severity) = class.severity {
        record["severity"] = json!(severity.as_str());
    }
    if let Some(top) = parsed.stack.first() {
        if let Some(file) = &top.file {
            record["target"] = json!({
                "subprogram": top.function,
                "source_path": file,
                "line": top.line,
            });
        }
    }
    record
}

/// The `finding.json` of `crash` under `id`, before the v1 envelope.
pub fn finding_record(id: &str, crash: &KernelCrash) -> Value {
    let class = &crash.class;
    let reproducer = (crash.syz_repro.is_some() || crash.c_repro.is_some()).then(|| {
        json!({
            "syz": crash.syz_repro.as_ref().map(|_| SYZ_REPRO_FILE),
            "c": crash.c_repro.as_ref().map(|_| C_REPRO_FILE),
            "options": crash.repro_options,
        })
    });
    let mut record = crash_fields(id, &crash.title, class, &crash.parsed);
    record["confidence"] = json!(if reproducer.is_some() {
        "high"
    } else {
        "medium"
    });
    record["fidelity_caveat"] = json!(
        "imported from syzkaller: the kernel ran in syzkaller's test VM, \
         and bhf did not run or reproduce the crash"
    );
    record["kernel"] = json!({
        "schema": KERNEL_BLOCK_SCHEMA,
        "tool": "syzkaller",
        "title": crash.title,
        "class": class.class,
        "detector": class.detector,
        "access": class.access,
        "function": class.function,
        "crash_dir": crash
            .dir
            .file_name()
            .map(|name| name.to_string_lossy().into_owned()),
        "occurrences": crash.occurrences,
        "report": crash.report.as_ref().map(|(name, _)| name.clone()),
        "kernel_tag": crash.kernel_tag,
        "reproducer": reproducer,
    });
    record["paths"] = json!({
        "sanitizer_log": crash.report.as_ref().map(|_| REPORT_FILE),
        "console_log": crash.console.as_ref().map(|_| CONSOLE_FILE),
        "repro_syz": crash.syz_repro.as_ref().map(|_| SYZ_REPRO_FILE),
        "repro_c": crash.c_repro.as_ref().map(|_| C_REPRO_FILE),
        "finding": "finding.json",
    });
    record
}

// ── Guest crashes ────────────────────────────────────────────────────────

/// A kernel crash `bhf kernel fuzz` found in its guest.
#[derive(Debug, Clone, Copy)]
pub struct GuestCrash<'a> {
    pub report: &'a ConsoleReport,
    /// The console from the program's start.
    pub console: &'a str,
    /// The program, as the executor runs it.
    pub program: &'a [u8],
    /// It, decoded: one call per line, and as JSON.
    pub program_text: &'a str,
    pub decoded: &'a Value,
    /// A C program making the same calls.
    pub c_repro: &'a str,
    /// How the guest was booted, which `bhf kernel replay` boots again.
    pub guest: &'a Value,
    /// The program crashed a freshly booted guest again, with the same title.
    pub reproduced: bool,
    /// Why it is not known whether it did: the confirming run has not run
    /// yet ([`CONFIRMING`]), or could not be made.
    pub unconfirmed: Option<&'a str>,
    /// The guest's `uname -r`.
    pub release: Option<&'a str>,
}

/// A guest crash's `kernel.unconfirmed` until its confirming run is made:
/// what stays when bhf stops during it.
pub const CONFIRMING: &str =
    "the confirming run of its program alone in a freshly booted guest did not finish";

/// The `finding.json` of `crash` under `id`, before the v1 envelope.
pub fn guest_finding_record(id: &str, crash: &GuestCrash<'_>) -> Value {
    let report = crash.report;
    let class = &report.class;
    let mut record = crash_fields(id, &report.title, class, &report.parsed);
    record["confidence"] = json!(if crash.reproduced { "high" } else { "medium" });
    record["fidelity_caveat"] = json!(
        "found by bhf kernel fuzz in a qemu-system guest, where other programs ran before \
         it in the same boot"
    );
    record["kernel"] = json!({
        "schema": KERNEL_BLOCK_SCHEMA,
        "tool": GUEST_TOOL,
        "title": report.title,
        "class": class.class,
        "detector": class.detector,
        "access": class.access,
        "function": class.function,
        "occurrences": 1,
        "report": "console",
        "release": crash.release,
        "reproduced": crash.reproduced,
        "unconfirmed": crash.unconfirmed,
        "guest": crash.guest,
        "reproducer": {
            "program": TESTCASE_FILE,
            "c": C_REPRO_FILE,
        },
    });
    if crash.unconfirmed.is_none() {
        if let Some(kernel) = record["kernel"].as_object_mut() {
            kernel.remove("unconfirmed");
        }
    }
    record["paths"] = json!({
        "testcase": TESTCASE_FILE,
        "decoded": DECODED_FILE,
        "program": PROGRAM_FILE,
        "sanitizer_log": REPORT_FILE,
        "console_log": CONSOLE_FILE,
        "repro_syz": null,
        "repro_c": C_REPRO_FILE,
        "finding": "finding.json",
    });
    record
}

/// Record the confirming run of the guest crash `id` under `<work_dir>`:
/// whether its program alone made the report again in a freshly booted
/// guest (`kernel.reproduced`, and confidence `high` when it did), or why
/// that run could not be made (`kernel.unconfirmed`).
pub fn confirm_guest_crash(
    work_dir: &Path,
    id: &str,
    reproduced: bool,
    unconfirmed: Option<&str>,
) -> Result<(), ResultsError> {
    let path = corpus::layout::findings_dir(work_dir)
        .join(id)
        .join("finding.json");
    let mut record = read_capped(&path, MAX_FILE_BYTES)
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .filter(is_guest_crash)
        .ok_or_else(|| ResultsError::Io {
            path: path.clone(),
            source: std::io::Error::other("no finding.json of a guest crash"),
        })?;
    record["confidence"] = json!(if reproduced { "high" } else { "medium" });
    let kernel = record["kernel"]
        .as_object_mut()
        .expect("a guest crash has a kernel block");
    kernel.insert("reproduced".to_owned(), json!(reproduced));
    match unconfirmed {
        Some(why) => kernel.insert("unconfirmed".to_owned(), json!(why)),
        None => kernel.remove("unconfirmed"),
    };
    let bytes = serde_json::to_vec_pretty(&record).map_err(|source| ResultsError::Json {
        path: path.clone(),
        source,
    })?;
    crate::rebuild::write_atomic(&path, &bytes)
}

/// Write `crash` as a finding under `<work_dir>/results/findings/`, or,
/// when the guest lane found its title before, count it on that finding,
/// whose program and evidence stay.
pub fn record_guest_crash(
    work_dir: &Path,
    crash: &GuestCrash<'_>,
) -> Result<Imported, ResultsError> {
    let findings_dir = corpus::layout::findings_dir(work_dir);
    fs::create_dir_all(&findings_dir).map_err(crate::io_err(&findings_dir))?;
    let title = &crash.report.title;
    let finding_json = |id: &str| findings_dir.join(id).join("finding.json");
    let write_json = |path: &Path, record: &Value| -> Result<(), ResultsError> {
        let bytes = serde_json::to_vec_pretty(record).map_err(|source| ResultsError::Json {
            path: path.to_path_buf(),
            source,
        })?;
        crate::rebuild::write_atomic(path, &bytes)
    };
    if let Some((id, _)) = earlier_kernel_findings(&findings_dir, true).remove(title) {
        let path = finding_json(&id);
        let mut record = read_capped(&path, MAX_FILE_BYTES)
            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
            .ok_or_else(|| ResultsError::Io {
                path: path.clone(),
                source: std::io::Error::other("unreadable finding.json"),
            })?;
        let occurrences = record
            .pointer("/kernel/occurrences")
            .and_then(Value::as_u64)
            .unwrap_or(1);
        record["kernel"]["occurrences"] = json!(occurrences + 1);
        record["last_seen"] = json!(corpus::finding::now_rfc3339());
        write_json(&path, &record)?;
        return Ok(Imported {
            id,
            title: title.clone(),
            class: crash.report.class.class.clone(),
            reproducer: Some(TESTCASE_FILE),
            updated: true,
        });
    }
    let mut allocator = corpus::layout::FamilyAllocator::new(&findings_dir, ID_PREFIX)
        .map_err(crate::io_err(&findings_dir))?;
    let (id, dir) = allocator
        .create_with_suffix(&sha256_hex(title)[..8])
        .map_err(crate::io_err(&findings_dir))?;
    let mut record = guest_finding_record(&id, crash);
    corpus::finding::stamp_v1(&mut record, corpus::finding::finding_kind::FUZZ);
    crate::rebuild::write_atomic(&dir.join(TESTCASE_FILE), crash.program)?;
    write_evidence(&dir, REPORT_FILE, Some(&crash.report.report))?;
    write_evidence(&dir, CONSOLE_FILE, Some(crash.console))?;
    write_evidence(&dir, PROGRAM_FILE, Some(crash.program_text))?;
    write_evidence(&dir, C_REPRO_FILE, Some(crash.c_repro))?;
    let decoded =
        serde_json::to_string_pretty(crash.decoded).map_err(|source| ResultsError::Json {
            path: dir.join(DECODED_FILE),
            source,
        })?;
    write_evidence(&dir, DECODED_FILE, Some(&decoded))?;
    write_json(&dir.join("finding.json"), &record)?;
    Ok(Imported {
        id,
        title: title.clone(),
        class: crash.report.class.class.clone(),
        reproducer: Some(TESTCASE_FILE),
        updated: false,
    })
}

// ── Import ───────────────────────────────────────────────────────────────

/// One crash [`import`] wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Imported {
    pub id: String,
    pub title: String,
    pub class: String,
    /// The reproducer file the finding holds (`repro.c`, `repro.syz`).
    pub reproducer: Option<&'static str>,
    /// An earlier import of the same crash was updated.
    pub updated: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportSummary {
    pub imported: Vec<Imported>,
    /// Crash directories left out, and why.
    pub skipped: Vec<(PathBuf, String)>,
}

/// The kernel crashes earlier imports wrote: title -> (id, `created_at`).
fn earlier_imports(findings_dir: &Path) -> HashMap<String, (String, Option<Value>)> {
    earlier_kernel_findings(findings_dir, false)
}

/// The kernel crashes of `findings_dir`, the guest lane's or syzkaller's
/// imports: title -> (id, `created_at`).
fn earlier_kernel_findings(
    findings_dir: &Path,
    guest: bool,
) -> HashMap<String, (String, Option<Value>)> {
    let mut found = HashMap::new();
    let Ok(entries) = fs::read_dir(findings_dir) else {
        return found;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with(ID_PREFIX) || !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let Some(raw) = read_capped(&entry.path().join("finding.json"), MAX_FILE_BYTES)
            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
            .filter(|raw| is_kernel_crash(raw) && is_guest_crash(raw) == guest)
        else {
            continue;
        };
        if let Some(title) = raw.pointer("/kernel/title").and_then(Value::as_str) {
            found
                .entry(title.to_owned())
                .or_insert((name, raw.get("created_at").cloned()));
        }
    }
    found
}

/// Write `text` as `name` in `dir`, or remove an earlier `name` when there
/// is none.
fn write_evidence(dir: &Path, name: &str, text: Option<&str>) -> Result<(), ResultsError> {
    let path = dir.join(name);
    match text {
        Some(text) => crate::rebuild::write_atomic(&path, text.as_bytes()),
        None => match fs::remove_file(&path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(ResultsError::Io {
                path,
                source: error,
            }),
            _ => Ok(()),
        },
    }
}

/// Import each of `dirs` (crash directories, see [`crash_dirs`]) into
/// `<work_dir>/results/findings/`.
pub fn import(work_dir: &Path, dirs: &[PathBuf]) -> Result<ImportSummary, ResultsError> {
    let findings_dir = corpus::layout::findings_dir(work_dir);
    fs::create_dir_all(&findings_dir).map_err(crate::io_err(&findings_dir))?;
    let mut allocator = corpus::layout::FamilyAllocator::new(&findings_dir, ID_PREFIX)
        .map_err(crate::io_err(&findings_dir))?;
    let mut earlier = earlier_imports(&findings_dir);
    let mut summary = ImportSummary::default();
    for dir in dirs {
        let crash = match read_crash_dir(dir) {
            Ok(crash) => crash,
            Err(reason) => {
                summary.skipped.push((dir.clone(), reason));
                continue;
            }
        };
        let existing = earlier.get(&crash.title).cloned();
        let updated = existing.is_some();
        let (id, finding_dir, created_at) = match existing {
            Some((id, created)) => (id.clone(), findings_dir.join(&id), created),
            None => {
                let suffix = &sha256_hex(&crash.title)[..8];
                let (id, dir) = allocator
                    .create_with_suffix(suffix)
                    .map_err(crate::io_err(&findings_dir))?;
                (id, dir, None)
            }
        };
        let mut record = finding_record(&id, &crash);
        if let Some(created_at) = created_at {
            record["created_at"] = created_at;
            record["last_seen"] = json!(corpus::finding::now_rfc3339());
        }
        corpus::finding::stamp_v1(&mut record, corpus::finding::finding_kind::FUZZ);
        write_evidence(
            &finding_dir,
            REPORT_FILE,
            crash.report.as_ref().map(|(_, text)| text.as_str()),
        )?;
        write_evidence(&finding_dir, CONSOLE_FILE, crash.console.as_deref())?;
        write_evidence(&finding_dir, SYZ_REPRO_FILE, crash.syz_repro.as_deref())?;
        write_evidence(&finding_dir, C_REPRO_FILE, crash.c_repro.as_deref())?;
        let bytes = serde_json::to_vec_pretty(&record).map_err(|source| ResultsError::Json {
            path: finding_dir.join("finding.json"),
            source,
        })?;
        crate::rebuild::write_atomic(&finding_dir.join("finding.json"), &bytes)?;
        earlier
            .entry(crash.title.clone())
            .or_insert((id.clone(), record.get("created_at").cloned()));
        summary.imported.push(Imported {
            id,
            title: crash.title.clone(),
            class: crash.class.class.clone(),
            reproducer: if crash.c_repro.is_some() {
                Some(C_REPRO_FILE)
            } else if crash.syz_repro.is_some() {
                Some(SYZ_REPRO_FILE)
            } else {
                None
            },
            updated,
        });
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../tests/fixtures/kernel_widget/crashes/330f1cd22e8dec39433794b0af2230020ad97506",
        )
    }

    /// A console log recorded from a guest, `tests/fixtures/kernel_guest/console/`.
    fn recorded_console(name: &str) -> String {
        fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/kernel_guest/console")
                .join(name),
        )
        .unwrap()
    }

    #[test]
    fn recorded_console_logs_parse_into_classified_reports() {
        struct Expected {
            log: &'static str,
            title: &'static str,
            class: &'static str,
            exception: &'static str,
            detector: Option<&'static str>,
            rule: Option<&'static str>,
            cwe: &'static [u32],
            access: Option<(&'static str, u64)>,
            top: &'static str,
            last_line: &'static str,
        }
        let cases = [
            Expected {
                log: "kasan-slab-out-of-bounds.log",
                title: "KASAN: slab-out-of-bounds Write in widget_ioctl",
                class: "slab-out-of-bounds",
                exception: "SLAB_OUT_OF_BOUNDS",
                detector: Some("KASAN"),
                rule: Some("BHF-201"),
                cwe: &[122, 787],
                access: Some(("write", 16)),
                top: "widget_ioctl",
                last_line: "====",
            },
            Expected {
                log: "kasan-slab-use-after-free.log",
                title: "KASAN: slab-use-after-free Read in bugs_ioctl",
                class: "slab-use-after-free",
                exception: "SLAB_USE_AFTER_FREE",
                detector: Some("KASAN"),
                rule: Some("BHF-202"),
                cwe: &[416],
                access: Some(("read", 8)),
                top: "bugs_ioctl",
                last_line: "====",
            },
            Expected {
                log: "kasan-double-free.log",
                title: "KASAN: double-free in bugs_ioctl",
                class: "double-free",
                exception: "DOUBLE_FREE",
                detector: Some("KASAN"),
                rule: Some("BHF-204"),
                cwe: &[415],
                access: None,
                top: "bugs_ioctl",
                last_line: "====",
            },
            Expected {
                log: "kasan-null-ptr-deref.log",
                title: "general protection fault in bugs_ioctl",
                class: "null-ptr-deref",
                exception: "NULL_PTR_DEREF",
                detector: None,
                rule: Some("BHF-206"),
                cwe: &[476],
                access: None,
                top: "bugs_ioctl",
                last_line: "---[ end trace",
            },
            Expected {
                log: "null-ptr-deref.log",
                title: "BUG: kernel NULL pointer dereference in bugs_ioctl",
                class: "null-ptr-deref",
                exception: "NULL_PTR_DEREF",
                detector: None,
                rule: Some("BHF-206"),
                cwe: &[476],
                access: None,
                top: "bugs_ioctl",
                last_line: "---[ end trace",
            },
            Expected {
                log: "warning.log",
                title: "WARNING in bugs_ioctl",
                class: "warning",
                exception: "WARNING",
                detector: None,
                rule: None,
                cwe: &[617],
                access: None,
                top: "bugs_ioctl",
                last_line: "</TASK>",
            },
            Expected {
                log: "kcsan-data-race.log",
                title: "KCSAN: data-race in test_kernel_read / test_kernel_write",
                class: "data-race",
                exception: "DATA_RACE",
                detector: Some("KCSAN"),
                rule: Some("BHF-556"),
                cwe: &[362],
                access: None,
                top: "test_kernel_write",
                last_line: "====",
            },
        ];
        for case in cases {
            let console = recorded_console(case.log);
            let report = console_report(&console).unwrap_or_else(|| panic!("{}", case.log));
            assert_eq!(report.title, case.title, "{}", case.log);
            assert_eq!(report.class.class, case.class, "{}", case.log);
            assert_eq!(report.class.exception, case.exception, "{}", case.log);
            assert_eq!(report.class.detector, case.detector, "{}", case.log);
            assert_eq!(report.class.rule, case.rule, "{}", case.log);
            assert_eq!(report.class.cwe, case.cwe, "{}", case.log);
            assert_eq!(report.parsed.access, case.access, "{}", case.log);
            assert_eq!(report.parsed.stack[0].function, case.top, "{}", case.log);
            // The report is its own lines: from its header to its end, not
            // the boot before it or the panic after it.
            let first = report.report.lines().next().unwrap();
            assert!(
                starts_report(strip_console_prefix(first)),
                "{}: {first}",
                case.log
            );
            let last = strip_console_prefix(report.report.lines().last().unwrap()).trim();
            assert!(last.starts_with(case.last_line), "{}: {last}", case.log);
            assert!(
                !report.report.contains("bhf-executor: ready"),
                "{}",
                case.log
            );
            assert!(!report.report.contains("Kernel panic"), "{}", case.log);
        }
        // KASAN's report names the object and both its stacks.
        let oob = console_report(&recorded_console("kasan-slab-out-of-bounds.log")).unwrap();
        let region = oob.parsed.region.unwrap();
        assert_eq!(
            (region.kind, region.size, region.relation),
            ("heap", Some(104), "after")
        );
        assert_eq!(oob.parsed.alloc_stack[0].function, "widget_open");
        let uaf = console_report(&recorded_console("kasan-slab-use-after-free.log")).unwrap();
        assert_eq!(uaf.parsed.free_stack[0].function, "bugs_ioctl");
    }

    #[test]
    fn a_console_log_titles_its_report_as_syzkaller_does() {
        // syzkaller's own console log of a crash, symbolized: the title is
        // the one syz-manager wrote.
        let log = fs::read_to_string(fixture_dir().join("log0")).unwrap();
        let description = fs::read_to_string(fixture_dir().join("description")).unwrap();
        let report = console_report(&log).unwrap();
        assert_eq!(report.title, description.trim());
        assert_eq!(report.parsed.stack[0].function, "widget_copy_at");
        assert_eq!(report.parsed.stack[0].line, Some(46));

        let title = |text: &str| console_report(text).map(|report| report.title);
        assert_eq!(title("[    1.0] booting\n[    2.0] all quiet\n"), None);
        // The guest's /init dying is not a kernel bug.
        assert_eq!(
            title(
                "[ 9.1] Kernel panic - not syncing: Attempted to kill init! exitcode=0x00000009\n"
            ),
            None
        );
        assert_eq!(
            title("Kernel panic - not syncing: Out of memory and no killable processes...\n"),
            Some("kernel panic: Out of memory and no killable processes...".to_owned())
        );
        assert_eq!(
            title(
                "watchdog: BUG: soft lockup - CPU#0 stuck for 22s! [bhf-program:51]\n\
                 RIP: 0010:widget_spin+0x10/0x20 [widget]\n"
            ),
            Some("BUG: soft lockup in widget_spin".to_owned())
        );
        assert_eq!(
            title(
                "BUG: sleeping function called from invalid context at mm/slab.h:12\n\
                 Call Trace:\n widget_lock+0x1/0x2 [widget]\n"
            ),
            Some("BUG: sleeping function called from invalid context in widget_lock".to_owned())
        );
        assert_eq!(
            title(
                "UBSAN: shift-out-of-bounds in drivers/misc/widget.c:70:12\n\
                 Call Trace:\n dump_stack_lvl+0x1/0x2\n widget_shift+0x1/0x2 [widget]\n"
            ),
            Some("UBSAN: shift-out-of-bounds in widget_shift".to_owned())
        );
        assert_eq!(
            title("INFO: task bhf-program:51 blocked for more than 143 seconds.\nCall Trace:\n widget_wait+0x1/0x2\n"),
            Some("INFO: task hung in widget_wait".to_owned())
        );
        assert_eq!(title("INFO: task bhf-program:51 is waiting\n"), None);
        assert_eq!(
            title("WARNING: possible circular locking dependency detected\nCall Trace:\n widget_lock+0x1/0x2\n"),
            Some("possible deadlock in widget_lock".to_owned())
        );
        assert_eq!(
            title("Oops: divide error: 0000 [#1] PREEMPT SMP\nRIP: 0010:widget_div+0x1/0x2 [widget]\n"),
            Some("divide error in widget_div".to_owned())
        );
        let class = console_report(
            "kernel BUG at drivers/misc/widget.c:9!\nRIP: 0010:widget_check+0x1/0x2\n",
        )
        .unwrap();
        assert_eq!(class.title, "kernel BUG in widget_check");
        assert_eq!(class.class.class, "kernel-bug");
    }

    #[test]
    fn a_guest_crash_becomes_a_finding_with_its_program() {
        let work = tempfile::tempdir().unwrap();
        let console = recorded_console("kasan-slab-out-of-bounds.log");
        let report = console_report(&console).unwrap();
        let guest = json!({"kernel": "/k/bzImage", "modules": ["/k/widget.ko"]});
        let decoded = json!({"calls": [{"call": "openat"}, {"call": "ioctl"}]});
        let crash = GuestCrash {
            report: &report,
            console: &console,
            program: b"\x00\x04program",
            program_text: "r0 = openat(...)\nr1 = ioctl(r0, 0xc0285703, ...)\n",
            decoded: &decoded,
            c_repro: "int main(void) { return 0; }\n",
            guest: &guest,
            reproduced: true,
            unconfirmed: None,
            release: Some("6.12.118"),
        };
        let first = record_guest_crash(work.path(), &crash).unwrap();
        assert!(first.id.starts_with("F-KERNEL-0000-"), "{first:?}");
        assert!(!first.updated);
        assert_eq!(first.class, "slab-out-of-bounds");
        assert_eq!(first.reproducer, Some(TESTCASE_FILE));
        let dir = corpus::layout::findings_dir(work.path()).join(&first.id);
        let raw: Value =
            serde_json::from_slice(&fs::read(dir.join("finding.json")).unwrap()).unwrap();
        assert!(is_kernel_crash(&raw));
        assert_eq!(producer(&raw), GUEST_PRODUCER);
        assert_eq!(
            raw["message"],
            "KASAN: slab-out-of-bounds Write in widget_ioctl"
        );
        assert_eq!(raw["rule_id"], "BHF-201");
        assert_eq!(raw["exception"]["access"]["direction"], "write");
        assert_eq!(raw["exception"]["stack"][0]["function"], "widget_ioctl");
        assert_eq!(raw["confidence"], "high");
        assert_eq!(raw["kernel"]["tool"], GUEST_TOOL);
        assert_eq!(raw["kernel"]["reproduced"], true);
        assert_eq!(raw["kernel"]["occurrences"], 1);
        assert_eq!(raw["kernel"]["release"], "6.12.118");
        assert_eq!(raw["kernel"]["guest"], guest);
        assert_eq!(raw["kernel"]["reproducer"]["program"], TESTCASE_FILE);
        assert_eq!(raw["kernel"]["reproducer"]["c"], C_REPRO_FILE);
        assert_eq!(raw["paths"]["repro_c"], C_REPRO_FILE);
        assert!(raw["paths"]["repro_syz"].is_null());
        assert_eq!(
            fs::read(dir.join(TESTCASE_FILE)).unwrap(),
            b"\x00\x04program"
        );
        assert_eq!(
            fs::read_to_string(dir.join(REPORT_FILE)).unwrap(),
            report.report
        );
        assert_eq!(fs::read_to_string(dir.join(CONSOLE_FILE)).unwrap(), console);
        assert!(fs::read_to_string(dir.join(PROGRAM_FILE))
            .unwrap()
            .contains("ioctl"));
        assert!(dir.join(DECODED_FILE).is_file() && dir.join(C_REPRO_FILE).is_file());
        assert_eq!(
            reproduce_command(&first.id, &raw, true, false),
            Some(format!("bhf kernel replay findings/{}", first.id))
        );
        let text = explanation(&raw).unwrap();
        assert!(text.contains("the guest kernel's KASAN report"), "{text}");
        assert!(text.contains("bhf kernel replay"), "{text}");
        assert!(!text.contains("syzkaller"), "{text}");

        // Found again: the same finding, counted, its first program kept.
        let again = GuestCrash {
            program: b"another program",
            reproduced: false,
            ..crash
        };
        let second = record_guest_crash(work.path(), &again).unwrap();
        assert_eq!(second.id, first.id);
        assert!(second.updated);
        let raw: Value =
            serde_json::from_slice(&fs::read(dir.join("finding.json")).unwrap()).unwrap();
        assert_eq!(raw["kernel"]["occurrences"], 2);
        assert_eq!(raw["kernel"]["reproduced"], true);
        assert_eq!(
            fs::read(dir.join(TESTCASE_FILE)).unwrap(),
            b"\x00\x04program"
        );
        assert!(raw["created_at"].as_str().is_some());

        // A syzkaller import of the same title is a finding of its own.
        let imported = import(work.path(), &[fixture_dir()]).unwrap();
        assert_ne!(imported.imported[0].id, first.id);
        let raw: Value = serde_json::from_slice(
            &fs::read(
                corpus::layout::findings_dir(work.path())
                    .join(&imported.imported[0].id)
                    .join("finding.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(producer(&raw), PRODUCER);

        // A crash the program did not repeat in a fresh guest is less sure.
        let other = console_report(&recorded_console("warning.log")).unwrap();
        let unconfirmed = GuestCrash {
            report: &other,
            reproduced: false,
            ..crash
        };
        let found = record_guest_crash(work.path(), &unconfirmed).unwrap();
        let raw: Value = serde_json::from_slice(
            &fs::read(
                corpus::layout::findings_dir(work.path())
                    .join(&found.id)
                    .join("finding.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["confidence"], "medium");
        assert_eq!(raw["kernel"]["reproduced"], false);
    }

    /// A guest crash is written before its program runs alone in a fresh
    /// guest, as not yet confirmed; the confirming run's outcome then
    /// updates it, and a run that could not be made says why.
    #[test]
    fn a_guest_crash_is_written_before_it_is_confirmed_and_updated_after() {
        let work = tempfile::tempdir().unwrap();
        let console = recorded_console("kasan-slab-out-of-bounds.log");
        let report = console_report(&console).unwrap();
        let null = Value::Null;
        let crash = GuestCrash {
            report: &report,
            console: &console,
            program: b"program",
            program_text: "r0 = openat(...)\n",
            decoded: &null,
            c_repro: "int main(void) { return 0; }\n",
            guest: &null,
            reproduced: false,
            unconfirmed: Some(CONFIRMING),
            release: None,
        };
        let found = record_guest_crash(work.path(), &crash).unwrap();
        let path = corpus::layout::findings_dir(work.path())
            .join(&found.id)
            .join("finding.json");
        let read = || -> Value { serde_json::from_slice(&fs::read(&path).unwrap()).unwrap() };
        let raw = read();
        assert_eq!(raw["kernel"]["reproduced"], false);
        assert_eq!(raw["kernel"]["unconfirmed"], CONFIRMING);
        assert_eq!(raw["confidence"], "medium");

        let why = "its confirming run could not be made: the guest did not start: qemu \
                   exited (exit status: 1) before it connected";
        confirm_guest_crash(work.path(), &found.id, false, Some(why)).unwrap();
        let raw = read();
        assert_eq!(raw["kernel"]["reproduced"], false);
        assert_eq!(raw["kernel"]["unconfirmed"], why);
        assert_eq!(raw["confidence"], "medium");
        let text = explanation(&raw).unwrap();
        assert!(text.contains("could not run it alone"), "{text}");
        assert!(text.contains("qemu exited (exit status: 1)"), "{text}");

        confirm_guest_crash(work.path(), &found.id, true, None).unwrap();
        let raw = read();
        assert_eq!(raw["kernel"]["reproduced"], true);
        assert!(raw["kernel"].get("unconfirmed").is_none(), "{raw:#}");
        assert_eq!(raw["confidence"], "high");
        assert!(explanation(&raw)
            .unwrap()
            .contains("as bhf did once, in a freshly booted guest"));
        // The rest of the finding is as it was written.
        assert_eq!(
            raw["message"],
            "KASAN: slab-out-of-bounds Write in widget_ioctl"
        );
        assert_eq!(
            fs::read(path.parent().unwrap().join(TESTCASE_FILE)).unwrap(),
            b"program"
        );

        let error = confirm_guest_crash(work.path(), "F-KERNEL-9999-00000000", true, None);
        assert!(error.is_err());
    }

    fn frame(function: &str, file: &str, line: u64, inline: bool) -> KernelFrame {
        KernelFrame {
            function: function.to_owned(),
            file: Some(file.to_owned()),
            line: Some(line),
            inline,
        }
    }

    /// (title, class, rule, CWEs, exception name, blamed function).
    type Case = (
        &'static str,
        &'static str,
        Option<&'static str>,
        &'static [u32],
        &'static str,
        Option<&'static str>,
    );

    #[test]
    fn titles_classify_into_rules_and_cwes() {
        let cases: &[Case] = &[
            (
                "KASAN: slab-out-of-bounds Write in widget_copy_at",
                "slab-out-of-bounds",
                Some("BHF-201"),
                &[122, 787],
                "SLAB_OUT_OF_BOUNDS",
                Some("widget_copy_at"),
            ),
            (
                "KASAN: slab-use-after-free Read in widget_release",
                "slab-use-after-free",
                Some("BHF-202"),
                &[416],
                "SLAB_USE_AFTER_FREE",
                Some("widget_release"),
            ),
            (
                "KASAN: global-out-of-bounds Read in widget_lookup",
                "global-out-of-bounds",
                None,
                &[125],
                "GLOBAL_OUT_OF_BOUNDS",
                Some("widget_lookup"),
            ),
            (
                "KASAN: double-free in widget_release",
                "double-free",
                Some("BHF-204"),
                &[415],
                "DOUBLE_FREE",
                Some("widget_release"),
            ),
            (
                "KFENCE: use-after-free read in widget_poll",
                "use-after-free",
                Some("BHF-202"),
                &[416],
                "USE_AFTER_FREE",
                Some("widget_poll"),
            ),
            (
                "KFENCE: invalid free in widget_release",
                "invalid-free",
                None,
                &[763],
                "INVALID_FREE",
                Some("widget_release"),
            ),
            (
                "KMSAN: uninit-value in widget_parse",
                "uninit-value",
                Some("BHF-212"),
                &[457],
                "UNINIT_VALUE",
                Some("widget_parse"),
            ),
            (
                "KMSAN: kernel-infoleak in _copy_to_user",
                "kernel-infoleak",
                None,
                &[908],
                "KERNEL_INFOLEAK",
                Some("_copy_to_user"),
            ),
            (
                "UBSAN: array-index-out-of-bounds in widget_set",
                "array-index-out-of-bounds",
                Some("BHF-220"),
                &[129],
                "UBSAN_OUT_OF_BOUNDS_ACCESS",
                Some("widget_set"),
            ),
            (
                "UBSAN: shift-out-of-bounds in widget_mask",
                "shift-out-of-bounds",
                Some("BHF-215"),
                &[1335],
                "UBSAN_INVALID_SHIFT",
                Some("widget_mask"),
            ),
            (
                "KCSAN: data-race in widget_read / widget_write",
                "data-race",
                Some("BHF-556"),
                &[362],
                "DATA_RACE",
                Some("widget_read"),
            ),
            (
                "general protection fault in widget_ioctl",
                "general-protection-fault",
                Some("BHF-223"),
                &[119],
                "GENERAL_PROTECTION_FAULT",
                Some("widget_ioctl"),
            ),
            (
                "BUG: unable to handle kernel NULL pointer dereference in widget_open",
                "null-ptr-deref",
                Some("BHF-206"),
                &[476],
                "NULL_PTR_DEREF",
                Some("widget_open"),
            ),
            (
                "WARNING in widget_flush",
                "warning",
                None,
                &[617],
                "WARNING",
                Some("widget_flush"),
            ),
            (
                "WARNING: refcount bug in widget_put",
                "refcount-bug",
                None,
                &[911],
                "REFCOUNT_BUG",
                Some("widget_put"),
            ),
            (
                "kernel BUG at drivers/misc/widget.c:120!",
                "kernel-bug",
                None,
                &[617],
                "KERNEL_BUG",
                None,
            ),
            (
                "INFO: task hung in widget_wait",
                "task-hung",
                None,
                &[835],
                "TASK_HUNG",
                Some("widget_wait"),
            ),
            (
                "possible deadlock in widget_lock",
                "possible-deadlock",
                None,
                &[833],
                "POSSIBLE_DEADLOCK",
                Some("widget_lock"),
            ),
            (
                "memory leak in widget_alloc",
                "memory-leak",
                Some("BHF-208"),
                &[401],
                "MEMORY_LEAK",
                Some("widget_alloc"),
            ),
            (
                "divide error in widget_rate",
                "divide-error",
                Some("BHF-222"),
                &[369],
                "DIVIDE_ERROR",
                Some("widget_rate"),
            ),
        ];
        for (title, class, rule, cwe, exception, function) in cases {
            let got = classify(title).unwrap_or_else(|| panic!("{title}"));
            assert_eq!(got.class, *class, "{title}");
            assert_eq!(got.rule, *rule, "{title}");
            assert_eq!(got.cwe, *cwe, "{title}");
            assert_eq!(got.exception, *exception, "{title}");
            assert_eq!(got.function.as_deref(), *function, "{title}");
            assert!(
                got.rule.is_some() || got.severity.is_some(),
                "{title}: a crash with no rule needs a severity"
            );
        }
        assert_eq!(
            classify("KASAN: slab-out-of-bounds Write in widget_copy_at")
                .unwrap()
                .access,
            Some("write")
        );
        assert_eq!(
            classify("possible deadlock in widget_lock")
                .unwrap()
                .detector,
            Some("lockdep")
        );
        let unknown = classify("something new in widget_x").unwrap();
        assert_eq!(unknown.class, "kernel-crash");
        assert!(unknown.cwe.is_empty());
    }

    #[test]
    fn syzkaller_infrastructure_crashes_are_not_kernel_crashes() {
        for title in [
            "lost connection to test machine",
            "no output from test machine",
            "SYZFAIL: failed to recv rpc",
            "test machine is not executing programs",
        ] {
            assert_eq!(classify(title), None, "{title}");
        }
    }

    #[test]
    fn a_kasan_report_yields_its_stack_access_and_object() {
        let report = fs::read_to_string(fixture_dir().join("report0")).unwrap();
        let parsed = parse_report(&report);
        assert_eq!(
            parsed.stack,
            vec![
                frame("widget_copy_at", "drivers/misc/widget.c", 46, true),
                frame("widget_do_xfer", "drivers/misc/widget.c", 60, true),
                frame("widget_ioctl", "drivers/misc/widget.c", 98, false),
                frame("vfs_ioctl", "fs/ioctl.c", 51, true),
            ]
        );
        assert_eq!(parsed.access, Some(("write", 16)));
        assert_eq!(
            parsed.region,
            Some(Region {
                kind: "heap",
                size: Some(104),
                relation: "after",
                distance: 0,
            })
        );
        assert_eq!(
            parsed.alloc_stack.first(),
            Some(&frame("widget_open", "drivers/misc/widget.c", 27, false))
        );
        assert!(parsed.free_stack.is_empty());
    }

    #[test]
    fn a_console_log_and_headerless_stacks_parse_too() {
        // KMSAN prints the stack straight after its first line; console
        // lines carry a timestamp and a task.
        let log = "[  61.200][ T812] =====================================================\n\
                   [  61.201][ T812] BUG: KMSAN: uninit-value in widget_parse+0x1c4/0x2e0 drivers/misc/widget.c:140\n\
                   [  61.202][ T812]  widget_parse+0x1c4/0x2e0 drivers/misc/widget.c:140\n\
                   [  61.203][ T812]  widget_ioctl+0x91/0x6d0 drivers/misc/widget.c:96\n\
                   [  61.204][ T812]  ? widget_guess+0x10/0x20\n\
                   [  61.205][ T812]  __do_sys_ioctl fs/ioctl.c:871 [inline]\n\
                   [  61.206][ T812] \n\
                   [  61.207][ T812] Uninit was created at:\n";
        let parsed = parse_report(log);
        assert_eq!(
            parsed.stack,
            vec![
                frame("widget_parse", "drivers/misc/widget.c", 140, false),
                frame("widget_ioctl", "drivers/misc/widget.c", 96, false),
            ]
        );
        assert_eq!(parsed.access, None);
        assert_eq!(parsed.region, None);
    }

    #[test]
    fn the_recorded_crash_dir_reads_with_class_reproducers_and_options() {
        let crash = read_crash_dir(&fixture_dir()).unwrap();
        assert_eq!(
            crash.title,
            "KASAN: slab-out-of-bounds Write in widget_copy_at"
        );
        assert_eq!(crash.class.class, "slab-out-of-bounds");
        assert_eq!(crash.occurrences, 1);
        assert_eq!(
            crash.report.as_ref().map(|(name, _)| name.as_str()),
            Some("report0")
        );
        assert!(crash
            .syz_repro
            .as_deref()
            .unwrap()
            .contains("ioctl$WIDGET_IOC_XFER"));
        assert!(crash.c_repro.as_deref().unwrap().contains("__NR_ioctl"));
        // The options line as syz-manager writes it (Go's `%+v`).
        let options = crash.repro_options.unwrap();
        for (key, value) in [
            ("threaded", json!(false)),
            ("repeat", json!(false)),
            ("repeat_times", json!(0)),
            ("procs", json!(1)),
            ("slowdown", json!(1)),
            ("sandbox", json!("")),
            ("sandbox_arg", json!(0)),
            ("close_fds", json!(false)),
            ("fault", json!(false)),
        ] {
            assert_eq!(options[key], value, "{key}: {options}");
        }
        assert_eq!(crash.kernel_tag.as_deref(), Some("v6.6"));
    }

    fn crash_dir(root: &Path, name: &str, files: &[(&str, &str)]) -> PathBuf {
        let dir = root.join("crashes").join(name);
        fs::create_dir_all(&dir).unwrap();
        for (file, text) in files {
            fs::write(dir.join(file), text).unwrap();
        }
        dir
    }

    #[test]
    fn import_writes_a_finding_with_its_class_and_reproducers() {
        let work = tempfile::tempdir().unwrap();
        let summary = import(work.path(), &[fixture_dir()]).unwrap();
        assert_eq!(summary.skipped, vec![]);
        let imported = &summary.imported[0];
        assert!(imported.id.starts_with("F-KERNEL-0000-"), "{imported:?}");
        assert_eq!(imported.class, "slab-out-of-bounds");
        assert_eq!(imported.reproducer, Some(C_REPRO_FILE));
        assert!(!imported.updated);
        let dir = corpus::layout::findings_dir(work.path()).join(&imported.id);
        let raw: Value =
            serde_json::from_slice(&fs::read(dir.join("finding.json")).unwrap()).unwrap();
        assert_eq!(raw["schema_version"], "bhf.finding.v1");
        assert_eq!(raw["finding_kind"], "fuzz");
        assert_eq!(raw["kind"], KERNEL_CRASH_KIND);
        assert_eq!(raw["rule_id"], "BHF-201");
        assert_eq!(raw["cwe"], json!(["CWE-122", "CWE-787"]));
        assert_eq!(raw["confidence"], "high");
        assert_eq!(raw["exception"]["name"], "SLAB_OUT_OF_BOUNDS");
        assert_eq!(raw["exception"]["sanitizer"], "kasan");
        assert_eq!(raw["exception"]["stack"][0]["function"], "widget_copy_at");
        assert_eq!(raw["exception"]["access"]["direction"], "write");
        assert_eq!(raw["exception"]["access"]["region"]["offset"], 104);
        assert_eq!(raw["kernel"]["reproducer"]["c"], C_REPRO_FILE);
        assert_eq!(raw["kernel"]["reproducer"]["options"]["procs"], 1);
        for (file, source) in [
            (REPORT_FILE, "report0"),
            (CONSOLE_FILE, "log0"),
            (SYZ_REPRO_FILE, "repro.prog"),
            (C_REPRO_FILE, "repro.cprog"),
        ] {
            assert_eq!(
                fs::read(dir.join(file)).unwrap(),
                fs::read(fixture_dir().join(source)).unwrap(),
                "{file}"
            );
        }
    }

    #[test]
    fn reimporting_a_crash_updates_its_finding_in_place() {
        let root = tempfile::tempdir().unwrap();
        let title = "WARNING in widget_flush\n";
        let report = "WARNING: CPU: 0 PID: 1 at drivers/misc/widget.c:77 widget_flush+0x10/0x20\n\
                      Call Trace:\n widget_flush+0x10/0x20 drivers/misc/widget.c:77\n\n";
        let dir = crash_dir(
            root.path(),
            "a1",
            &[("description", title), ("report0", report)],
        );
        let work = root.path().join("work");
        let first = import(&work, std::slice::from_ref(&dir)).unwrap();
        assert_eq!(first.imported[0].reproducer, None);
        let id = first.imported[0].id.clone();
        let finding = corpus::layout::findings_dir(&work).join(&id);
        let raw: Value =
            serde_json::from_slice(&fs::read(finding.join("finding.json")).unwrap()).unwrap();
        assert_eq!(raw["confidence"], "medium");
        assert_eq!(raw["severity"], "medium");
        assert!(raw.get("rule_id").is_none());
        assert!(!finding.join(SYZ_REPRO_FILE).exists());

        // syz-repro found a reproducer since.
        fs::write(
            dir.join("repro.prog"),
            "r0 = openat$widget(0x0, 0x0, 0x0, 0x0)\n",
        )
        .unwrap();
        let second = import(&work, &[dir]).unwrap();
        assert_eq!(second.imported[0].id, id);
        assert!(second.imported[0].updated);
        assert_eq!(second.imported[0].reproducer, Some(SYZ_REPRO_FILE));
        let again: Value =
            serde_json::from_slice(&fs::read(finding.join("finding.json")).unwrap()).unwrap();
        assert_eq!(again["created_at"], raw["created_at"]);
        assert!(again["last_seen"].is_string());
        assert!(finding.join(SYZ_REPRO_FILE).is_file());
        assert_eq!(
            fs::read_dir(corpus::layout::findings_dir(&work))
                .unwrap()
                .count(),
            1
        );
    }

    #[test]
    fn crash_dirs_are_found_in_a_workdir_its_crashes_dir_or_one_crash() {
        let root = tempfile::tempdir().unwrap();
        let a = crash_dir(
            root.path(),
            "b2",
            &[("description", "WARNING in widget_b\n")],
        );
        let b = crash_dir(
            root.path(),
            "a1",
            &[("description", "WARNING in widget_a\n")],
        );
        fs::create_dir_all(root.path().join("crashes/empty")).unwrap();
        assert_eq!(crash_dirs(root.path()).unwrap(), vec![b.clone(), a.clone()]);
        assert_eq!(
            crash_dirs(&root.path().join("crashes")).unwrap(),
            vec![b.clone(), a]
        );
        assert_eq!(crash_dirs(&b).unwrap(), vec![b]);
    }

    #[test]
    fn dirs_without_a_kernel_crash_are_skipped_with_the_reason() {
        let root = tempfile::tempdir().unwrap();
        let lost = crash_dir(
            root.path(),
            "c3",
            &[("description", "lost connection to test machine\n")],
        );
        let empty = crash_dir(root.path(), "d4", &[("description", "\n")]);
        let summary = import(&root.path().join("work"), &[lost, empty]).unwrap();
        assert!(summary.imported.is_empty());
        assert!(
            summary.skipped[0].1.contains("syzkaller's test machine"),
            "{summary:?}"
        );
        assert!(
            summary.skipped[1].1.contains("no crash title"),
            "{summary:?}"
        );
    }

    #[test]
    fn the_reproduce_command_prefers_the_c_program() {
        let raw = json!({"kernel": {"reproducer": {"options": {"procs": 4, "sandbox": "setuid", "repeat": true, "threaded": true}}}});
        assert_eq!(
            reproduce_command("F-KERNEL-0000-aa", &raw, true, true).as_deref(),
            Some("gcc -pthread -o repro findings/F-KERNEL-0000-aa/repro.c && ./repro")
        );
        assert_eq!(
            reproduce_command("F-KERNEL-0000-aa", &raw, false, true).as_deref(),
            Some(
                "syz-execprog -executor=./syz-executor -repeat=0 -procs=4 -sandbox=setuid \
                 -threaded=true -cover=0 findings/F-KERNEL-0000-aa/repro.syz"
            )
        );
        // A sandbox value that is not a plain word is not put in a command.
        let odd = json!({"kernel": {"reproducer": {"options": {"sandbox": "none; rm -rf ~"}}}});
        assert!(reproduce_command("F-KERNEL-0000-aa", &odd, false, true)
            .unwrap()
            .contains("-sandbox=none "));
        assert_eq!(
            reproduce_command("F-KERNEL-0000-aa", &raw, false, false),
            None
        );
    }

    #[test]
    fn a_guest_crash_in_results_is_the_kernel_fuzz_producers_with_its_replay() {
        let work = tempfile::tempdir().unwrap();
        let console = recorded_console("kasan-slab-use-after-free.log");
        let report = console_report(&console).unwrap();
        let null = Value::Null;
        let crash = GuestCrash {
            report: &report,
            console: &console,
            program: b"program",
            program_text: "r0 = openat(...)\n",
            decoded: &null,
            c_repro: "int main(void) { return 0; }\n",
            guest: &null,
            reproduced: true,
            unconfirmed: None,
            release: None,
        };
        let found = record_guest_crash(work.path(), &crash).unwrap();
        let options = crate::RebuildOptions {
            now: Some("2026-11-19T00:00:00Z".to_owned()),
            ..crate::RebuildOptions::default()
        };
        crate::ProducerRun::begin(work.path(), GUEST_PRODUCER, vec!["bhf".to_owned()])
            .complete_with(0, crate::model::ProducerStatus::Complete, &options)
            .unwrap();
        let doc: Value =
            serde_json::from_slice(&fs::read(work.path().join("results/findings.json")).unwrap())
                .unwrap();
        let finding = &doc["findings"][0];
        assert_eq!(finding["id"], found.id.as_str());
        assert_eq!(finding["producer"], GUEST_PRODUCER);
        assert_eq!(
            finding["title"],
            "KASAN: slab-use-after-free Read in bugs_ioctl"
        );
        assert_eq!(finding["rule"]["id"], "BHF-202");
        assert_eq!(finding["cwe"], json!([416]));
        assert_eq!(
            finding["reproduce"]["command"],
            format!("bhf kernel replay findings/{}", found.id)
        );
        let roles: Vec<&str> = finding["evidence"]["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|file| file["role"].as_str().unwrap())
            .collect();
        for role in [
            "testcase",
            "sanitizer_log",
            "console_log",
            "repro_c",
            "decoded",
        ] {
            assert!(roles.contains(&role), "{role}: {roles:?}");
        }
        assert!(!roles.contains(&"replay_script"), "{roles:?}");
        assert_eq!(finding["reachability"]["kind"], "syscall");
        assert_eq!(finding["reachability"]["target"], "bugs_ioctl");
        let explanation = finding["explanation"].as_str().unwrap();
        assert!(explanation.contains("bhf kernel replay"), "{explanation}");
        let index = fs::read_to_string(work.path().join("results/INDEX.md")).unwrap();
        assert!(
            index.contains("slab-use-after-free Read in bugs\\_ioctl"),
            "{index}"
        );
        assert!(
            index.contains(&format!(
                "Reproduce: `bhf kernel replay findings/{}`",
                found.id
            )),
            "{index}"
        );
    }

    #[test]
    fn the_results_index_shows_the_crash_its_class_and_reproducer() {
        let work = tempfile::tempdir().unwrap();
        let source_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/kernel_widget/linux")
            .canonicalize()
            .unwrap();
        import(work.path(), &[fixture_dir()]).unwrap();
        let options = crate::RebuildOptions {
            now: Some("2026-11-19T00:00:00Z".to_owned()),
            ..crate::RebuildOptions::default()
        };
        crate::ProducerRun::begin(work.path(), PRODUCER, vec!["bhf".to_owned()])
            .source_root(&source_root)
            .complete_with(0, crate::model::ProducerStatus::Complete, &options)
            .unwrap();
        let doc: crate::model::FindingsDocument =
            serde_json::from_slice(&fs::read(work.path().join("results/findings.json")).unwrap())
                .unwrap();
        assert_eq!(doc.findings.len(), 1, "{:#?}", doc.errors);
        let finding = &doc.findings[0];
        assert_eq!(finding.producer, PRODUCER);
        // syzkaller's title, the name its reports and dashboards use.
        assert_eq!(
            finding.title,
            "KASAN: slab-out-of-bounds Write in widget_copy_at"
        );
        let explanation = finding.explanation.as_deref().unwrap();
        assert!(
            explanation.contains("KASAN")
                && explanation.contains("write of 16 bytes")
                && explanation.contains("`widget_copy_at` (drivers/misc/widget.c:46)")
                && explanation.contains("repro.c"),
            "{explanation}"
        );
        assert!(!explanation.contains("testcase.bin"), "{explanation}");
        assert_eq!(finding.kind, crate::model::Kind::Fuzz);
        assert_eq!(finding.rule.id.as_deref(), Some("BHF-201"));
        assert_eq!(finding.cwe, vec![122, 787]);
        assert_eq!(
            finding.confirmation.level,
            crate::model::ConfirmationLevel::SanitizerCrash
        );
        let fuzz = finding.fuzz.as_ref().unwrap();
        assert_eq!(fuzz.exception.name.as_deref(), Some("SLAB_OUT_OF_BOUNDS"));
        assert_eq!(fuzz.exception.sanitizer.as_deref(), Some("kasan"));
        assert_eq!(
            finding.message,
            "KASAN: slab-out-of-bounds Write in widget_copy_at"
        );
        let location = finding.location.as_ref().unwrap();
        assert_eq!(
            (
                location.file.as_str(),
                location.line,
                location.function.as_deref()
            ),
            ("drivers/misc/widget.c", Some(46), Some("widget_copy_at"))
        );
        // Only the driver's frames: the tree has no fs/ioctl.c.
        assert_eq!(
            finding
                .stack
                .iter()
                .map(|frame| frame.function.as_deref().unwrap_or(""))
                .collect::<Vec<_>>(),
            vec!["widget_copy_at", "widget_do_xfer", "widget_ioctl"]
        );
        let access = fuzz.access.as_ref().unwrap();
        assert_eq!(
            (access.direction.as_str(), access.size),
            ("write", Some(16))
        );
        assert_eq!(
            access.alloc_stack[0].function.as_deref(),
            Some("widget_open")
        );
        let reproduce = finding.reproduce.as_ref().unwrap();
        assert_eq!(
            reproduce.command.as_deref(),
            Some(&*format!(
                "gcc -pthread -o repro findings/{}/repro.c && ./repro",
                finding.id
            ))
        );
        assert_eq!(reproduce.build.sanitizers, vec!["kasan"]);
        let roles: Vec<&str> = finding
            .evidence
            .as_ref()
            .unwrap()
            .files
            .iter()
            .map(|file| file.role.as_str())
            .collect();
        assert_eq!(
            roles,
            vec![
                "finding",
                "sanitizer_log",
                "console_log",
                "repro_syz",
                "repro_c"
            ]
        );
        // A kernel crash has no host harness for a replay.py to run.
        let dir = corpus::layout::findings_dir(work.path()).join(&finding.id);
        assert!(!dir.join("replay.py").exists());
        assert!(finding
            .fidelity
            .caveats
            .iter()
            .any(|caveat| caveat.contains("syzkaller")));
        // Reached through the syscalls of syzkaller's program in its VM, not
        // a harness input.
        let reachability = finding.reachability.as_ref().unwrap();
        assert_eq!(reachability["kind"], "syscall", "{reachability}");
        assert_eq!(reachability["source"], SYZ_REPRO_FILE, "{reachability}");
        assert_eq!(reachability["target"], "widget_copy_at", "{reachability}");
        assert!(!reachability.to_string().contains("testcase.bin"));
    }

    /// syz-manager's header of the options syz-repro found: Go's `%+v` of
    /// csource.Options, as `fmt.Sprintf("# %+v\n", repro.Opts)` prints it.
    const MANAGER_OPTIONS: &str = "# {Threaded:true Repeat:true RepeatTimes:0 Procs:4 Slowdown:1 \
        Sandbox:namespace SandboxArg:0 Leak:false NetInjection:true NetDevices:true NetReset:true \
        Cgroups:true BinfmtMisc:true CloseFDs:true KCSAN:false DevlinkPCI:false NicVF:false USB:false \
        VhciInjection:false Wifi:false IEEE802154:false Sysctl:false Swap:false UseTmpDir:true \
        HandleSegv:true Trace:false CallComments:false LegacyOptions:{Collide:false Fault:false \
        FaultCall:0 FaultNth:0}}";

    #[test]
    fn the_options_line_reads_as_syz_manager_and_the_dashboard_write_it() {
        let program = "r0 = openat$widget(0xffffffffffffff9c, &(0x7f0000000000)='/dev/widget\\x00', 0x2, 0x0)\n";
        let options = repro_options(&format!("{MANAGER_OPTIONS}\n{program}")).unwrap();
        for (key, value) in [
            ("threaded", json!(true)),
            ("repeat", json!(true)),
            ("repeat_times", json!(0)),
            ("procs", json!(4)),
            ("slowdown", json!(1)),
            ("sandbox", json!("namespace")),
            ("sandbox_arg", json!(0)),
            ("tun", json!(true)),
            ("cgroups", json!(true)),
            ("close_fds", json!(true)),
            ("tmpdir", json!(true)),
            ("segv", json!(true)),
            ("collide", json!(false)),
            ("fault_nth", json!(0)),
        ] {
            assert_eq!(options[key], value, "{key}: {options}");
        }
        // An empty sandbox prints as `Sandbox: `.
        let empty = repro_options(
            "# {Threaded:false Repeat:true RepeatTimes:3 Procs:1 Slowdown:1 Sandbox: SandboxArg:2 \
             Leak:false LegacyOptions:{Collide:false Fault:false FaultCall:0 FaultNth:0}}\n",
        )
        .unwrap();
        assert_eq!(
            (
                &empty["sandbox"],
                &empty["sandbox_arg"],
                &empty["repeat_times"]
            ),
            (&json!(""), &json!(2), &json!(3))
        );
        // Older syz-manager versions wrote fewer fields under other names.
        let legacy = repro_options(
            "# {Threaded:true Collide:true Repeat:true Procs:8 Sandbox:setuid Fault:false \
             FaultCall:-1 FaultNth:0 EnableTun:true UseTmpDir:true HandleSegv:true WaitRepeat:true \
             Debug:false Repro:false}\n",
        )
        .unwrap();
        assert_eq!(
            (&legacy["procs"], &legacy["tun"]),
            (&json!(8), &json!(true))
        );
        assert_eq!(legacy["fault_call"], json!(-1));
        // The dashboard's JSON form.
        let dashboard =
            repro_options("#{\"threaded\":true,\"procs\":2,\"sandbox\":\"none\"}\n").unwrap();
        assert_eq!(
            dashboard,
            json!({"threaded": true, "procs": 2, "sandbox": "none"})
        );
        // A comment that is neither.
        assert_eq!(repro_options("# {not options}\nr0 = x()\n"), None);
    }

    #[test]
    fn a_syz_reproducer_runs_with_the_options_either_header_records() {
        let root = tempfile::tempdir().unwrap();
        let report =
            "BUG: KASAN: slab-out-of-bounds in widget_copy_at+0x5d/0x90 drivers/misc/widget.c:46\n\
                      Write of size 16 at addr ffff888012345678 by task syz-executor/1\n\n\
                      Call Trace:\n widget_copy_at+0x5d/0x90 drivers/misc/widget.c:46\n\n";
        let program = "r0 = openat$widget(0xffffffffffffff9c, &(0x7f0000000000)='/dev/widget\\x00', 0x2, 0x0)\n";
        let manager = crash_dir(
            root.path(),
            "m1",
            &[
                (
                    "description",
                    "KASAN: slab-out-of-bounds Write in widget_copy_at\n",
                ),
                ("report0", report),
                ("repro.prog", &format!("{MANAGER_OPTIONS}\n{program}")),
            ],
        );
        let dashboard = crash_dir(
            root.path(),
            "d1",
            &[
                (
                    "description",
                    "KASAN: slab-out-of-bounds Write in widget_flush\n",
                ),
                ("report0", &report.replace("widget_copy_at", "widget_flush")),
                (
                    "repro.prog",
                    &format!(
                        "#{{\"threaded\":true,\"repeat\":true,\"repeat_times\":5,\"procs\":2,\
                         \"sandbox\":\"setuid\",\"sandbox_arg\":1}}\n{program}"
                    ),
                ),
            ],
        );
        let work = root.path().join("work");
        let summary = import(&work, &[manager, dashboard]).unwrap();
        assert_eq!(summary.imported.len(), 2, "{summary:?}");
        let command = |imported: &Imported| {
            let dir = corpus::layout::findings_dir(&work).join(&imported.id);
            let raw: Value =
                serde_json::from_slice(&fs::read(dir.join("finding.json")).unwrap()).unwrap();
            reproduce_command(&imported.id, &raw, false, true).unwrap()
        };
        let by_title = |needle: &str| {
            summary
                .imported
                .iter()
                .find(|imported| imported.title.contains(needle))
                .unwrap()
        };
        let manager = by_title("widget_copy_at");
        assert_eq!(
            command(manager),
            format!(
                "syz-execprog -executor=./syz-executor -repeat=0 -procs=4 -sandbox=namespace \
                 -threaded=true -cover=0 findings/{}/repro.syz",
                manager.id
            )
        );
        let dashboard = by_title("widget_flush");
        assert_eq!(
            command(dashboard),
            format!(
                "syz-execprog -executor=./syz-executor -repeat=5 -procs=2 -sandbox=setuid \
                 -sandbox_arg=1 -threaded=true -cover=0 findings/{}/repro.syz",
                dashboard.id
            )
        );
    }

    #[test]
    fn a_region_offset_past_u64_is_left_out_not_wrapped() {
        let root = tempfile::tempdir().unwrap();
        let dir = crash_dir(
            root.path(),
            "o1",
            &[
                ("description", "KASAN: slab-out-of-bounds Write in widget_copy_at\n"),
                (
                    "report0",
                    "BUG: KASAN: slab-out-of-bounds in widget_copy_at+0x5d/0x90 drivers/misc/widget.c:46\n\
                     Write of size 16 at addr ffff888012345678 by task syz-executor/1\n\
                     The buggy address is located 18446744073709551615 bytes to the right of\n \
                     allocated 18446744073709551615-byte region [ffff888012345600, ffff888012345668)\n",
                ),
            ],
        );
        let crash = read_crash_dir(&dir).unwrap();
        let record = finding_record("F-KERNEL-0000-aa", &crash);
        let region = &record["exception"]["access"]["region"];
        assert_eq!(region["distance"], json!(u64::MAX), "{region}");
        assert_eq!(region["offset"], Value::Null, "{region}");
    }

    #[test]
    fn the_findings_schema_names_the_kernel_producer_and_evidence() {
        let schema: Value =
            serde_json::from_str(include_str!("../../../schemas/bhf.findings.v1.schema.json"))
                .unwrap();
        let text = schema.to_string();
        for value in [
            PRODUCER,
            GUEST_PRODUCER,
            "console_log",
            "repro_syz",
            "repro_c",
        ] {
            assert!(text.contains(&format!("\"{value}\"")), "{value}");
        }
    }
}
