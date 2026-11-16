// SPDX-License-Identifier: Apache-2.0

//! Root-cause clustering on top of bhf's per-input signature.
//! See docs/superpowers/specs/2026-05-13-crash-dedup-clustering-design.md.
//!
//! `signature` (from `crate::signature`) identifies a specific
//! `(input -> behaviour)` pair and drives corpus growth.
//! `ClusterKey` (this module) is a coarser, root-cause identifier
//! derived from the normalized top-N stack frames; two findings with
//! the same `ClusterKey` are likely the same bug.

use crate::sanitizer::{Sanitizer, SanitizerReport, StackFrame};
use event_log::{HandlerEvent, Testcase};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const TOP_FRAMES: usize = 3;
const CLUSTER_KEY_VERSION_PREFIX: &str = "bhf-cluster-v1\n";
/// Sanitizer-crash keys also hash the rule, the crash kind, the sanitizer's
/// check name and (for UBSan, or a report with no usable frame) the reported
/// site, so they carry their own version prefix.
const SANITIZER_CLUSTER_KEY_VERSION_PREFIX: &str = "bhf-sanitizer-cluster-v2\n";
/// Prefix of the key of a sanitizer crash with no informative frame and no
/// reported source position, which hashes the harness scope it was found in.
const FRAMELESS_CLUSTER_KEY_VERSION_PREFIX: &str = "bhf-frameless-cluster-v1\n";

/// A frame fed into the clustering pipeline. Real sanitizer frames
/// arrive via `From<&StackFrame>`; synthesized Ada frames are built
/// with `InputFrame::symbol`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputFrame {
    pub function: String,
    pub file: Option<String>,
    pub line: Option<u32>,
}

impl InputFrame {
    pub fn symbol(function: impl Into<String>) -> Self {
        Self {
            function: function.into(),
            file: None,
            line: None,
        }
    }
}

impl From<&StackFrame> for InputFrame {
    fn from(value: &StackFrame) -> Self {
        InputFrame {
            function: value.function.clone(),
            file: value.file.clone(),
            line: value.line,
        }
    }
}

/// Result of clustering a single finding. `short` is the 16-character
/// lowercase-hex display key; `full` is the 64-character SHA-256 hex
/// digest. `frames` preserves the normalized frame list the key was
/// hashed over so consumers can inspect why two findings clustered
/// together (or didn't). `fallback = true` means normalization
/// produced no informative frames. A fallback key that is the all-zero
/// [placeholder](ClusterKey::is_placeholder) is replaced by the per-input
/// signature before it is persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterKey {
    pub short: String,
    pub full: String,
    pub frames: Vec<String>,
    pub fallback: bool,
}

/// Function-name prefixes that identify uninformative scaffolding
/// frames the user does not care about when clustering by root
/// cause. Matched as a left-anchored prefix on the raw function
/// string after toolchain decoration has been stripped.
const NOISE_PREFIXES: &[&str] = &[
    // Sanitizer runtimes: both the C `__asan_*` interceptor form and the
    // C++ `__asan::*` namespace form (e.g. `__asan::Allocator::Deallocate`).
    "__asan",
    "__sanitizer",
    "__interceptor",
    "__ubsan",
    "__lsan",
    "__hwasan",
    "__tsan",
    // libFuzzer driver: `LLVMFuzzer*` entrypoints and the whole `fuzzer::*`
    // namespace (`fuzzer::RunOneTest`, `fuzzer::Fuzzer::ExecuteCallback`, ...).
    "LLVMFuzzer",
    "fuzzer::",
    "_dl_",
    "__GI_",
    "__libc_",
];

/// Exact function names dropped even when no `NOISE_PREFIXES` match.
const NOISE_EXACT: &[&str] = &["main", "_start"];

/// Function-name prefixes that unambiguously identify a libFuzzer / sanitizer
/// *driver* frame (as opposed to generic libc/startup noise). A crash whose
/// stack contains one of these and *no* target frame is a harness/driver
/// fault, not a target bug — see [`is_driver_glue_crash`].
const DRIVER_PREFIXES: &[&str] = &[
    "fuzzer::",
    "LLVMFuzzer",
    "__asan",
    "__ubsan",
    "__lsan",
    "__tsan",
    "__hwasan",
    "__sanitizer",
];

/// The libFuzzer hooks a fuzz target defines itself. They are driver or
/// harness code only in a harness bhf generated around a target of its own;
/// in a project's fuzz target (a hand-built `-fsanitize=fuzzer` binary, or
/// bhf's driver around the project's entry) they are the target.
const FUZZ_TARGET_HOOKS: &[&str] = &[
    "LLVMFuzzerTestOneInput",
    "LLVMFuzzerInitialize",
    "LLVMFuzzerCustomMutator",
    "LLVMFuzzerCustomCrossOver",
];

fn is_fuzz_target_hook(function: &str) -> bool {
    FUZZ_TARGET_HOOKS.contains(&function)
}

/// The glue files bhf writes into a harness dir that define a fuzz target's
/// hooks themselves: the Fortran and COBOL lanes' `LLVMFuzzerTestOneInput`
/// around the project's routine, and the libFuzzer shim that forwards to
/// bhf's entry.
const BHF_GLUE_FILES: &[&str] = &["fortran_glue.c", "cobol_glue.c", "bhf_libfuzzer.c"];

/// Whether `frame` is in one of [`BHF_GLUE_FILES`]: a hook there is bhf's
/// code, whatever else is known about the harness.
fn in_bhf_glue(frame: &StackFrame) -> bool {
    frame.file.as_deref().is_some_and(|file| {
        let name = file.rsplit(['/', '\\']).next().unwrap_or(file);
        BHF_GLUE_FILES.contains(&name)
    })
}

/// libc / C++ allocator-runtime frames. On their own (with no target frame
/// and a driver frame present) these signal allocator-glue corruption rather
/// than a target double-free, which always carries the target caller above.
const ALLOC_RUNTIME: &[&str] = &[
    "free",
    "malloc",
    "calloc",
    "realloc",
    "reallocarray",
    "aligned_alloc",
    "posix_memalign",
    "memalign",
    "valloc",
    "pvalloc",
    "cfree",
    "operator new",
    "operator delete",
    "operator new[]",
    "operator delete[]",
];

/// Drop noise, strip toolchain decoration, strip C++ argument lists,
/// and truncate to the top `TOP_FRAMES` frames. Returns an empty
/// `Vec` when every frame was noise — callers fall back to the
/// per-input signature in that case.
pub fn normalize_frames(input: &[InputFrame]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for frame in input {
        let stripped = strip_toolchain_decoration(frame.function.as_str());
        let trimmed = stripped.trim();
        if trimmed.is_empty() {
            continue;
        }
        if NOISE_EXACT.contains(&trimmed) {
            continue;
        }
        if NOISE_PREFIXES.iter().any(|p| trimmed.starts_with(p)) {
            continue;
        }
        let no_args = strip_cpp_args(trimmed);
        if no_args.is_empty() {
            continue;
        }
        // Drop runtime and bhf harness frames so one root cause doesn't
        // over-split into multiple issue rows depending on which allocator,
        // formatting, or generated-driver frame the PC landed in. The key must
        // start at the first in-project frame (#31, #44).
        if is_runtime_or_harness_noise(&no_args) {
            continue;
        }
        // libc and sanitizer-interceptor frames (`__memcmp_avx2_movbe`,
        // `MemcmpInterceptorCommon`, `bcmp`, glibc `sysdeps/` sources): the same
        // test the sink search uses, so every crash inside `memcmp` does not
        // share one key whatever project code called it.
        if actionability::is_runtime_noise_frame(trimmed, frame.file.as_deref()) {
            continue;
        }
        out.push(no_args);
        if out.len() >= TOP_FRAMES {
            break;
        }
    }
    out
}

/// Runtime (`printf`/`fprintf`/`vfprintf`, the `str*`/`mem*` builtins, glibc
/// `_IO_*` stdio internals, Rust std allocation/string conversion frames, ASan's
/// `printf_common` interceptor) and bhf harness (`bhf_*`/`bhf_*`/
/// `rust_runtime::*`/`LLVMFuzzerTestOneInput`) frames are scaffolding, never the
/// project's root-cause site — the real caller is the frame above them. Dropping
/// them keeps the cluster key anchored at the first in-project frame so a single
/// bug clusters to one issue regardless of which runtime frame the PC landed in
/// (#31, #44). Mirrors actionability's `is_libc_runtime_function` /
/// `is_harness_frame` for the clustering pipeline.
fn is_runtime_or_harness_noise(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower.starts_with("bhf_")
        || lower.starts_with("bhf_")
        || lower.starts_with("rust_runtime::")
        || lower.starts_with("<rust_runtime::")
        || lower.starts_with("_io_")
        || lower.contains("printf_common")
        || lower == "llvmfuzzertestoneinput"
        || ALLOC_RUNTIME.contains(&lower.as_str())
        || is_rust_std_allocator_noise(&lower)
    {
        return true;
    }
    matches!(
        lower.as_str(),
        "printf"
            | "fprintf"
            | "vfprintf"
            | "vprintf"
            | "sprintf"
            | "snprintf"
            | "vsnprintf"
            | "vsprintf"
            | "dprintf"
            | "vdprintf"
            | "puts"
            | "fputs"
            | "fwrite"
            | "fread"
            | "fputc"
            | "fgetc"
            | "getc"
            | "putc"
            | "putchar"
            | "memcpy"
            | "memmove"
            | "memset"
            | "memcmp"
            | "memchr"
            | "strlen"
            | "strnlen"
            | "strcmp"
            | "strncmp"
            | "strcpy"
            | "strncpy"
            | "strcat"
            | "strncat"
            | "strchr"
            | "strrchr"
            | "strstr"
            | "strdup"
            | "strndup"
    )
}

fn is_rust_std_allocator_noise(lower_name: &str) -> bool {
    lower_name.starts_with("alloc::")
        || lower_name.starts_with("<alloc::")
        || lower_name.contains(" as alloc::")
        || lower_name.starts_with("<[u8]>::to_vec")
        || lower_name.starts_with("<u8 as <[_]>::to_vec")
}

/// True when an LSan leak's entire allocation stack is bhf's own decode /
/// harness scaffolding (`bhf_*`/`bhf_*`/`LLVMFuzzerTestOneInput` frames plus
/// allocator/runtime noise) with NO target frame. Such a leak is the decoder
/// buffer the harness allocates and WOULD free, left dangling only because an
/// `exit()`/`abort()`-only target (e.g. tomlc99 `fatal()`) terminates before the
/// harness's free() runs — bhf manufactured it, so it must be suppressed, not
/// reported as a target CWE-401 (#49).
///
/// Conservative, like [`is_driver_glue_crash`]: requires a POSITIVE harness frame
/// and bails the instant any real target/library frame resolves. An
/// `LLVMFuzzerTestOneInput` frame is harness scaffolding only when `bhf_entry`
/// (bhf generated that function) or when it is in a glue file bhf writes
/// ([`BHF_GLUE_FILES`]); otherwise it is the project's fuzz target.
pub fn is_harness_scaffolding_leak(report: &SanitizerReport, bhf_entry: bool) -> bool {
    if report.sanitizer != Some(Sanitizer::LeakSanitizer) {
        return false;
    }
    let mut saw_harness = false;
    let mut saw_rust_std_allocator = false;
    for frame in &report.stack {
        let stripped = strip_toolchain_decoration(frame.function.as_str());
        let trimmed = stripped.trim();
        if trimmed.is_empty() {
            continue; // unsymbolized — neutral
        }
        let no_args = strip_cpp_args(trimmed);
        if no_args.is_empty() {
            continue;
        }
        let lower = no_args.to_ascii_lowercase();
        if is_fuzz_target_hook(&no_args) && !bhf_entry && !in_bhf_glue(frame) {
            // The project's own fuzz target: a real leak.
            return false;
        }
        if lower.starts_with("bhf_")
            || lower.starts_with("bhf_")
            || lower.starts_with("rust_runtime::")
            || lower.starts_with("<rust_runtime::")
            || lower == "llvmfuzzertestoneinput"
        {
            saw_harness = true;
            continue;
        }
        if is_rust_std_allocator_noise(&lower) {
            saw_rust_std_allocator = true;
            continue;
        }
        // Allocator / libc / sanitizer / startup noise — neutral.
        if ALLOC_RUNTIME.contains(&no_args.as_str())
            || NOISE_EXACT.contains(&trimmed)
            || NOISE_PREFIXES.iter().any(|p| trimmed.starts_with(p))
            || is_runtime_or_harness_noise(&no_args)
        {
            continue;
        }
        // A genuine target / library frame: this is a real leak.
        return false;
    }
    saw_harness || saw_rust_std_allocator
}

impl ClusterKey {
    /// The all-zero key [`cluster_key_from_frames`] gives an empty frame list,
    /// which says nothing about the crash: the caller substitutes the
    /// per-input signature for it.
    pub fn is_placeholder(&self) -> bool {
        self.fallback && self.full.bytes().all(|byte| byte == b'0')
    }
}

/// The scope a crash without frames or a source position is grouped in: the
/// harness that found it and, when known, the function it calls. Two
/// harnesses' frame-less crashes are then two root-cause groups, while one
/// harness keeps one group per rule, kind, check and faulting pc.
pub fn crash_scope(harness_id: &str, target_function: Option<&str>) -> String {
    match target_function
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        Some(function) => format!("{harness_id}|{function}"),
        None => harness_id.to_owned(),
    }
}

/// Hash the supplied normalized frame list into a `ClusterKey`. An
/// empty frame list produces a placeholder all-zero key and sets
/// `fallback = true`; callers are responsible for substituting the
/// per-input signature short before persisting.
pub fn cluster_key_from_frames(frames: &[String]) -> ClusterKey {
    if frames.is_empty() {
        return ClusterKey {
            short: "0".repeat(16),
            full: "0".repeat(64),
            frames: Vec::new(),
            fallback: true,
        };
    }
    let mut hasher = Sha256::new();
    hasher.update(CLUSTER_KEY_VERSION_PREFIX.as_bytes());
    for (i, f) in frames.iter().enumerate() {
        if i > 0 {
            hasher.update(b"\n");
        }
        hasher.update(f.as_bytes());
    }
    let digest = hasher.finalize();
    let full = hex_lower(&digest);
    let short = full.chars().take(16).collect();
    ClusterKey {
        short,
        full,
        frames: frames.to_vec(),
        fallback: false,
    }
}

/// Cluster a sanitizer crash by root cause.
///
/// The key hashes the rule, the crash kind and the sanitizer's check name with
/// the normalized crash frames, so an ASan overflow and a UBSan overflow in one
/// function, or two different UBSan checks in one function, are different
/// root causes.
///
/// A UBSan report names the exact site of the failed check (`file:line:col`),
/// so its key is that site plus the function it is in: the same site reached
/// through different callers is one root cause, and two sites are two. A report
/// with no informative frame keys on its reported site when it has one.
/// `fallback` is set only when neither a frame nor a site is known.
///
/// Such a report gets the all-zero placeholder key here; the finding emitter
/// and the fuzz loop key it with [`cluster_for_sanitizer_scoped`] instead.
pub fn cluster_for_sanitizer(report: &SanitizerReport) -> ClusterKey {
    cluster_for_sanitizer_scoped(report, "")
}

/// [`cluster_for_sanitizer`] for a crash found in `scope` (see
/// [`crash_scope`]). A report with no informative frame and no reported
/// source position keys on its rule, kind, check, the faulting instruction's
/// offset in the executable when the driver printed one
/// ([`SanitizerReport::pc_offset`]), and `scope`, so frame-less crashes of
/// different harnesses are different root causes. That key is still a
/// `fallback` key: it does not name a source location. With an empty scope and
/// no pc offset it is the placeholder.
pub fn cluster_for_sanitizer_scoped(report: &SanitizerReport, scope: &str) -> ClusterKey {
    let input: Vec<InputFrame> = report.stack.iter().map(InputFrame::from).collect();
    let frames = normalize_frames(&input);
    let site = sanitizer_site(report, &frames);
    if frames.is_empty() && site.is_none() {
        if scope.is_empty() && report.pc_offset.is_none() {
            return cluster_key_from_frames(&frames);
        }
        let mut hasher = Sha256::new();
        hasher.update(FRAMELESS_CLUSTER_KEY_VERSION_PREFIX.as_bytes());
        let pc = report.fault_site().unwrap_or_default();
        for part in [
            report.rule_id,
            report.kind.as_str(),
            report.check.as_deref().unwrap_or(""),
            pc.as_str(),
            scope,
        ] {
            hasher.update(part.as_bytes());
            hasher.update(b"\n");
        }
        let full = hex_lower(&hasher.finalize());
        return ClusterKey {
            short: full.chars().take(16).collect(),
            full,
            frames,
            fallback: true,
        };
    }
    let mut hasher = Sha256::new();
    hasher.update(SANITIZER_CLUSTER_KEY_VERSION_PREFIX.as_bytes());
    for part in [
        report.rule_id,
        report.kind.as_str(),
        report.check.as_deref().unwrap_or(""),
        site.as_deref().unwrap_or(""),
    ] {
        hasher.update(part.as_bytes());
        hasher.update(b"\n");
    }
    // With a site, the enclosing function disambiguates same-named files; the
    // callers below it are not part of the root cause.
    let keyed: &[String] = match site {
        Some(_) => &frames[..frames.len().min(1)],
        None => &frames,
    };
    for frame in keyed {
        hasher.update(frame.as_bytes());
        hasher.update(b"\n");
    }
    let full = hex_lower(&hasher.finalize());
    ClusterKey {
        short: full.chars().take(16).collect(),
        full,
        frames,
        fallback: false,
    }
}

/// The reported site that identifies `report`'s root cause: always for UBSan
/// (its location is the check that failed), otherwise only when no
/// informative frame survived normalization.
pub fn sanitizer_site(report: &SanitizerReport, normalized_frames: &[String]) -> Option<String> {
    let ubsan = report.sanitizer == Some(Sanitizer::UndefinedBehaviorSanitizer);
    if ubsan || normalized_frames.is_empty() {
        report.site()
    } else {
        None
    }
}

/// True when a sanitizer crash is entirely libFuzzer / sanitizer / allocator
/// driver glue with no target frame — a harness fault, not a target bug.
///
/// The classic case is a passthrough libFuzzer harness whose own `main` /
/// `RunOneTest` corrupts allocator state, producing a SEGV in
/// `[__asan::Allocator::Deallocate, free, fuzzer::RunOneTest]` even on empty
/// input. Such "findings" do not reproduce and are not in target code.
///
/// To avoid dropping a genuine but *unsymbolized* target crash, this returns
/// true only when (a) every symbolized frame is driver / sanitizer / startup
/// or allocator-runtime, and (b) at least one frame is an unambiguous libFuzzer
/// or sanitizer *driver* frame. A crash with only `module+offset` frames (no
/// driver frame) is left for replay-verification to judge.
///
/// The hooks a fuzz target defines (`LLVMFuzzerTestOneInput`,
/// `LLVMFuzzerInitialize`, `LLVMFuzzerCustomMutator`,
/// `LLVMFuzzerCustomCrossOver`) are driver frames only when `bhf_entry` (bhf
/// generated them) or in a glue file bhf writes ([`BHF_GLUE_FILES`]);
/// otherwise they are target frames. The runtime's own
/// entry points (`LLVMFuzzerRunDriver`, `LLVMFuzzerMutate`, `fuzzer::*`) are
/// driver frames either way.
pub fn is_driver_glue_crash(report: &SanitizerReport, bhf_entry: bool) -> bool {
    let mut saw_driver = false;
    for frame in &report.stack {
        let stripped = strip_toolchain_decoration(frame.function.as_str());
        let trimmed = stripped.trim();
        if trimmed.is_empty() {
            // Unsymbolized (module+offset) frame — neither confirms nor denies.
            continue;
        }
        if is_fuzz_target_hook(&strip_cpp_args(trimmed)) && !bhf_entry && !in_bhf_glue(frame) {
            // The project's own fuzz target: a real crash.
            return false;
        }
        if DRIVER_PREFIXES.iter().any(|p| trimmed.starts_with(p)) {
            saw_driver = true;
            continue;
        }
        if NOISE_EXACT.contains(&trimmed) || NOISE_PREFIXES.iter().any(|p| trimmed.starts_with(p)) {
            // libc startup / interceptor noise — neutral.
            continue;
        }
        let no_args = strip_cpp_args(trimmed);
        if ALLOC_RUNTIME.contains(&no_args.as_str()) {
            continue;
        }
        // A genuine target / library frame: this is a real crash.
        return false;
    }
    saw_driver
}

/// Cluster an Ada exception by synthesizing a logical frame list
/// from the handler location plus up to the two earliest preceding
/// raises (filtered to those strictly before the handler's
/// `sequence_index`).
pub fn cluster_for_ada(testcase: &Testcase, handler: &HandlerEvent) -> ClusterKey {
    let mut frames: Vec<InputFrame> = Vec::new();
    frames.push(InputFrame::symbol(handler.exception_name.clone()));
    frames.push(InputFrame::symbol(format!(
        "{}:{}",
        handler.handler_file, handler.handler_line
    )));
    let mut raises: Vec<&event_log::RaiseEvent> = testcase
        .raises
        .iter()
        .filter(|r| r.sequence_index < handler.sequence_index)
        .collect();
    raises.sort_by_key(|r| r.sequence_index);
    for raise in raises.iter().take(2) {
        frames.push(InputFrame::symbol(format!("{}:{}", raise.file, raise.line)));
    }
    let normalized = normalize_frames(&frames);
    cluster_key_from_frames(&normalized)
}

/// Reconstruct a `ClusterKey` from a `finding.json` value. Order of
/// precedence:
/// 0. A frame-less sanitizer crash an earlier release keyed on its
///    rule-wide signature: the key this release gives its stored report
///    ([`legacy_fallback_cluster_key`]).
/// 1. `cluster_key_full` + `cluster_normalized_frames` already on
///    the record — return them as-is.
/// 2. `exception.stack` array — normalize and hash.
/// 3. `handler` + `raises` (Ada path) — synthesize and hash.
/// 4. Otherwise return `None`; the caller falls back to the
///    per-input signature.
pub fn cluster_from_finding_json(raw: &serde_json::Value) -> Option<ClusterKey> {
    if let Some(key) = legacy_fallback_cluster_key(raw) {
        return Some(key);
    }
    if let (Some(full), Some(frames)) = (
        raw.get("cluster_key_full").and_then(|v| v.as_str()),
        raw.get("cluster_normalized_frames")
            .and_then(|v| v.as_array()),
    ) {
        let frames: Vec<String> = frames
            .iter()
            .filter_map(|f| f.as_str().map(str::to_owned))
            .collect();
        let fallback = raw
            .get("cluster_fallback")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let short = raw
            .get("cluster_key")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .unwrap_or_else(|| full.chars().take(16).collect());
        return Some(ClusterKey {
            short,
            full: full.to_owned(),
            frames,
            fallback,
        });
    }
    if let Some(stack) = raw
        .get("exception")
        .and_then(|e| e.get("stack"))
        .and_then(|s| s.as_array())
    {
        let input: Vec<InputFrame> = stack.iter().filter_map(input_frame_from_json).collect();
        if !input.is_empty() {
            let frames = normalize_frames(&input);
            return Some(cluster_key_from_frames(&frames));
        }
    }
    if let Some(handler) = raw.get("handler").and_then(|v| v.as_object()) {
        let exception_name = handler
            .get("exception_name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let handler_file = handler
            .get("handler_file")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let handler_line = handler
            .get("handler_line")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let sequence_index = handler
            .get("sequence_index")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        let raises = raw
            .get("raises")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut frames: Vec<InputFrame> = Vec::new();
        frames.push(InputFrame::symbol(exception_name));
        frames.push(InputFrame::symbol(format!(
            "{}:{}",
            handler_file, handler_line
        )));
        let mut raise_pairs: Vec<(usize, String)> = raises
            .iter()
            .filter_map(|r| {
                let seq = r.get("sequence_index").and_then(|v| v.as_u64())? as usize;
                if seq >= sequence_index {
                    return None;
                }
                let file = r.get("file").and_then(|v| v.as_str())?.to_owned();
                let line = r.get("line").and_then(|v| v.as_u64())? as u32;
                Some((seq, format!("{}:{}", file, line)))
            })
            .collect();
        raise_pairs.sort_by_key(|(s, _)| *s);
        for (_, label) in raise_pairs.iter().take(2) {
            frames.push(InputFrame::symbol(label.clone()));
        }
        let normalized = normalize_frames(&frames);
        if !normalized.is_empty() {
            return Some(cluster_key_from_frames(&normalized));
        }
    }
    None
}

/// The root-cause key this release gives a sanitizer crash that an earlier
/// release recorded with no informative frame, rebuilt from the report the
/// finding stores.
///
/// Releases up to 0.3.0 keyed such a crash on its signature, which then hashed
/// only the rule and the crash kind: one constant key per rule, so every
/// frame-less UBSan report of a rule, at any site and in any harness, was one
/// root cause, and so was every frame-less crash with no sanitizer report of a
/// kind: a fatal signal (`FATAL_SIGNAL`, which 0.2.x named
/// `ASAN_FATAL_SIGNAL` and tagged `asan`), a transport-reported fault
/// (`TARGET_*`) and a transport deadline (`TRANSPORT_DEADLINE_EXCEEDED`). A
/// finding is read as one of those when its `cluster_key_full` is its
/// `signature`, marked `cluster_fallback`, with no normalized frames. A
/// sanitizer report is parsed again from its stored message; a crash with no
/// sanitizer report is rebuilt as the shared crash builder builds it now, with
/// no sanitizer and a fatal signal as its check. The location, check name,
/// crash stack (written later by `bhf report --backfill`) and pc offset the
/// record holds take precedence, and the key is computed in the finding's
/// harness scope as the emitter computes it ([`cluster_for_sanitizer_scoped`]).
///
/// `None` for any other record: one this release keyed (whose fallback key is
/// already scoped and sited), an oracle hit, a finding that is not a sanitizer
/// crash, and one whose stored report gives no better key than the one it has.
pub fn legacy_fallback_cluster_key(raw: &serde_json::Value) -> Option<ClusterKey> {
    use serde_json::Value;
    if raw.get("oracle").is_some()
        || raw.get("cluster_fallback").and_then(Value::as_bool) != Some(true)
    {
        return None;
    }
    let persisted = raw
        .get("cluster_key_full")
        .and_then(Value::as_str)
        .filter(|full| !full.is_empty())?;
    if raw.get("signature").and_then(Value::as_str) != Some(persisted) {
        return None;
    }
    let framed = raw
        .get("cluster_normalized_frames")
        .and_then(Value::as_array)
        .is_some_and(|frames| !frames.is_empty());
    let exception = raw.get("exception")?;
    let name = exception.get("name").and_then(Value::as_str).unwrap_or("");
    let undiagnosed = undiagnosed_crash_kind(name);
    let sanitizer_crash = exception.get("sanitizer").and_then(Value::as_str).is_some()
        || ["ASAN_", "UBSAN_", "LSAN_", "MSAN_", "TSAN_"]
            .iter()
            .any(|prefix| name.starts_with(prefix));
    if framed || !(sanitizer_crash || undiagnosed.is_some()) {
        return None;
    }
    let message = exception.get("message").and_then(Value::as_str)?;
    let mut report = match undiagnosed {
        Some(kind) => earlier_undiagnosed_crash_report(raw, exception, kind, message)?,
        None => crate::sanitizer::parse_sanitizer_report(message)?,
    };
    if let Some(location) = exception
        .get("location")
        .and_then(|value| serde_json::from_value(value.clone()).ok())
    {
        report.location = Some(location);
    }
    if let Some(check) = exception
        .get("check")
        .and_then(Value::as_str)
        .filter(|check| !check.is_empty())
    {
        // The check name decides a UBSan report's kind, as when the report
        // printed it.
        if report.sanitizer == Some(Sanitizer::UndefinedBehaviorSanitizer) {
            if let Some(kind) = finding_rules::ubsan::kind_for_check_name(check) {
                report.kind = kind.to_owned();
                report.rule_id = finding_rules::ubsan::rule_for_kind(kind);
            }
        }
        report.check = Some(check.to_owned());
    }
    if let Some(stack) = exception
        .get("stack")
        .and_then(|value| serde_json::from_value::<Vec<StackFrame>>(value.clone()).ok())
        .filter(|stack| !stack.is_empty())
    {
        report.stack = stack;
    }
    if let Some(offset) = exception
        .get("pc_offset")
        .and_then(Value::as_str)
        .and_then(|hex| u64::from_str_radix(hex.trim_start_matches("0x"), 16).ok())
    {
        report.pc_offset = Some(offset);
    }
    let harness = raw.get("harness_id").and_then(Value::as_str).unwrap_or("");
    let key = cluster_for_sanitizer_scoped(&report, &crash_scope(harness, None));
    (!key.is_placeholder() && key.full != persisted).then_some(key)
}

/// The kind of a crash with no sanitizer report, read from the name an
/// earlier release gave it: the shared crash builder's kind in upper case
/// (`FATAL_SIGNAL`, `TARGET_CPU_EXCEPTION`, `TRANSPORT_DEADLINE_EXCEEDED`),
/// which 0.2.x prefixed with `ASAN_`, as it tagged every such crash with
/// AddressSanitizer. No sanitizer report has one of these kinds.
fn undiagnosed_crash_kind(name: &str) -> Option<String> {
    let kind = name
        .strip_prefix("ASAN_")
        .unwrap_or(name)
        .to_ascii_lowercase()
        .replace('_', "-");
    (kind == "fatal-signal" || kind == "transport-deadline-exceeded" || kind.starts_with("target-"))
        .then_some(kind)
}

/// The report of a crash with no sanitizer report as the shared crash builder
/// makes it now: no sanitizer, whatever an earlier release tagged it with, and,
/// for a fatal signal, the signal it died by (recorded, or named in the
/// message, `harness crashed with SIGSEGV ...`) as its check.
fn earlier_undiagnosed_crash_report(
    raw: &serde_json::Value,
    exception: &serde_json::Value,
    kind: String,
    message: &str,
) -> Option<SanitizerReport> {
    use serde_json::Value;
    let rule_id = finding_rules::by_id(raw.get("rule_id").and_then(Value::as_str)?)?.id;
    let signal = (kind == "fatal-signal")
        .then(|| {
            ["signal", "check"]
                .iter()
                .find_map(|key| exception.get(*key).and_then(Value::as_str))
                .map(str::to_owned)
                .or_else(|| {
                    message
                        .split_whitespace()
                        .find(|word| {
                            word.len() > 3
                                && word.starts_with("SIG")
                                && word[3..].bytes().all(|b| b.is_ascii_uppercase())
                        })
                        .map(str::to_owned)
                })
        })
        .flatten();
    Some(SanitizerReport {
        sanitizer: None,
        kind,
        rule_id,
        message: message.to_owned(),
        check: signal,
        ..Default::default()
    })
}

fn input_frame_from_json(v: &serde_json::Value) -> Option<InputFrame> {
    let function = v.get("function").and_then(|f| f.as_str())?;
    if function.is_empty() {
        return None;
    }
    let file = v.get("file").and_then(|f| f.as_str()).map(str::to_owned);
    let line = v.get("line").and_then(|l| l.as_u64()).map(|n| n as u32);
    Some(InputFrame {
        function: function.to_owned(),
        file,
        line,
    })
}

/// Remove trailing whitespace-preceded balanced paren groups
/// (`(/path/build/main+0xfec85)`, `(BuildId: ...)`, etc.). C++
/// argument lists glued to the function name without whitespace
/// stay intact at this stage — they are stripped in `strip_cpp_args`.
fn strip_toolchain_decoration(raw: &str) -> String {
    let mut cursor = raw.trim_end();
    while let Some(stripped) = strip_one_trailing_paren_group(cursor) {
        cursor = stripped;
    }
    cursor.to_owned()
}

fn strip_one_trailing_paren_group(s: &str) -> Option<&str> {
    let trimmed = s.trim_end();
    if !trimmed.ends_with(')') {
        return None;
    }
    let bytes = trimmed.as_bytes();
    let mut depth = 0_i32;
    let mut open_idx: Option<usize> = None;
    for (i, b) in bytes.iter().enumerate().rev() {
        match b {
            b')' => depth += 1,
            b'(' => {
                depth -= 1;
                if depth == 0 {
                    open_idx = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let open = open_idx?;
    let preceding = &trimmed[..open];
    if !preceding.ends_with(char::is_whitespace) {
        return None;
    }
    Some(preceding.trim_end())
}

/// Strip a trailing C++ argument list and any trailing CV/ref
/// qualifiers (`const`, `&`, `&&`, `noexcept`). Preserves `operator`
/// overloads — if the substring immediately preceding the first
/// top-level `(` is `operator`, the original string is returned
/// unchanged.
fn strip_cpp_args(raw: &str) -> String {
    let trimmed = raw.trim();
    let Some(open) = find_top_level_open_paren(trimmed) else {
        return trimmed.to_owned();
    };
    let preceding = &trimmed[..open];
    if preceding.ends_with("operator") {
        return trimmed.to_owned();
    }
    preceding.trim_end().to_owned()
}

/// Byte index of the `(` that opens the argument list at template depth 0 in
/// `s`, skipping the literal `(anonymous namespace)` scope token — a
/// non-argument parenthetical embedded in a qualified C++ name (e.g.
/// `pugi::impl::(anonymous namespace)::strlength_wide(...)`), which would
/// otherwise be mistaken for the argument list and collapse the top frame.
fn find_top_level_open_paren(s: &str) -> Option<usize> {
    const ANON: &str = "(anonymous namespace)";
    let bytes = s.as_bytes();
    let mut angle = 0_i32;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'<' => angle += 1,
            b'>' => angle -= 1,
            b'(' if angle <= 0 => {
                if s[i..].starts_with(ANON) {
                    i += ANON.len();
                    continue;
                }
                return Some(i);
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sanitizer::{Sanitizer, SanitizerReport, StackFrame};
    use event_log::{HandlerEvent, RaiseEvent, Testcase};

    fn fr(function: &str) -> InputFrame {
        InputFrame::symbol(function)
    }

    #[test]
    fn input_frame_symbol_constructor_omits_file_and_line() {
        let frame = InputFrame::symbol("foo");
        assert_eq!(frame.function, "foo");
        assert!(frame.file.is_none());
        assert!(frame.line.is_none());
    }

    #[test]
    fn normalize_strips_module_offset_annotation() {
        let frames = vec![fr("foo (/tmp/build/main+0xfec85)")];
        let out = normalize_frames(&frames);
        assert_eq!(out, vec!["foo".to_owned()]);
    }

    #[test]
    fn normalize_strips_buildid_blob() {
        let frames = vec![fr("foo (BuildId: deadbeef)")];
        let out = normalize_frames(&frames);
        assert_eq!(out, vec!["foo".to_owned()]);
    }

    #[test]
    fn normalize_drops_sanitizer_infrastructure_frames() {
        let frames = vec![
            fr("__asan_memcpy"),
            fr("__sanitizer_internal"),
            fr("__interceptor_strlen"),
            fr("__ubsan_handle_signed_overflow"),
            fr("real_target_fn"),
        ];
        let out = normalize_frames(&frames);
        assert_eq!(out, vec!["real_target_fn".to_owned()]);
    }

    #[test]
    fn normalize_drops_libfuzzer_scaffolding() {
        let frames = vec![
            fr("LLVMFuzzerTestOneInput"),
            fr("LLVMFuzzerRunDriver"),
            fr("fuzzer::Fuzzer::ExecuteCallback"),
            fr("main"),
            fr("__libc_start_main"),
            fr("_start"),
            fr("my_target_parse"),
        ];
        let out = normalize_frames(&frames);
        assert_eq!(out, vec!["my_target_parse".to_owned()]);
    }

    #[test]
    fn normalize_strips_cpp_arg_list_but_keeps_operator_call() {
        let frames = vec![
            fr("Foo::Bar(int, char const*)"),
            fr("Baz::operator()(int)"),
            fr("Qux::operator()"),
        ];
        let out = normalize_frames(&frames);
        assert_eq!(
            out,
            vec![
                "Foo::Bar".to_owned(),
                "Baz::operator()(int)".to_owned(),
                "Qux::operator()".to_owned(),
            ]
        );
    }

    #[test]
    fn normalize_keeps_anonymous_namespace_and_strips_only_arg_list() {
        // The "(anonymous namespace)" scope token must not be mistaken for the
        // argument list — only the trailing "(const wchar_t*)" is stripped.
        let frames = vec![fr(
            "pugi::impl::(anonymous namespace)::strlength_wide(wchar_t const*)",
        )];
        let out = normalize_frames(&frames);
        assert_eq!(
            out,
            vec!["pugi::impl::(anonymous namespace)::strlength_wide".to_owned()]
        );
    }

    #[test]
    fn normalize_strips_cpp_trailing_qualifiers() {
        let frames = vec![fr("Foo::Bar(int) const noexcept")];
        let out = normalize_frames(&frames);
        assert_eq!(out, vec!["Foo::Bar".to_owned()]);
    }

    #[test]
    fn normalize_truncates_to_top_3() {
        let frames = vec![fr("a"), fr("b"), fr("c"), fr("d"), fr("e")];
        let out = normalize_frames(&frames);
        assert_eq!(out, vec!["a", "b", "c"]);
    }

    #[test]
    fn normalize_returns_empty_when_only_noise_present() {
        let frames = vec![fr("__asan_memcpy"), fr("LLVMFuzzerTestOneInput")];
        let out = normalize_frames(&frames);
        assert!(out.is_empty());
    }

    #[test]
    fn normalize_drops_libc_runtime_and_bhf_harness_frames() {
        // #31: fprintf (libc) + bhf_run_one (harness) are scaffolding — the key
        // must start at the first in-project frame (stdout_callback).
        let frames = vec![
            fr("fprintf"),
            fr("bhf_run_one"),
            fr("stdout_callback"),
            fr("log_log"),
        ];
        let out = normalize_frames(&frames);
        assert_eq!(
            out,
            vec!["stdout_callback".to_owned(), "log_log".to_owned()]
        );
    }

    #[test]
    fn normalize_drops_rust_allocator_and_runtime_scaffolding() {
        let frames = vec![
            fr("malloc"),
            fr("<alloc::raw_vec::RawVecInner>::try_allocate_in"),
            fr("<alloc::vec::Vec<u8>>::with_capacity_in"),
            fr("<str as alloc::borrow::ToOwned>::to_owned"),
            fr("<rust_runtime::Cursor>::string"),
            fr("bhf_run_one"),
            fr("bhf_run_one_bytes"),
            fr("main"),
        ];
        let out = normalize_frames(&frames);
        assert!(
            out.is_empty(),
            "scaffolding frames must not form a cluster: {out:?}"
        );
    }

    #[test]
    fn normalize_keeps_rust_target_frame_after_allocator_noise() {
        let frames = vec![
            fr("malloc"),
            fr("<alloc::raw_vec::RawVecInner>::try_allocate_in"),
            fr("<alloc::vec::Vec<u8>>::with_capacity_in"),
            fr("roxmltree::ExpandedName::from_static"),
            fr("bhf_run_one"),
        ];
        let out = normalize_frames(&frames);
        assert_eq!(out, vec!["roxmltree::ExpandedName::from_static".to_owned()]);
    }

    #[test]
    fn cluster_one_root_cause_regardless_of_runtime_pc_landing() {
        // #31: the same log.c bug crashing inside the format machinery on one input
        // and at the project array load on another must cluster to ONE issue.
        let in_fprintf = cluster_for_sanitizer(&sample_sanitizer_report(vec![
            "fprintf",
            "stdout_callback",
            "log_log",
        ]));
        let in_array =
            cluster_for_sanitizer(&sample_sanitizer_report(vec!["stdout_callback", "log_log"]));
        assert!(!in_fprintf.fallback);
        assert_eq!(in_fprintf.full, in_array.full);
    }

    fn sample_leak_report(frames: Vec<&str>) -> SanitizerReport {
        SanitizerReport {
            sanitizer: Some(Sanitizer::LeakSanitizer),
            kind: "memory-leak".to_owned(),
            rule_id: "BHF-208",
            stack: frames
                .into_iter()
                .map(|f| StackFrame {
                    function: f.to_owned(),
                    file: None,
                    line: None,
                })
                .collect(),
            message: "ERROR: LeakSanitizer: detected memory leaks".to_owned(),
            ..Default::default()
        }
    }

    #[test]
    fn harness_scaffolding_leak_suppressed_when_every_frame_is_bhf() {
        // #49: a leak whose whole allocation stack is bhf's bhf_* decoder +
        // harness scaffolding (unfreed because an exit()-only target died first) is
        // suppressed, not reported as a target CWE-401.
        let report = sample_leak_report(vec!["malloc", "bhf_c_string", "bhf_run_one"]);
        assert!(is_harness_scaffolding_leak(&report, true));
    }

    #[test]
    fn rust_static_decoder_leak_is_harness_scaffolding() {
        // #44: Rust &'static decoders intentionally Box::leak fuzz-owned strings.
        // LSan reports those allocations through Rust std/allocator frames before
        // reaching rust_runtime::Cursor and bhf_run_one; that is generated
        // harness scaffolding, not a target CWE-401.
        let report = sample_leak_report(vec![
            "malloc",
            "<alloc::raw_vec::RawVecInner>::try_allocate_in",
            "<alloc::vec::Vec<u8>>::with_capacity_in",
            "<str as alloc::borrow::ToOwned>::to_owned",
            "<rust_runtime::Cursor>::string",
            "bhf_run_one",
            "bhf_run_one_bytes",
            "main",
        ]);
        assert!(is_harness_scaffolding_leak(&report, true));
    }

    #[test]
    fn rust_static_decoder_shrink_leak_with_allocator_only_stack_is_scaffolding() {
        // #44: into_boxed_str may shrink through realloc and produce a symbolized
        // LSan stack containing only Rust std allocator frames. With no target
        // frame, this is still the generated Box::leak decoder allocation.
        let report = sample_leak_report(vec![
            "realloc",
            "alloc::alloc::realloc_nonnull",
            "<alloc::alloc::Global>::shrink_impl_runtime",
            "<alloc::alloc::Global>::shrink_impl",
            "<alloc::alloc::Global as core::alloc::Allocator>::shrink",
            "<alloc::raw_vec::RawVecInner>::shrink_unchecked",
        ]);
        assert!(is_harness_scaffolding_leak(&report, true));
    }

    #[test]
    fn harness_scaffolding_leak_false_with_a_target_frame() {
        // #49 guard: a leak WITH a real target frame is genuine — never suppressed.
        let report = sample_leak_report(vec!["malloc", "bhf_c_string", "toml_parse_table"]);
        assert!(!is_harness_scaffolding_leak(&report, true));
    }

    #[test]
    fn harness_scaffolding_leak_false_for_non_leak_sanitizer() {
        // Only LSan leaks are in scope; an ASan overflow with bhf_ frames is handled
        // by the harness-cleanup-artifact verdict path, not suppressed here.
        let report = sample_sanitizer_report(vec!["bhf_c_string", "bhf_run_one"]);
        assert!(!is_harness_scaffolding_leak(&report, true));
    }

    #[test]
    fn cluster_key_from_frames_is_deterministic() {
        let a = cluster_key_from_frames(&["foo".to_owned(), "bar".to_owned()]);
        let b = cluster_key_from_frames(&["foo".to_owned(), "bar".to_owned()]);
        assert_eq!(a.short, b.short);
        assert_eq!(a.full, b.full);
        assert_eq!(a.frames, vec!["foo", "bar"]);
        assert!(!a.fallback);
    }

    #[test]
    fn cluster_key_short_is_16_hex_chars() {
        let key = cluster_key_from_frames(&["foo".to_owned()]);
        assert_eq!(key.short.len(), 16);
        assert!(key.short.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(key.short.chars().all(|c| !c.is_ascii_uppercase()));
    }

    #[test]
    fn cluster_key_changes_when_frames_differ() {
        let a = cluster_key_from_frames(&["foo".to_owned()]);
        let b = cluster_key_from_frames(&["bar".to_owned()]);
        assert_ne!(a.short, b.short);
    }

    #[test]
    fn cluster_key_full_is_64_hex_chars() {
        let key = cluster_key_from_frames(&["foo".to_owned()]);
        assert_eq!(key.full.len(), 64);
    }

    #[test]
    fn cluster_key_from_empty_frames_marks_fallback_with_zero_padding() {
        let key = cluster_key_from_frames(&[]);
        assert!(key.fallback);
        assert!(key.frames.is_empty());
        assert_eq!(key.short, "0000000000000000");
    }

    #[test]
    fn cluster_key_struct_serializes_short_as_string() {
        let key = ClusterKey {
            short: "abcd1234deadbeef".to_owned(),
            full: "abcd1234deadbeef".repeat(4),
            frames: vec!["foo".to_owned()],
            fallback: false,
        };
        let v = serde_json::to_value(&key).unwrap();
        assert_eq!(v["short"], "abcd1234deadbeef");
        assert_eq!(v["fallback"], false);
        assert_eq!(v["frames"][0], "foo");
    }

    fn sample_sanitizer_report(frames: Vec<&str>) -> SanitizerReport {
        SanitizerReport {
            sanitizer: Some(Sanitizer::AddressSanitizer),
            kind: "heap-buffer-overflow".to_owned(),
            rule_id: "BHF-201",
            stack: frames
                .into_iter()
                .map(|f| StackFrame {
                    function: f.to_owned(),
                    file: None,
                    line: None,
                })
                .collect(),
            message: "ERROR: AddressSanitizer: heap-buffer-overflow".to_owned(),
            ..Default::default()
        }
    }

    #[test]
    fn cluster_for_sanitizer_drops_scaffolding_and_keeps_target_frames() {
        let report = sample_sanitizer_report(vec![
            "__asan_memcpy",
            "real_parse",
            "real_dispatch",
            "LLVMFuzzerTestOneInput",
        ]);
        let key = cluster_for_sanitizer(&report);
        assert!(!key.fallback);
        assert_eq!(key.frames, vec!["real_parse", "real_dispatch"]);
    }

    #[test]
    fn cluster_for_sanitizer_equal_for_same_target_frames_with_different_scaffolding() {
        let a = cluster_for_sanitizer(&sample_sanitizer_report(vec![
            "__asan_memcpy",
            "real_parse",
            "main",
        ]));
        let b = cluster_for_sanitizer(&sample_sanitizer_report(vec![
            "__sanitizer_internal",
            "real_parse",
            "_start",
        ]));
        assert_eq!(a.short, b.short);
    }

    #[test]
    fn cluster_for_sanitizer_differs_when_target_frames_differ() {
        let a = cluster_for_sanitizer(&sample_sanitizer_report(vec!["real_parse_v1"]));
        let b = cluster_for_sanitizer(&sample_sanitizer_report(vec!["real_parse_v2"]));
        assert_ne!(a.short, b.short);
    }

    #[test]
    fn cluster_for_sanitizer_marks_fallback_when_all_noise() {
        let report = sample_sanitizer_report(vec!["__asan_memcpy", "main"]);
        let key = cluster_for_sanitizer(&report);
        assert!(key.fallback);
    }

    #[test]
    fn normalize_drops_cpp_namespace_sanitizer_and_fuzzer_frames() {
        let frames = vec![
            fr("__asan::Allocator::Deallocate"),
            fr("fuzzer::RunOneTest"),
            fr("real_target"),
        ];
        let out = normalize_frames(&frames);
        assert_eq!(out, vec!["real_target".to_owned()]);
    }

    #[test]
    fn is_driver_glue_crash_true_for_allocator_glue_stack() {
        let report = sample_sanitizer_report(vec![
            "__asan::Allocator::Deallocate",
            "free",
            "fuzzer::RunOneTest",
        ]);
        assert!(is_driver_glue_crash(&report, true));
    }

    #[test]
    fn is_driver_glue_crash_false_when_target_frame_present() {
        let report =
            sample_sanitizer_report(vec!["cJSON_GetObjectItem", "free", "fuzzer::RunOneTest"]);
        assert!(!is_driver_glue_crash(&report, true));
    }

    /// `LLVMFuzzerTestOneInput` is driver code only in a harness bhf
    /// generated around a target of its own; in a project's own fuzz target
    /// (a hand-built libFuzzer binary, or bhf's driver around it) its body is
    /// the target.
    #[test]
    fn a_crash_in_a_projects_own_fuzz_entry_is_not_driver_glue() {
        let mut report = sample_sanitizer_report(vec![
            "LLVMFuzzerTestOneInput",
            "fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long)",
            "fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long)",
            "main",
        ]);
        report.stack[0].file = Some("/src/fuzz/f.c".to_owned());
        report.stack[0].line = Some(9);
        assert!(!is_driver_glue_crash(&report, false));
        assert!(is_driver_glue_crash(&report, true));
        // The runtime's own entry points stay driver frames either way.
        let runtime = sample_sanitizer_report(vec![
            "__asan::Allocator::Deallocate",
            "LLVMFuzzerRunDriver",
            "fuzzer::RunOneTest",
        ]);
        assert!(is_driver_glue_crash(&runtime, false));
        let allocator = sample_sanitizer_report(vec![
            "__asan::Allocator::Deallocate",
            "free",
            "fuzzer::RunOneTest",
        ]);
        assert!(is_driver_glue_crash(&allocator, false));
        assert!(is_driver_glue_crash(&allocator, true));
    }

    #[test]
    fn a_leak_in_a_projects_own_fuzz_entry_is_not_scaffolding() {
        let report = sample_leak_report(vec!["malloc", "LLVMFuzzerTestOneInput"]);
        assert!(!is_harness_scaffolding_leak(&report, false));
        assert!(is_harness_scaffolding_leak(&report, true));
    }

    /// The fuzz entry in a glue file bhf writes into a harness dir (the
    /// Fortran and COBOL lanes' glue, the libFuzzer shim) is bhf's code even
    /// where nothing else says bhf generated the entry, such as a harness
    /// built before the glue carried a marker.
    #[test]
    fn a_fuzz_entry_in_bhf_glue_is_harness_code() {
        let leak = |file: &str| {
            let mut report = sample_leak_report(vec![
                "malloc",
                "LLVMFuzzerTestOneInput",
                "bhf_run_one_bytes",
                "main",
            ]);
            report.stack[1].file = Some(file.to_owned());
            report.stack[1].line = Some(42);
            report
        };
        for glue in [
            "/w/harnesses/H-F/fortran_glue.c",
            "/w/harnesses/H-C/cobol_glue.c",
            "bhf_libfuzzer.c",
            "C:\\w\\harnesses\\H-C\\cobol_glue.c",
        ] {
            assert!(is_harness_scaffolding_leak(&leak(glue), false), "{glue}");
        }
        assert!(!is_harness_scaffolding_leak(
            &leak("/src/fuzz/fortran_glue_test.c"),
            false
        ));
        assert!(!is_harness_scaffolding_leak(&leak("/src/fuzz/f.c"), false));

        let crash = |file: &str| {
            let mut report = sample_sanitizer_report(vec![
                "LLVMFuzzerTestOneInput",
                "fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long)",
            ]);
            report.stack[0].file = Some(file.to_owned());
            report
        };
        assert!(is_driver_glue_crash(
            &crash("/w/auto/H-R/bhf_libfuzzer.c"),
            false
        ));
        assert!(!is_driver_glue_crash(&crash("/src/fuzz/f.c"), false));
    }

    #[test]
    fn is_driver_glue_crash_false_for_unsymbolized_only_stack() {
        // module+offset frames with no recognizable driver frame: leave the
        // verdict to replay-verification rather than silently dropping it.
        let report = sample_sanitizer_report(vec!["(/opt/build/main+0x12ab)"]);
        assert!(!is_driver_glue_crash(&report, true));
    }

    fn handler_event(name: &str, file: &str, line: u32, last_breadcrumb: u32) -> HandlerEvent {
        HandlerEvent {
            sequence_index: 3,
            exception_name: name.to_owned(),
            exception_message: "msg".to_owned(),
            handler_file: file.to_owned(),
            handler_line: line,
            last_breadcrumb,
            target_id: 0x42,
            testcase_id: 1,
        }
    }

    fn testcase_with(handlers: Vec<HandlerEvent>, raises: Vec<RaiseEvent>) -> Testcase {
        Testcase {
            testcase_id: 1,
            target_id: 0x42,
            target_entered: false,
            crumbs: vec![1],
            handlers,
            raises,
            top_level: None,
            end: None,
            mocks: Vec::new(),
        }
    }

    #[test]
    fn cluster_for_ada_uses_exception_name_and_handler_location() {
        let h = handler_event("CONSTRAINT_ERROR", "pkg.adb", 9, 1);
        let key = cluster_for_ada(&testcase_with(vec![h.clone()], vec![]), &h);
        assert!(!key.fallback);
        assert_eq!(
            key.frames,
            vec!["CONSTRAINT_ERROR".to_owned(), "pkg.adb:9".to_owned(),]
        );
    }

    #[test]
    fn cluster_for_ada_includes_preceding_raise_chain() {
        let h = handler_event("CONSTRAINT_ERROR", "pkg.adb", 9, 1);
        let raises = vec![RaiseEvent {
            sequence_index: 1,
            exception_name: "CONSTRAINT_ERROR".to_owned(),
            file: "inner.adb".to_owned(),
            line: 22,
            breadcrumb: 7,
        }];
        let key = cluster_for_ada(&testcase_with(vec![h.clone()], raises), &h);
        assert_eq!(
            key.frames,
            vec![
                "CONSTRAINT_ERROR".to_owned(),
                "pkg.adb:9".to_owned(),
                "inner.adb:22".to_owned(),
            ]
        );
    }

    #[test]
    fn cluster_for_ada_distinguishes_different_raise_sites_same_handler() {
        let h = handler_event("CONSTRAINT_ERROR", "pkg.adb", 9, 1);
        let a = cluster_for_ada(
            &testcase_with(
                vec![h.clone()],
                vec![RaiseEvent {
                    sequence_index: 1,
                    exception_name: "CONSTRAINT_ERROR".to_owned(),
                    file: "a.adb".to_owned(),
                    line: 1,
                    breadcrumb: 1,
                }],
            ),
            &h,
        );
        let b = cluster_for_ada(
            &testcase_with(
                vec![h.clone()],
                vec![RaiseEvent {
                    sequence_index: 1,
                    exception_name: "CONSTRAINT_ERROR".to_owned(),
                    file: "b.adb".to_owned(),
                    line: 1,
                    breadcrumb: 1,
                }],
            ),
            &h,
        );
        assert_ne!(a.short, b.short);
    }

    #[test]
    fn cluster_from_finding_json_uses_existing_cluster_key_full_when_present() {
        let raw = serde_json::json!({
            "cluster_key_full": "ab".repeat(32),
            "cluster_normalized_frames": ["foo", "bar"],
        });
        let key = cluster_from_finding_json(&raw).expect("present");
        assert_eq!(key.full, "ab".repeat(32));
        assert_eq!(key.short, &"ab".repeat(32)[..16]);
        assert_eq!(key.frames, vec!["foo", "bar"]);
        assert!(!key.fallback);
    }

    #[test]
    fn cluster_from_finding_json_backfills_from_exception_stack() {
        let raw = serde_json::json!({
            "exception": {
                "stack": [
                    { "function": "__asan_memcpy" },
                    { "function": "target_parse", "file": "/src/p.c", "line": 9 },
                    { "function": "LLVMFuzzerTestOneInput" },
                ]
            }
        });
        let key = cluster_from_finding_json(&raw).expect("present");
        assert_eq!(key.frames, vec!["target_parse"]);
        assert!(!key.fallback);
    }

    #[test]
    fn cluster_from_finding_json_backfills_from_handler_for_ada() {
        let raw = serde_json::json!({
            "exception": { "name": "CONSTRAINT_ERROR" },
            "handler": {
                "exception_name": "CONSTRAINT_ERROR",
                "handler_file": "pkg.adb",
                "handler_line": 9,
                "sequence_index": 3
            },
            "raises": []
        });
        let key = cluster_from_finding_json(&raw).expect("present");
        assert_eq!(
            key.frames,
            vec!["CONSTRAINT_ERROR".to_owned(), "pkg.adb:9".to_owned()]
        );
    }

    #[test]
    fn cluster_from_finding_json_returns_none_when_nothing_usable() {
        let raw = serde_json::json!({ "id": "F-0001", "signature": "deadbeef" });
        assert!(cluster_from_finding_json(&raw).is_none());
    }

    fn located(function: &str, file: &str, line: u32) -> InputFrame {
        InputFrame {
            function: function.to_owned(),
            file: Some(file.to_owned()),
            line: Some(line),
        }
    }

    /// A fault inside a libc string routine reached through a sanitizer
    /// interceptor: the key must start at the first project frame, not at the
    /// runtime frames every such crash shares.
    #[test]
    fn libc_and_sanitizer_interceptor_frames_are_cluster_noise() {
        let frames = vec![
            located(
                "__memcmp_avx2_movbe",
                "string/../sysdeps/x86_64/multiarch/memcmp-avx2-movbe.S",
                84,
            ),
            fr("MemcmpInterceptorCommon(void*, int (*)(void const*, void const*, unsigned long), void const*, void const*, unsigned long)"),
            located(
                "bcmp",
                "/llvm/compiler-rt/lib/sanitizer_common/sanitizer_common_interceptors.inc",
                860,
            ),
            located("Widget::parse_record(unsigned char const*)", "/src/widget/parser.cc", 11),
            fr("Widget::load()"),
        ];
        assert_eq!(
            normalize_frames(&frames),
            vec!["Widget::parse_record".to_owned(), "Widget::load".to_owned()]
        );
    }

    /// An `assert()` abort unwinds through glibc's signal, abort and assert
    /// sources before the failing check; none of them names the root cause.
    #[test]
    fn glibc_abort_and_assert_frames_are_cluster_noise() {
        let frames = vec![
            located("__pthread_kill_implementation", "nptl/pthread_kill.c", 44),
            located("raise", "signal/../sysdeps/posix/raise.c", 26),
            located("abort", "stdlib/abort.c", 79),
            located("__assert_fail_base", "assert/assert.c", 96),
            located("__assert_fail", "assert/assert.c", 105),
            located("check_record", "/src/widget/check.c", 3),
            located("parse_record", "/src/widget/check.c", 9),
        ];
        assert_eq!(
            normalize_frames(&frames),
            vec!["check_record".to_owned(), "parse_record".to_owned()]
        );
    }

    /// A project whose relative source paths start with a directory named like
    /// a glibc component (`./io/scaled_reader.cpp`) keeps those frames in its key;
    /// glibc's own frames under such dirs are still noise.
    #[test]
    fn project_frames_in_dirs_named_like_glibc_components_are_kept() {
        let frames = vec![
            located("read_scaled(int)", "./io/scaled_reader.cpp", 4),
            located("Widget::load()", "./misc/widget.cpp", 9),
            located(
                "__libc_start_call_main",
                "../sysdeps/nptl/libc_start_call_main.h",
                58,
            ),
            located("__libc_start_main", "csu/../csu/libc-start.c", 360),
        ];
        assert_eq!(
            normalize_frames(&frames),
            vec!["read_scaled".to_owned(), "Widget::load".to_owned()]
        );
    }

    #[test]
    fn interceptor_crashes_from_different_callers_do_not_share_a_cluster() {
        let report = |caller: &str| {
            crate::sanitizer::parse_sanitizer_report(&format!(
                "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000012\n\
                 READ of size 8 at 0x502000000012 thread T0\n    \
                 #0 0x1 in MemcmpInterceptorCommon(void*, int (*)(void const*, void const*, unsigned long), void const*, void const*, unsigned long) (/bin/h+0x48a9b)\n    \
                 #1 0x2 in bcmp (/bin/h+0x48f70)\n    \
                 #2 0x3 in {caller} /src/widget/{caller}.c:19:65\n"
            ))
            .unwrap()
        };
        let a = cluster_for_sanitizer(&report("check_magic"));
        let b = cluster_for_sanitizer(&report("compare_names"));
        assert_eq!(a.frames, vec!["check_magic".to_owned()]);
        assert_ne!(a.full, b.full);
    }

    fn ubsan(text: &str) -> SanitizerReport {
        crate::sanitizer::parse_sanitizer_report(text).expect("a UBSan report")
    }

    fn missing_return_at(line: u32) -> SanitizerReport {
        ubsan(&format!(
            "/src/widget/classify.c:{line}:5: runtime error: execution reached the end of a value-returning function without returning a value\n\
             SUMMARY: UndefinedBehaviorSanitizer: missing-return /src/widget/classify.c:{line}:5 \n"
        ))
    }

    #[test]
    fn frameless_ubsan_reports_at_different_sites_get_distinct_cluster_keys() {
        let a = cluster_for_sanitizer(&missing_return_at(3));
        let b = cluster_for_sanitizer(&missing_return_at(9));
        assert!(!a.fallback && !b.fallback, "the site is an identity");
        assert_ne!(a.full, b.full);
        assert_eq!(a, cluster_for_sanitizer(&missing_return_at(3)));
    }

    #[test]
    fn distinct_checks_in_one_function_get_distinct_cluster_keys() {
        let shift = ubsan(
            "/src/widget/two.c:5:15: runtime error: shift exponent 40 is too large for 32-bit type 'int'\n    \
             #0 0x1 in two_sites /src/widget/two.c:5:15\n    \
             #1 0x2 in bhf_run_one /work/harnesses/H-1/main.c:9:3\n\n\
             SUMMARY: UndefinedBehaviorSanitizer: invalid-shift-exponent /src/widget/two.c:5:15 \n",
        );
        let missing_return = ubsan(
            "/src/widget/two.c:3:5: runtime error: execution reached the end of a value-returning function without returning a value\n    \
             #0 0x1 in two_sites /src/widget/two.c:7:1\n    \
             #1 0x2 in bhf_run_one /work/harnesses/H-1/main.c:9:3\n\n\
             SUMMARY: UndefinedBehaviorSanitizer: missing-return /src/widget/two.c:3:5 \n",
        );
        let a = cluster_for_sanitizer(&shift);
        let b = cluster_for_sanitizer(&missing_return);
        assert_eq!(a.frames, b.frames, "same function");
        assert_ne!(
            a.full, b.full,
            "different UB sites are different root causes"
        );
    }

    #[test]
    fn one_ubsan_site_reached_from_different_callers_shares_a_cluster() {
        let via = |caller: &str| {
            ubsan(&format!(
                "/src/widget/classify.c:3:5: runtime error: execution reached the end of a value-returning function without returning a value\n    \
                 #0 0x1 in classify /src/widget/classify.c:8:16\n    \
                 #1 0x2 in {caller} /src/widget/callers.c:4:3\n\n\
                 SUMMARY: UndefinedBehaviorSanitizer: missing-return /src/widget/classify.c:3:5 \n"
            ))
        };
        assert_eq!(
            cluster_for_sanitizer(&via("classify_pair")).full,
            cluster_for_sanitizer(&via("classify_with_bias")).full
        );
    }

    #[test]
    fn asan_and_ubsan_reports_in_one_function_do_not_share_a_cluster() {
        let asan = sample_sanitizer_report(vec!["scale_value"]);
        let ubsan = ubsan(
            "/src/widget/scale.c:16:12: runtime error: signed integer overflow: 2147483647 * 2 cannot be represented in type 'int'\n    \
             #0 0x1 in scale_value /src/widget/scale.c:16:12\n",
        );
        assert_ne!(
            cluster_for_sanitizer(&asan).full,
            cluster_for_sanitizer(&ubsan).full
        );
    }

    /// A fatal signal with no sanitizer report: no frames, no source position.
    fn frameless_signal(pc_offset: Option<u64>) -> SanitizerReport {
        SanitizerReport {
            sanitizer: None,
            kind: "fatal-signal".to_owned(),
            rule_id: "BHF-210",
            message: "harness crashed with SIGSEGV and no sanitizer report".to_owned(),
            pc_offset,
            ..Default::default()
        }
    }

    /// Frame-less crashes of two harnesses are two root causes; the same
    /// harness keeps one key for them. The key is still a fallback key.
    #[test]
    fn frameless_crashes_of_different_harnesses_are_different_root_causes() {
        let report = frameless_signal(None);
        let parse = cluster_for_sanitizer_scoped(&report, "H-PARSE|parse_record");
        let copy = cluster_for_sanitizer_scoped(&report, "H-COPY|copy_at");
        assert_ne!(parse.full, copy.full);
        assert_eq!(
            parse,
            cluster_for_sanitizer_scoped(&report, "H-PARSE|parse_record")
        );
        assert!(parse.fallback && copy.fallback);
        assert!(!parse.is_placeholder() && !copy.is_placeholder());
        assert_eq!(parse.full.len(), 64);
        // Without a scope the key stays the placeholder the emitter replaces
        // with the signature.
        assert!(cluster_for_sanitizer(&report).is_placeholder());
    }

    /// The faulting instruction's offset separates two crash sites of one
    /// harness.
    #[test]
    fn frameless_crashes_at_different_pcs_of_one_harness_are_different_root_causes() {
        let scope = "H-PARSE|parse_record";
        let a = cluster_for_sanitizer_scoped(&frameless_signal(Some(0x1b3c)), scope);
        let b = cluster_for_sanitizer_scoped(&frameless_signal(Some(0x2a10)), scope);
        assert_ne!(a.full, b.full);
        assert_eq!(
            a,
            cluster_for_sanitizer_scoped(&frameless_signal(Some(0x1b3c)), scope)
        );
        assert_ne!(
            a.full,
            cluster_for_sanitizer_scoped(&frameless_signal(None), scope).full
        );
    }

    /// A report with frames keys on them whatever the scope.
    #[test]
    fn a_scope_does_not_change_the_key_of_a_report_with_frames() {
        let report = sample_sanitizer_report(vec!["real_parse"]);
        assert_eq!(
            cluster_for_sanitizer_scoped(&report, "H-A"),
            cluster_for_sanitizer(&report)
        );
    }

    const MISSING_RETURN: &str =
        "runtime error: execution reached the end of a value-returning function without returning a value";

    /// A finding as releases up to 0.3.0 recorded a sanitizer crash with no
    /// frames: its signature hashed only the rule and kind, and its cluster
    /// key was that signature, one constant per rule.
    fn earlier_frameless(
        harness: &str,
        message: &str,
        rule: &str,
        kind: &str,
    ) -> serde_json::Value {
        let signature = hex_lower(&Sha256::digest(format!("{rule}|{kind}").as_bytes()));
        serde_json::json!({
            "id": format!("F-0000-{}", &signature[..8]),
            "signature": signature,
            "cluster_key": &signature[..16],
            "cluster_key_full": signature,
            "cluster_normalized_frames": [],
            "cluster_fallback": true,
            "rule_id": rule,
            "classification": "unhandled",
            "harness_id": harness,
            "exception": {
                "name": format!("UBSAN_{}", kind.to_uppercase().replace('-', "_")),
                "message": message,
                "sanitizer": "ubsan",
                "stack": [],
            },
        })
    }

    fn earlier_missing_return(harness: &str, site: &str) -> serde_json::Value {
        earlier_frameless(
            harness,
            &format!("{site}: {MISSING_RETURN}"),
            "BHF-210",
            "undefined-behavior",
        )
    }

    /// Frame-less UBSan findings an earlier release recorded share one key per
    /// rule. Read back, each is keyed on its reported site as this release
    /// keys it, so unrelated sites are separate root causes and one site
    /// reached from two harnesses is still one.
    #[test]
    fn earlier_frameless_findings_are_rekeyed_on_their_reported_site() {
        let records = [
            earlier_missing_return("H-C0001", "/src/widget/parse.cpp:12:1"),
            earlier_missing_return("H-C0002", "/src/widget/parse.cpp:19:1"),
            earlier_missing_return("H-C0003", "/src/widget/scale.cpp:7:1"),
            earlier_missing_return("H-C0004", "/src/widget/parse.cpp:12:1"),
        ];
        let persisted = records[0]["cluster_key_full"].as_str().unwrap().to_owned();
        assert!(records
            .iter()
            .all(|r| r["cluster_key_full"].as_str() == Some(persisted.as_str())));
        let keys: Vec<ClusterKey> = records
            .iter()
            .map(|r| cluster_from_finding_json(r).expect("a key"))
            .collect();
        for key in &keys {
            assert_ne!(key.full, persisted, "{key:?}");
            assert_eq!(key.short, key.full[..16]);
            assert!(!key.fallback, "the site is an identity: {key:?}");
        }
        assert_ne!(keys[0].full, keys[1].full);
        assert_ne!(keys[0].full, keys[2].full);
        assert_ne!(keys[1].full, keys[2].full);
        assert_eq!(keys[0].full, keys[3].full, "one site, two harnesses");
        // The key this release gives the same frame-less report.
        let report = crate::sanitizer::parse_sanitizer_report(&format!(
            "/src/widget/parse.cpp:12:1: {MISSING_RETURN}\n"
        ))
        .unwrap();
        assert_eq!(
            keys[0],
            cluster_for_sanitizer_scoped(&report, &crash_scope("H-C0001", None))
        );
        assert_eq!(
            Some(keys[0].clone()),
            legacy_fallback_cluster_key(&records[0])
        );
    }

    /// Frames recorded later (`bhf report --backfill`) key the finding as
    /// they key a report that carries them.
    #[test]
    fn an_earlier_frameless_finding_with_backfilled_frames_keys_on_them() {
        let mut record = earlier_missing_return("H-C0001", "/src/widget/parse.cpp:12:1");
        record["exception"]["stack"] = serde_json::json!([
            {"function": "classify", "file": "/src/widget/parse.cpp", "line": 12},
            {"function": "bhf_run_one", "file": "/work/harnesses/H-C0001/main.cpp", "line": 9},
        ]);
        record["exception"]["check"] = serde_json::json!("missing-return");
        let report = crate::sanitizer::parse_sanitizer_report(&format!(
            "/src/widget/parse.cpp:12:1: {MISSING_RETURN}\n    \
             #0 0x1 in classify /src/widget/parse.cpp:12\n    \
             #1 0x2 in bhf_run_one /work/harnesses/H-C0001/main.cpp:9\n\n\
             SUMMARY: UndefinedBehaviorSanitizer: missing-return /src/widget/parse.cpp:12:1 \n"
        ))
        .unwrap();
        assert_eq!(
            cluster_from_finding_json(&record),
            Some(cluster_for_sanitizer_scoped(&report, "H-C0001"))
        );
    }

    /// An earlier frame-less crash with no reported site either is grouped
    /// per harness, as this release groups one.
    #[test]
    fn an_earlier_siteless_frameless_finding_is_grouped_per_harness() {
        let segv = |harness: &str| {
            let mut record = earlier_frameless(
                harness,
                "==1==ERROR: AddressSanitizer: SEGV on unknown address 0x7f0000001000 \
                 (pc 0x55 bp 0x1 sp 0x2 T0) (WRITE memory access)",
                "BHF-206",
                "SEGV",
            );
            record["exception"]["name"] = serde_json::json!("ASAN_SEGV");
            record["exception"]["sanitizer"] = serde_json::json!("asan");
            record
        };
        let a = cluster_from_finding_json(&segv("H-C0001")).unwrap();
        let b = cluster_from_finding_json(&segv("H-C0002")).unwrap();
        assert_ne!(a.full, b.full);
        assert!(a.fallback, "no source location: {a:?}");
        assert_eq!(a, cluster_from_finding_json(&segv("H-C0001")).unwrap());
    }

    /// An earlier release's crash with no sanitizer report had no frames and
    /// one key per rule too. Read back, it is grouped by its harness and its
    /// signal, as this release groups one.
    #[test]
    fn an_earlier_fatal_signal_finding_is_grouped_per_harness_and_signal() {
        let fatal = |harness: &str, signal: &str| {
            let mut record = earlier_frameless(
                harness,
                &format!(
                    "harness crashed with {signal} and no sanitizer report — a reachable crash"
                ),
                "BHF-210",
                "fatal-signal",
            );
            record["exception"] = serde_json::json!({
                "name": "FATAL_SIGNAL",
                "message": record["exception"]["message"].clone(),
                "stack": [],
            });
            record
        };
        let a = cluster_from_finding_json(&fatal("H-C0001", "SIGSEGV")).unwrap();
        let b = cluster_from_finding_json(&fatal("H-C0002", "SIGSEGV")).unwrap();
        let c = cluster_from_finding_json(&fatal("H-C0001", "SIGILL")).unwrap();
        assert_ne!(a.full, b.full);
        assert_ne!(a.full, c.full);
        let persisted = fatal("H-C0001", "SIGSEGV")["cluster_key_full"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_ne!(a.full, persisted);
        let report = SanitizerReport {
            kind: "fatal-signal".to_owned(),
            rule_id: "BHF-210",
            message: "harness crashed with SIGSEGV and no sanitizer report — a reachable crash"
                .to_owned(),
            check: Some("SIGSEGV".to_owned()),
            ..Default::default()
        };
        assert_eq!(a, cluster_for_sanitizer_scoped(&report, "H-C0001"));
    }

    /// A crash with no sanitizer report as 0.2.x recorded it: the shared crash
    /// builder tagged it with AddressSanitizer, so its name carries an
    /// `ASAN_` prefix and its record a `sanitizer` of `asan`.
    fn earlier_asan_tagged(
        harness: &str,
        message: &str,
        rule: &str,
        kind: &str,
    ) -> serde_json::Value {
        let mut record = earlier_frameless(harness, message, rule, kind);
        record["exception"]["name"] =
            serde_json::json!(format!("ASAN_{}", kind.to_uppercase().replace('-', "_")));
        record["exception"]["sanitizer"] = serde_json::json!("asan");
        record
    }

    /// The same frame-less crash with no sanitizer report as 0.3.0 recorded
    /// it: no `sanitizer` tag and the kind alone as its name.
    fn earlier_untagged(harness: &str, message: &str, rule: &str, kind: &str) -> serde_json::Value {
        let mut record = earlier_frameless(harness, message, rule, kind);
        record["exception"] = serde_json::json!({
            "name": kind.to_uppercase().replace('-', "_"),
            "message": message,
            "stack": [],
        });
        record
    }

    /// A 0.2.x crash with no sanitizer report (`ASAN_FATAL_SIGNAL`, tagged
    /// `asan`) had the constant key of its rule too. Read back, it is grouped
    /// by its harness and its signal, with the key the same crash gets when
    /// 0.3.0 recorded it, and when this release does.
    #[test]
    fn an_earlier_asan_tagged_fatal_signal_finding_is_grouped_per_harness_and_signal() {
        let message = |signal: &str| {
            format!("harness crashed with {signal} and no sanitizer report — a reachable crash")
        };
        let tagged = |harness: &str, signal: &str| {
            earlier_asan_tagged(harness, &message(signal), "BHF-210", "fatal-signal")
        };
        let record = tagged("H-C0001", "SIGSEGV");
        let persisted = record["cluster_key_full"].as_str().unwrap().to_owned();
        let a = legacy_fallback_cluster_key(&record).expect("a recomputed key");
        let b = legacy_fallback_cluster_key(&tagged("H-C0002", "SIGSEGV")).unwrap();
        let c = legacy_fallback_cluster_key(&tagged("H-C0001", "SIGBUS")).unwrap();
        assert_ne!(a.full, persisted, "the constant key is gone");
        assert_ne!(a.full, b.full, "two harnesses");
        assert_ne!(a.full, c.full, "two signals");
        assert_eq!(cluster_from_finding_json(&record), Some(a.clone()));
        let untagged = earlier_untagged("H-C0001", &message("SIGSEGV"), "BHF-210", "fatal-signal");
        assert_eq!(legacy_fallback_cluster_key(&untagged), Some(a.clone()));
        let report = SanitizerReport {
            kind: "fatal-signal".to_owned(),
            rule_id: "BHF-210",
            message: message("SIGSEGV"),
            check: Some("SIGSEGV".to_owned()),
            ..Default::default()
        };
        assert_eq!(a, cluster_for_sanitizer_scoped(&report, "H-C0001"));
    }

    /// The transport lane's frame-less findings an earlier release recorded
    /// (a 0.2.x fault, tagged `asan`; a 0.3.0 deadline or timeout) had the
    /// constant key of their rule and kind. Read back, each is grouped by its
    /// harness and fault class, as this release groups a frame-less one.
    #[test]
    fn earlier_transport_faults_and_deadlines_are_grouped_per_harness_and_class() {
        let trap = "target transport reported a target memory-protection (MMU/MPU) trap with no \
                    sanitizer report (fault address 0x20001000)";
        let crash = "target transport reported a crash with no fault detail — a reachable crash";
        let deadline = "target transport completed but its host-observed execution time 950ms \
                        exceeded the configured deadline 500ms — a timing/availability finding";
        let timeout =
            "target transport reported a target deadline / watchdog timeout with no sanitizer report";
        for (shape, rule, kind, message) in [
            ("tagged", "BHF-210", "target-memory-protection", trap),
            ("tagged", "BHF-210", "target-crash", crash),
            ("tagged", "BHF-210", "target-timeout", timeout),
            (
                "untagged",
                "BHF-555",
                "transport-deadline-exceeded",
                deadline,
            ),
            ("untagged", "BHF-555", "target-timeout", timeout),
        ] {
            let record = |harness: &str| match shape {
                "tagged" => earlier_asan_tagged(harness, message, rule, kind),
                _ => earlier_untagged(harness, message, rule, kind),
            };
            let persisted = record("H-T0001")["cluster_key_full"]
                .as_str()
                .unwrap()
                .to_owned();
            let a = legacy_fallback_cluster_key(&record("H-T0001"))
                .unwrap_or_else(|| panic!("{shape} {kind}: a recomputed key"));
            let b = legacy_fallback_cluster_key(&record("H-T0002")).unwrap();
            assert_ne!(a.full, persisted, "{shape} {kind}");
            assert_ne!(a.full, b.full, "{shape} {kind}: two harnesses");
            assert_eq!(
                cluster_from_finding_json(&record("H-T0001")),
                Some(a.clone()),
                "{shape} {kind}"
            );
            // The key this release gives the frame-less report it builds.
            let report = SanitizerReport {
                kind: kind.to_owned(),
                rule_id: finding_rules::by_id(rule).unwrap().id,
                message: message.to_owned(),
                ..Default::default()
            };
            assert_eq!(
                a,
                cluster_for_sanitizer_scoped(&report, "H-T0001"),
                "{shape} {kind}"
            );
        }
    }

    /// What this release wrote keeps its key, and so does a fallback record
    /// that is not a sanitizer crash.
    #[test]
    fn records_this_release_keys_are_not_rekeyed() {
        // Removed when this scope ends.
        let dir_tmp = tempfile::Builder::new()
            .prefix("bhf-")
            .tempdir()
            .expect("create test dir");
        let dir = dir_tmp.path().join(format!(
            "bhf-cluster-rekey-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let emitter = crate::finding::FindingEmitter::with_metadata(
            dir.clone(),
            "H-C0001".to_owned(),
            "cpp".to_owned(),
            String::new(),
        );
        let report = crate::sanitizer::parse_sanitizer_report(&format!(
            "/src/widget/parse.cpp:12:1: {MISSING_RETURN}\n"
        ))
        .unwrap();
        let id = emitter.emit_sanitizer_crash(b"x", &report).unwrap();
        let path = crate::layout::findings_dir(&dir)
            .join(&id.0)
            .join("finding.json");
        let current: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(legacy_fallback_cluster_key(&current), None);
        assert_eq!(
            cluster_from_finding_json(&current).map(|key| key.full),
            current["cluster_key_full"].as_str().map(str::to_owned)
        );
        // Nor does a crash with no sanitizer report this release wrote.
        for (kind, rule_id, check) in [
            ("fatal-signal", "BHF-210", Some("SIGSEGV")),
            ("transport-deadline-exceeded", "BHF-555", None),
            ("target-timeout", "BHF-555", None),
        ] {
            let report = SanitizerReport {
                kind: kind.to_owned(),
                rule_id,
                message: format!("{kind} with no sanitizer report"),
                check: check.map(str::to_owned),
                ..Default::default()
            };
            let id = emitter.emit_sanitizer_crash(b"y", &report).unwrap();
            let path = crate::layout::findings_dir(&dir)
                .join(&id.0)
                .join("finding.json");
            let current: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(legacy_fallback_cluster_key(&current), None, "{kind}");
            assert_eq!(
                cluster_from_finding_json(&current).map(|key| key.full),
                current["cluster_key_full"].as_str().map(str::to_owned),
                "{kind}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);

        let mut ada = earlier_missing_return("H-A0001", "/src/widget/parse.cpp:12:1");
        ada["exception"] = serde_json::json!({
            "name": "CONSTRAINT_ERROR",
            "message": "parser.adb:17 range check failed",
        });
        assert_eq!(legacy_fallback_cluster_key(&ada), None);
        let mut oracle = earlier_missing_return("H-C0001", "/src/widget/parse.cpp:12:1");
        oracle["oracle"] = serde_json::json!({"name": "path-traversal"});
        assert_eq!(legacy_fallback_cluster_key(&oracle), None);
    }
}
