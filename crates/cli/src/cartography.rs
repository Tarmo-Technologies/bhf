// SPDX-License-Identifier: Apache-2.0

//! `bhf cartography` — a byte-control card for a crash: which input bytes
//! control which sink operand (offset / size / index, or the faulting address of
//! a wild access), and what exploit primitive that implies.
//!
//! A crash tells you *where* memory safety broke; an exploit developer needs to
//! know *what they control*. bhf answers this offline and deterministically by
//! PERTURBATION: it replays the crashing input (the minimized one when it
//! reproduces) with each byte flipped and reads how the sanitizer's report
//! changes. Where the report names a RELATIVE operand — the access size (`READ/WRITE
//! of size N`) and the offset from the object (`located N bytes after a M-byte
//! region`, `at offset N in frame`) — that is the signal, and it is
//! ASLR-independent. A SEGV on a wild pointer names neither, only the faulting
//! address; replays then run with address-space randomization off, and the address
//! is compared only when two identical replays agree on it.
//!
//!   * flipping a byte removes the crash          ⇒ STRUCTURAL (a gate to reach the sink)
//!   * flipping a byte moves the relative offset  ⇒ controls the ACCESS OFFSET/INDEX
//!   * flipping a byte moves the faulting address ⇒ controls the WILD ADDRESS (SEGV)
//!   * flipping a byte changes the access size    ⇒ controls the ACCESS SIZE/LENGTH
//!   * flipping a byte changes nothing            ⇒ don't-care (payload/filler)
//!
//! From the controlled operand + access direction it classifies the exploit
//! primitive (a WRITE whose offset an attacker byte controls is a controlled
//! relative write, CWE-787), writes a `<finding>/byte-control.json` card, and
//! enriches the finding with a `primitive` object. It replays the built harness of
//! a C or C++ finding ([`crate::repro_lane`]); any other finding is refused with
//! its reason. When the harness carries the argument trace (`BHF_TRACE_ARGS`),
//! one more replay names the harness parameter each byte was decoded into, so a
//! byte that steers the access is reported as part of a named parameter.

use crate::repro_lane::{self, Tool};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Cap the number of input bytes perturbed so a large min input can't stall.
const MAX_BYTES: usize = 256;

/// `bhf cartography` — map which input bytes control which sink operand.
#[derive(Debug, clap::Args)]
pub struct CartographyArgs {
    /// Work directory of a prior `auto` run.
    #[arg(long = "work-dir", default_value = "bhf_work")]
    pub work_dir: PathBuf,

    /// Map only this finding id (default: every runtime crash finding of a
    /// built C or C++ harness). Exits non-zero, with the reason, when it
    /// cannot be mapped.
    #[arg(long = "finding-id", value_name = "ID")]
    pub finding_id: Option<String>,
}

pub fn run(args: CartographyArgs) -> i32 {
    let requested = args.finding_id.is_some();
    let selection = match repro_lane::select(
        &args.work_dir,
        args.finding_id.as_deref(),
        Tool::Cartography,
    ) {
        Ok(selection) => selection,
        Err(e) => {
            bhfeprintln!("error: {e}");
            return 1;
        }
    };
    if selection.considered == 0 {
        bhfeprintln!(
            "bhf cartography: no runtime crash findings in {}",
            args.work_dir.display()
        );
        return 0;
    }
    repro_lane::print_refusals(Tool::Cartography, &selection.refused, requested, 10);
    if selection.eligible.is_empty() {
        if !requested {
            bhfeprintln!(
                "bhf cartography: nothing mapped: none of the {} runtime finding(s) in {} can \
                 be mapped",
                selection.considered,
                args.work_dir.display()
            );
        }
        return 1;
    }
    let mut mapped = 0usize;
    let mut unmapped = 0usize;
    let mut first = true;
    let randomization_off = address_randomization_can_be_disabled();
    let mut warned = false;
    for (record, eligible) in selection.eligible {
        let Some(binary) = eligible.binary else {
            continue;
        };
        let f = FindingRef {
            id: record.id,
            dir: record.dir,
            binary,
            inputs: eligible.inputs,
        };
        match map_finding(&f) {
            Some(card) => {
                if card.address_stable.is_some() && !randomization_off && !warned {
                    warned = true;
                    bhfeprintln!("{RANDOMIZATION_WARNING}");
                }
                if !first {
                    println!();
                }
                first = false;
                print!("{}", render_card(&f.id, &card));
                write_card(&f, &card);
                mapped += 1;
            }
            None => {
                unmapped += 1;
                bhfeprintln!(
                    "bhf cartography: {} skipped: replaying its crash input through {} \
                     produced no AddressSanitizer report to map (cartography maps memory-access \
                     crashes)",
                    f.id,
                    f.binary.display()
                );
            }
        }
    }
    if mapped == 0 {
        bhfeprintln!("bhf cartography: no finding reproduced under perturbation analysis");
        return 1;
    }
    if requested && unmapped > 0 {
        1
    } else {
        0
    }
}

struct FindingRef {
    id: String,
    dir: PathBuf,
    /// The built harness executable.
    binary: PathBuf,
    /// Crash inputs, minimized first.
    inputs: Vec<PathBuf>,
}

/// The ASLR-independent facts of one crash, parsed from the sanitizer report.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct CrashFacts {
    class: String,
    access: Option<String>,
    size: Option<u64>,
    /// Signed offset of the faulting access from the object it overflowed (+ =
    /// after/right, - = before/left). ASLR-independent.
    rel_offset: Option<i64>,
    /// The address a wild access faulted on (`SEGV on unknown address 0x...`).
    /// Absolute, so only comparable between replays that agree on it.
    fault_address: Option<u64>,
}

/// Per-byte control classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ByteClass {
    Structural,
    ControlsOffset,
    ControlsAddress,
    ControlsSize,
    ControlsClass,
    DontCare,
    /// The crash survived but its faulting address is not stable between
    /// identical replays, so whether this byte steers it cannot be measured.
    Unknown,
}

impl ByteClass {
    fn tag(self) -> &'static str {
        match self {
            ByteClass::Structural => "structural",
            ByteClass::ControlsOffset => "controls_offset",
            ByteClass::ControlsAddress => "controls_address",
            ByteClass::ControlsSize => "controls_size",
            ByteClass::ControlsClass => "controls_class",
            ByteClass::DontCare => "dont_care",
            ByteClass::Unknown => "unknown",
        }
    }
}

struct Card {
    /// The input replayed (`min_testcase.bin` or `testcase.bin`).
    input_name: String,
    input_len: usize,
    analyzed: usize,
    baseline: CrashFacts,
    /// For a crash with a faulting address and no relative offset: whether
    /// two identical replays faulted on the same address.
    address_stable: Option<bool>,
    classes: Vec<ByteClass>,
    primitive: Primitive,
    /// The harness's decoded arguments for the replayed input, from its
    /// argument trace (empty without one).
    args: Vec<corpus::decoded_args::TracedArg>,
}

struct Primitive {
    kind: &'static str,
    cwe: &'static str,
    exploitability: &'static str,
    summary: String,
    controlling_bytes: Vec<usize>,
}

fn map_finding(f: &FindingRef) -> Option<Card> {
    let bin = &f.binary;
    // The first input that still crashes is the baseline (must reproduce to map it).
    let (input_path, input, baseline) = f.inputs.iter().find_map(|path| {
        let input = std::fs::read(path).ok()?;
        let facts = replay_facts(bin, &input)?;
        Some((path, input, facts))
    })?;
    // A wild access names no relative operand, only the address it faulted on.
    // Compare addresses only when a second identical replay agrees on it.
    let address_stable =
        (baseline.rel_offset.is_none() && baseline.fault_address.is_some()).then(|| {
            replay_facts(bin, &input)
                .is_some_and(|again| again.fault_address == baseline.fault_address)
        });
    let analyzed = input.len().min(MAX_BYTES);

    let mut classes = Vec::with_capacity(analyzed);
    for i in 0..analyzed {
        classes.push(classify_byte(
            bin,
            &input,
            i,
            &baseline,
            address_stable.unwrap_or(false),
        ));
    }
    let primitive = classify_primitive(&baseline, &classes);
    let args = traced_args(bin, &input);
    Some(Card {
        input_name: input_path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
        input_len: input.len(),
        analyzed,
        baseline,
        address_stable,
        classes,
        primitive,
        args,
    })
}

/// The target call's decoded arguments for `input`, from one replay with the
/// harness's argument trace on; empty when the harness has none.
fn traced_args(bin: &Path, input: &[u8]) -> Vec<corpus::decoded_args::TracedArg> {
    if !crate::fuzz::harness_has_arg_trace(bin) {
        return Vec::new();
    }
    let Some(bin) = std::path::absolute(bin).ok() else {
        return Vec::new();
    };
    let Some(dir) = bin.parent() else {
        return Vec::new();
    };
    let scratch = dir.join("cart_trace_input.bin");
    if std::fs::write(&scratch, input).is_err() {
        return Vec::new();
    }
    // A run cut off at its bound still printed the trace, which the harness
    // writes before it calls the target.
    let out = crate::command_output::bounded_replay_output(
        replay_command(&bin)
            .arg(&scratch)
            .env(
                "ASAN_OPTIONS",
                "abort_on_error=1:symbolize=0:detect_leaks=0",
            )
            .env(corpus::decoded_args::TRACE_ARGS_ENV, "1"),
        REPLAY_BOUND,
    );
    let _ = std::fs::remove_file(&scratch);
    let Ok((out, _)) = out else {
        return Vec::new();
    };
    let args = corpus::decoded_args::parse_arg_trace(&String::from_utf8_lossy(&out.stderr));
    corpus::decoded_args::summary_args(&args)
        .into_iter()
        .cloned()
        .collect()
}

/// The parameters whose decoded bytes include `offset`.
fn params_at(args: &[corpus::decoded_args::TracedArg], offset: usize) -> Vec<String> {
    let offset = offset as u64;
    let mut names: Vec<String> = Vec::new();
    for arg in args {
        if arg
            .byte_range()
            .is_some_and(|range| range.contains(&offset))
        {
            let name = arg.display_name();
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    names
}

/// ` (in bit_index, data)`: the parameters any of `offs` was decoded into.
fn params_label(args: &[corpus::decoded_args::TracedArg], offs: &[usize]) -> String {
    let mut names: Vec<String> = Vec::new();
    for &offset in offs {
        for name in params_at(args, offset) {
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    if names.is_empty() {
        String::new()
    } else {
        format!(" (in {})", names.join(", "))
    }
}

/// Classify one byte by perturbing it (XOR 0xFF and XOR 0x01) and comparing the
/// resulting crash facts to the baseline.
fn classify_byte(
    bin: &Path,
    input: &[u8],
    i: usize,
    baseline: &CrashFacts,
    address_stable: bool,
) -> ByteClass {
    let mut crashed_variants = Vec::new();
    for delta in [0xFFu8, 0x01u8] {
        let mut mutated = input.to_vec();
        mutated[i] ^= delta;
        if let Some(facts) = replay_facts(bin, &mutated) {
            crashed_variants.push(facts);
        }
    }
    classify_variants(baseline, &crashed_variants, address_stable)
}

/// The control a byte has, from the crashes its perturbations still produced.
fn classify_variants(
    baseline: &CrashFacts,
    crashed_variants: &[CrashFacts],
    address_stable: bool,
) -> ByteClass {
    if crashed_variants.is_empty() {
        return ByteClass::Structural; // every perturbation removed the crash.
    }
    // Prefer the strongest operand-control signal observed across perturbations.
    let mut seen_offset = false;
    let mut seen_address = false;
    let mut seen_size = false;
    let mut seen_class = false;
    for v in crashed_variants {
        if v.rel_offset.is_some() && v.rel_offset != baseline.rel_offset {
            seen_offset = true;
        }
        if address_stable && v.fault_address.is_some() && v.fault_address != baseline.fault_address
        {
            seen_address = true;
        }
        if v.size.is_some() && v.size != baseline.size {
            seen_size = true;
        }
        if v.class != baseline.class {
            seen_class = true;
        }
    }
    if seen_offset {
        ByteClass::ControlsOffset
    } else if seen_address {
        ByteClass::ControlsAddress
    } else if seen_size {
        ByteClass::ControlsSize
    } else if seen_class {
        ByteClass::ControlsClass
    } else if baseline.rel_offset.is_none() && baseline.fault_address.is_some() && !address_stable {
        ByteClass::Unknown
    } else {
        ByteClass::DontCare
    }
}

/// Replay one input and parse its crash facts, or `None` if it did not crash.
///
/// `symbolize=0` is load-bearing: the coverage-instrumented `main` otherwise hangs
/// in the ASan crash symbolizer (llvm-symbolizer, run without the shim here), and
/// the memory-locator line we parse (`located N bytes after region`) is emitted by
/// ASan's shadow analysis, NOT symbolization, so it survives.
///
/// An input that loops (a flipped length or count byte can do that) is killed
/// at [`REPLAY_BOUND`] and stands for no crash: the run is bounded by bhf
/// itself, as no `timeout` wrapper runs on Windows or on a host without
/// coreutils.
///
/// The replay runs beside the binary, so the binary and the scratch input are
/// made absolute first: a relative `--work-dir` would otherwise resolve against
/// the binary's own dir.
fn replay_facts(bin: &Path, input: &[u8]) -> Option<CrashFacts> {
    let bin = std::path::absolute(bin).ok()?;
    let dir = bin.parent()?;
    let scratch = dir.join("cart_input.bin");
    std::fs::write(&scratch, input).ok()?;
    let out = crate::command_output::bounded_replay_output(
        replay_command(&bin).arg(&scratch).env(
            "ASAN_OPTIONS",
            "abort_on_error=1:symbolize=0:detect_leaks=0",
        ),
        REPLAY_BOUND,
    );
    let _ = std::fs::remove_file(&scratch);
    let (out, cut_off) = out.ok()?;
    if cut_off {
        return None;
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    parse_crash(&stderr)
}

/// How long one cartography replay may run: past the 10 s of the `timeout`
/// wrapper ([`replay_command`]) where one runs, the only bound where none
/// does.
const REPLAY_BOUND: std::time::Duration = std::time::Duration::from_secs(15);

/// Build the replay command, killed after 10 s ([`killed_after`]) where a
/// coreutils `timeout` runs; callers run it with
/// [`bounded_replay_output`] and [`REPLAY_BOUND`], so a pathological input
/// can never wedge the analysis.
///
/// [`killed_after`]: crate::command_output::killed_after
/// [`bounded_replay_output`]: crate::command_output::bounded_replay_output
fn replay_command(bin: &Path) -> Command {
    let mut cmd = crate::command_output::killed_after(bin, 10);
    crate::command_output::run_target_beside_binary(&mut cmd, bin);
    disable_address_randomization(&mut cmd);
    cmd
}

/// Run the replay (and, through `timeout`, the harness it execs) with
/// address-space randomization off, so a wild pointer's faulting address is the
/// same on every identical replay and a perturbed byte that moves it shows.
#[cfg(target_os = "linux")]
fn disable_address_randomization(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: personality(2) is a plain syscall, safe between fork and exec; the
    // closure allocates nothing. A refusal (seccomp) leaves randomization on,
    // which the baseline stability check then detects.
    unsafe {
        command.pre_exec(|| {
            let current = libc::personality(0xffff_ffff);
            if current != -1 {
                libc::personality((current | libc::ADDR_NO_RANDOMIZE) as libc::c_ulong);
            }
            Ok(())
        });
    }
}

#[cfg(not(target_os = "linux"))]
fn disable_address_randomization(_command: &mut Command) {}

/// Whether the replays can run with address-space randomization off. A
/// container's default seccomp profile (Docker's, even with
/// `--cap-add=SYS_PTRACE`) refuses the personality(2) call that turns it off;
/// the replays then fault on a different address every run.
#[cfg(target_os = "linux")]
fn address_randomization_can_be_disabled() -> bool {
    // SAFETY: personality(2) changes only the calling thread's persona, which
    // matters only at its next exec; it is restored before returning.
    unsafe {
        let current = libc::personality(0xffff_ffff);
        if current == -1 {
            return false;
        }
        if current & libc::ADDR_NO_RANDOMIZE != 0 {
            return true;
        }
        if libc::personality((current | libc::ADDR_NO_RANDOMIZE) as libc::c_ulong) == -1 {
            return false;
        }
        let set = libc::personality(0xffff_ffff);
        libc::personality(current as libc::c_ulong);
        set != -1 && set & libc::ADDR_NO_RANDOMIZE != 0
    }
}

#[cfg(not(target_os = "linux"))]
fn address_randomization_can_be_disabled() -> bool {
    false
}

/// Printed once per run when a wild-pointer crash is mapped where
/// randomization stays on.
const RANDOMIZATION_WARNING: &str = "bhf cartography: warning: address-space randomization \
    cannot be turned off here (personality(2) was refused, as a container's default seccomp \
    profile does), so the input bytes that set a SEGV's faulting address cannot be \
    attributed and show as `unknown`; in Docker, rerun with `--security-opt \
    seccomp=unconfined`";

/// Parse the ASLR-independent crash facts from a sanitizer report.
fn parse_crash(stderr: &str) -> Option<CrashFacts> {
    let pos = stderr.find("AddressSanitizer: ")?;
    let class: String = stderr[pos + "AddressSanitizer: ".len()..]
        .split(|c: char| c.is_whitespace())
        .next()?
        .to_owned();
    if class.is_empty() {
        return None;
    }
    let mut facts = CrashFacts {
        class,
        ..CrashFacts::default()
    };
    // "READ of size 4 at 0x..." / "WRITE of size 9 at 0x..."
    for dir in ["READ", "WRITE"] {
        if let Some(p) = stderr.find(&format!("{dir} of size ")) {
            facts.access = Some(dir.to_owned());
            let rest = &stderr[p + format!("{dir} of size ").len()..];
            facts.size = rest
                .split(|c: char| !c.is_ascii_digit())
                .find(|s| !s.is_empty())
                .and_then(|s| s.parse::<u64>().ok());
            break;
        }
    }
    facts.rel_offset = parse_rel_offset(stderr);
    // A wild access: "SEGV on unknown address 0x... (pc ...)" and "The signal is
    // caused by a READ memory access."
    if let Some(p) = stderr.find(" on unknown address 0x") {
        let hex: String = stderr[p + " on unknown address 0x".len()..]
            .chars()
            .take_while(char::is_ascii_hexdigit)
            .collect();
        facts.fault_address = u64::from_str_radix(&hex, 16).ok();
    }
    if facts.access.is_none() {
        for dir in ["READ", "WRITE"] {
            if stderr.contains(&format!("caused by a {dir} memory access")) {
                facts.access = Some(dir.to_owned());
                break;
            }
        }
    }
    Some(facts)
}

/// Extract the signed relative offset of the faulting access from the object it
/// overflowed. Handles heap (`N bytes after/before an M-byte region`), stack (`at
/// offset N in frame`), and global (`N bytes to the right/left of global`). The
/// address-description parser is shared with finding emission
/// ([`corpus::sanitizer::relative_offset`]), which records the same facts as
/// `exception.access.region`.
fn parse_rel_offset(stderr: &str) -> Option<i64> {
    corpus::sanitizer::relative_offset(stderr)
}

/// Classify the exploit primitive from the baseline access + the per-byte control map.
fn classify_primitive(baseline: &CrashFacts, classes: &[ByteClass]) -> Primitive {
    let controlling: Vec<usize> = classes
        .iter()
        .enumerate()
        .filter(|(_, c)| {
            matches!(
                c,
                ByteClass::ControlsOffset
                    | ByteClass::ControlsAddress
                    | ByteClass::ControlsSize
                    | ByteClass::ControlsClass
            )
        })
        .map(|(i, _)| i)
        .collect();
    let controls_offset = classes.contains(&ByteClass::ControlsOffset);
    let controls_address = classes.contains(&ByteClass::ControlsAddress);
    let controls_size = classes.contains(&ByteClass::ControlsSize);
    let is_write = baseline.access.as_deref() == Some("WRITE");
    let operand = if controls_offset {
        "offset/index"
    } else if controls_size {
        "size/length"
    } else {
        ""
    };

    if controls_address && !controls_offset {
        // A wild pointer: the bytes set the address the access faults on.
        let (kind, cwe, exploitability, what) = match baseline.access.as_deref() {
            Some("WRITE") => ("controlled_address_write", "CWE-787", "high", "WRITE"),
            Some("READ") => ("controlled_address_read", "CWE-125", "medium", "READ"),
            _ => ("controlled_address_access", "CWE-119", "medium", "access"),
        };
        return Primitive {
            kind,
            cwe,
            exploitability,
            summary: format!(
                "input byte(s) {} set the faulting address of a wild {what} — an \
                 attacker-steered memory access",
                span_list(&controlling)
            ),
            controlling_bytes: controlling,
        };
    }
    if !controlling.is_empty() && is_write {
        Primitive {
            kind: "controlled_relative_write",
            cwe: "CWE-787",
            exploitability: "high",
            summary: format!(
                "input byte(s) {} control the {operand} of an out-of-bounds WRITE — a controlled relative write",
                span_list(&controlling)
            ),
            controlling_bytes: controlling,
        }
    } else if !controlling.is_empty() {
        Primitive {
            kind: "controlled_relative_read",
            cwe: "CWE-125",
            exploitability: "medium",
            summary: format!(
                "input byte(s) {} control the {operand} of an out-of-bounds READ — a controlled relative read (info leak)",
                span_list(&controlling)
            ),
            controlling_bytes: controlling,
        }
    } else if classes.contains(&ByteClass::Unknown) {
        Primitive {
            kind: "unattributed_crash",
            cwe: baseline_cwe(baseline),
            exploitability: "unknown",
            summary: "the faulting address moved between identical replays, so which input \
                      bytes steer it could not be measured"
                .to_owned(),
            controlling_bytes: Vec::new(),
        }
    } else if is_write {
        Primitive {
            kind: "fixed_write",
            cwe: "CWE-787",
            exploitability: "low",
            summary:
                "an out-of-bounds WRITE whose operand no single input byte controls (fixed offset)"
                    .to_owned(),
            controlling_bytes: Vec::new(),
        }
    } else if !classes.contains(&ByteClass::Structural) {
        Primitive {
            kind: "uncontrolled_crash",
            cwe: baseline_cwe(baseline),
            exploitability: "low",
            summary: if classes.is_empty() {
                "the crash input is empty, so no input byte gates or steers the crash".to_owned()
            } else {
                "every perturbed input still crashed the same way: no input byte gates or \
                 steers the crash"
                    .to_owned()
            },
            controlling_bytes: Vec::new(),
        }
    } else {
        Primitive {
            kind: "gated_crash",
            cwe: baseline_cwe(baseline),
            exploitability: "low",
            summary: "a gated crash with no byte-level operand control found by perturbation"
                .to_owned(),
            controlling_bytes: Vec::new(),
        }
    }
}

fn baseline_cwe(baseline: &CrashFacts) -> &'static str {
    match baseline.access.as_deref() {
        Some("WRITE") => "CWE-787",
        Some("READ") => "CWE-125",
        _ => "CWE-119",
    }
}

/// Coalesce contiguous byte offsets into `a-b` spans for a compact summary.
fn span_list(offs: &[usize]) -> String {
    if offs.is_empty() {
        return "(none)".to_owned();
    }
    let mut spans = Vec::new();
    let mut start = offs[0];
    let mut prev = offs[0];
    for &o in &offs[1..] {
        if o == prev + 1 {
            prev = o;
        } else {
            spans.push(fmt_span(start, prev));
            start = o;
            prev = o;
        }
    }
    spans.push(fmt_span(start, prev));
    spans.join(", ")
}

fn fmt_span(a: usize, b: usize) -> String {
    if a == b {
        format!("{a}")
    } else {
        format!("{a}-{b}")
    }
}

/// Render the human-readable card.
fn render_card(id: &str, card: &Card) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let b = &card.baseline;
    let _ = writeln!(s, "━━━ Byte-control card — {id} ━━━");
    let address = match (b.fault_address, card.address_stable) {
        (Some(address), Some(true)) => format!(", faulting address {address:#x}"),
        (Some(address), _) => {
            format!(", faulting address {address:#x}, not stable between replays")
        }
        (None, _) => String::new(),
    };
    let _ = writeln!(
        s,
        "  crash: {} ({} of size {}{}{address})",
        b.class,
        b.access.as_deref().unwrap_or("?"),
        b.size.map(|n| n.to_string()).unwrap_or_else(|| "?".into()),
        b.rel_offset
            .map(|o| format!(", offset {o:+}"))
            .unwrap_or_default(),
    );
    let _ = writeln!(
        s,
        "  input: {} byte(s), {}{}",
        card.input_len,
        card.input_name,
        if card.analyzed < card.input_len {
            format!(" (first {} analyzed)", card.analyzed)
        } else {
            String::new()
        }
    );
    let _ = writeln!(
        s,
        "  primitive: {} ({}, exploitability {})",
        card.primitive.kind, card.primitive.cwe, card.primitive.exploitability
    );
    let _ = writeln!(s, "    {}", card.primitive.summary);
    let _ = writeln!(s, "  byte map:");
    for (label, class) in [
        ("structural (gate)", ByteClass::Structural),
        ("controls offset/index", ByteClass::ControlsOffset),
        ("controls faulting address", ByteClass::ControlsAddress),
        ("controls size/length", ByteClass::ControlsSize),
        ("controls crash kind", ByteClass::ControlsClass),
        ("unknown (faulting address not stable)", ByteClass::Unknown),
    ] {
        let offs: Vec<usize> = card
            .classes
            .iter()
            .enumerate()
            .filter(|(_, c)| **c == class)
            .map(|(i, _)| i)
            .collect();
        if !offs.is_empty() {
            let _ = writeln!(
                s,
                "    {label}: bytes {}{}",
                span_list(&offs),
                params_label(&card.args, &offs)
            );
        }
    }
    if !card.args.is_empty() {
        let _ = writeln!(s, "  parameter bytes:");
        for arg in &card.args {
            if let Some(range) = arg.byte_range().filter(|range| !range.is_empty()) {
                let _ = writeln!(
                    s,
                    "    {}: bytes {}",
                    arg.display_name(),
                    fmt_span(range.start as usize, range.end as usize - 1)
                );
            }
        }
    }
    s
}

/// Write the machine-readable card + enrich the finding with a `primitive` object.
fn write_card(f: &FindingRef, card: &Card) {
    let bytes: Vec<Value> = card
        .classes
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let params = params_at(&card.args, i);
            if params.is_empty() {
                json!({ "offset": i, "class": c.tag() })
            } else {
                json!({ "offset": i, "class": c.tag(), "params": params })
            }
        })
        .collect();
    let card_json = json!({
        "schema": "bhf.byte-control/v1",
        "finding_id": f.id,
        "input": card.input_name,
        "input_len": card.input_len,
        "analyzed_bytes": card.analyzed,
        "crash": {
            "class": card.baseline.class,
            "access": card.baseline.access,
            "size": card.baseline.size,
            "rel_offset": card.baseline.rel_offset,
            "fault_address": card.baseline.fault_address.map(|a| format!("{a:#x}")),
            "fault_address_stable": card.address_stable,
        },
        "primitive": {
            "kind": card.primitive.kind,
            "cwe": card.primitive.cwe,
            "exploitability": card.primitive.exploitability,
            "summary": card.primitive.summary,
            "controlling_bytes": card.primitive.controlling_bytes,
        },
        "bytes": bytes,
        "parameters": card.args.iter().filter_map(|arg| {
            let [start, end] = arg.span?;
            Some(json!({ "name": arg.display_name(), "type": arg.ty, "span": [start, end] }))
        }).collect::<Vec<_>>(),
    });
    let _ = std::fs::write(
        f.dir.join("byte-control.json"),
        serde_json::to_vec_pretty(&card_json).unwrap_or_default(),
    );
    // Enrich the finding record itself so the primitive travels with the finding.
    if let Some(mut raw) = read_json(&f.dir.join("finding.json")) {
        if let Some(obj) = raw.as_object_mut() {
            obj.insert(
                "primitive".to_owned(),
                json!({
                    "kind": card.primitive.kind,
                    "cwe": card.primitive.cwe,
                    "exploitability": card.primitive.exploitability,
                    "controlling_bytes": card.primitive.controlling_bytes,
                }),
            );
            corpus::finding::append_history(&mut raw, "cartography", &["primitive"]);
            let _ = std::fs::write(
                f.dir.join("finding.json"),
                serde_json::to_vec_pretty(&raw).unwrap_or_default(),
            );
        }
    }
}

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The probe answers what a replay really gets: a child started the way
    /// replays are runs with randomization off exactly when the probe says it
    /// can be turned off (a seccomp profile that refuses personality(2) makes
    /// both false), and the probe leaves this thread's persona as it was.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_randomization_probe_matches_what_a_replay_gets() {
        let persona = || std::fs::read_to_string("/proc/thread-self/personality").unwrap();
        let before = persona();
        let probe = address_randomization_can_be_disabled();
        assert_eq!(persona(), before, "the probe must restore the persona");
        let mut child = Command::new("cat");
        child.arg("/proc/self/personality");
        disable_address_randomization(&mut child);
        let out = child.output().expect("run cat");
        let text = String::from_utf8_lossy(&out.stdout);
        let flags = u64::from_str_radix(text.trim(), 16).expect("hex persona");
        assert_eq!(
            flags & libc::ADDR_NO_RANDOMIZE as u64 != 0,
            probe,
            "child persona {text:?}"
        );
    }

    #[test]
    fn parses_heap_read_facts_with_relative_offset() {
        let report = "\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000035\n\
READ of size 1 at 0x502000000035 thread T0\n\
0x502000000035 is located 21 bytes after 16-byte region [0x..,0x..)\n";
        let f = parse_crash(report).unwrap();
        assert_eq!(f.class, "heap-buffer-overflow");
        assert_eq!(f.access.as_deref(), Some("READ"));
        assert_eq!(f.size, Some(1));
        assert_eq!(f.rel_offset, Some(21));
    }

    #[test]
    fn parses_stack_write_and_before_region() {
        let write = "AddressSanitizer: stack-buffer-overflow\nWRITE of size 9 at 0x..\nAddress 0x.. at offset 96 in frame";
        let f = parse_crash(write).unwrap();
        assert_eq!(f.access.as_deref(), Some("WRITE"));
        assert_eq!(f.size, Some(9));
        assert_eq!(f.rel_offset, Some(96));

        let before = "AddressSanitizer: heap-buffer-overflow\nREAD of size 4 at 0x..\n0x.. is located 8 bytes before 32-byte region";
        assert_eq!(parse_crash(before).unwrap().rel_offset, Some(-8));
    }

    #[test]
    fn no_crash_yields_none() {
        assert!(parse_crash("all fine\n").is_none());
    }

    #[test]
    fn primitive_controlled_read_from_offset_bytes() {
        let baseline = CrashFacts {
            class: "heap-buffer-overflow".into(),
            access: Some("READ".into()),
            size: Some(1),
            rel_offset: Some(21),
            fault_address: None,
        };
        let classes = vec![
            ByteClass::Structural,
            ByteClass::ControlsOffset,
            ByteClass::DontCare,
        ];
        let p = classify_primitive(&baseline, &classes);
        assert_eq!(p.kind, "controlled_relative_read");
        assert_eq!(p.cwe, "CWE-125");
        assert_eq!(p.controlling_bytes, vec![1]);
    }

    #[test]
    fn primitive_controlled_write_is_high() {
        let baseline = CrashFacts {
            class: "heap-buffer-overflow".into(),
            access: Some("WRITE".into()),
            size: Some(4),
            rel_offset: Some(0),
            fault_address: None,
        };
        let classes = vec![ByteClass::ControlsSize];
        let p = classify_primitive(&baseline, &classes);
        assert_eq!(p.kind, "controlled_relative_write");
        assert_eq!(p.cwe, "CWE-787");
        assert_eq!(p.exploitability, "high");
    }

    /// A SEGV on a wild pointer reports no region-relative offset: the
    /// faulting address and the access direction are what is left.
    #[test]
    fn parses_segv_faulting_address_and_direction() {
        let report = "\
==7==ERROR: AddressSanitizer: SEGV on unknown address 0x555595558000 (pc 0x5555 bp 0x7fff sp 0x7fff T0)\n\
==7==The signal is caused by a READ memory access.\n";
        let f = parse_crash(report).unwrap();
        assert_eq!(f.class, "SEGV");
        assert_eq!(f.access.as_deref(), Some("READ"));
        assert_eq!(f.fault_address, Some(0x5555_9555_8000));
        assert_eq!(f.rel_offset, None);
        assert_eq!(f.size, None);
    }

    fn segv(address: u64) -> CrashFacts {
        CrashFacts {
            class: "SEGV".into(),
            access: Some("READ".into()),
            size: None,
            rel_offset: None,
            fault_address: Some(address),
        }
    }

    /// With the harness's argument trace, the card names the parameter each
    /// classified byte was decoded into.
    #[test]
    fn the_card_names_the_parameters_bytes_were_decoded_into() {
        let args = corpus::decoded_args::parse_arg_trace(
            "BHF_ARG {\"call\":\"target\",\"i\":0,\"role\":\"param\",\"name\":\"bit_index\",\"type\":\"unsigned int\",\"span\":[0,4],\"value\":\"9\"}\n\
             BHF_ARG {\"call\":\"target\",\"i\":1,\"role\":\"param\",\"name\":\"width\",\"type\":\"unsigned int\",\"span\":[4,5],\"value\":\"1\"}\n",
        );
        let baseline = segv(0x6030_0a1b_2c40);
        let classes = vec![
            ByteClass::ControlsAddress,
            ByteClass::ControlsAddress,
            ByteClass::ControlsAddress,
            ByteClass::ControlsAddress,
            ByteClass::DontCare,
        ];
        let card = Card {
            input_name: "testcase.bin".into(),
            input_len: 5,
            analyzed: 5,
            primitive: classify_primitive(&baseline, &classes),
            baseline,
            address_stable: Some(true),
            classes,
            args,
        };
        let text = render_card("F-0001-0a0b0c0d", &card);
        assert!(
            text.contains("controls faulting address: bytes 0-3 (in bit_index)"),
            "{text}"
        );
        assert!(text.contains("    width: bytes 4\n"), "{text}");
        assert_eq!(params_at(&card.args, 4), vec!["width".to_owned()]);
        assert!(params_at(&card.args, 5).is_empty());
    }

    /// A byte that moves a stable faulting address controls it; when the
    /// address is not stable between identical replays, that cannot be told
    /// and the byte is not called don't-care.
    #[test]
    fn segv_bytes_are_classified_by_the_faulting_address() {
        let baseline = segv(0x1000);
        assert_eq!(
            classify_variants(&baseline, &[segv(0x2000)], true),
            ByteClass::ControlsAddress
        );
        assert_eq!(
            classify_variants(&baseline, &[segv(0x1000), segv(0x1000)], true),
            ByteClass::DontCare
        );
        assert_eq!(
            classify_variants(&baseline, &[segv(0x2000)], false),
            ByteClass::Unknown
        );
        assert_eq!(
            classify_variants(&baseline, &[], true),
            ByteClass::Structural
        );
    }

    #[test]
    fn primitives_for_wild_and_uncontrolled_crashes() {
        let classes = vec![
            ByteClass::ControlsAddress,
            ByteClass::ControlsAddress,
            ByteClass::DontCare,
        ];
        let p = classify_primitive(&segv(0x1000), &classes);
        assert_eq!(p.kind, "controlled_address_read");
        assert_eq!(p.cwe, "CWE-125");
        assert_eq!(p.controlling_bytes, vec![0, 1]);
        assert!(p.summary.contains("faulting address"), "{}", p.summary);

        let mut write = segv(0x1000);
        write.access = Some("WRITE".into());
        assert_eq!(
            classify_primitive(&write, &[ByteClass::ControlsAddress]).kind,
            "controlled_address_write"
        );
        assert_eq!(
            classify_primitive(&segv(0x1000), &[ByteClass::Unknown, ByteClass::Structural]).kind,
            "unattributed_crash"
        );
        // Nothing gates the crash: it is not a "gated" crash.
        assert_eq!(
            classify_primitive(&segv(0x1000), &[ByteClass::DontCare, ByteClass::DontCare]).kind,
            "uncontrolled_crash"
        );
        assert_eq!(
            classify_primitive(&segv(0x1000), &[]).kind,
            "uncontrolled_crash"
        );
        assert_eq!(
            classify_primitive(&segv(0x1000), &[ByteClass::Structural, ByteClass::DontCare]).kind,
            "gated_crash"
        );
    }

    #[test]
    fn span_list_coalesces_ranges() {
        assert_eq!(span_list(&[0, 1, 2, 5, 7, 8]), "0-2, 5, 7-8");
        assert_eq!(span_list(&[]), "(none)");
    }
}
