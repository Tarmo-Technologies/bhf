// SPDX-License-Identifier: Apache-2.0

//! Comparison evidence for one finding's input: which input bytes reach which
//! comparison of the target.
//!
//! bhf's C/C++ driver (`c_runtime/bhf_driver.c`) records every comparison the
//! instrumented code makes while `BHF_CMP_EVIDENCE` names a file: integer
//! compares and switches from `-fsanitize-coverage=trace-cmp`, and
//! `memcmp`/`bcmp`/`str*cmp` from the sanitizer's interceptor hooks. Replaying
//! the finding's input once with it set lists the comparisons that input
//! reached.
//!
//! A comparison counts as evidence for input bytes only when, as in
//! RedQueen's input-to-state correspondence, one operand's bytes occur in the
//! input AND a replay with those input bytes changed shows that operand
//! changed the same way. A byte sequence that merely occurs in the input is
//! never reported. Input bytes are also flipped to find comparisons whose
//! operand is computed from them rather than copied (a folded range check
//! such as `width - 1 > 31`): every byte of a short input, and in a longer one
//! the bytes of its scalar parameters, then byte ranges halved down to the
//! bytes that change a comparison; two replays of the unchanged input bracket
//! the flips, and an operand that differs between identical runs (a process
//! id, a clock) is left out.
//!
//! The harness's own comparisons are left out: those it makes before it
//! enters the target (`bhf_target_enter`), which the driver discards at
//! entry, and those whose site symbolizes to harness code. Under
//! AddressSanitizer the `memcmp`/`bcmp` interceptor reports itself as the
//! site; the driver records the frames above it, and the first that is not
//! the sanitizer runtime becomes the comparison's site.
//!
//! A harness built for another platform is replayed the way it was fuzzed:
//! under the emulator `bhf auto` recorded beside it ([`RUNNER_FILE`]), such as
//! `qemu-aarch64 -L /usr/aarch64-linux-gnu`, which passes the evidence
//! variable through to the harness. Such a build has no sanitizer runtime to
//! report its string and buffer comparisons, so bhf links it with
//! [`COMPARISON_WRAP_LDFLAGS`] and the driver's wrappers report them instead.
//!
//! The replays are bounded: one baseline run, at most [`MAX_VERIFY_RUNS`]
//! verification runs, [`MAX_DERIVED_INPUT`] byte flips or [`MAX_DERIVED_RUNS`]
//! range flips and their two controls, each under [`RUN_TIMEOUT`], and nothing
//! after the caller's deadline.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The driver variable naming the evidence file.
pub(crate) const EVIDENCE_ENV: &str = "BHF_CMP_EVIDENCE";
/// The driver records nothing without this string in its binary: a harness
/// built by an older bhf ignores the variable.
const DRIVER_MARKER: &[u8] = b"BHF_CMP_EVIDENCE";

/// Link flags that route a harness's own `memcmp`/`bcmp`/`str*cmp` calls
/// through the driver's wrappers (`__wrap_strcmp`, ...), which report them to
/// the same hooks a sanitizer's interceptors call. For builds without a
/// sanitizer runtime, such as a cross build run under an emulator.
pub(crate) const COMPARISON_WRAP_LDFLAGS: &str = "-Wl,--wrap=memcmp,--wrap=bcmp,--wrap=strcmp,\
--wrap=strncmp,--wrap=strcasecmp,--wrap=strncasecmp";

/// The file beside a harness binary naming the emulator it runs under, when
/// `bhf auto` built it for a platform this host cannot run directly.
pub(crate) const RUNNER_FILE: &str = "bhf_runner.json";
const RUNNER_SCHEMA: &str = "bhf.harness_runner.v1";

/// The emulator a harness runs under: `<program> <args...> <harness>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HarnessRunner {
    pub(crate) program: PathBuf,
    #[serde(default)]
    pub(crate) args: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct RunnerRecord {
    schema: String,
    #[serde(flatten)]
    runner: HarnessRunner,
}

/// Record (or, with `None`, forget) the emulator the harness built in
/// `harness_dir` runs under, so a later replay of its findings uses it too.
pub(crate) fn record_runner(
    harness_dir: &Path,
    runner: Option<&HarnessRunner>,
) -> std::io::Result<()> {
    let path = harness_dir.join(RUNNER_FILE);
    match runner {
        Some(runner) => {
            let record = RunnerRecord {
                schema: RUNNER_SCHEMA.to_owned(),
                runner: runner.clone(),
            };
            std::fs::write(path, serde_json::to_vec_pretty(&record)?)
        }
        None => match std::fs::remove_file(path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        },
    }
}

/// The emulator recorded beside `harness`, if any.
pub(crate) fn recorded_runner(harness: &Path) -> Option<HarnessRunner> {
    let bytes = std::fs::read(harness.parent()?.join(RUNNER_FILE)).ok()?;
    let record: RunnerRecord = serde_json::from_slice(&bytes).ok()?;
    (record.schema == RUNNER_SCHEMA).then_some(record.runner)
}

const MAGIC: u32 = 0x4546_4842;
/// The record format the driver writes: each record carries the return
/// addresses of the frames above its site ([`CALLERS`] of them).
const VERSION: u32 = 2;
/// The format of drivers before the callers were recorded, still read.
const VERSION_WITHOUT_CALLERS: u32 = 1;
const HEADER: usize = 16;
const OPMAX: usize = 32;
const CALLERS: usize = 4;
const RECORD: usize = 12 + 4 * CALLERS + 2 * OPMAX;
const RECORD_WITHOUT_CALLERS: usize = 12 + 2 * OPMAX;

const FLAG_IN_TARGET: u8 = 1;
const FLAG_CONST_A: u8 = 2;
const FLAG_CONST_B: u8 = 4;
const FLAG_EQUAL: u8 = 8;

/// One harness run's time limit.
pub(crate) const RUN_TIMEOUT: Duration = Duration::from_secs(10);
/// Most verification replays per capture.
pub(crate) const MAX_VERIFY_RUNS: usize = 48;
/// Inputs up to this many bytes get one replay per flipped byte when operands
/// computed from input bytes are searched; a longer input is searched by
/// flipping byte ranges ([`MAX_DERIVED_RUNS`] replays at most).
pub(crate) const MAX_DERIVED_INPUT: usize = 32;
/// Most replays the range search for operands computed from input bytes
/// makes on an input longer than [`MAX_DERIVED_INPUT`].
pub(crate) const MAX_DERIVED_RUNS: usize = 256;
/// Inputs longer than this are not searched for computed operands at all.
pub(crate) const MAX_SEARCHED_INPUT: usize = 1 << 20;
/// Occurrences of one operand in the input tried in one verification replay.
const MAX_OCCURRENCES: usize = 64;
/// Evidence entries kept per finding.
pub(crate) const MAX_GATES: usize = 64;
/// Candidate operands checked per comparison site (per site and compared
/// value for a buffer or string comparison).
const MAX_CANDIDATES_PER_SITE: usize = 4;
/// Comparisons the driver keeps per run (`BHF_EV_CAP` in `bhf_driver.c`).
const DRIVER_CAPACITY: usize = 8192;

/// The comparison a record came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum CmpKind {
    Int,
    Switch,
    Float,
    Double,
    Memcmp,
    Strncmp,
    Strcmp,
    Strncasecmp,
    Strcasecmp,
}

impl CmpKind {
    fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::Int,
            2 => Self::Switch,
            3 => Self::Float,
            4 => Self::Double,
            5 => Self::Memcmp,
            6 => Self::Strncmp,
            7 => Self::Strcmp,
            8 => Self::Strncasecmp,
            9 => Self::Strcasecmp,
            _ => return None,
        })
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Int => "cmp",
            Self::Switch => "switch",
            Self::Float => "float_cmp",
            Self::Double => "double_cmp",
            Self::Memcmp => "memcmp",
            Self::Strncmp => "strncmp",
            Self::Strcmp => "strcmp",
            Self::Strncasecmp => "strncasecmp",
            Self::Strcasecmp => "strcasecmp",
        }
    }

    /// A byte-buffer or string comparison (operands in memory order), as
    /// opposed to an integer one (operands little-endian).
    fn is_buffer(self) -> bool {
        matches!(
            self,
            Self::Memcmp | Self::Strncmp | Self::Strcmp | Self::Strncasecmp | Self::Strcasecmp
        )
    }

    fn is_string(self) -> bool {
        matches!(
            self,
            Self::Strncmp | Self::Strcmp | Self::Strncasecmp | Self::Strcasecmp
        )
    }
}

/// One recorded comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CmpRecord {
    pub(crate) kind: CmpKind,
    pub(crate) a: Vec<u8>,
    pub(crate) b: Vec<u8>,
    pub(crate) a_const: bool,
    pub(crate) b_const: bool,
    pub(crate) equal: bool,
    pub(crate) in_target: bool,
    pub(crate) site: u32,
    /// For a buffer or string comparison, the return addresses of the frames
    /// above `site` (executable offsets, 0 for none or outside it): under
    /// AddressSanitizer `site` is inside the `memcmp`/`bcmp` interceptor and
    /// these say where the call came from.
    pub(crate) callers: Vec<u32>,
    /// `site` is the sanitizer's interceptor and none of `callers` names the
    /// code that called it.
    pub(crate) unattributable: bool,
}

impl CmpRecord {
    fn operand(&self, side: Side) -> &[u8] {
        match side {
            Side::A => &self.a,
            Side::B => &self.b,
        }
    }

    fn other(&self, side: Side) -> &[u8] {
        match side {
            Side::A => &self.b,
            Side::B => &self.a,
        }
    }

    fn is_const(&self, side: Side) -> bool {
        match side {
            Side::A => self.a_const,
            Side::B => self.b_const,
        }
    }

    /// A 64-bit operand that looks like a user-space pointer: a heap or stack
    /// address moves whenever an allocation does, so it is never input state.
    /// That includes the switches the sanitizers' own pointer checks compile
    /// to.
    fn is_pointer_like(&self) -> bool {
        let pointer = |bytes: &[u8]| {
            bytes.len() == 8 && {
                let value = u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]));
                (1u64 << 40..1u64 << 47).contains(&value)
            }
        };
        matches!(self.kind, CmpKind::Int | CmpKind::Switch)
            && (pointer(&self.a) || pointer(&self.b))
    }
}

/// Which operand of a comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Side {
    A,
    B,
}

/// A parsed evidence file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct EvidenceLog {
    pub(crate) target_entered: bool,
    pub(crate) truncated: bool,
    pub(crate) records: Vec<CmpRecord>,
}

impl EvidenceLog {
    /// The target's own comparisons. When the harness marked where the target
    /// starts (the header's entry flag), only those made after it: what came
    /// before is the harness decoding the input. A harness that never marks
    /// entry leaves no way to tell, so all of its records count.
    pub(crate) fn target_records(&self) -> Vec<&CmpRecord> {
        self.records
            .iter()
            .filter(|r| !self.target_entered || r.in_target)
            .filter(|r| !r.is_pointer_like())
            .collect()
    }
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

/// Parse an evidence file the driver wrote.
pub(crate) fn parse_log(bytes: &[u8]) -> Result<EvidenceLog, String> {
    if u32_at(bytes, 0) != Some(MAGIC) {
        return Err("the evidence file has no driver header".to_owned());
    }
    let version = u32_at(bytes, 4).unwrap_or(0);
    let (size, callers) = match version {
        VERSION => (RECORD, CALLERS),
        VERSION_WITHOUT_CALLERS => (RECORD_WITHOUT_CALLERS, 0),
        _ => {
            return Err(format!(
                "the evidence file is version {version}, not {VERSION}"
            ))
        }
    };
    let count = u32_at(bytes, 8).unwrap_or(0) as usize;
    let flags = bytes.get(12).copied().unwrap_or(0);
    let mut records = Vec::new();
    for index in 0..count {
        let at = HEADER + index * size;
        let Some(record) = bytes.get(at..at + size) else {
            break;
        };
        let Some(kind) = CmpKind::from_code(record[0]) else {
            continue;
        };
        let la = usize::from(record[1]).min(OPMAX);
        let lb = usize::from(record[2]).min(OPMAX);
        let rflags = record[3];
        let operands = 12 + 4 * callers;
        records.push(CmpRecord {
            kind,
            a: record[operands..operands + la].to_vec(),
            b: record[operands + OPMAX..operands + OPMAX + lb].to_vec(),
            a_const: rflags & FLAG_CONST_A != 0,
            b_const: rflags & FLAG_CONST_B != 0,
            equal: rflags & FLAG_EQUAL != 0,
            in_target: rflags & FLAG_IN_TARGET != 0,
            site: u32_at(record, 4).unwrap_or(0),
            callers: (0..callers)
                .map(|i| u32_at(record, 12 + 4 * i).unwrap_or(0))
                .collect(),
            unattributable: false,
        });
    }
    Ok(EvidenceLog {
        target_entered: flags & 1 != 0,
        truncated: flags & 2 != 0,
        records,
    })
}

/// Where a comparison is in the source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SiteLocation {
    pub(crate) file: String,
    pub(crate) line: Option<u64>,
    pub(crate) function: Option<String>,
}

/// One input span that reached a comparison (`finding.json` `gates[]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Gate {
    pub(crate) offset: usize,
    pub(crate) len: usize,
    /// The operand as the comparison saw it.
    pub(crate) operand_hex: String,
    /// The other operand.
    pub(crate) compared_with_hex: String,
    pub(crate) cmp_kind: String,
    /// The comparison's offset in the harness executable.
    pub(crate) site: String,
    pub(crate) location: Option<SiteLocation>,
    /// `equal`, `byte_swapped` or `derived`.
    pub(crate) relation: String,
    pub(crate) operands_equal: bool,
    /// `site` is the sanitizer's `memcmp`/`bcmp` interceptor and the code that
    /// called it could not be named (no caller frame resolved).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) site_unattributable: bool,
}

/// What a capture did (`finding.json` `gate_capture`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CaptureSummary {
    /// The file replayed, e.g. `min_testcase.bin`.
    pub(crate) input: String,
    pub(crate) input_len: usize,
    /// `recorded`, `no_input_comparisons`, `no_comparisons` or
    /// `unavailable`.
    pub(crate) status: String,
    /// Why there is no evidence, when there is none.
    pub(crate) reason: Option<String>,
    /// Comparisons the target made on this input.
    pub(crate) comparisons: usize,
    /// More comparisons happened than the driver keeps.
    pub(crate) truncated: bool,
    /// Candidate operands whose bytes occur in the input but that were not
    /// checked (replay budget spent) or did not follow a change of them.
    pub(crate) unconfirmed: usize,
    /// Harness runs this capture made.
    pub(crate) runs: usize,
    /// The baseline replay ran with the runtrace shim, so `runtrace.jsonl` in
    /// the finding dir lists this input's own environment use.
    pub(crate) shim_armed: bool,
    /// The emulator the replays ran under (`qemu-aarch64`), for a harness
    /// built for another platform.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) runner: Option<String>,
    /// How far the search for operands computed from input bytes (range
    /// checks such as `width - 1 > 31`) got: `done`, `partial` (the replay
    /// budget ran out) or `too_long` (not searched). Absent when no search
    /// ran, and in captures recorded before it was kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) derived_search: Option<String>,
    /// The input bytes that search covered, of `input_len`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) searched_bytes: Option<usize>,
}

impl CaptureSummary {
    /// The computed-operand search as `(state, searched bytes)` when it did
    /// not cover the whole input: the recorded one, or, for a capture
    /// recorded before it was kept, the per-byte search's length limit.
    pub(crate) fn incomplete_derived_search(&self) -> Option<(&str, usize)> {
        match (self.derived_search.as_deref(), self.searched_bytes) {
            (Some("done"), _) => None,
            (Some(state), searched) => Some((state, searched.unwrap_or(0))),
            (None, _)
                if matches!(self.status.as_str(), "recorded" | "no_input_comparisons")
                    && self.input_len > MAX_DERIVED_INPUT =>
            {
                Some(("too_long", 0))
            }
            (None, _) => None,
        }
    }
}

/// A finished capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Capture {
    pub(crate) gates: Vec<Gate>,
    pub(crate) summary: CaptureSummary,
}

impl Capture {
    fn unavailable(input: &str, input_len: usize, reason: String) -> Self {
        Self {
            gates: Vec::new(),
            summary: CaptureSummary {
                input: input.to_owned(),
                input_len,
                status: "unavailable".to_owned(),
                reason: Some(reason),
                comparisons: 0,
                truncated: false,
                unconfirmed: 0,
                runs: 0,
                shim_armed: false,
                runner: None,
                derived_search: None,
                searched_bytes: None,
            },
        }
    }
}

/// How to replay the harness.
pub(crate) struct Replay<'a> {
    pub(crate) harness: &'a Path,
    /// The finding's record: its leak rule, recorded runtime mode and
    /// injected environment shape the replay as `bhf replay` does.
    pub(crate) raw: &'a Value,
    /// Scratch directory for inputs and evidence files; created and removed.
    pub(crate) scratch: PathBuf,
    /// Where the baseline run's runtrace events go (the shim is preloaded for
    /// it only when this is set and the shim is found).
    pub(crate) runtrace_log: Option<PathBuf>,
    pub(crate) deadline: Instant,
}

/// Whether `harness` carries a driver that records comparison evidence: its
/// binary names the variable the driver reads.
pub(crate) fn harness_records_evidence(harness: &Path) -> bool {
    use std::io::Read;
    let Ok(mut file) = std::fs::File::open(harness) else {
        return false;
    };
    let keep = DRIVER_MARKER.len() - 1;
    let mut window = Vec::with_capacity(64 * 1024 + keep);
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let read = match file.read(&mut chunk) {
            Ok(0) | Err(_) => return false,
            Ok(read) => read,
        };
        window.extend_from_slice(&chunk[..read]);
        if window
            .windows(DRIVER_MARKER.len())
            .any(|candidate| candidate == DRIVER_MARKER)
        {
            return true;
        }
        let tail = window.len().saturating_sub(keep);
        window.drain(..tail);
    }
}

/// Replay `input` (named `input_name`) and return the comparison evidence.
pub(crate) fn capture(replay: &Replay<'_>, input: &[u8], input_name: &str) -> Capture {
    capture_with(
        replay,
        input,
        input_name,
        find_symbolizer(),
        Limits::default(),
    )
}

/// [`capture`] with `symbolizer` (`llvm-symbolizer`) giving the comparison
/// sites their source positions, when there is one, and `limits` bounding
/// the replays.
fn capture_with(
    replay: &Replay<'_>,
    input: &[u8],
    input_name: &str,
    symbolizer: Option<PathBuf>,
    limits: Limits,
) -> Capture {
    if !replay.harness.is_file() {
        return Capture::unavailable(
            input_name,
            input.len(),
            format!(
                "the harness binary {} was not found",
                replay.harness.display()
            ),
        );
    }
    if !harness_records_evidence(replay.harness) {
        return Capture::unavailable(
            input_name,
            input.len(),
            "the harness was built without a driver that records comparisons \
             (built by an earlier bhf, or not by bhf); rebuild it to record them"
                .to_owned(),
        );
    }
    if let Err(error) = std::fs::create_dir_all(&replay.scratch) {
        return Capture::unavailable(
            input_name,
            input.len(),
            format!("cannot create {}: {error}", replay.scratch.display()),
        );
    }
    let capture = capture_in(replay, input, input_name, symbolizer.as_deref(), limits);
    let _ = std::fs::remove_dir_all(&replay.scratch);
    capture
}

fn capture_in(
    replay: &Replay<'_>,
    input: &[u8],
    input_name: &str,
    symbolizer: Option<&Path>,
    limits: Limits,
) -> Capture {
    let mut runner = Runner::new(replay, symbolizer);
    let baseline = match runner.run(input, true) {
        Ok(log) => log,
        Err(reason) => return Capture::unavailable(input_name, input.len(), reason),
    };
    // Every site the baseline reached, symbolized once: a comparison in bhf's
    // harness code (decoding it does after entering the target, or checks of
    // the target's result) is left out of this run and every later one.
    let mut all_located = false;
    if let Some(symbols) = runner.symbols.as_mut() {
        let sites: BTreeSet<u32> = baseline.target_records().iter().map(|r| r.site).collect();
        if sites.len() <= MAX_SYMBOLIZED_SITES {
            symbols.resolve(&sites);
            all_located = true;
            runner.excluded = sites
                .iter()
                .filter(|site| {
                    symbols
                        .location(**site)
                        .is_some_and(|location| is_harness_location(&location))
                })
                .copied()
                .collect();
        }
    }
    let records: Vec<CmpRecord> = baseline
        .target_records()
        .into_iter()
        .filter(|r| !runner.excluded.contains(&r.site))
        .cloned()
        .collect();
    let mut summary = CaptureSummary {
        input: input_name.to_owned(),
        input_len: input.len(),
        status: String::new(),
        reason: None,
        comparisons: records.len(),
        truncated: baseline.truncated,
        unconfirmed: 0,
        runs: 0,
        shim_armed: runner.shim_armed,
        runner: runner.emulator_label(),
        derived_search: None,
        searched_bytes: None,
    };
    let mut gates = Vec::new();
    if input.is_empty() {
        summary.status = if records.is_empty() {
            "no_comparisons"
        } else {
            "no_input_comparisons"
        }
        .to_owned();
        summary.reason = Some(
            "the input is empty, so no comparison operand can come from it: every scalar \
             parameter decodes to 0 and every buffer is empty"
                .to_owned(),
        );
    } else if records.is_empty() {
        summary.status = "no_comparisons".to_owned();
        summary.reason = Some(if baseline.target_entered {
            "no instrumented comparison was recorded in the target on this input (code built \
             without bhf's comparison instrumentation, such as a prebuilt library, is not \
             observed)"
                .to_owned()
        } else {
            "no instrumented comparison was recorded on this input".to_owned()
        });
    } else {
        let (equal, unconfirmed) = equal_gates(&mut runner, input, &records);
        summary.unconfirmed = unconfirmed;
        gates.extend(equal);
        let spans = scalar_spans(replay.harness, input);
        let (derived, search) = derived_gates(&mut runner, input, &records, &gates, &spans, limits);
        gates.extend(derived);
        summary.derived_search = Some(search.state.as_str().to_owned());
        summary.searched_bytes = Some(search.searched);
        if gates.is_empty() {
            summary.status = "no_input_comparisons".to_owned();
            summary.reason = Some(no_gate_reason(
                records.len(),
                input.len(),
                baseline.truncated,
                search,
            ));
        } else {
            summary.status = "recorded".to_owned();
        }
    }
    summary.runs = runner.runs;
    gates.sort_by(|a, b| {
        (a.offset, a.len, &a.site, &a.cmp_kind).cmp(&(b.offset, b.len, &b.site, &b.cmp_kind))
    });
    gates.dedup_by(|a, b| {
        a.offset == b.offset && a.len == b.len && a.site == b.site && a.cmp_kind == b.cmp_kind
    });
    let gate_site = |gate: &Gate| u32::from_str_radix(gate.site.trim_start_matches("0x"), 16).ok();
    if let Some(symbols) = runner.symbols.as_mut() {
        if !all_located {
            let sites: BTreeSet<u32> = gates.iter().filter_map(gate_site).collect();
            symbols.resolve(&sites);
        }
        for gate in &mut gates {
            let site = gate_site(gate);
            gate.location = site.and_then(|site| symbols.location(site));
            gate.site_unattributable =
                gate.location.is_none() && site.is_some_and(|site| symbols.is_interceptor(site));
        }
    }
    gates.retain(|gate| !gate.location.as_ref().is_some_and(is_harness_location));
    gates.truncate(MAX_GATES);
    if gates.is_empty() && summary.status == "recorded" {
        summary.status = "no_input_comparisons".to_owned();
        summary.reason = Some(
            "the only comparisons of input bytes were in bhf's harness code, which decodes \
             the input"
                .to_owned(),
        );
    }
    Capture { gates, summary }
}

/// Bounds of one capture's replays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Limits {
    /// Most replays the range search of a long input makes.
    derived_runs: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            derived_runs: MAX_DERIVED_RUNS,
        }
    }
}

/// The input byte spans the harness decodes its scalar parameters from
/// (`arg-layout.json` beside the harness, decoded over `input`): the bytes a
/// range check most likely reads, searched first in a long input.
fn scalar_spans(harness: &Path, input: &[u8]) -> Vec<std::ops::Range<usize>> {
    let Some(Ok(layout)) = harness
        .parent()
        .and_then(harness_gen::arg_layout::ArgLayout::read)
    else {
        return Vec::new();
    };
    let scalar: BTreeSet<(String, String, usize)> = layout
        .params()
        .filter(|param| {
            matches!(
                param.decoder.as_str(),
                "scalar" | "bounded_int" | "enum_member"
            )
        })
        .map(|param| (param.call.clone(), param.name.clone(), param.index))
        .collect();
    let mut spans: Vec<std::ops::Range<usize>> = layout
        .decode(input)
        .into_iter()
        .filter(|arg| scalar.contains(&(arg.call.clone(), arg.name.clone(), arg.index)))
        .filter_map(|arg| {
            let [start, end] = arg.span?;
            let (start, end) = (usize::try_from(start).ok()?, usize::try_from(end).ok()?);
            (start < end && end <= input.len()).then_some(start..end)
        })
        .collect();
    spans.sort_by_key(|span| (span.start, span.end));
    spans.dedup();
    spans
}

/// How far the search for operands computed from input bytes got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SearchState {
    /// Every byte was searched and the controls agreed.
    Done,
    /// The replay budget ran out first.
    Partial,
    /// The input is longer than [`MAX_SEARCHED_INPUT`], so it was not tried.
    TooLong,
}

impl SearchState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Done => "done",
            Self::Partial => "partial",
            Self::TooLong => "too_long",
        }
    }
}

/// The computed-operand search's outcome: its state and the input bytes it
/// covered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DerivedSearch {
    state: SearchState,
    searched: usize,
}

/// Why comparisons were recorded but none is evidence, with what the search
/// left out.
fn no_gate_reason(
    comparisons: usize,
    input_len: usize,
    truncated: bool,
    search: DerivedSearch,
) -> String {
    let mut reason = format!(
        "{comparisons} comparison(s) recorded; no operand followed a change of the input bytes"
    );
    match search.state {
        SearchState::Done => {}
        SearchState::Partial => reason.push_str(&format!(
            "; the replay budget ran out after {} of {input_len} bytes were searched for \
             operands computed from them (such as range checks)",
            search.searched
        )),
        SearchState::TooLong => reason.push_str(&format!(
            "; operands computed from input bytes (such as range checks) are searched only in \
             inputs of up to {MAX_SEARCHED_INPUT} bytes, and this one has {input_len}"
        )),
    }
    if truncated {
        reason.push_str(&format!(
            "; the driver keeps the first {DRIVER_CAPACITY} comparisons of a run and this one \
             made more, so later ones were not seen"
        ));
    }
    reason
}

/// How an operand's bytes are laid out in the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Order {
    /// The operand bytes occur in the input as they are.
    Same,
    /// They occur reversed: an integer read big-endian.
    Reversed,
}

/// Operand bytes that occur in the input, at the occurrences found.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Candidate {
    site: u32,
    kind: CmpKind,
    side: Side,
    order: Order,
    /// The bytes to find in the input, in input order.
    pattern: Vec<u8>,
    compared_with: Vec<u8>,
    equal: bool,
}

/// The input-side byte sequences of `record` worth looking for: the whole
/// operand of a buffer or string comparison (up to the shorter string), and
/// for an integer the full width in either byte order, else its low bytes (a
/// narrower value the compiler widened).
fn patterns(record: &CmpRecord, side: Side) -> Vec<(Order, Vec<u8>)> {
    let operand = record.operand(side);
    if operand.is_empty() {
        return Vec::new();
    }
    if record.kind.is_buffer() {
        let len = if record.kind.is_string() {
            operand.len().min(record.other(side).len().max(1))
        } else {
            operand.len()
        };
        return vec![(Order::Same, operand[..len].to_vec())];
    }
    let mut out = vec![(Order::Same, operand.to_vec())];
    if operand.len() > 1 {
        out.push((Order::Reversed, operand.iter().rev().copied().collect()));
    }
    // A zero- or sign-extended narrower value: its significant low bytes.
    let fill = if operand.last().is_some_and(|b| b & 0x80 != 0) {
        0xff
    } else {
        0x00
    };
    let significant = operand
        .iter()
        .rposition(|b| *b != fill)
        .map(|i| i + 1)
        .unwrap_or(1);
    if significant < operand.len() {
        out.push((Order::Same, operand[..significant].to_vec()));
        if significant > 1 {
            out.push((
                Order::Reversed,
                operand[..significant].iter().rev().copied().collect(),
            ));
        }
    }
    out
}

/// Offsets at which `needle` occurs in `haystack`, at most `cap` of them, and
/// how many there are in all.
fn occurrences(haystack: &[u8], needle: &[u8], cap: usize) -> (Vec<usize>, usize) {
    if needle.is_empty() || needle.len() > haystack.len() {
        return (Vec::new(), 0);
    }
    let mut found = Vec::new();
    let mut total = 0;
    for (offset, window) in haystack.windows(needle.len()).enumerate() {
        if window == needle {
            total += 1;
            if found.len() < cap {
                found.push(offset);
            }
        }
    }
    (found, total)
}

/// The input byte a verification replay changes for an occurrence: the
/// operand's first byte (lowest for an integer).
fn changed_byte(order: Order, len: usize) -> usize {
    match order {
        Order::Same => 0,
        Order::Reversed => len - 1,
    }
}

/// Comparisons whose operand is a copy of input bytes, each confirmed by a
/// replay in which those bytes changed and the operand changed with them.
/// Returns the gates and the number of candidates left unconfirmed.
fn equal_gates(runner: &mut Runner<'_>, input: &[u8], records: &[CmpRecord]) -> (Vec<Gate>, usize) {
    // Candidate operands, with the occurrences of their bytes in the input.
    let mut candidates: BTreeMap<Candidate, Vec<usize>> = BTreeMap::new();
    for record in records {
        for side in [Side::A, Side::B] {
            if record.is_const(side) {
                continue;
            }
            // The first byte order and width whose bytes occur in the input.
            for (order, pattern) in patterns(record, side) {
                let (found, _) = occurrences(input, &pattern, MAX_OCCURRENCES);
                if found.is_empty() {
                    continue;
                }
                let key = Candidate {
                    site: record.site,
                    kind: record.kind,
                    side,
                    order,
                    pattern,
                    compared_with: record.other(side).to_vec(),
                    equal: record.equal,
                };
                candidates.entry(key).or_insert(found);
                break;
            }
        }
    }
    // Strings and buffers first, then operands found in few places, then
    // wider integers before single bytes: an operand that occurs all over a
    // large input is the least likely to be one, so it does not spend the
    // replay budget first.
    let mut ordered: Vec<(Candidate, Vec<usize>)> = candidates.into_iter().collect();
    ordered.sort_by_key(|(c, found)| {
        (
            !c.kind.is_buffer(),
            found.len() > MAX_TRIED_ALONE,
            std::cmp::Reverse(c.pattern.len()),
            found.first().copied(),
        )
    });
    let mut gates = Vec::new();
    let mut unconfirmed = 0;
    let mut confirmed_spans: BTreeSet<(u32, usize, usize)> = BTreeSet::new();
    // Under AddressSanitizer every memcmp and bcmp reports the interceptor as
    // its site, so a buffer comparison's budget is per compared value too.
    let mut tried_at_site: BTreeMap<(u32, Option<Vec<u8>>), usize> = BTreeMap::new();
    for (candidate, found) in ordered {
        if found
            .iter()
            .all(|o| confirmed_spans.contains(&(candidate.site, *o, candidate.pattern.len())))
        {
            continue;
        }
        // A loop that compares every byte it scans gives one site many
        // operand values; a few of them say what it does.
        let site_key = (
            candidate.site,
            candidate
                .kind
                .is_buffer()
                .then(|| candidate.compared_with.clone()),
        );
        let tried = tried_at_site.entry(site_key).or_default();
        if *tried >= MAX_CANDIDATES_PER_SITE || !runner.budget_left(1 + MAX_VERIFY_RUNS) {
            unconfirmed += 1;
            continue;
        }
        *tried += 1;
        let confirmed = confirm_candidate(runner, input, records, &candidate, &found);
        if confirmed.is_empty() {
            unconfirmed += 1;
            continue;
        }
        for offset in confirmed {
            confirmed_spans.insert((candidate.site, offset, candidate.pattern.len()));
            gates.push(Gate {
                offset,
                len: candidate.pattern.len(),
                operand_hex: hex(&input_operand(&candidate, input, offset)),
                compared_with_hex: hex(&candidate.compared_with),
                cmp_kind: candidate.kind.as_str().to_owned(),
                site: format!("{:#x}", candidate.site),
                location: None,
                relation: match candidate.order {
                    Order::Same => "equal",
                    Order::Reversed => "byte_swapped",
                }
                .to_owned(),
                operands_equal: candidate.equal,
                site_unattributable: false,
            });
        }
    }
    (gates, unconfirmed)
}

/// The operand bytes as the comparison saw them, read back from the input.
fn input_operand(candidate: &Candidate, input: &[u8], offset: usize) -> Vec<u8> {
    let span = &input[offset..offset + candidate.pattern.len()];
    match candidate.order {
        Order::Same => span.to_vec(),
        Order::Reversed => span.iter().rev().copied().collect(),
    }
}

/// Occurrences of an operand tried one replay each when a replay changing all
/// of them at once confirmed none.
const MAX_TRIED_ALONE: usize = 3;

/// The occurrences of `candidate` that a replay confirms: one replay changes
/// every non-overlapping occurrence at once, each to a different value, and
/// an occurrence is confirmed when the comparison at the same site then saw
/// exactly its changed bytes. When that replay confirms nothing (the changes
/// moved the path), the first few occurrences are tried alone.
fn confirm_candidate(
    runner: &mut Runner<'_>,
    input: &[u8],
    records: &[CmpRecord],
    candidate: &Candidate,
    found: &[usize],
) -> Vec<usize> {
    let len = candidate.pattern.len();
    let mut batch = Vec::new();
    let mut end = 0;
    for &offset in found {
        if offset >= end || batch.is_empty() {
            batch.push(offset);
            end = offset + len;
        }
    }
    // The values this site's operand took on the unchanged input: a changed
    // value it already took proves nothing.
    let before: BTreeSet<Vec<u8>> = records
        .iter()
        .filter(|r| r.site == candidate.site && r.kind == candidate.kind)
        .map(|r| r.operand(candidate.side))
        .filter(|operand| operand.len() >= len)
        .map(|operand| operand[..len].to_vec())
        .collect();
    let confirmed = confirm_occurrences(runner, input, candidate, &batch, &before);
    if !confirmed.is_empty() || batch.len() == 1 || batch.len() > MAX_TRIED_ALONE * 3 {
        return confirmed;
    }
    let mut alone = Vec::new();
    for &offset in batch.iter().take(MAX_TRIED_ALONE) {
        if !runner.budget_left(1 + MAX_VERIFY_RUNS) {
            break;
        }
        alone.extend(confirm_occurrences(
            runner,
            input,
            candidate,
            &[offset],
            &before,
        ));
    }
    alone
}

fn confirm_occurrences(
    runner: &mut Runner<'_>,
    input: &[u8],
    candidate: &Candidate,
    offsets: &[usize],
    before: &BTreeSet<Vec<u8>>,
) -> Vec<usize> {
    let len = candidate.pattern.len();
    let at = changed_byte(candidate.order, len);
    let original = candidate.pattern[at];
    // Each occurrence gets its own change: bit 7 kept (a sign-extended
    // operand keeps its high bytes), never a NUL that would end a string
    // operand early, and never a value the operand already took.
    let mut masks = (1u8..0x80).filter(|mask| original ^ mask != 0);
    let mut mutated = input.to_vec();
    let mut expected: Vec<(usize, Vec<u8>)> = Vec::new();
    for &offset in offsets {
        // The changed input byte is the operand's first byte in either order.
        let next = masks.by_ref().find_map(|mask| {
            let mut operand = operand_bytes(candidate);
            operand[0] ^= mask;
            (!before.contains(&operand)).then_some((mask, operand))
        });
        let Some((mask, operand)) = next else {
            break;
        };
        mutated[offset + at] ^= mask;
        expected.push((offset, operand));
    }
    let Ok(log) = runner.run(&mutated, false) else {
        return Vec::new();
    };
    let seen: Vec<&[u8]> = log
        .target_records()
        .into_iter()
        .filter(|r| r.site == candidate.site && r.kind == candidate.kind)
        .map(|r| r.operand(candidate.side))
        .collect();
    expected
        .into_iter()
        .filter(|(_, operand)| {
            seen.iter()
                .any(|got| got.len() >= operand.len() && got[..operand.len()] == operand[..])
        })
        .map(|(offset, _)| offset)
        .collect()
}

/// The candidate's bytes in operand order (lowest byte first for an integer).
fn operand_bytes(candidate: &Candidate) -> Vec<u8> {
    match candidate.order {
        Order::Same => candidate.pattern.clone(),
        Order::Reversed => candidate.pattern.iter().rev().copied().collect(),
    }
}

/// Each comparison site's operand pairs, in execution order.
type OperandsBySite = BTreeMap<(u32, CmpKind), Vec<(Vec<u8>, Vec<u8>)>>;

/// Comparisons whose operand is computed from input bytes: a byte feeds a
/// comparison when, with that byte flipped, the operand on the comparison's
/// non-constant side changed while it ran as often as before. Comparisons the
/// copied-bytes pass already explained are skipped.
///
/// An input of up to [`MAX_DERIVED_INPUT`] bytes has every byte flipped once.
/// A longer one is searched by range: first each byte of the spans the harness
/// decodes its scalar parameters from (`spans`, from `arg-layout.json`), then
/// the whole input, halved again and again where flipping a range changed a
/// comparison (an operand, or how often it ran) down to the bytes, and left
/// alone where it changed none. That stops after `limits.derived_runs`
/// replays, and the result says how many bytes were searched.
///
/// Two control replays of the unchanged input, one before the flips and one
/// after them, are the reference: an operand that differs between them, or
/// from the baseline, depends on something besides the input (a process id,
/// a clock, an address), so its change after a flip says nothing about the
/// flipped byte and it is left out. Without the closing control no gate is
/// reported.
fn derived_gates(
    runner: &mut Runner<'_>,
    input: &[u8],
    records: &[CmpRecord],
    known: &[Gate],
    spans: &[std::ops::Range<usize>],
    limits: Limits,
) -> (Vec<Gate>, DerivedSearch) {
    let nothing = |state| (Vec::new(), DerivedSearch { state, searched: 0 });
    if input.len() > MAX_SEARCHED_INPUT {
        return nothing(SearchState::TooLong);
    }
    let explained: BTreeSet<u32> = known
        .iter()
        .filter_map(|g| u32::from_str_radix(g.site.trim_start_matches("0x"), 16).ok())
        .collect();
    let base_refs: Vec<&CmpRecord> = records.iter().collect();
    let base = operands_by_site(&base_refs);
    let consts: BTreeMap<(u32, CmpKind), (bool, bool)> = records
        .iter()
        .map(|r| ((r.site, r.kind), (r.a_const, r.b_const)))
        .collect();
    let per_byte = input.len() <= MAX_DERIVED_INPUT;
    let flips = if per_byte {
        input.len()
    } else {
        limits.derived_runs
    };
    // The flips plus the two controls.
    let limit = runner.runs + flips + 2;
    if !runner.budget_left(limit) {
        return nothing(SearchState::Partial);
    }
    let Ok(control) = runner.run(input, false) else {
        return nothing(SearchState::Partial);
    };
    let reference = operands_by_site(&control.target_records());
    let mut unstable = unstable_operands(&base, &reference);
    // (site, kind, side) -> input offsets that fed it.
    let mut fed: BTreeMap<(u32, CmpKind, Side), BTreeSet<usize>> = BTreeMap::new();
    let mut searched = vec![false; input.len()];
    // Replay `input` with the bytes of `range` flipped: whether any
    // comparison changed, and for a single byte, the operands it fed.
    let mut flip = |runner: &mut Runner<'_>, range: std::ops::Range<usize>| -> Option<bool> {
        let mut mutated = input.to_vec();
        for byte in &mut mutated[range.clone()] {
            *byte ^= 0x5a;
        }
        let log = runner.run(&mutated, false).ok()?;
        let after = operands_by_site(&log.target_records());
        let mut changed = false;
        for key in reference.keys().chain(after.keys()) {
            if explained.contains(&key.0) {
                continue;
            }
            let empty = Vec::new();
            let before = reference.get(key).unwrap_or(&empty);
            let now = after.get(key).unwrap_or(&empty);
            let (a_const, b_const) = consts.get(key).copied().unwrap_or((false, false));
            for side in [Side::A, Side::B] {
                let constant = match side {
                    Side::A => a_const,
                    Side::B => b_const,
                };
                if constant
                    || unstable.contains(&(key.0, key.1, side))
                    || !side_differs(before, now, side)
                {
                    continue;
                }
                changed = true;
                // Only a change at an unchanged run count is this byte's
                // value reaching the operand rather than a different path.
                if range.len() == 1 && now.len() == before.len() {
                    fed.entry((key.0, key.1, side))
                        .or_default()
                        .insert(range.start);
                }
            }
        }
        Some(changed)
    };
    if per_byte {
        for (offset, done) in searched.iter_mut().enumerate() {
            // One run stays for the closing control.
            if !runner.budget_left(limit - 1) {
                break;
            }
            *done = flip(runner, offset..offset + 1).is_some();
        }
    } else {
        let mut singles: Vec<usize> = spans.iter().flat_map(|span| span.clone()).collect();
        singles.sort_unstable();
        singles.dedup();
        for offset in singles {
            if !runner.budget_left(limit - 1) {
                break;
            }
            if flip(runner, offset..offset + 1).is_some() {
                searched[offset] = true;
            }
        }
        let mut pending: Vec<std::ops::Range<usize>> = Vec::new();
        pending.push(0..input.len());
        while let Some(range) = pending.pop() {
            if searched[range.clone()].iter().all(|done| *done) {
                continue;
            }
            if !runner.budget_left(limit - 1) {
                break;
            }
            match flip(runner, range.clone()) {
                None => {}
                Some(changed) if !changed || range.len() == 1 => {
                    searched[range].iter_mut().for_each(|done| *done = true);
                }
                Some(_) => {
                    let mid = range.start + range.len() / 2;
                    pending.push(mid..range.end);
                    pending.push(range.start..mid);
                }
            }
        }
    }
    let closing = if runner.budget_left(limit) {
        runner.run(input, false).ok()
    } else {
        None
    };
    let searched = searched.iter().filter(|done| **done).count();
    let Some(closing) = closing else {
        return (
            Vec::new(),
            DerivedSearch {
                state: SearchState::Partial,
                searched,
            },
        );
    };
    unstable.extend(unstable_operands(
        &reference,
        &operands_by_site(&closing.target_records()),
    ));
    fed.retain(|key, _| !unstable.contains(key));
    let search = DerivedSearch {
        state: if searched == input.len() {
            SearchState::Done
        } else {
            SearchState::Partial
        },
        searched,
    };
    let mut gates = Vec::new();
    for ((site, kind, side), offsets) in fed {
        let Some((a, b)) = base.get(&(site, kind)).and_then(|v| v.first()) else {
            continue;
        };
        let (operand, other) = match side {
            Side::A => (a, b),
            Side::B => (b, a),
        };
        let equal = records
            .iter()
            .find(|r| r.site == site && r.kind == kind)
            .is_some_and(|r| r.equal);
        for (start, len) in runs(&offsets) {
            // Bytes a copied operand already explains: this comparison is a
            // consequence of that one (the `== 0` test of a strcmp result,
            // which the terminator after the string decides too).
            if (start..start + len).all(|offset| {
                known.iter().any(|g| {
                    let terminator = usize::from(is_string_kind(&g.cmp_kind));
                    g.offset <= offset && offset < g.offset + g.len + terminator
                })
            }) {
                continue;
            }
            gates.push(Gate {
                offset: start,
                len,
                operand_hex: hex(operand),
                compared_with_hex: hex(other),
                cmp_kind: kind.as_str().to_owned(),
                site: format!("{site:#x}"),
                location: None,
                relation: "derived".to_owned(),
                operands_equal: equal,
                site_unattributable: false,
            });
        }
    }
    (gates, search)
}

/// A string comparison's kind as a gate names it (`strcmp`, `strncasecmp`).
fn is_string_kind(cmp_kind: &str) -> bool {
    matches!(
        cmp_kind,
        "strcmp" | "strncmp" | "strcasecmp" | "strncasecmp"
    )
}

/// Each comparison site's operand pairs, in execution order.
fn operands_by_site(records: &[&CmpRecord]) -> OperandsBySite {
    let mut map = OperandsBySite::new();
    for r in records {
        map.entry((r.site, r.kind))
            .or_default()
            .push((r.a.clone(), r.b.clone()));
    }
    map
}

/// Whether the `side` operands of two runs of one site differ.
fn side_differs(before: &[(Vec<u8>, Vec<u8>)], now: &[(Vec<u8>, Vec<u8>)], side: Side) -> bool {
    before.len() != now.len()
        || before
            .iter()
            .zip(now)
            .any(|((a0, b0), (a1, b1))| match side {
                Side::A => a0 != a1,
                Side::B => b0 != b1,
            })
}

/// The operands that differ between two runs of the same input: a site that
/// ran a different number of times, or whose operand on a side took
/// different values.
fn unstable_operands(
    first: &OperandsBySite,
    second: &OperandsBySite,
) -> BTreeSet<(u32, CmpKind, Side)> {
    let empty = Vec::new();
    let mut unstable = BTreeSet::new();
    for key in first.keys().chain(second.keys()) {
        let one = first.get(key).unwrap_or(&empty);
        let two = second.get(key).unwrap_or(&empty);
        for side in [Side::A, Side::B] {
            if side_differs(one, two, side) {
                unstable.insert((key.0, key.1, side));
            }
        }
    }
    unstable
}

/// Contiguous runs of `offsets` as `(start, len)`.
fn runs(offsets: &BTreeSet<usize>) -> Vec<(usize, usize)> {
    let mut out: Vec<(usize, usize)> = Vec::new();
    for &offset in offsets {
        match out.last_mut() {
            Some((start, len)) if *start + *len == offset => *len += 1,
            _ => out.push((offset, 1)),
        }
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Runs the harness on inputs with evidence capture armed.
struct Runner<'a> {
    replay: &'a Replay<'a>,
    runs: usize,
    shim_armed: bool,
    /// Sites in the harness's own code, dropped from every run's records.
    excluded: BTreeSet<u32>,
    /// The emulator the harness runs under, recorded beside it.
    emulator: Option<HarnessRunner>,
    /// The harness's symbols, when a symbolizer was found: they move a
    /// comparison the sanitizer's interceptor reported to its caller.
    symbols: Option<Symbols>,
}

impl<'a> Runner<'a> {
    fn new(replay: &'a Replay<'a>, symbolizer: Option<&Path>) -> Self {
        Self {
            replay,
            runs: 0,
            shim_armed: false,
            excluded: BTreeSet::new(),
            emulator: recorded_runner(replay.harness),
            symbols: symbolizer.map(|symbolizer| Symbols::new(replay.harness, symbolizer)),
        }
    }

    /// The emulator's program name, for the capture summary.
    fn emulator_label(&self) -> Option<String> {
        self.emulator
            .as_ref()
            .map(|runner| runner.program.display().to_string())
    }

    /// Whether another replay fits under `limit` runs in all and the deadline.
    fn budget_left(&self, limit: usize) -> bool {
        self.runs < limit && Instant::now() < self.replay.deadline
    }

    /// Run `input`; `baseline` arms the runtrace shim when a log is wanted.
    fn run(&mut self, input: &[u8], baseline: bool) -> Result<EvidenceLog, String> {
        let index = self.runs;
        self.runs += 1;
        let scratch = &self.replay.scratch;
        let input_path = scratch.join(format!("input-{index}.bin"));
        let evidence = scratch.join(format!("evidence-{index}.bin"));
        std::fs::write(&input_path, input)
            .map_err(|error| format!("write {}: {error}", input_path.display()))?;
        let _ = std::fs::remove_file(&evidence);
        // A foreign harness runs under its emulator, which hands the guest
        // the environment set here (the evidence file among it). A guest
        // abort makes qemu-user dump its own address space: no core dumps.
        let mut command = match &self.emulator {
            Some(runner) => {
                let mut command = std::process::Command::new(&runner.program);
                command.args(&runner.args).arg(self.replay.harness);
                replay_min::process::disable_core_dumps(&mut command);
                command
            }
            None => std::process::Command::new(self.replay.harness),
        };
        command
            .arg(&input_path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .env(EVIDENCE_ENV, &evidence)
            // The driver's other channels belong to a fuzz campaign.
            .env_remove("BHF_CMP_SHM")
            .env_remove("BHF_COV_SHM")
            .env_remove("BHF_VP_SHM")
            .env_remove("BHF_CMPLOG")
            .env_remove("BHF_FRAMED");
        for (key, value) in replay_env(self.replay.raw, self.emulator.is_some()) {
            command.env(key, value);
        }
        command.env_remove("LD_PRELOAD");
        command.env_remove("BHF_RUNTRACE_LOG");
        // The runtrace shim is a host library: it cannot load into a
        // harness that runs under an emulator.
        let mut armed_log = None;
        if baseline && self.emulator.is_none() {
            if let Some(log) = &self.replay.runtrace_log {
                // A log from an earlier capture would not describe this run.
                let _ = std::fs::remove_file(log);
                if let Some(shim) = crate::auto::shim_path::locate() {
                    command
                        .env(
                            "LD_PRELOAD",
                            crate::auto::shim_path::ld_preload_value(&shim),
                        )
                        .env("BHF_RUNTRACE_LOG", log);
                    armed_log = Some(log.clone());
                }
            }
        }
        let mut child = command.spawn().map_err(|error| match &self.emulator {
            Some(runner) => format!(
                "cannot run {} under {}: {error}",
                self.replay.harness.display(),
                runner.program.display()
            ),
            None => format!("cannot run {}: {error}", self.replay.harness.display()),
        })?;
        let started = Instant::now();
        let limit = RUN_TIMEOUT.min(
            self.replay
                .deadline
                .saturating_duration_since(started)
                .max(Duration::from_secs(1)),
        );
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if started.elapsed() >= limit => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                Err(error) => return Err(format!("wait for the harness: {error}")),
            }
        }
        let _ = std::fs::remove_file(&input_path);
        // The shim creates its log when it loads: no log, no shim, whatever
        // LD_PRELOAD said.
        if armed_log.is_some_and(|log| log.is_file()) {
            self.shim_armed = true;
        }
        let bytes = std::fs::read(&evidence).map_err(|_| {
            "the harness wrote no comparison evidence (its driver does not record \
             comparisons, or it exited before its driver started)"
                .to_owned()
        })?;
        let _ = std::fs::remove_file(&evidence);
        let mut log = parse_log(&bytes)?;
        if let Some(symbols) = self.symbols.as_mut() {
            symbols.attribute(&mut log.records);
        }
        log.records.retain(|r| !self.excluded.contains(&r.site));
        Ok(log)
    }
}

/// The environment of a capture replay: the fuzz child's sanitizer options
/// without symbolization or leak checks (no report is read; `emulated`, a
/// run under the harness's emulator, does not abort on a report either), and
/// the runtime mode and injected environment the finding recorded.
fn replay_env(raw: &Value, emulated: bool) -> Vec<(String, String)> {
    let mut env = Vec::new();
    for (key, value) in crate::fuzz::sanitizer_child_env_for(false, emulated) {
        let value =
            multicore_fuzz::merge_sanitizer_options(Some(&value), "symbolize=0:detect_leaks=0");
        env.push((key, value));
    }
    let runtime_mode = raw.get("runtime_mode");
    // Without a recorded pass the shim runs in its default, observe-only mode.
    if let Some(pass) = runtime_mode
        .and_then(|m| m.get("pass"))
        .and_then(Value::as_str)
    {
        env.push(("BHF_RUNTRACE_MODE".to_owned(), pass.to_owned()));
    }
    if let Some(injected) = runtime_mode
        .and_then(|m| m.get("env_injected"))
        .and_then(Value::as_object)
    {
        for (key, value) in injected {
            if let Some(value) = value.as_str() {
                env.push((key.clone(), value.to_owned()));
            }
        }
    }
    env
}

/// Most distinct comparison sites symbolized up front; a run reaching more
/// has only its evidence sites symbolized, after the search.
const MAX_SYMBOLIZED_SITES: usize = 4096;

/// One symbolized address: the innermost function there and its source
/// position.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Symbol {
    function: String,
    file: Option<String>,
    line: Option<u64>,
}

/// A harness's symbols, from its debug info by `llvm-symbolizer`, looked up
/// once per address and kept for the capture's later runs.
struct Symbols {
    harness: PathBuf,
    symbolizer: PathBuf,
    base: Option<u64>,
    /// `None` for an address with no function.
    known: BTreeMap<u32, Option<Symbol>>,
}

impl Symbols {
    fn new(harness: &Path, symbolizer: &Path) -> Self {
        Self {
            harness: harness.to_path_buf(),
            symbolizer: symbolizer.to_path_buf(),
            base: elf_link_base(harness),
            known: BTreeMap::new(),
        }
    }

    /// Symbolize the addresses of `sites` not yet looked up, at most
    /// [`MAX_SYMBOLIZED_SITES`] of them in one call.
    fn resolve(&mut self, sites: &BTreeSet<u32>) {
        let missing: Vec<u32> = sites
            .iter()
            .copied()
            .filter(|site| *site != 0 && !self.known.contains_key(site))
            .take(MAX_SYMBOLIZED_SITES)
            .collect();
        if missing.is_empty() {
            return;
        }
        let found = match self.base {
            Some(base) => symbolize(&self.harness, &self.symbolizer, base, &missing),
            None => BTreeMap::new(),
        };
        for site in missing {
            let symbol = found.get(&site).cloned();
            self.known.insert(site, symbol);
        }
    }

    /// Where the comparison at `site` is in the target's source: absent for a
    /// site without debug info, or inside libc or the sanitizer runtime.
    fn location(&self, site: u32) -> Option<SiteLocation> {
        let symbol = self.known.get(&site)?.as_ref()?;
        if symbol.function == "??" || is_interceptor_function(&symbol.function) {
            return None;
        }
        let file = symbol.file.as_deref()?;
        if actionability::is_runtime_noise_frame(&symbol.function, Some(file)) {
            return None;
        }
        Some(SiteLocation {
            file: file.to_owned(),
            line: symbol.line,
            function: Some(symbol.function.clone()),
        })
    }

    /// Whether `site` is in the sanitizer runtime's interceptors (or a
    /// comparison wrapper or hook in bhf's driver), not the code that called
    /// them.
    fn is_interceptor(&self, site: u32) -> bool {
        self.known
            .get(&site)
            .and_then(Option::as_ref)
            .is_some_and(|symbol| {
                is_interceptor_function(&symbol.function)
                    || actionability::is_runtime_noise_frame(
                        &symbol.function,
                        symbol.file.as_deref(),
                    )
            })
    }

    /// Move each record whose site is an interceptor to the first frame above
    /// it that is not (its caller), and drop a record whose caller is outside
    /// the executable: a library's own `memcmp`, not the target's. A record
    /// whose callers name nothing keeps its site and is marked
    /// unattributable.
    fn attribute(&mut self, records: &mut Vec<CmpRecord>) {
        let wanted: BTreeSet<u32> = records
            .iter()
            .filter(|r| r.callers.iter().any(|c| *c != 0))
            .flat_map(|r| std::iter::once(r.site).chain(r.callers.iter().copied()))
            .collect();
        self.resolve(&wanted);
        records.retain_mut(|record| {
            if !record.callers.iter().any(|c| *c != 0) || !self.is_interceptor(record.site) {
                return true;
            }
            for caller in record.callers.clone() {
                if caller == 0 {
                    // The frame above the interceptor is outside the
                    // executable: the comparison is a library's.
                    return false;
                }
                if !self.is_interceptor(caller) {
                    record.site = caller;
                    return true;
                }
            }
            record.unattributable = true;
            true
        });
    }
}

/// The sanitizer runtime's interceptor, or a bhf comparison wrapper or hook:
/// a frame between a comparison call and the code that made it.
fn is_interceptor_function(function: &str) -> bool {
    let name = function.trim();
    name.starts_with("___interceptor_")
        || name.starts_with("__interceptor_")
        || name.starts_with("__sanitizer_")
        || name.starts_with("__wrap_")
        || name.contains("InterceptorCommon")
        || name.starts_with("bhf_ev_")
        || name.starts_with("bhf_cmplog_")
}

/// Source positions of `sites` (executable offsets from `base`) in the
/// harness's debug info, by `llvm-symbolizer`: the innermost function at each
/// site, so target code inlined into the harness keeps its own position.
fn symbolize(harness: &Path, symbolizer: &Path, base: u64, sites: &[u32]) -> BTreeMap<u32, Symbol> {
    let mut found = BTreeMap::new();
    // A return address: the comparison is the instruction before it.
    let addresses: Vec<(u32, u64)> = sites
        .iter()
        .map(|site| (*site, (base + u64::from(*site)).saturating_sub(1)))
        .collect();
    let mut command = std::process::Command::new(symbolizer);
    command
        .arg(format!("--obj={}", harness.display()))
        .arg("--functions=linkage")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        // A debuginfod lookup could wait on the network.
        .env("DEBUGINFOD_URLS", "");
    for (_, address) in &addresses {
        command.arg(format!("{address:#x}"));
    }
    let Ok(output) =
        crate::command_output::output_with_timeout(&mut command, Duration::from_secs(10))
    else {
        return found;
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let blocks: Vec<&str> = text.split("\n\n").collect();
    for ((site, _), block) in addresses.iter().zip(blocks) {
        let mut lines = block.lines().filter(|l| !l.trim().is_empty());
        let function = lines.next().map(str::trim).unwrap_or("??");
        let position = lines.next().map(str::trim).unwrap_or("??");
        if function == "??" {
            continue;
        }
        let mut parts = position.rsplitn(3, ':');
        let _column = parts.next();
        let line = parts.next().and_then(|l| l.parse::<u64>().ok());
        let file = parts
            .next()
            .filter(|f| !f.is_empty() && *f != "??")
            .map(str::to_owned);
        found.insert(
            *site,
            Symbol {
                function: function.to_owned(),
                file,
                line: line.filter(|l| *l > 0),
            },
        );
    }
    found
}

/// Whether a comparison site is in bhf's harness or runtime code rather than
/// the target's: the harness compares input bytes while decoding them, which
/// says nothing about the target.
fn is_harness_location(location: &SiteLocation) -> bool {
    actionability::is_harness_frame(
        location.function.as_deref().unwrap_or_default(),
        Some(&location.file),
    )
}

fn find_symbolizer() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("ASAN_SYMBOLIZER_PATH").map(PathBuf::from) {
        if path.is_file() {
            return Some(path);
        }
    }
    which::which("llvm-symbolizer").ok().or_else(|| {
        (14..=24)
            .rev()
            .find_map(|version| which::which(format!("llvm-symbolizer-{version}")).ok())
    })
}

/// The link-time address the driver's `__executable_start` corresponds to:
/// 0 for a position-independent executable, the first loadable segment's
/// address otherwise. ELF32 and ELF64, either byte order, so a harness built
/// for another architecture is symbolized too.
fn elf_link_base(path: &Path) -> Option<u64> {
    use std::io::Read;
    let mut header = vec![0u8; 4096];
    let mut file = std::fs::File::open(path).ok()?;
    let read = file.read(&mut header).ok()?;
    header.truncate(read);
    if header.get(..4)? != b"\x7fELF" {
        return None;
    }
    let wide = match header.get(4)? {
        1 => false,
        2 => true,
        _ => return None,
    };
    let big = match header.get(5)? {
        1 => false,
        2 => true,
        _ => return None,
    };
    let bytes_at = |at: usize, len: usize| header.get(at..at + len);
    let u16_at = |at: usize| -> Option<u16> {
        let raw: [u8; 2] = bytes_at(at, 2)?.try_into().ok()?;
        Some(if big {
            u16::from_be_bytes(raw)
        } else {
            u16::from_le_bytes(raw)
        })
    };
    let u32_at = |at: usize| -> Option<u32> {
        let raw: [u8; 4] = bytes_at(at, 4)?.try_into().ok()?;
        Some(if big {
            u32::from_be_bytes(raw)
        } else {
            u32::from_le_bytes(raw)
        })
    };
    let u64_at = |at: usize| -> Option<u64> {
        let raw: [u8; 8] = bytes_at(at, 8)?.try_into().ok()?;
        Some(if big {
            u64::from_be_bytes(raw)
        } else {
            u64::from_le_bytes(raw)
        })
    };
    match u16_at(16)? {
        3 => return Some(0),
        2 => {}
        _ => return None,
    }
    // (e_phoff, e_phentsize, e_phnum) and each entry's p_vaddr.
    let (phoff, phentsize, phnum, vaddr_at) = if wide {
        (
            usize::try_from(u64_at(32)?).ok()?,
            u16_at(54)?,
            u16_at(56)?,
            16,
        )
    } else {
        (
            usize::try_from(u32_at(28)?).ok()?,
            u16_at(42)?,
            u16_at(44)?,
            8,
        )
    };
    (0..usize::from(phnum))
        .filter_map(|index| {
            let at = phoff + index * usize::from(phentsize);
            let loadable = u32_at(at)? == 1;
            let vaddr = if wide {
                u64_at(at + vaddr_at)?
            } else {
                u64::from(u32_at(at + vaddr_at)?)
            };
            loadable.then_some(vaddr)
        })
        .min()
}

/// Total time `bhf auto` spends recording comparison evidence after fuzzing.
pub(crate) const PASS_BUDGET: Duration = Duration::from_secs(120);
/// Time for one finding's capture.
pub(crate) const PER_FINDING: Duration = Duration::from_secs(20);

/// The input explain and the capture use: `min_testcase.bin` when the
/// finding has one, else `testcase.bin`, as `(file name, bytes)`.
pub(crate) fn preferred_input(finding_dir: &Path) -> Option<(&'static str, Vec<u8>)> {
    ["min_testcase.bin", "testcase.bin"]
        .into_iter()
        .find_map(|name| Some((name, std::fs::read(finding_dir.join(name)).ok()?)))
}

/// The harness binary a finding replays against, as minimization finds it.
pub(crate) fn harness_for_finding(
    work_dir: &Path,
    finding_dir: &Path,
    raw: &Value,
) -> Option<PathBuf> {
    let text = |key: &str| raw.get(key).and_then(Value::as_str).map(str::to_owned);
    let pick = crate::auto::minimize_pass::Pick {
        id: text("id").unwrap_or_default(),
        dir: finding_dir.to_path_buf(),
        harness_id: text("harness_id"),
        fixture_path: text("fixture_path"),
    };
    crate::auto::minimize_pass::harness_for(work_dir, &pick)
}

/// After fuzzing and minimization, `bhf auto` records the comparison evidence
/// of every runtime finding whose harness can record it, replaying its
/// preferred input, and the environment that replay touched. A finding whose
/// recorded capture already covers that input is left alone. Bounded by
/// [`PASS_BUDGET`]; returns how many findings were recorded and how many were
/// left for lack of time.
pub(crate) fn run_pass(work_dir: &Path) -> (usize, usize) {
    let findings_dir = corpus::layout::findings_dir(work_dir);
    let Ok(entries) = std::fs::read_dir(&findings_dir) else {
        return (0, 0);
    };
    let mut dirs: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    let started = Instant::now();
    let (mut recorded_count, mut skipped) = (0, 0);
    for dir in dirs {
        let path = dir.join("finding.json");
        let Some(raw) = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        else {
            continue;
        };
        if !matches!(
            raw.get("classification").and_then(Value::as_str),
            Some("unhandled" | "oracle")
        ) {
            continue;
        }
        let Some((name, bytes)) = preferred_input(&dir) else {
            continue;
        };
        if recorded(&raw)
            .is_some_and(|c| c.summary.input == name && c.summary.input_len == bytes.len())
        {
            continue;
        }
        let Some(harness) = harness_for_finding(work_dir, &dir, &raw) else {
            continue;
        };
        if !harness_records_evidence(&harness) {
            continue;
        }
        let remaining = PASS_BUDGET.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            skipped += 1;
            continue;
        }
        let replay = Replay {
            harness: &harness,
            raw: &raw,
            scratch: dir.join(".gate-capture"),
            runtrace_log: Some(dir.join(FINDING_RUNTRACE)),
            deadline: Instant::now() + PER_FINDING.min(remaining),
        };
        let capture = capture(&replay, &bytes, name);
        match write_capture(&path, &capture) {
            Ok(()) => recorded_count += 1,
            Err(error) => bhfeprintln!(
                "bhf: comparison evidence for {} not written: {error}",
                dir.display()
            ),
        }
    }
    (recorded_count, skipped)
}

/// The runtrace log of a finding's own capture replay, in its finding dir.
pub(crate) const FINDING_RUNTRACE: &str = "runtrace.jsonl";

/// Store `capture` in the `finding.json` at `path`.
pub(crate) fn write_capture(path: &Path, capture: &Capture) -> std::io::Result<()> {
    let bytes = std::fs::read(path)?;
    let mut value: Value = serde_json::from_slice(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let (gates, summary) = record_fields(capture);
    let Some(object) = value.as_object_mut() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "finding.json is not a JSON object",
        ));
    };
    object.insert("gates".to_owned(), gates);
    object.insert("gate_capture".to_owned(), summary);
    corpus::finding::append_history(&mut value, "auto", &["gates", "gate_capture"]);
    std::fs::write(path, serde_json::to_vec_pretty(&value)?)
}

/// The capture as `finding.json` stores it: `gates` and `gate_capture`.
pub(crate) fn record_fields(capture: &Capture) -> (Value, Value) {
    (
        serde_json::to_value(&capture.gates).unwrap_or_else(|_| json!([])),
        serde_json::to_value(&capture.summary).unwrap_or_else(|_| json!({})),
    )
}

/// The capture a finding records, if any.
pub(crate) fn recorded(raw: &Value) -> Option<Capture> {
    let summary: CaptureSummary = serde_json::from_value(raw.get("gate_capture")?.clone()).ok()?;
    let gates = raw
        .get("gates")
        .and_then(Value::as_array)
        .map(|gates| {
            gates
                .iter()
                .filter_map(|gate| serde_json::from_value::<Gate>(gate.clone()).ok())
                .collect()
        })
        .unwrap_or_default();
    Some(Capture { gates, summary })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_with(kind: u8, flags: u8, site: u32, callers: &[u32], a: &[u8], b: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; RECORD];
        out[0] = kind;
        out[1] = a.len() as u8;
        out[2] = b.len() as u8;
        out[3] = flags;
        out[4..8].copy_from_slice(&site.to_le_bytes());
        for (i, caller) in callers.iter().enumerate() {
            out[12 + 4 * i..16 + 4 * i].copy_from_slice(&caller.to_le_bytes());
        }
        let operands = 12 + 4 * CALLERS;
        out[operands..operands + a.len()].copy_from_slice(a);
        out[operands + OPMAX..operands + OPMAX + b.len()].copy_from_slice(b);
        out
    }

    fn record(kind: u8, flags: u8, site: u32, a: &[u8], b: &[u8]) -> Vec<u8> {
        record_with(kind, flags, site, &[], a, b)
    }

    fn log_bytes_of(version: u32, flags: u8, records: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.extend_from_slice(&version.to_le_bytes());
        out.extend_from_slice(&(records.len() as u32).to_le_bytes());
        out.extend_from_slice(&[flags, 0, 0, 0]);
        for r in records {
            out.extend_from_slice(r);
        }
        out
    }

    fn log_bytes(flags: u8, records: &[Vec<u8>]) -> Vec<u8> {
        log_bytes_of(VERSION, flags, records)
    }

    /// A buffer record carries the frames above its site; an evidence file
    /// written by a driver from before they were recorded still reads.
    #[test]
    fn records_carry_their_callers_and_older_records_still_parse() {
        let bytes = log_bytes(
            1,
            &[record_with(
                5,
                1,
                0x51a3c,
                &[0x1210, 0x1300, 0, 0],
                b"WIDG",
                b"WIDG",
            )],
        );
        let log = parse_log(&bytes).unwrap();
        assert_eq!(log.records[0].site, 0x51a3c);
        assert_eq!(log.records[0].callers, vec![0x1210, 0x1300, 0, 0]);
        assert_eq!(log.records[0].a, b"WIDG");

        let mut old = vec![0u8; RECORD_WITHOUT_CALLERS];
        old[0] = 7;
        old[1] = 6;
        old[2] = 6;
        old[3] = 1 | 8;
        old[4..8].copy_from_slice(&0x20u32.to_le_bytes());
        old[12..18].copy_from_slice(b"WIDGET");
        old[12 + OPMAX..18 + OPMAX].copy_from_slice(b"WIDGET");
        let log = parse_log(&log_bytes_of(VERSION_WITHOUT_CALLERS, 1, &[old])).unwrap();
        assert_eq!(log.records.len(), 1);
        assert_eq!(log.records[0].a, b"WIDGET");
        assert!(log.records[0].callers.is_empty());
        assert!(parse_log(&log_bytes_of(9, 1, &[])).is_err());
    }

    #[test]
    fn parses_driver_records_and_keeps_only_the_targets_own() {
        let bytes = log_bytes(
            1,
            &[
                // The harness's decoding, before it entered the target.
                record(1, 0, 0x10, &[4, 0, 0, 0], &[8, 0, 0, 0]),
                record(7, 1 | 8, 0x20, b"WIDGET", b"WIDGET"),
                record(1, 1 | 2, 0x30, &[0x42], &[0x41]),
                // A heap pointer compare.
                record(
                    1,
                    1,
                    0x40,
                    &0x5020_0000_0010u64.to_le_bytes(),
                    &0u64.to_le_bytes(),
                ),
            ],
        );
        let log = parse_log(&bytes).unwrap();
        assert!(log.target_entered && !log.truncated);
        assert_eq!(log.records.len(), 4);
        let own = log.target_records();
        assert_eq!(own.len(), 2, "{own:?}");
        assert_eq!(own[0].kind, CmpKind::Strcmp);
        assert!(own[0].equal && !own[0].a_const);
        assert!(own[1].a_const);
        assert_eq!(
            parse_log(b"nope").unwrap_err(),
            "the evidence file has no driver header"
        );
        // The target was entered but compared nothing: the harness's records
        // are not the target's.
        let decoding_only = log_bytes(
            1,
            &[
                record(1, 0, 0x10, &[4, 0, 0, 0], &[8, 0, 0, 0]),
                record(1, 2, 0x30, &[0x25], &[0x41]),
            ],
        );
        assert!(parse_log(&decoding_only)
            .unwrap()
            .target_records()
            .is_empty());
        // A harness that never marks entry: every record counts.
        let unmarked = log_bytes(0, &[record(1, 0, 0x10, &[4, 0, 0, 0], &[8, 0, 0, 0])]);
        assert_eq!(parse_log(&unmarked).unwrap().target_records().len(), 1);
    }

    #[test]
    fn a_reason_without_evidence_says_what_was_not_searched() {
        let search = |state, searched| DerivedSearch { state, searched };
        let done = no_gate_reason(4, 8, false, search(SearchState::Done, 8));
        assert_eq!(
            done,
            "4 comparison(s) recorded; no operand followed a change of the input bytes"
        );
        let long = no_gate_reason(4, 2 << 20, false, search(SearchState::TooLong, 0));
        assert!(
            long.contains(
                "searched only in inputs of up to 1048576 bytes, and this one has 2097152"
            ),
            "{long}"
        );
        let partial = no_gate_reason(4, 80, true, search(SearchState::Partial, 24));
        assert!(
            partial.contains("replay budget ran out after 24 of 80 bytes were searched"),
            "{partial}"
        );
        assert!(
            partial.contains("keeps the first 8192 comparisons"),
            "{partial}"
        );
    }

    /// A capture recorded before the search state was kept had no
    /// computed-operand search past 32 bytes, and says so.
    #[test]
    fn an_older_capture_of_a_long_input_reports_an_unsearched_input() {
        let summary =
            |input_len: usize, state: Option<&str>, searched: Option<usize>| CaptureSummary {
                input: "testcase.bin".to_owned(),
                input_len,
                status: "recorded".to_owned(),
                reason: None,
                comparisons: 3,
                truncated: false,
                unconfirmed: 0,
                runs: 4,
                shim_armed: false,
                runner: None,
                derived_search: state.map(str::to_owned),
                searched_bytes: searched,
            };
        assert_eq!(
            summary(64, None, None).incomplete_derived_search(),
            Some(("too_long", 0))
        );
        assert_eq!(summary(16, None, None).incomplete_derived_search(), None);
        assert_eq!(
            summary(64, Some("done"), Some(64)).incomplete_derived_search(),
            None
        );
        assert_eq!(
            summary(64, Some("partial"), Some(20)).incomplete_derived_search(),
            Some(("partial", 20))
        );
    }

    #[test]
    fn operands_that_differ_between_identical_runs_are_unstable() {
        let a = |value: u8| (vec![value, 0, 0, 0], vec![1, 0, 0, 0]);
        let mut first = OperandsBySite::new();
        first.insert((0x10, CmpKind::Int), vec![a(7)]);
        first.insert((0x20, CmpKind::Int), vec![a(9)]);
        first.insert((0x30, CmpKind::Int), vec![a(3)]);
        let mut second = first.clone();
        second.insert((0x10, CmpKind::Int), vec![a(8)]);
        second.insert((0x30, CmpKind::Int), vec![a(3), a(3)]);
        let unstable = unstable_operands(&first, &second);
        assert!(unstable.contains(&(0x10, CmpKind::Int, Side::A)));
        assert!(!unstable.contains(&(0x10, CmpKind::Int, Side::B)));
        assert!(!unstable.contains(&(0x20, CmpKind::Int, Side::A)));
        // A site that ran a different number of times is unstable on both sides.
        assert!(unstable.contains(&(0x30, CmpKind::Int, Side::A)));
        assert!(unstable.contains(&(0x30, CmpKind::Int, Side::B)));
    }

    #[test]
    fn integer_operands_are_looked_up_in_both_byte_orders_and_narrowed() {
        let r = CmpRecord {
            kind: CmpKind::Int,
            a: vec![0x5a, 0x4d, 0, 0],
            b: vec![0x4d, 0x5a, 0, 0],
            a_const: false,
            b_const: true,
            equal: false,
            in_target: true,
            site: 1,
            callers: Vec::new(),
            unattributable: false,
        };
        let found = patterns(&r, Side::A);
        assert!(found.contains(&(Order::Same, vec![0x5a, 0x4d, 0, 0])));
        assert!(found.contains(&(Order::Reversed, vec![0, 0, 0x4d, 0x5a])));
        assert!(found.contains(&(Order::Same, vec![0x5a, 0x4d])));
        assert!(found.contains(&(Order::Reversed, vec![0x4d, 0x5a])));
        // A sign-extended byte narrows to that byte.
        let negative = CmpRecord {
            a: vec![0xfb, 0xff, 0xff, 0xff],
            ..r.clone()
        };
        assert!(patterns(&negative, Side::A).contains(&(Order::Same, vec![0xfb])));
        // A string operand is cut to the shorter string.
        let string = CmpRecord {
            kind: CmpKind::Strcmp,
            a: b"WIDGETS-AND-MORE".to_vec(),
            b: b"WIDGET".to_vec(),
            ..r
        };
        assert_eq!(
            patterns(&string, Side::A),
            vec![(Order::Same, b"WIDGET".to_vec())]
        );
    }

    #[test]
    fn occurrences_are_capped_but_counted() {
        let (found, total) = occurrences(b"abab_ab", b"ab", 2);
        assert_eq!(found, vec![0, 2]);
        assert_eq!(total, 3);
        assert_eq!(occurrences(b"", b"a", 4), (Vec::new(), 0));
    }

    #[test]
    fn runs_merge_contiguous_offsets() {
        let offsets: BTreeSet<usize> = [4, 5, 6, 7, 9].into_iter().collect();
        assert_eq!(runs(&offsets), vec![(4, 4), (9, 1)]);
    }

    #[test]
    fn a_recorded_capture_round_trips_through_finding_json() {
        let capture = Capture {
            gates: vec![Gate {
                offset: 0,
                len: 6,
                operand_hex: hex(b"WIDGET"),
                compared_with_hex: hex(b"WIDGET"),
                cmp_kind: "strcmp".to_owned(),
                site: "0x20".to_owned(),
                location: None,
                relation: "equal".to_owned(),
                operands_equal: true,
                site_unattributable: true,
            }],
            summary: CaptureSummary {
                input: "min_testcase.bin".to_owned(),
                input_len: 6,
                status: "recorded".to_owned(),
                reason: None,
                comparisons: 3,
                truncated: false,
                unconfirmed: 0,
                runs: 2,
                shim_armed: false,
                runner: Some("qemu-aarch64".to_owned()),
                derived_search: Some("done".to_owned()),
                searched_bytes: Some(6),
            },
        };
        let (gates, summary) = record_fields(&capture);
        let raw = json!({"gates": gates, "gate_capture": summary});
        assert_eq!(recorded(&raw), Some(capture));
        assert!(recorded(&json!({})).is_none());
    }

    /// A capture run under the harness's emulator gets `abort_on_error=0`
    /// and no core dumps (a guest abort makes qemu-user dump its own address
    /// space); a native run keeps `abort_on_error=1`.
    #[cfg(unix)]
    #[test]
    fn an_emulated_capture_run_neither_aborts_nor_dumps_core() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let executable = |path: &Path, body: &str| {
            std::fs::write(path, body).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        let seen = dir.path().join("seen.txt");
        let report = format!(
            "{{\n  printf 'asan=%s\\n' \"$ASAN_OPTIONS\"\n  printf 'ubsan=%s\\n' \"$UBSAN_OPTIONS\"\n  printf 'core=%s\\n' \"$(ulimit -H -c)\"\n}} > '{}'\n",
            seen.display()
        );
        let harness = dir.path().join("main");
        executable(&harness, &format!("#!/bin/sh\n{report}exit 0\n"));
        let emulator = dir.path().join("emulator.sh");
        executable(&emulator, "#!/bin/sh\nexec \"$@\"\n");
        let raw = json!({});
        let replay = Replay {
            harness: &harness,
            raw: &raw,
            scratch: dir.path().join("scratch"),
            runtrace_log: None,
            deadline: Instant::now() + Duration::from_secs(30),
        };
        std::fs::create_dir_all(&replay.scratch).unwrap();
        let options = |runner: &mut Runner| -> BTreeMap<String, String> {
            let _ = std::fs::remove_file(&seen);
            // The harness records no evidence; the run itself is what counts.
            assert!(runner.run(b"x", false).is_err());
            std::fs::read_to_string(&seen)
                .unwrap()
                .lines()
                .filter_map(|line| line.split_once('='))
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
                .collect()
        };
        let last = |options: &str| -> Option<String> {
            options
                .rsplit(':')
                .find_map(|item| item.strip_prefix("abort_on_error="))
                .map(str::to_owned)
        };

        let native = options(&mut Runner::new(&replay, None));
        assert_eq!(last(&native["asan"]).as_deref(), Some("1"), "{native:?}");

        record_runner(
            dir.path(),
            Some(&HarnessRunner {
                program: emulator.clone(),
                args: Vec::new(),
            }),
        )
        .unwrap();
        let emulated = options(&mut Runner::new(&replay, None));
        assert_eq!(
            last(&emulated["asan"]).as_deref(),
            Some("0"),
            "{emulated:?}"
        );
        assert_eq!(
            last(&emulated["ubsan"]).as_deref(),
            Some("0"),
            "{emulated:?}"
        );
        assert_eq!(emulated["core"], "0", "{emulated:?}");
    }
}

/// End to end through bhf's real driver: AddressSanitizer harnesses built
/// the way bhf builds them (trace-cmp coverage, the driver uninstrumented).
#[cfg(all(test, target_os = "linux"))]
pub(crate) mod harness_tests {
    use super::*;
    use std::process::Command;

    const TARGET: &str = r#"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
extern void bhf_target_enter(void);
/* Not constants, so the compiler keeps the library calls. */
volatile size_t tag_len = 5;
volatile size_t field_len = 4;
volatile size_t name_len = 6;
volatile size_t check_len = 2;
__attribute__((noinline)) int parse_record(const char *s, const uint8_t *raw, size_t n) {
    if (getenv("WIDGET_MODE")) return 0;
    if (strcmp(s, "WIDGET") == 0) {
        volatile char *p = malloc(2);
        p[3] = 1;
        free((void *)p);
        return 1;
    }
    if (n >= 13 && memcmp(raw + 8, "WXYZQ", tag_len) == 0) {
        volatile char *p = malloc(2);
        p[4] = 1;
        free((void *)p);
        return 2;
    }
    return 0;
}
__attribute__((noinline)) int copy_at(uint32_t width) {
    if (width == 0 || width > 32) return 0;
    volatile char *p = malloc(4);
    p[width] = 1;
    free((void *)p);
    return 1;
}
/* Compares only values the input does not decide: the process id and a
 * clock reading, which differ from run to run. */
__attribute__((noinline)) int check_host(void) {
    volatile int pid = getpid();
    if (pid == 1) return 0;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    volatile long nanos = ts.tv_nsec;
    if ((nanos & 0xffff) == 0x1234) return 0;
    return 1;
}
/* Reads input bytes but compares nothing. */
__attribute__((noinline)) int mix(const uint8_t *raw, const char *s) {
    (void)s;
    return raw[1] * 3 + raw[2];
}
__attribute__((noinline)) int check_name(const uint8_t *raw, const char *s) {
    (void)raw;
    return strncmp(s + 1, "WIDGET", name_len) == 0;
}
/* A header whose 4-byte field at offset 40 is range-checked (`width == 0 ||
 * width > 32` compiles to one compare of `width - 1`). */
__attribute__((noinline)) int parse_wide(const uint8_t *p, size_t n) {
    uint32_t width;
    if (n < 64) return 0;
    if (p[0] != 'H' || p[1] != 'D') return 0;
    memcpy(&width, p + 40, 4);
    return copy_at(width);
}
/* Six fields, each checked by its own memcmp. */
__attribute__((noinline)) int parse_header(const uint8_t *p) {
    if (memcmp(p, "HDR1", field_len)) return 0;
    if (memcmp(p + 4, "VER2", field_len)) return 1;
    if (memcmp(p + 8, "TYP3", field_len)) return 2;
    if (memcmp(p + 12, "LEN4", field_len)) return 3;
    if (memcmp(p + 16, "CRC5", field_len)) return 4;
    if (memcmp(p + 20, "END6", field_len)) return 5;
    return 6;
}
int bhf_run_one(const uint8_t *data, size_t size) {
    /* The harness's own decoding: a NUL-terminated copy of the input and a
     * 4-byte field. Its comparisons are not the target's. */
    char *s = malloc(size + 1);
    memcpy(s, data, size);
    s[size] = 0;
    int r;
    if (size >= 3 && (data[0] == '!' || data[0] == '%')) {
        /* More decoding: neutralise every '%' after the first byte. The
         * target is chosen before entry, so the harness compares nothing
         * after it. */
        int (*target)(const uint8_t *, const char *) = data[0] == '!' ? mix : check_name;
        for (size_t i = 1; i < size; i++)
            if (s[i] == '%') s[i] = ' ';
        bhf_target_enter();
        r = target(data, s);
    } else if (size >= 3 && data[0] == '?') {
        bhf_target_enter();
        r = mix(data, s);
        /* The harness checks an input byte after the call: its own
         * comparison, not the target's. */
        if (data[1] == 'Q') r = 0;
    } else if (size >= 4 && data[0] == '^') {
        bhf_target_enter();
        r = mix(data, s);
        /* The harness's own memcmp of input bytes after the call. */
        if (memcmp(data + 1, "QQ", check_len) == 0) r = 0;
    } else if (size >= 1 && data[0] == '$') {
        bhf_target_enter();
        r = check_host();
    } else if (size >= 25 && data[0] == '&') {
        bhf_target_enter();
        r = parse_header(data + 1);
    } else if (size >= 64 && data[0] == 'H') {
        bhf_target_enter();
        r = parse_wide(data, size);
    } else {
        uint32_t width = 0;
        int ranged = size >= 8 && data[0] == '#';
        if (ranged) memcpy(&width, data + 4, 4);
        bhf_target_enter();
        r = ranged ? copy_at(width) : parse_record(s + 2, data, size);
    }
    free(s);
    return r;
}
"#;

    fn clang() -> bool {
        Command::new("clang")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    }

    /// Build the target and bhf's driver into an ASan harness in `dir`.
    fn build(dir: &Path) -> Option<PathBuf> {
        build_target(dir, TARGET)
    }

    /// Build `source` and bhf's driver into an ASan harness in `dir`.
    fn build_target(dir: &Path, source: &str) -> Option<PathBuf> {
        let driver = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime/bhf_driver.c");
        std::fs::write(dir.join("target.c"), source).unwrap();
        let run = |args: &[&str]| {
            Command::new("clang")
                .current_dir(dir)
                .args(args)
                .output()
                .is_ok_and(|o| o.status.success())
        };
        // The generated Makefile's sanitizer set.
        let ok = run(&[
            "-O1",
            "-g",
            "-fsanitize=address,undefined",
            "-fno-sanitize=function,vptr,alignment",
            "-fsanitize-coverage=trace-pc-guard,trace-cmp",
            "-c",
            "target.c",
            "-o",
            "target.o",
        ]) && run(&[
            "-O1",
            "-g",
            "-c",
            driver.to_str().unwrap(),
            "-o",
            "driver.o",
        ]) && run(&[
            "-fsanitize=address,undefined",
            "target.o",
            "driver.o",
            "-o",
            "main",
        ]);
        ok.then(|| dir.join("main"))
    }

    /// The runtrace shim this checkout built, if it was built.
    fn built_shim() -> Option<PathBuf> {
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"));
        ["debug", "release"]
            .into_iter()
            .map(|profile| target.join(profile).join("libbhf_runtrace_shim.so"))
            .find(|path| path.is_file())
    }

    fn capture_for(harness: &Path, scratch: &Path, input: &[u8]) -> Capture {
        capture_limited(harness, scratch, input, Limits::default())
    }

    fn capture_limited(harness: &Path, scratch: &Path, input: &[u8], limits: Limits) -> Capture {
        let raw = json!({});
        let replay = Replay {
            harness,
            raw: &raw,
            scratch: scratch.join("capture"),
            runtrace_log: None,
            deadline: Instant::now() + Duration::from_secs(60),
        };
        capture_with(&replay, input, "testcase.bin", find_symbolizer(), limits)
    }

    /// The 1-based line of `TARGET` holding `needle`.
    fn target_line(needle: &str) -> u64 {
        TARGET
            .lines()
            .position(|line| line.contains(needle))
            .map(|index| index as u64 + 1)
            .unwrap_or_else(|| panic!("{needle} is not in the target"))
    }

    /// As [`capture_for`], with no symbolizer: nothing can tell harness code
    /// from target code by its source position.
    fn capture_unsymbolized(harness: &Path, scratch: &Path, input: &[u8]) -> Capture {
        let raw = json!({});
        let replay = Replay {
            harness,
            raw: &raw,
            scratch: scratch.join("capture-unsymbolized"),
            runtrace_log: None,
            deadline: Instant::now() + Duration::from_secs(60),
        };
        capture_with(&replay, input, "testcase.bin", None, Limits::default())
    }

    /// An AddressSanitizer harness with bhf's driver whose target compares
    /// input bytes 2.. with `strcmp(s, "WIDGET")`, or `None` without clang.
    pub(crate) fn harness() -> Option<(tempfile::TempDir, PathBuf)> {
        if !clang() {
            eprintln!("skipping: clang not installed");
            return None;
        }
        let dir = tempfile::tempdir().unwrap();
        let Some(main) = build(dir.path()) else {
            eprintln!("skipping: clang cannot build an AddressSanitizer harness here");
            return None;
        };
        Some((dir, main))
    }

    #[test]
    fn a_strcmp_gate_is_recorded_at_its_input_offset() {
        let Some((dir, main)) = harness() else {
            return;
        };
        assert!(harness_records_evidence(&main));
        let capture = capture_for(&main, dir.path(), b"\x05\x00WIDGET");
        assert_eq!(capture.summary.status, "recorded", "{capture:?}");
        let gate = capture
            .gates
            .iter()
            .find(|g| g.cmp_kind == "strcmp")
            .unwrap_or_else(|| panic!("no strcmp evidence: {capture:?}"));
        assert_eq!((gate.offset, gate.len), (2, 6), "{gate:?}");
        assert_eq!(gate.operand_hex, hex(b"WIDGET"));
        assert_eq!(gate.compared_with_hex, hex(b"WIDGET"));
        assert!(gate.operands_equal);
        assert_eq!(gate.relation, "equal");
        if find_symbolizer().is_some() {
            let location = gate.location.as_ref().expect("symbolized site");
            assert_eq!(
                location.function.as_deref(),
                Some("parse_record"),
                "{location:?}"
            );
            assert!(location.file.ends_with("target.c"), "{location:?}");
        }
        // The harness's own decoding compared input bytes too ('#' at byte
        // 0); it ran before the target and is not evidence.
        assert!(
            capture.gates.iter().all(|g| g.offset >= 2),
            "{:?}",
            capture.gates
        );
    }

    /// A harness cross-built for another architecture, the way a cross sweep
    /// builds it (GCC `trace-pc,trace-cmp`, no sanitizer runtime, the
    /// comparison wrappers linked in), is replayed under the emulator recorded
    /// beside it, and its `strcmp` gate is recorded and symbolized.
    #[test]
    fn a_cross_built_harness_records_its_strcmp_gate_under_its_emulator() {
        let driver = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime/bhf_driver.c");
        let lanes = [
            (
                "aarch64-linux-gnu-gcc",
                "qemu-aarch64",
                "/usr/aarch64-linux-gnu",
            ),
            (
                "arm-linux-gnueabihf-gcc",
                "qemu-arm",
                "/usr/arm-linux-gnueabihf",
            ),
        ];
        for (cc, emulator, sysroot) in lanes {
            if which::which(cc).is_err()
                || which::which(emulator).is_err()
                || !Path::new(sysroot).is_dir()
            {
                eprintln!("skipping: {cc}/{emulator}/{sysroot} not installed");
                continue;
            }
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join("target.c"), TARGET).unwrap();
            let run = |args: &[&str]| {
                let output = Command::new(cc)
                    .current_dir(dir.path())
                    .args(args)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{cc} {args:?}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            };
            run(&[
                "-O1",
                "-g",
                "-fsanitize-coverage=trace-pc,trace-cmp",
                "-c",
                "target.c",
                "-o",
                "target.o",
            ]);
            run(&[
                "-O1",
                "-g",
                "-c",
                driver.to_str().unwrap(),
                "-o",
                "driver.o",
            ]);
            run(&[
                COMPARISON_WRAP_LDFLAGS,
                "target.o",
                "driver.o",
                "-o",
                "main",
            ]);
            let main = dir.path().join("main");
            let runner = HarnessRunner {
                program: PathBuf::from(emulator),
                args: vec!["-L".to_owned(), sysroot.to_owned()],
            };
            record_runner(dir.path(), Some(&runner)).unwrap();
            assert_eq!(recorded_runner(&main), Some(runner));

            let capture = capture_for(&main, dir.path(), b"\x05\x00WIDGET");
            assert_eq!(capture.summary.status, "recorded", "{cc}: {capture:?}");
            assert_eq!(capture.summary.runner.as_deref(), Some(emulator));
            assert!(!capture.summary.shim_armed, "no host shim in a guest");
            let gate = capture
                .gates
                .iter()
                .find(|g| g.cmp_kind == "strcmp")
                .unwrap_or_else(|| panic!("{cc}: no strcmp evidence: {capture:?}"));
            assert_eq!((gate.offset, gate.len), (2, 6), "{cc}: {gate:?}");
            assert_eq!(gate.operand_hex, hex(b"WIDGET"));
            assert!(gate.operands_equal);
            if find_symbolizer().is_some() {
                let location = gate.location.as_ref().expect("symbolized site");
                assert_eq!(location.function.as_deref(), Some("parse_record"), "{cc}");
            }

            // Forgetting the runner leaves a native harness alone.
            record_runner(dir.path(), None).unwrap();
            assert_eq!(recorded_runner(&main), None);
            record_runner(dir.path(), None).unwrap();
        }
    }

    #[test]
    fn a_memcmp_gate_compiled_to_bcmp_is_recorded_at_its_input_offset() {
        let Some((dir, main)) = harness() else {
            return;
        };
        let capture = capture_for(&main, dir.path(), b"\x05\x00nopeABWXYZQ");
        let gate = capture
            .gates
            .iter()
            .find(|g| g.cmp_kind == "memcmp")
            .unwrap_or_else(|| panic!("no memcmp evidence: {capture:?}"));
        assert_eq!((gate.offset, gate.len), (8, 5), "{gate:?}");
        assert_eq!(gate.operand_hex, hex(b"WXYZQ"));
        assert!(gate.operands_equal);
        // AddressSanitizer reports the interceptor as the site; the frame
        // that called it is the target's memcmp call.
        if find_symbolizer().is_some() {
            let location = gate
                .location
                .as_ref()
                .unwrap_or_else(|| panic!("the call site is named: {gate:?}"));
            assert_eq!(location.function.as_deref(), Some("parse_record"));
            assert!(location.file.ends_with("target.c"), "{location:?}");
            assert_eq!(
                location.line,
                Some(target_line("memcmp(raw + 8, \"WXYZQ\"")),
                "{location:?}"
            );
            assert!(!gate.site_unattributable, "{gate:?}");
        }
    }

    /// A range check on bytes 40..44 of a 64-byte input is found by the
    /// range search, alongside the header bytes it is checked after, and the
    /// search says it covered the whole input.
    #[test]
    fn a_range_check_in_a_long_input_is_found_with_the_other_gates() {
        let Some((dir, main)) = harness() else {
            return;
        };
        let mut input = b"HD".to_vec();
        input.resize(40, b'.');
        input.extend_from_slice(&[0x0f, 0, 0, 0]);
        input.resize(64, b'.');
        let capture = capture_for(&main, dir.path(), &input);
        assert_eq!(capture.summary.status, "recorded", "{capture:?}");
        // (Byte 0 also selects the target in this harness, so a change of it
        // never reaches the target's own check of it.)
        assert!(
            capture
                .gates
                .iter()
                .any(|g| g.offset == 1 && g.relation == "equal"),
            "the header byte is evidence: {:?}",
            capture.gates
        );
        let range = capture
            .gates
            .iter()
            .find(|g| g.relation == "derived" && g.offset == 40)
            .unwrap_or_else(|| panic!("the range check on bytes 40.. is found: {capture:?}"));
        assert!(range.offset + range.len <= 44, "{range:?}");
        assert_eq!(capture.summary.derived_search.as_deref(), Some("done"));
        assert_eq!(capture.summary.searched_bytes, Some(64));
        assert!(capture.summary.incomplete_derived_search().is_none());
    }

    /// A range search that runs out of replays says how far it got.
    #[test]
    fn a_range_search_cut_short_by_its_budget_is_partial() {
        let Some((dir, main)) = harness() else {
            return;
        };
        let mut input = b"HD".to_vec();
        input.resize(40, b'.');
        input.extend_from_slice(&[0x0f, 0, 0, 0]);
        input.resize(64, b'.');
        let capture = capture_limited(&main, dir.path(), &input, Limits { derived_runs: 3 });
        assert_eq!(
            capture.summary.derived_search.as_deref(),
            Some("partial"),
            "{capture:?}"
        );
        let searched = capture.summary.searched_bytes.expect("searched bytes");
        assert!(searched < 64, "{capture:?}");
        assert_eq!(
            capture.summary.incomplete_derived_search(),
            Some(("partial", searched))
        );
    }

    /// A large seed-like input holds every single-byte value many times over;
    /// none of that is evidence. Only the comparison that read input bytes
    /// is reported.
    #[test]
    fn coincidental_bytes_of_a_large_input_are_not_reported() {
        let Some((dir, main)) = harness() else {
            return;
        };
        let mut input = b"\x05\x00WIDGET\x00".to_vec();
        let mut state = 0x2545_f491_u32;
        for _ in 0..40_000 {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            input.push(match (state >> 16) % 5 {
                0 => 0,
                1 => b'0',
                2 => b'1',
                3 => 1,
                _ => (state >> 24) as u8,
            });
        }
        let capture = capture_for(&main, dir.path(), &input);
        assert!(!capture.gates.is_empty(), "{capture:?}");
        for gate in &capture.gates {
            assert!(
                gate.offset >= 2 && gate.offset + gate.len <= 8,
                "only the strcmp operand at bytes 2..8 is evidence: {gate:?}"
            );
        }
    }

    /// A folded range check (`width == 0 || width > 32` compiles to one
    /// compare of `width - 1`) has no operand equal to input bytes; flipping
    /// each byte of a short input finds the bytes that feed it.
    #[test]
    fn a_range_check_operand_is_traced_to_the_bytes_it_is_computed_from() {
        let Some((dir, main)) = harness() else {
            return;
        };
        let capture = capture_for(&main, dir.path(), b"#...\x0f\x00\x00\x00");
        let derived: Vec<&Gate> = capture
            .gates
            .iter()
            .filter(|g| g.relation == "derived" || g.relation == "equal")
            .filter(|g| g.offset >= 4)
            .collect();
        assert!(
            derived.iter().any(|g| g.offset == 4),
            "byte 4 (the low byte of width) feeds the range check: {capture:?}"
        );
        assert!(capture.summary.runs > 1, "{capture:?}");
    }

    /// Without `BHF_CMP_EVIDENCE` the driver records nothing, so a fuzz
    /// campaign pays nothing for it; and an empty input says why it has none.
    #[test]
    fn evidence_is_recorded_only_on_request_and_an_empty_input_says_so() {
        let Some((dir, main)) = harness() else {
            return;
        };
        let input = dir.path().join("in.bin");
        std::fs::write(&input, b"\x05\x00WIDGEX").unwrap();
        let evidence = dir.path().join("evidence.bin");
        let status = Command::new(&main).arg(&input).status().unwrap();
        assert!(status.success());
        assert!(!evidence.exists());
        let capture = capture_for(&main, dir.path(), b"");
        assert!(capture.gates.is_empty());
        assert!(
            capture
                .summary
                .reason
                .as_deref()
                .is_some_and(|r| r.contains("empty")),
            "{capture:?}"
        );
    }

    /// A comparison of values that differ between identical runs (a process
    /// id, a clock reading) changes on every replay whatever byte changed;
    /// it is not computed from the input and is not evidence.
    #[test]
    fn a_comparison_that_varies_between_identical_runs_is_not_evidence() {
        let Some((dir, main)) = harness() else {
            return;
        };
        let capture = capture_for(&main, dir.path(), b"$abcdefg");
        assert!(capture.summary.comparisons > 0, "{capture:?}");
        assert!(capture.gates.is_empty(), "{:?}", capture.gates);
        assert_eq!(
            capture.summary.status, "no_input_comparisons",
            "{capture:?}"
        );
    }

    /// A target that compares nothing: the harness's own decoding compared
    /// every input byte before entering it, and none of that is the
    /// target's, with or without a symbolizer to name the harness code.
    #[test]
    fn a_target_without_comparisons_has_none_whatever_the_harness_compared() {
        let Some((dir, main)) = harness() else {
            return;
        };
        for capture in [
            capture_for(&main, dir.path(), b"!abc%efg"),
            capture_unsymbolized(&main, dir.path(), b"!abc%efg"),
        ] {
            assert!(capture.gates.is_empty(), "{:?}", capture.gates);
            assert_eq!(capture.summary.status, "no_comparisons", "{capture:?}");
            assert_eq!(capture.summary.comparisons, 0, "{capture:?}");
            let reason = capture.summary.reason.as_deref().unwrap_or_default();
            assert!(
                reason.contains("no instrumented comparison was recorded in the target"),
                "{reason}"
            );
        }
    }

    /// A comparison the harness makes after entering the target (checking
    /// an input byte after the call) is harness code, located as such, and
    /// neither evidence nor counted as the target's.
    #[test]
    fn a_harness_comparison_after_target_entry_is_not_the_targets() {
        let Some((dir, main)) = harness() else {
            return;
        };
        if find_symbolizer().is_none() {
            eprintln!("skipping: no llvm-symbolizer to locate harness code");
            return;
        }
        let capture = capture_for(&main, dir.path(), b"?Qcdefgh");
        assert!(capture.gates.is_empty(), "{:?}", capture.gates);
        assert_eq!(capture.summary.status, "no_comparisons", "{capture:?}");
        assert_eq!(capture.summary.comparisons, 0, "{capture:?}");
    }

    /// A `memcmp` the harness makes after entering the target is placed at
    /// its call in harness code, not at the sanitizer's interceptor, and so is
    /// left out like any harness comparison.
    #[test]
    fn a_harness_memcmp_after_target_entry_is_not_the_targets() {
        let Some((dir, main)) = harness() else {
            return;
        };
        if find_symbolizer().is_none() {
            eprintln!("skipping: no llvm-symbolizer to locate harness code");
            return;
        }
        let capture = capture_for(&main, dir.path(), b"^QQdefgh");
        assert!(
            capture.gates.iter().all(|g| g.cmp_kind != "memcmp"),
            "{:?}",
            capture.gates
        );
        assert_eq!(capture.summary.comparisons, 0, "{capture:?}");
    }

    /// The harness decodes a large input with a comparison per byte before
    /// it enters the target; those records must not use up the driver's
    /// capacity before the target's own comparison is recorded.
    #[test]
    fn harness_decoding_before_the_target_does_not_crowd_out_its_comparisons() {
        let Some((dir, main)) = harness() else {
            return;
        };
        let mut input = b"%WIDGET".to_vec();
        input.extend(std::iter::repeat_n(b'x', 9000));
        for capture in [
            capture_for(&main, dir.path(), &input),
            capture_unsymbolized(&main, dir.path(), &input),
        ] {
            assert!(!capture.summary.truncated, "{capture:?}");
            let gate = capture
                .gates
                .iter()
                .find(|g| g.cmp_kind == "strncmp")
                .unwrap_or_else(|| panic!("no strncmp evidence: {capture:?}"));
            assert_eq!((gate.offset, gate.len), (1, 6), "{gate:?}");
            assert!(gate.operands_equal, "{gate:?}");
            assert!(
                capture
                    .gates
                    .iter()
                    .all(|g| g.cmp_kind == "strncmp" || g.offset >= 1),
                "{:?}",
                capture.gates
            );
        }
    }

    /// Under AddressSanitizer every memcmp reports the interceptor as its
    /// call site, so six field checks share one site; each field is still
    /// confirmed on its own.
    #[test]
    fn every_field_checked_by_memcmp_is_confirmed() {
        let Some((dir, main)) = harness() else {
            return;
        };
        let mut input = b"&HDR1VER2TYP3LEN4CRC5END6".to_vec();
        input.extend_from_slice(b"................");
        let capture = capture_for(&main, dir.path(), &input);
        let mut offsets: Vec<usize> = capture
            .gates
            .iter()
            .filter(|g| g.cmp_kind == "memcmp" && g.relation == "equal")
            .map(|g| g.offset)
            .collect();
        offsets.sort_unstable();
        offsets.dedup();
        assert_eq!(offsets, vec![1, 5, 9, 13, 17, 21], "{capture:?}");
    }

    /// Runtime cmplog (`BHF_CMPLOG=1`) for a sanitized harness: the sanitizer
    /// defines strcmp/bcmp in the executable, so the operands come from the
    /// driver's hooks, in the shim's record format the engine ingests.
    #[test]
    fn runtime_cmplog_records_sanitized_string_and_buffer_compares() {
        let Some((dir, main)) = harness() else {
            return;
        };
        let log = dir.path().join("runtrace.jsonl");
        for input in [&b"\x05\x00WIDGEX"[..], &b"\x05\x00nopeABWXYZR"[..]] {
            let path = dir.path().join("in.bin");
            std::fs::write(&path, input).unwrap();
            let status = Command::new(&main)
                .arg(&path)
                .env("BHF_CMPLOG", "1")
                .env("BHF_RUNTRACE_LOG", &log)
                .status()
                .unwrap();
            assert!(status.success());
        }
        let text = std::fs::read_to_string(&log).unwrap();
        // Each record names its site: the hook's pc and the frame above it.
        let site_of = |kind: &str, a: &[u8], b: &[u8]| -> String {
            let tail = format!("\",\"a\":\"{}\",\"b\":\"{}\"}}", hex(a), hex(b));
            let head = format!("{{\"e\":\"cmplog\",\"k\":\"{kind}\",\"s\":\"");
            let line = text
                .lines()
                .find(|line| line.starts_with(&head) && line.ends_with(&tail))
                .unwrap_or_else(|| panic!("no {kind} record of {a:?}: {text}"));
            line[head.len()..line.len() - tail.len()].to_owned()
        };
        let strcmp_site = site_of("strcmp", b"WIDGEX", b"WIDGET");
        let memcmp_site = site_of("memcmp", b"WXYZR", b"WXYZQ");
        for site in [&strcmp_site, &memcmp_site] {
            let (pc, caller) = site.split_once('.').expect("pc.caller");
            assert!(pc.len() == 8 && caller.len() == 8, "{site}");
        }
        // Under AddressSanitizer the memcmp hook's pc is the interceptor's;
        // the frame above it is the target's call.
        assert!(!memcmp_site.ends_with(".00000000"), "{memcmp_site}");
        // The runtrace shim's own name checks inside its getenv hook reach
        // the sanitizer's comparison hooks too; they are not recorded.
        if let Some(shim) = built_shim() {
            let shim_log = dir.path().join("shim-runtrace.jsonl");
            let path = dir.path().join("in.bin");
            std::fs::write(&path, b"\x05\x00WIDGEX").unwrap();
            let status = Command::new(&main)
                .arg(&path)
                .env("LD_PRELOAD", &shim)
                .env("ASAN_OPTIONS", "verify_asan_link_order=0:detect_leaks=0")
                .env("BHF_CMPLOG", "1")
                .env("BHF_RUNTRACE_LOG", &shim_log)
                .status()
                .unwrap();
            assert!(status.success());
            let text = std::fs::read_to_string(&shim_log).unwrap();
            assert!(text.contains("\"e\":\"getenv\""), "the shim ran: {text}");
            assert!(text.contains(&hex(b"WIDGEX")), "{text}");
            assert!(
                !text.contains(&format!("\"{}", hex(b"BHF_"))),
                "the shim's own compares are not the target's: {text}"
            );
        }
        let ingested = cmplog::ingest_from_jsonl_log(&log).expect("the engine reads it");
        let tokens = ingested.dictionary_tokens();
        assert!(tokens.contains(&b"WIDGET".to_vec()), "{tokens:?}");
        assert!(tokens.contains(&b"WXYZQ".to_vec()), "{tokens:?}");
    }

    /// A target that compares far more distinct operand pairs than the
    /// runtime cmplog cap holds, counting the driver's stack unwinds.
    const CMPLOG_FLOOD: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
static int unwinds;
/* Counts each unwind the driver asks for, then does it. */
int backtrace(void **frames, int size) {
    static int (*real)(void **, int);
    unwinds++;
    if (!real) real = (int (*)(void **, int))dlsym(RTLD_NEXT, "backtrace");
    return real ? real(frames, size) : 0;
}
/* Not a constant, so the compiler keeps the library call. */
volatile size_t key_len = 32;
static void token_of(int i, char *token) {
    int j;
    memset(token, '.', 32);
    for (j = 31; j >= 0 && i; j--, i /= 10) token[j] = (char)('0' + i % 10);
}
static int compare_tokens(int from, int to) {
    char key[32], token[32];
    int i, hits = 0;
    memset(key, 'k', sizeof key);
    for (i = from; i < to; i++) {
        token_of(i, token);
        hits += memcmp(token, key, key_len) == 0;
    }
    return hits;
}
int bhf_run_one(const uint8_t *data, size_t size) {
    int hits, filling;
    (void)data;
    (void)size;
    /* About 5400 records of this size fit under the cap. */
    hits = compare_tokens(0, 12000);
    filling = unwinds;
    hits += compare_tokens(12000, 13000);
    fprintf(stderr, "unwinds filling=%d after=%d\n", filling, unwinds - filling);
    return hits;
}
"#;

    /// Once the runtime cmplog file holds its cap, a new operand pair costs
    /// nothing: the driver does not unwind the stack for a record it cannot
    /// write (an unwind per comparison slows a persistent fuzz process down
    /// many times over).
    #[test]
    fn runtime_cmplog_stops_unwinding_once_its_cap_is_reached() {
        if !clang() {
            eprintln!("skipping: clang not installed");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let Some(main) = build_target(dir.path(), CMPLOG_FLOOD) else {
            eprintln!("skipping: clang cannot build an AddressSanitizer harness here");
            return;
        };
        let input = dir.path().join("in.bin");
        std::fs::write(&input, b"x").unwrap();
        let log = dir.path().join("runtrace.jsonl");
        let output = Command::new(&main)
            .arg(&input)
            .env("BHF_CMPLOG", "1")
            .env("BHF_RUNTRACE_LOG", &log)
            .env("ASAN_OPTIONS", "detect_leaks=0")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        let counts = stderr
            .lines()
            .find_map(|line| line.strip_prefix("unwinds "))
            .unwrap_or_else(|| panic!("the target reported no counts: {stderr}"));
        let count = |name: &str| -> u64 {
            counts
                .split(' ')
                .find_map(|field| field.strip_prefix(name)?.strip_prefix('='))
                .and_then(|value| value.parse().ok())
                .unwrap_or_else(|| panic!("no {name} count: {counts}"))
        };
        let size = std::fs::metadata(&log).unwrap().len();
        // The cap was reached, and the records under it named their callers.
        assert!(
            size > (1 << 20) - 256 && size <= 1 << 20,
            "cmplog size {size}"
        );
        assert!(count("filling") > 1000, "{counts}");
        assert_eq!(count("after"), 0, "unwinds after the cap: {counts}");
    }
}
