// SPDX-License-Identifier: Apache-2.0

//! What makes a reproduced crash the crash a finding recorded: its rule, its
//! kind, and where it happened. Where is the finding's sink (the top project
//! frame, chosen by the same selector the finding's `actionability.sink`
//! uses) or, for a report without frames (or a UBSan report), the site the
//! sanitizer printed (`file:line:col: runtime error:`), the identity the
//! finding signature uses for such reports.
//!
//! A fatal signal without a sanitizer report is also identified by its signal
//! and, when bhf's driver printed one, the faulting pc offset in the
//! executable, which only the recorded build can reproduce.
//!
//! A COBOL harness's crash is recorded as the libcob runtime error it printed
//! ([`crate::auto::cobol_oracle`]): its kind is `cobol-runtime-error`, its
//! site the COBOL source line libcob named (`cobol_source`), and it is still
//! identified by its signal. The callers give a replayed run the same
//! attribution ([`crate::replay::CRun::report_for`]) before comparing.
//!
//! `bhf replay`, `bhf report --backfill` and the fuzz loop's fresh-process
//! confirmation all compare through [`compare_with`], so a crash of the same
//! class at another site never counts as a reproduction. The [`Verdict`] also
//! says when nothing differed but where the crash happened could not be
//! checked: such a replay is not a reproduction either.

use corpus::SanitizerReport;
use serde::Serialize;
use serde_json::{json, Value};

/// How one compared field turned out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Outcome {
    Equal,
    /// Equal under the name an earlier bhf release gave the same report.
    Legacy,
    /// The same out-of-bounds access, reported by the other sanitizer: gcc's
    /// UBSan object-size check guards the access ASan reports, and fires
    /// first (an ASan rebuild, or bhf's re-run with that check off, reports
    /// the overflow; the gcc binary reports `insufficient-object-size`).
    SameAccess,
    Differs,
    /// The finding records nothing to compare this field with.
    NotRecorded,
    /// The replayed report has nothing to compare it with: no frame naming a
    /// function and no source position, as an unsymbolized report prints.
    NotComparable,
}

/// Why a field was [`Outcome::NotComparable`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NotCompared {
    /// The replay names no function or source position.
    Unlocated,
    /// The replay printed no pc offset.
    NoPcOffset,
    /// A pc offset is compared in the recorded build only; whether the
    /// harness is that build (`Some(false)`: its sha256 differs; `None`: no
    /// recorded sha256 to check it against).
    OtherBuild(Option<bool>),
}

impl NotCompared {
    fn describe(self) -> &'static str {
        match self {
            Self::Unlocated => "the replay names no function or source position",
            Self::NoPcOffset => "the replay printed no pc offset",
            Self::OtherBuild(Some(_)) => "the harness's sha256 differs from the recorded build",
            Self::OtherBuild(None) => "no build sha256 to check the harness against",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Check {
    pub(crate) field: &'static str,
    pub(crate) recorded: Option<String>,
    pub(crate) replayed: Option<String>,
    pub(crate) outcome: Outcome,
    /// Why a [`Outcome::NotComparable`] field was not compared.
    #[serde(skip)]
    pub(crate) why: Option<NotCompared>,
}

impl Check {
    fn describe(&self) -> String {
        let recorded = self.recorded.as_deref().unwrap_or("(not recorded)");
        let replayed = self.replayed.as_deref().unwrap_or("(none)");
        match self.outcome {
            Outcome::Equal => format!("{} {recorded}", self.field),
            Outcome::Legacy => format!("{} {recorded} (earlier name of {replayed})", self.field),
            Outcome::SameAccess => format!(
                "{} {recorded} (the same out-of-bounds access as {replayed}, which gcc's \
                 object-size check reports first)",
                self.field
            ),
            Outcome::Differs => format!("{}: recorded {recorded}, replayed {replayed}", self.field),
            Outcome::NotRecorded => format!("{} not recorded", self.field),
            Outcome::NotComparable => format!(
                "{} not compared (recorded {recorded}; {})",
                self.field,
                self.why.unwrap_or(NotCompared::Unlocated).describe()
            ),
        }
    }
}

/// What a comparison concludes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Verdict {
    /// The recorded crash, at the recorded place.
    Match,
    /// A compared field differs.
    Mismatch,
    /// Nothing differs, but where the crash happened was not compared: the
    /// replay names no location, or the finding records none (or only a pc
    /// offset) and the harness is not the recorded build.
    Unverified,
}

impl Verdict {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Match => "match",
            Self::Mismatch => "mismatch",
            Self::Unverified => "unverified",
        }
    }
}

/// The fields that say where a crash happened.
const LOCATION_FIELDS: [&str; 3] = ["sink", "site", "pc"];

/// The field-by-field comparison of a replayed report with a recorded finding.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct Comparison {
    pub(crate) checks: Vec<Check>,
    /// Whether the binary that ran is the one the finding was recorded with
    /// (its sha256 is `build.binary.sha256`); `None` when that is unknown.
    #[serde(skip)]
    pub(crate) same_binary: Option<bool>,
}

impl Comparison {
    /// What the comparison concludes: a [`Verdict::Mismatch`] when a field
    /// differs; [`Verdict::Unverified`] when nothing differs but a location
    /// field was not comparable, or when the finding records no location and
    /// the harness is not shown to be the recorded build; else a match.
    pub(crate) fn verdict(&self) -> Verdict {
        if self.differences().next().is_some() {
            Verdict::Mismatch
        } else if self.location_not_compared() || self.location_unverified() {
            Verdict::Unverified
        } else {
            Verdict::Match
        }
    }

    /// The finding records no crash location to compare, and the harness is
    /// not known to be the binary it was recorded with.
    fn location_unverified(&self) -> bool {
        self.same_binary != Some(true)
            && !self.checks.iter().any(|check| {
                LOCATION_FIELDS.contains(&check.field)
                    && matches!(check.outcome, Outcome::Equal | Outcome::Legacy)
            })
    }

    /// The fields an [`Verdict::Unverified`] verdict could not compare,
    /// comma-separated (`sink`, `pc`, or `location` for a finding that
    /// records none).
    pub(crate) fn not_compared_fields(&self) -> String {
        let fields: Vec<&str> = self
            .checks
            .iter()
            .filter(|check| check.outcome == Outcome::NotComparable)
            .map(|check| check.field)
            .collect();
        if fields.is_empty() && self.location_unverified() {
            return "location".to_owned();
        }
        fields.join(",")
    }

    /// Every compared field is equal (or an earlier name for the same thing);
    /// a field the finding does not record cannot fail the match.
    pub(crate) fn matches(&self) -> bool {
        self.checks
            .iter()
            .all(|check| check.outcome != Outcome::Differs)
    }

    /// Where the crash happened could not be compared: the replayed report
    /// names no function and no source position (an unsymbolized report).
    pub(crate) fn location_not_compared(&self) -> bool {
        self.checks
            .iter()
            .any(|check| check.outcome == Outcome::NotComparable)
    }

    pub(crate) fn differences(&self) -> impl Iterator<Item = &Check> {
        self.checks
            .iter()
            .filter(|check| check.outcome == Outcome::Differs)
    }

    /// The names of the differing fields, comma-separated (`kind,sink`).
    pub(crate) fn differing_fields(&self) -> String {
        self.differences()
            .map(|check| check.field)
            .collect::<Vec<_>>()
            .join(",")
    }

    /// One line per compared field, for the replay summary.
    pub(crate) fn compared_line(&self) -> String {
        self.checks
            .iter()
            .filter(|check| check.outcome != Outcome::Differs)
            .map(Check::describe)
            .collect::<Vec<_>>()
            .join("; ")
    }

    pub(crate) fn difference_lines(&self) -> Vec<String> {
        self.differences().map(Check::describe).collect()
    }
}

/// A source position reduced to what identifies it across checkouts: the last
/// two path components, the line and (when known) the column.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Position {
    tail: String,
    line: u64,
    column: Option<u64>,
}

impl Position {
    fn new(file: &str, line: u64, column: Option<u64>) -> Option<Self> {
        let file = file.trim();
        if file.is_empty() || file.starts_with('(') {
            return None;
        }
        let normalized = file.replace('\\', "/");
        let parts: Vec<&str> = normalized
            .split('/')
            .filter(|part| !part.is_empty() && *part != ".")
            .collect();
        let tail = parts[parts.len().saturating_sub(2)..].join("/");
        (!tail.is_empty()).then_some(Self { tail, line, column })
    }

    fn basename(&self) -> &str {
        self.tail.rsplit('/').next().unwrap_or(&self.tail)
    }

    /// Same file (by basename, and by directory when both name one), line, and
    /// column when both know it.
    fn same(&self, other: &Self) -> bool {
        let dirs_agree =
            !(self.tail.contains('/') && other.tail.contains('/')) || self.tail == other.tail;
        self.basename() == other.basename()
            && dirs_agree
            && self.line == other.line
            && match (self.column, other.column) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            }
    }

    fn render(&self) -> String {
        match self.column {
            Some(column) => format!("{}:{}:{column}", self.tail, self.line),
            None => format!("{}:{}", self.tail, self.line),
        }
    }
}

/// The finding's sink: the top project frame's function and position.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SinkSite {
    function: String,
    position: Option<Position>,
}

impl SinkSite {
    fn from_sink(sink: actionability::Sink) -> Option<Self> {
        if sink.function.trim().is_empty() {
            return None;
        }
        let position = sink
            .file
            .as_deref()
            .zip(sink.line)
            .and_then(|(file, line)| Position::new(file, line, None));
        Some(Self {
            function: sink.function,
            position,
        })
    }

    fn same(&self, other: &Self) -> bool {
        self.function == other.function
            && match (&self.position, &other.position) {
                (Some(a), Some(b)) => a.same(b),
                _ => true,
            }
    }

    fn render(&self) -> String {
        match &self.position {
            Some(position) => format!("{} ({})", self.function, position.render()),
            None => self.function.clone(),
        }
    }
}

/// What a finding (or a fresh report) says about its crash.
#[derive(Clone, Debug, Default)]
struct Identity {
    rule: Option<String>,
    kind: Option<String>,
    sink: Option<SinkSite>,
    site: Option<Position>,
    ubsan: bool,
    /// The fatal signal of a crash with no sanitizer report (`SIGSEGV`).
    signal: Option<String>,
    /// Where such a crash faulted: the pc offset in the executable.
    pc_offset: Option<u64>,
}

/// The signal a fatal-signal message names: `harness crashed with SIGABRT ...`.
fn message_signal(message: &str) -> Option<String> {
    let rest = message.split("crashed with ").nth(1)?;
    let name: String = rest
        .chars()
        .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        .collect();
    (name.len() > 3 && name.starts_with("SIG")).then_some(name)
}

/// `0x1b3c` (or a bare hex or decimal number) as an offset.
fn parse_offset(text: &str) -> Option<u64> {
    let text = text.trim();
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

fn normalize_kind(kind: &str) -> String {
    kind.trim().to_ascii_lowercase().replace('_', "-")
}

/// Whether a crash of `kind` (normalized) is reported by a fatal signal with
/// no sanitizer report, so its signal is part of what identifies it: a bare
/// fatal signal, and a COBOL runtime error, which the harness ends by one.
fn reported_by_signal(kind: &str) -> bool {
    kind == "fatal-signal" || kind == crate::auto::cobol_oracle::KIND
}

/// The kind token of a recorded `exception.name` (`ASAN_HEAP_BUFFER_OVERFLOW`,
/// `UBSAN_MISSING_RETURN`, `FATAL_SIGNAL`), without its sanitizer prefix.
fn kind_from_exception_name(name: &str) -> Option<String> {
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let kind = ["ASAN_", "UBSAN_", "LSAN_", "MSAN_", "TSAN_"]
        .iter()
        .find_map(|prefix| name.strip_prefix(prefix))
        .unwrap_or(name);
    Some(normalize_kind(kind))
}

fn message_position(message: &str) -> Option<Position> {
    let prefix = message.split("runtime error:").next()?;
    if prefix.len() == message.len() {
        return None;
    }
    let parts: Vec<&str> = prefix.trim().trim_end_matches(':').split(':').collect();
    let line_idx = parts
        .iter()
        .position(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))?;
    if line_idx == 0 {
        return None;
    }
    let file = parts[..line_idx].join(":");
    let line = parts[line_idx].parse().ok()?;
    let column = parts
        .get(line_idx + 1)
        .and_then(|part| part.parse::<u64>().ok());
    Position::new(&file, line, column)
}

fn recorded_identity(raw: &Value) -> Identity {
    let exception = raw.get("exception");
    let text = |value: Option<&Value>| value.and_then(Value::as_str).map(str::to_owned);
    let location = exception.and_then(|e| e.get("location"));
    // A COBOL runtime error happened at the COBOL source line libcob named.
    let cobol_site = raw.get("cobol_source").and_then(|source| {
        Position::new(
            source.get("file")?.as_str()?,
            source.get("line")?.as_u64()?,
            None,
        )
    });
    let site = cobol_site
        .or_else(|| {
            location.and_then(|loc| {
                Position::new(
                    loc.get("file")?.as_str()?,
                    loc.get("line")?.as_u64()?,
                    loc.get("column").and_then(Value::as_u64),
                )
            })
        })
        .or_else(|| {
            text(exception.and_then(|e| e.get("message")))
                .as_deref()
                .and_then(message_position)
        });
    let name = text(exception.and_then(|e| e.get("name")));
    let sanitizer = text(exception.and_then(|e| e.get("sanitizer")));
    let kind = name.as_deref().and_then(kind_from_exception_name);
    // The signal: recorded since this release, else the check name a fatal
    // signal carries, else the message an older release wrote.
    let signal = text(exception.and_then(|e| e.get("signal")))
        .or_else(|| {
            text(exception.and_then(|e| e.get("check"))).filter(|check| {
                kind.as_deref().is_some_and(reported_by_signal) && check.starts_with("SIG")
            })
        })
        .or_else(|| {
            text(exception.and_then(|e| e.get("message")))
                .filter(|_| kind.as_deref() == Some("fatal-signal"))
                .as_deref()
                .and_then(message_signal)
        });
    Identity {
        rule: text(raw.get("rule_id")),
        kind,
        sink: actionability::sink_for_finding(raw).and_then(SinkSite::from_sink),
        site,
        ubsan: sanitizer.as_deref() == Some("ubsan")
            || name.as_deref().is_some_and(|n| n.starts_with("UBSAN_")),
        signal,
        pc_offset: text(exception.and_then(|e| e.get("pc_offset")))
            .as_deref()
            .and_then(parse_offset),
    }
}

/// The record shape the sink selector reads, built from a report.
fn report_record(report: &SanitizerReport) -> Value {
    json!({
        "rule_id": report.rule_id,
        "exception": {
            "message": report.message,
            "stack": report.stack,
        },
    })
}

fn replayed_identity(report: &SanitizerReport) -> Identity {
    let site = report.location.as_ref().and_then(|location| {
        Position::new(
            &location.file,
            u64::from(location.line),
            location.column.map(u64::from),
        )
    });
    let fatal = report.sanitizer.is_none() && reported_by_signal(&normalize_kind(&report.kind));
    Identity {
        rule: Some(report.rule_id.to_owned()),
        kind: Some(normalize_kind(&report.kind)),
        sink: actionability::sink_for_finding(&report_record(report)).and_then(SinkSite::from_sink),
        site,
        ubsan: report.sanitizer == Some(corpus::sanitizer::Sanitizer::UndefinedBehaviorSanitizer),
        signal: fatal
            .then(|| {
                report
                    .check
                    .clone()
                    .filter(|check| check.starts_with("SIG"))
                    .or_else(|| message_signal(&report.message))
            })
            .flatten(),
        pc_offset: report.pc_offset,
    }
}

/// The kind an earlier release gave a UBSan report, from the text after
/// `runtime error:`: integer overflow and "cannot be represented" were one
/// kind, the NULL shapes another, array indexes and division by zero their
/// own, and everything else `undefined-behavior`. An ASan report's earlier
/// kind is the first word of its `ERROR:` line
/// ([`corpus::sanitizer::legacy_kind`]).
fn legacy_kind(report: &SanitizerReport) -> Option<String> {
    if report.sanitizer != Some(corpus::sanitizer::Sanitizer::UndefinedBehaviorSanitizer) {
        return corpus::sanitizer::legacy_kind(report).map(|kind| normalize_kind(&kind));
    }
    let after = report
        .message
        .split_once("runtime error:")
        .map_or("", |(_, text)| text.trim());
    const NULL_PREFIXES: &[&str] = &[
        "load of null pointer",
        "store to null pointer",
        "member access within null pointer",
        "reference binding to null pointer",
        "null pointer passed as argument",
        "null pointer returned from function",
    ];
    let kind = if after.starts_with("signed integer overflow")
        || after.starts_with("unsigned integer overflow")
        || after.contains("cannot be represented in type")
    {
        "signed-integer-overflow"
    } else if NULL_PREFIXES.iter().any(|prefix| after.starts_with(prefix))
        || (after.starts_with("applying") && after.contains("to null pointer"))
    {
        "null-pointer-dereference"
    } else if after.starts_with("index ") && after.contains("out of bounds") {
        "out-of-bounds-access"
    } else if after.starts_with("division by zero") {
        "division-by-zero"
    } else {
        "undefined-behavior"
    };
    Some(kind.to_owned())
}

/// The kinds of an ASan out-of-bounds report whose access gcc's UBSan
/// object-size check also guards, and reports first as
/// [`OBJECT_SIZE_KIND`].
const ASAN_BOUNDS_KINDS: &[&str] = &[
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "global-buffer-overflow",
];
const OBJECT_SIZE_KIND: &str = "insufficient-object-size";

/// Whether `recorded` and `replayed` are one bounds error seen by the two
/// sanitizers: an ASan overflow and UBSan's insufficient-object-size, either
/// way round. Where it happened is compared as for any report.
fn same_access(recorded: &Identity, replayed: &Identity) -> bool {
    let bounds = |kind: &str| ASAN_BOUNDS_KINDS.contains(&kind);
    match (recorded.kind.as_deref(), replayed.kind.as_deref()) {
        (Some(a), Some(b)) => {
            (bounds(a) && b == OBJECT_SIZE_KIND) || (a == OBJECT_SIZE_KIND && bounds(b))
        }
        _ => false,
    }
}

fn check_rule(recorded: &Identity, replayed: &Identity, report: &SanitizerReport) -> Check {
    let outcome = match recorded.rule.as_deref() {
        None => Outcome::NotRecorded,
        Some(rule) if rule == report.rule_id => Outcome::Equal,
        Some(rule) if corpus::sanitizer::rule_matches(rule, report) => Outcome::Legacy,
        Some(_) if same_access(recorded, replayed) => Outcome::SameAccess,
        Some(_) => Outcome::Differs,
    };
    let replayed = Some(report.rule_id.to_owned());
    Check {
        field: "rule",
        recorded: recorded.rule.clone(),
        replayed,
        outcome,
        why: None,
    }
}

fn check_kind(recorded: &Identity, replayed: &Identity, report: &SanitizerReport) -> Check {
    let outcome = match (&recorded.kind, &replayed.kind) {
        (None, _) => Outcome::NotRecorded,
        (Some(a), Some(b)) if a == b => Outcome::Equal,
        (Some(a), _) if legacy_kind(report).as_deref() == Some(a.as_str()) => Outcome::Legacy,
        _ if same_access(recorded, replayed) => Outcome::SameAccess,
        _ => Outcome::Differs,
    };
    Check {
        field: "kind",
        recorded: recorded.kind.clone(),
        replayed: replayed.kind.clone(),
        outcome,
        why: None,
    }
}

/// The signal of a recorded fatal signal against the replay's.
fn check_signal(recorded: &Identity, replayed: &Identity) -> Option<Check> {
    let signal = recorded.signal.as_ref()?;
    Some(Check {
        field: "signal",
        recorded: Some(signal.clone()),
        replayed: replayed.signal.clone(),
        outcome: if replayed.signal.as_ref() == Some(signal) {
            Outcome::Equal
        } else {
            Outcome::Differs
        },
        why: None,
    })
}

/// A recorded pc offset, for a finding with no sink or site: a crash site of
/// the recorded build, so it is compared only when `same_binary`.
fn check_pc(recorded: &Identity, replayed: &Identity, same_binary: Option<bool>) -> Check {
    let render = |offset: u64| format!("exe+{offset:#x}");
    let (outcome, why) = match replayed.pc_offset {
        Some(pc) if same_binary == Some(true) => {
            if Some(pc) == recorded.pc_offset {
                (Outcome::Equal, None)
            } else {
                (Outcome::Differs, None)
            }
        }
        None => (Outcome::NotComparable, Some(NotCompared::NoPcOffset)),
        Some(_) => (
            Outcome::NotComparable,
            Some(NotCompared::OtherBuild(same_binary)),
        ),
    };
    Check {
        field: "pc",
        recorded: recorded.pc_offset.map(render),
        replayed: replayed.pc_offset.map(render),
        outcome,
        why,
    }
}

/// The sink when the finding names a function; the reported site when it
/// records none (a UBSan report recorded without frames), or for UBSan, whose
/// signature keys on the site; the faulting pc offset for a fatal signal
/// recorded with neither. A replay that names neither a function nor a
/// position (an unsymbolized report) is not comparable, which is not a
/// difference: missing information is not another crash site.
fn check_location(
    recorded: &Identity,
    replayed: &Identity,
    same_binary: Option<bool>,
) -> Vec<Check> {
    let mut checks = Vec::new();
    if recorded.sink.is_none() && recorded.site.is_none() && recorded.pc_offset.is_some() {
        checks.push(check_pc(recorded, replayed, same_binary));
        return checks;
    }
    let replay_has_nothing = replayed.sink.is_none() && replayed.site.is_none();
    if let Some(sink) = &recorded.sink {
        let outcome = match &replayed.sink {
            Some(other) if sink.same(other) => Outcome::Equal,
            _ if replay_has_nothing => Outcome::NotComparable,
            // A replay without a frame naming a function still has the site.
            None => match (&sink.position, &replayed.site) {
                (Some(position), Some(site)) if position.same(site) => Outcome::Equal,
                _ => Outcome::Differs,
            },
            Some(_) => Outcome::Differs,
        };
        checks.push(Check {
            field: "sink",
            recorded: Some(sink.render()),
            replayed: replayed
                .sink
                .as_ref()
                .map(SinkSite::render)
                .or_else(|| replayed.site.as_ref().map(Position::render)),
            outcome,
            why: (outcome == Outcome::NotComparable).then_some(NotCompared::Unlocated),
        });
    }
    if recorded.sink.is_none() || recorded.ubsan {
        let outcome = match (&recorded.site, &replayed.site) {
            (None, _) if recorded.sink.is_some() => return checks,
            (None, _) => Outcome::NotRecorded,
            (Some(a), Some(b)) if a.same(b) => Outcome::Equal,
            (Some(_), None) if replay_has_nothing => Outcome::NotComparable,
            _ => Outcome::Differs,
        };
        checks.push(Check {
            field: "site",
            recorded: recorded.site.as_ref().map(Position::render),
            replayed: replayed.site.as_ref().map(Position::render),
            outcome,
            why: (outcome == Outcome::NotComparable).then_some(NotCompared::Unlocated),
        });
    }
    checks
}

/// Compare a replayed report with the finding record `raw`, not knowing
/// whether the binary that ran is the recorded build.
pub(crate) fn compare(raw: &Value, report: &SanitizerReport) -> Comparison {
    compare_with(raw, report, None)
}

/// Compare a replayed report with the finding record `raw`. `same_binary`
/// says whether the harness that ran is the build the finding was recorded
/// with (its sha256 is the recorded `build.binary.sha256`).
pub(crate) fn compare_with(
    raw: &Value,
    report: &SanitizerReport,
    same_binary: Option<bool>,
) -> Comparison {
    let recorded = recorded_identity(raw);
    let replayed = replayed_identity(report);
    let mut checks = vec![
        check_rule(&recorded, &replayed, report),
        check_kind(&recorded, &replayed, report),
    ];
    checks.extend(check_signal(&recorded, &replayed));
    checks.extend(check_location(&recorded, &replayed, same_binary));
    Comparison {
        checks,
        same_binary,
    }
}

/// Whether a fresh re-run's report is the same crash as `original`: same rule,
/// kind and sink (or reported site).
pub(crate) fn same_crash(original: &SanitizerReport, fresh: &SanitizerReport) -> bool {
    let mut record = report_record(original);
    if let Some(location) = &original.location {
        record["exception"]["location"] = json!(location);
    }
    let kind_token = original.kind.to_uppercase().replace('-', "_");
    record["exception"]["name"] = json!(match original.sanitizer {
        Some(sanitizer) => format!("{}_{kind_token}", sanitizer.as_str().to_uppercase()),
        None => kind_token,
    });
    if let Some(sanitizer) = original.sanitizer {
        record["exception"]["sanitizer"] = json!(sanitizer.as_str());
    }
    if let Some(check) = &original.check {
        record["exception"]["check"] = json!(check);
    }
    if let Some(offset) = original.pc_offset {
        record["exception"]["pc_offset"] = json!(format!("{offset:#x}"));
    }
    // The fresh re-run runs the same binary.
    let comparison = compare_with(&record, fresh, Some(true));
    comparison.matches()
        && comparison
            .checks
            .iter()
            .all(|check| !matches!(check.outcome, Outcome::Legacy | Outcome::SameAccess))
}

/// The finding's recorded sink, rendered, for the replay summary.
pub(crate) fn recorded_sink(raw: &Value) -> Option<String> {
    recorded_identity(raw).sink.map(|sink| sink.render())
}

/// The function of the finding's recorded sink, by its bare name (no
/// parameter list): where a debugger session breaks when the harness names no
/// target function.
pub(crate) fn recorded_sink_function(raw: &Value) -> Option<String> {
    recorded_identity(raw).sink.map(|sink| sink.function)
}

/// The replayed report's sink, rendered.
pub(crate) fn replayed_sink(report: &SanitizerReport) -> Option<String> {
    replayed_identity(report).sink.map(|sink| sink.render())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asan(frame: &str) -> SanitizerReport {
        corpus::parse_sanitizer_report(&format!(
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000031 at pc 0x1 bp 0x2 sp 0x3\n\
             WRITE of size 1 at 0x602000000031 thread T0\n\
             {frame}\
                 #2 0x4 in main /w/harnesses/H-1/main.cpp:90:3\n\
             \n\
             0x602000000031 is located 0 bytes after 1-byte region [0x602000000030,0x602000000031)\n\
             SUMMARY: AddressSanitizer: heap-buffer-overflow /src/widget/widget.cc:12:5 in Widget::copy_at\n"
        ))
        .expect("asan report")
    }

    const COPY_AT: &str =
        "    #0 0x1 in Widget::copy_at(char const*, unsigned long) /src/widget/widget.cc:12:5\n\
                           #1 0x2 in parse_record(char const*) /src/widget/parse.cc:40:7\n";
    const OTHER: &str =
        "    #0 0x1 in Widget::other(char const*, unsigned short&) /src/widget/widget.cc:8:26\n\
                         #1 0x2 in parse_record(char const*) /src/widget/parse.cc:44:7\n";

    fn recorded_from(report: &SanitizerReport) -> Value {
        let mut record = report_record(report);
        record["exception"]["name"] = json!("ASAN_HEAP_BUFFER_OVERFLOW");
        record["exception"]["sanitizer"] = json!("asan");
        record
    }

    #[test]
    fn the_same_crash_matches_on_rule_kind_and_sink() {
        let report = asan(COPY_AT);
        let comparison = compare(&recorded_from(&report), &asan(COPY_AT));
        assert!(comparison.matches(), "{comparison:?}");
        let fields: Vec<_> = comparison.checks.iter().map(|c| c.field).collect();
        assert_eq!(fields, ["rule", "kind", "sink"]);
        assert!(
            comparison
                .compared_line()
                .contains("sink Widget::copy_at (widget/widget.cc:12)"),
            "{}",
            comparison.compared_line()
        );
    }

    /// Same rule, same kind, another function: not this finding.
    #[test]
    fn the_same_class_at_another_site_is_a_mismatch_that_names_the_sink() {
        let recorded = recorded_from(&asan(COPY_AT));
        let comparison = compare(&recorded, &asan(OTHER));
        assert!(!comparison.matches());
        assert_eq!(comparison.differing_fields(), "sink");
        let lines = comparison.difference_lines();
        assert_eq!(
            lines,
            ["sink: recorded Widget::copy_at (widget/widget.cc:12), replayed Widget::other (widget/widget.cc:8)"]
        );
    }

    /// gcc's UBSan report of the store [`asan`] reports: its object-size
    /// check guards the same access and fires first.
    fn object_size(frame: &str) -> SanitizerReport {
        corpus::parse_sanitizer_report(&format!(
            "/src/widget/widget.cc:12:5: runtime error: store to address 0x602000000031 with insufficient space for an object of type 'char'\n\
             {frame}\
                 #2 0x4 in main /w/harnesses/H-1/main.cpp:90:3\n\
             SUMMARY: UndefinedBehaviorSanitizer: insufficient-object-size /src/widget/widget.cc:12:5\n"
        ))
        .expect("ubsan report")
    }

    /// An ASan overflow and gcc's object-size report of the same access are
    /// the same crash, either way round (a finding bhf recorded from ASan's
    /// view replayed on the gcc binary, a gcc finding rebuilt with clang); at
    /// another sink, or against another UBSan check, they are not. The fuzz
    /// loop's same-binary confirmation never takes one for the other.
    #[test]
    fn an_overflow_and_gccs_object_size_report_of_it_are_the_same_crash() {
        let overflow = asan(COPY_AT);
        let mut gcc_record = report_record(&object_size(COPY_AT));
        gcc_record["exception"]["name"] = json!("UBSAN_INSUFFICIENT_OBJECT_SIZE");
        gcc_record["exception"]["sanitizer"] = json!("ubsan");
        assert_eq!(object_size(COPY_AT).rule_id, "BHF-227");
        for (record, replayed) in [
            (recorded_from(&overflow), object_size(COPY_AT)),
            (gcc_record.clone(), asan(COPY_AT)),
        ] {
            let comparison = compare(&record, &replayed);
            assert_eq!(comparison.verdict(), Verdict::Match, "{comparison:?}");
            assert!(
                comparison
                    .compared_line()
                    .contains("the same out-of-bounds access"),
                "{}",
                comparison.compared_line()
            );
        }
        let elsewhere = compare(&recorded_from(&overflow), &object_size(OTHER));
        assert_eq!(elsewhere.differing_fields(), "sink");
        let other_check = compare(&recorded_from(&overflow), &ubsan(COPY_AT));
        assert_eq!(other_check.differing_fields(), "rule,kind");
        assert!(!same_crash(&overflow, &object_size(COPY_AT)));
    }

    fn ubsan(stack: &str) -> SanitizerReport {
        corpus::parse_sanitizer_report(&format!(
            "/src/widget/classify.cc:3:5: runtime error: execution reached the end of a value-returning function without returning a value\n\
             {stack}\
             SUMMARY: UndefinedBehaviorSanitizer: missing-return /src/widget/classify.cc:3:5\n"
        ))
        .expect("ubsan report")
    }

    /// A UBSan finding recorded without frames (`sink.function` empty) is
    /// matched on its reported site, even when the replay now has frames.
    #[test]
    fn a_frameless_record_matches_on_the_reported_site() {
        let recorded = json!({
            "rule_id": "BHF-210",
            "exception": {
                "name": "UBSAN_UNDEFINED_BEHAVIOR",
                "sanitizer": "ubsan",
                "message": "classify.cc:3:5: runtime error: execution reached the end of a value-returning function without returning a value",
                "stack": [],
            },
        });
        let replay = ubsan("    #0 0x1 in classify_code(int) /src/widget/classify.cc:8:16\n");
        let comparison = compare(&recorded, &replay);
        assert!(comparison.matches(), "{comparison:?}");
        let outcomes: Vec<_> = comparison
            .checks
            .iter()
            .map(|c| (c.field, c.outcome))
            .collect();
        assert_eq!(
            outcomes,
            [
                ("rule", Outcome::Legacy),
                ("kind", Outcome::Legacy),
                ("site", Outcome::Equal)
            ]
        );
        let elsewhere = corpus::parse_sanitizer_report(
            "/src/widget/classify.cc:9:5: runtime error: execution reached the end of a value-returning function without returning a value\n",
        )
        .unwrap();
        let comparison = compare(&recorded, &elsewhere);
        assert_eq!(comparison.differing_fields(), "site");
    }

    /// The generic rule an earlier release gave UBSan is also the fatal-signal
    /// rule; the kind tells them apart.
    #[test]
    fn a_fatal_signal_does_not_reproduce_a_recorded_ubsan_report() {
        let recorded = json!({
            "rule_id": "BHF-210",
            "exception": {"name": "UBSAN_UNDEFINED_BEHAVIOR", "sanitizer": "ubsan", "stack": []},
        });
        let fatal = SanitizerReport {
            sanitizer: None,
            kind: "fatal-signal".to_owned(),
            rule_id: "BHF-210",
            message: "harness crashed with SIGABRT".to_owned(),
            ..Default::default()
        };
        let comparison = compare(&recorded, &fatal);
        assert_eq!(comparison.differing_fields(), "kind");
    }

    /// A record holding only a rule (written by hand or by an old release)
    /// matches on the rule alone.
    #[test]
    fn a_rule_only_record_matches_on_the_rule() {
        let report = asan(COPY_AT);
        let comparison = compare(&json!({"rule_id": "BHF-201"}), &report);
        assert!(comparison.matches(), "{comparison:?}");
        let comparison = compare(&json!({"rule_id": "BHF-202"}), &report);
        assert_eq!(comparison.differing_fields(), "rule");
    }

    /// The same crash replayed without a symbolizer has frames that name no
    /// function and a summary without a position: its location cannot be
    /// compared, which is not a difference.
    #[test]
    fn an_unsymbolized_replay_is_not_a_sink_difference() {
        let recorded = recorded_from(&asan(COPY_AT));
        let unsymbolized = corpus::parse_sanitizer_report(
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000031 at pc 0x1 bp 0x2 sp 0x3\n\
             WRITE of size 1 at 0x602000000031 thread T0\n\
             \x20   #0 0x4f5a2b  (/w/build/H-1/main+0x4f5a2b)\n\
             \x20   #1 0x4f5c10  (/w/build/H-1/main+0x4f5c10)\n\
             \n\
             SUMMARY: AddressSanitizer: heap-buffer-overflow (/w/build/H-1/main+0x4f5a2b)\n",
        )
        .expect("asan report");
        let comparison = compare(&recorded, &unsymbolized);
        assert!(comparison.matches(), "{comparison:?}");
        assert!(comparison.location_not_compared());
        // Nothing differs, but where it crashed was not compared: that is
        // not a reproduction, whatever binary ran.
        assert_eq!(comparison.verdict(), Verdict::Unverified);
        assert_eq!(comparison.not_compared_fields(), "sink");
        assert_eq!(
            compare_with(&recorded, &unsymbolized, Some(true)).verdict(),
            Verdict::Unverified
        );
        let sink = comparison
            .checks
            .iter()
            .find(|check| check.field == "sink")
            .expect("sink check");
        assert_eq!(sink.outcome, Outcome::NotComparable);
        assert!(comparison.compared_line().contains("sink not compared"));
        assert!(
            comparison
                .compared_line()
                .contains("the replay names no function or source position"),
            "{}",
            comparison.compared_line()
        );
        // A replay that does name another function still differs.
        let comparison = compare(&recorded, &asan(OTHER));
        assert!(!comparison.location_not_compared());
        assert_eq!(comparison.differing_fields(), "sink");
    }

    fn fatal(signal: &str, pc_offset: Option<u64>) -> SanitizerReport {
        SanitizerReport {
            sanitizer: None,
            kind: "fatal-signal".to_owned(),
            rule_id: "BHF-210",
            message: format!("harness crashed with {signal} and no sanitizer report"),
            check: Some(signal.to_owned()),
            pc_offset,
            ..Default::default()
        }
    }

    /// A record that names no crash location (no stack, sink, site or pc)
    /// is reproduced only by a run of the binary it was recorded with.
    #[test]
    fn a_location_less_record_is_verified_only_against_the_recorded_build() {
        let recorded = json!({
            "rule_id": "BHF-210",
            "exception": {"name": "FATAL_SIGNAL", "signal": "SIGABRT", "stack": []},
        });
        let replay = fatal("SIGABRT", None);
        assert_eq!(
            compare_with(&recorded, &replay, Some(true)).verdict(),
            Verdict::Match
        );
        for other in [Some(false), None] {
            let comparison = compare_with(&recorded, &replay, other);
            assert_eq!(comparison.verdict(), Verdict::Unverified, "{other:?}");
            assert_eq!(comparison.not_compared_fields(), "location");
        }
        // A rule-only record from an earlier release likewise.
        let comparison = compare(&json!({"rule_id": "BHF-201"}), &asan(COPY_AT));
        assert!(comparison.matches());
        assert_eq!(comparison.verdict(), Verdict::Unverified);
    }

    /// A fatal-signal finding is reproduced only by the same signal: an abort
    /// is not reproduced by an illegal instruction. The signal is read from
    /// `exception.signal`, or from the message of an older record.
    #[test]
    fn a_fatal_signal_of_another_signal_differs_on_the_signal() {
        let recorded = json!({
            "rule_id": "BHF-210",
            "exception": {"name": "FATAL_SIGNAL", "signal": "SIGABRT", "stack": []},
        });
        let comparison = compare_with(&recorded, &fatal("SIGILL", None), Some(true));
        assert_eq!(comparison.differing_fields(), "signal");
        assert_eq!(comparison.verdict(), Verdict::Mismatch);
        assert_eq!(
            comparison.difference_lines(),
            ["signal: recorded SIGABRT, replayed SIGILL"]
        );
        let older = json!({
            "rule_id": "BHF-210",
            "exception": {
                "name": "FATAL_SIGNAL",
                "message": "harness crashed with SIGABRT and no sanitizer report — a reachable crash",
            },
        });
        assert_eq!(
            compare_with(&older, &fatal("SIGILL", None), Some(true)).differing_fields(),
            "signal"
        );
        assert_eq!(
            compare_with(&older, &fatal("SIGABRT", None), Some(true)).verdict(),
            Verdict::Match
        );
    }

    /// The faulting pc offset the driver printed is a crash site of one
    /// build: compared against that build only.
    #[test]
    fn a_recorded_pc_offset_is_compared_in_the_recorded_build_only() {
        let recorded = json!({
            "rule_id": "BHF-210",
            "exception": {"name": "FATAL_SIGNAL", "signal": "SIGSEGV", "pc_offset": "0x1b3c"},
        });
        let same = compare_with(&recorded, &fatal("SIGSEGV", Some(0x1b3c)), Some(true));
        assert_eq!(same.verdict(), Verdict::Match, "{same:?}");
        let elsewhere = compare_with(&recorded, &fatal("SIGSEGV", Some(0x2a10)), Some(true));
        assert_eq!(elsewhere.differing_fields(), "pc");
        let rebuilt = compare_with(&recorded, &fatal("SIGSEGV", Some(0x2a10)), Some(false));
        assert_eq!(rebuilt.verdict(), Verdict::Unverified);
        assert_eq!(rebuilt.not_compared_fields(), "pc");
        // The compared line gives the reason the pc was not compared.
        let line = rebuilt.compared_line();
        assert!(
            line.contains(
                "pc not compared (recorded exe+0x1b3c; the harness's sha256 differs from the \
                 recorded build)"
            ),
            "{line}"
        );
        assert!(!line.contains("names no function"), "{line}");
        let line = compare_with(&recorded, &fatal("SIGSEGV", Some(0x2a10)), None).compared_line();
        assert!(line.contains("no build sha256"), "{line}");
        assert!(!line.contains("names no function"), "{line}");
        let line = compare_with(&recorded, &fatal("SIGSEGV", None), Some(true)).compared_line();
        assert!(line.contains("the replay printed no pc offset"), "{line}");
        // A fresh re-run (the same binary) at another pc is another crash.
        assert!(same_crash(
            &fatal("SIGSEGV", Some(0x1b3c)),
            &fatal("SIGSEGV", Some(0x1b3c))
        ));
        assert!(!same_crash(
            &fatal("SIGSEGV", Some(0x1b3c)),
            &fatal("SIGSEGV", Some(0x2a10))
        ));
        assert!(!same_crash(&fatal("SIGSEGV", None), &fatal("SIGILL", None)));
    }

    #[test]
    fn a_fresh_rerun_is_the_same_crash_only_at_the_same_sink() {
        assert!(same_crash(&asan(COPY_AT), &asan(COPY_AT)));
        assert!(!same_crash(&asan(COPY_AT), &asan(OTHER)));
        let a = ubsan("");
        let b = corpus::parse_sanitizer_report(
            "/src/widget/classify.cc:9:5: runtime error: execution reached the end of a value-returning function without returning a value\n",
        )
        .unwrap();
        assert!(same_crash(&a, &a.clone()));
        assert!(!same_crash(&a, &b));
    }

    /// A COBOL finding as `bhf auto` records it: the harness's SIGSEGV,
    /// attributed to the libcob runtime error it printed at `parseit.cob:11`.
    #[cfg(unix)]
    fn cobol_record() -> Value {
        json!({
            "rule_id": "BHF-210",
            "harness_id": "H-B0002-10C8E67B",
            "exception": {
                "name": "COBOL_RUNTIME_ERROR",
                "check": "SIGSEGV",
                "signal": "SIGSEGV",
                "message": "COBOL out-of-bounds reference-modification / subscript at \
                            /src/cobol/parseit.cob:11: offset of 'BUF' out of bounds: 200, \
                            maximum: 8",
                "libcob_diagnostic": "offset of 'BUF' out of bounds: 200, maximum: 8",
                "stack": [],
            },
            "cobol_source": {"file": "/src/cobol/parseit.cob", "line": 11},
            "analysis": {"engine": "bhf.cobol.attribution"},
        })
    }

    /// A COBOL harness run that died by `signal` after printing `stderr`.
    #[cfg(unix)]
    fn harness_run(signal: i32, stderr: &str) -> crate::replay::CRun {
        use std::os::unix::process::ExitStatusExt;
        crate::replay::CRun {
            status: Some(std::process::ExitStatus::from_raw(signal)),
            timed_out: false,
            duration: std::time::Duration::ZERO,
            stdout: Vec::new(),
            stderr: stderr.as_bytes().to_vec(),
            env: Vec::new(),
        }
    }

    /// libcob's diagnostic for an out-of-bounds reference-modification at
    /// `line`, as the harness prints it before it dies.
    #[cfg(unix)]
    fn libcob_ref_mod(line: u32) -> String {
        format!(
            "libcob: /src/cobol/parseit.cob:{line}: error: offset of 'BUF' out of bounds: 200, \
             maximum: 8\n\n Last statement of PARSEIT was at line {line} of \
             /src/cobol/parseit.cob\n\n/src/cobol/parseit.cob:{line}: attempt to reference \
             unallocated memory (signal SIGSEGV)\n"
        )
    }

    /// The replay of a COBOL finding gets the attribution the finding got, so
    /// the same libcob error at the same COBOL line, by the same signal, is
    /// the recorded crash, in any build: the COBOL line is where it happened.
    #[cfg(unix)]
    #[test]
    fn a_cobol_finding_matches_the_same_runtime_error_on_replay() {
        let recorded = cobol_record();
        let report = harness_run(11, &libcob_ref_mod(11))
            .report_for(&recorded)
            .expect("a crash");
        let comparison = compare(&recorded, &report);
        assert_eq!(comparison.verdict(), Verdict::Match, "{comparison:?}");
        assert_eq!(
            comparison.compared_line(),
            "rule BHF-210; kind cobol-runtime-error; signal SIGSEGV; site cobol/parseit.cob:11"
        );
        // The minimizer's predicate holds a reduction to the same COBOL line.
        let other_line = harness_run(11, &libcob_ref_mod(20))
            .report_for(&recorded)
            .expect("a crash");
        assert!(same_crash(&report, &report.clone()));
        assert!(!same_crash(&report, &other_line));
    }

    /// The attribution keeps the comparison strict: a COBOL finding is not
    /// reproduced by a bare SIGSEGV without libcob's diagnostic, by a libcob
    /// error at another COBOL line, or by another signal.
    #[cfg(unix)]
    #[test]
    fn a_cobol_finding_mismatches_a_different_crash() {
        let recorded = cobol_record();
        let differs = |signal: i32, stderr: &str| {
            let report = harness_run(signal, stderr)
                .report_for(&recorded)
                .expect("a crash");
            let comparison = compare_with(&recorded, &report, Some(true));
            assert_eq!(comparison.verdict(), Verdict::Mismatch, "{comparison:?}");
            comparison.difference_lines()
        };
        assert_eq!(
            differs(11, "Segmentation fault\n"),
            ["kind: recorded cobol-runtime-error, replayed fatal-signal"]
        );
        assert_eq!(
            differs(11, &libcob_ref_mod(20)),
            ["site: recorded cobol/parseit.cob:11, replayed cobol/parseit.cob:20"]
        );
        assert_eq!(
            differs(6, &libcob_ref_mod(11)),
            ["signal: recorded SIGSEGV, replayed SIGABRT"]
        );
        // A call to a program the harness does not link is an artifact the
        // attribution never records: such a crash stays a bare fatal signal.
        assert_eq!(
            differs(11, "libcob: error: module 'SIBLING' not found\n"),
            ["kind: recorded cobol-runtime-error, replayed fatal-signal"]
        );
    }

    /// Only a COBOL harness's crash is attributed, as only its findings are:
    /// a libcob line in another harness's output leaves its fatal signal as
    /// it was recorded.
    #[cfg(unix)]
    #[test]
    fn only_a_cobol_harness_crash_is_attributed() {
        let recorded = json!({
            "rule_id": "BHF-210",
            "harness_id": "H-C0001-0A0B0C0D",
            "exception": {"name": "FATAL_SIGNAL", "signal": "SIGSEGV", "stack": []},
        });
        let report = harness_run(11, &libcob_ref_mod(11))
            .report_for(&recorded)
            .expect("a crash");
        assert_eq!(report.kind, "fatal-signal");
        assert_eq!(
            compare_with(&recorded, &report, Some(true)).verdict(),
            Verdict::Match
        );
    }

    /// Earlier releases recorded an ASan out-of-memory report under the
    /// heap-overflow rule, with the first word of its `ERROR:` line as its
    /// kind (`ASAN_OUT`). A replay that reports it now, as BHF-209
    /// `out-of-memory`, is the same crash.
    #[test]
    fn an_earlier_out_of_memory_record_matches_its_replay() {
        let replay = corpus::parse_sanitizer_report(
            "==546834==ERROR: AddressSanitizer: out of memory: allocator is trying to allocate 0x8000000000 bytes\n\
             \x20   #0 0x623d6b09a1b3 in malloc (/w/harnesses/H-1/main+0xc71b3)\n\
             \x20   #1 0x623d6b0d8e04 in read_blob /src/widget/blob.c:14:43\n\
             \x20   #2 0x623d6b0d8aab in parse_record /src/widget/parse.c:26:43\n\
             \n\
             SUMMARY: AddressSanitizer: out-of-memory (/w/harnesses/H-1/main+0xc71b3)\n",
        )
        .expect("asan report");
        assert_eq!(
            (replay.rule_id, replay.kind.as_str()),
            ("BHF-209", "out-of-memory")
        );
        let mut recorded = report_record(&replay);
        recorded["rule_id"] = json!("BHF-201");
        recorded["exception"]["name"] = json!("ASAN_OUT");
        recorded["exception"]["sanitizer"] = json!("asan");
        let comparison = compare(&recorded, &replay);
        assert!(comparison.matches(), "{comparison:?}");
        let outcomes: Vec<_> = comparison
            .checks
            .iter()
            .map(|c| (c.field, c.outcome))
            .collect();
        assert_eq!(
            outcomes,
            [
                ("rule", Outcome::Legacy),
                ("kind", Outcome::Legacy),
                ("sink", Outcome::Equal)
            ]
        );
        // Another earlier kind is still another crash.
        recorded["exception"]["name"] = json!("ASAN_HEAP_BUFFER_OVERFLOW");
        assert_eq!(compare(&recorded, &replay).differing_fields(), "kind");
    }

    #[test]
    fn positions_compare_across_checkouts() {
        let a = Position::new("/home/a/src/widget/x.cc", 3, Some(5)).unwrap();
        let b = Position::new("/build/src/widget/x.cc", 3, Some(5)).unwrap();
        let bare = Position::new("x.cc", 3, None).unwrap();
        let other_dir = Position::new("/src/other/x.cc", 3, Some(5)).unwrap();
        assert!(a.same(&b));
        assert!(a.same(&bare));
        assert!(!a.same(&other_dir));
        assert!(!a.same(&Position::new("/src/widget/x.cc", 4, Some(5)).unwrap()));
    }
}
