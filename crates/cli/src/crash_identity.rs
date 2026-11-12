// SPDX-License-Identifier: Apache-2.0

//! What makes a reproduced crash the crash a finding recorded: its rule, its
//! kind, and where it happened. Where is the finding's sink (the top project
//! frame, chosen by the same selector the finding's `actionability.sink`
//! uses) or, for a report without frames (or a UBSan report), the site the
//! sanitizer printed (`file:line:col: runtime error:`), the identity the
//! finding signature uses for such reports.
//!
//! `bhf replay` and the fuzz loop's fresh-process confirmation both compare
//! through [`compare`], so a crash of the same class at another site never
//! counts as a reproduction.

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
    Differs,
    /// The finding records nothing to compare this field with.
    NotRecorded,
    /// The replayed report has nothing to compare it with: no frame naming a
    /// function and no source position, as an unsymbolized report prints.
    NotComparable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Check {
    pub(crate) field: &'static str,
    pub(crate) recorded: Option<String>,
    pub(crate) replayed: Option<String>,
    pub(crate) outcome: Outcome,
}

impl Check {
    fn describe(&self) -> String {
        let recorded = self.recorded.as_deref().unwrap_or("(not recorded)");
        let replayed = self.replayed.as_deref().unwrap_or("(none)");
        match self.outcome {
            Outcome::Equal => format!("{} {recorded}", self.field),
            Outcome::Legacy => format!("{} {recorded} (earlier name of {replayed})", self.field),
            Outcome::Differs => format!("{}: recorded {recorded}, replayed {replayed}", self.field),
            Outcome::NotRecorded => format!("{} not recorded", self.field),
            Outcome::NotComparable => format!(
                "{} not compared (recorded {recorded}; the replay names no function or source \
                 position)",
                self.field
            ),
        }
    }
}

/// The field-by-field comparison of a replayed report with a recorded finding.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct Comparison {
    pub(crate) checks: Vec<Check>,
}

impl Comparison {
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
}

fn normalize_kind(kind: &str) -> String {
    kind.trim().to_ascii_lowercase().replace('_', "-")
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
    let site = location
        .and_then(|loc| {
            Position::new(
                loc.get("file")?.as_str()?,
                loc.get("line")?.as_u64()?,
                loc.get("column").and_then(Value::as_u64),
            )
        })
        .or_else(|| {
            text(exception.and_then(|e| e.get("message")))
                .as_deref()
                .and_then(message_position)
        });
    let name = text(exception.and_then(|e| e.get("name")));
    let sanitizer = text(exception.and_then(|e| e.get("sanitizer")));
    Identity {
        rule: text(raw.get("rule_id")),
        kind: name.as_deref().and_then(kind_from_exception_name),
        sink: actionability::sink_for_finding(raw).and_then(SinkSite::from_sink),
        site,
        ubsan: sanitizer.as_deref() == Some("ubsan")
            || name.as_deref().is_some_and(|n| n.starts_with("UBSAN_")),
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
    Identity {
        rule: Some(report.rule_id.to_owned()),
        kind: Some(normalize_kind(&report.kind)),
        sink: actionability::sink_for_finding(&report_record(report)).and_then(SinkSite::from_sink),
        site,
        ubsan: report.sanitizer == Some(corpus::sanitizer::Sanitizer::UndefinedBehaviorSanitizer),
    }
}

/// The kind an earlier release gave a UBSan report, from the text after
/// `runtime error:`: integer overflow and "cannot be represented" were one
/// kind, the NULL shapes another, array indexes and division by zero their
/// own, and everything else `undefined-behavior`.
fn legacy_kind(report: &SanitizerReport) -> Option<String> {
    if report.sanitizer != Some(corpus::sanitizer::Sanitizer::UndefinedBehaviorSanitizer) {
        return None;
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

fn check_rule(recorded: &Identity, report: &SanitizerReport) -> Check {
    let replayed = Some(report.rule_id.to_owned());
    let outcome = match recorded.rule.as_deref() {
        None => Outcome::NotRecorded,
        Some(rule) if rule == report.rule_id => Outcome::Equal,
        Some(rule) if corpus::sanitizer::rule_matches(rule, report) => Outcome::Legacy,
        Some(_) => Outcome::Differs,
    };
    Check {
        field: "rule",
        recorded: recorded.rule.clone(),
        replayed,
        outcome,
    }
}

fn check_kind(recorded: &Identity, replayed: &Identity, report: &SanitizerReport) -> Check {
    let outcome = match (&recorded.kind, &replayed.kind) {
        (None, _) => Outcome::NotRecorded,
        (Some(a), Some(b)) if a == b => Outcome::Equal,
        (Some(a), _) if legacy_kind(report).as_deref() == Some(a.as_str()) => Outcome::Legacy,
        _ => Outcome::Differs,
    };
    Check {
        field: "kind",
        recorded: recorded.kind.clone(),
        replayed: replayed.kind.clone(),
        outcome,
    }
}

/// The sink when the finding names a function; the reported site when it
/// records none (a UBSan report recorded without frames), or for UBSan, whose
/// signature keys on the site. A replay that names neither a function nor a
/// position (an unsymbolized report) is not comparable, which is not a
/// difference: missing information is not another crash site.
fn check_location(recorded: &Identity, replayed: &Identity) -> Vec<Check> {
    let mut checks = Vec::new();
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
        });
    }
    checks
}

/// Compare a replayed report with the finding record `raw`.
pub(crate) fn compare(raw: &Value, report: &SanitizerReport) -> Comparison {
    let recorded = recorded_identity(raw);
    let replayed = replayed_identity(report);
    let mut checks = vec![
        check_rule(&recorded, report),
        check_kind(&recorded, &replayed, report),
    ];
    checks.extend(check_location(&recorded, &replayed));
    Comparison { checks }
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
    let comparison = compare(&record, fresh);
    comparison.matches()
        && comparison
            .checks
            .iter()
            .all(|check| check.outcome != Outcome::Legacy)
}

/// The finding's recorded sink, rendered, for the replay summary.
pub(crate) fn recorded_sink(raw: &Value) -> Option<String> {
    recorded_identity(raw).sink.map(|sink| sink.render())
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
        let sink = comparison
            .checks
            .iter()
            .find(|check| check.field == "sink")
            .expect("sink check");
        assert_eq!(sink.outcome, Outcome::NotComparable);
        assert!(comparison.compared_line().contains("sink not compared"));
        // A replay that does name another function still differs.
        let comparison = compare(&recorded, &asan(OTHER));
        assert!(!comparison.location_not_compared());
        assert_eq!(comparison.differing_fields(), "sink");
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
