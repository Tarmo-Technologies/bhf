// SPDX-License-Identifier: Apache-2.0

//! Replaying a finding that is not a sanitizer crash. A runtime-oracle hit (a
//! failed assertion, a fuzz-controlled format string, ...), an
//! input-triggered capability and a crash `bhf auto` filed as a format-string
//! bug are confirmed from what the replay did: its runtrace, run through the
//! oracle registry or the capability classifier again, and, for an assertion,
//! the message the C runtime printed before it aborted.

use std::path::{Path, PathBuf};

use finding_rules::oracle_sdk::OracleHit;
use serde_json::Value;

use crate::auto::runtrace::{self, RuntraceEvent};
use crate::crash_identity::{Check, Outcome};

/// The format-string oracle's rule.
const FORMAT_STRING_RULE: &str = "BHF-408";
/// The oracle that reports a failed C/C++ assertion.
const ASSERTION_ORACLE: &str = "native-assertion-contract";

/// What a finding records that a replay can show again without a crash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Recorded {
    /// A runtime-oracle hit: its rule, the API it fired at and the oracle's
    /// site evidence (an assertion's source and expression).
    Oracle {
        rule: String,
        oracle: String,
        api: String,
        site: Vec<(&'static str, String)>,
    },
    /// A crash `bhf auto` filed as the format-string bug at `api`. The crash
    /// reads whatever the format's conversions find in the argument area,
    /// which varies from run to run; the format-string oracle firing at `api`
    /// confirms the bug when the crash itself does not come back.
    FormatStringCrash { api: String },
    /// An input-triggered capability of `kind`, with the operands the
    /// finding's testcase reached.
    Capability { kind: String, operands: Vec<String> },
}

impl Recorded {
    /// What the finding `raw` records for a replay to show again, if it is
    /// one of these findings.
    pub(crate) fn from_finding(raw: &Value) -> Option<Self> {
        let text = |pointer: &str| raw.pointer(pointer).and_then(Value::as_str);
        match text("/classification") {
            Some("oracle_hit") => {
                let oracle = text("/oracle/name")?.to_owned();
                let evidence = raw.pointer("/oracle/evidence").and_then(Value::as_array);
                let site = finding_rules::oracle_manifest::site_keys_for(&oracle)
                    .iter()
                    .filter_map(|key| {
                        let item = evidence?.iter().find(|item| item["key"] == *key)?;
                        Some((*key, item["value"].as_str()?.to_owned()))
                    })
                    .collect();
                Some(Self::Oracle {
                    rule: text("/rule_id")?.to_owned(),
                    oracle,
                    api: text("/oracle/api").unwrap_or_default().to_owned(),
                    site,
                })
            }
            Some("capability") => Some(Self::Capability {
                kind: text("/capability/kind")?.to_owned(),
                operands: raw
                    .pointer("/capability/testcase_operands")
                    .and_then(Value::as_array)
                    .map(|operands| {
                        operands
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
            }),
            _ => text("/format_string/api")
                .filter(|_| text("/rule_id") == Some(FORMAT_STRING_RULE))
                .map(|api| Self::FormatStringCrash {
                    api: api.to_owned(),
                }),
        }
    }

    /// Whether the finding is a crash, compared as one first.
    pub(crate) fn is_crash(&self) -> bool {
        matches!(self, Self::FormatStringCrash { .. })
    }
}

/// What a replay showed of a [`Recorded`] finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Observed {
    /// The recorded fields, each compared with what the replay showed.
    pub(crate) checks: Vec<Check>,
    /// The rule the replay showed, for the status line's `actual=`.
    pub(crate) actual: Option<String>,
    /// How the replay showed it, when that needs saying.
    pub(crate) note: Option<String>,
}

impl Observed {
    /// Whether the replay showed what the finding records.
    pub(crate) fn reproduced(&self) -> bool {
        !self.checks.is_empty()
            && self
                .checks
                .iter()
                .all(|check| matches!(check.outcome, Outcome::Equal | Outcome::NotRecorded))
    }
}

/// What a replay of `recorded`'s testcase `input` showed, from its runtrace
/// `events` and its `stderr`.
pub(crate) fn observe(
    recorded: &Recorded,
    events: &[RuntraceEvent],
    stderr: &str,
    input: &Path,
) -> Observed {
    let mut observed = match recorded {
        Recorded::Oracle {
            rule,
            oracle,
            api,
            site,
        } => observe_oracle(rule, oracle, api, site, events, stderr),
        Recorded::FormatStringCrash { api } => {
            let mut observed = observe_oracle(FORMAT_STRING_RULE, "", api, &[], events, stderr);
            if observed.reproduced() {
                observed.note = Some(format!(
                    "the crash did not come back (its format reads whatever is in the argument \
                     area, which differs from run to run); the format-string oracle fired at \
                     {api}, the call the finding records"
                ));
            }
            observed
        }
        Recorded::Capability { kind, operands } => {
            observe_capability(kind, operands, events, input)
        }
    };
    if events.is_empty() && !observed.reproduced() && observed.note.is_none() {
        observed.note = Some(
            "the replay recorded no runtrace: the runtrace shim did not run in the harness, so \
             no runtime oracle could fire"
                .to_owned(),
        );
    }
    observed
}

fn observe_oracle(
    rule: &str,
    oracle: &str,
    api: &str,
    site: &[(&'static str, String)],
    events: &[RuntraceEvent],
    stderr: &str,
) -> Observed {
    let hits = runtrace::oracle_hits_from_events(events);
    let checks_for = |hit: &OracleHit| {
        let mut checks = vec![equal("rule", rule)];
        checks.push(compared("api", Some(api), Some(&hit.api), api == hit.api));
        for (key, value) in site {
            let replayed = hit.evidence_value(key);
            checks.push(compared(
                key,
                Some(value),
                replayed,
                replayed == Some(value),
            ));
        }
        checks
    };
    // The hit of the recorded rule that agrees with the most recorded fields.
    let closest = hits
        .iter()
        .filter(|hit| hit.rule_id == rule)
        .map(checks_for)
        .min_by_key(|checks| differing(checks));
    if let Some(checks) = closest.as_ref().filter(|checks| differing(checks) == 0) {
        return Observed {
            checks: checks.clone(),
            actual: Some(rule.to_owned()),
            note: None,
        };
    }
    if oracle == ASSERTION_ORACLE {
        if let Some(failure) = corpus::assertion::parse_assertion(stderr) {
            return observe_assertion(rule, site, &failure);
        }
    }
    match closest {
        Some(checks) => Observed {
            checks,
            actual: Some(rule.to_owned()),
            note: None,
        },
        None => Observed {
            checks: vec![compared("rule", Some(rule), None, false)],
            actual: hits.first().map(|hit| hit.rule_id.clone()),
            note: None,
        },
    }
}

/// An assertion failure the runtrace did not record, from the message its
/// runtime printed: the expression is compared as spelled, and the source by
/// its file's last two path components and its line.
fn observe_assertion(
    rule: &str,
    site: &[(&'static str, String)],
    failure: &corpus::assertion::AssertionFailure,
) -> Observed {
    let mut checks = vec![equal("rule", rule)];
    for (key, value) in site {
        checks.push(match *key {
            "expression" => compared(
                key,
                Some(value),
                Some(&failure.expression),
                *value == failure.expression,
            ),
            "source" => {
                let replayed = match (&failure.file, failure.line) {
                    (Some(file), Some(line)) => Some(format!("{file}:{line}")),
                    _ => None,
                };
                let same = match (split_source(value), &failure.file, failure.line) {
                    (Some((file, line)), Some(replayed_file), Some(replayed_line)) => {
                        line == replayed_line && path_tail(file) == path_tail(replayed_file)
                    }
                    _ => false,
                };
                compared(key, Some(value), replayed.as_deref(), same)
            }
            _ => compared(key, Some(value), None, false),
        });
    }
    let runtime = match failure.runtime {
        corpus::assertion::AssertionRuntime::Glibc => "glibc",
        corpus::assertion::AssertionRuntime::Msvc => "Microsoft C runtime",
        corpus::assertion::AssertionRuntime::Bsd => "BSD libc",
        corpus::assertion::AssertionRuntime::Musl => "musl",
    };
    Observed {
        checks,
        actual: Some(rule.to_owned()),
        note: Some(format!(
            "the runtrace recorded no failed assertion; the {runtime} assertion message the \
             harness printed is compared instead"
        )),
    }
}

/// The file and line of an assertion's `file:line[:function]` source.
fn split_source(source: &str) -> Option<(&str, u64)> {
    source.match_indices(':').find_map(|(at, _)| {
        let rest = &source[at + 1..];
        let digits = rest.split(':').next()?;
        let line = digits.parse().ok()?;
        (at > 0).then(|| (&source[..at], line))
    })
}

/// The last two components of `path`, `/` or `\` separated.
fn path_tail(path: &str) -> Vec<&str> {
    let mut parts: Vec<&str> = path.rsplit(['/', '\\']).take(2).collect();
    parts.reverse();
    parts
}

fn observe_capability(
    kind: &str,
    operands: &[String],
    events: &[RuntraceEvent],
    input: &Path,
) -> Observed {
    let reached = crate::auto::capability::operands_reached(events, input, kind);
    let shown = operands.iter().find(|operand| reached.contains(*operand));
    let operand = if operands.is_empty() {
        Check {
            field: "operand",
            recorded: None,
            replayed: reached.iter().next().cloned(),
            outcome: Outcome::NotRecorded,
            why: None,
        }
    } else {
        compared(
            "operand",
            Some(&operands.join(", ")),
            shown.or(reached.iter().next()).map(String::as_str),
            shown.is_some(),
        )
    };
    Observed {
        checks: vec![
            compared(
                "capability",
                Some(kind),
                (!reached.is_empty()).then_some(kind),
                !reached.is_empty(),
            ),
            operand,
        ],
        actual: (!reached.is_empty()).then(|| "BHF-668".to_owned()),
        note: None,
    }
}

fn equal(field: &'static str, value: &str) -> Check {
    compared(field, Some(value), Some(value), true)
}

fn compared(
    field: &'static str,
    recorded: Option<&str>,
    replayed: Option<&str>,
    same: bool,
) -> Check {
    Check {
        field,
        recorded: recorded.map(str::to_owned),
        replayed: replayed.map(str::to_owned),
        outcome: if same {
            Outcome::Equal
        } else {
            Outcome::Differs
        },
        why: None,
    }
}

fn differing(checks: &[Check]) -> usize {
    checks
        .iter()
        .filter(|check| check.outcome == Outcome::Differs)
        .count()
}

/// A runtrace log for one replay, in a scratch directory removed with it.
pub(crate) struct RuntraceLog {
    dir: tempfile::TempDir,
}

impl RuntraceLog {
    pub(crate) fn create() -> Result<Self, String> {
        tempfile::Builder::new()
            .prefix("bhf-replay-")
            .tempdir()
            .map(|dir| Self { dir })
            .map_err(|error| format!("create the replay's runtrace dir: {error}"))
    }

    pub(crate) fn path(&self) -> PathBuf {
        self.dir.path().join("runtrace.jsonl")
    }

    /// The events the replay recorded, each once.
    pub(crate) fn events(&self) -> Vec<RuntraceEvent> {
        let mut events = runtrace::parse_log(&self.path()).unwrap_or_default();
        runtrace::dedupe_in_place(&mut events);
        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SOURCE: &str = "/src/fmt.c:14:int check_header(const unsigned char *, size_t)";

    fn assertion_finding() -> Value {
        json!({
            "rule_id": "BHF-415",
            "classification": "oracle_hit",
            "oracle": {
                "name": "native-assertion-contract",
                "api": "__assert_fail",
                "evidence": [
                    {"key": "exception", "value": "AssertionFailure"},
                    {"key": "expression", "value": "data[0] != 'Z'"},
                    {"key": "source", "value": SOURCE},
                ],
            },
        })
    }

    fn failed_assertion(line: i64) -> RuntraceEvent {
        runtrace::parse_str(&format!(
            "{{\"e\":\"assertion_failed\",\"a\":\"__assert_fail\",\"x\":\"data[0] != 'Z'\",\
             \"f\":\"/src/fmt.c\",\"n\":{line},\"g\":\"int check_header(const unsigned char *, \
             size_t)\"}}\n"
        ))
        .remove(0)
    }

    #[test]
    fn an_oracle_finding_records_its_rule_api_and_site() {
        let recorded = Recorded::from_finding(&assertion_finding()).unwrap();
        assert_eq!(
            recorded,
            Recorded::Oracle {
                rule: "BHF-415".to_owned(),
                oracle: "native-assertion-contract".to_owned(),
                api: "__assert_fail".to_owned(),
                site: vec![
                    ("source", SOURCE.to_owned()),
                    ("expression", "data[0] != 'Z'".to_owned()),
                ],
            }
        );
        let crash = json!({"rule_id": "BHF-201", "classification": "unhandled"});
        assert_eq!(Recorded::from_finding(&crash), None);
    }

    #[test]
    fn the_same_assertion_in_the_runtrace_reproduces_the_finding() {
        let recorded = Recorded::from_finding(&assertion_finding()).unwrap();
        let observed = observe(&recorded, &[failed_assertion(14)], "", Path::new("t"));
        assert!(observed.reproduced(), "{observed:?}");

        let observed = observe(&recorded, &[failed_assertion(15)], "", Path::new("t"));
        assert!(!observed.reproduced());
        let differs: Vec<&str> = observed
            .checks
            .iter()
            .filter(|check| check.outcome == Outcome::Differs)
            .map(|check| check.field)
            .collect();
        assert_eq!(differs, ["source"]);
    }

    #[test]
    fn without_a_runtrace_the_runtime_assertion_message_is_compared() {
        let recorded = Recorded::from_finding(&assertion_finding()).unwrap();
        let glibc = "main: /work/src/fmt.c:14: int check_header(const unsigned char *, size_t): \
                     Assertion `data[0] != 'Z'' failed.\n";
        let observed = observe(&recorded, &[], glibc, Path::new("t"));
        assert!(observed.reproduced(), "{observed:?}");
        assert!(observed.note.as_deref().unwrap().contains("glibc"));

        let msvc = "Assertion failed: data[0] != 'Z', file C:\\src\\fmt.c, line 14\r\n";
        assert!(observe(&recorded, &[], msvc, Path::new("t")).reproduced());

        let other_line = "Assertion failed: data[0] != 'Z', file C:\\src\\fmt.c, line 20\r\n";
        assert!(!observe(&recorded, &[], other_line, Path::new("t")).reproduced());
        let other_expression = "Assertion failed: len > 1, file C:\\src\\fmt.c, line 14\r\n";
        assert!(!observe(&recorded, &[], other_expression, Path::new("t")).reproduced());
    }

    #[test]
    fn no_oracle_firing_is_a_rule_difference() {
        let recorded = Recorded::from_finding(&assertion_finding()).unwrap();
        let observed = observe(&recorded, &[], "", Path::new("t"));
        assert!(!observed.reproduced());
        assert_eq!(observed.checks[0].field, "rule");
        assert_eq!(observed.checks[0].replayed, None);
        assert!(observed.note.as_deref().unwrap().contains("no runtrace"));
    }

    fn controlled_format(api: &str) -> RuntraceEvent {
        RuntraceEvent::FormatString {
            api: api.to_owned(),
            format: "%n%n".to_owned(),
            controlled: true,
        }
    }

    #[test]
    fn a_format_string_crash_is_confirmed_by_the_oracle_at_its_call() {
        let raw = json!({
            "rule_id": "BHF-408",
            "classification": "unhandled",
            "format_string": {"api": "snprintf", "crash_rule_id": "BHF-206"},
        });
        let recorded = Recorded::from_finding(&raw).unwrap();
        assert!(recorded.is_crash());
        let observed = observe(
            &recorded,
            &[controlled_format("snprintf")],
            "",
            Path::new("t"),
        );
        assert!(observed.reproduced(), "{observed:?}");
        assert!(observed.note.as_deref().unwrap().contains("snprintf"));
        let elsewhere = observe(
            &recorded,
            &[controlled_format("printf")],
            "",
            Path::new("t"),
        );
        assert!(!elsewhere.reproduced());
    }

    #[test]
    fn a_capability_finding_is_shown_by_an_operand_its_testcase_reached() {
        let raw = json!({
            "rule_id": "BHF-668",
            "classification": "capability",
            "capability": {"kind": "process-exec", "testcase_operands": ["id"]},
        });
        let recorded = Recorded::from_finding(&raw).unwrap();
        let exec = |command: &str| RuntraceEvent::CommandExecuted {
            api: "system".to_owned(),
            command: command.to_owned(),
            taint_offset: None,
        };
        let observed = observe(&recorded, &[exec("id")], "", Path::new("t"));
        assert!(observed.reproduced(), "{observed:?}");
        assert_eq!(observed.actual.as_deref(), Some("BHF-668"));
        let other = observe(&recorded, &[exec("ls")], "", Path::new("t"));
        assert!(!other.reproduced());
        assert_eq!(other.checks[1].replayed.as_deref(), Some("ls"));
    }

    #[test]
    fn a_source_splits_at_its_line() {
        assert_eq!(split_source(SOURCE), Some(("/src/fmt.c", 14)));
        assert_eq!(
            split_source("C:\\src\\fmt.c:14:check"),
            Some(("C:\\src\\fmt.c", 14))
        );
        assert_eq!(split_source("fmt.c:9"), Some(("fmt.c", 9)));
        assert_eq!(path_tail("C:\\src\\fmt.c"), ["src", "fmt.c"]);
        assert_eq!(path_tail("/work/src/fmt.c"), ["src", "fmt.c"]);
    }
}
