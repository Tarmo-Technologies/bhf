// SPDX-License-Identifier: Apache-2.0

//! What an Ada (event-log) testcase raised and where, for a reader: the
//! exception's name and message, where it was raised and where it was
//! handled. A replay compares signatures; this is what those signatures stand
//! for.

use corpus::SourceLineMaps;
use corpus::{classify, compute_signature, resolve_handler, Classification, Signature};
use event_log::{HandlerEvent, RaiseEvent, Testcase};
use serde::Serialize;
use serde_json::Value;

/// One exception a testcase's event log reports reaching a handler, or the
/// harness unhandled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RaisedException {
    /// The event-log signature it gives a finding.
    pub signature: Signature,
    pub classification: Classification,
    /// The exception's name (`CONSTRAINT_ERROR`).
    pub name: String,
    /// Its message, with instrumented-copy lines mapped back to the source
    /// when the line maps are known.
    pub message: String,
    /// `file:line` it was raised at: the explicit raise the event log
    /// records for it, or the location GNAT puts first in its message (a
    /// failed runtime check's, or a `raise` without a message). `None` when
    /// neither says.
    pub raised_at: Option<String>,
    /// `file:line` of the handler that caught it; `None` when it escaped to
    /// the harness unhandled.
    pub handled_at: Option<String>,
    pub target_id: u32,
    pub last_breadcrumb: u32,
}

impl RaisedException {
    /// Describe the exception `handler` reports in `testcase`, rewriting its
    /// message's instrumented lines through `line_maps`.
    pub fn from_event(
        testcase: &Testcase,
        handler: &HandlerEvent,
        classification: Classification,
        line_maps: &SourceLineMaps,
    ) -> Self {
        let (message, _) = line_maps.remap_message(&handler.exception_message);
        Self::describe(
            compute_signature(testcase, handler),
            classification,
            handler,
            &testcase.raises,
            message,
        )
    }

    /// The exception a finding.json bhf recorded describes: its `handler`,
    /// `raises`, `classification` and `signature`, and the `exception`
    /// message (already mapped back to the source when it was recorded).
    /// `None` for a finding without them (one written by hand with only a
    /// signature).
    pub fn from_finding(finding: &Value) -> Option<Self> {
        let handler: HandlerEvent = serde_json::from_value(finding.get("handler")?.clone()).ok()?;
        let classification: Classification =
            serde_json::from_value(finding.get("classification")?.clone()).ok()?;
        let signature: Signature =
            serde_json::from_value(finding.get("signature")?.clone()).ok()?;
        let raises: Vec<RaiseEvent> = finding
            .get("raises")
            .cloned()
            .and_then(|raises| serde_json::from_value(raises).ok())
            .unwrap_or_default();
        let message = finding
            .pointer("/exception/message")
            .and_then(Value::as_str)
            .map_or_else(|| handler.exception_message.clone(), str::to_owned);
        Some(Self::describe(
            signature,
            classification,
            &handler,
            &raises,
            message,
        ))
    }

    fn describe(
        signature: Signature,
        classification: Classification,
        handler: &HandlerEvent,
        raises: &[RaiseEvent],
        message: String,
    ) -> Self {
        let raised_at = matching_raise(raises, handler)
            .map(|raise| format!("{}:{}", raise.file, raise.line))
            .or_else(|| message_location(&message));
        let handled_at = (handler.handler_file != UNHANDLED_FILE)
            .then(|| format!("{}:{}", handler.handler_file, handler.handler_line));
        Self {
            signature,
            classification,
            name: handler.exception_name.clone(),
            message,
            raised_at,
            handled_at,
            target_id: handler.target_id,
            last_breadcrumb: handler.last_breadcrumb,
        }
    }

    /// `NAME: message`, or the name alone when there is no message.
    pub fn what(&self) -> String {
        if self.message.is_empty() {
            self.name.clone()
        } else {
            format!("{}: {}", self.name, self.message)
        }
    }

    /// Where it was raised and handled, as one phrase.
    pub fn where_text(&self) -> String {
        let raised = self.raised_at.as_deref().map_or_else(
            || "raised at an unknown location".to_owned(),
            |site| format!("raised at {site}"),
        );
        format!("{raised}; {}", self.handled_text())
    }

    /// Where it was handled, as a phrase.
    pub fn handled_text(&self) -> String {
        self.handled_at.as_deref().map_or_else(
            || "not handled: it reached the harness".to_owned(),
            |site| format!("handled at {site}"),
        )
    }
}

/// The handler file the event log gives an exception that escaped the target.
const UNHANDLED_FILE: &str = "<unhandled>";

/// The explicit raise `handler` caught: the last raise of the same exception
/// before it, as the signature counts it.
fn matching_raise<'a>(raises: &'a [RaiseEvent], handler: &HandlerEvent) -> Option<&'a RaiseEvent> {
    raises
        .iter()
        .filter(|raise| {
            raise.sequence_index < handler.sequence_index
                && raise
                    .exception_name
                    .eq_ignore_ascii_case(&handler.exception_name)
        })
        .max_by_key(|raise| raise.sequence_index)
}

/// The `file.adb:LINE` GNAT puts at the start of an exception message (a
/// failed runtime check's `file.adb:12 index check failed`, or a bare
/// `raise`'s `file.adb:12`).
fn message_location(message: &str) -> Option<String> {
    let token = message.split_whitespace().next()?;
    let (file, line) = token.rsplit_once(':')?;
    let (stem, extension) = file.rsplit_once('.')?;
    let source = ["adb", "ads", "ada"]
        .iter()
        .any(|known| extension.eq_ignore_ascii_case(known));
    let stem_ok = !stem.is_empty()
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'));
    let line_ok = !line.is_empty() && line.bytes().all(|byte| byte.is_ascii_digit());
    (source && stem_ok && line_ok).then(|| token.to_owned())
}

/// The exception in `replayed` closest to `recorded`: the one a mismatch is
/// described against. The same exception (by name) comes first, and among
/// those the one with the same classification and handler, then either, then
/// the same raise site; after that one that reached the harness unhandled,
/// then the first in event-log order. Without a recorded description only
/// the last two apply. `None` when the replay raised none.
pub fn closest_to<'a>(
    recorded: Option<&RaisedException>,
    replayed: &'a [RaisedException],
) -> Option<&'a RaisedException> {
    replayed
        .iter()
        .enumerate()
        .min_by_key(|(index, raised)| {
            let same = recorded.filter(|recorded| recorded.name.eq_ignore_ascii_case(&raised.name));
            let disagreements = same.map_or(0, |recorded| {
                u8::from(recorded.classification != raised.classification)
                    + u8::from(recorded.handled_at != raised.handled_at)
            });
            let other_site = same.is_some_and(|recorded| recorded.raised_at != raised.raised_at);
            (
                same.is_none(),
                disagreements,
                other_site,
                raised.handled_at.is_some(),
                *index,
            )
        })
        .map(|(_, raised)| raised)
}

/// Every exception `testcases` raised, in the order (and with the signatures)
/// a replay compares them.
pub fn raised_exceptions(
    testcases: &[Testcase],
    line_maps: &SourceLineMaps,
) -> Vec<RaisedException> {
    let mut raised = Vec::new();
    for testcase in testcases {
        for (handler_index, classification) in classify(testcase) {
            let Some(handler) = resolve_handler(testcase, handler_index) else {
                continue;
            };
            raised.push(RaisedException::from_event(
                testcase,
                handler.as_ref(),
                classification,
                line_maps,
            ));
        }
    }
    raised
}

#[cfg(test)]
mod tests {
    use super::*;
    use corpus::UNHANDLED_HANDLER_INDEX;
    use event_log::TopLevelEvent;
    use std::path::PathBuf;

    fn escaped_testcase() -> Testcase {
        Testcase {
            testcase_id: 9,
            target_id: 0,
            target_entered: true,
            crumbs: vec![1],
            handlers: Vec::new(),
            raises: vec![RaiseEvent {
                sequence_index: 4,
                exception_name: "Program_Error".to_owned(),
                file: "widgets.adb".to_owned(),
                line: 6,
                breadcrumb: 1,
            }],
            top_level: Some(TopLevelEvent {
                exception_name: "PROGRAM_ERROR".to_owned(),
                exception_message: "empty record".to_owned(),
            }),
            end: None,
            mocks: Vec::new(),
        }
    }

    fn handled_check_testcase() -> Testcase {
        Testcase {
            testcase_id: 3,
            target_id: 7,
            target_entered: true,
            crumbs: vec![1, 2],
            handlers: vec![HandlerEvent {
                sequence_index: 5,
                exception_name: "CONSTRAINT_ERROR".to_owned(),
                exception_message: "widgets.adb:16 index check failed".to_owned(),
                handler_file: "widgets.adb".to_owned(),
                handler_line: 11,
                last_breadcrumb: 2,
                target_id: 7,
                testcase_id: 3,
            }],
            raises: Vec::new(),
            top_level: None,
            end: None,
            mocks: Vec::new(),
        }
    }

    /// Line maps that put instrumented line 16 of widgets.adb at source
    /// line 8.
    fn widget_line_maps() -> (tempfile::TempDir, PathBuf, SourceLineMaps) {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        // Removed when this scope ends.
        let dir_tmp = tempfile::Builder::new()
            .prefix("bhf-")
            .tempdir()
            .expect("create test dir");
        let dir = dir_tmp.path().join(format!("bhf-raised-maps-{nonce}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("widgets.adb.bhf-lines.json"),
            r#"{"source_path": "/src/widgets.adb", "anchors": [[1, 1], [16, 8]]}"#,
        )
        .unwrap();
        let maps = SourceLineMaps::load(&dir);
        assert!(!maps.is_empty());
        (dir_tmp, dir, maps)
    }

    #[test]
    fn an_escaped_explicit_raise_names_its_raise_and_no_handler() {
        let raised = raised_exceptions(&[escaped_testcase()], &SourceLineMaps::default());
        assert_eq!(raised.len(), 1, "{raised:?}");
        let exception = &raised[0];
        assert_eq!(exception.name, "PROGRAM_ERROR");
        assert_eq!(exception.message, "empty record");
        assert_eq!(exception.classification, Classification::Unhandled);
        assert_eq!(exception.raised_at.as_deref(), Some("widgets.adb:6"));
        assert_eq!(exception.handled_at, None);
        assert_eq!(exception.what(), "PROGRAM_ERROR: empty record");
        assert_eq!(
            exception.where_text(),
            "raised at widgets.adb:6; not handled: it reached the harness"
        );
        let testcase = escaped_testcase();
        let handler = resolve_handler(&testcase, UNHANDLED_HANDLER_INDEX).unwrap();
        assert_eq!(
            exception.signature,
            compute_signature(&testcase, handler.as_ref())
        );
    }

    /// A failed runtime check has no raise event; GNAT's message names the
    /// (instrumented) line, which the line maps put back at the source line.
    #[test]
    fn a_runtime_check_is_located_by_its_message_on_the_source_line() {
        let (_dir_guard, dir, maps) = widget_line_maps();
        let raised = raised_exceptions(&[handled_check_testcase()], &maps);
        assert_eq!(raised.len(), 1, "{raised:?}");
        let exception = &raised[0];
        assert_eq!(exception.message, "widgets.adb:8 index check failed");
        assert_eq!(exception.raised_at.as_deref(), Some("widgets.adb:8"));
        assert_eq!(exception.handled_at.as_deref(), Some("widgets.adb:11"));
        assert_eq!(
            exception.classification,
            Classification::SwallowedPredefined
        );
        // Without the maps, the instrumented line is all there is.
        let raw = raised_exceptions(&[handled_check_testcase()], &SourceLineMaps::default());
        assert_eq!(raw[0].raised_at.as_deref(), Some("widgets.adb:16"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn exception(
        name: &str,
        classification: Classification,
        raised_at: &str,
        handled_at: Option<&str>,
    ) -> RaisedException {
        RaisedException {
            signature: Signature([0; 32]),
            classification,
            name: name.to_owned(),
            message: String::new(),
            raised_at: Some(raised_at.to_owned()),
            handled_at: handled_at.map(str::to_owned),
            target_id: 7,
            last_breadcrumb: 1,
        }
    }

    /// Which replayed exception a mismatch is described against, by
    /// closeness to the recorded one rather than by position.
    #[test]
    fn the_closest_replayed_exception_is_the_one_most_like_the_recorded() {
        use Classification::{ExplicitRaise, SwallowedPredefined, SwallowedUser, Unhandled};
        let recorded = exception("CONSTRAINT_ERROR", Unhandled, "widgets.adb:19", None);
        let handled_user = exception(
            "WIDGET_ERROR",
            ExplicitRaise,
            "widgets.adb:17",
            Some("widgets.adb:21"),
        );
        let escaped = exception("CONSTRAINT_ERROR", Unhandled, "widgets.adb:22", None);
        let caught_check = exception(
            "CONSTRAINT_ERROR",
            SwallowedPredefined,
            "widgets.adb:19",
            Some("widgets.adb:30"),
        );
        let escaped_other = exception("PROGRAM_ERROR", Unhandled, "widgets.adb:40", None);
        let pick = |replayed: &[RaisedException]| {
            closest_to(Some(&recorded), replayed).map(|picked| {
                replayed
                    .iter()
                    .position(|raised| std::ptr::eq(raised, picked))
                    .unwrap()
            })
        };

        // The same exception, reaching the harness like the recorded one,
        // wins over an earlier handled one and over a caught one that shares
        // only the raise site.
        assert_eq!(pick(&[handled_user.clone(), escaped.clone()]), Some(1));
        assert_eq!(
            pick(&[caught_check.clone(), handled_user.clone(), escaped.clone()]),
            Some(2)
        );
        // The same name, even caught, beats another exception.
        assert_eq!(
            pick(&[escaped_other.clone(), caught_check.clone()]),
            Some(1)
        );
        // With the same name and agreement, the same raise site decides.
        let same_site = exception("CONSTRAINT_ERROR", Unhandled, "widgets.adb:19", None);
        assert_eq!(pick(&[escaped.clone(), same_site]), Some(1));
        // No same name: one that reached the harness, then the first.
        assert_eq!(
            pick(&[handled_user.clone(), escaped_other.clone()]),
            Some(1)
        );
        let other_caught = exception(
            "STORAGE_ERROR",
            SwallowedUser,
            "widgets.adb:5",
            Some("widgets.adb:6"),
        );
        assert_eq!(pick(&[handled_user.clone(), other_caught]), Some(0));
        // Nothing recorded to compare with: one that reached the harness.
        assert!(std::ptr::eq(
            closest_to(None, std::slice::from_ref(&escaped_other)).unwrap(),
            &escaped_other
        ));
        let replayed = [handled_user, escaped_other];
        assert!(std::ptr::eq(
            closest_to(None, &replayed).unwrap(),
            &replayed[1]
        ));
        assert_eq!(closest_to(Some(&recorded), &[]), None);
    }

    #[test]
    fn only_a_leading_source_location_is_a_raise_site() {
        assert_eq!(
            message_location("widgets.adb:12 range check failed").as_deref(),
            Some("widgets.adb:12")
        );
        assert_eq!(
            message_location("a-strunb.adb:340").as_deref(),
            Some("a-strunb.adb:340")
        );
        assert_eq!(message_location("empty record"), None);
        assert_eq!(message_location("len:40 too long"), None);
        assert_eq!(message_location("see widgets.adb:12"), None);
        assert_eq!(message_location("widgets.adb:x"), None);
        assert_eq!(message_location(""), None);
    }

    /// The recorded side reads the same description from finding.json, with
    /// the message as recorded (already mapped back to the source).
    #[test]
    fn the_recorded_exception_is_read_from_the_finding() {
        let testcase = escaped_testcase();
        let handler = resolve_handler(&testcase, UNHANDLED_HANDLER_INDEX).unwrap();
        let signature = compute_signature(&testcase, handler.as_ref());
        let finding = serde_json::json!({
            "signature": signature.hex(),
            "classification": "unhandled",
            "handler": handler.as_ref(),
            "raises": testcase.raises,
            "exception": {"name": "PROGRAM_ERROR", "message": "empty record"},
        });
        let recorded = RaisedException::from_finding(&finding).expect("described");
        let replayed =
            raised_exceptions(std::slice::from_ref(&testcase), &SourceLineMaps::default());
        assert_eq!(recorded, replayed[0]);

        let mut check = serde_json::json!({
            "signature": signature.hex(),
            "classification": "swallowed_predefined",
            "handler": handled_check_testcase().handlers[0],
            "raises": [],
            "exception": {"name": "CONSTRAINT_ERROR", "message": "widgets.adb:8 index check failed"},
        });
        let recorded = RaisedException::from_finding(&check).expect("described");
        assert_eq!(recorded.raised_at.as_deref(), Some("widgets.adb:8"));
        assert_eq!(recorded.handled_at.as_deref(), Some("widgets.adb:11"));
        assert_eq!(recorded.message, "widgets.adb:8 index check failed");

        // A finding with only a signature says nothing about the exception.
        check = serde_json::json!({"signature": signature.hex()});
        assert_eq!(RaisedException::from_finding(&check), None);
    }
}
