// SPDX-License-Identifier: Apache-2.0

//! Driving a session against a request/response transport, plus replay and
//! minimization — all pure, with the socket/process backend kept behind the
//! [`SessionTransport`] trait and an in-memory [`ScriptedTransport`] for tests.
//!
//! The live TCP backend and the CLI campaign loop live in the `bhf` binary
//! crate, not here, so this crate stays hardware-free and unit-testable. The
//! runner encodes each structured message (resolving references + repairing
//! derived fields), sends it, reads the reply, extracts the declared response
//! captures into the binding table, walks the protocol state graph, and asks a
//! [`SessionOracle`] whether a (crash-free) security violation occurred.

use std::collections::BTreeMap;

use ada_state_machine::adapter::StateId;

use crate::binding::{Bindings, BoundValue};
use crate::model::{EncodeError, ProtocolModel};
use crate::novelty::TransitionId;
use crate::profile::OracleDef;
use crate::response::{extract, ResponseError};
use crate::testcase::{encode_message, MessageInstance, SessionTestcase};

/// A request/response transport to a target. The only live I/O seam; a drive
/// never touches sockets directly.
pub trait SessionTransport {
    /// Send one framed request and return the reply bytes.
    fn send_request(&mut self, request: &[u8]) -> Result<Vec<u8>, TransportError>;
    /// Reset the session (e.g. reconnect), giving the target fresh per-session
    /// state so a later request captures a *new* handle / id / nonce.
    fn reset(&mut self) -> Result<(), TransportError>;
}

/// A transport-layer failure. Carries a bounded, descriptive message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("session transport error: {message}")]
pub struct TransportError {
    pub message: String,
}

impl TransportError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// An in-memory transport that replays scripted replies. Each "session" is a
/// queue of replies returned in order; [`reset`](SessionTransport::reset)
/// advances to the next scripted session, so a second drive (a replay) can be
/// handed different reply values (e.g. a different handle).
#[derive(Debug, Clone)]
pub struct ScriptedTransport {
    sessions: Vec<Vec<Vec<u8>>>,
    active: Option<usize>,
    resets: usize,
    step: usize,
}

impl ScriptedTransport {
    /// A single-session transport returning `replies` in order.
    pub fn single(replies: Vec<Vec<u8>>) -> Self {
        Self::new(vec![replies])
    }

    /// A multi-session transport; the Nth `reset` selects the Nth session
    /// (saturating at the last).
    pub fn new(sessions: Vec<Vec<Vec<u8>>>) -> Self {
        Self {
            sessions,
            active: None,
            resets: 0,
            step: 0,
        }
    }

    pub fn resets(&self) -> usize {
        self.resets
    }
}

impl SessionTransport for ScriptedTransport {
    fn send_request(&mut self, _request: &[u8]) -> Result<Vec<u8>, TransportError> {
        let session = self
            .active
            .ok_or_else(|| TransportError::new("transport used before reset"))?;
        let replies = self
            .sessions
            .get(session)
            .ok_or_else(|| TransportError::new("no scripted session"))?;
        let reply = replies.get(self.step).ok_or_else(|| {
            TransportError::new(format!("no scripted reply for step {}", self.step))
        })?;
        self.step += 1;
        Ok(reply.clone())
    }

    fn reset(&mut self) -> Result<(), TransportError> {
        if self.sessions.is_empty() {
            return Err(TransportError::new("no scripted sessions"));
        }
        let idx = self.resets.min(self.sessions.len() - 1);
        self.active = Some(idx);
        self.resets += 1;
        self.step = 0;
        Ok(())
    }
}

/// The verdict of a session drive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionVerdict {
    /// No oracle fired.
    Clean,
    /// An oracle fired — a security violation that exits cleanly (no crash).
    Finding {
        oracle: String,
        rule_id: Option<String>,
        message: String,
        detail: String,
    },
}

impl SessionVerdict {
    pub fn is_finding(&self) -> bool {
        matches!(self, SessionVerdict::Finding { .. })
    }
}

/// The profile-declared oracle: it flags a finding on a response-condition
/// match (a sentinel value in a captured response field) or on arrival in a
/// declared violation state. Deliberately a plain verdict with no dependency on
/// any external finding/oracle SDK — the CLI maps a finding verdict onto its
/// finding emitter.
pub struct SessionOracle<'a> {
    oracles: &'a [OracleDef],
}

impl<'a> SessionOracle<'a> {
    pub fn new(oracles: &'a [OracleDef]) -> Self {
        Self { oracles }
    }

    /// Evaluate the oracles after one message's reply has been captured and the
    /// state advanced.
    pub fn evaluate(
        &self,
        message: &str,
        captures: &BTreeMap<String, BoundValue>,
        state: &str,
    ) -> SessionVerdict {
        for oracle in self.oracles {
            // Response-condition oracle.
            if let (Some(field), Some(equals)) = (&oracle.response_field, oracle.equals) {
                let applies = oracle.message.as_deref().is_none_or(|m| m == message);
                if applies {
                    if let Some(value) = captures.get(field).and_then(BoundValue::as_u64) {
                        if value == equals {
                            return SessionVerdict::Finding {
                                oracle: oracle.name.clone(),
                                rule_id: oracle.rule_id.clone(),
                                message: message.to_owned(),
                                detail: format!("{field}={value} matched sentinel {equals}"),
                            };
                        }
                    }
                }
            }
            // Violation-state oracle.
            if let Some(violation) = &oracle.violation_state {
                if violation == state {
                    return SessionVerdict::Finding {
                        oracle: oracle.name.clone(),
                        rule_id: oracle.rule_id.clone(),
                        message: message.to_owned(),
                        detail: format!("entered violation state {state:?}"),
                    };
                }
            }
        }
        SessionVerdict::Clean
    }
}

/// The result of driving a session: the testcase with run-time evidence filled
/// in, the oracle verdict, and the state/transition trace for novelty tracking.
#[derive(Debug, Clone)]
pub struct SessionRun {
    pub testcase: SessionTestcase,
    pub verdict: SessionVerdict,
    pub state_ids: Vec<StateId>,
    pub transitions: Vec<TransitionId>,
    /// The framed request bytes sent per step (diagnostic / for replay checks).
    pub sent_frames: Vec<Vec<u8>>,
}

/// Drives, replays, and minimizes sessions against a [`SessionTransport`].
pub struct SessionRunner<'a> {
    model: &'a ProtocolModel,
}

impl<'a> SessionRunner<'a> {
    pub fn new(model: &'a ProtocolModel) -> Self {
        Self { model }
    }

    /// Drive a message sequence against `transport`, capturing responses,
    /// resolving references, walking the state graph, and evaluating the oracle.
    pub fn drive(
        &self,
        messages: &[MessageInstance],
        transport: &mut dyn SessionTransport,
    ) -> Result<SessionRun, RunnerError> {
        transport.reset().map_err(RunnerError::Transport)?;

        let graph = self.model.graph();
        let oracle = SessionOracle::new(self.model.oracles());
        let mut cur = graph.initial();
        let mut bindings = Bindings::new();
        let mut state_ids = vec![cur];
        let mut state_path = vec![graph.state_name(cur).unwrap_or("?").to_owned()];
        let mut transitions = Vec::new();
        let mut captured_responses = Vec::new();
        let mut sent_frames = Vec::new();
        let mut verdict = SessionVerdict::Clean;

        for instance in messages {
            let compiled = self.model.message(&instance.message).ok_or_else(|| {
                RunnerError::UnknownMessage {
                    name: instance.message.clone(),
                }
            })?;
            let next = graph.next_state(cur, &instance.message).ok_or_else(|| {
                RunnerError::IllegalTransition {
                    message: instance.message.clone(),
                    state: graph.state_name(cur).unwrap_or("?").to_owned(),
                }
            })?;

            let frame = encode_message(self.model, instance, &bindings)
                .map_err(RunnerError::Encode)?
                .into_bytes();
            sent_frames.push(frame.clone());

            let reply = transport
                .send_request(&frame)
                .map_err(RunnerError::Transport)?;
            captured_responses.push(reply.clone());

            let captures = extract(&instance.message, &compiled.response, &reply)
                .map_err(RunnerError::Response)?;
            let mut local: BTreeMap<String, BoundValue> = BTreeMap::new();
            for (capture, (source, value)) in compiled.response.iter().zip(captures.iter()) {
                bindings.bind(source.clone(), value.clone());
                local.insert(capture.name.clone(), value.clone());
            }

            transitions.push((cur, instance.message.clone(), next));
            cur = next;
            state_ids.push(cur);
            let state_name = graph.state_name(cur).unwrap_or("?").to_owned();
            state_path.push(state_name.clone());

            let step_verdict = oracle.evaluate(&instance.message, &local, &state_name);
            if step_verdict.is_finding() {
                verdict = step_verdict;
                break;
            }
        }

        let testcase = SessionTestcase {
            profile_sha256: self.model.profile_sha256().to_owned(),
            messages: messages.to_vec(),
            state_path,
            captured_responses,
            bindings,
        };
        Ok(SessionRun {
            testcase,
            verdict,
            state_ids,
            transitions,
            sent_frames,
        })
    }

    /// Re-drive a recorded testcase against a freshly reset transport. The
    /// references are re-resolved from the *new* responses, so the session still
    /// reproduces even when the target returns a different handle — the recorded
    /// binding snapshot is never reused.
    pub fn replay(
        &self,
        testcase: &SessionTestcase,
        transport: &mut dyn SessionTransport,
    ) -> Result<SessionRun, RunnerError> {
        self.drive(&testcase.messages, transport)
    }

    /// Minimize a reproducing testcase: shrink the message sequence (delta
    /// debugging), then shrink each bytes field, re-repairing computed fields
    /// and re-resolving bindings on every candidate (the `predicate` re-drives).
    /// The smallest still-reproducing testcase is returned.
    pub fn minimize<F>(&self, testcase: &SessionTestcase, mut predicate: F) -> SessionTestcase
    where
        F: FnMut(&SessionTestcase) -> bool,
    {
        let sha = testcase.profile_sha256.clone();
        let base = testcase.messages.clone();

        // 1. Sequence ddmin.
        let kept = ddmin(base.len(), |idxs| {
            let msgs = idxs.iter().map(|&i| base[i].clone()).collect();
            predicate(&SessionTestcase::from_messages(&sha, msgs))
        });
        let mut messages: Vec<MessageInstance> = kept.iter().map(|&i| base[i].clone()).collect();

        // 2. Per-field byte ddmin over bytes-typed data fields.
        for mi in 0..messages.len() {
            let byte_fields = self.bytes_field_names(&messages[mi]);
            for field in byte_fields {
                let Some(crate::model::FieldValue::Bytes { value: original }) =
                    messages[mi].get(&field).cloned()
                else {
                    continue;
                };
                let kept = ddmin(original.len(), |idxs| {
                    let bytes: Vec<u8> = idxs.iter().map(|&i| original[i]).collect();
                    let mut candidate = messages.clone();
                    candidate[mi].set(&field, crate::model::FieldValue::Bytes { value: bytes });
                    predicate(&SessionTestcase::from_messages(&sha, candidate))
                });
                let bytes: Vec<u8> = kept.iter().map(|&i| original[i]).collect();
                messages[mi].set(&field, crate::model::FieldValue::Bytes { value: bytes });
            }
        }

        let mut result = SessionTestcase::from_messages(&sha, messages);
        result.state_path = self.state_path_names(&result.message_names());
        result
    }

    fn bytes_field_names(&self, instance: &MessageInstance) -> Vec<String> {
        let Some(compiled) = self.model.message(&instance.message) else {
            return Vec::new();
        };
        instance
            .fields
            .iter()
            .filter(|a| {
                compiled.data_field(&a.name).is_some_and(|f| {
                    matches!(
                        f.role,
                        crate::model::FieldRole::Data(crate::model::DataSpec::Bytes { .. })
                    )
                })
            })
            .map(|a| a.name.clone())
            .collect()
    }

    fn state_path_names(&self, names: &[&str]) -> Vec<String> {
        let graph = self.model.graph();
        let mut cur = graph.initial();
        let mut path = vec![graph.state_name(cur).unwrap_or("?").to_owned()];
        for &name in names {
            match graph.next_state(cur, name) {
                Some(next) => {
                    cur = next;
                    path.push(graph.state_name(cur).unwrap_or("?").to_owned());
                }
                None => break,
            }
        }
        path
    }
}

/// Delta-debugging minimization over `0..n`: returns the smallest index subset
/// (ascending) for which `test` holds, by repeatedly removing complements.
fn ddmin<F: FnMut(&[usize]) -> bool>(n: usize, mut test: F) -> Vec<usize> {
    let mut kept: Vec<usize> = (0..n).collect();
    let mut granularity = 2usize;
    while kept.len() >= 2 {
        let subset_size = kept.len().div_ceil(granularity);
        let mut reduced = false;
        let mut start = 0;
        while start < kept.len() {
            let end = (start + subset_size).min(kept.len());
            let complement: Vec<usize> = kept[..start]
                .iter()
                .chain(kept[end..].iter())
                .copied()
                .collect();
            if !complement.is_empty() && test(&complement) {
                kept = complement;
                granularity = granularity.saturating_sub(1).max(2);
                reduced = true;
                break;
            }
            start = end;
        }
        if !reduced {
            if granularity >= kept.len() {
                break;
            }
            granularity = (granularity * 2).min(kept.len());
        }
    }
    kept
}

/// Errors from driving a session. Every variant is descriptive and bounded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RunnerError {
    #[error(transparent)]
    Transport(TransportError),
    #[error("encoding failed: {0}")]
    Encode(EncodeError),
    #[error("response extraction failed: {0}")]
    Response(ResponseError),
    #[error("no message type named {name:?} in the model")]
    UnknownMessage { name: String },
    #[error("message {message:?} is not legal to send from state {state:?}")]
    IllegalTransition { message: String, state: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ProtocolModel;
    use crate::profile::Profile;
    use crate::testcase::MessageInstance;

    const TOY: &str = include_str!("../tests/fixtures/toy-open-write.toml");

    fn toy_model() -> ProtocolModel {
        ProtocolModel::from_profile(&Profile::from_toml(TOY).unwrap()).unwrap()
    }

    fn open_write(model: &ProtocolModel) -> Vec<MessageInstance> {
        vec![
            MessageInstance::from_seed(model.message("OPEN").unwrap()),
            MessageInstance::from_seed(model.message("WRITE").unwrap()),
        ]
    }

    fn handle_reply(handle: u32) -> Vec<u8> {
        handle.to_be_bytes().to_vec()
    }

    #[test]
    fn runner_drives_open_then_write_and_binds_handle() {
        let model = toy_model();
        let mut transport = ScriptedTransport::single(vec![handle_reply(0x1122_3344), vec![0x00]]);
        let runner = SessionRunner::new(&model);
        let run = runner
            .drive(&open_write(&model), &mut transport)
            .expect("drive");

        // Two structured messages, a start->opened->opened state path.
        assert_eq!(run.testcase.messages.len(), 2);
        assert_eq!(run.testcase.state_path, vec!["start", "opened", "opened"]);
        // The handle was captured and bound.
        assert_eq!(
            run.testcase
                .bindings
                .get("OPEN.response.handle")
                .and_then(BoundValue::as_u64),
            Some(0x1122_3344)
        );
        // The WRITE frame echoed the captured handle (bytes 1..5: op then handle).
        let write_frame = &run.sent_frames[1];
        assert_eq!(&write_frame[1..5], &0x1122_3344u32.to_be_bytes());
        assert!(!run.verdict.is_finding());
    }

    #[test]
    fn runner_flags_profile_oracle_violation() {
        let model = toy_model();
        // WRITE reply status = 0xEF => the profile oracle fires.
        let mut transport = ScriptedTransport::single(vec![handle_reply(0xAABB_CCDD), vec![0xEF]]);
        let runner = SessionRunner::new(&model);
        let run = runner
            .drive(&open_write(&model), &mut transport)
            .expect("drive");
        match &run.verdict {
            SessionVerdict::Finding {
                rule_id, message, ..
            } => {
                assert_eq!(rule_id.as_deref(), Some("HDF7-PATHTRAV"));
                assert_eq!(message, "WRITE");
            }
            other => panic!("expected a finding, got {other:?}"),
        }
    }

    #[test]
    fn runner_surfaces_truncated_reply_error() {
        let model = toy_model();
        // OPEN reply only 2 bytes; the u32 handle capture needs 4.
        let mut transport = ScriptedTransport::single(vec![vec![0x00, 0x11]]);
        let runner = SessionRunner::new(&model);
        let err = runner
            .drive(&open_write(&model), &mut transport)
            .unwrap_err();
        assert!(
            matches!(
                err,
                RunnerError::Response(ResponseError::Truncated {
                    needed: 4,
                    got: 2,
                    ..
                })
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn replay_succeeds_when_service_returns_a_different_handle() {
        let model = toy_model();
        // Session 0 (drive): handle A, boundary status. Session 1 (replay):
        // DIFFERENT handle B, boundary status.
        let mut transport = ScriptedTransport::new(vec![
            vec![handle_reply(0x1111_1111), vec![0xEF]],
            vec![handle_reply(0x2222_2222), vec![0xEF]],
        ]);
        let runner = SessionRunner::new(&model);

        let first = runner
            .drive(&open_write(&model), &mut transport)
            .expect("drive");
        assert!(first.verdict.is_finding());
        assert_eq!(&first.sent_frames[1][1..5], &0x1111_1111u32.to_be_bytes());

        let replay = runner
            .replay(&first.testcase, &mut transport)
            .expect("replay");
        assert!(
            replay.verdict.is_finding(),
            "replay still reaches the oracle"
        );
        // The replay rebinds to the fresh handle and does NOT reuse the snapshot.
        assert_eq!(
            replay
                .testcase
                .bindings
                .get("OPEN.response.handle")
                .and_then(BoundValue::as_u64),
            Some(0x2222_2222)
        );
        assert_eq!(&replay.sent_frames[1][1..5], &0x2222_2222u32.to_be_bytes());
    }

    #[test]
    fn ddmin_finds_a_minimal_passing_subset() {
        // A toy predicate: a subset passes iff it contains both indices 1 and 3.
        let required = [1usize, 3usize];
        let kept = ddmin(5, |idxs| required.iter().all(|r| idxs.contains(r)));
        assert_eq!(kept, vec![1, 3]);
    }
}
