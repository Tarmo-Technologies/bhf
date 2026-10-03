// SPDX-License-Identifier: Apache-2.0

//! Crate-level acceptance tests over an in-memory toy OPEN/WRITE service.
//!
//! These exercise the full response-dependent session loop without any sockets
//! or process spawn: a [`ToyService`] implements the [`SessionTransport`] seam
//! in memory, decoding frames and responding the way the vertical-slice service
//! does. A checked-in profile (`toy-open-write.toml`) drives the service.
//!
//! The service models the response dependency exactly: OPEN issues a fresh
//! per-session handle (different after every reset); a WRITE is accepted only
//! when it echoes the current handle and passes its CRC gate; and a WRITE
//! through a handle whose OPEN path escaped the sandbox ("..") returns the
//! boundary status 0xEF — a security violation that exits cleanly.

use fuzz_engine_builtin::{crc32, MutationRng};
use protocol_session::{
    encode_message, MessageInstance, Profile, ProtocolModel, SessionRunner, SessionTestcase,
    SessionTransport, TransportError,
};

const TOY: &str = include_str!("fixtures/toy-open-write.toml");

fn toy_model() -> ProtocolModel {
    ProtocolModel::from_profile(&Profile::from_toml(TOY).expect("parse")).expect("compile")
}

/// An in-memory toy OPEN/WRITE service behind the transport seam.
struct ToyService {
    session: u32,
    current_handle: Option<u32>,
    tainted: bool,
    open_count: u32,
}

impl ToyService {
    fn new() -> Self {
        Self {
            session: 0,
            current_handle: None,
            tainted: false,
            open_count: 0,
        }
    }

    fn session_base(&self) -> u32 {
        self.session
            .wrapping_mul(0x0100_0000)
            .wrapping_add(0x00AB_CD01)
    }
}

fn be16(buf: &[u8], at: usize) -> Option<usize> {
    let s = buf.get(at..at + 2)?;
    Some(usize::from(u16::from_be_bytes([s[0], s[1]])))
}

fn be32(buf: &[u8], at: usize) -> Option<u32> {
    let s = buf.get(at..at + 4)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

impl SessionTransport for ToyService {
    fn send_request(&mut self, req: &[u8]) -> Result<Vec<u8>, TransportError> {
        let reject = || Ok(vec![0x01]);
        let Some(&op) = req.first() else {
            return reject();
        };
        match op {
            1 => {
                // OPEN: op(1) mode(1) len(2) path(len) crc(4)
                let Some(len) = be16(req, 2) else {
                    return reject();
                };
                let path_end = 4 + len;
                let crc_end = path_end + 4;
                if req.len() < crc_end {
                    return reject();
                }
                let stored = be32(req, path_end).unwrap();
                if stored != crc32(&req[0..path_end]) {
                    // Integrity gate failed: issue an invalid (zero) handle and
                    // do not establish a usable session handle.
                    return Ok(vec![0, 0, 0, 0]);
                }
                let path = &req[4..path_end];
                self.tainted = path.windows(2).any(|w| w == b"..");
                let handle = self.session_base().wrapping_add(self.open_count);
                self.open_count = self.open_count.wrapping_add(1);
                self.current_handle = Some(handle);
                Ok(handle.to_be_bytes().to_vec())
            }
            2 => {
                // WRITE: op(1) handle(4) len(2) data(len) crc(4) [flags]
                let Some(handle) = be32(req, 1) else {
                    return reject();
                };
                let Some(len) = be16(req, 5) else {
                    return reject();
                };
                let data_end = 7 + len;
                let crc_end = data_end + 4;
                if req.len() < crc_end {
                    return reject();
                }
                let stored = be32(req, data_end).unwrap();
                if stored != crc32(&req[0..data_end]) {
                    return reject();
                }
                if self.current_handle == Some(handle) {
                    if self.tainted {
                        Ok(vec![0xEF]) // boundary violation, clean exit
                    } else {
                        Ok(vec![0x00]) // ok
                    }
                } else {
                    Ok(vec![0x01]) // stale/guessed handle rejected
                }
            }
            _ => reject(),
        }
    }

    fn reset(&mut self) -> Result<(), TransportError> {
        self.session = self.session.wrapping_add(1);
        self.current_handle = None;
        self.tainted = false;
        self.open_count = 0;
        Ok(())
    }
}

fn open_write_seed(model: &ProtocolModel, path: &[u8], data: &[u8]) -> SessionTestcase {
    let mut open = MessageInstance::from_seed(model.message("OPEN").unwrap());
    open.set(
        "path",
        protocol_session::FieldValue::Bytes {
            value: path.to_vec(),
        },
    );
    let mut write = MessageInstance::from_seed(model.message("WRITE").unwrap());
    write.set(
        "data",
        protocol_session::FieldValue::Bytes {
            value: data.to_vec(),
        },
    );
    SessionTestcase::from_messages(model.profile_sha256(), vec![open, write])
}

fn assert_ac2_evidence(run: &protocol_session::SessionRun) {
    // >= 2 structured messages.
    assert!(run.testcase.messages.len() >= 2, "AC2: >= 2 messages");
    // A non-empty state path.
    assert!(!run.testcase.state_path.is_empty(), "AC2: state path");
    // Per-step captured response bytes.
    assert_eq!(
        run.testcase.captured_responses.len(),
        run.testcase.messages.len(),
        "AC2: a captured reply per step"
    );
    assert!(run
        .testcase
        .captured_responses
        .iter()
        .all(|r| !r.is_empty()));
    // A handle binding sourced from OPEN.response.handle.
    assert!(
        run.testcase.bindings.contains("OPEN.response.handle"),
        "AC2: response-derived handle binding present"
    );
}

#[test]
fn campaign_reaches_boundary_from_valid_seeds() {
    // AC1: a checked-in profile drives the toy service from an ORDINARY VALID
    // seed to the boundary violation, discovered by field mutation of the path.
    let model = toy_model();
    let seed = open_write_seed(&model, b"track", b"payload");
    let runner = SessionRunner::new(&model);
    let mut service = ToyService::new();

    // The traversal token is the only dictionary entry, so a fixed-seed,
    // bounded budget provably splices ".." into the path and reaches the oracle.
    let dictionary = vec![b"..".to_vec()];
    let mut rng = MutationRng::new(0x00C0_FFEE_D00D);
    let budget = 4000;

    let mut found = None;
    for _ in 0..budget {
        let candidate = protocol_session::mutate_fields(&seed, &model, &mut rng, &dictionary);
        if let Ok(run) = runner.drive(&candidate.messages, &mut service) {
            if run.verdict.is_finding() {
                found = Some(run);
                break;
            }
        }
    }

    let run = found.expect("the bounded campaign reached the boundary violation");
    assert_ac2_evidence(&run);
    // The finding came from a path that escaped the sandbox.
    let open = &run.testcase.messages[0];
    let path = match open.get("path") {
        Some(protocol_session::FieldValue::Bytes { value }) => value.clone(),
        other => panic!("expected bytes path, got {other:?}"),
    };
    assert!(
        path.windows(2).any(|w| w == b".."),
        "the discovered path escaped the sandbox: {path:?}"
    );
}

#[test]
fn replay_after_reset_rebinds_a_different_handle() {
    // AC3: replay against a fresh reset re-captures a DIFFERENT handle and still
    // reproduces the finding (rebinding), never reusing the snapshot handle.
    let model = toy_model();
    let seed = open_write_seed(&model, b"../escaped", b"payload");
    let runner = SessionRunner::new(&model);
    let mut service = ToyService::new();

    let first = runner.drive(&seed.messages, &mut service).expect("drive");
    assert!(first.verdict.is_finding(), "initial run trips the oracle");
    let first_handle = first
        .testcase
        .bindings
        .get("OPEN.response.handle")
        .and_then(protocol_session::BoundValue::as_u64)
        .unwrap();

    let replay = runner
        .replay(&first.testcase, &mut service)
        .expect("replay");
    assert!(replay.verdict.is_finding(), "replay still trips the oracle");
    let replay_handle = replay
        .testcase
        .bindings
        .get("OPEN.response.handle")
        .and_then(protocol_session::BoundValue::as_u64)
        .unwrap();

    assert_ne!(
        first_handle, replay_handle,
        "the service returned a different handle on replay"
    );
    // The replayed WRITE echoed the FRESH handle, not the snapshot.
    assert_eq!(
        &replay.sent_frames[1][1..5],
        &(replay_handle as u32).to_be_bytes(),
        "replay rebinds to the fresh handle"
    );
}

#[test]
fn minimize_preserves_smallest_valid_sequence_and_bindings() {
    // AC4: a padded session minimizes to the smallest still-reproducing
    // sequence, recomputing derived fields and maintaining dynamic bindings.
    let model = toy_model();
    let runner = SessionRunner::new(&model);

    // A padded 4-message session: two OPEN/WRITE pairs; only one pair is needed.
    let mut open_a = MessageInstance::from_seed(model.message("OPEN").unwrap());
    open_a.set(
        "path",
        protocol_session::FieldValue::Bytes {
            value: b"../escaped-a".to_vec(),
        },
    );
    let mut open_b = MessageInstance::from_seed(model.message("OPEN").unwrap());
    open_b.set(
        "path",
        protocol_session::FieldValue::Bytes {
            value: b"../escaped-b".to_vec(),
        },
    );
    let write = MessageInstance::from_seed(model.message("WRITE").unwrap());
    let padded = SessionTestcase::from_messages(
        model.profile_sha256(),
        vec![open_a, write.clone(), open_b, write],
    );

    // Sanity: the padded session reproduces.
    let mut service = ToyService::new();
    assert!(runner
        .drive(&padded.messages, &mut service)
        .unwrap()
        .verdict
        .is_finding());

    // The predicate re-drives each candidate on a fresh service (fresh handle).
    let predicate = |tc: &SessionTestcase| {
        let mut service = ToyService::new();
        runner
            .replay(tc, &mut service)
            .map(|run| run.verdict.is_finding())
            .unwrap_or(false)
    };

    let minimized = runner.minimize(&padded, predicate);
    assert_eq!(
        minimized.message_names(),
        vec!["OPEN", "WRITE"],
        "minimized to the smallest valid OPEN,WRITE sequence"
    );

    // Re-drive the minimized testcase: it still trips the oracle, its derived
    // fields are valid (the service's CRC gate accepted it), its dynamic handle
    // binding is live, and every frame verifies after repair.
    let mut service = ToyService::new();
    let run = runner
        .replay(&minimized, &mut service)
        .expect("drive minimized");
    assert!(run.verdict.is_finding(), "minimized still reproduces");
    assert!(run.testcase.bindings.contains("OPEN.response.handle"));
    for instance in &run.testcase.messages {
        let frame = encode_message(&model, instance, &run.testcase.bindings).expect("encode");
        assert!(frame.verify(), "derived fields valid after minimization");
    }

    // The minimized OPEN path still escapes the sandbox.
    let path = match minimized.messages[0].get("path") {
        Some(protocol_session::FieldValue::Bytes { value }) => value.clone(),
        other => panic!("expected bytes path, got {other:?}"),
    };
    assert!(
        path.windows(2).any(|w| w == b".."),
        "path still escapes: {path:?}"
    );
}
