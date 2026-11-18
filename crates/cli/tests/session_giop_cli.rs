// SPDX-License-Identifier: Apache-2.0

//! The session lane's `giop` profile kind (#315): with a `kind = "giop"`
//! profile, `bhf fuzz --protocol-profile` sends GIOP 1.2 Requests, their
//! arguments marshalled in CDR at the IDL types the profile gives, over the
//! TCP session transport, and captures values from the GIOP Replies.
//!
//! The fixture server in this test is built from the iiop crate: it frames
//! each message by its GIOP header, decodes the request against the servant's
//! IDL (`warehouse.idl`) with iiop's dispatcher, and answers with iiop's
//! Reply encoder. Its servant has a planted bug: `store` indexes the bin's
//! eight slots with the slot it is given and no bounds check (CWE-129), so a
//! slot past them panics the servant, and the connection ends as a crashed
//! server's does. The bug is behind the session: `store` needs the handle of
//! a bin `open_bin` returned on the same connection.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use iiop::dispatch::{DispatchError, Dispatcher, Servant, ServantError, ServantReply};
use iiop::encode::{CdrValue, Reply12};
use iiop::giop::{
    parse_header, parse_message, read_request_1_2, CompletionStatus, ReplyStatus, HEADER_LEN,
};
use iiop::idl_args::{DecodedArgumentValue, DecodedRequestArguments, IdlOperationCatalog};
use protocol_session::{FieldValue, SessionTestcase};

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

const WAREHOUSE_IDL: &str = include_str!("../../protocol_session/tests/fixtures/warehouse.idl");

fn warehouse_profile() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../protocol_session/tests/fixtures/giop-warehouse.toml")
}

/// The slots in a bin.
const SLOTS: usize = 8;

#[derive(Default)]
struct GiopCounts {
    /// Requests the servant answered with a result.
    results: AtomicUsize,
    /// Requests that crashed the servant.
    servant_crashes: AtomicUsize,
}

/// The Inventory::Warehouse servant: bins of eight slots, by handle.
struct Warehouse {
    bins: HashMap<u32, Vec<i32>>,
    next_handle: u32,
}

impl Servant for Warehouse {
    fn invoke(
        &mut self,
        request: &DecodedRequestArguments<'_>,
    ) -> Result<ServantReply, ServantError> {
        use DecodedArgumentValue::{Long, String, ULong, UShort};
        let arguments: Vec<&DecodedArgumentValue> =
            request.arguments.iter().map(|arg| &arg.value).collect();
        let bad = |detail: &str| ServantError::BadArguments {
            operation: request.operation.clone(),
            detail: detail.to_owned(),
        };
        match (request.operation.as_str(), arguments.as_slice()) {
            ("open_bin", [String(label)]) => {
                if label.is_empty() || label.len() > 32 {
                    return Err(bad("a label is 1 to 32 characters"));
                }
                let handle = self.next_handle;
                self.next_handle = handle.wrapping_mul(0x9e37_79b1).wrapping_add(0x7f4a_7c15) | 1;
                self.bins.insert(handle, vec![0; SLOTS]);
                Ok(ServantReply::value(CdrValue::ULong(handle)))
            }
            ("store", [ULong(bin), UShort(slot), Long(quantity)]) => {
                let Some(slots) = self.bins.get_mut(bin) else {
                    return Err(bad("no such bin"));
                };
                // The planted bug: `slot` is not checked against the bin's
                // slots before it indexes them.
                let slot = usize::from(*slot);
                slots[slot] = slots[slot].wrapping_add(*quantity);
                Ok(ServantReply::value(CdrValue::Long(slots[slot])))
            }
            ("count", [ULong(bin), UShort(slot)]) => {
                let Some(slots) = self.bins.get(bin) else {
                    return Err(bad("no such bin"));
                };
                let Some(quantity) = slots.get(usize::from(*slot)) else {
                    return Err(bad("no such slot"));
                };
                Ok(ServantReply::value(CdrValue::Long(*quantity)))
            }
            (operation, _) => Err(ServantError::UnknownOperation(operation.to_owned())),
        }
    }
}

/// A CORBA system exception's repository id.
fn system_exception(name: &str) -> String {
    format!("IDL:omg.org/CORBA/{name}:1.0")
}

fn serve_giop(
    mut stream: TcpStream,
    catalog: IdlOperationCatalog,
    handle: u32,
    counts: &GiopCounts,
) {
    stream.set_nodelay(true).ok();
    let mut dispatcher = Dispatcher::new(
        catalog,
        Warehouse {
            bins: HashMap::new(),
            next_handle: handle,
        },
    );
    loop {
        // The GIOP header says how long the message is.
        let mut frame = vec![0u8; HEADER_LEN];
        if stream.read_exact(&mut frame).is_err() {
            return;
        }
        let Ok(header) = parse_header(&frame) else {
            return;
        };
        frame.resize(HEADER_LEN + header.body_len as usize, 0);
        if stream.read_exact(&mut frame[HEADER_LEN..]).is_err() {
            return;
        }
        // What is not a GIOP 1.2 Request ends the connection.
        let Ok(request_id) = parse_message(&frame)
            .and_then(|message| read_request_1_2(&message).map(|request| request.request_id))
        else {
            return;
        };
        let reply = match catch_unwind(AssertUnwindSafe(|| dispatcher.handle_frame(&frame))) {
            Ok(Ok(invocation)) => {
                counts.results.fetch_add(1, Ordering::SeqCst);
                Reply12::new(request_id, ReplyStatus::NoException)
                    .with_body(invocation.reply.result.into_iter().collect())
            }
            Ok(Err(error)) => {
                let name = match error {
                    DispatchError::Servant(ServantError::UnknownOperation(_)) => "BAD_OPERATION",
                    DispatchError::Servant(_) => "BAD_PARAM",
                    // The arguments do not decode at the operation's IDL types.
                    DispatchError::Giop(_) | DispatchError::Decode(_) => "MARSHAL",
                };
                Reply12::system_exception(
                    request_id,
                    system_exception(name),
                    0,
                    CompletionStatus::CompletedNo,
                )
            }
            // The servant crashed, and the connection goes with it.
            Err(_) => {
                counts.servant_crashes.fetch_add(1, Ordering::SeqCst);
                return;
            }
        };
        let reply = reply
            .with_endian(header.endian)
            .encode()
            .expect("encode a reply");
        if stream.write_all(&reply).is_err() {
            return;
        }
    }
}

/// The servant on a localhost port, a servant of its own per connection, its
/// bin handles different on every connection.
fn start_giop_server(counts: Arc<GiopCounts>) -> u16 {
    let idl = idl_parser::parse_idl(WAREHOUSE_IDL).expect("the servant's IDL parses");
    let catalog = IdlOperationCatalog::from_idl_file(&idl);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the GIOP server");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let mut handle = std::process::id().wrapping_mul(0x0100_0193) | 1;
        for stream in listener.incoming().flatten() {
            let (catalog, counts) = (catalog.clone(), counts.clone());
            handle = handle.wrapping_mul(0x9e37_79b1).wrapping_add(1);
            let first = handle;
            thread::spawn(move || serve_giop(stream, catalog, first, &counts));
        }
    });
    port
}

#[test]
fn a_giop_profile_finds_the_servant_bug_behind_the_session_it_opened() {
    let counts = Arc::new(GiopCounts::default());
    let port = start_giop_server(counts.clone());
    let work = TestDir::new("giop-session");
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("fuzz")
        .arg(work.path())
        .args(["--harness", "H-giop", "--protocol-profile"])
        .arg(warehouse_profile())
        .args(["--session-transport", &format!("tcp:127.0.0.1:{port}")])
        .args(["--session-reply-timeout", "2s", "--iterations", "300"])
        .output()
        .expect("run bhf fuzz");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    let summary: serde_json::Value =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("summary ({e}):\n{stderr}"));
    assert_eq!(summary["framing"], "giop", "{summary:#}");
    // start, opened and stocked: the servant decoded the requests against
    // its IDL and answered them.
    assert_eq!(summary["states_covered"], 3, "{summary:#}");
    assert!(counts.results.load(Ordering::SeqCst) >= 3);

    // The servant crash, found once and confirmed on a new connection.
    let findings = summary["findings"].as_array().expect("findings");
    assert_eq!(findings.len(), 1, "{summary:#}");
    assert!(counts.servant_crashes.load(Ordering::SeqCst) >= 2);
    let dir = work
        .path()
        .join("results/findings")
        .join(findings[0].as_str().unwrap());
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("finding.json")).unwrap()).unwrap();
    assert_eq!(record["rule_id"], "BHF-210", "{record:#}");
    assert_eq!(record["oracle"]["name"], "session-disconnect", "{record:#}");
    assert_eq!(record["oracle"]["api"], "STORE", "{record:#}");

    // The session went through open_bin, and the request the servant crashed
    // on is a store into a slot past the bin's.
    let session = SessionTestcase::from_json(
        &std::fs::read_to_string(dir.join("session.json")).expect("session.json"),
    )
    .expect("a session");
    assert!(session.state_path.iter().any(|state| state == "opened"));
    assert!(session.bindings.contains("OPEN_BIN.response.bin"));
    let crashed = &session.messages[session.captured_responses.len()];
    assert_eq!(crashed.message, "STORE");
    let Some(FieldValue::Int { value: slot }) = crashed.get("slot") else {
        panic!("a store's slot: {crashed:?}");
    };
    assert!(*slot >= SLOTS as u64, "slot {slot}");

    // The finding replays: on a new connection, with a new bin handle, the
    // store crashes the servant again.
    let replay = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["replay", "--finding"])
        .arg(&dir)
        .output()
        .expect("run bhf replay");
    let shown = String::from_utf8_lossy(&replay.stdout);
    assert!(
        replay.status.success() && shown.starts_with("MATCH"),
        "{shown}\n{}",
        String::from_utf8_lossy(&replay.stderr)
    );
}
