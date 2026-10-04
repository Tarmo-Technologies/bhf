// SPDX-License-Identifier: Apache-2.0

//! #80: replay a transport (on-target) finding through its ORIGINAL target and
//! reset contract, not a host harness.
//!
//! A finding emitted by the `--target-transport` lane carries a
//! `transport_profile.json` (`bhf.transport-profile.v1`) recording the spec,
//! coverage map, backend, and reset mechanism it was found with. Replaying it
//! rebuilds that transport (optionally relocating the endpoint the operator
//! supplies), re-drives the recorded input through it, and checks the relevant
//! fault identity (rule + fault site) against the finding — NOT merely the broad
//! rule id, and never by silently falling back to a local host harness, which
//! would not be equivalent assurance. An unreachable endpoint, a missing
//! profile, or a backend the parser cannot rebuild is an actionable error.

use crate::transport_fuzz::{TransportPlan, TRANSPORT_PROFILE_FILE};
use std::path::Path;
use std::time::{Duration, Instant};
use target_transport::ExitKind;

/// The `exception.name` a BHF-555 "completed-but-slow" deadline finding carries
/// (the upper-snake form of the `transport-deadline-exceeded` crash class). Such
/// a finding is matched by a TIMING predicate on replay, not a fault identity.
const DEADLINE_EXCEPTION_NAME: &str = "TRANSPORT_DEADLINE_EXCEEDED";

/// Default per-input bound used to rebuild a transport whose profile predates the
/// persisted `timing` block (older findings carry no recorded deadline).
const REPLAY_DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// A transport finding is one that carries a `transport_profile.json`.
pub(crate) fn is_transport_finding(finding_dir: &Path) -> bool {
    finding_dir.join(TRANSPORT_PROFILE_FILE).is_file()
}

/// The fault identity used to decide a replay MATCH: the catalog rule plus the
/// backend-attributed fault site (address), so a reproduction must hit the same
/// rule AND the same site, not just any crash of the same broad rule id.
#[derive(Debug, PartialEq, Eq)]
struct FaultIdentity {
    rule_id: String,
    site: String,
}

/// Replay a transport finding. Returns 0 (MATCH), 3 (MISMATCH), or 1 (error).
pub(crate) fn replay_transport_finding(finding_dir: &Path, endpoint: Option<&str>) -> i32 {
    let profile_path = finding_dir.join(TRANSPORT_PROFILE_FILE);
    let profile: serde_json::Value = match std::fs::read(&profile_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    {
        Some(value) => value,
        None => {
            bhfeprintln!("read transport profile {}", profile_path.display());
            return 1;
        }
    };
    let Some(recorded_spec) = profile.get("spec").and_then(|v| v.as_str()) else {
        bhfeprintln!("transport profile has no spec; cannot rebuild the target");
        return 1;
    };
    let coverage_map = profile
        .get("coverage_map")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned);

    // The timing contract recorded with the finding (#70/#80): the per-input
    // execution deadline is reused to rebuild the transport so an execution
    // timeout re-times-out identically, and the response-time deadline is the
    // predicate a "completed-but-slow" BHF-555 finding is re-evaluated against.
    let timing = profile.get("timing");
    let per_input_timeout = timing
        .and_then(|t| t.get("per_input_timeout_ms"))
        .and_then(serde_json::Value::as_u64)
        .map(Duration::from_millis)
        .unwrap_or(REPLAY_DEFAULT_TIMEOUT);
    let deadline = timing
        .and_then(|t| t.get("deadline_ms"))
        .and_then(serde_json::Value::as_u64)
        .map(Duration::from_millis);

    // Relocate the endpoint if the operator supplied one (the recorded endpoint
    // is often gone or unreachable from the replay host).
    let spec = match relocate_endpoint(recorded_spec, endpoint) {
        Ok(spec) => spec,
        Err(error) => {
            bhfeprintln!("{error}");
            return 1;
        }
    };

    let input = match std::fs::read(finding_dir.join("testcase.bin")) {
        Ok(bytes) => bytes,
        Err(error) => {
            bhfeprintln!("read testcase: {error}");
            return 1;
        }
    };

    let recorded = match recorded_identity(finding_dir) {
        Ok(identity) => identity,
        Err(error) => {
            bhfeprintln!("{error}");
            return 1;
        }
    };

    // Rebuild the transport from the (possibly relocated) spec and re-drive the
    // input through it. Fail explicitly rather than host-executing.
    let plan = match TransportPlan::parse(&spec, coverage_map.as_deref()) {
        Ok(plan) => plan,
        Err(error) => {
            bhfeprintln!("rebuild transport from profile: {error}");
            return 1;
        }
    };
    let transport = match plan.into_transport(Some(per_input_timeout)) {
        Ok(transport) => transport,
        Err(error) => {
            bhfeprintln!("rebuild transport from profile: {error}");
            return 1;
        }
    };
    let mut session = match transport.arm() {
        Ok(session) => session,
        Err(error) => {
            bhfeprintln!(
                "could not reach the recorded transport ({spec}): {error}; \
                 relocate it with --transport-endpoint HOST:PORT"
            );
            return 1;
        }
    };
    let started = Instant::now();
    let outcome = match session.run_input(&input) {
        Ok(outcome) => outcome,
        Err(error) => {
            bhfeprintln!("re-driving the recorded input through the transport failed: {error}");
            return 1;
        }
    };
    let elapsed = started.elapsed();

    // A "completed-but-slow" deadline finding (BHF-555, emitted by the deadline
    // oracle on an Ok run) reproduces no fault — so a fault-identity check would
    // always report "no fault reproduced". Match it by the TIMING predicate it was
    // found with instead: the replay must also exceed the recorded deadline.
    if recorded_exception_name(finding_dir).as_deref() == Some(DEADLINE_EXCEPTION_NAME) {
        let Some(deadline) = deadline else {
            bhfeprintln!(
                "deadline finding {} carries no recorded deadline in its transport profile; \
                 cannot evaluate the timing predicate",
                finding_dir.display()
            );
            return 1;
        };
        if elapsed > deadline {
            let _ = corpus::finding::touch_last_seen(finding_dir, "replay (transport timing)");
            println!("MATCH");
            return 0;
        }
        bhfeprintln!(
            "MISMATCH recorded=host-observed>{}ms actual={}ms (within the deadline)",
            deadline.as_millis(),
            elapsed.as_millis()
        );
        return 3;
    }

    let actual = replay_identity(&outcome);
    match actual {
        Some(actual) if actual == recorded => {
            let _ = corpus::finding::touch_last_seen(finding_dir, "replay (transport)");
            println!("MATCH");
            0
        }
        Some(actual) => {
            bhfeprintln!(
                "MISMATCH recorded={}|{} actual={}|{}",
                recorded.rule_id,
                recorded.site,
                actual.rule_id,
                actual.site
            );
            3
        }
        None => {
            bhfeprintln!(
                "MISMATCH recorded={}|{} actual=<no fault reproduced>",
                recorded.rule_id,
                recorded.site
            );
            3
        }
    }
}

/// Reconstruct the recorded fault identity from `finding.json`: its `rule_id`
/// and the fault site encoded in the synthetic `<on-target fault … @ SITE>`
/// stack frame the emitter planted (#75).
fn recorded_identity(finding_dir: &Path) -> Result<FaultIdentity, String> {
    let path = finding_dir.join("finding.json");
    let value: serde_json::Value = std::fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or_else(|| format!("read finding {}", path.display()))?;
    let rule_id = value
        .get("rule_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "finding has no rule_id".to_owned())?
        .to_owned();
    let site = value
        .get("exception")
        .and_then(|e| e.get("stack"))
        .and_then(|s| s.as_array())
        .and_then(|frames| {
            frames
                .iter()
                .filter_map(|f| f.get("function").and_then(|v| v.as_str()))
                .find_map(parse_site_frame)
        })
        .map(|site| normalize_site(&site))
        .unwrap_or_else(|| "unlocalized".to_owned());
    Ok(FaultIdentity { rule_id, site })
}

/// Read the recorded finding's `exception.name` (the upper-snake crash class),
/// used to recognize a timing finding that is matched by a predicate rather than
/// a fault identity. `None` when the finding is unreadable or carries no name.
fn recorded_exception_name(finding_dir: &Path) -> Option<String> {
    let value: serde_json::Value = std::fs::read(finding_dir.join("finding.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())?;
    value
        .get("exception")
        .and_then(|e| e.get("name"))
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
}

/// Collapse an unlocalized fault site to its bare form. The emitter indexes
/// unlocalized sites (`unlocalized#N`) only to keep distinct same-class
/// candidates apart WITHIN a campaign (#75); that index is not a reproducible
/// property, so a replay's bare `unlocalized` must match a recorded
/// `unlocalized#N` of the same rule. A real attributed address is left intact.
fn normalize_site(site: &str) -> String {
    if site.starts_with("unlocalized") {
        "unlocalized".to_owned()
    } else {
        site.to_owned()
    }
}

/// Extract `SITE` from a synthetic `<on-target fault <label> @ SITE>` frame.
fn parse_site_frame(function: &str) -> Option<String> {
    let rest = function.strip_prefix("<on-target fault ")?;
    let inner = rest.strip_suffix('>')?;
    let (_label, site) = inner.rsplit_once(" @ ")?;
    Some(site.to_owned())
}

/// The fault identity a freshly re-driven `outcome` presents, or `None` when the
/// replay reproduced no fault at all.
fn replay_identity(outcome: &target_transport::RunOutcome) -> Option<FaultIdentity> {
    if outcome.exit == ExitKind::Ok {
        return None;
    }
    let report = crate::transport_fault::outcome_finding(outcome)?;
    let site = outcome
        .fault
        .as_ref()
        .and_then(|fault| fault.address)
        .map(|address| format!("{address:#x}"))
        .unwrap_or_else(|| "unlocalized".to_owned());
    Some(FaultIdentity {
        rule_id: report.rule_id.to_owned(),
        site: normalize_site(&site),
    })
}

/// Apply an operator endpoint relocation to a recorded spec. Supports the
/// single-endpoint backends (`agent:tcp:HOST:PORT`, `gdb:HOST:PORT`); a
/// multi-endpoint `qemu-system` spec cannot be relocated by a single
/// `HOST:PORT`, so that is an explicit error rather than a silent no-op.
fn relocate_endpoint(spec: &str, endpoint: Option<&str>) -> Result<String, String> {
    let Some(endpoint) = endpoint else {
        return Ok(spec.to_owned());
    };
    let spec = spec.trim();
    if let Some(rest) = spec.strip_prefix("agent:tcp:") {
        let _ = rest;
        Ok(format!("agent:tcp:{endpoint}"))
    } else if spec.strip_prefix("gdb:").is_some() {
        Ok(format!("gdb:{endpoint}"))
    } else {
        Err(format!(
            "--transport-endpoint cannot relocate a {spec:?} spec \
             (only agent:tcp / gdb single endpoints); edit the profile instead"
        ))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use target_transport::testsupport::{MockAgent, ScriptedResponse};
    use target_transport::{Fault, FaultKind};

    fn write_profile(dir: &Path, spec: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join(TRANSPORT_PROFILE_FILE),
            serde_json::to_vec(&serde_json::json!({
                "schema_version": "bhf.transport-profile.v1",
                "spec": spec,
                "coverage_map": serde_json::Value::Null,
                "transport_label": spec,
                "backend": "agent",
                "reset_mechanism": "agent-protocol reset",
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(dir.join("testcase.bin"), b"payload").unwrap();
    }

    /// Write a profile carrying a `timing` block (per-input + response deadline),
    /// in milliseconds (`None` -> JSON null, as an unset bound).
    fn write_timing_profile(
        dir: &Path,
        spec: &str,
        per_input_ms: Option<u64>,
        deadline_ms: Option<u64>,
    ) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join(TRANSPORT_PROFILE_FILE),
            serde_json::to_vec(&serde_json::json!({
                "schema_version": "bhf.transport-profile.v1",
                "spec": spec,
                "coverage_map": serde_json::Value::Null,
                "transport_label": spec,
                "backend": "agent",
                "reset_mechanism": "agent-protocol reset",
                "timing": {
                    "per_input_timeout_ms": per_input_ms,
                    "deadline_ms": deadline_ms,
                },
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(dir.join("testcase.bin"), b"payload").unwrap();
    }

    /// A completed-but-slow BHF-555 deadline finding (the deadline oracle's shape:
    /// a timing class, no reproduced fault).
    fn write_deadline_finding(dir: &Path) {
        std::fs::write(
            dir.join("finding.json"),
            serde_json::to_vec(&serde_json::json!({
                "rule_id": "BHF-555",
                "exception": {
                    "name": DEADLINE_EXCEPTION_NAME,
                    "stack": [],
                },
            }))
            .unwrap(),
        )
        .unwrap();
    }

    /// A transport finding with a MemoryProtection fault at the given site.
    fn write_finding(dir: &Path, rule_id: &str, site: &str) {
        std::fs::write(
            dir.join("finding.json"),
            serde_json::to_vec(&serde_json::json!({
                "rule_id": rule_id,
                "exception": {
                    "name": "TARGET_MEMORY_PROTECTION",
                    "stack": [ { "function": format!("<on-target fault agent @ {site}>") } ],
                },
            }))
            .unwrap(),
        )
        .unwrap();
    }

    /// Serve one scripted MockAgent connection on a fresh loopback port, logging
    /// the inputs it received. Returns (port, received-log, join-handle).
    #[allow(clippy::type_complexity)]
    fn spawn_scripted_agent(
        response: ScriptedResponse,
    ) -> (u16, Arc<Mutex<Vec<Vec<u8>>>>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let received = Arc::new(Mutex::new(Vec::new()));
        let received_for_thread = Arc::clone(&received);
        let handle = std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let agent = MockAgent::new(stream, vec![response], received_for_thread);
                let _ = agent.serve();
            }
        });
        (port, received, handle)
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("bhf-transport-replay-{tag}-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn replays_through_the_agent_and_matches_fault_identity() {
        let fault = Fault {
            kind: FaultKind::MemoryProtection,
            address: Some(0x2000_4000),
            detail: "MPU".to_owned(),
        };
        let (port, received, handle) =
            spawn_scripted_agent(ScriptedResponse::crash(vec![1], fault));

        let dir = temp_dir("match");
        // The recorded finding: BHF-210 memory-protection at 0x20004000.
        write_profile(&dir, &format!("agent:tcp:127.0.0.1:{port}"));
        write_finding(&dir, "BHF-210", "0x20004000");

        assert!(is_transport_finding(&dir));
        let code = replay_transport_finding(&dir, None);
        handle.join().unwrap();

        assert_eq!(
            code, 0,
            "same rule+site re-driven through the agent is a MATCH"
        );
        // Proof it re-executed THROUGH the agent (not a local harness): the agent
        // received the recorded input.
        assert_eq!(received.lock().unwrap().len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mismatched_fault_site_is_a_mismatch_not_a_match() {
        let fault = Fault {
            kind: FaultKind::MemoryProtection,
            address: Some(0x2000_9999), // a DIFFERENT site than recorded
            detail: String::new(),
        };
        let (port, _received, handle) =
            spawn_scripted_agent(ScriptedResponse::crash(vec![1], fault));

        let dir = temp_dir("mismatch");
        write_profile(&dir, &format!("agent:tcp:127.0.0.1:{port}"));
        write_finding(&dir, "BHF-210", "0x20004000");

        let code = replay_transport_finding(&dir, None);
        handle.join().unwrap();
        // Same rule id, different site: NOT a match (checks fault identity, not
        // just the broad rule id).
        assert_eq!(code, 3);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unreachable_endpoint_is_an_actionable_error_not_a_match() {
        // A free port with nothing listening — arm() cannot connect.
        let dead_port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let dir = temp_dir("dead");
        write_profile(&dir, &format!("agent:tcp:127.0.0.1:{dead_port}"));
        write_finding(&dir, "BHF-210", "0x20004000");

        assert_eq!(
            replay_transport_finding(&dir, None),
            1,
            "an unreachable endpoint is an error, never a MATCH"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn deadline_finding_matches_when_replay_also_exceeds_the_deadline() {
        // A completed-but-slow BHF-555 finding reproduces NO fault, so a
        // fault-identity check would always report "no fault reproduced" — a false
        // MISMATCH. It must instead be matched by the recorded timing predicate:
        // host-observed elapsed > deadline. A 0ms recorded deadline is exceeded by
        // any real agent round-trip, so the clean replay MATCHes (#70 replay).
        let (port, received, handle) = spawn_scripted_agent(ScriptedResponse::ok(vec![1, 2]));
        let dir = temp_dir("deadline-match");
        write_timing_profile(
            &dir,
            &format!("agent:tcp:127.0.0.1:{port}"),
            Some(1000),
            Some(0),
        );
        write_deadline_finding(&dir);

        let code = replay_transport_finding(&dir, None);
        handle.join().unwrap();

        assert_eq!(
            code, 0,
            "a replay that also exceeds the deadline is a MATCH"
        );
        assert_eq!(
            received.lock().unwrap().len(),
            1,
            "the timing finding was re-driven THROUGH the agent, not host-executed"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn deadline_finding_without_a_recorded_deadline_is_an_actionable_error() {
        // A deadline finding whose profile carries no deadline cannot have its
        // timing predicate evaluated: that is an actionable error (exit 1), never
        // a silent MATCH or a fault-identity MISMATCH.
        let (port, _received, handle) = spawn_scripted_agent(ScriptedResponse::ok(vec![1]));
        let dir = temp_dir("deadline-missing");
        write_timing_profile(
            &dir,
            &format!("agent:tcp:127.0.0.1:{port}"),
            Some(1000),
            None,
        );
        write_deadline_finding(&dir);

        let code = replay_transport_finding(&dir, None);
        handle.join().unwrap();

        assert_eq!(
            code, 1,
            "no recorded deadline -> cannot evaluate the predicate"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn replay_identity_of_a_timeout_is_bhf555_unlocalized() {
        // An execution-timeout finding (rule BHF-555, unlocalized site) must
        // reproduce as a BHF-555 unlocalized identity when the target hangs again,
        // so it matches the recorded finding through the normal identity path once
        // the transport is rebuilt with the recorded per-input deadline (#70).
        use target_transport::{Fault, FaultKind, RunOutcome};
        let outcome = RunOutcome {
            exit: ExitKind::Timeout,
            coverage_edges: Vec::new(),
            fault: Some(Fault {
                kind: FaultKind::Timeout,
                address: None,
                detail: "hang".to_owned(),
            }),
            stdout: Vec::new(),
            coverage_incomplete: Some("hung".to_owned()),
        };
        let id = replay_identity(&outcome).expect("a timeout reproduces a BHF-555 identity");
        assert_eq!(id.rule_id, "BHF-555");
        assert_eq!(id.site, "unlocalized");
    }

    #[test]
    fn normalize_site_collapses_unlocalized_index_but_keeps_addresses() {
        // The `#N` on an unlocalized site is a within-campaign dedup index, not a
        // reproducible property, so it must normalize away for replay matching; a
        // real attributed address is preserved exactly.
        assert_eq!(normalize_site("unlocalized#3"), "unlocalized");
        assert_eq!(normalize_site("unlocalized"), "unlocalized");
        assert_eq!(normalize_site("0x20004000"), "0x20004000");
    }

    #[test]
    fn endpoint_relocation_rewrites_the_agent_spec() {
        assert_eq!(
            relocate_endpoint("agent:tcp:10.0.0.1:1234", Some("127.0.0.1:5555")).unwrap(),
            "agent:tcp:127.0.0.1:5555"
        );
        assert_eq!(
            relocate_endpoint("gdb:10.0.0.1:1234", Some("127.0.0.1:5555")).unwrap(),
            "gdb:127.0.0.1:5555"
        );
        // A multi-endpoint qemu-system spec cannot be relocated by one HOST:PORT.
        assert!(relocate_endpoint("qemu-system:qmp=h:1,gdb=h:2", Some("127.0.0.1:5555")).is_err());
        // No override leaves the spec untouched.
        assert_eq!(
            relocate_endpoint("agent:tcp:h:1", None).unwrap(),
            "agent:tcp:h:1"
        );
    }
}
