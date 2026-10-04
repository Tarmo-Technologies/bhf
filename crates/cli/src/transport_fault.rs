// SPDX-License-Identifier: Apache-2.0

//! HDF-2: turn a transport-reported [`target_transport::Fault`] into a BHF
//! finding, independent of host POSIX signals.
//!
//! On an RTOS single-address-space image, a Cortex-M board, or a `qemu-system`
//! guest, a fault never reaches `waitpid`: there is no `SIGSEGV`, no exit status
//! to read. The HDF-1 transport seam surfaces such a fault structurally as a
//! [`target_transport::Fault`] (a [`FaultKind`], an optional faulting address, a
//! detail string). This module is the CONSUMER side: it maps that fault onto the
//! *existing* BHF finding taxonomy (the `BHF-210` fatal-crash family and its
//! siblings in [`finding_rules`]) and produces a replayable finding record —
//! the same [`corpus::SanitizerReport`] the host-signal lane emits, so both lanes
//! funnel into one findings pipeline.
//!
//! # Why reuse [`corpus::SanitizerReport`]
//!
//! A finding's CWE is resolved from its `rule_id` through the [`finding_rules`]
//! catalog (see `report::ensure_finding_cwe`), exactly as the cross-language
//! crash parsers in [`corpus::sanitizer`] already do: a "reachable assertion"
//! and an "uncaught crash" both carry `BHF-210`, while a stack overflow carries
//! `BHF-207` so it inherits `CWE-674`. We follow that established convention
//! rather than inventing a parallel finding struct or a second CWE channel.
//!
//! # The taxonomy map
//!
//! | [`FaultKind`]           | rule    | CWE (from catalog) | rationale |
//! |-------------------------|---------|--------------------|-----------|
//! | `CpuException`          | BHF-210 | CWE-119 | CPU exception vector, unlocalized reachable crash |
//! | `MemoryProtection`      | BHF-210 | CWE-119 | MMU/MPU access violation (faulting address kept in the message; a NULL-deref is NOT inferred from a low address without a target memory map) |
//! | `Watchdog`              | BHF-555 | CWE-400 | watchdog / reset-controller trip — an availability failure, not memory corruption |
//! | `AssertionPanic`        | BHF-557 | CWE-617 | reachable assertion / panic / abort |
//! | `StackOverflow`         | BHF-207 | CWE-674 | stack-overflow / guard-region violation — stack exhaustion |
//! | `Timeout`               | BHF-555 | CWE-400 | exceeded a hard real-time / watchdog deadline — a timing/availability failure |
//! | `Other(code)`           | BHF-210 | CWE-119 | an unrecognized backend fault code, preserved and surfaced |
//!
//! No fault claims a sanitizer: an on-target CPU fault is not produced by ASan,
//! so the emitted report carries `sanitizer: None` (#78).

use target_transport::{ExitKind, Fault, FaultKind, RunOutcome};

/// A transport fault classified into the BHF finding taxonomy.
///
/// The `rule_id` selects a real [`finding_rules`] catalog rule so its CWE (and
/// severity, references, …) is resolved downstream exactly as for every other
/// finding; `kind` is the short crash-class token carried on the
/// [`corpus::SanitizerReport`]; `name` is a human phrase for the finding message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultClass {
    /// Numeric BHF rule id (`BHF-NNN`), guaranteed to resolve via
    /// [`finding_rules::by_id`].
    pub rule_id: &'static str,
    /// Short crash-class token, e.g. `target-stack-overflow`.
    pub kind: String,
    /// Human-readable classification, e.g. `target stack-overflow / guard-region
    /// violation`.
    pub name: String,
}

/// Map a backend-neutral transport [`Fault`] to a finding rule + crash class,
/// with no reliance on a host POSIX signal (HDF-2).
///
/// Every [`FaultKind`] — including [`FaultKind::Other`] — resolves to a real
/// catalog rule, so a transport-reported fault is never silently dropped.
pub fn classify_fault(fault: &Fault) -> FaultClass {
    match fault.kind {
        FaultKind::CpuException => FaultClass {
            rule_id: "BHF-210",
            kind: "target-cpu-exception".to_owned(),
            name: "target CPU exception".to_owned(),
        },
        // An MMU/MPU access trap is a memory-protection violation (the BHF-210
        // family). We do NOT infer a NULL-pointer dereference from a low faulting
        // address: address 0 being the unmapped null guard is a target-specific
        // memory-map assumption, not a universal embedded truth, and the
        // transport carries no memory map here. The faulting address is preserved
        // in the message for triage instead of forcing a CWE-476 label.
        FaultKind::MemoryProtection => FaultClass {
            rule_id: "BHF-210",
            kind: "target-memory-protection".to_owned(),
            name: "target memory-protection (MMU/MPU) trap".to_owned(),
        },
        // A watchdog / reset-controller trip is an availability failure (the
        // target went down), NOT a memory-bounds weakness — CWE-400, not CWE-119.
        FaultKind::Watchdog => FaultClass {
            rule_id: "BHF-555",
            kind: "target-watchdog-reset".to_owned(),
            name: "target watchdog / reset-controller trip".to_owned(),
        },
        // A reachable assertion / panic / abort is CWE-617 (reachable assertion),
        // not memory corruption.
        FaultKind::AssertionPanic => FaultClass {
            rule_id: "BHF-557",
            kind: "target-reachable-assertion".to_owned(),
            name: "target reachable assertion / panic / abort".to_owned(),
        },
        FaultKind::StackOverflow => FaultClass {
            rule_id: "BHF-207",
            kind: "target-stack-overflow".to_owned(),
            name: "target stack-overflow / guard-region violation".to_owned(),
        },
        // A hard deadline / watchdog timeout is a timing/availability failure
        // (CWE-400), not a memory error.
        FaultKind::Timeout => FaultClass {
            rule_id: "BHF-555",
            kind: "target-timeout".to_owned(),
            name: "target deadline / watchdog timeout".to_owned(),
        },
        FaultKind::Other(code) => FaultClass {
            rule_id: "BHF-210",
            kind: format!("target-fault-{code}"),
            name: format!("target fault (unmapped backend code {code})"),
        },
    }
}

/// The single [`corpus::SanitizerReport`] constructor both the host-signal lane
/// (`crate::fuzz::fatal_signal_report`) and the transport-fault lane funnel
/// through, so every undiagnosed crash — POSIX signal or on-target fault —
/// becomes one finding shape with a catalog `rule_id`.
///
/// `sanitizer` is `None`: neither a host fatal signal nor an on-target CPU fault
/// is produced by a sanitizer, so the finding must not claim one — the CWE is
/// keyed off `rule_id`, and the provenance states only what actually occurred
/// (#78). The stack is empty because an undiagnosed fault carries no sanitizer
/// frames; the transport lane attaches a structured fault-site frame separately.
pub fn crash_report(
    rule_id: &'static str,
    kind: String,
    message: String,
) -> corpus::SanitizerReport {
    corpus::SanitizerReport {
        sanitizer: None,
        kind,
        rule_id,
        stack: Vec::new(),
        message,
    }
}

/// Build the replayable finding record for a transport [`Fault`].
///
/// The record is a [`corpus::SanitizerReport`] — the same structure the host
/// fatal-signal lane produces — so it flows through the existing replay /
/// minimize / report pipeline unchanged. The message names the fault class and
/// carries the faulting address and any backend detail for triage.
pub fn fault_report(fault: &Fault) -> corpus::SanitizerReport {
    let class = classify_fault(fault);
    let mut message = format!(
        "target transport reported a {} with no sanitizer report",
        class.name
    );
    if let Some(address) = fault.address {
        message.push_str(&format!(" (fault address {address:#x})"));
    }
    if !fault.detail.is_empty() {
        message.push_str(": ");
        message.push_str(&fault.detail);
    }
    crash_report(class.rule_id, class.kind, message)
}

/// Build a BHF-555 timing finding for a completed-but-too-slow transport run
/// (its host-observed execution time exceeded the configured `--deadline`).
///
/// This is the transport lane's deadline oracle (#70): the input ran to
/// completion but took longer than `deadline`, which is a CWE-400 timing /
/// availability finding rather than a memory crash. The message states the
/// timing is host-observed round-trip, so the provenance is not overstated.
pub fn deadline_report(
    elapsed: std::time::Duration,
    deadline: std::time::Duration,
) -> corpus::SanitizerReport {
    crash_report(
        "BHF-555",
        "transport-deadline-exceeded".to_owned(),
        format!(
            "target transport completed but its host-observed execution time {}ms exceeded \
             the configured deadline {}ms — a timing/availability finding",
            elapsed.as_millis(),
            deadline.as_millis()
        ),
    )
}

/// Turn a transport [`RunOutcome`] into a replayable finding, or `None` for a
/// clean run.
///
/// This is the HDF-2 seam an HDF-1 transport backend (agent, gdb-remote,
/// emulator) calls after each execution: a crash/timeout outcome funnels into
/// the same [`corpus::SanitizerReport`] finding pipeline the host lane uses. A
/// crash or timeout that carries no structured [`Fault`] (a backend that could
/// not attribute one) still becomes a finding rather than being lost.
pub fn outcome_finding(outcome: &RunOutcome) -> Option<corpus::SanitizerReport> {
    match outcome.exit {
        ExitKind::Ok => None,
        ExitKind::Crash => Some(match &outcome.fault {
            Some(fault) => fault_report(fault),
            None => crash_report(
                "BHF-210",
                "target-crash".to_owned(),
                "target transport reported a crash with no fault detail — a reachable crash"
                    .to_owned(),
            ),
        }),
        ExitKind::Timeout => Some(match &outcome.fault {
            Some(fault) => fault_report(fault),
            // No structured fault: synthesize the deadline class so a hang is
            // still classified (BHF-210) and recorded.
            None => fault_report(&Fault::new(FaultKind::Timeout)),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use target_transport::testsupport::{duplex, MockAgent, ScriptedResponse};
    use target_transport::{AgentLimits, AgentSession, TargetSession};

    /// The CWE the reporter would attach to this finding, resolved from the rule
    /// catalog exactly as `report::ensure_finding_cwe` does at emit time.
    fn cwe_of(report: &corpus::SanitizerReport) -> &'static str {
        finding_rules::by_id(report.rule_id)
            .unwrap_or_else(|| panic!("rule {} must exist in the catalog", report.rule_id))
            .cwe
    }

    /// Every fault kind maps to a real catalog rule + the expected CWE, and
    /// yields a replayable finding record — with NO POSIX signal involved (the
    /// input here is a plain constructed `Fault`).
    #[test]
    fn each_fault_kind_maps_to_the_expected_rule_and_cwe() {
        // (fault, expected rule id, expected CWE, a token expected in `kind`).
        let cases: Vec<(Fault, &str, &str, &str)> = vec![
            (
                Fault::new(FaultKind::CpuException),
                "BHF-210",
                "CWE-119",
                "cpu-exception",
            ),
            // MMU/MPU trap at a real address: unlocalized memory-bounds crash.
            (
                Fault {
                    kind: FaultKind::MemoryProtection,
                    address: Some(0x2000_4000),
                    detail: "MPU region 3".to_owned(),
                },
                "BHF-210",
                "CWE-119",
                "memory-protection",
            ),
            // MMU/MPU trap at a LOW address is NOT inferred as a null-pointer
            // dereference without a target memory map (#78): it stays a generic
            // memory-protection trap, with the address preserved in the message.
            (
                Fault {
                    kind: FaultKind::MemoryProtection,
                    address: Some(0x8),
                    detail: String::new(),
                },
                "BHF-210",
                "CWE-119",
                "memory-protection",
            ),
            // A watchdog trip is an availability failure, not memory corruption.
            (
                Fault::new(FaultKind::Watchdog),
                "BHF-555",
                "CWE-400",
                "watchdog",
            ),
            // A reachable assertion is CWE-617, not memory corruption.
            (
                Fault::new(FaultKind::AssertionPanic),
                "BHF-557",
                "CWE-617",
                "assertion",
            ),
            (
                Fault::new(FaultKind::StackOverflow),
                "BHF-207",
                "CWE-674",
                "stack-overflow",
            ),
            // A hard-deadline timeout is a timing/availability failure, not memory.
            (
                Fault::new(FaultKind::Timeout),
                "BHF-555",
                "CWE-400",
                "timeout",
            ),
            (
                Fault::new(FaultKind::Other(4242)),
                "BHF-210",
                "CWE-119",
                "target-fault-4242",
            ),
        ];

        for (fault, expected_rule, expected_cwe, kind_token) in cases {
            let class = classify_fault(&fault);
            assert_eq!(class.rule_id, expected_rule, "rule id for {:?}", fault.kind);
            assert!(
                class.kind.contains(kind_token),
                "kind `{}` for {:?} must contain `{kind_token}`",
                class.kind,
                fault.kind
            );

            let report = fault_report(&fault);
            // A replayable finding record: a real catalog rule, its correct CWE,
            // no phantom sanitizer frames, and no false sanitizer provenance (#78).
            assert_eq!(report.rule_id, expected_rule, "report rule for {fault:?}");
            assert_eq!(cwe_of(&report), expected_cwe, "CWE for {fault:?}");
            assert!(report.stack.is_empty(), "undiagnosed fault has no frames");
            assert!(
                report.sanitizer.is_none(),
                "an on-target fault must not claim a sanitizer: {fault:?}"
            );
            assert!(
                report.message.contains("no sanitizer report"),
                "message: {}",
                report.message
            );
        }
    }

    /// The faulting address and detail are surfaced in the finding message for
    /// triage / replay.
    #[test]
    fn fault_report_carries_address_and_detail() {
        let fault = Fault {
            kind: FaultKind::CpuException,
            address: Some(0xDEAD_BEEF),
            detail: "undefined instruction @ vector 3".to_owned(),
        };
        let report = fault_report(&fault);
        assert!(report.message.contains("0xdeadbeef"), "{}", report.message);
        assert!(
            report.message.contains("undefined instruction @ vector 3"),
            "{}",
            report.message
        );
    }

    /// End-to-end through the real HDF-1 agent transport + `MockAgent`: a scripted
    /// crash for each fault class is delivered over an in-memory duplex (no
    /// process, no signal) and classified to the expected rule + CWE.
    #[test]
    fn mock_agent_faults_classify_through_the_transport() {
        let faults = [
            (FaultKind::CpuException, "BHF-210", "CWE-119"),
            (FaultKind::MemoryProtection, "BHF-210", "CWE-119"),
            (FaultKind::Watchdog, "BHF-555", "CWE-400"),
            (FaultKind::AssertionPanic, "BHF-557", "CWE-617"),
            (FaultKind::StackOverflow, "BHF-207", "CWE-674"),
            (FaultKind::Timeout, "BHF-555", "CWE-400"),
            (FaultKind::Other(7), "BHF-210", "CWE-119"),
        ];

        for (kind, expected_rule, expected_cwe) in faults {
            let script = vec![ScriptedResponse::crash(
                vec![1, 2, 3],
                Fault {
                    kind,
                    address: Some(0x2000_0000),
                    detail: format!("{kind:?}"),
                },
            )];
            let (host_end, target_end) = duplex();
            let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
            let agent = MockAgent::new(target_end, script, std::sync::Arc::clone(&received));
            let handle = std::thread::spawn(move || agent.serve());

            let mut session = AgentSession::new(host_end, AgentLimits::default());
            let outcome = session
                .run_input(b"input")
                .expect("mock agent answers one input");
            drop(session);
            handle.join().unwrap().unwrap();

            assert_eq!(outcome.exit, ExitKind::Crash);
            let report = outcome_finding(&outcome).expect("a crash outcome is a finding");
            assert_eq!(report.rule_id, expected_rule, "rule for {kind:?}");
            assert_eq!(cwe_of(&report), expected_cwe, "CWE for {kind:?}");
        }
    }

    /// A clean transport outcome is not a finding; a crash/timeout without a
    /// structured fault still is (never silently dropped).
    #[test]
    fn outcome_finding_covers_faultless_crash_and_timeout() {
        assert!(outcome_finding(&RunOutcome::clean(vec![1, 2])).is_none());

        let bare_crash = RunOutcome {
            exit: ExitKind::Crash,
            coverage_edges: Vec::new(),
            fault: None,
            stdout: Vec::new(),
            coverage_incomplete: None,
        };
        let report = outcome_finding(&bare_crash).expect("faultless crash is still a finding");
        assert_eq!(report.rule_id, "BHF-210");

        let bare_timeout = RunOutcome {
            exit: ExitKind::Timeout,
            coverage_edges: Vec::new(),
            fault: None,
            stdout: Vec::new(),
            coverage_incomplete: None,
        };
        let report = outcome_finding(&bare_timeout).expect("faultless timeout is still a finding");
        // A timeout is a timing/availability failure (CWE-400), not memory (#78).
        assert_eq!(report.rule_id, "BHF-555");
        assert_eq!(cwe_of(&report), "CWE-400");
        assert!(report.sanitizer.is_none(), "a timeout claims no sanitizer");
    }
}
