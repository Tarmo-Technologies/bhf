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
//! | `MemoryProtection` @null| BHF-206 | CWE-476 | MMU/MPU trap at the null page — a NULL-pointer deref |
//! | `MemoryProtection`      | BHF-210 | CWE-119 | MMU/MPU access violation — out-of-bounds memory access |
//! | `Watchdog`              | BHF-210 | CWE-119 | watchdog / reset-controller trip — the target went down |
//! | `AssertionPanic`        | BHF-210 | CWE-119 | reachable assertion / panic / abort (as the ruby/lua/php lanes map it) |
//! | `StackOverflow`         | BHF-207 | CWE-674 | stack-overflow / guard-region violation — stack exhaustion |
//! | `Timeout`               | BHF-210 | CWE-119 | exceeded a hard real-time / watchdog deadline — a hang |
//! | `Other(code)`           | BHF-210 | CWE-119 | an unrecognized backend fault code, preserved and surfaced |

use target_transport::{ExitKind, Fault, FaultKind, RunOutcome};

/// A memory-protection trap whose faulting address is at or below this bound is a
/// NULL / near-NULL pointer dereference — the CWE-476 case `BHF-206` already
/// covers ("SEGV at low addresses ... via mmap of the null page"), not an
/// arbitrary out-of-bounds access. One 4 KiB page, the conventional null guard
/// region.
const NULL_PAGE_LIMIT: u64 = 0x1000;

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
        // An MMU/MPU trap at (or just above) address zero is a NULL-pointer
        // dereference; any other faulting address is an out-of-bounds access we
        // cannot localize without a sanitizer, i.e. the generic memory-bounds
        // crash the BHF-210 family covers.
        FaultKind::MemoryProtection => match fault.address {
            Some(address) if address < NULL_PAGE_LIMIT => FaultClass {
                rule_id: "BHF-206",
                kind: "target-null-pointer-dereference".to_owned(),
                name: "target NULL-pointer dereference (MMU/MPU trap at the null page)".to_owned(),
            },
            _ => FaultClass {
                rule_id: "BHF-210",
                kind: "target-memory-protection".to_owned(),
                name: "target memory-protection (MMU/MPU) trap".to_owned(),
            },
        },
        FaultKind::Watchdog => FaultClass {
            rule_id: "BHF-210",
            kind: "target-watchdog-reset".to_owned(),
            name: "target watchdog / reset-controller trip".to_owned(),
        },
        FaultKind::AssertionPanic => FaultClass {
            rule_id: "BHF-210",
            kind: "target-reachable-assertion".to_owned(),
            name: "target reachable assertion / panic / abort".to_owned(),
        },
        FaultKind::StackOverflow => FaultClass {
            rule_id: "BHF-207",
            kind: "target-stack-overflow".to_owned(),
            name: "target stack-overflow / guard-region violation".to_owned(),
        },
        FaultKind::Timeout => FaultClass {
            rule_id: "BHF-210",
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
/// The sanitizer tag is `AddressSanitizer` to match the host lane's synthesized
/// crash report (the reporter keys the CWE off `rule_id`, not this tag) and the
/// stack is empty because an undiagnosed fault carries no sanitizer frames.
pub fn crash_report(
    rule_id: &'static str,
    kind: String,
    message: String,
) -> corpus::SanitizerReport {
    corpus::SanitizerReport {
        sanitizer: corpus::Sanitizer::AddressSanitizer,
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
        "target transport reported a {} with no sanitizer report — a reachable crash",
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
            // MMU/MPU trap at the null page: a NULL-pointer dereference.
            (
                Fault {
                    kind: FaultKind::MemoryProtection,
                    address: Some(0x8),
                    detail: String::new(),
                },
                "BHF-206",
                "CWE-476",
                "null-pointer",
            ),
            (
                Fault::new(FaultKind::Watchdog),
                "BHF-210",
                "CWE-119",
                "watchdog",
            ),
            (
                Fault::new(FaultKind::AssertionPanic),
                "BHF-210",
                "CWE-119",
                "assertion",
            ),
            (
                Fault::new(FaultKind::StackOverflow),
                "BHF-207",
                "CWE-674",
                "stack-overflow",
            ),
            (
                Fault::new(FaultKind::Timeout),
                "BHF-210",
                "CWE-119",
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
            // no phantom sanitizer frames, and an informative message.
            assert_eq!(report.rule_id, expected_rule, "report rule for {fault:?}");
            assert_eq!(cwe_of(&report), expected_cwe, "CWE for {fault:?}");
            assert!(report.stack.is_empty(), "undiagnosed fault has no frames");
            assert!(
                report.message.contains("reachable crash"),
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
            (FaultKind::Watchdog, "BHF-210", "CWE-119"),
            (FaultKind::AssertionPanic, "BHF-210", "CWE-119"),
            (FaultKind::StackOverflow, "BHF-207", "CWE-674"),
            (FaultKind::Timeout, "BHF-210", "CWE-119"),
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
        };
        let report = outcome_finding(&bare_crash).expect("faultless crash is still a finding");
        assert_eq!(report.rule_id, "BHF-210");

        let bare_timeout = RunOutcome {
            exit: ExitKind::Timeout,
            coverage_edges: Vec::new(),
            fault: None,
            stdout: Vec::new(),
        };
        let report = outcome_finding(&bare_timeout).expect("faultless timeout is still a finding");
        assert_eq!(report.rule_id, "BHF-210");
        assert_eq!(cwe_of(&report), "CWE-119");
    }
}
