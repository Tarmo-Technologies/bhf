// SPDX-License-Identifier: Apache-2.0
#![cfg(windows)]

//! Dependency-gated live ETW tests. The whole file is `#[cfg(windows)]`, so on
//! Linux CI it compiles to an empty test binary and runs nothing. Each test is
//! additionally `#[ignore]` unless `BHF_WIN_LIVE=1`, so it only executes on a
//! Windows runner that opts in (the `windows-build` CI job sets the variable).

use bhf_collector_win::etw;
use runtime_collector::{CollectorContext, CollectorSessionSet};

fn live_enabled() -> bool {
    std::env::var("BHF_WIN_LIVE").as_deref() == Ok("1")
}

fn ctx() -> CollectorContext {
    CollectorContext::new("tc-live", 0, "C:\\sandbox", 250)
}

#[test]
#[ignore = "requires BHF_WIN_LIVE=1 on a Windows runner"]
fn collect_emits_well_formed_schema() {
    if !live_enabled() {
        return;
    }
    let jsonl = etw::collect(
        &ctx(),
        std::process::id(),
        "C:\\sandbox\\target.exe",
        Vec::new(),
    );
    let set = CollectorSessionSet::from_jsonl(&jsonl);
    assert_eq!(set.malformed_lines, 0, "live stream must be valid schema");
    assert!(set.session("tc-live", 0).is_some());
}

#[test]
#[ignore = "requires BHF_WIN_LIVE=1 on a Windows runner"]
fn missing_session_rights_report_permission_denied_not_clean() {
    // AC #6 (native): a degraded ETW observation must never be reported clean —
    // when the provider records a fidelity limitation (e.g. it could not start
    // an ETW session without rights), `clean_assurance_ok()` must be false.
    //
    // This asserts the environment-robust invariant `degraded ⟹ not clean`
    // rather than assuming the runner lacks rights: GitHub's Windows runners are
    // elevated, so `etw::collect` starts the NT Kernel Logger session and
    // (correctly) reports a non-degraded, clean observation — there the
    // implication is vacuously true. On a runner without session rights the
    // permission limitation is recorded and the clean claim must be refused.
    // The deterministic form of this property is covered by the `win_core` unit
    // test `permission_denied_is_recorded_not_silent`.
    if !live_enabled() {
        return;
    }
    let jsonl = etw::collect(
        &ctx(),
        std::process::id(),
        "C:\\sandbox\\target.exe",
        Vec::new(),
    );
    let set = CollectorSessionSet::from_jsonl(&jsonl);
    let session = set.session("tc-live", 0).expect("session present");
    if session.fidelity.is_degraded() {
        assert!(
            !session.clean_assurance_ok(),
            "a degraded live observation must never be reported clean"
        );
    }
}

// The three positive fixtures (ShellExecuteExW on a fuzz-controlled target, a
// fuzz-controlled `..\\escaped` path, and LoadLibraryW on a fuzz-controlled
// non-system path) plus the fixed-constant negative controls require live
// EVENT_RECORD decoding, which is validated and completed on the Windows runner.
// They are tracked separately so this gate stays honest about what the current
// native cut observes.
