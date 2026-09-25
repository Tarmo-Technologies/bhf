// SPDX-License-Identifier: Apache-2.0

//! Shared classification for fatal harness exits without sanitizer diagnostics.

/// Rule emitted for a fatal signal that has no more specific runtime diagnostic.
pub(crate) const RULE_ID: &str = "BHF-210";

/// The exit code used by the Windows harness exception handler.
pub(crate) const BHF_WIN_CRASH_EXIT: i32 = 0x39;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FatalSignal {
    pub(crate) name: String,
}

fn has_abort_rejection_diagnostic(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    (lower.contains("assertion") && lower.contains("failed"))
        || lower.contains("assert failed")
        || lower.contains("panicked at")
        || lower.contains("panic:")
}

/// Classify an undiagnosed fatal-signal exit. Plain non-zero exits, external
/// termination signals, SIGPIPE, and diagnosed assertion/panic aborts are not
/// crashes for this purpose.
#[cfg(unix)]
pub(crate) fn classify(status: &std::process::ExitStatus, stderr: &str) -> Option<FatalSignal> {
    use std::os::unix::process::ExitStatusExt;

    if status.code() == Some(BHF_WIN_CRASH_EXIT) {
        return Some(FatalSignal {
            name: "Windows exception (access violation / fault, via wine)".to_owned(),
        });
    }

    let signal = status.signal()?;
    if signal == 6 && has_abort_rejection_diagnostic(stderr) {
        return None;
    }
    let name = match signal {
        4 => "SIGILL".to_owned(),
        6 => "SIGABRT".to_owned(),
        7 => "SIGBUS".to_owned(),
        8 => "SIGFPE".to_owned(),
        11 => "SIGSEGV".to_owned(),
        _ => return None,
    };
    Some(FatalSignal { name })
}

#[cfg(not(unix))]
pub(crate) fn classify(status: &std::process::ExitStatus, _stderr: &str) -> Option<FatalSignal> {
    (status.code() == Some(BHF_WIN_CRASH_EXIT)).then(|| FatalSignal {
        name: "Windows exception (access violation / fault)".to_owned(),
    })
}

pub(crate) fn rule_id(status: &std::process::ExitStatus, stderr: &str) -> Option<&'static str> {
    classify(status, stderr).map(|_| RULE_ID)
}

#[cfg(all(test, unix))]
mod tests {
    use super::{classify, rule_id, RULE_ID};
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    fn by_signal(signal: i32) -> ExitStatus {
        ExitStatus::from_raw(signal)
    }

    #[test]
    fn silent_abort_is_a_fatal_signal() {
        let crash = classify(&by_signal(6), "").expect("silent SIGABRT");
        assert_eq!(crash.name, "SIGABRT");
        assert_eq!(rule_id(&by_signal(6), ""), Some(RULE_ID));
    }

    #[test]
    fn diagnosed_abort_is_an_input_rejection() {
        assert_eq!(classify(&by_signal(6), "Assertion failed."), None);
        assert_eq!(classify(&by_signal(6), "thread panicked at source"), None);
    }

    #[test]
    fn host_signal_path_still_maps_sigsegv_and_sigabrt_to_bhf210() {
        // Regression (HDF-2): generalizing the crash taxonomy for transport faults
        // must not move the host `ExitStatus::signal()` path. A silent SIGSEGV and
        // a silent SIGABRT stay classified crashes on rule BHF-210, exactly as
        // before the transport-fault lane was added.
        let segv = classify(&by_signal(11), "").expect("SIGSEGV is a crash");
        assert_eq!(segv.name, "SIGSEGV");
        assert_eq!(rule_id(&by_signal(11), ""), Some(RULE_ID));

        let abrt = classify(&by_signal(6), "").expect("silent SIGABRT is a crash");
        assert_eq!(abrt.name, "SIGABRT");
        assert_eq!(rule_id(&by_signal(6), ""), Some(RULE_ID));

        assert_eq!(RULE_ID, "BHF-210");
    }

    #[test]
    fn only_hardware_fault_signals_are_classified() {
        for signal in [4, 7, 8, 11] {
            assert!(classify(&by_signal(signal), "").is_some());
        }
        for signal in [1, 2, 13, 14, 15] {
            assert_eq!(classify(&by_signal(signal), ""), None);
        }
        assert_eq!(classify(&ExitStatus::from_raw(2 << 8), ""), None);
    }
}
