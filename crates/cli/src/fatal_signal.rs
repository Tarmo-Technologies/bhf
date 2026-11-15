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

#[cfg(unix)]
fn has_abort_rejection_diagnostic(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    (lower.contains("assertion") && lower.contains("failed"))
        || lower.contains("assert failed")
        || lower.contains("panicked at")
        || lower.contains("panic:")
}

/// What sanitizer runtimes print when they cannot start on this host: the
/// process dies before `main`, whatever the input. Each is a problem of the
/// host or the build, never of the target.
const RUNTIME_START_FAILURES: &[&str] = &[
    // ThreadSanitizer's shadow layout against the kernel's address space
    // layout (GCC's libtsan under high-entropy ASLR), and a non-PIE binary.
    "ThreadSanitizer: unexpected memory mapping",
    "ThreadSanitizer: failed to mmap",
    "is out of application range. Non-PIE build?",
    "Make sure to compile with -fPIE and to link with -pie",
    // MemorySanitizer's shadow.
    "MemorySanitizer can not mmap the shadow memory",
    // AddressSanitizer's shadow and its interceptors.
    "Shadow memory range interleaves with an existing memory mapping",
    "ReserveShadowMemoryRange failed while trying to map",
    "ASan runtime does not come first in initial library list",
    "Interceptors are not working. This may be because AddressSanitizer is loaded too late",
];

/// The line in `stderr` where a sanitizer runtime says it cannot start on
/// this host (`FATAL: ThreadSanitizer: unexpected memory mapping ...`), if
/// there is one. Such an exit is an environment error: it is never a
/// finding, whatever signal ended the process.
pub(crate) fn sanitizer_runtime_start_failure(stderr: &str) -> Option<String> {
    stderr
        .lines()
        .find(|line| {
            RUNTIME_START_FAILURES
                .iter()
                .any(|marker| line.contains(marker))
        })
        .map(|line| line.trim().chars().take(240).collect())
}

/// Classify an undiagnosed fatal-signal exit. Plain non-zero exits, external
/// termination signals, SIGPIPE, diagnosed assertion/panic aborts and a
/// sanitizer runtime that could not start are not crashes for this purpose.
#[cfg(unix)]
pub(crate) fn classify(status: &std::process::ExitStatus, stderr: &str) -> Option<FatalSignal> {
    use std::os::unix::process::ExitStatusExt;

    if sanitizer_runtime_start_failure(stderr).is_some() {
        return None;
    }
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
        // A trap instruction: `__builtin_trap` on AArch64, and the sanitizer
        // checks built with `-fsanitize-trap` there.
        5 => "SIGTRAP".to_owned(),
        6 => "SIGABRT".to_owned(),
        7 => "SIGBUS".to_owned(),
        8 => "SIGFPE".to_owned(),
        11 => "SIGSEGV".to_owned(),
        _ => return None,
    };
    Some(FatalSignal { name })
}

#[cfg(not(unix))]
pub(crate) fn classify(status: &std::process::ExitStatus, stderr: &str) -> Option<FatalSignal> {
    (status.code() == Some(BHF_WIN_CRASH_EXIT) && sanitizer_runtime_start_failure(stderr).is_none())
        .then(|| FatalSignal {
            name: "Windows exception (access violation / fault)".to_owned(),
        })
}

#[cfg(all(test, unix))]
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

    /// A trap instruction (`__builtin_trap` on AArch64, or a sanitizer check
    /// built with `-fsanitize-trap`) raises SIGTRAP: a crash, not a
    /// rejection.
    #[test]
    fn a_trap_is_a_fatal_signal() {
        let trap = classify(&by_signal(5), "").expect("SIGTRAP is a crash");
        assert_eq!(trap.name, "SIGTRAP");
        assert_eq!(rule_id(&by_signal(5), ""), Some(RULE_ID));
    }

    #[test]
    fn only_hardware_fault_signals_are_classified() {
        for signal in [4, 5, 7, 8, 11] {
            assert!(classify(&by_signal(signal), "").is_some());
        }
        for signal in [1, 2, 13, 14, 15] {
            assert_eq!(classify(&by_signal(signal), ""), None);
        }
        assert_eq!(classify(&ExitStatus::from_raw(2 << 8), ""), None);
    }

    /// A sanitizer runtime that cannot start (GCC's ThreadSanitizer under
    /// high-entropy ASLR) aborts every run before `main`: never a crash, and
    /// its own line is what the run reports.
    #[test]
    fn a_sanitizer_runtime_that_cannot_start_is_not_a_crash() {
        use super::sanitizer_runtime_start_failure;
        let tsan =
            "FATAL: ThreadSanitizer: unexpected memory mapping 0x5a34d0219000-0x5a34d0222000\n";
        assert_eq!(classify(&by_signal(6), tsan), None);
        assert_eq!(classify(&by_signal(11), tsan), None);
        assert_eq!(
            sanitizer_runtime_start_failure(tsan).as_deref(),
            Some("FATAL: ThreadSanitizer: unexpected memory mapping 0x5a34d0219000-0x5a34d0222000")
        );
        let asan = "==12==Shadow memory range interleaves with an existing memory mapping. \
                    ASan cannot proceed correctly. ABORTING.\n";
        assert_eq!(classify(&by_signal(6), asan), None);
        assert!(sanitizer_runtime_start_failure(
            "==7==ASan runtime does not come first in initial library list; you should either \
             link runtime to your application or manually preload it with LD_PRELOAD.\n"
        )
        .is_some());
        // A report from a runtime that started is not one.
        let report = "==9==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020\n";
        assert_eq!(sanitizer_runtime_start_failure(report), None);
        assert!(classify(&by_signal(6), report).is_some());
    }
}
