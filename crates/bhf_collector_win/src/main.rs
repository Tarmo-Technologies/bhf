// SPDX-License-Identifier: Apache-2.0

//! `bhf-collector-win` sidecar entry point.
//!
//! As an external collector it reads its context from the `BHF_COLLECTOR_*`
//! environment variables and writes a `bhf.collector-event.v1` JSONL stream to
//! the sink named by `BHF_COLLECTOR_LOG` (or stdout). The native ETW provider
//! only exists on Windows; on any other host this binary exits non-zero rather
//! than pretending to observe, so a host never mistakes a stub for a clean run.

fn main() {
    #[cfg(windows)]
    {
        std::process::exit(bhf_collector_win::etw::main_entry());
    }

    #[cfg(not(windows))]
    {
        eprintln!(
            "bhf-collector-win is the native Windows ETW provider and requires Windows; \
             this build cannot observe on the current platform."
        );
        std::process::exit(2);
    }
}
