// SPDX-License-Identifier: Apache-2.0

//! Recording only once the target is entered (#300).
//!
//! An interpreter launcher's process runs the interpreter's own start-up
//! before its harness reaches the target: imports, locale and configuration
//! probes, and its own string comparisons, megabytes of them for CPython.
//! None of it is the target's. With `BHF_RUNTRACE_AFTER_TARGET_ENTRY=1` the
//! shim records no event until the process opens the file
//! `BHF_TARGET_ENTRY_SHM` names, which the harness does right before it first
//! calls the target to mark that it got there. From then on it records as
//! usual. Without the variable it records from the start, as before.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;

const UNKNOWN: u8 = 0;
const RECORDING: u8 = 1;
const WAITING: u8 = 2;

static STATE: AtomicU8 = AtomicU8::new(UNKNOWN);
static ENTRY_PATH: OnceLock<Option<Vec<u8>>> = OnceLock::new();

fn entry_path() -> Option<&'static [u8]> {
    ENTRY_PATH
        .get_or_init(|| {
            use std::os::unix::ffi::OsStrExt;
            std::env::var_os("BHF_TARGET_ENTRY_SHM")
                .filter(|path| !path.is_empty())
                .map(|path| path.as_bytes().to_vec())
        })
        .as_deref()
}

fn state() -> u8 {
    let current = STATE.load(Ordering::Acquire);
    if current != UNKNOWN {
        return current;
    }
    let gated = std::env::var_os("BHF_RUNTRACE_AFTER_TARGET_ENTRY")
        .is_some_and(|value| value == "1")
        && entry_path().is_some();
    // Name the input file now, in the driver's process (see `input_file`).
    let _ = crate::fakes::fuzz_input::input_file();
    let next = if gated { WAITING } else { RECORDING };
    let _ = STATE.compare_exchange(UNKNOWN, next, Ordering::AcqRel, Ordering::Acquire);
    STATE.load(Ordering::Acquire)
}

/// Whether events are recorded now.
pub fn recording() -> bool {
    state() == RECORDING
}

/// An open of `path` by the process: the target-entry file starts recording.
pub fn note_open(path: &[u8]) {
    if state() == WAITING && entry_path() == Some(path) {
        STATE.store(RECORDING, Ordering::Release);
    }
}

/// Whether `path` is one of bhf's own files a launcher's driver opens (the
/// target-entry mark, the input it publishes): not the target's, so no open
/// event is recorded for it.
pub fn is_bhf_file(path: &[u8]) -> bool {
    entry_path() == Some(path)
        || crate::fakes::fuzz_input::input_file().is_some_and(|file| file.to_bytes() == path)
}
