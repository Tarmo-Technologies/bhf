// SPDX-License-Identifier: Apache-2.0

//! `libbhf_runtrace.so` — LD_PRELOAD shim loaded by `bhf auto`
//! into each fuzz target binary. Intercepts a fixed list of libc and
//! libdl entry points (open / getenv / connect / dlopen / ...), calls
//! the real implementation via dlsym(RTLD_NEXT, ...), and appends
//! one-line JSONL runtime events to the file path given in
//! `BHF_RUNTRACE_LOG`.
//!
//! Allocation discipline: every hook formats its event into a stack
//! buffer and writes it via libc::write directly. We must NOT call
//! malloc / free / Box::new / String / Vec from inside a hook because
//! the hooked process may already be inside its own allocator on the
//! path we're being called from.

// This crate is an LD_PRELOAD interposer: it intentionally defines `#[no_mangle]
// extern "C"` symbols (e.g. `open(path, flags, mode_t)`) that shadow libc at load
// time. rustc 1.99 added `invalid_runtime_symbol_definitions` (deny-by-default),
// which flags `open` because libc's canonical declaration is variadic
// (`..., ...`). The fixed-arity interposer signature is the standard, ABI-safe
// idiom for overriding `open`, so allow it crate-wide.
#![allow(invalid_runtime_symbol_definitions)]

#[cfg(target_os = "linux")]
pub mod dlsym;
#[cfg(target_os = "linux")]
pub mod fakes;
#[cfg(target_os = "linux")]
pub mod hooks;
#[cfg(target_os = "linux")]
pub mod jsonl;
#[cfg(target_os = "linux")]
pub mod policy;
#[cfg(target_os = "linux")]
pub mod reentrancy;
#[cfg(target_os = "linux")]
pub mod registry;
pub mod sdk;

/// Re-export the manifest types so the existing test/code paths
/// continue to work while the data itself lives in the cli-safe
/// `runtrace_manifest` crate.
pub mod manifest {
    pub use runtrace_manifest::{ManifestEntry, MANIFEST};
}

#[cfg(not(target_os = "linux"))]
mod stub {
    // Empty cdylib on macOS / Windows. The auto loop's
    // shim_path::locate() will probably still find the .so/.dylib,
    // but none of the symbols override anything, so the audit is
    // a no-op.
}
