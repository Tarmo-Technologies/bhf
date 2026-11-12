// SPDX-License-Identifier: Apache-2.0

//! Whether a sanitizer has started writing a report in this process. The
//! report's symbolizer opens objects and debug files by name, and a fake one
//! breaks the report (GCC's static libasan aborts with a nested error and the
//! finding loses its stack), so from then on the shim fakes nothing
//! ([`crate::fakes::mode::current`]).

use std::sync::atomic::{AtomicBool, Ordering};

static SANITIZER_REPORTING: AtomicBool = AtomicBool::new(false);

/// Whether [`bhf_shim_sanitizer_reporting`] was called in this process.
pub fn sanitizer_is_reporting() -> bool {
    SANITIZER_REPORTING.load(Ordering::Relaxed)
}

/// Called by bhf's C/C++ driver from AddressSanitizer's `__asan_on_error`,
/// at the start of every report: from then on this process fakes nothing.
#[no_mangle]
pub extern "C" fn bhf_shim_sanitizer_reporting() {
    SANITIZER_REPORTING.store(true, Ordering::Relaxed);
}
