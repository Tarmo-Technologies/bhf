// SPDX-License-Identifier: Apache-2.0

//! Resolve the "real" implementations of intercepted syscalls in the
//! next link-map entry after ours (the host libc).
//!
//! We must not call the plain `dlsym` symbol from inside the shim:
//! this cdylib overrides `dlsym` (see `hooks/dlsym.rs`), so the
//! `dlsym` name would bind back to our own hook and recurse. So we
//! resolve in two steps:
//!
//! 1. Look up the symbol at the architecture's base glibc version
//!    with `dlvsym`, which bypasses our hook.
//! 2. For symbols introduced later, use the real libc `dlsym`,
//!    resolved once at that base version. This avoids re-entering
//!    the shim's own `dlsym` hook.
//!
//! We cache each resolution in a static AtomicPtr so subsequent
//! calls are a single relaxed-atomic load.

use std::ffi::CStr;
use std::sync::atomic::{AtomicPtr, Ordering};

#[cfg(target_arch = "aarch64")]
const GLIBC_BASE_VERSION: &[u8] = b"GLIBC_2.17\0";
#[cfg(not(target_arch = "aarch64"))]
const GLIBC_BASE_VERSION: &[u8] = b"GLIBC_2.2.5\0";

/// The real libc `dlsym`, resolved once via the un-hooked `dlvsym`.
/// Used only for the unversioned fallback in `resolve`.
static REAL_DLSYM_PTR: AtomicPtr<libc::c_void> = AtomicPtr::new(std::ptr::null_mut());

type DlsymFn = unsafe extern "C" fn(*mut libc::c_void, *const libc::c_char) -> *mut libc::c_void;

unsafe fn real_dlsym() -> Option<DlsymFn> {
    let cached = REAL_DLSYM_PTR.load(Ordering::Relaxed);
    let raw = if cached.is_null() {
        // `dlsym` itself is present at the base version, so the
        // versioned lookup resolves it without touching our hook.
        let p = libc::dlvsym(
            libc::RTLD_NEXT,
            c"dlsym".as_ptr(),
            GLIBC_BASE_VERSION.as_ptr() as *const libc::c_char,
        );
        REAL_DLSYM_PTR.store(p, Ordering::Relaxed);
        p
    } else {
        cached
    };
    if raw.is_null() {
        None
    } else {
        Some(std::mem::transmute::<*mut libc::c_void, DlsymFn>(raw))
    }
}

/// Look up `symbol` in the next link-map entry after ours (the host
/// libc). Returns null on failure — caller should short-circuit
/// (not call anything, just return a sensible default to the
/// original caller).
unsafe fn resolve(symbol: &CStr) -> *mut libc::c_void {
    let versioned = libc::dlvsym(
        libc::RTLD_NEXT,
        symbol.as_ptr(),
        GLIBC_BASE_VERSION.as_ptr() as *const libc::c_char,
    );
    if !versioned.is_null() {
        return versioned;
    }
    // Symbol versioned later than the base — unversioned fallback via
    // the real dlsym. RTLD_NEXT is evaluated against this shim's call
    // frame, so it still resolves to libc, not back to our hook.
    match real_dlsym() {
        Some(dlsym) => dlsym(libc::RTLD_NEXT, symbol.as_ptr()),
        None => std::ptr::null_mut(),
    }
}

/// Cache the resolution of a single named symbol. Use one
/// `ResolvedFn` per intercepted function:
///
/// ```ignore
/// static REAL_OPEN: ResolvedFn = ResolvedFn::new(b"open\0");
/// ```
pub struct ResolvedFn {
    name: &'static [u8],
    cache: AtomicPtr<libc::c_void>,
}

impl ResolvedFn {
    pub const fn new(name: &'static [u8]) -> Self {
        Self {
            name,
            cache: AtomicPtr::new(std::ptr::null_mut()),
        }
    }

    /// Returns the resolved fn pointer or null if dlsym failed. Use
    /// `is_null()` on the result before casting + calling.
    pub fn ptr(&self) -> *mut libc::c_void {
        let cached = self.cache.load(Ordering::Relaxed);
        if !cached.is_null() {
            return cached;
        }
        // Safety: `name` is a static nul-terminated byte slice.
        let cstr = unsafe { CStr::from_bytes_with_nul_unchecked(self.name) };
        let p = unsafe { resolve(cstr) };
        self.cache.store(p, Ordering::Relaxed);
        p
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn libc_lookup_resolves_base_and_later_symbols() {
        unsafe {
            assert!(super::real_dlsym().is_some());
            for symbol in [c"getpid", c"openat", c"secure_getenv"] {
                assert!(
                    !super::resolve(symbol).is_null(),
                    "failed to resolve {symbol:?}"
                );
            }
        }
    }
}
