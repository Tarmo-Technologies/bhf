// SPDX-License-Identifier: Apache-2.0

//! Intercept dlsym(handle, name). When the handle is one of ours
//! (synthetic dlopen handle from Task 5), return a pointer to the
//! per-name stub. Otherwise pass through to the real dlsym.
//!
//! Safety: the #[no_mangle] extern "C" fn here overrides libdl's
//! dlsym. Caller-supplied pointers must satisfy libdl's dlsym()
//! contract — we forward unchanged or substitute a stub address.

#![allow(clippy::missing_safety_doc)]
#![allow(clippy::missing_transmute_annotations)]

use crate::dlsym::ResolvedFn;
use crate::fakes::dl_handle::{bhf_fake_dlsym_stub, is_synthetic};
use crate::fakes::mode::current;
use crate::jsonl::Builder;
use crate::reentrancy::HookGuard;
use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::ptr::NonNull;

static REAL_DLSYM: ResolvedFn = ResolvedFn::new(b"dlsym\0");

/// The `dlsym` hook, entered from the C trampoline in `format_hooks.c` with
/// the address it was called from.
///
/// `dlsym(RTLD_NEXT, name)` means "the next definition after the calling
/// object", and glibc reads the caller from `dlsym`'s return address. A
/// sanitizer runtime resolves the real `fopen`, `dlopen`, `memcmp`, ...
/// behind its interceptors this way; were the lookup forwarded from here, it
/// would search the objects after this library and skip its hooks (or, for a
/// runtime loaded after it, find the interceptor itself). So this only
/// answers what is the shim's to answer: a synthetic handle's stub, and for
/// the symbols in [`next_hook`], when the caller was loaded before this
/// library, this library's hook. Anything else returns [`FORWARD`], and the C
/// trampoline in `format_hooks.c` tail-calls the real `dlsym`, which then
/// sees the original caller.
#[no_mangle]
pub unsafe extern "C" fn bhf_shim_dlsym(
    handle: *mut libc::c_void,
    symbol: *const libc::c_char,
    caller: *const libc::c_void,
) -> *mut libc::c_void {
    if is_synthetic(handle) {
        if !symbol.is_null() {
            if let Some(_g) = HookGuard::acquire() {
                let name = CStr::from_ptr(symbol).to_bytes();
                let mut b = Builder::new(b"dlsym");
                b.field_str(b"s", name);
                b.field_str(b"r", b"stub");
                b.field_str(b"m", current().as_str().as_bytes());
                b.emit();
            }
        }
        return bhf_fake_dlsym_stub as *mut libc::c_void;
    }
    if handle == libc::RTLD_NEXT && !symbol.is_null() {
        if let Some(hook) = next_hook(CStr::from_ptr(symbol).to_bytes()) {
            if loaded_before_this_library(caller) {
                return hook;
            }
        }
    }
    FORWARD as *mut libc::c_void
}

/// What [`bhf_shim_dlsym`] returns for a lookup the real `dlsym` answers. No
/// symbol resolves to the last address.
pub const FORWARD: usize = usize::MAX;

/// The real `dlsym` the trampoline forwards to, or null when it cannot be
/// resolved (calling `libc::dlsym` from here would re-enter the hook).
#[no_mangle]
pub extern "C" fn bhf_shim_real_dlsym() -> *mut libc::c_void {
    REAL_DLSYM.ptr()
}

/// This library's hook that `dlsym(RTLD_NEXT, name)` from an earlier object
/// should find.
fn next_hook(name: &[u8]) -> Option<*mut libc::c_void> {
    Some(match name {
        b"fopen" => crate::hooks::fs::fopen_hook as *mut libc::c_void,
        b"fopen64" => crate::hooks::fs::fopen64_hook as *mut libc::c_void,
        _ => return None,
    })
}

/// glibc's `struct link_map` prefix (`<link.h>`).
#[repr(C)]
struct LinkMap {
    l_addr: usize,
    l_name: *const libc::c_char,
    l_ld: *mut libc::c_void,
    l_next: *mut LinkMap,
    l_prev: *mut LinkMap,
}

const RTLD_DL_LINKMAP: libc::c_int = 2;

/// libc's `dladdr1`, not the one the PLT binds: a sanitizer defines `dladdr1`
/// in the executable, and its interceptor has nothing to call while the
/// sanitizer is still resolving its interceptors through this hook.
static REAL_DLADDR1: ResolvedFn = ResolvedFn::new(b"dladdr1\0");

/// The loaded object that contains `addr`.
unsafe fn link_map_of(addr: *const libc::c_void) -> Option<NonNull<LinkMap>> {
    let real = REAL_DLADDR1.ptr();
    if real.is_null() {
        return None;
    }
    let real: unsafe extern "C" fn(
        *const libc::c_void,
        *mut libc::Dl_info,
        *mut *mut libc::c_void,
        libc::c_int,
    ) -> libc::c_int = std::mem::transmute(real);
    let mut info: libc::Dl_info = std::mem::zeroed();
    // dladdr1 writes the link map only when it succeeds, so it is read only then.
    let mut map = MaybeUninit::<*mut libc::c_void>::uninit();
    if real(addr, &mut info, map.as_mut_ptr(), RTLD_DL_LINKMAP) == 0 {
        return None;
    }
    NonNull::new(map.assume_init().cast::<LinkMap>())
}

/// Whether the object containing `caller` comes before this library in load
/// order (the program itself always does).
unsafe fn loaded_before_this_library(caller: *const libc::c_void) -> bool {
    let (Some(caller), Some(own)) = (
        link_map_of(caller),
        link_map_of(next_hook as *const libc::c_void),
    ) else {
        return false;
    };
    if caller == own {
        return false;
    }
    let mut next = NonNull::new(caller.as_ref().l_next);
    for _ in 0..4096 {
        let Some(entry) = next else {
            return false;
        };
        if entry == own {
            return true;
        }
        next = NonNull::new(entry.as_ref().l_next);
    }
    false
}

pub struct Dlsym;

impl crate::sdk::FakeResource for Dlsym {
    fn name(&self) -> &'static str {
        "dlsym"
    }
    fn intercepts(&self) -> &'static [&'static [u8]] {
        &[b"dlsym\0"]
    }
    fn is_enabled(&self) -> bool {
        true
    }
    fn describe(&self) -> &'static str {
        "resolve dlsym lookups against fake dlopen handles"
    }
}
