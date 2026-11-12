// SPDX-License-Identifier: Apache-2.0

//! Printf-style format-string audit hooks. The variadic entrypoints
//! live in `format_hooks.c`; this Rust module provides the log helper
//! and plugin metadata.

#![allow(clippy::missing_safety_doc)]

use crate::jsonl::Builder;
use crate::reentrancy::HookGuard;
use std::ffi::CStr;

unsafe extern "C" {
    fn dprintf();
    fn fprintf();
    fn bhf_format_hook_anchor();
    fn printf();
    fn snprintf();
    fn sprintf();
    fn asprintf();
    fn vprintf();
    fn vfprintf();
    fn vsprintf();
    fn vsnprintf();
    fn vdprintf();
    fn vasprintf();
    fn bhf_format_next_hook(name: *const libc::c_char) -> *mut libc::c_void;
}

#[used]
static KEEP_FORMAT_HOOKS: [unsafe extern "C" fn(); 13] = [
    bhf_format_hook_anchor,
    printf,
    fprintf,
    dprintf,
    sprintf,
    snprintf,
    asprintf,
    vprintf,
    vfprintf,
    vsprintf,
    vsnprintf,
    vdprintf,
    vasprintf,
];

/// The `va_list` format hook a `dlsym(RTLD_NEXT, name)` from an object loaded
/// before this library should find (a sanitizer runtime forwards `printf` to
/// the `vprintf` it resolves this way), or `None` for any other name.
pub(crate) fn next_hook(name: &[u8]) -> Option<*mut libc::c_void> {
    // The C table holds the hooks' own (hidden) addresses; the exported names
    // are preemptible and would resolve to the interceptor itself.
    let mut buf = [0u8; 32];
    if name.len() >= buf.len() || name.contains(&0) {
        return None;
    }
    buf[..name.len()].copy_from_slice(name);
    let hook = unsafe { bhf_format_next_hook(buf.as_ptr().cast()) };
    (!hook.is_null()).then_some(hook)
}

#[no_mangle]
pub unsafe extern "C" fn bhf_runtrace_log_format(
    api: *const libc::c_char,
    format: *const libc::c_char,
) {
    if api.is_null() || format.is_null() {
        return;
    }
    let api = CStr::from_ptr(api).to_bytes();
    let format = CStr::from_ptr(format).to_bytes();
    if api.is_empty() || format.is_empty() {
        return;
    }
    let Some(_guard) = HookGuard::acquire() else {
        return;
    };
    let controlled = crate::fakes::fuzz_input::contains_bytes(format);
    let mut builder = Builder::new(b"format");
    builder.field_str(b"a", api);
    builder.field_str(b"f", format);
    builder.field_i64(b"u", i64::from(controlled));
    builder.emit();
}

pub struct Format;

impl crate::sdk::FakeResource for Format {
    fn name(&self) -> &'static str {
        "format"
    }
    fn intercepts(&self) -> &'static [&'static [u8]] {
        &[
            b"printf\0",
            b"fprintf\0",
            b"sprintf\0",
            b"snprintf\0",
            b"dprintf\0",
            b"asprintf\0",
            b"vprintf\0",
            b"vfprintf\0",
            b"vsprintf\0",
            b"vsnprintf\0",
            b"vdprintf\0",
            b"vasprintf\0",
            b"__printf_chk\0",
            b"__fprintf_chk\0",
            b"__sprintf_chk\0",
            b"__snprintf_chk\0",
            b"__dprintf_chk\0",
            b"__asprintf_chk\0",
            b"__vprintf_chk\0",
            b"__vfprintf_chk\0",
            b"__vsprintf_chk\0",
            b"__vsnprintf_chk\0",
            b"__vdprintf_chk\0",
            b"__vasprintf_chk\0",
        ]
    }
    fn is_enabled(&self) -> bool {
        true
    }
    fn describe(&self) -> &'static str {
        "log printf-style format strings and whether they match current fuzz input"
    }
}
