// SPDX-License-Identifier: Apache-2.0

//! The paths a sanitizer's symbolizer opens while it writes a report, which
//! are no resource of the target's: never logged as missing, never faked.

/// The names the kernel's vDSO goes by in a link map. They are not files; a
/// symbolizer that tries to open one must see it missing.
const VDSO_NAMES: &[&[u8]] = &[b"linux-vdso.so.1", b"linux-gate.so.1", b"linux-vdso64.so.1"];

/// Whether `path` is one a symbolizer opens while it writes a report: the
/// vDSO's link-map name, a separate debug file beside an object
/// (`<obj>.debug`, `<dir>/.debug/<obj>`), or the name of an object the
/// process has loaded. Faking any of them hands the symbolizer a bogus file.
pub fn is_symbolizer_path(path: &[u8]) -> bool {
    let name = path.rsplit(|&b| b == b'/').next().unwrap_or(path);
    VDSO_NAMES.contains(&name)
        || name.ends_with(b".debug")
        || path
            .split(|&b| b == b'/')
            .any(|segment| segment == b".debug")
        || is_loaded_object_name(path)
}

/// Whether `path` is the name of an object the process has already loaded
/// (its link-map name, as `dl_iterate_phdr` reports it). A symbolizer
/// re-opens the loaded objects by those names; one it cannot open is not a
/// resource the target is missing. Walks the link map in place (no
/// allocation), a few string compares per call.
pub fn is_loaded_object_name(path: &[u8]) -> bool {
    struct Probe<'a> {
        path: &'a [u8],
        found: bool,
    }
    unsafe extern "C" fn visit(
        info: *mut libc::dl_phdr_info,
        _size: libc::size_t,
        data: *mut libc::c_void,
    ) -> libc::c_int {
        let probe = &mut *(data as *mut Probe<'_>);
        let name = (*info).dlpi_name;
        if !name.is_null() && std::ffi::CStr::from_ptr(name).to_bytes() == probe.path {
            probe.found = true;
            return 1;
        }
        0
    }
    if path.is_empty() {
        return false;
    }
    let mut probe = Probe { path, found: false };
    unsafe {
        libc::dl_iterate_phdr(Some(visit), (&mut probe as *mut Probe<'_>).cast());
    }
    probe.found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_vdso_and_separate_debug_files_are_symbolizer_paths() {
        for path in [
            b"linux-vdso.so.1".as_slice(),
            b"linux-gate.so.1".as_slice(),
            b"linux-vdso64.so.1".as_slice(),
            b"/usr/lib/x86_64-linux-gnu/linux-vdso.so.1".as_slice(),
            b"/lib/x86_64-linux-gnu/libc.so.6.debug".as_slice(),
            b"/lib/x86_64-linux-gnu/.debug/libc.so.6".as_slice(),
            b"/opt/app/bin/.debug/widget".as_slice(),
            b"widget.debug".as_slice(),
        ] {
            assert!(
                is_symbolizer_path(path),
                "{} is a symbolizer path",
                String::from_utf8_lossy(path)
            );
        }
        // Lookalikes are ordinary paths.
        for path in [
            b"/etc/linux-vdso.so.1.conf".as_slice(),
            b"/srv/data/widget.debugger".as_slice(),
            b"/srv/data.debug-notes/cfg".as_slice(),
            b"/etc/widget.conf".as_slice(),
        ] {
            assert!(
                !is_symbolizer_path(path),
                "{} is an ordinary path",
                String::from_utf8_lossy(path)
            );
        }
    }

    /// A path naming an object the process has loaded (the symbolizer
    /// re-opening a library by its link-map name) is a symbolizer path.
    #[test]
    fn a_loaded_object_name_is_a_symbolizer_path() {
        let mut loaded: Vec<Vec<u8>> = Vec::new();
        unsafe extern "C" fn collect(
            info: *mut libc::dl_phdr_info,
            _size: libc::size_t,
            data: *mut libc::c_void,
        ) -> libc::c_int {
            let names = &mut *(data as *mut Vec<Vec<u8>>);
            let name = (*info).dlpi_name;
            if !name.is_null() {
                let bytes = std::ffi::CStr::from_ptr(name).to_bytes();
                if bytes.starts_with(b"/") {
                    names.push(bytes.to_vec());
                }
            }
            0
        }
        unsafe {
            libc::dl_iterate_phdr(Some(collect), (&mut loaded as *mut Vec<Vec<u8>>).cast());
        }
        let name = loaded.first().expect("a test binary loads libc");
        assert!(
            is_loaded_object_name(name),
            "{}",
            String::from_utf8_lossy(name)
        );
        assert!(is_symbolizer_path(name));
        assert!(!is_loaded_object_name(b"/nonexistent/libwidget.so.3"));
    }
}
