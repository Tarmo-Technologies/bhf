// SPDX-License-Identifier: Apache-2.0

//! The paths a tenant's request was authorized to use, pinned for the
//! operation (#362).
//!
//! Authorization resolves a request's path and checks that it is inside the
//! tenant's workspace root. The operation then opened the path again by its
//! raw spelling, so a component swapped for a symlink after the check could
//! redirect it outside the root. On Linux an authorized path is now opened as
//! an `O_PATH` handle beneath a handle on the root, following no symlink
//! (`openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`), and the operation
//! reaches it through `/proc/<pid>/fd/<fd>`: the handle names the object the
//! check approved, whatever its path names later. Responses, and the reports
//! a static scan writes, name the resolved path instead. Elsewhere, or on a
//! kernel without `openat2`, nothing is pinned and the operation uses the
//! path the request named, checked as before.

use serde_json::Value;
use std::path::{Path, PathBuf};

/// A path an operation opens in place of the one a request named, and the
/// resolved path to show for it.
struct Pin {
    access: String,
    shown: String,
    #[cfg(target_os = "linux")]
    _handle: std::os::fd::OwnedFd,
}

/// The paths one request has pinned. They stay pinned until it is dropped,
/// after the response is built.
#[derive(Default)]
pub(crate) struct Pins {
    pins: Vec<Pin>,
}

/// Why a path could not be pinned: it changed after it was authorized, or
/// cannot be opened.
pub(crate) struct PinError(pub(crate) String);

impl Pins {
    /// The path to open for `target` (resolved and inside `root`, which is
    /// resolved too), with `rest` (not yet existing components, for an output
    /// path) joined to it; `None` where nothing can be pinned.
    pub(crate) fn pin(
        &mut self,
        root: &Path,
        target: &Path,
        rest: Option<&Path>,
    ) -> Result<Option<PathBuf>, PinError> {
        #[cfg(target_os = "linux")]
        {
            match linux::open_beneath(root, target) {
                Ok(handle) => {
                    use std::os::fd::AsRawFd;
                    let base = PathBuf::from(format!(
                        "/proc/{}/fd/{}",
                        std::process::id(),
                        handle.as_raw_fd()
                    ));
                    let access = match rest {
                        Some(rest) => base.join(rest),
                        None => base.clone(),
                    };
                    self.pins.push(Pin {
                        access: base.to_string_lossy().into_owned(),
                        shown: target.to_string_lossy().into_owned(),
                        _handle: handle,
                    });
                    return Ok(Some(access));
                }
                // A kernel before 5.6 has no openat2: use the resolved path.
                Err(error) if error.raw_os_error() == Some(libc::ENOSYS) => {}
                Err(error) => {
                    return Err(PinError(format!(
                        "{} changed after it was authorized, or cannot be opened beneath {} \
                         without following a symlink: {error}",
                        target.display(),
                        root.display()
                    )))
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (root, target, rest);
        Ok(None)
    }

    /// `value` with every pinned path it names shown as the resolved one.
    pub(crate) fn unpin(&self, mut value: Value) -> Value {
        if !self.pins.is_empty() {
            self.unpin_value(&mut value);
        }
        value
    }

    fn unpin_value(&self, value: &mut Value) {
        match value {
            Value::String(text) => {
                if let Some(shown) = self.unpin_text(text) {
                    *text = shown;
                }
            }
            Value::Array(items) => items.iter_mut().for_each(|item| self.unpin_value(item)),
            Value::Object(fields) => fields.values_mut().for_each(|item| self.unpin_value(item)),
            _ => {}
        }
    }

    /// `text` with each pinned path in it replaced by the resolved one, or
    /// `None` when it names none.
    pub(crate) fn unpin_text(&self, text: &str) -> Option<String> {
        let mut out = None::<String>;
        for pin in &self.pins {
            let current = out.as_deref().unwrap_or(text);
            if current.contains(&pin.access) {
                out = Some(replace_path(current, &pin.access, &pin.shown));
            }
        }
        out
    }

    /// Rewrite `files` (a static scan's reports) where they name a pinned
    /// path, to name the resolved one.
    pub(crate) fn unpin_files(&self, files: &[&Path]) -> std::io::Result<()> {
        if self.pins.is_empty() {
            return Ok(());
        }
        for file in files {
            let Ok(text) = std::fs::read_to_string(file) else {
                continue;
            };
            if let Some(shown) = self.unpin_text(&text) {
                std::fs::write(file, shown)?;
            }
        }
        Ok(())
    }
}

/// `text` with `from` replaced by `to` where `from` is a whole path: followed
/// by a separator, a quote or the end, so `/proc/1/fd/7` does not match the
/// start of `/proc/1/fd/70`.
fn replace_path(text: &str, from: &str, to: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(from) {
        let end = at + from.len();
        let boundary = rest[end..]
            .chars()
            .next()
            .is_none_or(|next| !next.is_ascii_alphanumeric() && next != '_' && next != '.');
        out.push_str(&rest[..at]);
        out.push_str(if boundary { to } else { from });
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    /// An `O_PATH` handle on `target`, opened beneath a handle on `root`
    /// without following a symlink or leaving `root`.
    pub(super) fn open_beneath(root: &Path, target: &Path) -> std::io::Result<OwnedFd> {
        let root_c = CString::new(root.as_os_str().as_bytes())?;
        // SAFETY: a valid NUL-terminated path; the fd is owned below.
        let root_fd = unsafe {
            libc::open(
                root_c.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if root_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `open` returned a fresh descriptor this function owns.
        let root_fd = unsafe { OwnedFd::from_raw_fd(root_fd) };
        let relative = target.strip_prefix(root).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "outside the root")
        })?;
        let relative = if relative.as_os_str().is_empty() {
            Path::new(".")
        } else {
            relative
        };
        let relative_c = CString::new(relative.as_os_str().as_bytes())?;
        // SAFETY: `open_how` is plain data; the zeroed fields are the
        // documented defaults.
        let mut how: libc::open_how = unsafe { std::mem::zeroed() };
        how.flags = (libc::O_PATH | libc::O_CLOEXEC) as u64;
        how.resolve =
            libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;
        use std::os::fd::AsRawFd;
        // SAFETY: valid fd, NUL-terminated path, and a `how` of the size passed.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                root_fd.as_raw_fd(),
                relative_c.as_ptr(),
                &how as *const libc::open_how,
                std::mem::size_of::<libc::open_how>(),
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: openat2 returned a fresh descriptor this function owns.
        Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pinned_prefix_is_replaced_only_as_a_whole_path() {
        assert_eq!(
            replace_path(
                "/proc/1/fd/7/a.c and /proc/1/fd/70/b.c",
                "/proc/1/fd/7",
                "/w"
            ),
            "/w/a.c and /proc/1/fd/70/b.c"
        );
        assert_eq!(
            replace_path("\"/proc/1/fd/7\"", "/proc/1/fd/7", "/w"),
            "\"/w\""
        );
    }

    /// A symlink swapped in after authorization is not followed (#362): the
    /// pinned path still reaches what was authorized, and a path whose
    /// component is a symlink by the time it is pinned is refused.
    #[cfg(target_os = "linux")]
    #[test]
    fn symlink_swapped_after_authorization_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("workspace")).unwrap();
        let root = dir.path().join("workspace").canonicalize().unwrap();
        let outside = dir.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), "outside\n").unwrap();
        let project = root.join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join("secret.txt"), "inside\n").unwrap();

        // Authorized and pinned, then swapped for a symlink out of the root.
        let mut pins = Pins::default();
        let access = pins
            .pin(&root, &project.canonicalize().unwrap(), None)
            .unwrap_or_else(|error| panic!("{}", error.0))
            .expect("pinned on Linux");
        std::fs::rename(&project, root.join("moved")).unwrap();
        std::os::unix::fs::symlink(&outside, &project).unwrap();
        assert_eq!(
            std::fs::read_to_string(access.join("secret.txt")).unwrap(),
            "inside\n",
            "the pinned path reaches what was authorized"
        );
        assert_eq!(
            pins.unpin(Value::String(
                access.join("secret.txt").display().to_string()
            )),
            Value::String(project.join("secret.txt").display().to_string())
        );

        // Swapped between the check and the pin: refused.
        let mut late = Pins::default();
        assert!(late.pin(&root, &project, None).is_err());

        // An ordinary path inside the root, and an output dir to be made.
        let mut ordinary = Pins::default();
        let made = ordinary
            .pin(&root, &root, Some(Path::new("bhf_work/static")))
            .unwrap_or_else(|error| panic!("{}", error.0))
            .expect("pinned on Linux");
        std::fs::create_dir_all(&made).unwrap();
        assert!(root.join("bhf_work/static").is_dir());
    }
}
