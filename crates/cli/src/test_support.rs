// SPDX-License-Identifier: Apache-2.0

//! Scratch directories for tests that clean up after themselves.
//!
//! A test that builds `temp_dir()/bhf-<name>-<nanos>` by hand removes it, at
//! best, as its last statement, so every failing test, and every test that
//! never removes it, leaves the directory behind. [`TestDir`] removes its
//! directory when it is dropped, including while a failing test unwinds.
//!
//! Set `BHF_KEEP_TEST_DIRS=1` to keep the directories for inspection; each
//! kept path is printed to stderr when its guard is dropped.
//!
//! The `bhf` crate's unit tests use it as `crate::test_support::TestDir`. Its
//! integration tests include this file by path:
//!
//! ```text
//! #[path = "../src/test_support.rs"]
//! mod test_support;
//! use test_support::TestDir;
//! ```
//!
//! Reaching it through the `cli` library instead would link all of `bhf` into
//! every test binary that uses it (an 8 MB test binary grows to 280 MB), so
//! this file uses only `std` and `tempfile`. Its own tests are in
//! `tests/test_dir_guard.rs`. Crates that `bhf` depends on use `tempfile`
//! directly.

// Each test binary that includes this file uses a different part of it.
#![allow(dead_code)]

use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::ops::Deref;
use std::path::{Path, PathBuf};

/// Environment variable that keeps every [`TestDir`] instead of removing it.
/// Any value other than empty or `0` keeps them.
pub const KEEP_TEST_DIRS_ENV: &str = "BHF_KEEP_TEST_DIRS";

/// A directory `<temp_dir>/bhf-<name>-<random>` that is removed on drop.
///
/// It dereferences to [`Path`], so `dir.join(..)`, `dir.display()` and `&dir`
/// as a `&Path` argument work as they do on a `PathBuf`. `&dir` also passes
/// where an `impl AsRef<Path>` or `impl AsRef<OsStr>` is taken. The guard
/// itself does not, on purpose: passing it by value to such a function would
/// drop it, and remove the directory, as soon as that call returns.
pub struct TestDir {
    dir: Option<tempfile::TempDir>,
    /// How the directory is spelled to the test: the created path, or the
    /// form [`TestDir::spelled_as`] gave it.
    path: PathBuf,
    keep: bool,
}

impl TestDir {
    /// Create `<temp_dir>/bhf-<name>-<random>`.
    ///
    /// # Panics
    ///
    /// When the directory cannot be created; a test cannot go on without it.
    pub fn new(name: &str) -> Self {
        // Neither the name nor the error's message: CodeQL's cleartext-logging
        // query reads a name such as `c-sequence-private` as sensitive, and
        // the message holds the generated path. The backtrace names the test.
        Self::try_new(name)
            .unwrap_or_else(|error| panic!("cannot create a test dir: {:?}", error.kind()))
    }

    /// [`TestDir::new`] for a probe that treats a temp dir it cannot create
    /// as a missing capability rather than a test failure.
    pub fn try_new(name: &str) -> io::Result<Self> {
        Self::create(name, keep_requested(std::env::var_os(KEEP_TEST_DIRS_ENV)))
    }

    /// Create the directory, keeping it on drop when `keep` is set, whatever
    /// the environment says.
    pub fn create(name: &str, keep: bool) -> io::Result<Self> {
        let mut dir = tempfile::Builder::new()
            .prefix(&format!("bhf-{name}-"))
            .tempdir()?;
        dir.disable_cleanup(keep);
        Ok(Self {
            path: dir.path().to_path_buf(),
            dir: Some(dir),
            keep,
        })
    }

    /// Spell the directory as `resolve` does, for a test of code that
    /// resolves the paths it writes (Windows' temp dir is often spelled with
    /// an 8.3 short name such as `RUNNER~1`). The directory removed on drop
    /// is the one created.
    pub fn spelled_as(mut self, resolve: impl FnOnce(&Path) -> PathBuf) -> Self {
        self.path = resolve(&self.path);
        self
    }

    /// The directory's path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Whether a `BHF_KEEP_TEST_DIRS` value asks to keep the directories.
pub fn keep_requested(value: Option<std::ffi::OsString>) -> bool {
    value.is_some_and(|value| !value.is_empty() && value != "0")
}

impl Deref for TestDir {
    type Target = Path;

    fn deref(&self) -> &Path {
        self.path()
    }
}

impl AsRef<Path> for &TestDir {
    fn as_ref(&self) -> &Path {
        self.path()
    }
}

impl AsRef<OsStr> for &TestDir {
    fn as_ref(&self) -> &OsStr {
        self.path().as_os_str()
    }
}

impl fmt::Debug for TestDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.path(), f)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let Some(dir) = self.dir.take() else {
            return;
        };
        if self.keep {
            eprintln!(
                "{KEEP_TEST_DIRS_ENV} is set: kept test dir {}",
                self.path.display()
            );
            return;
        }
        let path = dir.path().to_path_buf();
        if dir.close().is_err() {
            // A test that took away write or search permission (to exercise a
            // permission error) leaves entries that cannot be removed. Give
            // them back and try once more; a drop must not panic.
            restore_permissions(&path);
            let _ = std::fs::remove_dir_all(&path);
        }
    }
}

#[cfg(unix)]
fn restore_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if !meta.is_dir() {
        return;
    }
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            restore_permissions(&entry.path());
        }
    }
}

#[cfg(not(unix))]
fn restore_permissions(path: &Path) {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    let mut permissions = meta.permissions();
    if permissions.readonly() {
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        let _ = std::fs::set_permissions(path, permissions);
    }
    if meta.is_dir() {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                restore_permissions(&entry.path());
            }
        }
    }
}
