// SPDX-License-Identifier: Apache-2.0
//! Cross-process exclusive lock on `results/.lock`, held for one rebuild.
//! Never unlink the lock pathname: doing so permits two independently locked
//! inodes.
//!
//! This is an advisory, local-filesystem lock: `flock` (unix) and share-mode
//! opens (windows) are not reliable over NFS or most FUSE mounts, where two
//! hosts (or even two processes, depending on the mount) can both believe
//! they hold the lock. Run bhf against a local filesystem.

use crate::ResultsError;
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::time::{Duration, Instant};

const LOCK_NAME: &str = ".lock";

#[derive(Debug)]
pub struct ResultsLock {
    _file: File,
}

impl ResultsLock {
    pub fn acquire(results_dir: &Path, timeout: Duration) -> Result<Self, ResultsError> {
        let path = results_dir.join(LOCK_NAME);
        // `checked_add` so a very large timeout cannot overflow `Instant`;
        // overflow is treated as "no deadline" rather than failing closed.
        let deadline = Instant::now().checked_add(timeout);
        loop {
            match try_lock(&path) {
                Ok(Some(file)) => return Ok(Self { _file: file }),
                Ok(None) => {}
                Err(source) => return Err(ResultsError::Io { path, source }),
            }
            if deadline.is_some_and(|d| Instant::now() >= d) {
                // `seconds` rounds a sub-second timeout up to 1 rather than
                // reporting a misleading "timed out after 0s".
                let seconds = if timeout.is_zero() {
                    0
                } else {
                    timeout.as_secs().max(1)
                };
                return Err(ResultsError::LockTimeout { path, seconds });
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

#[cfg(unix)]
fn try_lock(path: &Path) -> std::io::Result<Option<File>> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    // SAFETY: `file` owns a live fd for the duration of the call.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(Some(file));
    }
    let error = std::io::Error::last_os_error();
    match error.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => Ok(None),
        _ => Err(error),
    }
}

#[cfg(windows)]
fn try_lock(path: &Path) -> std::io::Result<Option<File>> {
    use std::os::windows::fs::OpenOptionsExt;
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .open(path)
    {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.raw_os_error() == Some(32) => Ok(None), // ERROR_SHARING_VIOLATION
        Err(error) => Err(error),
    }
}

#[cfg(not(any(unix, windows)))]
fn try_lock(_path: &Path) -> std::io::Result<Option<File>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "results lock: exclusive file locking is not implemented on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn second_acquire_times_out_while_first_is_held() {
        let tmp = tempfile::tempdir().unwrap();
        let first = ResultsLock::acquire(tmp.path(), Duration::from_secs(1)).unwrap();
        let start = std::time::Instant::now();
        let err = ResultsLock::acquire(tmp.path(), Duration::from_millis(200)).unwrap_err();
        assert!(matches!(err, crate::ResultsError::LockTimeout { .. }));
        assert!(start.elapsed() >= Duration::from_millis(200));
        drop(first);
        ResultsLock::acquire(tmp.path(), Duration::from_secs(1)).unwrap();
    }

    #[test]
    fn sub_second_timeout_rounds_up_to_one_second_in_the_error() {
        let tmp = tempfile::tempdir().unwrap();
        let first = ResultsLock::acquire(tmp.path(), Duration::from_secs(1)).unwrap();
        let err = ResultsLock::acquire(tmp.path(), Duration::from_millis(50)).unwrap_err();
        match err {
            crate::ResultsError::LockTimeout { seconds, .. } => assert_eq!(seconds, 1),
            other => panic!("expected LockTimeout, got {other:?}"),
        }
        drop(first);
    }
}
