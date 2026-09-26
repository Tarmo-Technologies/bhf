// SPDX-License-Identifier: Apache-2.0
//! Cooperative, process-lifetime ownership of a trusted local scheduler directory.
//! Never unlink the lock pathname: doing so permits two independently locked inodes.

use crate::DaemonError;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

const LOCK_NAME: &str = ".bhf-scheduler.lock";

pub(super) struct StorageLease {
    _file: File,
}

fn regular_file(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // FILE_ATTRIBUTE_REPARSE_POINT. Reject links opened without following.
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "scheduler storage must not be a reparse point",
            ));
        }
    }
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "scheduler storage must be a regular file",
        ));
    }
    Ok(())
}

fn no_follow(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // NONBLOCK prevents special-file opens (e.g. FIFOs) from hanging before
        // regular_file can reject them. std also creates close-on-exec handles.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT: inspect/reject the link, not its target.
        options.custom_flags(0x0020_0000);
    }
    #[cfg(not(any(unix, windows)))]
    let _ = options;
}

pub(super) fn acquire(data_dir: &Path) -> Result<StorageLease, DaemonError> {
    #[cfg(not(any(unix, windows)))]
    return Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "scheduler storage locking is unsupported on this platform",
    )
    .into());

    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    no_follow(&mut options);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Exclusive open, released by the OS even after process termination.
        options.share_mode(0);
    }
    let file = options.open(data_dir.join(LOCK_NAME)).map_err(|error| {
        #[cfg(windows)]
        if error.raw_os_error() == Some(32) {
            // ERROR_SHARING_VIOLATION
            return DaemonError::DataDirInUse(data_dir.to_owned());
        }
        DaemonError::Io(error)
    })?;
    regular_file(&file)?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        // flock is bound to the open file description, which fork() duplicates
        // into every child until it exec()s (O_CLOEXEC closes at exec, not at
        // fork). While this process is concurrently spawning `bhf fuzz`
        // children, a fork can briefly hold a copy of a *just-released* lock fd,
        // so a genuinely-free directory can momentarily report EWOULDBLOCK.
        // Retry for a short bounded window to ride out that race. A real
        // concurrent owner keeps the lock for its whole lifetime — far longer
        // than this budget — so true contention is still reported as
        // DataDirInUse.
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
        loop {
            // SAFETY: file owns a live fd; flock borrows it and uses no pointers.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return Err(DaemonError::DataDirInUse(data_dir.to_owned()));
                    }
                }
                io::ErrorKind::Interrupted => {}
                _ => return Err(DaemonError::Io(error)),
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    Ok(StorageLease { _file: file })
}

pub(super) fn open_snapshot(path: &Path) -> io::Result<Option<File>> {
    let mut options = OpenOptions::new();
    options.read(true);
    no_follow(&mut options);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    regular_file(&file)?;
    Ok(Some(file))
}
