// SPDX-License-Identifier: Apache-2.0

//! The files behind `bhf fuzz`'s shared-memory channels (edge coverage, value
//! profile, comparison operands). They live in `<work>/fuzz_shm/`, named for
//! the process that made them (`<pid>-<random>.shm`), and go when the run
//! does: when it ends, when SIGINT, SIGTERM or SIGHUP stops it, and, for a run
//! killed outright, when a later run in the work dir finds their process gone,
//! or with `bhf clean --all`. They were `.tmp*` files at the top of the work
//! dir, which an interrupted run left there and `clean --all` did not remove.

use std::path::Path;

/// The work-dir subdirectory the shared maps live in.
pub(crate) const SHM_DIR: &str = "fuzz_shm";

/// One shared map's file, removed when this drops.
pub(crate) struct SharedMapFile {
    #[cfg(unix)]
    slot: Option<usize>,
    _path: tempfile::TempPath,
}

impl SharedMapFile {
    /// A zero-filled, `bytes`-sized file in `<work_dir>/fuzz_shm/`, and its
    /// path for the child's `*_SHM` variable.
    pub(crate) fn create(work_dir: &Path, bytes: usize) -> Result<(Self, String), String> {
        let dir = work_dir.join(SHM_DIR);
        std::fs::create_dir_all(&dir)
            .map_err(|error| format!("create {}: {error}", dir.display()))?;
        remove_stale(&dir, std::process::id(), &process_alive);
        let file = tempfile::Builder::new()
            .prefix(&format!("{}-", std::process::id()))
            .suffix(".shm")
            .tempfile_in(&dir)
            .map_err(|error| format!("create harness shared map: {error}"))?;
        file.as_file()
            .set_len(bytes as u64)
            .map_err(|error| format!("size harness shared map: {error}"))?;
        let path = file.into_temp_path();
        let value = path.to_string_lossy().into_owned();
        Ok((
            Self {
                #[cfg(unix)]
                slot: interrupt::register(&path),
                _path: path,
            },
            value,
        ))
    }
}

impl Drop for SharedMapFile {
    fn drop(&mut self) {
        // Before the file goes, so the handler never unlinks a name another
        // file has taken since.
        #[cfg(unix)]
        if let Some(slot) = self.slot.take() {
            interrupt::unregister(slot);
        }
    }
}

/// The pid a shared map's name says made it.
fn owner_pid(name: &str) -> Option<u32> {
    let (pid, rest) = name.split_once('-')?;
    rest.ends_with(".shm").then_some(())?;
    pid.parse().ok()
}

/// Remove the maps in `dir` whose process is gone: a run killed with SIGKILL
/// (or by the OOM killer) left them.
fn remove_stale(dir: &Path, own_pid: u32, alive: &dyn Fn(u32) -> bool) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(owner_pid) else {
            continue;
        };
        if pid != own_pid && !alive(pid) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

#[cfg(unix)]
fn process_alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return true;
    };
    // SAFETY: signal 0 only checks that the process exists.
    let found = unsafe { libc::kill(pid, 0) } == 0;
    found || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Off Unix every map is assumed live; `bhf clean --all` removes leftovers.
#[cfg(not(unix))]
fn process_alive(_pid: u32) -> bool {
    true
}

/// Unlinks the registered maps when SIGINT, SIGTERM or SIGHUP ends the
/// process, then lets the signal end it as it would have. Lock-free: a
/// handler may run while another thread registers or drops a map, and
/// whichever of the two takes a slot's path first owns it.
#[cfg(unix)]
mod interrupt {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::null_mut;
    use std::sync::atomic::{AtomicPtr, Ordering};
    use std::sync::Once;

    const SLOTS: usize = 64;
    static PATHS: [AtomicPtr<libc::c_char>; SLOTS] = [const { AtomicPtr::new(null_mut()) }; SLOTS];
    static INSTALL: Once = Once::new();

    /// Register `path` for removal on a stopping signal; its slot, or `None`
    /// when every slot is taken (the file then only goes with its run).
    pub(super) fn register(path: &Path) -> Option<usize> {
        INSTALL.call_once(install);
        let raw = CString::new(path.as_os_str().as_bytes()).ok()?.into_raw();
        for (index, slot) in PATHS.iter().enumerate() {
            if slot
                .compare_exchange(null_mut(), raw, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Some(index);
            }
        }
        // SAFETY: `raw` came from `into_raw` and no slot holds it.
        drop(unsafe { CString::from_raw(raw) });
        None
    }

    pub(super) fn unregister(slot: usize) {
        let raw = PATHS[slot].swap(null_mut(), Ordering::SeqCst);
        if !raw.is_null() {
            // SAFETY: the swap took the only copy of a pointer `register`
            // made with `into_raw`.
            drop(unsafe { CString::from_raw(raw) });
        }
    }

    extern "C" fn on_signal(signal: libc::c_int) {
        for slot in &PATHS {
            let raw = slot.swap(null_mut(), Ordering::SeqCst);
            if !raw.is_null() {
                // SAFETY: a NUL-terminated path; unlink is async-signal-safe.
                unsafe { libc::unlink(raw) };
            }
        }
        // SA_RESETHAND put the default action back: the signal ends the
        // process as it would have without this handler.
        // SAFETY: raise is async-signal-safe.
        unsafe { libc::raise(signal) };
    }

    fn install() {
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            // SAFETY: plain sigaction calls on zeroed structs.
            unsafe {
                let mut previous: libc::sigaction = std::mem::zeroed();
                if libc::sigaction(signal, std::ptr::null(), &mut previous) != 0 {
                    continue;
                }
                // An ignored signal (nohup) stays ignored, and a handler
                // someone else installed stays theirs.
                if previous.sa_sigaction != libc::SIG_DFL {
                    continue;
                }
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as usize;
                action.sa_flags = libc::SA_RESETHAND;
                libc::sigemptyset(&mut action.sa_mask);
                libc::sigaction(signal, &action, null_mut());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_map_is_named_for_its_process_and_goes_when_it_drops() {
        let work = tempfile::tempdir().unwrap();
        let (map, path) = SharedMapFile::create(work.path(), 4096).unwrap();
        let path = std::path::PathBuf::from(path);
        assert_eq!(path.parent().unwrap(), work.path().join(SHM_DIR));
        let name = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(owner_pid(name), Some(std::process::id()), "{name}");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 4096);
        drop(map);
        assert!(!path.exists());
    }

    #[test]
    fn maps_of_a_process_that_is_gone_are_removed() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["11-a.shm", "22-b.shm", "33-c.shm", "notes.txt", "44-d.bin"] {
            std::fs::write(dir.path().join(name), b"").unwrap();
        }
        // 22 is alive, 33 is this process, 11 is gone.
        remove_stale(dir.path(), 33, &|pid| pid == 22);
        let mut left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(left, ["22-b.shm", "33-c.shm", "44-d.bin", "notes.txt"]);
    }

    #[cfg(unix)]
    #[test]
    fn this_process_is_alive() {
        assert!(process_alive(std::process::id()));
    }
}
