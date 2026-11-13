// SPDX-License-Identifier: Apache-2.0

//! Shared work-directory layout for `bhf auto`.

use std::path::{Path, PathBuf};

pub(crate) const REPORTS_DIR: &str = "auto";
pub(crate) const HARNESSES_DIR: &str = "harnesses";
pub(crate) const LEGACY_AUTO_HARNESSES_DIR: &str = "auto";
pub(crate) const GENERATED_HARNESSES_DIR: &str = "generated_harnesses";

pub(crate) fn reports_dir(work_dir: &Path) -> PathBuf {
    work_dir.join(REPORTS_DIR)
}

pub(crate) fn harness_root(work_dir: &Path) -> PathBuf {
    work_dir.join(HARNESSES_DIR)
}

pub(crate) fn harness_dir(work_dir: &Path, harness_id: &str) -> PathBuf {
    harness_root(work_dir).join(harness_id)
}

pub(crate) fn legacy_auto_harness_dir(work_dir: &Path, harness_id: &str) -> PathBuf {
    work_dir.join(LEGACY_AUTO_HARNESSES_DIR).join(harness_id)
}

pub(crate) fn generated_harness_dir(work_dir: &Path, harness_id: &str) -> PathBuf {
    work_dir.join(GENERATED_HARNESSES_DIR).join(harness_id)
}

pub(crate) fn harness_dir_candidates(work_dir: &Path, harness_id: &str) -> Vec<PathBuf> {
    vec![
        harness_dir(work_dir, harness_id),
        legacy_auto_harness_dir(work_dir, harness_id),
        generated_harness_dir(work_dir, harness_id),
    ]
}

/// The file name a harness build gives the executable `stem` (`main`,
/// `main_cov`, ...): `stem.exe` on Windows, where cmd and PowerShell start a
/// program only by an executable extension, else `stem`. The generated
/// Makefiles name their binaries the same way (`$(EXEEXT)`).
pub(crate) fn harness_exe_name(stem: &str) -> String {
    format!("{stem}{}", std::env::consts::EXE_SUFFIX)
}

/// The built executable `stem` in `dir`. On Windows `stem.exe`, or else the
/// extensionless `stem` a work dir built before the binaries had the suffix
/// holds; `stem.exe` when neither exists, the name a build writes. Elsewhere
/// `stem`.
pub(crate) fn harness_exe(dir: &Path, stem: &str) -> PathBuf {
    let named = dir.join(harness_exe_name(stem));
    if cfg!(windows) && !named.is_file() && dir.join(stem).is_file() {
        return dir.join(stem);
    }
    named
}

/// Every name a harness executable can have in a harness dir, the platform's
/// own spelling first: `main`, the AFL++ build `main_afl`, and their `.exe`
/// forms (a Windows build, or a MinGW cross build elsewhere).
pub(crate) fn harness_exe_leaves() -> [&'static str; 4] {
    if cfg!(windows) {
        ["main.exe", "main_afl.exe", "main", "main_afl"]
    } else {
        ["main", "main_afl", "main.exe", "main_afl.exe"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_harness_executable_carries_the_platform_suffix() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        let suffixed = dir.join("main_cov.exe");
        let bare = dir.join("main_cov");
        if cfg!(windows) {
            assert_eq!(harness_exe_name("main_cov"), "main_cov.exe");
            assert_eq!(harness_exe(dir, "main_cov"), suffixed, "the name to build");
            std::fs::write(&bare, b"MZ").unwrap();
            assert_eq!(harness_exe(dir, "main_cov"), bare, "an older build");
            std::fs::write(&suffixed, b"MZ").unwrap();
            assert_eq!(harness_exe(dir, "main_cov"), suffixed, "the suffix wins");
            assert_eq!(harness_exe_leaves()[0], "main.exe");
        } else {
            assert_eq!(harness_exe_name("main_cov"), "main_cov");
            std::fs::write(&suffixed, b"MZ").unwrap();
            assert_eq!(
                harness_exe(dir, "main_cov"),
                bare,
                "a MinGW cross build's .exe is not this platform's harness"
            );
            assert_eq!(harness_exe_leaves()[0], "main");
        }
        assert_eq!(harness_exe_leaves().len(), 4);
    }
}
