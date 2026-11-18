// SPDX-License-Identifier: Apache-2.0

//! Locates the language harness runtimes shipped with bhf.
//!
//! Release archives carry these directories beside the executable. Installers,
//! however, install only the executable, so every tracked runtime source is also
//! embedded in the CLI and materialized on first use into
//! `<user cache>/bhf/runtime-<sha256>/`, named by the content's digest. The
//! directory outlives the run: the Makefiles and capsules of generated
//! harnesses name files in it, and a later run of the same bhf reuses it.
//! (It was a temporary directory that was never removed, which a cleaned
//! `/tmp` took away from under those Makefiles.)

use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

type EmbeddedFile = (&'static str, &'static [u8]);

static EMBEDDED_ROOT: OnceLock<Result<PathBuf, String>> = OnceLock::new();

/// The file a staged runtime directory holds once every runtime file is in it.
const STAGED_MARKER: &str = ".bhf-runtime-complete";

const EMBEDDED_FILES: &[EmbeddedFile] = &[
    (
        "ada_runtime/adafuzz-decode.adb",
        include_bytes!("../../../ada_runtime/adafuzz-decode.adb"),
    ),
    (
        "ada_runtime/adafuzz-decode.ads",
        include_bytes!("../../../ada_runtime/adafuzz-decode.ads"),
    ),
    (
        "ada_runtime/adafuzz-input.adb",
        include_bytes!("../../../ada_runtime/adafuzz-input.adb"),
    ),
    (
        "ada_runtime/adafuzz-input.ads",
        include_bytes!("../../../ada_runtime/adafuzz-input.ads"),
    ),
    (
        "ada_runtime/adafuzz-probe-gnat_actions.ads",
        include_bytes!("../../../ada_runtime/adafuzz-probe-gnat_actions.ads"),
    ),
    (
        "ada_runtime/adafuzz-probe-memory_buffer.adb",
        include_bytes!("../../../ada_runtime/adafuzz-probe-memory_buffer.adb"),
    ),
    (
        "ada_runtime/adafuzz-probe-semihosting.adb",
        include_bytes!("../../../ada_runtime/adafuzz-probe-semihosting.adb"),
    ),
    (
        "ada_runtime/adafuzz-probe-stub.adb",
        include_bytes!("../../../ada_runtime/adafuzz-probe-stub.adb"),
    ),
    (
        "ada_runtime/adafuzz-probe.adb",
        include_bytes!("../../../ada_runtime/adafuzz-probe.adb"),
    ),
    (
        "ada_runtime/adafuzz-probe.ads",
        include_bytes!("../../../ada_runtime/adafuzz-probe.ads"),
    ),
    (
        "ada_runtime/adafuzz.ads",
        include_bytes!("../../../ada_runtime/adafuzz.ads"),
    ),
    (
        "ada_runtime/adafuzz.gpr",
        include_bytes!("../../../ada_runtime/adafuzz.gpr"),
    ),
    (
        "ada_runtime/adafuzz_cov.c",
        include_bytes!("../../../ada_runtime/adafuzz_cov.c"),
    ),
    (
        "ada_runtime/adafuzz_probe83.ads",
        include_bytes!("../../../ada_runtime/adafuzz_probe83.ads"),
    ),
    (
        "c_runtime/bhf_asan.h",
        include_bytes!("../../../c_runtime/bhf_asan.h"),
    ),
    (
        "c_runtime/bhf_asan_fiber.h",
        include_bytes!("../../../c_runtime/bhf_asan_fiber.h"),
    ),
    (
        "c_runtime/bhf_decode.h",
        include_bytes!("../../../c_runtime/bhf_decode.h"),
    ),
    (
        "c_runtime/bhf_decode_test.c",
        include_bytes!("../../../c_runtime/bhf_decode_test.c"),
    ),
    (
        "c_runtime/bhf_driver.c",
        include_bytes!("../../../c_runtime/bhf_driver.c"),
    ),
    (
        "c_runtime/bhf_service_cov.c",
        include_bytes!("../../../c_runtime/bhf_service_cov.c"),
    ),
    (
        "c_runtime/bhf_trace.h",
        include_bytes!("../../../c_runtime/bhf_trace.h"),
    ),
    (
        "csharp_runtime/Driver.cs",
        include_bytes!("../../../csharp_runtime/Driver.cs"),
    ),
    (
        "java_runtime/build-agent.sh",
        include_bytes!("../../../java_runtime/build-agent.sh"),
    ),
    (
        "java_runtime/build-agent.ps1",
        include_bytes!("../../../java_runtime/build-agent.ps1"),
    ),
    (
        "java_runtime/src/com/bhf/Cmplog.java",
        include_bytes!("../../../java_runtime/src/com/bhf/Cmplog.java"),
    ),
    (
        "java_runtime/src/com/bhf/Coverage.java",
        include_bytes!("../../../java_runtime/src/com/bhf/Coverage.java"),
    ),
    (
        "java_runtime/src/com/bhf/CoverageAgent.java",
        include_bytes!("../../../java_runtime/src/com/bhf/CoverageAgent.java"),
    ),
    (
        "java_runtime/src/com/bhf/Driver.java",
        include_bytes!("../../../java_runtime/src/com/bhf/Driver.java"),
    ),
    (
        "java_runtime/src/com/bhf/BhfData.java",
        include_bytes!("../../../java_runtime/src/com/bhf/BhfData.java"),
    ),
    (
        "java_runtime/src/com/bhf/Sink.java",
        include_bytes!("../../../java_runtime/src/com/bhf/Sink.java"),
    ),
    (
        "js_runtime/bhf_driver.js",
        include_bytes!("../../../js_runtime/bhf_driver.js"),
    ),
    (
        "lua_runtime/bhf_driver.lua",
        include_bytes!("../../../lua_runtime/bhf_driver.lua"),
    ),
    (
        "perl_runtime/Devel/BhfCov.pm",
        include_bytes!("../../../perl_runtime/Devel/BhfCov.pm"),
    ),
    (
        "perl_runtime/bhf_driver.pl",
        include_bytes!("../../../perl_runtime/bhf_driver.pl"),
    ),
    (
        "php_runtime/bhf_driver.php",
        include_bytes!("../../../php_runtime/bhf_driver.php"),
    ),
    (
        "python_runtime/bhf_cov.py",
        include_bytes!("../../../python_runtime/bhf_cov.py"),
    ),
    (
        "python_runtime/bhf_decode.py",
        include_bytes!("../../../python_runtime/bhf_decode.py"),
    ),
    (
        "python_runtime/bhf_driver.py",
        include_bytes!("../../../python_runtime/bhf_driver.py"),
    ),
    (
        "ruby_runtime/bhf_driver.rb",
        include_bytes!("../../../ruby_runtime/bhf_driver.rb"),
    ),
    (
        "rust_runtime/Cargo.toml",
        include_bytes!("../../rust_runtime/Cargo.toml"),
    ),
    (
        "rust_runtime/src/lib.rs",
        include_bytes!("../../rust_runtime/src/lib.rs"),
    ),
];

/// Locate a runtime directory in an extracted release, a development checkout,
/// or the embedded installer fallback.
pub(crate) fn locate(runtime_dir: &str, marker: &str) -> Option<PathBuf> {
    let force_embedded = std::env::var_os("BHF_FORCE_EMBEDDED_RUNTIMES").is_some();
    if !force_embedded {
        if let Ok(exe) = std::env::current_exe() {
            for dir in exe.ancestors().skip(1) {
                let candidate = dir.join(runtime_dir);
                if candidate.join(marker).is_file() {
                    return Some(candidate);
                }

                // Older source-tree layouts keep the Rust runtime under `crates/`.
                let nested_candidate = dir.join("crates").join(runtime_dir);
                if nested_candidate.join(marker).is_file() {
                    return Some(nested_candidate);
                }
            }
        }

        let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for candidate in [
            source_root.join(runtime_dir),
            source_root.join("crates").join(runtime_dir),
        ] {
            if candidate.join(marker).is_file() {
                return Some(candidate);
            }
        }
    }

    let root = embedded_root()?;
    let candidate = root.join(runtime_dir);
    candidate.join(marker).is_file().then_some(candidate)
}

fn embedded_root() -> Option<&'static Path> {
    EMBEDDED_ROOT
        .get_or_init(stage_embedded)
        .as_ref()
        .ok()
        .map(PathBuf::as_path)
}

/// Stage the embedded runtimes in the user's cache, else (no cache directory,
/// or one that cannot be written: a read-only container image) in a
/// temporary directory that lasts as long as `/tmp`.
fn stage_embedded() -> Result<PathBuf, String> {
    stage_embedded_with(crate::msvc_cc::per_user_cache_dir(cfg!(windows), &|name| {
        std::env::var(name).ok()
    }))
}

fn stage_embedded_with(cache: Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(cache) = cache {
        match stage_embedded_in(&cache.join("bhf")) {
            Ok(dir) => return Ok(dir),
            Err(error) => {
                bhfeprintln!(
                    "bhf: note: the embedded runtimes cannot be cached ({error}); staging \
                     them in a temporary directory"
                );
            }
        }
    }
    let dir = tempfile::Builder::new()
        .prefix("bhf-runtime-")
        .tempdir()
        .map_err(|error| format!("create embedded runtime directory: {error}"))?
        .keep();
    write_embedded(&dir)?;
    Ok(dir)
}

/// `<base>/runtime-<sha256 of the embedded files>`, written whole into a
/// staging directory beside it and renamed into place, so a reader never
/// sees half of it. A directory already there is reused once its files
/// match the embedded bytes; one that does not match is replaced.
fn stage_embedded_in(base: &Path) -> Result<PathBuf, String> {
    let dir = base.join(format!("runtime-{}", embedded_digest()));
    if holds_embedded(&dir) {
        return Ok(dir);
    }
    fs::create_dir_all(base).map_err(|error| format!("create '{}': {error}", base.display()))?;
    let staging = tempfile::Builder::new()
        .prefix(".runtime-staging-")
        .tempdir_in(base)
        .map_err(|error| {
            format!(
                "create a staging directory in '{}': {error}",
                base.display()
            )
        })?;
    write_embedded(staging.path())?;
    fs::write(staging.path().join(STAGED_MARKER), b"")
        .map_err(|error| format!("write '{}': {error}", staging.path().display()))?;
    if dir.exists() && !holds_embedded(&dir) {
        let _ = fs::remove_dir_all(&dir);
    }
    match fs::rename(staging.path(), &dir) {
        Ok(()) => {
            // Renamed away: nothing for the guard to remove.
            let _ = staging.keep();
            Ok(dir)
        }
        // Another bhf staged the same content first.
        Err(_) if holds_embedded(&dir) => Ok(dir),
        Err(error) => Err(format!(
            "move the embedded runtimes into '{}': {error}",
            dir.display()
        )),
    }
}

fn write_embedded(dir: &Path) -> Result<(), String> {
    for (relative, bytes) in EMBEDDED_FILES {
        let destination = dir.join(relative);
        let parent = destination
            .parent()
            .ok_or_else(|| format!("embedded runtime path has no parent: {relative}"))?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("create '{}': {error}", parent.display()))?;
        fs::write(&destination, bytes)
            .map_err(|error| format!("write '{}': {error}", destination.display()))?;
    }
    Ok(())
}

/// Whether `dir` is a complete staging of the embedded runtimes, byte for byte.
fn holds_embedded(dir: &Path) -> bool {
    dir.join(STAGED_MARKER).is_file()
        && EMBEDDED_FILES
            .iter()
            .all(|(relative, bytes)| fs::read(dir.join(relative)).is_ok_and(|held| held == *bytes))
}

/// SHA-256 over every embedded file's path and bytes, in hex.
fn embedded_digest() -> String {
    let mut hasher = Sha256::new();
    for (relative, bytes) in EMBEDDED_FILES {
        hasher.update((relative.len() as u64).to_le_bytes());
        hasher.update(relative.as_bytes());
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    corpus::hex_lower(&hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_fallback_contains_every_runtime_lane() {
        let cache = tempfile::tempdir().unwrap();
        let staged = stage_embedded_in(cache.path()).expect("stage embedded runtimes");
        for marker in [
            "ada_runtime/adafuzz.ads",
            "c_runtime/bhf_driver.c",
            "c_runtime/bhf_trace.h",
            "csharp_runtime/Driver.cs",
            "java_runtime/build-agent.sh",
            "java_runtime/build-agent.ps1",
            "java_runtime/src/com/bhf/CoverageAgent.java",
            "js_runtime/bhf_driver.js",
            "lua_runtime/bhf_driver.lua",
            "perl_runtime/Devel/BhfCov.pm",
            "php_runtime/bhf_driver.php",
            "python_runtime/bhf_driver.py",
            "ruby_runtime/bhf_driver.rb",
            "rust_runtime/Cargo.toml",
            "rust_runtime/src/lib.rs",
        ] {
            assert!(staged.join(marker).is_file(), "missing {marker}");
        }
    }

    #[test]
    fn embedded_files_match_the_compiled_assets() {
        let cache = tempfile::tempdir().unwrap();
        let staged = stage_embedded_in(cache.path()).expect("stage embedded runtimes");
        for (relative, expected) in EMBEDDED_FILES {
            assert_eq!(
                fs::read(staged.join(relative)).expect("read staged runtime"),
                *expected,
                "staged bytes differ for {relative}"
            );
        }
    }

    /// The staging is named by its content, reused as long as it holds the
    /// embedded bytes, and replaced when a file in it was changed.
    #[test]
    fn a_staged_runtime_is_reused_and_a_changed_one_replaced() {
        let cache = tempfile::tempdir().unwrap();
        let first = stage_embedded_in(cache.path()).unwrap();
        assert_eq!(
            first.file_name().unwrap().to_string_lossy(),
            format!("runtime-{}", embedded_digest())
        );
        let driver = first.join("c_runtime/bhf_driver.c");
        let stamp = fs::metadata(&driver).unwrap().modified().unwrap();
        assert_eq!(stage_embedded_in(cache.path()).unwrap(), first);
        assert_eq!(fs::metadata(&driver).unwrap().modified().unwrap(), stamp);

        fs::write(&driver, b"tampered").unwrap();
        assert_eq!(stage_embedded_in(cache.path()).unwrap(), first);
        assert!(holds_embedded(&first));
        // Only the staging is left in the cache.
        let entries: Vec<_> = fs::read_dir(cache.path()).unwrap().flatten().collect();
        assert_eq!(entries.len(), 1, "{entries:?}");
    }

    /// A cache directory that cannot be written (a read-only container image)
    /// leaves the runtimes staged in a temporary directory, not missing.
    #[cfg(unix)]
    #[test]
    fn an_unwritable_cache_falls_back_to_a_temporary_directory() {
        use std::os::unix::fs::PermissionsExt;
        let cache = tempfile::tempdir().unwrap();
        fs::set_permissions(cache.path(), fs::Permissions::from_mode(0o555)).unwrap();
        if fs::write(cache.path().join("probe"), b"").is_ok() {
            // Root ignores the permission bits: nothing to check.
            fs::set_permissions(cache.path(), fs::Permissions::from_mode(0o755)).unwrap();
            return;
        }
        let staged = stage_embedded_with(Some(cache.path().to_path_buf()));
        fs::set_permissions(cache.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let staged = staged.expect("staged in a temporary directory");
        assert!(!staged.starts_with(cache.path()), "{}", staged.display());
        assert!(staged.join("c_runtime/bhf_driver.c").is_file());
        let _ = fs::remove_dir_all(&staged);
    }
}
