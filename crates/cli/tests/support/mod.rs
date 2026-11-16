// SPDX-License-Identifier: Apache-2.0
// Shared test support: each test binary that `mod support;`-includes this uses a
// different subset, so unused-in-one-binary helpers are expected.
#![allow(dead_code)]

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// Serializes fuzz-bearing tests inside one test binary.
///
/// A test that asserts a planted bug is FOUND is budgeted in wall-clock seconds,
/// so how many executions it gets — and therefore whether it finds the bug —
/// depends on how much of the machine it has. `cargo test` runs a binary's tests
/// concurrently, so seven fuzz tests on a six-core box each got ~6 executions
/// where the same test alone gets ~32, and the planted OOB went unfound. The
/// assertion was right; the budget was being spent on contention. Hold this
/// guard around the fuzz run and the budget means what it says.
///
/// Recovers from poisoning: a panic in one fuzz test (which is how a failure
/// reports) must not turn every later test in the binary into a lock error.
pub fn fuzz_serial_guard() -> std::sync::MutexGuard<'static, ()> {
    static FUZZ_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    FUZZ_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Put clang's sanitizer runtime DLL directory first on `cmd`'s PATH, so a
/// binary a test built with `-fsanitize=address` starts on Windows, where
/// `bhf build` would stage the DLL next to it. Nothing changes elsewhere.
pub fn with_sanitizer_runtime(cmd: &mut Command) -> &mut Command {
    #[cfg(windows)]
    if let Some(runtime) = clang_sanitizer_runtime_dir() {
        let path = std::env::var_os("PATH").unwrap_or_default();
        let dirs = std::iter::once(runtime.clone()).chain(std::env::split_paths(&path));
        cmd.env(
            "PATH",
            std::env::join_paths(dirs).expect("PATH entries join"),
        );
    }
    cmd
}

/// `<clang resource dir>/lib/windows`, where clang keeps its sanitizer DLLs.
#[cfg(windows)]
fn clang_sanitizer_runtime_dir() -> Option<&'static PathBuf> {
    static DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
    DIR.get_or_init(|| {
        let output = Command::new("clang")
            .arg("-print-resource-dir")
            .output()
            .ok()?;
        let resource = String::from_utf8_lossy(&output.stdout);
        let dir = Path::new(resource.trim()).join("lib").join("windows");
        dir.is_dir().then_some(dir)
    })
    .as_ref()
}

/// The release bhf a heavy test runs: the prebuilt binary `$BHF_TEST_BIN`
/// names (the nightly builds it once, beside its runtrace shim), else
/// `cargo run --release` of this crate.
#[allow(dead_code)]
pub fn bhf_cargo_command() -> Command {
    bhf_command_with(std::env::var_os("BHF_TEST_BIN").map(PathBuf::from))
}

/// [`bhf_cargo_command`] for an explicit `test_bin`: with one, that binary
/// runs and cargo never does.
#[allow(dead_code)]
pub fn bhf_command_with(test_bin: Option<PathBuf>) -> Command {
    if let Some(bin) = test_bin {
        let mut cmd = Command::new(&bin);
        if let Some(shim) = prebuilt_shim(&bin) {
            cmd.env("BHF_RUNTRACE_SHIM", shim);
        }
        return cmd;
    }
    let mut cmd = Command::new(env!("CARGO"));
    cmd.args(["run", "--manifest-path"])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .args(["--release", "-q", "--"]);
    // `cargo run -p bhf` does NOT build the runtrace shim — cli has no
    // dependency on the `bhf_runtrace_shim` cdylib — so on a clean
    // checkout (e.g. CI) the release `libbhf_runtrace_shim.so` is absent,
    // the auto loop's shim locator finds nothing, runtrace silently disables,
    // and env-injection cascades never fire. Build the shim once and point
    // the locator at it via $BHF_RUNTRACE_SHIM (which it checks first).
    configure_runtrace_shim(&mut cmd);
    cmd
}

/// Ensure a command that launches bhf can find the runtrace shim from a
/// clean Cargo target directory. The CLI does not link the cdylib directly, so
/// Cargo does not guarantee that it is built beside `CARGO_BIN_EXE_bhf`.
pub fn configure_runtrace_shim(cmd: &mut Command) {
    if let Some(shim) = runtrace_shim_path() {
        cmd.env("BHF_RUNTRACE_SHIM", shim);
    }
}

/// Build the release runtrace-shim cdylib (the profile
/// `bhf_cargo_command` runs under) once per test binary and return its
/// path. Returns `None` if the build fails or the artifact is missing, in
/// which case callers fall back to bhf's own audit-disabled mode.
#[allow(dead_code)]
fn runtrace_shim_path() -> Option<PathBuf> {
    static SHIM: OnceLock<Option<PathBuf>> = OnceLock::new();
    SHIM.get_or_init(|| {
        // A prebuilt bhf comes with its shim: build nothing.
        if let Some(bin) = std::env::var_os("BHF_TEST_BIN") {
            return prebuilt_shim(Path::new(&bin));
        }
        let status = Command::new(env!("CARGO"))
            .args(["build", "--release", "-p", "bhf_runtrace_shim"])
            .status()
            .ok()?;
        if !status.success() {
            return None;
        }
        let shim = target_dir().join("release/libbhf_runtrace_shim.so");
        shim.is_file().then_some(shim)
    })
    .clone()
}

/// The runtrace shim for the prebuilt bhf `bin`: `$BHF_RUNTRACE_SHIM` when it
/// names a file, else the one beside `bin`.
#[allow(dead_code)]
fn prebuilt_shim(bin: &Path) -> Option<PathBuf> {
    std::env::var_os("BHF_RUNTRACE_SHIM")
        .map(PathBuf::from)
        .filter(|shim| shim.is_file())
        .or_else(|| {
            let shim = bin.with_file_name("libbhf_runtrace_shim.so");
            shim.is_file().then_some(shim)
        })
}

/// Workspace target directory, honouring $CARGO_TARGET_DIR when set and
/// otherwise defaulting to `<workspace-root>/target`.
fn target_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("CARGO_TARGET_DIR") {
        return PathBuf::from(dir);
    }
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root above crates/cli")
        .join("target")
}

pub fn libfuzzer_toolchain_available(prefix: &str) -> bool {
    libfuzzer_toolchain_available_with("clang", prefix)
}

pub fn libfuzzer_toolchain_available_with(compiler: &str, prefix: &str) -> bool {
    // Removed when the probe returns.
    let Ok(scratch) = tempfile::Builder::new()
        .prefix(&format!("bhf-{prefix}-toolchain-probe-"))
        .tempdir()
    else {
        return false;
    };
    let dir = scratch.path();
    let src = dir.join("p.c");
    if fs::write(
        &src,
        // `extern "C"` when a C++ driver (clang++) compiles it as C++: a
        // mangled name would leave libFuzzer's main without its entry point.
        "#ifdef __cplusplus\nextern \"C\"\n#endif\n\
         int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n){return (int)n;}\n",
    )
    .is_err()
    {
        return false;
    }
    let bin = dir.join("p");
    let mut cmd = Command::new(compiler);
    cmd.args(libfuzzer_probe_args(
        &bin,
        &src,
        libstdcxx_search_path().as_deref(),
    ));

    cmd.output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

pub fn libfuzzer_probe_args(bin: &Path, src: &Path, libstdcxx_dir: Option<&Path>) -> Vec<OsString> {
    let mut args = vec![
        OsString::from("-O1"),
        OsString::from("-g"),
        OsString::from("-fsanitize=fuzzer,address,undefined"),
        OsString::from("-o"),
        bin.as_os_str().to_os_string(),
        src.as_os_str().to_os_string(),
    ];
    if let Some(dir) = libstdcxx_dir {
        args.push(OsString::from(format!("-L{}", dir.display())));
    }
    args
}

fn libstdcxx_search_path() -> Option<PathBuf> {
    libstdcxx_search_path_from_dirs(
        [
            "/usr/lib/gcc/x86_64-linux-gnu/13",
            "/usr/lib/gcc/x86_64-linux-gnu/14",
            "/usr/lib/gcc/x86_64-linux-gnu/12",
            "/usr/lib/gcc/aarch64-linux-gnu/13",
            "/usr/lib/gcc/aarch64-linux-gnu/14",
            "/usr/lib/gcc/aarch64-linux-gnu/12",
        ]
        .into_iter()
        .map(Path::new),
    )
}

pub fn libstdcxx_search_path_from_dirs<I, P>(dirs: I) -> Option<PathBuf>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    dirs.into_iter()
        .map(|dir| dir.as_ref().to_path_buf())
        .find(|dir| dir.join("libstdc++.so").is_file())
}

/// Whether `compiler` can compile a C++ translation unit that pulls the standard
/// headers — the capability a bhf builtin-engine C++ harness needs. Mirrors
/// `crates/cli/src/build.rs::detect_libstdcxx_include_flags`: some hosts (a mixed
/// gcc-13/14 layout, where clang++ picks gcc-14's prefix but the libstdc++
/// headers are under `/usr/include/c++/13`) need an explicit `-isystem` for
/// `<cstddef>` to resolve. Unlike `libfuzzer_toolchain_available*`, this does NOT
/// require the `-fsanitize=fuzzer` runtime (the builtin harness builds with ASan
/// and trace-pc-guard, no libFuzzer), so it is the correct guard for
/// builtin-engine C++ integration tests.
pub fn cpp_stdlib_toolchain_available(compiler: &str) -> bool {
    // Removed when the probe returns.
    let Ok(scratch) = tempfile::Builder::new()
        .prefix("bhf-cpp-stdlib-probe-")
        .tempdir()
    else {
        return false;
    };
    let dir = scratch.path();
    let src = dir.join("p.cpp");
    fs::write(&src, "#include <cstddef>\n#include <cstdlib>\nint d;\n").is_ok()
        && cxx_compiles_std_headers(compiler, &src)
}

fn cxx_compiles_std_headers(compiler: &str, src: &Path) -> bool {
    // Bare first; then retry with each candidate libstdc++ include set, exactly
    // as bhf's build path does.
    let mut attempts: Vec<Vec<OsString>> = vec![Vec::new()];
    for ver in ["13", "14", "12"] {
        let flags: Vec<OsString> = [
            format!("/usr/include/c++/{ver}"),
            format!("/usr/include/x86_64-linux-gnu/c++/{ver}"),
            format!("/usr/include/aarch64-linux-gnu/c++/{ver}"),
        ]
        .into_iter()
        .filter(|base| Path::new(base).is_dir())
        .flat_map(|base| [OsString::from("-isystem"), OsString::from(base)])
        .collect();
        if !flags.is_empty() {
            attempts.push(flags);
        }
    }
    attempts.into_iter().any(|extra| {
        Command::new(compiler)
            .args(["-std=gnu++20", "-fsyntax-only"])
            .args(&extra)
            .arg(src)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}
