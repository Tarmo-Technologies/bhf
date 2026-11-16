// SPDX-License-Identifier: Apache-2.0

//! The WinAFL engine (`--engine winafl`, native Windows only).
//!
//! WinAFL (github.com/googleprojectzero/winafl) fuzzes a harness in persistent
//! mode: its DynamoRIO client (or its Intel PT debugger) runs the harness until
//! `-target_method` is reached, then loops that function `-fuzz_iterations`
//! times, rewriting the input file between calls and measuring coverage of the
//! `-coverage_module`s. bhf's C/C++ driver exports such a function,
//! `bhf_winafl_fuzz(const char *path)`, which opens, reads and closes the file
//! and runs it.
//!
//! An AddressSanitizer harness cannot run under DynamoRIO (64-bit Windows ASan
//! commits its shadow memory on demand from access violations, which WinAFL's
//! client reports as crashes, and the process hangs at start-up under drrun),
//! so WinAFL fuzzes `main_winafl.exe`, the same sources built without ASan
//! or SanitizerCoverage (`make winafl`). The crashes and hangs WinAFL saves
//! are then replayed, within bounds, through the sanitized `main.exe` for
//! the sanitizer or exception report, and each report becomes a finding through
//! the same dedupe and results flow as an AFL++ crash. Each such finding records
//! how it was found in its `discovery` block.

use super::*;
use std::ffi::OsString;
use std::sync::Arc;

mod page_heap;
use page_heap::{PageHeapRun, Registry};

/// The driver's persistent entry, passed to WinAFL as `-target_method`.
pub(crate) const TARGET_METHOD: &str = "bhf_winafl_fuzz";
/// The file stem of the WinAFL build `make winafl` writes beside `main`.
pub(crate) const FUZZ_BINARY_STEM: &str = "main_winafl";
/// `-fuzz_iterations`: target-function calls before WinAFL restarts the
/// process (WinAFL's documented example value).
pub(crate) const DEFAULT_FUZZ_ITERATIONS: u32 = 5000;
/// `-t`: the per-iteration timeout, in milliseconds, when `--timeout` is not
/// given. Each iteration is one call of the persistent entry; the process
/// start under DynamoRIO is covered by WinAFL's own initialization timeout.
pub(crate) const DEFAULT_TIMEOUT_MS: u64 = 2000;
/// `-I`: the timeout of the first iteration after each (re)start of the
/// harness, which includes starting the process under DynamoRIO, at least
/// this many milliseconds. Without it that iteration gets only `-t`, and a
/// slow start reads as a hang and restarts the harness again.
pub(crate) const MIN_INIT_TIMEOUT_MS: u64 = 30_000;
/// WinAFL refuses a seed larger than this (`MAX_FILE` in its config.h).
const MAX_SEED_BYTES: usize = 1 << 20;
/// WinAFL refuses a dictionary token longer than this (`MAX_DICT_FILE`).
const MAX_DICTIONARY_TOKEN: usize = 128;
/// The bytes of WinAFL's coverage map (`MAP_SIZE`).
const MAP_SIZE: usize = 1 << 16;
/// What `-m` allows beyond `--rss-limit-mb`: WinAFL caps the committed memory
/// of drrun and the target (a job object's process memory limit), and the
/// target's includes DynamoRIO's own heap and code cache.
pub(crate) const DYNAMORIO_HEADROOM_MB: u64 = 1024;
/// Replaying the saved hangs stops after this many of them time out again with
/// no report in between: WinAFL keeps up to 500 hangs, and each that still
/// times out costs a replay timeout. A hang that replays clean costs only its
/// run, so it does not count.
pub(crate) const MAX_QUIET_HANGS: usize = 8;
/// The replay of the saved inputs gets half the fuzzing budget, at least this
/// long and at most [`MAX_INGEST`].
const MIN_INGEST: Duration = Duration::from_secs(30);
const MAX_INGEST: Duration = Duration::from_secs(600);
/// Replay failures named one by one; the rest are counted.
const MAX_REPLAY_WARNINGS: usize = 5;

pub(crate) const ENV_WINAFL_PATH: &str = "BHF_WINAFL_PATH";
pub(crate) const ENV_DYNAMORIO_PATH: &str = "BHF_DYNAMORIO_PATH";
/// DynamoRIO's own convention for its install root.
pub(crate) const ENV_DYNAMORIO_HOME: &str = "DYNAMORIO_HOME";

/// Why the WinAFL binary carries no sanitizer, recorded on the run and on
/// every finding it produced.
pub(crate) const SANITIZER_NOTE: &str = "WinAFL fuzzed a build without AddressSanitizer: an \
     ASan binary does not run under DynamoRIO (64-bit Windows ASan commits its shadow memory \
     from access violations, which WinAFL counts as crashes). Each saved crash and hang was \
     replayed through the sanitized harness for its report, so a memory error that does not \
     fault without ASan is found only by the other engines.";

/// The refusal on a host other than native Windows.
pub(crate) const NOT_WINDOWS: &str = "--engine winafl runs only on native Windows: WinAFL and \
     DynamoRIO are Windows programs. Use --engine builtin or afl++ on this host.";

/// How WinAFL collects coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WinaflInstrumentation {
    /// DynamoRIO dynamic instrumentation (`afl-fuzz -D`), the default.
    #[default]
    Dynamorio,
    /// Intel Processor Trace (`afl-fuzz -P`): needs an Intel CPU with PT, a
    /// WinAFL built with `-DINTELPT=1`, and no virtual machine in between
    /// unless the hypervisor passes PT through.
    #[value(name = "intel-pt")]
    IntelPt,
}

impl WinaflInstrumentation {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Dynamorio => "dynamorio",
            Self::IntelPt => "intel-pt",
        }
    }
}

/// The WinAFL settings a run was given (flags, config keys, environment),
/// before the tools are located.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WinaflSettings {
    pub winafl_path: Option<PathBuf>,
    pub dynamorio_path: Option<PathBuf>,
    pub instrumentation: WinaflInstrumentation,
    pub fuzz_iterations: Option<u32>,
    /// Extra `-coverage_module`s: DLLs of the target loaded by the harness.
    pub coverage_modules: Vec<String>,
    /// Run the WinAFL build under full PageHeap (`--winafl-page-heap`).
    pub page_heap: bool,
}

/// The architecture of a Windows harness, which picks DynamoRIO's `bin32` or
/// `bin64` and the matching `winafl.dll`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeArch {
    X86,
    X64,
}

impl PeArch {
    fn as_str(self) -> &'static str {
        match self {
            Self::X86 => "x86",
            Self::X64 => "x64",
        }
    }

    fn dynamorio_bin(self) -> &'static str {
        match self {
            Self::X86 => "bin32",
            Self::X64 => "bin64",
        }
    }

    fn winafl_dirs(self) -> &'static [&'static str] {
        match self {
            Self::X86 => &["", "bin32", "build32/bin/Release", "build/bin/Release"],
            Self::X64 => &["", "bin64", "build64/bin/Release", "build/bin/Release"],
        }
    }
}

/// `IMAGE_FILE_LARGE_ADDRESS_AWARE` in the COFF characteristics.
const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;

/// The COFF header's machine type and characteristics of a PE image, or
/// `None` for a file that is not one.
fn coff_header(bytes: &[u8]) -> Option<(u16, u16)> {
    if bytes.len() < 0x40 || &bytes[..2] != b"MZ" {
        return None;
    }
    let at = u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
    let header = bytes.get(at..at.checked_add(24)?)?;
    if &header[..4] != b"PE\0\0" {
        return None;
    }
    Some((
        u16::from_le_bytes([header[4], header[5]]),
        u16::from_le_bytes([header[22], header[23]]),
    ))
}

/// The architecture in a PE executable's header, `Ok(None)` for a file that is
/// not a PE image (a test's stand-in), or an error for one WinAFL cannot fuzz.
pub(crate) fn pe_arch(bytes: &[u8]) -> Result<Option<PeArch>, String> {
    let Some((machine, _)) = coff_header(bytes) else {
        return Ok(None);
    };
    match machine {
        0x8664 => Ok(Some(PeArch::X64)),
        0x014c => Ok(Some(PeArch::X86)),
        0xaa64 => Err(
            "--engine winafl: this harness is an ARM64 executable; WinAFL fuzzes x86 and x64 \
             harnesses (build it with --vs-arch x64)"
                .to_owned(),
        ),
        other => Err(format!(
            "--engine winafl: unsupported PE machine type 0x{other:04x}; WinAFL fuzzes x86 and \
             x64 harnesses"
        )),
    }
}

/// The first bytes of `path`, enough for its PE headers.
fn file_head(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut head = vec![0u8; 4096];
    let read = fs::File::open(path).and_then(|mut file| file.read(&mut head))?;
    head.truncate(read);
    Ok(head)
}

fn harness_arch(harness: &Path) -> Result<PeArch, String> {
    let head = file_head(harness)
        .map_err(|error| format!("read harness '{}': {error}", harness.display()))?;
    Ok(pe_arch(&head)?.unwrap_or(PeArch::X64))
}

/// The architecture `bhf auto` builds harnesses for: the Visual Studio
/// environment's target (`--vs-arch`, `VSCMD_ARG_TGT_ARCH`), or without one
/// the architecture bhf was built for (`host_arch`, as
/// [`std::env::consts::ARCH`] names it), which is the Visual Studio
/// environment's default. An ARM or ARM64 target is refused: WinAFL fuzzes
/// only x86 and x64 harnesses.
pub(crate) fn target_arch(
    env: &dyn Fn(&str) -> Option<OsString>,
    host_arch: &str,
) -> Result<PeArch, String> {
    let arch = match env("VSCMD_ARG_TGT_ARCH") {
        Some(arch) => arch.to_string_lossy().to_ascii_lowercase(),
        None => match host_arch {
            "x86" => "x86".to_owned(),
            "x86_64" => "x64".to_owned(),
            other => other.to_owned(),
        },
    };
    match arch.as_str() {
        "x86" => Ok(PeArch::X86),
        "x64" | "amd64" => Ok(PeArch::X64),
        other => Err(format!(
            "--engine winafl: harnesses here are built for {other} (--vs-arch, or this \
             machine's default); WinAFL fuzzes x86 and x64 harnesses, so run bhf with --vs-arch \
             x64 (or x86)"
        )),
    }
}

/// The name in a PE image's export directory, which DynamoRIO prefers to the
/// file name as a module's name (so WinAFL matches `-coverage_module` against
/// it). The WinAFL build exports its persistent entry, so it has one: the
/// file name it was linked as.
pub(crate) fn pe_export_name(bytes: &[u8]) -> Option<String> {
    let u16_at = |at: usize| Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?));
    let u32_at = |at: usize| Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?));
    if bytes.get(..2)? != b"MZ" {
        return None;
    }
    let pe = u32_at(0x3c)? as usize;
    if bytes.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let sections = usize::from(u16_at(pe + 6)?);
    let optional_size = usize::from(u16_at(pe + 20)?);
    let optional = pe + 24;
    let directories = match u16_at(optional)? {
        0x10b => optional + 96,
        0x20b => optional + 112,
        _ => return None,
    };
    if optional + optional_size < directories + 8 {
        return None;
    }
    let export_rva = u32_at(directories)?;
    if export_rva == 0 {
        return None;
    }
    let table = optional + optional_size;
    let offset_of = |rva: u32| -> Option<usize> {
        (0..sections).find_map(|index| {
            let header = table + index * 40;
            let size = u32_at(header + 8)?.max(u32_at(header + 16)?);
            let start = u32_at(header + 12)?;
            let raw = u32_at(header + 20)?;
            (rva >= start && rva - start < size).then(|| (rva - start + raw) as usize)
        })
    };
    let name_rva = u32_at(offset_of(export_rva)? + 12)?;
    let name_at = offset_of(name_rva)?;
    let name = bytes.get(name_at..)?;
    let end = name.iter().take(260).position(|&byte| byte == 0)?;
    let name = std::str::from_utf8(&name[..end]).ok()?;
    (!name.is_empty()).then(|| name.to_owned())
}

/// [`pe_export_name`] of a file (read in full, up to 256 MiB).
fn export_name_of(path: &Path) -> Option<String> {
    let bytes = read_seed_file_prefix(path, 256 << 20).ok()?.0;
    pe_export_name(&bytes)
}

/// Refuse a `--winafl-coverage-module` WinAFL cannot take: afl-fuzz joins the
/// client options into drrun's command line unquoted.
fn check_coverage_modules(modules: &[String]) -> Result<(), String> {
    for module in modules {
        if module.trim().is_empty() || module.chars().any(|ch| ch.is_whitespace() || ch == '"') {
            return Err(format!(
                "--winafl-coverage-module {module:?}: a module name with a space or a quote \
                 cannot be passed to WinAFL, which puts its client options into drrun's command \
                 line unquoted; give the module's file name (for example target.dll)"
            ));
        }
    }
    Ok(())
}

/// Where WinAFL's programs are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WinaflTools {
    pub(crate) afl_fuzz: PathBuf,
    /// The DynamoRIO client (`-w`), for DynamoRIO mode.
    pub(crate) winafl_dll: Option<PathBuf>,
    /// DynamoRIO's `bin64` (or `bin32`) directory (`-D`), for DynamoRIO mode.
    pub(crate) dynamorio_bin: Option<PathBuf>,
    pub(crate) instrumentation: WinaflInstrumentation,
}

/// Refuse `--engine winafl` anywhere but native Windows.
pub(crate) fn host_supported() -> Result<(), String> {
    if cfg!(windows) {
        Ok(())
    } else {
        Err(NOT_WINDOWS.to_owned())
    }
}

const WINAFL_INSTALL_HINT: &str = "build WinAFL from https://github.com/googleprojectzero/winafl \
     with CMake against DynamoRIO (`cmake -G \"Visual Studio 17 2022\" -A x64 .. \
     -DDynamoRIO_DIR=<DynamoRIO>\\cmake`, then `cmake --build . --config Release`); see \
     docs/site/windows.md";
const DYNAMORIO_INSTALL_HINT: &str = "download the DynamoRIO Windows package from \
     https://github.com/DynamoRIO/dynamorio/releases and unpack it (see docs/site/windows.md \
     for the version WinAFL was built against)";

fn exe(name: &str) -> String {
    format!("{name}.exe")
}

fn search_path(env: &dyn Fn(&str) -> Option<OsString>, program: &str) -> Option<PathBuf> {
    let paths = env("PATH")?;
    std::env::split_paths(&paths)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

/// The setting from a flag, else the first environment variable that is set.
fn setting_or_env(
    flag: Option<&Path>,
    flag_name: &str,
    env: &dyn Fn(&str) -> Option<OsString>,
    keys: &[&'static str],
) -> Option<(PathBuf, String)> {
    if let Some(path) = flag {
        return Some((path.to_path_buf(), flag_name.to_owned()));
    }
    keys.iter().find_map(|key| {
        env(key)
            .filter(|value| !value.is_empty())
            .map(|value| (PathBuf::from(value), (*key).to_owned()))
    })
}

/// Locate afl-fuzz.exe (and, for DynamoRIO, winafl.dll and DynamoRIO's bin
/// directory) from the settings, then the environment, then `PATH`, with an
/// error naming what is missing and how to install it.
pub(crate) fn resolve_tools(
    settings: &WinaflSettings,
    arch: PeArch,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Result<WinaflTools, String> {
    check_coverage_modules(&settings.coverage_modules)?;
    let afl_fuzz_name = exe("afl-fuzz");
    let candidates: Vec<PathBuf> = match setting_or_env(
        settings.winafl_path.as_deref(),
        "--winafl-path",
        env,
        &[ENV_WINAFL_PATH],
    ) {
        Some((dir, source)) => {
            if dir.is_file()
                && dir
                    .file_name()
                    .is_some_and(|name| name.eq_ignore_ascii_case(afl_fuzz_name.as_str()))
            {
                vec![dir]
            } else {
                let looked: Vec<PathBuf> = arch
                    .winafl_dirs()
                    .iter()
                    .map(|sub| dir.join(sub).join(&afl_fuzz_name))
                    .collect();
                let found: Vec<PathBuf> = looked
                    .iter()
                    .filter(|path| path.is_file())
                    .cloned()
                    .collect();
                if found.is_empty() {
                    return Err(format!(
                        "WinAFL not found: {} ({source}) holds no {afl_fuzz_name} (looked for {}); \
                         {WINAFL_INSTALL_HINT}",
                        dir.display(),
                        looked
                            .iter()
                            .map(|path| path.display().to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                found
            }
        }
        None => vec![search_path(env, &afl_fuzz_name).ok_or_else(|| {
            format!(
                "WinAFL not found: pass --winafl-path <dir> (the directory holding \
                 {afl_fuzz_name} and winafl.dll), set {ENV_WINAFL_PATH}, or put {afl_fuzz_name} \
                 on PATH; {WINAFL_INSTALL_HINT}"
            )
        })?],
    };
    // DynamoRIO loads winafl.dll into the target, so its architecture has to
    // be the harness's: a checkout holds both builds, and the first match wins.
    let mut wrong_arch: Option<(PathBuf, String)> = None;
    let mut afl_fuzz = candidates[0].clone();
    if settings.instrumentation == WinaflInstrumentation::Dynamorio {
        for candidate in &candidates {
            let dll = candidate.with_file_name("winafl.dll");
            if !dll.is_file() {
                continue;
            }
            let dll_arch = file_head(&dll).ok().map(|head| pe_arch(&head));
            match dll_arch {
                Some(Ok(Some(found))) if found != arch => {
                    wrong_arch.get_or_insert((dll, found.as_str().to_owned()));
                }
                Some(Err(_)) => {
                    wrong_arch.get_or_insert((dll, "unsupported".to_owned()));
                }
                _ => {
                    afl_fuzz = candidate.clone();
                    wrong_arch = None;
                    break;
                }
            }
        }
    }
    if let Some((dll, found)) = wrong_arch {
        let bits = if arch == PeArch::X86 { "32" } else { "64" };
        return Err(format!(
            "{} is an {found} DynamoRIO client, but the harness is {}: WinAFL's client must \
             match it. Pass the {} WinAFL build with --winafl-path (a checkout's \
             build{bits}\\bin\\Release)",
            dll.display(),
            arch.as_str(),
            arch.as_str()
        ));
    }
    let winafl_dir = afl_fuzz.parent().map(Path::to_path_buf).unwrap_or_default();
    match settings.instrumentation {
        WinaflInstrumentation::IntelPt => {
            // Only a WinAFL configured with -DINTELPT=1 builds winaflpt-debug.exe.
            if !winafl_dir.join(exe("winaflpt-debug")).is_file() {
                return Err(format!(
                    "--winafl-instrumentation intel-pt needs a WinAFL built with -DINTELPT=1 \
                     (no winaflpt-debug.exe beside {}); rebuild it with -DINTELPT=1 after \
                     `git submodule update --init --recursive`",
                    afl_fuzz.display()
                ));
            }
            Ok(WinaflTools {
                afl_fuzz,
                winafl_dll: None,
                dynamorio_bin: None,
                instrumentation: WinaflInstrumentation::IntelPt,
            })
        }
        WinaflInstrumentation::Dynamorio => {
            let winafl_dll = winafl_dir.join("winafl.dll");
            if !winafl_dll.is_file() {
                return Err(format!(
                    "WinAFL at {} has {afl_fuzz_name} but no winafl.dll, its DynamoRIO client: \
                     build WinAFL with -DDynamoRIO_DIR=<DynamoRIO>\\cmake so the client is built \
                     ({WINAFL_INSTALL_HINT})",
                    winafl_dir.display()
                ));
            }
            let drrun = exe("drrun");
            let dynamorio_bin = match setting_or_env(
                settings.dynamorio_path.as_deref(),
                "--dynamorio-path",
                env,
                &[ENV_DYNAMORIO_PATH, ENV_DYNAMORIO_HOME],
            ) {
                Some((dir, source)) => {
                    if dir.join(&drrun).is_file() {
                        dir
                    } else if dir.join(arch.dynamorio_bin()).join(&drrun).is_file() {
                        dir.join(arch.dynamorio_bin())
                    } else {
                        return Err(format!(
                            "DynamoRIO not found: {} ({source}) holds neither {drrun} nor {}\\{drrun}; \
                             pass the DynamoRIO install root (or its {} directory); \
                             {DYNAMORIO_INSTALL_HINT}",
                            dir.display(),
                            arch.dynamorio_bin(),
                            arch.dynamorio_bin()
                        ));
                    }
                }
                None => search_path(env, &drrun)
                    .and_then(|path| path.parent().map(Path::to_path_buf))
                    .ok_or_else(|| {
                        format!(
                            "DynamoRIO not found: pass --dynamorio-path <dir> (the DynamoRIO \
                             install root, holding {}\\{drrun}), set {ENV_DYNAMORIO_PATH} or \
                             {ENV_DYNAMORIO_HOME}, or put {drrun} on PATH; {DYNAMORIO_INSTALL_HINT}",
                            arch.dynamorio_bin()
                        )
                    })?,
            };
            // afl-fuzz writes both into drrun's command line unquoted.
            for path in [&dynamorio_bin, &winafl_dll] {
                if path.to_string_lossy().contains(' ') {
                    return Err(format!(
                        "{} has a space in it, and afl-fuzz puts the DynamoRIO directory and \
                         winafl.dll into drrun's command line unquoted: install DynamoRIO and \
                         WinAFL in paths without spaces (for example under C:\\tools)",
                        path.display()
                    ));
                }
            }
            Ok(WinaflTools {
                afl_fuzz,
                winafl_dll: Some(winafl_dll),
                dynamorio_bin: Some(dynamorio_bin),
                instrumentation: WinaflInstrumentation::Dynamorio,
            })
        }
    }
}

/// [`resolve_tools`] for `harness` (its architecture) with the process
/// environment.
pub(crate) fn resolve_tools_for(
    settings: &WinaflSettings,
    harness: &Path,
) -> Result<WinaflTools, String> {
    let arch = harness_arch(harness)?;
    resolve_tools(settings, arch, &|key| std::env::var_os(key))
}

/// Everything one afl-fuzz invocation is built from.
pub(crate) struct WinaflCommand<'a> {
    pub(crate) tools: &'a WinaflTools,
    pub(crate) seeds_dir: &'a Path,
    pub(crate) out_dir: &'a Path,
    pub(crate) timeout_ms: u64,
    pub(crate) dictionary: Option<&'a Path>,
    pub(crate) fuzz_binary: &'a Path,
    pub(crate) coverage_modules: &'a [String],
    pub(crate) fuzz_iterations: u32,
    /// `-m`: the memory cap of drrun and the target in MiB, `None` for no cap
    /// (`-m none`).
    pub(crate) memory_limit_mb: Option<u64>,
}

/// How much memory a WinAFL build can address: its architecture, and for an
/// x86 one whether it is linked `/LARGEADDRESSAWARE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MemoryModel {
    pub(crate) arch: PeArch,
    pub(crate) large_address_aware: bool,
}

impl MemoryModel {
    pub(crate) const X64: Self = Self {
        arch: PeArch::X64,
        large_address_aware: true,
    };

    /// The model of the image at `path` (x64 for a file that is not a PE
    /// image, a test's stand-in).
    fn of(path: &Path) -> Self {
        match file_head(path).ok().as_deref().and_then(coff_header) {
            Some((0x014c, characteristics)) => Self {
                arch: PeArch::X86,
                large_address_aware: characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE != 0,
            },
            _ => Self::X64,
        }
    }

    /// The most an x86 process can commit, in MiB: its 2 GiB of user
    /// address space, or 4 GiB under WOW64 when large-address aware.
    fn x86_address_space_mb(self) -> Option<u64> {
        (self.arch == PeArch::X86).then_some(if self.large_address_aware { 4096 } else { 2048 })
    }
}

/// WinAFL's `-m` for `--rss-limit-mb`: the limit plus DynamoRIO's share, or
/// no limit for `0`. For an x86 harness (which gets a 32-bit afl-fuzz, whose
/// `SIZE_T` job memory limit wraps at 4 GiB) a cap the process's address space
/// already enforces, or one past it, is no limit (`-m none`), so `-m` never
/// reaches 4096 there.
pub(crate) fn memory_limit_mb(rss_limit_mb: usize, model: MemoryModel) -> Option<u64> {
    let limit =
        (rss_limit_mb > 0).then(|| (rss_limit_mb as u64).saturating_add(DYNAMORIO_HEADROOM_MB))?;
    match model.x86_address_space_mb() {
        Some(space) if limit >= space => None,
        _ => Some(limit),
    }
}

/// The module name WinAFL matches (case-insensitively) against loaded
/// modules: the fuzz binary's file name.
fn module_name(binary: &Path) -> String {
    binary
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| binary.display().to_string())
}

/// afl-fuzz's arguments: `[afl options] -- [instrumentation options] --
/// <target> @@`. The harness exe is always a coverage module (the target
/// sources are compiled into it); `coverage_modules` adds the target's own
/// DLLs. `-t <ms>+` skips seeds that time out instead of aborting, `-I` gives
/// the first iteration of each process its start-up time, `-m` caps the
/// memory of drrun and the target, and `-d` skips AFL's deterministic
/// stages, as AFL++ does by default: on a campaign of minutes they spend the
/// budget walking the first queue entries.
pub(crate) fn afl_fuzz_args(command: &WinaflCommand<'_>) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        "-i".into(),
        command.seeds_dir.into(),
        "-o".into(),
        command.out_dir.into(),
    ];
    match command.tools.instrumentation {
        WinaflInstrumentation::Dynamorio => {
            if let Some(bin) = &command.tools.dynamorio_bin {
                args.push("-D".into());
                args.push(bin.into());
            }
            if let Some(dll) = &command.tools.winafl_dll {
                args.push("-w".into());
                args.push(dll.into());
            }
        }
        WinaflInstrumentation::IntelPt => args.push("-P".into()),
    }
    let timeout_ms = command.timeout_ms.max(1);
    args.push("-t".into());
    args.push(format!("{timeout_ms}+").into());
    args.push("-I".into());
    args.push(
        timeout_ms
            .saturating_mul(10)
            .max(MIN_INIT_TIMEOUT_MS)
            .min(u64::from(u32::MAX))
            .to_string()
            .into(),
    );
    args.push("-m".into());
    args.push(
        command
            .memory_limit_mb
            .map_or_else(|| "none".to_owned(), |limit| limit.max(5).to_string())
            .into(),
    );
    args.push("-d".into());
    if let Some(dictionary) = command.dictionary {
        args.push("-x".into());
        args.push(dictionary.into());
    }
    args.push("--".into());
    let module = module_name(command.fuzz_binary);
    let mut modules = vec![module.clone()];
    for extra in command.coverage_modules {
        if !modules
            .iter()
            .any(|known| known.eq_ignore_ascii_case(extra.as_str()))
        {
            modules.push(extra.clone());
        }
    }
    for name in modules {
        args.push("-coverage_module".into());
        args.push(name.into());
    }
    args.extend(
        [
            "-target_module".to_owned(),
            module,
            "-target_method".to_owned(),
            TARGET_METHOD.to_owned(),
            "-nargs".to_owned(),
            "1".to_owned(),
            "-fuzz_iterations".to_owned(),
            command.fuzz_iterations.max(1).to_string(),
        ]
        .map(OsString::from),
    );
    if command.tools.instrumentation == WinaflInstrumentation::Dynamorio {
        args.push("-covtype".into());
        args.push("edge".into());
    }
    args.push("--".into());
    args.push(command.fuzz_binary.into());
    args.push("@@".into());
    args
}

/// The WinAFL build beside the sanitized harness: `main_winafl.exe` on
/// Windows (the Makefile names it with `$(EXEEXT)`), or the extensionless
/// `main_winafl` an earlier build left; `main_winafl` elsewhere.
pub(crate) fn fuzz_binary_beside(harness: &Path) -> Option<PathBuf> {
    let path = crate::auto::layout::harness_exe(harness.parent()?, FUZZ_BINARY_STEM);
    path.is_file().then_some(path)
}

/// One dictionary token in the syntax WinAFL's AFL 2.x parser reads:
/// `"..."` with printable ASCII as is, `\\` and `\"` escaped, and every other
/// byte as `\xNN`.
pub(crate) fn dictionary_line(token: &[u8]) -> String {
    let mut line = String::with_capacity(token.len() + 2);
    line.push('"');
    for &byte in token {
        match byte {
            b'\\' => line.push_str("\\\\"),
            b'"' => line.push_str("\\\""),
            0x20..=0x7e => line.push(byte as char),
            _ => line.push_str(&format!("\\x{byte:02x}")),
        }
    }
    line.push('"');
    line
}

/// Merge the harness's `dictionary.txt` and learned dictionary into the one
/// `-x` file WinAFL takes (AFL 2.x accepts a single dictionary), keeping each
/// token once and leaving out the empty ones and those over WinAFL's limit.
/// Returns the file and its token count, or `None` when there is no token.
pub(crate) fn write_merged_dictionary(
    work_dir: &Path,
    harness_id: &str,
    dest: &Path,
) -> Result<Option<(PathBuf, usize)>, String> {
    let mut tokens: Vec<Vec<u8>> = Vec::new();
    for path in [
        find_generated_dictionary(work_dir, harness_id),
        find_learned_dictionary(work_dir, harness_id),
    ]
    .into_iter()
    .flatten()
    {
        // A damaged dictionary costs its hints, never the run.
        match load_afl_dictionary_tokens(&path) {
            Ok(found) => {
                for token in found {
                    if !token.is_empty()
                        && token.len() <= MAX_DICTIONARY_TOKEN
                        && !tokens.contains(&token)
                    {
                        tokens.push(token);
                    }
                }
            }
            Err(error) => bhfeprintln!(
                "bhf: warning: dictionary {} not used for WinAFL: {error}",
                path.display()
            ),
        }
    }
    if tokens.is_empty() {
        let _ = fs::remove_file(dest);
        return Ok(None);
    }
    let mut text = String::from("# bhf: the harness dictionaries, merged for WinAFL's -x\n");
    for token in &tokens {
        text.push_str(&dictionary_line(token));
        text.push('\n');
    }
    fs::write(dest, text)
        .map_err(|error| format!("write WinAFL dictionary '{}': {error}", dest.display()))?;
    Ok(Some((dest.to_path_buf(), tokens.len())))
}

/// Write the seeds byte for byte into `dir` (`seed-NNNN`). WinAFL skips an
/// empty file and refuses one over 1 MiB, so an empty seed is left out and a
/// larger one is cut to 1 MiB (with a note). A default seed stands in when no
/// seed is left. Returns how many seeds were written.
pub(crate) fn write_seed_dir(seeds: &[Vec<u8>], dir: &Path) -> Result<usize, String> {
    fs::create_dir_all(dir)
        .map_err(|error| format!("create WinAFL seeds dir '{}': {error}", dir.display()))?;
    let mut written = 0usize;
    for (index, seed) in seeds.iter().enumerate() {
        if seed.is_empty() {
            continue;
        }
        let bytes = if seed.len() > MAX_SEED_BYTES {
            bhfeprintln!(
                "bhf: seed {index} is {} bytes; WinAFL takes at most {MAX_SEED_BYTES}, so its \
                 first {MAX_SEED_BYTES} bytes are used",
                seed.len()
            );
            &seed[..MAX_SEED_BYTES]
        } else {
            &seed[..]
        };
        let path = dir.join(format!("seed-{index:04}"));
        fs::write(&path, bytes)
            .map_err(|error| format!("write seed '{}': {error}", path.display()))?;
        written += 1;
    }
    if written == 0 {
        let path = dir.join("seed-default");
        fs::write(&path, b"AAAA").map_err(|error| format!("write default seed: {error}"))?;
    }
    Ok(written)
}

/// The inputs WinAFL saved in `dir` (`crashes/` or `hangs/`): its `id_...`
/// files (or AFL's `id:...` spelling), in name order, without `README.txt`.
pub(crate) fn saved_inputs(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("id_") || name.starts_with("id:"))
        })
        .collect();
    paths.sort();
    paths
}

/// The exception WinAFL named a crash file after:
/// `id_000000_00_EXCEPTION_ACCESS_VIOLATION` -> `EXCEPTION_ACCESS_VIOLATION`.
pub(crate) fn crash_exception_name(file_name: &str) -> Option<&str> {
    let mut parts = file_name.splitn(4, '_');
    (parts.next()? == "id").then_some(())?;
    let id = parts.next()?;
    let signal = parts.next()?;
    let name = parts.next()?;
    (id.bytes().all(|b| b.is_ascii_digit())
        && signal.bytes().all(|b| b.is_ascii_digit())
        && !name.is_empty())
    .then_some(name)
}

/// The seeds WinAFL's dry run found crashing (`AFL_SKIP_CRASHES` skips them,
/// so they never reach `crashes/`): each `Attempting dry run with '<file>'`
/// followed by `Test case results in a crash`.
pub(crate) fn crashing_seeds_in_log(log: &str) -> Vec<PathBuf> {
    let mut current: Option<&str> = None;
    let mut out = Vec::new();
    for line in log.lines() {
        if let Some(rest) = line.split("Attempting dry run with '").nth(1) {
            current = rest.split('\'').next();
        } else if line.contains("results in a crash") {
            if let Some(file) = current.take() {
                let path = PathBuf::from(file);
                if !out.contains(&path) {
                    out.push(path);
                }
            }
        }
    }
    out
}

/// One `plot_data` row (written every five seconds).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PlotRow {
    pub(crate) relative_time: u64,
    pub(crate) paths_total: u64,
    pub(crate) map_density_percent: f64,
    pub(crate) unique_crashes: u64,
    pub(crate) unique_hangs: u64,
    pub(crate) execs_per_sec: f64,
}

/// Parse WinAFL's `plot_data`: `relative_time, cycles_done, cur_path,
/// paths_total, pending_total, pending_favs, map_size, unique_crashes,
/// unique_hangs, max_depth, execs_per_sec`, skipping the header and any line
/// that does not parse.
pub(crate) fn parse_plot_data(text: &str) -> Vec<PlotRow> {
    text.lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(',').map(str::trim).collect();
            if fields.len() < 11 {
                return None;
            }
            Some(PlotRow {
                relative_time: fields[0].parse().ok()?,
                paths_total: fields[3].parse().ok()?,
                map_density_percent: fields[6].trim_end_matches('%').parse().ok()?,
                unique_crashes: fields[7].parse().ok()?,
                unique_hangs: fields[8].parse().ok()?,
                execs_per_sec: fields[10].parse().ok()?,
            })
        })
        .collect()
}

/// Parse WinAFL's `fuzzer_stats` (`key : value` lines).
pub(crate) fn parse_fuzzer_stats(text: &str) -> std::collections::BTreeMap<String, String> {
    text.lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        .collect()
}

/// The edges WinAFL's `fuzz_bitmap` (its virgin map) shows as hit: the bytes
/// no longer `0xff`.
pub(crate) fn bitmap_edges(bitmap: &[u8]) -> usize {
    bitmap.iter().filter(|&&byte| byte != 0xff).count()
}

/// Executions estimated from `plot_data` when `fuzzer_stats` (written once a
/// minute) is older: each row's rate over the time since the row before, and
/// the last row's rate up to `elapsed_secs`.
pub(crate) fn estimate_executions(rows: &[PlotRow], elapsed_secs: f64) -> u64 {
    let mut total = 0.0f64;
    let mut previous = 0u64;
    for row in rows {
        let span = row.relative_time.saturating_sub(previous) as f64;
        total += row.execs_per_sec.max(0.0) * span;
        previous = row.relative_time;
    }
    if let Some(last) = rows.last() {
        let tail = (elapsed_secs - last.relative_time as f64).max(0.0);
        total += last.execs_per_sec.max(0.0) * tail;
    }
    total.round() as u64
}

/// What WinAFL reported about its run, from the freshest of `fuzzer_stats`,
/// `fuzz_bitmap` and `plot_data`.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub(crate) struct WinaflStats {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) afl_version: Option<String>,
    pub(crate) executions: u64,
    /// `fuzzer_stats` (exact, at its last write), `plot_data` (estimated from
    /// its rates), or `none`.
    pub(crate) executions_source: &'static str,
    pub(crate) execs_per_sec: f64,
    pub(crate) paths_total: u64,
    /// WinAFL's map density (`bitmap_cvg` / `map_size`), in percent.
    pub(crate) map_density_percent: f64,
    /// Map bytes WinAFL saw hit: from `fuzz_bitmap` when it was written, else
    /// from the density.
    pub(crate) map_edges: usize,
    pub(crate) unique_crashes: u64,
    pub(crate) unique_hangs: u64,
}

pub(crate) fn read_stats(out_dir: &Path, elapsed_secs: f64) -> WinaflStats {
    let stats = fs::read_to_string(out_dir.join("fuzzer_stats"))
        .map(|text| parse_fuzzer_stats(&text))
        .unwrap_or_default();
    let rows = fs::read_to_string(out_dir.join("plot_data"))
        .map(|text| parse_plot_data(&text))
        .unwrap_or_default();
    let number = |key: &str| -> Option<f64> {
        stats
            .get(key)
            .and_then(|value| value.trim_end_matches('%').parse::<f64>().ok())
    };
    let last = rows.last();
    let stats_execs = number("execs_done").map(|value| value as u64);
    let plot_execs = (!rows.is_empty()).then(|| estimate_executions(&rows, elapsed_secs));
    let (executions, executions_source) = match (stats_execs, plot_execs) {
        (Some(exact), Some(estimate)) if estimate > exact => (estimate, "plot_data"),
        (Some(exact), _) => (exact, "fuzzer_stats"),
        (None, Some(estimate)) => (estimate, "plot_data"),
        (None, None) => (0, "none"),
    };
    let map_density_percent = number("bitmap_cvg")
        .into_iter()
        .chain(last.map(|row| row.map_density_percent))
        .fold(0.0f64, f64::max);
    let density_edges = (map_density_percent / 100.0 * MAP_SIZE as f64).round() as usize;
    let file_edges = read_seed_file_prefix(&out_dir.join("fuzz_bitmap"), MAP_SIZE)
        .map(|(bytes, _)| bitmap_edges(&bytes))
        .unwrap_or(0);
    let max_u64 = |key: &str, plot: Option<u64>| -> u64 {
        number(key)
            .map(|value| value as u64)
            .into_iter()
            .chain(plot)
            .max()
            .unwrap_or(0)
    };
    WinaflStats {
        afl_version: stats.get("afl_version").cloned(),
        executions,
        executions_source,
        execs_per_sec: last
            .map(|row| row.execs_per_sec)
            .or_else(|| number("execs_per_sec"))
            .unwrap_or(0.0),
        paths_total: max_u64("paths_total", last.map(|row| row.paths_total)),
        map_density_percent,
        map_edges: file_edges.max(density_edges),
        unique_crashes: max_u64("unique_crashes", last.map(|row| row.unique_crashes)),
        unique_hangs: max_u64("unique_hangs", last.map(|row| row.unique_hangs)),
    }
}

/// WinAFL run provenance recorded in `run.json` (`winafl`).
#[derive(Debug, Serialize)]
pub(crate) struct WinaflRunProvenance {
    pub(crate) instrumentation: &'static str,
    pub(crate) afl_fuzz: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) winafl_dll: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) dynamorio: Option<PathBuf>,
    /// The binary WinAFL fuzzed (no sanitizer) and the one every saved input
    /// was replayed through.
    pub(crate) fuzz_binary: PathBuf,
    pub(crate) replay_binary: PathBuf,
    pub(crate) fuzz_binary_sanitizers: Vec<String>,
    pub(crate) sanitizer_note: &'static str,
    pub(crate) target_method: &'static str,
    pub(crate) coverage_modules: Vec<String>,
    pub(crate) fuzz_iterations: u32,
    pub(crate) timeout_ms: u64,
    /// WinAFL's `-m` (MiB), `None` for `-m none` (`--rss-limit-mb 0`).
    pub(crate) memory_limit_mb: Option<u64>,
    /// The WinAFL build ran under full PageHeap, as its Image File Execution
    /// Options key read when the run started (`--winafl-page-heap`, or a
    /// setting made outside bhf).
    pub(crate) page_heap: bool,
    /// The key bhf set for this run and removed after it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) page_heap_key: Option<String>,
    /// The run's copy of `fuzz_binary` WinAFL ran under PageHeap (deleted
    /// after the run).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) page_heap_image: Option<PathBuf>,
    pub(crate) seeds: usize,
    pub(crate) dictionary_tokens: usize,
    pub(crate) stats: WinaflStats,
    pub(crate) crashes_saved: usize,
    pub(crate) hangs_saved: usize,
    pub(crate) crashing_seeds: usize,
    /// Saved inputs of earlier runs of the harness that ended before they
    /// replayed them (Ctrl-C, a kill), replayed with this run's.
    pub(crate) earlier_inputs: usize,
    /// Saved inputs that produced a report on replay, that ran clean, and
    /// that still timed out.
    pub(crate) replay_reported: usize,
    pub(crate) replay_clean: usize,
    pub(crate) replay_timed_out: usize,
    /// Saved inputs not replayed because their bytes were replayed already,
    /// because the replay was bounded (its deadline, or hangs that kept
    /// replaying without a report), or because they could not be replayed.
    pub(crate) replay_duplicates: usize,
    pub(crate) replay_skipped: usize,
    pub(crate) replay_errors: usize,
    pub(crate) queue_persisted: usize,
    /// afl-fuzz sessions run: more than one when WinAFL stopped early and was
    /// restarted on its queue.
    pub(crate) sessions: usize,
    /// How the last session ended when it stopped before the budget.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) stopped_early: Option<String>,
}

/// What the replay of WinAFL's saved inputs produced.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Ingested {
    pub(crate) finding_ids: Vec<String>,
    pub(crate) reported: usize,
    pub(crate) clean: usize,
    pub(crate) timed_out: usize,
    /// Saved inputs with the same bytes as one replayed before.
    pub(crate) duplicates: usize,
    /// Saved inputs left unreplayed: the replay deadline passed, or
    /// [`MAX_QUIET_HANGS`] hangs timed out again with no report in between.
    pub(crate) skipped: usize,
    /// Saved inputs that could not be read or replayed.
    pub(crate) errors: usize,
}

/// How one saved input replayed through the sanitized harness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Replayed {
    /// A report: the new finding's id, or `None` for a known root cause.
    Reported(Option<String>),
    Clean,
    TimedOut,
}

/// The bounds of the replay of a run's saved inputs.
#[derive(Debug, Clone, Copy)]
pub(crate) struct IngestLimits {
    /// No input is replayed after this.
    pub(crate) deadline: Instant,
    /// The end of the replay time kept for the hangs: while hangs wait, the
    /// crashes and crashing seeds are replayed only until this long before
    /// the deadline, so a run of many crashes cannot leave the hangs no time.
    pub(crate) hang_share: Duration,
    /// Hangs stop being replayed after this many timed out again with no
    /// report in between.
    pub(crate) max_quiet_hangs: usize,
}

impl IngestLimits {
    /// Half the fuzzing budget from now, at least [`MIN_INGEST`] and at most
    /// [`MAX_INGEST`], half of it kept for the hangs.
    pub(crate) fn for_budget(budget: Duration) -> Self {
        let window = (budget / 2).clamp(MIN_INGEST, MAX_INGEST);
        Self {
            deadline: Instant::now() + window,
            hang_share: window / 2,
            max_quiet_hangs: MAX_QUIET_HANGS,
        }
    }
}

/// The order saved inputs are replayed in: the first crash of each exception
/// name, then the other crashes, then the crashing seeds, then the hangs, so a
/// bounded replay reaches every kind of fault first.
pub(crate) fn replay_order(saved: &[(PathBuf, SavedKind)]) -> Vec<(PathBuf, SavedKind)> {
    let rank = |kind: SavedKind| match kind {
        SavedKind::Crash => 1,
        SavedKind::CrashingSeed => 2,
        SavedKind::Hang => 3,
    };
    let mut names_seen: HashSet<String> = HashSet::new();
    let mut keyed: Vec<(usize, usize, (PathBuf, SavedKind))> = saved
        .iter()
        .enumerate()
        .map(|(index, (path, kind))| {
            let first_of_name = *kind == SavedKind::Crash
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .and_then(crash_exception_name)
                    .is_some_and(|name| names_seen.insert(name.to_owned()));
            let rank = if first_of_name { 0 } else { rank(*kind) };
            (rank, index, (path.clone(), *kind))
        })
        .collect();
    keyed.sort_by_key(|(rank, index, _)| (*rank, *index));
    keyed.into_iter().map(|(_, _, entry)| entry).collect()
}

/// Replays one saved input (its path, kind and bytes).
pub(crate) type ReplayOne<'a> = dyn FnMut(&Path, SavedKind, &[u8]) -> Result<Replayed, String> + 'a;

/// Replay `saved` through `replay` within `limits`, `now` telling the time:
/// each distinct input once (by content), and nothing after the deadline.
/// The crashes and crashing seeds go first ([`replay_order`]) but stop at the
/// hangs' share of the time ([`IngestLimits::hang_share`]) while there are
/// hangs; the hangs follow until [`IngestLimits::max_quiet_hangs`] of them
/// time out again with no report in between (one that replays clean does not
/// count); the crashes left over then get what time remains. An input that
/// cannot be read or replayed is a warning; the others are still replayed.
pub(crate) fn replay_saved(
    saved: &[(PathBuf, SavedKind)],
    limits: IngestLimits,
    now: &dyn Fn() -> Instant,
    replay: &mut ReplayOne<'_>,
) -> Ingested {
    use sha2::{Digest, Sha256};
    let mut out = Ingested::default();
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut replay_one = |out: &mut Ingested, path: &Path, kind: SavedKind| -> Option<Replayed> {
        let input = match read_seed_file_prefix(path, MAX_SEED_BYTES) {
            Ok((bytes, _)) => bytes,
            Err(error) => {
                out.errors += 1;
                if out.errors <= MAX_REPLAY_WARNINGS {
                    bhfeprintln!(
                        "bhf: warning: could not read WinAFL {} '{}': {error}",
                        kind.as_str(),
                        path.display()
                    );
                }
                return None;
            }
        };
        if !seen.insert(Sha256::digest(&input).into()) {
            out.duplicates += 1;
            return None;
        }
        match replay(path, kind, &input) {
            Ok(Replayed::Reported(finding)) => {
                out.reported += 1;
                out.finding_ids.extend(finding.clone());
                Some(Replayed::Reported(finding))
            }
            Ok(outcome) => {
                if outcome == Replayed::Clean {
                    out.clean += 1;
                } else {
                    out.timed_out += 1;
                }
                Some(outcome)
            }
            Err(error) => {
                out.errors += 1;
                if out.errors <= MAX_REPLAY_WARNINGS {
                    bhfeprintln!(
                        "bhf: warning: could not replay WinAFL {} '{}': {error}",
                        kind.as_str(),
                        path.display()
                    );
                }
                None
            }
        }
    };
    let (hangs, others): (Vec<_>, Vec<_>) = replay_order(saved)
        .into_iter()
        .partition(|(_, kind)| *kind == SavedKind::Hang);
    let others_until = if hangs.is_empty() {
        limits.deadline
    } else {
        limits
            .deadline
            .checked_sub(limits.hang_share)
            .unwrap_or(limits.deadline)
    };
    let mut deferred = Vec::new();
    for (path, kind) in others {
        if now() >= others_until {
            deferred.push((path, kind));
            continue;
        }
        replay_one(&mut out, &path, kind);
    }
    let mut quiet_hangs = 0usize;
    for (path, kind) in hangs {
        if now() >= limits.deadline || quiet_hangs >= limits.max_quiet_hangs {
            out.skipped += 1;
            continue;
        }
        match replay_one(&mut out, &path, kind) {
            Some(Replayed::Reported(_)) => quiet_hangs = 0,
            Some(Replayed::TimedOut) => quiet_hangs += 1,
            Some(Replayed::Clean) | None => {}
        }
    }
    for (path, kind) in deferred {
        if now() >= limits.deadline {
            out.skipped += 1;
            continue;
        }
        replay_one(&mut out, &path, kind);
    }
    if out.errors > MAX_REPLAY_WARNINGS {
        bhfeprintln!(
            "bhf: warning: {} more WinAFL inputs could not be read or replayed",
            out.errors - MAX_REPLAY_WARNINGS
        );
    }
    out
}

/// Where a saved input came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SavedKind {
    Crash,
    Hang,
    CrashingSeed,
}

impl SavedKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Crash => "crash",
            Self::Hang => "hang",
            Self::CrashingSeed => "crashing-seed",
        }
    }
}

/// The `discovery` block of a finding WinAFL found.
fn discovery_record(
    tools: &WinaflTools,
    fuzz_binary: &Path,
    replay_binary: &Path,
    saved: &Path,
    kind: SavedKind,
    page_heap: bool,
) -> serde_json::Value {
    let name = saved
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut record = serde_json::json!({
        "engine": "winafl",
        "instrumentation": tools.instrumentation.as_str(),
        "binary": fuzz_binary,
        "sanitizers": Vec::<String>::new(),
        "page_heap": page_heap,
        "saved_as": kind.as_str(),
        "saved_input": saved,
        "confirmed_by": replay_binary,
        "note": SANITIZER_NOTE,
    });
    if let Some(exception) = (kind == SavedKind::Crash)
        .then(|| crash_exception_name(&name))
        .flatten()
    {
        record["exception"] = serde_json::json!(exception);
    }
    record
}

fn stamp_discovery(work_dir: &Path, finding_id: &str, discovery: serde_json::Value) {
    let path = corpus::layout::finding_dir(work_dir, finding_id).join("finding.json");
    let result = fs::read(&path)
        .map_err(|error| error.to_string())
        .and_then(|bytes| {
            serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|error| error.to_string())
        })
        .and_then(|mut record| {
            let Some(object) = record.as_object_mut() else {
                return Err("finding.json is not an object".to_owned());
            };
            object.insert("discovery".to_owned(), discovery);
            corpus::finding::append_history(&mut record, "fuzz", &["discovery"]);
            serde_json::to_vec_pretty(&record).map_err(|error| error.to_string())
        })
        .and_then(|bytes| {
            crate::auto::report::atomic_write(&path, &bytes).map_err(|error| error.to_string())
        });
    if let Err(error) = result {
        bhfeprintln!("bhf: warning: could not record how {finding_id} was found: {error}");
    }
}

/// Replay the saved inputs through the sanitized harness (within `limits`)
/// and emit a finding for each new root cause, deduped as AFL++ crashes are.
#[allow(clippy::too_many_arguments)]
pub(crate) fn ingest(
    prepared: &PreparedFuzzRun,
    emitter: &FindingEmitter,
    dedup: &mut SanitizerClusterDedup,
    tools: &WinaflTools,
    fuzz_binary: &Path,
    page_heap: bool,
    saved: &[(PathBuf, SavedKind)],
    replay_timeout: Duration,
    limits: IngestLimits,
) -> Ingested {
    replay_saved(saved, limits, &Instant::now, &mut |path, kind, input| {
        let started = Instant::now();
        let run = run_harness(
            &prepared.runner,
            &prepared.work_dir,
            input,
            &prepared.extra_env,
            replay_timeout,
            prepared.rss_limit_mb,
            prepared.deadline,
        )?;
        let Some(report) = run.sanitizer else {
            return Ok(if started.elapsed() >= replay_timeout {
                Replayed::TimedOut
            } else {
                Replayed::Clean
            });
        };
        if !afl_crash_is_new(dedup, &report) {
            return Ok(Replayed::Reported(None));
        }
        let id = emitter
            .emit_sanitizer_crash_with_log(input, &report, run.stderr.as_deref().map(str::as_bytes))
            .map_err(|error| format!("emit WinAFL finding: {error}"))?;
        record_finding_arguments(
            &prepared.work_dir,
            &id.0,
            &prepared.harness_path,
            input,
            TraceInput::ArgvFile,
            &prepared.extra_env,
            replay_timeout,
            None,
        );
        stamp_discovery(
            &prepared.work_dir,
            &id.0,
            discovery_record(
                tools,
                fuzz_binary,
                &prepared.harness_path,
                path,
                kind,
                page_heap,
            ),
        );
        Ok(Replayed::Reported(Some(id.0)))
    })
}

/// The refusal of `--winafl-page-heap` in a shell that may not write the
/// Image File Execution Options key.
pub(crate) const PAGE_HEAP_NEEDS_ELEVATION: &str = "--winafl-page-heap turns on PageHeap through \
     an Image File Execution Options key under HKLM, which needs an elevated (administrator) \
     shell, and this one is not: run bhf from an elevated shell, or leave out \
     --winafl-page-heap (bhf then replays the hangs WinAFL saves, which finds heap overflows \
     too)";

/// Refuse `--winafl-page-heap` up front when the key cannot be written.
pub(crate) fn check_page_heap_allowed(
    settings: &WinaflSettings,
    registry: &dyn Registry,
) -> Result<(), String> {
    if settings.page_heap && !registry.writable(page_heap::IFEO) {
        return Err(PAGE_HEAP_NEEDS_ELEVATION.to_owned());
    }
    Ok(())
}

/// The checks `bhf auto` makes before its sweep: WinAFL and DynamoRIO located
/// for the architecture harnesses are built for, and PageHeap writable when
/// asked for.
pub(crate) fn check_tools(
    settings: &WinaflSettings,
    env: &dyn Fn(&str) -> Option<OsString>,
    registry: &dyn Registry,
) -> Result<(), String> {
    resolve_tools(settings, target_arch(env, std::env::consts::ARCH)?, env)?;
    check_page_heap_allowed(settings, registry)
}

/// [`check_tools`] on this host, after refusing any host but native Windows.
pub(crate) fn check_available(settings: &WinaflSettings) -> Result<(), String> {
    host_supported()?;
    check_tools(
        settings,
        &|key| std::env::var_os(key),
        page_heap::system_registry().as_ref(),
    )
}

/// [`check_page_heap_allowed`] on this host.
pub(crate) fn check_page_heap_here(settings: &WinaflSettings) -> Result<(), String> {
    check_page_heap_allowed(settings, page_heap::system_registry().as_ref())
}

/// Kills the afl-fuzz process tree: a Windows job object holds afl-fuzz,
/// drrun and the target, so a time-budget stop leaves none of them running
/// (WinAFL has no time limit and no graceful stop of its own).
struct ProcessTree {
    #[cfg(windows)]
    job: Option<win_job::Job>,
}

impl ProcessTree {
    fn adopt(child: &std::process::Child) -> Self {
        #[cfg(windows)]
        {
            let job = win_job::Job::new().and_then(|job| job.assign(child).then_some(job));
            if job.is_none() {
                bhfeprintln!(
                    "bhf: warning: could not put afl-fuzz in a job object; its target \
                     processes are stopped with taskkill instead"
                );
            }
            Self { job }
        }
        #[cfg(not(windows))]
        {
            let _ = child;
            Self {}
        }
    }

    /// Stop the tree. `reaped`: afl-fuzz already exited and was waited for,
    /// so only what it left behind (drrun, the target) is stopped.
    fn kill(&self, child: &mut std::process::Child, reaped: bool) {
        #[cfg(windows)]
        {
            match &self.job {
                Some(job) => job.terminate(),
                None if !reaped => {
                    let _ = std::process::Command::new("taskkill")
                        .args(["/PID", &child.id().to_string(), "/T", "/F"])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                }
                None => {}
            }
        }
        if !reaped {
            kill_process_group(child);
            let _ = child.wait();
        }
    }
}

#[cfg(windows)]
mod win_job {
    //! A job object that kills every process in it when bhf terminates it (or
    //! exits): `KILL_ON_JOB_CLOSE`. Nested in any job bhf itself runs in.
    use std::os::windows::io::AsRawHandle;
    type Handle = *mut core::ffi::c_void;
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: i32 = 9;
    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;

    #[repr(C)]
    #[derive(Default)]
    struct BasicLimit {
        per_process_user_time_limit: i64,
        per_job_user_time_limit: i64,
        limit_flags: u32,
        minimum_working_set_size: usize,
        maximum_working_set_size: usize,
        active_process_limit: u32,
        affinity: usize,
        priority_class: u32,
        scheduling_class: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    struct IoCounters {
        counts: [u64; 6],
    }

    #[repr(C)]
    #[derive(Default)]
    struct ExtendedLimit {
        basic: BasicLimit,
        io: IoCounters,
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory_used: usize,
        peak_job_memory_used: usize,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateJobObjectW(attributes: *mut core::ffi::c_void, name: *const u16) -> Handle;
        fn SetInformationJobObject(
            job: Handle,
            class: i32,
            info: *mut core::ffi::c_void,
            length: u32,
        ) -> i32;
        fn AssignProcessToJobObject(job: Handle, process: Handle) -> i32;
        fn TerminateJobObject(job: Handle, exit_code: u32) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
    }

    pub(super) struct Job(Handle);

    /// The handles of the jobs alive in this process, for
    /// [`terminate_all`]; a job leaves it before its handle is closed.
    static LIVE: std::sync::Mutex<Vec<usize>> = std::sync::Mutex::new(Vec::new());

    fn live() -> std::sync::MutexGuard<'static, Vec<usize>> {
        LIVE.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Terminate every live job (the console control handler).
    pub(super) fn terminate_all() {
        for &handle in live().iter() {
            // SAFETY: a handle in LIVE is open until its job leaves LIVE,
            // which needs this lock.
            unsafe {
                TerminateJobObject(handle as Handle, 1);
            }
        }
    }

    impl Job {
        pub(super) fn new() -> Option<Self> {
            // SAFETY: plain Win32 calls on a handle this function owns; the
            // limit struct outlives the call that reads it.
            unsafe {
                let handle = CreateJobObjectW(core::ptr::null_mut(), core::ptr::null());
                if handle.is_null() {
                    return None;
                }
                let job = Self(handle);
                let mut limit = ExtendedLimit::default();
                limit.basic.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                let set = SetInformationJobObject(
                    job.0,
                    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                    (&mut limit as *mut ExtendedLimit).cast(),
                    std::mem::size_of::<ExtendedLimit>() as u32,
                );
                if set == 0 {
                    return None;
                }
                live().push(job.0 as usize);
                Some(job)
            }
        }

        pub(super) fn assign(&self, child: &std::process::Child) -> bool {
            // SAFETY: `child` owns a live process handle for this call.
            unsafe { AssignProcessToJobObject(self.0, child.as_raw_handle() as Handle) != 0 }
        }

        pub(super) fn terminate(&self) {
            // SAFETY: the job handle is owned by `self`.
            unsafe {
                TerminateJobObject(self.0, 1);
            }
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            let mut live = live();
            live.retain(|&handle| handle != self.0 as usize);
            // SAFETY: closing the handle this value owns, out of LIVE under
            // its lock; with KILL_ON_JOB_CLOSE this also ends anything still
            // in the job.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

/// The last `lines` lines of afl-fuzz's log, without its terminal escapes.
fn log_tail(log: &Path, lines: usize) -> String {
    let bytes = read_bounded_file_head_tail(log, max_captured_stderr_bytes()).unwrap_or_default();
    let text = String::from_utf8_lossy(&bytes);
    let cleaned = strip_terminal_escapes(&text);
    let kept: Vec<&str> = cleaned
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    kept[kept.len().saturating_sub(lines)..].join("\n")
}

/// Drop ANSI escape sequences (`ESC [ ... letter`) and other control bytes.
pub(crate) fn strip_terminal_escapes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for next in chars.by_ref() {
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        if ch.is_control() && ch != '\n' && ch != '\t' {
            continue;
        }
        out.push(ch);
    }
    out
}

/// A hint for an afl-fuzz that stopped before its time budget.
fn failure_hint(log: &str) -> &'static str {
    if log.contains("Error opening pidfile") || log.contains("pipe") {
        "\nHint: the target never connected to afl-fuzz. Check that the DynamoRIO directory \
         matches the one WinAFL was built against, and run the target once under \
         `drrun -c winafl.dll -debug ...` (see docs/site/windows.md)."
    } else if log.contains("results in a timeout") || log.contains("All test cases time out") {
        "\nHint: the first runs under DynamoRIO timed out; raise --timeout."
    } else if log.contains("Intel PT") || log.contains("IPT") {
        "\nHint: Intel PT tracing is unavailable on this machine (it needs an Intel CPU with \
         PT and does not run inside most virtual machines); use the default \
         --winafl-instrumentation dynamorio."
    } else {
        ""
    }
}

/// The shortest session worth restarting WinAFL for, and the shortest time
/// left worth a new one.
const MIN_SESSION: Duration = Duration::from_secs(5);
/// At most this many WinAFL sessions per run (restarts after early stops).
const MAX_SESSIONS: usize = 8;

/// One afl-fuzz session: its output directory and log, and how it ended.
struct Session {
    out_dir: PathBuf,
    log_path: PathBuf,
    log: String,
    early_exit: Option<std::process::ExitStatus>,
    elapsed: Duration,
    crashes: Vec<PathBuf>,
    hangs: Vec<PathBuf>,
    crashing_seeds: Vec<PathBuf>,
}

impl Session {
    fn read(
        out_dir: PathBuf,
        log_path: PathBuf,
        early_exit: Option<std::process::ExitStatus>,
        elapsed: Duration,
    ) -> Self {
        let raw =
            read_bounded_file_head_tail(&log_path, max_captured_stderr_bytes()).unwrap_or_default();
        let log = strip_terminal_escapes(&String::from_utf8_lossy(&raw));
        // WinAFL names a dry-run file relative to its queue or as a path.
        let crashing_seeds = crashing_seeds_in_log(&log)
            .into_iter()
            .map(|path| {
                if path.is_file() {
                    path
                } else {
                    out_dir.join("queue").join(path)
                }
            })
            .filter(|path| path.is_file())
            .collect();
        Self {
            crashes: saved_inputs(&out_dir.join("crashes")),
            hangs: saved_inputs(&out_dir.join("hangs")),
            crashing_seeds,
            out_dir,
            log_path,
            log,
            early_exit,
            elapsed,
        }
    }
}

/// WinAFL's numbers over all sessions of a run: executions, crashes and hangs
/// add up; the map is the widest any session saw; paths and rate are the
/// last session's, which started from the queue of the one before.
fn combined_stats(sessions: &[Session]) -> WinaflStats {
    let all: Vec<WinaflStats> = sessions
        .iter()
        .map(|session| read_stats(&session.out_dir, session.elapsed.as_secs_f64()))
        .collect();
    let mut combined = all.last().cloned().unwrap_or_default();
    combined.afl_version = all.iter().find_map(|stats| stats.afl_version.clone());
    combined.executions = all.iter().map(|stats| stats.executions).sum();
    combined.executions_source = if all
        .iter()
        .any(|stats| stats.executions_source == "plot_data")
    {
        "plot_data"
    } else {
        combined.executions_source
    };
    combined.map_edges = all.iter().map(|stats| stats.map_edges).max().unwrap_or(0);
    combined.map_density_percent = all
        .iter()
        .map(|stats| stats.map_density_percent)
        .fold(0.0, f64::max);
    combined.unique_crashes = all.iter().map(|stats| stats.unique_crashes).sum();
    combined.unique_hangs = all.iter().map(|stats| stats.unique_hangs).sum();
    combined
}

/// Run WinAFL for `bhf fuzz --engine winafl` / `bhf auto --engine winafl`.
pub(super) fn run(prepared: PreparedFuzzRun) -> Result<FuzzRunSummary, String> {
    host_supported()?;
    let tools = resolve_tools_for(&prepared.winafl, &prepared.harness_path)?;
    run_with_tools(prepared, &tools)
}

/// The error for a harness without its WinAFL build beside it.
pub(crate) fn missing_build_error(harness: &Path) -> String {
    let dir = harness.parent().unwrap_or(Path::new("."));
    format!(
        "WinAFL build not found: no {} beside {}. `bhf auto --engine winafl` builds it; \
         otherwise run `bhf build --c-engine winafl ...` or `make winafl` in the harness \
         directory.",
        crate::auto::layout::harness_exe_name(FUZZ_BINARY_STEM),
        dir.display()
    )
}

/// The registry, process identity and process table a run's PageHeap uses,
/// and whether a console control event is ending bhf: this host's, or a
/// test's.
pub(crate) struct Host {
    pub(crate) registry: Arc<dyn Registry>,
    /// This process as a PageHeap key records it (needed only with
    /// `--winafl-page-heap`).
    pub(crate) owner: Result<page_heap::Owner, String>,
    pub(crate) liveness: fn(u32) -> page_heap::Liveness,
    pub(crate) stopping: fn() -> bool,
}

impl Host {
    pub(crate) fn system() -> Self {
        Self {
            registry: page_heap::system_registry(),
            owner: page_heap::current_owner(),
            liveness: page_heap::process_liveness,
            stopping: page_heap::console_stopping,
        }
    }
}

/// Stop every afl-fuzz process tree of this process at once (the console
/// control handler's step before it deletes the run copies the targets ran).
pub(crate) fn stop_all_process_trees() {
    #[cfg(windows)]
    win_job::terminate_all();
}

/// What a run says when it ends before it replayed what WinAFL saved (a
/// console control event): where those inputs are, and how they become
/// findings.
pub(crate) fn unreplayed_note(harness_id: &str, root: &Path, harness: &Path) -> String {
    format!(
        "the WinAFL run of {harness_id} stopped (Ctrl-C, Ctrl-Break or a closed console) \
         before it replayed what WinAFL saved: those inputs stay under {}, and the next `bhf \
         fuzz --engine winafl` or `bhf auto --engine winafl` run of {harness_id} in this work \
         dir replays them into findings (to run one by hand: {} <file>)",
        root.display(),
        harness.display()
    )
}

/// The notes of the WinAFL runs going in this process, which the console
/// control handler prints as a console control event ends it.
static STOP_NOTES: std::sync::Mutex<Vec<(u64, String)>> = std::sync::Mutex::new(Vec::new());

fn stop_notes() -> std::sync::MutexGuard<'static, Vec<(u64, String)>> {
    STOP_NOTES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A run's entry in [`STOP_NOTES`], for as long as it lives.
struct StopNote(u64);

impl StopNote {
    fn register(note: String) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        stop_notes().push((id, note));
        Self(id)
    }
}

impl Drop for StopNote {
    fn drop(&mut self) {
        stop_notes().retain(|(id, _)| *id != self.0);
    }
}

/// Print the note of every WinAFL run a console control event is ending (the
/// handler's last step).
pub(crate) fn print_stop_notes() {
    for (_, note) in stop_notes().iter() {
        bhfeprintln!("bhf: {note}");
    }
}

/// Written into a run's WinAFL output directory once its saved inputs were
/// replayed, so the next run of the harness clears it.
pub(crate) const REPLAYED_MARKER: &str = "replayed";
/// Where a run keeps the WinAFL output of earlier runs of the harness that
/// ended before they replayed what WinAFL saved, one numbered directory each,
/// oldest first.
pub(crate) const EARLIER_RUNS_DIR: &str = "earlier";
/// The most earlier runs kept; older ones are dropped.
const MAX_EARLIER_RUNS: usize = 8;

/// `out`, `out-1`, ...: a session's suffix.
fn session_suffix(index: usize) -> String {
    if index == 0 {
        String::new()
    } else {
        format!("-{index}")
    }
}

/// What the sessions in a run's WinAFL output directory `dir` saved: their
/// crashes, crashing seeds and hangs.
fn saved_in_run(dir: &Path) -> Vec<(PathBuf, SavedKind)> {
    let (mut crashes, mut seeds, mut hangs) = (Vec::new(), Vec::new(), Vec::new());
    for index in 0..MAX_SESSIONS {
        let suffix = session_suffix(index);
        let out = dir.join(format!("out{suffix}"));
        if !out.is_dir() {
            continue;
        }
        let log = dir.join(format!("afl-fuzz{suffix}.log"));
        let session = Session::read(out, log, None, Duration::ZERO);
        crashes.extend(
            session
                .crashes
                .into_iter()
                .map(|path| (path, SavedKind::Crash)),
        );
        seeds.extend(
            session
                .crashing_seeds
                .into_iter()
                .map(|path| (path, SavedKind::CrashingSeed)),
        );
        hangs.extend(
            session
                .hangs
                .into_iter()
                .map(|path| (path, SavedKind::Hang)),
        );
    }
    crashes.into_iter().chain(seeds).chain(hangs).collect()
}

/// The numbered directories in `dir`, by number.
fn numbered_dirs(dir: &Path) -> Vec<PathBuf> {
    let mut found: Vec<(usize, PathBuf)> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| entry.path().is_dir())
        .filter_map(|entry| Some((entry.file_name().to_str()?.parse().ok()?, entry.path())))
        .collect();
    found.sort();
    found.into_iter().map(|(_, path)| path).collect()
}

/// Make `root` empty for a new run of the harness. What an earlier run left
/// there is deleted once that run replayed it ([`REPLAYED_MARKER`]); the
/// output of one that ended first (Ctrl-C, a kill) moves to
/// `root/earlier/<n>` with the earlier runs it kept (at most
/// [`MAX_EARLIER_RUNS`]), so this run replays what they saved. Returns those
/// directories, oldest first.
fn reset_output_root(root: &Path) -> Result<Vec<PathBuf>, String> {
    let create = |dir: &Path| {
        fs::create_dir_all(dir)
            .map_err(|error| format!("create WinAFL dir '{}': {error}", dir.display()))
    };
    if !root.is_dir() || root.join(REPLAYED_MARKER).exists() {
        let _ = fs::remove_dir_all(root);
        create(root)?;
        return Ok(Vec::new());
    }
    let name = root
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let aside = root.with_file_name(format!("{name}.unreplayed"));
    let _ = fs::remove_dir_all(&aside);
    let moved = |from: &Path, to: &Path| {
        fs::rename(from, to).map_err(|error| {
            format!(
                "keep the unreplayed WinAFL output '{}' as '{}': {error}",
                from.display(),
                to.display()
            )
        })
    };
    moved(root, &aside)?;
    let mut runs = numbered_dirs(&aside.join(EARLIER_RUNS_DIR));
    if !saved_in_run(&aside).is_empty() {
        runs.push(aside.clone());
    }
    let dropped = runs.len().saturating_sub(MAX_EARLIER_RUNS);
    if dropped > 0 {
        bhfeprintln!(
            "bhf: warning: dropping the WinAFL output of the {dropped} oldest runs of this \
             harness that ended before they replayed it (bhf keeps {MAX_EARLIER_RUNS})"
        );
    }
    create(root)?;
    let mut kept = Vec::new();
    for (index, run) in runs.into_iter().enumerate() {
        if index < dropped {
            let _ = fs::remove_dir_all(&run);
            continue;
        }
        let to = root.join(EARLIER_RUNS_DIR).join(kept.len().to_string());
        create(&root.join(EARLIER_RUNS_DIR))?;
        moved(&run, &to)?;
        kept.push(to);
    }
    let _ = fs::remove_dir_all(&aside);
    Ok(kept)
}

/// [`run`] with the tools already located (the host check is the caller's).
pub(super) fn run_with_tools(
    prepared: PreparedFuzzRun,
    tools: &WinaflTools,
) -> Result<FuzzRunSummary, String> {
    run_on_host(prepared, tools, &Host::system())
}

/// [`run_with_tools`] with PageHeap set through `host`.
pub(crate) fn run_on_host(
    prepared: PreparedFuzzRun,
    tools: &WinaflTools,
    host: &Host,
) -> Result<FuzzRunSummary, String> {
    use std::process::Command;
    reset_target_entry(&prepared.extra_env);
    let build = fuzz_binary_beside(&prepared.harness_path)
        .ok_or_else(|| missing_build_error(&prepared.harness_path))?;
    let fuzz_iterations = prepared
        .winafl
        .fuzz_iterations
        .unwrap_or(DEFAULT_FUZZ_ITERATIONS)
        .max(1);
    let timeout_ms = prepared
        .winafl_timeout
        .map(|timeout| timeout.as_millis().clamp(1, u128::from(u32::MAX)) as u64)
        .unwrap_or(DEFAULT_TIMEOUT_MS);
    let memory_model = MemoryModel::of(&build);
    let memory_limit = memory_limit_mb(prepared.rss_limit_mb, memory_model);
    if prepared.rss_limit_mb > 0 && memory_limit.is_none() {
        bhfeprintln!(
            "bhf: note: --rss-limit-mb {} plus {DYNAMORIO_HEADROOM_MB} MiB for DynamoRIO does \
             not fit below the {} MiB a 32-bit {} can address, so WinAFL runs it with -m none \
             (its address space is the cap)",
            prepared.rss_limit_mb,
            memory_model.x86_address_space_mb().unwrap_or_default(),
            module_name(&build)
        );
    }

    let root = prepared
        .work_dir
        .join("winafl_out")
        .join(&prepared.harness_id);
    // afl-fuzz creates each output directory itself and refuses one that holds
    // an earlier session, so only their parent is made here. What an earlier
    // run of this harness left is cleared, or kept and replayed below when that
    // run ended before it replayed it.
    page_heap::install_console_handler();
    let earlier_runs = reset_output_root(&root)?;
    let earlier: Vec<(PathBuf, SavedKind)> = earlier_runs
        .iter()
        .flat_map(|dir| saved_in_run(dir))
        .collect();
    if !earlier.is_empty() {
        bhfeprintln!(
            "bhf: replaying {} inputs WinAFL saved in earlier runs of {} that ended before \
             they replayed them ({} runs, kept under {}), with this run's",
            earlier.len(),
            prepared.harness_id,
            earlier_runs.len(),
            root.join(EARLIER_RUNS_DIR).display()
        );
    }
    let note = unreplayed_note(&prepared.harness_id, &root, &prepared.harness_path);
    let _stop_note = StopNote::register(note.clone());
    let seeds_dir = root.join("seeds");
    let seeds = write_seed_dir(&prepared.seeds, &seeds_dir)?;
    let dictionary = write_merged_dictionary(
        &prepared.work_dir,
        &prepared.harness_id,
        &root.join("dictionary.txt"),
    )?;
    let time_budget = prepared.time.unwrap_or_else(|| {
        let ms = (prepared.iterations as u64).saturating_mul(100).min(30_000);
        Duration::from_millis(ms.max(1_000))
    });
    // PageHeap is set for a copy of the build under a name only this run uses,
    // held for the whole run so every restart of the harness gets it.
    let page_heap_run = if prepared.winafl.page_heap {
        let owner = host.owner.clone()?;
        let run = PageHeapRun::start(Arc::clone(&host.registry), owner, &host.liveness, &build)?;
        bhfeprintln!(
            "bhf: full PageHeap: WinAFL fuzzes {} (a copy of {}) with PageHeap set under {} \
             until the run ends",
            run.image.display(),
            build.display(),
            run.key
        );
        if !run.in_effect {
            bhfeprintln!(
                "bhf: warning: PageHeap did not read back as on under {}; the findings record \
                 page_heap false",
                run.key
            );
        }
        Some(run)
    } else {
        // What a killed page-heap run left is reclaimed by every run.
        page_heap::reclaim(
            host.registry.as_ref(),
            &host.liveness,
            build.parent().unwrap_or(Path::new(".")),
        );
        None
    };
    let fuzz_binary = page_heap_run
        .as_ref()
        .map_or_else(|| build.clone(), |run| run.image.clone());
    let page_heap = match &page_heap_run {
        Some(run) => run.in_effect,
        None => {
            let configured =
                page_heap::configured_for(host.registry.as_ref(), &module_name(&build));
            if configured {
                bhfeprintln!(
                    "bhf: note: PageHeap is set for {} outside bhf (under {}), so WinAFL runs it \
                     under PageHeap and the findings record that",
                    module_name(&build),
                    page_heap::image_key(&module_name(&build))
                );
            }
            configured
        }
    };
    // DynamoRIO names a module by its export directory before its file name,
    // and the build exports its persistent entry: that name (the one it was
    // linked as) is a coverage module too, which matters for the copy.
    let mut coverage_modules: Vec<String> = export_name_of(&build)
        .filter(|name| !name.eq_ignore_ascii_case(&module_name(&fuzz_binary)))
        .into_iter()
        .collect();
    coverage_modules.extend(prepared.winafl.coverage_modules.iter().cloned());
    bhfeprintln!(
        "bhf: WinAFL ({}) fuzzing {} for {}s (replaying saved inputs through {})",
        tools.instrumentation.as_str(),
        fuzz_binary.display(),
        time_budget.as_secs(),
        prepared.harness_path.display()
    );
    let start = Instant::now();
    let deadline = start + time_budget;
    let scratch = ensure_harness_scratch(&prepared.work_dir)?;
    // WinAFL stops for good on some failures of its own (it could not stop a
    // hung target, a pipe broke). With budget left, a new session continues
    // on the queue the stopped one reached.
    let mut sessions: Vec<Session> = Vec::new();
    let mut session_seeds = seeds_dir.clone();
    loop {
        let index = sessions.len();
        let suffix = if index == 0 {
            String::new()
        } else {
            format!("-{index}")
        };
        let out_dir = root.join(format!("out{suffix}"));
        let log_path = root.join(format!("afl-fuzz{suffix}.log"));
        let log = fs::File::create(&log_path)
            .map_err(|error| format!("create WinAFL log '{}': {error}", log_path.display()))?;
        let args = afl_fuzz_args(&WinaflCommand {
            tools,
            seeds_dir: &session_seeds,
            out_dir: &out_dir,
            timeout_ms,
            dictionary: dictionary.as_ref().map(|(path, _)| path.as_path()),
            fuzz_binary: &fuzz_binary,
            coverage_modules: &coverage_modules,
            fuzz_iterations,
            memory_limit_mb: memory_limit,
        });
        let mut command = Command::new(&tools.afl_fuzz);
        command
            .args(&args)
            .current_dir(&scratch)
            .stdin(Stdio::null())
            // A file, never an undrained pipe: afl-fuzz keeps printing status.
            .stdout(Stdio::from(
                log.try_clone()
                    .map_err(|error| format!("dup WinAFL log handle: {error}"))?,
            ))
            .stderr(Stdio::from(log));
        for (key, value) in &prepared.extra_env {
            command.env(key, value);
        }
        command
            // A crashing seed is skipped instead of aborting the session; bhf
            // replays the ones the log names.
            .env("AFL_SKIP_CRASHES", "1")
            // Concurrent campaigns (auto --jobs) must not fight over one core.
            .env("AFL_NO_AFFINITY", "1");
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command.process_group(0);
        }
        let session_start = Instant::now();
        let mut child = command
            .spawn()
            .map_err(|error| format!("spawn afl-fuzz '{}': {error}", tools.afl_fuzz.display()))?;
        let tree = ProcessTree::adopt(&child);
        let early_exit = loop {
            match child
                .try_wait()
                .map_err(|error| format!("wait for afl-fuzz: {error}"))?
            {
                Some(status) => break Some(status),
                None if Instant::now() >= deadline || (host.stopping)() => {
                    tree.kill(&mut child, false);
                    break None;
                }
                None => std::thread::sleep(Duration::from_millis(200)),
            }
        };
        if early_exit.is_some() {
            // afl-fuzz stopped on its own; what it started (drrun, the target)
            // goes too.
            tree.kill(&mut child, true);
        }
        if (host.stopping)() {
            // The process is ending: no restart and no replay (a replay
            // started now would outlive it). The PageHeap run cleans up as it
            // drops.
            return Err(note);
        }
        let session = Session::read(out_dir, log_path, early_exit, session_start.elapsed());
        if session.early_exit.is_none() {
            sessions.push(session);
            break;
        }
        // Every seed timed out (or crashed): a new session would fail the same
        // way, so the crashing ones are replayed and the run ends.
        let every_seed_failed = session.log.contains("All test cases time out");
        if every_seed_failed {
            bhfeprintln!(
                "bhf: WinAFL could not start for {}: every seed timed out or crashed; \
                 replaying the crashing ones",
                prepared.harness_id
            );
        }
        let left = deadline.saturating_duration_since(Instant::now());
        let queue = saved_inputs(&session.out_dir.join("queue"));
        let restart = !every_seed_failed
            && left >= MIN_SESSION
            && session.elapsed >= MIN_SESSION
            && !queue.is_empty()
            && index + 1 < MAX_SESSIONS;
        let reason = log_tail(&session.log_path, 1);
        sessions.push(session);
        if !restart {
            break;
        }
        bhfeprintln!(
            "bhf: afl-fuzz stopped early for {} ({reason}); restarting it on its queue for the \
             remaining {}s",
            prepared.harness_id,
            left.as_secs()
        );
        session_seeds = root.join(format!("seeds-{}", index + 1));
        fs::create_dir_all(&session_seeds).map_err(|error| {
            format!(
                "create WinAFL seeds dir '{}': {error}",
                session_seeds.display()
            )
        })?;
        let crashed = &sessions[index].crashing_seeds;
        for (entry, path) in queue
            .iter()
            .filter(|path| !crashed.contains(path))
            .enumerate()
        {
            fs::copy(path, session_seeds.join(format!("seed-{entry:04}"))).map_err(|error| {
                format!(
                    "carry WinAFL queue entry '{}' over: {error}",
                    path.display()
                )
            })?;
        }
    }
    let elapsed = start.elapsed();
    // The fuzzing is over: the PageHeap key and the run's copy go now.
    let page_heap_key = page_heap_run.as_ref().map(|run| run.key.clone());
    let page_heap_image = page_heap_run.as_ref().map(|run| run.image.clone());
    drop(page_heap_run);
    let crashes: Vec<PathBuf> = sessions
        .iter()
        .flat_map(|session| session.crashes.iter().cloned())
        .collect();
    let hangs: Vec<PathBuf> = sessions
        .iter()
        .flat_map(|session| session.hangs.iter().cloned())
        .collect();
    let crashing_seeds: Vec<PathBuf> = sessions
        .iter()
        .flat_map(|session| session.crashing_seeds.iter().cloned())
        .collect();
    let last = sessions.last().expect("at least one WinAFL session ran");
    let out_dir = last.out_dir.clone();
    let nothing_saved =
        crashes.is_empty() && hangs.is_empty() && crashing_seeds.is_empty() && earlier.is_empty();
    // The last session stopped before the budget: a warning when it saved
    // something (which is replayed below), the run's error when nothing was.
    let stopped_early = last.early_exit.map(|status| {
        (
            format!(
                "afl-fuzz exited before its time budget ({status}). Output tail:\n{}{}",
                log_tail(&last.log_path, 15),
                failure_hint(&last.log)
            ),
            format!("{status}: {}", log_tail(&last.log_path, 1)),
        )
    });

    let sandbox_metadata = prepared.runner.sandbox_metadata();
    let mut emitter = with_harness_format(
        FindingEmitter::with_metadata_and_sandbox(
            prepared.work_dir.clone(),
            prepared.harness_id.clone(),
            "unknown".to_owned(),
            prepared.harness_path.display().to_string(),
            serde_json::to_value(&sandbox_metadata)
                .map_err(|error| format!("serialize sandbox metadata: {error}"))?,
        )
        .with_mode(prepared.mode)
        .with_line_maps_dir(&prepared.work_dir.join("src_instrumented")),
        &prepared.harness_path,
        &prepared.work_dir,
        &prepared.harness_id,
    );
    if let Some(identity) = build_binary_record(&prepared.harness_path) {
        emitter = emitter.with_build_binary(identity);
    }
    let mut dedup = SanitizerClusterDedup::new(Vec::new()).with_scope(run_crash_scope(
        &prepared.harness_path,
        &prepared.work_dir,
        &prepared.harness_id,
    ));
    let saved: Vec<(PathBuf, SavedKind)> = crashes
        .iter()
        .map(|path| (path.clone(), SavedKind::Crash))
        .chain(
            crashing_seeds
                .iter()
                .map(|path| (path.clone(), SavedKind::CrashingSeed)),
        )
        .chain(hangs.iter().map(|path| (path.clone(), SavedKind::Hang)))
        .chain(earlier.iter().cloned())
        .collect();
    let replay_timeout = prepared
        .per_input_timeout
        .max(Duration::from_millis(timeout_ms));
    let ingested = ingest(
        &prepared,
        &emitter,
        &mut dedup,
        tools,
        &build,
        page_heap,
        &saved,
        replay_timeout,
        IngestLimits::for_budget(time_budget),
    );
    // Replayed (within its bounds): the next run of the harness clears it.
    if let Err(error) = fs::write(root.join(REPLAYED_MARKER), b"") {
        bhfeprintln!(
            "bhf: warning: could not mark {} replayed ({error}); the next run replays its \
             inputs again",
            root.display()
        );
    }
    if ingested.skipped > 0 {
        bhfeprintln!(
            "bhf: warning: {} of the {} inputs WinAFL saved were not replayed (the replay \
             deadline passed, or {MAX_QUIET_HANGS} hangs timed out again with no report in \
             between); they stay under {}",
            ingested.skipped,
            saved.len(),
            root.display()
        );
    }

    // Hand WinAFL's queue back to bhf's corpus, so later passes and `bhf
    // corpus` see what it reached, however the run ended. A queue file that
    // crashed is not in it.
    let queue: Vec<Vec<u8>> = saved_inputs(&out_dir.join("queue"))
        .iter()
        .filter(|path| !crashing_seeds.contains(path))
        .filter_map(|path| read_seed_file_prefix(path, MAX_SEED_BYTES).ok())
        .map(|(bytes, _)| bytes)
        .collect();
    emitter.record_corpus_format();
    let limits = corpus_limits(prepared.max_len);
    let queue_persisted = CorpusManager::new(prepared.work_dir.clone())
        .with_retention_limits(limits.entries, limits.bytes)
        .persist_coverage_corpus(&prepared.harness_id, queue.iter())
        .unwrap_or_else(|error| {
            bhfeprintln!("bhf fuzz: warning: could not persist the WinAFL queue: {error}");
            0
        });

    if let Some((error, _)) = &stopped_early {
        if nothing_saved {
            return Err(error.clone());
        }
        bhfeprintln!(
            "bhf: warning: {error}\nbhf: the {} inputs WinAFL saved before it stopped were \
             replayed",
            saved.len()
        );
    }

    let stats = combined_stats(&sessions);
    let elapsed_secs = elapsed.as_secs_f64();
    let executions = usize::try_from(stats.executions).unwrap_or(usize::MAX);
    let summary = FuzzRunSummary {
        schema_version: 1,
        harness_id: prepared.harness_id.clone(),
        engine: "winafl".to_owned(),
        mode: prepared.mode,
        harness_path: prepared.harness_path.clone(),
        sandbox: sandbox_metadata,
        iterations_requested: prepared.iterations,
        executions,
        target_entry_observed: target_entry_from_env(&prepared.extra_env),
        corpus_new: queue.len(),
        corpus_duplicates: 0,
        corpus_persisted: queue_persisted,
        execution: ExecutionRunSummary {
            harness_protocol: "winafl_persistent_file".to_owned(),
            forkserver: false,
            persistent: true,
            persistent_iterations: Some(fuzz_iterations),
        },
        cmplog: load_cmplog_for_run(prepared.cmplog_log.as_deref(), &prepared.seeds).1,
        sanitizers: sanitizer_summary(&prepared.sanitizers, &prepared.sanitizer_env, false),
        coverage: CoverageRunSummary {
            edges: stats.map_edges,
            source: format!("winafl-{}", tools.instrumentation.as_str()),
        },
        findings: ingested.finding_ids.clone(),
        duplicates_of_existing: Vec::new(),
        duplicate_crashes_of_existing: 0,
        elapsed_secs,
        executions_per_sec: if stats.execs_per_sec > 0.0 {
            stats.execs_per_sec
        } else {
            executions_per_sec(executions, elapsed_secs)
        },
        afl: None,
        winafl: Some(WinaflRunProvenance {
            instrumentation: tools.instrumentation.as_str(),
            afl_fuzz: tools.afl_fuzz.clone(),
            winafl_dll: tools.winafl_dll.clone(),
            dynamorio: tools.dynamorio_bin.clone(),
            fuzz_binary: build.clone(),
            replay_binary: prepared.harness_path.clone(),
            fuzz_binary_sanitizers: Vec::new(),
            sanitizer_note: SANITIZER_NOTE,
            target_method: TARGET_METHOD,
            coverage_modules: std::iter::once(module_name(&fuzz_binary))
                .chain(coverage_modules.iter().cloned())
                .collect(),
            fuzz_iterations,
            timeout_ms,
            memory_limit_mb: memory_limit,
            page_heap,
            page_heap_key,
            page_heap_image,
            seeds,
            dictionary_tokens: dictionary.as_ref().map_or(0, |(_, count)| *count),
            stats,
            crashes_saved: crashes.len(),
            hangs_saved: hangs.len(),
            crashing_seeds: crashing_seeds.len(),
            earlier_inputs: earlier.len(),
            replay_reported: ingested.reported,
            replay_clean: ingested.clean,
            replay_timed_out: ingested.timed_out,
            replay_duplicates: ingested.duplicates,
            replay_skipped: ingested.skipped,
            replay_errors: ingested.errors,
            queue_persisted,
            sessions: sessions.len(),
            stopped_early: stopped_early.map(|(_, short)| short),
        }),
        extension: None,
        duplicate_sanitizer_hits: dedup.duplicate_hits(),
        unreproduced_sanitizer_hits: dedup.unreproduced_hits(),
        fresh_reruns: None,
        hangs: None,
    };
    write_run_summary(&prepared.work_dir, &summary)?;
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn tmpdir(tag: &str) -> crate::test_support::TestDir {
        crate::test_support::TestDir::new(&format!("winafl-{tag}"))
    }

    fn touch(path: &Path) -> PathBuf {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"").unwrap();
        path.to_path_buf()
    }

    fn env_of(pairs: &[(&str, &Path)]) -> impl Fn(&str) -> Option<OsString> {
        let map: HashMap<String, OsString> = pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.as_os_str().to_owned()))
            .collect();
        move |key: &str| map.get(key).cloned()
    }

    /// A WinAFL build dir and a DynamoRIO root, as installed.
    fn install(root: &Path) -> (PathBuf, PathBuf) {
        let winafl = root.join("winafl");
        touch(&winafl.join("afl-fuzz.exe"));
        touch(&winafl.join("winafl.dll"));
        let dynamorio = root.join("DynamoRIO-Windows-11.91.20763");
        touch(&dynamorio.join("bin64").join("drrun.exe"));
        touch(&dynamorio.join("bin32").join("drrun.exe"));
        (winafl, dynamorio)
    }

    fn pe(machine: u16) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x80];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        bytes[0x40..0x44].copy_from_slice(b"PE\0\0");
        bytes[0x44..0x46].copy_from_slice(&machine.to_le_bytes());
        bytes
    }

    #[test]
    fn pe_arch_reads_the_coff_machine() {
        assert_eq!(pe_arch(&pe(0x8664)), Ok(Some(PeArch::X64)));
        assert_eq!(pe_arch(&pe(0x014c)), Ok(Some(PeArch::X86)));
        let arm = pe_arch(&pe(0xaa64)).unwrap_err();
        assert!(
            arm.contains("ARM64") && arm.contains("--vs-arch x64"),
            "{arm}"
        );
        assert!(pe_arch(&pe(0x01c4)).unwrap_err().contains("0x01c4"));
        assert_eq!(pe_arch(b"#!/bin/sh\nexit 0\n"), Ok(None));
        let mut truncated = pe(0x8664);
        truncated[0x3c..0x40].copy_from_slice(&0x1000u32.to_le_bytes());
        assert_eq!(pe_arch(&truncated), Ok(None));
    }

    #[test]
    fn tools_come_from_the_flags_with_dynamorio_bin64_under_its_root() {
        let root = tmpdir("flags");
        let (winafl, dynamorio) = install(&root);
        let settings = WinaflSettings {
            winafl_path: Some(winafl.clone()),
            dynamorio_path: Some(dynamorio.clone()),
            ..Default::default()
        };
        let tools = resolve_tools(&settings, PeArch::X64, &env_of(&[])).unwrap();
        assert_eq!(tools.afl_fuzz, winafl.join("afl-fuzz.exe"));
        assert_eq!(tools.winafl_dll, Some(winafl.join("winafl.dll")));
        assert_eq!(tools.dynamorio_bin, Some(dynamorio.join("bin64")));
        assert_eq!(tools.instrumentation, WinaflInstrumentation::Dynamorio);
        // An x86 harness runs under bin32; DynamoRIO's bin dir itself works too.
        let x86 = resolve_tools(&settings, PeArch::X86, &env_of(&[])).unwrap();
        assert_eq!(x86.dynamorio_bin, Some(dynamorio.join("bin32")));
        let direct = WinaflSettings {
            dynamorio_path: Some(dynamorio.join("bin64")),
            ..settings
        };
        let tools = resolve_tools(&direct, PeArch::X64, &env_of(&[])).unwrap();
        assert_eq!(tools.dynamorio_bin, Some(dynamorio.join("bin64")));
    }

    #[test]
    fn tools_come_from_a_winafl_checkout_and_the_environment() {
        let root = tmpdir("env");
        let checkout = root.join("winafl-src");
        let release = checkout.join("build64").join("bin").join("Release");
        touch(&release.join("afl-fuzz.exe"));
        touch(&release.join("winafl.dll"));
        let (_, dynamorio) = install(&root);
        let other = root.join("other-dr");
        touch(&other.join("bin64").join("drrun.exe"));
        let env = env_of(&[
            (ENV_WINAFL_PATH, &checkout),
            (ENV_DYNAMORIO_PATH, &dynamorio),
            (ENV_DYNAMORIO_HOME, &other),
        ]);
        let tools = resolve_tools(&WinaflSettings::default(), PeArch::X64, &env).unwrap();
        assert_eq!(tools.afl_fuzz, release.join("afl-fuzz.exe"));
        // BHF_DYNAMORIO_PATH wins over DynamoRIO's own DYNAMORIO_HOME ...
        assert_eq!(tools.dynamorio_bin, Some(dynamorio.join("bin64")));
        // ... which is used when it is the only one.
        let env = env_of(&[(ENV_WINAFL_PATH, &checkout), (ENV_DYNAMORIO_HOME, &other)]);
        let tools = resolve_tools(&WinaflSettings::default(), PeArch::X64, &env).unwrap();
        assert_eq!(tools.dynamorio_bin, Some(other.join("bin64")));
        // A flag beats the environment.
        let flagged = WinaflSettings {
            dynamorio_path: Some(other.clone()),
            ..Default::default()
        };
        let env = env_of(&[
            (ENV_WINAFL_PATH, &checkout),
            (ENV_DYNAMORIO_PATH, &dynamorio),
        ]);
        let tools = resolve_tools(&flagged, PeArch::X64, &env).unwrap();
        assert_eq!(tools.dynamorio_bin, Some(other.join("bin64")));
    }

    #[test]
    fn tools_come_from_path_last() {
        let root = tmpdir("path");
        let (winafl, dynamorio) = install(&root);
        let joined = std::env::join_paths([winafl.clone(), dynamorio.join("bin64")]).unwrap();
        let path = PathBuf::from(joined);
        let tools = resolve_tools(
            &WinaflSettings::default(),
            PeArch::X64,
            &env_of(&[("PATH", &path)]),
        )
        .unwrap();
        assert_eq!(tools.afl_fuzz, winafl.join("afl-fuzz.exe"));
        assert_eq!(tools.dynamorio_bin, Some(dynamorio.join("bin64")));
    }

    #[test]
    fn a_missing_tool_is_named_with_how_to_install_it() {
        let root = tmpdir("missing");
        let none = WinaflSettings::default();
        let error = resolve_tools(&none, PeArch::X64, &env_of(&[])).unwrap_err();
        assert!(error.starts_with("WinAFL not found"), "{error}");
        assert!(
            error.contains("--winafl-path") && error.contains(ENV_WINAFL_PATH),
            "{error}"
        );
        assert!(
            error.contains("github.com/googleprojectzero/winafl"),
            "{error}"
        );

        let empty = root.join("empty");
        fs::create_dir_all(&empty).unwrap();
        let named = WinaflSettings {
            winafl_path: Some(empty.clone()),
            ..Default::default()
        };
        let error = resolve_tools(&named, PeArch::X64, &env_of(&[])).unwrap_err();
        assert!(error.contains(&empty.display().to_string()), "{error}");
        assert!(error.contains("afl-fuzz.exe"), "{error}");

        let no_client = root.join("no-client");
        touch(&no_client.join("afl-fuzz.exe"));
        let error = resolve_tools(
            &WinaflSettings {
                winafl_path: Some(no_client),
                ..Default::default()
            },
            PeArch::X64,
            &env_of(&[]),
        )
        .unwrap_err();
        assert!(
            error.contains("no winafl.dll") && error.contains("-DDynamoRIO_DIR"),
            "{error}"
        );

        let (winafl, _) = install(&root);
        let only_winafl = WinaflSettings {
            winafl_path: Some(winafl.clone()),
            ..Default::default()
        };
        let error = resolve_tools(&only_winafl, PeArch::X64, &env_of(&[])).unwrap_err();
        assert!(error.starts_with("DynamoRIO not found"), "{error}");
        assert!(
            error.contains("--dynamorio-path") && error.contains(ENV_DYNAMORIO_HOME),
            "{error}"
        );
        assert!(
            error.contains("github.com/DynamoRIO/dynamorio/releases"),
            "{error}"
        );
        let wrong_dr = WinaflSettings {
            dynamorio_path: Some(empty.clone()),
            ..only_winafl.clone()
        };
        let error = resolve_tools(&wrong_dr, PeArch::X64, &env_of(&[])).unwrap_err();
        assert!(error.contains("bin64\\drrun.exe"), "{error}");
        assert!(error.contains(&empty.display().to_string()), "{error}");
        assert!(error.contains("(--dynamorio-path)"), "{error}");

        // afl-fuzz cannot quote a DynamoRIO install path with a space.
        let spaced = root.join("Program Files").join("DynamoRIO");
        touch(&spaced.join("bin64").join("drrun.exe"));
        let error = resolve_tools(
            &WinaflSettings {
                dynamorio_path: Some(spaced),
                ..only_winafl
            },
            PeArch::X64,
            &env_of(&[]),
        )
        .unwrap_err();
        assert!(error.contains("has a space in it"), "{error}");
    }

    #[test]
    fn intel_pt_needs_a_pt_build_of_winafl_and_no_dynamorio() {
        let root = tmpdir("pt");
        let (winafl, _) = install(&root);
        let settings = WinaflSettings {
            winafl_path: Some(winafl.clone()),
            instrumentation: WinaflInstrumentation::IntelPt,
            ..Default::default()
        };
        let error = resolve_tools(&settings, PeArch::X64, &env_of(&[])).unwrap_err();
        assert!(error.contains("-DINTELPT=1"), "{error}");
        touch(&winafl.join("winaflpt-debug.exe"));
        let tools = resolve_tools(&settings, PeArch::X64, &env_of(&[])).unwrap();
        assert_eq!(tools.instrumentation, WinaflInstrumentation::IntelPt);
        assert_eq!(tools.dynamorio_bin, None);
        assert_eq!(tools.winafl_dll, None);
    }

    fn strings(args: &[OsString]) -> Vec<String> {
        args.iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn afl_fuzz_args_follow_winafl_dynamorio_syntax() {
        let tools = WinaflTools {
            afl_fuzz: PathBuf::from("W/afl-fuzz.exe"),
            winafl_dll: Some(PathBuf::from("W/winafl.dll")),
            dynamorio_bin: Some(PathBuf::from("DR/bin64")),
            instrumentation: WinaflInstrumentation::Dynamorio,
        };
        let modules = vec!["target.dll".to_owned(), "MAIN_WINAFL.EXE".to_owned()];
        let args = afl_fuzz_args(&WinaflCommand {
            tools: &tools,
            seeds_dir: Path::new("S"),
            out_dir: Path::new("O"),
            timeout_ms: 2000,
            dictionary: Some(Path::new("D/dictionary.txt")),
            fuzz_binary: Path::new("H/main_winafl.exe"),
            coverage_modules: &modules,
            fuzz_iterations: 5000,
            memory_limit_mb: memory_limit_mb(2048, MemoryModel::X64),
        });
        assert_eq!(
            strings(&args),
            [
                "-i",
                "S",
                "-o",
                "O",
                "-D",
                "DR/bin64",
                "-w",
                "W/winafl.dll",
                "-t",
                "2000+",
                "-I",
                "30000",
                "-m",
                "3072",
                "-d",
                "-x",
                "D/dictionary.txt",
                "--",
                "-coverage_module",
                "main_winafl.exe",
                "-coverage_module",
                "target.dll",
                "-target_module",
                "main_winafl.exe",
                "-target_method",
                "bhf_winafl_fuzz",
                "-nargs",
                "1",
                "-fuzz_iterations",
                "5000",
                "-covtype",
                "edge",
                "--",
                "H/main_winafl.exe",
                "@@",
            ]
        );
    }

    #[test]
    fn afl_fuzz_args_for_intel_pt_use_p_and_no_dynamorio() {
        let tools = WinaflTools {
            afl_fuzz: PathBuf::from("W/afl-fuzz.exe"),
            winafl_dll: None,
            dynamorio_bin: None,
            instrumentation: WinaflInstrumentation::IntelPt,
        };
        let args = strings(&afl_fuzz_args(&WinaflCommand {
            tools: &tools,
            seeds_dir: Path::new("S"),
            out_dir: Path::new("O"),
            timeout_ms: 0,
            dictionary: None,
            fuzz_binary: Path::new("main_winafl.exe"),
            coverage_modules: &[],
            fuzz_iterations: 0,
            memory_limit_mb: memory_limit_mb(0, MemoryModel::X64),
        }));
        assert_eq!(
            &args[..12],
            ["-i", "S", "-o", "O", "-P", "-t", "1+", "-I", "30000", "-m", "none", "-d"]
        );
        for absent in ["-D", "-w", "-x", "-covtype"] {
            assert!(!args.iter().any(|arg| arg == absent), "{absent}: {args:?}");
        }
        let iterations = args
            .iter()
            .position(|arg| arg == "-fuzz_iterations")
            .unwrap();
        assert_eq!(args[iterations + 1], "1");
        assert_eq!(args.last().map(String::as_str), Some("@@"));
        // A longer --timeout raises the start-up allowance with it.
        let slow = strings(&afl_fuzz_args(&WinaflCommand {
            tools: &tools,
            seeds_dir: Path::new("S"),
            out_dir: Path::new("O"),
            timeout_ms: 5000,
            dictionary: None,
            fuzz_binary: Path::new("main_winafl.exe"),
            coverage_modules: &[],
            fuzz_iterations: 10,
            memory_limit_mb: None,
        }));
        let init = slow.iter().position(|arg| arg == "-I").unwrap();
        assert_eq!(slow[init + 1], "50000");
    }

    #[test]
    fn dictionary_lines_use_the_afl2_escapes() {
        assert_eq!(dictionary_line(b"GIF89a"), "\"GIF89a\"");
        assert_eq!(dictionary_line(b"a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(
            dictionary_line(&[0x00, 0x7f, 0xff, b' ']),
            "\"\\x00\\x7f\\xff \""
        );
    }

    #[test]
    fn the_dictionaries_merge_into_one_file_each_token_once() {
        let work = tmpdir("dict");
        let harness = crate::auto::layout::harness_dir(&work, "H-D");
        fs::create_dir_all(&harness).unwrap();
        let long = "x".repeat(MAX_DICTIONARY_TOKEN + 1);
        fs::write(
            harness.join("dictionary.txt"),
            format!("magic=\"BHF\"\nbin=\"\\x00\\xff\"\nlong=\"{long}\"\n"),
        )
        .unwrap();
        fs::write(
            harness.join(LEARNED_DICTIONARY_FILE),
            "\"BHF\"\nlearned=\"KEY\"\n",
        )
        .unwrap();
        let dest = work.join("dictionary.txt");
        let (path, count) = write_merged_dictionary(&work, "H-D", &dest)
            .unwrap()
            .unwrap();
        assert_eq!(path, dest);
        assert_eq!(count, 3);
        let lines: Vec<String> = fs::read_to_string(&dest)
            .unwrap()
            .lines()
            .filter(|line| !line.starts_with('#'))
            .map(str::to_owned)
            .collect();
        assert_eq!(lines, ["\"BHF\"", "\"\\x00\\xff\"", "\"KEY\""]);
        // Tokens round-trip through bhf's own AFL dictionary reader.
        assert_eq!(
            load_afl_dictionary_tokens(&dest).unwrap(),
            [b"BHF".to_vec(), vec![0x00, 0xff], b"KEY".to_vec()]
        );
        let bare = tmpdir("dict-none");
        assert_eq!(
            write_merged_dictionary(&bare, "H-NONE", &bare.join("d.txt")).unwrap(),
            None
        );
    }

    #[test]
    fn seeds_are_written_byte_for_byte() {
        let root = tmpdir("seeds");
        let dir = root.join("seeds");
        let binary: Vec<u8> = (0..=255u8).rev().collect();
        let big = vec![7u8; MAX_SEED_BYTES + 10];
        let written = write_seed_dir(&[binary.clone(), Vec::new(), big], &dir).unwrap();
        assert_eq!(written, 2);
        assert_eq!(fs::read(dir.join("seed-0000")).unwrap(), binary);
        assert!(!dir.join("seed-0001").exists(), "an empty seed is left out");
        assert_eq!(
            fs::read(dir.join("seed-0002")).unwrap().len(),
            MAX_SEED_BYTES
        );
        let none = root.join("none").join("seeds");
        assert_eq!(write_seed_dir(&[Vec::new()], &none).unwrap(), 0);
        assert_eq!(fs::read(none.join("seed-default")).unwrap(), b"AAAA");
    }

    #[test]
    fn saved_inputs_and_their_exception_names() {
        let out = tmpdir("saved");
        let crashes = out.join("crashes");
        touch(&crashes.join("README.txt"));
        touch(&crashes.join("id_000001_00_STATUS_HEAP_CORRUPTION"));
        touch(&crashes.join("id_000000_00_EXCEPTION_ACCESS_VIOLATION"));
        // AFL's own `id:` spelling, which only a non-Windows file system holds.
        let afl_spelling = cfg!(unix).then(|| touch(&crashes.join("id:000002,sig:11,src:000000")));
        fs::create_dir_all(crashes.join("id_dir")).unwrap();
        let names: Vec<String> = saved_inputs(&crashes)
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        let mut expected = vec![
            "id_000000_00_EXCEPTION_ACCESS_VIOLATION",
            "id_000001_00_STATUS_HEAP_CORRUPTION",
        ];
        if afl_spelling.is_some() {
            expected.insert(0, "id:000002,sig:11,src:000000");
        }
        assert_eq!(names, expected);
        assert!(saved_inputs(&out.join("missing")).is_empty());
        assert_eq!(
            crash_exception_name("id_000000_00_EXCEPTION_ACCESS_VIOLATION"),
            Some("EXCEPTION_ACCESS_VIOLATION")
        );
        assert_eq!(
            crash_exception_name("id_000007_00_STATUS_STACK_BUFFER_OVERRUN"),
            Some("STATUS_STACK_BUFFER_OVERRUN")
        );
        assert_eq!(crash_exception_name("id_000000"), None);
        assert_eq!(crash_exception_name("README.txt"), None);
        assert_eq!(crash_exception_name("id_00x000_00_X"), None);
    }

    #[test]
    fn crashing_seeds_are_read_from_the_dry_run_log() {
        let log = "\u{1b}[1;94m[*] \u{1b}[0mAttempting dry run with 'O\\queue\\id_000000'...\n\
                   \u{1b}[1;92m[+] \u{1b}[0mAll right - fork server is up.\n\
                   [*] Attempting dry run with 'O\\queue\\id_000001'...\n\
                   [!] WARNING: Test case results in a crash (skipping)\n\
                   [*] Attempting dry run with 'O\\queue\\id_000002'...\n\
                   [!] WARNING: Test case results in a timeout (skipping)\n";
        assert_eq!(
            crashing_seeds_in_log(&strip_terminal_escapes(log)),
            [PathBuf::from("O\\queue\\id_000001")]
        );
        assert!(crashing_seeds_in_log("").is_empty());
    }

    /// Lines WinAFL 2.43b (master fd85f38, DynamoRIO 11.91) wrote on the VM.
    const PLOT: &str = "# relative_time, cycles_done, cur_path, paths_total, pending_total, \
        pending_favs, map_size, unique_crashes, unique_hangs, max_depth, execs_per_sec\n\
        5, 2, 4, 5, 0, 0, 0.61%, 0, 0, 4, 4633.23\n\
        10, 4, 5, 11, 6, 1, 0.64%, 0, 0, 4, 4586.46\n\
        52, 4, 7, 20, 13, 7, 0.67%, 2, 13, 4, 49.41\n\
        garbage\n";

    #[test]
    fn plot_data_and_fuzzer_stats_parse() {
        let rows = parse_plot_data(PLOT);
        assert_eq!(rows.len(), 3);
        assert_eq!(
            rows[2],
            PlotRow {
                relative_time: 52,
                paths_total: 20,
                map_density_percent: 0.67,
                unique_crashes: 2,
                unique_hangs: 13,
                execs_per_sec: 49.41,
            }
        );
        // 5s at 4633.23 + 5s at 4586.46 + 42s at 49.41 + 3s more at 49.41.
        assert_eq!(estimate_executions(&rows, 55.0), 48_322);
        assert_eq!(estimate_executions(&[], 10.0), 0);
        let stats = parse_fuzzer_stats("execs_done        : 104531\nbitmap_cvg        : 0.67%\n");
        assert_eq!(stats["execs_done"], "104531");
        assert_eq!(stats["bitmap_cvg"], "0.67%");
        assert_eq!(bitmap_edges(&[0xff, 0xfe, 0x00, 0xff]), 2);
    }

    #[test]
    fn stats_take_the_freshest_of_fuzzer_stats_bitmap_and_plot_data() {
        let out = tmpdir("stats");
        // Only plot_data (a run shorter than WinAFL's one-minute stats write).
        fs::write(out.join("plot_data"), PLOT).unwrap();
        let stats = read_stats(&out, 55.0);
        assert_eq!(stats.executions_source, "plot_data");
        assert_eq!(stats.executions, 48_322);
        assert_eq!(stats.map_edges, 439, "0.67% of the 64 KiB map");
        assert_eq!(
            (stats.paths_total, stats.unique_crashes, stats.unique_hangs),
            (20, 2, 13)
        );
        // fuzzer_stats ahead of the plot rows wins, and so does fuzz_bitmap's
        // exact count.
        fs::write(
            out.join("fuzzer_stats"),
            "execs_done        : 104531\nexecs_per_sec     : 1718.81\npaths_total       : 21\n\
             bitmap_cvg        : 0.67%\nunique_crashes    : 2\nunique_hangs      : 13\n\
             afl_version       : 2.43b\n",
        )
        .unwrap();
        let mut bitmap = vec![0xffu8; MAP_SIZE];
        bitmap[..450].fill(0x7f);
        fs::write(out.join("fuzz_bitmap"), &bitmap).unwrap();
        let stats = read_stats(&out, 55.0);
        assert_eq!(stats.executions_source, "fuzzer_stats");
        assert_eq!(stats.executions, 104_531);
        assert_eq!(stats.map_edges, 450);
        assert_eq!(stats.paths_total, 21);
        assert_eq!(stats.afl_version.as_deref(), Some("2.43b"));
        assert_eq!(read_stats(&out.join("none"), 1.0).executions_source, "none");
    }

    #[test]
    fn winafl_is_an_engine_name() {
        assert_eq!(
            parse_engine_list("builtin, winafl").unwrap(),
            [FuzzEngine::Builtin, FuzzEngine::Winafl]
        );
        assert!(parse_engine_list("winafl++")
            .unwrap_err()
            .contains("builtin, afl++, winafl"));
        assert_eq!(engine_arg_name(FuzzEngine::Winafl), "winafl");
    }

    #[cfg(not(windows))]
    #[test]
    fn winafl_is_refused_off_windows() {
        assert_eq!(host_supported(), Err(NOT_WINDOWS.to_owned()));
        assert!(
            crate::fuzz::check_winafl_available(&WinaflSettings::default())
                .unwrap_err()
                .contains("runs only on native Windows")
        );
    }

    /// The whole engine against a stand-in afl-fuzz. Its first session
    /// records its argv and environment, writes what WinAFL writes (two
    /// crashes of one root cause, a hang that replays clean, a crashing seed
    /// named in its dry-run log, a queue and plot_data) and aborts after six
    /// seconds as WinAFL does when it cannot stop a hung target; bhf restarts
    /// it on that queue, and the second session keeps running until bhf stops
    /// it at the time budget. Every saved input of both is replayed through
    /// the sanitized harness.
    #[cfg(unix)]
    #[test]
    fn a_winafl_run_restarts_after_an_abort_stops_on_time_and_ingests_both_sessions() {
        use std::os::unix::fs::PermissionsExt;
        let root = tmpdir("run");
        let work = root.join("work");
        let id = "H-WAF";
        let build = work.join("build").join(id);
        fs::create_dir_all(&build).unwrap();
        fs::write(build.join("main.c"), "// marker for libFuzzer detection\n").unwrap();
        let harness = build.join("main");
        fs::write(
            &harness,
            "#!/bin/sh\n\
             if grep -q 'BHF!' \"$1\"; then\n\
               >&2 echo 'ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602 at pc 0x444'\n\
               >&2 echo 'WRITE of size 64 at 0x602 thread T0'\n\
               >&2 echo '    #0 0x444 in parse_record /src/record.c:21'\n\
               >&2 echo '    #1 0x445 in bhf_run_one /src/main.c:30'\n\
               exit 1\n\
             fi\n\
             exit 0\n",
        )
        .unwrap();
        fs::set_permissions(&harness, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(build.join(FUZZ_BINARY_STEM), b"stand-in WinAFL build").unwrap();

        let tools_dir = root.join("winafl");
        fs::create_dir_all(&tools_dir).unwrap();
        let record = root.join("record");
        let afl_fuzz = tools_dir.join("afl-fuzz.exe");
        fs::write(
            &afl_fuzz,
            format!(
                "#!/bin/sh\n\
                 n=$(ls '{record}'.argv.* 2>/dev/null | wc -l)\n\
                 printf '%s\\n' \"$@\" > '{record}.argv.'$n\n\
                 env > '{record}.env'\n\
                 while [ $# -gt 0 ]; do\n\
                   case \"$1\" in -i) in=\"$2\"; shift;; -o) out=\"$2\"; shift;; esac\n\
                   shift\n\
                 done\n\
                 ls \"$in\" > '{record}.seeds.'$n\n\
                 mkdir -p \"$out/queue\" \"$out/crashes\" \"$out/hangs\"\n\
                 if [ $n -eq 0 ]; then\n\
                   printf 'BHF!seed' > \"$out/queue/id_000000\"\n\
                   printf 'queue-entry' > \"$out/queue/id_000001\"\n\
                   echo \"[*] Attempting dry run with 'id_000000'...\"\n\
                   echo '[!] WARNING: Test case results in a crash (skipping)'\n\
                   echo \"[*] Attempting dry run with 'id_000001'...\"\n\
                   echo 'crash dir notes' > \"$out/crashes/README.txt\"\n\
                   printf 'BHF!crash-a' > \"$out/crashes/id_000000_00_EXCEPTION_ACCESS_VIOLATION\"\n\
                   printf 'BHF!crash-b' > \"$out/crashes/id_000001_00_STATUS_HEAP_CORRUPTION\"\n\
                   printf 'slow' > \"$out/hangs/id_000000\"\n\
                   printf '# relative_time, cycles_done, cur_path, paths_total, pending_total, pending_favs, map_size, unique_crashes, unique_hangs, max_depth, execs_per_sec\\n5, 1, 0, 2, 0, 0, 0.50%%, 2, 1, 1, 1000.00\\n6, 1, 1, 2, 0, 0, 0.50%%, 2, 1, 1, 2000.00\\n' > \"$out/plot_data\"\n\
                   sleep 6\n\
                   echo '[-] PROGRAM ABORT : Cannot kill child process'\n\
                   exit 1\n\
                 fi\n\
                 cp \"$in/seed-0000\" \"$out/queue/id_000000\"\n\
                 printf 'BHF!late' > \"$out/crashes/id_000000_00_EXCEPTION_ACCESS_VIOLATION\"\n\
                 printf '# relative_time, cycles_done, cur_path, paths_total, pending_total, pending_favs, map_size, unique_crashes, unique_hangs, max_depth, execs_per_sec\\n5, 1, 0, 3, 0, 0, 0.75%%, 1, 0, 1, 100.00\\n' > \"$out/plot_data\"\n\
                 sleep 60\n",
                record = record.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&afl_fuzz, fs::Permissions::from_mode(0o755)).unwrap();
        let tools = WinaflTools {
            afl_fuzz: afl_fuzz.clone(),
            winafl_dll: Some(tools_dir.join("winafl.dll")),
            dynamorio_bin: Some(root.join("DynamoRIO").join("bin64")),
            instrumentation: WinaflInstrumentation::Dynamorio,
        };

        let seed: Vec<u8> = vec![0x00, 0xff, 0x80, b'Z', 0x0a];
        let mut args = afl_programmatic_args(
            &work,
            id,
            vec![seed.clone()],
            Some(Duration::from_secs(20)),
            &[],
            actionability::RunMode::Reporting,
            0,
            &[],
            4096,
        );
        args.engine = FuzzEngine::Winafl;
        args.winafl_coverage_modules = vec!["target.dll".to_owned()];
        let prepared = prepare(args).unwrap();
        let summary = run_with_tools(prepared, &tools).unwrap();
        // The fuzzing itself (both sessions, not the replays after it) ends at
        // the budget although the second session would sleep for a minute.
        assert!(
            (19.0..30.0).contains(&summary.elapsed_secs),
            "afl-fuzz was not stopped at its 20s budget: {}s",
            summary.elapsed_secs
        );

        let argv = fs::read_to_string(root.join("record.argv.0")).unwrap();
        let argv: Vec<&str> = argv.lines().collect();
        let after = |flag: &str| argv[argv.iter().position(|arg| *arg == flag).unwrap() + 1];
        assert_eq!(
            after("-D"),
            root.join("DynamoRIO").join("bin64").display().to_string()
        );
        assert_eq!(after("-t"), "2000+");
        assert_eq!(after("-I"), "30000");
        assert_eq!(after("-m"), "none", "--rss-limit-mb 0 sets no memory cap");
        assert!(argv.contains(&"-d"), "{argv:?}");
        assert_eq!(after("-target_method"), TARGET_METHOD);
        assert_eq!(after("-target_module"), FUZZ_BINARY_STEM);
        assert_eq!(after("-nargs"), "1");
        assert_eq!(after("-fuzz_iterations"), "5000");
        assert!(argv
            .windows(2)
            .any(|pair| pair == ["-coverage_module", "target.dll"]));
        let fuzz_binary = build.join(FUZZ_BINARY_STEM).display().to_string();
        assert_eq!(&argv[argv.len() - 2..], [fuzz_binary.as_str(), "@@"]);
        let env = fs::read_to_string(record.with_extension("env")).unwrap();
        assert!(
            env.lines().any(|line| line == "AFL_SKIP_CRASHES=1"),
            "{env}"
        );
        assert_eq!(
            fs::read_to_string(root.join("record.seeds.0")).unwrap(),
            "seed-0000\n"
        );
        let winafl_root = work.join("winafl_out").join(id);
        assert_eq!(
            fs::read(winafl_root.join("seeds").join("seed-0000")).unwrap(),
            seed
        );

        // The restart ran on the first session's queue, less its crashing seed.
        let second = fs::read_to_string(root.join("record.argv.1")).unwrap();
        let second: Vec<&str> = second.lines().collect();
        let restart_seeds = winafl_root.join("seeds-1");
        assert_eq!(second[1], restart_seeds.display().to_string());
        assert_eq!(second[3], winafl_root.join("out-1").display().to_string());
        assert_eq!(
            fs::read(restart_seeds.join("seed-0000")).unwrap(),
            b"queue-entry"
        );
        assert!(!restart_seeds.join("seed-0001").exists());
        assert!(!root.join("record.argv.2").exists(), "one restart only");

        // Three crashes and the crashing seed share one root cause: one finding.
        assert_eq!(summary.engine, "winafl");
        assert_eq!(summary.findings.len(), 1, "{:?}", summary.findings);
        let provenance = summary.winafl.as_ref().unwrap();
        assert_eq!(provenance.sessions, 2);
        assert_eq!((provenance.crashes_saved, provenance.hangs_saved), (3, 1));
        assert_eq!(provenance.crashing_seeds, 1);
        assert_eq!(provenance.replay_reported, 4);
        assert_eq!(provenance.replay_clean, 1, "the hang replays clean");
        assert_eq!(provenance.replay_timed_out, 0);
        assert_eq!(
            provenance.stopped_early, None,
            "the last session ran to the budget"
        );
        assert!(!provenance.page_heap);
        assert_eq!(provenance.memory_limit_mb, None);
        assert_eq!(provenance.fuzz_binary, build.join(FUZZ_BINARY_STEM));
        assert_eq!(provenance.replay_binary, harness);
        assert_eq!(
            provenance.coverage_modules,
            [FUZZ_BINARY_STEM.to_owned(), "target.dll".to_owned()]
        );
        // WinAFL's own numbers, over both sessions: 5s at 1000/s and 1s at
        // 2000/s, then 5s at 100/s, each rate carried on to its session's end;
        // the wider map is 0.75%.
        assert!(summary.executions >= 7_500, "{}", summary.executions);
        assert_eq!(summary.coverage.edges, 492);
        assert_eq!(summary.coverage.source, "winafl-dynamorio");
        assert!(summary.execution.persistent);
        assert_eq!(summary.execution.persistent_iterations, Some(5000));

        let finding_dir = corpus::layout::finding_dir(&work, &summary.findings[0]);
        let finding: serde_json::Value =
            serde_json::from_slice(&fs::read(finding_dir.join("finding.json")).unwrap()).unwrap();
        assert_eq!(finding["discovery"]["engine"], "winafl");
        assert_eq!(finding["discovery"]["saved_as"], "crash");
        assert_eq!(
            finding["discovery"]["exception"],
            "EXCEPTION_ACCESS_VIOLATION"
        );
        assert_eq!(finding["discovery"]["sanitizers"], serde_json::json!([]));
        assert_eq!(
            finding["discovery"]["confirmed_by"],
            serde_json::json!(harness.display().to_string())
        );
        assert!(
            finding.to_string().contains("heap-buffer-overflow"),
            "{finding:#}"
        );

        // The last session's queue reaches bhf's corpus.
        let queue = work.join("corpus").join(id).join("queue");
        let persisted: Vec<Vec<u8>> = fs::read_dir(&queue)
            .unwrap()
            .flatten()
            .map(|entry| fs::read(entry.path()).unwrap())
            .collect();
        assert_eq!(persisted, [b"queue-entry".to_vec()]);
        assert_eq!(provenance.queue_persisted, 1);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_missing_winafl_build_says_how_to_make_it() {
        let root = tmpdir("nobuild");
        let harness = touch(&root.join("harnesses").join("H-X").join("main.exe"));
        assert_eq!(fuzz_binary_beside(&harness), None);
        let error = missing_build_error(&harness);
        assert!(error.starts_with("WinAFL build not found"), "{error}");
        assert!(
            error.contains(&format!(
                "no {} beside",
                crate::auto::layout::harness_exe_name(FUZZ_BINARY_STEM)
            )),
            "{error}"
        );
        assert!(
            error.contains(&harness.parent().unwrap().display().to_string()),
            "{error}"
        );
        assert!(
            error.contains("bhf build --c-engine winafl") && error.contains("make winafl"),
            "{error}"
        );
        let built =
            touch(&harness.with_file_name(crate::auto::layout::harness_exe_name(FUZZ_BINARY_STEM)));
        assert_eq!(fuzz_binary_beside(&harness), Some(built));
    }

    /// A PE image exporting `bhf_winafl_fuzz` from a module linked as `name`:
    /// one `.rdata` section holding the export directory and the name.
    fn pe_with_export(name: &str, pe32_plus: bool) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x400];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        let optional_size: u16 = if pe32_plus { 240 } else { 224 };
        bytes[0x94..0x96].copy_from_slice(&optional_size.to_le_bytes());
        let optional = 0x98;
        let magic: u16 = if pe32_plus { 0x20b } else { 0x10b };
        bytes[optional..optional + 2].copy_from_slice(&magic.to_le_bytes());
        let directories = optional + if pe32_plus { 112 } else { 96 };
        // The export directory at RVA 0x2000, in a section mapped from 0x200.
        bytes[directories..directories + 4].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[directories + 4..directories + 8].copy_from_slice(&0x40u32.to_le_bytes());
        let section = optional + usize::from(optional_size);
        bytes[section..section + 6].copy_from_slice(b".rdata");
        bytes[section + 8..section + 12].copy_from_slice(&0x100u32.to_le_bytes());
        bytes[section + 12..section + 16].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
        // IMAGE_EXPORT_DIRECTORY.Name -> RVA 0x2040.
        bytes[0x200 + 12..0x200 + 16].copy_from_slice(&0x2040u32.to_le_bytes());
        bytes[0x240..0x240 + name.len()].copy_from_slice(name.as_bytes());
        bytes
    }

    #[test]
    fn the_export_name_dynamorio_matches_is_read_from_the_pe() {
        assert_eq!(
            pe_export_name(&pe_with_export("main_winafl", true)).as_deref(),
            Some("main_winafl")
        );
        assert_eq!(
            pe_export_name(&pe_with_export("main_winafl.exe", false)).as_deref(),
            Some("main_winafl.exe")
        );
        // No export directory, no PE, a truncated one.
        assert_eq!(pe_export_name(&pe(0x8664)), None);
        assert_eq!(pe_export_name(b"#!/bin/sh\n"), None);
        assert_eq!(
            pe_export_name(&pe_with_export("main_winafl", true)[..0x210]),
            None
        );
    }

    #[test]
    fn the_memory_cap_is_the_rss_limit_plus_dynamorio_headroom() {
        let x64 = MemoryModel::X64;
        assert_eq!(memory_limit_mb(0, x64), None);
        assert_eq!(
            memory_limit_mb(2048, x64),
            Some(2048 + DYNAMORIO_HEADROOM_MB)
        );
        assert_eq!(
            memory_limit_mb(4096, x64),
            Some(4096 + DYNAMORIO_HEADROOM_MB)
        );
    }

    /// A 32-bit afl-fuzz computes its job memory limit in a 32-bit `SIZE_T`:
    /// `-m 4096` would wrap to 0 and `-m 5120` to 1 GiB. An x86 harness gets
    /// `-m` only while the cap is below what its address space allows, and
    /// `-m none` otherwise; never 4096 or more.
    #[test]
    fn an_x86_harness_never_gets_a_memory_cap_its_afl_fuzz_wraps() {
        let x86 = MemoryModel {
            arch: PeArch::X86,
            large_address_aware: false,
        };
        let x86_large = MemoryModel {
            large_address_aware: true,
            ..x86
        };
        assert_eq!(memory_limit_mb(0, x86), None);
        assert_eq!(memory_limit_mb(512, x86), Some(512 + DYNAMORIO_HEADROOM_MB));
        assert_eq!(memory_limit_mb(1024, x86), None, "2048: the address space");
        assert_eq!(memory_limit_mb(2048, x86), None);
        assert_eq!(memory_limit_mb(2048, x86_large), Some(3072));
        assert_eq!(memory_limit_mb(3072, x86_large), None, "4096 wraps to 0");
        assert_eq!(
            memory_limit_mb(4096, x86_large),
            None,
            "5120 wraps to 1 GiB"
        );
        for rss in (0..=16384).step_by(64) {
            for model in [x86, x86_large] {
                assert!(
                    memory_limit_mb(rss, model).is_none_or(|limit| limit < 4096),
                    "{rss} {model:?}"
                );
            }
        }
        // The model is read from the build's PE header.
        let dir = tmpdir("memory-model");
        let image = |name: &str, machine: u16, characteristics: u16| {
            let mut bytes = pe(machine);
            bytes[0x56..0x58].copy_from_slice(&characteristics.to_le_bytes());
            let path = dir.join(name);
            fs::write(&path, bytes).unwrap();
            path
        };
        assert_eq!(MemoryModel::of(&image("x86.exe", 0x014c, 0x0102)), x86);
        assert_eq!(
            MemoryModel::of(&image("x86-laa.exe", 0x014c, 0x0122)),
            x86_large
        );
        assert_eq!(
            MemoryModel::of(&image("x64.exe", 0x8664, 0x0022)),
            MemoryModel::X64
        );
        assert_eq!(
            MemoryModel::of(&touch(&dir.join("stand-in"))),
            MemoryModel::X64
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_x86_harness_gets_the_32_bit_winafl_build_of_a_checkout() {
        let root = tmpdir("arch");
        let checkout = root.join("winafl-checkout");
        // The checkout's root holds an x64 build; bin32 the x86 one.
        touch(&checkout.join("afl-fuzz.exe"));
        fs::write(checkout.join("winafl.dll"), pe(0x8664)).unwrap();
        touch(&checkout.join("bin32").join("afl-fuzz.exe"));
        fs::write(checkout.join("bin32").join("winafl.dll"), pe(0x014c)).unwrap();
        let (_, dynamorio) = install(&root);
        let settings = WinaflSettings {
            winafl_path: Some(checkout.clone()),
            dynamorio_path: Some(dynamorio.clone()),
            ..Default::default()
        };
        let x86 = resolve_tools(&settings, PeArch::X86, &env_of(&[])).unwrap();
        assert_eq!(x86.afl_fuzz, checkout.join("bin32").join("afl-fuzz.exe"));
        assert_eq!(
            x86.winafl_dll,
            Some(checkout.join("bin32").join("winafl.dll"))
        );
        let x64 = resolve_tools(&settings, PeArch::X64, &env_of(&[])).unwrap();
        assert_eq!(x64.winafl_dll, Some(checkout.join("winafl.dll")));
        // Only the x64 build: an x86 harness is refused, naming both.
        fs::remove_dir_all(checkout.join("bin32")).unwrap();
        let error = resolve_tools(&settings, PeArch::X86, &env_of(&[])).unwrap_err();
        assert!(
            error.contains("is an x64 DynamoRIO client, but the harness is x86"),
            "{error}"
        );
        assert!(error.contains("build32"), "{error}");
        // The architecture auto checks for follows the Visual Studio target.
        let vs_x86 = |key: &str| (key == "VSCMD_ARG_TGT_ARCH").then(|| OsString::from("x86"));
        assert_eq!(target_arch(&vs_x86, "x86_64"), Ok(PeArch::X86));
        assert_eq!(target_arch(&env_of(&[]), "x86_64"), Ok(PeArch::X64));
    }

    /// `bhf auto --engine winafl --vs-arch arm64`, or an ARM64 machine's
    /// default, is refused by the check made before the sweep, not per target
    /// after `make winafl`.
    #[test]
    fn an_arm64_target_is_refused_before_the_sweep() {
        let vs = |arch: &'static str| {
            move |key: &str| (key == "VSCMD_ARG_TGT_ARCH").then(|| OsString::from(arch))
        };
        for (env_arch, host) in [("arm64", "x86_64"), ("ARM64", "x86_64"), ("arm", "x86_64")] {
            let error = target_arch(&vs(env_arch), host).unwrap_err();
            assert!(error.contains("WinAFL fuzzes x86 and x64"), "{error}");
            assert!(error.contains("--vs-arch x64"), "{error}");
        }
        assert!(target_arch(&env_of(&[]), "aarch64").is_err());
        assert_eq!(target_arch(&env_of(&[]), "x86"), Ok(PeArch::X86));
        assert_eq!(target_arch(&vs("x64"), "aarch64"), Ok(PeArch::X64));
        assert_eq!(target_arch(&vs("AMD64"), "x86_64"), Ok(PeArch::X64));
        let root = tmpdir("arm64");
        let (winafl, dynamorio) = install(&root);
        let settings = WinaflSettings {
            winafl_path: Some(winafl),
            dynamorio_path: Some(dynamorio),
            ..Default::default()
        };
        let registry = page_heap::MemoryRegistry::default();
        assert_eq!(check_tools(&settings, &vs("x64"), &registry), Ok(()));
        let error = check_tools(&settings, &vs("arm64"), &registry).unwrap_err();
        assert!(error.contains("built for arm64"), "{error}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_coverage_module_with_a_space_is_refused() {
        let root = tmpdir("module-space");
        let (winafl, dynamorio) = install(&root);
        for module in ["my target.dll", "\"target.dll\"", " "] {
            let settings = WinaflSettings {
                winafl_path: Some(winafl.clone()),
                dynamorio_path: Some(dynamorio.clone()),
                coverage_modules: vec![module.to_owned()],
                ..Default::default()
            };
            let error = resolve_tools(&settings, PeArch::X64, &env_of(&[])).unwrap_err();
            assert!(error.starts_with("--winafl-coverage-module"), "{error}");
        }
    }

    #[test]
    fn page_heap_without_rights_to_the_key_is_refused_up_front() {
        let root = tmpdir("elevation");
        let (winafl, dynamorio) = install(&root);
        let settings = WinaflSettings {
            winafl_path: Some(winafl),
            dynamorio_path: Some(dynamorio),
            page_heap: true,
            ..Default::default()
        };
        let read_only = page_heap::MemoryRegistry {
            read_only: true,
            ..Default::default()
        };
        let error = check_tools(&settings, &env_of(&[]), &read_only).unwrap_err();
        assert_eq!(error, PAGE_HEAP_NEEDS_ELEVATION);
        assert!(error.contains("elevated (administrator) shell"), "{error}");
        let writable = page_heap::MemoryRegistry::default();
        assert_eq!(check_tools(&settings, &env_of(&[]), &writable), Ok(()));
        let without = WinaflSettings {
            page_heap: false,
            ..settings
        };
        assert_eq!(check_tools(&without, &env_of(&[]), &read_only), Ok(()));
    }

    fn saved_files(dir: &Path, kind: SavedKind, contents: &[&[u8]]) -> Vec<(PathBuf, SavedKind)> {
        fs::create_dir_all(dir).unwrap();
        contents
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                let name = match kind {
                    SavedKind::Crash => format!("id_{index:06}_00_EXCEPTION_ACCESS_VIOLATION"),
                    _ => format!("id_{index:06}"),
                };
                let path = dir.join(name);
                fs::write(&path, bytes).unwrap();
                (path, kind)
            })
            .collect()
    }

    fn far_limits() -> IngestLimits {
        IngestLimits {
            deadline: Instant::now() + Duration::from_secs(3600),
            hang_share: Duration::from_secs(1800),
            max_quiet_hangs: MAX_QUIET_HANGS,
        }
    }

    /// A clock for [`replay_saved`] that moves only when a replay moves it.
    struct FakeClock(std::cell::Cell<Instant>);

    impl FakeClock {
        fn new() -> Self {
            Self(std::cell::Cell::new(Instant::now()))
        }
        fn now(&self) -> Instant {
            self.0.get()
        }
        fn advance(&self, by: Duration) {
            self.0.set(self.0.get() + by);
        }
    }

    #[test]
    fn identical_saved_inputs_are_replayed_once() {
        let dir = tmpdir("ingest-dupes");
        let mut saved = saved_files(&dir.join("crashes"), SavedKind::Crash, &[b"A", b"B", b"A"]);
        saved.extend(saved_files(
            &dir.join("hangs"),
            SavedKind::Hang,
            &[b"B", b"C"],
        ));
        let mut replayed: Vec<Vec<u8>> = Vec::new();
        let out = replay_saved(&saved, far_limits(), &Instant::now, &mut |_, _, input| {
            replayed.push(input.to_vec());
            Ok(Replayed::Clean)
        });
        assert_eq!(replayed, [b"A".to_vec(), b"B".to_vec(), b"C".to_vec()]);
        assert_eq!((out.clean, out.duplicates, out.skipped), (3, 2, 0));
    }

    #[test]
    fn hangs_stop_replaying_after_a_run_of_quiet_ones_and_a_report_resets_the_run() {
        let dir = tmpdir("ingest-hangs");
        let contents: Vec<Vec<u8>> = (0..40u8).map(|byte| vec![byte]).collect();
        let refs: Vec<&[u8]> = contents.iter().map(Vec::as_slice).collect();
        let saved = saved_files(&dir.join("hangs"), SavedKind::Hang, &refs);
        let mut calls = 0usize;
        let out = replay_saved(
            &saved,
            far_limits(),
            &Instant::now,
            &mut |_, kind, input| {
                assert_eq!(kind, SavedKind::Hang);
                calls += 1;
                // Hang 3 reports; every other one times out.
                Ok(if input == [3] {
                    Replayed::Reported(Some("F-1".to_owned()))
                } else {
                    Replayed::TimedOut
                })
            },
        );
        // 0..=2 quiet, 3 reports, then 4..=11 are the eight quiet ones.
        assert_eq!(calls, 4 + MAX_QUIET_HANGS);
        assert_eq!(out.finding_ids, ["F-1"]);
        assert_eq!(out.timed_out, 3 + MAX_QUIET_HANGS);
        assert_eq!(out.skipped, 40 - calls);
    }

    #[test]
    fn crashes_are_still_replayed_after_quiet_hangs_and_nothing_after_the_deadline() {
        let dir = tmpdir("ingest-deadline");
        let mut saved = saved_files(&dir.join("hangs"), SavedKind::Hang, &[b"h1", b"h2", b"h3"]);
        saved.extend(saved_files(
            &dir.join("crashes"),
            SavedKind::Crash,
            &[b"c1"],
        ));
        let mut order: Vec<SavedKind> = Vec::new();
        let out = replay_saved(
            &saved,
            IngestLimits {
                max_quiet_hangs: 1,
                ..far_limits()
            },
            &Instant::now,
            &mut |_, kind, _| {
                order.push(kind);
                Ok(if kind == SavedKind::Hang {
                    Replayed::TimedOut
                } else {
                    Replayed::Clean
                })
            },
        );
        assert_eq!(order, [SavedKind::Crash, SavedKind::Hang]);
        assert_eq!(out.skipped, 2);
        let past = IngestLimits {
            deadline: Instant::now(),
            ..far_limits()
        };
        let out = replay_saved(&saved, past, &Instant::now, &mut |_, _, _| {
            panic!("replayed after the deadline")
        });
        assert_eq!(out.skipped, 4);
    }

    /// Hangs that replay clean (load-induced or slow-path ones, which cost
    /// only their run) do not use up the quiet-hang stop: the one real hang
    /// after many of them is still replayed. Only hangs that time out again
    /// count, and a read or spawn error does not.
    #[test]
    fn hangs_that_replay_clean_do_not_stop_the_hang_replay() {
        let dir = tmpdir("ingest-clean-hangs");
        let contents: Vec<Vec<u8>> = (0..40u8).map(|byte| vec![byte]).collect();
        let refs: Vec<&[u8]> = contents.iter().map(Vec::as_slice).collect();
        let saved = saved_files(&dir.join("hangs"), SavedKind::Hang, &refs);
        let mut calls = 0usize;
        let out = replay_saved(&saved, far_limits(), &Instant::now, &mut |_, _, input| {
            calls += 1;
            // 0..=19 replay clean, 20 and 21 fail to spawn, 22 is the real
            // one, and 23.. time out again.
            match input[0] {
                0..=19 => Ok(Replayed::Clean),
                20 | 21 => Err("spawn failed".to_owned()),
                22 => Ok(Replayed::Reported(Some("F-HANG".to_owned()))),
                _ => Ok(Replayed::TimedOut),
            }
        });
        assert_eq!(out.finding_ids, ["F-HANG"], "{out:?}");
        assert_eq!(out.clean, 20);
        assert_eq!(out.errors, 2);
        assert_eq!(out.timed_out, MAX_QUIET_HANGS);
        assert_eq!(calls, 23 + MAX_QUIET_HANGS);
        assert_eq!(out.skipped, 40 - calls);
    }

    /// However many crashes come first, the hangs keep their share of the
    /// replay time: the crashes stop at it while hangs wait, the hangs are
    /// replayed, and the crashes left over get the time that remains.
    #[test]
    fn many_crashes_cannot_use_up_the_time_the_hangs_get() {
        let dir = tmpdir("ingest-hang-share");
        let contents: Vec<Vec<u8>> = (0..200u8).map(|byte| vec![b'c', byte]).collect();
        let refs: Vec<&[u8]> = contents.iter().map(Vec::as_slice).collect();
        let mut saved = saved_files(&dir.join("crashes"), SavedKind::Crash, &refs);
        // Eight hangs that replay clean, then the real one.
        let hangs: Vec<Vec<u8>> = (0..9u8).map(|byte| vec![b'h', byte]).collect();
        let hang_refs: Vec<&[u8]> = hangs.iter().map(Vec::as_slice).collect();
        saved.extend(saved_files(&dir.join("hangs"), SavedKind::Hang, &hang_refs));
        let clock = FakeClock::new();
        let limits = IngestLimits {
            deadline: clock.now() + Duration::from_secs(30),
            hang_share: Duration::from_secs(15),
            max_quiet_hangs: MAX_QUIET_HANGS,
        };
        let mut order: Vec<Vec<u8>> = Vec::new();
        let out = replay_saved(&saved, limits, &|| clock.now(), &mut |_, kind, input| {
            order.push(input.to_vec());
            if kind == SavedKind::Hang {
                clock.advance(Duration::from_millis(500));
                return Ok(if input == [b'h', 8] {
                    Replayed::Reported(Some("F-HANG".to_owned()))
                } else {
                    Replayed::Clean
                });
            }
            // Each crash replay takes a second, with a benign report.
            clock.advance(Duration::from_secs(1));
            Ok(Replayed::Reported(None))
        });
        assert_eq!(out.finding_ids, ["F-HANG"], "{out:?}");
        // 15 crashes until the hangs' share began, the nine hangs in 4.5 s,
        // then the crashes left over until the deadline.
        assert_eq!(order[15], [b'h', 0]);
        assert_eq!(order[23], [b'h', 8]);
        assert_eq!(order[24], [b'c', 15]);
        let crashes_replayed = order.iter().filter(|input| input[0] == b'c').count();
        assert_eq!(crashes_replayed, 15 + 11);
        assert_eq!(out.skipped, 200 - crashes_replayed);
        // With no hang waiting, the crashes get the whole window.
        let only_crashes: Vec<_> = saved
            .iter()
            .filter(|(_, kind)| *kind == SavedKind::Crash)
            .cloned()
            .collect();
        let clock = FakeClock::new();
        let limits = IngestLimits {
            deadline: clock.now() + Duration::from_secs(30),
            ..limits
        };
        let out = replay_saved(&only_crashes, limits, &|| clock.now(), &mut |_, _, _| {
            clock.advance(Duration::from_secs(1));
            Ok(Replayed::Clean)
        });
        assert_eq!(out.clean, 30);
    }

    #[test]
    fn the_replay_window_is_half_the_budget_and_half_of_it_is_the_hangs() {
        let limits = IngestLimits::for_budget(Duration::from_secs(600));
        assert_eq!(limits.hang_share, Duration::from_secs(150));
        let short = IngestLimits::for_budget(Duration::from_secs(10));
        assert_eq!(short.hang_share, MIN_INGEST / 2);
        assert_eq!(short.max_quiet_hangs, MAX_QUIET_HANGS);
    }

    #[test]
    fn an_input_that_fails_to_read_or_replay_does_not_stop_the_others() {
        let dir = tmpdir("ingest-errors");
        let mut saved = saved_files(&dir.join("crashes"), SavedKind::Crash, &[b"bad", b"good"]);
        saved.insert(
            0,
            (
                dir.join("crashes").join("id_000009_00_GONE"),
                SavedKind::Crash,
            ),
        );
        let out = replay_saved(&saved, far_limits(), &Instant::now, &mut |_, _, input| {
            if input == b"bad" {
                Err("spawn failed".to_owned())
            } else {
                Ok(Replayed::Reported(Some("F-2".to_owned())))
            }
        });
        assert_eq!(out.errors, 2, "{out:?}");
        assert_eq!(out.finding_ids, ["F-2"]);
    }

    #[test]
    fn the_first_crash_of_each_exception_is_replayed_first() {
        let saved = [
            (PathBuf::from("h/id_000000"), SavedKind::Hang),
            (
                PathBuf::from("c/id_000000_00_EXCEPTION_ACCESS_VIOLATION"),
                SavedKind::Crash,
            ),
            (
                PathBuf::from("c/id_000001_00_EXCEPTION_ACCESS_VIOLATION"),
                SavedKind::Crash,
            ),
            (PathBuf::from("q/id_000003"), SavedKind::CrashingSeed),
            (
                PathBuf::from("c/id_000002_00_STATUS_HEAP_CORRUPTION"),
                SavedKind::Crash,
            ),
        ];
        let names: Vec<String> = replay_order(&saved)
            .iter()
            .map(|(path, _)| path.display().to_string())
            .collect();
        assert_eq!(
            names,
            [
                "c/id_000000_00_EXCEPTION_ACCESS_VIOLATION",
                "c/id_000002_00_STATUS_HEAP_CORRUPTION",
                "c/id_000001_00_EXCEPTION_ACCESS_VIOLATION",
                "q/id_000003",
                "h/id_000000",
            ]
        );
    }

    /// A work dir with a stand-in harness that reports a heap overflow for an
    /// input holding `BHF!`, its stand-in WinAFL build, and a stand-in
    /// afl-fuzz running `script` (after it records its argv).
    #[cfg(unix)]
    fn stand_in_run(
        tag: &str,
        script: &str,
    ) -> (crate::test_support::TestDir, PathBuf, WinaflTools) {
        use std::os::unix::fs::PermissionsExt;
        let root = tmpdir(tag);
        let build = root.join("work").join("build").join("H-WAF");
        fs::create_dir_all(&build).unwrap();
        fs::write(build.join("main.c"), "// marker for libFuzzer detection\n").unwrap();
        let harness = build.join("main");
        fs::write(
            &harness,
            "#!/bin/sh\n\
             if grep -q 'BHF!' \"$1\"; then\n\
               >&2 echo 'ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602 at pc 0x444'\n\
               >&2 echo 'WRITE of size 64 at 0x602 thread T0'\n\
               >&2 echo '    #0 0x444 in parse_record /src/record.c:21'\n\
               >&2 echo '    #1 0x445 in bhf_run_one /src/main.c:30'\n\
               exit 1\n\
             fi\n\
             exit 0\n",
        )
        .unwrap();
        fs::set_permissions(&harness, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(build.join(FUZZ_BINARY_STEM), b"stand-in WinAFL build").unwrap();
        let tools_dir = root.join("winafl");
        fs::create_dir_all(&tools_dir).unwrap();
        let afl_fuzz = tools_dir.join("afl-fuzz.exe");
        fs::write(
            &afl_fuzz,
            format!(
                "#!/bin/sh\n\
                 printf '%s\\n' \"$@\" > '{root}/argv'\n\
                 for arg; do target=\"$prev\"; prev=\"$arg\"; done\n\
                 ls \"$target\" > '{root}/target-present' 2>&1\n\
                 while [ $# -gt 0 ]; do\n\
                   case \"$1\" in -o) out=\"$2\"; shift;; esac\n\
                   shift\n\
                 done\n\
                 mkdir -p \"$out/queue\" \"$out/crashes\" \"$out/hangs\"\n\
                 {script}",
                root = root.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&afl_fuzz, fs::Permissions::from_mode(0o755)).unwrap();
        let tools = WinaflTools {
            afl_fuzz,
            winafl_dll: Some(tools_dir.join("winafl.dll")),
            dynamorio_bin: Some(root.join("DynamoRIO").join("bin64")),
            instrumentation: WinaflInstrumentation::Dynamorio,
        };
        let work = root.join("work");
        (root, work, tools)
    }

    #[cfg(unix)]
    fn prepared_for(work: &Path, time: Duration, page_heap: bool) -> PreparedFuzzRun {
        let mut args = afl_programmatic_args(
            work,
            "H-WAF",
            vec![b"seed".to_vec()],
            Some(time),
            &[],
            actionability::RunMode::Reporting,
            2048,
            &[],
            4096,
        );
        args.engine = FuzzEngine::Winafl;
        args.winafl_page_heap = page_heap;
        prepare(args).unwrap()
    }

    /// WinAFL aborting early with only a hang saved (its "Cannot kill child
    /// process" abort): the hang is still replayed into a finding, the queue
    /// still reaches the corpus, and the early stop is a warning.
    #[cfg(unix)]
    #[test]
    fn an_early_abort_that_saved_only_a_hang_still_yields_its_finding() {
        let (root, work, tools) = stand_in_run(
            "early-hang",
            "printf 'BHF!AAAAAAAA' > \"$out/hangs/id_000000\"\n\
             printf 'queued' > \"$out/queue/id_000000\"\n\
             sleep 6\n\
             echo '[-] PROGRAM ABORT : Cannot kill child process'\n\
             exit 1\n",
        );
        let summary =
            run_with_tools(prepared_for(&work, Duration::from_secs(10), false), &tools).unwrap();
        assert_eq!(summary.findings.len(), 1, "{summary:?}");
        let provenance = summary.winafl.as_ref().unwrap();
        assert_eq!(provenance.hangs_saved, 1);
        assert_eq!(provenance.replay_reported, 1);
        assert_eq!(
            provenance.sessions, 1,
            "4s left is too little for a restart"
        );
        assert!(
            provenance
                .stopped_early
                .as_deref()
                .is_some_and(|reason| reason.contains("Cannot kill child process")),
            "{:?}",
            provenance.stopped_early
        );
        let finding: serde_json::Value = serde_json::from_slice(
            &fs::read(
                corpus::layout::finding_dir(&work, &summary.findings[0]).join("finding.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(finding["discovery"]["saved_as"], "hang");
        assert_eq!(provenance.queue_persisted, 1);
        let argv = fs::read_to_string(root.join("argv")).unwrap();
        assert!(argv.contains("-m\n3072\n"), "{argv}");
        let _ = fs::remove_dir_all(&root);
    }

    /// An early stop that saved nothing is still the run's error, with the
    /// log tail and hint, and the queue still reaches the corpus.
    #[cfg(unix)]
    #[test]
    fn an_early_stop_that_saved_nothing_is_an_error_and_keeps_the_queue() {
        let (root, work, tools) = stand_in_run(
            "early-none",
            "printf 'queued' > \"$out/queue/id_000000\"\n\
             echo '[-] PROGRAM ABORT : Error opening pidfile'\n\
             exit 1\n",
        );
        let error = run_with_tools(prepared_for(&work, Duration::from_secs(10), false), &tools)
            .unwrap_err();
        assert!(
            error.contains("afl-fuzz exited before its time budget"),
            "{error}"
        );
        assert!(error.contains("Error opening pidfile"), "{error}");
        assert!(
            error.contains("Hint: the target never connected"),
            "{error}"
        );
        let queue = work.join("corpus").join("H-WAF").join("queue");
        assert_eq!(fs::read_dir(&queue).map(|dir| dir.count()).unwrap_or(0), 1);
        let _ = fs::remove_dir_all(&root);
    }

    /// `--winafl-page-heap`: WinAFL fuzzes a run-unique copy whose key is set
    /// while it runs, and both are gone after; the finding records the PageHeap
    /// actually in effect.
    #[cfg(unix)]
    #[test]
    fn a_page_heap_run_fuzzes_its_own_copy_and_cleans_up_after() {
        let (root, work, tools) = stand_in_run(
            "page-heap",
            "printf 'BHF!crash' > \"$out/crashes/id_000000_00_EXCEPTION_ACCESS_VIOLATION\"\n\
             sleep 60\n",
        );
        // The build is a PE image exporting its entry under the name it was
        // linked as, which DynamoRIO names the copy's module by.
        let build = work.join("build").join("H-WAF").join(FUZZ_BINARY_STEM);
        fs::write(&build, pe_with_export("main_winafl.exe", true)).unwrap();
        let registry = Arc::new(page_heap::MemoryRegistry::default());
        let host = Host {
            registry: registry.clone(),
            owner: Ok(page_heap::Owner {
                pid: 31337,
                started: 1,
            }),
            liveness: |_| page_heap::Liveness::Unknown,
            stopping: || false,
        };
        let summary = run_on_host(
            prepared_for(&work, Duration::from_secs(3), true),
            &tools,
            &host,
        )
        .unwrap();
        let provenance = summary.winafl.as_ref().unwrap();
        assert!(provenance.page_heap);
        let image = provenance.page_heap_image.clone().unwrap();
        let name = image.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("main_winafl-31337-"), "{name}");
        assert_eq!(
            provenance.page_heap_key.as_deref(),
            Some(page_heap::image_key(&name).as_str())
        );
        let argv = fs::read_to_string(root.join("argv")).unwrap();
        let argv: Vec<&str> = argv.lines().collect();
        let after = |flag: &str| argv[argv.iter().position(|arg| *arg == flag).unwrap() + 1];
        assert_eq!(after("-target_module"), name);
        assert_eq!(argv[argv.len() - 2], image.display().to_string());
        let coverage: Vec<&str> = argv
            .windows(2)
            .filter(|pair| pair[0] == "-coverage_module")
            .map(|pair| pair[1])
            .collect();
        assert_eq!(coverage, [name.as_str(), "main_winafl.exe"]);
        assert!(
            !page_heap::marker_path(&image).exists(),
            "the copy's marker goes with it"
        );
        assert_eq!(
            fs::read_to_string(root.join("target-present"))
                .unwrap()
                .trim(),
            image.display().to_string(),
            "the copy existed while afl-fuzz ran"
        );
        assert!(!image.exists(), "the copy is deleted after the run");
        assert!(
            registry.keys.lock().unwrap().is_empty(),
            "the key is removed after the run"
        );
        assert_eq!(
            provenance.fuzz_binary,
            work.join("build").join("H-WAF").join(FUZZ_BINARY_STEM)
        );
        let finding: serde_json::Value = serde_json::from_slice(
            &fs::read(
                corpus::layout::finding_dir(&work, &summary.findings[0]).join("finding.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(finding["discovery"]["page_heap"], true);
        let _ = fs::remove_dir_all(&root);
    }

    /// A run without the flag records PageHeap someone set for the build's own
    /// name, rather than claiming it ran without, and reclaims what a killed
    /// page-heap run left.
    #[cfg(unix)]
    #[test]
    fn page_heap_set_outside_bhf_is_recorded_as_in_effect() {
        let (root, work, tools) = stand_in_run(
            "page-heap-outside",
            "printf 'BHF!crash' > \"$out/crashes/id_000000_00_EXCEPTION_ACCESS_VIOLATION\"\n\
             sleep 60\n",
        );
        let registry = Arc::new(page_heap::MemoryRegistry::default());
        registry.insert(
            &page_heap::image_key(FUZZ_BINARY_STEM),
            &[(
                page_heap::GLOBAL_FLAG,
                page_heap::RegValue::Dword(0x0200_0000),
            )],
        );
        // A killed page-heap run's key and copy (with its marker), which this
        // run reclaims, and a file bhf did not make, which it keeps.
        let stale = crate::auto::layout::harness_exe_name("main_winafl-7-0-0");
        let stale = stale.as_str();
        let stale_copy = work.join("build").join("H-WAF").join(stale);
        fs::write(&stale_copy, b"copy").unwrap();
        fs::write(page_heap::marker_path(&stale_copy), "bhf pid=7 started=0\n").unwrap();
        let unmarked = work
            .join("build")
            .join("H-WAF")
            .join(crate::auto::layout::harness_exe_name("main_winafl-8-0-0"));
        fs::write(&unmarked, b"someone's file").unwrap();
        registry.insert(
            &page_heap::image_key(stale),
            &[
                (
                    page_heap::GLOBAL_FLAG,
                    page_heap::RegValue::Dword(0x0200_0000),
                ),
                (
                    page_heap::OWNER_VALUE,
                    page_heap::RegValue::Str(
                        "bhf pid=7 started=0 created=1 GlobalFlag=- PageHeapFlags=-".to_owned(),
                    ),
                ),
            ],
        );
        let host = Host {
            registry: registry.clone(),
            owner: Err("not needed without --winafl-page-heap".to_owned()),
            liveness: |pid| {
                if pid == 7 || pid == 8 {
                    page_heap::Liveness::Gone
                } else {
                    page_heap::Liveness::Unknown
                }
            },
            stopping: || false,
        };
        let summary = run_on_host(
            prepared_for(&work, Duration::from_secs(2), false),
            &tools,
            &host,
        )
        .unwrap();
        let provenance = summary.winafl.as_ref().unwrap();
        assert!(provenance.page_heap);
        assert_eq!(provenance.page_heap_key, None, "bhf set no key");
        assert_eq!(registry.snapshot(&page_heap::image_key(stale)), None);
        assert!(!stale_copy.exists());
        assert!(!page_heap::marker_path(&stale_copy).exists());
        assert!(unmarked.exists(), "a copy without bhf's marker is kept");
        let _ = fs::remove_dir_all(&root);
    }

    /// What a run left unreplayed (it ended on Ctrl-C or a kill before its
    /// replay) is replayed by the next run of the harness, which keeps it under
    /// `earlier/` with what that run kept; once replayed, the run after clears
    /// it and replays nothing again.
    #[cfg(unix)]
    #[test]
    fn a_later_run_replays_what_an_interrupted_run_saved_then_clears_it() {
        let (root, work, tools) = stand_in_run("leftover", "sleep 60\n");
        let out_root = work.join("winafl_out").join("H-WAF");
        let put = |path: PathBuf, bytes: &[u8]| {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        };
        // The interrupted run: a crash and a hang that replays clean, no
        // marker; and an earlier run it had kept itself, with a hang.
        let crash = out_root.join("out").join("crashes");
        put(
            crash.join("id_000000_00_EXCEPTION_ACCESS_VIOLATION"),
            b"BHF!crash",
        );
        put(
            out_root.join("out").join("hangs").join("id_000000"),
            b"plain",
        );
        put(out_root.join("afl-fuzz.log"), b"");
        let kept_before = out_root.join(EARLIER_RUNS_DIR).join("0");
        put(
            kept_before.join("out-1").join("hangs").join("id_000003"),
            b"BHF!hang",
        );
        let host = || Host {
            registry: Arc::new(page_heap::MemoryRegistry::default()),
            owner: Err("not needed".to_owned()),
            liveness: |_| page_heap::Liveness::Unknown,
            stopping: || false,
        };
        let prepared = || prepared_for(&work, Duration::from_secs(2), false);
        let summary = run_on_host(prepared(), &tools, &host()).unwrap();
        let provenance = summary.winafl.as_ref().unwrap();
        assert_eq!(provenance.earlier_inputs, 3, "{provenance:?}");
        assert_eq!(provenance.crashes_saved + provenance.hangs_saved, 0);
        // The crash and the earlier hang report the same overflow: one finding.
        assert_eq!(summary.findings.len(), 1, "{summary:?}");
        assert_eq!(
            (provenance.replay_reported, provenance.replay_clean),
            (2, 1)
        );
        let finding_json =
            corpus::layout::finding_dir(&work, &summary.findings[0]).join("finding.json");
        let finding: serde_json::Value =
            serde_json::from_slice(&fs::read(finding_json).unwrap()).unwrap();
        let kept = out_root.join(EARLIER_RUNS_DIR);
        let saved_input = finding["discovery"]["saved_input"].as_str().unwrap();
        assert!(
            saved_input.starts_with(&kept.display().to_string()),
            "{saved_input}"
        );
        // Kept oldest first: the run the interrupted one kept, then that run.
        assert!(kept
            .join("0")
            .join("out-1")
            .join("hangs")
            .join("id_000003")
            .is_file());
        assert!(kept.join("1").join("out").join("crashes").is_dir());
        assert!(out_root.join(REPLAYED_MARKER).is_file());
        // Replayed: the next run clears it and replays nothing of it.
        let summary = run_on_host(prepared(), &tools, &host()).unwrap();
        assert_eq!(summary.winafl.as_ref().unwrap().earlier_inputs, 0);
        assert!(summary.findings.is_empty(), "{summary:?}");
        assert!(!kept.exists());
        let _ = fs::remove_dir_all(&root);
    }

    /// The output an unreplayed run left is kept with the earlier runs it
    /// kept, at most [`MAX_EARLIER_RUNS`] of them (the oldest go); one that
    /// saved nothing is not kept, and a replayed one is cleared.
    #[test]
    fn unreplayed_runs_are_kept_up_to_a_limit_and_replayed_ones_cleared() {
        let dir = tmpdir("earlier-runs");
        let root = dir.join("H-1");
        let hang = |run: &Path, name: &str| {
            let path = run.join("out").join("hangs").join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, name).unwrap();
        };
        for index in 0..MAX_EARLIER_RUNS {
            let run = root.join(EARLIER_RUNS_DIR).join(index.to_string());
            hang(&run, &format!("id_00000{index}"));
        }
        hang(&root, "id_000100");
        let names = |run: &Path| -> Vec<String> {
            saved_in_run(run)
                .iter()
                .map(|(path, _)| path.file_name().unwrap().to_string_lossy().into_owned())
                .collect()
        };
        let kept = reset_output_root(&root).unwrap();
        assert_eq!(kept.len(), MAX_EARLIER_RUNS);
        assert_eq!(names(&kept[0]), ["id_000001"], "the oldest is dropped");
        assert_eq!(names(kept.last().unwrap()), ["id_000100"]);
        assert!(!dir.join("H-1.unreplayed").exists());
        // A run that saved nothing is not kept, but what it kept is.
        let kept = reset_output_root(&root).unwrap();
        assert_eq!(kept.len(), MAX_EARLIER_RUNS);
        assert_eq!(names(kept.last().unwrap()), ["id_000100"]);
        // Marked replayed: cleared.
        fs::write(root.join(REPLAYED_MARKER), b"").unwrap();
        assert_eq!(reset_output_root(&root).unwrap(), Vec::<PathBuf>::new());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    /// A console control event (Ctrl-C) ending bhf mid-run: afl-fuzz is
    /// stopped, nothing is restarted or replayed (a replay would outlive the
    /// process), and the PageHeap key, the copy and its marker are gone.
    #[cfg(unix)]
    #[test]
    fn a_console_stop_ends_the_run_without_replaying_and_cleans_up() {
        let (root, work, tools) = stand_in_run(
            "console-stop",
            "printf 'BHF!crash' > \"$out/crashes/id_000000_00_EXCEPTION_ACCESS_VIOLATION\"\n\
             sleep 60\n",
        );
        let registry = Arc::new(page_heap::MemoryRegistry::default());
        let host = Host {
            registry: registry.clone(),
            owner: Ok(page_heap::Owner {
                pid: 31338,
                started: 1,
            }),
            liveness: |_| page_heap::Liveness::Unknown,
            stopping: || true,
        };
        let started = Instant::now();
        let error = run_on_host(
            prepared_for(&work, Duration::from_secs(30), true),
            &tools,
            &host,
        )
        .unwrap_err();
        // It says where the unreplayed inputs are and how they become findings.
        let out_root = work.join("winafl_out").join("H-WAF");
        assert!(error.contains(&out_root.display().to_string()), "{error}");
        assert!(error.contains("replays them into findings"), "{error}");
        let main = work.join("build").join("H-WAF").join("main");
        assert!(
            error.contains(&format!("{} <file>", main.display())),
            "{error}"
        );
        assert!(
            !out_root.join(REPLAYED_MARKER).exists(),
            "nothing was replayed"
        );
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "afl-fuzz was stopped"
        );
        assert!(
            registry.keys.lock().unwrap().is_empty(),
            "the key is removed"
        );
        let build_dir = work.join("build").join("H-WAF");
        let left: Vec<String> = fs::read_dir(&build_dir)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("main_winafl-"))
            .collect();
        assert!(left.is_empty(), "copy and marker deleted: {left:?}");
        assert!(
            !work.join("findings").exists()
                || fs::read_dir(work.join("findings"))
                    .unwrap()
                    .next()
                    .is_none(),
            "nothing was replayed"
        );
        let _ = fs::remove_dir_all(&root);
    }
}
