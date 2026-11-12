// SPDX-License-Identifier: Apache-2.0

use crate::protocol_detect::HarnessProtocol;
use clap::ValueEnum;
use replay_min::{HarnessRunner, SandboxConfig};
use std::path::{Path, PathBuf};

/// How a foreign-platform/arch harness is launched. Both variants prefix the
/// harness argv with an emulator executable (`qemu-aarch64 <harness>` /
/// `wine <harness>`), so both reuse `HarnessRunner::qemu_user` — wine takes no
/// emulator args, qemu may take a `-L <sysroot>` pair. Set by `bhf auto`
/// only for a cross candidate; the host-native path uses `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HarnessWrapper {
    QemuUser { exe: PathBuf, args: Vec<String> },
    Wine { exe: PathBuf },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum SandboxModeArg {
    None,
    Auto,
    Firejail,
    Bubblewrap,
}

pub(crate) fn harness_runner(
    harness: PathBuf,
    qemu_user: Option<PathBuf>,
    qemu_args: Vec<String>,
    sandbox: SandboxModeArg,
    sandbox_tool: Option<PathBuf>,
    sandbox_strict: bool,
) -> HarnessRunner {
    let wrapper = qemu_user.map(|exe| HarnessWrapper::QemuUser {
        exe,
        args: qemu_args,
    });
    harness_runner_with_wrapper(harness, wrapper, sandbox, sandbox_tool, sandbox_strict)
}

/// Build a `HarnessRunner` for a harness launched directly, under qemu-user, or
/// under wine. `wrapper == None` is byte-identical to the historical
/// `HarnessRunner::direct` path; the wine variant is just a qemu-user prefix
/// with no emulator args (`wine <harness>`).
pub(crate) fn harness_runner_with_wrapper(
    harness: PathBuf,
    wrapper: Option<HarnessWrapper>,
    sandbox: SandboxModeArg,
    sandbox_tool: Option<PathBuf>,
    sandbox_strict: bool,
) -> HarnessRunner {
    let runner = match wrapper {
        Some(HarnessWrapper::QemuUser { exe, args }) => {
            HarnessRunner::qemu_user(exe, args, harness)
        }
        Some(HarnessWrapper::Wine { exe }) => HarnessRunner::qemu_user(exe, Vec::new(), harness),
        None => HarnessRunner::direct(harness),
    };
    let runner = runner.with_sandbox(sandbox_config(sandbox, sandbox_tool, sandbox_strict));
    // Read-only-bind the runtrace shim's directory into the sandbox so the
    // LD_PRELOAD shim still loads (and the executable oracles still fire) when
    // the harness runs sandboxed. No effect when not sandboxed or shim absent.
    match crate::auto::shim_path::locate().and_then(|shim| shim.parent().map(Path::to_path_buf)) {
        Some(shim_dir) => runner.with_ro_binds([shim_dir]),
        None => runner,
    }
}

/// Classify a built harness binary by the engine its main() expects.
/// AdaStdin is the default for native Ada harnesses (read events file
/// via env). CLibFuzzer accepts an input file via argv (libFuzzer
/// `single input` mode, which bhf's own C/C++ driver also accepts). CAfl
/// reads input from stdin (AFL persistent mode handshake).
///   - filename `main_afl` is unambiguous (bhf build only stages
///     it for `--c-engine afl++`).
///   - everything else goes through the detector `bhf fuzz` uses
///     ([`crate::protocol_detect::detect`]): a declared input mode, the
///     `BHF_FRAMED` marker in a launcher, in a driver source anywhere in the
///     work dir, or compiled into the binary, a plain libFuzzer source, or the
///     libFuzzer runtime in the binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HarnessEngine {
    AdaStdin,
    CLibFuzzer,
    CAfl,
}

/// Classify `harness`, also searching the harness dirs of `work_dirs` (for a
/// finding, the work dir that holds it) for its sources.
pub(crate) fn detect_harness_engine_in(harness: &Path, work_dirs: &[&Path]) -> HarnessEngine {
    let name = harness
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if name == "main_afl" || name == "main_afl.exe" {
        return HarnessEngine::CAfl;
    }
    engine_for(crate::protocol_detect::detect(harness, work_dirs).protocol)
}

pub(crate) fn engine_for(protocol: HarnessProtocol) -> HarnessEngine {
    match protocol {
        HarnessProtocol::BhfFramed | HarnessProtocol::LibFuzzerSingleInput => {
            HarnessEngine::CLibFuzzer
        }
        HarnessProtocol::StdinEventLog => HarnessEngine::AdaStdin,
    }
}

fn sandbox_config(
    sandbox: SandboxModeArg,
    sandbox_tool: Option<PathBuf>,
    sandbox_strict: bool,
) -> SandboxConfig {
    match sandbox {
        SandboxModeArg::None => SandboxConfig::none(),
        SandboxModeArg::Auto => {
            if sandbox_strict {
                SandboxConfig::strict_auto()
            } else {
                SandboxConfig::auto()
            }
        }
        SandboxModeArg::Firejail => {
            SandboxConfig::firejail(sandbox_tool.unwrap_or_else(|| PathBuf::from("firejail")))
                .with_strict(sandbox_strict)
        }
        SandboxModeArg::Bubblewrap => {
            SandboxConfig::bubblewrap(sandbox_tool.unwrap_or_else(|| PathBuf::from("bwrap")))
                .with_strict(sandbox_strict)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{detect_harness_engine_in, HarnessEngine};
    use std::path::Path;

    fn detect_harness_engine(harness: &Path) -> HarnessEngine {
        detect_harness_engine_in(harness, &[])
    }
    use std::fs;

    /// A binary with `BHF_FRAMED` compiled in, past the first 4 KiB.
    fn framed_binary() -> Vec<u8> {
        let mut bytes = b"\x7fELF\x02\x01\x01\0".to_vec();
        bytes.resize(64 * 1024, 0);
        bytes.extend_from_slice(b"BHF_FRAMED\0BHF_COV_SHM\0");
        bytes
    }

    /// `bhf build` stages only the binary into `build/<id>/main`; replay and
    /// minimize must still feed it the testcase as a file.
    #[test]
    fn a_driver_binary_staged_alone_takes_its_input_as_a_file() {
        let work = tempfile::tempdir().unwrap();
        let dir = work.path().join("build/H-STAGED");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("main"), framed_binary()).unwrap();
        assert_eq!(
            detect_harness_engine(&dir.join("main")),
            HarnessEngine::CLibFuzzer
        );
    }

    /// The driver source of a staged binary lives in the generated harness dir.
    #[test]
    fn a_staged_binary_finds_its_driver_source_in_the_work_dir() {
        let work = tempfile::tempdir().unwrap();
        let build = work.path().join("build/H-GEN");
        let generated = work.path().join("generated_harnesses/H-GEN");
        fs::create_dir_all(&build).unwrap();
        fs::create_dir_all(&generated).unwrap();
        fs::write(build.join("main"), b"\x7fELF\0").unwrap();
        fs::write(generated.join("main.cpp"), "// BHF_FRAMED driver\n").unwrap();
        assert_eq!(
            detect_harness_engine(&build.join("main")),
            HarnessEngine::CLibFuzzer
        );
    }

    #[test]
    fn an_unmarked_binary_is_an_ada_stdin_harness() {
        let work = tempfile::tempdir().unwrap();
        let dir = work.path().join("build/H-ADA/obj");
        fs::create_dir_all(&dir).unwrap();
        let mut bytes = framed_binary();
        bytes.extend_from_slice(b"BHF_EVENTS_PATH\0");
        fs::write(dir.join("main"), bytes).unwrap();
        assert_eq!(
            detect_harness_engine(&dir.join("main")),
            HarnessEngine::AdaStdin
        );
    }
}
