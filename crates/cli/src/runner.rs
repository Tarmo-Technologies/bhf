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

/// The runner for a command that runs a finding's or a work dir's harness:
/// an explicit `qemu_user` wins; otherwise the emulator recorded
/// beside the harness ([`recorded_runner_for`]) runs it, with a note saying
/// so; otherwise it runs directly, and a harness built for an architecture
/// this host cannot run is refused before it runs, naming the flag to pass.
pub(crate) fn harness_runner_for(
    harness: PathBuf,
    qemu_user: Option<PathBuf>,
    qemu_args: Vec<String>,
    sandbox: SandboxModeArg,
    sandbox_tool: Option<PathBuf>,
    sandbox_strict: bool,
) -> Result<HarnessRunner, String> {
    let wrapper = match qemu_user {
        Some(exe) => Some(HarnessWrapper::QemuUser {
            exe,
            args: qemu_args,
        }),
        None => match recorded_runner_for(&harness) {
            Some(recorded) => {
                bhfeprintln!(
                    "note: running {} under the recorded runner {}",
                    harness.display(),
                    runner_text(&recorded)
                );
                Some(HarnessWrapper::QemuUser {
                    exe: recorded.program,
                    args: recorded.args,
                })
            }
            None => {
                refuse_foreign_harness(&harness)?;
                None
            }
        },
    };
    Ok(harness_runner_with_wrapper(
        harness,
        wrapper,
        sandbox,
        sandbox_tool,
        sandbox_strict,
    ))
}

/// `program arg...`, as a command line shows it.
fn runner_text(runner: &crate::gate_evidence::HarnessRunner) -> String {
    std::iter::once(runner.program.display().to_string())
        .chain(runner.args.iter().cloned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The emulator recorded for `harness` (`bhf_runner.json`): beside it, or,
/// for a binary `bhf build` staged into `<work>/build/<id>/main`, in the
/// harness dir it was built from (`harnesses/<id>/`, ...).
pub(crate) fn recorded_runner_for(harness: &Path) -> Option<crate::gate_evidence::HarnessRunner> {
    crate::gate_evidence::recorded_runner(harness).or_else(|| {
        let dir = harness.parent()?;
        let id = dir.file_name()?.to_str()?;
        let build = dir.parent()?;
        if build.file_name()? != "build" {
            return None;
        }
        let work = build.parent()?;
        crate::auto::layout::harness_dir_candidates(work, id)
            .into_iter()
            .find_map(|dir| crate::gate_evidence::recorded_runner(&dir.join("main")))
    })
}

/// Whether a binary for `machine` runs on this host without an emulator: the
/// host's own machine, or the 32-bit one an x86_64 or AArch64 kernel also
/// runs.
fn runs_natively(machine: u16) -> bool {
    match host_elf_machine() {
        Some(host) if host == machine => true,
        Some(62) => machine == 3,
        Some(183) => machine == 40,
        Some(_) => false,
        // An unknown host: do not second-guess it.
        None => true,
    }
}

/// The qemu-user program for an ELF harness, by its machine and byte order.
fn qemu_program(info: &ElfInfo) -> String {
    let arch = match (info.machine, info.big_endian, info.class64) {
        (3, _, _) => "i386",
        (62, _, _) => "x86_64",
        (183, false, _) => "aarch64",
        (183, true, _) => "aarch64_be",
        (40, false, _) => "arm",
        (40, true, _) => "armeb",
        (243, _, true) => "riscv64",
        (243, _, false) => "riscv32",
        (8, true, false) => "mips",
        (8, false, false) => "mipsel",
        (8, true, true) => "mips64",
        (8, false, true) => "mips64el",
        (20, _, _) => "ppc",
        (21, true, _) => "ppc64",
        (21, false, _) => "ppc64le",
        (22, _, _) => "s390x",
        (2, _, _) => "sparc",
        (43, _, _) => "sparc64",
        (258, _, _) => "loongarch64",
        _ => return "qemu-<arch>".to_owned(),
    };
    format!("qemu-{arch}")
}

/// Refuse to run `harness` directly when it is an ELF binary for another
/// architecture: it would fail to execute, or fail in its loader, and look
/// like a broken harness.
pub(crate) fn refuse_foreign_harness(harness: &Path) -> Result<(), String> {
    let Some(info) = elf_info(harness) else {
        return Ok(());
    };
    if runs_natively(info.machine) {
        return Ok(());
    }
    Err(format!(
        "{} is built for {}; run it under an emulator: --qemu-user {} [--qemu-arg ...] (a \
         dynamically linked harness also needs --qemu-arg=-L --qemu-arg=<its sysroot>)",
        harness.display(),
        elf_machine_name(info.machine),
        qemu_program(&info)
    ))
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

/// What bhf reads from an ELF file's header: the machine it is built for and
/// its byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ElfInfo {
    /// `e_machine` (`EM_X86_64` 62, `EM_AARCH64` 183, ...).
    pub(crate) machine: u16,
    pub(crate) class64: bool,
    pub(crate) big_endian: bool,
}

/// The ELF header of `path`, or `None` for anything that is not an ELF file
/// (a script, a PE binary, an unreadable path).
pub(crate) fn elf_info(path: &Path) -> Option<ElfInfo> {
    use std::io::Read;
    let mut header = [0u8; 20];
    std::fs::File::open(path)
        .ok()?
        .read_exact(&mut header)
        .ok()?;
    if &header[..4] != b"\x7fELF" {
        return None;
    }
    let big_endian = match header[5] {
        1 => false,
        2 => true,
        _ => return None,
    };
    let class64 = match header[4] {
        1 => false,
        2 => true,
        _ => return None,
    };
    let bytes = [header[18], header[19]];
    let machine = if big_endian {
        u16::from_be_bytes(bytes)
    } else {
        u16::from_le_bytes(bytes)
    };
    Some(ElfInfo {
        machine,
        class64,
        big_endian,
    })
}

/// The ELF `e_machine` of the host bhf runs on, when it has one.
pub(crate) fn host_elf_machine() -> Option<u16> {
    Some(match std::env::consts::ARCH {
        "x86_64" => 62,
        "x86" => 3,
        "aarch64" => 183,
        "arm" => 40,
        "riscv64" | "riscv32" => 243,
        "powerpc64" => 21,
        "powerpc" => 20,
        "mips" | "mips64" => 8,
        "s390x" => 22,
        "loongarch64" => 258,
        "sparc64" => 43,
        _ => return None,
    })
}

/// A short architecture name for an ELF `e_machine`.
pub(crate) fn elf_machine_name(machine: u16) -> String {
    match machine {
        2 => "sparc".to_owned(),
        3 => "x86 (i386)".to_owned(),
        8 => "mips".to_owned(),
        20 => "powerpc".to_owned(),
        21 => "powerpc64".to_owned(),
        22 => "s390x".to_owned(),
        40 => "arm".to_owned(),
        43 => "sparc64".to_owned(),
        62 => "x86_64".to_owned(),
        183 => "aarch64".to_owned(),
        243 => "riscv".to_owned(),
        258 => "loongarch".to_owned(),
        other => format!("ELF machine {other}"),
    }
}

/// Whether the ELF file at `path` carries a symbol table or debug
/// information (`.symtab`, `.debug_info`). `Some(false)` is a stripped
/// binary; `None` is not an ELF file or one whose section headers cannot be
/// read.
pub(crate) fn elf_has_symbols(path: &Path) -> Option<bool> {
    use std::io::{Read, Seek, SeekFrom};
    let info = elf_info(path)?;
    let mut file = std::fs::File::open(path).ok()?;
    let mut header = vec![0u8; if info.class64 { 64 } else { 52 }];
    file.read_exact(&mut header).ok()?;
    let read = |bytes: &[u8], at: usize, len: usize| -> Option<u64> {
        let field = bytes.get(at..at + len)?;
        let mut value = 0u64;
        for index in 0..len {
            let byte = if info.big_endian {
                field[index]
            } else {
                field[len - 1 - index]
            };
            value = (value << 8) | u64::from(byte);
        }
        Some(value)
    };
    let (shoff, shentsize, shnum, shstrndx) = if info.class64 {
        (
            read(&header, 0x28, 8)?,
            read(&header, 0x3a, 2)?,
            read(&header, 0x3c, 2)?,
            read(&header, 0x3e, 2)?,
        )
    } else {
        (
            read(&header, 0x20, 4)?,
            read(&header, 0x2e, 2)?,
            read(&header, 0x30, 2)?,
            read(&header, 0x32, 2)?,
        )
    };
    if shoff == 0 || shnum == 0 || shnum > 4096 || shentsize < 40 || shstrndx >= shnum {
        return None;
    }
    let mut table = vec![0u8; usize::try_from(shentsize * shnum).ok()?];
    file.seek(SeekFrom::Start(shoff)).ok()?;
    file.read_exact(&mut table).ok()?;
    let section = |index: u64| -> Option<(u64, u64, u64)> {
        let base = usize::try_from(index * shentsize).ok()?;
        let entry = table.get(base..base + usize::try_from(shentsize).ok()?)?;
        Some(if info.class64 {
            (
                read(entry, 0, 4)?,
                read(entry, 0x18, 8)?,
                read(entry, 0x20, 8)?,
            )
        } else {
            (
                read(entry, 0, 4)?,
                read(entry, 0x10, 4)?,
                read(entry, 0x14, 4)?,
            )
        })
    };
    let (_, names_offset, names_size) = section(shstrndx)?;
    if names_size > 1 << 20 {
        return None;
    }
    let mut names = vec![0u8; usize::try_from(names_size).ok()?];
    file.seek(SeekFrom::Start(names_offset)).ok()?;
    file.read_exact(&mut names).ok()?;
    let name_at = |offset: u64| -> &[u8] {
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(names.len());
        let rest = &names[start..];
        &rest[..rest.iter().position(|b| *b == 0).unwrap_or(rest.len())]
    };
    Some((0..shnum).filter_map(section).any(|(name, _, _)| {
        matches!(
            name_at(name),
            b".symtab" | b".debug_info" | b".zdebug_info" | b".gnu_debuglink"
        )
    }))
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

    /// A built binary has symbols, a stripped copy has none, and a script is
    /// not an ELF file.
    #[cfg(unix)]
    #[test]
    fn a_stripped_binary_is_told_from_one_with_symbols() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("w.c"), "int main(void) { return 0; }\n").unwrap();
        let built = std::process::Command::new("cc")
            .current_dir(dir.path())
            .args(["-g", "-o", "w", "w.c"])
            .status();
        if !built.is_ok_and(|status| status.success()) {
            eprintln!("skipping: no C compiler");
            return;
        }
        let binary = dir.path().join("w");
        let info = super::elf_info(&binary).expect("an ELF file");
        assert!(info.class64 == cfg!(target_pointer_width = "64"));
        assert_eq!(super::elf_has_symbols(&binary), Some(true));
        let stripped = dir.path().join("w.stripped");
        let ok = std::process::Command::new("strip")
            .arg("-o")
            .arg(&stripped)
            .arg(&binary)
            .status();
        if ok.is_ok_and(|status| status.success()) {
            assert_eq!(super::elf_has_symbols(&stripped), Some(false));
        }
        fs::write(dir.path().join("s"), "#!/bin/sh\n").unwrap();
        assert_eq!(super::elf_info(&dir.path().join("s")), None);
        assert_eq!(super::elf_has_symbols(&dir.path().join("s")), None);
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
