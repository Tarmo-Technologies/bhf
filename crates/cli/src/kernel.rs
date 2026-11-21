// SPDX-License-Identifier: Apache-2.0

//! `bhf kernel`: Linux drivers, fuzzed with syzkaller.
//!
//! `bhf kernel syzlang` reads a driver's C source and writes the syzkaller
//! description of its ioctl interface: a file-descriptor resource, the
//! `openat` of the device node, one `ioctl$CMD` variant per command its
//! handler dispatches on, and the argument structs, from the command macros
//! (`_IOW('W', 1, struct widget_config)`) and the struct layouts the C type
//! model recovers. It also writes the `.const` file syz-sysgen reads, with each
//! command's number computed per architecture, so no kernel build or
//! `syz-extract` run is needed.
//!
//! `bhf kernel import` brings what syzkaller found back: each crash
//! directory syz-manager wrote (its title, report, console log and
//! reproducers) becomes a finding in `<work>/results/`, with its crash class,
//! rule, CWE, stack and reproducer (`results::import_syzkaller`).
//!
//! `bhf kernel run` boots the kernel itself, in a qemu-system guest whose
//! `/init` is bhf's executor (`c_runtime/kernel_executor.c`), and runs
//! system-call programs in it: each call's result and the KCOV edges it
//! took come back over a virtio-serial port (`crate::kernel_guest`).

use anyhow::{bail, Context, Result};
use c_parser::{CDispatchFunction, CIoctlFacts, CRecordDef, CValue};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, clap::Args)]
pub struct KernelArgs {
    #[command(subcommand)]
    command: KernelCommand,
}

#[derive(Debug, clap::Subcommand)]
enum KernelCommand {
    /// Write syzkaller (syzlang) descriptions of a Linux driver's ioctl interface from its source
    ///
    /// Reads the .c and .h files given (directories recursively), finds the
    /// ioctl handlers a `struct file_operations` registers (`.unlocked_ioctl`,
    /// `.compat_ioctl`), the commands their `switch (cmd)` dispatches on
    /// (following calls that pass `cmd` on), the `_IO`/`_IOR`/`_IOW`/`_IOWR`
    /// macros that define them, their argument struct layouts, and the device
    /// node (a `struct miscdevice`, `device_create` or `register_chrdev` name).
    /// Writes `<out>/dev_<name>.txt` and `<out>/dev_<name>.txt.const`: put both
    /// in a syzkaller checkout's sys/linux and run syz-sysgen (`make
    /// descriptions`). The .const file gives each command's number for every
    /// architecture syzkaller builds for Linux. A command whose argument type
    /// the source does not define, or whose struct syzkaller would lay out
    /// unlike C on some architecture, is left out with the reason. Exit 0 when
    /// at least one command was described, 1 otherwise.
    Syzlang(SyzlangArgs),
    /// Import syzkaller crash directories into <work-dir>/results as findings
    ///
    /// Each finding carries the crash class (KASAN, KMSAN, UBSAN, KCSAN,
    /// WARNING, ...), rule, CWE, stack and reproducer. Takes crash directories (`<syz-manager workdir>/crashes/<id>`), a
    /// workdir's `crashes/`, or a syz-manager workdir. Each crash becomes
    /// `<work-dir>/results/findings/F-KERNEL-NNNN-<hash>/`: `finding.json`, the
    /// report as `sanitizer.log`, the first console log as `console.log`, and
    /// the reproducers as `repro.syz` and `repro.c`. The title gives the
    /// class, rule and CWE; the report gives the stack, the access and the
    /// object it hit. Importing a crash again updates its finding (a
    /// reproducer syz-repro found since is added). A crash of syzkaller's own
    /// test machine (`lost connection to test machine`) is skipped. Exit 0
    /// when at least one crash was imported, 1 otherwise.
    Import(ImportArgs),
    /// Boot a kernel in a qemu-system guest and run system-call programs in it, with KCOV
    ///
    /// Prints each call's result and the KCOV edges it took.
    ///
    /// The guest boots `--kernel` (built with CONFIG_KCOV and CONFIG_DEBUG_FS,
    /// and CONFIG_KASAN for memory-safety reports) with an initramfs bhf
    /// builds. Its /init is bhf's executor, compiled from
    /// c_runtime/kernel_executor.c with `--cc` and linked statically, and it
    /// loads each `--module` at boot. The executor talks to bhf over a
    /// virtio-serial port. Each PROGRAM (in the executor's program format,
    /// such as a finding's testcase.bin or a `bhf kernel fuzz` corpus file)
    /// runs in a child process with KCOV on. The kernel boots with `nokaslr
    /// panic_on_warn=1 oops=panic panic=-1`, so a kernel report stops the
    /// guest, and bhf prints the report's title. Exit 0 when every program ran
    /// with no kernel report; 1 when the kernel reported, or the guest
    /// stopped, did not answer or could not boot.
    Run(RunArgs),
    /// Fuzz a Linux kernel in a qemu-system guest with KCOV-guided system-call programs
    ///
    /// Boots the guest as `bhf kernel run` does. The seed programs are: one
    /// per ioctl command the `--source` driver's handlers dispatch on (as `bhf
    /// kernel syzlang` reads them), calling it on the device node with a
    /// zeroed argument of its size, and one program with all of them; every
    /// program in `--seeds`; with `--device` alone, a few calls on that node;
    /// and the corpus an earlier run left in <work-dir>/kernel/corpus. The
    /// commands' numbers (for the guest's architecture) and the node's path
    /// are mutation tokens.
    ///
    /// Each program's KCOV PCs go into the coverage map, each pair of
    /// consecutive PCs as one edge, and a program that reaches new coverage
    /// joins the corpus. When the kernel records KCOV comparisons
    /// (CONFIG_KCOV_ENABLE_COMPARISONS), each corpus program runs once more to
    /// collect the comparisons its calls made: an argument that holds one
    /// operand is tried with the other, and the operands become CmpLog
    /// entries that mutations splice in.
    ///
    /// A kernel report on the console (with `panic_on_warn` the guest panics
    /// on it) is written as a finding and the guest boots again. A run the
    /// guest does not survive, with no report, is saved under
    /// <work-dir>/kernel/crashes/. The campaign writes
    /// <work-dir>/kernel/fuzz.json. Exit 0 when the campaign ran its budget;
    /// 1 when the guest could not boot, no seed left it running, or it did not
    /// load a --module (then no program runs, and the executor's setup notes,
    /// which bhf prints and fuzz.json keeps, say why).
    ///
    /// A KASAN, KCSAN, KMSAN, KFENCE or UBSAN report, an oops, a WARNING, a
    /// hang or a panic on the guest's console becomes a finding in
    /// <work-dir>/results/findings/F-KERNEL-*: syzkaller's title for it, its
    /// class, rule and CWE, the stack, the access and the object, and the
    /// program (testcase.bin, decoded.json, program.txt, repro.c). A new
    /// title's program first runs alone in a freshly booted guest, and
    /// `kernel.reproduced` says whether it made the report again. The finding
    /// is written first, so when that guest does not boot, `kernel.unconfirmed`
    /// says why. A title found again is counted on its existing finding. `bhf
    /// kernel replay` replays a finding.
    Fuzz(KernelFuzzArgs),
    /// Re-run a `bhf kernel fuzz` finding's program in its guest and compare the kernel report
    ///
    /// Reads the guest the finding's finding.json records (kernel, modules,
    /// qemu, accel, memory, CPUs, command line, timeout) and its program
    /// (testcase.bin), builds the executor and the initramfs in a temporary
    /// directory, boots the guest and runs the program. Prints MATCH and the
    /// title when the kernel reports the crash the finding records, MISMATCH
    /// and the other title when it reports another, or NOT REPRODUCED.
    /// `--kernel`, `--module` and the other options replace what the finding
    /// records, for a kernel or module that moved. Exit 0 on a MATCH, 1
    /// otherwise, 2 when the finding cannot be read or the guest cannot boot.
    Replay(ReplayArgs),
}

#[derive(Debug, clap::Args)]
#[cfg_attr(not(unix), allow(dead_code))]
pub struct KernelFuzzArgs {
    #[command(flatten)]
    guest: GuestArgs,
    /// Work directory: <work-dir>/kernel gets the guest's files, the corpus, the crashes and fuzz.json
    #[arg(long, value_name = "DIR")]
    work_dir: PathBuf,
    /// The driver's C sources and headers, as `bhf kernel syzlang` reads them: each ioctl command becomes a seed program
    #[arg(long = "source", value_name = "SOURCE")]
    sources: Vec<PathBuf>,
    /// The device node the seeds open when the source names none, or, without --source, a node to open and call read, write and ioctl on
    #[arg(long, value_name = "PATH")]
    device: Option<String>,
    /// A directory of seed programs, in the executor's format
    #[arg(long, value_name = "DIR")]
    seeds: Option<PathBuf>,
    /// Most program executions (default 1000; no limit when --time is given)
    #[arg(long)]
    iterations: Option<usize>,
    /// Wall-clock budget such as 30s, 5m or 1h
    #[arg(long, value_parser = crate::fuzz::parse_duration)]
    time: Option<std::time::Duration>,
    /// Seed of the mutation RNG, so a campaign repeats exactly
    #[arg(long, default_value_t = 0x4b43_4f56)]
    rng_seed: u64,
    /// Longest program a mutation makes, in bytes (at most 65536)
    #[arg(long, value_name = "BYTES", default_value_t = 4096)]
    max_len: usize,
    /// Stop once this many findings were written or counted again
    #[arg(long, value_name = "N")]
    stop_after_findings: Option<usize>,
}

#[derive(Debug, clap::Args)]
#[cfg_attr(not(unix), allow(dead_code))]
pub struct ReplayArgs {
    /// The finding: its directory (<work-dir>/results/findings/F-KERNEL-...), or its finding.json
    #[arg(value_name = "FINDING")]
    finding: PathBuf,
    /// The guest kernel, in place of the one the finding names
    #[arg(long, value_name = "PATH")]
    kernel: Option<PathBuf>,
    /// The modules, in place of the ones the finding names (repeat for more)
    #[arg(long = "module", value_name = "PATH")]
    modules: Vec<PathBuf>,
    /// The qemu-system binary, in place of the finding's
    #[arg(long, value_name = "PATH")]
    qemu: Option<PathBuf>,
    /// How QEMU runs the guest, in place of the finding's
    #[arg(long, value_enum)]
    accel: Option<crate::kernel_guest::Accel>,
    /// The C compiler that builds the executor, in place of the finding's
    #[arg(long, value_name = "CC")]
    cc: Option<String>,
    /// A prebuilt executor, in place of building one
    #[arg(long, value_name = "PATH")]
    executor: Option<PathBuf>,
    /// Seconds the guest has to boot (at most 86400)
    #[arg(long, value_name = "SECS", default_value_t = 300, value_parser = guest_wait())]
    boot_timeout: u64,
    /// Seconds the program may run (default: the finding's; at most 86400)
    #[arg(long, value_name = "SECS", value_parser = guest_wait())]
    timeout: Option<u64>,
}

/// A wait for the guest, in seconds: 1 to a day.
fn guest_wait() -> clap::builder::RangedU64ValueParser {
    clap::value_parser!(u64).range(1..=crate::kernel_guest::MAX_WAIT_SECS)
}

/// How the guest kernel boots: the options `bhf kernel run` and `fuzz`
/// share.
#[derive(Debug, Clone, clap::Args)]
#[cfg_attr(not(unix), allow(dead_code))]
pub struct GuestArgs {
    /// The guest kernel image (a bzImage), built with CONFIG_KCOV and CONFIG_DEBUG_FS, and CONFIG_KASAN for memory-safety reports
    #[arg(long, value_name = "PATH")]
    kernel: PathBuf,
    /// A kernel module (.ko) the guest loads at boot, before the executor serves; repeat for more, loaded in order
    #[arg(long = "module", value_name = "PATH")]
    modules: Vec<PathBuf>,
    /// The qemu-system binary
    #[arg(long, value_name = "PATH", default_value = "qemu-system-x86_64")]
    qemu: PathBuf,
    /// How QEMU runs the guest: kvm when /dev/kvm is usable (auto), else tcg
    #[arg(long, value_enum, default_value = "auto")]
    accel: crate::kernel_guest::Accel,
    /// Guest memory in MiB
    #[arg(long, value_name = "MIB", default_value_t = 1024)]
    memory: u32,
    /// Guest CPUs
    #[arg(long, value_name = "N", default_value_t = 1)]
    smp: u32,
    /// Kernel command-line arguments added after bhf's own (console=ttyS0 nokaslr panic_on_warn=1 oops=panic panic=-1 rcupdate.rcu_cpu_stall_timeout=100)
    #[arg(long, value_name = "ARGS")]
    append: Option<String>,
    /// An extra qemu argument (repeat for more), such as `-machine virt` for another architecture's qemu
    #[arg(long = "qemu-arg", value_name = "ARG", allow_hyphen_values = true)]
    qemu_args: Vec<String>,
    /// The C compiler that builds the executor for the guest; it links statically
    #[arg(long, value_name = "CC", default_value = "cc")]
    cc: String,
    /// A prebuilt executor (c_runtime/kernel_executor.c, linked statically for the guest) in place of building one
    #[arg(long, value_name = "PATH")]
    executor: Option<PathBuf>,
    /// Seconds the guest has to boot and its executor to connect (at most 86400)
    #[arg(long, value_name = "SECS", default_value_t = 300, value_parser = guest_wait())]
    boot_timeout: u64,
    /// Seconds one program may run before the executor kills it (at most 86400)
    #[arg(long, value_name = "SECS", default_value_t = 10, value_parser = guest_wait())]
    timeout: u64,
}

#[derive(Debug, clap::Args)]
#[cfg_attr(not(unix), allow(dead_code))]
pub struct RunArgs {
    #[command(flatten)]
    guest: GuestArgs,
    /// Programs to run, in the executor's format
    #[arg(required = true, value_name = "PROGRAM")]
    programs: Vec<PathBuf>,
    /// Directory for the executor, the initramfs and the console log (default: a temporary directory, removed after)
    #[arg(long, value_name = "DIR")]
    work_dir: Option<PathBuf>,
    /// Print one JSON object per program
    #[arg(long)]
    json: bool,
}

#[derive(Debug, clap::Args)]
pub struct ImportArgs {
    /// syzkaller crash directories, a workdir's crashes/ directory, or a syz-manager workdir
    #[arg(required = true, value_name = "CRASHES")]
    crashes: Vec<PathBuf>,
    /// Work directory whose results/ receives the findings
    #[arg(long, value_name = "DIR")]
    work_dir: PathBuf,
    /// The kernel or driver source tree the report's paths are relative to: findings then keep only the frames of its files, and name them relative to it
    #[arg(long, value_name = "DIR")]
    source_root: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
pub struct SyzlangArgs {
    /// The driver's C sources and headers: files, or directories read recursively for .c and .h files. Include the header that defines its ioctl commands and argument structs
    #[arg(required = true, value_name = "SOURCE")]
    sources: Vec<PathBuf>,
    /// Directory to write dev_<name>.txt and dev_<name>.txt.const into, such as a syzkaller checkout's sys/linux
    #[arg(long, value_name = "DIR")]
    out: PathBuf,
    /// The description's name: its file names, fd resource and struct-name prefix. Default: the device node's name
    #[arg(long)]
    name: Option<String>,
    /// The device node to open (`/dev/widget`, or `/dev/widget#` for numbered nodes) when the source does not name one
    #[arg(long, value_name = "PATH")]
    device: Option<String>,
}

pub fn run(args: KernelArgs) -> i32 {
    match args.command {
        KernelCommand::Syzlang(args) => match syzlang(&args) {
            Ok(()) => 0,
            Err(error) => {
                bhfeprintln!("bhf kernel syzlang: {error:#}");
                1
            }
        },
        KernelCommand::Run(args) => run_programs(&args),
        // A findings producer: results/ gets its manifest record and rebuild.
        KernelCommand::Fuzz(args) => crate::with_results(
            &args.work_dir,
            results::import_syzkaller::GUEST_PRODUCER,
            None,
            |_| results::model::ProducerStatus::Complete,
            || fuzz_kernel(&args),
        ),
        KernelCommand::Replay(args) => replay_finding(&args),
        // A findings producer: results/ gets its manifest record and rebuild.
        KernelCommand::Import(args) => crate::with_results(
            &args.work_dir,
            results::import_syzkaller::PRODUCER,
            args.source_root.as_deref(),
            |_| results::model::ProducerStatus::Complete,
            || import(&args),
        ),
    }
}

#[cfg(not(unix))]
fn run_programs(_args: &RunArgs) -> i32 {
    bhfeprintln!("bhf kernel run: the guest lane needs a Linux or other Unix host");
    1
}

#[cfg(unix)]
impl GuestArgs {
    /// The guest's setup, its executor and initramfs built in `dir`.
    fn setup(&self, dir: &Path) -> Result<crate::kernel_guest::GuestSetup> {
        use crate::kernel_guest as guest;
        fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        let executor = match &self.executor {
            Some(path) => {
                anyhow::ensure!(
                    path.is_file(),
                    "--executor {} is not a file",
                    path.display()
                );
                path.clone()
            }
            None => guest::build_executor(&self.cc, dir)?,
        };
        let initrd = dir.join("initramfs.cpio");
        guest::build_initramfs(&executor, &self.modules, &initrd)?;
        Ok(guest::GuestSetup {
            qemu: self.qemu.clone(),
            kernel: self.kernel.clone(),
            initrd,
            memory_mb: self.memory,
            smp: self.smp.max(1),
            accel: self.accel,
            append: self.append.clone(),
            qemu_args: self.qemu_args.clone(),
            boot_timeout: std::time::Duration::from_secs(self.boot_timeout.max(1)),
        })
    }

    fn timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.timeout.max(1))
    }

    /// The guest as a finding records it, for `bhf kernel replay`: what to
    /// boot again, its paths absolute.
    fn record(&self) -> serde_json::Value {
        let absolute = |path: &Path| {
            std::path::absolute(path)
                .unwrap_or_else(|_| path.to_path_buf())
                .display()
                .to_string()
        };
        serde_json::json!({
            "kernel": absolute(&self.kernel),
            "modules": self.modules.iter().map(|module| absolute(module)).collect::<Vec<_>>(),
            "qemu": self.qemu.display().to_string(),
            "accel": self.accel.as_str(),
            "memory_mb": self.memory,
            "smp": self.smp.max(1),
            "append": self.append,
            "qemu_args": self.qemu_args,
            "cc": self.cc,
            "executor": self.executor.as_deref().map(absolute),
            "timeout_secs": self.timeout.max(1),
        })
    }
}

/// The guest a finding records, with `args` replacing what they name.
#[cfg(unix)]
fn replay_guest(record: &serde_json::Value, args: &ReplayArgs) -> Result<GuestArgs> {
    use crate::kernel_guest::Accel;
    let text = |key: &str| record.get(key).and_then(serde_json::Value::as_str);
    let kernel = args
        .kernel
        .clone()
        .or_else(|| text("kernel").map(PathBuf::from))
        .context("the finding records no guest kernel (give --kernel)")?;
    let modules = if args.modules.is_empty() {
        record
            .get("modules")
            .and_then(serde_json::Value::as_array)
            .map(|modules| {
                modules
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(PathBuf::from)
                    .collect()
            })
            .unwrap_or_default()
    } else {
        args.modules.clone()
    };
    let accel = match (args.accel, text("accel")) {
        (Some(accel), _) => accel,
        (None, Some("kvm")) => Accel::Kvm,
        (None, Some("tcg")) => Accel::Tcg,
        _ => Accel::Auto,
    };
    let number = |key: &str| record.get(key).and_then(serde_json::Value::as_u64);
    Ok(GuestArgs {
        kernel,
        modules,
        qemu: args
            .qemu
            .clone()
            .or_else(|| text("qemu").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("qemu-system-x86_64")),
        accel,
        memory: number("memory_mb")
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(1024),
        smp: number("smp")
            .and_then(|n| u32::try_from(n).ok())
            .unwrap_or(1),
        append: text("append").map(str::to_owned),
        qemu_args: record
            .get("qemu_args")
            .and_then(serde_json::Value::as_array)
            .map(|args| {
                args.iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        cc: args
            .cc
            .clone()
            .or_else(|| text("cc").map(str::to_owned))
            .unwrap_or_else(|| "cc".to_owned()),
        executor: args
            .executor
            .clone()
            .or_else(|| text("executor").map(PathBuf::from)),
        boot_timeout: args.boot_timeout,
        timeout: args
            .timeout
            .or_else(|| number("timeout_secs"))
            .unwrap_or(10)
            .clamp(1, crate::kernel_guest::MAX_WAIT_SECS),
    })
}

#[cfg(not(unix))]
fn replay_finding(_args: &ReplayArgs) -> i32 {
    bhfeprintln!("bhf kernel replay: the guest lane needs a Linux or other Unix host");
    2
}

#[cfg(unix)]
fn replay_finding(args: &ReplayArgs) -> i32 {
    match replay_finding_inner(args) {
        Ok(code) => code,
        Err(error) => {
            bhfeprintln!("bhf kernel replay: {error:#}");
            2
        }
    }
}

#[cfg(unix)]
fn replay_finding_inner(args: &ReplayArgs) -> Result<i32> {
    use crate::kernel_guest::{Guest, RunEnd};
    let (dir, finding_json) = if args.finding.is_dir() {
        (args.finding.clone(), args.finding.join("finding.json"))
    } else {
        (
            args.finding
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_default(),
            args.finding.clone(),
        )
    };
    let raw: serde_json::Value = serde_json::from_slice(
        &fs::read(&finding_json).with_context(|| format!("read {}", finding_json.display()))?,
    )
    .with_context(|| format!("parse {}", finding_json.display()))?;
    anyhow::ensure!(
        results::import_syzkaller::is_guest_crash(&raw),
        "{} is not a crash bhf kernel fuzz found in its guest",
        finding_json.display()
    );
    let title = raw["kernel"]["title"]
        .as_str()
        .context("the finding records no crash title")?
        .to_owned();
    let program = read_program(&dir.join(results::import_syzkaller::TESTCASE_FILE))?;
    let guest_args = replay_guest(&raw["kernel"]["guest"], args)?;
    let temp = tempfile::Builder::new()
        .prefix("bhf-kernel-replay-")
        .tempdir()
        .context("create a temporary directory")?;
    let setup = guest_args.setup(temp.path())?;
    let mut guest = Guest::boot(&setup, None)?;
    let run = guest.run(&program, guest_args.timeout());
    drop(guest);
    match results::import_syzkaller::console_report(&run.console) {
        Some(report) if report.title == title => {
            println!("MATCH: {title}");
            Ok(0)
        }
        Some(report) => {
            println!(
                "MISMATCH: the finding records `{title}`; the kernel reported `{}`",
                report.title
            );
            Ok(1)
        }
        None => {
            let how = match &run.end {
                RunEnd::Replied(reply) => format!("the program ran ({})", reply.status.describe()),
                RunEnd::Stopped(reason) => format!("the guest stopped: {reason}"),
                RunEnd::NoReply => "the guest did not answer".to_owned(),
            };
            println!("NOT REPRODUCED: `{title}`: {how}, and the kernel reported nothing");
            Ok(1)
        }
    }
}

/// The name of a Linux errno, for the call results bhf prints.
#[cfg(unix)]
fn errno_name(errno: u32) -> String {
    const NAMES: &[(u32, &str)] = &[
        (1, "EPERM"),
        (2, "ENOENT"),
        (3, "ESRCH"),
        (4, "EINTR"),
        (5, "EIO"),
        (6, "ENXIO"),
        (7, "E2BIG"),
        (9, "EBADF"),
        (11, "EAGAIN"),
        (12, "ENOMEM"),
        (13, "EACCES"),
        (14, "EFAULT"),
        (16, "EBUSY"),
        (17, "EEXIST"),
        (19, "ENODEV"),
        (20, "ENOTDIR"),
        (21, "EISDIR"),
        (22, "EINVAL"),
        (24, "EMFILE"),
        (25, "ENOTTY"),
        (28, "ENOSPC"),
        (29, "ESPIPE"),
        (34, "ERANGE"),
        (38, "ENOSYS"),
        (95, "EOPNOTSUPP"),
    ];
    NAMES
        .iter()
        .find(|(number, _)| *number == errno)
        .map(|(_, name)| (*name).to_owned())
        .unwrap_or_else(|| format!("errno {errno}"))
}

/// Read a program file: at most what the executor takes.
#[cfg(unix)]
fn read_program(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    fs::File::open(path)
        .with_context(|| format!("open {}", path.display()))?
        .take(crate::kernel_guest::MAX_PROGRAM as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() <= crate::kernel_guest::MAX_PROGRAM,
        "{} is larger than a program the executor takes ({} bytes)",
        path.display(),
        crate::kernel_guest::MAX_PROGRAM
    );
    Ok(bytes)
}

/// The calls of `program` with the results `reply` gives them, one line
/// each.
#[cfg(unix)]
fn call_lines(program: &[u8], reply: &crate::kernel_guest::ExecReply) -> Vec<String> {
    let decoded = crate::kernel_guest::decode(program);
    let text = decoded.text();
    text.lines()
        .enumerate()
        .map(|(index, line)| match reply.calls.get(index) {
            Some(call) if call.errno != 0 => format!(
                "{line} = -1 {}  [{} PCs]",
                errno_name(call.errno),
                call.pcs.len()
            ),
            Some(call) => format!("{line} = {:#x}  [{} PCs]", call.ret, call.pcs.len()),
            None => format!("{line}  (not run)"),
        })
        .collect()
}

#[cfg(unix)]
fn run_programs(args: &RunArgs) -> i32 {
    match run_programs_inner(args) {
        Ok(code) => code,
        Err(error) => {
            bhfeprintln!("bhf kernel run: {error:#}");
            1
        }
    }
}

#[cfg(unix)]
fn run_programs_inner(args: &RunArgs) -> Result<i32> {
    use crate::kernel_guest::{Guest, RunEnd};
    let programs = args
        .programs
        .iter()
        .map(|path| Ok((path, read_program(path)?)))
        .collect::<Result<Vec<_>>>()?;
    let temp;
    let dir = match &args.work_dir {
        Some(dir) => dir.join("kernel").join("guest"),
        None => {
            temp = tempfile::Builder::new()
                .prefix("bhf-kernel-run-")
                .tempdir()
                .context("create a temporary directory")?;
            temp.path().to_path_buf()
        }
    };
    let setup = args.guest.setup(&dir)?;
    let console_log = dir.join("console.log");
    let mut guest = Guest::boot(&setup, Some(&console_log))?;
    let hello = guest.hello().clone();
    if !args.json {
        println!(
            "guest: Linux {} {}, {}, KCOV {}",
            hello.release,
            hello.machine,
            guest.accel().as_str(),
            if hello.kcov { "on" } else { "off" }
        );
        for note in hello.notes.lines().filter(|line| !line.trim().is_empty()) {
            println!("  {note}");
        }
    }
    let mut code = 0;
    for (path, program) in &programs {
        let run = guest.run(program, args.guest.timeout());
        let report =
            results::import_syzkaller::console_report(&run.console).map(|report| report.title);
        if let Some(title) = &report {
            if !args.json {
                println!("{}: the kernel reported: {title}", path.display());
            }
            code = 1;
        }
        match &run.end {
            RunEnd::Replied(reply) => {
                if args.json {
                    let calls: Vec<serde_json::Value> = reply
                        .calls
                        .iter()
                        .zip(crate::kernel_guest::decode(program).calls.iter())
                        .map(|(result, call)| {
                            serde_json::json!({
                                "call": call.sys.name(),
                                "result": result.ret,
                                "errno": result.errno,
                                "pcs": result.pcs.len(),
                                "truncated": result.truncated,
                            })
                        })
                        .collect();
                    println!(
                        "{}",
                        serde_json::json!({
                            "program": path.display().to_string(),
                            "status": reply.status.describe(),
                            "decoded": reply.decoded,
                            "calls": calls,
                            "kcov": reply.kcov,
                            "pcs": reply.calls.iter().map(|call| call.pcs.len()).sum::<usize>(),
                            "edges": reply.edges(),
                            "elapsed_ms": run.elapsed.as_millis() as u64,
                            "report": report,
                        })
                    );
                } else {
                    println!(
                        "{}: {} of {} calls ran ({}), {} KCOV edges",
                        path.display(),
                        reply.calls.len(),
                        reply.decoded,
                        reply.status.describe(),
                        reply.edges()
                    );
                    for line in call_lines(program, reply) {
                        println!("  {line}");
                    }
                }
            }
            RunEnd::Stopped(_) | RunEnd::NoReply if args.json => {
                let reason = match &run.end {
                    RunEnd::Stopped(reason) => reason.clone(),
                    _ => "no reply".to_owned(),
                };
                println!(
                    "{}",
                    serde_json::json!({
                        "program": path.display().to_string(),
                        "status": "stopped",
                        "reason": reason,
                        "report": report,
                        "console": run.console,
                    })
                );
                code = 1;
                break;
            }
            end => {
                let reason = match end {
                    RunEnd::Stopped(reason) => reason.clone(),
                    _ => format!(
                        "no reply within {}s",
                        crate::kernel_guest::reply_wait(args.guest.timeout()).as_secs()
                    ),
                };
                println!("{}: the guest stopped: {reason}", path.display());
                let lines: Vec<&str> = run.console.lines().collect();
                for line in &lines[lines.len().saturating_sub(40)..] {
                    println!("  | {line}");
                }
                code = 1;
                break;
            }
        }
    }
    if !args.json {
        if let Some(dir) = &args.work_dir {
            println!(
                "console log: {}",
                dir.join("kernel/guest/console.log").display()
            );
        }
    }
    Ok(code)
}

#[cfg(not(unix))]
fn fuzz_kernel(_args: &KernelFuzzArgs) -> i32 {
    bhfeprintln!("bhf kernel fuzz: the guest lane needs a Linux or other Unix host");
    1
}

#[cfg(unix)]
fn fuzz_kernel(args: &KernelFuzzArgs) -> i32 {
    match fuzz_kernel_inner(args) {
        Ok(code) => code,
        Err(error) => {
            bhfeprintln!("bhf kernel fuzz: {error:#}");
            1
        }
    }
}

/// Most seed files read from one directory.
#[cfg(unix)]
const MAX_SEED_FILES: usize = 10_000;

/// The programs in `dir`, in name order.
#[cfg(unix)]
fn seed_files(dir: &Path) -> Result<Vec<Vec<u8>>> {
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .with_context(|| format!("read {}", dir.display()))?
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .map(|entry| entry.path())
        .take(MAX_SEED_FILES)
        .collect();
    paths.sort();
    paths.iter().map(|path| read_program(path)).collect()
}

#[cfg(unix)]
fn fuzz_kernel_inner(args: &KernelFuzzArgs) -> Result<i32> {
    use crate::kernel_guest as guest;
    let dir = args.work_dir.join("kernel");
    let setup = args.guest.setup(&dir.join("guest"))?;
    let interface = if args.sources.is_empty() {
        None
    } else {
        let interface = driver_interface(&args.sources, args.device.as_deref())?;
        for (name, reason) in &interface.skipped {
            println!("  no seed for {name}: {reason}");
        }
        Some(interface)
    };
    let mut given = Vec::new();
    let mut origin = Vec::new();
    if let Some(seeds) = &args.seeds {
        let programs = seed_files(seeds)?;
        origin.push(format!("{} from {}", programs.len(), seeds.display()));
        given.extend(programs);
    }
    let corpus = dir.join("corpus");
    if corpus.is_dir() {
        let programs = seed_files(&corpus)?;
        origin.push(format!(
            "{} from the corpus of an earlier run",
            programs.len()
        ));
        given.extend(programs);
    }
    let device = args.device.clone();
    let seeds = move |hello: &guest::Hello| -> Result<guest::SeedSet> {
        let mut set = guest::SeedSet::default();
        if let Some(interface) = &interface {
            let crate::kernel_guest::SeedSet {
                programs,
                dictionary,
                ..
            } = interface.seeds(&hello.machine)?;
            set.origin.push(format!(
                "{} from the ioctl commands of {} ({})",
                programs.len(),
                interface.device,
                interface
                    .commands
                    .iter()
                    .map(|command| command.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            set.programs.extend(programs);
            set.dictionary.extend(dictionary);
        } else if let Some(device) = &device {
            set.programs.push(device_program(device)?);
            set.dictionary.push(device.as_bytes().to_vec());
            set.origin.push(format!("1 opening {device}"));
        }
        set.programs.extend(given.iter().cloned());
        set.origin.extend(origin.iter().cloned());
        Ok(set)
    };
    let config = guest::FuzzConfig {
        work_dir: args.work_dir.clone(),
        dir: dir.clone(),
        guest_record: args.guest.record(),
        stop_after_findings: args.stop_after_findings,
        setup,
        iterations: args.iterations.unwrap_or(if args.time.is_some() {
            usize::MAX
        } else {
            1000
        }),
        time_budget: args.time,
        timeout: args.guest.timeout(),
        rng_seed: args.rng_seed,
        max_len: args.max_len,
    };
    let summary = guest::fuzz(&config, &seeds)?;
    for line in fuzz_report(&summary, &args.work_dir) {
        println!("{line}");
    }
    Ok(match &summary.halted {
        Some(reason) => {
            bhfeprintln!("bhf kernel fuzz: stopped early: {reason}");
            1
        }
        None => 0,
    })
}

/// What `bhf kernel fuzz` prints of its campaign: the guest and its setup
/// notes (each module loaded, or why not), the coverage, the crashes and
/// the findings, under `work_dir`.
#[cfg(unix)]
fn fuzz_report(summary: &crate::kernel_guest::FuzzSummary, work_dir: &Path) -> Vec<String> {
    let plural = |count: usize| if count == 1 { "" } else { "s" };
    let mut lines = vec![format!(
        "bhf kernel fuzz: {} executions ({:.1}/s) in Linux {} {} ({}), {} seeds",
        summary.executions,
        summary.executions_per_sec,
        summary.release,
        summary.machine,
        summary.accel,
        summary.seeds
    )];
    for note in &summary.notes {
        lines.push(format!("  guest setup: {note}"));
    }
    lines.push(format!(
        "  coverage: {} KCOV edges ({} after the seeds), corpus {} ({} new)",
        summary.coverage.edges,
        summary.coverage_after_seeds.edges,
        summary.corpus,
        summary.corpus_new
    ));
    lines.push(format!(
        "  {} run{} the guest did not survive, {} boot{}",
        summary.crashes,
        plural(summary.crashes),
        summary.boots,
        plural(summary.boots)
    ));
    for crash in &summary.crash_dirs {
        lines.push(format!("    {}", work_dir.join(crash).display()));
    }
    if !summary.findings.is_empty() {
        lines.push(format!(
            "  {} kernel report{} ({} run{} of a program alone to confirm one), {} finding{}:",
            summary.reports,
            plural(summary.reports),
            summary.confirm_runs,
            plural(summary.confirm_runs),
            summary.findings.len(),
            plural(summary.findings.len())
        ));
        for id in &summary.findings {
            let finding = work_dir
                .join("results/findings")
                .join(id)
                .join("finding.json");
            let raw: serde_json::Value = fs::read(&finding)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .unwrap_or_default();
            let confirmed = match raw["kernel"]["unconfirmed"].as_str() {
                _ if raw["kernel"]["reproduced"] == true => {
                    "the program alone made it again".to_owned()
                }
                Some(why) => format!("not confirmed: {why}"),
                None => "not made again by the program alone".to_owned(),
            };
            lines.push(format!(
                "    {id}: {} ({confirmed})",
                raw["message"].as_str().unwrap_or("?")
            ));
        }
    }
    if !summary.kcov {
        lines.push(
            "  KCOV is off in the guest (no coverage): build the kernel with CONFIG_KCOV and \
             CONFIG_DEBUG_FS"
                .to_owned(),
        );
    }
    lines.push(format!(
        "  summary: {}",
        work_dir.join("kernel").join("fuzz.json").display()
    ));
    lines
}

// ── Kernel crash findings in the generic triage commands ────────────────

/// Most bytes of a finding's program.txt `bhf explain` reads.
const MAX_PROGRAM_TEXT: u64 = 64 << 10;
/// Most calls of it `bhf explain` prints.
const PROGRAM_LINES_SHOWN: usize = 40;

/// The `finding.json` of `finding_dir` when it is a kernel crash's (one
/// `bhf kernel fuzz` found in its guest, or one `bhf kernel import` brought
/// in from syzkaller).
fn kernel_crash_record(finding_dir: &Path) -> Option<serde_json::Value> {
    use std::io::Read;
    let mut bytes = Vec::new();
    fs::File::open(finding_dir.join("finding.json"))
        .ok()?
        .take(16 << 20)
        .read_to_end(&mut bytes)
        .ok()?;
    let raw: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    results::import_syzkaller::is_kernel_crash(&raw).then_some(raw)
}

/// Why `bhf <command>` (replay, minimize), which runs a harness, does not
/// take the kernel crash finding in `finding_dir`, and what reproduces it
/// instead. `None` for any other finding.
pub(crate) fn harness_command_refusal(command: &str, finding_dir: &Path) -> Option<String> {
    let raw = kernel_crash_record(finding_dir)?;
    let id = raw["id"].as_str().unwrap_or("the finding");
    let dir = crate::repro_lane::host_word(&finding_dir.to_string_lossy());
    Some(if results::import_syzkaller::is_guest_crash(&raw) {
        format!(
            "{id} is a kernel crash bhf kernel fuzz found in a qemu-system guest, which no \
             harness runs, so bhf {command} does not take it: `bhf kernel replay {dir}` boots \
             the guest it was found in and runs its program (testcase.bin; repro.c makes the \
             same calls)"
        )
    } else {
        let how = match imported_reproduce_command(finding_dir, &raw) {
            Some(reproduce) => {
                format!("run `{reproduce}` from the results directory in the kernel's test VM")
            }
            None => format!(
                "syzkaller found no reproducer; {} holds the programs it ran before the crash",
                results::import_syzkaller::CONSOLE_FILE
            ),
        };
        format!(
            "{id} is a kernel crash syzkaller found (bhf kernel import), which no harness runs, \
             so bhf {command} does not take it: {how}"
        )
    })
}

/// The reproduce command of an imported syzkaller crash, relative to
/// `results/`.
fn imported_reproduce_command(finding_dir: &Path, raw: &serde_json::Value) -> Option<String> {
    use results::import_syzkaller::{reproduce_command, C_REPRO_FILE, SYZ_REPRO_FILE};
    reproduce_command(
        raw["id"].as_str()?,
        raw,
        finding_dir.join(C_REPRO_FILE).is_file(),
        finding_dir.join(SYZ_REPRO_FILE).is_file(),
    )
}

/// What `bhf explain` says of a kernel crash finding in place of a
/// harness's arguments: the program's calls, from program.txt (a guest
/// crash's; an imported one has none). Empty for any other finding.
pub(crate) fn program_lines(finding_dir: &Path) -> Vec<String> {
    use std::io::Read;
    if kernel_crash_record(finding_dir).is_none() {
        return Vec::new();
    }
    let mut text = String::new();
    let read = fs::File::open(finding_dir.join(results::import_syzkaller::PROGRAM_FILE))
        .and_then(|file| file.take(MAX_PROGRAM_TEXT).read_to_string(&mut text));
    if read.is_err() || text.trim().is_empty() {
        return Vec::new();
    }
    let calls: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    let mut lines = vec![format!(
        "\nTHE PROGRAM  ({}: the calls {} makes, in order)",
        results::import_syzkaller::PROGRAM_FILE,
        results::import_syzkaller::TESTCASE_FILE
    )];
    lines.extend(
        calls
            .iter()
            .take(PROGRAM_LINES_SHOWN)
            .map(|call| format!("  {}", crate::terminal_text::terminal_safe(call))),
    );
    if calls.len() > PROGRAM_LINES_SHOWN {
        lines.push(format!(
            "  ... and {} more",
            calls.len() - PROGRAM_LINES_SHOWN
        ));
    }
    lines
}

/// `bhf explain`'s REPRODUCE OFFLINE lines for a kernel crash finding:
/// `bhf kernel replay` and repro.c for one `bhf kernel fuzz` found, the
/// syzkaller reproducer for an imported one. `None` for any other finding.
pub(crate) fn reproduce_lines(finding_dir: &Path) -> Option<Vec<String>> {
    let raw = kernel_crash_record(finding_dir)?;
    let mut lines = Vec::new();
    if results::import_syzkaller::is_guest_crash(&raw) {
        let dir = crate::repro_lane::host_word(&finding_dir.to_string_lossy());
        let repro = crate::repro_lane::host_word(
            &finding_dir
                .join(results::import_syzkaller::C_REPRO_FILE)
                .to_string_lossy(),
        );
        lines.push(format!(
            "bhf kernel replay {dir}   # boots the guest it was found in and runs testcase.bin"
        ));
        lines.push(format!(
            "cc -static -o repro {repro}   # the same calls; run ./repro in a guest of the same \
             kernel and modules"
        ));
        let kernel = &raw["kernel"];
        if kernel["reproduced"] != true {
            lines.push(match kernel["unconfirmed"].as_str() {
                Some(why) => format!("(not confirmed when it was found: {why})"),
                None => "(its program alone did not make the report again in a freshly booted \
                         guest when it was found: the crash may depend on what ran before it)"
                    .to_owned(),
            });
        }
    } else {
        match imported_reproduce_command(finding_dir, &raw) {
            Some(command) => {
                lines.push("In the kernel's test VM, from the results directory:".to_owned());
                lines.push(format!("  {command}"));
            }
            None => lines.push(format!(
                "syzkaller found no reproducer; {} holds the programs it ran before the crash.",
                results::import_syzkaller::CONSOLE_FILE
            )),
        }
    }
    Some(lines)
}

/// `O_RDWR`, which the seeds open device nodes with.
#[cfg(unix)]
const O_RDWR: u64 = 2;
/// `AT_FDCWD`.
#[cfg(unix)]
const AT_FDCWD: u64 = -100i64 as u64;

/// A program that opens `device` and reads, writes and makes an ioctl on
/// it.
#[cfg(unix)]
fn device_program(device: &str) -> Result<Vec<u8>> {
    use crate::kernel_guest::{ProgramBuilder, SeedArg};
    let mut path = device.as_bytes().to_vec();
    path.push(0);
    let mut program = ProgramBuilder::default();
    let fd = program.call(
        "openat",
        &[
            SeedArg::Const(AT_FDCWD),
            SeedArg::Data(&path),
            SeedArg::Const(O_RDWR),
            SeedArg::Const(0),
        ],
    )?;
    program.call(
        "read",
        &[SeedArg::Result(fd), SeedArg::Out(64), SeedArg::Const(64)],
    )?;
    program.call(
        "write",
        &[
            SeedArg::Result(fd),
            SeedArg::Data(&[0; 16]),
            SeedArg::Const(16),
        ],
    )?;
    program.call(
        "ioctl",
        &[
            SeedArg::Result(fd),
            SeedArg::Const(0),
            SeedArg::Data(&[0; 64]),
        ],
    )?;
    program.call("close", &[SeedArg::Result(fd)])?;
    Ok(program.finish())
}

#[cfg(unix)]
/// One ioctl command of a driver, for seed programs.
#[derive(Debug, Clone)]
struct DriverCommand {
    name: String,
    /// `None` for a plain-number command, whose argument bhf does not know.
    dir: Option<Dir>,
    /// Per architecture of [`ARCHES`]: the command's number and its
    /// argument's size, when they could be computed.
    numbers: Vec<Option<(u64, u64)>>,
}

#[cfg(unix)]
/// A driver's ioctl interface: its device node and commands.
#[derive(Debug, Clone)]
struct DriverInterface {
    device: String,
    commands: Vec<DriverCommand>,
    /// Commands left out, and why.
    skipped: Vec<(String, String)>,
}

#[cfg(unix)]
/// The architecture of [`ARCHES`] a guest's `uname -m` names.
fn arch_index(machine: &str) -> Option<usize> {
    let name = match machine {
        "x86_64" | "amd64" => "amd64",
        "i386" | "i486" | "i586" | "i686" => "386",
        "aarch64" | "arm64" => "arm64",
        machine if machine.starts_with("arm") => "arm",
        "riscv64" => "riscv64",
        "ppc64le" => "ppc64le",
        "mips64" | "mips64el" => "mips64le",
        "s390x" => "s390x",
        "loongarch64" => "loong64",
        _ => return None,
    };
    ARCHES.iter().position(|arch| arch.name == name)
}

#[cfg(unix)]
/// The ioctl interface of the driver `sources` hold, as `bhf kernel
/// syzlang` reads it; `device` names its node when the source does not.
fn driver_interface(sources: &[PathBuf], device: Option<&str>) -> Result<DriverInterface> {
    let corpus = Corpus::read(sources)?;
    for warning in &corpus.warnings {
        bhfeprintln!("bhf kernel: warning: {warning}");
    }
    let handlers = find_handlers(&corpus);
    if handlers.is_empty() {
        bail!(
            "no ioctl handler found in the source read: no `struct file_operations` registers \
             an .unlocked_ioctl or .compat_ioctl, and no function takes (struct file *, \
             unsigned int, unsigned long)"
        );
    }
    let mut names = Vec::new();
    for handler in &handlers {
        for command in handled_commands(&corpus, &handler.function) {
            if !names.contains(&command) {
                names.push(command);
            }
        }
    }
    if names.is_empty() {
        names = all_ioc_commands(&corpus);
    }
    let device = match device {
        Some(device) => device.to_owned(),
        None => find_device_nodes(&corpus)
            .into_iter()
            .map(|node| node.path.replace('#', "0"))
            .next()
            .ok_or_else(|| {
                anyhow::anyhow!("the source names no device node; give it with --device")
            })?,
    };
    let mut interface = DriverInterface {
        device,
        commands: Vec::new(),
        skipped: Vec::new(),
    };
    for name in names {
        let Some(def) = command_def(&corpus, &name, true) else {
            continue;
        };
        let command = match &def.shape {
            CommandShape::Plain => eval(&corpus, &def.value)
                .ok()
                .and_then(|value| u64::try_from(value).ok())
                .filter(|value| *value <= u64::from(u32::MAX))
                .map(|value| DriverCommand {
                    name: name.clone(),
                    dir: None,
                    numbers: vec![Some((value, 0)); ARCHES.len()],
                })
                .ok_or_else(|| format!("`{}` is not a 32-bit ioctl number", def.value)),
            CommandShape::Ioc { dir, kind, nr, arg } => (|| {
                let kind = u64::try_from(eval(&corpus, kind)?)
                    .map_err(|_| format!("type `{kind}` is negative"))?;
                let nr = u64::try_from(eval(&corpus, nr)?)
                    .map_err(|_| format!("number `{nr}` is negative"))?;
                let ty = arg
                    .as_deref()
                    .map(|arg| parse_type(&corpus, arg))
                    .transpose()?;
                let numbers = ARCHES
                    .iter()
                    .map(|arch| {
                        let size = match &ty {
                            Some(ty) => layout(&corpus, ty, arch, 0).ok()?.0,
                            None => 0,
                        };
                        Some((ioc(arch, *dir, kind, nr, size).ok()?, size))
                    })
                    .collect();
                Ok(DriverCommand {
                    name: name.clone(),
                    dir: Some(*dir),
                    numbers,
                })
            })(),
        };
        match command {
            Ok(command) => interface.commands.push(command),
            Err(reason) => interface.skipped.push((name, reason)),
        }
    }
    if interface.commands.is_empty() {
        bail!(
            "the driver's handlers dispatch on no ioctl command bhf could compute{}",
            interface
                .skipped
                .iter()
                .map(|(name, reason)| format!("; {name}: {reason}"))
                .collect::<String>()
        );
    }
    Ok(interface)
}

#[cfg(unix)]
impl DriverInterface {
    /// Seed programs for a guest whose `uname -m` is `machine`: one per
    /// command, opening the device and calling it with a zeroed argument of
    /// its size, and one calling every command; and the dictionary: the
    /// commands' numbers (as 4- and 8-byte words) and the device's path.
    fn seeds(&self, machine: &str) -> Result<crate::kernel_guest::SeedSet> {
        use crate::kernel_guest::{ProgramBuilder, SeedArg, MAX_ARG_BYTES, MAX_CALLS};
        let arch = arch_index(machine).unwrap_or(DEFAULT_ARCH);
        let mut path = self.device.as_bytes().to_vec();
        path.push(0);
        let zeros = vec![0u8; MAX_ARG_BYTES];
        let open = |program: &mut ProgramBuilder| {
            program.call(
                "openat",
                &[
                    SeedArg::Const(AT_FDCWD),
                    SeedArg::Data(&path),
                    SeedArg::Const(O_RDWR),
                    SeedArg::Const(0),
                ],
            )
        };
        let call = |program: &mut ProgramBuilder, fd: usize, command: &DriverCommand| {
            let Some((number, size)) = command.numbers[arch] else {
                return Ok(false);
            };
            let size = (size as usize).min(MAX_ARG_BYTES);
            let arg = match command.dir {
                None => SeedArg::Data(&zeros[..64]),
                Some(Dir::None) => SeedArg::Const(0),
                Some(Dir::Read) if size > 0 => SeedArg::Out(size as u16),
                Some(_) if size > 0 => SeedArg::Data(&zeros[..size]),
                Some(_) => SeedArg::Const(0),
            };
            program
                .call("ioctl", &[SeedArg::Result(fd), SeedArg::Const(number), arg])
                .map(|_| true)
        };
        let mut programs = Vec::new();
        let mut all = ProgramBuilder::default();
        let all_fd = open(&mut all)?;
        let mut in_all = 0;
        let mut dictionary = vec![self.device.as_bytes().to_vec()];
        for command in &self.commands {
            let mut program = ProgramBuilder::default();
            let fd = open(&mut program)?;
            if call(&mut program, fd, command)? {
                programs.push(program.finish());
                if in_all + 1 < MAX_CALLS && call(&mut all, all_fd, command)? {
                    in_all += 1;
                }
            }
            if let Some((number, _)) = command.numbers[arch] {
                dictionary.push((number as u32).to_le_bytes().to_vec());
                dictionary.push(number.to_le_bytes().to_vec());
            }
        }
        if in_all > 1 {
            programs.push(all.finish());
        }
        Ok(crate::kernel_guest::SeedSet {
            programs,
            dictionary,
            origin: Vec::new(),
        })
    }
}

fn import(args: &ImportArgs) -> i32 {
    let mut dirs = Vec::new();
    for path in &args.crashes {
        match results::import_syzkaller::crash_dirs(path) {
            Ok(found) if found.is_empty() => bhfeprintln!(
                "bhf kernel import: {}: no syzkaller crash directory (one with a description \
                 file) here or under its crashes/",
                path.display()
            ),
            Ok(found) => dirs.extend(found),
            Err(error) => {
                bhfeprintln!("bhf kernel import: {error}");
                return 1;
            }
        }
    }
    if dirs.is_empty() {
        bhfeprintln!("bhf kernel import: nothing to import");
        return 1;
    }
    let summary = match results::import_syzkaller::import(&args.work_dir, &dirs) {
        Ok(summary) => summary,
        Err(error) => {
            bhfeprintln!("bhf kernel import: {error}");
            return 1;
        }
    };
    for crash in &summary.imported {
        println!(
            "{} {}: {} ({}, reproducer: {})",
            if crash.updated { "updated" } else { "imported" },
            crash.id,
            crash.title,
            crash.class,
            crash.reproducer.unwrap_or("none")
        );
    }
    for (dir, reason) in &summary.skipped {
        println!("skipped {}: {reason}", dir.display());
    }
    println!(
        "bhf kernel import: {} crash{} imported, {} skipped",
        summary.imported.len(),
        if summary.imported.len() == 1 {
            ""
        } else {
            "es"
        },
        summary.skipped.len()
    );
    if summary.imported.is_empty() {
        1
    } else {
        0
    }
}

fn syzlang(args: &SyzlangArgs) -> Result<()> {
    let corpus = Corpus::read(&args.sources)?;
    for warning in &corpus.warnings {
        bhfeprintln!("bhf kernel syzlang: warning: {warning}");
    }
    let description = describe(&corpus, args.name.as_deref(), args.device.as_deref())?;
    fs::create_dir_all(&args.out).with_context(|| format!("create {}", args.out.display()))?;
    let txt = args.out.join(format!("dev_{}.txt", description.name));
    let consts = args.out.join(format!("dev_{}.txt.const", description.name));
    fs::write(&txt, &description.syzlang).with_context(|| format!("write {}", txt.display()))?;
    fs::write(&consts, &description.consts)
        .with_context(|| format!("write {}", consts.display()))?;
    println!(
        "bhf kernel syzlang: described {} ioctl command{} of {}",
        description.described,
        if description.described == 1 { "" } else { "s" },
        description.handlers.join(", ")
    );
    println!("  wrote {}", txt.display());
    println!("  wrote {}", consts.display());
    for (name, reason) in &description.skipped {
        println!("  not described: {name}: {reason}");
    }
    Ok(())
}

// ── Reading the source ───────────────────────────────────────────────────

/// Most files one run reads.
const MAX_FILES: usize = 20_000;
/// Larger files are generated tables, not a driver's source.
const MAX_FILE_BYTES: u64 = 4 << 20;
/// Deepest directory nesting walked.
const MAX_DEPTH: usize = 64;

struct SourceFile {
    /// The path as the description names it: relative to the SOURCE it was
    /// found under, `/`-separated.
    display: String,
    facts: CIoctlFacts,
}

/// Every fact of the files read, indexed by name (the first definition of a
/// name wins, files in the order given, directories sorted).
#[derive(Default)]
struct Corpus {
    files: Vec<SourceFile>,
    macros: HashMap<String, (usize, usize)>,
    records: HashMap<String, (usize, usize)>,
    typedefs: HashMap<String, String>,
    functions: HashMap<String, (usize, usize)>,
    warnings: Vec<String>,
    /// Each macro's value, evaluated once: a header whose macros fan out
    /// (`#define A (B + B)`) costs its size, not the size of its expansion.
    values: RefCell<HashMap<String, Result<i128, String>>>,
    /// The macros being evaluated, to refuse one that expands into itself.
    evaluating: RefCell<HashSet<String>>,
    /// Each record's layout per architecture, computed once, as `values`.
    layouts: RefCell<HashMap<(String, &'static str), LayoutResult>>,
}

/// `(size, align)` in bytes, or why the type cannot be laid out.
type LayoutResult = Result<(u64, u64), String>;

impl Corpus {
    fn read(sources: &[PathBuf]) -> Result<Self> {
        let mut paths = Vec::new();
        let mut truncated = false;
        for source in sources {
            let meta =
                fs::metadata(source).with_context(|| format!("read {}", source.display()))?;
            if meta.is_dir() {
                walk(source, source, 0, &mut paths, &mut truncated)
                    .with_context(|| format!("read {}", source.display()))?;
            } else {
                let display = source
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_else(|| source.display().to_string());
                paths.push((source.clone(), display));
            }
        }
        let mut corpus = Corpus::default();
        if truncated {
            corpus.warnings.push(format!(
                "read the first {MAX_FILES} source files only; name the driver's own directory"
            ));
        }
        for (path, display) in paths {
            let size = fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0);
            if size > MAX_FILE_BYTES {
                corpus
                    .warnings
                    .push(format!("{display}: skipped ({size} bytes)"));
                continue;
            }
            let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            match c_parser::parse_ioctl_facts(&String::from_utf8_lossy(&bytes)) {
                Ok(facts) => corpus.add(SourceFile { display, facts }),
                Err(error) => corpus.warnings.push(format!("{display}: {error}")),
            }
        }
        Ok(corpus)
    }

    fn add(&mut self, file: SourceFile) {
        let index = self.files.len();
        for (at, def) in file.facts.macros.iter().enumerate() {
            self.macros.entry(def.name.clone()).or_insert((index, at));
        }
        for (at, record) in file.facts.records.iter().enumerate() {
            self.records
                .entry(record.name.clone())
                .or_insert((index, at));
        }
        for typedef in &file.facts.typedefs {
            self.typedefs
                .entry(typedef.name.clone())
                .or_insert_with(|| typedef.underlying.clone());
        }
        for (at, function) in file.facts.functions.iter().enumerate() {
            self.functions
                .entry(function.name.clone())
                .or_insert((index, at));
        }
        self.files.push(file);
    }

    fn macro_def(&self, name: &str) -> Option<(&c_parser::CMacroDef, &SourceFile)> {
        let (file, at) = *self.macros.get(name)?;
        Some((&self.files[file].facts.macros[at], &self.files[file]))
    }

    fn record(&self, name: &str) -> Option<&CRecordDef> {
        let (file, at) = *self.records.get(name)?;
        Some(&self.files[file].facts.records[at])
    }

    /// The value of macro `name`, expanded at `depth`.
    fn macro_value(&self, name: &str, depth: usize) -> Result<i128, String> {
        if let Some(value) = self.values.borrow().get(name) {
            return value.clone();
        }
        if !self.evaluating.borrow_mut().insert(name.to_owned()) {
            return Err(format!("`{name}` expands into itself"));
        }
        let value = match self.macro_def(name) {
            Some((def, _)) => eval_at(self, &def.value, depth),
            None => Err(format!("`{name}` is not defined in the scanned source")),
        };
        self.evaluating.borrow_mut().remove(name);
        // How deep an expansion got depends on where it started.
        if !value
            .as_ref()
            .is_err_and(|error| error.contains(DEPTH_ERROR))
        {
            self.values
                .borrow_mut()
                .insert(name.to_owned(), value.clone());
        }
        value
    }

    fn function(&self, name: &str) -> Option<(&CDispatchFunction, &SourceFile)> {
        let (file, at) = *self.functions.get(name)?;
        Some((&self.files[file].facts.functions[at], &self.files[file]))
    }
}

fn walk(
    root: &Path,
    dir: &Path,
    depth: usize,
    out: &mut Vec<(PathBuf, String)>,
    truncated: &mut bool,
) -> std::io::Result<()> {
    if depth > MAX_DEPTH {
        return Ok(());
    }
    let mut entries: Vec<_> = fs::read_dir(dir)?.flatten().collect();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        if out.len() >= MAX_FILES {
            *truncated = true;
            return Ok(());
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        if kind.is_dir() && !name.starts_with('.') {
            walk(root, &path, depth + 1, out, truncated)?;
        } else if kind.is_file() && (name.ends_with(".c") || name.ends_with(".h")) {
            let display = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .components()
                .map(|part| part.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            out.push((path, display));
        }
    }
    Ok(())
}

// ── Constant expressions ─────────────────────────────────────────────────

/// Deepest macro expansion or typedef chain followed.
const MAX_EXPANSION: usize = 32;
/// Deepest nesting of struct, union and array types laid out.
const MAX_NESTING: usize = 64;
/// What every error about a depth limit says, so it is never memoized.
const DEPTH_ERROR: &str = "too deep";

/// The value of a C integer constant expression, macros expanded from the
/// corpus: literals (decimal, hex, octal, binary, character), `+ - * / % <<
/// >> & | ^ ~ !`, parentheses, and casts to an integer type.
fn eval(corpus: &Corpus, expr: &str) -> Result<i128, String> {
    eval_at(corpus, expr, 0)
}

fn eval_at(corpus: &Corpus, expr: &str, depth: usize) -> Result<i128, String> {
    if depth > MAX_EXPANSION {
        return Err(format!(
            "`{expr}` expands macros {DEPTH_ERROR} (more than {MAX_EXPANSION})"
        ));
    }
    let tokens = tokenize(expr)?;
    let mut parser = ExprParser {
        corpus,
        tokens: &tokens,
        at: 0,
        depth,
    };
    let value = parser.or()?;
    if parser.at != tokens.len() {
        return Err(format!(
            "`{expr}` is not an integer constant bhf can evaluate"
        ));
    }
    Ok(value)
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Number(i128),
    Ident(String),
    Punct(&'static str),
}

fn tokenize(expr: &str) -> Result<Vec<Token>, String> {
    const PUNCTS: [&str; 15] = [
        "<<", ">>", "(", ")", "+", "-", "*", "/", "%", "&", "|", "^", "~", "!", ",",
    ];
    let bytes = expr.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_whitespace() {
            i += 1;
        } else if c.is_ascii_digit() {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            tokens.push(Token::Number(integer_literal(&expr[start..i])?));
        } else if c.is_ascii_alphabetic() || c == b'_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            tokens.push(Token::Ident(expr[start..i].to_owned()));
        } else if c == b'\'' {
            let (value, end) = char_literal(expr, i)?;
            tokens.push(Token::Number(value));
            i = end;
        } else if let Some(punct) = PUNCTS.iter().find(|p| expr[i..].starts_with(**p)) {
            tokens.push(Token::Punct(punct));
            i += punct.len();
        } else {
            return Err(format!(
                "`{expr}` is not an integer constant bhf can evaluate"
            ));
        }
    }
    Ok(tokens)
}

fn integer_literal(text: &str) -> Result<i128, String> {
    let digits = text.trim_end_matches(['u', 'U', 'l', 'L']);
    let parsed = if let Some(hex) = digits.strip_prefix("0x").or(digits.strip_prefix("0X")) {
        i128::from_str_radix(hex, 16)
    } else if let Some(binary) = digits.strip_prefix("0b").or(digits.strip_prefix("0B")) {
        i128::from_str_radix(binary, 2)
    } else if digits.len() > 1 && digits.starts_with('0') {
        i128::from_str_radix(&digits[1..], 8)
    } else {
        digits.parse::<i128>()
    };
    parsed.map_err(|_| format!("`{text}` is not an integer literal"))
}

/// A character literal at `start` (`'W'`, `'\n'`, `'\x57'`, `'\127'`) and
/// the index past it.
fn char_literal(expr: &str, start: usize) -> Result<(i128, usize), String> {
    let bad = || format!("`{expr}` holds a character literal bhf cannot read");
    let rest = &expr[start + 1..];
    // `'\''` closes one quote later.
    let close = match rest.strip_prefix("\\'") {
        Some(after) => after.find('\'').map(|at| at + 2),
        None => rest.find('\''),
    }
    .ok_or_else(bad)?;
    let body = &rest[..close];
    let value = match body.strip_prefix('\\') {
        None => {
            let mut chars = body.chars();
            match (chars.next(), chars.next()) {
                (Some(ch), None) if ch.is_ascii() => ch as i128,
                _ => return Err(bad()),
            }
        }
        Some(escape) => match escape {
            "n" => 10,
            "t" => 9,
            "r" => 13,
            "0" => 0,
            "\\" => 92,
            "'" => 39,
            "\"" => 34,
            "a" => 7,
            "b" => 8,
            "f" => 12,
            "v" => 11,
            _ => match escape.strip_prefix('x') {
                Some(hex) => i128::from_str_radix(hex, 16).map_err(|_| bad())?,
                None if escape.bytes().all(|b| (b'0'..=b'7').contains(&b)) => {
                    i128::from_str_radix(escape, 8).map_err(|_| bad())?
                }
                None => return Err(bad()),
            },
        },
    };
    Ok((value, start + 1 + close + 1))
}

struct ExprParser<'a> {
    corpus: &'a Corpus,
    tokens: &'a [Token],
    at: usize,
    depth: usize,
}

impl ExprParser<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    fn eat(&mut self, punct: &str) -> bool {
        if matches!(self.peek(), Some(Token::Punct(p)) if *p == punct) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn binary(
        &mut self,
        ops: &[&'static str],
        next: fn(&mut Self) -> Result<i128, String>,
    ) -> Result<i128, String> {
        let mut value = next(self)?;
        'outer: loop {
            for op in ops {
                if self.eat(op) {
                    let rhs = next(self)?;
                    value = apply(op, value, rhs)?;
                    continue 'outer;
                }
            }
            return Ok(value);
        }
    }

    fn or(&mut self) -> Result<i128, String> {
        self.binary(&["|"], Self::xor)
    }

    fn xor(&mut self) -> Result<i128, String> {
        self.binary(&["^"], Self::and)
    }

    fn and(&mut self) -> Result<i128, String> {
        self.binary(&["&"], Self::shift)
    }

    fn shift(&mut self) -> Result<i128, String> {
        self.binary(&["<<", ">>"], Self::additive)
    }

    fn additive(&mut self) -> Result<i128, String> {
        self.binary(&["+", "-"], Self::multiplicative)
    }

    fn multiplicative(&mut self) -> Result<i128, String> {
        self.binary(&["*", "/", "%"], Self::unary)
    }

    fn unary(&mut self) -> Result<i128, String> {
        if self.eat("-") {
            let value = self.unary()?;
            return value
                .checked_neg()
                .ok_or_else(|| format!("`-({value})` overflows"));
        }
        if self.eat("+") {
            return self.unary();
        }
        if self.eat("~") {
            return Ok(!self.unary()?);
        }
        if self.eat("!") {
            return Ok(i128::from(self.unary()? == 0));
        }
        self.primary()
    }

    fn primary(&mut self) -> Result<i128, String> {
        match self.peek().cloned() {
            Some(Token::Number(value)) => {
                self.at += 1;
                Ok(value)
            }
            Some(Token::Ident(name)) => {
                self.at += 1;
                self.corpus.macro_value(&name, self.depth + 1)
            }
            Some(Token::Punct("(")) => {
                self.at += 1;
                // A cast to an integer type: `(unsigned int)x`, `(__u32)x`.
                let close = self.tokens[self.at..]
                    .iter()
                    .position(|token| *token == Token::Punct(")"));
                if let Some(close) = close {
                    let words: Option<Vec<&str>> = self.tokens[self.at..self.at + close]
                        .iter()
                        .map(|token| match token {
                            Token::Ident(word) => Some(word.as_str()),
                            _ => None,
                        })
                        .collect();
                    if let Some(words) = words.filter(|words| !words.is_empty()) {
                        if scalar_type(&words.join(" ")).is_some() {
                            self.at += close + 1;
                            return self.unary();
                        }
                    }
                }
                let value = self.or()?;
                if !self.eat(")") {
                    return Err("an unclosed `(`".to_owned());
                }
                Ok(value)
            }
            _ => Err("an incomplete expression".to_owned()),
        }
    }
}

fn apply(op: &str, lhs: i128, rhs: i128) -> Result<i128, String> {
    let overflow = || format!("`{lhs} {op} {rhs}` overflows");
    match op {
        "|" => Ok(lhs | rhs),
        "^" => Ok(lhs ^ rhs),
        "&" => Ok(lhs & rhs),
        "<<" if (0..64).contains(&rhs) => lhs.checked_shl(rhs as u32).ok_or_else(overflow),
        ">>" if (0..128).contains(&rhs) => Ok(lhs >> rhs),
        "+" => lhs.checked_add(rhs).ok_or_else(overflow),
        "-" => lhs.checked_sub(rhs).ok_or_else(overflow),
        "*" => lhs.checked_mul(rhs).ok_or_else(overflow),
        "/" if rhs != 0 => lhs.checked_div(rhs).ok_or_else(overflow),
        "%" if rhs != 0 => lhs.checked_rem(rhs).ok_or_else(overflow),
        _ => Err(format!("`{lhs} {op} {rhs}` is undefined")),
    }
}

// ── Types and layouts ────────────────────────────────────────────────────

/// A C type as far as a syzkaller description and an ioctl number need it.
#[derive(Debug, Clone, PartialEq)]
enum KType {
    /// A fixed-width integer (floating point is described as its bits).
    /// `always_aligned`: `__aligned_u64` and its kin, 8-aligned even where
    /// the ABI aligns a 64-bit integer to 4 (i386).
    Int {
        bytes: u8,
        big_endian: bool,
        always_aligned: bool,
    },
    /// `long`, `size_t` and the other pointer-wide integers.
    Long,
    Pointer(Box<KType>),
    /// `void`: only behind a pointer.
    Void,
    /// `None`: a flexible array member (`[]` or `[0]`).
    Array(Box<KType>, Option<u64>),
    /// A struct or union the corpus defines, by its C name.
    Record(String),
    Enum,
    FuncPtr,
    /// A type the corpus does not define: only behind a pointer.
    Opaque(String),
}

fn int(bytes: u8) -> KType {
    KType::Int {
        bytes,
        big_endian: false,
        always_aligned: false,
    }
}

/// Integer spellings by width, kernel and uapi spellings included.
const INT8: &[&str] = &[
    "char",
    "signed char",
    "unsigned char",
    "__u8",
    "__s8",
    "u8",
    "s8",
    "uint8_t",
    "int8_t",
    "bool",
    "_Bool",
];
const INT16: &[&str] = &[
    "short",
    "short int",
    "signed short",
    "signed short int",
    "unsigned short",
    "unsigned short int",
    "__u16",
    "__s16",
    "u16",
    "s16",
    "uint16_t",
    "int16_t",
    "__le16",
    "__sum16",
];
const INT32: &[&str] = &[
    "int",
    "signed",
    "signed int",
    "unsigned",
    "unsigned int",
    "__u32",
    "__s32",
    "u32",
    "s32",
    "uint32_t",
    "int32_t",
    "__le32",
    "__wsum",
    "__poll_t",
    "float",
    "pid_t",
    "__kernel_pid_t",
    "uid_t",
    "gid_t",
    "__kernel_uid32_t",
    "__kernel_gid32_t",
    "__kernel_mode_t",
    "mode_t",
    "__kernel_key_t",
    "key_t",
    "__kernel_daddr_t",
    "__kernel_timer_t",
    "__kernel_clockid_t",
    "clockid_t",
];
const INT64: &[&str] = &[
    "long long",
    "long long int",
    "signed long long",
    "signed long long int",
    "unsigned long long",
    "unsigned long long int",
    "__u64",
    "__s64",
    "u64",
    "s64",
    "uint64_t",
    "int64_t",
    "__le64",
    "double",
    "loff_t",
    "__kernel_loff_t",
    "__kernel_time64_t",
    "time64_t",
];
/// The pointer-wide integers.
const LONG: &[&str] = &[
    "long",
    "long int",
    "signed long",
    "signed long int",
    "unsigned long",
    "unsigned long int",
    "size_t",
    "ssize_t",
    "uintptr_t",
    "intptr_t",
    "ptrdiff_t",
    "__kernel_size_t",
    "__kernel_ssize_t",
    "__kernel_long_t",
    "__kernel_ulong_t",
    "__kernel_off_t",
    "off_t",
    "__kernel_ptrdiff_t",
    "__kernel_old_time_t",
    "time_t",
    "__kernel_suseconds_t",
    "__kernel_clock_t",
];

/// The scalar a C spelling names.
fn scalar_type(spelling: &str) -> Option<KType> {
    let fixed = |bytes: u8, big_endian: bool, always_aligned: bool| KType::Int {
        bytes,
        big_endian,
        always_aligned,
    };
    let ty = match spelling {
        "__be16" => fixed(2, true, false),
        "__be32" => fixed(4, true, false),
        "__be64" => fixed(8, true, false),
        "__aligned_u64" | "__aligned_s64" | "__aligned_le64" => fixed(8, false, true),
        "__aligned_be64" => fixed(8, true, true),
        _ if INT8.contains(&spelling) => int(1),
        _ if INT16.contains(&spelling) => int(2),
        _ if INT32.contains(&spelling) => int(4),
        _ if INT64.contains(&spelling) => int(8),
        _ if LONG.contains(&spelling) => KType::Long,
        _ => return None,
    };
    Some(ty)
}

/// The [`KType`] of a C type spelling (`struct widget_config`, `__u8[16]`,
/// `void *`), typedefs followed through the corpus.
fn parse_type(corpus: &Corpus, spelling: &str) -> Result<KType, String> {
    parse_type_at(corpus, spelling, 0)
}

fn parse_type_at(corpus: &Corpus, spelling: &str, depth: usize) -> Result<KType, String> {
    if depth > MAX_EXPANSION {
        return Err(format!("`{spelling}` nests {DEPTH_ERROR}"));
    }
    let words: Vec<&str> = spelling
        .split_whitespace()
        .filter(|word| !matches!(*word, "const" | "volatile" | "restrict" | "__restrict"))
        .collect();
    let text = words.join(" ");
    if text.contains("(*") {
        return Ok(KType::FuncPtr);
    }
    if let Some(open) = text.find('[') {
        let mut ty = parse_type_at(corpus, text[..open].trim(), depth + 1)?;
        let dims: Vec<&str> = text[open..]
            .split('[')
            .filter(|part| !part.trim().is_empty())
            .map(|part| part.trim().trim_end_matches(']').trim())
            .collect();
        for dim in dims.iter().rev() {
            let len = if dim.is_empty() {
                None
            } else {
                let value = eval(corpus, dim)
                    .map_err(|reason| format!("the array length of `{spelling}`: {reason}"))?;
                // `[0]` is the GNU spelling of a flexible array member.
                let len = u64::try_from(value)
                    .map_err(|_| format!("`{spelling}` has a negative array length"))?;
                (len > 0).then_some(len)
            };
            ty = KType::Array(Box::new(ty), len);
        }
        return Ok(ty);
    }
    if let Some(pointee) = text.strip_suffix('*') {
        let pointee = pointee.trim();
        let inner = parse_type_at(corpus, pointee, depth + 1)
            .unwrap_or_else(|_| KType::Opaque(pointee.to_owned()));
        return Ok(KType::Pointer(Box::new(inner)));
    }
    if text == "void" {
        return Ok(KType::Void);
    }
    if let Some(tag) = text
        .strip_prefix("struct ")
        .or_else(|| text.strip_prefix("union "))
    {
        let tag = tag.trim();
        return Ok(if corpus.record(tag).is_some() {
            KType::Record(tag.to_owned())
        } else {
            KType::Opaque(text.clone())
        });
    }
    if text.starts_with("enum ") {
        return Ok(KType::Enum);
    }
    if let Some(scalar) = scalar_type(&text) {
        return Ok(scalar);
    }
    if let Some(underlying) = corpus.typedefs.get(&text) {
        return parse_type_at(corpus, underlying, depth + 1);
    }
    if corpus.record(&text).is_some() {
        return Ok(KType::Record(text));
    }
    Ok(KType::Opaque(text))
}

/// The kernel ABI of one architecture syzkaller builds descriptions for.
#[derive(Debug, Clone, Copy)]
struct Arch {
    name: &'static str,
    pointer: u64,
    /// Alignment of a 64-bit integer inside a struct.
    int64_align: u64,
    /// mips and powerpc encode ioctl numbers with 13 size bits and 3
    /// direction bits (none 1, read 2, write 4); the rest with 14 and 2
    /// (none 0, write 1, read 2).
    alternate_ioc: bool,
    /// An unnamed bit-field's type aligns the record (the Arm procedure
    /// call standard); elsewhere only a named member's type does.
    unnamed_bitfields_align: bool,
}

/// The Linux architectures of syzkaller, in its `arches` order.
const ARCHES: [Arch; 9] = [
    Arch {
        name: "386",
        pointer: 4,
        int64_align: 4,
        alternate_ioc: false,
        unnamed_bitfields_align: false,
    },
    Arch {
        name: "amd64",
        pointer: 8,
        int64_align: 8,
        alternate_ioc: false,
        unnamed_bitfields_align: false,
    },
    Arch {
        name: "arm",
        pointer: 4,
        int64_align: 8,
        alternate_ioc: false,
        unnamed_bitfields_align: true,
    },
    Arch {
        name: "arm64",
        pointer: 8,
        int64_align: 8,
        alternate_ioc: false,
        unnamed_bitfields_align: true,
    },
    Arch {
        name: "loong64",
        pointer: 8,
        int64_align: 8,
        alternate_ioc: false,
        unnamed_bitfields_align: false,
    },
    Arch {
        name: "mips64le",
        pointer: 8,
        int64_align: 8,
        alternate_ioc: true,
        unnamed_bitfields_align: false,
    },
    Arch {
        name: "ppc64le",
        pointer: 8,
        int64_align: 8,
        alternate_ioc: true,
        unnamed_bitfields_align: false,
    },
    Arch {
        name: "riscv64",
        pointer: 8,
        int64_align: 8,
        alternate_ioc: false,
        unnamed_bitfields_align: false,
    },
    Arch {
        name: "s390x",
        pointer: 8,
        int64_align: 8,
        alternate_ioc: false,
        unnamed_bitfields_align: false,
    },
];

/// The arch whose value a `.const` line gives first.
const DEFAULT_ARCH: usize = 1;

/// `value` rounded up to a multiple of `align`, saturating: a size past
/// `u64::MAX` is refused by [`ioc`] as too large, never wrapped.
fn round_up(value: u64, align: u64) -> u64 {
    if align <= 1 {
        value
    } else {
        value.div_ceil(align).saturating_mul(align)
    }
}

/// `(size, align)` in bytes of `ty` on `arch`.
fn layout(corpus: &Corpus, ty: &KType, arch: &Arch, depth: usize) -> LayoutResult {
    if depth > MAX_NESTING {
        return Err(format!("the argument type nests {DEPTH_ERROR}"));
    }
    Ok(match ty {
        KType::Int {
            bytes,
            always_aligned,
            ..
        } => {
            let size = u64::from(*bytes);
            let align = if size == 8 && !always_aligned {
                arch.int64_align
            } else {
                size
            };
            (size, align)
        }
        KType::Long | KType::Pointer(_) | KType::FuncPtr => (arch.pointer, arch.pointer),
        KType::Enum => (4, 4),
        KType::Array(elem, len) => {
            let (size, align) = layout(corpus, elem, arch, depth + 1)?;
            (size.saturating_mul(len.unwrap_or(0)), align)
        }
        KType::Record(name) => record_layout(corpus, name, arch, depth + 1)?,
        KType::Void => return Err("`void` has no size".to_owned()),
        KType::Opaque(spelling) => {
            return Err(format!("`{spelling}` is not defined in the scanned source"))
        }
    })
}

fn record_layout(corpus: &Corpus, name: &str, arch: &Arch, depth: usize) -> LayoutResult {
    let key = (name.to_owned(), arch.name);
    if let Some(layout) = corpus.layouts.borrow().get(&key) {
        return layout.clone();
    }
    let layout = record_layout_uncached(corpus, name, arch, depth);
    if !layout
        .as_ref()
        .is_err_and(|error| error.contains(DEPTH_ERROR))
    {
        corpus.layouts.borrow_mut().insert(key, layout.clone());
    }
    layout
}

fn record_layout_uncached(corpus: &Corpus, name: &str, arch: &Arch, depth: usize) -> LayoutResult {
    c_record_layout(corpus, name, arch, depth).map(|layout| (layout.size, layout.align))
}

/// A struct or union as C lays it out on one architecture.
#[derive(Debug)]
struct CLayout {
    size: u64,
    align: u64,
    /// Per member, in bits: where the member before it ended, where it
    /// starts, and where it ends. Union members all start at 0.
    spans: Vec<(u64, u64, u64)>,
}

/// The C layout of record `name` on `arch`, by the rules GCC and Clang
/// follow on Linux: a member at the next multiple of its alignment; a
/// bit-field where the last one ended unless that crosses out of an aligned
/// unit of its type (anywhere when packed); `: 0` moving on to the next
/// multiple of its type's alignment; an unnamed bit-field's type aligning
/// the record only on arm and arm64.
fn c_record_layout(
    corpus: &Corpus,
    name: &str,
    arch: &Arch,
    depth: usize,
) -> Result<CLayout, String> {
    let record = corpus
        .record(name)
        .ok_or_else(|| format!("`{name}` is not defined in the scanned source"))?;
    let mut bits = 0u64;
    let mut max_size = 0u64;
    let mut max_align = 1u64;
    let mut spans = Vec::with_capacity(record.fields.len());
    for field in &record.fields {
        let ty = parse_type(corpus, &field.c_type)?;
        let (size, natural_align) = layout(corpus, &ty, arch, depth + 1)?;
        let align = if record.packed { 1 } else { natural_align };
        let width = field
            .bit_width
            .as_deref()
            .map(|width| {
                eval(corpus, width).and_then(|value| {
                    u64::try_from(value)
                        .ok()
                        .filter(|value| *value <= size.saturating_mul(8))
                        .ok_or_else(|| format!("bit-field width `{width}` is out of range"))
                })
            })
            .transpose()?;
        let unnamed_bitfield = width.is_some() && field.name.is_none();
        if !unnamed_bitfield || arch.unnamed_bitfields_align {
            max_align = max_align.max(align);
        }
        if record.union {
            let member = width.map_or(size, |width| width.div_ceil(8));
            max_size = max_size.max(member);
            spans.push((0, 0, member.saturating_mul(8)));
            continue;
        }
        let before = bits;
        let unit_align = natural_align.saturating_mul(8);
        let start = match width {
            Some(0) => round_up(bits, unit_align),
            Some(width) => {
                let unit = size.saturating_mul(8);
                let unit_start = bits - bits % unit_align.max(1);
                if !record.packed && bits.saturating_add(width) > unit_start.saturating_add(unit) {
                    round_up(bits, unit_align)
                } else {
                    bits
                }
            }
            None => round_up(round_up(bits, 8), align.saturating_mul(8)),
        };
        bits = start.saturating_add(width.unwrap_or(size.saturating_mul(8)));
        spans.push((before, start, bits));
    }
    let size = if record.union {
        max_size
    } else {
        bits.div_ceil(8)
    };
    Ok(CLayout {
        size: round_up(size, max_align),
        align: max_align,
        spans,
    })
}

/// An ioctl command's transfer direction, from its macro.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dir {
    None,
    Read,
    Write,
    ReadWrite,
}

/// The ioctl number `_IOC(dir, type, nr, size)` on `arch`.
fn ioc(arch: &Arch, dir: Dir, kind: u64, nr: u64, size: u64) -> Result<u64, String> {
    if kind > 0xff || nr > 0xff {
        return Err(format!(
            "type {kind:#x} or number {nr:#x} does not fit in 8 bits"
        ));
    }
    let (size_bits, dir_shift, none, read, write) = if arch.alternate_ioc {
        (13, 29, 1, 2, 4)
    } else {
        (14, 30, 0, 2, 1)
    };
    if size >= 1 << size_bits {
        return Err(format!(
            "its argument is {size} bytes on {}, more than an ioctl number holds",
            arch.name
        ));
    }
    let dir = match dir {
        Dir::None => none,
        Dir::Read => read,
        Dir::Write => write,
        Dir::ReadWrite => read | write,
    };
    Ok((dir << dir_shift) | (size << 16) | (kind << 8) | nr)
}

// ── Commands ─────────────────────────────────────────────────────────────

/// A command macro: `_IO`-family, or a plain number a handler's `case`
/// names.
#[derive(Debug, Clone)]
struct CommandDef {
    name: String,
    value: String,
    location: String,
    shape: CommandShape,
}

#[derive(Debug, Clone)]
enum CommandShape {
    Ioc {
        dir: Dir,
        kind: String,
        nr: String,
        arg: Option<String>,
    },
    Plain,
}

/// The `_IO`-family call `value` spells, as `(dir, arguments)`.
fn ioc_call(value: &str) -> Option<(Dir, Vec<String>)> {
    let open = value.find('(')?;
    let dir = match value[..open].trim() {
        "_IO" => Dir::None,
        "_IOR" => Dir::Read,
        "_IOW" => Dir::Write,
        "_IOWR" => Dir::ReadWrite,
        _ => return None,
    };
    let inner = value[open + 1..].trim_end().strip_suffix(')')?;
    let mut args = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    for ch in inner.chars() {
        match ch {
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                args.push(current.trim().to_owned());
                current.clear();
                continue;
            }
            _ => {}
        }
        current.push(ch);
    }
    args.push(current.trim().to_owned());
    let expected = if dir == Dir::None { 2 } else { 3 };
    (args.len() == expected).then_some((dir, args))
}

fn is_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The command `name` defines, following `#define A B` aliases.
fn command_def(corpus: &Corpus, name: &str, plain: bool) -> Option<CommandDef> {
    let mut current = name.to_owned();
    for _ in 0..MAX_EXPANSION {
        let (def, file) = corpus.macro_def(&current)?;
        let location = format!("{}:{}", file.display, def.line);
        if is_identifier(&def.value) {
            current = def.value.clone();
            continue;
        }
        if let Some((dir, mut args)) = ioc_call(&def.value) {
            let arg = (args.len() == 3).then(|| args.remove(2));
            return Some(CommandDef {
                name: name.to_owned(),
                value: def.value.clone(),
                location,
                shape: CommandShape::Ioc {
                    dir,
                    kind: args[0].clone(),
                    nr: args[1].clone(),
                    arg,
                },
            });
        }
        return (plain && eval(corpus, &def.value).is_ok()).then(|| CommandDef {
            name: name.to_owned(),
            value: def.value.clone(),
            location,
            shape: CommandShape::Plain,
        });
    }
    None
}

/// Whether `condition` names the identifier `name`.
fn mentions(condition: &str, name: &str) -> bool {
    condition
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .any(|word| word == name)
}

/// The commands a handler dispatches on: the `case` labels of each `switch`
/// on its command parameter that name a command macro, and those of the
/// functions it passes the command on to.
fn handled_commands(corpus: &Corpus, handler: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut visited = HashSet::new();
    if let Some((function, _)) = corpus.function(handler) {
        if let Some(cmd) = function.params.get(1) {
            visit_dispatch(corpus, handler, &cmd.name, 0, &mut visited, &mut found);
        }
    }
    found
}

fn visit_dispatch(
    corpus: &Corpus,
    name: &str,
    cmd: &str,
    depth: usize,
    visited: &mut HashSet<String>,
    found: &mut Vec<String>,
) {
    if cmd.is_empty() || depth > 4 || !visited.insert(name.to_owned()) {
        return;
    }
    let Some((function, _)) = corpus.function(name) else {
        return;
    };
    for switch in function
        .switches
        .iter()
        .filter(|s| mentions(&s.condition, cmd))
    {
        for label in &switch.case_labels {
            if is_identifier(label)
                && !found.contains(label)
                && command_def(corpus, label, true).is_some()
            {
                found.push(label.clone());
            }
        }
    }
    for call in &function.calls {
        let Some(position) = call
            .args
            .iter()
            .position(|arg| *arg == CValue::Identifier(cmd.to_owned()))
        else {
            continue;
        };
        let Some((callee, _)) = corpus.function(&call.callee) else {
            continue;
        };
        if let Some(param) = callee.params.get(position) {
            let param = param.name.clone();
            visit_dispatch(corpus, &call.callee, &param, depth + 1, visited, found);
        }
    }
}

// ── Handlers and device nodes ────────────────────────────────────────────

/// The `struct file_operations` members an ioctl handler is registered as.
const IOCTL_MEMBERS: [&str; 3] = ["unlocked_ioctl", "compat_ioctl", "ioctl"];

struct Handler {
    function: String,
    /// `.unlocked_ioctl of widget_fops`, or why it was taken without one.
    registration: String,
    /// The `file_operations` variable, when one registers it.
    fops: Option<String>,
}

fn find_handlers(corpus: &Corpus) -> Vec<Handler> {
    let mut handlers = Vec::new();
    for file in &corpus.files {
        for init in &file.facts.initializers {
            for (member, value) in &init.fields {
                let CValue::Identifier(function) = value else {
                    continue;
                };
                if IOCTL_MEMBERS.contains(&member.as_str())
                    && corpus.function(function).is_some()
                    && !handlers.iter().any(|h: &Handler| {
                        h.function == *function && h.fops.as_deref() == Some(&init.variable)
                    })
                {
                    handlers.push(Handler {
                        function: function.clone(),
                        registration: format!(".{member} of {}", init.variable),
                        fops: Some(init.variable.clone()),
                    });
                }
            }
        }
    }
    if handlers.is_empty() {
        // No registration in the source read: a function with the handler
        // signature and an ioctl name.
        for file in &corpus.files {
            for function in &file.facts.functions {
                let params = &function.params;
                if params.len() == 3
                    && params[0].c_type.contains("struct file")
                    && function.name.contains("ioctl")
                    && !handlers.iter().any(|h| h.function == function.name)
                {
                    handlers.push(Handler {
                        function: function.name.clone(),
                        registration: "no file_operations registers it in the source read"
                            .to_owned(),
                        fops: None,
                    });
                }
            }
        }
    }
    handlers
}

#[derive(Debug, Clone, PartialEq)]
struct DeviceNode {
    /// `/dev/widget`, or `/dev/widget#` for a numbered node.
    path: String,
    origin: String,
    fops: Option<String>,
    /// The file it was found in, to pair a node with no `fops` with that
    /// file's `file_operations`.
    file: usize,
}

fn device_path(name: &str) -> String {
    let mut path = String::from("/dev/");
    let mut chars = name.trim_start_matches('/').chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '%' {
            // `%d`, `%u`, `%lu`, ...: syz_open_dev's `#`.
            while chars.peek().is_some_and(|c| c.is_ascii_alphabetic()) {
                let spec = chars.next();
                if matches!(spec, Some('d' | 'u' | 'i' | 'x')) {
                    break;
                }
            }
            path.push('#');
        } else {
            path.push(ch);
        }
    }
    path
}

fn find_device_nodes(corpus: &Corpus) -> Vec<DeviceNode> {
    let mut nodes = Vec::new();
    let field = |init: &c_parser::CInitializer, name: &str| -> Option<CValue> {
        init.fields
            .iter()
            .find(|(member, _)| member == name)
            .map(|(_, value)| value.clone())
    };
    for (index, file) in corpus.files.iter().enumerate() {
        for init in &file.facts.initializers {
            if init.type_name != "struct miscdevice" {
                continue;
            }
            let name = [field(init, "nodename"), field(init, "name")]
                .into_iter()
                .flatten()
                .find_map(|value| match value {
                    CValue::String(name) if !name.is_empty() => Some(name),
                    _ => None,
                });
            if let Some(name) = name {
                nodes.push(DeviceNode {
                    path: device_path(&name),
                    origin: format!("miscdevice {}", init.variable),
                    fops: match field(init, "fops") {
                        Some(CValue::AddressOf(fops)) => Some(fops),
                        _ => None,
                    },
                    file: index,
                });
            }
        }
        for function in &file.facts.functions {
            for call in &function.calls {
                let (name_at, fops_at) = match call.callee.as_str() {
                    "device_create" => (4, None),
                    "device_create_with_groups" => (5, None),
                    "register_chrdev" => (1, Some(2)),
                    "__register_chrdev" => (3, Some(4)),
                    _ => continue,
                };
                let Some(CValue::String(name)) = call.args.get(name_at) else {
                    continue;
                };
                let fops = fops_at.and_then(|at| match call.args.get(at) {
                    Some(CValue::AddressOf(fops)) => Some(fops.clone()),
                    _ => None,
                });
                nodes.push(DeviceNode {
                    path: device_path(name),
                    origin: format!("{} in {}", call.callee, function.name),
                    fops,
                    file: index,
                });
            }
        }
    }
    nodes
}

/// The `file_operations` a file's `cdev_init(&cdev, &fops)` names, else
/// the only one of `registered` (those that register a handler) the file
/// defines.
fn file_fops(corpus: &Corpus, file: usize, registered: &[String]) -> Option<String> {
    let facts = &corpus.files[file].facts;
    let cdev = facts
        .functions
        .iter()
        .flat_map(|f| &f.calls)
        .find_map(|call| match (call.callee.as_str(), call.args.get(1)) {
            ("cdev_init", Some(CValue::AddressOf(fops))) => Some(fops.clone()),
            _ => None,
        });
    if cdev.is_some() {
        return cdev;
    }
    let defined: Vec<&String> = facts
        .initializers
        .iter()
        .filter(|init| registered.contains(&init.variable))
        .map(|init| &init.variable)
        .collect();
    (defined.len() == 1).then(|| defined[0].clone())
}

// ── The description ──────────────────────────────────────────────────────

/// What [`describe`] produced.
struct Description {
    name: String,
    syzlang: String,
    consts: String,
    described: usize,
    handlers: Vec<String>,
    skipped: Vec<(String, String)>,
}

/// A syzlang identifier made of `text`: letters, digits and `_`, starting
/// with a letter.
fn identifier(text: &str) -> String {
    let mut out = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    let out = out.trim_matches('_').to_owned();
    if out.is_empty() {
        "driver".to_owned()
    } else if out.starts_with(|c: char| c.is_ascii_digit()) {
        format!("dev_{out}")
    } else {
        out
    }
}

/// One `file_operations` and what it serves.
struct Group {
    id: String,
    handlers: Vec<Handler>,
    nodes: Vec<DeviceNode>,
}

fn describe(corpus: &Corpus, name: Option<&str>, device: Option<&str>) -> Result<Description> {
    let handlers = find_handlers(corpus);
    if handlers.is_empty() {
        bail!(
            "no ioctl handler found: no `struct file_operations` registers an \
             .unlocked_ioctl or .compat_ioctl defined in the source read, and no \
             function takes (struct file *, unsigned int, unsigned long)"
        );
    }
    let nodes = find_device_nodes(corpus);
    let registered: Vec<String> = handlers.iter().filter_map(|h| h.fops.clone()).collect();
    let mut groups: Vec<Group> = Vec::new();
    for handler in handlers {
        let key = handler.fops.clone();
        match groups
            .iter_mut()
            .find(|group| key.is_some() && group.handlers[0].fops == key)
        {
            Some(group) => group.handlers.push(handler),
            None => groups.push(Group {
                id: String::new(),
                handlers: vec![handler],
                nodes: Vec::new(),
            }),
        }
    }
    for node in nodes {
        let fops = node
            .fops
            .clone()
            .or_else(|| file_fops(corpus, node.file, &registered));
        let at = match &fops {
            Some(fops) => groups
                .iter()
                .position(|group| group.handlers[0].fops.as_ref() == Some(fops)),
            None if groups.len() == 1 => Some(0),
            None => None,
        };
        if let Some(at) = at {
            if !groups[at].nodes.iter().any(|n| n.path == node.path) {
                groups[at].nodes.push(node);
            }
        }
    }

    let first_name = name.map(identifier).unwrap_or_else(|| {
        groups[0]
            .nodes
            .first()
            .map(|node| identifier(node.path.trim_start_matches("/dev/").trim_end_matches('#')))
            .unwrap_or_else(|| {
                identifier(
                    groups[0].handlers[0]
                        .function
                        .trim_end_matches("_unlocked_ioctl")
                        .trim_end_matches("_compat_ioctl")
                        .trim_end_matches("_ioctl"),
                )
            })
    });
    let mut ids = HashSet::new();
    for (index, group) in groups.iter_mut().enumerate() {
        let base = if index == 0 {
            first_name.clone()
        } else {
            let own = group
                .nodes
                .first()
                .map(|node| {
                    node.path
                        .trim_start_matches("/dev/")
                        .trim_end_matches('#')
                        .to_owned()
                })
                .or_else(|| {
                    group.handlers[0]
                        .fops
                        .as_deref()
                        .map(|fops| fops.trim_end_matches("_fops").to_owned())
                })
                .unwrap_or_else(|| group.handlers[0].function.clone());
            let own = identifier(&own);
            if own.starts_with(&first_name) {
                own
            } else {
                format!("{first_name}_{own}")
            }
        };
        let mut id = base.clone();
        let mut n = 2;
        while !ids.insert(id.clone()) {
            id = format!("{base}{n}");
            n += 1;
        }
        group.id = id;
    }

    let mut emitter = Emitter {
        corpus,
        prefix: first_name.clone(),
        names: HashMap::new(),
        taken: HashSet::new(),
        definitions: Vec::new(),
        records: Vec::new(),
        layouts: RefCell::default(),
    };
    let mut body = String::new();
    let mut consts: Vec<(String, [u64; ARCHES.len()])> = Vec::new();
    let mut syscalls = HashSet::new();
    let mut skipped = Vec::new();
    let mut header = Vec::new();
    let mut described = 0usize;
    for group in &groups {
        let mut names = Vec::new();
        for handler in &group.handlers {
            for command in handled_commands(corpus, &handler.function) {
                if !names.contains(&command) {
                    names.push(command);
                }
            }
        }
        let from_defines = names.is_empty();
        if from_defines {
            names = all_ioc_commands(corpus);
        }
        let mut lines = String::new();
        let resource = format!("fd_{}", group.id);
        let mut any = false;
        for command in &names {
            let Some(def) = command_def(corpus, command, true) else {
                continue;
            };
            match emitter.command(&def, &resource) {
                Ok((args, values)) => {
                    let mut syscall = format!("ioctl${}", def.name);
                    if !syscalls.insert(syscall.clone()) {
                        syscall = format!("ioctl${}_{}", def.name, group.id);
                        syscalls.insert(syscall.clone());
                    }
                    let _ = writeln!(
                        lines,
                        "{}",
                        comment(&format!(
                            "{} defined at {}: {}",
                            def.name, def.location, def.value
                        ))
                    );
                    let _ = writeln!(lines, "{syscall}({args})");
                    if !consts.iter().any(|(name, _)| *name == def.name) {
                        consts.push((def.name.clone(), values));
                    }
                    described += 1;
                    any = true;
                }
                Err(reason) => {
                    let _ = writeln!(
                        lines,
                        "{}",
                        comment(&format!("Not described: {}: {reason}", def.name))
                    );
                    skipped.push((def.name.clone(), reason));
                }
            }
        }
        if !any {
            continue;
        }
        let mut handler_lines = Vec::new();
        for handler in &group.handlers {
            let location = corpus
                .function(&handler.function)
                .map(|(function, file)| format!("{}:{}", file.display, function.line))
                .unwrap_or_default();
            handler_lines.push(format!(
                "Handler {} ({location}), {}.",
                handler.function, handler.registration
            ));
        }
        if from_defines {
            handler_lines.push(
                "Its switch names no command macro bhf could read, so every \
                 _IO/_IOR/_IOW/_IOWR command of the source read is described."
                    .to_owned(),
            );
        }
        let mut nodes = group.nodes.clone();
        if nodes.is_empty() {
            let path = device
                .map(str::to_owned)
                .unwrap_or_else(|| format!("/dev/{}", group.id));
            handler_lines.push(if device.is_some() {
                format!("Device node {path}, from --device.")
            } else {
                format!(
                    "The source names no device node; {path} is assumed (set it with --device)."
                )
            });
            nodes.push(DeviceNode {
                path,
                origin: String::new(),
                fops: None,
                file: 0,
            });
        }
        for node in nodes.iter().filter(|node| !node.origin.is_empty()) {
            handler_lines.push(format!("Device node {} ({}).", node.path, node.origin));
        }
        header.extend(handler_lines);
        let _ = writeln!(body, "resource {resource}[fd]\n");
        let mut opens = HashSet::new();
        for node in &nodes {
            let base = identifier(node.path.trim_start_matches("/dev/").trim_end_matches('#'));
            let mut open = base.clone();
            let mut n = 2;
            while !opens.insert(open.clone()) {
                open = format!("{base}{n}");
                n += 1;
            }
            if node.path.contains('#') {
                let _ = writeln!(
                    body,
                    "syz_open_dev${open}(dev ptr[in, string[\"{}\"]], id intptr, flags flags[open_flags]) {resource}",
                    node.path
                );
            } else {
                let _ = writeln!(
                    body,
                    "openat${open}(fd const[AT_FDCWD], file ptr[in, string[\"{}\"]], flags flags[open_flags], mode const[0]) {resource}",
                    node.path
                );
            }
        }
        body.push('\n');
        body.push_str(&lines);
        body.push('\n');
    }
    if described == 0 {
        let reasons = skipped
            .iter()
            .map(|(name, reason)| format!("{name}: {reason}"))
            .collect::<Vec<_>>();
        if reasons.is_empty() {
            bail!(
                "the ioctl handler{} found ({}) dispatch on no _IO/_IOR/_IOW/_IOWR \
                 command the source read defines; include the header that defines them",
                if groups.iter().map(|g| g.handlers.len()).sum::<usize>() == 1 {
                    ""
                } else {
                    "s"
                },
                groups
                    .iter()
                    .flat_map(|g| &g.handlers)
                    .map(|h| h.function.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        bail!("no command could be described: {}", reasons.join("; "));
    }

    let file_name = format!("dev_{first_name}.txt");
    let mut syzlang = String::new();
    let _ = writeln!(
        syzlang,
        "# Generated by `bhf kernel syzlang` from the driver source it read: check it\n\
         # before you fuzz with it. The command numbers are in {file_name}.const,\n\
         # computed by bhf for each architecture, so no syz-extract run is needed.\n#"
    );
    for line in &header {
        for wrapped in wrap(line, 76) {
            let _ = writeln!(syzlang, "{}", comment(&wrapped));
        }
    }
    syzlang.push('\n');
    syzlang.push_str(&body);
    for definition in &emitter.definitions {
        syzlang.push_str(definition);
        syzlang.push('\n');
    }
    while syzlang.ends_with("\n\n") {
        syzlang.pop();
    }

    let mut const_text = format!(
        "# Generated by `bhf kernel syzlang`: the ioctl command numbers {file_name} uses.\n\
         arches = {}\n",
        ARCHES.map(|arch| arch.name).join(", ")
    );
    consts.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, values) in &consts {
        let default = values[DEFAULT_ARCH];
        let _ = write!(const_text, "{name} = {default}");
        for (arch, value) in ARCHES.iter().zip(values) {
            if *value != default {
                let _ = write!(const_text, ", {}:{value}", arch.name);
            }
        }
        const_text.push('\n');
    }

    Ok(Description {
        name: first_name,
        syzlang,
        consts: const_text,
        described,
        handlers: groups
            .iter()
            .flat_map(|g| &g.handlers)
            .map(|h| h.function.clone())
            .collect(),
        skipped,
    })
}

/// Every `_IO`-family command macro of the corpus, in file and line order.
fn all_ioc_commands(corpus: &Corpus) -> Vec<String> {
    let mut names = Vec::new();
    for file in &corpus.files {
        for def in &file.facts.macros {
            if ioc_call(&def.value).is_some() && !names.contains(&def.name) {
                names.push(def.name.clone());
            }
        }
    }
    names
}

/// Whether syzkaller's compiler would reject comment text `text` as faking a
/// directive: it refuses a comment that starts, after blanks, with
/// `include`, `incdir` or `define`.
fn fakes_directive(text: &str) -> bool {
    let text = text.trim_start();
    ["include", "incdir", "define"]
        .iter()
        .any(|word| text.starts_with(word))
}

/// `text` as a syzlang comment line syzkaller cannot take for a directive.
fn comment(text: &str) -> String {
    if fakes_directive(text) {
        format!("# - {text}")
    } else {
        format!("# {text}")
    }
}

/// `text` in lines of at most `width` columns where its words allow. A
/// word that would fake a directive at the start of a comment line stays on
/// the line before.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.len() + 1 + word.len() > width && !fakes_directive(word) {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

/// Member names syzlang cannot take: those its `len` paths reserve, and its
/// keywords.
const RESERVED_FIELDS: [&str; 6] = [
    "parent", "syscall", "include", "incdir", "define", "resource",
];

/// A syzlang type as syzkaller lays it out.
#[derive(Debug, Clone, PartialEq)]
enum Syz {
    /// `intN`, `intNbe` or `const[0, intN]`: N/8 bytes, a bit-field's unit.
    Int(u8),
    /// `align64[...]`: 8 bytes, 8-aligned on every architecture.
    Align64,
    /// `intptr` and `ptr[...]`.
    Pointer,
    /// `None`: variable length.
    Array(Box<Syz>, Option<u64>),
    /// The description's struct or union defined in this slot.
    Record(usize),
}

/// A struct or union of the description, for its layout check.
#[derive(Debug, Clone, Default)]
struct SyzRecord {
    c_name: String,
    union: bool,
    packed: bool,
    /// The `[size[N]]` a union is given.
    size: Option<u64>,
    fields: Vec<SyzField>,
    /// Its members are all rendered: only then is it laid out.
    complete: bool,
}

#[derive(Debug, Clone)]
struct SyzField {
    name: String,
    ty: Syz,
    /// A bit-field's width.
    bits: Option<u64>,
    /// The C member it describes; `None` for padding.
    member: Option<usize>,
}

/// `(size, align)` as syzkaller lays out a type: size `None` when variable.
type SyzLayout = Result<(Option<u64>, u64), String>;

/// A struct or union as syzkaller lays it out on one architecture.
#[derive(Debug, Clone)]
struct SyzRecordLayout {
    /// `None`: variable length.
    size: Option<u64>,
    align: u64,
    /// Where each member starts, in bits.
    offsets: Vec<u64>,
}

/// Renders types as syzlang, defining each struct and union once.
#[derive(Clone)]
struct Emitter<'a> {
    corpus: &'a Corpus,
    prefix: String,
    /// C record name -> its syzlang name and slot.
    names: HashMap<String, (String, usize)>,
    taken: HashSet<String>,
    /// Struct and union definitions, in the order they were first used.
    definitions: Vec<String>,
    /// What each definition lays out, slot for slot.
    records: Vec<SyzRecord>,
    /// Each complete record's syzkaller layout per architecture, computed
    /// once: a struct whose members fan out costs its size, not the size of
    /// its expansion.
    layouts: RefCell<HashMap<(usize, &'static str), SyzRecordLayout>>,
}

impl Emitter<'_> {
    /// The syscall arguments and per-arch numbers of `def`. On error nothing
    /// is defined.
    fn command(
        &mut self,
        def: &CommandDef,
        resource: &str,
    ) -> Result<(String, [u64; ARCHES.len()]), String> {
        let mut values = [0u64; ARCHES.len()];
        match &def.shape {
            CommandShape::Plain => {
                let value = eval(self.corpus, &def.value)?;
                let value = u64::try_from(value)
                    .ok()
                    .filter(|v| *v <= u64::from(u32::MAX))
                    .ok_or_else(|| format!("{value} is not a 32-bit ioctl number"))?;
                values = [value; ARCHES.len()];
                Ok((
                    format!(
                        "fd {resource}, cmd const[{}], arg ptr[inout, array[int8]]",
                        def.name
                    ),
                    values,
                ))
            }
            CommandShape::Ioc { dir, kind, nr, arg } => {
                let kind = u64::try_from(eval(self.corpus, kind)?)
                    .map_err(|_| format!("type `{kind}` is negative"))?;
                let nr = u64::try_from(eval(self.corpus, nr)?)
                    .map_err(|_| format!("number `{nr}` is negative"))?;
                let Some(arg) = arg else {
                    for (value, arch) in values.iter_mut().zip(&ARCHES) {
                        *value = ioc(arch, *dir, kind, nr, 0)?;
                    }
                    return Ok((
                        format!("fd {resource}, cmd const[{}], arg intptr", def.name),
                        values,
                    ));
                };
                let ty = parse_type(self.corpus, arg)?;
                for (value, arch) in values.iter_mut().zip(&ARCHES) {
                    let (size, _) = layout(self.corpus, &ty, arch, 0)?;
                    *value = ioc(arch, *dir, kind, nr, size)?;
                }
                let direction = match dir {
                    Dir::Write => "in",
                    Dir::Read => "out",
                    _ => "inout",
                };
                let from = self.records.len();
                let mut scratch = self.clone();
                let (rendered, _) = scratch.render(&ty)?;
                scratch.check_layouts(from)?;
                *self = scratch;
                Ok((
                    format!(
                        "fd {resource}, cmd const[{}], arg ptr[{direction}, {rendered}]",
                        def.name
                    ),
                    values,
                ))
            }
        }
    }

    fn render(&mut self, ty: &KType) -> Result<(String, Syz), String> {
        Ok(match ty {
            KType::Int {
                bytes,
                big_endian,
                always_aligned,
            } => {
                let int = format!(
                    "int{}{}",
                    u32::from(*bytes) * 8,
                    if *big_endian && *bytes > 1 { "be" } else { "" }
                );
                // syzkaller aligns int64 to 4 on 386, as C does a plain
                // 64-bit integer; `__aligned_u64` is 8-aligned there too.
                if *always_aligned && *bytes == 8 {
                    (format!("align64[{int}]"), Syz::Align64)
                } else {
                    (int, Syz::Int(*bytes))
                }
            }
            KType::Long | KType::FuncPtr => ("intptr".to_owned(), Syz::Pointer),
            KType::Enum => ("int32".to_owned(), Syz::Int(4)),
            KType::Pointer(pointee) => {
                let bytes = "ptr[inout, array[int8]]".to_owned();
                let text = match &**pointee {
                    KType::Void | KType::Opaque(_) | KType::Int { bytes: 1, .. } => bytes,
                    other => {
                        // A pointee syzkaller cannot lay out as C does is
                        // described as bytes.
                        let from = self.records.len();
                        let mut scratch = self.clone();
                        match scratch
                            .render(other)
                            .and_then(|rendered| scratch.check_layouts(from).map(|()| rendered))
                        {
                            Ok((inner, _)) => {
                                *self = scratch;
                                let opt = if matches!(other, KType::Record(_)) {
                                    ", opt"
                                } else {
                                    ""
                                };
                                format!("ptr[inout, {inner}{opt}]")
                            }
                            Err(_) => bytes,
                        }
                    }
                };
                (text, Syz::Pointer)
            }
            KType::Array(elem, len) => {
                let (inner, syz) = self.render(elem)?;
                let text = match len {
                    Some(len) => format!("array[{inner}, {len}]"),
                    None => format!("array[{inner}]"),
                };
                (text, Syz::Array(Box::new(syz), *len))
            }
            KType::Record(name) => {
                let (name, slot) = self.record(name)?;
                (name, Syz::Record(slot))
            }
            KType::Void => return Err("`void` has no size".to_owned()),
            KType::Opaque(spelling) => {
                return Err(format!("`{spelling}` is not defined in the scanned source"))
            }
        })
    }

    /// The syzlang name and slot of record `c_name`, defining it on first
    /// use.
    fn record(&mut self, c_name: &str) -> Result<(String, usize), String> {
        if let Some(found) = self.names.get(c_name) {
            return Ok(found.clone());
        }
        let corpus = self.corpus;
        let record = corpus
            .record(c_name)
            .ok_or_else(|| format!("`{c_name}` is not defined in the scanned source"))?;
        if record.fields.is_empty() {
            return Err(format!("`{c_name}` has no members"));
        }
        let own = identifier(c_name);
        let base = if own == self.prefix || own.starts_with(&format!("{}_", self.prefix)) {
            own
        } else {
            format!("{}_{own}", self.prefix)
        };
        let mut name = base.clone();
        let mut n = 2;
        while self.taken.contains(&name) {
            name = format!("{base}{n}");
            n += 1;
        }
        let slot = self.definitions.len();
        self.taken.insert(name.clone());
        self.names.insert(c_name.to_owned(), (name.clone(), slot));
        self.definitions.push(String::new());
        self.records.push(SyzRecord {
            c_name: c_name.to_owned(),
            union: record.union,
            packed: record.packed,
            ..SyzRecord::default()
        });
        // Where C puts each member, for the padding an unnamed bit-field
        // stands for.
        let c_layout = if !record.union
            && record
                .fields
                .iter()
                .any(|field| field.name.is_none() && field.bit_width.is_some())
        {
            Some(c_record_layout(corpus, c_name, &ARCHES[DEFAULT_ARCH], 0)?)
        } else {
            None
        };
        let mut fields: Vec<SyzField> = Vec::new();
        let mut texts: Vec<String> = Vec::new();
        let mut anonymous = 0usize;
        let mut used = HashSet::new();
        for (member, field) in record.fields.iter().enumerate() {
            let ty = parse_type(corpus, &field.c_type)
                .map_err(|reason| format!("member of `{c_name}`: {reason}"))?;
            let width = field
                .bit_width
                .as_deref()
                .map(|width| eval(corpus, width))
                .transpose()?;
            if width.is_some() && (field.name.is_none() || width == Some(0)) {
                // An unnamed bit-field is padding: in a struct, the bits C
                // skips for it, as zero bytes and bits; in a union, nothing.
                let Some(c_layout) = &c_layout else {
                    continue;
                };
                let (before, _, after) = c_layout.spans[member];
                for (text, syz, bits) in padding(before, after) {
                    anonymous += 1;
                    let name = unique(format!("unused{}", anonymous - 1), &mut used);
                    texts.push(text);
                    fields.push(SyzField {
                        name,
                        ty: syz,
                        bits,
                        member: None,
                    });
                }
                continue;
            }
            let (mut rendered, mut syz) = self
                .render(&ty)
                .map_err(|reason| format!("member of `{c_name}`: {reason}"))?;
            let mut bits = None;
            // syzlang has bit-fields in structs only: a union member is its
            // whole integer.
            if let (Some(width), false) = (width, record.union) {
                let (base, unit) = match ty {
                    KType::Int { bytes, .. } => {
                        (format!("int{}", u32::from(bytes) * 8), Syz::Int(bytes))
                    }
                    KType::Enum => ("int32".to_owned(), Syz::Int(4)),
                    KType::Long => ("intptr".to_owned(), Syz::Pointer),
                    _ => return Err(format!("`{c_name}` has a bit-field of a non-integer type")),
                };
                rendered = format!("{base}:{width}");
                syz = unit;
                bits = u64::try_from(width).ok();
            }
            let field_name = match &field.name {
                Some(name) if RESERVED_FIELDS.contains(&name.as_str()) => format!("{name}_"),
                Some(name) => identifier(name),
                None => {
                    anonymous += 1;
                    format!("anon{}", anonymous - 1)
                }
            };
            let name = unique(field_name, &mut used);
            texts.push(rendered);
            fields.push(SyzField {
                name,
                ty: syz,
                bits,
                member: Some(member),
            });
        }
        let mut text = String::new();
        let (open, close) = if record.union { ('[', ']') } else { ('{', '}') };
        let _ = writeln!(text, "{name} {open}");
        for (field, ty) in fields.iter().zip(&texts) {
            let _ = writeln!(text, "\t{}\t{ty}", field.name);
        }
        text.push(close);
        self.records[slot].fields = fields;
        if record.union {
            // C rounds a union up to its alignment; syzkaller sizes it by its
            // largest member unless given the size.
            if let Some(size) = self.union_size(slot) {
                self.records[slot].size = Some(size);
                let _ = write!(text, " [size[{size}]]");
            }
        } else if record.packed {
            text.push_str(" [packed]");
        }
        text.push('\n');
        self.definitions[slot] = text;
        self.records[slot].complete = true;
        Ok((name, slot))
    }

    /// The `[size[N]]` union `slot` needs to be as large as C makes it: one
    /// when C pads it past its largest member, to a size every architecture
    /// shares.
    fn union_size(&self, slot: usize) -> Option<u64> {
        let mut needed = None;
        let mut padded = false;
        for arch in &ARCHES {
            let c = c_record_layout(self.corpus, &self.records[slot].c_name, arch, 0).ok()?;
            let mut largest = 0u64;
            for field in &self.records[slot].fields {
                largest = largest.max(self.syz_layout(&field.ty, arch, 0).ok()?.0?);
            }
            padded |= c.size > largest;
            match needed {
                None => needed = Some(c.size),
                Some(size) if size != c.size => return None,
                Some(_) => {}
            }
        }
        needed.filter(|_| padded)
    }

    /// An error when syzkaller would lay out a record defined from slot
    /// `from` on differently from C on some architecture: the kernel would
    /// read its members where syzkaller does not put them.
    fn check_layouts(&self, from: usize) -> Result<(), String> {
        for slot in from..self.records.len() {
            let record = &self.records[slot];
            for arch in &ARCHES {
                let c = c_record_layout(self.corpus, &record.c_name, arch, 0)?;
                let SyzRecordLayout {
                    size,
                    align,
                    offsets,
                } = self.syz_record_layout(slot, arch, 0)?;
                let differs = |what: String| {
                    format!(
                        "syzkaller would lay out `{}` unlike C on {}: {what}",
                        record.c_name, arch.name
                    )
                };
                for (field, offset) in record.fields.iter().zip(&offsets) {
                    let Some(member) = field.member else {
                        continue;
                    };
                    let c_offset = c.spans[member].1;
                    if *offset != c_offset {
                        return Err(differs(format!(
                            "member `{}` at {}, C puts it at {}",
                            field.name,
                            position(*offset),
                            position(c_offset)
                        )));
                    }
                }
                if align != c.align {
                    return Err(differs(format!(
                        "aligned to {align} bytes, C aligns it to {}",
                        c.align
                    )));
                }
                if let Some(size) = size.filter(|size| *size != c.size) {
                    return Err(differs(format!("{size} bytes, C makes it {}", c.size)));
                }
            }
        }
        Ok(())
    }

    /// `(size, align)` of `ty` on `arch` as syzkaller lays it out.
    fn syz_layout(&self, ty: &Syz, arch: &Arch, depth: usize) -> SyzLayout {
        if depth > MAX_NESTING {
            return Err(format!("the argument type nests {DEPTH_ERROR}"));
        }
        Ok(match ty {
            Syz::Int(bytes) => {
                let size = u64::from(*bytes);
                (Some(size), if size == 8 { arch.int64_align } else { size })
            }
            Syz::Align64 => (Some(8), 8),
            Syz::Pointer => (Some(arch.pointer), arch.pointer),
            Syz::Array(elem, len) => {
                let (size, align) = self.syz_layout(elem, arch, depth + 1)?;
                let size = match (size, len) {
                    (Some(size), Some(len)) => Some(size.saturating_mul(*len)),
                    _ => None,
                };
                (size, align)
            }
            Syz::Record(slot) => {
                let layout = self.syz_record_layout(*slot, arch, depth + 1)?;
                (layout.size, layout.align)
            }
        })
    }

    /// Size (`None`: variable), alignment and member offsets in bits of the
    /// record in `slot`, as syzkaller's compiler lays it out
    /// (`layoutStructFields` and `layoutUnion` in pkg/compiler/gen.go).
    fn syz_record_layout(
        &self,
        slot: usize,
        arch: &Arch,
        depth: usize,
    ) -> Result<SyzRecordLayout, String> {
        if let Some(layout) = self.layouts.borrow().get(&(slot, arch.name)) {
            return Ok(layout.clone());
        }
        let layout = self.syz_record_layout_uncached(slot, arch, depth)?;
        self.layouts
            .borrow_mut()
            .insert((slot, arch.name), layout.clone());
        Ok(layout)
    }

    fn syz_record_layout_uncached(
        &self,
        slot: usize,
        arch: &Arch,
        depth: usize,
    ) -> Result<SyzRecordLayout, String> {
        let record = &self.records[slot];
        // Only a record that contains itself, through the records it
        // contains, is laid out while its members are still being rendered.
        if !record.complete {
            return Err(format!("`{}` contains itself", record.c_name));
        }
        let mut layouts = Vec::with_capacity(record.fields.len());
        for field in &record.fields {
            layouts.push(self.syz_layout(&field.ty, arch, depth + 1)?);
        }
        if record.union {
            let mut size = 0u64;
            let mut align = 1u64;
            for (field, (member_size, member_align)) in record.fields.iter().zip(&layouts) {
                let member_size = member_size
                    .ok_or_else(|| format!("its member `{}` has a variable size", field.name))?;
                size = size.max(member_size);
                align = align.max(*member_align);
            }
            return Ok(SyzRecordLayout {
                size: Some(record.size.unwrap_or(size)),
                align,
                offsets: vec![0; record.fields.len()],
            });
        }
        let packed = record.packed;
        let mut struct_align = 1u64;
        let mut byte_offset = 0u64;
        let mut bit_offset = 0u64;
        let mut varlen = false;
        let mut offsets = Vec::with_capacity(record.fields.len());
        let last = record.fields.len().saturating_sub(1);
        for (index, (field, (size, align))) in record.fields.iter().zip(&layouts).enumerate() {
            if size.is_none() {
                if index != last && !packed {
                    return Err(format!(
                        "its member `{}` has a variable size and is not the last",
                        field.name
                    ));
                }
                varlen = true;
            }
            let size = size.unwrap_or(0);
            let field_align = if packed { 1 } else { *align };
            struct_align = struct_align.max(field_align);
            let full = byte_offset.saturating_mul(8).saturating_add(bit_offset);
            let field_offset;
            match field.bits {
                Some(width) => {
                    let unit_align = if packed { 1 } else { size.max(1) };
                    let unit_bits = size.saturating_mul(8).max(1);
                    let mut start = full / 8 / unit_align * unit_align;
                    let mut full = full;
                    if unit_bits - (full - start * 8) < width {
                        start = round_up(full.div_ceil(8), unit_align);
                        full = 0;
                        bit_offset = 0;
                    } else if start * 8 >= full {
                        full = start * 8;
                        bit_offset = 0;
                    }
                    let in_unit = full.wrapping_sub(start * 8) % unit_bits;
                    offsets.push(start * 8 + in_unit);
                    field_offset = start;
                }
                None => {
                    field_offset = round_up(full.div_ceil(8), field_align);
                    bit_offset = 0;
                    offsets.push(field_offset.saturating_mul(8));
                }
            }
            if field_offset > byte_offset {
                let pad = field_offset - byte_offset;
                byte_offset = field_offset;
                let after_bitfield = index > 0 && record.fields[index - 1].bits.is_some();
                if after_bitfield {
                    if bit_offset >= 8 * pad {
                        bit_offset -= 8 * pad;
                    } else if bit_offset >= 8 {
                        // syzkaller's compiler gives up on such a struct.
                        return Err(format!(
                            "syzkaller cannot place its member `{}`",
                            field.name
                        ));
                    }
                }
            }
            match field.bits {
                Some(width) => bit_offset = bit_offset.saturating_add(width),
                None => byte_offset = byte_offset.saturating_add(size),
            }
        }
        if bit_offset != 0 {
            byte_offset = byte_offset.saturating_add(bit_offset.div_ceil(8));
        }
        let align = if packed { 1 } else { struct_align };
        Ok(SyzRecordLayout {
            size: (!varlen).then(|| round_up(byte_offset, align)),
            align,
            offsets,
        })
    }
}

/// `base`, or `base` numbered from 2 when `used` has it, added to `used`.
fn unique(base: String, used: &mut HashSet<String>) -> String {
    let mut unique = base.clone();
    let mut n = 2;
    while !used.insert(unique.clone()) {
        unique = format!("{base}{n}");
        n += 1;
    }
    unique
}

/// `bits` as a member offset: `byte N`, or `bit N` within no whole byte.
fn position(bits: u64) -> String {
    if bits.is_multiple_of(8) {
        format!("byte {}", bits / 8)
    } else {
        format!("bit {bits}")
    }
}

/// Padding members that fill bits `from..to` of a struct as syzkaller
/// places them: zero bits up to a byte boundary, zero bytes, and the bits
/// left, each `(type, layout, bit-field width)`.
fn padding(from: u64, to: u64) -> Vec<(String, Syz, Option<u64>)> {
    let mut pieces = Vec::new();
    let mut at = from;
    let head = (8 - at % 8) % 8;
    if head > 0 && at < to {
        let bits = head.min(to - at);
        pieces.push((format!("const[0, int8:{bits}]"), Syz::Int(1), Some(bits)));
        at += bits;
    }
    let bytes = to.saturating_sub(at) / 8;
    if bytes > 0 {
        pieces.push((
            format!("array[const[0, int8], {bytes}]"),
            Syz::Array(Box::new(Syz::Int(1)), Some(bytes)),
            None,
        ));
        at += bytes * 8;
    }
    if at < to {
        let bits = to - at;
        pieces.push((format!("const[0, int8:{bits}]"), Syz::Int(1), Some(bits)));
    }
    pieces
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A corpus of in-memory files, `(display, source)`.
    fn corpus(files: &[(&str, &str)]) -> Corpus {
        let mut corpus = Corpus::default();
        for (display, source) in files {
            corpus.add(SourceFile {
                display: (*display).to_owned(),
                facts: c_parser::parse_ioctl_facts(source).unwrap(),
            });
        }
        corpus
    }

    fn arch(name: &str) -> Arch {
        *ARCHES.iter().find(|arch| arch.name == name).unwrap()
    }

    #[cfg(unix)]
    fn widget_source() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/kernel_widget/linux")
    }

    /// `(call name, ioctl number, argument)` of each ioctl call of a seed.
    #[cfg(unix)]
    fn ioctls(program: &[u8]) -> Vec<(String, u64, String)> {
        use crate::kernel_guest::{decode, ArgValue};
        let decoded = decode(program);
        assert_eq!(decoded.calls[0].sys.name(), "openat");
        match &decoded.calls[0].args[1].value {
            ArgValue::Data { bytes, .. } => assert_eq!(&program[bytes.clone()], b"/dev/widget\0"),
            other => panic!("{other:?}"),
        }
        decoded.calls[1..]
            .iter()
            .map(|call| {
                assert_eq!(call.args[0].value, ArgValue::Result(Some(0)));
                let number = match call.args[1].value {
                    ArgValue::Const(number) => number,
                    ref other => panic!("{other:?}"),
                };
                let arg = match &call.args[2].value {
                    ArgValue::Const(value) => format!("const {value}"),
                    ArgValue::Data { bytes, .. } => {
                        assert!(program[bytes.clone()].iter().all(|b| *b == 0));
                        format!("data {}", bytes.len())
                    }
                    ArgValue::Out { len, .. } => format!("out {len}"),
                    other => panic!("{other:?}"),
                };
                (call.sys.name(), number, arg)
            })
            .collect()
    }

    /// The widget driver's commands become seeds that open its node and
    /// call each with an argument of its size, for the guest's
    /// architecture.
    #[cfg(unix)]
    #[test]
    fn a_drivers_ioctl_commands_become_seed_programs() {
        let interface = driver_interface(&[widget_source()], None).unwrap();
        assert_eq!(interface.device, "/dev/widget");
        let names: Vec<&str> = interface.commands.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "WIDGET_IOC_RESET",
                "WIDGET_IOC_SET_CONFIG",
                "WIDGET_IOC_GET_STATS",
                "WIDGET_IOC_SET_MODE",
                "WIDGET_IOC_WRITE_REG",
                "WIDGET_IOC_XFER"
            ]
        );
        let seeds = interface.seeds("x86_64").unwrap();
        let (programs, dictionary) = (seeds.programs, seeds.dictionary);
        assert_eq!(programs.len(), 7);
        let single: Vec<(String, u64, String)> =
            programs[..6].iter().flat_map(|p| ioctls(p)).collect();
        let expected = [
            (0x5700, "const 0"),
            (0x4020_5701, "data 32"),
            (0x8018_5702, "out 24"),
            (0x4004_5704, "data 4"),
            (0x4007_5705, "data 7"),
            (0xc028_5703, "data 40"),
        ];
        for ((call, number, arg), (want, want_arg)) in single.iter().zip(expected) {
            assert_eq!(call, "ioctl");
            assert_eq!((*number, arg.as_str()), (want, want_arg));
        }
        // The last calls every command on one descriptor.
        assert_eq!(ioctls(&programs[6]), single);
        assert!(dictionary.contains(&b"/dev/widget".to_vec()));
        assert!(dictionary.contains(&0xc028_5703u32.to_le_bytes().to_vec()));
        assert!(dictionary.contains(&0xc028_5703u64.to_le_bytes().to_vec()));

        // On a 32-bit x86 guest `unsigned long` is 4 bytes: widget_stats is
        // 20, and so is the number.
        let programs = interface.seeds("i686").unwrap().programs;
        assert_eq!(ioctls(&programs[2])[0].1, 0x8014_5702);
        assert_eq!(arch_index("aarch64"), arch_index("arm64"));
        assert_eq!(arch_index("x86_64"), Some(DEFAULT_ARCH));
        assert_eq!(arch_index("sparc64"), None);

        // --device names another node.
        let other = driver_interface(&[widget_source()], Some("/dev/widget1")).unwrap();
        assert_eq!(other.device, "/dev/widget1");
        let error = driver_interface(&[widget_source().join("include")], None).unwrap_err();
        assert!(error.to_string().contains("no ioctl handler"), "{error}");
    }

    /// A campaign that booted once, with its setup notes, and ran nothing.
    #[cfg(unix)]
    fn campaign_summary() -> crate::kernel_guest::FuzzSummary {
        crate::kernel_guest::FuzzSummary {
            schema: crate::kernel_guest::FUZZ_SUMMARY_SCHEMA,
            kernel: "bzImage".to_owned(),
            release: "6.12.118".to_owned(),
            machine: "x86_64".to_owned(),
            accel: "tcg",
            kcov: true,
            notes: vec![
                "module 00-broken.ko: not loaded: Exec format error".to_owned(),
                "ready (kcov on, comparisons on)".to_owned(),
            ],
            seeds: 1,
            seed_origin: Vec::new(),
            executions: 0,
            comparisons: true,
            comparison_runs: 0,
            hint_runs: 0,
            corpus_new: 0,
            corpus: 0,
            coverage_after_seeds: Default::default(),
            coverage: Default::default(),
            reports: 0,
            findings: Vec::new(),
            confirm_runs: 0,
            crashes: 0,
            crash_dirs: Vec::new(),
            boots: 1,
            halted: Some("the guest did not load every --module".to_owned()),
            elapsed_secs: 1.0,
            executions_per_sec: 0.0,
        }
    }

    /// A campaign's report says what the guest's executor did at setup:
    /// each module it loaded, or why not.
    #[cfg(unix)]
    #[test]
    fn a_campaign_report_prints_the_guests_setup_notes() {
        let lines = fuzz_report(&campaign_summary(), Path::new("work"));
        assert_eq!(
            lines[..3],
            [
                "bhf kernel fuzz: 0 executions (0.0/s) in Linux 6.12.118 x86_64 (tcg), 1 seeds",
                "  guest setup: module 00-broken.ko: not loaded: Exec format error",
                "  guest setup: ready (kcov on, comparisons on)",
            ]
        );
        assert!(
            lines[3].starts_with("  coverage: 0 KCOV edges"),
            "{lines:#?}"
        );
        assert_eq!(lines.last().unwrap(), "  summary: work/kernel/fuzz.json");
    }

    /// A finding whose program could not run alone in a fresh guest is
    /// reported as not confirmed, with the reason.
    #[cfg(unix)]
    #[test]
    fn a_campaign_report_says_why_a_finding_is_not_confirmed() {
        use results::import_syzkaller as kernel;
        let work = tempfile::tempdir().unwrap();
        let console = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/kernel_guest/console/kasan-slab-out-of-bounds.log"),
        )
        .unwrap();
        let report = kernel::console_report(&console).unwrap();
        let why = "its confirming run could not be made: the guest did not start";
        let found = kernel::record_guest_crash(
            work.path(),
            &kernel::GuestCrash {
                report: &report,
                console: &console,
                program: b"program",
                program_text: "",
                decoded: &serde_json::Value::Null,
                c_repro: "",
                guest: &serde_json::Value::Null,
                reproduced: false,
                unconfirmed: Some(why),
                release: None,
            },
        )
        .unwrap();
        let summary = crate::kernel_guest::FuzzSummary {
            reports: 1,
            findings: vec![found.id.clone()],
            ..campaign_summary()
        };
        let lines = fuzz_report(&summary, work.path());
        let line = format!(
            "    {}: KASAN: slab-out-of-bounds Write in widget_ioctl (not confirmed: {why})",
            found.id
        );
        assert!(lines.contains(&line), "{lines:#?}");
        kernel::confirm_guest_crash(work.path(), &found.id, true, None).unwrap();
        let lines = fuzz_report(&summary, work.path());
        assert!(
            lines
                .iter()
                .any(|line| line.ends_with("(the program alone made it again)")),
            "{lines:#?}"
        );
    }

    /// The guest's waits are seconds a u64 holds: one longer than a day is
    /// refused when the command line is read, not left to overflow a
    /// deadline.
    #[test]
    fn a_guest_wait_longer_than_a_day_is_refused() {
        #[derive(clap::Parser)]
        struct Cli {
            #[command(flatten)]
            run: RunArgs,
        }
        let parse = |flag: &str, secs: &str| {
            <Cli as clap::Parser>::try_parse_from([
                "bhf", "--kernel", "bzImage", flag, secs, "prog.bin",
            ])
        };
        for flag in ["--boot-timeout", "--timeout"] {
            let error = match parse(flag, "18446744073709551615") {
                Ok(_) => panic!("{flag} 18446744073709551615 was accepted"),
                Err(error) => error.to_string(),
            };
            assert!(error.contains("1..=86400"), "{flag}: {error}");
            assert!(parse(flag, "86400").is_ok(), "{flag} 86400");
        }
        let cli = parse("--timeout", "86400").unwrap();
        assert_eq!(
            (cli.run.guest.boot_timeout, cli.run.guest.timeout),
            (300, 86400)
        );
    }

    /// A finding records the guest it was found in; a replay boots it
    /// again, with what its options replace.
    #[cfg(unix)]
    #[test]
    fn a_replay_boots_the_guest_the_finding_records() {
        use crate::kernel_guest::Accel;
        let guest = GuestArgs {
            kernel: PathBuf::from("bzImage"),
            modules: vec![PathBuf::from("/m/widget.ko")],
            qemu: PathBuf::from("/q/qemu-system-x86_64"),
            accel: Accel::Tcg,
            memory: 2048,
            smp: 2,
            append: Some("kasan.fault=report".to_owned()),
            qemu_args: vec!["-machine".to_owned(), "q35".to_owned()],
            cc: "gcc".to_owned(),
            executor: None,
            boot_timeout: 30,
            timeout: 7,
        };
        let record = guest.record();
        // Relative paths are recorded absolute.
        let kernel = record["kernel"].as_str().unwrap();
        assert!(
            Path::new(kernel).is_absolute() && kernel.ends_with("bzImage"),
            "{kernel}"
        );
        let args = |extra: &[&str]| {
            #[derive(clap::Parser)]
            struct Cli {
                #[command(flatten)]
                replay: ReplayArgs,
            }
            let mut argv = vec!["bhf", "F-KERNEL-0000-x"];
            argv.extend_from_slice(extra);
            <Cli as clap::Parser>::parse_from(argv).replay
        };
        let again = replay_guest(&record, &args(&[])).unwrap();
        assert_eq!(again.kernel, PathBuf::from(kernel));
        assert_eq!(again.modules, guest.modules);
        assert_eq!(again.qemu, guest.qemu);
        assert_eq!(again.accel, Accel::Tcg);
        assert_eq!((again.memory, again.smp, again.timeout), (2048, 2, 7));
        assert_eq!(again.append, guest.append);
        assert_eq!(again.qemu_args, guest.qemu_args);
        assert_eq!(again.cc, "gcc");
        let moved = replay_guest(
            &record,
            &args(&[
                "--kernel",
                "/new/bzImage",
                "--module",
                "/new/a.ko",
                "--accel",
                "kvm",
                "--timeout",
                "3",
            ]),
        )
        .unwrap();
        assert_eq!(moved.kernel, PathBuf::from("/new/bzImage"));
        assert_eq!(moved.modules, vec![PathBuf::from("/new/a.ko")]);
        assert_eq!((moved.accel, moved.timeout), (Accel::Kvm, 3));
        let error = replay_guest(&serde_json::json!({}), &args(&[])).unwrap_err();
        assert!(error.to_string().contains("--kernel"), "{error}");
        // A finding's timeout past a day is cut to it; an option's is refused.
        let mut long = record.clone();
        long["timeout_secs"] = serde_json::json!(u64::MAX);
        assert_eq!(replay_guest(&long, &args(&[])).unwrap().timeout, 86_400);
        #[derive(clap::Parser)]
        struct Replay {
            #[command(flatten)]
            replay: ReplayArgs,
        }
        for flag in ["--boot-timeout", "--timeout"] {
            let parsed = <Replay as clap::Parser>::try_parse_from([
                "bhf",
                "F-KERNEL-0000-x",
                flag,
                "18446744073709551615",
            ]);
            assert!(parsed.is_err(), "{flag} 18446744073709551615 was accepted");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_device_alone_is_opened_read_written_and_called() {
        let program = device_program("/dev/widget").unwrap();
        let text = crate::kernel_guest::decode(&program).text();
        let calls: Vec<&str> = text
            .lines()
            .map(|line| line.split_once(" = ").unwrap().1.split('(').next().unwrap())
            .collect();
        assert_eq!(calls, ["openat", "read", "write", "ioctl", "close"]);
        assert!(text.contains("\"/dev/widget\\x00\""), "{text}");
    }

    #[test]
    fn ioctl_numbers_match_the_kernels_per_architecture() {
        // FS_IOC_GETFLAGS = _IOR('f', 1, long), as syzkaller's const files
        // record it.
        let long = |a: &str| ioc(&arch(a), Dir::Read, 'f' as u64, 1, arch(a).pointer).unwrap();
        assert_eq!(long("amd64"), 2_148_034_049);
        assert_eq!(long("386"), 2_147_771_905);
        assert_eq!(long("arm"), 2_147_771_905);
        assert_eq!(long("mips64le"), 1_074_292_225);
        assert_eq!(long("ppc64le"), 1_074_292_225);
        assert_eq!(long("loong64"), 2_148_034_049);
        // KVM_CREATE_VM = _IO(0xAE, 0x01).
        assert_eq!(ioc(&arch("amd64"), Dir::None, 0xae, 1, 0).unwrap(), 44_545);
        assert_eq!(
            ioc(&arch("ppc64le"), Dir::None, 0xae, 1, 0).unwrap(),
            536_915_457
        );
        // _IOWR: both direction bits.
        assert_eq!(
            ioc(&arch("amd64"), Dir::ReadWrite, 'W' as u64, 3, 40).unwrap(),
            0xc028_5703
        );
        assert_eq!(
            ioc(&arch("mips64le"), Dir::ReadWrite, 'W' as u64, 3, 40).unwrap(),
            0xc028_5703
        );
        assert_eq!(
            ioc(&arch("mips64le"), Dir::Write, 'W' as u64, 3, 40).unwrap(),
            0x8028_5703
        );
        // The size field is 14 bits, 13 on mips and powerpc.
        assert!(ioc(&arch("amd64"), Dir::Write, 1, 1, 1 << 14).is_err());
        assert!(ioc(&arch("amd64"), Dir::Write, 1, 1, (1 << 14) - 1).is_ok());
        assert!(ioc(&arch("ppc64le"), Dir::Write, 1, 1, 1 << 13).is_err());
    }

    #[test]
    fn layouts_follow_each_architectures_alignment() {
        let corpus = corpus(&[(
            "widget.h",
            "struct widget_stats { __u64 packets; __u32 errors; __u32 count; unsigned long last; };\n\
             struct widget_ptr { __u32 slot; void *reply; };\n\
             struct widget_aligned { __u32 a; __aligned_u64 b; };\n\
             struct widget_reg { __u16 addr; __u8 width : 4; __u8 bank : 4; __be32 value; } __packed;\n\
             struct widget_bits { __u32 a : 30; __u32 b : 4; };\n\
             union widget_any { __u8 tag[3]; __u16 half; };\n\
             struct widget_flex { __u32 len; __u8 data[]; };\n",
        )]);
        let size = |name: &str, a: &str| {
            layout(&corpus, &KType::Record(name.to_owned()), &arch(a), 0).unwrap()
        };
        assert_eq!(size("widget_stats", "amd64"), (24, 8));
        assert_eq!(size("widget_stats", "386"), (20, 4));
        assert_eq!(size("widget_stats", "arm"), (24, 8));
        assert_eq!(size("widget_ptr", "amd64"), (16, 8));
        assert_eq!(size("widget_ptr", "arm"), (8, 4));
        assert_eq!(size("widget_aligned", "386"), (16, 8));
        assert_eq!(size("widget_reg", "amd64"), (7, 1));
        assert_eq!(size("widget_bits", "amd64"), (8, 4));
        assert_eq!(size("widget_any", "amd64"), (4, 2));
        assert_eq!(size("widget_flex", "amd64"), (4, 4));
    }

    #[test]
    fn bit_fields_follow_each_architectures_rules() {
        // Each expectation is what clang and gcc give for the target.
        let corpus = corpus(&[(
            "widget.h",
            "struct widget_wide { __u64 a : 40; __u64 b : 40; };\n\
             struct widget_unnamed { char a; int : 3; char b; };\n\
             struct widget_zero { __u8 x : 3; __u64 : 0; __u8 y : 2; };\n\
             struct widget_after { __u32 a; __u64 : 0; __u8 c; };\n\
             struct widget_packed { char a; int : 0; char b; } __packed;\n",
        )]);
        let size = |name: &str, a: &str| {
            layout(&corpus, &KType::Record(name.to_owned()), &arch(a), 0).unwrap()
        };
        // A 64-bit bit-field may start at any 4-byte boundary on 386.
        assert_eq!(size("widget_wide", "386"), (12, 4));
        assert_eq!(size("widget_wide", "amd64"), (16, 8));
        // An unnamed bit-field's type aligns the record on arm and arm64
        // only.
        assert_eq!(size("widget_unnamed", "amd64"), (3, 1));
        assert_eq!(size("widget_unnamed", "386"), (3, 1));
        assert_eq!(size("widget_unnamed", "arm"), (4, 4));
        assert_eq!(size("widget_unnamed", "arm64"), (4, 4));
        assert_eq!(size("widget_zero", "amd64"), (9, 1));
        assert_eq!(size("widget_zero", "arm64"), (16, 8));
        // `: 0` aligns what follows to its type's alignment: 4 on 386.
        assert_eq!(size("widget_after", "386"), (8, 4));
        assert_eq!(size("widget_after", "amd64"), (12, 4));
        // Even in a packed record.
        assert_eq!(size("widget_packed", "amd64"), (5, 1));
        let offsets = |name: &str, a: &str| {
            c_record_layout(&corpus, name, &arch(a), 0)
                .unwrap()
                .spans
                .iter()
                .map(|span| span.1)
                .collect::<Vec<_>>()
        };
        assert_eq!(offsets("widget_wide", "386"), [0, 40]);
        assert_eq!(offsets("widget_after", "386"), [0, 32, 32]);
        assert_eq!(offsets("widget_after", "amd64"), [0, 64, 64]);
    }

    #[test]
    fn constant_expressions_expand_macros() {
        let corpus = corpus(&[(
            "widget.h",
            "#define WIDGET_MAGIC 'W'\n\
             #define WIDGET_BASE (0x10 + 2)\n\
             #define WIDGET_NR (WIDGET_BASE << 1 | 1)\n\
             #define WIDGET_LOOP WIDGET_LOOP\n\
             #define WIDGET_CAST ((unsigned int)7)\n",
        )]);
        assert_eq!(eval(&corpus, "WIDGET_MAGIC"), Ok(87));
        assert_eq!(eval(&corpus, "WIDGET_NR"), Ok(37));
        assert_eq!(eval(&corpus, "'\\x41' + 017 - 0b1"), Ok(65 + 15 - 1));
        assert_eq!(eval(&corpus, "WIDGET_CAST"), Ok(7));
        assert_eq!(eval(&corpus, "~0 & 0xffUL"), Ok(255));
        assert!(eval(&corpus, "WIDGET_LOOP")
            .unwrap_err()
            .contains("expands into itself"));
        let chain = corpus_chain(40);
        assert!(eval(&chain, "WIDGET_D0").unwrap_err().contains("too deep"));
        assert_eq!(eval(&corpus_chain(20), "WIDGET_D0"), Ok(1));
        assert!(eval(&corpus, "WIDGET_MISSING")
            .unwrap_err()
            .contains("not defined"));
    }

    /// `#define WIDGET_D<n> WIDGET_D<n+1>`, `levels` long, ending in 1.
    fn corpus_chain(levels: usize) -> Corpus {
        let text: String = (0..levels)
            .map(|level| format!("#define WIDGET_D{level} (WIDGET_D{} + 0)\n", level + 1))
            .collect::<String>()
            + &format!("#define WIDGET_D{levels} 1\n");
        corpus(&[("widget.h", &text)])
    }

    /// Ten-way fan-out, `levels` deep: `<prefix>0` refers to `<prefix>1` ten
    /// times, and so on, so expanding it naively visits 10^levels nodes.
    fn fan_out(levels: usize, line: impl Fn(usize) -> String) -> String {
        (0..levels).map(line).collect()
    }

    #[test]
    fn macros_and_structs_that_fan_out_are_expanded_once_each() {
        let macros = fan_out(14, |level| {
            format!(
                "#define WIDGET_M{level} ({})\n",
                vec![format!("WIDGET_M{}", level + 1); 10].join(" + ")
            )
        }) + "#define WIDGET_M14 1\n";
        let structs = fan_out(14, |level| {
            let fields: String = (0..10)
                .map(|field| format!("struct widget_s{} f{field}; ", level + 1))
                .collect();
            format!("struct widget_s{level} {{ {fields}}};\n")
        }) + "struct widget_s14 { __u8 byte; };\n";
        let corpus = corpus(&[("widget.h", &(macros + &structs))]);
        let started = std::time::Instant::now();
        assert_eq!(eval(&corpus, "WIDGET_M0"), Ok(10i128.pow(14)));
        let (size, _) = layout(
            &corpus,
            &KType::Record("widget_s0".to_owned()),
            &arch("amd64"),
            0,
        )
        .unwrap();
        assert_eq!(size, 10u64.pow(14));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_pointee_whose_members_fan_out_is_laid_out_once_per_record() {
        // Behind a pointer the argument's size bounds nothing: the layout
        // check of a struct whose members fan out must not expand them.
        let structs = fan_out(14, |level| {
            let fields: String = (0..10)
                .map(|field| format!("struct widget_s{} f{field}; ", level + 1))
                .collect();
            format!("struct widget_s{level} {{ {fields}}};\n")
        }) + "struct widget_s14 { __u8 byte; };\n";
        let started = std::time::Instant::now();
        let description = describe_arg(
            &(structs + "struct gizmo_ref { struct widget_s0 *p; };"),
            "struct gizmo_ref",
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
        assert!(
            description
                .syzlang
                .contains("gizmo_ref {\n\tp\tptr[inout, gizmo_widget_s0, opt]\n}\n"),
            "{}",
            description.syzlang
        );
    }

    #[test]
    fn a_huge_array_is_refused_rather_than_overflowing() {
        let corpus = corpus(&[(
            "widget.h",
            "struct widget_huge { __u64 cells[1UL << 62][1UL << 62]; };\n",
        )]);
        let ty = KType::Record("widget_huge".to_owned());
        let (size, _) = layout(&corpus, &ty, &arch("amd64"), 0).unwrap();
        assert!(ioc(&arch("amd64"), Dir::Write, 1, 1, size).is_err());
    }

    const UAPI: &str = "#define WIDGET_MAGIC 'W'\n\
        struct widget_cfg { __u32 mode; char name[8]; };\n\
        #define WIDGET_IOC_RESET _IO(WIDGET_MAGIC, 0)\n\
        #define WIDGET_IOC_SET _IOW(WIDGET_MAGIC, 1, struct widget_cfg)\n\
        #define WIDGET_IOC_PEEK _IOR(WIDGET_MAGIC, 2, struct widget_hidden)\n\
        #define WIDGET_IOC_UNUSED _IOW(WIDGET_MAGIC, 9, int)\n\
        #define WIDGET_LEGACY 0x7701\n";

    const DRIVER: &str =
        "static long widget_ioctl(struct file *f, unsigned int cmd, unsigned long arg)\n\
        {\n\
        \tswitch (cmd) {\n\
        \tcase WIDGET_IOC_RESET: return 0;\n\
        \tcase WIDGET_IOC_SET: return 0;\n\
        \tcase WIDGET_IOC_PEEK: return 0;\n\
        \tcase WIDGET_LEGACY: return 0;\n\
        \t}\n\
        \treturn -ENOTTY;\n\
        }\n\
        static const struct file_operations widget_fops = { .unlocked_ioctl = widget_ioctl };\n\
        static struct miscdevice widget_dev = { .name = \"widget\", .fops = &widget_fops };\n";

    #[test]
    fn a_handler_describes_the_commands_it_dispatches_on() {
        let corpus = corpus(&[("widget.h", UAPI), ("widget.c", DRIVER)]);
        let description = describe(&corpus, None, None).unwrap();
        assert_eq!(description.name, "widget");
        let text = &description.syzlang;
        assert!(text.contains("resource fd_widget[fd]\n"), "{text}");
        assert!(
            text.contains("openat$widget(fd const[AT_FDCWD], file ptr[in, string[\"/dev/widget\"]], flags flags[open_flags], mode const[0]) fd_widget\n"),
            "{text}"
        );
        assert!(text.contains(
            "ioctl$WIDGET_IOC_RESET(fd fd_widget, cmd const[WIDGET_IOC_RESET], arg intptr)\n"
        ));
        assert!(text.contains(
            "ioctl$WIDGET_IOC_SET(fd fd_widget, cmd const[WIDGET_IOC_SET], arg ptr[in, widget_cfg])\n"
        ));
        assert!(text.contains(
            "ioctl$WIDGET_LEGACY(fd fd_widget, cmd const[WIDGET_LEGACY], arg ptr[inout, array[int8]])\n"
        ));
        assert!(text.contains("widget_cfg {\n\tmode\tint32\n\tname\tarray[int8, 8]\n}\n"));
        // Not dispatched on: not described.
        assert!(!text.contains("WIDGET_IOC_UNUSED"), "{text}");
        // An argument type the source does not define: left out, with why.
        assert!(text.contains(
            "# Not described: WIDGET_IOC_PEEK: `struct widget_hidden` is not defined in the scanned source\n"
        ));
        assert_eq!(
            description.skipped,
            vec![(
                "WIDGET_IOC_PEEK".to_owned(),
                "`struct widget_hidden` is not defined in the scanned source".to_owned()
            )]
        );
        assert_eq!(description.described, 3);
        assert_eq!(
            description.consts,
            "# Generated by `bhf kernel syzlang`: the ioctl command numbers dev_widget.txt uses.\n\
             arches = 386, amd64, arm, arm64, loong64, mips64le, ppc64le, riscv64, s390x\n\
             WIDGET_IOC_RESET = 22272, mips64le:536893184, ppc64le:536893184\n\
             WIDGET_IOC_SET = 1074550529, mips64le:2148292353, ppc64le:2148292353\n\
             WIDGET_LEGACY = 30465\n"
        );
    }

    #[test]
    fn without_a_switch_on_cmd_every_command_macro_is_described() {
        let driver = "static long widget_ioctl(struct file *f, unsigned int cmd, unsigned long arg)\n\
            { return widget_table[_IOC_NR(cmd)](f, arg); }\n\
            static const struct file_operations widget_fops = { .unlocked_ioctl = widget_ioctl };\n";
        let corpus = corpus(&[("widget.h", UAPI), ("widget.c", driver)]);
        let description = describe(&corpus, None, Some("/dev/widget0")).unwrap();
        let text = &description.syzlang;
        assert!(text.contains("ioctl$WIDGET_IOC_UNUSED("), "{text}");
        assert!(text.contains("arg ptr[in, int32])"), "{text}");
        assert!(!text.contains("WIDGET_LEGACY("), "{text}");
        assert!(text.contains("string[\"/dev/widget0\"]"), "{text}");
        assert!(
            text.replace("\n# ", " ")
                .contains("every _IO/_IOR/_IOW/_IOWR command of the source read is described"),
            "{text}"
        );
    }

    #[test]
    fn commands_passed_on_to_a_helper_are_followed() {
        let driver = "static long widget_xfer(void *state, unsigned int op)\n\
            { switch (op) { case WIDGET_IOC_SET: return 1; } return 0; }\n\
            static long widget_ioctl(struct file *f, unsigned int cmd, unsigned long arg)\n\
            { switch (cmd) { case WIDGET_IOC_RESET: return 0; default: return widget_xfer(f, cmd); } }\n\
            static const struct file_operations widget_fops = { .compat_ioctl = widget_ioctl };\n\
            int widget_init(void) { device_create(cls, NULL, 0, NULL, \"widget%d\", 1); return 0; }\n";
        let corpus = corpus(&[("widget.h", UAPI), ("widget.c", driver)]);
        let description = describe(&corpus, None, None).unwrap();
        let text = &description.syzlang;
        assert!(text.contains("ioctl$WIDGET_IOC_SET("), "{text}");
        assert!(text.contains("ioctl$WIDGET_IOC_RESET("), "{text}");
        assert!(
            text.contains("syz_open_dev$widget(dev ptr[in, string[\"/dev/widget#\"]], id intptr, flags flags[open_flags]) fd_widget\n"),
            "{text}"
        );
    }

    #[test]
    fn no_handler_is_an_error_that_says_what_was_looked_for() {
        let corpus = corpus(&[("widget.h", UAPI)]);
        let error = describe(&corpus, None, None).err().unwrap().to_string();
        assert!(error.contains("no ioctl handler found"), "{error}");
    }

    /// The description of one `_IOW` command whose argument is `arg`,
    /// defined with the other `records` in a uapi header.
    fn describe_arg(records: &str, arg: &str) -> Description {
        let header = format!("{records}\n#define GIZMO_IOC_SET _IOW('G', 1, {arg})\n");
        let driver =
            "static long gizmo_ioctl(struct file *f, unsigned int cmd, unsigned long arg)\n\
            { switch (cmd) { case GIZMO_IOC_SET: return 0; } return -ENOTTY; }\n\
            static const struct file_operations gizmo_fops = { .unlocked_ioctl = gizmo_ioctl };\n\
            static struct miscdevice gizmo_dev = { .name = \"gizmo\", .fops = &gizmo_fops };\n";
        let corpus = corpus(&[
            ("include/uapi/linux/gizmo.h", &header),
            ("drivers/misc/gizmo.c", driver),
        ]);
        describe(&corpus, None, None).unwrap()
    }

    /// Whether syzkaller's compiler would reject comment line `line` as one
    /// faking a directive (`^\s*(include|incdir|define)` after the `#`).
    fn fakes_a_directive(line: &str) -> bool {
        line.strip_prefix('#').is_some_and(|text| {
            let text = text.trim_start();
            ["include", "incdir", "define"]
                .iter()
                .any(|word| text.starts_with(word))
        })
    }

    #[test]
    fn no_comment_of_a_description_reads_as_a_directive() {
        // A uapi header under include/, and command and file_operations
        // names a wrapped header line could start with.
        let header = "#define GIZMO_MAGIC 'G'\n\
            #define GIZMO_IOC_RESET _IO(GIZMO_MAGIC, 0)\n\
            #define define_gizmo_probe _IO(GIZMO_MAGIC, 1)\n";
        let driver = "static long gizmo_ioctl(struct file *f, unsigned int cmd, unsigned long arg)\n\
            { switch (cmd) { case GIZMO_IOC_RESET: case define_gizmo_probe: return 0; } return 0; }\n\
            static const struct file_operations include_gizmo_fops = { .unlocked_ioctl = gizmo_ioctl };\n\
            static struct miscdevice gizmo_dev = { .name = \"gizmo\", .fops = &include_gizmo_fops };\n";
        let corpus = corpus(&[
            ("include/uapi/linux/gizmo.h", header),
            ("drivers/misc/gizmo.c", driver),
        ]);
        let text = describe(&corpus, None, None).unwrap().syzlang;
        assert!(
            text.contains(
                "# GIZMO_IOC_RESET defined at include/uapi/linux/gizmo.h:2: _IO(GIZMO_MAGIC, 0)\n"
            ),
            "{text}"
        );
        let faking: Vec<&str> = text
            .lines()
            .filter(|line| fakes_a_directive(line))
            .collect();
        assert!(faking.is_empty(), "{faking:?}\n{text}");
        // A header line wrapped before a word that would fake a directive
        // keeps that word on the line before.
        for width in 1..60 {
            for line in wrap(
                "Handler gizmo_ioctl (drivers/misc/gizmo.c:1), .unlocked_ioctl of include_gizmo_fops \
                 defined in include/uapi/linux/gizmo.h",
                width,
            ) {
                assert!(!fakes_a_directive(&format!("# {line}")), "{width}: {line}");
            }
        }
    }

    #[test]
    fn members_named_after_syzlang_keywords_are_renamed() {
        let text = describe_arg(
            "struct gizmo_kw { __u32 type; __u32 resource; __u32 include; __u32 incdir; \
             __u32 define; __u32 parent; __u32 len; };",
            "struct gizmo_kw",
        )
        .syzlang;
        assert!(
            text.contains(
                "gizmo_kw {\n\ttype\tint32\n\tresource_\tint32\n\tinclude_\tint32\n\
                 \tincdir_\tint32\n\tdefine_\tint32\n\tparent_\tint32\n\tlen\tint32\n}\n"
            ),
            "{text}"
        );
    }

    #[test]
    fn a_bit_field_in_a_union_is_described_by_its_type() {
        let description = describe_arg(
            "struct gizmo_bits { union { __u32 a : 3; __u32 b : 5; } u; __u32 tail; };",
            "struct gizmo_bits",
        );
        let text = &description.syzlang;
        assert!(
            text.contains("gizmo_bits_u [\n\ta\tint32\n\tb\tint32\n]\n"),
            "{text}"
        );
        assert_eq!(description.described, 1, "{text}");
    }

    #[test]
    fn always_aligned_64_bit_members_keep_their_alignment() {
        let description = describe_arg(
            "struct gizmo_al { __u32 a; __aligned_u64 b; __u32 c; __aligned_be64 d; };",
            "struct gizmo_al",
        );
        let text = &description.syzlang;
        assert!(
            text.contains(
                "gizmo_al {\n\ta\tint32\n\tb\talign64[int64]\n\tc\tint32\n\td\talign64[int64be]\n}\n"
            ),
            "{text}"
        );
        // 32 bytes on every architecture, 386 included.
        assert!(
            description
                .consts
                .contains("GIZMO_IOC_SET = 1075857153, mips64le:2149598977, ppc64le:2149598977\n"),
            "{}",
            description.consts
        );
    }

    #[test]
    fn a_zero_width_bit_field_starts_the_next_unit() {
        let description = describe_arg(
            "struct gizmo_pb { __u32 x : 3; __u32 : 0; __u32 y : 2; };",
            "struct gizmo_pb",
        );
        let text = &description.syzlang;
        // y starts the second 32-bit unit, as in C: 8 bytes.
        assert!(
            text.contains(
                "gizmo_pb {\n\tx\tint32:3\n\tunused0\tconst[0, int8:5]\n\
                 \tunused1\tarray[const[0, int8], 3]\n\ty\tint32:2\n}\n"
            ),
            "{text}"
        );
        assert!(
            description
                .consts
                .contains("GIZMO_IOC_SET = 1074284289, mips64le:2148026113, ppc64le:2148026113\n"),
            "{}",
            description.consts
        );
    }

    fn emitter(corpus: &Corpus) -> Emitter<'_> {
        Emitter {
            corpus,
            prefix: "gizmo".to_owned(),
            names: HashMap::new(),
            taken: HashSet::new(),
            definitions: Vec::new(),
            records: Vec::new(),
            layouts: RefCell::default(),
        }
    }

    #[test]
    fn rendered_layouts_match_the_c_layout_on_every_architecture() {
        let corpus = corpus(&[(
            "gizmo.h",
            "struct gizmo_al { __u32 a; __aligned_u64 b; };\n\
             struct gizmo_pb { __u32 x : 3; __u32 : 0; __u32 y : 2; };\n\
             struct gizmo_plain { __u32 a; __u64 b; };\n\
             struct gizmo_gap { __u8 x : 3; __u8 : 4; __u8 y : 4; char tail; };\n\
             struct gizmo_jump { __u32 a : 30; __u32 : 5; __u32 b : 2; };\n",
        )]);
        let mut emitter = emitter(&corpus);
        let mut slots = HashMap::new();
        for name in [
            "gizmo_al",
            "gizmo_pb",
            "gizmo_plain",
            "gizmo_gap",
            "gizmo_jump",
        ] {
            let (_, slot) = emitter.record(name).unwrap();
            slots.insert(name, slot);
            for arch in &ARCHES {
                let c = c_record_layout(&corpus, name, arch, 0).unwrap();
                let SyzRecordLayout {
                    size,
                    align,
                    offsets,
                } = emitter.syz_record_layout(slot, arch, 0).unwrap();
                assert_eq!(
                    (size, align),
                    (Some(c.size), c.align),
                    "{name} on {}",
                    arch.name
                );
                for (field, offset) in emitter.records[slot].fields.iter().zip(&offsets) {
                    if let Some(member) = field.member {
                        assert_eq!(
                            *offset, c.spans[member].1,
                            "{name}.{} on {}",
                            field.name, arch.name
                        );
                    }
                }
            }
            assert!(emitter.check_layouts(slot).is_ok(), "{name}");
        }
        let i386 = arch("386");
        let c = c_record_layout(&corpus, "gizmo_al", &i386, 0).unwrap();
        assert_eq!((c.size, c.spans[1].1), (16, 64));
        let c = c_record_layout(&corpus, "gizmo_pb", &i386, 0).unwrap();
        assert_eq!((c.size, c.spans[2].1), (8, 32));
        // As a plain int64, b would sit at byte 4 on 386 and the record
        // would be 12 bytes; as dropped, `: 0` would leave y in x's unit.
        let al = slots["gizmo_al"];
        let mut plain = emitter.clone();
        plain.layouts.borrow_mut().clear();
        plain.records[al].fields[1].ty = Syz::Int(8);
        let error = plain.check_layouts(al).unwrap_err();
        assert!(
            error.contains("on 386: member `b` at byte 4, C puts it at byte 8"),
            "{error}"
        );
        let pb = slots["gizmo_pb"];
        let mut dropped = emitter.clone();
        dropped.layouts.borrow_mut().clear();
        dropped.records[pb]
            .fields
            .retain(|field| field.member.is_some());
        let error = dropped.check_layouts(pb).unwrap_err();
        assert!(
            error.contains("member `y` at bit 3, C puts it at byte 4"),
            "{error}"
        );
    }

    #[test]
    fn a_layout_syzkaller_cannot_give_is_left_out_with_the_reason() {
        // On 386 a 64-bit bit-field may start at any 4-byte boundary, so
        // b starts at bit 40; syzkaller starts every int64 unit at a
        // multiple of 8 bytes.
        let corpus = corpus(&[
            (
                "include/uapi/linux/gizmo.h",
                "struct gizmo_wide { __u64 a : 40; __u64 b : 40; };\n\
                 struct gizmo_ok { __u32 a; };\n\
                 #define GIZMO_IOC_WIDE _IOW('G', 1, struct gizmo_wide)\n\
                 #define GIZMO_IOC_OK _IOW('G', 2, struct gizmo_ok)\n",
            ),
            (
                "drivers/misc/gizmo.c",
                "static long gizmo_ioctl(struct file *f, unsigned int cmd, unsigned long arg)\n\
                 { switch (cmd) { case GIZMO_IOC_WIDE: case GIZMO_IOC_OK: return 0; } return 0; }\n\
                 static const struct file_operations gizmo_fops = { .unlocked_ioctl = gizmo_ioctl };\n",
            ),
        ]);
        let description = describe(&corpus, None, Some("/dev/gizmo")).unwrap();
        let text = &description.syzlang;
        assert!(!text.contains("ioctl$GIZMO_IOC_WIDE("), "{text}");
        assert!(!text.contains("gizmo_wide {"), "{text}");
        assert!(text.contains("ioctl$GIZMO_IOC_OK("), "{text}");
        let (name, reason) = &description.skipped[0];
        assert_eq!(name, "GIZMO_IOC_WIDE");
        assert!(
            reason.contains("`gizmo_wide`") && reason.contains("386") && reason.contains("`b`"),
            "{reason}"
        );
    }

    #[test]
    fn a_union_is_sized_as_c_pads_it() {
        // C rounds the union up to its alignment, 8 bytes; syzkaller sizes a
        // union by its largest member, 5, unless told.
        let text = describe_arg(
            "struct gizmo_u { union { __u32 a; __u8 b[5]; } u; __u8 tail; };",
            "struct gizmo_u",
        )
        .syzlang;
        assert!(
            text.contains("gizmo_u_u [\n\ta\tint32\n\tb\tarray[int8, 5]\n] [size[8]]\n"),
            "{text}"
        );
    }

    #[test]
    fn expressions_that_overflow_are_errors_not_panics() {
        let corpus = corpus(&[(
            "gizmo.h",
            "#define GIZMO_BIG (-170141183460469231731687303715884105727 - 1)\n\
             #define GIZMO_DIV (GIZMO_BIG / -1)\n\
             #define GIZMO_REM (GIZMO_BIG % -1)\n\
             #define GIZMO_NEG (-(GIZMO_BIG))\n",
        )]);
        for name in ["GIZMO_DIV", "GIZMO_REM", "GIZMO_NEG"] {
            let error = eval(&corpus, name).unwrap_err();
            assert!(error.contains("overflows"), "{name}: {error}");
        }
        assert_eq!(eval(&corpus, "GIZMO_BIG / 2"), Ok(i128::MIN / 2));
    }

    #[test]
    fn device_paths_turn_format_specifiers_into_syz_open_dev_numbers() {
        assert_eq!(device_path("widget"), "/dev/widget");
        assert_eq!(device_path("widget%d"), "/dev/widget#");
        assert_eq!(device_path("widget/ctl%lu"), "/dev/widget/ctl#");
    }
}
