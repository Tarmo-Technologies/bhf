// SPDX-License-Identifier: Apache-2.0

//! `bhf kernel run`: a Linux kernel in a qemu-system guest, with bhf's
//! executor (`c_runtime/kernel_executor.c`) as its `/init`.
//!
//! These tests boot a real guest, so they run where `BHF_KERNEL_GUEST=1`,
//! with `BHF_KERNEL_IMAGE` naming a kernel built with KCOV and KASAN
//! (`scripts/ci/build-kcov-guest-kernel.sh` builds one, with the widget
//! driver fixture as `BHF_KERNEL_MODULE`), and qemu-system-x86_64 and a C
//! compiler that links statically on `PATH`. With `BHF_REQUIRE_TOOLS=1` a
//! missing one fails the test. The protocol and the executor's decoder are
//! tested without a guest in `kernel_guest`'s unit tests.

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn bhf() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
}

/// The guest kernel, when this run boots guests and one is there.
fn guest_kernel() -> Option<PathBuf> {
    if std::env::var_os("BHF_KERNEL_GUEST").is_none_or(|value| value != "1") {
        eprintln!(
            "skip kernel_guest_cli: set BHF_KERNEL_GUEST=1 and BHF_KERNEL_IMAGE to a KCOV kernel \
             (scripts/ci/build-kcov-guest-kernel.sh builds one)"
        );
        return None;
    }
    let kernel = std::env::var_os("BHF_KERNEL_IMAGE").map(PathBuf::from);
    let available = kernel.as_ref().is_some_and(|path| path.is_file())
        && which::which("qemu-system-x86_64").is_ok();
    support::require_tool(
        available,
        "a KCOV guest kernel (BHF_KERNEL_IMAGE) and qemu-system-x86_64",
    )
    .then(|| kernel.unwrap())
}

/// The widget driver module, when the kernel's build made one.
fn widget_module() -> Option<PathBuf> {
    let module = std::env::var_os("BHF_KERNEL_MODULE").map(PathBuf::from);
    let available = module.as_ref().is_some_and(|path| path.is_file());
    support::require_tool(available, "the widget driver module (BHF_KERNEL_MODULE)")
        .then(|| module.unwrap())
}

/// A program in the executor's format, written call by call.
#[derive(Default)]
struct Program {
    bytes: Vec<u8>,
}

impl Program {
    /// Call `selector` (0 openat, 1 close, 2 read, 3 write, 4 ioctl, ...).
    fn call(mut self, selector: u8, args: &[Arg<'_>]) -> Self {
        self.bytes.push(selector);
        self.bytes.push(args.len() as u8);
        for arg in args {
            match arg {
                Arg::Const(value) => {
                    self.bytes.push(0);
                    self.bytes.extend_from_slice(&value.to_le_bytes());
                }
                Arg::Data(bytes) => {
                    self.bytes.push(1);
                    self.bytes
                        .extend_from_slice(&(bytes.len() as u16).to_le_bytes());
                    self.bytes.extend_from_slice(bytes);
                }
                Arg::Result(call) => self.bytes.extend_from_slice(&[2, *call]),
            }
        }
        self
    }

    fn open(path: &[u8], flags: u64) -> Self {
        Self::default().call(
            0,
            &[
                Arg::Const(-100i64 as u64),
                Arg::Data(path),
                Arg::Const(flags),
                Arg::Const(0),
            ],
        )
    }

    fn write_to(self, dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, &self.bytes).unwrap();
        path
    }
}

enum Arg<'a> {
    Const(u64),
    Data(&'a [u8]),
    Result(u8),
}

fn run(kernel: &Path, modules: &[&Path], work: &Path, programs: &[PathBuf]) -> Output {
    let mut command = bhf();
    command
        .args(["kernel", "run", "--json", "--timeout", "20"])
        .arg("--kernel")
        .arg(kernel)
        .arg("--work-dir")
        .arg(work);
    for module in modules {
        command.arg("--module").arg(module);
    }
    command.args(programs).output().expect("bhf runs")
}

fn json_lines(stdout: &[u8]) -> Vec<Value> {
    String::from_utf8_lossy(stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("{line}: {e}")))
        .collect()
}

/// Inside a KCOV guest, the executor runs a program and its reply carries
/// each call's result and a non-empty set of KCOV edges.
#[test]
fn a_kcov_guest_runs_a_program_and_returns_its_edges() {
    let Some(kernel) = guest_kernel() else {
        return;
    };
    let work = TestDir::new("kernel-guest-run");
    let program = Program::open(b"/dev/null\0", 1)
        .call(3, &[Arg::Result(0), Arg::Data(b"abc"), Arg::Const(3)])
        .call(1, &[Arg::Result(0)])
        .write_to(&work, "devnull.bin");
    let output = run(&kernel, &[], &work, &[program.clone(), program]);
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let runs = json_lines(&output.stdout);
    assert_eq!(runs.len(), 2, "{runs:#?}");
    for run in &runs {
        assert_eq!(run["status"], "ok", "{run:#}");
        assert_eq!(run["kcov"], true, "{run:#}");
        let calls = run["calls"].as_array().unwrap();
        let names: Vec<&str> = calls.iter().map(|c| c["call"].as_str().unwrap()).collect();
        assert_eq!(names, ["openat", "write", "close"]);
        assert!(calls[0]["result"].as_i64().unwrap() >= 0, "{run:#}");
        assert_eq!(calls[1]["result"], 3, "{run:#}");
        assert_eq!(calls[2]["result"], 0, "{run:#}");
        // Every call ran kernel code KCOV traced.
        for call in calls {
            assert!(call["pcs"].as_u64().unwrap() > 0, "{run:#}");
        }
        assert!(run["edges"].as_u64().unwrap() > 0, "{run:#}");
    }
    assert!(work.join("kernel/guest/console.log").is_file());
}

/// The executor loads `--module` at boot: the widget driver's node opens
/// and its ioctl runs.
#[test]
fn a_module_given_at_boot_serves_its_device() {
    let Some(kernel) = guest_kernel() else {
        return;
    };
    let Some(module) = widget_module() else {
        return;
    };
    let work = TestDir::new("kernel-guest-module");
    // WIDGET_IOC_GET_STATS into a 24-byte buffer.
    let program = Program::open(b"/dev/widget\0", 2)
        .call(
            4,
            &[
                Arg::Result(0),
                Arg::Const(0x8018_5702),
                Arg::Data(&[0u8; 24]),
            ],
        )
        .write_to(&work, "stats.bin");
    let output = run(&kernel, &[&module], &work, &[program]);
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let runs = json_lines(&output.stdout);
    let calls = runs[0]["calls"].as_array().unwrap();
    assert!(calls[0]["result"].as_i64().unwrap() >= 0, "{runs:#?}");
    assert_eq!(calls[1]["result"], 0, "{runs:#?}");
    assert_eq!(calls[1]["errno"], 0, "{runs:#?}");
}

fn widget_source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/kernel_widget/linux")
}

fn fuzz(kernel: &Path, module: &Path, work: &Path, iterations: usize) -> Output {
    bhf()
        .args(["kernel", "fuzz", "--timeout", "20", "--rng-seed", "7"])
        .arg("--kernel")
        .arg(kernel)
        .arg("--module")
        .arg(module)
        .arg("--source")
        .arg(widget_source())
        .arg("--work-dir")
        .arg(work)
        .args(["--iterations", &iterations.to_string()])
        .output()
        .expect("bhf runs")
}

/// A campaign of a fixed number of programs on the widget driver: the
/// KCOV coverage grows past the seeds', and the programs that grew it join
/// the corpus.
#[test]
fn coverage_grows_over_a_fixed_number_of_programs() {
    let Some(kernel) = guest_kernel() else {
        return;
    };
    let Some(module) = widget_module() else {
        return;
    };
    let work = TestDir::new("kernel-guest-fuzz");
    let output = fuzz(&kernel, &module, &work, 150);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: Value =
        serde_json::from_slice(&fs::read(work.join("kernel/fuzz.json")).unwrap()).unwrap();
    assert_eq!(summary["schema"], "bhf.kernel-fuzz.v1");
    assert_eq!(summary["kcov"], true, "{summary:#}");
    assert_eq!(summary["executions"], 150, "{summary:#}");
    // One seed per command the handler dispatches on, and one with all.
    assert_eq!(summary["seeds"], 7, "{summary:#}");
    let after_seeds = summary["coverage_after_seeds"]["edges"].as_u64().unwrap();
    let end = summary["coverage"]["edges"].as_u64().unwrap();
    assert!(after_seeds > 0, "{summary:#}");
    assert!(end > after_seeds, "{summary:#}");
    let corpus_new = summary["corpus_new"].as_u64().unwrap();
    assert!(corpus_new > 0, "{summary:#}");
    let kept = fs::read_dir(work.join("kernel/corpus")).unwrap().count() as u64;
    assert_eq!(kept, summary["corpus"].as_u64().unwrap(), "{summary:#}");
    assert!(stdout.contains("KCOV edges"), "{stdout}");
}
