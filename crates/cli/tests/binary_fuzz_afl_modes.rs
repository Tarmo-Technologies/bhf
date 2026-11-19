// SPDX-License-Identifier: Apache-2.0

//! `bhf binary fuzz` under AFL++'s binary-only modes, on binaries built
//! without instrumentation:
//! - `--engine afl-frida` finds an abort (#322);
//! - a QEMU-mode persistent loop (`--persistent-addr`) finds one, faster
//!   than a QEMU run that starts the binary for every input (#375);
//! - CmpLog, on by default, solves a four-byte magic that a run with
//!   `--no-cmplog` does not reach in the same budget (#376).
//!
//! These need `afl-fuzz` and AFL++'s QEMU and Frida modes, which Ubuntu's
//! afl++ package leaves out: `scripts/ci/build-afl-binary-modes.sh` builds
//! them, as the container image and the nightly do, and
//! `BHF_AFL_BINARY_MODES` names where it installed them (else the image's
//! `/usr/bin` and `/usr/lib/afl`). `BHF_REQUIRE_TOOLS=1` makes a missing one
//! a failure.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::path::{Path, PathBuf};
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// The AFL++ QEMU- and Frida-mode files, if they and afl-fuzz are here.
struct Modes {
    qemu_trace: PathBuf,
    frida_trace: PathBuf,
}

/// The modes `BHF_AFL_BINARY_MODES` (an install prefix) or the image names,
/// through `support::require_tool`.
fn have_afl_binary_modes() -> Option<Modes> {
    let prefix = std::env::var_os("BHF_AFL_BINARY_MODES")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"));
    let modes = Modes {
        qemu_trace: prefix.join("usr/bin/afl-qemu-trace"),
        frida_trace: prefix.join("usr/lib/afl/afl-frida-trace.so"),
    };
    let found = Command::new("afl-fuzz").arg("-h").output().is_ok()
        && Command::new("cc").arg("--version").output().is_ok()
        && modes.qemu_trace.is_file()
        && modes.frida_trace.is_file();
    support::require_tool(found, "afl-fuzz with AFL++'s QEMU and Frida modes").then_some(modes)
}

/// Compile `source` without instrumentation, as a non-PIE executable so its
/// symbols' addresses are where QEMU runs them.
fn build(dir: &Path, name: &str, source: &str) -> PathBuf {
    let c = dir.join(format!("{name}.c"));
    std::fs::write(&c, source).unwrap();
    let elf = dir.join(name);
    let built = Command::new("cc")
        .args(["-O1", "-no-pie", "-fno-inline", "-o"])
        .arg(&elf)
        .arg(&c)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    elf
}

/// `bhf binary fuzz <elf> <args>` with the modes' files named, and its run
/// JSON.
fn binary_fuzz(modes: &Modes, work: &Path, elf: &Path, args: &[&str]) -> serde_json::Value {
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["binary", "fuzz"])
        .arg(elf)
        .arg("--work-dir")
        .arg(work)
        .args(args)
        .env("BHF_AFL_QEMU_TRACE", &modes.qemu_trace)
        .env("BHF_AFL_FRIDA_TRACE", &modes.frida_trace)
        .env("AFL_NO_AFFINITY", "1")
        .output()
        .expect("run bhf binary fuzz");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json = &stdout[stdout.find('{').expect("a run JSON")..];
    let end = json.rfind('}').unwrap() + 1;
    serde_json::from_str(&json[..end]).unwrap_or_else(|e| panic!("{e}: {stdout}"))
}

fn findings(run: &serde_json::Value) -> usize {
    run["findings"].as_array().map_or(0, Vec::len)
}

/// Reads stdin and aborts on an input starting "FU".
const ABORT_ON_FU: &str = "#include <stdlib.h>\n#include <unistd.h>\n\
    int main(void) {\n  char b[8] = {0};\n  ssize_t n = read(0, b, sizeof b);\n  \
    if (n > 1 && b[0] == 'F' && b[1] == 'U') abort();\n  return 0;\n}\n";

#[test]
fn frida_mode_finds_the_abort_and_records_its_engine() {
    let Some(modes) = have_afl_binary_modes() else {
        eprintln!("skipping: no AFL++ Frida mode");
        return;
    };
    let dir = TestDir::new("afl-frida");
    let elf = build(&dir, "gate", ABORT_ON_FU);
    let run = binary_fuzz(
        &modes,
        &dir.join("work"),
        &elf,
        &[
            "--engine",
            "afl-frida",
            "--seed-input",
            "AAAA",
            "--time",
            "30s",
        ],
    );
    assert_eq!(run["engine"], "afl-frida", "{run:#}");
    assert_eq!(run["degraded"], false, "{run:#}");
    assert!(run["fidelity"]["coverage"]
        .as_str()
        .is_some_and(|coverage| coverage.contains("Frida")));
    assert!(run["fidelity"]["edges_found"].as_u64() > Some(0), "{run:#}");
    assert!(findings(&run) > 0, "Frida mode finds the abort: {run:#}");
}

/// Reads its input file in `process`, which `main` calls once: a persistent
/// loop around `process` runs each input without starting the binary again.
const PROCESS_FILE: &str = "#include <stdio.h>\n#include <stdlib.h>\n\
    int process(const char *path) {\n  char b[8] = {0};\n  FILE *f = fopen(path, \"rb\");\n  \
    if (!f) return 1;\n  size_t n = fread(b, 1, sizeof b, f);\n  fclose(f);\n  \
    if (n > 1 && b[0] == 'F' && b[1] == 'U') abort();\n  return 0;\n}\n\
    int main(int argc, char **argv) { return argc > 1 ? process(argv[1]) : 1; }\n";

/// The address of the function `name` (from `nm`), as `0x` hex.
fn symbol(elf: &Path, name: &str) -> String {
    let out = Command::new("nm").arg(elf).output().expect("run nm");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            let addr = u64::from_str_radix(fields.next()?, 16).ok()?;
            (fields.next()? == "T" && fields.next()? == name).then(|| format!("0x{addr:x}"))
        })
        .unwrap_or_else(|| panic!("no {name} in {}", elf.display()))
}

#[test]
fn a_qemu_persistent_loop_finds_the_abort_faster_than_a_restart_per_input() {
    let Some(modes) = have_afl_binary_modes() else {
        eprintln!("skipping: no AFL++ QEMU mode");
        return;
    };
    let dir = TestDir::new("afl-qemu-persistent");
    let elf = build(&dir, "process", PROCESS_FILE);
    let addr = symbol(&elf, "process");
    let common = [
        "--engine",
        "afl-qemu",
        "--input-mode",
        "file",
        "--seed-input",
        "AAAA",
        "--time",
        "15s",
    ];
    let persistent_args: Vec<&str> = common
        .iter()
        .copied()
        .chain(["--persistent-addr", addr.as_str()])
        .collect();
    let persistent = binary_fuzz(&modes, &dir.join("persistent"), &elf, &persistent_args);
    assert_eq!(persistent["fidelity"]["persistent_addr"], addr.as_str());
    assert!(
        findings(&persistent) > 0,
        "the persistent loop finds the abort: {persistent:#}"
    );
    let restarting = binary_fuzz(&modes, &dir.join("restarting"), &elf, &common);
    let execs = |run: &serde_json::Value| run["executions"].as_u64().unwrap_or(0);
    assert!(
        execs(&persistent) > 2 * execs(&restarting),
        "a persistent loop runs inputs without starting the binary again: {} vs {} executions",
        execs(&persistent),
        execs(&restarting)
    );
}

/// Aborts only on a four-byte magic, compared as one integer: the havoc
/// stage does not guess it, CmpLog reads it off the comparison.
const MAGIC: &str = "#include <stdint.h>\n#include <stdlib.h>\n#include <string.h>\n\
    #include <unistd.h>\n\
    int main(void) {\n  unsigned char b[8] = {0};\n  ssize_t n = read(0, b, sizeof b);\n  \
    uint32_t v;\n  if (n < 4) return 0;\n  memcpy(&v, b, 4);\n  \
    if (v == 0x4b434148u) abort();\n  return 0;\n}\n";

#[test]
fn cmplog_solves_a_magic_the_same_run_without_it_does_not() {
    let Some(modes) = have_afl_binary_modes() else {
        eprintln!("skipping: no AFL++ QEMU mode");
        return;
    };
    let dir = TestDir::new("afl-qemu-cmplog");
    let elf = build(&dir, "magic", MAGIC);
    let args = [
        "--engine",
        "afl-qemu",
        "--seed-input",
        "AAAAAAAA",
        "--time",
        "20s",
    ];
    let with = binary_fuzz(&modes, &dir.join("cmplog"), &elf, &args);
    assert_eq!(with["fidelity"]["cmplog"], true, "{with:#}");
    assert!(findings(&with) > 0, "CmpLog solves the magic: {with:#}");
    let without_args: Vec<&str> = args.iter().copied().chain(["--no-cmplog"]).collect();
    let without = binary_fuzz(&modes, &dir.join("plain"), &elf, &without_args);
    assert_eq!(without["fidelity"]["cmplog"], false, "{without:#}");
    assert_eq!(
        findings(&without),
        0,
        "without CmpLog the havoc stage does not guess a 32-bit magic in the same budget: \
         {without:#}"
    );
}
