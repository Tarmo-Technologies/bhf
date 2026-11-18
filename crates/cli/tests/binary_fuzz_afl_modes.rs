// SPDX-License-Identifier: Apache-2.0

//! `bhf binary fuzz` under AFL++'s binary-only modes, on binaries built
//! without instrumentation.
//! `--engine afl-frida` finds an abort (#322).
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
