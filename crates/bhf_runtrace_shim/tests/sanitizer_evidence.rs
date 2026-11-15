// SPDX-License-Identifier: Apache-2.0
//! The shim must not change what AddressSanitizer reports about the target.
//!
//! bhf's driver passes each input in a heap allocation of exactly its size and
//! publishes it to the shim (`bhf_shim_set_fuzz_input`), and a generated
//! harness publishes it again at the top of `bhf_run_one`. A read past the end
//! of the input that goes beyond the redzone lands in whatever ASan put next on
//! the heap. A shim that kept its copy of the input on the target's heap put
//! that copy right there: the report then named the shim's allocation (or, for
//! the copy the second publication freed, a heap-use-after-free), and a read
//! into the live copy was not reported at all. Fuzzing and replay preload the
//! shim, so the finding set depended on whether it was installed.
//!
//! The probe is bhf's own driver (`c_runtime/bhf_driver.c`) linked to a
//! harness that publishes like a generated one and reads at an offset the
//! input gives. Each input runs with and without the shim; the error kind, the
//! described region and the allocation stack must be the same, and every read
//! past the input must be a heap-buffer-overflow on the driver's buffer.

#![cfg(target_os = "linux")]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn target_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("CARGO_TARGET_DIR") {
        return PathBuf::from(dir);
    }
    workspace_root().join("target")
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root above crates/bhf_runtrace_shim")
        .to_path_buf()
}

/// The shim cdylib, when one is built and newer than the input-publishing
/// source this test is about (a stale build would test the old code).
fn shim_so() -> Option<PathBuf> {
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/fakes/fuzz_input.rs");
    let source_mtime = source.metadata().and_then(|m| m.modified()).ok()?;
    ["debug", "release"].into_iter().find_map(|profile| {
        let so = target_dir().join(profile).join("libbhf_runtrace_shim.so");
        let built = so.metadata().and_then(|m| m.modified()).ok()?;
        if built < source_mtime {
            eprintln!("skipping {}: older than {}", so.display(), source.display());
            return None;
        }
        Some(so)
    })
}

/// A symbolizer, so the allocation stack names functions; without one the
/// frames are module offsets, which compare just as well.
fn symbolizer() -> Option<PathBuf> {
    let on_path = std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join("llvm-symbolizer"))
            .find(|candidate| candidate.is_file())
    });
    on_path.or_else(|| {
        (14..=22)
            .rev()
            .map(|version| PathBuf::from(format!("/usr/bin/llvm-symbolizer-{version}")))
            .find(|candidate| candidate.is_file())
    })
}

const HARNESS: &str = r#"
#include <stddef.h>
#include <stdint.h>
extern void bhf_shim_set_fuzz_input(const uint8_t *data, size_t size) __attribute__((weak));
#define BHF_PUBLISH_INPUT(data, size) do { \
    if (bhf_shim_set_fuzz_input) bhf_shim_set_fuzz_input((data), (size)); \
} while (0)

/* The record's first two bytes are an offset the parser trusts. */
__attribute__((noinline)) static int parse_record(const uint8_t *data, size_t size) {
    size_t at = (size_t)data[0] | ((size_t)data[1] << 8);
    (void)size;
    return data[at];
}

int bhf_run_one(const uint8_t *Data, size_t Size) {
    BHF_PUBLISH_INPUT(Data, Size);
    if (Size < 2) return 0;
    volatile int value = parse_record(Data, Size);
    (void)value;
    return 0;
}
"#;

/// What a run's ASan report says, with addresses and pcs removed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Report {
    kind: String,
    region: String,
    allocated: Vec<String>,
    freed: Vec<String>,
}

fn strip_hex(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find("0x") {
        out.push_str(&rest[..start]);
        let tail = &rest[start + 2..];
        let end = tail
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(tail.len());
        out.push_str("0x?");
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// A stack frame without its index, pc and build id.
fn frame(line: &str) -> String {
    let line = line.trim();
    let line = line.split_once(' ').map_or(line, |(_, rest)| rest);
    let line = line.split_once(' ').map_or(line, |(_, rest)| rest);
    let line = line.split(" (BuildId:").next().unwrap_or(line);
    strip_hex(line)
}

fn stack_after(lines: &[&str], header: &str) -> Vec<String> {
    let Some(start) = lines.iter().position(|line| line.contains(header)) else {
        return Vec::new();
    };
    lines[start + 1..]
        .iter()
        .take_while(|line| line.trim_start().starts_with('#'))
        .map(|line| frame(line))
        .collect()
}

fn parse_report(stderr: &str) -> Option<Report> {
    let lines: Vec<&str> = stderr.lines().collect();
    let error = lines
        .iter()
        .find_map(|line| line.split_once("ERROR: AddressSanitizer: ").map(|(_, e)| e))?;
    let kind = error.split_whitespace().next()?.to_owned();
    let region = lines
        .iter()
        .find(|line| line.contains(" is located "))
        .map(|line| {
            let described = line.split_once(" is located ").map_or(*line, |(_, d)| d);
            strip_hex(described)
        })
        .unwrap_or_default();
    Some(Report {
        kind,
        region,
        allocated: stack_after(&lines, "allocated by thread"),
        freed: stack_after(&lines, "freed by thread"),
    })
}

/// Run `bin input`, stderr to a file, killed after a deadline.
fn run(bin: &Path, input: &Path, stderr: &Path, shim: Option<(&Path, &str, &Path)>) -> String {
    let mut command = Command::new(bin);
    command
        .arg(input)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(File::create(stderr).unwrap())
        .env(
            "ASAN_OPTIONS",
            "detect_leaks=0:abort_on_error=0:halt_on_error=1:symbolize=1:verify_asan_link_order=0",
        )
        .env_remove("LD_PRELOAD")
        .env_remove("BHF_FRAMED")
        .env_remove("BHF_FUZZ_INPUT_FD")
        .env_remove("BHF_FUZZ_INPUT_LEN")
        // A symbolizer with debuginfod set would look the shim's frames up
        // over the network.
        .env_remove("DEBUGINFOD_URLS");
    if let Some(symbolizer) = symbolizer() {
        command.env("ASAN_SYMBOLIZER_PATH", symbolizer);
    }
    if let Some((so, mode, log)) = shim {
        command
            .env("LD_PRELOAD", so)
            .env("BHF_RUNTRACE_LOG", log)
            .env_remove("BHF_RUNTRACE_MODE");
        if mode != "default" {
            command.env("BHF_RUNTRACE_MODE", mode);
        }
    }
    let mut child = command.spawn().expect("spawn probe");
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{} {} did not finish", bin.display(), input.display());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    std::fs::read_to_string(stderr).unwrap_or_default()
}

/// Inputs of a few sizes, each reading at a distance past its end: inside the
/// redzone, in the next chunks of its size class, and further on.
fn inputs(dir: &Path) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    for size in [16usize, 40] {
        for past in [0usize, 11, 27, 43, 59, 75, 140] {
            let at = size + past;
            let mut bytes = vec![b'r'; size];
            bytes[0] = (at & 0xff) as u8;
            bytes[1] = (at >> 8) as u8;
            let name = format!("record-{size}-past-{past}");
            let path = dir.join(&name);
            std::fs::write(&path, bytes).unwrap();
            out.push((name, path));
        }
    }
    out
}

#[test]
fn a_read_past_the_input_is_reported_the_same_with_and_without_the_shim() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built (cargo build -p bhf_runtrace_shim)");
        return;
    };
    let dir = std::env::temp_dir().join(format!("bhf-shim-asan-input-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let harness = dir.join("harness.c");
    std::fs::write(&harness, HARNESS).unwrap();
    let driver = workspace_root().join("c_runtime/bhf_driver.c");

    let mut lanes = Vec::new();
    for (lane, compiler) in [("clang-asan", "clang"), ("gcc-asan", "gcc")] {
        let bin = dir.join(format!("probe-{lane}"));
        let built = Command::new(compiler)
            .args(["-g", "-O1", "-fsanitize=address", "-D_GNU_SOURCE"])
            .arg(&harness)
            .arg(&driver)
            .arg("-o")
            .arg(&bin)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
        if built {
            lanes.push((lane, bin));
        }
    }
    if lanes.is_empty() {
        eprintln!("skipping: no compiler here builds with -fsanitize=address");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }

    let inputs = inputs(&dir);
    for (lane, bin) in &lanes {
        let mut without = BTreeMap::new();
        for (name, input) in &inputs {
            let stderr = run(bin, input, &dir.join(format!("{lane}-{name}.plain")), None);
            let report = parse_report(&stderr).unwrap_or_else(|| {
                panic!("{lane} {name}: no ASan report without the shim:\n{stderr}")
            });
            assert_eq!(
                report.kind, "heap-buffer-overflow",
                "{lane} {name}:\n{stderr}"
            );
            assert!(
                report.region.contains("bytes after"),
                "{lane} {name}: {}",
                report.region
            );
            assert!(report.freed.is_empty(), "{lane} {name}:\n{stderr}");
            without.insert(name.clone(), report);
        }
        // The shim's default, observe-only mode, and the mode that serves
        // the published input to faked resources.
        for mode in ["default", "fuzz_driven"] {
            let mut with = BTreeMap::new();
            for (name, input) in &inputs {
                let log = dir.join(format!("{lane}-{mode}-{name}.jsonl"));
                let stderr = run(
                    bin,
                    input,
                    &dir.join(format!("{lane}-{mode}-{name}.shim")),
                    Some((&shim, mode, &log)),
                );
                let report = parse_report(&stderr).unwrap_or_else(|| {
                    panic!("{lane} {mode} {name}: no ASan report with the shim:\n{stderr}")
                });
                assert!(
                    report
                        .allocated
                        .iter()
                        .all(|frame| !frame.contains("bhf_runtrace") && !frame.contains("alloc::")),
                    "{lane} {mode} {name}: the allocation is the shim's:\n{stderr}"
                );
                assert_eq!(
                    Some(&report),
                    without.get(name),
                    "{lane} {mode} {name}: the shim changed the report:\n{stderr}"
                );
                with.insert(name.clone(), report);
            }
            // The distinct reports are the findings a run records.
            let findings = |reports: &BTreeMap<String, Report>| -> BTreeSet<Report> {
                reports.values().cloned().collect()
            };
            assert_eq!(findings(&with), findings(&without), "{lane} {mode}");
        }
        // With a symbolizer the allocation is the driver's own buffer.
        if symbolizer().is_some() && *lane == "clang-asan" {
            let report = &without["record-16-past-43"];
            assert!(
                report
                    .allocated
                    .iter()
                    .any(|frame| frame.contains("bhf_run_file")),
                "{report:?}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
