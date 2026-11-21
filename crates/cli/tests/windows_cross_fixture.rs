// SPDX-License-Identifier: Apache-2.0

//! Windows-native cross-fuzzing (mingw + wine) end-to-end fixture.
//!
//! Proves bhf can BUILD a fuzz harness as a real Windows PE with the
//! `x86_64-w64-mingw32` cross toolchain and RUN it under wine — the
//! higher-fidelity path for Windows-platform-guarded targets that the attempt
//! loop FUTURE note (attempt.rs) calls for. Each test is gated on the cross
//! toolchain + wine being present, mirroring `m17_aarch64_cross_fixture.rs`, so
//! it is a no-op skip on a host without the toolchain and a real check here.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// The cross toolchain + wine bhf drives for a real Windows-PE harness.
struct WindowsTools {
    wine: PathBuf,
}

impl WindowsTools {
    fn discover() -> Option<Self> {
        which::which("x86_64-w64-mingw32-gcc").ok()?;
        let wine = which::which("wine").ok()?;
        Some(Self { wine })
    }
}

/// A `bhf_run_one` that faults on an input beginning with `CRASH` and is
/// otherwise a no-op. The faulting address is derived from the input so the
/// compiler cannot const-fold the dereference away as UB.
const RUN_ONE_CRASH_ON_PREFIX: &str =
    "#include <stdint.h>\n#include <stddef.h>\n#include <string.h>\n\
     int bhf_run_one(const uint8_t *d, size_t n) {\n\
     \x20 if (n >= 5 && memcmp(d, \"CRASH\", 5) == 0) {\n\
     \x20   volatile char *p = (volatile char *)(uintptr_t)d[0];\n\
     \x20   *p = (char)0x41;\n\
     \x20 }\n\
     \x20 return 0;\n\
     }\n";

/// A C++ source whose parser is guarded by `_WIN32` — exercises the cpp.tera
/// driver template's Windows port (cross-compiled with mingw g++, fuzzed under
/// wine). Same input-triggered wild write as the C fixture.
const WIN_PARSER_CPP_FIXTURE: &str = "#include <cstddef>\n#include <cstdint>\n\
     #ifdef _WIN32\n\
     #include <windows.h>\n\
     int cpp_parse(const uint8_t *data, std::size_t len) {\n\
     \x20 if (len >= 1 && data[0] != 0) {\n\
     \x20   volatile char *p = reinterpret_cast<volatile char *>(static_cast<std::uintptr_t>(data[0]));\n\
     \x20   *p = static_cast<char>(0x41);\n\
     \x20 }\n\
     \x20 return static_cast<int>(len);\n\
     }\n\
     #endif\n";

/// A C source whose parser is guarded by `_WIN32`, so discovery tags it with a
/// `foreign_guard` and the attempt loop must cross-compile it to a PE and fuzz it
/// under wine. The parser does a wild write to a low (unmapped) address derived
/// from the input, so almost any non-empty input faults — caught by the driver's
/// vectored exception handler as a crash. Models a Windows-only code path.
const WIN_PARSER_FIXTURE: &str = "#include <stddef.h>\n#include <stdint.h>\n\
     #ifdef _WIN32\n\
     #include <windows.h>\n\
     int parse_record(const uint8_t *data, size_t len) {\n\
     \x20 if (len >= 1 && data[0] != 0) {\n\
     \x20   volatile char *p = (volatile char *)(uintptr_t)((unsigned)data[0]);\n\
     \x20   *p = (char)0x41; /* wild write -> access violation */\n\
     \x20 }\n\
     \x20 return (int)len;\n\
     }\n\
     #endif\n";

/// A `bhf_run_one` that exercises several input-dependent edges, so the
/// trace-pc coverage runtime sets bits in the bitmap.
const RUN_ONE_EXERCISE: &str = "#include <stdint.h>\n#include <stddef.h>\n\
     int bhf_run_one(const uint8_t *d, size_t n) {\n\
     \x20 volatile int acc = 0;\n\
     \x20 for (size_t i = 0; i < n; i++) {\n\
     \x20   if (d[i] & 1) acc += d[i]; else acc -= d[i];\n\
     \x20 }\n\
     \x20 return acc & 1;\n\
     }\n";

/// Cross-build the bhf driver + a `bhf_run_one` TU into a Windows PE
/// with the mingw coverage/cmplog flags, returning the `.exe` path.
fn build_windows_harness(dir: &Path, run_one_src: &str) -> PathBuf {
    let driver = repo_root().join("c_runtime/bhf_driver.c");
    let run_one = dir.join("run_one.c");
    std::fs::write(&run_one, run_one_src).expect("run_one source is written");
    let exe = dir.join("main.exe");
    let output = Command::new("x86_64-w64-mingw32-gcc")
        .args(["-fsanitize-coverage=trace-pc,trace-cmp", "-O1", "-g"])
        .arg(&driver)
        .arg(&run_one)
        .arg("-o")
        .arg(&exe)
        .output()
        .expect("mingw cc runs");
    assert!(
        output.status.success(),
        "windows harness builds; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    exe
}

/// Write one framed `{u32 LE length, bytes}` record to the harness stdin.
fn write_frame(w: &mut impl Write, bytes: &[u8]) {
    w.write_all(&(bytes.len() as u32).to_le_bytes())
        .expect("frame length is written");
    w.write_all(bytes).expect("frame body is written");
    w.flush().expect("frame is flushed");
}

/// The mingw C cross compiler bhf drives for a Windows target, if present.
fn mingw_cc() -> Option<&'static str> {
    let cc = "x86_64-w64-mingw32-gcc";
    which::which(cc).ok().map(|_| cc)
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("cli crate is under crates/cli")
        .to_path_buf()
}

fn temp_dir(name: &str) -> TestDir {
    TestDir::new(&format!("windows-{name}"))
}

/// Write a trivial `bhf_run_one` translation unit beside the driver so the
/// driver links into a standalone PE without pulling a real target in.
fn write_trivial_run_one(dir: &Path) -> PathBuf {
    let run_one = dir.join("run_one.c");
    std::fs::write(
        &run_one,
        b"#include <stdint.h>\n#include <stddef.h>\n\
          int bhf_run_one(const uint8_t *d, size_t n) { (void)d; (void)n; return 0; }\n",
    )
    .expect("run_one source is written");
    run_one
}

#[test]
fn bhf_driver_compiles_under_mingw_with_trace_pc_coverage() {
    let Some(cc) = mingw_cc() else {
        eprintln!("skipping: no x86_64-w64-mingw32-gcc on PATH");
        return;
    };

    let driver = repo_root().join("c_runtime/bhf_driver.c");
    assert!(driver.is_file(), "driver source is present at {driver:?}");

    let dir = temp_dir("driver-compile");
    let run_one = write_trivial_run_one(&dir);
    let exe = dir.join("main.exe");

    // mingw-w64 gcc rejects `trace-pc-guard` (clang-only here) but accepts
    // `trace-pc` + `trace-cmp` — the coverage/cmplog flags the Windows build
    // uses. The driver must compile cleanly under them.
    let output = Command::new(cc)
        .args(["-fsanitize-coverage=trace-pc,trace-cmp", "-O1", "-g"])
        .arg(&driver)
        .arg(&run_one)
        .arg("-o")
        .arg(&exe)
        .output()
        .expect("mingw cc runs");

    assert!(
        output.status.success(),
        "bhf_driver.c must cross-compile under mingw; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(exe.is_file(), "a Windows PE is produced at {exe:?}");
}

#[test]
fn windows_harness_runs_clean_input_under_wine_via_framed_protocol() {
    let Some(tools) = WindowsTools::discover() else {
        eprintln!("skipping: requires x86_64-w64-mingw32-gcc and wine");
        return;
    };

    let dir = temp_dir("framed-clean");
    let exe = build_windows_harness(&dir, RUN_ONE_CRASH_ON_PREFIX);

    let mut child = Command::new(&tools.wine)
        .arg(&exe)
        .env("BHF_FRAMED", "1")
        .env("WINEDEBUG", "-all")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("wine harness starts");
    let mut stdin = child.stdin.take().expect("harness stdin is piped");
    let mut stdout = child.stdout.take().expect("harness stdout is piped");

    let mut byte = [0u8; 1];
    stdout
        .read_exact(&mut byte)
        .expect("harness writes ready byte");
    assert_eq!(byte[0], 1, "ready byte is 1");

    write_frame(&mut stdin, b"hello");
    stdout
        .read_exact(&mut byte)
        .expect("harness writes a sync byte after a clean exec");
    assert_eq!(byte[0], 1, "sync byte is 1");

    drop(stdin); // EOF ends the persistent loop
    let status = child.wait().expect("harness exits");
    assert!(
        status.success(),
        "a clean framed run under wine exits 0, got {status}"
    );
}

#[test]
fn windows_harness_crash_is_detected_under_wine() {
    let Some(tools) = WindowsTools::discover() else {
        eprintln!("skipping: requires x86_64-w64-mingw32-gcc and wine");
        return;
    };

    let dir = temp_dir("framed-crash");
    let exe = build_windows_harness(&dir, RUN_ONE_CRASH_ON_PREFIX);

    let mut child = Command::new(&tools.wine)
        .arg(&exe)
        .env("BHF_FRAMED", "1")
        .env("WINEDEBUG", "-all")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("wine harness starts");
    let mut stdin = child.stdin.take().expect("harness stdin is piped");
    let mut stdout = child.stdout.take().expect("harness stdout is piped");

    let mut byte = [0u8; 1];
    stdout
        .read_exact(&mut byte)
        .expect("harness writes ready byte");

    // A crashing input faults inside run_one; the vectored exception handler
    // converts it into an immediate process exit, so no sync byte arrives and
    // the process exits with the crash sentinel rather than hanging.
    write_frame(&mut stdin, b"CRASH");
    let got = stdout.read(&mut byte).expect("read after crash");
    assert_eq!(got, 0, "no sync byte after a crash (pipe closes at EOF)");

    drop(stdin);
    let status = child.wait().expect("harness exits");
    assert!(
        !status.success(),
        "a crash under wine yields a nonzero exit, got {status}"
    );
    if let Some(code) = status.code() {
        assert_eq!(
            code, 0x39,
            "crash exit is the driver's vectored-handler sentinel"
        );
    }
}

#[test]
fn windows_harness_coverage_shm_is_visible_to_host_after_wine_run() {
    let Some(tools) = WindowsTools::discover() else {
        eprintln!("skipping: requires x86_64-w64-mingw32-gcc and wine");
        return;
    };

    let dir = temp_dir("cov-shm");
    let exe = build_windows_harness(&dir, RUN_ONE_EXERCISE);
    let cov = dir.join("cov.bin");
    // Pre-create the backing file zeroed so "host sees nothing" is unambiguous:
    // the driver must write coverage THROUGH to this same host file.
    std::fs::write(&cov, vec![0u8; 1 << 16]).expect("cov backing file is created");

    let mut child = Command::new(&tools.wine)
        .arg(&exe)
        .env("BHF_FRAMED", "1")
        .env("BHF_COV_SHM", &cov)
        .env("WINEDEBUG", "-all")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("wine harness starts");
    let mut stdin = child.stdin.take().expect("harness stdin is piped");
    let mut stdout = child.stdout.take().expect("harness stdout is piped");

    let mut byte = [0u8; 1];
    stdout
        .read_exact(&mut byte)
        .expect("harness writes ready byte");
    write_frame(&mut stdin, b"the quick brown fox");
    stdout
        .read_exact(&mut byte)
        .expect("harness writes a sync byte");
    drop(stdin);
    child.wait().expect("harness exits");

    let bytes = std::fs::read(&cov).expect("cov backing file is readable");
    let nonzero = bytes.iter().filter(|b| **b != 0).count();
    assert!(
        nonzero > 0,
        "coverage written under wine must be visible in the host's backing file \
         (got {nonzero} nonzero bytes of {})",
        bytes.len()
    );
}

#[test]
fn bhf_auto_cross_builds_and_fuzzes_a_windows_guarded_target_under_wine() {
    let Some(_tools) = WindowsTools::discover() else {
        eprintln!("skipping: requires x86_64-w64-mingw32-gcc and wine");
        return;
    };

    let dir = temp_dir("auto-win");
    std::fs::write(dir.join("win_parser.c"), WIN_PARSER_FIXTURE).expect("fixture written");
    let work = dir.join("work");

    // `bhf auto` must DISCOVER parse_record (tagged `_WIN32` foreign-guard),
    // pick the Cross(mingw+wine) strategy, build a real PE, and fuzz it under wine.
    let rc = cli::run_from([
        "bhf",
        "auto",
        dir.to_str().unwrap(),
        "--per-target-time",
        "10",
        "--max-targets",
        "4",
        "--work-dir",
        work.to_str().unwrap(),
    ]);
    assert_eq!(rc, 0, "bhf auto exits 0 (findings are data, not an error)");

    let run_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(work.join("auto").join("run.json")).expect("run.json exists"),
    )
    .expect("run.json parses");
    let attempts = run_json
        .get("targets")
        .or_else(|| run_json.get("attempts"))
        .and_then(|v| v.as_array())
        .expect("run.json has a targets/attempts array");
    let pr = attempts
        .iter()
        .find(|a| a.get("name").and_then(|n| n.as_str()) == Some("parse_record"))
        .unwrap_or_else(|| panic!("parse_record was attempted; run.json:\n{run_json:#}"));

    let outcome = pr.get("outcome").expect("parse_record has an outcome");
    let passes = outcome
        .get("passes")
        .and_then(|p| p.as_array())
        .unwrap_or_else(|| {
            panic!("parse_record must build+fuzz via the Cross mingw+wine path, not skip/stub; outcome:\n{outcome:#}")
        });

    let edges: u64 = passes
        .iter()
        .filter_map(|p| p.get("coverage_edges").and_then(|e| e.as_u64()))
        .max()
        .unwrap_or(0);
    let execs: u64 = passes
        .iter()
        .filter_map(|p| p.get("executions").and_then(|e| e.as_u64()))
        .sum();
    let findings: usize = passes
        .iter()
        .filter_map(|p| p.get("findings").and_then(|f| f.as_array()))
        .map(|f| f.len())
        .sum();

    assert!(execs > 0, "real executions under wine, got {execs}");
    assert!(
        edges > 0,
        "real coverage edges under wine via trace-pc, got {edges}"
    );
    assert!(
        findings > 0,
        "the wild-write crash must be found under wine (0 findings over {execs} execs, {edges} edges)"
    );
}

#[test]
fn bhf_auto_cross_builds_and_fuzzes_a_windows_guarded_cpp_target_under_wine() {
    if which::which("x86_64-w64-mingw32-g++").is_err() || which::which("wine").is_err() {
        eprintln!("skipping: requires x86_64-w64-mingw32-g++ and wine");
        return;
    }

    let dir = temp_dir("auto-win-cpp");
    std::fs::write(dir.join("win_parser.cpp"), WIN_PARSER_CPP_FIXTURE).expect("fixture written");
    let work = dir.join("work");

    let rc = cli::run_from([
        "bhf",
        "auto",
        dir.to_str().unwrap(),
        "--per-target-time",
        "10",
        "--max-targets",
        "4",
        "--work-dir",
        work.to_str().unwrap(),
    ]);
    assert_eq!(rc, 0, "bhf auto exits 0");

    let run_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(work.join("auto").join("run.json")).expect("run.json exists"),
    )
    .expect("run.json parses");
    let attempts = run_json
        .get("targets")
        .or_else(|| run_json.get("attempts"))
        .and_then(|v| v.as_array())
        .expect("run.json has a targets/attempts array");
    let pr = attempts
        .iter()
        .find(|a| a.get("name").and_then(|n| n.as_str()) == Some("cpp_parse"))
        .unwrap_or_else(|| panic!("cpp_parse was attempted; run.json:\n{run_json:#}"));
    let passes = pr
        .get("outcome")
        .and_then(|o| o.get("passes"))
        .and_then(|p| p.as_array())
        .unwrap_or_else(|| panic!("cpp_parse must build+fuzz via Cross mingw+wine; got:\n{pr:#}"));
    let execs: u64 = passes
        .iter()
        .filter_map(|p| p.get("executions").and_then(|e| e.as_u64()))
        .sum();
    let findings: usize = passes
        .iter()
        .filter_map(|p| p.get("findings").and_then(|f| f.as_array()))
        .map(|f| f.len())
        .sum();
    assert!(execs > 0, "real C++ executions under wine, got {execs}");
    assert!(
        findings > 0,
        "the wild-write crash in the C++ target must be found under wine ({execs} execs)"
    );
}

/// The `name` target's entry in a `bhf auto` work dir's `run.json`.
fn attempt_named(work: &Path, name: &str) -> serde_json::Value {
    let run_json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(work.join("auto").join("run.json")).expect("run.json exists"),
    )
    .expect("run.json parses");
    run_json
        .get("targets")
        .or_else(|| run_json.get("attempts"))
        .and_then(|v| v.as_array())
        .expect("run.json has a targets/attempts array")
        .iter()
        .find(|a| a.get("name").and_then(|n| n.as_str()) == Some(name))
        .unwrap_or_else(|| panic!("{name} was attempted; run.json:\n{run_json:#}"))
        .clone()
}

/// Stop the Wine server of a prefix a test created, so nothing writes into
/// it while the test dir is removed.
fn stop_wine_server(prefix: &Path) {
    for flag in ["-k", "-w"] {
        let _ = Command::new("wineserver")
            .arg(flag)
            .env("WINEPREFIX", prefix)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// #394: from a Wine prefix that does not exist yet, `bhf auto` creates it
/// before the first harness starts, so the first run fuzzes the target
/// instead of timing every input out while Wine sets the prefix up.
#[test]
fn bhf_auto_creates_a_missing_wine_prefix_and_fuzzes_on_the_first_run() {
    let Some(_tools) = WindowsTools::discover() else {
        eprintln!("skipping: requires x86_64-w64-mingw32-gcc and wine");
        return;
    };
    if which::which("wineserver").is_err() {
        eprintln!("skipping: requires wineserver");
        return;
    }

    let dir = temp_dir("auto-win-fresh-prefix");
    std::fs::write(dir.join("win_parser.c"), WIN_PARSER_FIXTURE).expect("fixture written");
    let work = dir.join("work");
    let prefix = dir.join("wine-prefix");

    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["auto"])
        .arg(&*dir)
        .args([
            "--per-target-time",
            "10",
            "--max-targets",
            "4",
            "--work-dir",
        ])
        .arg(&work)
        .env("WINEPREFIX", &prefix)
        .env_remove("WINESERVER")
        .stdin(Stdio::null())
        .output()
        .expect("bhf runs");
    stop_wine_server(&prefix);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("creating the Wine prefix"),
        "bhf says it creates the prefix; stderr:\n{stderr}"
    );
    assert!(
        prefix.join("system.reg").is_file(),
        "the prefix is created; stderr:\n{stderr}"
    );
    assert!(
        output.status.success(),
        "bhf auto exits 0 on the first run in a new prefix; stderr:\n{stderr}"
    );

    let parse_record = attempt_named(&work, "parse_record");
    let outcome = &parse_record["outcome"];
    assert_eq!(
        outcome["outcome"], "built_and_fuzzed",
        "the first run enters the target; stderr:\n{stderr}"
    );
    let passes = outcome["passes"].as_array().expect("passes");
    let execs: u64 = passes.iter().filter_map(|p| p["executions"].as_u64()).sum();
    let findings: usize = passes
        .iter()
        .filter_map(|p| p["findings"].as_array())
        .map(Vec::len)
        .sum();
    assert!(execs > 0, "inputs run under wine, got {execs}");
    assert!(
        findings > 0,
        "the wild write is found on the first run ({execs} execs)"
    );
}

/// #394: a Wine that cannot create its prefix makes the target a toolchain
/// problem with Wine's own words, not a target that was never entered.
#[cfg(unix)]
#[test]
fn a_wine_prefix_that_cannot_be_created_is_a_toolchain_error() {
    use std::os::unix::fs::PermissionsExt as _;
    if mingw_cc().is_none() {
        eprintln!("skipping: no x86_64-w64-mingw32-gcc on PATH");
        return;
    }

    let dir = temp_dir("auto-win-broken-prefix");
    std::fs::write(dir.join("win_parser.c"), WIN_PARSER_FIXTURE).expect("fixture written");
    let work = dir.join("work");
    let bin = dir.join("bin");
    std::fs::create_dir(&bin).expect("bin dir is created");
    let wine = bin.join("wine");
    std::fs::write(
        &wine,
        "#!/bin/sh\necho 'wine: could not set up the configuration directory' >&2\nexit 1\n",
    )
    .expect("stand-in wine is written");
    std::fs::set_permissions(&wine, std::fs::Permissions::from_mode(0o755))
        .expect("stand-in wine is executable");
    let path = std::env::join_paths(std::iter::once(bin.clone()).chain(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    )))
    .expect("PATH joins");

    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["auto"])
        .arg(&*dir)
        .args(["--per-target-time", "5", "--max-targets", "4", "--work-dir"])
        .arg(&work)
        .env("PATH", path)
        .env("WINEPREFIX", dir.join("wine-prefix"))
        .stdin(Stdio::null())
        .output()
        .expect("bhf runs");
    let stderr = String::from_utf8_lossy(&output.stderr);

    let outcome = attempt_named(&work, "parse_record")["outcome"].clone();
    assert_eq!(
        outcome["outcome"], "missing_toolchain",
        "a prefix Wine cannot create is a toolchain problem; outcome:\n{outcome:#}\nstderr:\n{stderr}"
    );
    let reason = outcome["reason"].as_str().expect("a reason");
    assert!(reason.contains("Wine prefix"), "{reason}");
    assert!(
        reason.contains("could not set up the configuration directory"),
        "Wine's own words are kept: {reason}"
    );
}

/// The finding directories of a work dir.
fn finding_dirs(work: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(work.join("results").join("findings"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|dir| dir.join("finding.json").is_file())
        .collect();
    dirs.sort();
    dirs
}

/// #394: a Windows finding replayed where the Wine prefix does not exist yet
/// (a new machine, a fresh `WINEPREFIX`) reproduces on the first replay:
/// bhf creates the prefix before the harness starts. The replay had run out
/// its timeout while Wine set the prefix up.
#[test]
fn a_windows_finding_replays_from_a_fresh_wine_prefix() {
    let Some(_tools) = WindowsTools::discover() else {
        eprintln!("skipping: requires x86_64-w64-mingw32-gcc and wine");
        return;
    };
    if which::which("wineserver").is_err() {
        eprintln!("skipping: requires wineserver");
        return;
    }

    let dir = temp_dir("replay-win-fresh-prefix");
    std::fs::write(dir.join("win_parser.c"), WIN_PARSER_FIXTURE).expect("fixture written");
    let work = dir.join("work");
    let fuzzed_in = dir.join("wine-prefix-fuzz");
    let fuzz = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["auto"])
        .arg(&*dir)
        .args([
            "--per-target-time",
            "10",
            "--max-targets",
            "4",
            "--work-dir",
        ])
        .arg(&work)
        .env("WINEPREFIX", &fuzzed_in)
        .env_remove("WINESERVER")
        .stdin(Stdio::null())
        .output()
        .expect("bhf auto runs");
    stop_wine_server(&fuzzed_in);
    let fuzz_stderr = String::from_utf8_lossy(&fuzz.stderr);
    let finding = finding_dirs(&work)
        .into_iter()
        .find(|dir| {
            std::fs::read_to_string(dir.join("finding.json"))
                .is_ok_and(|text| text.contains("parse_record"))
        })
        .unwrap_or_else(|| panic!("bhf auto finds the wild write; stderr:\n{fuzz_stderr}"));

    let replayed_in = dir.join("wine-prefix-replay");
    // `--sandbox none`: this test is about the prefix, and runs the harness
    // as a host without a sandbox tool does.
    let replay = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("replay")
        .arg(&finding)
        .args(["--sandbox", "none", "--json"])
        .env("WINEPREFIX", &replayed_in)
        .env_remove("WINESERVER")
        .stdin(Stdio::null())
        .output()
        .expect("bhf replay runs");
    stop_wine_server(&replayed_in);
    let stderr = String::from_utf8_lossy(&replay.stderr);
    let stdout = String::from_utf8_lossy(&replay.stdout);
    assert!(
        stderr.contains("creating the Wine prefix"),
        "bhf replay creates the prefix first; stderr:\n{stderr}"
    );
    assert!(
        replayed_in.join("system.reg").is_file(),
        "the prefix is created; stderr:\n{stderr}"
    );
    let verdict: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("{error}: stdout:\n{stdout}\nstderr:\n{stderr}"));
    assert_eq!(
        verdict["verdict"], "match",
        "the first replay in a new prefix reproduces the crash: {verdict:#}\nstderr:\n{stderr}"
    );
}

/// An executable shell script at `path`.
#[cfg(unix)]
fn write_script(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).expect("script is written");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .expect("script is executable");
}

/// #394: `bhf binary fuzz --runner wine` (what `bhf project` runs for a
/// Windows binary) creates a missing prefix before the target's first run,
/// and so does a replay of its finding. A stand-in `wine` records how it is
/// run, creates the prefix's registry for `wineboot --init` and otherwise
/// runs the target.
#[cfg(unix)]
#[test]
fn binary_fuzz_under_wine_creates_a_missing_prefix_before_the_first_run() {
    let dir = temp_dir("binary-wine-prefix");
    let calls = dir.join("calls.log");
    let wine = dir.join("wine");
    write_script(
        &wine,
        &format!(
            "if [ \"$1 $2\" = 'wineboot --init' ]; then\n\
             \x20 echo \"wineboot WINEDEBUG=$WINEDEBUG\" >> '{log}'\n\
             \x20 mkdir -p \"$WINEPREFIX\" && echo 'WINE REGISTRY' > \"$WINEPREFIX/system.reg\"\n\
             \x20 exit 0\n\
             fi\n\
             echo \"run $1\" >> '{log}'\n\
             exec \"$@\"",
            log = calls.display()
        ),
    );
    write_script(
        &dir.join("wineserver"),
        &format!("echo \"wineserver $*\" >> '{}'", calls.display()),
    );
    // A target that crashes on every input.
    let target = dir.join("parse_record.exe");
    write_script(&target, "kill -SEGV $$");
    let prefix = dir.join("wine-prefix");
    let work = dir.join("work");
    let bhf = |args: &[&std::ffi::OsStr]| {
        Command::new(env!("CARGO_BIN_EXE_bhf"))
            .args(args)
            .env("WINEPREFIX", &prefix)
            .env_remove("WINESERVER")
            .env_remove("WINEDLLOVERRIDES")
            .stdin(Stdio::null())
            .output()
            .expect("bhf runs")
    };
    let fuzz = bhf(&[
        "binary".as_ref(),
        "fuzz".as_ref(),
        target.as_os_str(),
        "--runner".as_ref(),
        wine.as_os_str(),
        "--engine".as_ref(),
        "builtin".as_ref(),
        "--sandbox".as_ref(),
        "none".as_ref(),
        "--iterations".as_ref(),
        "2".as_ref(),
        "--seed-input".as_ref(),
        "AAAA".as_ref(),
        "--work-dir".as_ref(),
        work.as_os_str(),
    ]);
    let stderr = String::from_utf8_lossy(&fuzz.stderr);
    let log = std::fs::read_to_string(&calls).unwrap_or_default();
    let first: Vec<&str> = log.lines().take(3).collect();
    assert_eq!(
        first,
        [
            "wineboot WINEDEBUG=-all",
            "wineserver --wait",
            format!("run {}", target.display()).as_str()
        ],
        "the prefix is created before the target first runs; stderr:\n{stderr}"
    );
    let findings = finding_dirs(&work);
    assert_eq!(
        findings.len(),
        1,
        "the crash is a finding; stderr:\n{stderr}"
    );

    // The finding replayed on a machine with no prefix yet.
    std::fs::remove_dir_all(&prefix).expect("the prefix is removed");
    std::fs::remove_file(&calls).expect("the call log is reset");
    let replay = bhf(&[
        "replay".as_ref(),
        findings[0].as_os_str(),
        "--harness".as_ref(),
        target.as_os_str(),
        "--json".as_ref(),
    ]);
    let stderr = String::from_utf8_lossy(&replay.stderr);
    let stdout = String::from_utf8_lossy(&replay.stdout);
    let log = std::fs::read_to_string(&calls).unwrap_or_default();
    assert_eq!(
        log.lines().next(),
        Some("wineboot WINEDEBUG=-all"),
        "the replay creates the prefix first; calls:\n{log}\nstderr:\n{stderr}"
    );
    let verdict: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("{error}: stdout:\n{stdout}\nstderr:\n{stderr}"));
    assert_eq!(
        verdict["verdict"], "match",
        "{verdict:#}\nstderr:\n{stderr}"
    );
}
