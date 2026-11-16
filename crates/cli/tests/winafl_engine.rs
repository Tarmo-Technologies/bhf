// SPDX-License-Identifier: Apache-2.0

//! `--engine winafl` end to end.
//!
//! On a host other than native Windows the engine is refused with a specific
//! message. On Windows a missing WinAFL is refused naming what to install.
//! The end-to-end tests need WinAFL and DynamoRIO, so they are `#[ignore]`d
//! and listed as ignored in every run that does not ask for them; run them
//! with `cargo test --test winafl_engine -- --ignored` and `BHF_WINAFL_PATH`
//! plus `BHF_DYNAMORIO_PATH` (or `DYNAMORIO_HOME`) set, from an elevated shell
//! for the PageHeap one. Asked for without those, they fail rather than pass.
//! `bhf auto --engine winafl` on a tiny C project with a planted heap overflow
//! then finds it with nonzero WinAFL coverage, and the finding replays,
//! explains and packages into a capsule that reproduces it (see
//! docs/site/windows.md).

use std::path::{Path, PathBuf};
use std::process::Command;

fn bhf() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bhf"));
    command.env("RAYON_NUM_THREADS", "1");
    command
}

fn text(output: &std::process::Output) -> String {
    format!(
        "status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// A one-file C project whose parser overflows a 32-byte heap buffer by up to
/// 4 KiB behind a three-byte magic.
fn planted_project(root: &Path) -> PathBuf {
    let project = root.join("proj");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("record.c"),
        r#"#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int parse_record(const uint8_t *data, size_t len) {
    unsigned char scratch[4096];
    char *buf;
    size_t n;
    int first;
    if (len < 4 || data[0] != 'B' || data[1] != 'H' || data[2] != 'F') {
        return 0;
    }
    n = (size_t)data[3] * 16u;
    memset(scratch, 'A', sizeof scratch);
    memcpy(scratch, data + 4, len - 4 < sizeof scratch ? len - 4 : sizeof scratch);
    buf = (char *)malloc(32);
    if (!buf) {
        return 0;
    }
    memcpy(buf, scratch, n); /* planted heap overflow when n > 32 */
    first = buf[0];
    free(buf);
    return first;
}
"#,
    )
    .unwrap();
    project
}

#[cfg(not(windows))]
#[test]
fn engine_winafl_is_refused_off_windows() {
    let tmp = tempfile::tempdir().unwrap();
    let project = planted_project(tmp.path());
    let output = bhf()
        .args(["auto", "--engine", "winafl", "--per-target-time", "1"])
        .arg("--work-dir")
        .arg(tmp.path().join("work"))
        .arg(&project)
        .output()
        .unwrap();
    // Refused like an unusable toolchain: a usage error.
    assert_eq!(output.status.code(), Some(2), "{}", text(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--engine winafl runs only on native Windows"),
        "{}",
        text(&output)
    );
    // Refused before any target is built.
    assert!(!tmp.path().join("work").join("harnesses").exists());

    let fuzz = bhf()
        .args(["fuzz", "--engine", "winafl", "--harness", "H-NONE"])
        .arg(tmp.path())
        .output()
        .unwrap();
    assert_eq!(fuzz.status.code(), Some(3), "{}", text(&fuzz));
    assert!(
        String::from_utf8_lossy(&fuzz.stderr).contains("runs only on native Windows"),
        "{}",
        text(&fuzz)
    );
}

#[cfg(windows)]
#[test]
fn engine_winafl_without_winafl_names_what_to_install() {
    let tmp = tempfile::tempdir().unwrap();
    let project = planted_project(tmp.path());
    let missing = tmp.path().join("no-winafl-here");
    std::fs::create_dir_all(&missing).unwrap();
    let output = bhf()
        .args(["auto", "--engine", "winafl", "--per-target-time", "1"])
        .arg("--winafl-path")
        .arg(&missing)
        .arg("--work-dir")
        .arg(tmp.path().join("work"))
        .arg(&project)
        .env_remove("BHF_WINAFL_PATH")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{}", text(&output));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("WinAFL not found") && stderr.contains("afl-fuzz.exe"),
        "{}",
        text(&output)
    );
    assert!(
        stderr.contains("github.com/googleprojectzero/winafl"),
        "{}",
        text(&output)
    );
}

/// WinAFL and DynamoRIO from the environment. The end-to-end tests run only
/// when asked for (`--ignored`), so a missing tool fails them.
#[cfg(windows)]
fn installed_tools() -> (PathBuf, PathBuf) {
    let winafl = std::env::var_os("BHF_WINAFL_PATH").map(PathBuf::from);
    let dynamorio = std::env::var_os("BHF_DYNAMORIO_PATH")
        .or_else(|| std::env::var_os("DYNAMORIO_HOME"))
        .map(PathBuf::from);
    match (winafl, dynamorio) {
        (Some(winafl), Some(dynamorio)) => (winafl, dynamorio),
        _ => panic!(
            "the WinAFL end-to-end tests need BHF_WINAFL_PATH and BHF_DYNAMORIO_PATH (or \
             DYNAMORIO_HOME) set to a WinAFL build and a DynamoRIO install"
        ),
    }
}

/// Every JSON object under `value` whose `key` is `expected`.
#[cfg(windows)]
fn objects_with<'a>(
    value: &'a serde_json::Value,
    key: &str,
    expected: &str,
    out: &mut Vec<&'a serde_json::Value>,
) {
    match value {
        serde_json::Value::Object(map) => {
            if map.get(key).and_then(serde_json::Value::as_str) == Some(expected) {
                out.push(value);
            }
            for child in map.values() {
                objects_with(child, key, expected, out);
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                objects_with(child, key, expected, out);
            }
        }
        _ => {}
    }
}

/// `bhf auto --engine winafl` on the planted project, then the finding through
/// `replay`, `explain` and `capsule` + `verify-poc`. Returns how WinAFL saved
/// the input (`crash` or `hang`). `vs_arch` is `--vs-arch` (`x86` for the
/// 32-bit leg), else the host's.
#[cfg(windows)]
fn auto_winafl_finds_and_replays(page_heap: bool, vs_arch: Option<&str>) -> String {
    // One WinAFL campaign at a time, so neither starves the other's time budget.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (winafl, dynamorio) = installed_tools();
    let tmp = tempfile::tempdir().unwrap();
    let project = planted_project(tmp.path());
    let work = tmp.path().join("work");
    // A well-formed record that does not overflow (16 bytes into 32), as a
    // user's sample input would be: WinAFL has to change one byte.
    let seed = tmp.path().join("sample.rec");
    std::fs::write(&seed, b"BHF\x01sixteen bytes...").unwrap();
    let mut command = bhf();
    command
        .args([
            "auto",
            "--engine",
            "winafl",
            "--per-target-time",
            "60",
            "--max-targets",
            "1",
            "--no-minimize",
        ])
        .arg("--winafl-path")
        .arg(&winafl)
        .arg("--dynamorio-path")
        .arg(&dynamorio)
        .arg("--seed-file")
        .arg(&seed)
        .arg("--work-dir")
        .arg(&work)
        .arg(&project);
    if page_heap {
        command.arg("--winafl-page-heap");
    }
    if let Some(arch) = vs_arch {
        command.args(["--vs-arch", arch]);
    }
    let output = command.output().unwrap();
    let log = text(&output);
    assert!(
        !(page_heap && log.contains("elevated (administrator) shell")),
        "the PageHeap end-to-end test needs an elevated shell:\n{log}"
    );
    assert!(output.status.success(), "{log}");

    // The WinAFL pass ran with coverage WinAFL reported and found something.
    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("auto").join("run.json")).unwrap())
            .unwrap();
    let mut passes = Vec::new();
    objects_with(&run, "engine", "winafl", &mut passes);
    let pass = passes
        .iter()
        .find(|pass| pass.get("coverage_edges").is_some())
        .unwrap_or_else(|| panic!("no winafl pass in run.json:\n{run:#}\n{log}"));
    assert!(
        pass["coverage_edges"].as_u64().unwrap_or(0) > 0,
        "WinAFL reported no coverage: {pass:#}\n{log}"
    );
    assert!(
        pass["executions"].as_u64().unwrap_or(0) > 0,
        "{pass:#}\n{log}"
    );
    eprintln!(
        "WinAFL pass (page heap {page_heap}): {} executions, {} edges, findings {}",
        pass["executions"], pass["coverage_edges"], pass["findings"]
    );
    assert!(
        !run.to_string().contains("\"engine\":\"builtin\""),
        "a WinAFL-only run must not run the builtin passes:\n{run:#}"
    );

    // The finding is the planted overflow, confirmed by the sanitized harness
    // and marked as found by WinAFL.
    let findings = work.join("results").join("findings");
    let (dir, finding) = std::fs::read_dir(&findings)
        .unwrap_or_else(|error| panic!("no findings dir ({error}):\n{log}"))
        .flatten()
        .filter_map(|entry| {
            let record: serde_json::Value =
                serde_json::from_slice(&std::fs::read(entry.path().join("finding.json")).ok()?)
                    .ok()?;
            (record["discovery"]["engine"] == "winafl").then(|| (entry.path(), record))
        })
        .find(|(_, record)| record.to_string().contains("heap-buffer-overflow"))
        .unwrap_or_else(|| panic!("no WinAFL heap-buffer-overflow finding:\n{log}"));
    assert_eq!(finding["discovery"]["sanitizers"], serde_json::json!([]));
    assert_eq!(finding["discovery"]["page_heap"], page_heap, "{finding:#}");
    if page_heap {
        // The run fuzzed its own copy under its own key, and removed both.
        let image = finding["discovery"]["binary"].as_str().unwrap_or_default();
        assert!(
            image.ends_with("main_winafl") || image.ends_with("main_winafl.exe"),
            "{image}"
        );
        let printed = log
            .lines()
            .find(|line| line.contains("bhf: full PageHeap: WinAFL fuzzes"))
            .unwrap_or_else(|| panic!("no PageHeap line:\n{log}"));
        let key = printed
            .split(" with PageHeap set under ")
            .nth(1)
            .and_then(|rest| rest.split(" until the run ends").next())
            .unwrap_or_else(|| panic!("no key in {printed}"));
        assert!(key.contains("\\main_winafl-"), "{printed}");
        let query = Command::new("reg").args(["query", key]).output().unwrap();
        assert!(
            !query.status.success(),
            "the run left its PageHeap key {key} behind"
        );
        // Nor its copy of the build, or the copy's marker.
        let left: Vec<String> = std::fs::read_dir(std::path::Path::new(image).parent().unwrap())
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.to_ascii_lowercase().starts_with("main_winafl-"))
            .collect();
        assert!(left.is_empty(), "the run left {left:?} behind");
    }
    assert!(
        finding["fidelity"]["sanitizers"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("found by WinAFL")),
        "{finding:#}"
    );

    // Every later command runs in the build's environment: a capsule rebuilds
    // the harness, for x86 with the x86 toolset.
    let in_build_env = || {
        let mut command = bhf();
        if let Some(arch) = vs_arch {
            command.args(["--vs-arch", arch]);
        }
        command
    };
    let replay = in_build_env().arg("replay").arg(&dir).output().unwrap();
    let replayed = text(&replay);
    assert!(
        replayed.contains("heap-buffer-overflow"),
        "bhf replay did not reproduce the finding:\n{replayed}"
    );

    let id = dir.file_name().unwrap().to_owned();
    let explain = in_build_env()
        .arg("explain")
        .arg("--work-dir")
        .arg(&work)
        .arg("--finding-id")
        .arg(&id)
        .output()
        .unwrap();
    assert!(explain.status.success(), "{}", text(&explain));
    assert!(
        String::from_utf8_lossy(&explain.stdout).contains("heap-buffer-overflow"),
        "{}",
        text(&explain)
    );

    let capsule = in_build_env()
        .arg("capsule")
        .arg("--work-dir")
        .arg(&work)
        .arg("--finding-id")
        .arg(&id)
        .output()
        .unwrap();
    assert!(capsule.status.success(), "{}", text(&capsule));
    let capsule_dir = work
        .join("capsules")
        .join(format!("capsule_{}", id.to_string_lossy()));
    let verified = in_build_env()
        .arg("verify-poc")
        .arg(&capsule_dir)
        .output()
        .unwrap();
    assert!(verified.status.success(), "{}", text(&verified));
    finding["discovery"]["saved_as"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

/// Without PageHeap the Windows heap ends a corrupted process with a
/// fail-fast WinAFL's client never sees, so WinAFL may save the overflowing
/// input as a hang; bhf replays hangs too, so the overflow is found either way.
#[cfg(windows)]
#[test]
#[ignore = "needs WinAFL and DynamoRIO (BHF_WINAFL_PATH, BHF_DYNAMORIO_PATH); run with --ignored"]
fn auto_engine_winafl_finds_the_planted_heap_overflow_and_it_replays() {
    let saved_as = auto_winafl_finds_and_replays(false, None);
    assert!(
        ["crash", "hang", "crashing-seed"].contains(&saved_as.as_str()),
        "{saved_as}"
    );
}

/// Under PageHeap the overflow faults at once, so WinAFL saves it as a crash.
#[cfg(windows)]
#[test]
#[ignore = "needs WinAFL, DynamoRIO and an elevated shell; run with --ignored"]
fn auto_engine_winafl_with_page_heap_saves_the_overflow_as_a_crash() {
    assert_eq!(auto_winafl_finds_and_replays(true, None), "crash");
}

/// The x86 leg: `--vs-arch x86` builds a 32-bit harness, which WinAFL's
/// 32-bit build (`build32` in a checkout) fuzzes under DynamoRIO's `bin32`.
#[cfg(windows)]
#[test]
#[ignore = "needs a 32-bit WinAFL build and DynamoRIO (BHF_WINAFL_PATH, BHF_DYNAMORIO_PATH); run with --ignored"]
fn auto_engine_winafl_x86_finds_the_planted_heap_overflow_and_it_replays() {
    let saved_as = auto_winafl_finds_and_replays(false, Some("x86"));
    assert!(
        ["crash", "hang", "crashing-seed"].contains(&saved_as.as_str()),
        "{saved_as}"
    );
}

/// An x86 smoke with the builtin engine: `--vs-arch x86` builds the 32-bit
/// harness, and the planted overflow is found and replays.
#[cfg(windows)]
#[test]
fn auto_x86_builds_a_32_bit_harness_and_finds_the_planted_overflow() {
    let tmp = tempfile::tempdir().unwrap();
    let project = planted_project(tmp.path());
    let work = tmp.path().join("work");
    let seed = tmp.path().join("overflow.rec");
    // 0x10 * 16 = 256 bytes into a 32-byte block.
    std::fs::write(&seed, b"BHF\x10sixteen bytes...").unwrap();
    let output = bhf()
        .args([
            "auto",
            "--vs-arch",
            "x86",
            "--per-target-time",
            "20",
            "--max-targets",
            "1",
        ])
        .arg("--seed-file")
        .arg(&seed)
        .arg("--work-dir")
        .arg(&work)
        .arg(&project)
        .output()
        .unwrap();
    let log = text(&output);
    assert!(output.status.success(), "{log}");
    let found = std::fs::read_dir(work.join("results").join("findings"))
        .unwrap_or_else(|error| panic!("no findings dir ({error}):\n{log}"))
        .flatten()
        .find(|entry| {
            std::fs::read_to_string(entry.path().join("finding.json"))
                .is_ok_and(|record| record.contains("heap-buffer-overflow"))
        })
        .unwrap_or_else(|| panic!("no heap-buffer-overflow finding:\n{log}"));
    let replay = bhf().arg("replay").arg(found.path()).output().unwrap();
    assert!(
        text(&replay).contains("heap-buffer-overflow"),
        "{}",
        text(&replay)
    );
}
