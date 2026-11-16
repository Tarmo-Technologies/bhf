// SPDX-License-Identifier: Apache-2.0

//! An interrupted `bhf fuzz` leaves no shared-memory files behind (#368). It
//! left `.tmp*` files at the top of the work dir, which `bhf clean --all` kept.
//! The maps now live in `<work>/fuzz_shm/`: SIGTERM removes them, a later run
//! removes those of a run killed outright, and `clean --all` removes the
//! directory and `fuzz_inputs/`.

#![cfg(unix)]

use std::fs;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn clang_runs() -> bool {
    let present = {
        Command::new("clang")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    };
    support::require_tool(present, "clang")
}

const TARGET: &str = "#include <stddef.h>\n#include <stdint.h>\n\
     static volatile unsigned total;\n\
     int bhf_run_one(const uint8_t *data, size_t size) {\n\
         for (size_t i = 0; i < size; i++) total += data[i];\n\
         return 0;\n\
     }\n";

fn build_harness(work: &Path, id: &str) {
    let dir = work.join("harnesses").join(id);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("target.c"), TARGET).unwrap();
    let driver = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime/bhf_driver.c");
    let built = Command::new("clang")
        .current_dir(&dir)
        .args([
            "-O1",
            "-g",
            "-fsanitize=address",
            "-fsanitize-coverage=trace-pc-guard,trace-cmp",
            "-o",
            "main",
            "target.c",
        ])
        .arg(&driver)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
}

fn fuzz(work: &Path, id: &str, budget: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bhf"));
    command
        .arg("fuzz")
        .arg(work)
        .args(["--harness", id, "--quiet", "--seed-input", "seed"])
        .args(budget)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn shared_maps(work: &Path) -> Vec<PathBuf> {
    let mut maps: Vec<PathBuf> = fs::read_dir(work.join("fuzz_shm"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .collect();
    maps.sort();
    maps
}

fn top_level_tmp_files(work: &Path) -> Vec<String> {
    fs::read_dir(work)
        .unwrap()
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.starts_with(".tmp"))
        .collect()
}

/// A long run, once its shared maps exist.
fn running_campaign(work: &Path, id: &str) -> Child {
    let mut child = fuzz(work, id, &["--time", "120s"]).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    while shared_maps(work).is_empty() {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("bhf fuzz ended before arming its maps: {status}");
        }
        assert!(Instant::now() < deadline, "no shared map in 60s");
        std::thread::sleep(Duration::from_millis(50));
    }
    // Let the loop reach its executions.
    std::thread::sleep(Duration::from_millis(500));
    child
}

#[test]
fn sigterm_leaves_no_shared_map_behind() {
    if !clang_runs() {
        eprintln!("skipping: clang unavailable");
        return;
    }
    let root = TestDir::new("fuzz-sigterm");
    let work = root.join("work");
    build_harness(&work, "H-TERM");
    let mut child = running_campaign(&work, "H-TERM");
    let maps = shared_maps(&work);
    assert!(maps
        .iter()
        .all(|map| map.file_name().unwrap().to_string_lossy().ends_with(".shm")));

    let pid = libc::pid_t::try_from(child.id()).unwrap();
    // SAFETY: signals a child this test owns.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    let status = child.wait().unwrap();
    // The signal still ends the run.
    assert_eq!(status.signal(), Some(libc::SIGTERM), "{status}");
    assert_eq!(shared_maps(&work), Vec::<PathBuf>::new());
    assert_eq!(top_level_tmp_files(&work), Vec::<String>::new());
}

#[test]
fn a_sigkilled_runs_maps_go_with_the_next_run_or_clean_all() {
    if !clang_runs() {
        eprintln!("skipping: clang unavailable");
        return;
    }
    let root = TestDir::new("fuzz-sigkill");
    let work = root.join("work");
    build_harness(&work, "H-KILL");

    let mut child = running_campaign(&work, "H-KILL");
    child.kill().unwrap();
    child.wait().unwrap();
    let left = shared_maps(&work);
    assert!(!left.is_empty(), "SIGKILL ran no cleanup");
    // The next run removes the maps of a process that is gone.
    let next = fuzz(&work, "H-KILL", &["--iterations", "1"])
        .status()
        .unwrap();
    assert!(next.success(), "{next}");
    let after = shared_maps(&work);
    assert!(
        left.iter().all(|map| !after.contains(map)),
        "{left:?} {after:?}"
    );

    // And `clean --all` removes what another killed run leaves.
    let mut child = running_campaign(&work, "H-KILL");
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(!shared_maps(&work).is_empty());
    fs::create_dir_all(work.join("fuzz_inputs")).unwrap();
    fs::write(work.join("fuzz_inputs").join("input-0"), b"x").unwrap();
    let clean = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["clean", "--all"])
        .arg(&work)
        .output()
        .unwrap();
    assert!(
        clean.status.success(),
        "{}",
        String::from_utf8_lossy(&clean.stderr)
    );
    assert!(!work.join("fuzz_shm").exists());
    assert!(!work.join("fuzz_inputs").exists());
}
