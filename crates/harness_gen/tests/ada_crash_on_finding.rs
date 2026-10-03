// SPDX-License-Identifier: Apache-2.0
//! End-to-end proof of the Ada portability knob `BHF_CRASH_ON_FINDING` (#64):
//! a reported top-level finding aborts the process (SIGABRT) — so an external
//! crash-keying fuzzer (Mayhem base-executable, AFL) detects it — ONLY when the
//! env var is set; unset, the finding is reported and the process exits cleanly,
//! exactly as before. Gated on a GNAT toolchain; skips cleanly otherwise.

use std::path::PathBuf;
use std::process::Command;

fn have(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn bhf_crash_on_finding_aborts_only_when_set() {
    if !have("gprbuild") {
        eprintln!("skipping Ada crash-on-finding e2e: gprbuild unavailable");
        return;
    }
    let ada_runtime = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../ada_runtime")
        .canonicalize()
        .expect("ada_runtime dir");
    let tmp = std::env::temp_dir().join(format!("bhf-ada-cof-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    // Copy the runtime sources + its project file so the build happens entirely in
    // the temp dir (no obj/lib written into the repo's ada_runtime).
    for entry in std::fs::read_dir(&ada_runtime).unwrap().flatten() {
        let p = entry.path();
        if p.is_file() {
            std::fs::copy(&p, tmp.join(p.file_name().unwrap())).unwrap();
        }
    }

    // A driver that reports a single top-level finding, as the harness does when
    // it catches a top-level exception.
    std::fs::write(
        tmp.join("main.adb"),
        "with AdaFuzz.Probe;\n\
         procedure Main is\n\
         begin\n\
         \x20  AdaFuzz.Probe.On_Top_Level_Catch (\"Constraint_Error\", \"boom\");\n\
         end Main;\n",
    )
    .unwrap();
    // A driver project that withs the runtime library project and lands the
    // executable in the temp root.
    std::fs::write(
        tmp.join("drv.gpr"),
        "with \"adafuzz.gpr\";\n\
         project Drv is\n\
         \x20  for Source_Dirs use (\".\");\n\
         \x20  for Source_Files use (\"main.adb\");\n\
         \x20  for Object_Dir use \"obj_drv\";\n\
         \x20  for Exec_Dir use \".\";\n\
         \x20  for Main use (\"main.adb\");\n\
         end Drv;\n",
    )
    .unwrap();

    let build = Command::new("gprbuild")
        .arg("-p")
        .arg("-P")
        .arg(tmp.join("drv.gpr"))
        .current_dir(&tmp)
        .output()
        .expect("run gprbuild");
    assert!(
        build.status.success(),
        "gprbuild failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&build.stdout),
        String::from_utf8_lossy(&build.stderr)
    );
    let bin = tmp.join("main");
    assert!(bin.is_file(), "gprbuild produced no `main` executable");

    let events = tmp.join("events.bin");

    // Unset: the finding is reported and the process exits cleanly (0).
    let clean = Command::new(&bin)
        .env("BHF_EVENTS_PATH", &events)
        .env_remove("BHF_CRASH_ON_FINDING")
        .output()
        .unwrap();
    assert!(
        clean.status.success(),
        "without BHF_CRASH_ON_FINDING the process must exit cleanly, got {:?}",
        clean.status
    );

    // Set: the finding aborts the process (SIGABRT), so an external engine sees a
    // crash.
    let crashed = Command::new(&bin)
        .env("BHF_EVENTS_PATH", &events)
        .env("BHF_CRASH_ON_FINDING", "1")
        .output()
        .unwrap();
    assert!(
        !crashed.status.success(),
        "with BHF_CRASH_ON_FINDING=1 the process must crash, got {:?}",
        crashed.status
    );
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            crashed.status.signal(),
            Some(libc_sigabrt()),
            "expected SIGABRT (6); status = {:?}",
            crashed.status
        );
    }

    std::fs::remove_dir_all(&tmp).ok();
}

#[cfg(unix)]
fn libc_sigabrt() -> i32 {
    6
}
