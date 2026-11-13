// SPDX-License-Identifier: Apache-2.0
//! End-to-end coverage for `bhf env-capsule` + environment-response fuzzing. A
//! parser of a "trusted" external config file (opened via raw open/read, which the
//! shim fakes and fuzzes) overflows on the SERVED content — so the crash is driven
//! by the environment, not the input, and its minimized input is empty. The
//! env-capsule must record the served world and replay it to reproduce the crash
//! DETERMINISTICALLY from that empty input, in a pristine location.

use std::path::Path;
use std::process::Command;

fn clang_available() -> bool {
    which::which("clang").is_ok()
}

fn shim_present() -> bool {
    // The env-capsule needs the runtrace shim built beside the test binary.
    let exe = std::env::current_exe().unwrap();
    let dir = exe.parent().and_then(|p| p.parent()).unwrap().to_path_buf();
    dir.join("libbhf_runtrace_shim.so").is_file() || dir.join("libbhf_runtrace.so").is_file()
}

/// Reads a faked config file's (fuzzed) content into a fixed buffer — overflow when
/// the shim serves > 8 bytes. Raw open/read so the shim's `open` interposition fires.
const ENV_DRIVEN_C: &str = "\
#include <fcntl.h>
#include <unistd.h>
int load_config(const char *data, unsigned int len) {
    (void)data; (void)len;
    int fd = open(\"/etc/bhf_envcap_demo.conf\", O_RDONLY);
    if (fd < 0) return 0;
    char cfg[8];
    long n = read(fd, cfg, 64);
    close(fd);
    return n > 0 ? cfg[0] : 0;
}
";

/// Run from the project dir with the default (relative) `bhf_work`: the
/// replays, which run beside the harness binary, must still find the binary,
/// the input and the recorded world.
#[test]
fn env_capsule_replays_environment_driven_crash() {
    if !clang_available() {
        eprintln!("skipping: clang not installed");
        return;
    }
    if !shim_present() {
        eprintln!("skipping: runtrace shim not built");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let work = root.path().join("bhf_work");
    let src = root.path().join("load_config.c");
    std::fs::write(&src, ENV_DRIVEN_C).unwrap();
    let snip = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("snippet")
        .arg(&src)
        .arg("--lang")
        .arg("c")
        .arg("--per-target-time")
        .arg("8")
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run snippet");
    if !has_crash_finding(&work) {
        // Environment-response fuzzing needs the shim to fake the config read; if the
        // build/shim couldn't produce the crash, skip rather than falsely fail.
        eprintln!(
            "skipping: no env-driven crash found; stderr:\n{}",
            String::from_utf8_lossy(&snip.stderr)
        );
        return;
    }

    let cap = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("env-capsule")
        .current_dir(root.path())
        .output()
        .expect("run env-capsule");
    let stdout = String::from_utf8_lossy(&cap.stdout);
    assert!(
        cap.status.success()
            && stdout.contains("verified to replay")
            && stdout.contains("✓ replays"),
        "env-capsule should verify a replay; stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&cap.stderr)
    );

    // Independently verify: copy the capsule to a pristine dir and run replay.sh.
    let capsule = first_capsule(&work).expect("a capsule dir");
    let scratch = tempfile::tempdir().unwrap();
    let dest = scratch.path().join("cap");
    assert!(Command::new("cp")
        .arg("-r")
        .arg(&capsule)
        .arg(&dest)
        .status()
        .unwrap()
        .success());
    // The shipped primary input is (typically) empty — the reproducer is the world.
    let replay = Command::new("sh")
        .arg("replay.sh")
        .current_dir(&dest)
        .output()
        .expect("run replay.sh");
    let rep_err = String::from_utf8_lossy(&replay.stderr);
    assert!(
        rep_err.contains("AddressSanitizer"),
        "replay.sh must reproduce the crash from the pinned environment; stderr:\n{rep_err}"
    );
}

fn has_crash_finding(work: &Path) -> bool {
    std::fs::read_dir(work.join("results").join("findings"))
        .map(|d| {
            d.flatten().any(|e| {
                e.file_name().to_string_lossy().starts_with("F-0000")
                    && e.path().join("testcase.bin").is_file()
            })
        })
        .unwrap_or(false)
}

fn first_capsule(work: &Path) -> Option<std::path::PathBuf> {
    std::fs::read_dir(work.join("env-capsules"))
        .ok()?
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("env_capsule_"))
        })
}

/// Same environment-driven overflow, in a C++ target: env-capsule handles the
/// native C++ lane as it does C.
const ENV_DRIVEN_CPP: &str = "\
#include <fcntl.h>
#include <unistd.h>
int load_config(const char *data, unsigned int len) {
    (void)data; (void)len;
    int fd = open(\"/etc/bhf_envcap_demo.conf\", O_RDONLY);
    if (fd < 0) return 0;
    char cfg[8];
    long n = read(fd, cfg, 64);
    close(fd);
    return n > 0 ? cfg[0] : 0;
}
";

#[test]
fn env_capsule_replays_a_cpp_environment_driven_crash() {
    if which::which("clang++").is_err() {
        eprintln!("skipping: clang++ not installed");
        return;
    }
    if !shim_present() {
        eprintln!("skipping: runtrace shim not built");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let work = root.path().join("work");
    let src = root.path().join("load_config.cpp");
    std::fs::write(&src, ENV_DRIVEN_CPP).unwrap();
    let snip = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("snippet")
        .arg(&src)
        .args(["--lang", "cpp", "--per-target-time", "8", "--work-dir"])
        .arg(&work)
        .output()
        .expect("run snippet");
    if !has_crash_finding(&work) {
        eprintln!(
            "skipping: no env-driven crash found; stderr:\n{}",
            String::from_utf8_lossy(&snip.stderr)
        );
        return;
    }
    let cap = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("env-capsule")
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run env-capsule");
    let stdout = String::from_utf8_lossy(&cap.stdout);
    assert!(
        cap.status.success() && stdout.contains("✓ replays"),
        "env-capsule must capture the C++ crash; stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&cap.stderr)
    );
    let capsule = first_capsule(&work).expect("a capsule dir");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(capsule.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["reproduced"], true, "{manifest}");
}

/// A requested finding env-capsule cannot capture is refused with its reason
/// and a non-zero exit, whether or not the runtrace shim is installed, and no
/// output dir is left behind.
#[test]
fn env_capsule_refusing_a_requested_finding_exits_non_zero() {
    let root = tempfile::tempdir().unwrap();
    let work = root.path().join("work");
    let id = "F-0001-0000aaaa";
    let harness_id = "H-A0003-0000ABCD";
    let finding_dir = work.join("results/findings").join(id);
    std::fs::create_dir_all(&finding_dir).unwrap();
    std::fs::write(finding_dir.join("testcase.bin"), b"AAAA").unwrap();
    std::fs::write(
        finding_dir.join("finding.json"),
        serde_json::json!({"id": id, "classification": "unhandled", "harness_id": harness_id})
            .to_string(),
    )
    .unwrap();
    let harness = work.join("harnesses").join(harness_id);
    std::fs::create_dir_all(&harness).unwrap();
    std::fs::write(
        harness.join("generation-metadata.json"),
        br#"{"schema_version":1,"language":"ada"}"#,
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("env-capsule")
        .arg("--work-dir")
        .arg(&work)
        .arg("--finding-id")
        .arg(id)
        .output()
        .expect("run env-capsule");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains(id) && stderr.contains("Ada"),
        "the refusal must name the finding and its language:\n{stderr}"
    );
    assert!(!work.join("env-capsules").exists(), "{stderr}");
}

/// Without `--finding-id`, a work dir none of whose findings crash under a
/// faked environment captures nothing: env-capsule says so, counts them as
/// skipped and exits non-zero, as capsule does when it packages nothing.
#[cfg(unix)]
#[test]
fn env_capsule_that_captures_nothing_says_so_and_exits_non_zero() {
    if !shim_present() {
        eprintln!("skipping: runtrace shim not built");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let work = root.path().join("work");
    let id = "F-0002-0000bbbb";
    let harness_id = "H-C0002-0000ABCD";
    let harness = work.join("harnesses").join(harness_id);
    std::fs::create_dir_all(&harness).unwrap();
    // A built harness that never crashes, whatever it is served.
    let main = harness.join("main");
    std::fs::write(&main, "#!/bin/sh\nexit 0\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&main, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let finding_dir = work.join("results/findings").join(id);
    std::fs::create_dir_all(&finding_dir).unwrap();
    std::fs::write(finding_dir.join("testcase.bin"), b"AAAA").unwrap();
    std::fs::write(
        finding_dir.join("finding.json"),
        serde_json::json!({"id": id, "classification": "unhandled", "harness_id": harness_id})
            .to_string(),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("env-capsule")
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run env-capsule");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stdout}\n{stderr}");
    assert!(
        stdout.contains("0 capsule(s)") && stdout.contains("1 finding(s) skipped"),
        "{stdout}"
    );
    assert!(stderr.contains("nothing captured"), "{stderr}");
}

/// A harness that runs inside a language runtime cannot have the shim
/// preloaded: env-capsule refuses it with that reason.
#[test]
fn env_capsule_refuses_an_interpreted_harness_with_its_reason() {
    let root = tempfile::tempdir().unwrap();
    let work = root.path().join("work");
    let id = "F-0003-0000cccc";
    let harness_id = "H-P0003-0000ABCD";
    let finding_dir = work.join("results/findings").join(id);
    std::fs::create_dir_all(&finding_dir).unwrap();
    std::fs::write(finding_dir.join("testcase.bin"), b"A").unwrap();
    std::fs::write(
        finding_dir.join("finding.json"),
        serde_json::json!({"id": id, "classification": "unhandled", "harness_id": harness_id})
            .to_string(),
    )
    .unwrap();
    std::fs::create_dir_all(work.join("harnesses").join(harness_id)).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("env-capsule")
        .arg("--work-dir")
        .arg(&work)
        .args(["--finding-id", id])
        .output()
        .expect("run env-capsule");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(
        stderr.contains("a Python harness") && stderr.contains("language runtime"),
        "{stderr}"
    );
}

/// An Ada target that reads a "trusted" config file through C's open/read
/// overflows its buffer on the content bhf's shim serves. env-capsule records
/// that world under the shim mode the finding fired in, feeds the Ada harness
/// its input on stdin, and replays the unhandled exception from the pinned
/// environment.
#[test]
fn env_capsule_replays_an_ada_environment_driven_crash() {
    let gnat = ["gprbuild", "gnatmake"].iter().all(|tool| {
        Command::new(tool)
            .arg("--version")
            .output()
            .is_ok_and(|out| out.status.success())
    });
    if !gnat {
        eprintln!("skipping: GNAT with gprbuild not installed");
        return;
    }
    if !shim_present() {
        eprintln!("skipping: runtrace shim not built");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let src = root.path().join("src");
    let work = root.path().join("work");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("config_loader.ads"),
        "package Config_Loader is\n   function Load_Config (Data : String) return Natural;\nend Config_Loader;\n",
    )
    .unwrap();
    std::fs::write(src.join("config_loader.adb"), ADA_ENV_DRIVEN).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(&src)
        .arg("--work-dir")
        .arg(&work)
        .args(["--languages", "ada", "--max-targets", "1", "--jobs", "1"])
        .args(["--per-target-time", "8", "--no-discovery-cache"])
        .output()
        .expect("run bhf auto");
    let crashed = std::fs::read_dir(work.join("results/findings"))
        .into_iter()
        .flatten()
        .flatten()
        .any(|entry| {
            std::fs::read_to_string(entry.path().join("finding.json"))
                .is_ok_and(|text| text.contains("\"unhandled\""))
        });
    assert!(
        crashed,
        "bhf auto must find the environment-driven Ada crash: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let cap = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("env-capsule")
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run env-capsule");
    let stdout = String::from_utf8_lossy(&cap.stdout);
    assert!(
        cap.status.success() && stdout.contains("✓ replays"),
        "env-capsule must capture the Ada crash; stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&cap.stderr)
    );
    let capsule = first_capsule(&work).expect("a capsule dir");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(capsule.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["lang"], "ada", "{manifest}");
    assert_eq!(manifest["protocol"], "stdin event log", "{manifest}");
    assert_eq!(manifest["reproduced"], true, "{manifest}");
    let replay = std::fs::read_to_string(capsule.join("replay.sh")).unwrap();
    assert!(
        replay.contains("cat input.bin | ") && replay.contains("BHF_EVENTS_PATH=events.bin"),
        "{replay}"
    );
    assert!(
        replay.contains(&format!(
            "BHF_RUNTRACE_MODE={}",
            manifest["runtime_mode"].as_str().unwrap()
        )),
        "{replay}"
    );
    // replay.sh replays it from a pristine copy: the event log records the
    // unhandled exception.
    let scratch = tempfile::tempdir().unwrap();
    let dest = scratch.path().join("cap");
    assert!(Command::new("cp")
        .arg("-r")
        .arg(&capsule)
        .arg(&dest)
        .status()
        .unwrap()
        .success());
    let replayed = Command::new("sh")
        .arg("replay.sh")
        .current_dir(&dest)
        .output()
        .expect("run replay.sh");
    assert!(replayed.status.success(), "{replayed:?}");
    let events = std::fs::read(dest.join("events.bin")).unwrap_or_default();
    assert!(
        events
            .windows(16)
            .any(|window| window == b"CONSTRAINT_ERROR"),
        "the replay raises the recorded exception"
    );
}

/// Reads up to 64 bytes of a config file into an 8-character buffer through
/// C's open/read (which the runtrace shim fakes): an index check fails when
/// the served content is longer than 8 bytes.
const ADA_ENV_DRIVEN: &str = "\
with Interfaces.C; use Interfaces.C;
with Interfaces.C.Strings;
with System;
package body Config_Loader is
   function C_Open (Path : Interfaces.C.Strings.chars_ptr; Flags : int) return int;
   pragma Import (C, C_Open, \"open\");
   function C_Read (Fd : int; Buf : System.Address; Count : size_t) return long;
   pragma Import (C, C_Read, \"read\");
   function C_Close (Fd : int) return int;
   pragma Import (C, C_Close, \"close\");

   function Load_Config (Data : String) return Natural is
      Path : Interfaces.C.Strings.chars_ptr :=
        Interfaces.C.Strings.New_String (\"/etc/bhf_envcap_demo.conf\");
      Fd   : int;
      Done : int;
      Buf  : String (1 .. 64) := (others => ' ');
      N    : long;
      Cfg  : String (1 .. 8) := (others => ' ');
   begin
      Fd := C_Open (Path, 0);
      Interfaces.C.Strings.Free (Path);
      if Fd < 0 then
         return 0;
      end if;
      N := C_Read (Fd, Buf'Address, 64);
      Done := C_Close (Fd);
      for I in 1 .. Integer (N) loop
         Cfg (I) := Buf (I);
      end loop;
      return Data'Length + Character'Pos (Cfg (1)) + Natural (Done + 1);
   end Load_Config;
end Config_Loader;
";
