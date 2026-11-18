// SPDX-License-Identifier: Apache-2.0

//! The RealtimeSanitizer replay lane (#298): `bhf auto --sanitizers
//! asan,ubsan,realtime` marks the targets that must not block (by default
//! interrupt handlers and RTOS task bodies), builds their harnesses with clang
//! 20+ and `-fsanitize=realtime`, and replays the corpus. A task body that
//! allocates on its real-time path is a BHF-232 finding that replays. Needs a
//! clang 20 or newer; `BHF_REQUIRE_TOOLS=1` makes a missing one a failure.

#![cfg(unix)]

use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// Whether a clang 20 or newer is on PATH, as the lane looks for one,
/// through `support::require_tool`.
fn have_rtsan_clang() -> bool {
    let found = ["clang-22", "clang-21", "clang-20", "clang"]
        .iter()
        .any(|cc| {
            Command::new(cc).arg("--version").output().is_ok_and(|out| {
                String::from_utf8_lossy(&out.stdout)
                    .split("clang version ")
                    .nth(1)
                    .and_then(|v| v.split('.').next())
                    .and_then(|major| major.trim().parse::<u32>().ok())
                    .is_some_and(|major| major >= 20)
            })
        });
    support::require_tool(found, "clang 20 or newer (RealtimeSanitizer)")
}

#[test]
fn an_allocation_in_a_task_body_is_a_realtime_finding() {
    if !have_rtsan_clang() {
        eprintln!("skipping: no clang 20 or newer on PATH");
        return;
    }
    let root = TestDir::new("rtsan-replay");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    // The allocation escapes through a volatile global, so the optimizer
    // keeps it.
    std::fs::write(
        src.join("sensor.c"),
        "#include <stdlib.h>\n\
         static char *volatile kept;\n\
         void sensor_task(void *params) {\n\
         \x20   const unsigned char *in = params;\n\
         \x20   if (in[0] == 'M') {\n\
         \x20       /* Planted: the task allocates on its real-time path. */\n\
         \x20       kept = malloc(8);\n\
         \x20       kept[0] = (char)in[0];\n\
         \x20       free(kept);\n\
         \x20   }\n\
         }\n",
    )
    .unwrap();
    let seed = root.join("seed.bin");
    std::fs::write(&seed, b"MX").unwrap();
    let work = root.join("work");
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(&src)
        .arg("--work-dir")
        .arg(&work)
        .args([
            "--target",
            "sensor_task",
            "--per-target-time",
            "3",
            "--jobs",
            "1",
        ])
        .args(["--sanitizers", "asan,ubsan,realtime", "--seed-file"])
        .arg(&seed)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains(
            "RealtimeSanitizer — 1 real-time unsafe call(s) found by corpus replay of 1 \
             nonblocking target(s)"
        ),
        "{stderr}"
    );

    let finding = work.join("results/findings/F-RTSAN-0000");
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(finding.join("finding.json")).unwrap()).unwrap();
    assert_eq!(record["rule_id"], "BHF-232", "{record:#}");
    assert_eq!(record["target"]["line"], 7, "the malloc's line: {record:#}");
    assert!(
        record["exception"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("`malloc`")),
        "{record:#}"
    );
    let replay = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("replay")
        .arg(&finding)
        .output()
        .unwrap();
    let replayed = String::from_utf8_lossy(&replay.stdout);
    assert!(replayed.starts_with("MATCH"), "{replayed}");
}

/// `--nonblocking` belongs to the realtime lane; without it the run says so.
#[test]
fn nonblocking_without_the_realtime_lane_is_refused() {
    let root = TestDir::new("rtsan-refused");
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(root.path())
        .args(["--nonblocking", "sensor_task", "--work-dir"])
        .arg(root.join("work"))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("add `--sanitizers realtime`"), "{stderr}");
}
