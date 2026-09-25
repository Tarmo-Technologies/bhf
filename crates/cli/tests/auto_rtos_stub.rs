// SPDX-License-Identifier: Apache-2.0

//! End-to-end: `bhf auto` on UNGUARDED RTOS application code — the dominant
//! real-world shape for radar/avionics software, which simply `#include
//! <vxWorks.h>` and is built only by the vendor toolchain in production. On a
//! Linux lab host those platform headers are absent, so the host harness build
//! first fails with `'vxWorks.h' file not found`. bhf must recover: the
//! repair loop fills the missing RTOS headers with a rich type surface (STATUS,
//! SEM_ID, OK/ERROR, …) and the placeholder dir is searched with `-idirafter`
//! so the ANGLED `<...>` includes resolve — the target then builds + fuzzes
//! stub-isolated on the host with the builtin engine.
//!
//! Shells the built `bhf` binary. Gated on clang so a toolchain-less CI lane
//! skips cleanly rather than failing.

use std::path::Path;
use std::process::Command;

fn toolchain_available() -> bool {
    if which::which("clang").is_err() {
        eprintln!("skipping auto_rtos_stub: clang not on PATH");
        return false;
    }
    true
}

/// A representative unguarded VxWorks translation unit: it pulls in three vendor
/// headers and uses their type surface (STATUS / SEM_ID / OK / ERROR) in the
/// algorithmic body bhf should fuzz.
fn write_fixture(root: &Path) {
    std::fs::write(
        root.join("radar_track.c"),
        "#include <vxWorks.h>\n\
         #include <semLib.h>\n\
         #include <msgQLib.h>\n\
         \n\
         static SEM_ID track_lock;\n\
         \n\
         /* Parse a radar track message. Built only by the vendor toolchain in\n\
            production; bhf stubs the RTOS headers to fuzz it on the host. */\n\
         int parse_track_msg(const unsigned char *buf, unsigned len)\n\
         {\n\
         \x20   STATUS s = OK;\n\
         \x20   unsigned i, checksum = 0;\n\
         \x20   if (len < 4) return ERROR;\n\
         \x20   for (i = 0; i < len; i++) {\n\
         \x20       checksum += buf[i];\n\
         \x20       if (buf[i] == 0xFF && i + 1 < len && buf[i + 1] == 0xFE)\n\
         \x20           s = ERROR;\n\
         \x20   }\n\
         \x20   return s == OK ? (int)(checksum & 0x7fff) : ERROR;\n\
         }\n",
    )
    .unwrap();
}

#[test]
fn unguarded_vxworks_code_builds_stub_isolated_and_fuzzes() {
    if !toolchain_available() {
        return;
    }
    let tmp = tempfile::Builder::new()
        .prefix("bhf-rtos-vxworks-")
        .tempdir()
        .expect("tempdir");
    let root = tmp.path();
    write_fixture(root);
    let work = root.join("gw");

    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(root)
        .arg("--work-dir")
        .arg(&work)
        .arg("--per-target-time")
        .arg("1")
        .output()
        .expect("spawn bhf auto");

    let run_json_path = work.join("auto/run.json");
    let run_bytes = std::fs::read(&run_json_path).unwrap_or_else(|e| {
        panic!(
            "read {}: {e}; bhf auto exit={:?}\nstderr:\n{}",
            run_json_path.display(),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    let run: serde_json::Value = serde_json::from_slice(&run_bytes).expect("parse run.json");

    // The whole point: the RTOS target must reach built_and_fuzzed on the host,
    // NOT failed_build. Without the rich RTOS header packs + the -idirafter
    // fallback it would die on `'vxWorks.h' file not found`.
    let built_and_fuzzed = run["summary"]["built_and_fuzzed"].as_u64().unwrap_or(0);
    assert!(
        built_and_fuzzed >= 1,
        "unguarded VxWorks code must build+fuzz stub-isolated; summary={}\nstderr:\n{}",
        run["summary"],
        String::from_utf8_lossy(&output.stderr)
    );

    // And specifically the radar parser, with no opaque failed_build left behind.
    let targets = run["targets"].as_array().expect("targets array");
    assert!(
        targets
            .iter()
            .any(|t| t["name"].as_str() == Some("parse_track_msg")
                && t["outcome"]["outcome"].as_str() == Some("built_and_fuzzed")),
        "parse_track_msg should be built_and_fuzzed; targets={targets:#?}"
    );
}

/// A translation unit whose fuzzable entry point exists ONLY inside a
/// `#ifdef __vxworks` branch — invisible on a Linux host unless bhf detects
/// the platform guard, defines it, and stub-isolates the platform headers. This
/// exercises the discovery→`foreign_platform_stub`→`apply_platform_stub` route
/// (the parser tags the guard; the build defines `__vxworks` + supplies the
/// header pack), distinct from the unguarded repair-loop route above.
fn write_guarded_fixture(root: &Path) {
    std::fs::write(
        root.join("sonar.c"),
        "#include <vxWorks.h>\n\
         #include <semLib.h>\n\
         \n\
         #ifdef __vxworks\n\
         int sonar_decode(const unsigned char *ping, unsigned len)\n\
         {\n\
         \x20   STATUS s = OK;\n\
         \x20   unsigned i, energy = 0;\n\
         \x20   if (len < 8) return ERROR;\n\
         \x20   for (i = 0; i < len; i++) {\n\
         \x20       energy += ping[i];\n\
         \x20       if (ping[i] == 0xDE && i + 1 < len && ping[i + 1] == 0xAD)\n\
         \x20           s = ERROR;\n\
         \x20   }\n\
         \x20   return s == OK ? (int)(energy % 1024) : ERROR;\n\
         }\n\
         #endif\n",
    )
    .unwrap();
}

#[test]
fn guarded_vxworks_branch_is_made_visible_and_fuzzed_stub_isolated() {
    if !toolchain_available() {
        return;
    }
    let tmp = tempfile::Builder::new()
        .prefix("bhf-rtos-guarded-")
        .tempdir()
        .expect("tempdir");
    let root = tmp.path();
    write_guarded_fixture(root);
    let work = root.join("gw");

    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(root)
        .arg("--work-dir")
        .arg(&work)
        .arg("--per-target-time")
        .arg("1")
        .output()
        .expect("spawn bhf auto");

    let run: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work.join("auto/run.json")).unwrap_or_else(|e| {
            panic!(
                "read run.json: {e}; exit={:?}\nstderr:\n{}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            )
        }),
    )
    .expect("parse run.json");

    // The guard-only function must be discovered, made visible, and fuzzed.
    let targets = run["targets"].as_array().expect("targets array");
    assert!(
        targets
            .iter()
            .any(|t| t["name"].as_str() == Some("sonar_decode")
                && t["outcome"]["outcome"].as_str() == Some("built_and_fuzzed")),
        "guard-only sonar_decode should be built_and_fuzzed; targets={targets:#?}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    // It routed through the stub-isolated platform path (not a plain native
    // build), and bhf flagged the reduced fidelity in its output.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("STUB-ISOLATED") && stderr.to_lowercase().contains("vxworks"),
        "must report the stub-isolated vxworks build; stderr:\n{stderr}"
    );
}

/// CC-1: a stub-isolated VxWorks target's report must carry a STRUCTURED fidelity
/// record — enumerating the un-exercised dimensions, not just a coarse text
/// caveat — on both the per-target `run.json` entry and the campaign summary.
#[test]
fn stub_isolated_target_carries_structured_fidelity_record() {
    if !toolchain_available() {
        return;
    }
    let tmp = tempfile::Builder::new()
        .prefix("bhf-rtos-fidelity-")
        .tempdir()
        .expect("tempdir");
    let root = tmp.path();
    write_guarded_fixture(root);
    let work = root.join("gw");

    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(root)
        .arg("--work-dir")
        .arg(&work)
        .arg("--per-target-time")
        .arg("1")
        .output()
        .expect("spawn bhf auto");

    let run: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work.join("auto/run.json")).unwrap_or_else(|e| {
            panic!(
                "read run.json: {e}; exit={:?}\nstderr:\n{}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            )
        }),
    )
    .expect("parse run.json");

    // Per-target fidelity block: the VxWorks target ran host-stubbed, so its ISA,
    // RTOS runtime, and hardware were NOT exercised, each with a reason.
    let target = run["targets"]
        .as_array()
        .expect("targets array")
        .iter()
        .find(|t| t["name"].as_str() == Some("sonar_decode"))
        .unwrap_or_else(|| panic!("sonar_decode target missing; run={run:#?}"));
    let fidelity = &target["fidelity"];
    assert_eq!(
        fidelity["arch"]["status"].as_str(),
        Some("not_exercised"),
        "target ISA must read not_exercised for a host stub; fidelity={fidelity:#?}"
    );
    assert_eq!(
        fidelity["rtos_runtime"]["status"].as_str(),
        Some("not_exercised"),
        "RTOS runtime must read not_exercised; fidelity={fidelity:#?}"
    );
    assert_eq!(
        fidelity["hardware_peripherals"]["status"].as_str(),
        Some("not_exercised"),
        "hardware must read not_exercised; fidelity={fidelity:#?}"
    );
    // Reasons must be present and name the platform / the missing surface.
    assert!(
        fidelity["arch"]["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("vxworks"),
        "arch reason must name the platform; fidelity={fidelity:#?}"
    );
    assert!(
        !fidelity["rtos_runtime"]["reason"]
            .as_str()
            .unwrap_or_default()
            .is_empty(),
        "rtos_runtime must carry a reason; fidelity={fidelity:#?}"
    );

    // Campaign rollup: at least one reduced-fidelity target, vxworks listed, and a
    // derived caveat that refuses to read as target assurance.
    let summary_fidelity = &run["summary"]["fidelity"];
    assert!(
        summary_fidelity["reduced_fidelity_targets"]
            .as_u64()
            .unwrap_or(0)
            >= 1,
        "summary must count the reduced-fidelity target; summary={summary_fidelity:#?}"
    );
    let platforms = summary_fidelity["stubbed_platforms"]
        .as_array()
        .expect("stubbed_platforms array");
    assert!(
        platforms.iter().any(|p| p.as_str() == Some("vxworks")),
        "summary must list the stubbed platform; summary={summary_fidelity:#?}"
    );
    let caveat = summary_fidelity["caveat"].as_str().unwrap_or_default();
    assert!(
        caveat.contains("RTOS runtime") && caveat.contains("not target assurance"),
        "summary caveat must enumerate gaps and refuse assurance; caveat={caveat:?}"
    );
}

/// A plain host C translation unit with no foreign platform header. bhf builds
/// and fuzzes it natively, so it is the host target — CC-1 must NOT stamp it with
/// a spurious reduced-fidelity caveat.
fn write_native_fixture(root: &Path) {
    std::fs::write(
        root.join("frame_len.c"),
        "#include <stddef.h>\n\
         \n\
         /* A plain portable parser: no RTOS, no platform header. */\n\
         int parse_frame(const unsigned char *buf, unsigned len)\n\
         {\n\
         \x20   unsigned i, acc = 0;\n\
         \x20   if (len < 2) return -1;\n\
         \x20   for (i = 0; i < len; i++) {\n\
         \x20       acc += buf[i];\n\
         \x20       if (buf[i] == 0x7E && i + 1 < len && buf[i + 1] == 0x7F)\n\
         \x20           return (int)(acc & 0x3ff);\n\
         \x20   }\n\
         \x20   return (int)(acc & 0x7f);\n\
         }\n",
    )
    .unwrap();
}

/// CC-1: a fully-native host target must carry a fidelity record that reads as
/// full-fidelity — arch/endianness `exercised`, RTOS/hardware `not_applicable` —
/// and NO caveat, so it is never confused with a host-stub result.
#[test]
fn native_host_target_carries_full_fidelity_without_caveat() {
    if !toolchain_available() {
        return;
    }
    let tmp = tempfile::Builder::new()
        .prefix("bhf-native-fidelity-")
        .tempdir()
        .expect("tempdir");
    let root = tmp.path();
    write_native_fixture(root);
    let work = root.join("gw");

    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(root)
        .arg("--work-dir")
        .arg(&work)
        .arg("--per-target-time")
        .arg("1")
        .output()
        .expect("spawn bhf auto");

    let run: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work.join("auto/run.json")).unwrap_or_else(|e| {
            panic!(
                "read run.json: {e}; exit={:?}\nstderr:\n{}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            )
        }),
    )
    .expect("parse run.json");

    let target = run["targets"]
        .as_array()
        .expect("targets array")
        .iter()
        .find(|t| t["name"].as_str() == Some("parse_frame"))
        .unwrap_or_else(|| {
            panic!(
                "parse_frame target missing; run={run:#?}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
        });

    // No platform stub: the host IS the target.
    assert!(
        target.get("platform_stub").is_none() || target["platform_stub"].is_null(),
        "native target must not be platform-stubbed; target={target:#?}"
    );
    let fidelity = &target["fidelity"];
    assert_eq!(
        fidelity["arch"]["status"].as_str(),
        Some("exercised"),
        "native arch must read exercised; fidelity={fidelity:#?}"
    );
    assert_eq!(
        fidelity["endianness"]["status"].as_str(),
        Some("exercised"),
        "native endianness must read exercised; fidelity={fidelity:#?}"
    );
    assert_eq!(
        fidelity["rtos_runtime"]["status"].as_str(),
        Some("not_applicable"),
        "native has no RTOS runtime; fidelity={fidelity:#?}"
    );
    assert_eq!(
        fidelity["hardware_peripherals"]["status"].as_str(),
        Some("not_applicable"),
        "native has no hardware; fidelity={fidelity:#?}"
    );

    // No spurious campaign caveat, and no reduced-fidelity target counted.
    let summary_fidelity = &run["summary"]["fidelity"];
    assert_eq!(
        summary_fidelity["reduced_fidelity_targets"]
            .as_u64()
            .unwrap_or(0),
        0,
        "native sweep must count zero reduced-fidelity targets; summary={summary_fidelity:#?}"
    );
    assert!(
        summary_fidelity.get("caveat").is_none() || summary_fidelity["caveat"].is_null(),
        "native sweep must carry no caveat; summary={summary_fidelity:#?}"
    );
}
