// SPDX-License-Identifier: Apache-2.0
//! End-to-end coverage for `bhf cartography`: after fuzzing an OOB read whose
//! offset a single input byte controls, the perturbation analysis must identify
//! that byte as controlling the offset and classify the exploit primitive as a
//! controlled relative read (CWE-125) — deterministically and offline.

use std::process::Command;

fn clang_available() -> bool {
    which::which("clang").is_ok()
}

/// byte 0 controls an OOB read offset that lands in the 16-byte heap redzone, so
/// ANY input reliably crashes and byte 0 is the offset control.
const BYTE_CONTROLLED_OOB_C: &str = "\
#include <string.h>
#include <stdlib.h>
int idx_read(const char *data, unsigned int len) {
    if (len < 2) return 0;
    char *buf = malloc(16);
    memset(buf, 0, 16);
    unsigned idx = 16 + ((unsigned char)data[0] % 8);
    char r = buf[idx];
    free(buf);
    return r;
}
";

/// Run from the project dir with the default (relative) `bhf_work`, as
/// `bhf explain` suggests: the replays, which run beside the harness binary,
/// must still find the binary and the input.
#[test]
fn cartography_maps_byte_to_controlled_read_offset() {
    if !clang_available() {
        eprintln!("skipping: clang not installed");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let work = root.path().join("bhf_work");
    let src = root.path().join("idx_read.c");
    std::fs::write(&src, BYTE_CONTROLLED_OOB_C).unwrap();
    let snip = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("snippet")
        .arg(&src)
        .arg("--lang")
        .arg("c")
        .arg("--per-target-time")
        .arg("6")
        .arg("--work-dir")
        .arg(&work)
        .output()
        .expect("run snippet");
    assert!(
        find_finding(&work).is_some(),
        "snippet produced no crash: {}",
        String::from_utf8_lossy(&snip.stderr)
    );

    let carto = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("cartography")
        .current_dir(root.path())
        .output()
        .expect("run cartography");
    let stdout = String::from_utf8_lossy(&carto.stdout);
    assert!(
        carto.status.success()
            && (stdout.contains("controls offset/index")
                || stdout.contains("controlled_relative_read")),
        "cartography should map an offset-controlling byte; stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&carto.stderr)
    );

    // The machine-readable card must carry the primitive + the controlling byte.
    let fdir = find_finding(&work).unwrap();
    let card: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fdir.join("byte-control.json")).unwrap()).unwrap();
    assert_eq!(card["primitive"]["kind"], "controlled_relative_read");
    assert_eq!(card["primitive"]["cwe"], "CWE-125");
    let ctrl = card["primitive"]["controlling_bytes"].as_array().unwrap();
    assert!(
        ctrl.iter().any(|b| b.as_u64() == Some(0)),
        "byte 0 must be flagged as controlling the offset; card: {card}"
    );

    // The finding itself is enriched with the primitive.
    let finding: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fdir.join("finding.json")).unwrap()).unwrap();
    assert_eq!(finding["primitive"]["kind"], "controlled_relative_read");
}

fn find_finding(work: &std::path::Path) -> Option<std::path::PathBuf> {
    std::fs::read_dir(work.join("results").join("findings"))
        .ok()?
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("F-0000"))
                && p.join("testcase.bin").is_file()
        })
}

fn clangxx_available() -> bool {
    which::which("clang++").is_ok()
}

/// A wild read: bytes 0-3 are an index that puts the access far outside a
/// 16-byte table (through a pointer, so no UBSan bounds check fires first),
/// so every input of four bytes or more ends in a SEGV whose faulting address
/// those bytes set. A SEGV report carries no region-relative offset, so the
/// address is the only operand perturbation can watch.
const WILD_READ_CPP: &str = "\
#include <cstring>
static char table[16];
int wild_read(const char *data, unsigned int len) {
    if (len < 4) return 0;
    unsigned int index;
    std::memcpy(&index, data, 4);
    const char *base = table;
    return base[index | 0x40000000u];
}
";

#[test]
fn cartography_maps_the_bytes_that_set_a_cpp_segv_faulting_address() {
    if !clangxx_available() {
        eprintln!("skipping: clang++ not installed");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let work = root.path().join("work");
    let src = root.path().join("wild.cpp");
    std::fs::write(&src, WILD_READ_CPP).unwrap();
    let snip = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("snippet")
        .arg(&src)
        .args(["--lang", "cpp", "--per-target-time", "6", "--work-dir"])
        .arg(&work)
        .output()
        .expect("run snippet");
    let fdir = find_finding(&work).unwrap_or_else(|| {
        panic!(
            "snippet produced no crash: {}",
            String::from_utf8_lossy(&snip.stderr)
        )
    });
    let finding: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fdir.join("finding.json")).unwrap()).unwrap();
    let id = finding["id"].as_str().unwrap().to_owned();
    assert!(
        finding["harness_id"]
            .as_str()
            .is_some_and(|h| h.starts_with("H-X")),
        "{finding}"
    );
    // Windows' AddressSanitizer reports the fault as an access violation.
    let fault = if cfg!(windows) {
        "ASAN_ACCESS_VIOLATION"
    } else {
        "ASAN_SEGV"
    };
    assert_eq!(finding["exception"]["name"], fault, "{finding}");

    let carto = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("cartography")
        .arg("--work-dir")
        .arg(&work)
        .arg("--finding-id")
        .arg(&id)
        .output()
        .expect("run cartography");
    let stdout = String::from_utf8_lossy(&carto.stdout);
    assert!(
        carto.status.success(),
        "cartography must map the C++ finding; stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&carto.stderr)
    );
    let card: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fdir.join("byte-control.json")).unwrap()).unwrap();
    assert_eq!(card["crash"]["class"], "SEGV", "{card}");
    let classes: Vec<&str> = card["bytes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["class"].as_str().unwrap())
        .collect();
    assert!(
        classes.len() >= 4 && classes[..4].iter().all(|c| *c == "controls_address"),
        "bytes 0-3 set the faulting address: {card}"
    );
    assert_eq!(
        card["primitive"]["kind"], "controlled_address_read",
        "{card}"
    );
    assert!(
        card["primitive"]["controlling_bytes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b.as_u64() == Some(0)),
        "{card}"
    );
}

/// A requested finding cartography cannot map is refused with its reason and
/// a non-zero exit; a run that maps nothing from a work dir with crash
/// findings fails too.
#[test]
fn cartography_refusing_a_requested_finding_exits_non_zero() {
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

    for args in [vec!["--finding-id", id], vec![]] {
        let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
            .arg("cartography")
            .arg("--work-dir")
            .arg(&work)
            .args(&args)
            .output()
            .expect("run cartography");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{args:?}: {stderr}");
        assert!(
            stderr.contains(id) && stderr.contains("Ada"),
            "{args:?}: the refusal must name the finding and its language:\n{stderr}"
        );
    }
}
