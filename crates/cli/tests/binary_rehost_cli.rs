// SPDX-License-Identifier: Apache-2.0

//! `bhf binary rehost` on the fault fixture firmware
//! (`crates/rehost/tests/fixtures/faults.c`): an invalid access becomes a
//! finding, and `bhf replay` reproduces it as a MATCH.

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn bhf() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../rehost/tests/fixtures")
        .join(name)
}

fn text(output: &Output) -> String {
    format!(
        "status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// "FUZZ", the command byte, and a little-endian address.
fn record(dir: &Path, command: u8, address: u32) -> PathBuf {
    let mut bytes = b"FUZZ".to_vec();
    bytes.push(command);
    bytes.extend_from_slice(&address.to_le_bytes());
    let path = dir.join(format!("seed-{}-{address:08x}", command as char));
    fs::write(&path, bytes).unwrap();
    path
}

fn rehost(work: &Path, image: &Path, extra: &[&str]) -> Output {
    bhf()
        .args(["binary", "rehost"])
        .arg(image)
        .arg("--work-dir")
        .arg(work)
        .args([
            "--input-buffer",
            "rx_buf",
            "--input-length",
            "rx_len",
            "--inject-at",
            "main",
        ])
        .args(extra)
        .output()
        .unwrap()
}

fn summary(output: &Output) -> Value {
    assert!(output.status.success(), "{}", text(output));
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("run JSON: {error}\n{}", text(output)))
}

#[test]
fn an_invalid_access_is_a_finding_that_replays_as_a_match() {
    let root = TestDir::new("binary-rehost-match");
    let work = root.join("work");
    let seed = record(&root, b'W', 0x6000_0000);
    let output = rehost(
        &work,
        &fixture("faults.elf"),
        &["--seed-file", seed.to_str().unwrap(), "--iterations", "8"],
    );
    let summary = summary(&output);
    assert_eq!(summary["engine"], "rehost");
    assert_eq!(summary["fidelity"]["execution"], "rehosted");
    let findings = summary["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "{summary:#}");
    let id = findings[0].as_str().unwrap();
    let dir = work.join("results/findings").join(id);
    let finding: Value =
        serde_json::from_slice(&fs::read(dir.join("finding.json")).unwrap()).unwrap();
    assert_eq!(finding["kind"], "rehost_fault");
    assert_eq!(finding["finding_kind"], "binary");
    assert_eq!(finding["classification"], "invalid_access");
    assert_eq!(finding["rehost"]["fault"]["kind"], "write_unmapped");
    assert_eq!(finding["rehost"]["fault"]["address"], "0x60000000");
    assert_eq!(
        fs::read(dir.join("testcase.bin")).unwrap(),
        fs::read(&seed).unwrap()
    );
    // The results index lists it.
    let index = fs::read_to_string(work.join("results/INDEX.md")).unwrap();
    assert!(index.contains(id), "{index}");

    let replay = bhf().arg("replay").arg(&dir).output().unwrap();
    assert_eq!(replay.status.code(), Some(0), "{}", text(&replay));
    let stdout = String::from_utf8_lossy(&replay.stdout);
    assert!(stdout.starts_with("MATCH"), "{}", text(&replay));

    let json = bhf().args(["replay", "--json"]).arg(&dir).output().unwrap();
    assert_eq!(json.status.code(), Some(0), "{}", text(&json));
    let report: Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(report["verdict"], "match");
    assert_eq!(report["lane"], "rehost");
}

#[test]
fn a_campaign_reaches_a_fault_by_mutation_and_the_replay_matches() {
    let root = TestDir::new("binary-rehost-campaign");
    let work = root.join("work");
    // A store into RAM: the seed runs clean.
    let seed = record(&root, b'W', 0x2000_0100);
    let output = rehost(
        &work,
        &fixture("faults.elf"),
        &[
            "--seed-file",
            seed.to_str().unwrap(),
            "--iterations",
            "3000",
        ],
    );
    let summary = summary(&output);
    let findings = summary["findings"].as_array().unwrap();
    assert!(!findings.is_empty(), "{summary:#}");
    for id in findings {
        let dir = work.join("results/findings").join(id.as_str().unwrap());
        let replay = bhf().arg("replay").arg(&dir).output().unwrap();
        assert_eq!(replay.status.code(), Some(0), "{}", text(&replay));
    }
}

#[test]
fn a_changed_testcase_replays_as_a_mismatch() {
    let root = TestDir::new("binary-rehost-mismatch");
    let work = root.join("work");
    let seed = record(&root, b'J', 0x4000_0001);
    let summary = summary(&rehost(
        &work,
        &fixture("faults.elf"),
        &["--seed-file", seed.to_str().unwrap(), "--iterations", "1"],
    ));
    let id = summary["findings"][0].as_str().unwrap();
    let dir = work.join("results/findings").join(id);
    fs::write(dir.join("testcase.bin"), b"FUZZQ").unwrap();
    let replay = bhf().arg("replay").arg(&dir).output().unwrap();
    assert_eq!(replay.status.code(), Some(3), "{}", text(&replay));
    assert!(
        String::from_utf8_lossy(&replay.stderr).contains("MISMATCH"),
        "{}",
        text(&replay)
    );
}

#[test]
fn a_raw_image_runs_at_its_base_and_names_addresses_by_number() {
    let root = TestDir::new("binary-rehost-raw");
    let work = root.join("work");
    let seed = record(&root, b'R', 0x7000_0000);
    // The raw image has no symbols: rx_buf and rx_len are at 0x20000000 and
    // 0x20000044 (`arm-none-eabi-nm faults.elf`), main at 0x08000184, which
    // is given the way `nm` prints it.
    let output = bhf()
        .args(["binary", "rehost"])
        .arg(fixture("faults.bin"))
        .arg("--work-dir")
        .arg(&work)
        .args([
            "--base",
            "0x08000000",
            "--input-buffer",
            "0x20000000",
            "--input-size",
            "64",
            "--input-length",
            "0x20000044",
            "--inject-at",
            "08000184",
            "--seed-file",
            seed.to_str().unwrap(),
            "--iterations",
            "1",
        ])
        .output()
        .unwrap();
    let summary = summary(&output);
    assert_eq!(summary["format"], "raw");
    let id = summary["findings"][0].as_str().unwrap();
    let replay = bhf()
        .arg("replay")
        .arg(work.join("results/findings").join(id))
        .output()
        .unwrap();
    assert_eq!(replay.status.code(), Some(0), "{}", text(&replay));
}

#[test]
fn setup_errors_are_reported_before_anything_runs() {
    let root = TestDir::new("binary-rehost-errors");
    let work = root.join("work");
    let raw = bhf()
        .args(["binary", "rehost"])
        .arg(fixture("faults.bin"))
        .arg("--work-dir")
        .arg(&work)
        .args(["--input-buffer", "0x20000000", "--input-size", "64"])
        .output()
        .unwrap();
    assert_eq!(raw.status.code(), Some(1), "{}", text(&raw));
    assert!(
        String::from_utf8_lossy(&raw.stderr).contains("--base"),
        "{}",
        text(&raw)
    );
    let symbol = rehost(
        &work,
        &fixture("faults.elf"),
        &["--exit-at", "no_such_function"],
    );
    assert_eq!(symbol.status.code(), Some(1), "{}", text(&symbol));
    assert!(
        String::from_utf8_lossy(&symbol.stderr).contains("no_such_function"),
        "{}",
        text(&symbol)
    );
}

#[test]
fn an_input_the_firmware_never_receives_is_counted_and_warned_about() {
    let root = TestDir::new("binary-rehost-undelivered");
    let work = root.join("work");
    let delivered = rehost(
        &work,
        &fixture("faults.elf"),
        &["--seed-input", "FUZZQ", "--iterations", "3"],
    );
    assert_eq!(summary(&delivered)["input_not_delivered"], 0);
    assert!(
        !String::from_utf8_lossy(&delivered.stderr).contains("warning"),
        "{}",
        text(&delivered)
    );
    // No exception is ever taken, so the default handler never runs.
    let output = bhf()
        .args(["binary", "rehost"])
        .arg(fixture("faults.elf"))
        .arg("--work-dir")
        .arg(&work)
        .args([
            "--input-buffer",
            "rx_buf",
            "--inject-at",
            "Default_Handler",
            "--seed-input",
            "FUZZQ",
            "--iterations",
            "3",
        ])
        .output()
        .unwrap();
    let run = summary(&output);
    assert_eq!(run["executions"], 3);
    assert_eq!(run["input_not_delivered"], 3);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("warning") && stderr.contains("--inject-at 0x08000040"),
        "{}",
        text(&output)
    );
}

/// The length byte, then a "FUZZW" record for the peripheral fixture
/// (`mmio.c`) that stores `value` at `offset` in its table.
fn store_record(dir: &Path, offset: u32, value: u8) -> PathBuf {
    let mut record = b"FUZZW".to_vec();
    record.extend_from_slice(&offset.to_le_bytes());
    record.push(value);
    let mut bytes = vec![record.len() as u8];
    bytes.extend_from_slice(&record);
    let path = dir.join(format!("seed-store-{offset:08x}"));
    fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn a_peripheral_fed_image_reaches_its_parser_bug_and_replays_with_its_models() {
    let root = TestDir::new("binary-rehost-mmio");
    let work = root.join("work");
    // An in-bounds store: the seed runs clean, one byte from a wild write.
    let seed = store_record(&root, 4, 0x5a);
    let output = bhf()
        .args(["binary", "rehost"])
        .arg(fixture("mmio.elf"))
        .arg("--work-dir")
        .arg(&work)
        .args([
            "--mmio",
            "0x40013000=constant:0x4c31a5c3",
            "--seed-file",
            seed.to_str().unwrap(),
            "--iterations",
            "3000",
        ])
        .output()
        .unwrap();
    let run = summary(&output);
    assert_eq!(run["setup"]["input"], Value::Null);
    assert_eq!(run["setup"]["mmio"]["default"], "passthrough");
    let findings = run["findings"].as_array().unwrap();
    assert!(!findings.is_empty(), "{run:#}");
    for id in findings {
        let dir = work.join("results/findings").join(id.as_str().unwrap());
        let finding: Value =
            serde_json::from_slice(&fs::read(dir.join("finding.json")).unwrap()).unwrap();
        // The wild store lands in unmapped memory or in the read-only image.
        assert_eq!(finding["classification"], "invalid_access", "{finding:#}");
        assert_eq!(
            finding["rehost"]["setup"]["mmio"]["models"][0]["value"],
            "0x4c31a5c3"
        );
        let replay = bhf().arg("replay").arg(&dir).output().unwrap();
        assert_eq!(replay.status.code(), Some(0), "{}", text(&replay));
        assert!(
            String::from_utf8_lossy(&replay.stdout).contains("peripheral reads"),
            "{}",
            text(&replay)
        );
    }
    // Without the ID model the firmware never reaches its parser.
    let unmodelled = bhf()
        .args(["binary", "rehost"])
        .arg(fixture("mmio.elf"))
        .arg("--work-dir")
        .arg(root.join("unmodelled"))
        .args([
            "--seed-file",
            store_record(&root, 0x4000_0000, 0x5a).to_str().unwrap(),
            "--iterations",
            "1",
        ])
        .output()
        .unwrap();
    let unmodelled = summary(&unmodelled);
    assert_eq!(
        unmodelled["findings"],
        serde_json::json!([]),
        "{unmodelled:#}"
    );
}

#[test]
fn an_mmio_model_flag_that_does_not_parse_is_refused() {
    let root = TestDir::new("binary-rehost-mmio-bad");
    let output = bhf()
        .args(["binary", "rehost"])
        .arg(fixture("mmio.elf"))
        .arg("--work-dir")
        .arg(root.join("work"))
        .args(["--mmio", "0x40013000=sometimes"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{}", text(&output));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("\"sometimes\""),
        "{}",
        text(&output)
    );
    // The input buffer's companions need the buffer.
    let output = bhf()
        .args(["binary", "rehost"])
        .arg(fixture("mmio.elf"))
        .args(["--input-size", "16"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{}", text(&output));
}

/// A "FUZZC" line for the polled-UART fixture (`uart.c`) whose field length
/// is `length`, laid out as the inferred models read it: a byte for the
/// prompt's transmit poll, then for each byte of the line and its newline a
/// byte for the receive poll and the four bytes of the data register.
fn polled_field_line(dir: &Path, length: u8) -> PathBuf {
    let mut line = b"FUZZC".to_vec();
    line.push(length);
    line.extend_from_slice(&[b'A'; 16]);
    let mut input = vec![1];
    for &byte in line.iter().chain(b"\n") {
        input.extend_from_slice(&[1, byte, 0, 0, 0]);
    }
    let path = dir.join(format!("seed-line-{length}"));
    fs::write(&path, input).unwrap();
    path
}

#[test]
fn a_uart_polling_image_reaches_its_parser_bug_through_inferred_models() {
    let root = TestDir::new("binary-rehost-uart");
    let work = root.join("work");
    // A two-byte field: the seed runs clean, one byte from the overflow.
    let seed = polled_field_line(&root, 2);
    let output = bhf()
        .args(["binary", "rehost"])
        .arg(fixture("uart.elf"))
        .arg("--work-dir")
        .arg(&work)
        .args([
            "--seed-file",
            seed.to_str().unwrap(),
            "--max-instructions",
            "200000",
            "--iterations",
            "3000",
        ])
        .output()
        .unwrap();
    let run = summary(&output);
    let loops = run["mmio_inference"]["polling_loops"].as_array().unwrap();
    assert_eq!(loops.len(), 2, "{run:#}");
    assert!(
        loops.iter().all(|found| found["model"] == "bitextract"),
        "{run:#}"
    );
    let findings = run["findings"].as_array().unwrap();
    assert!(!findings.is_empty(), "{run:#}");
    for id in findings {
        let dir = work.join("results/findings").join(id.as_str().unwrap());
        let finding: Value =
            serde_json::from_slice(&fs::read(dir.join("finding.json")).unwrap()).unwrap();
        assert_eq!(finding["classification"], "bad_pc", "{finding:#}");
        let models = finding["rehost"]["setup"]["mmio"]["models"]
            .as_array()
            .unwrap();
        assert!(
            models
                .iter()
                .all(|model| model["model"] == "bitextract" && model["inferred"] == true),
            "{finding:#}"
        );
        let replay = bhf().arg("replay").arg(&dir).output().unwrap();
        assert_eq!(replay.status.code(), Some(0), "{}", text(&replay));
    }
    // With inference off the same campaign never gets past the polls.
    let off = bhf()
        .args(["binary", "rehost"])
        .arg(fixture("uart.elf"))
        .arg("--work-dir")
        .arg(root.join("off"))
        .args([
            "--no-mmio-inference",
            "--seed-file",
            polled_field_line(&root, 16).to_str().unwrap(),
            "--max-instructions",
            "200000",
            "--iterations",
            "1",
        ])
        .output()
        .unwrap();
    let off = summary(&off);
    assert_eq!(off["mmio_inference"], Value::Null);
    assert_eq!(off["findings"], serde_json::json!([]), "{off:#}");
}

#[test]
fn a_data_register_dispatch_loop_keeps_its_input_and_reaches_its_bug_with_inference_on() {
    // `dispatch.c` reads each command byte from a data register through a
    // getter, so the read repeats like a status poll; 0x01 arms it and 'X'
    // once armed three times stores through a wild pointer.
    let root = TestDir::new("binary-rehost-dispatch");
    let work = root.join("work");
    let seed = root.join("seed-armed");
    fs::write(&seed, [1, 1, 1, b'Y']).unwrap();
    let output = bhf()
        .args(["binary", "rehost"])
        .arg(fixture("dispatch.elf"))
        .arg("--work-dir")
        .arg(&work)
        .args([
            "--seed-file",
            seed.to_str().unwrap(),
            "--max-instructions",
            "200000",
            "--iterations",
            "3000",
        ])
        .output()
        .unwrap();
    let run = summary(&output);
    let loops = run["mmio_inference"]["polling_loops"].as_array().unwrap();
    assert_eq!(loops.len(), 1, "{run:#}");
    assert_eq!(loops[0]["address"], "0x40013004", "{run:#}");
    assert_eq!(loops[0]["model"], Value::Null, "{run:#}");
    assert_eq!(loops[0]["not_a_poll"]["reason"], "other_bits", "{run:#}");
    assert_eq!(run["setup"]["mmio"]["models"], serde_json::json!([]));
    let findings = run["findings"].as_array().unwrap();
    assert!(!findings.is_empty(), "{run:#}");
    for id in findings {
        let dir = work.join("results/findings").join(id.as_str().unwrap());
        let finding: Value =
            serde_json::from_slice(&fs::read(dir.join("finding.json")).unwrap()).unwrap();
        assert_eq!(
            finding["rehost"]["fault"]["address"], "0x60000000",
            "{finding:#}"
        );
        let replay = bhf().arg("replay").arg(&dir).output().unwrap();
        assert_eq!(replay.status.code(), Some(0), "{}", text(&replay));
    }
}
