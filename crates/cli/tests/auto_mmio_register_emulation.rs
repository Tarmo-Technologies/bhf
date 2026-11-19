// SPDX-License-Identifier: Apache-2.0

//! A bug gated on a device register's value is found on the host (#341).
//!
//! A UART frame handler reads its status register through a macro at a fixed
//! address and, only in a framing-error state (`(UART_SR & 0xff) == 0x5a`),
//! forgets to clamp the copy into its 8-byte frame. Unmapped, the register
//! read faulted and the overflow behind it was never reached. The harness now
//! maps the UART's page and refills it from each input, so the fuzzer
//! chooses the register's value, the overflow is found, and the finding's
//! `hardware_peripherals` fidelity says the registers were emulated.
//!
//! A poison pointer is no device: list.h's `LIST_POISON1` is a plain
//! `(void *)0x00100100`, and a use after `list_del` that reads through it
//! still faults with emulation on.
//!
//! A window the build cannot map claims nothing: ASan reserves the Cortex-M
//! system control space (0xE000E000) as its shadow gap on x86-64, so a read
//! of `SCB_CPUID` there faults as before and its findings do not say the
//! register was emulated.
#![cfg(target_os = "linux")]

use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

const UART_H: &str = "#include <stdint.h>\n\
                      #define PERIPH_BASE 0x40000000UL\n\
                      #define UART1_BASE (PERIPH_BASE + 0x11000)\n\
                      #define UART_SR (*(volatile uint32_t *)(UART1_BASE + 0x00))\n\
                      #define UART_DR (*(volatile uint32_t *)(UART1_BASE + 0x04))\n";

const UART_C: &str = "#include <stddef.h>\n#include <string.h>\n#include \"uart.h\"\n\n\
                      int uart_handle_frame(const unsigned char *buf, size_t len) {\n  \
                      unsigned char frame[8];\n  \
                      size_t n = len < sizeof frame ? len : sizeof frame;\n  \
                      if ((UART_SR & 0xffu) == 0x5au) {\n    \
                      /* framing-error recovery copies the whole frame */\n    \
                      n = len;\n  }\n  \
                      memcpy(frame, buf, n);\n  \
                      UART_DR = frame[0];\n  \
                      return (int)n;\n}\n";

#[test]
fn a_bug_gated_on_a_device_register_is_found_with_the_register_emulated() {
    if Command::new("cc").arg("--version").output().is_err() {
        eprintln!("skipping: no C compiler on PATH");
        return;
    }
    let root = TestDir::new("mmio-register-emulation");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("uart.h"), UART_H).unwrap();
    std::fs::write(src.join("uart.c"), UART_C).unwrap();
    let work = root.join("work");
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["auto", "--work-dir", work.to_str().unwrap()])
        .args(["--jobs", "1", "--per-target-time", "20"])
        .arg(&src)
        .output()
        .expect("run bhf auto");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let doc: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work.join("results/findings.json"))
            .unwrap_or_else(|e| panic!("findings.json: {e}\n{stderr}")),
    )
    .unwrap();
    let findings: Vec<&serde_json::Value> = doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| finding["location"]["function"] == "uart_handle_frame")
        .collect();
    let overflow = findings
        .iter()
        .find(|finding| {
            finding.to_string().contains("stack-buffer-overflow")
                || finding["cwe"]
                    .as_str()
                    .is_some_and(|cwe| cwe.contains("121"))
        })
        .unwrap_or_else(|| panic!("the register-gated overflow is found:\n{doc:#}\n{stderr}"));
    let id = overflow["id"].as_str().unwrap();
    let raw: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work.join("results/findings").join(id).join("finding.json")).unwrap(),
    )
    .unwrap();
    assert!(
        raw.get("environment_origin").is_none(),
        "the overflow is the target's, not the missing device's: {raw:#}"
    );
    let peripherals = &raw["fidelity"]["hardware_peripherals"];
    let reason = peripherals["reason"].as_str().unwrap_or_default();
    assert_eq!(peripherals["status"], "not_exercised", "{raw:#}");
    assert!(
        reason.starts_with("emulated: ") && reason.contains("0x40011000 (UART_SR)"),
        "{raw:#}"
    );
    // No finding blames the register read itself.
    for finding in &findings {
        assert!(
            !finding
                .to_string()
                .contains("SEGV on unknown address 0x000040011"),
            "{finding:#}"
        );
    }
}

const SCB_C: &str = "#include <stddef.h>\n#include <stdint.h>\n\
                     #define SCB_CPUID (*(volatile uint32_t *)(0xE000ED00UL))\n\n\
                     int cpu_variant(const unsigned char *buf, size_t len) {\n  \
                     (void)buf;\n  (void)len;\n  \
                     return (int)((SCB_CPUID >> 20) & 0xfu);\n}\n";

#[cfg(target_arch = "x86_64")]
#[test]
fn a_window_the_sanitizer_layout_reserves_claims_no_emulation() {
    if Command::new("cc").arg("--version").output().is_err() {
        eprintln!("skipping: no C compiler on PATH");
        return;
    }
    let root = TestDir::new("mmio-register-unmappable");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("scb.c"), SCB_C).unwrap();
    let work = root.join("work");
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["auto", "--work-dir", work.to_str().unwrap()])
        .args(["--jobs", "1", "--per-target-time", "5"])
        .arg(&src)
        .output()
        .expect("run bhf auto");
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The harness was generated to map the SCB page, and its ASan build
    // reported it could not.
    let harness = std::fs::read_dir(work.join("harnesses"))
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .find(|dir| dir.join("mmio-windows.txt").is_file())
        .unwrap_or_else(|| panic!("a harness planned the SCB window:\n{stderr}"));
    let planned = std::fs::read_to_string(harness.join("mmio-windows.txt")).unwrap();
    assert_eq!(planned, "0xe000e000 0x1000 SCB_CPUID\n");
    assert!(
        !harness.join("mmio-mapped.txt").exists(),
        "nothing was mapped: {:?}",
        std::fs::read_to_string(harness.join("mmio-mapped.txt"))
    );
    let doc: serde_json::Value = serde_json::from_slice(
        &std::fs::read(work.join("results/findings.json"))
            .unwrap_or_else(|e| panic!("findings.json: {e}\n{stderr}")),
    )
    .unwrap();
    let findings: Vec<&serde_json::Value> = doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| finding["location"]["function"] == "cpu_variant")
        .collect();
    assert!(
        !findings.is_empty(),
        "the unmapped read faults:\n{doc:#}\n{stderr}"
    );
    for finding in findings {
        let id = finding["id"].as_str().unwrap();
        let raw: serde_json::Value = serde_json::from_slice(
            &std::fs::read(work.join("results/findings").join(id).join("finding.json")).unwrap(),
        )
        .unwrap();
        let reason = raw["fidelity"]["hardware_peripherals"]["reason"]
            .as_str()
            .unwrap_or_default();
        assert!(!reason.contains("emulated"), "{raw:#}");
    }
}

const LIST_C: &str = "#include <stddef.h>\n\
                      #define LIST_POISON1 ((void *) 0x00100100)\n\
                      #define LIST_POISON2 ((void *) 0x00200200)\n\
                      struct node { struct node *next, *prev; int v; };\n\
                      static void list_del(struct node *n) {\n  \
                      n->next = LIST_POISON1;\n  n->prev = LIST_POISON2;\n}\n\
                      int walk(const unsigned char *buf, size_t len) {\n  \
                      struct node tail = { NULL, NULL, 7 };\n  \
                      struct node n = { &tail, NULL, 1 };\n  \
                      if (len > 0 && buf[0] == 'D') list_del(&n);\n  \
                      return n.next->v;\n}\n";

#[test]
fn a_poison_pointer_dereference_still_faults_with_emulation_on() {
    if Command::new("cc").arg("--version").output().is_err() {
        eprintln!("skipping: no C compiler on PATH");
        return;
    }
    let root = TestDir::new("mmio-poison");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    let source = src.join("list.c");
    std::fs::write(&source, LIST_C).unwrap();
    let work = root.join("work");
    let generated = work.join("generated_harnesses");
    let bhf = |args: &[&std::ffi::OsStr]| {
        let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
            .args(args)
            .env_remove("BHF_NO_MMIO_EMULATION")
            .output()
            .expect("run bhf");
        assert!(
            out.status.success(),
            "bhf {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    bhf(&[
        "generate-harness".as_ref(),
        "--target".as_ref(),
        "walk".as_ref(),
        "--id".as_ref(),
        "H-WALK".as_ref(),
        "--output".as_ref(),
        generated.as_os_str(),
        source.as_os_str(),
    ]);
    let harness = generated.join("H-WALK");
    assert!(
        !harness.join("mmio-windows.txt").exists(),
        "no window for a poison value"
    );
    bhf(&[
        "build".as_ref(),
        work.as_os_str(),
        "--harness".as_ref(),
        "H-WALK".as_ref(),
    ]);
    let input = root.join("d.bin");
    std::fs::write(&input, b"D").unwrap();
    let run = Command::new(harness.join("main"))
        .arg(&input)
        .env_remove("LD_PRELOAD")
        .output()
        .expect("run the harness");
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(!run.status.success(), "the poison read faults: {stderr}");
    assert!(
        stderr.contains("SEGV on unknown address 0x000000100"),
        "{stderr}"
    );
}
