// SPDX-License-Identifier: Apache-2.0

//! A host SEGV on a fixed device-register address is the missing device, not
//! an out-of-bounds read the input caused. A UART driver polled its status
//! register through a macro and was reported as a HIGH attacker-reachable
//! BHF-223 read, with `hardware_peripherals: not_applicable`. It is now an
//! environment result (`lab_only`, low) with the peripheral `not_exercised`;
//! a genuine out-of-bounds read beside it is still a HIGH finding.
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

const UART_C: &str = "#include <stddef.h>\n#include \"uart.h\"\n\n\
                      int uart_send(const unsigned char *data, size_t len) {\n  \
                      for (size_t i = 0; i < len; i++) {\n    \
                      while (!(UART_SR & 0x80)) {}\n    UART_DR = data[i];\n  }\n  \
                      return (int)len;\n}\n\n\
                      int table_lookup(const unsigned char *data, size_t len) {\n  \
                      static const int table[4] = {1, 2, 3, 4};\n  \
                      if (len < 1) return 0;\n  return table[data[0]];\n}\n";

#[test]
fn a_segv_on_a_device_register_is_an_environment_result() {
    if Command::new("cc").arg("--version").output().is_err() {
        eprintln!("skipping: no C compiler on PATH");
        return;
    }
    let root = TestDir::new("mmio-register-fault");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("uart.h"), UART_H).unwrap();
    std::fs::write(src.join("uart.c"), UART_C).unwrap();
    let work = root.join("work");
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["auto", "--work-dir", work.to_str().unwrap()])
        .args(["--jobs", "1", "--per-target-time", "5"])
        .arg(&src)
        .output()
        .expect("run bhf auto");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("results/findings.json")).unwrap())
            .unwrap();
    let findings = doc["findings"].as_array().unwrap();
    let in_function = |function: &str| {
        findings
            .iter()
            .filter(|finding| finding["location"]["function"] == function)
            .collect::<Vec<_>>()
    };

    let device = in_function("uart_send");
    assert!(
        !device.is_empty(),
        "the register read is reported:\n{doc:#}\n{stderr}"
    );
    for finding in &device {
        assert_ne!(finding["severity"], "high", "{finding:#}");
        assert_ne!(finding["severity"], "critical", "{finding:#}");
        assert_eq!(finding["verdict"], "lab_only", "{finding:#}");
        let id = finding["id"].as_str().unwrap();
        let raw: serde_json::Value = serde_json::from_slice(
            &std::fs::read(work.join("results/findings").join(id).join("finding.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            raw["environment_origin"]["kind"], "mmio_register",
            "{raw:#}"
        );
        assert_eq!(raw["environment_origin"]["register"], "UART_SR");
        let peripherals = &raw["fidelity"]["hardware_peripherals"];
        assert_eq!(peripherals["status"], "not_exercised", "{raw:#}");
        assert!(peripherals["reason"]
            .as_str()
            .unwrap()
            .contains("0x40011000"));
    }

    // The genuine out-of-bounds read is still a high finding.
    let lookup = in_function("table_lookup");
    assert!(
        lookup.iter().any(|finding| finding["severity"] == "high"),
        "{doc:#}\n{stderr}"
    );
}
