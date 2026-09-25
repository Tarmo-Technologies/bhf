// SPDX-License-Identifier: Apache-2.0

//! HDF-5 deliverable 2 (end-to-end): a generated harness for a polled-register
//! reader fabricates the peripheral read accessor and drives a fuzz-controlled
//! SEQUENCE of reads — each read returns the NEXT value from the fuzz input — so
//! a branch gated on the 3rd read value is reachable. This compiles the emitted
//! harness against a planted fixture and proves the branch fires for the input
//! that lines up the 3rd read, and does NOT fire for a benign input.
//!
//! Gated on clang (self-skips on a toolchain-less lane), per repo convention.

use std::path::PathBuf;
use std::process::Command;

use harness_gen::c_generate::{
    generate_c_direct_harness, CEnvironmentModel, CPeripheralParam, CPeripheralReader,
    GenerateCDirectArgs,
};

fn c_runtime_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime")
}

/// A polled-register reader: it reads a status register three times through the
/// BSP accessor `mmio_read32` (undefined here — the harness fabricates it) and
/// traps only when the THIRD read yields the magic word. Nothing an ordinary
/// single-value harness supplies could line up three successive reads.
const FIXTURE: &str = r#"
#include <stdint.h>
extern uint32_t mmio_read32(volatile uint32_t *reg);
static volatile uint32_t STATUS_REG;
int radar_status_poll(void) {
    uint32_t a = mmio_read32(&STATUS_REG);
    uint32_t b = mmio_read32(&STATUS_REG);
    uint32_t c = mmio_read32(&STATUS_REG); /* 3rd read */
    if (a == 0x11111111u && b == 0x22222222u && c == 0xDEADBEEFu) {
        __builtin_trap(); /* planted branch gated on the 3rd read */
    }
    return (int)(a ^ b ^ c);
}
"#;

#[test]
fn peripheral_harness_reaches_branch_gated_on_third_register_read() {
    if which::which("clang").is_err() {
        eprintln!("skipping auto_peripheral_sequence: clang not on PATH");
        return;
    }

    let tmp = tempfile::Builder::new()
        .prefix("bhf-hdf5-periph-")
        .tempdir()
        .expect("tempdir");
    let root = tmp.path();
    let fixture = root.join("radar.c");
    std::fs::write(&fixture, FIXTURE).unwrap();
    let out = root.join("harness");
    std::fs::create_dir_all(&out).unwrap();

    let args = GenerateCDirectArgs {
        harness_id: "H-HDF5-PERIPH".to_owned(),
        output_dir: out.clone(),
        source_path: fixture.clone(),
        target: c_parser::CFunction {
            name: "radar_status_poll".to_owned(),
            line: 1,
            return_type: "int".to_owned(),
            params: Vec::new(),
            ..Default::default()
        },
        params: Vec::new(),
        return_type: "int".to_owned(),
        target_includes: Vec::new(),
        target_includes_dirs: vec![root.to_path_buf()],
        target_sources: vec![fixture.clone()],
        compile_flags: Vec::new(),
        target_declared_in_header: false,
        c_runtime_include: c_runtime_dir(),
        type_defs: Vec::new(),
        result_cleanup: None,
        lifecycle: Vec::new(),
        drive_plan: None,
        decoder_limits: Default::default(),
        force: false,
        environment: Some(CEnvironmentModel {
            peripheral_readers: vec![CPeripheralReader {
                return_type: "uint32_t".to_owned(),
                name: "mmio_read32".to_owned(),
                params: vec![CPeripheralParam {
                    c_type: "volatile uint32_t *".to_owned(),
                    name: "reg".to_owned(),
                }],
            }],
            fuzz_driven_callbacks: false,
        }),
    };

    let result = generate_c_direct_harness(args).expect("generate peripheral harness");
    let main_src = std::fs::read_to_string(&result.main_c).unwrap();
    // Mandatory: the emitted source carries the fuzz-controlled read sequence.
    assert!(
        main_src.contains("uint32_t mmio_read32(volatile uint32_t * reg)")
            && main_src.contains("return (uint32_t)_bhf_env_next_u32();")
            && main_src.contains("_bhf_env_data[_bhf_env_index++]"),
        "emitted harness must fabricate the accessor and drive a fuzz sequence:\n{main_src}"
    );

    // Compile the emitted harness (its own default file-replay driver) + fixture.
    let bin = out.join("periph_harness");
    let compile = Command::new("clang")
        .args(["-fsanitize=address", "-O0", "-g", "-o"])
        .arg(&bin)
        .arg(result.main_c)
        .arg(&fixture)
        .arg("-I")
        .arg(c_runtime_dir())
        .output()
        .expect("spawn clang");
    assert!(
        compile.status.success(),
        "harness must compile:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&compile.stdout),
        String::from_utf8_lossy(&compile.stderr)
    );

    // Input that lines up the three successive reads: a=0x11111111, b=0x22222222,
    // c=0xDEADBEEF (each 4 bytes little-endian, in read order).
    let hit = root.join("hit.bin");
    std::fs::write(
        &hit,
        [
            0x11, 0x11, 0x11, 0x11, // 1st read -> 0x11111111
            0x22, 0x22, 0x22, 0x22, // 2nd read -> 0x22222222
            0xEF, 0xBE, 0xAD, 0xDE, // 3rd read -> 0xDEADBEEF (LE)
        ],
    )
    .unwrap();
    let hit_run = Command::new(&bin)
        .arg(&hit)
        .output()
        .expect("run harness (hit)");
    assert!(
        !hit_run.status.success(),
        "the 3rd-read-gated branch must fire (trap) for the aligned input; \
         exit={:?}\nstderr:\n{}",
        hit_run.status.code(),
        String::from_utf8_lossy(&hit_run.stderr)
    );

    // A benign input must NOT trip the gate — proving the crash is driven by the
    // read SEQUENCE, not an unconditional fault in the harness.
    let miss = root.join("miss.bin");
    std::fs::write(&miss, [0u8; 12]).unwrap();
    let miss_run = Command::new(&bin)
        .arg(&miss)
        .output()
        .expect("run harness (miss)");
    assert!(
        miss_run.status.success(),
        "a benign input must not trip the gate; exit={:?}\nstderr:\n{}",
        miss_run.status.code(),
        String::from_utf8_lossy(&miss_run.stderr)
    );
}
