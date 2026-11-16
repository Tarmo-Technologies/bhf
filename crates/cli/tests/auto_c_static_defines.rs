// SPDX-License-Identifier: Apache-2.0
#![cfg(target_os = "linux")]

//! A C feature its build turns on with a define, found by a default `bhf auto`
//! with no compile database. The C lane applied no CMake or Makefile define but
//! a few header-capability macros, so code behind `#ifdef ENABLE_TLV` was
//! compiled out and its bug never found. A non-executing scan of the build
//! file now supplies the define, and the harness records it as statically
//! recovered.

use std::fs;
use std::path::Path;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// A stack overflow only a build with ENABLE_TLV defined compiles.
const TLV_C: &str = "#include <stddef.h>\n#include <string.h>\n\
                     int tlv_parse(const unsigned char *d, size_t n) {\n\
                     #ifdef ENABLE_TLV\n\
                         char buf[4];\n\
                         if (n > 1 && d[0] == 'T') { memcpy(buf, d, n); return buf[0]; }\n\
                     #endif\n\
                         return 0;\n\
                     }\n";

fn auto_finds_the_planted_bug(build_file: &str, contents: &str, provenance: &str) {
    if !support::libfuzzer_toolchain_available("c-static-defines") {
        eprintln!("skipping: clang+libfuzzer toolchain unavailable");
        return;
    }
    let root = TestDir::new(&format!("auto-c-defines-{provenance}"));
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("tlv.c"), TLV_C).unwrap();
    fs::write(src.join(build_file), contents).unwrap();
    let work = root.join("work");
    let out = support::bhf_cargo_command()
        .current_dir(root.path())
        .args(["auto", "--work-dir", work.to_str().unwrap()])
        .args(["--per-target-time", "10", src.to_str().unwrap()])
        .output()
        .expect("run bhf auto");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let findings: Vec<serde_json::Value> = fs::read_dir(work.join("results/findings"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| fs::read(entry.path().join("finding.json")).ok())
        .filter_map(|bytes| serde_json::from_slice(&bytes).ok())
        .collect();
    assert!(
        findings
            .iter()
            .any(|raw| raw["exception"]["name"] == "ASAN_STACK_BUFFER_OVERFLOW"),
        "{build_file}: the bug behind ENABLE_TLV is not found: {findings:#?}\n{stderr}"
    );
    let makefile = harness_makefile(&work);
    assert!(
        makefile.contains(&format!("BUILD_CONTEXT_PROVENANCE = {provenance}")),
        "{makefile}"
    );
    assert!(makefile.contains("-DENABLE_TLV"), "{makefile}");
}

/// The generated Makefile of the one C harness under `work`.
fn harness_makefile(work: &Path) -> String {
    fs::read_dir(work.join("harnesses"))
        .unwrap()
        .flatten()
        .map(|entry| entry.path().join("Makefile"))
        .find(|path| path.is_file())
        .map(|path| fs::read_to_string(path).unwrap())
        .expect("a harness Makefile")
}

#[test]
fn a_cmake_compile_definition_reaches_the_c_harness() {
    auto_finds_the_planted_bug(
        "CMakeLists.txt",
        "cmake_minimum_required(VERSION 3.10)\nproject(tlv C)\n\
         add_compile_definitions(ENABLE_TLV=1)\nadd_library(tlv tlv.c)\n",
        "cmake_statically_recovered",
    );
}

#[test]
fn a_makefile_define_reaches_the_c_harness() {
    auto_finds_the_planted_bug(
        "Makefile",
        "CFLAGS = -O2 -DENABLE_TLV\nlibtlv.a: tlv.o\n\tar rcs $@ $^\n",
        "makefile_statically_recovered",
    );
}
