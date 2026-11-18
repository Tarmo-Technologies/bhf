// SPDX-License-Identifier: Apache-2.0
//
// #356: a tree that vendors a GNAT predefined unit (a zero-footprint runtime
// ships `ada.ads`, `system.ads`, `s-*.ads`) builds against the host runtime.
// Staging the vendored `ada.ads` into src_instrumented shadowed the
// runtime's own, and the build stopped (`"s-stalib.adb" must be compiled`,
// `predefined unit depends on itself`). The vendored unit is now left out
// and the skip is logged.

use std::path::{Path, PathBuf};
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn have_ada_toolchain() -> bool {
    let present = which::which("gnatmake").is_ok() && which::which("gprbuild").is_ok();
    support::require_tool(present, "ada toolchain")
}

fn write(dir: &Path, name: &str, text: &str) {
    let path = dir.join(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

#[test]
fn a_vendored_predefined_unit_does_not_shadow_the_runtime() {
    if !have_ada_toolchain() {
        eprintln!("SKIP: gnatmake/gprbuild not installed — Ada lane unavailable");
        return;
    }
    let src = TestDir::new("ada-vendored-rts");
    // An older runtime's `Ada`: the host's adds No_Elaboration_Code_All. The
    // target withs `Ada.Strings.Fixed`, so `Ada` is in its closure.
    write(
        src.path(),
        "rts/adainclude/ada.ads",
        "package Ada is\n   pragma Pure;\nend Ada;\n",
    );
    write(
        src.path(),
        "src/parser.ads",
        "package Parser is\n   function Parse (Input : String) return Integer;\nend Parser;\n",
    );
    write(
        src.path(),
        "src/parser.adb",
        "with Ada.Strings.Fixed;\n\
         package body Parser is\n\
         \x20  function Parse (Input : String) return Integer is\n\
         \x20     type Slots is array (1 .. 4) of Integer;\n\
         \x20     Table : constant Slots := (others => 0);\n\
         \x20  begin\n\
         \x20     if Input'Length < 2 then\n\
         \x20        return 0;\n\
         \x20     end if;\n\
         \x20     return Table\n\
         \x20       (Ada.Strings.Fixed.Index (Input, \"!\") + Character'Pos (Input (Input'First)));\n\
         \x20  end Parse;\n\
         end Parser;\n",
    );
    let work = TestDir::new("ada-vendored-rts-work");
    let out = Command::new(PathBuf::from(env!("CARGO_BIN_EXE_bhf")))
        .args(["auto", src.to_str().unwrap(), "--target", "Parse"])
        .args([
            "--per-target-time",
            "10",
            "--max-targets",
            "1",
            "--jobs",
            "1",
        ])
        .args(["--work-dir", work.to_str().unwrap()])
        .output()
        .expect("run bhf auto");
    let log = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(log.contains("1 built+fuzzed"), "{log}");
    assert!(
        log.contains("it is the GNAT predefined unit ada"),
        "the skipped unit is logged: {log}"
    );
    assert!(!work.join("src_instrumented/ada.ads").exists());
    let findings: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("results/findings.json")).unwrap())
            .unwrap();
    assert!(
        findings["findings"]
            .as_array()
            .is_some_and(|all| !all.is_empty()),
        "the planted index error is found: {findings:#}\n{log}"
    );
}
