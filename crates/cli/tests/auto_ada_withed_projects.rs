// SPDX-License-Identifier: Apache-2.0
//
// #287: an Ada target whose project `with`s a sibling library project builds.
// bhf staged instrumented copies of the library's units beside the library
// project that owns them, and gprbuild refused the second owner
// (`unit "util.slots" cannot belong to several projects`). The library's units
// are now left to it, and `Source_Dirs` spelled `"src/" & project'Name` is
// read as gprbuild reads it.

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

/// The two-project tree: `core.gpr` `with`s the library project `util.gpr`.
/// `core.gpr` sorts first, so it governs the target, and the build extends it.
fn two_project_tree(root: &Path) {
    write(
        root,
        "core.gpr",
        "with \"util.gpr\";\n\
         project Core is\n\
         \x20  for Source_Dirs use (\"src/\" & project'Name);\n\
         \x20  for Object_Dir use \"obj/\" & project'Name;\n\
         end Core;\n",
    );
    write(
        root,
        "util.gpr",
        "library project Util is\n\
         \x20  for Library_Name use project'Name;\n\
         \x20  for Source_Dirs use (\"src/\" & project'Name);\n\
         \x20  for Library_Dir use \"lib/\" & project'Name;\n\
         \x20  for Object_Dir use \"obj/\" & project'Name;\n\
         end Util;\n",
    );
    write(root, "src/util/util.ads", "package Util is\nend Util;\n");
    write(
        root,
        "src/util/util-slots.ads",
        "package Util.Slots is\n   function Slot (C : Character) return Integer;\nend Util.Slots;\n",
    );
    write(
        root,
        "src/util/util-slots.adb",
        "package body Util.Slots is\n\
         \x20  function Slot (C : Character) return Integer is\n\
         \x20  begin\n\
         \x20     return Character'Pos (C) mod 8;\n\
         \x20  end Slot;\n\
         end Util.Slots;\n",
    );
    write(
        root,
        "src/core/core_parser.ads",
        "package Core_Parser is\n   function Parse (Input : String) return Integer;\nend Core_Parser;\n",
    );
    write(
        root,
        "src/core/core_parser.adb",
        "with Util.Slots;\n\
         package body Core_Parser is\n\
         \x20  function Parse (Input : String) return Integer is\n\
         \x20     type Slots is array (1 .. 4) of Integer;\n\
         \x20     Table : constant Slots := (others => 0);\n\
         \x20  begin\n\
         \x20     if Input'Length < 2 then\n\
         \x20        return 0;\n\
         \x20     end if;\n\
         \x20     return Table (Util.Slots.Slot (Input (Input'First)));\n\
         \x20  end Parse;\n\
         end Core_Parser;\n",
    );
}

#[test]
fn a_target_beside_a_withed_library_project_builds_and_fuzzes() {
    if !have_ada_toolchain() {
        eprintln!("SKIP: gnatmake/gprbuild not installed — Ada lane unavailable");
        return;
    }
    let src = TestDir::new("ada-two-projects");
    two_project_tree(src.path());
    let work = TestDir::new("ada-two-projects-work");
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
        log.contains("to the projects core.gpr depends on"),
        "the library's units are left to it: {log}"
    );
    assert!(!work.join("src_instrumented/util-slots.adb").exists());
    assert!(work.join("src_instrumented/core_parser.adb").exists());
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

/// `parser.gpr` `with`s the library project `codec.gpr`, whose directory sorts
/// first, so a run attempts the library's `Codec.Headers.Parse` before
/// `Parser_Main.Parse`, which `with`s `Codec.Slots` and not `Codec.Headers`.
fn library_first_tree(root: &Path) {
    write(
        root,
        "parser.gpr",
        "with \"codec.gpr\";\n\
         project Parser is\n\
         \x20  for Source_Dirs use (\"src/\" & project'Name);\n\
         \x20  for Object_Dir use \"obj/\" & project'Name;\n\
         end Parser;\n",
    );
    write(
        root,
        "codec.gpr",
        "library project Codec is\n\
         \x20  for Library_Name use project'Name;\n\
         \x20  for Source_Dirs use (\"src/\" & project'Name);\n\
         \x20  for Library_Dir use \"lib/\" & project'Name;\n\
         \x20  for Object_Dir use \"obj/\" & project'Name;\n\
         end Codec;\n",
    );
    write(
        root,
        "src/codec/codec.ads",
        "package Codec is\nend Codec;\n",
    );
    write(
        root,
        "src/codec/codec-slots.ads",
        "package Codec.Slots is\n   function Slot (C : Character) return Integer;\nend Codec.Slots;\n",
    );
    write(
        root,
        "src/codec/codec-slots.adb",
        "package body Codec.Slots is\n\
         \x20  function Slot (C : Character) return Integer is\n\
         \x20  begin\n\
         \x20     return Character'Pos (C) mod 8;\n\
         \x20  end Slot;\n\
         end Codec.Slots;\n",
    );
    write(
        root,
        "src/codec/codec-headers.ads",
        "package Codec.Headers is\n   function Parse (Input : String) return Integer;\nend Codec.Headers;\n",
    );
    write(
        root,
        "src/codec/codec-headers.adb",
        "package body Codec.Headers is\n\
         \x20  function Parse (Input : String) return Integer is\n\
         \x20  begin\n\
         \x20     return Input'Length / 2;\n\
         \x20  end Parse;\n\
         end Codec.Headers;\n",
    );
    write(
        root,
        "src/parser/parser_main.ads",
        "package Parser_Main is\n   function Parse (Input : String) return Integer;\nend Parser_Main;\n",
    );
    write(
        root,
        "src/parser/parser_main.adb",
        "with Codec.Slots;\n\
         package body Parser_Main is\n\
         \x20  function Parse (Input : String) return Integer is\n\
         \x20     type Slots is array (1 .. 4) of Integer;\n\
         \x20     Table : constant Slots := (others => 0);\n\
         \x20  begin\n\
         \x20     if Input'Length < 2 then\n\
         \x20        return 0;\n\
         \x20     end if;\n\
         \x20     return Table (Codec.Slots.Slot (Input (Input'First)));\n\
         \x20  end Parse;\n\
         end Parser_Main;\n",
    );
}

/// A copy an earlier target of the run staged of a library unit outside the
/// target's with-closure is dropped too: the staging is shared by the run's
/// targets and gprbuild reads every unit in it, so the copy of
/// `Codec.Headers` the library's own target staged would be a second owner of
/// it for `Parser_Main.Parse`, which never `with`s it.
#[test]
fn a_library_unit_an_earlier_target_staged_is_left_to_its_project() {
    if !have_ada_toolchain() {
        eprintln!("SKIP: gnatmake/gprbuild not installed — Ada lane unavailable");
        return;
    }
    let src = TestDir::new("ada-library-first");
    library_first_tree(src.path());
    let work = TestDir::new("ada-library-first-work");
    let out = Command::new(PathBuf::from(env!("CARGO_BIN_EXE_bhf")))
        .args(["auto", src.to_str().unwrap(), "--target", "Parse"])
        .args([
            "--per-target-time",
            "5",
            "--max-targets",
            "2",
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
    // The library's target goes first, or this would not test the stale copy.
    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
    let first_id = log
        .lines()
        .find(|line| line.contains("[   1/   2]"))
        .and_then(|line| line.split_whitespace().find(|word| word.starts_with("H-")))
        .unwrap_or_else(|| panic!("no first attempt: {log}"));
    let first_source = run["targets"]
        .as_array()
        .and_then(|targets| targets.iter().find(|t| t["harness_id"] == first_id))
        .and_then(|t| t["source"].as_str())
        .unwrap_or_default();
    assert!(
        first_source.ends_with("codec-headers.ads"),
        "{first_source}\n{log}"
    );
    // Before, the second build failed: `unit "codec.headers" cannot belong to
    // several projects`, the staged copy and the library's own.
    for target in run["targets"].as_array().unwrap() {
        assert_eq!(
            target["outcome"]["outcome"], "built_and_fuzzed",
            "{target:#}\n{log}"
        );
    }
    assert!(!work.join("src_instrumented/codec-headers.ads").exists());
    assert!(!work.join("src_instrumented/codec-headers.adb").exists());
}
