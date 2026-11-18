// SPDX-License-Identifier: Apache-2.0
//! Original Ada 83 (MIL-STD-1815A) is not rejected by the parser. A
//! `pragma Ada_83;` unit parses (lexed with the reduced 83 keyword set), is
//! tagged with the Ada 83 dialect, and `bhf auto` fuzzes it from an Ada 2012
//! harness (#284): its instrumentation names the probe through the
//! library-level `AdaFuzz_Probe83`, since Ada 83 has no child units.

use cli::auto::candidate::Lang;
use cli::auto::discovery::discover;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn tmp(tag: &str) -> TestDir {
    TestDir::new(tag)
}

#[test]
fn ada83_unit_is_parsed_and_discovered_with_ada83_dialect() {
    let dir = tmp("ada83-disc");
    // A legacy Ada 83 package spec. `pragma Ada_83;` used to be a hard parse
    // error; now it parses and the function is discovered.
    fs::write(
        dir.join("legacy_parser.ads"),
        "pragma Ada_83;\n\
         package Legacy_Parser is\n\
         \x20  function Parse (Input : String) return Integer;\n\
         end Legacy_Parser;\n",
    )
    .unwrap();

    let candidates = discover(&dir).expect("discover Ada 83 tree");
    let ada = candidates
        .iter()
        .find(|c| c.lang == Lang::Ada && c.name.eq_ignore_ascii_case("Parse"))
        .expect("the Ada 83 function must be discovered (not rejected)");
    assert_eq!(
        ada.dialect.map(|d| d.as_str()),
        Some("ada83"),
        "discovered Ada 83 target must carry the Ada 83 dialect"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn ada83_uses_post83_reserved_word_as_identifier() {
    // In Ada 83 `interface` / `protected` are ordinary identifiers (they only
    // became reserved in Ada 95+). The reduced-keyword lexer (Ada83 is the
    // smallest dialect) must accept them, so such a unit still parses + discovers.
    let dir = tmp("ada83-kw");
    fs::write(
        dir.join("driver.ads"),
        "pragma Ada_83;\n\
         package Driver is\n\
         \x20  function Interface_Id (Protected_Flag : Integer) return Integer;\n\
         end Driver;\n",
    )
    .unwrap();

    let candidates = discover(&dir).expect("discover Ada 83 tree");
    assert!(
        candidates
            .iter()
            .any(|c| c.lang == Lang::Ada && c.dialect.map(|d| d.as_str()) == Some("ada83")),
        "Ada 83 unit using a post-83 word as an identifier must still parse + discover"
    );

    let _ = fs::remove_dir_all(&dir);
}

fn have_ada_toolchain() -> bool {
    let present = which::which("gnatmake").is_ok() && which::which("gprbuild").is_ok();
    support::require_tool(present, "ada toolchain")
}

/// #284: an Ada 83 unit builds with an Ada 2012 harness and its planted
/// Constraint_Error is found. Ada 83 was report-only, and the instrumented
/// unit's `with AdaFuzz.Probe;` did not compile under `pragma Ada_83`.
#[test]
fn auto_fuzzes_an_ada83_unit_and_finds_its_constraint_error() {
    if !have_ada_toolchain() {
        eprintln!("SKIP: gnatmake/gprbuild not installed — Ada lane unavailable");
        return;
    }
    let src = tmp("ada83-auto-src");
    fs::write(
        src.join("legacy_parser.ads"),
        "pragma Ada_83;\n\
         package Legacy_Parser is\n\
         \x20  function Parse (Input : String) return Integer;\n\
         end Legacy_Parser;\n",
    )
    .unwrap();
    fs::write(
        src.join("legacy_parser.adb"),
        "pragma Ada_83;\n\
         package body Legacy_Parser is\n\
         \x20  function Parse (Input : String) return Integer is\n\
         \x20     type Slots is array (1 .. 4) of Integer;\n\
         \x20     Table : Slots := (others => 0);\n\
         \x20     Index : Integer;\n\
         \x20  begin\n\
         \x20     if Input'Length < 2 then\n\
         \x20        return 0;\n\
         \x20     end if;\n\
         \x20     Index := Character'Pos (Input (Input'First + 1));\n\
         \x20     return Table (Index);\n\
         \x20  end Parse;\n\
         end Legacy_Parser;\n",
    )
    .unwrap();
    let work = tmp("ada83-auto-work");
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
    let instrumented = fs::read_to_string(work.join("src_instrumented/legacy_parser.adb")).unwrap();
    assert!(
        instrumented.contains("with AdaFuzz_Probe83;"),
        "{instrumented}"
    );
    let findings: serde_json::Value =
        serde_json::from_slice(&fs::read(work.join("results/findings.json")).unwrap()).unwrap();
    let found = findings["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| {
            let id = finding["id"].as_str().unwrap_or("");
            fs::read_to_string(work.join("results/findings").join(id).join("finding.json"))
                .ok()
                .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
                .is_some_and(|record| {
                    record["exception"]["name"] == "CONSTRAINT_ERROR"
                        && record["exception"]["source_line"] == 12
                })
        });
    assert!(found, "no Constraint_Error at line 12: {findings:#}\n{log}");
}
