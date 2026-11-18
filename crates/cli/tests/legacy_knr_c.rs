// SPDX-License-Identifier: Apache-2.0
//! K&R / pre-ANSI C is discovered via the tolerant extractor (the modern
//! tree-sitter-c grammar cannot represent old-style untyped parameter lists)
//! and tagged with the K&R dialect. `bhf auto` fuzzes it through the ANSI
//! prototype synthesized from the declaration block (#283); the report-only
//! path still emits CWE-tagged static findings for it.

use cli::auto::candidate::Lang;
use cli::auto::discovery::discover;
use cli::auto::report_only::emit_report_only;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn tmp(tag: &str) -> TestDir {
    TestDir::new(tag)
}

const KNR_SRC: &str = "\
/* legacy K&R / pre-ANSI C */
int copy_into(dst, src)
    char *dst;
    char *src;
{
    strcpy(dst, src);   /* BHF-401: unbounded copy */
    return 0;
}
";

#[test]
fn knr_function_is_discovered_with_knr_dialect() {
    let dir = tmp("knr-disc");
    fs::write(dir.join("legacy.c"), KNR_SRC).unwrap();

    let candidates = discover(&dir).expect("discover K&R tree");
    let knr = candidates
        .iter()
        .find(|c| c.lang == Lang::C && c.name == "copy_into")
        .expect("the K&R function must be discovered by the tolerant extractor");
    assert_eq!(
        knr.dialect.map(|d| d.as_str()),
        Some("c_knr"),
        "discovered K&R target must carry the K&R dialect"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn knr_target_report_only_emits_cwe_finding() {
    let dir = tmp("knr-ro");
    fs::write(dir.join("legacy.c"), KNR_SRC).unwrap();

    let candidates = discover(&dir).expect("discover K&R tree");
    let knr = candidates
        .iter()
        .find(|c| c.lang == Lang::C && c.name == "copy_into")
        .expect("K&R function discovered");

    let work = tmp("knr-work");
    let outcome = emit_report_only(knr, "K&R C (test)".to_owned(), &work);
    let count = match &outcome {
        cli::auto::attempt::Outcome::ReportOnly {
            static_findings, ..
        } => *static_findings,
        other => panic!("expected ReportOnly, got {other:?}"),
    };
    // BHF-401 (strcpy) is a substring rule, so it fires even on K&R source.
    assert!(count >= 1, "expected >=1 static finding on the K&R source");

    let mut saw_cwe = false;
    for entry in fs::read_dir(work.join("results").join("findings")).unwrap() {
        let fj = entry.unwrap().path().join("finding.json");
        if !fj.exists() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_slice(&fs::read(&fj).unwrap()).unwrap();
        let cwe = v["actionability"]["cwe"].as_array().unwrap();
        assert!(!cwe.is_empty(), "report-only K&R finding must carry a CWE");
        saw_cwe = true;
    }
    assert!(saw_cwe, "expected a finding.json on disk");

    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&work);
}

/// #283: `bhf auto` builds a K&R definition's harness from the prototype its
/// declaration block gives, and finds the overflow behind it. The dialect was
/// report-only, and the modern parse called the function with no arguments.
#[test]
fn auto_fuzzes_a_knr_definition_and_finds_its_overflow() {
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_bhf"));
    let src = tmp("knr-auto-src");
    fs::write(
        src.join("rec.c"),
        "#include <string.h>\n\n\
         int parse_rec(buf, len)\n\
         \x20   unsigned char *buf;\n\
         \x20   int len;\n\
         {\n\
         \x20   char tmp[8];\n\
         \x20   if (len < 2 || buf[0] != 'R')\n\
         \x20       return -1;\n\
         \x20   memcpy(tmp, buf, len);\n\
         \x20   return tmp[1];\n\
         }\n",
    )
    .unwrap();
    let work = tmp("knr-auto-work");
    let out = Command::new(&bin)
        .args(["auto", src.to_str().unwrap(), "--target", "parse_rec"])
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
    let main = fs::read_dir(work.join("harnesses"))
        .unwrap()
        .map(|entry| entry.unwrap().path().join("main.c"))
        .find(|path| path.exists())
        .unwrap_or_else(|| panic!("no harness main.c: {log}"));
    let main = fs::read_to_string(main).unwrap();
    assert!(
        main.contains("parse_rec(unsigned char *, int);"),
        "the harness declares the synthesized prototype: {main}"
    );
    let findings: serde_json::Value =
        serde_json::from_slice(&fs::read(work.join("results/findings.json")).unwrap()).unwrap();
    let overflow = findings["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| {
            finding["title"]
                .as_str()
                .unwrap_or("")
                .contains("parse_rec")
        });
    let overflow = overflow.unwrap_or_else(|| panic!("no parse_rec finding: {findings:#}\n{log}"));
    assert_eq!(overflow["cwe"], serde_json::json!([121]), "{overflow:#}");
}
