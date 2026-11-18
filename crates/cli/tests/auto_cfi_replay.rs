// SPDX-License-Identifier: Apache-2.0

//! The control-flow integrity replay lane (#297): `bhf auto --sanitizers
//! asan,ubsan,cfi` fuzzes with ASan and UBSan, then replays the corpus through
//! a `-fsanitize=cfi` build (`make cfi`). A cast of a `Square` to a `Circle`
//! reads valid memory, so ASan and UBSan let it pass; the CFI build reports
//! it, and the finding replays. run.json and run.md list the bug classes no
//! lane of the run could observe.

#![cfg(unix)]

use std::path::Path;
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// Whether clang links a CFI program here: it needs an LTO linker (lld or
/// the LLVM gold plugin).
fn cfi_links(dir: &Path) -> bool {
    let source = dir.join("probe.cpp");
    std::fs::write(
        &source,
        "struct A { virtual ~A() {} };\nint main() { A a; return 0; }\n",
    )
    .unwrap();
    Command::new("clang++")
        .args(["-flto", "-fvisibility=hidden", "-fsanitize=cfi", "-o"])
        .arg(dir.join("probe"))
        .arg(&source)
        .output()
        .is_ok_and(|out| out.status.success())
}

#[test]
fn a_bad_cast_is_a_cfi_finding_and_the_unobservable_classes_are_listed() {
    let root = TestDir::new("cfi-replay");
    if !support::require_tool(cfi_links(root.path()), "clang++ with an LTO linker (CFI)") {
        eprintln!("skipping: clang++ cannot link a -fsanitize=cfi program here");
        return;
    }
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("shapes.cpp"),
        "#include <cstddef>\n#include <cstdint>\n\
         struct Shape {\n\
         \x20   virtual ~Shape() {}\n\
         \x20   virtual int area() const { return 0; }\n\
         };\n\
         struct Circle : Shape {\n\
         \x20   int r = 2;\n\
         \x20   int area() const override { return 3 * r * r; }\n\
         };\n\
         struct Square : Shape {\n\
         \x20   int s = 3;\n\
         \x20   int area() const override { return s * s; }\n\
         };\n\
         int classify(const uint8_t *data, size_t len) {\n\
         \x20   if (len < 1)\n\
         \x20       return -1;\n\
         \x20   Shape *shape = data[0] == 'C' ? static_cast<Shape *>(new Circle)\n\
         \x20                                 : static_cast<Shape *>(new Square);\n\
         \x20   int value = 0;\n\
         \x20   if (data[0] == 'C' || data[0] == 'Q') {\n\
         \x20       Circle *circle = static_cast<Circle *>(shape);\n\
         \x20       value = circle->r;\n\
         \x20   }\n\
         \x20   delete shape;\n\
         \x20   return value;\n\
         }\n",
    )
    .unwrap();
    let seed = root.join("seed.bin");
    std::fs::write(&seed, b"Q").unwrap();
    let work = root.join("work");
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(&src)
        .arg("--work-dir")
        .arg(&work)
        .args([
            "--target",
            "classify",
            "--per-target-time",
            "3",
            "--jobs",
            "1",
        ])
        .args(["--sanitizers", "asan,ubsan,cfi", "--seed-file"])
        .arg(&seed)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("control-flow integrity — 1 violation(s) found by corpus replay"),
        "{stderr}"
    );

    let finding = work.join("results/findings/F-CFI-0000");
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(finding.join("finding.json")).unwrap()).unwrap();
    assert_eq!(record["rule_id"], "BHF-221", "{record:#}");
    assert_eq!(record["target"]["line"], 22, "the cast's line: {record:#}");
    assert!(
        record["fixture_path"]
            .as_str()
            .is_some_and(|path| path.ends_with("main_cfi")),
        "{record:#}"
    );
    let replay = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("replay")
        .arg(&finding)
        .output()
        .unwrap();
    let replayed = String::from_utf8_lossy(&replay.stdout);
    assert!(
        replayed.starts_with("MATCH") && replayed.contains("control flow integrity check"),
        "{replayed}\n{}",
        String::from_utf8_lossy(&replay.stderr)
    );

    // Fuzzed with ASan and UBSan and replayed under CFI: no MSan or TSan lane
    // exists for C++.
    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
    let classes: Vec<&str> = run["summary"]["unobservable_classes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|class| class["class"].as_str().unwrap())
        .collect();
    assert_eq!(
        classes,
        ["uninitialized-reads", "data-races", "realtime-safety"],
        "{run:#}"
    );
    let md = std::fs::read_to_string(work.join("auto/run.md")).unwrap();
    assert!(
        md.contains("## Bug classes this run could not observe"),
        "{md}"
    );
    assert!(md.contains("data-races (c++)"), "{md}");
}
