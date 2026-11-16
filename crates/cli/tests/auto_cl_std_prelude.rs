// SPDX-License-Identifier: Apache-2.0
// Windows only: the MSVC `cl` lane.
#![cfg(windows)]

//! A pre-standard header that names `vector` and `string` without `std::`
//! builds under clang through the std-prelude repair, which reads clang's
//! "unknown type name 'vector'". cl reports such a declaration as C2143,
//! C4430, C3646 and C2238, which name no type, so with `--cc cl` the target
//! failed unclassified. bhf's cl front end now gives those errors clang's
//! spelling, and the header builds.

use std::fs;
use std::path::Path;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

const LEGACY_H: &str = "#include <vector>\n#include <string>\n\
                        struct Widget {\n    vector<int> items;\n    string name;\n};\n";

const WIDGET_CPP: &str = "#include <cstddef>\n#include \"legacy.h\"\n\
                          int widget_parse(const unsigned char *data, size_t len) {\n\
                              Widget w;\n\
                              for (size_t i = 0; i < len; i++) w.items.push_back(data[i]);\n\
                              return (int)w.items.size();\n\
                          }\n";

fn vs_installed() -> bool {
    Path::new(r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe").is_file()
}

#[test]
fn a_pre_standard_header_builds_with_cl() {
    if !vs_installed() {
        eprintln!("skipping: no Visual Studio (vswhere)");
        return;
    }
    let root = TestDir::new("auto-cl-std-prelude");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("legacy.h"), LEGACY_H).unwrap();
    fs::write(src.join("widget.cpp"), WIDGET_CPP).unwrap();
    let work = root.join("work");
    let out = support::bhf_cargo_command()
        .current_dir(root.path())
        .args(["auto", "--work-dir", work.to_str().unwrap()])
        .args(["--cc", "cl", "--cxx", "cl", "--per-target-time", "3"])
        .arg(src.to_str().unwrap())
        .output()
        .expect("run bhf auto");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let run: serde_json::Value =
        serde_json::from_slice(&fs::read(work.join("auto/run.json")).unwrap()).unwrap();
    let target = run["targets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|target| target["name"] == "widget_parse")
        .unwrap_or_else(|| panic!("no widget_parse target: {run:#}\n{stderr}"));
    let outcome = target["outcome"]["outcome"].as_str().unwrap_or_default();
    assert!(
        matches!(outcome, "built_and_fuzzed" | "built" | "built_not_entered"),
        "{target:#}\n{stderr}"
    );
}
