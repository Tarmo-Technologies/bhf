// SPDX-License-Identifier: Apache-2.0

//! `bhf generate-harness` writes C, C++ and Ada harnesses. A source in any
//! other language was parsed as Ada and reported as having no such
//! subprogram; it is now refused, naming its language and `bhf auto`.

use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

#[test]
fn other_languages_are_refused_by_name() {
    let work = TestDir::new("generate-harness-languages");
    for (file, source, language) in [
        ("tool.py", "def parse(data):\n    return data\n", "Python"),
        ("tool.rb", "def parse(data)\n  data\nend\n", "Ruby"),
        (
            "tool.go",
            "package tool\n\nfunc Parse(data []byte) int { return len(data) }\n",
            "Go",
        ),
    ] {
        std::fs::write(work.join(file), source).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
            .current_dir(work.path())
            .args(["generate-harness", file, "--target", "parse"])
            .args(["--output", "generated_harnesses"])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{file}: {stderr}");
        assert!(
            stderr.contains(&format!(
                "{file} is {language} source; bhf generate-harness writes C, C++ and Ada \
                 harnesses only"
            )),
            "{file}: {stderr}"
        );
        assert!(
            stderr.contains("bhf auto <dir> --target"),
            "{file}: {stderr}"
        );
        assert!(!stderr.contains("subprogram"), "{file}: {stderr}");
        assert!(!work.join("generated_harnesses").exists(), "{file}");
    }
}
