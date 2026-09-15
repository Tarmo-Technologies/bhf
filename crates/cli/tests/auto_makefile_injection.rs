// SPDX-License-Identifier: Apache-2.0
//
// GHSA-725h-95qg-44fv and the two sibling sinks found while fixing it.
//
// `bhf auto` reads two files straight out of the SCANNED (untrusted) tree without
// any opt-in flag: an auto-loaded `.bhf.toml`, and the project's own
// `compile_commands.json`. Values from both are interpolated into the generated
// harness Makefile, whose recipes `make` hands to `/bin/sh`. Three of those values
// reached the Makefile unescaped:
//
//   V1  `.bhf.toml` `cxx-std`            -> `CXX_STD ?= <value>` -> `-std=$(CXX_STD)`
//   V2  compile_commands.json `-std=`    -> `CXX_STD ?= <value>` -> `-std=$(CXX_STD)`
//   V3  compile_commands.json compiler   -> `CXX = <value>`      -> heads every recipe
//
// V1 is the reported advisory. V2 reaches the same sink by a different route and is
// NOT closed by validating the CLI flag, because the value never passes through it.
// V3 is a distinct sink. Each assertion below fails on the pre-fix binary.
//
// The payloads write a marker file rather than doing anything destructive; the test
// asserts the marker never appears AND that the emitted Makefile is clean, so a
// regression is caught even on a host where the build never runs.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bhf_bin() -> PathBuf {
    let mut dir = std::env::current_exe().expect("test exe path");
    dir.pop();
    if dir.ends_with("deps") {
        dir.pop();
    }
    dir.join("bhf")
}

const PARSER_CPP: &str = r#"
#include <string>
#include <cstdint>
#include <cstddef>
int parse_input(const uint8_t* d, size_t n){int a=0;for(size_t i=0;i<n;i++)a+=d[i];return a;}
bool check_name(const std::string& s){return s.size()>3 && s[0]=='A';}
"#;

/// A scratch tree plus the marker path a successful injection would create.
struct Scenario {
    root: PathBuf,
    work: PathBuf,
    marker: PathBuf,
}

impl Scenario {
    fn new(tag: &str) -> Self {
        // Keep the path free of shell/make metacharacters: bhf correctly refuses an
        // include dir containing one, and the default `{:?}` of a ThreadId carries
        // parentheses, which would fail the benign case for the wrong reason.
        let base = std::env::temp_dir().join(format!("bhf_mkinject_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("tree");
        std::fs::create_dir_all(&root).expect("create tree");
        std::fs::write(root.join("parser.cpp"), PARSER_CPP).expect("write parser.cpp");
        Self {
            work: base.join("work"),
            marker: base.join("PWNED"),
            root,
        }
    }

    /// A `compile_commands.json` whose single entry uses `compiler` and `extra_arg`.
    fn write_compile_db(&self, compiler: &str, extra_arg: &str) {
        let source = self.root.join("parser.cpp");
        let entry = serde_json::json!([{
            "directory": self.root.to_str().unwrap(),
            "file": source.to_str().unwrap(),
            "arguments": [compiler, extra_arg, "-c", source.to_str().unwrap()],
        }]);
        std::fs::write(
            self.root.join("compile_commands.json"),
            serde_json::to_string_pretty(&entry).expect("serialize compile db"),
        )
        .expect("write compile_commands.json");
    }

    fn run(&self) -> std::process::Output {
        Command::new(bhf_bin())
            .args([
                "auto",
                "--per-target-time",
                "3",
                "--single-pass",
                "--jobs",
                "1",
                "--work-dir",
                self.work.to_str().unwrap(),
                self.root.to_str().unwrap(),
            ])
            .output()
            .expect("run bhf auto")
    }

    /// Every generated harness Makefile, so assertions can inspect what was emitted.
    fn makefiles(&self) -> Vec<String> {
        let harnesses = self.work.join("harnesses");
        let Ok(entries) = std::fs::read_dir(&harnesses) else {
            return Vec::new();
        };
        entries
            .filter_map(Result::ok)
            .filter_map(|e| std::fs::read_to_string(e.path().join("Makefile")).ok())
            .collect()
    }

    fn assert_no_execution(&self, vector: &str) {
        assert!(
            !self.marker.exists(),
            "{vector}: the injected command RAN — marker {} was created, so a scanned \
             tree achieved command execution on the host",
            self.marker.display()
        );
    }

    /// The payload text must not survive into the Makefile at all: if it is there,
    /// the only thing standing between the operator and execution is a `make`
    /// variable-origin accident, which a manual `make` in the harness dir defeats.
    fn assert_makefile_clean(&self, vector: &str) {
        let needle = self.marker.to_str().expect("utf-8 marker path");
        for makefile in self.makefiles() {
            assert!(
                !makefile.contains(needle),
                "{vector}: the generated Makefile carries the injected payload:\n{}",
                makefile
                    .lines()
                    .filter(|l| l.contains(needle))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }
    }
}

/// V1 — the reported advisory. An auto-loaded `.bhf.toml` from the scanned tree.
#[test]
fn tree_config_cxx_std_cannot_inject_into_the_harness_makefile() {
    let s = Scenario::new("v1");
    std::fs::write(
        s.root.join(".bhf.toml"),
        format!(
            "cxx-std = \"c++17; touch {}; true\"\n",
            s.marker.to_str().unwrap()
        ),
    )
    .expect("write .bhf.toml");

    let out = s.run();
    s.assert_no_execution("V1 .bhf.toml cxx-std");
    s.assert_makefile_clean("V1 .bhf.toml cxx-std");

    // A malformed dialect is an operator-visible error, not a silent downgrade:
    // the value came from a file claiming to configure the run.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--cxx-std must be a C++ standard"),
        "expected an explicit rejection of the malformed cxx-std, got:\n{stderr}"
    );
}

/// V2 — same sink, different route: the tree's own compile database. This one is
/// reached without any `.bhf.toml`, so the advisory's CLI-flag validation alone
/// would have left it open.
#[test]
fn compile_database_std_flag_cannot_inject_into_the_harness_makefile() {
    let s = Scenario::new("v2");
    s.write_compile_db(
        "/usr/bin/clang++",
        &format!("-std=c++17; touch {}; true", s.marker.to_str().unwrap()),
    );

    s.run();
    s.assert_no_execution("V2 compile_commands.json -std=");
    s.assert_makefile_clean("V2 compile_commands.json -std=");

    // A rejected dialect falls back to the built-in default rather than failing the
    // run: the tree's build system is untrusted input, not an operator instruction.
    for makefile in s.makefiles() {
        for line in makefile.lines().filter(|l| l.starts_with("CXX_STD")) {
            assert!(
                line.contains("gnu++20"),
                "expected the safe default dialect, got: {line}"
            );
        }
    }
}

/// V3 — the compiler token heads every recipe line. Upstream recognition inspects
/// only the LEAF file name while emitting the WHOLE argument, so a payload whose
/// final path component still contains "clang" is accepted.
#[test]
fn compile_database_compiler_cannot_inject_into_the_harness_makefile() {
    let s = Scenario::new("v3");
    // Ordered so the leaf of the whole string still ends in `clang++`, which is what
    // the upstream recognition test looks at, and so a real build still succeeds —
    // the stealthiest shape, with no signal to the operator.
    s.write_compile_db(
        &format!("id > {}; clang++", s.marker.to_str().unwrap()),
        "-DHARMLESS=1",
    );

    s.run();
    s.assert_no_execution("V3 compile_commands.json compiler");
    s.assert_makefile_clean("V3 compile_commands.json compiler");

    for makefile in s.makefiles() {
        for line in makefile.lines().filter(|l| l.starts_with("CXX =")) {
            assert!(
                line == "CXX = clang++",
                "expected the safe default compiler, got: {line}"
            );
        }
    }
}

/// The fix must not cost legitimate projects their recovered build context: a
/// well-formed dialect and compiler from the same untrusted sources are still
/// honored, and ordinary compile flags still reach the recipe.
#[test]
fn well_formed_build_context_values_are_still_honored() {
    let s = Scenario::new("ok");
    std::fs::write(s.root.join(".bhf.toml"), "cxx-std = \"gnu++14\"\n").expect("write .bhf.toml");
    s.write_compile_db("/usr/bin/clang++", "-DFOO=1");

    let out = s.run();
    assert!(
        out.status.success(),
        "bhf auto exited non-zero on a benign tree: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let makefiles = s.makefiles();
    assert!(
        !makefiles.is_empty(),
        "expected at least one generated harness Makefile"
    );
    for makefile in &makefiles {
        assert!(
            makefile.contains("CXX_STD ?= gnu++14"),
            "the operator's dialect was dropped:\n{}",
            makefile
                .lines()
                .filter(|l| l.starts_with("CXX_STD"))
                .collect::<Vec<_>>()
                .join("\n")
        );
        assert!(
            makefile.contains("CXX = /usr/bin/clang++"),
            "the recovered compiler was dropped:\n{}",
            makefile
                .lines()
                .filter(|l| l.starts_with("CXX ="))
                .collect::<Vec<_>>()
                .join("\n")
        );
        assert!(
            makefile.contains("-DFOO=1"),
            "the recovered compile flag was dropped"
        );
    }
}

/// The `$(origin)` guard that shields bhf's own build path is not the control: an
/// operator rebuilding a generated harness by hand (a documented, supported use of
/// the harness directory) gets no such protection. Assert the value the Makefile
/// would use in that case is a plain compiler token.
#[test]
fn a_hand_run_make_in_the_harness_dir_uses_a_safe_compiler() {
    let s = Scenario::new("manual");
    s.write_compile_db(
        &format!("id > {}; clang++", s.marker.to_str().unwrap()),
        "-DHARMLESS=1",
    );
    s.run();

    let harnesses = s.work.join("harnesses");
    let Ok(entries) = std::fs::read_dir(&harnesses) else {
        return; // no harness generated on this host; the sink assertions above cover it
    };
    for entry in entries.filter_map(Result::ok) {
        let makefile = entry.path().join("Makefile");
        let Ok(text) = std::fs::read_to_string(&makefile) else {
            continue;
        };
        for line in text.lines().filter(|l| l.starts_with("CXX =")) {
            let value = line.trim_start_matches("CXX =").trim();
            assert!(
                !value.contains(';')
                    && !value.contains('&')
                    && !value.contains('`')
                    && !value.contains('$'),
                "a hand-run `make` in {} would execute {value:?}",
                entry.path().display()
            );
        }
    }
    let _: &Path = &s.root;
}
