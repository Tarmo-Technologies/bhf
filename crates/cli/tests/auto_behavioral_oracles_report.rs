// SPDX-License-Identifier: Apache-2.0

//! A run says, for each fuzzed target, whether the behavioral sink oracles
//! ran. The runtrace shim that runs them is preloaded into native harnesses
//! and the Python and Perl launchers (#300), so those targets are `on`, and
//! the Ruby, Lua and PHP targets, whose interpreters run without it, are
//! `off`.
#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn runs(bin: &str, args: &[&str]) -> bool {
    Command::new(bin)
        .args(args)
        .output()
        .is_ok_and(|o| o.status.success())
}

/// The fixture file for each interpreted lane present on this host.
fn interpreted_fixtures() -> Vec<(&'static str, &'static str, &'static str)> {
    let lanes = [
        (
            "python",
            "loader.py",
            "def load(name):\n    return len(name) + 1\n",
            runs("python3", &["-c", "1"]),
        ),
        (
            "perl",
            "Loader.pm",
            "package Loader;\nsub load {\n    my ($name) = @_;\n    return length($name) + 1;\n}\n1;\n",
            runs("perl", &["-e", "1"]),
        ),
        (
            "ruby",
            "loader.rb",
            "def load(name)\n  name.bytesize + 1\nend\n",
            runs("ruby", &["-e", "1"]),
        ),
        (
            "lua",
            "loader.lua",
            "local M = {}\nfunction M.load(name)\n  return #name + 1\nend\nreturn M\n",
            runs("lua", &["-e", "assert(math.type)"]) || runs("lua5.4", &["-e", "1"]),
        ),
        (
            "php",
            "loader.php",
            "<?php\nfunction load(string $name): int {\n    return strlen($name) + 1;\n}\n",
            runs("php", &["-r", "echo 1;"]),
        ),
    ];
    lanes
        .into_iter()
        .filter(|lane| lane.3)
        .map(|(lang, file, source, _)| (lang, file, source))
        .collect()
}

fn shim_built() -> bool {
    let exe = Path::new(env!("CARGO_BIN_EXE_bhf"));
    exe.with_file_name("libbhf_runtrace_shim.so").exists()
}

#[test]
fn run_md_and_run_json_mark_each_lane_on_or_off() {
    let interpreted = interpreted_fixtures();
    if interpreted.is_empty() || !runs("cc", &["--version"]) || !shim_built() {
        eprintln!("skipping: needs cc, the runtrace shim and one interpreter");
        return;
    }
    let root = TestDir::new("behavioral-oracles");
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("loader.c"),
        "#include <stddef.h>\nint load(const unsigned char *data, size_t size) {\n  \
         return size > 0 && data[0] == 'x';\n}\n",
    )
    .unwrap();
    let mut languages = vec!["c"];
    for (lang, file, source) in &interpreted {
        std::fs::write(src.join(file), source).unwrap();
        languages.push(lang);
    }
    let work = root.join("work");
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["auto", "--work-dir", work.to_str().unwrap()])
        .args(["--languages", &languages.join(",")])
        .args(["--jobs", "2", "--per-target-time", "2", "--single-pass"])
        .arg(&src)
        .output()
        .expect("run bhf auto");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
    let md = std::fs::read_to_string(work.join("auto/run.md")).unwrap();

    let targets = run["targets"].as_array().unwrap();
    for file in std::iter::once("loader.c").chain(interpreted.iter().map(|lane| lane.1)) {
        let target = targets
            .iter()
            .find(|t| t["source"].as_str().is_some_and(|s| s.ends_with(file)))
            .unwrap_or_else(|| panic!("no {file} target in run.json:\n{run:#}\n{stderr}"));
        let want = if ["loader.c", "loader.py", "Loader.pm"].contains(&file) {
            "on"
        } else {
            "off"
        };
        assert_eq!(
            target["behavioral_oracles"]["status"], want,
            "{file}: {target:#}\n{stderr}"
        );
        let id = target["harness_id"].as_str().unwrap();
        let row = md
            .lines()
            .find(|line| line.contains(id))
            .unwrap_or_else(|| panic!("no {id} row in run.md:\n{md}"));
        assert!(
            row.contains(&format!("[behavioral oracles: {want}")),
            "{file}: {row}"
        );
    }
}
