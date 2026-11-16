// SPDX-License-Identifier: Apache-2.0

//! Every C/C++ lane builds the target with OSS-Fuzz's
//! `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`, as AFL++'s compiler wrappers
//! do, so a bug behind a check the project compiles out of fuzz builds (a
//! firmware-update signature) is reached by the builtin lane too, and each
//! target's fidelity says the define was on. `--no-fuzzing-build-mode` and
//! `BHF_FUZZING_BUILD_MODE=0` leave it out of the generated Makefile.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// `fw_update_parse` copies `buf[0]` bytes into an 8-byte header, past a
/// signature check that random inputs never pass and fuzz builds skip;
/// `log_parse` overflows with no check in the way.
const TARGET: &str = "#include <stddef.h>\n#include <string.h>\n\n\
static int signature_ok(const unsigned char *buf, size_t len) {\n  \
unsigned sum = 0;\n  \
for (size_t i = 1; i < len; i++) sum = sum * 31u + buf[i];\n  \
return len > 8 && sum == 0x5eed1234u;\n}\n\n\
int fw_update_parse(const unsigned char *buf, size_t len) {\n  \
unsigned char hdr[8];\n  \
if (len < 2) return 0;\n\
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION\n  \
if (!signature_ok(buf, len)) return -1;\n\
#endif\n  \
memcpy(hdr, buf + 1, buf[0] < len - 1 ? buf[0] : len - 1);\n  \
return hdr[0];\n}\n\n\
int log_parse(const unsigned char *buf, size_t len) {\n  \
unsigned char tag[4];\n  \
memcpy(tag, buf, len);\n  \
return tag[0];\n}\n";

struct Run {
    work: PathBuf,
    log: String,
}

fn auto(root: &Path, name: &str, extra: &[&str], env: &[(&str, &str)]) -> Run {
    let src = root.join(name).join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("upd.c"), TARGET).unwrap();
    let work = root.join(name).join("work");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bhf"));
    cmd.args(["auto", "--work-dir", work.to_str().unwrap()])
        .args(["--jobs", "1", "--per-target-time", "5", "--single-pass"])
        .args(extra)
        .arg(&src)
        .env_remove("BHF_FUZZING_BUILD_MODE");
    for (key, value) in env {
        cmd.env(key, value);
    }
    let out = cmd.output().expect("run bhf auto");
    Run {
        work,
        log: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

impl Run {
    fn target(&self) -> serde_json::Value {
        let run: serde_json::Value =
            serde_json::from_slice(&std::fs::read(self.work.join("auto/run.json")).unwrap())
                .unwrap();
        run["targets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == "fw_update_parse")
            .unwrap_or_else(|| panic!("no fw_update_parse target:\n{run:#}\n{}", self.log))
            .clone()
    }

    fn makefile(&self) -> String {
        let id = self.target()["harness_id"].as_str().unwrap().to_owned();
        std::fs::read_to_string(self.work.join("harnesses").join(id).join("Makefile")).unwrap()
    }

    fn findings(&self) -> Vec<serde_json::Value> {
        let doc: serde_json::Value = serde_json::from_slice(
            &std::fs::read(self.work.join("results/findings.json")).unwrap_or_default(),
        )
        .unwrap_or_default();
        doc["findings"].as_array().cloned().unwrap_or_default()
    }
}

fn have_cc() -> bool {
    Command::new("cc")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

#[test]
fn the_builtin_lane_reaches_a_bug_behind_a_check_fuzz_builds_compile_out() {
    if !have_cc() {
        eprintln!("skipping: no C compiler on PATH");
        return;
    }
    let root = TestDir::new("fuzz-build-mode-on");
    let run = auto(&root, "on", &[], &[]);
    assert!(
        run.makefile()
            .contains("-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1"),
        "{}",
        run.log
    );
    assert_eq!(
        run.target()["fidelity"]["fuzzing_build_mode"],
        "on",
        "{}",
        run.log
    );
    let findings = run.findings();
    let in_function = |name: &str| {
        findings
            .iter()
            .find(|f| f["location"]["function"] == name)
            .unwrap_or_else(|| panic!("no {name} finding:\n{findings:#?}\n{}", run.log))
            .clone()
    };
    let guarded = in_function("fw_update_parse");
    let note = "reachable only with the check under \
                `#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION` at upd.c:13 disabled";
    let caveats = guarded["fidelity"]["caveats"].to_string();
    assert!(caveats.contains(note), "{guarded:#}");
    let id = guarded["id"].as_str().unwrap();
    let raw: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            run.work
                .join("results/findings")
                .join(id)
                .join("finding.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        raw["fuzzing_build_mode_note"]
            .as_str()
            .is_some_and(|text| text.starts_with(note)),
        "{raw:#}"
    );
    // INDEX.md escapes Markdown, so compare the caveat line without it.
    let index = std::fs::read_to_string(run.work.join("results/INDEX.md")).unwrap();
    let unescaped = index.replace('\\', "");
    assert!(
        unescaped
            .lines()
            .any(|line| line.starts_with("- Caveat:") && line.contains(note)),
        "{index}"
    );

    let unguarded = in_function("log_parse");
    assert!(
        !unguarded["fidelity"]["caveats"]
            .to_string()
            .contains("FUZZING_BUILD_MODE"),
        "{unguarded:#}"
    );
}

#[test]
fn the_opt_outs_leave_the_define_out_and_fidelity_says_off() {
    if !have_cc() {
        eprintln!("skipping: no C compiler on PATH");
        return;
    }
    let root = TestDir::new("fuzz-build-mode-off");
    for (name, run) in [
        (
            "flag",
            auto(&root, "flag", &["--no-fuzzing-build-mode"], &[]),
        ),
        (
            "env",
            auto(&root, "env", &[], &[("BHF_FUZZING_BUILD_MODE", "0")]),
        ),
    ] {
        let makefile = run.makefile();
        assert!(
            !makefile.contains("-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"),
            "{name}: the Makefile still defines it:\n{makefile}"
        );
        assert_eq!(
            run.target()["fidelity"]["fuzzing_build_mode"],
            "off",
            "{name}: {}",
            run.log
        );
        let past_the_check: Vec<_> = run
            .findings()
            .into_iter()
            .filter(|f| f["location"]["function"] == "fw_update_parse")
            .collect();
        assert!(
            past_the_check.is_empty(),
            "{name}: the signature check stands, so nothing past it is found:\n{past_the_check:#?}"
        );
    }
}
