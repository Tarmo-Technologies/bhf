// SPDX-License-Identifier: Apache-2.0

//! A Rust target refused for want of `--run-untrusted` is reported as needing
//! that consent (#241). It was filed as `unsupported_params`, among the
//! targets whose parameters could not be driven, and the next steps told the
//! operator to `--force` it, which cannot help: the build runs the project's
//! own code (Cargo build scripts and proc macros).

use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

#[test]
#[cfg_attr(
    windows,
    ignore = "the Rust lane runs under WSL on Windows, and is refused natively first; see \
              docs/site/windows.md"
)]
fn a_rust_crate_without_run_untrusted_needs_the_consent_not_force() {
    let root = TestDir::new("consent-rust");
    let src = root.join("src");
    std::fs::create_dir_all(src.join("src")).unwrap();
    std::fs::write(
        src.join("Cargo.toml"),
        "[package]\nname = \"widget\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lib]\npath = \"src/lib.rs\"\n",
    )
    .unwrap();
    std::fs::write(
        src.join("src/lib.rs"),
        "/// Sum a record's bytes.\n\
         pub fn parse_record(data: &[u8]) -> u32 {\n\
         \x20   data.iter().map(|&b| u32::from(b)).sum()\n\
         }\n",
    )
    .unwrap();
    let work = root.join("work");
    let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(&src)
        .arg("--work-dir")
        .arg(&work)
        .args(["--per-target-time", "1", "--jobs", "1"])
        .output()
        .unwrap();
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let run: serde_json::Value =
        serde_json::from_slice(&std::fs::read(work.join("auto/run.json")).unwrap()).unwrap();
    let targets = run["targets"].as_array().expect("run.json targets");
    assert!(!targets.is_empty(), "{log}");
    for target in targets {
        assert_eq!(
            target["outcome"]["outcome"], "consent_required",
            "{target:#}"
        );
        let reason = target["outcome"]["reason"].as_str().unwrap_or_default();
        assert!(reason.starts_with("needs --run-untrusted"), "{reason}");
    }
    assert_eq!(
        run["summary"]["unsupported_params"], 0,
        "{:#}",
        run["summary"]
    );
    let run_md = std::fs::read_to_string(work.join("auto/run.md")).unwrap();
    assert!(run_md.contains("needs --run-untrusted"), "{run_md}");
    assert!(log.contains("need --run-untrusted"), "{log}");
    assert!(!log.contains("Attempt them anyway with --force"), "{log}");
}
