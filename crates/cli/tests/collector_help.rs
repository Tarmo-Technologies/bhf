// SPDX-License-Identifier: Apache-2.0

//! `--collector`'s help said `auto` is inactive on Linux, where it selects the
//! runtrace adapter, and the docs said otherwise. `bhf fuzz --help`,
//! `bhf binary fuzz --help` and docs/site/cli.md now describe `auto` in the
//! same words.

use std::path::Path;
use std::process::Command;

/// What `auto` selects, as the help and the docs say it.
const AUTO: &str = "`auto` selects the built-in provider for the platform: the native Windows \
                    ETW provider `bhf-collector-win`, or on Linux the in-process `LD_PRELOAD` \
                    runtrace adapter, which arms the runtrace shim for the run (with \
                    `--runtime-oracles off` it writes no runtime-oracle findings) and stays \
                    inactive only when the shim is unavailable.";

fn words(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn help(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(args)
        .arg("--help")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    words(&String::from_utf8_lossy(&out.stdout))
}

fn docs() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/site/cli.md");
    words(&std::fs::read_to_string(path).unwrap())
}

#[test]
fn fuzz_help_collector_text() {
    let help = help(&["fuzz"]);
    assert!(help.contains(AUTO), "{help}");
    assert!(!help.contains("inactive on Linux"), "{help}");
    assert!(docs().contains(AUTO));
}

#[test]
fn binary_fuzz_help_collector_text() {
    let help = help(&["binary", "fuzz"]);
    assert!(help.contains(AUTO), "{help}");
    assert!(!help.contains("inactive on Linux"), "{help}");
    assert!(docs().contains(AUTO));
}
