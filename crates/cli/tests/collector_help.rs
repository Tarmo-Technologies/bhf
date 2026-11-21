// SPDX-License-Identifier: Apache-2.0

//! `--collector`'s help said `auto` is inactive on Linux, where it selects the
//! runtrace adapter, and the docs said otherwise. `bhf fuzz --help` and
//! `bhf binary fuzz --help` describe `auto` in the same words, and
//! docs/site/cli.md states the same facts.

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
        .env("COLUMNS", "100")
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

/// docs/site/cli.md says what `auto` selects on each platform, and that it is
/// inactive only without the shim.
fn assert_docs_describe_auto() {
    let docs = docs();
    for fact in [
        "`bhf-collector-win`",
        "`LD_PRELOAD` runtrace adapter",
        "arms the runtrace shim for the run",
        "shim is unavailable",
    ] {
        assert!(
            docs.contains(fact),
            "docs/site/cli.md does not say {fact:?}"
        );
    }
    assert!(!docs.contains("inactive on Linux"));
}

#[test]
fn fuzz_help_collector_text() {
    let help = help(&["fuzz"]);
    assert!(help.contains(AUTO), "{help}");
    assert!(!help.contains("inactive on Linux"), "{help}");
    assert_docs_describe_auto();
}

#[test]
fn binary_fuzz_help_collector_text() {
    let help = help(&["binary", "fuzz"]);
    assert!(help.contains(AUTO), "{help}");
    assert!(!help.contains("inactive on Linux"), "{help}");
    assert_docs_describe_auto();
}
