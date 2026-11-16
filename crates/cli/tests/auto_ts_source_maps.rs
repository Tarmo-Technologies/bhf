// SPDX-License-Identifier: Apache-2.0

//! A TypeScript finding names the `.ts` file and line, not the `target.js`
//! esbuild transpiled it to in the work dir (#367): the lane writes a source
//! map and runs node with `--enable-source-maps`. A plain JavaScript harness
//! runs node without it.
#![cfg(unix)]

use std::fs;
use std::path::Path;
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// The throw is on line 7.
const CODEC: &str = "// SPDX-License-Identifier: Apache-2.0\n\
                     export function decodeFrame(data: Buffer): number {\n  \
                     if (data.length < 2) {\n    \
                     return 0;\n  \
                     }\n  \
                     if (data[0] === 0x7f) {\n    \
                     throw new Error('bad frame marker');\n  \
                     }\n  \
                     return data[1];\n}\n";

fn have(tool: &str) -> bool {
    let present = { which::which(tool).is_ok() };
    support::require_tool(present, tool)
}

fn auto(src: &Path, work: &Path, language: &str, seed: &Path) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .args(["auto", "--work-dir", work.to_str().unwrap()])
        .args(["--languages", language, "--max-targets", "1"])
        .args(["--jobs", "1", "--per-target-time", "6", "--single-pass"])
        .arg("--seed-file")
        .arg(seed)
        .arg(src)
        .output()
        .expect("run bhf auto");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn findings(work: &Path) -> Vec<serde_json::Value> {
    fs::read_dir(work.join("results/findings"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            serde_json::from_slice(&fs::read(entry.path().join("finding.json")).ok()?).ok()
        })
        .collect()
}

fn launchers(work: &Path) -> Vec<String> {
    fs::read_dir(work.join("harnesses"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| fs::read_to_string(entry.path().join("main")).ok())
        .collect()
}

#[test]
fn a_typescript_finding_names_the_ts_source_line() {
    if !have("node") || !have("esbuild") {
        eprintln!("skipping: node or esbuild unavailable");
        return;
    }
    let root = TestDir::new("ts-source-maps");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("codec.ts"), CODEC).unwrap();
    let seed = root.join("seed.bin");
    fs::write(&seed, b"\x7f\x01").unwrap();
    let work = root.join("work");
    let stderr = auto(&src, &work, "typescript", &seed);

    let found = findings(&work);
    let finding = found
        .iter()
        .find(|finding| finding.to_string().contains("bad frame marker"))
        .unwrap_or_else(|| panic!("the planted throw is found: {found:#?}\n{stderr}"));
    let top = &finding["exception"]["stack"][0];
    assert!(
        top["file"]
            .as_str()
            .is_some_and(|file| file.ends_with("src/codec.ts")),
        "{finding:#}"
    );
    assert_eq!(top["line"], 7, "{finding:#}");
    assert!(
        launchers(&work)
            .iter()
            .all(|launcher| launcher.contains("exec node --enable-source-maps ")),
        "{:?}",
        launchers(&work)
    );
    let sarif = fs::read_to_string(work.join("results/findings.sarif")).unwrap();
    assert!(
        sarif.contains("\"codec.ts\"") && !sarif.contains("target.js"),
        "SARIF names the .ts source: {sarif}"
    );
}

#[test]
fn a_javascript_harness_runs_node_without_source_maps() {
    if !have("node") {
        eprintln!("skipping: node unavailable");
        return;
    }
    let root = TestDir::new("js-no-source-maps");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("codec.js"),
        "'use strict';\n\
         function decodeFrame(data) {\n\
           if (data.length >= 2 && data[0] === 0x7f) throw new Error('bad frame marker');\n\
           return 0;\n\
         }\n\
         module.exports = { decodeFrame };\n",
    )
    .unwrap();
    let seed = root.join("seed.bin");
    fs::write(&seed, b"\x7f\x01").unwrap();
    let work = root.join("work");
    let stderr = auto(&src, &work, "javascript", &seed);

    let found = findings(&work);
    let finding = found
        .iter()
        .find(|finding| finding.to_string().contains("bad frame marker"))
        .unwrap_or_else(|| panic!("the planted throw is found: {found:#?}\n{stderr}"));
    let top = &finding["exception"]["stack"][0];
    assert!(
        top["file"]
            .as_str()
            .is_some_and(|file| file.ends_with("src/codec.js")),
        "{finding:#}"
    );
    assert_eq!(top["line"], 3, "{finding:#}");
    let launchers = launchers(&work);
    assert!(!launchers.is_empty());
    assert!(
        launchers
            .iter()
            .all(|launcher| !launcher.contains("--enable-source-maps")),
        "{launchers:?}"
    );
}
