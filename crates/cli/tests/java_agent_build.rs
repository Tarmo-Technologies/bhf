// SPDX-License-Identifier: Apache-2.0

//! `java_runtime/build-agent.sh` pins ASM by SHA-256 (#410): a pre-staged,
//! cached or fetched jar with another digest is refused. The script took any
//! file at the cache path, fetched with no retry, and wrote in place.

#![cfg(unix)]

use std::path::Path;
use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

#[test]
fn a_pre_staged_asm_jar_with_the_wrong_digest_is_refused() {
    let root = TestDir::new("java-agent-pin");
    let staged = root.join("staged");
    let cache = root.join("cache");
    std::fs::create_dir_all(&staged).unwrap();
    std::fs::write(staged.join("asm-9.7.jar"), b"not ASM").unwrap();
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../java_runtime/build-agent.sh");
    let output = Command::new("sh")
        .arg(&script)
        .arg(root.join("agent.jar"))
        .env("ASM_JAR_DIR", &staged)
        .env("BHF_JVM_CACHE", &cache)
        .output()
        .expect("run build-agent.sh");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains(
            "not ASM 9.7's adf46d5e34940bdf148ecdd26a9ee8eea94496a72034ff7141066b3eea5c4e9d"
        ),
        "{stderr}"
    );
    assert!(!root.join("agent.jar").exists(), "no agent is built");
}
