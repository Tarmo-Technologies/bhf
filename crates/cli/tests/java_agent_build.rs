// SPDX-License-Identifier: Apache-2.0

//! `java_runtime/build-agent.sh` pins the ASM it fetches by SHA-256 (#410): a
//! fetched jar with another digest is refused, and a cached one is fetched
//! again. The script took any file at the cache path and fetched with no
//! retry. A fake `curl` stands in for Maven Central, so nothing is fetched.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

#[test]
fn a_fetched_asm_jar_with_another_digest_is_refused_and_a_bad_cached_one_discarded() {
    let root = TestDir::new("java-agent-pin");
    let cache = root.join("cache");
    let bin = root.join("bin");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::create_dir_all(&bin).unwrap();
    // A cached copy the script did not fetch: a partial download, say.
    std::fs::write(cache.join("asm-9.7.jar"), b"partial").unwrap();
    // A curl that serves anything but ASM.
    let curl = bin.join("curl");
    std::fs::write(
        &curl,
        "#!/bin/sh\nwhile [ $# -gt 0 ]; do [ \"$1\" = -o ] && printf 'not ASM' > \"$2\"; shift; done\n",
    )
    .unwrap();
    std::fs::set_permissions(&curl, std::fs::Permissions::from_mode(0o755)).unwrap();
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../java_runtime/build-agent.sh");
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new("sh")
        .arg(&script)
        .arg(root.join("agent.jar"))
        .env_remove("ASM_JAR_DIR")
        .env("BHF_JVM_CACHE", &cache)
        .env("PATH", path)
        .output()
        .expect("run build-agent.sh");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("asm-9.7.jar has SHA-256")
            && stderr.contains(
                "not ASM 9.7's adf46d5e34940bdf148ecdd26a9ee8eea94496a72034ff7141066b3eea5c4e9d"
            ),
        "{stderr}"
    );
    assert!(
        !cache.join("asm-9.7.jar").exists(),
        "the bad cached copy is gone, and nothing replaced it"
    );
    assert!(!root.join("agent.jar").exists(), "no agent is built");
}
