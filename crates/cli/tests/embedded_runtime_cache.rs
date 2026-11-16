// SPDX-License-Identifier: Apache-2.0
#![cfg(unix)]

//! An installed bhf, which carries its harness runtimes embedded, wrote them
//! to a temporary directory it never removed, and generated Makefiles named
//! files in it. Once `/tmp` was cleaned those harnesses no longer built. The
//! runtimes now go to `<user cache>/bhf/runtime-<sha256>/`: the temporary
//! directory stays empty, and the Makefile builds after it is cleared.

use std::path::Path;
use std::process::{Command, Output};

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn bhf(work: &Path, tmp: &Path, cache: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
        .current_dir(work)
        .env("BHF_FORCE_EMBEDDED_RUNTIMES", "1")
        .env("TMPDIR", tmp)
        .env("XDG_CACHE_HOME", cache)
        .args(args)
        .output()
        .unwrap()
}

fn entries(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect()
}

#[test]
fn embedded_runtimes_are_staged_in_the_user_cache_not_tmpdir() {
    if Command::new("clang").arg("--version").output().is_err() {
        eprintln!("skipping: no clang");
        return;
    }
    let root = TestDir::new("embedded-runtime-cache");
    let (work, tmp, cache) = (root.join("work"), root.join("tmp"), root.join("cache"));
    for dir in [&work, &tmp, &cache] {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::fs::write(
        work.join("tool.c"),
        "#include <stddef.h>\nint parse(const unsigned char *d, size_t n) { return n > 1 && d[0] == 'A'; }\n",
    )
    .unwrap();
    let ok = |args: &[&str]| {
        let out = bhf(&work, &tmp, &cache, args);
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    ok(&[
        "generate-harness",
        "tool.c",
        "--target",
        "parse",
        "--output",
        "generated_harnesses",
        "--id",
        "H-TOOL",
    ]);
    ok(&["build", ".", "--harness", "H-TOOL"]);
    assert!(entries(&tmp).is_empty(), "TMPDIR holds {:?}", entries(&tmp));
    let staged: Vec<String> = entries(&cache.join("bhf"))
        .into_iter()
        .filter(|name| name.starts_with("runtime-"))
        .collect();
    assert_eq!(staged.len(), 1, "{staged:?}");

    // The build does not depend on anything in TMPDIR: clear it and build
    // the harness again from its Makefile.
    std::fs::remove_dir_all(&tmp).unwrap();
    std::fs::create_dir_all(&tmp).unwrap();
    std::fs::remove_dir_all(work.join("build")).unwrap();
    ok(&["build", ".", "--harness", "H-TOOL"]);
    assert!(work.join("build/H-TOOL/main").is_file());
    let makefile =
        std::fs::read_to_string(work.join("generated_harnesses/H-TOOL/Makefile")).unwrap();
    assert!(!makefile.contains(tmp.to_str().unwrap()), "{makefile}");
}
