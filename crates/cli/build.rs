// SPDX-License-Identifier: Apache-2.0

//! Copy libbhf_runtrace_shim.so next to the bhf binary
//! as libbhf_runtrace.so so the auto loop can find it via
//! std::env::current_exe() + sibling lookup at runtime.

use std::env;
use std::path::PathBuf;

fn main() {
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_owned());
    let target_dir = PathBuf::from(env::var("OUT_DIR").unwrap())
        .ancestors()
        .nth(3)
        .expect("OUT_DIR is target/<profile>/build/<crate>-<hash>/out")
        .to_path_buf();

    let shim_src = target_dir.join("libbhf_runtrace_shim.so");
    let shim_dst = target_dir.join("libbhf_runtrace.so");

    // The shim is a workspace member, so cargo builds it before us
    // when cli is built as part of a workspace `cargo build`. Single-
    // crate builds (`cargo build -p bhf`) may NOT build the shim.
    // If the canonical cargo artifact exists but this copy step does
    // not run, the runtime locator can still load libbhf_runtrace_shim.so.

    println!("cargo:rerun-if-changed={}", shim_src.display());
    println!("cargo:rerun-if-env-changed=PROFILE");
    println!("cargo:rerun-if-env-changed=BHF_RELEASE_VERSION");
    let _ = profile;

    // Stamp the short git commit so `bug_report` can identify exactly which
    // bhf build produced a self-diagnostics report. Best-effort: an offline
    // unpacked source tarball with no git leaves BHF_GIT_COMMIT unset and the
    // report shows "unknown".
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let git = |args: &[&str]| -> Option<String> {
        std::process::Command::new("git")
            .args(args)
            .current_dir(&manifest_dir)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
    };
    // Refresh the version/commit stamp when HEAD, its current branch ref, or
    // tags move. Resolve these paths through Git so linked worktrees and a
    // .git file pointing elsewhere work as well as a normal .git directory.
    // Watching only HEAD misses commits because symbolic HEAD usually continues
    // to contain the same `ref: refs/heads/<branch>` text as the branch moves.
    let watch_git_path = |path: &str| {
        let path = std::path::Path::new(path);
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::path::Path::new(&manifest_dir).join(path)
        };
        let mut watched = path.as_path();
        while !watched.exists() {
            let Some(parent) = watched.parent() else {
                return;
            };
            watched = parent;
        }
        // Watching the nearest existing parent also detects a newly created
        // loose ref when the current branch is stored only in packed-refs.
        println!("cargo:rerun-if-changed={}", watched.display());
    };
    for git_path in ["HEAD", "packed-refs", "refs/tags"] {
        if let Some(path) = git(&["rev-parse", "--git-path", git_path]) {
            watch_git_path(&path);
        }
    }
    if let Some(reference) = git(&["symbolic-ref", "-q", "HEAD"]) {
        if let Some(path) = git(&["rev-parse", "--git-path", &reference]) {
            watch_git_path(&path);
        }
    }
    if let Some(commit) = git(&["rev-parse", "--short", "HEAD"]) {
        println!("cargo:rustc-env=BHF_GIT_COMMIT={commit}");
    }
    // A human version for `bhf --version`: the git tag/describe (e.g.
    // `v0.2.3` on a tag, or `v0.2.2-3-gc307502` between tags), falling back to the
    // Cargo package version for an unpacked source tarball with no git. ALWAYS
    // emitted so `env!("BHF_VERSION_FULL")` compiles.
    let package_version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".to_owned());
    let version_full = if env::var_os("BHF_RELEASE_VERSION").is_some() {
        format!("v{package_version}")
    } else {
        git(&["describe", "--tags", "--always", "--dirty"]).unwrap_or(package_version)
    };
    println!("cargo:rustc-env=BHF_VERSION_FULL={version_full}");

    if shim_src.is_file() {
        // Copy only if mtime changed.
        let needs_copy = match (shim_src.metadata(), shim_dst.metadata()) {
            (Ok(src), Ok(dst)) => src.modified().ok() != dst.modified().ok(),
            (Ok(_), Err(_)) => true,
            _ => false,
        };
        if needs_copy {
            if let Err(e) = std::fs::copy(&shim_src, &shim_dst) {
                println!("cargo:warning=copy shim: {e}");
            }
        }
    }
}
