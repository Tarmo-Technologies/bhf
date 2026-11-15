// SPDX-License-Identifier: Apache-2.0

//! Where the TypeScript lane finds its transpiler, and what a run does when it
//! has none: esbuild comes from PATH or from a `node_modules/.bin` inside the
//! scanned tree, never from a directory above it; the run-start toolchain
//! check agrees with the lane about a project's own esbuild; and `--resume`
//! tries a target again once its missing toolchain is installed.
#![cfg(unix)]

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const TARGET: &str = "export function parseRecord(data: Uint8Array): number {\n  \
                      return data.length > 0 ? data[0] : 0;\n}\n";

fn tmpdir(prefix: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("bhf-ts-toolchain-{prefix}-{n}"));
    fs::create_dir_all(&path).unwrap();
    path.canonicalize().unwrap()
}

/// `bin` holding a `node` link, then every inherited PATH dir that holds no
/// esbuild; `None` without node.
fn path_without_esbuild(bin: &Path) -> Option<OsString> {
    let node = which::which("node").ok()?;
    fs::create_dir_all(bin).unwrap();
    std::os::unix::fs::symlink(node, bin.join("node")).unwrap();
    let inherited = std::env::var_os("PATH").unwrap_or_default();
    Some(
        std::env::join_paths(
            std::iter::once(bin.to_path_buf()).chain(
                std::env::split_paths(&inherited).filter(|dir| !dir.join("esbuild").exists()),
            ),
        )
        .unwrap(),
    )
}

/// `dir` first, then `path`.
fn prepend(dir: &Path, path: &OsString) -> OsString {
    std::env::join_paths(std::iter::once(dir.to_path_buf()).chain(std::env::split_paths(path)))
        .unwrap()
}

/// A stand-in esbuild at `esbuild` that records each run in `log` and fails,
/// so a run that used it reports a failed transpile.
fn stand_in_esbuild(esbuild: &Path, log: &Path) {
    fs::create_dir_all(esbuild.parent().unwrap()).unwrap();
    fs::write(
        esbuild,
        format!(
            "#!/bin/sh\necho \"$0 $*\" >> '{}'\necho 'stand-in esbuild' >&2\nexit 1\n",
            log.display()
        ),
    )
    .unwrap();
    fs::set_permissions(esbuild, fs::Permissions::from_mode(0o755)).unwrap();
}

fn write_target(src: &Path) {
    fs::create_dir_all(src).unwrap();
    fs::write(src.join("parser.ts"), TARGET).unwrap();
}

/// `bhf auto` over `src` with `PATH` = `path`; its stderr.
fn auto(cwd: &Path, src: &Path, work: &Path, path: &OsString, extra: &[&str]) -> String {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bhf"))
        .current_dir(cwd)
        .args(["auto", "--work-dir", work.to_str().unwrap()])
        .args(["--languages", "typescript", "--max-targets", "1"])
        .args(["--jobs", "1", "--per-target-time", "1"])
        .args(extra)
        .arg(src)
        .env("PATH", path)
        .output()
        .expect("run bhf auto");
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn outcome(work: &Path) -> serde_json::Value {
    let run: serde_json::Value =
        serde_json::from_slice(&fs::read(work.join("auto/run.json")).unwrap()).unwrap();
    run["targets"][0]["outcome"].clone()
}

/// A `node_modules/.bin/esbuild` above the scan root is not the scanned
/// project's: any user can create `/tmp/node_modules/.bin/esbuild`, and
/// running it would run their program for every TypeScript tree scanned below
/// `/tmp`. bhf must never run it, and reports the missing transpiler instead.
#[test]
fn an_esbuild_above_the_scan_root_is_never_run() {
    let root = tmpdir("above");
    let Some(path) = path_without_esbuild(&root.join("bin")) else {
        eprintln!("skipping: node unavailable");
        return;
    };
    let ran = root.join("planted-esbuild-ran");
    stand_in_esbuild(&root.join("node_modules/.bin/esbuild"), &ran);
    let src = root.join("a/b/c/src");
    write_target(&src);
    let work = root.join("work");

    let stderr = auto(&root, &src, &work, &path, &["--no-discovery-cache"]);

    assert!(
        !ran.exists(),
        "an esbuild above the scan root ran: {}\n{stderr}",
        fs::read_to_string(&ran).unwrap_or_default()
    );
    let outcome = outcome(&work);
    assert_eq!(
        outcome["outcome"], "missing_toolchain",
        "{outcome}\n{stderr}"
    );
    let _ = fs::remove_dir_all(&root);
}

/// A project's own esbuild in the scanned tree is what the lane runs, and
/// the run-start toolchain check finds it too, so the run does not ask for an
/// esbuild install it then does without.
#[test]
fn a_project_esbuild_in_the_scanned_tree_is_used_and_the_toolchain_check_agrees() {
    let root = tmpdir("project");
    let Some(path) = path_without_esbuild(&root.join("bin")) else {
        eprintln!("skipping: node unavailable");
        return;
    };
    let project = root.join("project");
    let ran = root.join("project-esbuild-ran");
    stand_in_esbuild(&project.join("node_modules/.bin/esbuild"), &ran);
    write_target(&project.join("src"));
    let work = root.join("work");

    let stderr = auto(&root, &project, &work, &path, &["--no-discovery-cache"]);

    assert!(ran.exists(), "the project's esbuild was not run:\n{stderr}");
    assert!(
        stderr.contains("TypeScript (1 targets): ok"),
        "the toolchain check must find the project's esbuild:\n{stderr}"
    );
    assert!(!stderr.contains("MISSING esbuild"), "{stderr}");
    assert!(!stderr.contains("Install missing toolchains"), "{stderr}");
    assert_ne!(outcome(&work)["outcome"], "missing_toolchain", "{stderr}");
    let _ = fs::remove_dir_all(&root);
}

/// `--resume` keeps the results of targets that completed, but a missing
/// toolchain says nothing about the target: once esbuild is installed, the
/// resumed run tries the target again instead of reloading
/// `missing_toolchain`.
#[test]
fn resume_tries_a_missing_toolchain_target_again_once_the_tool_is_installed() {
    let root = tmpdir("resume");
    let Some(path) = path_without_esbuild(&root.join("bin")) else {
        eprintln!("skipping: node unavailable");
        return;
    };
    let src = root.join("src");
    write_target(&src);
    let work = root.join("work");

    let first = auto(&root, &src, &work, &path, &[]);
    assert_eq!(outcome(&work)["outcome"], "missing_toolchain", "{first}");

    let installed = root.join("installed");
    let ran = root.join("installed-esbuild-ran");
    stand_in_esbuild(&installed.join("esbuild"), &ran);
    let second = auto(
        &root,
        &src,
        &work,
        &prepend(&installed, &path),
        &["--resume"],
    );

    assert!(
        ran.exists(),
        "the resumed run must try the target with the installed esbuild:\n{second}"
    );
    let outcome = outcome(&work);
    assert_ne!(
        outcome["outcome"], "missing_toolchain",
        "{outcome}\n{second}"
    );
    let _ = fs::remove_dir_all(&root);
}
