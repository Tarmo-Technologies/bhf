// SPDX-License-Identifier: Apache-2.0
//! `mkdir` is judged by the mode the directory was created with (#407). The
//! usual `mkdir(path, 0777)` creates a `0755` directory under umask 022, and
//! was reported as an insecure-permissions assignment (BHF-416) though no
//! world-writable directory existed. A directory the umask leaves
//! world-writable still is.

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn target_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("CARGO_TARGET_DIR") {
        return PathBuf::from(dir);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root above crates/bhf_runtrace_shim")
        .join("target")
}

/// The preload cdylib, when it is newer than the hook that is under test.
fn shim_so() -> Option<PathBuf> {
    let hook = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/hooks/fs.rs");
    let hook_mtime = hook.metadata().and_then(|m| m.modified()).ok()?;
    ["debug", "release"].into_iter().find_map(|profile| {
        let shim = target_dir().join(profile).join("libbhf_runtrace_shim.so");
        let shim_mtime = shim.metadata().and_then(|m| m.modified()).ok()?;
        (shim_mtime >= hook_mtime).then_some(shim)
    })
}

fn cc() -> Option<&'static str> {
    ["cc", "gcc", "clang"].into_iter().find(|c| {
        Command::new(c)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    })
}

#[test]
fn a_directory_is_judged_by_the_mode_it_was_created_with() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built, or older than src/hooks/fs.rs");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let dir = tempfile::Builder::new()
        .prefix("bhf-mkdir-")
        .tempdir()
        .expect("create test dir");
    let src = dir.path().join("probe.c");
    std::fs::write(
        &src,
        r#"
        #include <fcntl.h>
        #include <sys/stat.h>
        int main(int argc, char **argv) {
            (void)argc;
            umask(022);
            mkdir(argv[1], 0777);        /* created 0755: not reported */
            mkdir(argv[1], 0777);        /* EEXIST: assigns nothing */
            umask(0);
            mkdirat(AT_FDCWD, argv[2], 0777); /* created 0777: reported */
            return 0;
        }
    "#,
    )
    .unwrap();
    let bin = dir.path().join("probe");
    assert!(Command::new(cc)
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap()
        .success());
    let usual = dir.path().join("usual");
    let open = dir.path().join("open");
    let log = dir.path().join("rt.jsonl");
    let status = Command::new(&bin)
        .arg(&usual)
        .arg(&open)
        .env("LD_PRELOAD", &shim)
        .env("BHF_RUNTRACE_LOG", &log)
        .env("BHF_RUNTRACE_MODE", "audit")
        .status()
        .unwrap();
    assert!(status.success());

    // One JSON object per line: `{"e":"insecure_mkdir","a":API,"p":PATH,"m":MODE}`.
    let text = std::fs::read_to_string(&log).unwrap_or_default();
    let reported: Vec<&str> = text
        .lines()
        .filter(|line| line.contains(r#""e":"insecure_mkdir""#))
        .collect();
    assert_eq!(reported.len(), 1, "{reported:?}");
    let event = reported[0];
    assert!(event.contains(r#""a":"mkdirat""#), "{event}");
    assert!(
        event.contains(&format!(r#""p":"{}""#, open.display())),
        "{event}"
    );
    assert!(event.contains(&format!(r#""m":{}"#, 0o777)), "{event}");
}
