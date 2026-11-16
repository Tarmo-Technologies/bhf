// SPDX-License-Identifier: Apache-2.0

//! With `BHF_TEST_BIN` set, the support helpers run that prebuilt bhf, with
//! the runtrace shim beside it, and never cargo: the heavy tests used to
//! `cargo run --release` bhf, and build the shim, inside the test, counting
//! that build against their deadlines. The nightly builds both once.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn env_of<'a>(cmd: &'a Command, key: &str) -> Option<&'a std::ffi::OsStr> {
    cmd.get_envs()
        .find(|(name, _)| *name == key)
        .and_then(|(_, value)| value)
}

#[test]
fn with_bhf_test_bin_the_helpers_run_it_and_never_cargo() {
    let dir = TestDir::new("support-test-bin");
    let bin = dir.join("bhf");
    std::fs::write(&bin, "#!/bin/sh\necho prebuilt \"$@\"\n").unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let shim = dir.join("libbhf_runtrace_shim.so");
    std::fs::write(&shim, b"").unwrap();
    // This binary's only test, so nothing else reads the environment it sets.
    std::env::set_var("BHF_TEST_BIN", &bin);
    std::env::remove_var("BHF_RUNTRACE_SHIM");

    let mut cmd = support::bhf_cargo_command();
    assert_eq!(
        cmd.get_program(),
        bin.as_os_str(),
        "the prebuilt bhf runs, not cargo"
    );
    assert_eq!(cmd.get_args().count(), 0, "no `run --release --`");
    assert_eq!(env_of(&cmd, "BHF_RUNTRACE_SHIM"), Some(shim.as_os_str()));
    let out = cmd.arg("--version").output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "prebuilt --version\n");

    // A command a test builds itself gets the same shim, and no shim build.
    let mut other = Command::new("true");
    support::configure_runtrace_shim(&mut other);
    assert_eq!(env_of(&other, "BHF_RUNTRACE_SHIM"), Some(shim.as_os_str()));

    // Without BHF_TEST_BIN the helper is `cargo run --release`.
    let cargo = support::bhf_command_with(None);
    assert!(
        Path::new(cargo.get_program()).ends_with("cargo")
            || cargo.get_program().to_string_lossy().contains("cargo"),
        "{:?}",
        cargo.get_program()
    );
    assert!(cargo.get_args().any(|arg| arg == "--release"));
}
