// SPDX-License-Identifier: Apache-2.0

//! The self-cleaning `TestDir` guard (`crates/cli/src/test_support.rs`),
//! tested as the integration tests include it.

#[path = "../src/test_support.rs"]
mod test_support;

use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use test_support::{keep_requested, TestDir, KEEP_TEST_DIRS_ENV};

/// Set on a re-run of this test binary: the test that sees it plays the
/// child, which holds a `TestDir`, prints its path and, for the panic case,
/// fails.
const CHILD_ENV: &str = "BHF_TEST_DIR_GUARD_CHILD";
const PATH_MARKER: &str = "test-dir-guard-path=";

/// Re-run `test` alone in a fresh process whose temp dir is `tmp`, with the
/// keep variable set to `keep` (or removed), and return its exit status and
/// the path of the `TestDir` it held.
fn run_child(test: &str, tmp: &Path, keep: Option<&str>) -> (ExitStatus, PathBuf) {
    let mut cmd = Command::new(std::env::current_exe().expect("current test binary"));
    cmd.args([test, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, "1")
        .env("TMPDIR", tmp)
        .env("TMP", tmp)
        .env("TEMP", tmp);
    match keep {
        Some(value) => cmd.env(KEEP_TEST_DIRS_ENV, value),
        None => cmd.env_remove(KEEP_TEST_DIRS_ENV),
    };
    let output = cmd.output().expect("re-run the test binary");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // libtest prints `test <name> ... ` before the child's own output, on the
    // same line.
    let path = stdout
        .lines()
        .find_map(|line| {
            line.split_once(PATH_MARKER)
                .map(|(_, path)| path.trim_end())
        })
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            panic!(
                "child printed no {PATH_MARKER} line\nstdout:\n{stdout}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
    (output.status, path)
}

/// What the child does: hold a populated `TestDir` and report where it is.
fn child_holds_a_test_dir() -> TestDir {
    let dir = TestDir::new("guard-child");
    std::fs::create_dir_all(dir.join("nested")).unwrap();
    std::fs::write(dir.join("nested").join("evidence.bin"), b"\x00\x01").unwrap();
    println!("{PATH_MARKER}{}", dir.display());
    dir
}

#[test]
fn test_dir_is_removed_after_a_panic() {
    if std::env::var_os(CHILD_ENV).is_some() {
        let _dir = child_holds_a_test_dir();
        panic!("the test holding the TestDir fails");
    }
    let tmp = TestDir::create("guard-parent", false).unwrap();
    let (status, path) = run_child("test_dir_is_removed_after_a_panic", &tmp, None);
    assert!(!status.success(), "the child test must fail: {status}");
    assert!(
        path.starts_with(tmp.path()),
        "the child used the temp dir it was given: {}",
        path.display()
    );
    let name = path.file_name().unwrap().to_string_lossy().into_owned();
    assert!(name.starts_with("bhf-guard-child-"), "{name}");
    assert!(
        !path.exists(),
        "a panicking test removes its TestDir: {}",
        path.display()
    );
}

#[test]
fn test_dir_is_kept_when_keep_env_is_set() {
    if std::env::var_os(CHILD_ENV).is_some() {
        let _dir = child_holds_a_test_dir();
        return;
    }
    let tmp = TestDir::create("guard-parent", false).unwrap();
    let (status, path) = run_child("test_dir_is_kept_when_keep_env_is_set", &tmp, Some("1"));
    assert!(status.success(), "the child test passes: {status}");
    assert!(path.starts_with(tmp.path()), "{}", path.display());
    assert_eq!(
        std::fs::read(path.join("nested").join("evidence.bin")).unwrap(),
        b"\x00\x01",
        "{KEEP_TEST_DIRS_ENV}=1 keeps the dir and its contents"
    );

    let (status, path) = run_child("test_dir_is_kept_when_keep_env_is_set", &tmp, Some("0"));
    assert!(status.success(), "the child test passes: {status}");
    assert!(
        !path.exists(),
        "{KEEP_TEST_DIRS_ENV}=0 removes the dir: {}",
        path.display()
    );
}

#[test]
fn test_dir_is_removed_when_dropped_even_without_write_permission() {
    let dir = TestDir::create("guard-perm", false).unwrap();
    let path = dir.to_path_buf();
    let locked = dir.join("locked");
    std::fs::create_dir_all(&locked).unwrap();
    std::fs::write(locked.join("file"), b"x").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).unwrap();
    }
    #[cfg(not(unix))]
    {
        let mut permissions = std::fs::metadata(locked.join("file"))
            .unwrap()
            .permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(locked.join("file"), permissions).unwrap();
    }
    assert!(path.is_dir());
    drop(dir);
    assert!(!path.exists(), "{}", path.display());
}

#[test]
fn a_respelled_test_dir_still_removes_the_dir_it_created() {
    let dir = TestDir::create("guard-spelled", false).unwrap();
    let created = dir.path().to_path_buf();
    let alias = created.with_extension("alias");
    let dir = dir.spelled_as(|_| alias.clone());
    assert_eq!(dir.path(), alias);
    assert_eq!(dir.join("x"), alias.join("x"));
    assert!(created.is_dir());
    drop(dir);
    assert!(!created.exists(), "{}", created.display());
}

#[test]
fn try_new_reports_a_temp_dir_it_cannot_create() {
    if std::env::var_os(CHILD_ENV).is_some() {
        // The child's temp dir is a file, so nothing can be created in it.
        let error = TestDir::try_new("guard-unwritable").unwrap_err();
        println!("{PATH_MARKER}{error}");
        return;
    }
    let tmp = TestDir::create("guard-parent", false).unwrap();
    let not_a_dir = tmp.join("file");
    std::fs::write(&not_a_dir, b"").unwrap();
    let (status, _) = run_child(
        "try_new_reports_a_temp_dir_it_cannot_create",
        &not_a_dir,
        None,
    );
    assert!(status.success(), "try_new returned an error: {status}");
}

#[test]
fn keep_is_requested_by_any_value_but_empty_or_zero() {
    assert!(!keep_requested(None));
    assert!(!keep_requested(Some("".into())));
    assert!(!keep_requested(Some("0".into())));
    assert!(keep_requested(Some("1".into())));
    assert!(keep_requested(Some("yes".into())));
}

#[test]
fn test_dir_derefs_to_its_path_and_debug_prints_it() {
    let dir = TestDir::create("guard-deref", false).unwrap();
    let name = dir.file_name().unwrap().to_string_lossy().into_owned();
    assert!(name.starts_with("bhf-guard-deref-"), "{name}");
    assert!(dir.is_dir());
    std::fs::write(dir.join("a"), b"x").unwrap();
    assert!(std::fs::metadata(&dir).unwrap().is_dir());
    assert_eq!(format!("{dir:?}"), format!("{:?}", dir.path()));
}
