// SPDX-License-Identifier: Apache-2.0

//! `bhf kernel syzlang` on the widget driver fixture
//! (`tests/fixtures/kernel_widget/linux`): the syzkaller description and its
//! `.const` file match the recorded snapshot, byte for byte.
//!
//! The snapshot is checked by syzkaller's own compiler in
//! `syz_sysgen_accepts_the_generated_description`, which needs a syzkaller
//! checkout and runs where `BHF_SYZKALLER_CLI=1`: `BHF_SYZKALLER` names the
//! checkout, and syz-sysgen is `BHF_SYZ_SYSGEN`, else the checkout's
//! `bin/syz-sysgen`, else `syz-sysgen` on `PATH`. With `BHF_REQUIRE_TOOLS=1`
//! a missing one fails the test.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn bhf() -> Command {
    Command::new(env!("CARGO_BIN_EXE_bhf"))
}

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/kernel_widget")
}

fn generate(out: &Path) -> Output {
    let output = bhf()
        .args(["kernel", "syzlang"])
        .arg(fixture().join("linux"))
        .arg("--out")
        .arg(out)
        .output()
        .expect("bhf runs");
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// `text` with Windows line endings (a checkout with autocrlf) as `\n`.
fn read_text(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
        .replace("\r\n", "\n")
}

#[test]
fn the_widget_driver_matches_the_recorded_description() {
    let out = TestDir::new("kernel-syzlang");
    let output = generate(&out);
    for name in ["dev_widget.txt", "dev_widget.txt.const"] {
        let generated = read_text(&out.join(name));
        let expected = read_text(&fixture().join(name));
        assert!(
            generated == expected,
            "{name} differs from tests/fixtures/kernel_widget/{name}:\n--- generated\n{generated}\n--- expected\n{expected}"
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("described 6 ioctl commands of widget_ioctl"),
        "{stdout}"
    );
}

/// syzkaller's compiler rejects a comment that reads like a directive
/// (`confusingComment` in pkg/compiler/check.go): the widget header lives
/// under include/, where every uapi header does.
#[test]
fn no_comment_of_the_description_reads_as_a_directive() {
    let out = TestDir::new("kernel-syzlang-comments");
    generate(&out);
    let text = read_text(&out.join("dev_widget.txt"));
    let directive = regex::Regex::new(r"^#\s*(include|incdir|define)").unwrap();
    let faking: Vec<&str> = text
        .lines()
        .filter(|line| directive.is_match(line))
        .collect();
    assert!(faking.is_empty(), "{faking:#?}");
    assert!(
        text.contains("# WIDGET_IOC_RESET defined at include/uapi/linux/widget.h:50:"),
        "{text}"
    );
}

#[test]
fn a_tree_with_no_ioctl_handler_fails_with_the_reason() {
    let out = TestDir::new("kernel-syzlang-none");
    let output = bhf()
        .args(["kernel", "syzlang"])
        .arg(fixture().join("linux/include"))
        .arg("--out")
        .arg(out.join("out"))
        .output()
        .expect("bhf runs");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no ioctl handler found"), "{stderr}");
    assert!(!out.join("out").exists(), "nothing is written");
}

/// syz-sysgen, and the syzkaller checkout it compiles, when this run tests
/// against syzkaller and both are there.
fn syzkaller() -> Option<(PathBuf, PathBuf)> {
    if std::env::var_os("BHF_SYZKALLER_CLI").is_none_or(|value| value != "1") {
        eprintln!("skip kernel_syzlang_cli: set BHF_SYZKALLER_CLI=1 and BHF_SYZKALLER to a syzkaller checkout");
        return None;
    }
    let checkout = std::env::var_os("BHF_SYZKALLER").map(PathBuf::from);
    let checkout_ok = checkout
        .as_ref()
        .is_some_and(|dir| dir.join("sys/linux").is_dir());
    let sysgen = std::env::var_os("BHF_SYZ_SYSGEN")
        .map(PathBuf::from)
        .or_else(|| {
            checkout
                .as_ref()
                .map(|dir| dir.join("bin/syz-sysgen"))
                .filter(|path| path.is_file())
        })
        .or_else(|| which::which("syz-sysgen").ok());
    let available = checkout_ok && sysgen.is_some();
    support::require_tool(available, "syzkaller checkout and syz-sysgen")
        .then(|| (checkout.unwrap(), sysgen.unwrap()))
}

/// Copy `from` to `to`, recursively, skipping `.git`.
fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap().flatten() {
        let path = entry.path();
        let target = to.join(entry.file_name());
        let kind = entry.file_type().unwrap();
        if kind.is_dir() {
            if entry.file_name() != ".git" {
                copy_tree(&path, &target);
            }
        } else if kind.is_file() {
            fs::copy(&path, &target).unwrap();
        }
    }
}

#[test]
fn syz_sysgen_accepts_the_generated_description() {
    let Some((checkout, sysgen)) = syzkaller() else {
        return;
    };
    let work = TestDir::new("kernel-syzlang-sysgen");
    // syz-sysgen compiles every description under sys/ and writes what it
    // generates beside them: a copy of the checkout's sys/ keeps the
    // checkout untouched.
    copy_tree(&checkout.join("sys"), &work.join("sys"));
    fs::create_dir_all(work.join("executor")).unwrap();
    generate(&work.join("sys/linux"));
    let output = Command::new(&sysgen)
        .current_dir(&work)
        .output()
        .expect("syz-sysgen runs");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "syz-sysgen rejected the description:\n{}\n{stderr}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        !stderr.contains("dev_widget.txt"),
        "syz-sysgen warned about the description:\n{stderr}"
    );
    // It compiled the variants: syz-sysgen writes each syscall's name into
    // what it generates (the executor's syscall table, the Go tables).
    let mut generated = Vec::new();
    files_under(&work, &mut generated);
    assert!(
        generated
            .iter()
            .filter(
                |path| !path.ends_with("dev_widget.txt") && !path.ends_with("dev_widget.txt.const")
            )
            .any(|path| fs::read(path).is_ok_and(|bytes| {
                bytes
                    .windows(b"ioctl$WIDGET_IOC_XFER".len())
                    .any(|window| window == b"ioctl$WIDGET_IOC_XFER")
            })),
        "syz-sysgen generated nothing for the widget syscalls"
    );
}

fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => files_under(&path, out),
            Ok(kind) if kind.is_file() => out.push(path),
            _ => {}
        }
    }
}
