// SPDX-License-Identifier: Apache-2.0

//! The license profile of the tools a run asks for by flag: the
//! `--external-tools` analyzers, `auto --symcc` and the `qemu-system:` lane's
//! `reset=fast`. A given `--profile` wins over `BHF_PROFILE`; without it,
//! `BHF_PROFILE` names the profile, and asking for the tool opts into
//! `external-tools`.

use std::path::PathBuf;
use std::process::{Command, Output};

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

/// `bhf <args>` with `BHF_PROFILE` set to `env_profile`, or unset.
fn bhf(args: &[&str], env_profile: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bhf"));
    command.args(args).env_remove("BHF_PROFILE");
    if let Some(profile) = env_profile {
        command.env("BHF_PROFILE", profile);
    }
    command.output().expect("run bhf")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A one-file C tree with a function to fuzz.
fn c_tree(root: &TestDir) -> PathBuf {
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("record.c"),
        "int parse_record(const unsigned char *data, unsigned long size) {\n\
         \x20   return size > 2 ? data[0] : 0;\n}\n",
    )
    .unwrap();
    src
}

/// The profile `static-scan --external-tools` recorded in its findings file.
fn external_tools_profile(
    root: &TestDir,
    name: &str,
    profile: &[&str],
    env: Option<&str>,
) -> String {
    let src = c_tree(root);
    let out = root.join(name);
    let mut args = profile.to_vec();
    args.extend(["static-scan", src.to_str().unwrap(), "--external-tools"]);
    args.extend(["--out", out.to_str().unwrap()]);
    let output = bhf(&args, env);
    assert!(output.status.success(), "{}", stderr(&output));
    let findings: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("external-findings.json")).unwrap())
            .unwrap();
    findings["profile"].as_str().unwrap().to_owned()
}

#[test]
fn static_scan_external_tools_take_the_given_profile_over_bhf_profile() {
    let root = TestDir::new("profile-static-scan");
    let strict = ["--profile", "strict-permissive"];
    let lab = ["--profile", "research-lab"];
    assert_eq!(
        external_tools_profile(&root, "strict", &strict, Some("research-lab")),
        "strict-permissive"
    );
    assert_eq!(
        external_tools_profile(&root, "lab", &lab, Some("strict-permissive")),
        "research-lab"
    );
    assert_eq!(
        external_tools_profile(&root, "env", &[], Some("research-lab")),
        "research-lab"
    );
    assert_eq!(
        external_tools_profile(&root, "none", &[], None),
        "external-tools"
    );
}

#[test]
fn auto_symcc_is_refused_under_a_given_strict_profile() {
    let root = TestDir::new("profile-symcc");
    let src = c_tree(&root);
    let work = root.join("work");
    let output = bhf(
        &[
            "auto",
            src.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
            "--dry-run",
            "--symcc",
            "--profile",
            "strict-permissive",
        ],
        Some("research-lab"),
    );
    let stderr = stderr(&output);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains(
            "--symcc: the `strict-permissive` license profile does not allow SymCC (GPL-3.0) \
             to run; pass --profile external-tools or research-lab to allow it"
        ),
        "{stderr}"
    );
}

#[test]
fn fast_reset_is_refused_under_a_given_strict_profile() {
    let root = TestDir::new("profile-fast-reset");
    let work = root.join("work");
    let log = root.join("dirty.log");
    let spec = format!(
        "qemu-system:qmp=127.0.0.1:1,gdb=127.0.0.1:2,reset=fast,dirty_log={}",
        log.display()
    );
    let output = bhf(
        &[
            "--profile",
            "strict-permissive",
            "fuzz",
            "--target-transport",
            &spec,
            "--transport-coverage-map",
            "input=4096,input_cap=64,ring=16384,write=20480,wrapped=20736,cap=32",
            "--harness",
            "widget",
            "--iterations",
            "1",
            work.to_str().unwrap(),
        ],
        Some("research-lab"),
    );
    let stderr = stderr(&output);
    assert_eq!(output.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains("which the `strict-permissive` license profile does not allow"),
        "{stderr}"
    );
    assert!(
        !work.join("qemu-plugin").exists(),
        "nothing is built when refused"
    );
}

/// The fuzz workers a run starts gate their tools on the run's `--profile`:
/// each worker gets it on its command line, and a run that gives none
/// passes none, so its workers read `BHF_PROFILE` as it does.
#[cfg(unix)]
#[test]
fn fuzz_workers_take_the_given_profile() {
    use std::os::unix::fs::PermissionsExt;
    let root = TestDir::new("profile-workers");
    let work = root.join("work");
    let harness = work.join("build/H-WIDGET/obj/main");
    std::fs::create_dir_all(harness.parent().unwrap()).unwrap();
    std::fs::copy(env!("CARGO_BIN_EXE_cli_fake_harness"), &harness).unwrap();
    std::fs::set_permissions(&harness, std::fs::Permissions::from_mode(0o755)).unwrap();
    // A stand-in for the worker `bhf fuzz`: it writes down its arguments.
    let worker = root.join("worker.sh");
    std::fs::write(
        &worker,
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$WIDGET_ARGV_DIR/$BHF_WORKER_ID\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&worker, std::fs::Permissions::from_mode(0o755)).unwrap();
    let worker_args = |name: &str, profile: &[&str]| {
        let argv_dir = root.join(name);
        std::fs::create_dir_all(&argv_dir).unwrap();
        let mut args = profile.to_vec();
        args.extend(["fuzz", work.to_str().unwrap(), "--harness", "H-WIDGET"]);
        args.extend(["--iterations", "1", "--workers", "2"]);
        args.extend(["--bhf-bin", worker.to_str().unwrap()]);
        let output = Command::new(env!("CARGO_BIN_EXE_bhf"))
            .args(&args)
            .env("BHF_PROFILE", "research-lab")
            .env("WIDGET_ARGV_DIR", &argv_dir)
            .output()
            .expect("run bhf");
        assert!(output.status.success(), "{}", stderr(&output));
        (0..2)
            .map(|id| std::fs::read_to_string(argv_dir.join(id.to_string())).unwrap())
            .collect::<Vec<_>>()
    };
    for argv in worker_args("given", &["--profile", "strict-permissive"]) {
        assert!(argv.contains("\n--profile\nstrict-permissive\n"), "{argv}");
    }
    for argv in worker_args("none", &[]) {
        assert!(!argv.contains("--profile"), "{argv}");
    }
}
