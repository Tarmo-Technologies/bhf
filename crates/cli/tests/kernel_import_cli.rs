// SPDX-License-Identifier: Apache-2.0

//! `bhf kernel import` of syzkaller crash directories into `results/`.
//!
//! The recorded crash (`tests/fixtures/kernel_widget/crashes/`) is a
//! syz-manager crash directory, `description`, `report0`, `log0`, `tag0`,
//! `repro.prog` and `repro.cprog` in the layout syz-manager writes them, of
//! the slab-out-of-bounds write planted in the widget driver fixture
//! (`tests/fixtures/kernel_widget/linux`), whose lines the report's frames
//! name. It always runs.
//!
//! `a_fresh_syz_manager_workdir_imports` imports the crashes of a real
//! syz-manager run: it runs where `BHF_SYZKALLER_CLI=1`, with
//! `BHF_SYZKALLER_WORKDIR` naming the workdir (one with `crashes/`). With
//! `BHF_REQUIRE_TOOLS=1` a missing workdir fails the test.

use serde_json::Value;
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

fn import(crashes: &Path, work: &Path, source_root: Option<&Path>) -> Output {
    let mut command = bhf();
    command
        .args(["kernel", "import"])
        .arg(crashes)
        .arg("--work-dir")
        .arg(work);
    if let Some(root) = source_root {
        command.arg("--source-root").arg(root);
    }
    command.output().expect("bhf runs")
}

fn findings(work: &Path) -> Vec<Value> {
    let doc: Value =
        serde_json::from_slice(&fs::read(work.join("results/findings.json")).unwrap()).unwrap();
    doc["findings"].as_array().unwrap().clone()
}

#[test]
fn the_recorded_crash_imports_with_its_class_and_reproducer() {
    let work = TestDir::new("kernel-import");
    let output = import(
        &fixture().join("crashes"),
        &work,
        Some(&fixture().join("linux")),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains(
            ": KASAN: slab-out-of-bounds Write in widget_copy_at (slab-out-of-bounds, reproducer: repro.c)"
        ),
        "{stdout}"
    );
    let findings = findings(&work);
    assert_eq!(findings.len(), 1, "{findings:#?}");
    let finding = &findings[0];
    let id = finding["id"].as_str().unwrap();
    assert!(id.starts_with("F-KERNEL-0000-"), "{id}");
    assert_eq!(finding["producer"], "kernel import");
    // The class.
    assert_eq!(finding["fuzz"]["exception"]["name"], "SLAB_OUT_OF_BOUNDS");
    assert_eq!(finding["fuzz"]["exception"]["sanitizer"], "kasan");
    assert_eq!(finding["rule"]["id"], "BHF-201");
    assert_eq!(finding["cwe"], serde_json::json!([122, 787]));
    assert_eq!(finding["confirmation"]["level"], "sanitizer_crash");
    assert_eq!(finding["location"]["file"], "drivers/misc/widget.c");
    assert_eq!(finding["location"]["line"], 46);
    assert_eq!(finding["location"]["function"], "widget_copy_at");
    // The recorded report names the fixture driver's own lines.
    let driver = fs::read_to_string(fixture().join("linux/drivers/misc/widget.c")).unwrap();
    let line = |number: usize| driver.lines().nth(number - 1).unwrap_or("").trim();
    assert!(line(46).starts_with("memcpy(state->slots"), "{}", line(46));
    assert!(line(27).contains("kzalloc"), "{}", line(27));
    assert!(line(60).contains("widget_copy_at("), "{}", line(60));
    assert!(line(98).contains("widget_do_xfer("), "{}", line(98));
    assert_eq!(finding["fuzz"]["access"]["direction"], "write");
    assert_eq!(finding["fuzz"]["access"]["region"]["size"], 104);
    // The reproducer.
    assert_eq!(
        finding["reproduce"]["command"],
        format!("gcc -pthread -o repro findings/{id}/repro.c && ./repro")
    );
    let roles: Vec<&str> = finding["evidence"]["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|file| file["role"].as_str().unwrap())
        .collect();
    for role in ["sanitizer_log", "console_log", "repro_syz", "repro_c"] {
        assert!(roles.contains(&role), "{role}: {roles:?}");
    }
    let dir = work.join("results/findings").join(id);
    assert_eq!(
        fs::read(dir.join("repro.c")).unwrap(),
        fs::read(fixture().join("crashes/330f1cd22e8dec39433794b0af2230020ad97506/repro.cprog"))
            .unwrap()
    );
    // The options syz-manager wrote atop repro.prog, in Go's `%+v` form.
    let raw: Value = serde_json::from_slice(&fs::read(dir.join("finding.json")).unwrap()).unwrap();
    let options = &raw["kernel"]["reproducer"]["options"];
    assert_eq!(options["procs"], 1, "{options}");
    assert_eq!(options["threaded"], false, "{options}");
    assert_eq!(options["sandbox"], "", "{options}");
    // Reached through the syscalls of syzkaller's program in its VM, not
    // through a harness input.
    let entry =
        serde_json::json!({"kind": "syscall", "source": "repro.syz", "target": "widget_copy_at"});
    assert_eq!(finding["reachability"], entry);
    let sarif: Value =
        serde_json::from_slice(&fs::read(work.join("results/findings.sarif")).unwrap()).unwrap();
    assert_eq!(
        sarif["runs"][0]["results"][0]["properties"]["actionabilityEntryPath"],
        entry
    );
    let index = fs::read_to_string(work.join("results/INDEX.md")).unwrap();
    assert!(index.contains("widget_copy_at"), "{index}");
    let manifest: Value =
        serde_json::from_slice(&fs::read(work.join("results/manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["producers"][0]["command"], "kernel import");

    // Importing it again updates the same finding.
    let again = import(
        &fixture().join("crashes"),
        &work,
        Some(&fixture().join("linux")),
    );
    assert!(again.status.success());
    assert!(String::from_utf8_lossy(&again.stdout).contains(&format!("updated {id}:")));
    assert_eq!(self::findings(&work).len(), 1);
}

#[test]
fn a_directory_with_no_crash_imports_nothing_and_fails() {
    let work = TestDir::new("kernel-import-none");
    let output = import(&fixture().join("linux"), &work.join("work"), None);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no syzkaller crash directory"), "{stderr}");
    assert!(!work.join("work").exists(), "no work dir is created");
}

/// A syz-manager workdir with crashes, when this run tests against
/// syzkaller and one is there.
fn syz_manager_workdir() -> Option<PathBuf> {
    if std::env::var_os("BHF_SYZKALLER_CLI").is_none_or(|value| value != "1") {
        eprintln!("skip kernel_import_cli: set BHF_SYZKALLER_CLI=1 and BHF_SYZKALLER_WORKDIR to a syz-manager workdir");
        return None;
    }
    let workdir = std::env::var_os("BHF_SYZKALLER_WORKDIR").map(PathBuf::from);
    let available = workdir.as_ref().is_some_and(|dir| {
        fs::read_dir(dir.join("crashes")).is_ok_and(|mut entries| entries.next().is_some())
    });
    support::require_tool(available, "a syz-manager workdir with crashes").then(|| workdir.unwrap())
}

#[test]
fn a_fresh_syz_manager_workdir_imports() {
    let Some(workdir) = syz_manager_workdir() else {
        return;
    };
    let work = TestDir::new("kernel-import-fresh");
    let output = import(&workdir, &work, None);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let findings = findings(&work);
    assert!(!findings.is_empty(), "{stdout}");
    for finding in &findings {
        assert_eq!(finding["producer"], "kernel import");
        assert!(
            finding["fuzz"]["exception"]["name"]
                .as_str()
                .is_some_and(|name| !name.is_empty()),
            "{finding:#}"
        );
        let id = finding["id"].as_str().unwrap();
        let dir = work.join("results/findings").join(id);
        let raw: Value =
            serde_json::from_slice(&fs::read(dir.join("finding.json")).unwrap()).unwrap();
        let crash = workdir
            .join("crashes")
            .join(raw["kernel"]["crash_dir"].as_str().unwrap());
        let has_repro = crash.join("repro.prog").is_file() || crash.join("repro.cprog").is_file();
        assert_eq!(
            finding["reproduce"]["command"].is_string(),
            has_repro,
            "{finding:#}"
        );
    }
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A kernel crash ran in a kernel, which no harness replays: `bhf replay`
/// and `bhf minimize` say what reproduces it instead of looking for a
/// harness, and `bhf explain` shows its program and that command.
#[test]
fn the_triage_commands_point_a_kernel_crash_at_what_reproduces_it() {
    use results::import_syzkaller as kernel;
    // A crash `bhf kernel fuzz` found in its guest, written as it writes one.
    let work = TestDir::new("kernel-guest-triage");
    let console =
        fs::read_to_string(fixture().join("../kernel_guest/console/kasan-slab-out-of-bounds.log"))
            .unwrap();
    let report = kernel::console_report(&console).unwrap();
    let program_text =
        "r0 = openat(0xffffffffffffff9c, &(0x20000000)=\"/dev/widget\\x00\", 0x2, 0x0)\n\
                        r1 = ioctl(r0, 0xc0285703, &(0x20000010)=x\"0400\")\n";
    let found = kernel::record_guest_crash(
        &work,
        &kernel::GuestCrash {
            report: &report,
            console: &console,
            program: b"\x00\x04program",
            program_text,
            decoded: &serde_json::json!({"calls": []}),
            c_repro: "int main(void) { return 0; }\n",
            guest: &serde_json::json!({"kernel": "/k/bzImage"}),
            reproduced: false,
            unconfirmed: Some("its confirming run could not be made: the guest did not start"),
            release: Some("6.12.118"),
        },
    )
    .unwrap();
    let dir = work.join("results/findings").join(&found.id);
    let replay_hint = format!("`bhf kernel replay {}`", dir.display());
    for command in ["replay", "minimize"] {
        let output = bhf().arg(command).arg(&dir).output().unwrap();
        let stderr = stderr_of(&output);
        assert_eq!(output.status.code(), Some(1), "{command}: {stderr}");
        assert!(
            stderr.contains(&format!(
                "{} is a kernel crash bhf kernel fuzz found in a qemu-system guest",
                found.id
            )) && stderr.contains(&replay_hint),
            "{command}: {stderr}"
        );
        assert!(!stderr.contains("harness binary"), "{command}: {stderr}");
    }
    let output = bhf()
        .args(["explain", "--work-dir"])
        .arg(&work)
        .args(["--finding-id", &found.id])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}\n{}", stderr_of(&output));
    assert!(
        stdout.contains(&format!(
            "━━━ {} — KASAN: slab-out-of-bounds Write in widget_ioctl (CWE-122, BHF-201) ━━━",
            found.id
        )),
        "{stdout}"
    );
    assert!(
        stdout.contains("the guest kernel's KASAN report"),
        "{stdout}"
    );
    let program = stdout
        .split("THE PROGRAM  (program.txt: the calls testcase.bin makes, in order)")
        .nth(1)
        .unwrap_or_else(|| panic!("no program in {stdout}"));
    assert!(program.contains("  r1 = ioctl(r0, 0xc0285703"), "{stdout}");
    let reproduce = stdout.split("REPRODUCE OFFLINE").nth(1).unwrap();
    assert!(
        reproduce.contains(&format!("bhf kernel replay {}", dir.display())),
        "{reproduce}"
    );
    assert!(
        reproduce.contains(&format!("{}", dir.join("repro.c").display())),
        "{reproduce}"
    );
    assert!(
        reproduce
            .contains("(not confirmed when it was found: its confirming run could not be made"),
        "{reproduce}"
    );
    for harness_only in [
        "bhf replay --show-args",
        "No offline reproducer is available",
        "bhf capsule",
        "HARNESS ARGUMENTS",
        "FAKED ENVIRONMENT",
        "No comparison evidence",
    ] {
        assert!(!stdout.contains(harness_only), "{harness_only}: {stdout}");
    }

    // A crash syzkaller found: its reproducer runs in the kernel's test VM.
    let imported = TestDir::new("kernel-import-triage");
    let output = import(&fixture().join("crashes"), &imported, None);
    assert!(output.status.success(), "{}", stderr_of(&output));
    let id = findings(&imported)[0]["id"].as_str().unwrap().to_owned();
    let dir = imported.join("results/findings").join(&id);
    let output = bhf().arg("replay").arg(&dir).output().unwrap();
    let stderr = stderr_of(&output);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "{id} is a kernel crash syzkaller found (bhf kernel import)"
        )) && stderr.contains(&format!(
            "run `gcc -pthread -o repro findings/{id}/repro.c && ./repro` from the results \
             directory in the kernel's test VM"
        )),
        "{stderr}"
    );
    let output = bhf()
        .args(["explain", "--work-dir"])
        .arg(&imported)
        .args(["--finding-id", &id])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}\n{}", stderr_of(&output));
    let reproduce = stdout.split("REPRODUCE OFFLINE").nth(1).unwrap();
    assert!(
        reproduce.contains(&format!(
            "  gcc -pthread -o repro findings/{id}/repro.c && ./repro"
        )),
        "{reproduce}"
    );
    assert!(
        !stdout.contains("No offline reproducer is available"),
        "{stdout}"
    );
}
