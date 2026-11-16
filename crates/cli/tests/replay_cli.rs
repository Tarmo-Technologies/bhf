// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

const CANONICAL_SIGNATURE: &str =
    "20b41fb2a2ceeabc9f0403546af14199d4ccacc54e55f6fcb5855015b5eb63bd";

#[test]
fn replay_subcommand_match_returns_zero() {
    let (_root, finding_dir) = write_finding("match");

    assert_eq!(
        cli::run_from([
            "bhf",
            "replay",
            finding_dir.to_str().unwrap(),
            "--harness",
            fake_harness().to_str().unwrap(),
        ]),
        0
    );
}

#[test]
fn replay_subcommand_accepts_finding_flag() {
    let (_root, finding_dir) = write_finding("match");

    assert_eq!(
        cli::run_from([
            "bhf",
            "replay",
            "--finding",
            finding_dir.to_str().unwrap(),
            "--harness",
            fake_harness().to_str().unwrap(),
        ]),
        0
    );
}

#[test]
fn replay_subcommand_resolves_bare_finding_id_under_findings_root() {
    let root = temp_dir("bare-id");
    let finding_id = "F-0000-test";
    write_finding_at(&root.join("findings").join(finding_id), "match");

    let output = Command::new(env!("CARGO_BIN_EXE_cli"))
        .current_dir(&root)
        .args([
            "replay",
            "--finding",
            finding_id,
            "--harness",
            fake_harness().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn replay_subcommand_resolves_bare_finding_id_under_results_findings() {
    // Mirrors the legacy test for the results layout: run from inside the work
    // dir, the bare id resolves via `./results/findings/<id>`.
    let root = temp_dir("bare-id-results");
    let finding_id = "F-0000-test";
    write_finding_at(
        &root.join("results").join("findings").join(finding_id),
        "match",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_cli"))
        .current_dir(&root)
        .args([
            "replay",
            "--finding",
            finding_id,
            "--harness",
            fake_harness().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn replay_subcommand_qemu_user_wraps_harness() {
    let root = temp_dir("qemu-user");
    let qemu_path = root.join("fake-qemu-aarch64");
    let qemu_log = root.join("qemu-argv.txt");
    write_fake_qemu_user(&qemu_path);
    let (_root, finding_dir) = write_finding("match");

    let exit = cli::run_from([
        "bhf",
        "replay",
        finding_dir.to_str().unwrap(),
        "--harness",
        fake_harness().to_str().unwrap(),
        "--qemu-user",
        qemu_path.to_str().unwrap(),
        "--qemu-arg=-L",
        "--qemu-arg=/opt/aarch64-sysroot",
    ]);

    assert_eq!(exit, 0);
    assert_eq!(
        fs::read_to_string(qemu_log).unwrap(),
        format!("-L\n/opt/aarch64-sysroot\n{}\n", fake_harness().display())
    );
}

#[cfg(unix)]
#[test]
fn replay_subcommand_firejail_sandbox_wraps_harness() {
    let root = temp_dir("firejail-sandbox");
    let sandbox_path = root.join("fake-firejail");
    let sandbox_log = root.join("sandbox-argv.txt");
    write_fake_sandbox(&sandbox_path);
    let (_root, finding_dir) = write_finding("match");

    let exit = cli::run_from([
        "bhf",
        "replay",
        finding_dir.to_str().unwrap(),
        "--harness",
        fake_harness().to_str().unwrap(),
        "--sandbox",
        "firejail",
        "--sandbox-tool",
        sandbox_path.to_str().unwrap(),
    ]);

    assert_eq!(exit, 0);
    let sandbox_argv = fs::read_to_string(sandbox_log).unwrap();
    assert!(sandbox_argv.contains("--net=none\n"));
    assert!(sandbox_argv.contains("--\n"));
    assert!(sandbox_argv.contains(&format!("{}\n", fake_harness().display())));
}

#[test]
fn replay_subcommand_strict_missing_sandbox_returns_one() {
    let root = temp_dir("strict-missing-sandbox");
    let (_root, finding_dir) = write_finding("match");

    assert_eq!(
        cli::run_from([
            "bhf",
            "replay",
            finding_dir.to_str().unwrap(),
            "--harness",
            fake_harness().to_str().unwrap(),
            "--sandbox",
            "firejail",
            "--sandbox-tool",
            root.join("missing-firejail").to_str().unwrap(),
            "--sandbox-strict",
        ]),
        1
    );
}

// --- #81: the C/C++ replay paths must honor --qemu-user / sandbox too ---

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).unwrap();
}

/// A minimal C/C++ finding (rule_id + testcase) the C replay paths expect.
#[cfg(unix)]
fn write_c_finding(root: &Path) -> PathBuf {
    let finding = root.join("finding");
    fs::create_dir_all(&finding).unwrap();
    fs::write(finding.join("finding.json"), r#"{"rule_id":"BHF-210"}"#).unwrap();
    fs::write(finding.join("testcase.bin"), b"input").unwrap();
    finding
}

#[cfg(unix)]
#[test]
fn replay_c_afl_routes_through_qemu_user() {
    // A CAfl harness (detected by the `main_afl` filename) reads stdin. Before
    // the fix, replay_c_afl spawned a bare Command::new(harness) and ignored
    // --qemu-user entirely; now it wraps through the runner (#81).
    let root = temp_dir("c-afl-qemu");
    let harness = root.join("main_afl");
    fs::write(&harness, "#!/bin/sh\ncat >/dev/null\nexit 0\n").unwrap();
    make_executable(&harness);
    let qemu = root.join("fake-qemu");
    write_fake_qemu_user(&qemu);
    let finding_dir = write_c_finding(&root);

    let exit = cli::run_from([
        "bhf",
        "replay",
        finding_dir.to_str().unwrap(),
        "--harness",
        harness.to_str().unwrap(),
        "--qemu-user",
        qemu.to_str().unwrap(),
        "--qemu-arg=-L",
        "--qemu-arg=/opt/sysroot",
    ]);

    // A clean harness reproduces no crash -> MISMATCH (3); the point is that it
    // ran THROUGH the qemu-user wrapper, which recorded the wrapped argv.
    assert_eq!(
        exit, 3,
        "clean C-AFL harness -> MISMATCH, but via the wrapper"
    );
    assert_eq!(
        fs::read_to_string(root.join("qemu-argv.txt")).unwrap(),
        format!("-L\n/opt/sysroot\n{}\n", harness.display()),
        "the C-AFL replay must wrap the harness under qemu-user"
    );
}

#[cfg(unix)]
#[test]
fn replay_c_libfuzzer_routes_through_sandbox_with_testcase_argv() {
    // A CLibFuzzer harness (detected by a sibling main.c carrying BHF_FRAMED)
    // takes the testcase as argv[1]. The fix routes it through the sandbox while
    // preserving that argv protocol (#81).
    let root = temp_dir("c-libfuzzer-sandbox");
    fs::write(
        root.join("main.c"),
        "/* BHF_FRAMED driver */\nint main(){return 0;}\n",
    )
    .unwrap();
    let harness = root.join("main");
    fs::write(
        &harness,
        "#!/bin/sh\nprintf '%s' \"$1\" > \"$(dirname \"$0\")/harness-argv1.txt\"\nexit 0\n",
    )
    .unwrap();
    make_executable(&harness);
    let sandbox = root.join("fake-firejail");
    write_fake_sandbox(&sandbox);
    let finding_dir = write_c_finding(&root);

    let exit = cli::run_from([
        "bhf",
        "replay",
        finding_dir.to_str().unwrap(),
        "--harness",
        harness.to_str().unwrap(),
        "--sandbox",
        "firejail",
        "--sandbox-tool",
        sandbox.to_str().unwrap(),
    ]);

    assert_eq!(
        exit, 3,
        "clean C-libFuzzer harness -> MISMATCH, but via the sandbox"
    );
    let sandbox_argv = fs::read_to_string(root.join("sandbox-argv.txt")).unwrap();
    assert!(
        sandbox_argv.contains(&format!("{}\n", harness.display())),
        "the C-libFuzzer replay must wrap the harness under the sandbox: {sandbox_argv}"
    );
    // The testcase was delivered as argv[1] (libFuzzer protocol), not stdin.
    let argv1 = fs::read_to_string(root.join("harness-argv1.txt")).unwrap();
    assert!(
        argv1.ends_with("testcase.bin"),
        "the libFuzzer testcase must be argv[1]: {argv1}"
    );
}

/// A finding written before UBSan checks had their own rules was recorded under
/// the generic rule; replaying it must still MATCH the same report, and the
/// replay runs with the fuzz child's UBSan options.
#[cfg(unix)]
#[test]
fn replay_c_libfuzzer_matches_a_finding_recorded_under_an_earlier_rule() {
    let root = temp_dir("c-libfuzzer-legacy-rule");
    fs::write(
        root.join("main.c"),
        "/* BHF_FRAMED driver */\nint main(){return 0;}\n",
    )
    .unwrap();
    let harness = root.join("main");
    fs::write(
        &harness,
        "#!/bin/sh\nprintf '%s' \"$UBSAN_OPTIONS\" > \"$(dirname \"$0\")/ubsan-options.txt\"\n\
         echo '/src/widget/classify.cc:3:5: runtime error: execution reached the end of a value-returning function without returning a value' >&2\n\
         echo 'SUMMARY: UndefinedBehaviorSanitizer: missing-return /src/widget/classify.cc:3:5 ' >&2\n\
         exit 1\n",
    )
    .unwrap();
    make_executable(&harness);
    let finding_dir = write_c_finding(&root);
    // The records name no crash location, so they are checked against the
    // build they were recorded with.
    let record = |rule: &str| {
        let value = serde_json::json!({
            "rule_id": rule,
            "build": {"binary": {"sha256": sha256_hex(&harness)}},
        });
        fs::write(finding_dir.join("finding.json"), value.to_string()).unwrap();
    };
    let replay = || {
        cli::run_from([
            "bhf",
            "replay",
            finding_dir.to_str().unwrap(),
            "--harness",
            harness.to_str().unwrap(),
        ])
    };
    record("BHF-210");
    assert_eq!(replay(), 0, "an older BHF-210 record still matches");
    let options = fs::read_to_string(root.join("ubsan-options.txt")).unwrap();
    assert!(options.contains("print_stacktrace=1"), "{options}");
    assert!(options.contains("report_error_type=1"), "{options}");
    record("BHF-214");
    assert_eq!(replay(), 0, "today's rule matches");
    record("BHF-202");
    assert_eq!(replay(), 3, "an unrelated rule does not");
}

/// The sha256 of `path`, as `build.binary.sha256` records it.
#[cfg(unix)]
fn sha256_hex(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    corpus::hex_lower(&Sha256::digest(fs::read(path).unwrap()))
}

#[cfg(unix)]
#[test]
fn replay_c_afl_strict_missing_sandbox_is_an_early_error() {
    // A requested strict sandbox that is unavailable must fail the C replay, not
    // be silently skipped (#81).
    let root = temp_dir("c-afl-strict-sandbox");
    let harness = root.join("main_afl");
    fs::write(&harness, "#!/bin/sh\ncat >/dev/null\nexit 0\n").unwrap();
    make_executable(&harness);
    let finding_dir = write_c_finding(&root);

    assert_eq!(
        cli::run_from([
            "bhf",
            "replay",
            finding_dir.to_str().unwrap(),
            "--harness",
            harness.to_str().unwrap(),
            "--sandbox",
            "firejail",
            "--sandbox-tool",
            root.join("missing-firejail").to_str().unwrap(),
            "--sandbox-strict",
        ]),
        1,
        "a strict missing sandbox must be an error on the C path, not a silent bypass"
    );
}

#[test]
fn replay_subcommand_mismatch_returns_three() {
    let (_root, finding_dir) = write_finding("mismatch");

    assert_eq!(
        cli::run_from([
            "bhf",
            "replay",
            finding_dir.to_str().unwrap(),
            "--harness",
            fake_harness().to_str().unwrap(),
        ]),
        3
    );
}

#[test]
fn replay_subcommand_auto_resolves_harness_from_fixture_path() {
    // No --harness: the finding records `fixture_path`, so replay resolves the
    // built harness itself and still reproduces (MATCH -> exit 0).
    let (_root, finding_dir) = write_finding_with_fixture("match", fake_harness());

    assert_eq!(
        cli::run_from(["bhf", "replay", finding_dir.to_str().unwrap(),]),
        0
    );
}

#[test]
fn replay_subcommand_auto_resolves_harness_from_harness_id_layout() {
    // No --harness, no fixture_path: resolve `<work>/harnesses/<harness_id>/main`
    // relative to the finding dir (`<work>/findings/<F-...>/`).
    let root = temp_dir("auto-harness-id");
    let work = root.join("work");
    let finding_dir = work.join("findings/F-0000-auto");
    let harness_id = "H-AUTO-1234";
    let auto_dir = work.join("harnesses").join(harness_id);
    fs::create_dir_all(&auto_dir).unwrap();
    copy_executable(fake_harness(), &auto_dir.join("main"));
    fs::create_dir_all(&finding_dir).unwrap();
    fs::write(finding_dir.join("testcase.bin"), b"match").unwrap();
    fs::write(
        finding_dir.join("finding.json"),
        format!("{{\"signature\":\"{CANONICAL_SIGNATURE}\",\"harness_id\":\"{harness_id}\"}}"),
    )
    .unwrap();

    assert_eq!(
        cli::run_from(["bhf", "replay", finding_dir.to_str().unwrap()]),
        0
    );
}

#[test]
fn replay_subcommand_explicit_harness_overrides_auto_resolution() {
    // An explicit --harness wins even when the finding records a (here bogus)
    // fixture_path that does not exist.
    let (_root, finding_dir) =
        write_finding_with_fixture("match", Path::new("/nonexistent/bhf/harness"));

    assert_eq!(
        cli::run_from([
            "bhf",
            "replay",
            finding_dir.to_str().unwrap(),
            "--harness",
            fake_harness().to_str().unwrap(),
        ]),
        0
    );
}

#[test]
fn replay_subcommand_unresolvable_harness_returns_one() {
    // No --harness and nothing resolvable: clear error, exit 1.
    let (_root, finding_dir) = write_finding("match");

    assert_eq!(
        cli::run_from(["bhf", "replay", finding_dir.to_str().unwrap()]),
        1
    );
}

#[test]
fn replay_subcommand_missing_finding_returns_one() {
    let missing_root = temp_dir("missing");
    let missing = missing_root.join("findings/F-0000-missing");

    assert_eq!(
        cli::run_from([
            "bhf",
            "replay",
            missing.to_str().unwrap(),
            "--harness",
            fake_harness().to_str().unwrap(),
        ]),
        1
    );
}

#[test]
fn minimize_subcommand_writes_min_testcase_and_updates_finding_record() {
    let input = format!("{}crash{}", "A".repeat(32), "B".repeat(32));
    let (_root, finding_dir) = write_finding(&input);

    assert_eq!(
        cli::run_from([
            "bhf",
            "minimize",
            "--finding",
            finding_dir.to_str().unwrap(),
            "--harness",
            fake_harness().to_str().unwrap(),
        ]),
        0
    );

    assert_eq!(
        fs::read(finding_dir.join("min_testcase.bin")).unwrap(),
        b"crash"
    );
    let finding = read_finding_json(&finding_dir);
    assert_eq!(finding["paths"]["minimized"], "min_testcase.bin");
    assert_eq!(finding["minimal_reproducer"], "min_testcase.bin");
    assert_eq!(finding["minimization"]["strategy"], "bytes");
    assert_eq!(finding["minimization"]["reduced"], true);
    assert_eq!(
        finding["minimization"]["original_len"].as_u64(),
        Some(input.len() as u64)
    );
    assert_eq!(finding["minimization"]["minimized_len"].as_u64(), Some(5));
    assert!(5 * 10 < input.len());
}

#[cfg(unix)]
#[test]
fn minimize_subcommand_qemu_user_wraps_harness() {
    let root = temp_dir("qemu-user-minimize");
    let qemu_path = root.join("fake-qemu-aarch64");
    let qemu_log = root.join("qemu-argv.txt");
    write_fake_qemu_user(&qemu_path);
    let (_root, finding_dir) = write_finding("AAAAcrashBBBB");

    let exit = cli::run_from([
        "bhf",
        "minimize",
        finding_dir.to_str().unwrap(),
        "--harness",
        fake_harness().to_str().unwrap(),
        "--qemu-user",
        qemu_path.to_str().unwrap(),
        "--qemu-arg=--sysroot",
        "--qemu-arg=/opt/aarch64-sysroot",
    ]);

    assert_eq!(exit, 0);
    assert_eq!(
        fs::read(finding_dir.join("min_testcase.bin")).unwrap(),
        b"crash"
    );
    assert!(fs::read_to_string(qemu_log)
        .unwrap()
        .contains(&fake_harness().display().to_string()));
}

#[test]
fn minimize_subcommand_typed_strategy_uses_decoded_spans() {
    let (_root, finding_dir) = write_finding("AAAAcrashBBBB");
    write_decoded_spans(
        &finding_dir,
        &[
            serde_json::json!({ "start": 0, "end": 4, "kind": "string" }),
            serde_json::json!({ "start": 9, "end": 13, "kind": "bytes" }),
        ],
    );

    assert_eq!(
        cli::run_from([
            "bhf",
            "minimize",
            finding_dir.to_str().unwrap(),
            "--harness",
            fake_harness().to_str().unwrap(),
            "--strategy",
            "typed",
        ]),
        0
    );

    assert_eq!(
        fs::read(finding_dir.join("min_testcase.bin")).unwrap(),
        b"crash"
    );
    let finding = read_finding_json(&finding_dir);
    assert_eq!(finding["minimization"]["strategy"], "typed");
    assert_eq!(
        finding["minimization"]["attempted_replacements"].as_u64(),
        Some(2)
    );
    assert_eq!(
        finding["minimization"]["accepted_replacements"].as_u64(),
        Some(2)
    );
}

#[test]
fn minimize_subcommand_typed_strategy_without_spans_records_no_reduction() {
    let (_root, finding_dir) = write_finding("AAAAcrashBBBB");

    assert_eq!(
        cli::run_from([
            "bhf",
            "minimize",
            finding_dir.to_str().unwrap(),
            "--harness",
            fake_harness().to_str().unwrap(),
            "--strategy",
            "typed",
        ]),
        0
    );

    assert_eq!(
        fs::read(finding_dir.join("min_testcase.bin")).unwrap(),
        b"AAAAcrashBBBB"
    );
    let finding = read_finding_json(&finding_dir);
    assert_eq!(finding["minimization"]["strategy"], "typed");
    assert_eq!(finding["minimization"]["reduced"], false);
    assert_eq!(
        finding["minimization"]["attempted_replacements"].as_u64(),
        Some(0)
    );
    assert_eq!(
        finding["minimization"]["accepted_replacements"].as_u64(),
        Some(0)
    );
}

#[test]
fn minimize_subcommand_rejects_non_reproducing_original() {
    let (_root, finding_dir) = write_finding("does-not-reproduce");

    assert_eq!(
        cli::run_from([
            "bhf",
            "minimize",
            finding_dir.to_str().unwrap(),
            "--harness",
            fake_harness().to_str().unwrap(),
        ]),
        1
    );
    assert!(!finding_dir.join("min_testcase.bin").exists());
}

/// A finding dir holding `input`; the guard holds the dir.
fn write_finding(input: &str) -> (TestDir, PathBuf) {
    let root = temp_dir(input);
    let finding_dir = root.join("findings/F-0000-test");
    write_finding_at(&finding_dir, input);
    (root, finding_dir)
}

fn write_finding_at(finding_dir: &Path, input: &str) {
    fs::create_dir_all(finding_dir).unwrap();
    fs::write(finding_dir.join("testcase.bin"), input.as_bytes()).unwrap();
    fs::write(
        finding_dir.join("finding.json"),
        format!("{{\"signature\":\"{CANONICAL_SIGNATURE}\"}}"),
    )
    .unwrap();
}

/// A finding dir holding `input` and naming `fixture`; the guard holds the dir.
fn write_finding_with_fixture(input: &str, fixture: &Path) -> (TestDir, PathBuf) {
    let root = temp_dir(&format!("{input}-fixture"));
    let finding_dir = root.join("findings/F-0000-test");
    fs::create_dir_all(&finding_dir).unwrap();
    fs::write(finding_dir.join("testcase.bin"), input.as_bytes()).unwrap();
    fs::write(
        finding_dir.join("finding.json"),
        serde_json::json!({
            "signature": CANONICAL_SIGNATURE,
            "fixture_path": fixture,
        })
        .to_string(),
    )
    .unwrap();
    (root, finding_dir)
}

fn copy_executable(from: &Path, to: &Path) {
    fs::copy(from, to).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(to).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(to, permissions).unwrap();
    }
}

fn write_decoded_spans(finding_dir: &Path, spans: &[serde_json::Value]) {
    fs::write(
        finding_dir.join("decoded.json"),
        serde_json::to_vec(&serde_json::json!({ "typed_spans": spans })).unwrap(),
    )
    .unwrap();
}

fn read_finding_json(finding_dir: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(finding_dir.join("finding.json")).unwrap()).unwrap()
}

fn fake_harness() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_cli_fake_harness"))
}

fn temp_dir(name: &str) -> TestDir {
    TestDir::new(&format!("cli-replay-{name}"))
}

#[cfg(unix)]
fn write_fake_qemu_user(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    fs::write(
        path,
        r#"#!/bin/sh
set -eu
printf '%s\n' "$@" > "$(dirname "$0")/qemu-argv.txt"
last=''
for arg in "$@"; do
  last="$arg"
done
exec "$last"
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

#[cfg(unix)]
fn write_fake_sandbox(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    fs::write(
        path,
        r#"#!/bin/sh
set -eu
printf '%s\n' "$@" > "$(dirname "$0")/sandbox-argv.txt"
found_separator=0
shifted=''
for arg in "$@"; do
  if [ "$found_separator" = 1 ]; then
    shifted="${shifted}${arg}
"
  elif [ "$arg" = "--" ]; then
    found_separator=1
  fi
done
if [ "$found_separator" != 1 ]; then
  exit 125
fi
set -- $shifted
exec "$@"
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

// --- replay summary, crash identity, sanitizer options, results freshness ---

/// An ASan heap-buffer-overflow report in `function` at `widget.cc:line`.
#[cfg(unix)]
fn asan_report(function: &str, line: u32) -> String {
    format!(
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000031 at pc 0x1 bp 0x2 sp 0x3\n\
         WRITE of size 1 at 0x602000000031 thread T0\n\
         \x20   #0 0x1 in {function}(char const*, unsigned long) /src/widget/widget.cc:{line}:5\n\
         \x20   #1 0x2 in parse_record(char const*) /src/widget/parse.cc:40:7\n\
         \n\
         0x602000000031 is located 0 bytes after 1-byte region [0x602000000030,0x602000000031)\n\
         allocated by thread T0 here:\n\
         \x20   #0 0x3 in malloc\n\
         \x20   #1 0x4 in parse_record(char const*) /src/widget/parse.cc:38:9\n\
         SUMMARY: AddressSanitizer: heap-buffer-overflow /src/widget/widget.cc:{line}:5 in {function}\n"
    )
}

/// A bhf-driver-protocol script harness that prints `report` and aborts, and
/// records the sanitizer options it was given.
#[cfg(unix)]
fn write_crashing_harness(path: &Path, report: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        path,
        format!(
            "#!/bin/sh\n# BHF_FRAMED test driver\n\
             printf '%s' \"$ASAN_OPTIONS\" > \"$(dirname \"$0\")/asan-options.txt\"\n\
             touch \"$(dirname \"$0\")/ran\"\n\
             cat >&2 <<'REPORT'\n{report}REPORT\nkill -ABRT $$\n"
        ),
    )
    .unwrap();
    make_executable(path);
}

/// A finding recorded the way the fuzz loop records one, in a work dir.
#[cfg(unix)]
fn emit_finding(work: &Path, harness: &Path, report: &str) -> PathBuf {
    let parsed = corpus::parse_sanitizer_report(report).expect("report parses");
    let id = corpus::FindingEmitter::with_metadata(
        work.to_path_buf(),
        "H-1".to_owned(),
        "cpp".to_owned(),
        harness.display().to_string(),
    )
    .emit_sanitizer_crash_with_log(b"widget-input", &parsed, Some(report.as_bytes()))
    .expect("finding emitted");
    corpus::layout::findings_dir(work).join(id.0)
}

#[cfg(unix)]
fn replay_output(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_cli"))
        .arg("replay")
        .args(args)
        .output()
        .unwrap()
}

#[cfg(unix)]
fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A MATCH prints what crashed: rule, kind, sink, frames, the memory access,
/// the allocation site, the exit status, the harness and the testcase.
#[cfg(unix)]
#[test]
fn replay_prints_a_crash_summary_under_the_match_line() {
    let root = temp_dir("summary");
    let work = root.join("work");
    let harness = work.join("harnesses/H-1/main");
    let report = asan_report("Widget::copy_at", 12);
    write_crashing_harness(&harness, &report);
    let finding = emit_finding(&work, &harness, &report);

    let output = replay_output(&[finding.to_str().unwrap()]);
    let stdout = text(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{stdout}\n{}",
        text(&output.stderr)
    );
    assert_eq!(stdout.lines().next(), Some("MATCH"), "{stdout}");
    for needle in [
        "rule BHF-201",
        "kind heap-buffer-overflow",
        "sink Widget::copy_at (widget/widget.cc:12)",
        "#0 Widget::copy_at(char const*, unsigned long) /src/widget/widget.cc:12",
        "WRITE of size 1 at 0x602000000031; 0 bytes after a 1-byte heap region",
        "#1 parse_record(char const*) /src/widget/parse.cc:38",
        "signal 6 (SIGABRT)",
        "bhf framed",
        "12 bytes",
    ] {
        assert!(stdout.contains(needle), "missing {needle:?} in:\n{stdout}");
    }
    // The raw report is shown only with --show-output.
    assert!(!stdout.contains("is located 0 bytes after"), "{stdout}");
}

/// The same rule and kind in another function is not this finding: MISMATCH
/// names the sink that differed, and the finding is not stamped as seen.
#[cfg(unix)]
#[test]
fn replay_of_the_same_class_at_another_site_is_a_mismatch_naming_the_sink() {
    let root = temp_dir("other-site");
    let work = root.join("work");
    let recorded = work.join("harnesses/H-1/main");
    write_crashing_harness(&recorded, &asan_report("Widget::copy_at", 12));
    let finding = emit_finding(&work, &recorded, &asan_report("Widget::copy_at", 12));
    let other = root.join("other/main");
    write_crashing_harness(&other, &asan_report("Widget::other", 8));

    let output = replay_output(&[
        finding.to_str().unwrap(),
        "--harness",
        other.to_str().unwrap(),
    ]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{stderr}");
    assert!(
        stderr.contains("MISMATCH recorded=BHF-201 actual=BHF-201 differs=sink"),
        "{stderr}"
    );
    assert!(
        stderr.contains(
            "sink: recorded Widget::copy_at (widget/widget.cc:12), replayed Widget::other (widget/widget.cc:8)"
        ),
        "{stderr}"
    );
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(finding.join("finding.json")).unwrap()).unwrap();
    assert!(
        record.get("last_seen").is_none(),
        "a mismatch is not a reproduction"
    );
}

/// minimize first replays the testcase and compares the crash with the
/// finding: a harness that reports another crash is refused like a replay
/// MISMATCH, and nothing is minimized.
#[cfg(unix)]
#[test]
fn minimize_refuses_a_harness_that_reports_another_crash() {
    let root = temp_dir("minimize-other-site");
    let work = root.join("work");
    let recorded = work.join("harnesses/H-1/main");
    write_crashing_harness(&recorded, &asan_report("Widget::copy_at", 12));
    let finding = emit_finding(&work, &recorded, &asan_report("Widget::copy_at", 12));
    let other = root.join("other/main");
    write_crashing_harness(&other, &asan_report("Widget::other", 8));

    let output = Command::new(env!("CARGO_BIN_EXE_cli"))
        .args([
            "minimize",
            finding.to_str().unwrap(),
            "--harness",
            other.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{stderr}");
    assert!(
        stderr.contains(
            "sink: recorded Widget::copy_at (widget/widget.cc:12), replayed Widget::other (widget/widget.cc:8)"
        ),
        "{stderr}"
    );
    assert!(!finding.join("min_testcase.bin").exists(), "{stderr}");

    // A finding that records no crash location cannot be checked against
    // this harness: it is minimized, with a note that says so.
    let mut record = read_finding_json(&finding);
    let exception = record["exception"].as_object_mut().unwrap();
    exception.insert("stack".to_owned(), serde_json::json!([]));
    exception.remove("location");
    record["actionability"] = serde_json::json!({});
    fs::write(
        finding.join("finding.json"),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cli"))
        .args([
            "minimize",
            finding.to_str().unwrap(),
            "--harness",
            other.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert!(
        stderr.contains(
            "note: the original testcase's crash could not be shown to be the recorded one \
             (location not compared)"
        ),
        "{stderr}"
    );
    assert!(finding.join("min_testcase.bin").exists(), "{stderr}");
}

/// `--allow-other-crash` minimizes against the crash the harness reports (an
/// intentional rebuild that moved the sink), with a warning naming what
/// differs, and the finding records it.
#[cfg(unix)]
#[test]
fn minimize_against_another_crash_when_asked() {
    let root = temp_dir("minimize-allow-other");
    let work = root.join("work");
    let recorded = work.join("harnesses/H-1/main");
    write_crashing_harness(&recorded, &asan_report("Widget::copy_at", 12));
    let finding = emit_finding(&work, &recorded, &asan_report("Widget::copy_at", 12));
    let other = root.join("other/main");
    write_crashing_harness(&other, &asan_report("Widget::other", 8));

    let output = Command::new(env!("CARGO_BIN_EXE_cli"))
        .args([
            "minimize",
            finding.to_str().unwrap(),
            "--harness",
            other.to_str().unwrap(),
            "--allow-other-crash",
        ])
        .output()
        .unwrap();
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert!(
        stderr.contains("warning: the original testcase crashes")
            && stderr.contains(
                "sink: recorded Widget::copy_at (widget/widget.cc:12), replayed Widget::other (widget/widget.cc:8)"
            ),
        "{stderr}"
    );
    assert!(finding.join("min_testcase.bin").exists(), "{stderr}");
    let record = read_finding_json(&finding);
    let other_crash = record["minimization"]["other_crash"]
        .as_str()
        .unwrap_or_default();
    assert!(other_crash.contains("sink: recorded"), "{record}");
}

/// A harness whose crash depends on a variable the finding recorded as
/// injected (`runtime_mode.env_injected`): replay sets it, and so does
/// minimize, for the testcase and for every reduction it tries.
#[cfg(unix)]
#[test]
fn minimize_runs_the_harness_with_the_recorded_environment() {
    let root = temp_dir("minimize-env");
    let work = root.join("work");
    let harness = work.join("harnesses/H-1/main");
    let recorded = asan_report("Widget::copy_at", 12);
    let other = asan_report("Widget::other", 8);
    fs::create_dir_all(harness.parent().unwrap()).unwrap();
    fs::write(
        &harness,
        format!(
            "#!/bin/sh\n# BHF_FRAMED test driver\n\
             case \"$(cat \"$1\")\" in *input*) ;; *) exit 0;; esac\n\
             if [ -n \"$WIDGET_HOME\" ]; then\ncat >&2 <<'REPORT'\n{recorded}REPORT\n\
             else\ncat >&2 <<'REPORT'\n{other}REPORT\nfi\nkill -ABRT $$\n"
        ),
    )
    .unwrap();
    make_executable(&harness);
    let finding = emit_finding(&work, &harness, &recorded);
    let mut record = read_finding_json(&finding);
    record["runtime_mode"] =
        serde_json::json!({"pass": "rng", "env_injected": {"WIDGET_HOME": "/x"}});
    fs::write(
        finding.join("finding.json"),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();

    let replay = Command::new(env!("CARGO_BIN_EXE_cli"))
        .arg("replay")
        .arg(&finding)
        .env_remove("WIDGET_HOME")
        .output()
        .unwrap();
    assert_eq!(replay.status.code(), Some(0), "{}", text(&replay.stderr));
    let output = Command::new(env!("CARGO_BIN_EXE_cli"))
        .arg("minimize")
        .arg(&finding)
        .env_remove("WIDGET_HOME")
        .output()
        .unwrap();
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert_eq!(
        fs::read(finding.join("min_testcase.bin")).unwrap(),
        b"input",
        "every reduction ran with the recorded environment: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn replay_json_and_show_output() {
    let root = temp_dir("json");
    let work = root.join("work");
    let harness = work.join("harnesses/H-1/main");
    let report = asan_report("Widget::copy_at", 12);
    write_crashing_harness(&harness, &report);
    let finding = emit_finding(&work, &harness, &report);

    let output = replay_output(&[finding.to_str().unwrap(), "--json"]);
    assert_eq!(output.status.code(), Some(0));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["schema_version"], "bhf.replay.v1");
    assert_eq!(value["verdict"], "match");
    assert_eq!(value["crash"]["rule"], "BHF-201");
    assert_eq!(value["crash"]["access"]["region"]["size"], 1);
    assert_eq!(value["exit"]["signal"], 6);
    assert_eq!(value["harness"]["protocol"], "bhf framed");
    assert!(value["compared"]
        .as_array()
        .unwrap()
        .iter()
        .any(|check| check["field"] == "sink" && check["outcome"] == "equal"));

    let output = replay_output(&[finding.to_str().unwrap(), "--show-output"]);
    assert_eq!(output.status.code(), Some(0));
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains("ERROR: AddressSanitizer: heap-buffer-overflow on address"),
        "{stderr}"
    );
}

/// A harness that hangs is reported as a timeout, not as a crash-free run.
#[cfg(unix)]
#[test]
fn replay_reports_a_hang_as_a_timeout() {
    let root = temp_dir("timeout");
    let work = root.join("work");
    let harness = work.join("harnesses/H-1/main");
    let report = asan_report("Widget::copy_at", 12);
    write_crashing_harness(&harness, &report);
    let finding = emit_finding(&work, &harness, &report);
    fs::write(&harness, "#!/bin/sh\n# BHF_FRAMED\nexec sleep 60\n").unwrap();

    let output = replay_output(&[finding.to_str().unwrap()]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{stderr}");
    assert!(stderr.contains("actual=<timeout>"), "{stderr}");
    assert!(stderr.contains("timed out after 10s"), "{stderr}");
}

/// A stdin harness that never reads a testcase larger than the pipe buffer
/// still times out instead of blocking replay on the write.
#[cfg(unix)]
#[test]
fn a_stdin_replay_of_a_large_testcase_still_times_out() {
    let root = temp_dir("timeout-stdin-large");
    let work = root.join("work");
    let harness = work.join("harnesses/H-1/main_afl");
    let report = asan_report("Widget::copy_at", 12);
    write_crashing_harness(&harness, &report);
    let finding = emit_finding(&work, &harness, &report);
    fs::write(finding.join("testcase.bin"), vec![b'A'; 1 << 20]).unwrap();
    fs::write(&harness, "#!/bin/sh\n# BHF_FRAMED\nexec sleep 30\n").unwrap();
    let started = std::time::Instant::now();
    let output = replay_output(&[finding.to_str().unwrap()]);
    let elapsed = started.elapsed();
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{stderr}");
    assert!(stderr.contains("actual=<timeout>"), "{stderr}");
    assert!(stderr.contains("timed out after 10s"), "{stderr}");
    assert!(
        elapsed < std::time::Duration::from_secs(15),
        "replay took {elapsed:?}"
    );
}

/// A launcher harness whose own child never finishes: the replay timeout
/// kills both, so replay returns soon after the timeout instead of hanging
/// on the pipe the grandchild holds.
#[cfg(unix)]
#[test]
fn a_replay_timeout_kills_what_the_harness_started() {
    for (name, launched, limit) in [
        ("busy", "sh -c 'while :; do :; done'", 13),
        ("sleep", "sleep 30", 15),
    ] {
        let root = temp_dir(&format!("timeout-group-{name}"));
        let work = root.join("work");
        let harness = work.join("harnesses/H-1/main");
        let report = asan_report("Widget::copy_at", 12);
        write_crashing_harness(&harness, &report);
        let finding = emit_finding(&work, &harness, &report);
        fs::write(&harness, format!("#!/bin/sh\n# BHF_FRAMED\n{launched}\n")).unwrap();
        let started = std::time::Instant::now();
        let output = replay_output(&[finding.to_str().unwrap()]);
        let elapsed = started.elapsed();
        let stderr = text(&output.stderr);
        assert_eq!(output.status.code(), Some(3), "{name}: {stderr}");
        assert!(stderr.contains("timed out after 10s"), "{name}: {stderr}");
        assert!(
            elapsed < std::time::Duration::from_secs(limit),
            "{name}: replay took {elapsed:?}"
        );
    }
}

/// An interrupted replay (Ctrl-C reaches bhf only: the harness runs in its
/// own process group) kills what the harness started before bhf ends by the
/// same signal.
#[cfg(target_os = "linux")]
#[test]
fn an_interrupted_replay_kills_what_the_harness_started() {
    use std::os::unix::process::ExitStatusExt;
    use std::time::{Duration, Instant};
    let ended = |pid: &str| match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Err(_) => true,
        Ok(stat) => stat
            .rsplit_once(')')
            .is_some_and(|(_, rest)| rest.trim_start().starts_with('Z')),
    };
    let root = temp_dir("interrupted");
    let work = root.join("work");
    let harness = work.join("harnesses/H-1/main");
    let report = asan_report("Widget::copy_at", 12);
    write_crashing_harness(&harness, &report);
    let finding = emit_finding(&work, &harness, &report);
    let pid_file = root.join("grandchild.pid");
    fs::write(
        &harness,
        format!(
            "#!/bin/sh\n# BHF_FRAMED\nsh -c 'echo $$ > \"{}\"; exec sleep 47'\n",
            pid_file.display()
        ),
    )
    .unwrap();
    let mut bhf = Command::new(env!("CARGO_BIN_EXE_cli"))
        .args(["replay", finding.to_str().unwrap()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let grandchild = loop {
        let pid = fs::read_to_string(&pid_file).unwrap_or_default();
        if !pid.trim().is_empty() || Instant::now() >= deadline {
            break pid.trim().to_owned();
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(
        !grandchild.is_empty(),
        "the harness did not start its child"
    );
    Command::new("kill")
        .args(["-INT", &bhf.id().to_string()])
        .status()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = bhf.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            let _ = bhf.kill();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ended(&grandchild) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let gone = ended(&grandchild);
    if !gone {
        let _ = Command::new("kill").args(["-9", &grandchild]).status();
    }
    let status = status.expect("bhf replay did not end after SIGINT");
    assert_eq!(status.signal(), Some(2), "{status:?}");
    assert!(gone, "process {grandchild} outlived the interrupted replay");
}

/// Replay runs with the fuzz child's sanitizer options; a leak finding keeps
/// leak detection on, and nothing turns it off.
#[cfg(unix)]
#[test]
fn replay_uses_the_fuzz_child_sanitizer_options() {
    let root = temp_dir("asan-options");
    let work = root.join("work");
    let harness = work.join("harnesses/H-1/main");
    let report = asan_report("Widget::copy_at", 12);
    write_crashing_harness(&harness, &report);
    let finding = emit_finding(&work, &harness, &report);
    assert_eq!(
        cli::run_from(["bhf", "replay", finding.to_str().unwrap()]),
        0
    );
    let options = fs::read_to_string(harness.parent().unwrap().join("asan-options.txt")).unwrap();
    assert!(options.contains("abort_on_error=1"), "{options}");
    assert!(options.contains("halt_on_error=1"), "{options}");
    assert!(!options.contains("detect_leaks=0"), "{options}");

    let leak = "==1==ERROR: LeakSanitizer: detected memory leaks\n\n\
                Direct leak of 8 byte(s) in 1 object(s) allocated from:\n\
                \x20   #0 0x1 in malloc\n\
                \x20   #1 0x2 in Widget::make(int) /src/widget/widget.cc:20:9\n\n\
                SUMMARY: AddressSanitizer: 8 byte(s) leaked in 1 allocation(s).\n";
    let leak_harness = work.join("harnesses/H-2/main");
    write_crashing_harness(&leak_harness, leak);
    let leak_finding = emit_finding(&work, &leak_harness, leak);
    assert_eq!(
        cli::run_from(["bhf", "replay", leak_finding.to_str().unwrap()]),
        0
    );
    let options =
        fs::read_to_string(leak_harness.parent().unwrap().join("asan-options.txt")).unwrap();
    assert!(options.contains("detect_leaks=1"), "{options}");
}

/// An inherited `symbolize=0` cannot strip the location a replay compares:
/// replay puts `symbolize=1` after it.
#[cfg(unix)]
#[test]
fn replay_symbolizes_whatever_the_inherited_options_say() {
    let root = temp_dir("symbolize");
    let work = root.join("work");
    let harness = work.join("harnesses/H-1/main");
    let report = asan_report("Widget::copy_at", 12);
    write_crashing_harness(&harness, &report);
    let finding = emit_finding(&work, &harness, &report);
    let output = Command::new(env!("CARGO_BIN_EXE_cli"))
        .arg("replay")
        .arg(&finding)
        .env("ASAN_OPTIONS", "symbolize=0")
        .env("UBSAN_OPTIONS", "symbolize=0")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let options = fs::read_to_string(harness.parent().unwrap().join("asan-options.txt")).unwrap();
    let last = options
        .split(':')
        .rev()
        .find(|item| item.starts_with("symbolize="));
    assert_eq!(last, Some("symbolize=1"), "{options}");
}

/// A copied work dir replays against its own harness, not the original's.
#[cfg(unix)]
#[test]
fn replay_in_a_copied_work_dir_runs_the_copy_harness() {
    let root = temp_dir("copied");
    let original = root.join("original");
    let harness = original.join("harnesses/H-1/main");
    let report = asan_report("Widget::copy_at", 12);
    write_crashing_harness(&harness, &report);
    let finding = emit_finding(&original, &harness, &report);
    // What an earlier release recorded: the absolute harness path.
    let mut record: serde_json::Value =
        serde_json::from_slice(&fs::read(finding.join("finding.json")).unwrap()).unwrap();
    record["fixture_path"] = serde_json::json!(harness.display().to_string());
    fs::write(
        finding.join("finding.json"),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();
    let copy = root.join("copy");
    assert!(Command::new("cp")
        .args(["-a", original.to_str().unwrap(), copy.to_str().unwrap()])
        .status()
        .unwrap()
        .success());
    let copied_finding = copy
        .join("results/findings")
        .join(finding.file_name().unwrap());

    assert_eq!(
        cli::run_from(["bhf", "replay", copied_finding.to_str().unwrap()]),
        0
    );
    assert!(copy.join("harnesses/H-1/ran").is_file(), "copy harness ran");
    assert!(
        !original.join("harnesses/H-1/ran").exists(),
        "the original's harness must not run"
    );
}

/// `bhf build` stages only the binary into `build/<id>/main`; its driver
/// source is in `generated_harnesses/<id>/`. Replay auto-resolution and an
/// explicit `--harness build/<id>/main` both feed it the testcase as a file.
#[cfg(unix)]
#[test]
fn replay_and_minimize_a_harness_staged_into_build() {
    let root = temp_dir("staged-build");
    let work = root.join("work");
    let report = asan_report("Widget::copy_at", 12);
    let staged = work.join("build/H-1/main");
    fs::create_dir_all(staged.parent().unwrap()).unwrap();
    // No marker in the staged binary itself; the testcase arrives as argv[1].
    fs::write(
        &staged,
        format!(
            "#!/bin/sh\n[ -f \"$1\" ] || exit 0\ncat >&2 <<'REPORT'\n{report}REPORT\nkill -ABRT $$\n"
        ),
    )
    .unwrap();
    make_executable(&staged);
    let generated = work.join("generated_harnesses/H-1");
    fs::create_dir_all(&generated).unwrap();
    fs::write(generated.join("main.cpp"), "// BHF_FRAMED driver\n").unwrap();
    let finding = emit_finding(&work, &staged, &report);

    assert_eq!(
        cli::run_from(["bhf", "replay", finding.to_str().unwrap()]),
        0,
        "auto-resolved build/<id>/main"
    );
    assert_eq!(
        cli::run_from([
            "bhf",
            "replay",
            finding.to_str().unwrap(),
            "--harness",
            staged.to_str().unwrap(),
        ]),
        0,
        "explicit build/<id>/main"
    );
    assert_eq!(
        cli::run_from([
            "bhf",
            "minimize",
            finding.to_str().unwrap(),
            "--harness",
            staged.to_str().unwrap(),
        ]),
        0,
        "minimize build/<id>/main"
    );
    assert!(finding.join("min_testcase.bin").is_file());
}

/// Every subject the results attestation lists has the digest of the file on
/// disk.
#[cfg(unix)]
fn assert_attestation_current(work: &Path) {
    use sha2::{Digest, Sha256};
    let results = work.join("results");
    let attestation: serde_json::Value =
        serde_json::from_slice(&fs::read(results.join("attestation.json")).unwrap()).unwrap();
    let subjects = attestation["subject"].as_array().unwrap();
    assert!(subjects
        .iter()
        .any(|s| s["name"].as_str().unwrap().ends_with("finding.json")));
    for subject in subjects {
        let name = subject["name"].as_str().unwrap();
        let digest = corpus::hex_lower(&Sha256::digest(fs::read(results.join(name)).unwrap()));
        assert_eq!(
            subject["digest"]["sha256"].as_str().unwrap(),
            digest,
            "{name} is stale in the attestation"
        );
    }
}

/// A binary finding replays through the same summary, `--json` and
/// `--show-output` as a harness finding, and its reproduction keeps results/
/// consistent.
#[cfg(unix)]
#[test]
fn a_binary_finding_replay_has_a_summary_json_and_a_current_attestation() {
    let root = temp_dir("binary-lane");
    let target = root.join("crashy.sh");
    fs::write(
        &target,
        "#!/bin/sh\ninput=$(cat)\nif [ \"$input\" = \"CRASH\" ]; then echo binary-crash-detail >&2; exit 42; fi\nexit 0\n",
    )
    .unwrap();
    make_executable(&target);
    let work = root.join("work");
    let fuzzed = Command::new(env!("CARGO_BIN_EXE_cli"))
        .args([
            "binary-fuzz",
            target.to_str().unwrap(),
            "--work-dir",
            work.to_str().unwrap(),
            "--input-mode",
            "stdin",
            "--seed-input",
            "CRASH",
            "--timeout-ms",
            "2000",
        ])
        .output()
        .unwrap();
    assert!(fuzzed.status.success(), "{}", text(&fuzzed.stderr));
    let finding = work.join("results/findings/BF-0001");
    assert!(finding.join("finding.json").is_file());
    assert_attestation_current(&work);

    let output = replay_output(&[
        finding.to_str().unwrap(),
        "--harness",
        target.to_str().unwrap(),
    ]);
    let stdout = text(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{stdout}{}",
        text(&output.stderr)
    );
    assert_eq!(stdout.lines().next(), Some("MATCH"), "{stdout}");
    for needle in [
        "crash signature",
        "exit status 42",
        "binary, stdin",
        "5 bytes",
    ] {
        assert!(stdout.contains(needle), "missing {needle:?} in:\n{stdout}");
    }
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(finding.join("finding.json")).unwrap()).unwrap();
    assert!(record.get("last_seen").is_some());
    assert_attestation_current(&work);

    let output = replay_output(&[
        finding.to_str().unwrap(),
        "--harness",
        target.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(0));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["schema_version"], "bhf.replay.v1");
    assert_eq!(value["verdict"], "match");
    assert_eq!(value["lane"], "binary");
    assert_eq!(value["exit"]["code"], 42);
    assert_eq!(value["harness"]["sha256_matches"], true);

    let output = replay_output(&[
        finding.to_str().unwrap(),
        "--harness",
        target.to_str().unwrap(),
        "--show-output",
    ]);
    assert_eq!(output.status.code(), Some(0));
    assert!(
        text(&output.stderr).contains("binary-crash-detail"),
        "{}",
        text(&output.stderr)
    );
}

/// The recorded crash replayed without a symbolizer names no function or
/// position: that is not another crash site, but it is not a reproduction
/// either. Replay says UNVERIFIED (exit 4), names what it could not compare,
/// and records nothing: no `last_seen`, no history entry.
#[cfg(unix)]
#[test]
fn an_unsymbolized_replay_of_the_recorded_crash_is_unverified() {
    let root = temp_dir("unsymbolized");
    let work = root.join("work");
    let harness = work.join("harnesses/H-1/main");
    let report = asan_report("Widget::copy_at", 12);
    write_crashing_harness(&harness, &report);
    let finding = emit_finding(&work, &harness, &report);
    write_crashing_harness(&harness, UNSYMBOLIZED_REPORT);
    let report = Command::new(env!("CARGO_BIN_EXE_cli"))
        .args(["report", "--work-dir", work.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(report.status.success(), "{}", text(&report.stderr));
    let before = fs::read(finding.join("finding.json")).unwrap();

    let output = replay_output(&[finding.to_str().unwrap()]);
    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(4), "{stdout}{stderr}");
    // The finding is left as it was; replay.log is rewritten, and results/
    // is rebuilt so the attestation covers it.
    assert_eq!(fs::read(finding.join("finding.json")).unwrap(), before);
    let log = fs::read_to_string(finding.join("replay.log")).unwrap();
    assert!(log.contains("verdict: unverified"), "{log}");
    assert_attestation_current(&work);
    assert_eq!(
        stderr.lines().next(),
        Some("UNVERIFIED recorded=BHF-201 actual=BHF-201 not_compared=sink"),
        "{stderr}"
    );
    assert!(!stderr.contains("differs"), "{stderr}");
    assert!(stderr.contains("sink not compared"), "{stderr}");
    assert!(stderr.contains("unsymbolized"), "{stderr}");
    assert!(stderr.contains("ASAN_SYMBOLIZER_PATH"), "{stderr}");
    let record = read_finding_json(&finding);
    assert!(record.get("last_seen").is_none(), "{record}");
    assert!(
        !record["history"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|entry| entry["command"]
                .as_str()
                .unwrap_or("")
                .starts_with("replay")),
        "{record}"
    );
    let output = replay_output(&[finding.to_str().unwrap(), "--json"]);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["verdict"], "unverified");
    assert_eq!(output.status.code(), Some(4));
}

/// bhf appends `symbolize=1` to an inherited `ASAN_OPTIONS`, so an inherited
/// `symbolize=0` does not reach the harness and is not named as the cause of
/// an unsymbolized report.
#[cfg(unix)]
#[test]
fn an_inherited_symbolize_0_is_not_named_as_the_cause() {
    let root = temp_dir("unsymbolized-inherited");
    let work = root.join("work");
    let harness = work.join("harnesses/H-1/main");
    let report = asan_report("Widget::copy_at", 12);
    write_crashing_harness(&harness, &report);
    let finding = emit_finding(&work, &harness, &report);
    write_crashing_harness(&harness, UNSYMBOLIZED_REPORT);

    let output = Command::new(env!("CARGO_BIN_EXE_cli"))
        .args(["replay", finding.to_str().unwrap()])
        .env("ASAN_OPTIONS", "symbolize=0")
        .output()
        .unwrap();
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(4), "{stderr}");
    let options = fs::read_to_string(harness.parent().unwrap().join("asan-options.txt")).unwrap();
    assert!(options.ends_with("symbolize=1"), "{options}");
    assert!(stderr.contains("ASAN_SYMBOLIZER_PATH"), "{stderr}");
    assert!(!stderr.contains("sets symbolize=0"), "{stderr}");
}

/// An ASan heap-buffer-overflow report printed without a symbolizer: frames
/// that name only a module offset, and a summary without a position.
#[cfg(unix)]
const UNSYMBOLIZED_REPORT: &str =
    "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000031 at pc 0x1 bp 0x2 sp 0x3\n\
     WRITE of size 1 at 0x602000000031 thread T0\n\
     \x20   #0 0x4f5a2b  (/w/harnesses/H-1/main+0x4f5a2b)\n\
     \x20   #1 0x4f5c10  (/w/harnesses/H-1/main+0x4f5c10)\n\
     \n\
     SUMMARY: AddressSanitizer: heap-buffer-overflow (/w/harnesses/H-1/main+0x4f5a2b)\n";

/// `--harness` naming another binary whose report is unsymbolized: the
/// replay cannot say it is the recorded crash, so it is no MATCH and the
/// results index is left as it was.
#[cfg(unix)]
#[test]
fn an_unsymbolized_report_of_another_binary_is_not_a_match() {
    let root = temp_dir("unsymbolized-other");
    let work = root.join("work");
    let harness = work.join("harnesses/H-1/main");
    let report = asan_report("Widget::copy_at", 12);
    write_crashing_harness(&harness, &report);
    let finding = emit_finding(&work, &harness, &report);
    let mut record = read_finding_json(&finding);
    record["build"] = serde_json::json!({"binary": {"sha256": sha256_hex(&harness)}});
    fs::write(
        finding.join("finding.json"),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();
    assert_eq!(
        cli::run_from(["bhf", "report", "--work-dir", work.to_str().unwrap()]),
        0
    );
    // The index, less the time it was written.
    let index = || {
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(work.join("results/findings.json")).unwrap()).unwrap();
        value.as_object_mut().unwrap().remove("generated_at");
        value
    };
    let index_before = index();
    let other = root.join("other/main");
    write_crashing_harness(&other, UNSYMBOLIZED_REPORT);

    let output = replay_output(&[
        finding.to_str().unwrap(),
        "--harness",
        other.to_str().unwrap(),
    ]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(4), "{stderr}");
    assert!(stderr.starts_with("UNVERIFIED "), "{stderr}");
    assert!(
        stderr.contains("sha256 differs from the recorded build"),
        "{stderr}"
    );
    assert!(read_finding_json(&finding).get("last_seen").is_none());
    assert_eq!(index(), index_before, "results/findings.json changed");
}

/// A clang AddressSanitizer harness built with bhf's driver from a target
/// that writes one byte past a heap buffer, or `None` without clang.
#[cfg(unix)]
fn build_overflowing_harness(dir: &Path) -> Option<PathBuf> {
    fs::create_dir_all(dir).unwrap();
    fs::write(
        dir.join("target.c"),
        "#include <stdint.h>\n#include <stddef.h>\n#include <stdlib.h>\n\
         __attribute__((noinline)) void copy_at(char *out, size_t n) { out[n] = 1; }\n\
         int bhf_run_one(const uint8_t *data, size_t size) {\n\
             char *out = malloc(4);\n\
             if (size > 0 && data[0] == 'W') copy_at(out, 4);\n\
             free(out);\n\
             return 0;\n\
         }\n",
    )
    .unwrap();
    let driver = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime/bhf_driver.c");
    let built = Command::new("clang")
        .current_dir(dir)
        .args(["-O0", "-g", "-fsanitize=address", "-o", "main", "target.c"])
        .arg(&driver)
        .output()
        .ok()?;
    built.status.success().then(|| dir.join("main"))
}

/// The runtrace shim this checkout built, when it is newer than the code that
/// copies the published input (an older build would test the old code).
#[cfg(target_os = "linux")]
fn fresh_runtrace_shim() -> Option<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let source = root.join("crates/bhf_runtrace_shim/src/fakes/fuzz_input.rs");
    let source_mtime = fs::metadata(source).and_then(|m| m.modified()).ok()?;
    let target =
        std::env::var_os("CARGO_TARGET_DIR").map_or_else(|| root.join("target"), PathBuf::from);
    ["debug", "release"].into_iter().find_map(|profile| {
        let shim = target.join(profile).join("libbhf_runtrace_shim.so");
        let built = fs::metadata(&shim).and_then(|m| m.modified()).ok()?;
        (built >= source_mtime).then_some(shim)
    })
}

/// llvm-symbolizer on `PATH` or a versioned one.
#[cfg(target_os = "linux")]
fn any_llvm_symbolizer() -> Option<PathBuf> {
    std::env::var_os("PATH")
        .and_then(|path| {
            std::env::split_paths(&path)
                .map(|dir| dir.join("llvm-symbolizer"))
                .find(|candidate| candidate.is_file())
        })
        .or_else(|| {
            (14..=22)
                .rev()
                .map(|version| PathBuf::from(format!("/usr/bin/llvm-symbolizer-{version}")))
                .find(|candidate| candidate.is_file())
        })
}

/// A read past the input, beyond its redzone, recorded from a run without the
/// runtrace shim, replays as the same crash with the shim preloaded: the
/// same kind, at the same site, in the buffer bhf's driver allocated. The
/// shim's copy of the input used to sit on the heap right after that buffer,
/// so with it the read was a heap-use-after-free in the shim's freed copy, or
/// no crash at all in its live one.
#[cfg(target_os = "linux")]
#[test]
fn a_read_past_the_input_replays_as_recorded_with_the_runtrace_shim() {
    let Some(shim) = fresh_runtrace_shim() else {
        eprintln!("skipping: runtrace shim not built (cargo build --workspace)");
        return;
    };
    let Some(symbolizer) = any_llvm_symbolizer() else {
        eprintln!("skipping: no llvm-symbolizer");
        return;
    };
    let root = temp_dir("shim-overread");
    let harness_dir = root.join("harness");
    fs::create_dir_all(&harness_dir).unwrap();
    fs::write(
        harness_dir.join("target.c"),
        "#include <stdint.h>\n#include <stddef.h>\n#include <stdio.h>\n\
         extern void bhf_shim_set_fuzz_input(const uint8_t *, size_t) __attribute__((weak));\n\
         __attribute__((noinline)) int parse_record(const uint8_t *data, size_t size) {\n\
             size_t at = (size_t)data[0] | ((size_t)data[1] << 8);\n\
             (void)size;\n\
             return data[at];\n\
         }\n\
         int bhf_run_one(const uint8_t *data, size_t size) {\n\
             if (bhf_shim_set_fuzz_input) {\n\
                 fprintf(stderr, \"input published to the shim\\n\");\n\
                 bhf_shim_set_fuzz_input(data, size);\n\
             }\n\
             if (size < 2) return 0;\n\
             volatile int value = parse_record(data, size);\n\
             (void)value;\n\
             return 0;\n\
         }\n",
    )
    .unwrap();
    let driver = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime/bhf_driver.c");
    let Ok(built) = Command::new("clang")
        .current_dir(&harness_dir)
        .args(["-O1", "-g", "-fsanitize=address", "-o", "main", "target.c"])
        .arg(&driver)
        .output()
    else {
        eprintln!("skipping: clang unavailable");
        return;
    };
    if !built.status.success() {
        eprintln!(
            "skipping: clang cannot build with ASan: {}",
            text(&built.stderr)
        );
        return;
    }
    let harness = harness_dir.join("main");

    for past in [0usize, 11, 27, 43, 59, 75] {
        let work = root.join(format!("work-{past}"));
        fs::create_dir_all(&work).unwrap();
        let at = 16 + past;
        let mut input = vec![b'r'; 16];
        input[0] = (at & 0xff) as u8;
        input[1] = (at >> 8) as u8;
        let testcase = work.join("input.bin");
        fs::write(&testcase, &input).unwrap();
        let recorded = Command::new(&harness)
            .arg(&testcase)
            .env_remove("LD_PRELOAD")
            .env_remove("DEBUGINFOD_URLS")
            .env("ASAN_SYMBOLIZER_PATH", &symbolizer)
            .env("ASAN_OPTIONS", "detect_leaks=0:symbolize=1")
            .output()
            .unwrap();
        let stderr = text(&recorded.stderr);
        assert!(!stderr.contains("input published"), "{stderr}");
        let parsed = corpus::parse_sanitizer_report(&stderr).expect("the harness reports");
        assert_eq!(parsed.kind, "heap-buffer-overflow", "{stderr}");
        let id = corpus::FindingEmitter::with_metadata(
            work.clone(),
            "H-1".to_owned(),
            "c".to_owned(),
            harness.display().to_string(),
        )
        .with_build_binary(serde_json::json!({"sha256": sha256_hex(&harness)}))
        .emit_sanitizer_crash_with_log(&input, &parsed, Some(stderr.as_bytes()))
        .expect("finding emitted");
        let finding = corpus::layout::findings_dir(&work).join(id.0);

        let output = Command::new(env!("CARGO_BIN_EXE_cli"))
            .args(["replay", finding.to_str().unwrap(), "--harness"])
            .arg(&harness)
            .args(["--json", "--show-output"])
            .env("BHF_RUNTRACE_SHIM", &shim)
            .env("ASAN_SYMBOLIZER_PATH", &symbolizer)
            .env_remove("DEBUGINFOD_URLS")
            .output()
            .unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|_| panic!("{}{}", text(&output.stdout), text(&output.stderr)));
        let replayed = doc["output"]["stderr"].as_str().unwrap_or_default();
        assert!(
            replayed.contains("input published to the shim"),
            "past {past}: the replay preloads the shim: {replayed}"
        );
        assert_eq!(
            output.status.code(),
            Some(0),
            "past {past}: {}\n{replayed}",
            doc["differences"]
        );
        assert_eq!(doc["verdict"], "match", "past {past}: {doc}");
        assert_eq!(
            doc["crash"]["kind"], "heap-buffer-overflow",
            "past {past}: {replayed}"
        );
        let allocated = doc["crash"]["allocated"].to_string();
        assert!(
            allocated.contains("bhf_run_file") && !allocated.contains("alloc::"),
            "past {past}: {allocated}\n{replayed}"
        );
    }
    fs::remove_dir_all(&root).ok();
}

/// A finding recorded from a real run of `harness` on `input`, with the
/// harness build's sha256.
#[cfg(unix)]
fn record_real_finding(work: &Path, harness: &Path, input: &[u8]) -> PathBuf {
    let testcase = work.join("input.bin");
    fs::write(&testcase, input).unwrap();
    let output = Command::new(harness).arg(&testcase).output().unwrap();
    let stderr = text(&output.stderr);
    let parsed = corpus::parse_sanitizer_report(&stderr).expect("the harness reports");
    let id = corpus::FindingEmitter::with_metadata(
        work.to_path_buf(),
        "H-1".to_owned(),
        "c".to_owned(),
        harness.display().to_string(),
    )
    .with_build_binary(serde_json::json!({"sha256": sha256_hex(harness)}))
    .emit_sanitizer_crash_with_log(input, &parsed, Some(stderr.as_bytes()))
    .expect("finding emitted");
    corpus::layout::findings_dir(work).join(id.0)
}

/// A stripped copy of the harness reports the crash with module offsets only:
/// UNVERIFIED, with a note that says the binary is stripped. The recorded
/// build replayed where only `addr2line` can symbolize it is symbolized by
/// replay itself and MATCHes; with no symbolizer at all it is UNVERIFIED.
#[cfg(unix)]
#[test]
fn an_unsymbolized_replay_is_symbolized_for_the_recorded_build_only() {
    let root = temp_dir("stripped");
    let work = root.join("work");
    let Some(harness) = build_overflowing_harness(&work.join("harnesses/H-1")) else {
        eprintln!("skipping: clang unavailable");
        return;
    };
    let finding = record_real_finding(&work, &harness, b"W");
    let stripped = root.join("stripped/main");
    fs::create_dir_all(stripped.parent().unwrap()).unwrap();
    copy_executable(&harness, &stripped);
    if !Command::new("strip")
        .arg(&stripped)
        .status()
        .is_ok_and(|status| status.success())
    {
        eprintln!("skipping: strip unavailable");
        return;
    }
    let output = replay_output(&[
        finding.to_str().unwrap(),
        "--harness",
        stripped.to_str().unwrap(),
    ]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(4), "{stderr}");
    assert!(stderr.starts_with("UNVERIFIED "), "{stderr}");
    assert!(
        stderr.contains("the harness binary is stripped"),
        "{stderr}"
    );

    // The recorded build, whose in-process symbolizer resolves nothing (a
    // symbolizer that answers `??`), under a PATH where only addr2line can
    // symbolize it.
    let Ok(addr2line) = which::which("addr2line") else {
        eprintln!("skipping the offline symbolization: addr2line unavailable");
        return;
    };
    let bin = root.join("bin");
    fs::create_dir_all(&bin).unwrap();
    std::os::unix::fs::symlink(&addr2line, bin.join("addr2line")).unwrap();
    let blind = root.join("blind/llvm-symbolizer");
    fs::create_dir_all(blind.parent().unwrap()).unwrap();
    fs::write(
        &blind,
        "#!/bin/sh\nwhile read -r line; do printf '??\\n??:0:0\\n\\n'; done\n",
    )
    .unwrap();
    make_executable(&blind);
    let replay_with_path = |path: &Path| {
        Command::new(env!("CARGO_BIN_EXE_cli"))
            .arg("replay")
            .arg(&finding)
            .env("PATH", path)
            .env(
                "ASAN_OPTIONS",
                format!("external_symbolizer_path={}", blind.display()),
            )
            .env_remove("ASAN_SYMBOLIZER_PATH")
            .output()
            .unwrap()
    };
    let output = replay_with_path(&bin);
    let stdout = text(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{stdout}{}",
        text(&output.stderr)
    );
    assert!(stdout.contains("sink copy_at"), "{stdout}");
    assert!(stdout.contains("symbolized"), "{stdout}");
    let empty = root.join("empty");
    fs::create_dir_all(&empty).unwrap();
    let output = replay_with_path(&empty);
    assert_eq!(output.status.code(), Some(4), "{}", text(&output.stderr));
}

/// A fatal-signal finding replays only as the same signal: an abort finding
/// replayed against a harness that dies of an illegal instruction is a
/// MISMATCH naming the signal, and nothing is recorded.
#[cfg(unix)]
#[test]
fn a_fatal_signal_replayed_as_another_signal_is_a_mismatch() {
    let root = temp_dir("signal");
    let work = root.join("work");
    let harness = work.join("harnesses/H-1/main");
    fs::create_dir_all(harness.parent().unwrap()).unwrap();
    fs::write(
        &harness,
        "#!/bin/sh
# BHF_FRAMED test driver
kill -ABRT $$
",
    )
    .unwrap();
    make_executable(&harness);
    let abort = corpus::SanitizerReport {
        kind: "fatal-signal".to_owned(),
        rule_id: "BHF-210",
        message: "harness crashed with SIGABRT and no sanitizer report — a reachable crash"
            .to_owned(),
        check: Some("SIGABRT".to_owned()),
        ..Default::default()
    };
    let id = corpus::FindingEmitter::with_metadata(
        work.clone(),
        "H-1".to_owned(),
        "c".to_owned(),
        harness.display().to_string(),
    )
    .with_build_binary(serde_json::json!({"sha256": sha256_hex(&harness)}))
    .emit_sanitizer_crash(b"x", &abort)
    .unwrap();
    let finding = corpus::layout::findings_dir(&work).join(id.0);
    assert_eq!(
        read_finding_json(&finding)["exception"]["signal"],
        "SIGABRT"
    );
    let output = replay_output(&[finding.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));

    let illegal = root.join("illegal/main");
    fs::create_dir_all(illegal.parent().unwrap()).unwrap();
    fs::write(
        &illegal,
        "#!/bin/sh
# BHF_FRAMED test driver
kill -ILL $$
",
    )
    .unwrap();
    make_executable(&illegal);
    let mut record = read_finding_json(&finding);
    record.as_object_mut().unwrap().remove("last_seen");
    fs::write(finding.join("finding.json"), record.to_string()).unwrap();
    let output = replay_output(&[
        finding.to_str().unwrap(),
        "--harness",
        illegal.to_str().unwrap(),
    ]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{stderr}");
    assert!(
        stderr.starts_with("MISMATCH recorded=BHF-210 actual=BHF-210 differs=signal"),
        "{stderr}"
    );
    assert!(read_finding_json(&finding).get("last_seen").is_none());
}

/// A relative `fixture_path` resolves in the work dir holding the finding. When
/// the harness has moved to another harness dir of that work dir, replay runs
/// it there, never a same-named harness relative to the current directory.
#[cfg(unix)]
#[test]
fn replay_never_runs_a_harness_relative_to_the_current_directory() {
    let root = temp_dir("cwd-fallback");
    let work = root.join("work");
    let built = work.join("build/H-1/main");
    let report = asan_report("Widget::copy_at", 12);
    write_crashing_harness(&built, &report);
    let finding = emit_finding(&work, &built, &report);
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(finding.join("finding.json")).unwrap()).unwrap();
    assert_eq!(record["fixture_path"], "build/H-1/main");
    let moved = work.join("auto/H-1/main");
    fs::create_dir_all(moved.parent().unwrap()).unwrap();
    fs::rename(&built, &moved).unwrap();
    let elsewhere = root.join("elsewhere");
    write_crashing_harness(
        &elsewhere.join("build/H-1/main"),
        &asan_report("Widget::other", 8),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_cli"))
        .arg("replay")
        .arg(&finding)
        .current_dir(&elsewhere)
        .output()
        .unwrap();
    let stdout = text(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{stdout}{}",
        text(&output.stderr)
    );
    assert!(
        work.join("auto/H-1/ran").is_file(),
        "the work dir's harness ran"
    );
    assert!(
        !elsewhere.join("build/H-1/ran").exists(),
        "a harness relative to the current directory ran"
    );
    assert!(stdout.contains(moved.to_str().unwrap()), "{stdout}");
}

/// A harness without bhf's marker whose input mode is declared beside it
/// (`harness-protocol.json`, as `bhf project run` writes it) replays through
/// that mode.
#[cfg(unix)]
#[test]
fn a_finding_replays_through_the_declared_input_mode() {
    let root = temp_dir("declared-mode");
    let work = root.join("work");
    let harness = work.join("build/H-1/main");
    let report = asan_report("Widget::copy_at", 12);
    fs::create_dir_all(harness.parent().unwrap()).unwrap();
    fs::write(
        &harness,
        format!(
            "#!/bin/sh\n[ -f \"$1\" ] || exit 0\ncat >&2 <<'REPORT'\n{report}REPORT\nkill -ABRT $$\n"
        ),
    )
    .unwrap();
    make_executable(&harness);
    fs::write(
        harness.parent().unwrap().join("harness-protocol.json"),
        r#"{"schema_version":1,"input_mode":"framed","source":"bhf.project.v1 manifest"}"#,
    )
    .unwrap();
    let finding = emit_finding(&work, &harness, &report);

    let output = replay_output(&[finding.to_str().unwrap(), "--json"]);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("{}", text(&output.stderr)));
    assert_eq!(value["verdict"], "match", "{value}");
    assert_eq!(value["harness"]["protocol"], "bhf framed", "{value}");
    let basis = value["harness"]["protocol_basis"].as_str().unwrap();
    assert!(
        basis.contains("declared in harness-protocol.json"),
        "{basis}"
    );
    assert_eq!(output.status.code(), Some(0));
}

/// `--harness` is a path: a bare name runs the file in the current
/// directory, never a program of that name on `PATH`.
#[cfg(unix)]
#[test]
fn a_bare_harness_name_runs_the_file_in_the_current_directory() {
    let root = temp_dir("bare-harness");
    let here = root.join("here");
    let harness = here.join("other_ab");
    let report = asan_report("Widget::copy_at", 12);
    write_crashing_harness(&harness, &report);
    let finding = emit_finding(&root.join("work"), &harness, &report);
    let on_path = root.join("on-path");
    fs::create_dir_all(&on_path).unwrap();
    fs::write(
        on_path.join("other_ab"),
        "#!/bin/sh\ntouch \"$(dirname \"$0\")/wrong\"\nexit 0\n",
    )
    .unwrap();
    make_executable(&on_path.join("other_ab"));
    let path = format!(
        "{}:{}",
        on_path.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let run = |command: &str| {
        Command::new(env!("CARGO_BIN_EXE_cli"))
            .args([command, finding.to_str().unwrap(), "--harness", "other_ab"])
            .current_dir(&here)
            .env("PATH", &path)
            .output()
            .unwrap()
    };
    let output = run("replay");
    let stderr = text(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}{stderr}",
        text(&output.stdout)
    );
    assert!(here.join("ran").is_file(), "{stderr}");
    assert!(!on_path.join("wrong").exists(), "{stderr}");
    assert!(!stderr.contains("spawn other_ab"), "{stderr}");

    let output = run("minimize");
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    assert!(finding.join("min_testcase.bin").is_file(), "{stderr}");
    assert!(!on_path.join("wrong").exists(), "{stderr}");
}

/// A recorded harness sha256 is read from finding.json and may not be hex: the
/// summary shortens it without splitting a character.
#[cfg(unix)]
#[test]
fn a_non_ascii_recorded_harness_hash_does_not_break_the_summary() {
    let root = temp_dir("hash");
    let work = root.join("work");
    let harness = work.join("harnesses/H-1/main");
    let report = asan_report("Widget::copy_at", 12);
    write_crashing_harness(&harness, &report);
    let finding = emit_finding(&work, &harness, &report);
    let mut record: serde_json::Value =
        serde_json::from_slice(&fs::read(finding.join("finding.json")).unwrap()).unwrap();
    record["build"] = serde_json::json!({"binary": {"sha256": "\u{20ac}".repeat(20)}});
    fs::write(
        finding.join("finding.json"),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();

    let output = replay_output(&[finding.to_str().unwrap()]);
    let stdout = text(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{stdout}{}",
        text(&output.stderr)
    );
    assert!(
        stdout.contains(&format!(
            "sha256 differs from the recorded build ({})",
            "\u{20ac}".repeat(16)
        )),
        "{stdout}"
    );
}

/// The Ada (event-log) replay summary carries the harness's exit status and
/// how long the run took.
#[cfg(unix)]
#[test]
fn the_event_log_replay_summary_has_an_exit_status() {
    let (_root, finding_dir) = write_finding("match");
    let output = replay_output(&[
        finding_dir.to_str().unwrap(),
        "--harness",
        fake_harness().to_str().unwrap(),
    ]);
    let stdout = text(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert_eq!(stdout.lines().next(), Some("MATCH"), "{stdout}");
    assert!(stdout.contains("exit status 0 after"), "{stdout}");
    let output = replay_output(&[
        finding_dir.to_str().unwrap(),
        "--harness",
        fake_harness().to_str().unwrap(),
        "--json",
    ]);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["exit"]["code"], 0);
}

/// The testcase the fake harness reports for the input `escaped`: a
/// `raise Program_Error with "empty record"` at widgets.adb:6 that escapes to
/// the harness.
#[cfg(unix)]
fn escaped_testcase() -> event_log::Testcase {
    event_log::Testcase {
        testcase_id: 1,
        target_id: 0x42,
        target_entered: false,
        crumbs: vec![1],
        handlers: Vec::new(),
        raises: vec![event_log::RaiseEvent {
            sequence_index: 3,
            exception_name: "Program_Error".to_owned(),
            file: "widgets.adb".to_owned(),
            line: 6,
            breadcrumb: 1,
        }],
        top_level: Some(event_log::TopLevelEvent {
            exception_name: "PROGRAM_ERROR".to_owned(),
            exception_message: "empty record".to_owned(),
        }),
        end: None,
        mocks: Vec::new(),
    }
}

/// An event-log replay says what was raised and where, for the recorded run
/// and the replayed one: the exception, its message, the raise site and the
/// handler, on a MATCH and on a MISMATCH, in text and in --json.
#[cfg(unix)]
#[test]
fn the_event_log_replay_says_what_was_raised_and_where() {
    let work_root = temp_dir("event-log-detail");
    let work = work_root.join("work");
    let id = corpus::FindingEmitter::new(work.clone())
        .emit(
            b"escaped",
            &escaped_testcase(),
            corpus::UNHANDLED_HANDLER_INDEX,
        )
        .expect("finding emitted");
    let finding = corpus::layout::findings_dir(&work).join(id.0);
    let finding_arg = finding.to_str().unwrap();
    let harness = fake_harness().to_str().unwrap();

    let output = replay_output(&[finding_arg, "--harness", harness]);
    let stdout = text(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{stdout}{}",
        text(&output.stderr)
    );
    assert_eq!(stdout.lines().next(), Some("MATCH"), "{stdout}");
    for needle in [
        "crash      BHF-101 unhandled: PROGRAM_ERROR: empty record",
        "reported   widgets.adb:6",
        "handled    not handled: it reached the harness",
        "recorded   BHF-101 unhandled: PROGRAM_ERROR: empty record",
        "           raised at widgets.adb:6; not handled: it reached the harness",
    ] {
        assert!(stdout.contains(needle), "missing {needle:?} in:\n{stdout}");
    }
    let log = fs::read_to_string(finding.join("replay.log")).unwrap();
    assert!(log.contains("PROGRAM_ERROR: empty record"), "{log}");

    let output = replay_output(&[finding_arg, "--harness", harness, "--json"]);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["crash"]["rule"], "BHF-101", "{value:#}");
    assert_eq!(value["crash"]["kind"], "unhandled");
    assert_eq!(value["crash"]["location"], "widgets.adb:6");
    let exceptions = &value["exceptions"];
    for raised in [&exceptions["recorded"], &exceptions["replayed"][0]] {
        assert_eq!(raised["name"], "PROGRAM_ERROR", "{value:#}");
        assert_eq!(raised["message"], "empty record");
        assert_eq!(raised["raised_at"], "widgets.adb:6");
        assert!(raised["handled_at"].is_null());
        assert_eq!(raised["classification"], "unhandled");
    }

    // Another fault from the same harness: both sides are named, and so is
    // what differs between them.
    fs::write(finding.join("testcase.bin"), b"index").unwrap();
    let output = replay_output(&[finding_arg, "--harness", harness]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{stderr}");
    assert!(stderr.starts_with("MISMATCH recorded="), "{stderr}");
    for needle in [
        "differs    exception: recorded PROGRAM_ERROR, replayed CONSTRAINT_ERROR",
        "differs    raised at: recorded widgets.adb:6, replayed widgets.adb:16",
        "crash      BHF-101 unhandled: CONSTRAINT_ERROR: widgets.adb:16 index check failed",
        "reported   widgets.adb:16",
        "recorded   BHF-101 unhandled: PROGRAM_ERROR: empty record",
        "           raised at widgets.adb:6; not handled: it reached the harness",
    ] {
        assert!(stderr.contains(needle), "missing {needle:?} in:\n{stderr}");
    }
}

/// A MISMATCH compares the recorded exception with the replayed one closest
/// to it. Here the replay first raises and handles another exception, then
/// raises the recorded one unhandled, at another site and after another
/// breadcrumb: `crash`, `actual=` and `differs` are about the escaped one,
/// and the handled one is listed under `also`.
#[cfg(unix)]
#[test]
fn an_event_log_mismatch_compares_the_closest_replayed_exception() {
    let work_root = temp_dir("event-log-closest");
    let work = work_root.join("work");
    let recorded = event_log::Testcase {
        testcase_id: 1,
        target_id: 0x42,
        target_entered: false,
        crumbs: vec![1, 3],
        handlers: vec![event_log::HandlerEvent {
            sequence_index: 4,
            exception_name: "WIDGET_ERROR".to_owned(),
            exception_message: "bad widget".to_owned(),
            handler_file: "widgets.adb".to_owned(),
            handler_line: 18,
            last_breadcrumb: 3,
            target_id: 0x42,
            testcase_id: 1,
        }],
        raises: vec![event_log::RaiseEvent {
            sequence_index: 3,
            exception_name: "Widget_Error".to_owned(),
            file: "widgets.adb".to_owned(),
            line: 14,
            breadcrumb: 3,
        }],
        top_level: Some(event_log::TopLevelEvent {
            exception_name: "CONSTRAINT_ERROR".to_owned(),
            exception_message: "widgets.adb:19 index check failed".to_owned(),
        }),
        end: None,
        mocks: Vec::new(),
    };
    let id = corpus::FindingEmitter::new(work.clone())
        .emit(
            b"handled-then-escaped",
            &recorded,
            corpus::UNHANDLED_HANDLER_INDEX,
        )
        .expect("finding emitted");
    let finding = corpus::layout::findings_dir(&work).join(id.0);
    let finding_arg = finding.to_str().unwrap();
    let harness = fake_harness().to_str().unwrap();

    let output = replay_output(&[finding_arg, "--harness", harness]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{stderr}");
    let differs: Vec<&str> = stderr
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("differs "))
        .map(str::trim_start)
        .filter(|difference| !difference.starts_with("signature:"))
        .collect();
    assert_eq!(
        differs,
        [
            "raised at: recorded widgets.adb:19, replayed widgets.adb:22",
            "last breadcrumb: recorded 3, replayed 4",
        ],
        "{stderr}"
    );
    for needle in [
        "crash      BHF-101 unhandled: CONSTRAINT_ERROR: widgets.adb:22 index check failed",
        "reported   widgets.adb:22",
        "handled    not handled: it reached the harness",
        "also       BHF-106 explicit_raise: WIDGET_ERROR: bad widget",
        "           raised at widgets.adb:17; handled at widgets.adb:21",
        "recorded   BHF-101 unhandled: CONSTRAINT_ERROR: widgets.adb:19 index check failed",
    ] {
        assert!(stderr.contains(needle), "missing {needle:?} in:\n{stderr}");
    }

    let output = replay_output(&[finding_arg, "--harness", harness, "--json"]);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    let replayed = &value["exceptions"]["replayed"];
    assert_eq!(replayed[0]["name"], "WIDGET_ERROR", "{value:#}");
    assert_eq!(replayed[1]["name"], "CONSTRAINT_ERROR", "{value:#}");
    let escaped = replayed[1]["signature"].as_str().expect("a signature");
    assert_eq!(value["signature"]["replayed"], escaped, "{value:#}");
    assert_eq!(
        value["crash"]["message"],
        "CONSTRAINT_ERROR: widgets.adb:22 index check failed"
    );
    let recorded_hex = value["signature"]["recorded"].as_str().unwrap();
    assert!(
        stderr.starts_with(&format!(
            "MISMATCH recorded={recorded_hex} actual={escaped}"
        )),
        "{stderr}"
    );
}

/// A replay that raised nothing says so, beside what the finding recorded.
#[cfg(unix)]
#[test]
fn an_event_log_replay_that_raised_nothing_says_so() {
    let work_root = temp_dir("event-log-nothing");
    let work = work_root.join("work");
    let id = corpus::FindingEmitter::new(work.clone())
        .emit(
            b"escaped",
            &escaped_testcase(),
            corpus::UNHANDLED_HANDLER_INDEX,
        )
        .expect("finding emitted");
    let finding = corpus::layout::findings_dir(&work).join(id.0);
    // The fake harness reports one handled exception for any other input;
    // a shell harness that writes an empty event log raises nothing.
    let harness = work.join("quiet.sh");
    fs::write(
        &harness,
        "#!/bin/sh\ncat >/dev/null\n: > \"$BHF_EVENTS_PATH\"\n",
    )
    .unwrap();
    make_executable(&harness);
    let output = replay_output(&[
        finding.to_str().unwrap(),
        "--harness",
        harness.to_str().unwrap(),
    ]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{stderr}");
    for needle in [
        "actual=<none>",
        "differs    exception: recorded PROGRAM_ERROR, the replay raised none",
        "crash      none: the replayed run raised no exception",
        "recorded   BHF-101 unhandled: PROGRAM_ERROR: empty record",
    ] {
        assert!(stderr.contains(needle), "missing {needle:?} in:\n{stderr}");
    }
}

/// An Ada package with two faults: an empty record is rejected with
/// `Program_Error` (an explicit raise at line 6), and any other record fails
/// the index check at line 8.
#[cfg(unix)]
const WIDGETS_ADS: &str = "package Widgets is
   function Parse_Record (Data : String) return Natural;
end Widgets;
";
#[cfg(unix)]
const WIDGETS_ADB: &str = "--  Reads one byte past the end of a record.
package body Widgets is
   function Parse_Record (Data : String) return Natural is
   begin
      if Data'Length = 0 then
         raise Program_Error with \"empty record\";
      end if;
      return Character'Pos (Data (Data'Last + 1));
   end Parse_Record;
end Widgets;
";

/// The findings `bhf auto` records for a real Ada target replay with what
/// was raised and where (on the source's own lines), on a MATCH and, when
/// one fault's input is replayed against the other's finding, on a MISMATCH.
#[cfg(unix)]
#[test]
fn an_ada_finding_replay_says_what_was_raised_and_where() {
    if which::which("gnatmake").is_err() || which::which("gprbuild").is_err() {
        eprintln!("SKIP: gnatmake/gprbuild not installed; the Ada lane is unavailable");
        return;
    }
    let root = temp_dir("ada-replay-detail");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("widgets.ads"), WIDGETS_ADS).unwrap();
    fs::write(src.join("widgets.adb"), WIDGETS_ADB).unwrap();
    let work = root.join("work");
    let auto = Command::new(env!("CARGO_BIN_EXE_bhf"))
        .arg("auto")
        .arg(&src)
        .arg("--work-dir")
        .arg(&work)
        .arg("--per-target-time")
        .arg("3")
        .output()
        .unwrap();
    let findings: Vec<(PathBuf, serde_json::Value)> =
        fs::read_dir(corpus::layout::findings_dir(&work))
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.path())
                    .filter_map(|dir| {
                        let raw = fs::read(dir.join("finding.json")).ok()?;
                        Some((dir, serde_json::from_slice(&raw).ok()?))
                    })
                    .collect()
            })
            .unwrap_or_default();
    let by_name = |name: &str| {
        findings
            .iter()
            .find(|(_, finding)| finding["exception"]["name"] == name)
            .unwrap_or_else(|| {
                panic!(
                    "no {name} finding in {findings:#?}\nbhf auto exit {:?}\n{}",
                    auto.status.code(),
                    text(&auto.stderr)
                )
            })
    };
    let (empty, empty_finding) = by_name("PROGRAM_ERROR");
    let (check, _) = by_name("CONSTRAINT_ERROR");
    let empty_what = "PROGRAM_ERROR: empty record";
    let check_what = "CONSTRAINT_ERROR: widgets.adb:8 index check failed";
    for (finding, what, site) in [
        (empty, empty_what, "widgets.adb:6"),
        (check, check_what, "widgets.adb:8"),
    ] {
        let output = replay_output(&[finding.to_str().unwrap()]);
        let stdout = text(&output.stdout);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{stdout}{}",
            text(&output.stderr)
        );
        assert_eq!(stdout.lines().next(), Some("MATCH"), "{stdout}");
        for needle in [
            format!("crash      BHF-101 unhandled: {what}"),
            format!("reported   {site}"),
            "handled    not handled: it reached the harness".to_owned(),
            format!("recorded   BHF-101 unhandled: {what}"),
            format!("           raised at {site}; not handled: it reached the harness"),
        ] {
            assert!(stdout.contains(&needle), "missing {needle:?} in:\n{stdout}");
        }
    }

    // The empty-record finding, replayed with the failing check's input.
    let swapped = root.join("swapped/findings/F-0000-swapped");
    fs::create_dir_all(&swapped).unwrap();
    fs::copy(empty.join("finding.json"), swapped.join("finding.json")).unwrap();
    fs::copy(check.join("testcase.bin"), swapped.join("testcase.bin")).unwrap();
    let harness = work.join(empty_finding["fixture_path"].as_str().unwrap());
    let output = replay_output(&[
        swapped.to_str().unwrap(),
        "--harness",
        harness.to_str().unwrap(),
    ]);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "{stderr}");
    assert!(stderr.starts_with("MISMATCH recorded="), "{stderr}");
    for needle in [
        "differs    exception: recorded PROGRAM_ERROR, replayed CONSTRAINT_ERROR".to_owned(),
        "differs    raised at: recorded widgets.adb:6, replayed widgets.adb:8".to_owned(),
        format!("crash      BHF-101 unhandled: {check_what}"),
        "reported   widgets.adb:8".to_owned(),
        format!("recorded   BHF-101 unhandled: {empty_what}"),
        "           raised at widgets.adb:6; not handled: it reached the harness".to_owned(),
    ] {
        assert!(stderr.contains(&needle), "missing {needle:?} in:\n{stderr}");
    }
}

/// A reproduction recorded by replay leaves results/ consistent: every
/// attested digest matches the file on disk.
#[cfg(unix)]
#[test]
fn replay_keeps_the_results_attestation_current() {
    use sha2::{Digest, Sha256};
    let root = temp_dir("attestation");
    let work = root.join("work");
    let harness = work.join("harnesses/H-1/main");
    let report = asan_report("Widget::copy_at", 12);
    write_crashing_harness(&harness, &report);
    let finding = emit_finding(&work, &harness, &report);
    assert_eq!(
        cli::run_from(["bhf", "report", "--work-dir", work.to_str().unwrap()]),
        0
    );
    assert_eq!(
        cli::run_from(["bhf", "replay", finding.to_str().unwrap()]),
        0
    );
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(finding.join("finding.json")).unwrap()).unwrap();
    assert!(record.get("last_seen").is_some());
    let results = work.join("results");
    let attestation: serde_json::Value =
        serde_json::from_slice(&fs::read(results.join("attestation.json")).unwrap()).unwrap();
    let subjects = attestation["subject"].as_array().unwrap();
    assert!(subjects
        .iter()
        .any(|s| s["name"].as_str().unwrap().ends_with("finding.json")));
    for subject in subjects {
        let name = subject["name"].as_str().unwrap();
        let digest = corpus::hex_lower(&Sha256::digest(fs::read(results.join(name)).unwrap()));
        assert_eq!(
            subject["digest"]["sha256"].as_str().unwrap(),
            digest,
            "{name} is stale in the attestation"
        );
    }
}

/// A bhf-driver-protocol script harness that, with BHF_TRACE_ARGS=1, prints
/// the argument trace a generated harness prints, then crashes with `report`.
#[cfg(unix)]
fn write_tracing_crashing_harness(path: &Path, report: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        path,
        format!(
            "#!/bin/sh\n# BHF_FRAMED test driver\n\
             if [ \"$BHF_TRACE_ARGS\" = 1 ]; then\n\
             >&2 echo 'BHF_ARG {{\"call\":\"target\",\"i\":0,\"role\":\"param\",\"name\":\"buffer\",\"type\":\"const char *\",\"decoder\":\"bhf_c_string(4096)\",\"span\":[0,2],\"ptr\":\"0x602000000030\",\"alloc_size\":1,\"len\":0,\"preview_hex\":\"\"}}'\n\
             >&2 echo 'BHF_ARG {{\"call\":\"target\",\"i\":1,\"role\":\"out\",\"name\":\"offset\",\"type\":\"unsigned short &\",\"span\":[2,6],\"value\":\"5\"}}'\n\
             fi\n\
             cat >&2 <<'REPORT'\n{report}REPORT\nkill -ABRT $$\n"
        ),
    )
    .unwrap();
    make_executable(path);
}

/// `--show-args` runs the harness with its argument trace on and prints each
/// decoded argument and the parameter whose buffer the access hit; `--json`
/// carries them as `arguments`. Without the flag the trace stays off.
#[cfg(unix)]
#[test]
fn replay_show_args_prints_the_decoded_arguments() {
    let root = temp_dir("show-args");
    let work = root.join("work");
    let harness = work.join("harnesses/H-1/main");
    let report = asan_report("Widget::copy_at", 12);
    write_tracing_crashing_harness(&harness, &report);
    let finding = emit_finding(&work, &harness, &report);

    let output = replay_output(&[finding.to_str().unwrap(), "--show-args"]);
    let stdout = text(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{stdout}\n{}",
        text(&output.stderr)
    );
    assert!(
        stdout.contains("--- decoded arguments (BHF_TRACE_ARGS=1) ---"),
        "{stdout}"
    );
    let buffer = stdout
        .lines()
        .find(|line| line.trim_start().starts_with("buffer"))
        .unwrap_or_else(|| panic!("no buffer row in:\n{stdout}"));
    assert!(buffer.contains("const char *"), "{buffer}");
    assert!(buffer.contains("0..2"), "{buffer}");
    // The prefix is read from the testcase ("wi"), the length is the harness's.
    assert!(buffer.contains("len 0 (prefix 26999), alloc 1"), "{buffer}");
    assert!(stdout.contains("unsigned short &"), "{stdout}");
    assert!(
        stdout.contains("the access hit parameter `buffer`'s buffer, at offset 1"),
        "{stdout}"
    );

    let output = replay_output(&[finding.to_str().unwrap(), "--json", "--show-args"]);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["arguments"]["traced"][0]["name"], "buffer");
    assert_eq!(value["arguments"]["traced"][1]["value"], "5");
    assert_eq!(value["arguments"]["accessed_parameter"]["name"], "buffer");

    let output = replay_output(&[finding.to_str().unwrap()]);
    let stdout = text(&output.stdout);
    assert!(!stdout.contains("decoded arguments"), "{stdout}");
}

/// A harness built without the argument trace says so under `--show-args`.
#[cfg(unix)]
#[test]
fn replay_show_args_explains_a_harness_without_the_trace() {
    let root = temp_dir("show-args-none");
    let work = root.join("work");
    let harness = work.join("harnesses/H-1/main");
    let report = asan_report("Widget::copy_at", 12);
    write_crashing_harness(&harness, &report);
    let finding = emit_finding(&work, &harness, &report);

    let output = replay_output(&[finding.to_str().unwrap(), "--show-args"]);
    let stdout = text(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert!(
        stdout
            .contains("--- no decoded arguments: the harness was built without the argument trace"),
        "{stdout}"
    );
}

/// A harness that hands the input straight to the project's own
/// `LLVMFuzzerTestOneInput` decodes no parameters: `--show-args` and
/// `decode-args` say so, instead of blaming a missing argument trace.
#[cfg(unix)]
#[test]
fn a_passthrough_harness_says_it_decodes_no_parameters() {
    let root = temp_dir("show-args-passthrough");
    let work = root.join("work");
    let harness = work.join("harnesses/H-1/main");
    let report = asan_report("Widget::copy_at", 12);
    write_crashing_harness(&harness, &report);
    let dir = harness.parent().unwrap();
    fs::write(
        dir.join("main.c"),
        "/* BHF_FRAMED */\n/* bhf driver for a passthrough libFuzzer entrypoint. */\n",
    )
    .unwrap();
    fs::write(
        dir.join("generation-metadata.json"),
        r#"{"schema_version":1,"language":"c","target_function":"LLVMFuzzerTestOneInput"}"#,
    )
    .unwrap();
    let finding = emit_finding(&work, &harness, &report);

    let output = replay_output(&[finding.to_str().unwrap(), "--show-args"]);
    let stdout = text(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert!(
        stdout.contains(
            "--- no decoded arguments: this harness passes the input straight to \
             LLVMFuzzerTestOneInput; it decodes no parameters ---"
        ),
        "{stdout}"
    );
    assert!(!stdout.contains("argument trace"), "{stdout}");

    let output = Command::new(env!("CARGO_BIN_EXE_cli"))
        .arg("decode-args")
        .arg("--finding")
        .arg(&finding)
        .output()
        .unwrap();
    let all = format!("{}{}", text(&output.stdout), text(&output.stderr));
    assert!(
        all.contains(
            "this harness passes the input straight to LLVMFuzzerTestOneInput; it decodes no \
             parameters"
        ),
        "{all}"
    );
    assert!(!all.contains("built without the argument trace"), "{all}");
}

/// A harness with an emulator recorded beside it (`bhf_runner.json`, as a
/// cross build writes it) runs under that emulator in replay, minimize,
/// decode-args and fuzz without `--qemu-user`, and each says so.
#[cfg(unix)]
#[test]
fn the_recorded_runner_runs_the_harness_everywhere() {
    let root = temp_dir("recorded-runner");
    let work = root.join("work");
    let harness = work.join("harnesses/H-1/main");
    let report = asan_report("Widget::copy_at", 12);
    write_tracing_crashing_harness(&harness, &report);
    let dir = harness.parent().unwrap();
    let wrapper = dir.join("emulator.sh");
    fs::write(
        &wrapper,
        "#!/bin/sh\nprintf 'ran %s\\n' \"$1\" >> \"$EMULATOR_LOG\"\nshift\nexec \"$@\"\n",
    )
    .unwrap();
    make_executable(&wrapper);
    fs::write(
        dir.join("bhf_runner.json"),
        serde_json::json!({
            "schema": "bhf.harness_runner.v1",
            "program": wrapper.display().to_string(),
            "args": ["--tag"],
        })
        .to_string(),
    )
    .unwrap();
    let finding = emit_finding(&work, &harness, &report);
    let log = finding.join("emulator.log");
    let runs = || {
        fs::read_to_string(&log)
            .unwrap_or_default()
            .lines()
            .filter(|line| *line == "ran --tag")
            .count()
    };
    let bhf = |args: &[&std::ffi::OsStr]| {
        Command::new(env!("CARGO_BIN_EXE_cli"))
            .args(args)
            .env("EMULATOR_LOG", &log)
            .output()
            .unwrap()
    };
    let note = format!(
        "note: running {} under the recorded runner {} --tag",
        harness.display(),
        wrapper.display()
    );

    let out = bhf(&[
        "replay".as_ref(),
        finding.as_os_str(),
        "--sandbox".as_ref(),
        "none".as_ref(),
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains(&note), "{}", text(&out.stderr));
    assert_eq!(runs(), 1, "replay ran under the runner");

    let out = bhf(&["minimize".as_ref(), finding.as_os_str()]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let after_minimize = runs();
    assert!(after_minimize > 1, "minimize ran under the runner");

    let out = bhf(&[
        "decode-args".as_ref(),
        "--finding".as_ref(),
        finding.as_os_str(),
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("buffer"),
        "{}",
        text(&out.stdout)
    );
    assert!(runs() > after_minimize, "decode-args ran under the runner");
    let after_decode = runs();

    let out = bhf(&[
        "fuzz".as_ref(),
        work.as_os_str(),
        "--harness".as_ref(),
        "H-1".as_ref(),
        "--iterations".as_ref(),
        "1".as_ref(),
        "--no-fork-server".as_ref(),
        "--sandbox".as_ref(),
        "none".as_ref(),
        "--seed-input".as_ref(),
        "x".as_ref(),
    ]);
    assert!(
        text(&out.stderr).contains(&note),
        "{}{}",
        text(&out.stdout),
        text(&out.stderr)
    );
    assert!(runs() > after_decode, "fuzz ran under the runner");
}

/// A copy of a native ELF binary relabelled as an AArch64 one (its
/// `e_machine`), which the host cannot run.
#[cfg(unix)]
fn foreign_elf(path: &Path) {
    let mut bytes = fs::read("/bin/true").unwrap();
    assert_eq!(&bytes[..4], b"\x7fELF");
    bytes[18] = 183;
    bytes[19] = 0;
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
    make_executable(path);
}

/// A harness built for another architecture, with no runner given or
/// recorded, is refused before it runs, with the flag to pass.
#[cfg(target_os = "linux")]
#[test]
fn a_foreign_harness_without_a_runner_is_refused_with_the_flag_to_pass() {
    if cfg!(target_arch = "aarch64") {
        eprintln!("skipping: the relabelled binary is native here");
        return;
    }
    let root = temp_dir("foreign-arch");
    let work = root.join("work");
    let harness = work.join("harnesses/H-1/main");
    foreign_elf(&harness);
    let report = asan_report("Widget::copy_at", 12);
    let finding = emit_finding(&work, &harness, &report);
    let expected = format!(
        "{} is built for aarch64; run it under an emulator: --qemu-user qemu-aarch64",
        harness.display()
    );
    for args in [
        vec!["replay".to_owned(), finding.display().to_string()],
        vec!["minimize".to_owned(), finding.display().to_string()],
        vec![
            "decode-args".to_owned(),
            "--finding".to_owned(),
            finding.display().to_string(),
        ],
        vec![
            "fuzz".to_owned(),
            work.display().to_string(),
            "--harness".to_owned(),
            "H-1".to_owned(),
            "--iterations".to_owned(),
            "1".to_owned(),
        ],
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_cli"))
            .args(&args)
            .output()
            .unwrap();
        let all = format!("{}{}", text(&out.stdout), text(&out.stderr));
        assert!(!out.status.success(), "{args:?}: {all}");
        assert!(all.contains(&expected), "{args:?}: {all}");
    }
}

/// A qemu-user replay of a sanitized harness does not abort on its report:
/// under emulation an abort makes the emulator dump its whole address space.
/// It also writes no core file at all.
#[cfg(unix)]
#[test]
fn an_emulated_replay_neither_aborts_nor_dumps_core() {
    let root = temp_dir("emulated-env");
    let work = root.join("work");
    let harness = work.join("harnesses/H-1/main");
    let report = asan_report("Widget::copy_at", 12);
    write_crashing_harness(&harness, &report);
    let finding = emit_finding(&work, &harness, &report);
    let qemu = root.join("qemu-fake");
    fs::write(
        &qemu,
        "#!/bin/sh\nulimit -c > \"$(dirname \"$0\")/core-limit.txt\"\nexec \"$@\"\n",
    )
    .unwrap();
    make_executable(&qemu);
    let out = replay_output(&[
        finding.to_str().unwrap(),
        "--qemu-user",
        qemu.to_str().unwrap(),
        "--sandbox",
        "none",
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert_eq!(
        fs::read_to_string(root.join("core-limit.txt"))
            .unwrap()
            .trim(),
        "0"
    );
    let options = fs::read_to_string(harness.parent().unwrap().join("asan-options.txt")).unwrap();
    let abort = options
        .split(':')
        .rev()
        .find(|item| item.starts_with("abort_on_error="));
    assert_eq!(abort, Some("abort_on_error=0"), "{options}");
}

/// A finding recorded against an older harness input format than its
/// harness now decodes is flagged by replay and minimize, which name both
/// formats; one recorded against the same format is not.
#[cfg(unix)]
#[test]
fn replay_and_minimize_flag_a_finding_recorded_against_another_harness_format() {
    let root = temp_dir("format-mismatch");
    let work = root.join("work");
    let harness = work.join("harnesses/H-1/main");
    let report = asan_report("Widget::copy_at", 12);
    write_crashing_harness(&harness, &report);
    fs::write(
        harness.parent().unwrap().join("generation-metadata.json"),
        "{\"schema_version\":1,\"harness_format_version\":3,\"language\":\"cpp\"}",
    )
    .unwrap();
    let emit = |version: Option<u32>| {
        let parsed = corpus::parse_sanitizer_report(&report).expect("report parses");
        let id = corpus::FindingEmitter::with_metadata(
            work.clone(),
            "H-1".to_owned(),
            "cpp".to_owned(),
            harness.display().to_string(),
        )
        .with_harness_format_version(version)
        .emit_sanitizer_crash_with_log(
            format!("widget-input-{version:?}").as_bytes(),
            &parsed,
            Some(report.as_bytes()),
        )
        .expect("finding emitted");
        corpus::layout::findings_dir(&work).join(id.0)
    };

    let older = emit(Some(2));
    let output = replay_output(&[older.to_str().unwrap()]);
    let stdout = text(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert!(
        stdout.contains("this finding was recorded against harness input format 2")
            && stdout.contains("decodes format 3"),
        "{stdout}"
    );
    let output = replay_output(&[older.to_str().unwrap(), "--json"]);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert!(value["notes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|note| note.as_str().unwrap().contains("input format 2")));

    let unversioned = emit(None);
    let stdout = text(&replay_output(&[unversioned.to_str().unwrap()]).stdout);
    assert!(stdout.contains("input format 2 or earlier"), "{stdout}");

    let current = emit(Some(3));
    let stdout = text(&replay_output(&[current.to_str().unwrap()]).stdout);
    assert!(
        !stdout.contains("recorded against harness input format"),
        "{stdout}"
    );

    let minimize = Command::new(env!("CARGO_BIN_EXE_cli"))
        .args([
            "minimize",
            older.to_str().unwrap(),
            "--harness",
            harness.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stderr = text(&minimize.stderr);
    assert!(
        stderr.contains("note: this finding was recorded against harness input format 2"),
        "{stderr}"
    );
}

/// Whether `tool --version` runs.
#[cfg(unix)]
fn tool_runs(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
}

/// `--debugger gdb` re-runs the testcase under gdb: it stops at the
/// harness's target function and prints its arguments and stack, then
/// continues to the AddressSanitizer report and prints the stack again.
#[cfg(unix)]
#[test]
fn replay_debugger_stops_at_the_target_and_at_the_crash() {
    if !tool_runs("clang") || !tool_runs("gdb") {
        eprintln!("skipping: clang or gdb unavailable");
        return;
    }
    let work = temp_dir("debugger");
    let harness_dir = work.join("harnesses/H-DBG");
    fs::create_dir_all(&harness_dir).unwrap();
    fs::write(
        harness_dir.join("main.c"),
        "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\
         __attribute__((noinline)) int widget_crash(int value, const char *label) {\n\
         \x20   char *buf = malloc(4);\n\
         \x20   memset(buf, 0, 4);\n\
         \x20   int r = buf[value & 0xff];\n\
         \x20   free(buf);\n\
         \x20   return r + label[0];\n\
         }\n\
         int main(int argc, char **argv) {\n\
         \x20   unsigned char b[4] = {0};\n\
         \x20   FILE *f = argc > 1 ? fopen(argv[1], \"rb\") : NULL;\n\
         \x20   if (!f) return 2;\n\
         \x20   if (fread(b, 1, 4, f) != 4) return 2;\n\
         \x20   fclose(f);\n\
         \x20   return widget_crash(b[0] | b[1] << 8 | b[2] << 16 | b[3] << 24, \"AB\");\n\
         }\n",
    )
    .unwrap();
    let build = Command::new("clang")
        .args(["-g", "-O0", "-fsanitize=address", "-o"])
        .arg(harness_dir.join("main"))
        .arg(harness_dir.join("main.c"))
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", text(&build.stderr));
    fs::write(
        harness_dir.join("generation-metadata.json"),
        r#"{"schema_version":1,"harness_format_version":3,"language":"c","target_function":"widget_crash"}"#,
    )
    .unwrap();
    let finding = corpus::layout::findings_dir(&work).join("F-0001-0dbg0dbg");
    fs::create_dir_all(&finding).unwrap();
    fs::write(finding.join("testcase.bin"), b"AAAA").unwrap();
    fs::write(
        finding.join("finding.json"),
        r#"{"id":"F-0001-0dbg0dbg","rule_id":"BHF-201","harness_id":"H-DBG","harness_format_version":3,
            "fixture_path":"harnesses/H-DBG/main",
            "exception":{"name":"ASAN_HEAP_BUFFER_OVERFLOW","sanitizer":"asan","stack":[]}}"#,
    )
    .unwrap();

    let out = replay_output(&[finding.to_str().unwrap(), "--debugger", "gdb"]);
    let all = format!("{}{}", text(&out.stdout), text(&out.stderr));
    assert!(
        all.contains("--- debugger session (gdb, breaking at widget_crash) ---"),
        "{all}"
    );
    // The markers are also in the printed command line; the transcript's
    // come last.
    let entry = all
        .rfind("--- bhf: stopped (at the target entry")
        .unwrap_or_else(|| panic!("{all}"));
    let crash = all
        .rfind("--- bhf: stopped at the crash ---")
        .unwrap_or_else(|| panic!("{all}"));
    assert!(entry < crash, "{all}");
    assert!(
        all[entry..crash].contains("value = 1094795585"),
        "info args at the target's entry: {all}"
    );
    assert!(all[crash..].contains("widget_crash"), "{all}");
    assert!(
        all.contains("heap-buffer-overflow"),
        "the sanitizer report reaches the transcript: {all}"
    );

    let out = replay_output(&[finding.to_str().unwrap(), "--debugger", "gdb", "--json"]);
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["debugger"]["tool"], "gdb", "{doc:#}");
    assert_eq!(doc["debugger"]["breakpoint"], "widget_crash");
    assert!(doc["debugger"]["transcript"]
        .as_str()
        .unwrap()
        .contains("value = 1094795585"));

    // A debugger that is not installed is an error naming what to install,
    // before anything runs.
    if !tool_runs("lldb") {
        let out = replay_output(&[finding.to_str().unwrap(), "--debugger", "lldb"]);
        assert_eq!(out.status.code(), Some(1));
        let stderr = text(&out.stderr);
        assert!(stderr.contains("--debugger needs lldb on PATH"), "{stderr}");
        assert!(!stderr.contains("MATCH"), "{stderr}");
    }
    fs::remove_dir_all(&work).ok();
}

/// A harness from an older bhf names no target function: the debugger
/// session breaks at the finding's recorded sink instead, and says so.
#[cfg(unix)]
#[test]
fn replay_debugger_breaks_at_the_recorded_sink_without_a_target_function() {
    if !tool_runs("clang") || !tool_runs("gdb") {
        eprintln!("skipping: clang or gdb unavailable");
        return;
    }
    let work = temp_dir("debugger-sink");
    let harness_dir = work.join("harnesses/H-DBG");
    fs::create_dir_all(&harness_dir).unwrap();
    fs::write(
        harness_dir.join("main.c"),
        "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\
         __attribute__((noinline)) int widget_crash(int value, const char *label) {\n\
         \x20   char *buf = malloc(4);\n\
         \x20   memset(buf, 0, 4);\n\
         \x20   int r = buf[value & 0xff];\n\
         \x20   free(buf);\n\
         \x20   return r + label[0];\n\
         }\n\
         int main(int argc, char **argv) {\n\
         \x20   unsigned char b[4] = {0};\n\
         \x20   FILE *f = argc > 1 ? fopen(argv[1], \"rb\") : NULL;\n\
         \x20   if (!f) return 2;\n\
         \x20   if (fread(b, 1, 4, f) != 4) return 2;\n\
         \x20   fclose(f);\n\
         \x20   return widget_crash(b[0] | b[1] << 8 | b[2] << 16 | b[3] << 24, \"AB\");\n\
         }\n",
    )
    .unwrap();
    let build = Command::new("clang")
        .args(["-g", "-O0", "-fsanitize=address", "-o"])
        .arg(harness_dir.join("main"))
        .arg(harness_dir.join("main.c"))
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", text(&build.stderr));
    fs::write(
        harness_dir.join("generation-metadata.json"),
        r#"{"schema_version":1,"language":"c"}"#,
    )
    .unwrap();
    let finding = corpus::layout::findings_dir(&work).join("F-0001-0dbg0dbg");
    fs::create_dir_all(&finding).unwrap();
    fs::write(finding.join("testcase.bin"), b"AAAA").unwrap();
    fs::write(
        finding.join("finding.json"),
        r#"{"id":"F-0001-0dbg0dbg","rule_id":"BHF-201","harness_id":"H-DBG",
            "fixture_path":"harnesses/H-DBG/main",
            "exception":{"name":"ASAN_HEAP_BUFFER_OVERFLOW","sanitizer":"asan","stack":[
              {"function":"widget_crash(int, char const*)","file":"/w/harnesses/H-DBG/main.c","line":7},
              {"function":"main","file":"/w/harnesses/H-DBG/main.c","line":16}]}}"#,
    )
    .unwrap();

    let out = replay_output(&[finding.to_str().unwrap(), "--debugger", "gdb"]);
    let all = format!("{}{}", text(&out.stdout), text(&out.stderr));
    assert!(
        all.contains("--- debugger session (gdb, breaking at widget_crash) ---"),
        "{all}"
    );
    assert!(
        all.contains(
            "breaking at the recorded sink widget_crash (the harness records no target function)"
        ),
        "{all}"
    );
    assert!(!all.contains("regenerate the harness"), "{all}");
    let entry = all
        .rfind("--- bhf: stopped (at the target entry")
        .unwrap_or_else(|| panic!("{all}"));
    let crash = all
        .rfind("--- bhf: stopped at the crash ---")
        .unwrap_or_else(|| panic!("{all}"));
    assert!(entry < crash, "{all}");
    assert!(all[entry..crash].contains("value = 1094795585"), "{all}");
    fs::remove_dir_all(&work).ok();
}

/// A finding whose crash needs the replay's runtime environment: the harness
/// overflows only when `WIDGET_MODE=x` (recorded as injected), the runtime
/// mode is `rng`, and the preload library (standing in for the runtrace shim)
/// has run in it. The library appends the path of every process it loads
/// into to `<work>/preload.log`. Returns the work dir, the finding and the
/// library, or `None` without clang.
#[cfg(unix)]
fn env_dependent_finding(name: &str) -> Option<(TestDir, PathBuf, PathBuf)> {
    if !tool_runs("clang") {
        return None;
    }
    let work = temp_dir(name);
    let harness_dir = work.join("harnesses/H-ENV");
    fs::create_dir_all(&harness_dir).unwrap();
    fs::write(
        harness_dir.join("main.c"),
        "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\
         __attribute__((noinline)) int widget_crash(int value, const char *label) {\n\
         \x20   const char *mode = getenv(\"WIDGET_MODE\");\n\
         \x20   const char *pass = getenv(\"BHF_RUNTRACE_MODE\");\n\
         \x20   int armed = mode && !strcmp(mode, \"x\") && pass && !strcmp(pass, \"rng\")\n\
         \x20       && getenv(\"WIDGET_PRELOADED\");\n\
         \x20   char *buf = malloc(4);\n\
         \x20   memset(buf, 0, 4);\n\
         \x20   int r = buf[armed ? 4 + (value & 7) : 0];\n\
         \x20   free(buf);\n\
         \x20   return r + label[0];\n\
         }\n\
         int main(int argc, char **argv) {\n\
         \x20   unsigned char b[4] = {0};\n\
         \x20   FILE *f = argc > 1 ? fopen(argv[1], \"rb\") : NULL;\n\
         \x20   if (!f) return 2;\n\
         \x20   if (fread(b, 1, 4, f) != 4) return 2;\n\
         \x20   fclose(f);\n\
         \x20   return widget_crash(b[0] | b[1] << 8 | b[2] << 16 | b[3] << 24, \"AB\");\n\
         }\n",
    )
    .unwrap();
    let build = Command::new("clang")
        .args(["-g", "-O0", "-fsanitize=address", "-o"])
        .arg(harness_dir.join("main"))
        .arg(harness_dir.join("main.c"))
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", text(&build.stderr));
    fs::write(
        harness_dir.join("preload.c"),
        "#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n\
         __attribute__((constructor)) static void widget_preload(void) {\n\
         \x20   char exe[4096];\n\
         \x20   ssize_t n = readlink(\"/proc/self/exe\", exe, sizeof exe - 1);\n\
         \x20   const char *log = getenv(\"WIDGET_PRELOAD_LOG\");\n\
         \x20   if (n > 0 && log) {\n\
         \x20       FILE *f;\n\
         \x20       exe[n] = 0;\n\
         \x20       f = fopen(log, \"a\");\n\
         \x20       if (f) { fprintf(f, \"%s\\n\", exe); fclose(f); }\n\
         \x20   }\n\
         \x20   setenv(\"WIDGET_PRELOADED\", \"1\", 1);\n\
         }\n",
    )
    .unwrap();
    let library = harness_dir.join("libwidget_preload.so");
    let build = Command::new("clang")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&library)
        .arg(harness_dir.join("preload.c"))
        .output()
        .unwrap();
    assert!(build.status.success(), "{}", text(&build.stderr));
    fs::write(
        harness_dir.join("generation-metadata.json"),
        r#"{"schema_version":1,"harness_format_version":3,"language":"c","target_function":"widget_crash"}"#,
    )
    .unwrap();
    let finding = corpus::layout::findings_dir(&work).join("F-0001-0e0e0e0e");
    fs::create_dir_all(&finding).unwrap();
    fs::write(finding.join("testcase.bin"), b"AAAA").unwrap();
    // Recorded without frames, so the replay is checked against the build.
    fs::write(
        finding.join("finding.json"),
        r#"{"id":"F-0001-0e0e0e0e","rule_id":"BHF-201","harness_id":"H-ENV","harness_format_version":3,
            "fixture_path":"harnesses/H-ENV/main",
            "runtime_mode":{"pass":"rng","env_injected":{"WIDGET_MODE":"x"}},
            "build":{"binary":{"sha256":"SHA256"}},
            "exception":{"name":"ASAN_HEAP_BUFFER_OVERFLOW","sanitizer":"asan","stack":[]}}"#
            .replace("SHA256", &sha256_hex(&harness_dir.join("main"))),
    )
    .unwrap();
    Some((work, finding, library))
}

/// The preload library ran in the harness for the replay and for the
/// session, and never in a debugger, its server or a shell. (The sanitizer's
/// symbolizer, which the harness starts, inherits it from the harness.)
#[cfg(unix)]
fn assert_preloaded_into_the_harness_only(work: &Path, log: &Path) {
    let loaded = fs::read_to_string(log).unwrap();
    let harness = fs::canonicalize(work.join("harnesses/H-ENV/main")).unwrap();
    assert!(
        loaded.lines().filter(|p| Path::new(p) == harness).count() >= 2,
        "the replay and the session both preload it: {loaded}"
    );
    for process in loaded.lines() {
        let name = Path::new(process)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        assert!(
            !name.starts_with("gdb")
                && !name.starts_with("lldb")
                && !matches!(name, "sh" | "dash" | "bash" | "env"),
            "{name} loaded the preload library: {loaded}"
        );
    }
}

/// `bhf replay --debugger` with the finding's runtime environment, the
/// preload library standing in for the runtrace shim, as JSON.
#[cfg(unix)]
fn debugger_replay_json(
    finding: &Path,
    library: &Path,
    log: &Path,
    tool: &str,
) -> serde_json::Value {
    let out = Command::new(env!("CARGO_BIN_EXE_cli"))
        .arg("replay")
        .arg(finding)
        .args(["--debugger", tool, "--sandbox", "none", "--json"])
        .env("BHF_RUNTRACE_SHIM", library)
        .env("WIDGET_PRELOAD_LOG", log)
        .output()
        .unwrap();
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}{}", text(&out.stdout), text(&out.stderr)))
}

/// The debugger session runs the harness with the replay's environment: the
/// runtime mode and the variables the finding recorded as injected, and the
/// runtrace shim preloaded into the harness alone, never into gdb or its
/// shell. A crash that needs them reaches its sanitizer report under the
/// debugger too.
#[cfg(unix)]
#[test]
fn replay_debugger_runs_the_harness_with_the_replay_environment() {
    if !tool_runs("gdb") {
        eprintln!("skipping: gdb unavailable");
        return;
    }
    let Some((work, finding, library)) = env_dependent_finding("debugger-env") else {
        eprintln!("skipping: clang unavailable");
        return;
    };
    let log = work.join("preload.log");
    let doc = debugger_replay_json(&finding, &library, &log, "gdb");
    assert_eq!(doc["verdict"], "match", "{doc:#}");
    let transcript = doc["debugger"]["transcript"].as_str().unwrap();
    let crash = transcript
        .rfind("--- bhf: stopped at the crash ---")
        .unwrap_or_else(|| panic!("{transcript}"));
    assert!(
        transcript.contains("ERROR: AddressSanitizer: heap-buffer-overflow"),
        "the crash happens under the debugger: {transcript}"
    );
    assert!(
        !transcript.contains("exited normally") && !transcript.contains("exited with code"),
        "{transcript}"
    );
    assert!(transcript[crash..].contains("widget_crash"), "{transcript}");
    assert_preloaded_into_the_harness_only(&work, &log);

    // The debugger starts the harness itself, so an explicit sandbox is
    // refused rather than silently bypassed.
    for sandbox in [&["--sandbox", "bubblewrap"][..], &["--sandbox-strict"][..]] {
        let mut args = vec![finding.to_str().unwrap(), "--debugger", "gdb"];
        args.extend_from_slice(sandbox);
        let out = replay_output(&args);
        assert_eq!(out.status.code(), Some(1), "{sandbox:?}");
        let stderr = text(&out.stderr);
        assert!(stderr.contains("outside the sandbox"), "{stderr}");
        assert!(!stderr.contains("MATCH"), "{stderr}");
    }
    fs::remove_dir_all(&work).ok();
}

/// `--debugger lldb` prints the stack at the target's entry and at the
/// crash: lldb's batch mode runs no more `-o` commands once the harness
/// crashes, so the crash-site commands also run on crash (`-k`), and the
/// sanitizer report stops at a breakpoint on its report path.
#[cfg(unix)]
#[test]
fn replay_debugger_under_lldb_prints_the_crash_stack() {
    if !tool_runs("lldb") {
        eprintln!("skipping: lldb unavailable");
        return;
    }
    let Some((work, finding, library)) = env_dependent_finding("debugger-lldb") else {
        eprintln!("skipping: clang unavailable");
        return;
    };
    let log = work.join("preload.log");
    let doc = debugger_replay_json(&finding, &library, &log, "lldb");
    assert_eq!(doc["verdict"], "match", "{doc:#}");
    assert_eq!(doc["debugger"]["tool"], "lldb", "{doc:#}");
    let transcript = doc["debugger"]["transcript"].as_str().unwrap();
    let entry = transcript
        .find("# --- bhf: stopped (at the target entry")
        .unwrap_or_else(|| panic!("{transcript}"));
    let crash = transcript
        .rfind("# --- bhf: stopped at the crash ---")
        .unwrap_or_else(|| panic!("{transcript}"));
    assert!(entry < crash, "{transcript}");
    assert!(
        transcript[entry..crash].contains("value = 1094795585"),
        "the arguments at the target's entry: {transcript}"
    );
    assert!(
        transcript.contains("ERROR: AddressSanitizer: heap-buffer-overflow"),
        "{transcript}"
    );
    let after = &transcript[crash..];
    assert!(
        after.contains("widget_crash"),
        "the crash stack: {transcript}"
    );
    assert!(
        !transcript.contains("PLEASE submit a bug report"),
        "{transcript}"
    );
    assert_preloaded_into_the_harness_only(&work, &log);
    fs::remove_dir_all(&work).ok();
}

/// Every replay writes the harness's raw output, bounded, to
/// `<finding>/replay.log` and names it in the summary and `--json`. A replay
/// of another harness that does not reproduce the finding writes
/// `replay-other-harness.log` instead and leaves `replay.log` as it was; the
/// results index is rebuilt after it too, so the attestation covers the log.
#[cfg(unix)]
#[test]
fn replay_writes_a_bounded_replay_log_and_keeps_the_attestation_current() {
    let root = temp_dir("replay-log");
    let work = root.join("work");
    let harness = work.join("harnesses/H-1/main");
    let report = asan_report("Widget::copy_at", 12);
    write_crashing_harness(&harness, &report);
    let finding = emit_finding(&work, &harness, &report);
    assert_eq!(
        cli::run_from(["bhf", "report", "--work-dir", work.to_str().unwrap()]),
        0
    );

    let output = replay_output(&[finding.to_str().unwrap()]);
    let stdout = text(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "{stdout}");
    let log_path = finding.join("replay.log");
    assert!(
        stdout.contains(&format!("  log        {}", log_path.display())),
        "{stdout}"
    );
    let log = fs::read_to_string(&log_path).unwrap();
    assert!(log.contains("verdict: match"), "{log}");
    assert!(log.contains("--- harness stderr"), "{log}");
    assert!(
        log.contains("ERROR: AddressSanitizer: heap-buffer-overflow"),
        "{log}"
    );
    assert_attestation_current(&work);

    let matched_log = fs::read(&log_path).unwrap();

    // A mismatch of another harness writes its own log, and results/ is
    // rebuilt for it.
    let other = root.join("other/main");
    let noisy = format!(
        "{}{}",
        "x".repeat(3 * 1024 * 1024),
        asan_report("Widget::other", 8)
    );
    write_crashing_harness(&other, &noisy);
    let output = replay_output(&[
        finding.to_str().unwrap(),
        "--harness",
        other.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(3));
    let doc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let other_log_path = finding.join("replay-other-harness.log");
    assert_eq!(
        doc["replay_log"],
        serde_json::json!(other_log_path.display().to_string())
    );
    assert_eq!(
        fs::read(&log_path).unwrap(),
        matched_log,
        "the replay of the finding's own harness is kept"
    );
    let log = fs::read_to_string(&other_log_path).unwrap();
    assert!(
        log.contains("verdict: mismatch"),
        "{}",
        &log[..log.len().min(400)]
    );
    assert!(
        log.len() < 2 * 1024 * 1024,
        "the log is bounded: {} bytes",
        log.len()
    );
    assert!(log.contains("bytes not kept"), "the cut is marked");
    assert_attestation_current(&work);
    let attestation: serde_json::Value =
        serde_json::from_slice(&fs::read(work.join("results/attestation.json")).unwrap()).unwrap();
    for name in ["replay.log", "replay-other-harness.log"] {
        assert!(
            attestation["subject"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["name"].as_str().unwrap().ends_with(&format!("/{name}"))),
            "the attestation covers {name}"
        );
    }
    // The log is not hashed as finding evidence.
    let findings: serde_json::Value =
        serde_json::from_slice(&fs::read(work.join("results/findings.json")).unwrap()).unwrap();
    assert!(
        !findings.to_string().contains("replay.log")
            && !findings.to_string().contains("replay-other-harness.log"),
        "replay logs are not evidence files"
    );

    // The finding's own harness still writes replay.log when it does not
    // reproduce the finding.
    write_crashing_harness(&harness, &asan_report("Widget::other", 8));
    let output = replay_output(&[finding.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(3));
    let log = fs::read_to_string(&log_path).unwrap();
    assert!(log.contains("verdict: mismatch"), "{log}");
    assert_attestation_current(&work);
    fs::remove_dir_all(&root).ok();
}

/// A finding that records its build: a rebuild of its harness at the same
/// path is another harness, and a replay of it that does not reproduce the
/// finding leaves `replay.log` (the recorded build's replay) as it was.
#[cfg(unix)]
#[test]
fn a_non_matching_replay_of_a_rebuilt_harness_keeps_the_replay_log() {
    let root = temp_dir("replay-log-rebuilt");
    let work = root.join("work");
    let harness = work.join("harnesses/H-1/main");
    let report = asan_report("Widget::copy_at", 12);
    write_crashing_harness(&harness, &report);
    let finding = emit_finding(&work, &harness, &report);
    let mut record = read_finding_json(&finding);
    record["build"] = serde_json::json!({"binary": {"sha256": sha256_hex(&harness)}});
    fs::write(
        finding.join("finding.json"),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();
    let output = replay_output(&[finding.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let log_path = finding.join("replay.log");
    let matched_log = fs::read(&log_path).unwrap();

    write_crashing_harness(&harness, &asan_report("Widget::other", 8));
    let output = replay_output(&[finding.to_str().unwrap()]);
    let summary = format!("{}{}", text(&output.stdout), text(&output.stderr));
    assert_eq!(output.status.code(), Some(3), "{summary}");
    assert!(
        summary.contains("sha256 differs from the recorded build"),
        "{summary}"
    );
    let other_log_path = finding.join("replay-other-harness.log");
    assert!(
        summary.contains(&format!("  log        {}", other_log_path.display())),
        "{summary}"
    );
    assert_eq!(fs::read(&log_path).unwrap(), matched_log);
    let log = fs::read_to_string(&other_log_path).unwrap();
    assert!(log.contains("verdict: mismatch"), "{log}");

    // A rebuild that reproduces the finding is its replay.
    write_crashing_harness(&harness, &format!("{report}# rebuilt\n"));
    let output = replay_output(&[finding.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stdout));
    let log = fs::read_to_string(&log_path).unwrap();
    assert!(log.contains("verdict: match"), "{log}");
    assert_ne!(log.as_bytes(), matched_log.as_slice());
    fs::remove_dir_all(&root).ok();
}
