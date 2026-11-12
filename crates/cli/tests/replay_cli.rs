// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const CANONICAL_SIGNATURE: &str =
    "20b41fb2a2ceeabc9f0403546af14199d4ccacc54e55f6fcb5855015b5eb63bd";

#[test]
fn replay_subcommand_match_returns_zero() {
    let finding_dir = write_finding("match");

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
    let finding_dir = write_finding("match");

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
    let finding_dir = write_finding("match");

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
    let finding_dir = write_finding("match");

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
    let finding_dir = write_finding("match");

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
    let replay = || {
        cli::run_from([
            "bhf",
            "replay",
            finding_dir.to_str().unwrap(),
            "--harness",
            harness.to_str().unwrap(),
        ])
    };
    assert_eq!(replay(), 0, "an older BHF-210 record still matches");
    let options = fs::read_to_string(root.join("ubsan-options.txt")).unwrap();
    assert!(options.contains("print_stacktrace=1"), "{options}");
    assert!(options.contains("report_error_type=1"), "{options}");
    fs::write(finding_dir.join("finding.json"), r#"{"rule_id":"BHF-214"}"#).unwrap();
    assert_eq!(replay(), 0, "today's rule matches");
    fs::write(finding_dir.join("finding.json"), r#"{"rule_id":"BHF-202"}"#).unwrap();
    assert_eq!(replay(), 3, "an unrelated rule does not");
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
    let finding_dir = write_finding("mismatch");

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
    let finding_dir = write_finding_with_fixture("match", fake_harness());

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
    let finding_dir = write_finding_with_fixture("match", Path::new("/nonexistent/bhf/harness"));

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
    let finding_dir = write_finding("match");

    assert_eq!(
        cli::run_from(["bhf", "replay", finding_dir.to_str().unwrap()]),
        1
    );
}

#[test]
fn replay_subcommand_missing_finding_returns_one() {
    let missing = temp_dir("missing").join("findings/F-0000-missing");

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
    let finding_dir = write_finding(&input);

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
    let finding_dir = write_finding("AAAAcrashBBBB");

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
    let finding_dir = write_finding("AAAAcrashBBBB");
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
    let finding_dir = write_finding("AAAAcrashBBBB");

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
    let finding_dir = write_finding("does-not-reproduce");

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

fn write_finding(input: &str) -> PathBuf {
    let finding_dir = temp_dir(input).join("findings/F-0000-test");
    write_finding_at(&finding_dir, input);
    finding_dir
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

fn write_finding_with_fixture(input: &str, fixture: &Path) -> PathBuf {
    let finding_dir = temp_dir(&format!("{input}-fixture")).join("findings/F-0000-test");
    fs::create_dir_all(&finding_dir).unwrap();
    fs::write(finding_dir.join("testcase.bin"), input.as_bytes()).unwrap();
    fs::write(
        finding_dir.join("finding.json"),
        format!(
            "{{\"signature\":\"{CANONICAL_SIGNATURE}\",\"fixture_path\":\"{}\"}}",
            fixture.display()
        ),
    )
    .unwrap();
    finding_dir
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

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("bhf-cli-replay-{name}-{nonce}"));
    fs::create_dir_all(&dir).unwrap();
    dir
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
        let digest = format!(
            "{:x}",
            Sha256::digest(fs::read(results.join(name)).unwrap())
        );
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

/// The same crash replayed without a symbolizer names no function and no
/// position: that is not another crash site. Replay says the location was not
/// compared instead of reporting a sink difference.
#[cfg(unix)]
#[test]
fn an_unsymbolized_replay_of_the_recorded_crash_is_not_a_sink_difference() {
    let root = temp_dir("unsymbolized");
    let work = root.join("work");
    let harness = work.join("harnesses/H-1/main");
    let report = asan_report("Widget::copy_at", 12);
    write_crashing_harness(&harness, &report);
    let finding = emit_finding(&work, &harness, &report);
    write_crashing_harness(
        &harness,
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000031 at pc 0x1 bp 0x2 sp 0x3\n\
         WRITE of size 1 at 0x602000000031 thread T0\n\
         \x20   #0 0x4f5a2b  (/w/harnesses/H-1/main+0x4f5a2b)\n\
         \x20   #1 0x4f5c10  (/w/harnesses/H-1/main+0x4f5c10)\n\
         \n\
         SUMMARY: AddressSanitizer: heap-buffer-overflow (/w/harnesses/H-1/main+0x4f5a2b)\n",
    );

    let output = replay_output(&[finding.to_str().unwrap()]);
    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stdout}{stderr}");
    assert_eq!(stdout.lines().next(), Some("MATCH"), "{stdout}");
    assert!(!stdout.contains("differs"), "{stdout}");
    assert!(stdout.contains("sink not compared"), "{stdout}");
    assert!(stdout.contains("unsymbolized"), "{stdout}");
    assert!(stdout.contains("ASAN_SYMBOLIZER_PATH"), "{stdout}");
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
    let finding_dir = write_finding("match");
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
        let digest = format!(
            "{:x}",
            Sha256::digest(fs::read(results.join(name)).unwrap())
        );
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
