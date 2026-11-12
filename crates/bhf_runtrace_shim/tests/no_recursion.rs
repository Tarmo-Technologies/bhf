// SPDX-License-Identifier: Apache-2.0
//! Regression guard for the dlvsym version bug: the shim resolved
//! every libc symbol at a hardcoded GLIBC_2.2.5, which returns NULL
//! for the GLIBC_2.4-versioned openat/faccessat/readlinkat. The
//! null-fallback then called the exported hook again and span
//! forever. A target's first openat() must complete, not hang.

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

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

/// Locate the preload cdylib without triggering a nested build. A
/// plain integration-test invocation may compile only this test
/// binary, so skip rather than load a stale .so from a previous build.
fn shim_so() -> Option<PathBuf> {
    ["debug", "release"].into_iter().find_map(fresh_shim)
}

/// The shim built for `profile`, when it is newer than the hook sources.
fn fresh_shim(profile: &str) -> Option<PathBuf> {
    let base = target_dir();
    {
        let p = base.join(profile).join("libbhf_runtrace_shim.so");
        if p.is_file() {
            let shim_mtime = p.metadata().and_then(|m| m.modified()).ok();
            let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            let newest_hook_mtime = [
                "src/hooks/assertion.rs",
                "src/hooks/env.rs",
                "src/hooks/fs.rs",
                "src/hooks/proc.rs",
                "src/hooks/format.rs",
                "src/hooks/format_hooks.c",
                "src/jsonl.rs",
            ]
            .iter()
            .filter_map(|relative| {
                manifest_dir
                    .join(relative)
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
            })
            .max();
            if let (Some(shim_mtime), Some(newest_hook_mtime)) = (shim_mtime, newest_hook_mtime) {
                if shim_mtime < newest_hook_mtime {
                    eprintln!(
                        "skipping: {p:?} is older than hook sources; run cargo build -p bhf_runtrace_shim first"
                    );
                    return None;
                }
            }
            return Some(p);
        }
    }
    None
}

fn cc() -> Option<&'static str> {
    ["cc", "gcc", "clang"].into_iter().find(|c| {
        Command::new(c)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    })
}

#[test]
fn at_syscall_hooks_do_not_hang_under_ld_preload() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };

    let dir = std::env::temp_dir().join(format!("bhf-shim-norec-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("probe.c");
    std::fs::write(
        &src,
        r#"
        #define _GNU_SOURCE
        #include <fcntl.h>
        #include <unistd.h>
        int main(void) {
            int fd = openat(AT_FDCWD, "/bhf/missing", O_RDONLY);
            if (fd >= 0) close(fd);
            faccessat(AT_FDCWD, "/bhf/missing", R_OK, 0);
            char buf[64];
            (void)readlinkat(AT_FDCWD, "/bhf/missing", buf, sizeof buf);
            return 0;
        }
    "#,
    )
    .unwrap();
    let bin = dir.join("probe");
    let built = Command::new(cc)
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(built.success(), "probe failed to compile");

    let log = dir.join("rt.jsonl");
    let mut child = Command::new(&bin)
        .env("LD_PRELOAD", &shim)
        .env("BHF_RUNTRACE_LOG", &log)
        .env("BHF_RUNTRACE_MODE", "audit")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn probe");

    // The old recursive hook span at 100% CPU forever; bound it.
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = std::fs::remove_dir_all(&dir);
            panic!("openat/faccessat/readlinkat under the shim HUNG (recursion regression)");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let _ = std::fs::remove_dir_all(&dir);
    assert!(status.success(), "probe exited abnormally: {status:?}");
}

#[test]
fn env_hooks_log_secure_getenv_under_ld_preload() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };

    let dir = std::env::temp_dir().join(format!("bhf-shim-env-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("probe.c");
    std::fs::write(
        &src,
        r#"
        #define _GNU_SOURCE
        #include <stdlib.h>
        int main(void) {
            unsetenv("DB_PASSWORD");
            return secure_getenv("DB_PASSWORD") != 0;
        }
    "#,
    )
    .unwrap();
    let bin = dir.join("probe");
    let built = Command::new(cc)
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(built.success(), "probe failed to compile");

    let log = dir.join("rt.jsonl");
    let status = Command::new(&bin)
        .env_remove("DB_PASSWORD")
        .env("LD_PRELOAD", &shim)
        .env("BHF_RUNTRACE_LOG", &log)
        .env("BHF_RUNTRACE_MODE", "audit")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn probe");
    assert!(status.success(), "probe exited abnormally: {status:?}");

    let text = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        text.lines().any(|line| {
            line.contains("\"e\":\"secure_getenv\"") && line.contains("\"n\":\"DB_PASSWORD\"")
        }),
        "secure_getenv event missing from runtrace log:\n{text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn env_hooks_log_present_getenv_without_value_under_ld_preload() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };

    let dir = std::env::temp_dir().join(format!("bhf-shim-env-present-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("probe.c");
    std::fs::write(
        &src,
        r#"
        #include <stdlib.h>
        int main(void) {
            const char *value = getenv("DB_PASSWORD");
            return value == 0;
        }
    "#,
    )
    .unwrap();
    let bin = dir.join("probe");
    let built = Command::new(cc)
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(built.success(), "probe failed to compile");

    let log = dir.join("rt.jsonl");
    let status = Command::new(&bin)
        .env("DB_PASSWORD", "super-secret-value")
        .env("LD_PRELOAD", &shim)
        .env("BHF_RUNTRACE_LOG", &log)
        .env("BHF_RUNTRACE_MODE", "audit")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn probe");
    assert!(status.success(), "probe exited abnormally: {status:?}");

    let text = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        text.lines().any(|line| {
            line.contains("\"e\":\"getenv\"")
                && line.contains("\"n\":\"DB_PASSWORD\"")
                && line.contains("\"r\":1")
        }),
        "present getenv event missing from runtrace log:\n{text}"
    );
    assert!(
        !text.contains("super-secret-value"),
        "runtrace log leaked env value:\n{text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn fs_hooks_log_open_close_lifecycle_under_ld_preload() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };

    let dir = std::env::temp_dir().join(format!("bhf-shim-lifecycle-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // The target file must live OUTSIDE the runtrace-log dir: that dir is the
    // engine-owned harness dir, and #403's self-exclusion (see policy.rs) keeps
    // the shim from auditing anything inside it. A real external open is what
    // this test exercises, so place it next to the dir, not within it.
    let target = std::env::temp_dir().join(format!(
        "bhf-shim-lifecycle-target-{}.txt",
        std::process::id()
    ));
    std::fs::write(&target, "fixture").unwrap();
    let src = dir.join("probe.c");
    std::fs::write(
        &src,
        r#"
        #include <fcntl.h>
        #include <unistd.h>
        int main(int argc, char **argv) {
            if (argc < 2) return 1;
            int fd = open(argv[1], O_RDONLY);
            if (fd < 0) return 2;
            if (close(fd) != 0) return 3;
            return 0;
        }
    "#,
    )
    .unwrap();
    let bin = dir.join("probe");
    let built = Command::new(cc)
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(built.success(), "probe failed to compile");

    let log = dir.join("rt.jsonl");
    let status = Command::new(&bin)
        .arg(&target)
        .env("LD_PRELOAD", &shim)
        .env("BHF_RUNTRACE_LOG", &log)
        .env("BHF_RUNTRACE_MODE", "audit")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn probe");
    assert!(status.success(), "probe exited abnormally: {status:?}");

    let text = std::fs::read_to_string(&log).unwrap_or_default();
    let expected_path = format!("\"p\":\"{}\"", target.display());
    assert!(
        text.lines()
            .any(|line| line.contains("\"e\":\"open\"") && line.contains(&expected_path)),
        "successful open event missing from runtrace log:\n{text}"
    );
    assert!(
        text.lines()
            .any(|line| line.contains("\"e\":\"close\"") && line.contains("\"r\":0")),
        "successful close event missing from runtrace log:\n{text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&target);
}

/// The runtrace log is created when the shim loads, so its existence after a
/// run proves the shim was preloaded, even for a target that touched nothing
/// the shim records (bhf reports such a run as observed, not as unobserved).
#[test]
fn the_runtrace_log_is_created_at_load_for_a_run_that_logs_nothing() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let dir = std::env::temp_dir().join(format!("bhf-shim-quiet-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("probe.c");
    std::fs::write(&src, "int main(void) { return 0; }\n").unwrap();
    let bin = dir.join("probe");
    let built = Command::new(cc)
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(built.success(), "probe failed to compile");
    let log = dir.join("rt.jsonl");
    let status = Command::new(&bin)
        .env("LD_PRELOAD", &shim)
        .env("BHF_RUNTRACE_LOG", &log)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn probe");
    assert!(status.success(), "probe exited abnormally: {status:?}");
    assert!(
        log.is_file(),
        "the preloaded shim did not create {}",
        log.display()
    );
    // Without the shim nothing creates it.
    let unshimmed = dir.join("rt-plain.jsonl");
    let status = Command::new(&bin)
        .env("BHF_RUNTRACE_LOG", &unshimmed)
        .status()
        .expect("spawn probe");
    assert!(status.success());
    assert!(!unshimmed.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn process_hooks_log_system_commands_under_ld_preload() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };

    let dir = std::env::temp_dir().join(format!("bhf-shim-process-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("probe.c");
    std::fs::write(
        &src,
        r#"
        #include <stdlib.h>
        int main(void) {
            return system(":; :");
        }
    "#,
    )
    .unwrap();
    let bin = dir.join("probe");
    let built = Command::new(cc)
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(built.success(), "probe failed to compile");

    let log = dir.join("rt.jsonl");
    let status = Command::new(&bin)
        .env("LD_PRELOAD", &shim)
        .env("BHF_RUNTRACE_LOG", &log)
        .env("BHF_RUNTRACE_MODE", "audit")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn probe");
    assert!(status.success(), "probe exited abnormally: {status:?}");

    let text = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        text.lines()
            .any(|line| { line.contains("\"e\":\"system\"") && line.contains("\"c\":\":; :\"") }),
        "system command event missing from runtrace log:\n{text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn format_hooks_log_printf_formats_under_ld_preload() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };

    let dir = std::env::temp_dir().join(format!("bhf-shim-format-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("probe.c");
    std::fs::write(
        &src,
        r#"
        #include <stdio.h>
        int main(void) {
            return printf("static %d\n", 7) < 0;
        }
    "#,
    )
    .unwrap();
    let bin = dir.join("probe");
    let built = Command::new(cc)
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(built.success(), "probe failed to compile");

    let log = dir.join("rt.jsonl");
    let status = Command::new(&bin)
        .env("LD_PRELOAD", &shim)
        .env("BHF_RUNTRACE_LOG", &log)
        .env("BHF_RUNTRACE_MODE", "audit")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn probe");
    assert!(status.success(), "probe exited abnormally: {status:?}");

    let text = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        text.lines().any(|line| {
            line.contains("\"e\":\"format\"")
                && line.contains("\"a\":\"printf\"")
                && line.contains("\"f\":\"static %d\\n\"")
        }),
        "printf format event missing from runtrace log:\n{text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// #403: the insecure-temp-file oracle (BHF-417 / CWE-377) must not flag
/// bhf's OWN per-harness instrumentation files. `bhf auto` writes
/// `coverage.shm` (and vp.shm / cmp.shm / runtrace.jsonl) into the harness
/// dir with O_CREAT-without-O_EXCL; when `--work-dir` is under /tmp those
/// SHM bitmaps otherwise self-trip the oracle, flooding every target with
/// phantom findings. A genuine target temp file OUTSIDE the engine dir must
/// still be flagged (the oracle is self-excluded, not disabled).
#[test]
fn insecure_tempfile_oracle_excludes_engine_owned_shm_under_ld_preload() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };

    // Mirror `bhf auto`: a per-harness dir UNDER /tmp (the #403 trigger),
    // holding the runtrace log + the coverage.shm bitmap the driver creates.
    let harness_dir =
        std::env::temp_dir().join(format!("bhf-shim-selfexcl-{}", std::process::id()));
    std::fs::create_dir_all(&harness_dir).unwrap();
    let owned_shm = harness_dir.join("coverage.shm");
    // A genuine attacker-racing temp file the target itself creates, OUTSIDE
    // the engine-owned dir: this one must STILL be flagged.
    let victim_name = format!("bhf-victim-{}.tmp", std::process::id());
    let target_tmp = std::env::temp_dir().join(&victim_name);

    let src = harness_dir.join("probe.c");
    std::fs::write(
        &src,
        r#"
        #define _GNU_SOURCE
        #include <fcntl.h>
        #include <unistd.h>
        int main(int argc, char **argv) {
            // argv[1] = engine-owned coverage.shm (O_CREAT, no O_EXCL)
            // argv[2] = genuine insecure temp file the target creates
            int a = open(argv[1], O_CREAT | O_RDWR, 0600);
            if (a >= 0) close(a);
            int b = open(argv[2], O_CREAT | O_RDWR, 0600);
            if (b >= 0) close(b);
            return 0;
        }
    "#,
    )
    .unwrap();
    let bin = harness_dir.join("probe");
    let built = Command::new(cc)
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(built.success(), "probe failed to compile");

    let log = harness_dir.join("runtrace.jsonl");
    let status = Command::new(&bin)
        .arg(&owned_shm)
        .arg(&target_tmp)
        .env("LD_PRELOAD", &shim)
        .env("BHF_RUNTRACE_LOG", &log)
        .env("BHF_RUNTRACE_MODE", "audit")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn probe");
    assert!(status.success(), "probe exited abnormally: {status:?}");

    let text = std::fs::read_to_string(&log).unwrap_or_default();
    let tempfile_lines: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("\"e\":\"insecure_tempfile\""))
        .collect();

    let _ = std::fs::remove_dir_all(&harness_dir);
    let _ = std::fs::remove_file(&target_tmp);

    // The engine-owned coverage.shm must NOT be flagged (the #403 bug).
    assert!(
        !tempfile_lines
            .iter()
            .any(|line| line.contains("coverage.shm")),
        "engine-owned coverage.shm self-flagged as insecure temp file:\n{text}"
    );
    // ...but a genuine target temp file in /tmp still must be (oracle alive).
    assert!(
        tempfile_lines
            .iter()
            .any(|line| line.contains(&victim_name)),
        "genuine insecure temp file no longer flagged (oracle over-suppressed):\n{text}"
    );
}

#[test]
fn assertion_hooks_log_assert_failures_under_ld_preload() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };

    let dir = std::env::temp_dir().join(format!("bhf-shim-assert-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("probe.c");
    std::fs::write(
        &src,
        r#"
        #include <assert.h>
        int main(void) {
            assert(0 && "boom");
            return 0;
        }
    "#,
    )
    .unwrap();
    let bin = dir.join("probe");
    let built = Command::new(cc)
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(built.success(), "probe failed to compile");

    let log = dir.join("rt.jsonl");
    let status = Command::new(&bin)
        .env("LD_PRELOAD", &shim)
        .env("BHF_RUNTRACE_LOG", &log)
        .env("BHF_RUNTRACE_MODE", "audit")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn probe");
    assert!(!status.success(), "assertion probe unexpectedly succeeded");

    let text = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(
        text.lines().any(|line| {
            line.contains("\"e\":\"assertion_failed\"")
                && line.contains("\"a\":\"__assert_fail\"")
                && line.contains("\\\"boom\\\"")
        }),
        "assertion failure event missing from runtrace log:\n{text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// #422: the open/openat hooks must tag a path event with byte-origin
/// taint (`u`=1, `o`=offset) when the path was derived from the current
/// fuzz input, and must NOT tag an unrelated path. This is the runtime
/// substrate the `path-controlled-open-runtime` oracle (BHF-405) confirms,
/// and the same publish→sink flow a generated harness uses
/// (`bhf_shim_set_fuzz_input` before driving the target).
#[test]
fn fs_hooks_record_path_taint_under_ld_preload() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };

    let dir = std::env::temp_dir().join(format!("bhf-shim-taint-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("probe.c");
    // The "input" embeds a tainted path; the program publishes it to the
    // shim, then opens (a) that exact path (controlled) and (b) an
    // unrelated path (not controlled). Both miss (ENOENT), so both take
    // the log_path_miss branch. The weak extern mirrors the harness
    // template: NULL when not preloaded, bound to the shim when preloaded.
    std::fs::write(
        &src,
        r#"
        #include <fcntl.h>
        #include <unistd.h>
        #include <string.h>
        #include <stddef.h>
        extern void bhf_shim_set_fuzz_input(const unsigned char *data, size_t size)
            __attribute__((weak));
        int main(void) {
            const char *input = "open:/var/lib/bhf-taint-probe.dat;mode=r";
            if (bhf_shim_set_fuzz_input)
                bhf_shim_set_fuzz_input((const unsigned char *)input, strlen(input));
            /* tainted: a >=4-byte substring of the published input */
            int a = open("/var/lib/bhf-taint-probe.dat", O_RDONLY);
            if (a >= 0) close(a);
            /* untainted: not derived from the input */
            int b = open("/var/lib/bhf-unrelated-file.dat", O_RDONLY);
            if (b >= 0) close(b);
            return 0;
        }
    "#,
    )
    .unwrap();
    let bin = dir.join("probe");
    let built = Command::new(cc)
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .unwrap();
    assert!(built.success(), "probe failed to compile");

    let log = dir.join("rt.jsonl");
    let status = Command::new(&bin)
        .env("LD_PRELOAD", &shim)
        .env("BHF_RUNTRACE_LOG", &log)
        .env("BHF_RUNTRACE_MODE", "audit")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn probe");
    assert!(status.success(), "probe exited abnormally: {status:?}");

    let text = std::fs::read_to_string(&log).unwrap_or_default();

    let tainted_line = text
        .lines()
        .find(|line| line.contains("bhf-taint-probe.dat"))
        .unwrap_or_default();
    let untainted_line = text
        .lines()
        .find(|line| line.contains("bhf-unrelated-file.dat"))
        .unwrap_or_default();

    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        !tainted_line.is_empty(),
        "tainted open event missing from runtrace log:\n{text}"
    );
    assert!(
        tainted_line.contains("\"u\":1") && tainted_line.contains("\"o\":"),
        "tainted open event missing byte-origin taint fields: {tainted_line}"
    );
    assert!(
        !untainted_line.is_empty(),
        "untainted open event missing from runtrace log:\n{text}"
    );
    assert!(
        !untainted_line.contains("\"u\":1"),
        "untainted open event must not carry taint: {untainted_line}"
    );
}

/// `fopen`/`fopen64` open the file through a glibc-internal call the `open`
/// hook never sees, so the shim hooks them directly. Under AddressSanitizer,
/// whose runtime defines `fopen` in the executable, its interceptor forwards
/// to the next definition, which is the shim's.
#[test]
fn fs_hooks_log_fopen_and_fopen64_under_ld_preload() {
    // Both profiles when both are built: an optimized build can merge the
    // hook `dlsym` hands out with the exported `fopen`.
    let shims: Vec<PathBuf> = ["debug", "release"]
        .into_iter()
        .filter_map(fresh_shim)
        .collect();
    if shims.is_empty() {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    }
    for shim in shims {
        fopen_events_are_logged(&shim);
    }
}

fn fopen_events_are_logged(shim: &std::path::Path) {
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let profile = shim
        .parent()
        .and_then(|p| p.file_name())
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!("bhf-shim-fopen-{profile}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // Outside the runtrace-log dir: the shim records nothing inside it.
    let present =
        std::env::temp_dir().join(format!("bhf-shim-fopen-present-{}.cfg", std::process::id()));
    std::fs::write(&present, "widget=1\n").unwrap();
    let missing = format!("/nonexistent-bhf-{}/widget.cfg", std::process::id());
    let src = dir.join("probe.c");
    std::fs::write(
        &src,
        r#"
        #define _LARGEFILE64_SOURCE 1
        #include <stdio.h>
        int main(int argc, char **argv) {
            if (argc < 3) return 1;
            FILE *f = fopen(argv[1], "r");
            if (!f) return 2;
            fclose(f);
            FILE *g = fopen64(argv[2], "r");
            if (g) return 3;
            return 0;
        }
    "#,
    )
    .unwrap();
    let mut builds = vec![("plain", Vec::<&str>::new())];
    let asan_ok = Command::new("clang")
        .args(["-fsanitize=address", "-x", "c", "-o"])
        .arg(dir.join("asan-probe"))
        .arg(&src)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if asan_ok {
        builds.push(("asan", vec!["-fsanitize=address"]));
    }
    for (label, flags) in builds {
        let bin = dir.join(format!("probe-{label}"));
        let compiler = if label == "asan" { "clang" } else { cc };
        let built = Command::new(compiler)
            .args(&flags)
            .arg(&src)
            .arg("-o")
            .arg(&bin)
            .status()
            .unwrap();
        assert!(built.success(), "{label} probe failed to compile");
        let log = dir.join(format!("rt-{label}.jsonl"));
        let status = Command::new(&bin)
            .arg(&present)
            .arg(&missing)
            .env("LD_PRELOAD", shim)
            .env("BHF_RUNTRACE_LOG", &log)
            .env("ASAN_OPTIONS", "verify_asan_link_order=0:detect_leaks=0")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("spawn probe");
        assert!(
            status.success(),
            "{label} probe under {} exited abnormally: {status:?}",
            shim.display()
        );
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        let opened = format!("\"p\":\"{}\"", present.display());
        assert!(
            text.lines().any(|line| line.contains("\"e\":\"fopen\"")
                && line.contains(&opened)
                && line.contains("\"d\":")),
            "{label}: fopen of an existing file missing from the runtrace log:\n{text}"
        );
        let probed = format!("\"p\":\"{missing}\"");
        assert!(
            text.lines().any(|line| line.contains("\"e\":\"fopen64\"")
                && line.contains(&probed)
                && line.contains("\"n\":2")),
            "{label}: fopen64 of a missing file missing from the runtrace log:\n{text}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&present);
}

/// A sanitizer runtime defines `dlopen` and resolves the real one with
/// `dlsym(RTLD_NEXT, "dlopen")`, which the shim forwards with the caller's
/// identity: for a runtime in the executable the next definition is the
/// shim's hook, for one loaded after the shim (gcc's shared libasan) it is
/// libc's, past the runtime's own interceptor. Either way a failed load is
/// logged as in a plain program, by a debug shim as by a release one.
#[test]
fn dl_hooks_log_failed_dlopen_under_a_sanitizer() {
    let shims: Vec<PathBuf> = ["debug", "release"]
        .into_iter()
        .filter_map(fresh_shim)
        .collect();
    if shims.is_empty() {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    }
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let dir = std::env::temp_dir().join(format!("bhf-shim-dlopen-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let missing = format!("libbhf_missing_{}.so.7", std::process::id());
    let src = dir.join("probe.c");
    std::fs::write(
        &src,
        r#"
        #include <dlfcn.h>
        int main(int argc, char **argv) {
            if (argc < 2) return 1;
            return dlopen(argv[1], RTLD_NOW) ? 2 : 0;
        }
    "#,
    )
    .unwrap();
    let mut builds = vec![("plain", cc, Vec::<&str>::new())];
    // Sanitizer lanes the host can build; each is skipped when it cannot.
    for (label, compiler, flags) in [
        ("clang-asan", "clang", vec!["-fsanitize=address"]),
        ("clang-ubsan", "clang", vec!["-fsanitize=undefined"]),
        ("gcc-asan-shared", "gcc", vec!["-fsanitize=address"]),
        (
            "gcc-asan-static",
            "gcc",
            vec!["-fsanitize=address", "-static-libasan"],
        ),
    ] {
        let built = Command::new(compiler)
            .args(&flags)
            .arg(&src)
            .arg("-ldl")
            .arg("-o")
            .arg(dir.join(format!("probe-{label}")))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if built {
            builds.push((label, compiler, flags));
        }
    }
    for (label, compiler, flags) in &builds {
        let bin = dir.join(format!("probe-{label}"));
        let built = Command::new(compiler)
            .args(flags)
            .arg(&src)
            .arg("-ldl")
            .arg("-o")
            .arg(&bin)
            .status()
            .unwrap();
        assert!(built.success(), "{label} probe failed to compile");
        for shim in &shims {
            let log = dir.join(format!("rt-{label}.jsonl"));
            let _ = std::fs::remove_file(&log);
            let status = Command::new(&bin)
                .arg(&missing)
                .env("LD_PRELOAD", shim)
                .env("BHF_RUNTRACE_LOG", &log)
                .env("BHF_DISABLE_DLOPEN_FAKE", "1")
                .env("ASAN_OPTIONS", "verify_asan_link_order=0:detect_leaks=0")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("spawn probe");
            assert!(
                status.success(),
                "{label} probe under {} exited abnormally: {status:?}",
                shim.display()
            );
            let text = std::fs::read_to_string(&log).unwrap_or_default();
            assert!(
                text.lines().any(|line| line.contains("\"e\":\"dlopen\"")
                    && line.contains(&format!("\"l\":\"{missing}\""))),
                "{label}: failed dlopen missing from the runtrace log of {}:\n{text}",
                shim.display()
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
