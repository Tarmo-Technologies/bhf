// SPDX-License-Identifier: Apache-2.0
//! Regression guard for the dlvsym version bug: the shim resolved
//! every libc symbol at a hardcoded GLIBC_2.2.5, which returns NULL
//! for the GLIBC_2.4-versioned openat/faccessat/readlinkat. The
//! null-fallback then called the exported hook again and span
//! forever. A target's first openat() must complete, not hang.

#![cfg(target_os = "linux")]

use std::os::unix::fs::OpenOptionsExt;
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
                "src/hooks/dlsym.rs",
                "src/dlsym.rs",
                "src/jsonl.rs",
                "src/policy.rs",
                "src/fakes/fuzz_input.rs",
                "src/fakes/mode.rs",
                "src/fakes/reporting.rs",
                "src/symbolizer.rs",
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

/// The shim starts the runtrace log with a `shim_loaded` line when it loads, so
/// that line proves the shim was preloaded, even for a target that touched
/// nothing the shim records (bhf reports such a run as observed, not as
/// unobserved). The log's existence proves nothing: the fuzz driver opens the
/// same path for its comparison records whether or not the shim is loaded.
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
    let marker = "{\"e\":\"shim_loaded\"}";
    let text = std::fs::read_to_string(&log)
        .unwrap_or_else(|e| panic!("the preloaded shim did not create {}: {e}", log.display()));
    assert_eq!(
        text.lines().next(),
        Some(marker),
        "the shim's log does not start with its load marker:\n{text}"
    );
    // A second process appending to the same log does not mark it again.
    let status = Command::new(&bin)
        .env("LD_PRELOAD", &shim)
        .env("BHF_RUNTRACE_LOG", &log)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn probe");
    assert!(status.success());
    let text = std::fs::read_to_string(&log).unwrap();
    assert_eq!(
        text.lines().filter(|line| *line == marker).count(),
        1,
        "a second run marked the log again:\n{text}"
    );
    // Without the shim nothing creates it.
    let unshimmed = dir.join("rt-plain.jsonl");
    let status = Command::new(&bin)
        .env("BHF_RUNTRACE_LOG", &unshimmed)
        .status()
        .expect("spawn probe");
    assert!(status.success());
    assert!(!unshimmed.exists());
    // A log someone else created (the fuzz driver opens it for its comparison
    // records) gets no marker from a run without the shim.
    let driver_made = dir.join("rt-driver.jsonl");
    std::fs::write(&driver_made, b"").unwrap();
    let status = Command::new(&bin)
        .env("BHF_CMPLOG", "1")
        .env("BHF_RUNTRACE_LOG", &driver_made)
        .status()
        .expect("spawn probe");
    assert!(status.success());
    let text = std::fs::read_to_string(&driver_made).unwrap();
    assert!(
        !text.contains("shim_loaded"),
        "a run without the shim marked the log:\n{text}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

const SHIM_LOADED_LINE: &str = "{\"e\":\"shim_loaded\"}";

/// Build `lib<name>.so` from `src` in `dir`, so a probe can link against it or
/// preload it.
fn build_shared_library(cc: &str, dir: &std::path::Path, name: &str, src: &str) -> PathBuf {
    let c = dir.join(format!("{name}.c"));
    std::fs::write(&c, src).unwrap();
    let so = dir.join(format!("lib{name}.so"));
    let built = Command::new(cc)
        .args(["-shared", "-fPIC"])
        .arg(&c)
        .arg("-o")
        .arg(&so)
        .status()
        .unwrap();
    assert!(built.success(), "lib{name}.so failed to compile");
    so
}

/// A library whose constructor reads an environment variable. glibc runs the
/// constructors of a program's other libraries, and of every library preloaded
/// after the shim, before the shim's own, with the shim's hooks already bound.
const GETENV_IN_CONSTRUCTOR_LIBRARY: &str = r#"
    #include <stdlib.h>
    static const char *probe_home;
    __attribute__((constructor)) static void read_home(void) {
        probe_home = getenv("PROBE_DEP_HOME");
    }
    int probe_dep_ready(void) { return probe_home == 0; }
"#;

/// Run `bin` with `preload` as `LD_PRELOAD` and `log` as the runtrace log, and
/// return the log's text.
fn run_logged(bin: &std::path::Path, preload: &std::ffi::OsStr, log: &std::path::Path) -> String {
    let status = Command::new(bin)
        .env("LD_PRELOAD", preload)
        .env("BHF_RUNTRACE_LOG", log)
        .env_remove("PROBE_DEP_HOME")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn probe");
    assert!(status.success(), "probe exited abnormally: {status:?}");
    std::fs::read_to_string(log)
        .unwrap_or_else(|e| panic!("the preloaded shim did not create {}: {e}", log.display()))
}

/// The log of a run with the shim loaded starts with the load marker even when
/// a hook fires before the shim's own constructor runs: the shim writes the
/// marker when it first opens the log, ahead of the event that opened it.
fn assert_marker_leads(text: &str, early_event: &str) {
    assert_eq!(
        text.lines().next(),
        Some(SHIM_LOADED_LINE),
        "the shim's log does not start with its load marker:\n{text}"
    );
    assert!(
        text.lines().any(|line| line.contains(early_event)),
        "the hooked call made before the shim's constructor was not logged:\n{text}"
    );
    assert_eq!(
        text.lines()
            .filter(|line| *line == SHIM_LOADED_LINE)
            .count(),
        1,
        "the shim marked its log more than once:\n{text}"
    );
}

/// A probe linked against a library whose constructor calls `getenv`: that
/// constructor runs before the shim's, through the shim's `getenv` hook.
#[test]
fn the_load_marker_leads_the_log_when_a_linked_library_reads_the_environment_first() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let dir = std::env::temp_dir().join(format!("bhf-shim-early-dep-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    build_shared_library(cc, &dir, "probedep", GETENV_IN_CONSTRUCTOR_LIBRARY);
    let src = dir.join("probe.c");
    std::fs::write(
        &src,
        "int probe_dep_ready(void);\nint main(void) { return probe_dep_ready() ? 0 : 1; }\n",
    )
    .unwrap();
    let bin = dir.join("probe");
    let built = Command::new(cc)
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .arg(format!("-L{}", dir.display()))
        .arg("-lprobedep")
        .arg(format!("-Wl,-rpath,{}", dir.display()))
        .status()
        .unwrap();
    assert!(built.success(), "probe failed to compile");
    let log = dir.join("rt.jsonl");
    let text = run_logged(&bin, shim.as_os_str(), &log);
    assert_marker_leads(&text, "PROBE_DEP_HOME");
    let _ = std::fs::remove_dir_all(&dir);
}

/// bhf puts its shim first in `LD_PRELOAD`, ahead of any library the run
/// already preloads; glibc runs that later library's constructor first.
#[test]
fn the_load_marker_leads_the_log_when_a_later_preload_reads_the_environment_first() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let dir = std::env::temp_dir().join(format!("bhf-shim-early-preload-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let dep = build_shared_library(cc, &dir, "probedep", GETENV_IN_CONSTRUCTOR_LIBRARY);
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
    let mut preload = shim.into_os_string();
    preload.push(":");
    preload.push(&dep);
    let log = dir.join("rt.jsonl");
    let text = run_logged(&bin, &preload, &log);
    assert_marker_leads(&text, "PROBE_DEP_HOME");
    let _ = std::fs::remove_dir_all(&dir);
}

/// An OpenMP program: libgomp's constructor reads its `OMP_*` settings
/// through the shim's hooks before the shim's constructor runs.
#[test]
fn the_load_marker_leads_the_log_of_an_openmp_program() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let dir = std::env::temp_dir().join(format!("bhf-shim-early-omp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("probe.c");
    std::fs::write(
        &src,
        "#include <omp.h>\nint main(void) { return omp_get_max_threads() > 0 ? 0 : 1; }\n",
    )
    .unwrap();
    let bin = dir.join("probe");
    let built = Command::new(cc)
        .arg("-fopenmp")
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .stderr(Stdio::null())
        .status()
        .unwrap();
    if !built.success() {
        let _ = std::fs::remove_dir_all(&dir);
        eprintln!("skipping: {cc} cannot build an OpenMP program (no libgomp)");
        return;
    }
    let log = dir.join("rt.jsonl");
    let status = Command::new(&bin)
        .env("LD_PRELOAD", &shim)
        .env("BHF_RUNTRACE_LOG", &log)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn probe");
    assert!(status.success(), "probe exited abnormally: {status:?}");
    let text = std::fs::read_to_string(&log)
        .unwrap_or_else(|e| panic!("the preloaded shim did not create {}: {e}", log.display()));
    if !text.lines().any(|line| line.contains("\"n\":\"OMP_")) {
        let _ = std::fs::remove_dir_all(&dir);
        eprintln!("skipping: this libgomp read no OMP_ variable through the shim:\n{text}");
        return;
    }
    assert_marker_leads(&text, "\"n\":\"OMP_");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A log another writer started (the fuzz driver's comparison records, a
/// process without the shim) still gets the marker from the first process
/// that runs with the shim, and only once: a later process finds it.
#[test]
fn the_shim_marks_a_log_another_writer_started_once() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let dir = std::env::temp_dir().join(format!("bhf-shim-late-mark-{}", std::process::id()));
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
    // More than one read's worth of earlier records, so a marker after them
    // is not found by a look at the first block alone.
    let earlier = "{\"e\":\"cmplog\",\"a\":\"00\",\"b\":\"01\"}\n".repeat(200);
    std::fs::write(&log, &earlier).unwrap();
    run_logged(&bin, shim.as_os_str(), &log);
    let text = run_logged(&bin, shim.as_os_str(), &log);
    assert!(
        text.starts_with(&earlier),
        "the earlier records were not kept"
    );
    assert_eq!(
        text.lines()
            .filter(|line| *line == SHIM_LOADED_LINE)
            .count(),
        1,
        "two runs with the shim left other than one marker:\n{}",
        &text[earlier.len()..]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Threads of a library constructor, spinning until all are started and then
/// released at once, whose `getenv` calls are the process's first hooked
/// calls: each may find the log not yet open.
const RACING_THREADS_LIBRARY: &str = r#"
    #include <pthread.h>
    #include <stdlib.h>
    #define RACERS 16
    static int ready, go;
    static void *race(void *arg) {
        /* No printf-family call: the shim logs those too. */
        char name[] = "PROBE_RACE_00";
        name[11] = (char)('0' + (int)(long)arg / 10);
        name[12] = (char)('0' + (int)(long)arg % 10);
        __atomic_add_fetch(&ready, 1, __ATOMIC_ACQ_REL);
        while (!__atomic_load_n(&go, __ATOMIC_ACQUIRE)) {}
        (void)getenv(name);
        return 0;
    }
    __attribute__((constructor)) static void start_racers(void) {
        pthread_t threads[RACERS];
        long i;
        /* The shim resolves the real getenv on its first call and logs no
           BHF_ variable: the racers then go straight to the log. */
        (void)getenv("BHF_PROBE_WARMUP");
        for (i = 0; i < RACERS; i++) pthread_create(&threads[i], 0, race, (void *)i);
        while (__atomic_load_n(&ready, __ATOMIC_ACQUIRE) < RACERS) {}
        __atomic_store_n(&go, 1, __ATOMIC_RELEASE);
        for (i = 0; i < RACERS; i++) pthread_join(threads[i], 0);
    }
    int probe_race_ready(void) { return 0; }
"#;

/// The program linked against [`RACING_THREADS_LIBRARY`]: it prints how many
/// of its descriptors are open on the runtrace log.
const RACING_THREADS_PROBE: &str = r#"
    #include <dirent.h>
    #include <limits.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    int probe_race_ready(void);
    int main(void) {
        char log[PATH_MAX], link[PATH_MAX + 32], target[PATH_MAX];
        struct dirent *entry;
        int count = 0;
        DIR *fds;
        if (!realpath(getenv("BHF_RUNTRACE_LOG"), log)) return 2;
        fds = opendir("/proc/self/fd");
        if (!fds) return 2;
        while ((entry = readdir(fds)) != 0) {
            ssize_t n;
            snprintf(link, sizeof link, "/proc/self/fd/%s", entry->d_name);
            n = readlink(link, target, sizeof target - 1);
            if (n < 0) continue;
            target[n] = 0;
            if (strcmp(target, log) == 0) count++;
        }
        closedir(fds);
        printf("%d\n", count);
        return probe_race_ready();
    }
"#;

/// How many closes of the watched file the events waiting on the inotify
/// descriptor `inotify` report. inotify merges an event into an identical one
/// at the end of its queue, so the watch takes writes too: a write between
/// two closes keeps them apart.
fn closes_seen(inotify: i32) -> usize {
    let mut closes = 0;
    let mut buf = [0u8; 4096];
    loop {
        // SAFETY: `buf` is writable for its length.
        let n = unsafe { libc::read(inotify, buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            return closes;
        }
        let mut at = 0usize;
        while at + 16 <= n as usize {
            let mask = u32::from_ne_bytes(buf[at + 4..at + 8].try_into().unwrap());
            let len = u32::from_ne_bytes(buf[at + 12..at + 16].try_into().unwrap()) as usize;
            if mask & libc::IN_CLOSE != 0 {
                closes += 1;
            }
            at += 16 + len;
        }
    }
}

/// Threads that all make their first hooked call at once may each open the
/// log; one keeps its descriptor and marks the log, the others close theirs
/// and write through it. Every thread's event is logged, the log is marked
/// once, and one descriptor stays open on it. The runs repeat until some are
/// seen (by their closes of the log) to have raced.
#[test]
fn threads_racing_the_first_open_of_the_log_share_one_descriptor() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let dir = std::env::temp_dir().join(format!("bhf-shim-race-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let c = dir.join("racedep.c");
    std::fs::write(&c, RACING_THREADS_LIBRARY).unwrap();
    let built = Command::new(cc)
        .args(["-shared", "-fPIC", "-pthread"])
        .arg(&c)
        .arg("-o")
        .arg(dir.join("libracedep.so"))
        .status()
        .unwrap();
    assert!(built.success(), "libracedep.so failed to compile");
    let src = dir.join("probe.c");
    std::fs::write(&src, RACING_THREADS_PROBE).unwrap();
    let bin = dir.join("probe");
    let built = Command::new(cc)
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .arg(format!("-L{}", dir.display()))
        .arg("-lracedep")
        .arg(format!("-Wl,-rpath,{}", dir.display()))
        .arg("-pthread")
        .status()
        .unwrap();
    assert!(built.success(), "probe failed to compile");
    // SAFETY: plain syscalls on descriptors this test owns.
    let inotify = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    assert!(inotify >= 0, "inotify_init1 failed");
    let log = dir.join("rt.jsonl");
    let log_c = std::ffi::CString::new(log.as_os_str().as_encoded_bytes()).unwrap();
    let mut raced = 0;
    for _ in 0..50 {
        std::fs::write(&log, b"").unwrap();
        // SAFETY: a NUL-terminated path and the descriptor made above.
        let watch = unsafe {
            libc::inotify_add_watch(inotify, log_c.as_ptr(), libc::IN_CLOSE | libc::IN_MODIFY)
        };
        assert!(watch >= 0, "inotify_add_watch failed");
        let out = Command::new(&bin)
            .env("LD_PRELOAD", &shim)
            .env("BHF_RUNTRACE_LOG", &log)
            .output()
            .expect("spawn probe");
        // The descriptor the process exits with closes once; a thread that
        // lost the race closed its own before writing through the kept one.
        let closes = closes_seen(inotify);
        // SAFETY: as above.
        unsafe { libc::inotify_rm_watch(inotify, watch) };
        let _ = closes_seen(inotify);
        assert!(out.status.success(), "probe exited abnormally: {out:?}");
        let text = std::fs::read_to_string(&log).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            "1",
            "descriptors open on the log at main ({closes} closes):\n{text}"
        );
        assert_eq!(
            text.lines()
                .filter(|line| *line == SHIM_LOADED_LINE)
                .count(),
            1,
            "the log is not marked once ({closes} closes):\n{text}"
        );
        for racer in 0..16 {
            let name = format!("\"PROBE_RACE_{racer:02}\"");
            assert!(
                text.lines().any(|line| line.contains(&name)),
                "{name} was not logged ({closes} closes):\n{text}"
            );
        }
        if closes > 1 {
            raced += 1;
            if raced == 3 {
                break;
            }
        }
    }
    // SAFETY: the descriptor made above.
    unsafe { libc::close(inotify) };
    let _ = std::fs::remove_dir_all(&dir);
    if raced == 0 {
        eprintln!("skipping the race: no run had a thread lose the first open of the log");
    }
}

/// A library whose constructor makes the process's first hooked call, ahead of
/// the shim's own constructor, through a hook that leaves `errno` to the shim's
/// log handling: with identity faking on, `getuid` answers without calling
/// libc, so a changed `errno` is the shim's doing.
const ERRNO_IN_CONSTRUCTOR_LIBRARY: &str = r#"
    #include <errno.h>
    #include <unistd.h>
    int probe_ctor_errno = -1;
    __attribute__((constructor)) static void read_uid(void) {
        errno = 0;
        (void)getuid();
        probe_ctor_errno = errno;
    }
"#;

/// Run `bin` under the shim with `log` as the runtrace log, bounded so a
/// shim that blocks on the log fails the test instead of hanging it, and
/// return its stdout.
fn run_bounded(bin: &std::path::Path, shim: &std::path::Path, log: &std::path::Path) -> String {
    let mut child = Command::new(bin)
        .env("LD_PRELOAD", shim)
        .env("BHF_RUNTRACE_LOG", log)
        .env("BHF_FAKE_IDENTITY", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn probe");
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!(
                "{} hung under the shim with log {}",
                bin.display(),
                log.display()
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(status.success(), "probe exited abnormally: {status:?}");
    let mut out = String::new();
    std::io::Read::read_to_string(&mut child.stdout.take().unwrap(), &mut out).unwrap();
    out
}

/// The shim's handling of its log leaves `errno` as the program had it, as C
/// requires it to be zero at `main`, even when the log cannot be read back
/// (a file only writable, a FIFO): looking for an earlier marker in such a
/// log fails, and that failure must not reach the program, neither at `main`
/// nor in a library constructor whose hooked call first opened the log.
#[test]
fn the_shim_leaves_errno_alone_when_its_log_cannot_be_read_back() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let dir = std::env::temp_dir().join(format!("bhf-shim-errno-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let plain = dir.join("plain");
    let plain_src = dir.join("plain.c");
    std::fs::write(
        &plain_src,
        "#include <errno.h>\n#include <stdio.h>\n\
         int main(void) { int at_main = errno; printf(\"%d\\n\", at_main); return 0; }\n",
    )
    .unwrap();
    let built = Command::new(cc)
        .arg(&plain_src)
        .arg("-o")
        .arg(&plain)
        .status()
        .unwrap();
    assert!(built.success(), "probe failed to compile");
    build_shared_library(cc, &dir, "errnodep", ERRNO_IN_CONSTRUCTOR_LIBRARY);
    let linked = dir.join("linked");
    let linked_src = dir.join("linked.c");
    std::fs::write(
        &linked_src,
        "#include <errno.h>\n#include <stdio.h>\nextern int probe_ctor_errno;\n\
         int main(void) { int at_main = errno; printf(\"%d %d\\n\", probe_ctor_errno, at_main); return 0; }\n",
    )
    .unwrap();
    let built = Command::new(cc)
        .arg(&linked_src)
        .arg("-o")
        .arg(&linked)
        .arg(format!("-L{}", dir.display()))
        .arg("-lerrnodep")
        .arg(format!("-Wl,-rpath,{}", dir.display()))
        .status()
        .unwrap();
    assert!(built.success(), "probe failed to compile");

    // A log only its writer may write: the shim falls back to opening it
    // write-only, and its look for a marker cannot read it.
    let write_only = dir.join("write-only.jsonl");
    std::fs::write(&write_only, b"").unwrap();
    std::fs::set_permissions(
        &write_only,
        std::os::unix::fs::PermissionsExt::from_mode(0o200),
    )
    .unwrap();
    if std::fs::File::open(&write_only).is_ok() {
        eprintln!("skipping the write-only log: this user reads any file");
    } else {
        assert_eq!(run_bounded(&plain, &shim, &write_only).trim(), "0");
        assert_eq!(run_bounded(&linked, &shim, &write_only).trim(), "0 0");
    }

    // A FIFO, read by another process: it cannot be read at an offset.
    for bin in [&plain, &linked] {
        let fifo = dir.join("fifo.jsonl");
        let _ = std::fs::remove_file(&fifo);
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        // The read end is open before the probe starts: the shim's open of
        // a FIFO does not wait for a reader, and what it writes is gone once
        // the probe exits with no reader holding the FIFO.
        let reader = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo)
            .unwrap();
        let out = run_bounded(bin, &shim, &fifo);
        // The probe has exited, so no writer is left: the read returns what
        // the FIFO holds, then end of file.
        let mut read = Vec::new();
        std::io::Read::read_to_end(&mut &reader, &mut read).unwrap();
        assert!(
            String::from_utf8_lossy(&read).contains(SHIM_LOADED_LINE),
            "the shim wrote no marker into the FIFO"
        );
        let expected = if bin == &plain { "0" } else { "0 0" };
        assert_eq!(out.trim(), expected, "errno changed under a FIFO log");
    }
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

/// A printf format counts as fuzz-controlled only when it is not a literal in
/// the program's read-only data: a constant format whose bytes the fuzzer put
/// into the input (a mined dictionary token) is not the input's format, while
/// a format copied out of the input into the heap is.
#[test]
fn format_taint_ignores_literal_formats_found_in_the_input() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let dir = std::env::temp_dir().join(format!("bhf-shim-fmt-taint-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("probe.c");
    std::fs::write(
        &src,
        r#"
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>
        #include <stddef.h>
        extern void bhf_shim_set_fuzz_input(const unsigned char *data, size_t size)
            __attribute__((weak));
        int main(void) {
            const char *input = "A%s%x%x%x\n";
            if (bhf_shim_set_fuzz_input)
                bhf_shim_set_fuzz_input((const unsigned char *)input, strlen(input));
            printf("%s", "x");
            printf("%x%x%x\n", 1, 2, 3);
            char *heap = malloc(8);
            if (!heap) return 1;
            memcpy(heap, input + 3, 7);
            heap[7] = '\0';
            printf(heap, 1, 2, 3);
            free(heap);
            return 0;
        }
    "#,
    )
    .unwrap();
    let mut builds = vec![("plain", cc, vec!["-fno-builtin"])];
    let asan = dir.join("probe-asan-check");
    if Command::new("clang")
        .args(["-fsanitize=address", "-fno-builtin"])
        .arg(&src)
        .arg("-o")
        .arg(&asan)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
    {
        builds.push((
            "clang-asan",
            "clang",
            vec!["-fsanitize=address", "-fno-builtin"],
        ));
    }
    for (label, compiler, flags) in &builds {
        let bin = dir.join(format!("probe-{label}"));
        let built = Command::new(compiler)
            .args(flags)
            .arg(&src)
            .arg("-o")
            .arg(&bin)
            .status()
            .unwrap();
        assert!(built.success(), "{label} probe failed to compile");
        let log = dir.join(format!("rt-{label}.jsonl"));
        let output = Command::new(&bin)
            .env("LD_PRELOAD", &shim)
            .env("BHF_RUNTRACE_LOG", &log)
            .env("ASAN_OPTIONS", "verify_asan_link_order=0:detect_leaks=0")
            .output()
            .expect("spawn probe");
        assert!(
            output.status.success(),
            "{label} probe exited abnormally: {:?}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        let formats: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("\"e\":\"format\"") && line.contains("\"a\":\"printf\""))
            .collect();
        let constant = formats
            .iter()
            .find(|line| line.contains("\"f\":\"%s\""))
            .unwrap_or_else(|| panic!("{label}: no printf event for \"%s\":\n{text}"));
        assert!(constant.contains("\"u\":0"), "{label}: {constant}");
        let copies: Vec<&&str> = formats
            .iter()
            .filter(|line| line.contains("\"f\":\"%x%x%x\\n\""))
            .collect();
        assert_eq!(copies.len(), 2, "{label}: {text}");
        assert!(
            copies[0].contains("\"u\":0"),
            "{label}: the literal format counted as input-controlled: {}",
            copies[0]
        );
        assert!(
            copies[1].contains("\"u\":1"),
            "{label}: the heap copy of the input's format was not counted: {}",
            copies[1]
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
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

/// The `"d"` field of a runtrace line.
fn event_fd(line: &str) -> Option<i64> {
    let start = line.find("\"d\":")? + 4;
    let digits: String = line[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    digits.parse().ok()
}

/// glibc's `fclose` closes the stream's descriptor internally, never through
/// the `close` hook, so a file opened with `fopen` (or wrapped with `fdopen`)
/// and closed with `fclose` must log its close itself, or every such file
/// reads as leaked. Checked in a plain program and under each sanitizer
/// runtime the host can build, whose `fclose` interceptor forwards to the next
/// definition.
#[test]
fn fclose_logs_the_close_of_a_fopened_or_fdopened_stream() {
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
    let dir = std::env::temp_dir().join(format!("bhf-shim-fclose-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // Outside the runtrace-log dir: the shim records nothing inside it.
    let present =
        std::env::temp_dir().join(format!("bhf-shim-fclose-widget-{}.cfg", std::process::id()));
    std::fs::write(&present, "widget=1\n").unwrap();
    let src = dir.join("probe.c");
    std::fs::write(
        &src,
        r#"
        #include <fcntl.h>
        #include <stdio.h>
        int main(int argc, char **argv) {
            if (argc < 2) return 1;
            FILE *f = fopen(argv[1], "r");
            if (!f) return 2;
            if (fclose(f) != 0) return 3;
            int fd = open(argv[1], O_RDONLY);
            if (fd < 0) return 4;
            FILE *g = fdopen(fd, "r");
            if (!g) return 5;
            if (fclose(g) != 0) return 6;
            return 0;
        }
    "#,
    )
    .unwrap();
    let mut builds = vec![("plain", cc, Vec::<&str>::new())];
    for (label, compiler, flags) in [
        ("clang-asan", "clang", vec!["-fsanitize=address"]),
        (
            "gcc-asan-static",
            "gcc",
            vec!["-fsanitize=address", "-static-libasan"],
        ),
    ] {
        let built = Command::new(compiler)
            .args(&flags)
            .arg(&src)
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
            .arg("-o")
            .arg(&bin)
            .status()
            .unwrap();
        assert!(built.success(), "{label} probe failed to compile");
        for shim in &shims {
            let log = dir.join(format!("rt-{label}.jsonl"));
            let _ = std::fs::remove_file(&log);
            let status = Command::new(&bin)
                .arg(&present)
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
            let fopen_fd = text
                .lines()
                .find(|line| line.contains("\"e\":\"fopen\"") && line.contains(&opened))
                .and_then(event_fd)
                .unwrap_or_else(|| panic!("{label}: no fopen event:\n{text}"));
            let closes: Vec<i64> = text
                .lines()
                .filter(|line| line.contains("\"e\":\"close\"") && line.contains("\"r\":0"))
                .filter_map(event_fd)
                .collect();
            assert!(
                closes.contains(&fopen_fd),
                "{label} under {}: fclose of fd {fopen_fd} logged no close:\n{text}",
                shim.display()
            );
            let open_fd = text
                .lines()
                .filter(|line| line.contains("\"e\":\"open\"") && line.contains(&opened))
                .filter_map(event_fd)
                .next_back()
                .unwrap_or_else(|| panic!("{label}: no open event:\n{text}"));
            assert!(
                text.lines().any(
                    |line| line.contains("\"e\":\"fdopen\"") && event_fd(line) == Some(open_fd)
                ),
                "{label}: fdopen of fd {open_fd} not logged:\n{text}"
            );
            assert!(
                closes.iter().filter(|fd| **fd == open_fd).count() >= 1,
                "{label}: fclose of the fdopened fd {open_fd} logged no close:\n{text}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&present);
}

/// A sanitizer runtime defines the printf family in the executable and
/// forwards each call to the `va_list` variant it finds next (`printf` to
/// `vprintf`, `snprintf` to `vsnprintf`), and a fortified build calls
/// `__printf_chk` and friends: the format strings must be logged on every
/// one of those lanes, under the variadic API the program called.
#[test]
fn format_hooks_log_printf_formats_under_sanitizers_and_fortify() {
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
    let dir = std::env::temp_dir().join(format!("bhf-shim-vformat-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("probe.c");
    std::fs::write(
        &src,
        r#"
        #include <stdarg.h>
        #include <stdio.h>
        #include <stdlib.h>
        static int log_line(const char *fmt, ...) {
            va_list ap;
            va_start(ap, fmt);
            int n = vfprintf(stdout, fmt, ap);
            va_end(ap);
            return n;
        }
        int main(int argc, char **argv) {
            char buf[64];
            char *heap = NULL;
            const char *fmt = argc > 99 ? argv[1] : "widget %d\n";
            if (printf(fmt, 1) < 0) return 1;
            if (snprintf(buf, sizeof buf, "copy_at %u", 2u) < 0) return 2;
            if (fprintf(stdout, "bit_index %d\n", 3) < 0) return 3;
            if (log_line("record %s\n", "x") < 0) return 4;
            if (asprintf(&heap, "heap %ld", 5L) < 0) return 5;
            free(heap);
            return 0;
        }
    "#,
    )
    .unwrap();
    let mut builds = vec![("plain", cc, Vec::<&str>::new())];
    for (label, compiler, flags) in [
        ("clang-asan", "clang", vec!["-fsanitize=address"]),
        (
            "clang-asan-ubsan",
            "clang",
            vec!["-fsanitize=address,undefined"],
        ),
        (
            "clang-asan-shared",
            "clang",
            vec!["-fsanitize=address", "-shared-libasan"],
        ),
        ("gcc-asan-shared", "gcc", vec!["-fsanitize=address"]),
        (
            "gcc-asan-static",
            "gcc",
            vec!["-fsanitize=address", "-static-libasan"],
        ),
        (
            "gcc-fortify",
            "gcc",
            vec!["-O2", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=2"],
        ),
    ] {
        let bin = dir.join(format!("probe-{label}"));
        let built = Command::new(compiler)
            .args(&flags)
            .arg(&src)
            .arg("-o")
            .arg(&bin)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        // A lane whose runtime library the loader cannot find (a shared
        // sanitizer runtime outside the library path) is skipped.
        let runs = built
            && Command::new(&bin)
                .env("ASAN_OPTIONS", "detect_leaks=0")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success());
        if runs {
            builds.push((label, compiler, flags));
        }
    }
    for (label, compiler, flags) in &builds {
        let bin = dir.join(format!("probe-{label}"));
        let built = Command::new(compiler)
            .args(flags)
            .arg(&src)
            .arg("-o")
            .arg(&bin)
            .status()
            .unwrap();
        assert!(built.success(), "{label} probe failed to compile");
        for shim in &shims {
            let log = dir.join(format!("rt-{label}.jsonl"));
            let _ = std::fs::remove_file(&log);
            let output = Command::new(&bin)
                .env("LD_PRELOAD", shim)
                .env("BHF_RUNTRACE_LOG", &log)
                .env("ASAN_OPTIONS", "verify_asan_link_order=0:detect_leaks=0")
                .output()
                .expect("spawn probe");
            assert!(
                output.status.success(),
                "{label} probe under {} exited abnormally: {:?}\n{}",
                shim.display(),
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            // The calls themselves still produce their output.
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                stdout.contains("widget 1") && stdout.contains("record x"),
                "{label}: {stdout}"
            );
            let text = std::fs::read_to_string(&log).unwrap_or_default();
            for (api, format) in [
                ("printf", "widget %d\\n"),
                ("snprintf", "copy_at %u"),
                ("fprintf", "bit_index %d\\n"),
                ("fprintf", "record %s\\n"),
                ("asprintf", "heap %ld"),
            ] {
                assert!(
                    text.lines().any(|line| line.contains("\"e\":\"format\"")
                        && line.contains(&format!("\"a\":\"{api}\""))
                        && line.contains(&format!("\"f\":\"{format}\""))),
                    "{label} under {}: no {api} format event for {format:?}:\n{text}",
                    shim.display()
                );
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// In a faking pass a missing file is replaced by a fake one, but never the
/// vDSO's link-map name a sanitizer's symbolizer opens, and nothing once a
/// sanitizer has started a report (the driver tells the shim through
/// `bhf_shim_sanitizer_reporting`).
#[test]
fn pseudo_paths_and_paths_opened_during_a_sanitizer_report_are_not_faked() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let dir = std::env::temp_dir().join(format!("bhf-shim-nofake-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("probe.c");
    std::fs::write(
        &src,
        r#"
        #include <errno.h>
        #include <fcntl.h>
        #include <stdio.h>
        #include <unistd.h>
        extern void bhf_shim_sanitizer_reporting(void) __attribute__((weak));
        static void report(const char *label, const char *path) {
            errno = 0;
            int fd = open(path, O_RDONLY);
            printf("%s fd=%d errno=%d\n", label, fd >= 0 ? 1 : -1, fd >= 0 ? 0 : errno);
            if (fd >= 0) close(fd);
        }
        int main(int argc, char **argv) {
            if (argc < 2) return 1;
            report("vdso", "linux-vdso.so.1");
            report("missing-before", argv[1]);
            if (!bhf_shim_sanitizer_reporting) return 2;
            bhf_shim_sanitizer_reporting();
            report("missing-after", argv[1]);
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
    let missing = format!("/nonexistent-bhf-{}/widget.cfg", std::process::id());
    let log = dir.join("rt.jsonl");
    let output = Command::new(&bin)
        .arg(&missing)
        .env("LD_PRELOAD", &shim)
        .env("BHF_RUNTRACE_LOG", &log)
        .env("BHF_RUNTRACE_MODE", "empty")
        .output()
        .expect("spawn probe");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{:?}\n{stdout}", output.status);
    assert!(stdout.contains("vdso fd=-1 errno=2"), "{stdout}");
    assert!(
        stdout.contains("missing-before fd=1 errno=0"),
        "an ordinary missing file is faked in an empty pass: {stdout}"
    );
    assert!(stdout.contains("missing-after fd=-1 errno=2"), "{stdout}");
    let text = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(!text.contains("linux-vdso"), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}
