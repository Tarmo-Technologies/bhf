// SPDX-License-Identifier: Apache-2.0
//! The opt-in deterministic clock (#342).
//!
//! With `BHF_FAKE_CLOCK=1` the shim serves `clock_gettime`, `gettimeofday`,
//! `time`, `clock` and `timespec_get` from a virtual clock: it starts at a
//! fixed instant, each read advances it 1 ms, and each input the harness
//! publishes starts it over. So the same input sees identical times, in a
//! second process and when it runs again in the same one, and a deadline loop
//! still ends. Without the gate the real clock shows through.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

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

fn shim_so() -> Option<PathBuf> {
    let base = target_dir();
    ["debug", "release"]
        .into_iter()
        .map(|profile| base.join(profile).join("libbhf_runtrace_shim.so"))
        .find(|p| p.is_file())
}

fn require_shim() -> Option<PathBuf> {
    let shim = shim_so();
    assert!(
        shim.is_some() || std::env::var_os("BHF_REQUIRE_TOOLS").is_none_or(|v| v != "1"),
        "BHF_REQUIRE_TOOLS=1 and the shim cdylib is not built (cargo build --workspace)"
    );
    shim
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

/// Samples every faked clock after publishing an input, publishes the same
/// input again and samples again, then spins until 100 ms of monotonic time
/// pass and prints how many reads that took.
const PROBE: &str = r#"
#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
extern void bhf_shim_set_fuzz_input(const uint8_t *data, size_t size) __attribute__((weak));
static void publish(void) {
    static const uint8_t input[] = "parse_record input";
    if (bhf_shim_set_fuzz_input) bhf_shim_set_fuzz_input(input, sizeof input - 1);
}
static void sample(const char *tag) {
    struct timespec rt, mono, cpu, utc;
    struct timeval tv;
    clock_gettime(CLOCK_REALTIME, &rt);
    clock_gettime(CLOCK_MONOTONIC, &mono);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu);
    gettimeofday(&tv, NULL);
    time_t now = time(NULL);
    clock_t ticks = clock();
    timespec_get(&utc, TIME_UTC);
    printf("%s %lld.%09ld %lld.%09ld %lld.%09ld %lld.%06ld %lld %ld %lld.%09ld\n", tag,
           (long long)rt.tv_sec, rt.tv_nsec, (long long)mono.tv_sec, mono.tv_nsec,
           (long long)cpu.tv_sec, cpu.tv_nsec, (long long)tv.tv_sec, (long)tv.tv_usec,
           (long long)now, (long)ticks, (long long)utc.tv_sec, utc.tv_nsec);
}
int main(void) {
    publish();
    sample("first");
    publish();
    sample("again");
    struct timespec start, at;
    long reads = 0;
    clock_gettime(CLOCK_MONOTONIC, &start);
    do {
        clock_gettime(CLOCK_MONOTONIC, &at);
        reads++;
    } while ((at.tv_sec - start.tv_sec) * 1000000000L + (at.tv_nsec - start.tv_nsec) < 100000000L);
    printf("reads %ld\n", reads);
    return 0;
}
"#;

fn build(dir: &Path) -> Option<PathBuf> {
    build_with(dir, cc()?, &[])
}

fn build_with(dir: &Path, cc: &str, flags: &[&str]) -> Option<PathBuf> {
    let src = dir.join("clock.c");
    let bin = dir.join(format!("clock{}", flags.len()));
    std::fs::write(&src, PROBE).unwrap();
    let built = Command::new(cc)
        .args(flags)
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .status()
        .is_ok_and(|s| s.success());
    assert!(built, "probe must compile with {cc} {flags:?}");
    Some(bin)
}

fn run(bin: &Path, shim: &Path, fake: bool) -> String {
    let mut cmd = Command::new(bin);
    cmd.env("LD_PRELOAD", shim).env_remove("BHF_FAKE_CLOCK");
    if fake {
        cmd.env("BHF_FAKE_CLOCK", "1");
    }
    let out = cmd.output().expect("run probe");
    assert!(
        out.status.success(),
        "probe failed under the shim: {:?} {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The fields after the tag of the line starting with `tag`.
fn fields<'a>(output: &'a str, tag: &str) -> Vec<&'a str> {
    output
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{tag} ")))
        .unwrap_or_else(|| panic!("no {tag} line in {output}"))
        .split(' ')
        .collect()
}

fn seconds(field: &str) -> f64 {
    field
        .parse()
        .unwrap_or_else(|_| panic!("not a time: {field}"))
}

#[test]
fn the_same_input_sees_identical_times_twice() {
    let Some(shim) = require_shim() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let dir = tempfile::Builder::new()
        .prefix("bhf-clock-")
        .tempdir()
        .unwrap();
    let Some(bin) = build(dir.path()) else {
        eprintln!("skipping: no C compiler");
        return;
    };

    let first = run(&bin, &shim, true);
    let second = run(&bin, &shim, true);
    assert_eq!(
        first, second,
        "two runs of the same input see the same times"
    );
    assert_eq!(
        fields(&first, "first"),
        fields(&first, "again"),
        "the input published again starts the clock over: {first}"
    );

    // Each read is 1 ms after the one before. The wall clocks start at
    // 2026-01-01T00:00:00Z, the monotonic one at 1000 s, the CPU clocks at 0.
    assert_eq!(
        fields(&first, "first"),
        [
            "1767225600.000000000", // clock_gettime(CLOCK_REALTIME), read 0
            "1000.001000000",       // clock_gettime(CLOCK_MONOTONIC), read 1
            "0.002000000",          // clock_gettime(CLOCK_PROCESS_CPUTIME_ID), read 2
            "1767225600.003000",    // gettimeofday, read 3
            "1767225600",           // time, read 4
            "5000",                 // clock, read 5, in CLOCKS_PER_SEC
            "1767225600.006000000", // timespec_get, read 6
        ],
        "{first}"
    );
    // A 100 ms deadline loop ends after 100 virtual milliseconds of reads.
    assert_eq!(fields(&first, "reads"), ["100"], "{first}");
}

#[test]
fn without_the_gate_the_real_clock_shows_through() {
    let Some(shim) = require_shim() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let dir = tempfile::Builder::new()
        .prefix("bhf-clock-")
        .tempdir()
        .unwrap();
    let Some(bin) = build(dir.path()) else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let real = run(&bin, &shim, false);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    let sample = fields(&real, "first");
    for (index, what) in [(0, "clock_gettime"), (3, "gettimeofday"), (4, "time")] {
        assert!(
            (seconds(sample[index]) - now).abs() < 600.0,
            "{what} reads the host clock: {real}"
        );
    }
    let reads: u64 = fields(&real, "reads")[0].parse().unwrap();
    assert!(reads > 100, "a real 100 ms spin takes many reads: {real}");
}

/// AddressSanitizer's allocator reads the clock itself, even from inside
/// glibc's `dlerror` bookkeeping while the shim loads. The hooks must neither
/// break that (a read that re-entered the shim's `getenv` hook double-freed
/// there) nor stop the fake from serving the target.
#[test]
fn the_clock_hooks_hold_under_address_sanitizer() {
    let Some(shim) = require_shim() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let clang = Command::new("clang")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !clang {
        eprintln!("skipping: no clang for the AddressSanitizer probe");
        return;
    }
    let dir = tempfile::Builder::new()
        .prefix("bhf-clock-")
        .tempdir()
        .unwrap();
    let bin = build_with(dir.path(), "clang", &["-fsanitize=address", "-g"]).unwrap();
    let real = run(&bin, &shim, false);
    assert!(real.contains("reads "), "{real}");
    let first = run(&bin, &shim, true);
    assert_eq!(first, run(&bin, &shim, true), "{first}");
    assert_eq!(fields(&first, "first"), fields(&first, "again"), "{first}");
    assert_eq!(
        fields(&first, "first")[0],
        "1767225600.000000000",
        "{first}"
    );
}

/// Waits until a deadline 300 ms ahead of the clock it reads, through each
/// absolute-deadline call, and prints how long each took on the kernel's
/// own monotonic clock (a raw system call the shim does not see).
const WAIT_PROBE: &str = r#"
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
static long long kernel_ms(void) {
    struct timespec ts;
    syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
}
static struct timespec ahead(clockid_t clock) {
    struct timespec ts;
    clock_gettime(clock, &ts);
    ts.tv_nsec += 300000000L;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec += 1; ts.tv_nsec -= 1000000000L; }
    return ts;
}
int main(void) {
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    sem_t sem;
    sem_init(&sem, 0, 0);
    long long start = kernel_ms();
    struct timespec deadline = ahead(CLOCK_MONOTONIC);
    int rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL);
    printf("clock_nanosleep %d %lld\n", rc, kernel_ms() - start);

    start = kernel_ms();
    deadline = ahead(CLOCK_MONOTONIC);
    pthread_mutex_lock(&mutex);
    rc = pthread_cond_clockwait(&cond, &mutex, CLOCK_MONOTONIC, &deadline);
    pthread_mutex_unlock(&mutex);
    printf("pthread_cond_clockwait %d %lld\n", rc == ETIMEDOUT, kernel_ms() - start);

    start = kernel_ms();
    struct timeval now;
    gettimeofday(&now, NULL);
    deadline.tv_sec = now.tv_sec;
    deadline.tv_nsec = now.tv_usec * 1000L + 300000000L;
    if (deadline.tv_nsec >= 1000000000L) { deadline.tv_sec += 1; deadline.tv_nsec -= 1000000000L; }
    pthread_mutex_lock(&mutex);
    rc = pthread_cond_timedwait(&cond, &mutex, &deadline);
    pthread_mutex_unlock(&mutex);
    printf("pthread_cond_timedwait %d %lld\n", rc == ETIMEDOUT, kernel_ms() - start);

    start = kernel_ms();
    deadline = ahead(CLOCK_REALTIME);
    rc = sem_timedwait(&sem, &deadline);
    printf("sem_timedwait %d %lld\n", rc == -1 && errno == ETIMEDOUT, kernel_ms() - start);

    start = kernel_ms();
    deadline = ahead(CLOCK_MONOTONIC);
    rc = sem_clockwait(&sem, CLOCK_MONOTONIC, &deadline);
    printf("sem_clockwait %d %lld\n", rc == -1 && errno == ETIMEDOUT, kernel_ms() - start);

    /* A deadline already past ends at once. */
    start = kernel_ms();
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec -= 1;
    rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL);
    printf("past %d %lld\n", rc, kernel_ms() - start);
    return 0;
}
"#;

/// #342: a deadline the target computes from the virtual clock is waited
/// for on the real one, as far ahead as it was of the virtual time. Without
/// that, a monotonic deadline (the virtual clock starts at 1000 s) ended at
/// once on a host up longer and slept until the uptime reached it on one
/// just booted, and a wall-clock one (2026-01-01) always ended at once.
#[test]
fn absolute_deadlines_wait_as_long_as_they_are_ahead_of_the_virtual_clock() {
    let Some(shim) = require_shim() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let dir = tempfile::Builder::new()
        .prefix("bhf-clock-wait-")
        .tempdir()
        .unwrap();
    let src = dir.path().join("wait.c");
    let bin = dir.path().join("wait");
    std::fs::write(&src, WAIT_PROBE).unwrap();
    let built = Command::new(cc)
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .arg("-pthread")
        .status()
        .is_ok_and(|s| s.success());
    assert!(built, "the wait probe must compile");
    for fake in [true, false] {
        let out = run(&bin, &shim, fake);
        for call in [
            "clock_nanosleep",
            "pthread_cond_clockwait",
            "pthread_cond_timedwait",
            "sem_timedwait",
            "sem_clockwait",
        ] {
            let line = fields(&out, call);
            let (result, waited): (&str, u64) = (line[0], line[1].parse().unwrap());
            let expected = if call == "clock_nanosleep" { "0" } else { "1" };
            assert_eq!(result, expected, "fake={fake} {call}: {out}");
            assert!(
                (250..3000).contains(&waited),
                "fake={fake} {call} waited {waited} ms: {out}"
            );
        }
        let past = fields(&out, "past");
        assert_eq!(past[0], "0", "{out}");
        assert!(past[1].parse::<u64>().unwrap() < 200, "{out}");
    }
}
