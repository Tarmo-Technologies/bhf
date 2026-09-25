// SPDX-License-Identifier: Apache-2.0
//! HDF-8 deliverables 2 + 3: schedule-perturbation exploration and pinned-schedule
//! replay, end-to-end through the LD_PRELOAD shim.
//!
//! A 2-thread fixture has an order-dependent bug — a double-spend that only occurs
//! when worker B's withdrawal lands *between* worker A's read and A's write of a
//! shared balance. Under plain execution the host scheduler runs A's tiny critical
//! section to completion before B (which starts with a real sleep) ever touches the
//! balance, so the bug is missed. Under schedule perturbation (`BHF_SCHED=1`) the
//! shim runs the threads under a cooperative baton whose ordering is drawn from a
//! pinned schedule (`BHF_SCHED_SEQUENCE`), forcing exactly the A-read → B-write →
//! A-write interleaving that triggers the bug — deterministically and repeatably.
//!
//! These assertions are the in-tree acceptance criteria for HDF-8: the race is
//! FOUND under exploration but MISSED by plain execution within a bounded budget;
//! the specific interleaving is shown to be reached (the fixture's double-spend
//! return code AND the realized schedule trace); and the pinned schedule replays
//! to the identical interleaving/outcome across repeated runs.
//!
//! clang+pthread gated: self-skips when no C compiler or the shim cdylib is absent.

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

fn shim_so() -> Option<PathBuf> {
    let base = target_dir();
    for profile in ["debug", "release"] {
        let p = base.join(profile).join("libbhf_runtrace_shim.so");
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

// Prefer clang (the track names clang+pthread), fall back to cc/gcc — the fixture
// is plain C and links against libc's pthread on any of them.
fn cc() -> Option<&'static str> {
    ["clang", "cc", "gcc"].into_iter().find(|c| {
        Command::new(c)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    })
}

/// Compile a pthread C program. Returns false if the compiler rejected it.
fn compile_pthread(cc: &str, src: &std::path::Path, bin: &std::path::Path) -> bool {
    Command::new(cc)
        .arg("-pthread")
        .arg("-O0")
        .arg(src)
        .arg("-o")
        .arg(bin)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Run `bin` under the shim, optionally engaging schedule perturbation with a
/// pinned sequence and a runtrace log. Returns the exit code, with a bounded wall
/// clock so a broken (deadlocking) scheduler fails loudly instead of hanging.
fn run(
    bin: &std::path::Path,
    shim: &std::path::Path,
    sched: Option<&str>,
    log: Option<&std::path::Path>,
) -> Option<i32> {
    let mut cmd = Command::new(bin);
    cmd.env("LD_PRELOAD", shim)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    match sched {
        Some(seq) => {
            cmd.env("BHF_SCHED", "1").env("BHF_SCHED_SEQUENCE", seq);
        }
        None => {
            // Plain execution: the scheduler is inert (bhf_sched_yield is a no-op,
            // pthread_create/join pass straight through).
            cmd.env_remove("BHF_SCHED");
        }
    }
    if let Some(log) = log {
        cmd.env("BHF_RUNTRACE_LOG", log);
    }
    let mut child = cmd.spawn().expect("spawn schedule fixture");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(s) = child.try_wait().unwrap() {
            return s.code();
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("schedule-perturbation fixture HUNG (scheduler deadlock?)");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

// Two workers withdraw 100 from a 100-unit balance. A correct bank allows exactly
// one withdrawal; a double-spend (two withdrawals) is only reachable when B's
// read+write lands between A's read and A's write. Worker B starts with a real
// sleep so that WITHOUT the cooperative scheduler, A always completes first
// (deterministic, no bug); WITH it, A is parked at its yield while B runs, so the
// scheduler — not luck — decides the order.
const FIXTURE: &str = r#"
#include <pthread.h>
#include <stdint.h>
#include <unistd.h>

extern void bhf_sched_yield(void) __attribute__((weak));
static void yield_point(void) { if (bhf_sched_yield) bhf_sched_yield(); }

static int account = 100;
static int withdrawals = 0;

static void *worker_a(void *arg) {
    (void)arg;
    int local = account;          /* READ */
    yield_point();                /* scheduling point: sched mode may run B here */
    if (local >= 100) {
        account = local - 100;    /* WRITE (uses the stale read) */
        withdrawals++;
    }
    return 0;
}

static void *worker_b(void *arg) {
    (void)arg;
    /* PLAIN execution: this 50ms sleep guarantees A finishes first (huge margin
     * over A's ~microsecond critical section), so plain runs never double-spend.
     * SCHEDULE mode: A is cooperatively parked, so the sleep only delays B; the
     * ORDER is the scheduler's choice. */
    usleep(50000);
    int local = account;
    if (local >= 100) {
        account = local - 100;
        withdrawals++;
    }
    return 0;
}

int main(void) {
    pthread_t ta, tb;
    if (pthread_create(&ta, 0, worker_a, 0) != 0) return 2;
    if (pthread_create(&tb, 0, worker_b, 0) != 0) return 2;
    pthread_join(ta, 0);
    pthread_join(tb, 0);
    return (withdrawals > 1) ? 42 : 7;   /* 42 = double-spend (the bug); 7 = safe */
}
"#;

/// The realized schedule trace: the ordered slots the shim granted the baton to,
/// read from the runtrace `sched` events.
fn granted_slots(log: &std::path::Path) -> Vec<i64> {
    let text = std::fs::read_to_string(log).unwrap_or_default();
    let mut slots = Vec::new();
    for line in text.lines() {
        if !line.contains("\"e\":\"sched\"") {
            continue;
        }
        // Extract the integer after "slot":
        if let Some(idx) = line.find("\"slot\":") {
            let rest = &line[idx + "\"slot\":".len()..];
            let end = rest
                .find(|c: char| !(c == '-' || c.is_ascii_digit()))
                .unwrap_or(rest.len());
            if let Ok(v) = rest[..end].parse::<i64>() {
                slots.push(v);
            }
        }
    }
    slots
}

/// True iff `pattern` occurs as an in-order subsequence of `slots`.
fn is_subsequence(slots: &[i64], pattern: &[i64]) -> bool {
    let mut it = slots.iter();
    pattern.iter().all(|p| it.any(|s| s == p))
}

#[test]
fn race_found_under_schedule_perturbation_missed_by_plain_execution() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let dir = std::env::temp_dir().join(format!("bhf-sched-vtest-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("race.c");
    std::fs::write(&src, FIXTURE).unwrap();
    let bin = dir.join("race");
    if !compile_pthread(cc, &src, &bin) {
        eprintln!("skipping: pthread fixture failed to compile with {cc}");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }

    // Plain execution, a bounded budget of runs: the specific interleaving is not
    // produced by the host scheduler, so the double-spend is MISSED every time.
    const PLAIN_BUDGET: usize = 20;
    for i in 0..PLAIN_BUDGET {
        let code = run(&bin, &shim, None, None);
        assert_eq!(
            code,
            Some(7),
            "plain execution must NOT find the order-dependent double-spend \
             (run {i}, got {code:?})"
        );
    }

    // Schedule perturbation with a pinned sequence: byte0 even -> grant worker A
    // first (it reads the balance), byte1 odd -> grant worker B next (it withdraws
    // between A's read and A's write). This forces the buggy interleaving.
    let log = dir.join("sched.jsonl");
    let code = run(&bin, &shim, Some("0001"), Some(&log));
    assert_eq!(
        code,
        Some(42),
        "schedule perturbation must FORCE the A-read/B-write/A-write interleaving \
         and find the double-spend (got {code:?})"
    );

    // Assert the SPECIFIC interleaving was reached: the trace must show the baton
    // going to the first worker (slot 1 = A, created first), then the second
    // worker (slot 2 = B), then BACK to the first worker (A resumes past its yield).
    // That return-to-A-after-B is the interleaving the bug requires.
    let slots = granted_slots(&log);
    assert!(
        is_subsequence(&slots, &[1, 2, 1]),
        "realized schedule must interleave A(1) -> B(2) -> A(1); got grants {slots:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pinned_schedule_replay_is_deterministic() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let dir = std::env::temp_dir().join(format!("bhf-sched-replay-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("race.c");
    std::fs::write(&src, FIXTURE).unwrap();
    let bin = dir.join("race");
    if !compile_pthread(cc, &src, &bin) {
        eprintln!("skipping: pthread fixture failed to compile with {cc}");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }

    // The schedule is a function of the input (here the pinned sequence), so the
    // same input under the same mode must reproduce the same interleaving AND the
    // same outcome — the reproducibility HDF-8 deliverable 3 requires.
    let seq = "0001";
    let mut outcomes = Vec::new();
    let mut traces = Vec::new();
    for run_idx in 0..3 {
        let log = dir.join(format!("replay-{run_idx}.jsonl"));
        let code = run(&bin, &shim, Some(seq), Some(&log));
        outcomes.push(code);
        traces.push(granted_slots(&log));
    }
    assert_eq!(
        outcomes,
        vec![Some(42), Some(42), Some(42)],
        "a pinned schedule must reproduce the same (buggy) outcome every run: {outcomes:?}"
    );
    assert_eq!(
        traces[0], traces[1],
        "a pinned schedule must reproduce the same interleaving: {:?} vs {:?}",
        traces[0], traces[1]
    );
    assert_eq!(
        traces[1], traces[2],
        "a pinned schedule must reproduce the same interleaving across all runs"
    );
    assert!(
        !traces[0].is_empty(),
        "the scheduler must have recorded a realized schedule"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// A different pinned schedule that grants worker B FIRST (byte0 odd) runs B to
// completion before A, so A sees the already-debited balance and does not
// double-spend: the outcome flips to safe. This proves the interleaving — and thus
// the bug's reachability — is genuinely controlled by the input, not incidental.
#[test]
fn a_different_pinned_schedule_yields_the_safe_interleaving() {
    let Some(shim) = shim_so() else {
        eprintln!("skipping: shim cdylib not built yet");
        return;
    };
    let Some(cc) = cc() else {
        eprintln!("skipping: no C compiler");
        return;
    };
    let dir = std::env::temp_dir().join(format!("bhf-sched-safe-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("race.c");
    std::fs::write(&src, FIXTURE).unwrap();
    let bin = dir.join("race");
    if !compile_pthread(cc, &src, &bin) {
        eprintln!("skipping: pthread fixture failed to compile with {cc}");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }

    // byte0 odd -> grant B first; B runs to exit before A gets the baton, so A's
    // read sees the debited balance and no double-spend occurs.
    let code = run(&bin, &shim, Some("0100"), None);
    assert_eq!(
        code,
        Some(7),
        "granting B before A must produce the safe (single-withdrawal) interleaving \
         (got {code:?})"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
