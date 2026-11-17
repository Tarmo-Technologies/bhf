// SPDX-License-Identifier: Apache-2.0

//! Fresh-process re-runs of new corpus inputs (#416) run beside the fork-server
//! loop, not in it. A crash only a fresh process sees is still reported, the
//! loop does not wait for the re-runs, and an input reaches the saved corpus
//! queue only once a fresh run has cleared it: what is still unchecked when a
//! pass ends is kept beside the queue and checked first by the next pass. The
//! pass still ends on time, and the re-runs neither share the fork-server's
//! working directory nor judge a response deadline while competing with it.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

mod support;

#[path = "../src/test_support.rs"]
mod test_support;
use test_support::TestDir;

fn temp_dir(name: &str) -> TestDir {
    TestDir::new(&format!("fresh-rerun-{name}"))
}

fn clang_runs() -> bool {
    let present = {
        std::process::Command::new("clang")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    };
    support::require_tool(present, "clang")
}

/// Background re-runs need a second CPU; with one, bhf runs them in the loop.
fn several_cpus() -> bool {
    std::thread::available_parallelism().is_ok_and(|cpus| cpus.get() > 1)
}

/// A sleep the harness takes only in a fresh process, as a target with a
/// heavy startup would on a loaded host. The fork-server runs with
/// `BHF_FRAMED` set and skips it.
fn slow_fresh_start(millis: u32) -> String {
    format!(
        "#include <stdlib.h>\n\
         #ifdef _WIN32\n#include <windows.h>\n#else\n#include <time.h>\n#endif\n\
         __attribute__((constructor)) static void slow_fresh_start(void) {{\n\
             if (getenv(\"BHF_FRAMED\")) return;\n\
         #ifdef _WIN32\n    Sleep({millis});\n#else\n\
             struct timespec t = {{ {secs}, {nanos} }};\n    nanosleep(&t, 0);\n#endif\n\
         }}\n",
        secs = millis / 1000,
        nanos = (millis % 1000) * 1_000_000,
    )
}

/// A heap over-read only a fresh process reaches, as with state a warm
/// process carries: the persistent fork-server never sees it.
const FRESH_ONLY_CRASH: &str = "#include <stdlib.h>\n#include <stddef.h>\n#include <stdint.h>\n\
     static int in_a_fresh_process(void) {\n\
         static int fresh = -1;\n\
         if (fresh < 0) fresh = getenv(\"BHF_FRAMED\") == NULL;\n\
         return fresh;\n\
     }\n\
     __attribute__((noinline)) int read_trailer(const uint8_t *data, size_t len) {\n\
         volatile uint8_t *copy = malloc(len);\n\
         int past = copy[len + 2];\n\
         free((void *)copy);\n\
         return past + data[0];\n\
     }\n";

/// Five seeds that each grow coverage; `READ` crashes, in a fresh process only.
fn five_branch_target(fresh_start_ms: u32) -> String {
    format!(
        "{}{FRESH_ONLY_CRASH}\
         __attribute__((noinline)) static int on_a(const uint8_t *d, size_t n) {{ return d[n - 1] + 1; }}\n\
         __attribute__((noinline)) static int on_b(const uint8_t *d, size_t n) {{ return d[0] * 3 + (int)n; }}\n\
         __attribute__((noinline)) static int on_c(const uint8_t *d, size_t n) {{ return (int)n * 7 - d[0]; }}\n\
         __attribute__((noinline)) static int on_d(const uint8_t *d, size_t n) {{ return d[n - 1] ^ 0x5a; }}\n\
         int bhf_run_one(const uint8_t *data, size_t size) {{\n\
             if (size == 0) return 0;\n\
             if (data[0] == 'A') return on_a(data, size);\n\
             if (data[0] == 'B') return on_b(data, size);\n\
             if (data[0] == 'C') return on_c(data, size);\n\
             if (data[0] == 'D') return on_d(data, size);\n\
             if (size >= 4 && data[0] == 'R' && data[1] == 'E' && in_a_fresh_process())\n\
                 return read_trailer(data, size);\n\
             return 0;\n\
         }}\n",
        slow_fresh_start(fresh_start_ms)
    )
}

const FIVE_SEEDS: [&str; 5] = ["A1", "B2", "C3", "D4", "READ"];

/// Build `target` with bhf's driver into `<work>/harnesses/<id>/main`.
fn build_harness(work: &Path, id: &str, target: &str, sanitize: bool) {
    let dir = work.join("harnesses").join(id);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("target.c"), target).unwrap();
    let driver = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../c_runtime/bhf_driver.c");
    let mut clang = std::process::Command::new("clang");
    clang.current_dir(&dir).args(["-O1", "-g"]);
    if sanitize {
        clang.arg("-fsanitize=address");
    }
    let built = clang
        .args([
            "-fsanitize-coverage=trace-pc-guard,trace-cmp",
            "-o",
            "main",
            "target.c",
        ])
        .arg(&driver)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
}

fn fuzz(work: &Path, id: &str, seeds: &[&Path], extra: &[&str]) -> (i32, serde_json::Value) {
    let mut argv: Vec<String> = ["bhf", "fuzz", work.to_str().unwrap(), "--harness", id]
        .map(str::to_owned)
        .to_vec();
    for seed in seeds {
        argv.push("--seed-file".to_owned());
        argv.push(seed.to_str().unwrap().to_owned());
    }
    argv.extend(extra.iter().map(|arg| (*arg).to_owned()));
    let exit = cli::run_from(argv);
    let summary = fs::read(work.join("fuzz_runs").join(format!("{id}-latest.json")))
        .map(|bytes| serde_json::from_slice(&bytes).unwrap())
        .unwrap_or(serde_json::Value::Null);
    (exit, summary)
}

fn seed(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = root.join(name);
    fs::write(&path, bytes).unwrap();
    path
}

fn seeds(root: &Path, names: &[&str]) -> Vec<PathBuf> {
    names
        .iter()
        .map(|name| seed(root, name, name.as_bytes()))
        .collect()
}

/// The bytes of every file in `dir`.
fn inputs_in(dir: &Path) -> Vec<Vec<u8>> {
    let mut inputs: Vec<Vec<u8>> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| fs::read(entry.path()).ok())
        .collect();
    inputs.sort();
    inputs
}

/// Each finding's record, with its testcase's bytes under `"input"`.
fn findings(work: &Path) -> Vec<serde_json::Value> {
    fs::read_dir(work.join("results/findings"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let bytes = fs::read(entry.path().join("finding.json")).ok()?;
            let mut finding: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
            finding["dir"] = entry.path().display().to_string().into();
            let testcase = fs::read(entry.path().join("testcase.bin")).unwrap_or_default();
            finding["input"] = String::from_utf8_lossy(&testcase).into_owned().into();
            Some(finding)
        })
        .collect()
}

/// A crash only a fresh process sees is reported from the background re-run,
/// with its sanitizer log, and kept out of the persisted corpus, while the
/// fork-server loop keeps fuzzing instead of waiting two seconds for every
/// new corpus input.
#[test]
fn a_fresh_only_crash_is_reported_while_the_loop_keeps_fuzzing() {
    if !clang_runs() || !several_cpus() {
        eprintln!("skipping: needs clang and a second CPU");
        return;
    }
    let root = temp_dir("async-crash");
    let work = root.join("work");
    let target = format!(
        "{}{FRESH_ONLY_CRASH}\
         int bhf_run_one(const uint8_t *data, size_t size) {{\n\
             if (size >= 4 && data[0] == 'R' && data[1] == 'E' && in_a_fresh_process())\n\
                 return read_trailer(data, size);\n\
             return 0;\n\
         }}\n",
        slow_fresh_start(2000)
    );
    build_harness(&work, "H-SLOWFRESH", &target, true);
    let crasher = seed(&root, "seed.bin", b"READ");

    let (exit, summary) = fuzz(
        &work,
        "H-SLOWFRESH",
        &[&crasher],
        &["--fork-server", "--time", "4s"],
    );
    let found = findings(&work);
    let finding = found
        .iter()
        .find(|finding| finding["rule_id"] == "BHF-201")
        .unwrap_or_else(|| panic!("exit {exit}: no heap-buffer-overflow finding: {found:?}"));
    let log = fs::read_to_string(Path::new(finding["dir"].as_str().unwrap()).join("sanitizer.log"))
        .expect("sanitizer.log written");
    assert!(log.contains("read_trailer"), "{log}");
    assert!(
        summary["fresh_reruns"]["reports"].as_u64() >= Some(1),
        "{summary}"
    );

    // The loop did not wait for the re-runs: a synchronous 2 s re-run of each
    // new corpus input leaves a 4 s pass with a handful of executions.
    let executions = summary["executions"].as_u64().unwrap();
    assert!(executions >= 500, "only {executions} executions: {summary}");

    // The crashing seed is a finding, not a coverage seed.
    let queue = inputs_in(&work.join("corpus/H-SLOWFRESH/queue"));
    assert!(!queue.iter().any(|input| input == b"READ"), "{queue:?}");
    let _ = fs::remove_dir_all(&root);
}

/// An input whose fresh re-run has not finished when the pass ends is kept
/// out of the corpus queue: it waits in `corpus/<harness>/unchecked/`, and
/// the next pass re-runs it first, then queues it if it is clean or reports
/// it if it crashes. A crasher is never in the queue, after either pass.
#[test]
fn an_input_reaches_the_queue_only_once_a_fresh_run_clears_it() {
    if !clang_runs() || !several_cpus() {
        eprintln!("skipping: needs clang and a second CPU");
        return;
    }
    let root = temp_dir("unchecked");
    let work = root.join("work");
    // Each fresh run takes 0.7 s: a 2 s pass checks two or three of the five
    // seeds, in order, and READ, the last, is still pending at its end.
    build_harness(&work, "H-UNCHECKED", &five_branch_target(700), true);
    let seeds = seeds(&root, &FIVE_SEEDS);
    let seeds: Vec<&Path> = seeds.iter().map(PathBuf::as_path).collect();
    let queue_dir = work.join("corpus/H-UNCHECKED/queue");
    let unchecked_dir = work.join("corpus/H-UNCHECKED/unchecked");

    let (exit, first) = fuzz(
        &work,
        "H-UNCHECKED",
        &seeds,
        &["--fork-server", "--time", "2s", "--timeout", "2s"],
    );
    assert_eq!(exit, 0, "{first}");
    let reruns = &first["fresh_reruns"];
    let submitted = reruns["submitted"].as_u64().unwrap();
    let checked = reruns["checked"].as_u64().unwrap();
    let unchecked = reruns["unchecked"].as_u64().unwrap();
    assert_eq!(
        checked + unchecked,
        submitted,
        "every input is accounted for: {first}"
    );
    assert!(unchecked >= 1, "{first}");
    let saved_in = PathBuf::from(reruns["unchecked_dir"].as_str().expect("unchecked_dir"));
    let pending = inputs_in(&saved_in);
    assert_eq!(pending.len() as u64, unchecked, "{pending:?}");
    let queued = inputs_in(&queue_dir);
    for input in &pending {
        assert!(
            !queued.contains(input),
            "unchecked {:?} is in the queue: {queued:?}",
            String::from_utf8_lossy(input)
        );
    }
    assert!(pending.contains(&b"READ".to_vec()), "{pending:?}");
    // Beside the queue, which `bhf auto` keeps, not under `fuzz_runs/`,
    // which it clears.
    assert_eq!(saved_in, unchecked_dir, "{first}");

    // The next pass, with time to spare, re-runs the saved inputs first:
    // READ becomes a finding, the clean ones join the queue.
    let (exit, second) = fuzz(
        &work,
        "H-UNCHECKED",
        &[],
        &["--fork-server", "--iterations", "1", "--timeout", "20s"],
    );
    assert_eq!(exit, 0, "{second}");
    let reruns = &second["fresh_reruns"];
    assert!(
        reruns["submitted"].as_u64().unwrap() >= unchecked,
        "{second}"
    );
    assert_eq!(reruns["unchecked"].as_u64(), Some(0), "{second}");
    assert!(
        inputs_in(&unchecked_dir).is_empty(),
        "{unchecked_dir:?} is cleared once its inputs are checked"
    );
    let found = findings(&work);
    assert!(
        found
            .iter()
            .any(|finding| finding["rule_id"] == "BHF-201" && finding["input"] == "READ"),
        "READ is reported once a fresh run checks it: {found:?}"
    );
    let queued = inputs_in(&queue_dir);
    assert!(!queued.contains(&b"READ".to_vec()), "{queued:?}");
    // A mutant of READ that keeps its first two bytes and length crashes in
    // a fresh process too: a later hit of READ's finding, not queued.
    let crashes = |input: &[u8]| input.len() >= 4 && input.starts_with(b"RE");
    for input in pending.iter().filter(|input| !crashes(input)) {
        assert!(
            queued.contains(input),
            "clean {:?} joins the queue once checked: {queued:?}",
            String::from_utf8_lossy(input)
        );
    }
    for input in pending.iter().filter(|input| crashes(input)) {
        assert!(!queued.contains(input), "{queued:?}");
    }
    let _ = fs::remove_dir_all(&root);
}

/// A multi-worker campaign whose fresh re-runs lag still ends inside the
/// workers' kill grace, with every worker finished, and the inputs the
/// workers left unchecked are carried into the campaign's `unchecked/`, not
/// into its queue.
#[test]
fn workers_with_slow_fresh_reruns_finish_and_keep_unchecked_inputs_out_of_the_queue() {
    if !clang_runs() || !several_cpus() {
        eprintln!("skipping: needs clang and a second CPU");
        return;
    }
    let root = temp_dir("workers");
    let work = root.join("work");
    build_harness(&work, "H-WORKERS", &five_branch_target(3000), true);
    let seeds = seeds(&root, &FIVE_SEEDS);

    let started = Instant::now();
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_bhf"));
    command
        .arg("fuzz")
        .arg(&work)
        .args(["--harness", "H-WORKERS", "--engine", "builtin"])
        .args(["--fork-server", "--time", "6s", "--timeout", "10s"])
        .args(["--workers", "2"]);
    for seed in &seeds {
        command.arg("--seed-file").arg(seed);
    }
    let output = command.output().unwrap();
    let wall = started.elapsed();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    let campaign: serde_json::Value = serde_json::from_slice(
        &fs::read(work.join("fuzz_campaigns/H-WORKERS-latest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(campaign["workers_completed"], 2, "{campaign}");
    // The workers are killed 5 s after the campaign's time; a pass that
    // drains its re-runs inside its budget ends well before that.
    assert!(wall.as_secs_f64() < 6.0 + 4.0, "took {wall:?}: {stderr}");

    let queued = inputs_in(&work.join("corpus/H-WORKERS/queue"));
    let pending = inputs_in(&work.join("corpus/H-WORKERS/unchecked"));
    assert!(!queued.contains(&b"READ".to_vec()), "{queued:?}");
    assert!(
        pending.contains(&b"READ".to_vec()),
        "a 3 s fresh start leaves READ unchecked in a 6 s pass: {pending:?}"
    );
    for input in &pending {
        assert!(!queued.contains(input), "{input:?} is in the queue");
    }
    for worker in 0..2 {
        let left = work.join(format!(
            "worker-H-WORKERS-{worker}/corpus/H-WORKERS/unchecked"
        ));
        assert!(inputs_in(&left).is_empty(), "{left:?} was carried over");
    }
    let _ = fs::remove_dir_all(&root);
}

/// The empty input runs in a fresh process once per pass; repeated empty
/// inputs reuse that run instead of each starting a process.
#[cfg(unix)]
#[test]
fn the_empty_input_runs_in_a_fresh_process_once_per_pass() {
    use std::os::unix::fs::PermissionsExt;
    let root = temp_dir("empty-input");
    let work = root.join("work");
    let dir = work.join("harnesses/H-EMPTY");
    fs::create_dir_all(&dir).unwrap();
    let starts = root.join("starts.log");
    let harness = dir.join("main");
    fs::write(
        &harness,
        format!(
            "#!/bin/sh\necho start >> '{}'\ncat > /dev/null\nexit 0\n",
            starts.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&harness, fs::Permissions::from_mode(0o755)).unwrap();

    // Four empty seeds: four executions of the empty input.
    let empty: Vec<PathBuf> = (0..4)
        .map(|n| seed(&root, &format!("empty-{n}"), b""))
        .collect();
    let empty: Vec<&Path> = empty.iter().map(PathBuf::as_path).collect();
    let (exit, summary) = fuzz(
        &work,
        "H-EMPTY",
        &empty,
        &["--no-fork-server", "--iterations", "4"],
    );
    assert_eq!(exit, 0, "{summary}");
    assert_eq!(summary["executions"].as_u64(), Some(4), "{summary}");
    let started = fs::read_to_string(&starts)
        .unwrap_or_default()
        .lines()
        .count();
    assert_eq!(started, 1, "4 empty inputs started {started} processes");
    let _ = fs::remove_dir_all(&root);
}

/// A target that keeps its input in a fixed-name file in its working
/// directory, as some parsers cache what they read, sees only its own file:
/// a background re-run does not share the fork-server's directory, so the
/// two never overwrite each other's file and no false crash is reported.
#[cfg(unix)]
#[test]
fn reruns_do_not_share_the_fork_servers_working_directory() {
    if !clang_runs() || !several_cpus() {
        eprintln!("skipping: needs clang and a second CPU");
        return;
    }
    let root = temp_dir("cwd");
    let work = root.join("work");
    // A fresh process holds its file for 50 ms, the fork-server for 2 ms per
    // input: in a shared directory the fork-server's inputs overwrite it, and
    // the fresh process reads back bytes it did not write.
    let target = "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\
         #include <stddef.h>\n#include <stdint.h>\n#include <unistd.h>\n\
         int bhf_run_one(const uint8_t *d, size_t n) {\n\
             if (n == 0 || n > 64) return 0;\n\
             FILE *f = fopen(\"cache.bin\", \"wb\");\n\
             if (!f) return 0;\n\
             fwrite(d, 1, n, f);\n\
             fclose(f);\n\
             usleep(getenv(\"BHF_FRAMED\") ? 2000 : 50000);\n\
             unsigned char back[64];\n\
             size_t got = 0;\n\
             f = fopen(\"cache.bin\", \"rb\");\n\
             if (f) { got = fread(back, 1, sizeof back, f); fclose(f); }\n\
             int r = 0;\n\
             if (d[0] == 'A') r += 1;\n\
             if (n > 1 && d[1] == 'B') r += 2;\n\
             if (n > 2 && d[2] == 'C') r += 4;\n\
             if (n > 3 && d[3] == 'D') r += 8;\n\
             if (!getenv(\"BHF_FRAMED\") && (got != n || memcmp(back, d, n) != 0)) {\n\
                 volatile char *p = malloc(4);\n\
                 p[4] = 1;\n\
                 free((void *)p);\n\
             }\n\
             return r;\n\
         }\n";
    build_harness(&work, "H-CWD", target, true);
    let seeds = seeds(&root, &["A", "AB", "ABC", "ABCD"]);
    let seeds: Vec<&Path> = seeds.iter().map(PathBuf::as_path).collect();

    let (exit, summary) = fuzz(&work, "H-CWD", &seeds, &["--fork-server", "--time", "4s"]);
    assert_eq!(exit, 0, "{summary}");
    assert!(
        summary["fresh_reruns"]["checked"].as_u64() >= Some(1),
        "{summary}"
    );
    let found = findings(&work);
    assert!(found.is_empty(), "false findings: {found:?}");
    let _ = fs::remove_dir_all(&root);
}

/// Linux: runs pinned to one core with `taskset`.
#[cfg(target_os = "linux")]
mod one_core {
    use super::*;
    use std::process::{Child, Command, Stdio};

    fn taskset_runs() -> bool {
        let present = {
            Command::new("taskset")
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success())
        };
        crate::support::require_tool(present, "taskset")
    }

    /// Busy and idle jiffies of each allowed CPU, from `/proc/stat`.
    fn cpu_times() -> Vec<(u32, u64, u64)> {
        let stat = fs::read_to_string("/proc/stat").unwrap_or_default();
        stat.lines()
            .filter_map(|line| {
                let rest = line.strip_prefix("cpu")?;
                let mut fields = rest.split_whitespace();
                let cpu: u32 = fields.next()?.parse().ok()?;
                let values: Vec<u64> = fields.filter_map(|v| v.parse().ok()).collect();
                let idle = values.get(3)? + values.get(4).unwrap_or(&0);
                let total: u64 = values.iter().take(8).sum();
                Some((cpu, total - idle, idle))
            })
            .collect()
    }

    /// The allowed CPU that was idlest over a short sample, so other load
    /// on the machine does not skew a timing measured on one core.
    fn idlest_cpu() -> u32 {
        let allowed = fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
                    .map(str::to_owned)
            })
            .unwrap_or_default();
        let mut cpus = Vec::new();
        for range in allowed.trim().split(',') {
            let mut ends = range
                .split('-')
                .filter_map(|end| end.trim().parse::<u32>().ok());
            if let Some(first) = ends.next() {
                cpus.extend(first..=ends.next().unwrap_or(first));
            }
        }
        let before = cpu_times();
        std::thread::sleep(std::time::Duration::from_millis(300));
        let after = cpu_times();
        cpus.into_iter()
            .min_by_key(|cpu| {
                let busy = |times: &[(u32, u64, u64)]| {
                    times
                        .iter()
                        .find(|(id, _, _)| id == cpu)
                        .map_or(u64::MAX / 2, |(_, busy, _)| *busy)
                };
                busy(&after).saturating_sub(busy(&before))
            })
            .unwrap_or(0)
    }

    /// A busy loop pinned to `cpu`, killed on drop.
    struct BusyLoop(Child);

    impl BusyLoop {
        fn start(cpu: u32) -> Self {
            Self(
                Command::new("taskset")
                    .args(["-c", &cpu.to_string(), "sh", "-c", "while :; do :; done"])
                    .spawn()
                    .unwrap(),
            )
        }
    }

    impl Drop for BusyLoop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn pinned_fuzz(cpu: u32, work: &Path, id: &str, seeds: &[PathBuf], extra: &[&str]) -> Output {
        let mut command = Command::new("taskset");
        command
            .args(["-c", &cpu.to_string()])
            .arg(env!("CARGO_BIN_EXE_bhf"))
            .arg("fuzz")
            .arg(work)
            .args(["--harness", id, "--engine", "builtin"]);
        for seed in seeds {
            command.arg("--seed-file").arg(seed);
        }
        let started = Instant::now();
        let output = command.args(extra).output().unwrap();
        Output {
            wall: started.elapsed().as_secs_f64(),
            exit: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            summary: serde_json::from_slice(&output.stdout).unwrap_or_default(),
        }
    }

    struct Output {
        wall: f64,
        exit: Option<i32>,
        stderr: String,
        summary: serde_json::Value,
    }

    /// On one core next to a busy loop, a pass whose fresh re-runs take
    /// longer than the time left still ends within `--time` plus a small
    /// constant, and what it could not check stays out of the queue.
    #[test]
    fn a_contended_pass_with_slow_fresh_reruns_ends_on_time() {
        if !clang_runs() || !taskset_runs() {
            eprintln!("skipping: needs clang and taskset");
            return;
        }
        let root = temp_dir("on-time");
        let work = root.join("work");
        build_harness(&work, "H-ONTIME", &five_branch_target(3000), true);
        let seeds = seeds(&root, &FIVE_SEEDS);
        let cpu = idlest_cpu();
        let run = {
            let _busy = BusyLoop::start(cpu);
            pinned_fuzz(
                cpu,
                &work,
                "H-ONTIME",
                &seeds,
                &["--fork-server", "--time", "4s", "--timeout", "10s"],
            )
        };
        assert_eq!(run.exit, Some(0), "{}", run.stderr);
        assert!(
            run.wall < 4.0 + 3.0,
            "a 4 s pass took {:.1} s: {}",
            run.wall,
            run.summary
        );
        let queued = inputs_in(&work.join("corpus/H-ONTIME/queue"));
        assert!(!queued.contains(&b"READ".to_vec()), "{queued:?}");
        for input in inputs_in(&work.join("corpus/H-ONTIME/unchecked")) {
            assert!(!queued.contains(&input), "{input:?} is in the queue");
        }
        let _ = fs::remove_dir_all(&root);
    }

    /// On one loaded core, where few fresh re-runs finish, an input whose
    /// re-run has not come back stays out of the queue. The next pass, still
    /// loaded, re-runs those inputs before any of its own, so it settles every
    /// one of them: the clean ones join the queue and the crasher is reported.
    #[test]
    fn on_a_loaded_core_unchecked_inputs_stay_out_of_the_queue_and_go_first() {
        if !clang_runs() || !taskset_runs() {
            eprintln!("skipping: needs clang and taskset");
            return;
        }
        let root = temp_dir("loaded");
        let work = root.join("work");
        // A 1.5 s fresh start: a 3 s pass checks about one of the five seeds.
        build_harness(&work, "H-LOADED", &five_branch_target(1500), true);
        let seeds = seeds(&root, &FIVE_SEEDS);
        let queue_dir = work.join("corpus/H-LOADED/queue");
        let unchecked_dir = work.join("corpus/H-LOADED/unchecked");
        let cpu = idlest_cpu();
        let loaded_pass = |seeds: &[PathBuf], time: &str| {
            let _busy = [BusyLoop::start(cpu), BusyLoop::start(cpu)];
            pinned_fuzz(
                cpu,
                &work,
                "H-LOADED",
                seeds,
                &["--fork-server", "--time", time, "--timeout", "10s"],
            )
        };

        let first = loaded_pass(&seeds, "3s");
        assert_eq!(first.exit, Some(0), "{}", first.stderr);
        let unchecked = first.summary["fresh_reruns"]["unchecked"]
            .as_u64()
            .unwrap_or(0);
        assert!(
            unchecked >= 3,
            "few re-runs finish on a loaded core: {}",
            first.summary
        );
        let pending = inputs_in(&unchecked_dir);
        assert_eq!(pending.len() as u64, unchecked, "{pending:?}");
        assert!(pending.contains(&b"READ".to_vec()), "{pending:?}");
        let queued = inputs_in(&queue_dir);
        for input in &pending {
            assert!(
                !queued.contains(input),
                "unchecked {:?} is in the queue: {queued:?}",
                String::from_utf8_lossy(input)
            );
        }

        // Each re-run sleeps 1.5 s before it runs on the loaded core: give
        // the pass the time to finish those it submits first, however many a
        // slower machine left.
        let second = loaded_pass(&[], &format!("{}s", 15.max(4 * unchecked)));
        assert_eq!(second.exit, Some(0), "{}", second.stderr);
        assert!(
            second.summary["fresh_reruns"]["submitted"].as_u64() >= Some(unchecked),
            "{}",
            second.summary
        );
        let still = inputs_in(&unchecked_dir);
        for input in &pending {
            assert!(
                !still.contains(input),
                "{:?}, left by the first pass, was not settled first: {still:?}",
                String::from_utf8_lossy(input)
            );
        }
        let found = findings(&work);
        assert!(
            found
                .iter()
                .any(|finding| finding["rule_id"] == "BHF-201" && finding["input"] == "READ"),
            "READ is reported by the next pass: {found:?}"
        );
        let queued = inputs_in(&queue_dir);
        assert!(!queued.contains(&b"READ".to_vec()), "{queued:?}");
        // A mutant of READ that keeps its first two bytes and length crashes
        // in a fresh process too: a later hit of READ's finding, not queued.
        let crashes = |input: &[u8]| input.len() >= 4 && input.starts_with(b"RE");
        for input in pending.iter().filter(|input| !crashes(input)) {
            assert!(
                queued.contains(input),
                "clean {:?} joins the queue once checked: {queued:?}",
                String::from_utf8_lossy(input)
            );
        }
        for input in pending.iter().filter(|input| crashes(input)) {
            assert!(!queued.contains(input), "{queued:?}");
        }
        for input in &still {
            assert!(!queued.contains(input), "{input:?} is in the queue");
        }
        let _ = fs::remove_dir_all(&root);
    }

    /// With `--deadline` on one core, a fresh process that answers inside the
    /// deadline when it has the core is not reported as too slow: on a
    /// single CPU the re-run does not compete with the fork-server loop.
    ///
    /// The deadline leaves the 600 ms fresh run room for a shared core (CI
    /// runs other tests on it). Which CPUs get inline re-runs is pinned
    /// exactly by `fresh_reruns_run_inline_only_on_one_cpu_with_a_response_deadline`.
    #[test]
    fn a_response_deadline_on_one_core_is_not_missed_because_of_the_loop() {
        if !clang_runs() || !taskset_runs() {
            eprintln!("skipping: needs clang and taskset");
            return;
        }
        let root = temp_dir("deadline");
        let work = root.join("work");
        // A fresh process does 600 ms of CPU work; each input 20 ms.
        let target =
            "#include <stdlib.h>\n#include <stddef.h>\n#include <stdint.h>\n#include <time.h>\n\
             static double cpu_ms(void) {\n\
                 struct timespec n;\n\
                 clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &n);\n\
                 return n.tv_sec * 1e3 + n.tv_nsec / 1e6;\n\
             }\n\
             static void spin(double ms) {\n\
                 volatile unsigned long s = 0;\n\
                 double end = cpu_ms() + ms;\n\
                 while (cpu_ms() < end) s++;\n\
             }\n\
             __attribute__((constructor)) static void fresh_work(void) {\n\
                 if (!getenv(\"BHF_FRAMED\")) spin(600);\n\
             }\n\
             int bhf_run_one(const uint8_t *d, size_t n) {\n\
                 spin(20);\n\
                 if (n == 0) return 0;\n\
                 switch (d[0]) { case 'A': return 1; case 'B': return 2; case 'C': return 3;\n\
                                 case 'D': return 4; case 'E': return 5; case 'F': return 6; }\n\
                 return 0;\n\
             }\n";
        build_harness(&work, "H-DEADLINE", target, false);
        let seeds = seeds(&root, &["A", "B", "C", "D", "E", "F"]);
        let run = pinned_fuzz(
            idlest_cpu(),
            &work,
            "H-DEADLINE",
            &seeds,
            &["--fork-server", "--time", "8s", "--deadline", "2s"],
        );
        assert_eq!(run.exit, Some(0), "{}", run.stderr);
        assert!(
            !run.stderr.contains("exceeded the response deadline"),
            "{}",
            run.stderr
        );
        let found = findings(&work);
        assert!(
            !found.iter().any(|finding| finding["rule_id"] == "BHF-555"),
            "false deadline findings: {found:?}"
        );
        let _ = fs::remove_dir_all(&root);
    }
}

/// A background re-run starts its process at a lower priority, so on a busy
/// machine it can take longer than a response deadline although the input
/// answers in time. Such a deadline report is confirmed with a re-run at the
/// loop's own priority before it becomes a finding. The target here is slow
/// only when started at a lower priority, as a starved process would be.
#[cfg(target_os = "linux")]
#[test]
fn a_deadline_report_from_a_low_priority_rerun_is_confirmed_first() {
    if !clang_runs() || !several_cpus() {
        eprintln!("skipping: needs clang and a second CPU");
        return;
    }
    // SAFETY: getpriority reads this process's nice value.
    let nice = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };
    if nice > 9 {
        eprintln!("skipping: already running at nice {nice}");
        return;
    }
    let root = temp_dir("low-priority");
    let work = root.join("work");
    let target = format!(
        "#include <stdlib.h>\n#include <stddef.h>\n#include <stdint.h>\n#include <time.h>\n\
         #include <sys/resource.h>\n\
         __attribute__((constructor)) static void starved_when_lowered(void) {{\n\
             if (getenv(\"BHF_FRAMED\")) return;\n\
             if (getpriority(PRIO_PROCESS, 0) >= {lowered}) {{\n\
                 struct timespec t = {{ 1, 500000000 }};\n\
                 nanosleep(&t, 0);\n\
             }}\n\
         }}\n\
         int bhf_run_one(const uint8_t *d, size_t n) {{\n\
             if (n == 0) return 0;\n\
             switch (d[0]) {{ case 'A': return 1; case 'B': return 2; case 'C': return 3; }}\n\
             return 0;\n\
         }}\n",
        lowered = nice + 10
    );
    build_harness(&work, "H-LOWERED", &target, false);
    let seeds = seeds(&root, &["A", "B", "C"]);
    let seeds: Vec<&Path> = seeds.iter().map(PathBuf::as_path).collect();
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_bhf"));
    command
        .arg("fuzz")
        .arg(&work)
        .args(["--harness", "H-LOWERED", "--engine", "builtin"])
        .args(["--fork-server", "--time", "8s", "--deadline", "1s"]);
    for seed in &seeds {
        command.arg("--seed-file").arg(seed);
    }
    let output = command.output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stderr}");
    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(work.join("fuzz_runs/H-LOWERED-latest.json")).unwrap())
            .unwrap();
    assert!(
        summary["fresh_reruns"]["checked"].as_u64() >= Some(1),
        "{summary}"
    );
    let found = findings(&work);
    assert!(
        !found.iter().any(|finding| finding["rule_id"] == "BHF-555"),
        "false deadline findings: {found:?}"
    );
    // Every lowered re-run overran the deadline and was cleared by its
    // re-check: stderr says so, and never announces a finding that is not
    // recorded.
    assert!(
        !stderr.contains("recording BHF-555 finding"),
        "stderr announces a deadline finding that was not recorded:\n{stderr}"
    );
    assert!(
        stderr.contains("met it when re-run at normal priority"),
        "stderr does not say the re-check cleared the overrun:\n{stderr}"
    );
    let _ = fs::remove_dir_all(&root);
}
