// SPDX-License-Identifier: Apache-2.0

//! The bounds the post-fuzz MemorySanitizer, ThreadSanitizer and
//! control-flow-integrity corpus replays share, the log of what each replayed
//! run did, and the sanitizers `bhf auto` runs only as a replay.
//!
//! Each replayed input runs at most `min(--timeout, 30 s)`, and a run that
//! times out is not retried: the input is a hang under that sanitizer, and an
//! input that hung under one is not replayed under the other. A harness's
//! replay stops at its per-target budget (`--per-target-time`). Every run is a
//! line of `auto/sanitizer-replay.jsonl`.

use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

/// A sanitizer `bhf auto --sanitizers` runs only as a corpus replay through a
/// build of its own, never in the fuzzed build (#297): control-flow integrity
/// needs whole-program LTO and hidden visibility, which the fuzzed build does
/// not use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayLane {
    /// `cfi`: `-fsanitize=cfi`, casts to the wrong class and calls through a
    /// function pointer or vtable of the wrong type.
    Cfi,
    /// `realtime`: `-fsanitize=realtime` (clang 20+, #298), allocations, locks
    /// and blocking calls in a target marked nonblocking.
    Realtime,
}

impl ReplayLane {
    /// The lane a `--sanitizers` value names.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "cfi" => Some(ReplayLane::Cfi),
            "realtime" | "rtsan" => Some(ReplayLane::Realtime),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ReplayLane::Cfi => "cfi",
            ReplayLane::Realtime => "realtime",
        }
    }
}

/// `--sanitizers`' values without the replay lanes, and the lanes, each once.
pub fn split_replay_lanes(values: &[String]) -> (Vec<String>, Vec<ReplayLane>) {
    let mut rest = Vec::new();
    let mut lanes = Vec::new();
    for value in values {
        match ReplayLane::parse(value) {
            Some(lane) if !lanes.contains(&lane) => lanes.push(lane),
            Some(_) => {}
            None => rest.push(value.clone()),
        }
    }
    (rest, lanes)
}

/// The longest one replayed input may run, whatever `--timeout` says.
pub(crate) const MAX_RUN_TIMEOUT: Duration = Duration::from_secs(30);

/// The command that replays one input on the sanitizer build `bin`, its
/// symbolizer kept off the network. On stock Ubuntu `DEBUGINFOD_URLS` names a
/// server, and the symbolizer then fetches debug info for every report: that
/// took seconds here and, on a CI runner, longer than the run's timeout, so
/// the report counted as a hang and was no finding. Local symbolization still
/// names the target's frames.
pub(crate) fn replay_command(bin: &Path) -> std::process::Command {
    let mut command = std::process::Command::new(bin);
    command.env("DEBUGINFOD_URLS", "");
    command
}

/// The `llvm-symbolizer` a sanitizer runtime should run: the one on `PATH`,
/// else a versioned one, else one in an LLVM install dir. A runtime built
/// for another LLVM release looks for its own release's symbolizer, which a
/// host with only that release's compiler does not have (Ubuntu's `clang-20`
/// without `llvm-20`): its reports then name no frame. The symbolizer's
/// protocol is the same across releases.
pub(crate) fn llvm_symbolizer() -> Option<PathBuf> {
    if let Ok(path) = which::which("llvm-symbolizer") {
        return Some(path);
    }
    (14..=22).rev().find_map(|major| {
        which::which(format!("llvm-symbolizer-{major}"))
            .ok()
            .or_else(|| {
                let path = PathBuf::from(format!("/usr/lib/llvm-{major}/bin/llvm-symbolizer"));
                path.is_file().then_some(path)
            })
    })
}

/// `options` for a sanitizer runtime with [`llvm_symbolizer`] named, when
/// there is one: `options:external_symbolizer_path=<path>`.
pub(crate) fn with_symbolizer(options: &str) -> String {
    match llvm_symbolizer() {
        Some(path) if options.is_empty() => format!("external_symbolizer_path={}", path.display()),
        Some(path) => format!("{options}:external_symbolizer_path={}", path.display()),
        None => options.to_owned(),
    }
}

/// The file every replayed run is logged to, under the work dir.
pub(crate) const REPLAY_LOG: &str = "auto/sanitizer-replay.jsonl";

/// The per-input run timeout for a replay: `--timeout`, capped at
/// [`MAX_RUN_TIMEOUT`], which is also the default.
pub(crate) fn run_timeout(timeout: Option<Duration>) -> Duration {
    timeout
        .map_or(MAX_RUN_TIMEOUT, |timeout| timeout.min(MAX_RUN_TIMEOUT))
        .max(Duration::from_millis(1))
}

/// What one replayed run did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunOutcome {
    /// It ran to its end: clean, a report, or another exit.
    Completed,
    /// It ran past the run timeout and was killed.
    TimedOut,
    /// It did not start.
    SpawnFailed,
    /// It was not run: the input hung under another sanitizer.
    SkippedKnownHang,
}

impl RunOutcome {
    fn as_str(self) -> &'static str {
        match self {
            RunOutcome::Completed => "completed",
            RunOutcome::TimedOut => "timeout",
            RunOutcome::SpawnFailed => "spawn_failed",
            RunOutcome::SkippedKnownHang => "skipped_known_hang",
        }
    }
}

/// The bounds of one `bhf auto` run's sanitizer replays.
pub struct ReplayBounds {
    pub(crate) run_timeout: Duration,
    /// How long one harness's replay may take, per sanitizer.
    pub(crate) per_harness: Duration,
    /// SHA-256 of each input that timed out under a sanitizer.
    hangs: Mutex<HashSet<[u8; 32]>>,
    log: Option<PathBuf>,
}

impl ReplayBounds {
    /// Bounds for the replays: runs of `min(timeout, 30 s)`, `per_harness` per
    /// harness and sanitizer, logged under `work_dir` when given.
    pub fn new(timeout: Option<Duration>, per_harness: Duration, work_dir: Option<&Path>) -> Self {
        let log = work_dir.map(|dir| dir.join(REPLAY_LOG));
        if let Some(log) = &log {
            let _ = std::fs::remove_file(log);
        }
        Self {
            run_timeout: run_timeout(timeout),
            per_harness,
            hangs: Mutex::new(HashSet::new()),
            log,
        }
    }

    /// Bounds with `run_timeout`, no per-harness budget and no log.
    #[cfg(test)]
    pub(crate) fn unbounded(run_timeout: Duration) -> Self {
        Self {
            run_timeout,
            per_harness: Duration::MAX,
            hangs: Mutex::new(HashSet::new()),
            log: None,
        }
    }

    pub(crate) fn is_known_hang(&self, input: &[u8]) -> bool {
        self.hangs
            .lock()
            .is_ok_and(|hangs| hangs.contains(&digest(input)))
    }

    pub(crate) fn note_hang(&self, input: &[u8]) {
        if let Ok(mut hangs) = self.hangs.lock() {
            hangs.insert(digest(input));
        }
    }

    /// Append one run to the replay log.
    pub(crate) fn log_run(
        &self,
        sanitizer: &str,
        harness_id: &str,
        input: &Path,
        elapsed: Duration,
        outcome: RunOutcome,
    ) {
        let Some(log) = &self.log else {
            return;
        };
        let line = serde_json::json!({
            "sanitizer": sanitizer,
            "harness": harness_id,
            "input": input.file_name().map(|name| name.to_string_lossy()),
            "elapsed_ms": elapsed.as_millis() as u64,
            "timeout_ms": self.run_timeout.as_millis() as u64,
            "outcome": outcome.as_str(),
        });
        if let Some(parent) = log.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)
        {
            let _ = writeln!(file, "{line}");
        }
    }
}

fn digest(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sanitizer_is_told_which_symbolizer_to_run() {
        let options = with_symbolizer("halt_on_error=1");
        match llvm_symbolizer() {
            Some(path) => assert_eq!(
                options,
                format!(
                    "halt_on_error=1:external_symbolizer_path={}",
                    path.display()
                )
            ),
            None => assert_eq!(options, "halt_on_error=1"),
        }
        assert!(!with_symbolizer("").starts_with(':'));
    }

    #[test]
    fn a_replay_does_not_ask_a_debuginfod_server() {
        let command = replay_command(Path::new("/w/main_rtsan"));
        let set: Vec<_> = command.get_envs().collect();
        assert_eq!(
            set,
            [(
                std::ffi::OsStr::new("DEBUGINFOD_URLS"),
                Some(std::ffi::OsStr::new(""))
            )]
        );
    }

    /// #297: `cfi` leaves `--sanitizers` as a replay lane, once, and the rest
    /// stays the fuzzed build's matrix in its order.
    #[test]
    fn the_replay_lanes_are_split_from_the_build_matrix() {
        let values: Vec<String> = ["asan", "CFI", "ubsan", "cfi"].map(String::from).to_vec();
        let (rest, lanes) = split_replay_lanes(&values);
        assert_eq!(rest, ["asan", "ubsan"]);
        assert_eq!(lanes, [ReplayLane::Cfi]);
        assert_eq!(split_replay_lanes(&[]), (Vec::new(), Vec::new()));
    }

    #[test]
    fn the_run_timeout_is_the_timeout_capped_at_30_seconds() {
        assert_eq!(run_timeout(None), Duration::from_secs(30));
        assert_eq!(
            run_timeout(Some(Duration::from_secs(1))),
            Duration::from_secs(1)
        );
        assert_eq!(
            run_timeout(Some(Duration::from_secs(120))),
            Duration::from_secs(30)
        );
        assert_eq!(run_timeout(Some(Duration::ZERO)), Duration::from_millis(1));
    }

    #[test]
    fn an_input_that_hung_once_is_a_known_hang() {
        let bounds = ReplayBounds::unbounded(Duration::from_secs(1));
        assert!(!bounds.is_known_hang(b"spin"));
        bounds.note_hang(b"spin");
        assert!(bounds.is_known_hang(b"spin"));
        assert!(!bounds.is_known_hang(b"other"));
    }

    #[test]
    fn each_run_is_a_line_of_the_replay_log() {
        let dir = crate::test_support::TestDir::new("sanitizer-replay-log");
        let bounds = ReplayBounds::new(
            Some(Duration::from_secs(1)),
            Duration::from_secs(60),
            Some(dir.path()),
        );
        bounds.log_run(
            "tsan",
            "H-1",
            Path::new("queue/id-1"),
            Duration::from_millis(1004),
            RunOutcome::TimedOut,
        );
        let text = std::fs::read_to_string(dir.join(REPLAY_LOG)).unwrap();
        let line: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(line["sanitizer"], "tsan");
        assert_eq!(line["input"], "id-1");
        assert_eq!(line["elapsed_ms"], 1004);
        assert_eq!(line["timeout_ms"], 1000);
        assert_eq!(line["outcome"], "timeout");
        // A new run starts a new log.
        let _again = ReplayBounds::new(None, Duration::from_secs(60), Some(dir.path()));
        assert!(!dir.join(REPLAY_LOG).exists());
    }
}
