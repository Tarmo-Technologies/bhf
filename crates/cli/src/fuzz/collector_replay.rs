// SPDX-License-Identifier: Apache-2.0

//! Launching a `bhf fuzz` harness on one retained input for the collector
//! (#246): under a sidecar observer, which watches the launched process, or
//! under the Linux runtrace shim, which records what that one run did. The
//! harness runs the way `bhf replay` runs it: the input file as its argument
//! for bhf's and libFuzzer-style drivers, on stdin for AFL++ and Ada.

use crate::collector_run::LaunchedReplay;
use crate::runner::HarnessEngine;
use anyhow::{anyhow, Context};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// What the collector needs to run the harness of a `bhf fuzz` campaign.
pub(crate) struct CollectorHarness {
    runner: replay_min::HarnessRunner,
    engine: HarnessEngine,
    /// The campaign's environment for re-runs, without the campaign's own
    /// runtrace log (each replay records to its own).
    env: Vec<(String, String)>,
    /// How long one replay may run.
    timeout: Duration,
    tmp_dir: PathBuf,
}

impl CollectorHarness {
    pub(crate) fn new(
        runner: replay_min::HarnessRunner,
        work_dir: &Path,
        env: &[(String, String)],
        per_input_timeout: Duration,
    ) -> Self {
        let engine = crate::runner::detect_harness_engine_in(runner.harness_path(), &[work_dir]);
        let env = env
            .iter()
            .filter(|(key, _)| key != "BHF_RUNTRACE_LOG" && key != "LD_PRELOAD")
            .cloned()
            .collect();
        Self {
            runner,
            engine,
            env,
            timeout: per_input_timeout.max(Duration::from_secs(1)) + Duration::from_secs(5),
            tmp_dir: work_dir.join("fuzz_scratch").join("collector_replay"),
        }
    }

    /// The command that runs the harness on `input` (written beside the
    /// replay's other files as `<name>.bin`), and the bytes to write to its
    /// stdin, if it reads one.
    fn command(&self, name: &str, input: &[u8]) -> anyhow::Result<(Command, Option<Vec<u8>>)> {
        std::fs::create_dir_all(&self.tmp_dir)
            .with_context(|| format!("create {}", self.tmp_dir.display()))?;
        let file = self.tmp_dir.join(format!("{}.bin", file_stem(name)));
        std::fs::write(&file, input).with_context(|| format!("write {}", file.display()))?;
        let mut command = self
            .runner
            .command_wrapped(&file)
            .map_err(|error| anyhow!("{error}"))?;
        command
            .envs(self.env.iter().map(|(key, value)| (key, value)))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let stdin = match self.engine {
            HarnessEngine::CLibFuzzer => {
                command.arg(&file).stdin(Stdio::null());
                None
            }
            HarnessEngine::CAfl => {
                command.stdin(Stdio::piped());
                Some(input.to_vec())
            }
            HarnessEngine::AdaStdin => {
                let events = self.tmp_dir.join(format!("{}.events", file_stem(name)));
                command.env("BHF_EVENTS_PATH", events).stdin(Stdio::piped());
                Some(input.to_vec())
            }
        };
        Ok((command, stdin))
    }

    /// Start the harness on `input` and return at once, for a sidecar that
    /// observes it: stdin is written on a thread, so a harness that does not
    /// read it cannot hold up the observer's bounded wait.
    pub(crate) fn launch(&self, name: &str, input: &[u8]) -> anyhow::Result<LaunchedReplay> {
        let (mut command, stdin) = self.command(name, input)?;
        let mut child = command.spawn().with_context(|| {
            format!("start the harness {}", self.runner.harness_path().display())
        })?;
        let delivery = match (stdin, child.stdin.take()) {
            (Some(bytes), Some(mut pipe)) => {
                Some(std::thread::spawn(move || pipe.write_all(&bytes)))
            }
            _ => None,
        };
        Ok(LaunchedReplay { child, delivery })
    }

    /// Run the harness on `input` under the runtrace `shim` to its end (killed
    /// after the replay timeout) and return the events it recorded.
    pub(crate) fn run_under_shim(
        &self,
        shim: &crate::runtime_oracles::RuntimeOracles,
        name: &str,
        input: &[u8],
    ) -> anyhow::Result<Vec<crate::auto::runtrace::RuntraceEvent>> {
        let (mut command, stdin) = self.command(name, input)?;
        let log = self
            .tmp_dir
            .join(format!("{}.runtrace.jsonl", file_stem(name)));
        let _ = std::fs::remove_file(&log);
        shim.apply(&mut command, &log);
        let mut child = command.spawn().with_context(|| {
            format!("start the harness {}", self.runner.harness_path().display())
        })?;
        let delivery = match (stdin, child.stdin.take()) {
            (Some(bytes), Some(mut pipe)) => {
                Some(std::thread::spawn(move || pipe.write_all(&bytes)))
            }
            _ => None,
        };
        let _ = crate::collector_run::wait_child_until(&mut child, Instant::now() + self.timeout);
        if let Some(delivery) = delivery {
            let _ = delivery.join();
        }
        let mut events = crate::auto::runtrace::parse_log(&log).unwrap_or_default();
        crate::auto::runtrace::dedupe_in_place(&mut events);
        Ok(events)
    }
}

/// `name` as a file name: a finding id or `corpus-<sha>` already is one.
fn file_stem(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A harness script that writes how it got its input to `out`.
    fn script(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("main");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn an_argv_harness_gets_the_input_file_and_a_stdin_harness_its_bytes() {
        let dir = crate::test_support::TestDir::new("collector-harness");
        let out = dir.join("out");
        // The driver marker makes it a bhf framed driver, which takes a file.
        let argv = script(
            &dir,
            &format!("# BHF_FRAMED\ncat \"$1\" > {}", out.display()),
        );
        let harness = CollectorHarness::new(
            replay_min::HarnessRunner::direct(&argv),
            &dir,
            &[],
            Duration::from_secs(1),
        );
        assert_eq!(harness.engine, HarnessEngine::CLibFuzzer);
        let mut launched = harness.launch("F-0001", b"by file").unwrap();
        launched.child.wait().unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"by file");

        let mut stdin = CollectorHarness::new(
            replay_min::HarnessRunner::direct(&argv),
            &dir,
            &[],
            Duration::from_secs(1),
        );
        stdin.engine = HarnessEngine::CAfl;
        std::fs::write(&argv, format!("#!/bin/sh\ncat > {}\n", out.display())).unwrap();
        let mut launched = stdin.launch("corpus-ab", b"by stdin").unwrap();
        launched.child.wait().unwrap();
        launched.delivery.unwrap().join().unwrap().unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"by stdin");
    }

    #[test]
    fn the_campaign_runtrace_log_is_not_passed_to_a_replay() {
        let dir = crate::test_support::TestDir::new("collector-harness-env");
        let harness = CollectorHarness::new(
            replay_min::HarnessRunner::direct(dir.join("main")),
            &dir,
            &[
                ("BHF_RUNTRACE_LOG".to_owned(), "/campaign.jsonl".to_owned()),
                ("ASAN_OPTIONS".to_owned(), "detect_leaks=0".to_owned()),
            ],
            Duration::from_millis(10),
        );
        assert_eq!(
            harness.env,
            [("ASAN_OPTIONS".to_owned(), "detect_leaks=0".to_owned())]
        );
        assert_eq!(file_stem("corpus-a/b:c"), "corpus-a_b_c");
    }
}
