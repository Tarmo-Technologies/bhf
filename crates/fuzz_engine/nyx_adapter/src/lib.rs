// SPDX-License-Identifier: Apache-2.0

//! Nyx / what-the-fuzz snapshot-fuzzing adapter — **scaffolding, superseded**.
//!
//! **Status (HDF-4 / roadmap CC-2).** This crate is early scaffolding whose
//! full-system snapshot role has been taken over by
//! [`target_transport::fullsystem::FullSystemTransport`], the real
//! `qemu-system-*` snapshot/reset backend (QMP `savevm`/`loadvm` + a gdbstub for
//! input delivery and coverage-ring readback). Nothing in the tree consumes this
//! adapter, and it does not implement the [`target_transport::TargetTransport`]
//! seam. It is retained only so dependents can probe the `nyx-engine` feature
//! flag at build time; new full-system work belongs in `FullSystemTransport`.
//!
//! It exposes two backends, neither of which is production coverage:
//!
//! - **Software replay** (default): the `snapshot_dir` contains a `target`
//!   binary spawned once per input, mimicking the one-shot semantics of a
//!   snapshot restore. It collects **no coverage** (`coverage_edges` is always
//!   empty) — it is a process-lifecycle stand-in, not a coverage-guided backend,
//!   and is strictly weaker than `target_transport::host::HostChildTransport`.
//!   No coverage is fabricated here.
//! - **Real Nyx** (`nyx-engine` feature): libnyx FFI + QEMU snapshot restore.
//!   Not implemented; the feature-gated path returns
//!   [`NyxError::NotImplemented`], whose message names
//!   `FullSystemTransport` (HDF-4) as the supported replacement.
//!
//! Architecture note: snapshot fuzzing (Nyx, kAFL, what-the-fuzz) is the
//! production form of state virtualization — see the sibling `bhf_runtrace_shim`
//! crate for the dependency-faking variant BHF ships today, and
//! `FullSystemTransport` for the process/machine-state variant. This adapter
//! predates both and is kept only as a probe point.

use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NyxAdapterConfig {
    /// Path to the Nyx snapshot directory produced by
    /// `libnyx` setup (containing `state.qcow2`, `regs.ymm`, etc.).
    pub snapshot_dir: PathBuf,
    /// Coverage strategy. `IntelPt` requires hardware support;
    /// `SanCov` requires the target to be compiled with
    /// `-fsanitize-coverage=trace-pc-guard`.
    pub coverage: CoverageStrategy,
    /// Maximum per-input wall-clock budget.
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageStrategy {
    IntelPt,
    SanCov,
}

#[derive(Debug, thiserror::Error)]
pub enum NyxError {
    #[error(
        "Nyx real-backend snapshot fuzzing is not implemented; this adapter is scaffolding \
         superseded by target_transport::fullsystem::FullSystemTransport (roadmap HDF-4), the \
         qemu-system snapshot/reset backend — use it for full-system snapshot fuzzing"
    )]
    NotImplemented,
    #[error("snapshot dir does not exist: {0}")]
    SnapshotMissing(PathBuf),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Open a Nyx snapshot and drive the provided input through it.
/// Returns the standard `EngineFeedback` the builtin engine
/// consumes via `fuzz_engine_builtin::EngineFeedbackTranslator`.
///
/// Software-replay backend: spawn `<snapshot_dir>/target` with
/// the input file path as argv[1]. Used when `nyx-engine` isn't
/// enabled (the default). The exit kind maps process exit status
/// onto Nyx's ExitKind. Coverage edges are empty in software mode
/// — real coverage requires libnyx's Intel-PT decoder.
pub fn run_snapshot_once(config: &NyxAdapterConfig, input: &[u8]) -> Result<RunOutcome, NyxError> {
    if !config.snapshot_dir.is_dir() {
        return Err(NyxError::SnapshotMissing(config.snapshot_dir.clone()));
    }
    #[cfg(feature = "nyx-engine")]
    {
        let _ = input;
        Err(NyxError::NotImplemented)
    }
    #[cfg(not(feature = "nyx-engine"))]
    {
        run_software_replay(config, input)
    }
}

#[cfg(not(feature = "nyx-engine"))]
fn run_software_replay(config: &NyxAdapterConfig, input: &[u8]) -> Result<RunOutcome, NyxError> {
    let target = config.snapshot_dir.join("target");
    if !target.is_file() {
        return Err(NyxError::SnapshotMissing(target));
    }
    use std::io::{Read, Seek, SeekFrom, Write};
    let mut input_file = tempfile::NamedTempFile::new_in(&config.snapshot_dir)?;
    input_file.write_all(input)?;
    let mut captured_stdout = tempfile::tempfile()?;
    let child_stdout = captured_stdout.try_clone()?;

    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let mut child = Command::new(&target)
        .arg(input_file.path())
        .stdin(Stdio::null())
        .stdout(Stdio::from(child_stdout))
        .stderr(Stdio::null())
        .spawn()?;
    let timeout = Duration::from_millis(config.timeout_ms);
    let start = Instant::now();
    let mut timed_out = false;
    loop {
        match child.try_wait()? {
            Some(_) => break,
            None => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    timed_out = true;
                    let _ = child.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
    captured_stdout.seek(SeekFrom::Start(0))?;
    let mut stdout = Vec::new();
    captured_stdout.take(1024 * 1024).read_to_end(&mut stdout)?;
    let exit_kind = if timed_out {
        ExitKind::Timeout
    } else {
        let status = child.wait()?;
        if status.success() {
            ExitKind::Ok
        } else {
            ExitKind::Crash
        }
    };
    Ok(RunOutcome {
        exit_kind,
        coverage_edges: Vec::new(),
        stdout,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutcome {
    pub exit_kind: ExitKind,
    pub coverage_edges: Vec<u32>,
    pub stdout: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitKind {
    Ok,
    Crash,
    Timeout,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tempdir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("bhf-nyx-{name}-{nonce}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(not(feature = "nyx-engine"))]
    #[test]
    fn run_snapshot_once_returns_snapshot_missing_when_target_absent() {
        let dir = tempdir("no-target");
        let config = NyxAdapterConfig {
            snapshot_dir: dir,
            coverage: CoverageStrategy::SanCov,
            timeout_ms: 1000,
        };
        let result = run_snapshot_once(&config, b"input");
        assert!(matches!(result, Err(NyxError::SnapshotMissing(_))));
    }

    #[cfg(all(unix, not(feature = "nyx-engine")))]
    #[test]
    fn run_snapshot_once_software_replay_against_bin_true() {
        use std::os::unix::fs::symlink;
        let dir = tempdir("sw-true");
        symlink("/bin/true", dir.join("target")).unwrap();
        let config = NyxAdapterConfig {
            snapshot_dir: dir,
            coverage: CoverageStrategy::SanCov,
            timeout_ms: 5000,
        };
        let outcome = run_snapshot_once(&config, b"hello").unwrap();
        assert_eq!(outcome.exit_kind, ExitKind::Ok);
    }

    #[cfg(all(unix, not(feature = "nyx-engine")))]
    #[test]
    fn run_snapshot_once_software_replay_against_bin_false() {
        use std::os::unix::fs::symlink;
        let dir = tempdir("sw-false");
        symlink("/bin/false", dir.join("target")).unwrap();
        let config = NyxAdapterConfig {
            snapshot_dir: dir,
            coverage: CoverageStrategy::SanCov,
            timeout_ms: 5000,
        };
        let outcome = run_snapshot_once(&config, b"hello").unwrap();
        assert_eq!(outcome.exit_kind, ExitKind::Crash);
    }

    #[cfg(all(unix, not(feature = "nyx-engine")))]
    #[test]
    fn software_replay_drains_large_stdout_before_waiting() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir("large-stdout");
        let target = dir.join("target");
        std::fs::write(&target, "#!/bin/sh\nhead -c 2097152 /dev/zero\n").unwrap();
        let mut permissions = std::fs::metadata(&target).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&target, permissions).unwrap();
        let config = NyxAdapterConfig {
            snapshot_dir: dir.clone(),
            coverage: CoverageStrategy::SanCov,
            timeout_ms: 5000,
        };
        let outcome = run_snapshot_once(&config, b"hello").unwrap();
        assert_eq!(outcome.exit_kind, ExitKind::Ok);
        assert_eq!(outcome.stdout.len(), 1024 * 1024);
        assert_eq!(std::fs::read_dir(dir).unwrap().count(), 1);
    }

    #[test]
    fn run_snapshot_once_rejects_missing_snapshot_dir() {
        let config = NyxAdapterConfig {
            snapshot_dir: PathBuf::from("/nonexistent/snapshot/path"),
            coverage: CoverageStrategy::IntelPt,
            timeout_ms: 1000,
        };
        let result = run_snapshot_once(&config, b"input");
        assert!(matches!(result, Err(NyxError::SnapshotMissing(_))));
    }

    #[cfg(feature = "nyx-engine")]
    #[test]
    fn enabled_but_unimplemented_engine_returns_error_instead_of_panicking() {
        let dir = tempdir("feature-not-implemented");
        let config = NyxAdapterConfig {
            snapshot_dir: dir,
            coverage: CoverageStrategy::IntelPt,
            timeout_ms: 1000,
        };
        assert!(matches!(
            run_snapshot_once(&config, b"input"),
            Err(NyxError::NotImplemented)
        ));
    }

    #[test]
    fn coverage_strategy_is_copy_and_eq() {
        let a = CoverageStrategy::IntelPt;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn not_implemented_error_names_the_full_system_replacement() {
        // CC-2 / HDF-4 disposition: this adapter is retired in favor of the real
        // qemu-system snapshot backend, and its unimplemented error must send
        // callers there rather than promise a Nyx backend that is not coming.
        let message = NyxError::NotImplemented.to_string();
        assert!(
            message.contains("FullSystemTransport"),
            "error must name the replacement transport: {message}"
        );
        assert!(
            message.contains("HDF-4"),
            "error must name the tracking track: {message}"
        );
    }

    #[test]
    fn software_replay_documents_zero_coverage_and_never_fabricates_edges() {
        // The software-replay backend is a lifecycle stand-in, not coverage
        // guided: a successful run must report an empty edge set, never a faked
        // one. (Gated by unix + no nyx-engine, matching the replay path.)
        #[cfg(all(unix, not(feature = "nyx-engine")))]
        {
            use std::os::unix::fs::symlink;
            let dir = tempdir("zero-cov");
            symlink("/bin/true", dir.join("target")).unwrap();
            let config = NyxAdapterConfig {
                snapshot_dir: dir,
                coverage: CoverageStrategy::SanCov,
                timeout_ms: 5000,
            };
            let outcome = run_snapshot_once(&config, b"hello").unwrap();
            assert_eq!(outcome.exit_kind, ExitKind::Ok);
            assert!(
                outcome.coverage_edges.is_empty(),
                "software replay must not fabricate coverage"
            );
        }
    }
}
