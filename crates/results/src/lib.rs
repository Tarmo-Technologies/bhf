// SPDX-License-Identifier: Apache-2.0
//! The unified `<work>/results/` directory: the `bhf.findings.v1` contract,
//! normalization from every producer, the renderers, and the rebuild that
//! keeps the derived index in sync with the evidence on disk.

pub mod confirmation;
pub mod lock;
pub mod manifest;
pub mod migrate;
pub mod model;
pub mod normalize;
pub mod rebuild;
pub mod render;
pub mod severity;

pub use corpus::layout;
pub use rebuild::{rebuild, ProducerRun, RebuildOptions, RebuildSummary};

/// Fidelity caveat on a finding whose reproducer was not minimized within
/// the auto time budget; `INDEX.md` counts the groups that carry it.
pub const UNMINIMIZED_CAVEAT: &str = "not minimized within the auto time budget";

use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum ResultsError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("JSON error in {path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("cannot migrate legacy {legacy}: {target} already exists; move one aside and retry")]
    MigrationConflict { legacy: PathBuf, target: PathBuf },
    #[error("timed out after {seconds}s waiting for results lock {path}")]
    LockTimeout { path: PathBuf, seconds: u64 },
    #[error(transparent)]
    Report(#[from] report::ReportError),
}

pub(crate) fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> ResultsError + '_ {
    move |source| ResultsError::Io {
        path: path.to_path_buf(),
        source,
    }
}
