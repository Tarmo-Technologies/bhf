// SPDX-License-Identifier: Apache-2.0

//! The extra build lanes of a C/C++ harness that are built after `main` has
//! built and can fail on their own: the source-coverage lane (`make cov`) that
//! line coverage is measured with, and the AFL++ lane (`make afl`). A lost
//! lane is recorded in the harness dir (`lanes.json`), so `run.json`
//! (`targets[].lanes`), `summary.txt` and `run.md` say what it cost instead of
//! staying silent.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// The per-harness record, beside the harness's Makefile.
pub(crate) const LANES_FILE: &str = "lanes.json";

/// The source-coverage lane (`make cov`, `main_cov`).
pub(crate) const COVERAGE: &str = "cov";
/// The AFL++ lane (`make afl`, `main_afl`).
pub(crate) const AFL: &str = "afl";

/// Whether one lane built, and why not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LaneStatus {
    pub built: bool,
    /// `make main_cov failed: <first error line>`; absent when it built.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl LaneStatus {
    pub(crate) fn built() -> Self {
        Self {
            built: true,
            reason: None,
        }
    }

    /// A lane whose `make <target>` failed with `output` (its stdout and
    /// stderr), named by the first error line of it.
    pub(crate) fn failed(binary: &str, output: &str) -> Self {
        Self {
            built: false,
            reason: Some(match first_error_line(output) {
                Some(line) => format!("make {binary} failed: {line}"),
                None => format!("make {binary} failed"),
            }),
        }
    }
}

/// The first line of a build's output that reports an error: a compiler or
/// linker diagnostic, else make's own `Error` line.
pub(crate) fn first_error_line(output: &str) -> Option<String> {
    const MAX_CHARS: usize = 240;
    let lines: Vec<&str> = output.lines().map(str::trim).collect();
    let pick = lines
        .iter()
        .find(|line| {
            line.contains("error:")
                || line.contains("undefined reference to")
                || line.contains("undefined symbol")
                || line.contains("cannot find -l")
        })
        .or_else(|| lines.iter().find(|line| line.contains("Error ")))
        .or_else(|| lines.iter().find(|line| line.contains("error")))?;
    let mut line: String = pick.chars().take(MAX_CHARS).collect();
    if pick.chars().count() > MAX_CHARS {
        line.push('…');
    }
    Some(line)
}

/// Record `status` for `lane` in `harness_dir`, keeping the other lanes'.
pub(crate) fn record(harness_dir: &Path, lane: &str, status: LaneStatus) {
    let mut lanes = read(harness_dir);
    lanes.insert(lane.to_owned(), status);
    if let Ok(bytes) = serde_json::to_vec_pretty(&lanes) {
        let _ = crate::auto::report::atomic_write(&harness_dir.join(LANES_FILE), &bytes);
    }
}

/// Forget the lanes an earlier attempt in `harness_dir` recorded, so a run
/// reports only what its own builds did.
pub(crate) fn clear(harness_dir: &Path) {
    let _ = std::fs::remove_file(harness_dir.join(LANES_FILE));
}

/// The lanes recorded for `harness_dir`; empty when none was.
pub(crate) fn read(harness_dir: &Path) -> BTreeMap<String, LaneStatus> {
    std::fs::read(harness_dir.join(LANES_FILE))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// What each lane that did not build cost, one line per lane:
/// `line coverage unavailable: make main_cov failed: <first error>`.
pub(crate) fn unavailable(lanes: &BTreeMap<String, LaneStatus>) -> Vec<String> {
    lanes
        .iter()
        .filter(|(_, status)| !status.built)
        .map(|(lane, status)| {
            let what = match lane.as_str() {
                COVERAGE => "line coverage unavailable",
                AFL => "AFL++ fuzzing unavailable",
                other => return format!("{other} lane unavailable: {}", reason(status)),
            };
            format!("{what}: {}", reason(status))
        })
        .collect()
}

fn reason(status: &LaneStatus) -> &str {
    status.reason.as_deref().unwrap_or("its build failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_lane_is_named_by_its_first_error_line() {
        let output = "clang -O0 -g ... -o main_cov main.c\n\
                      /usr/bin/ld: main.o: in function `parse_record':\n\
                      main.c:(.text+0x1a): undefined reference to `vendor_check'\n\
                      clang: error: linker command failed with exit code 1\n\
                      make: *** [Makefile:271: main_cov] Error 1\n";
        let status = LaneStatus::failed("main_cov", output);
        assert!(!status.built);
        assert_eq!(
            status.reason.as_deref(),
            Some(
                "make main_cov failed: main.c:(.text+0x1a): undefined reference to `vendor_check'"
            )
        );
        assert_eq!(
            LaneStatus::failed("main_afl", "make: *** [Makefile:9: main_afl] Error 127\n").reason,
            Some("make main_afl failed: make: *** [Makefile:9: main_afl] Error 127".to_owned())
        );
    }

    #[test]
    fn lanes_are_recorded_per_harness_and_report_what_was_lost() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read(dir.path()).is_empty());
        record(
            dir.path(),
            COVERAGE,
            LaneStatus::failed("main_cov", "x.c:3:1: error: unknown type name 'widget_t'"),
        );
        record(dir.path(), AFL, LaneStatus::built());
        let lanes = read(dir.path());
        assert_eq!(lanes.len(), 2);
        assert_eq!(
            unavailable(&lanes),
            vec![
                "line coverage unavailable: make main_cov failed: x.c:3:1: error: unknown type \
                 name 'widget_t'"
                    .to_owned()
            ]
        );
        // A later successful build clears the loss.
        record(dir.path(), COVERAGE, LaneStatus::built());
        assert!(unavailable(&read(dir.path())).is_empty());
        // A new attempt starts from nothing: an earlier run's AFL++ failure is
        // not reported as this run's.
        record(
            dir.path(),
            AFL,
            LaneStatus::failed("main_afl", "error: old"),
        );
        clear(dir.path());
        assert!(read(dir.path()).is_empty());
    }
}
