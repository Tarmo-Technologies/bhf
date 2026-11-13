// SPDX-License-Identifier: Apache-2.0

//! The extra build lanes of a C/C++ harness that are built after `main` has
//! built and can fail on their own: the source-coverage lane (`make cov`) that
//! line coverage is measured with, and the AFL++ lane (`make afl`). A lost
//! lane is recorded in the harness dir (`lanes.json`), so `run.json`
//! (`targets[].lanes`), `summary.txt` and `run.md` say what it cost instead of
//! staying silent.
//!
//! The record belongs to the attempt that built the harness: an attempt
//! starts it afresh, and so does a target that inherits a sibling's verdict
//! without building. Each entry says when it was recorded, so a lane of a
//! target `--resume` reloaded from an earlier run is reported as that run's.

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
    /// When the lane's build was recorded (RFC 3339, UTC), set by [`record`].
    /// Absent in a record written before the field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_at: Option<String>,
}

impl LaneStatus {
    pub(crate) fn built() -> Self {
        Self {
            built: true,
            reason: None,
            recorded_at: None,
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
            recorded_at: None,
        }
    }

    /// Whether this lane was recorded before `run_started_at` (an RFC 3339
    /// time), by an earlier run: a record with no time is one too.
    fn recorded_before(&self, run_started_at: &str) -> bool {
        let Ok(started) = chrono::DateTime::parse_from_rfc3339(run_started_at) else {
            return false;
        };
        match self
            .recorded_at
            .as_deref()
            .map(chrono::DateTime::parse_from_rfc3339)
        {
            Some(Ok(recorded)) => recorded < started,
            _ => true,
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

/// Record `status` for `lane` in `harness_dir`, keeping the other lanes',
/// stamped with the time it is recorded.
pub(crate) fn record(harness_dir: &Path, lane: &str, mut status: LaneStatus) {
    status.recorded_at = Some(chrono::Utc::now().to_rfc3339());
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
/// `line coverage unavailable: make main_cov failed: <first error>`. A lane
/// recorded before `run_started_at` (the current run's start, RFC 3339) says
/// it was recorded by an earlier run, and when.
pub(crate) fn unavailable(
    lanes: &BTreeMap<String, LaneStatus>,
    run_started_at: &str,
) -> Vec<String> {
    lanes
        .iter()
        .filter(|(_, status)| !status.built)
        .map(|(lane, status)| {
            let what = match lane.as_str() {
                COVERAGE => "line coverage unavailable".to_owned(),
                AFL => "AFL++ fuzzing unavailable".to_owned(),
                other => format!("{other} lane unavailable"),
            };
            let earlier = if !status.recorded_before(run_started_at) {
                String::new()
            } else if let Some(at) = &status.recorded_at {
                format!(" (recorded by an earlier run at {at})")
            } else {
                " (recorded by an earlier run)".to_owned()
            };
            format!("{what}: {}{earlier}", reason(status))
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
        assert!(lanes.values().all(|lane| lane.recorded_at.is_some()));
        assert_eq!(
            unavailable(&lanes, RUN_START),
            vec![
                "line coverage unavailable: make main_cov failed: x.c:3:1: error: unknown type \
                 name 'widget_t'"
                    .to_owned()
            ]
        );
        // A later successful build clears the loss.
        record(dir.path(), COVERAGE, LaneStatus::built());
        assert!(unavailable(&read(dir.path()), RUN_START).is_empty());
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

    /// A time before every lane these tests record.
    const RUN_START: &str = "2000-01-01T00:00:00+00:00";

    /// A lane recorded before the current run started (a target `--resume`
    /// reloaded) is reported as an earlier run's, with when it was recorded;
    /// one this run recorded is not.
    #[test]
    fn a_lane_recorded_by_an_earlier_run_says_so() {
        let dir = tempfile::tempdir().unwrap();
        record(
            dir.path(),
            COVERAGE,
            LaneStatus::failed("main_cov", "x.c:3:1: error: planted"),
        );
        let lanes = read(dir.path());
        let recorded = lanes[COVERAGE].recorded_at.clone().unwrap();
        assert!(
            chrono::DateTime::parse_from_rfc3339(&recorded).is_ok(),
            "{recorded}"
        );
        let this_run = unavailable(&lanes, RUN_START);
        assert_eq!(
            this_run,
            vec!["line coverage unavailable: make main_cov failed: x.c:3:1: error: planted"]
        );
        let later = "2999-01-01T00:00:00+00:00";
        assert_eq!(
            unavailable(&lanes, later),
            vec![format!(
                "line coverage unavailable: make main_cov failed: x.c:3:1: error: planted \
                 (recorded by an earlier run at {recorded})"
            )]
        );
        // A record written before lanes carried a time is an earlier run's.
        let mut untimed = lanes.clone();
        untimed.get_mut(COVERAGE).unwrap().recorded_at = None;
        assert_eq!(
            unavailable(&untimed, RUN_START),
            vec![
                "line coverage unavailable: make main_cov failed: x.c:3:1: error: planted \
                 (recorded by an earlier run)"
            ]
        );
        // The time is in run.json's lanes, and an older record still reads.
        let json = serde_json::to_value(&lanes).unwrap();
        assert_eq!(json[COVERAGE]["recorded_at"], recorded);
        let old: BTreeMap<String, LaneStatus> =
            serde_json::from_str(r#"{"cov":{"built":false,"reason":"make main_cov failed"}}"#)
                .unwrap();
        assert_eq!(old[COVERAGE].recorded_at, None);
    }
}
