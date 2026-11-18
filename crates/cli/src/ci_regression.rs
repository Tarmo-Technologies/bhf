// SPDX-License-Identifier: Apache-2.0

//! `bhf ci`'s regression replay (#318). The findings an earlier run stored,
//! in `<work>/regressions/` or a `--regressions` directory, are replayed
//! against this run's build of their harness: one that still reproduces
//! fails the gate, and one that no longer does is fixed and passes.
//!
//! A work dir a CI cache restored still holds its last run's findings in
//! `results/findings/`. They move to `regressions/` before the run, so they
//! are checked as regressions and not counted again as this run's findings.
//! Their minimized inputs also seed the run, so the engines run them first.
//! The gate fails closed: a finding with no input to replay stays where it
//! is, and one whose replay decides nothing goes back, so the gate judges
//! both as this run's findings.

use std::path::{Path, PathBuf};

/// The directory of a work dir's stored findings.
pub(crate) const REGRESSIONS_DIR: &str = "regressions";

/// A stored finding: its directory, id and the input it replays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Regression {
    pub(crate) dir: PathBuf,
    pub(crate) id: String,
    pub(crate) input: PathBuf,
}

/// What replaying the stored findings came to.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Outcome {
    /// Findings that reproduce against this run's build.
    pub(crate) reproduced: Vec<String>,
    /// Findings that no longer reproduce.
    pub(crate) fixed: Vec<String>,
    /// Findings replay could not decide (no harness, an unverified replay).
    pub(crate) unverified: Vec<String>,
}

impl Outcome {
    pub(crate) fn replayed(&self) -> usize {
        self.reproduced.len() + self.fixed.len() + self.unverified.len()
    }

    pub(crate) fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "replayed": self.replayed(),
            "reproduced": self.reproduced,
            "fixed": self.fixed,
            "unverified": self.unverified,
        })
    }
}

/// The stored findings to replay: `work_dir`'s last findings, moved into
/// `regressions/` first, those already there, and those in `extra_dirs`.
pub(crate) fn collect(work_dir: &Path, extra_dirs: &[PathBuf]) -> Vec<Regression> {
    let stored = work_dir.join(REGRESSIONS_DIR);
    let last = corpus::layout::findings_dir(work_dir);
    // A finding that still reproduces is found again by the run its input
    // seeds: one regression per root cause.
    let mut root_causes: std::collections::HashSet<String> = finding_dirs(&stored)
        .iter()
        .filter_map(|dir| root_cause(dir))
        .collect();
    for dir in finding_dirs(&last) {
        let Some(name) = dir.file_name() else {
            continue;
        };
        // Nothing to replay: it stays a finding the gate judges.
        if regression_in(&dir).is_none() {
            continue;
        }
        if root_cause(&dir).is_some_and(|key| !root_causes.insert(key)) {
            let _ = std::fs::remove_dir_all(&dir);
            continue;
        }
        let dest = stored.join(name);
        if dest.exists() || std::fs::create_dir_all(&stored).is_err() {
            continue;
        }
        if let Err(error) = std::fs::rename(&dir, &dest) {
            bhfeprintln!(
                "bhf ci: warning: could not keep {} as a regression: {error}",
                dir.display()
            );
        }
    }
    let mut regressions = Vec::new();
    for root in std::iter::once(&stored).chain(extra_dirs) {
        for dir in finding_dirs(root) {
            let Some(regression) = regression_in(&dir) else {
                continue;
            };
            if !regressions
                .iter()
                .any(|known: &Regression| known.id == regression.id)
            {
                regressions.push(regression);
            }
        }
    }
    regressions
}

/// A finding's root cause, as the results group findings: its
/// `cluster_key_full`.
fn root_cause(dir: &Path) -> Option<String> {
    let raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("finding.json")).ok()?).ok()?;
    raw.get("cluster_key_full")?.as_str().map(str::to_owned)
}

/// The finding directories directly under `root`, sorted.
fn finding_dirs(root: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(root)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|dir| dir.join("finding.json").is_file())
                .collect()
        })
        .unwrap_or_default();
    dirs.sort();
    dirs
}

/// The regression a finding directory holds: its minimized input, else its
/// testcase.
fn regression_in(dir: &Path) -> Option<Regression> {
    let input = ["min_testcase.bin", "testcase.bin"]
        .into_iter()
        .map(|name| dir.join(name))
        .find(|path| path.is_file())?;
    let id = std::fs::read(dir.join("finding.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|raw| raw.get("id").and_then(|id| id.as_str()).map(str::to_owned))
        .or_else(|| Some(dir.file_name()?.to_string_lossy().into_owned()))?;
    Some(Regression {
        dir: dir.to_path_buf(),
        id,
        input,
    })
}

/// Put each of `work_dir`'s stored findings that replay could not decide
/// back among its findings: it was not shown fixed, so the gate judges it as
/// one of this run's. A `--regressions` directory's are only reported.
pub(crate) fn keep_unverified(work_dir: &Path, regressions: &[Regression], outcome: &Outcome) {
    let stored = work_dir.join(REGRESSIONS_DIR);
    let last = corpus::layout::findings_dir(work_dir);
    for regression in regressions {
        if !outcome.unverified.contains(&regression.id) || !regression.dir.starts_with(&stored) {
            continue;
        }
        let Some(name) = regression.dir.file_name() else {
            continue;
        };
        let dest = last.join(name);
        if dest.exists() || std::fs::create_dir_all(&last).is_err() {
            continue;
        }
        if let Err(error) = std::fs::rename(&regression.dir, &dest) {
            bhfeprintln!(
                "bhf ci: warning: could not keep unreplayed {} among the findings: {error}",
                regression.dir.display()
            );
        }
    }
}

#[derive(clap::Parser)]
struct ReplayCommand {
    #[command(flatten)]
    args: crate::replay::ReplayArgs,
}

/// Replay each stored finding with `bhf replay` against the harness its
/// finding records, which this run built again: a MATCH reproduces it, a
/// MISMATCH means it no longer does.
pub(crate) fn replay(regressions: &[Regression]) -> Outcome {
    use clap::Parser;
    let mut outcome = Outcome::default();
    for regression in regressions {
        let parsed = ReplayCommand::try_parse_from([
            std::ffi::OsStr::new("replay"),
            std::ffi::OsStr::new("--finding"),
            regression.dir.as_os_str(),
        ]);
        let code = match parsed {
            Ok(command) => crate::replay::run(command.args),
            Err(_) => 1,
        };
        let id = regression.id.clone();
        match code {
            0 => {
                bhfeprintln!("bhf ci: regression {id} still reproduces");
                outcome.reproduced.push(id);
            }
            3 => {
                bhfeprintln!("bhf ci: regression {id} no longer reproduces: fixed");
                outcome.fixed.push(id);
            }
            _ => {
                bhfeprintln!("bhf ci: regression {id} could not be replayed (exit {code})");
                outcome.unverified.push(id);
            }
        }
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(root: &Path, id: &str, minimized: bool) -> PathBuf {
        let dir = root.join(id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("finding.json"),
            serde_json::json!({ "id": id, "cluster_key_full": format!("key-{id}") }).to_string(),
        )
        .unwrap();
        std::fs::write(dir.join("testcase.bin"), b"long input").unwrap();
        if minimized {
            std::fs::write(dir.join("min_testcase.bin"), b"x").unwrap();
        }
        dir
    }

    /// A restored work dir's last findings become its regressions, and are
    /// no longer this run's findings; each replays its minimized input.
    #[test]
    fn a_restored_work_dirs_findings_become_its_regressions() {
        let work = tempfile::tempdir().unwrap();
        let last = corpus::layout::findings_dir(work.path());
        finding(&last, "F-0000-aaaa", true);
        let extra = tempfile::tempdir().unwrap();
        finding(extra.path(), "F-0001-bbbb", false);
        // The same finding in both places is one regression.
        finding(extra.path(), "F-0000-aaaa", false);

        let regressions = collect(work.path(), &[extra.path().to_path_buf()]);
        let ids: Vec<&str> = regressions.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["F-0000-aaaa", "F-0001-bbbb"]);
        assert!(!last.join("F-0000-aaaa").exists());
        let stored = work.path().join(REGRESSIONS_DIR).join("F-0000-aaaa");
        assert_eq!(regressions[0].dir, stored);
        assert_eq!(regressions[0].input, stored.join("min_testcase.bin"));
        assert_eq!(
            regressions[1].input,
            extra.path().join("F-0001-bbbb/testcase.bin")
        );
        // A second run finds them where the first left them.
        assert_eq!(collect(work.path(), &[]).len(), 1);

        // The run the regression seeded found its bug again: the second
        // finding of that root cause is not kept beside the first.
        let again = finding(&last, "F-0002-aaaa", false);
        let raw = serde_json::json!({ "id": "F-0002-aaaa", "cluster_key_full": "key-F-0000-aaaa" });
        std::fs::write(again.join("finding.json"), raw.to_string()).unwrap();
        let regressions = collect(work.path(), &[]);
        assert_eq!(regressions.len(), 1, "{regressions:?}");
        assert!(!again.exists());
        assert!(!work
            .path()
            .join(REGRESSIONS_DIR)
            .join("F-0002-aaaa")
            .exists());
    }

    /// The gate fails closed: a finding with no input to replay stays among
    /// the findings, and a stored one replay could not decide goes back.
    #[test]
    fn findings_replay_cannot_decide_stay_findings() {
        let work = tempfile::tempdir().unwrap();
        let last = corpus::layout::findings_dir(work.path());
        let bare = last.join("BF-0001");
        std::fs::create_dir_all(&bare).unwrap();
        std::fs::write(bare.join("finding.json"), r#"{"id":"BF-0001"}"#).unwrap();
        finding(&last, "F-0000-aaaa", false);
        finding(&last, "F-0001-bbbb", false);
        let extra = tempfile::tempdir().unwrap();
        finding(extra.path(), "F-0002-cccc", false);

        let regressions = collect(work.path(), &[extra.path().to_path_buf()]);
        let ids: Vec<&str> = regressions.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["F-0000-aaaa", "F-0001-bbbb", "F-0002-cccc"]);
        assert!(bare.join("finding.json").is_file(), "no input: not moved");

        let outcome = Outcome {
            reproduced: Vec::new(),
            fixed: vec!["F-0000-aaaa".to_owned()],
            unverified: vec!["F-0001-bbbb".to_owned(), "F-0002-cccc".to_owned()],
        };
        keep_unverified(work.path(), &regressions, &outcome);
        assert!(last.join("F-0001-bbbb/finding.json").is_file());
        assert!(!work
            .path()
            .join(REGRESSIONS_DIR)
            .join("F-0001-bbbb")
            .exists());
        assert!(
            !last.join("F-0000-aaaa").exists(),
            "a fixed one stays stored"
        );
        assert!(
            !last.join("F-0002-cccc").exists(),
            "a --regressions one is reported only"
        );
        assert!(extra.path().join("F-0002-cccc/finding.json").is_file());
    }
}
