// SPDX-License-Identifier: Apache-2.0
//! After fuzzing, minimize the representative of each root-cause group so every
//! issue ships a small reproducer. Bounded: PER_GROUP per representative and
//! TOTAL overall; groups not reached are marked `minimization_skipped`.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const PER_GROUP: Duration = Duration::from_secs(30);
pub const TOTAL: Duration = Duration::from_secs(300);

pub(crate) struct Pick {
    pub id: String,
    pub dir: PathBuf,
    pub harness_id: Option<String>,
    pub fixture_path: Option<String>,
}

/// One representative per group (the report crate's actionability order),
/// dynamic findings only, skipping groups that already have a minimized input.
pub(crate) fn representatives(work_dir: &Path) -> Vec<Pick> {
    let findings_dir = corpus::layout::findings_dir(work_dir);
    let Ok((findings, _)) = bhf_report::load_findings_tolerant(&findings_dir, None, false) else {
        return Vec::new();
    };
    let mut seen = std::collections::HashSet::new();
    let mut groups_with_min = std::collections::HashSet::new();
    for f in &findings {
        if findings_dir.join(&f.id).join("min_testcase.bin").is_file() {
            groups_with_min.insert(bhf_report::issue_key(f));
        }
    }
    findings
        .iter()
        .filter(|f| {
            let kind = results::normalize::kind_for(&f.id, &f.raw);
            matches!(
                kind,
                results::model::Kind::Fuzz | results::model::Kind::Runtime
            )
        })
        .filter(|f| findings_dir.join(&f.id).join("testcase.bin").is_file())
        .filter(|f| {
            let key = bhf_report::issue_key(f);
            !groups_with_min.contains(&key) && seen.insert(key)
        })
        .map(|f| Pick {
            id: f.id.clone(),
            dir: findings_dir.join(&f.id),
            harness_id: f
                .raw
                .get("harness_id")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
            fixture_path: f
                .raw
                .get("fixture_path")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
        })
        .collect()
}

fn harness_for(work_dir: &Path, pick: &Pick) -> Option<PathBuf> {
    if let Some(path) = pick
        .fixture_path
        .as_deref()
        .map(PathBuf::from)
        .filter(|p| p.is_file())
    {
        return Some(path);
    }
    let hid = pick.harness_id.as_deref()?;
    crate::auto::layout::harness_dir_candidates(work_dir, hid)
        .into_iter()
        .flat_map(|dir| ["main", "main_afl", "main.exe", "main_afl.exe"].map(|leaf| dir.join(leaf)))
        .find(|p| p.is_file())
}

pub(crate) fn mark_skipped(dir: &Path, reason: &str) {
    let path = dir.join("finding.json");
    let Ok(bytes) = std::fs::read(&path) else {
        return;
    };
    let Ok(mut raw) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return;
    };
    if let Some(obj) = raw.as_object_mut() {
        obj.insert("minimization_skipped".to_owned(), serde_json::json!(reason));
    }
    corpus::finding::append_history(&mut raw, "auto", &["minimization_skipped"]);
    if let Ok(out) = serde_json::to_vec_pretty(&raw) {
        let _ = std::fs::write(&path, out);
    }
}

/// Returns (minimized, skipped_for_budget).
pub fn run(work_dir: &Path) -> (usize, usize) {
    let start = Instant::now();
    let (mut done, mut skipped) = (0, 0);
    for pick in representatives(work_dir) {
        let remaining = TOTAL.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            mark_skipped(&pick.dir, "time_budget");
            skipped += 1;
            continue;
        }
        let Some(harness) = harness_for(work_dir, &pick) else {
            continue;
        };
        let deadline = Instant::now() + PER_GROUP.min(remaining);
        match crate::minimize::minimize_for_auto(&pick.dir, &harness, deadline) {
            Ok(Some(_)) => done += 1,
            Ok(None) => {}
            Err(error) => bhfeprintln!("bhf: minimize {} skipped: {error:#}", pick.id),
        }
    }
    (done, skipped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_one_representative_per_group_and_skips_minimized_or_static() {
        let tmp = tempfile::tempdir().unwrap();
        let f = corpus::layout::findings_dir(tmp.path());
        for (id, cluster, extra) in [
            ("F-0000-aaaaaaaa", "k1", ""),
            ("F-0001-bbbbbbbb", "k1", ""),
            ("F-0002-cccccccc", "k2", "min"),
            ("F-STATIC-0000", "k3", ""),
        ] {
            std::fs::create_dir_all(f.join(id)).unwrap();
            std::fs::write(f.join(id).join("finding.json"), format!(
                r#"{{"id":"{id}","cluster_key_full":"{cluster}","cluster_normalized_frames":["frame-{cluster}"],"rule_id":"BHF-201","classification":"unhandled","harness_id":"H1"}}"#
            )).unwrap();
            std::fs::write(f.join(id).join("testcase.bin"), b"x").unwrap();
            if extra == "min" {
                std::fs::write(f.join(id).join("min_testcase.bin"), b"x").unwrap();
            }
        }
        let picks: Vec<String> = representatives(tmp.path())
            .into_iter()
            .map(|p| p.id)
            .collect();
        assert_eq!(picks, ["F-0000-aaaaaaaa"]);
    }

    #[test]
    fn out_of_budget_groups_are_marked() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("F-0000-aaaaaaaa");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("finding.json"), r#"{"id":"F-0000-aaaaaaaa"}"#).unwrap();
        mark_skipped(&dir, "time_budget");
        let raw: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("finding.json")).unwrap()).unwrap();
        assert_eq!(raw["minimization_skipped"], "time_budget");
    }
}
