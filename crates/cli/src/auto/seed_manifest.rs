// SPDX-License-Identifier: Apache-2.0

//! `auto/seeds.json`: which inputs seeded this run's targets, and where each
//! came from.
//!
//! Corpus queue entries are named by content hash only, so without this record
//! nobody can tell that a queue entry (or a finding's ancestry) started as a
//! file mined out of the tree's own test data. Each entry carries the file's
//! path, its size on disk, and the sha256 of the bytes the engine received,
//! which is also the name of that seed's `corpus/<harness-id>/queue/<sha256>.bin`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// File name of the manifest inside the run's `auto/` reports directory.
pub(crate) const SEED_MANIFEST_FILE: &str = "seeds.json";

/// Where one seed came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SeedSource {
    /// `--seed-file` / `--seed-dir`.
    User,
    /// Harvested from the tree's own test-data directories.
    Mined,
}

/// What happened to tree seed mining this run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SeedMining {
    /// No explicit seeds were given, so the tree's test data was searched.
    Ran,
    /// Explicit `--seed-file` / `--seed-dir` seeds replace mining.
    SkippedUserSeeds,
    /// Turned off with `--no-seed-mining` or `seed-mining = false`.
    Disabled,
}

impl SeedMining {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ran => "ran",
            Self::SkippedUserSeeds => "skipped (explicit seeds given)",
            Self::Disabled => "disabled",
        }
    }
}

/// A seed file as loaded: its path, the bytes the engine receives (possibly a
/// prefix, bounded by the run's seed cap), and the file's size on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LoadedSeed {
    pub(crate) path: PathBuf,
    pub(crate) bytes: Vec<u8>,
    pub(crate) file_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SeedEntry {
    pub(crate) path: String,
    pub(crate) source: SeedSource,
    /// sha256 of the bytes the engine received.
    pub(crate) sha256: String,
    /// The file's size on disk.
    pub(crate) size: u64,
    /// Bytes the engine received; smaller than `size` only when the file was
    /// longer than the run's seed cap.
    pub(crate) bytes_used: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SeedManifest {
    pub(crate) schema_version: u32,
    pub(crate) mining: SeedMining,
    pub(crate) seeds: Vec<SeedEntry>,
    /// The seeds given again, prefixed, to a target whose harness decodes
    /// fixed-width parameters before its buffer (see [`LayoutVariant`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) layout_variants: Vec<LayoutVariant>,
}

/// One target's prefixed seeds. Its harness decodes `layout_prefix` input
/// bytes into fixed-width parameters before the buffer that takes the bytes
/// left, so a seed given as is starts in those parameters; it is given
/// again behind `layout_prefix` zero bytes, so the buffer starts with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LayoutVariant {
    pub(crate) harness_id: String,
    pub(crate) layout_prefix: usize,
    /// sha256 of each prefixed seed the engine received, which also names
    /// its `corpus/<harness-id>/queue/<sha256>.bin`.
    pub(crate) sha256: Vec<String>,
}

/// The `seeds` block of `run.json`: enough to say where the run's seeds came
/// from without opening the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct SeedSummary {
    /// Work-dir-relative path of the full manifest.
    pub(crate) manifest: String,
    pub(crate) mining: SeedMining,
    /// `user`, `mined`, or `none` when no file seeded the run.
    pub(crate) source: &'static str,
    pub(crate) count: usize,
}

impl SeedManifest {
    pub(crate) fn new(mining: SeedMining, seeds: &[LoadedSeed], source: SeedSource) -> Self {
        Self {
            schema_version: 1,
            mining,
            seeds: seeds
                .iter()
                .map(|seed| SeedEntry {
                    path: seed.path.display().to_string(),
                    source,
                    sha256: format!("{:x}", Sha256::digest(&seed.bytes)),
                    size: seed.file_size,
                    bytes_used: seed.bytes.len(),
                })
                .collect(),
            layout_variants: Vec::new(),
        }
    }

    fn summary(&self) -> SeedSummary {
        let source = match self.seeds.first().map(|seed| seed.source) {
            Some(SeedSource::User) => "user",
            Some(SeedSource::Mined) => "mined",
            None => "none",
        };
        SeedSummary {
            manifest: format!("{}/{SEED_MANIFEST_FILE}", crate::auto::layout::REPORTS_DIR),
            mining: self.mining,
            source,
            count: self.seeds.len(),
        }
    }
}

pub(crate) fn manifest_path(work_dir: &Path) -> PathBuf {
    crate::auto::layout::reports_dir(work_dir).join(SEED_MANIFEST_FILE)
}

/// Write the manifest, replacing any left by an earlier run in this work dir.
pub(crate) fn write(work_dir: &Path, manifest: &SeedManifest) -> std::io::Result<PathBuf> {
    let path = manifest_path(work_dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec_pretty(manifest).map_err(std::io::Error::other)?;
    std::fs::write(&path, json)?;
    Ok(path)
}

/// Add (or replace) `harness_id`'s prefixed seeds in this run's manifest.
/// Targets are attempted concurrently, so the read-modify-write is
/// serialized. Best-effort: a run without a manifest records nothing.
pub(crate) fn record_layout_variant(
    work_dir: &Path,
    harness_id: &str,
    layout_prefix: usize,
    seeds: &[Vec<u8>],
) -> std::io::Result<()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let path = manifest_path(work_dir);
    let Ok(bytes) = std::fs::read(&path) else {
        return Ok(());
    };
    let mut manifest: SeedManifest =
        serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;
    manifest
        .layout_variants
        .retain(|variant| variant.harness_id != harness_id);
    manifest.layout_variants.push(LayoutVariant {
        harness_id: harness_id.to_owned(),
        layout_prefix,
        sha256: seeds
            .iter()
            .map(|seed| format!("{:x}", Sha256::digest(seed)))
            .collect(),
    });
    write(work_dir, &manifest).map(|_| ())
}

/// Remove a manifest an earlier run left in this work dir. Called before this
/// run writes any report, so a run that stops before resolving seeds (no
/// fuzzable targets, say) records none instead of the earlier run's.
pub(crate) fn remove_stale(work_dir: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(manifest_path(work_dir)) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// The `run.json` summary of the manifest this run wrote, or `None` when the
/// work dir has none (a run from before the manifest existed).
pub(crate) fn summary(work_dir: &Path) -> Option<SeedSummary> {
    let bytes = std::fs::read(manifest_path(work_dir)).ok()?;
    let manifest: SeedManifest = serde_json::from_slice(&bytes).ok()?;
    Some(manifest.summary())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_records_path_hash_size_and_source_and_round_trips_to_a_summary() {
        let work = tempfile::tempdir().unwrap();
        let bytes = vec![0x4d, 0x5a, 0x90, 0x00, 0xff];
        let seeds = vec![LoadedSeed {
            path: PathBuf::from("/tree/tests/data/record.bin"),
            bytes: bytes.clone(),
            file_size: 9,
        }];
        let manifest = SeedManifest::new(SeedMining::Ran, &seeds, SeedSource::Mined);
        let path = write(work.path(), &manifest).unwrap();
        assert_eq!(path, work.path().join("auto").join("seeds.json"));

        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["mining"], "ran");
        let entry = &json["seeds"][0];
        assert_eq!(entry["path"], "/tree/tests/data/record.bin");
        assert_eq!(entry["source"], "mined");
        assert_eq!(entry["size"], 9);
        assert_eq!(entry["bytes_used"], 5);
        assert_eq!(
            entry["sha256"],
            format!("{:x}", Sha256::digest(&bytes)),
            "the hash names the seed's corpus queue entry"
        );

        let summary = summary(work.path()).unwrap();
        assert_eq!(summary.manifest, "auto/seeds.json");
        assert_eq!(summary.source, "mined");
        assert_eq!(summary.count, 1);
        assert_eq!(summary.mining, SeedMining::Ran);
    }

    /// A target's prefixed seeds are listed with the prefix its layout asks
    /// for, once per target, keeping the seeds as they were.
    #[test]
    fn a_targets_prefixed_seeds_are_listed_with_their_prefix() {
        let work = tempfile::tempdir().unwrap();
        let seeds = vec![LoadedSeed {
            path: PathBuf::from("/tree/tests/data/magic.bin"),
            bytes: b"MAGC".to_vec(),
            file_size: 4,
        }];
        write(
            work.path(),
            &SeedManifest::new(SeedMining::Ran, &seeds, SeedSource::Mined),
        )
        .unwrap();
        let variant = b"\0\0\0\0\0\0\0\0MAGC".to_vec();
        record_layout_variant(work.path(), "H-C0001", 8, std::slice::from_ref(&variant)).unwrap();
        record_layout_variant(work.path(), "H-C0001", 8, std::slice::from_ref(&variant)).unwrap();
        record_layout_variant(work.path(), "H-C0002", 4, &[b"\0\0\0\0MAGC".to_vec()]).unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(manifest_path(work.path())).unwrap()).unwrap();
        assert_eq!(json["seeds"].as_array().unwrap().len(), 1);
        let variants = json["layout_variants"].as_array().unwrap();
        assert_eq!(variants.len(), 2, "{json}");
        assert_eq!(variants[0]["harness_id"], "H-C0001");
        assert_eq!(variants[0]["layout_prefix"], 8);
        assert_eq!(
            variants[0]["sha256"],
            serde_json::json!([format!("{:x}", Sha256::digest(&variant))])
        );
        assert_eq!(variants[1]["layout_prefix"], 4);
        // Read back, the summary is unchanged.
        assert_eq!(summary(work.path()).unwrap().count, 1);
    }

    #[test]
    fn an_empty_manifest_summarizes_as_no_seed_source() {
        let work = tempfile::tempdir().unwrap();
        write(
            work.path(),
            &SeedManifest::new(SeedMining::Disabled, &[], SeedSource::Mined),
        )
        .unwrap();
        let summary = summary(work.path()).unwrap();
        assert_eq!(summary.source, "none");
        assert_eq!(summary.count, 0);
        assert_eq!(summary.mining, SeedMining::Disabled);
        assert!(super::summary(&work.path().join("missing")).is_none());
    }

    #[test]
    fn remove_stale_drops_an_earlier_manifest_and_tolerates_none() {
        let work = tempfile::tempdir().unwrap();
        remove_stale(work.path()).expect("no manifest is not an error");
        write(
            work.path(),
            &SeedManifest::new(SeedMining::Ran, &[], SeedSource::Mined),
        )
        .unwrap();
        remove_stale(work.path()).unwrap();
        assert!(!manifest_path(work.path()).exists());
        assert!(summary(work.path()).is_none());
    }
}
