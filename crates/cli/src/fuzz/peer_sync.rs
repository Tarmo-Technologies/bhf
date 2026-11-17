// SPDX-License-Identifier: Apache-2.0

//! Live corpus sync between the workers of a `bhf fuzz --workers` campaign
//! (#277). The workers merged their queues only after every one had exited,
//! so none saw what another found while the campaign ran.
//!
//! The orchestrator gives each worker [`SYNC_DIR_ENV`], the campaign's sync
//! directory, and [`SYNC_INTERVAL_ENV`]. Every interval a worker writes the
//! entries its pool kept since the last sync to `<sync>/<worker>/<sha256>.bin`
//! and reads the entries its peers wrote that it has not seen, by content
//! hash, as AFL++'s `-M`/`-S` instances sync: each imported entry is run
//! next, and kept if it adds coverage here. A worker reads its peers'
//! entries before it writes its own, and writes none a peer has written, so
//! each hash is in the sync directory once, under the first worker to write
//! it; the workers' syncs are spread over the interval so two do not write
//! at once. Each import is a line of the worker's [`IMPORT_LOG`].

use std::collections::{HashSet, VecDeque};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sha2::Digest as _;

/// The campaign's sync directory, set by the orchestrator for each worker.
pub(crate) const SYNC_DIR_ENV: &str = multicore_fuzz::SYNC_DIR_ENV;

/// Milliseconds between a worker's syncs.
pub(crate) const SYNC_INTERVAL_ENV: &str = multicore_fuzz::SYNC_INTERVAL_ENV;

/// Milliseconds the worker's first sync waits past the interval, which
/// spreads the workers' syncs over it.
const SYNC_OFFSET_ENV: &str = multicore_fuzz::SYNC_OFFSET_ENV;

/// The worker id the orchestrator sets, which names its sync directory.
const WORKER_ID_ENV: &str = "BHF_WORKER_ID";

/// Each worker's log of the entries it imported, in its work dir: one line
/// per entry, `<ms since the pass started> <peer> <sha256>`.
pub(crate) const IMPORT_LOG: &str = "sync-import.log";

/// One worker's side of the sync.
pub(crate) struct PeerSync {
    root: PathBuf,
    own: PathBuf,
    interval: Duration,
    started: Instant,
    last: Instant,
    /// Pool entries below this index were exported, or were the pool's seeds.
    exported_to: usize,
    /// Content hashes this worker has: exported, imported or seeded.
    known: HashSet<String>,
    /// Content hashes a peer has written: never exported.
    at_peers: HashSet<String>,
    /// Peer files already read.
    seen: HashSet<PathBuf>,
    pending: VecDeque<Vec<u8>>,
    max_len: usize,
    log: Option<fs::File>,
}

fn hash(bytes: &[u8]) -> String {
    corpus::hex_lower(&sha2::Sha256::digest(bytes))
}

impl PeerSync {
    /// The sync of a worker of a `--workers` campaign, from the environment
    /// the orchestrator gives it; `None` for any other run. `seeds` are the
    /// pool's initial entries, which every worker has.
    pub(crate) fn from_env<'a>(
        work_dir: &Path,
        seeds: impl IntoIterator<Item = &'a [u8]>,
        max_len: usize,
    ) -> Option<Self> {
        let root = std::env::var_os(SYNC_DIR_ENV)
            .filter(|dir| !dir.is_empty())
            .map(PathBuf::from)?;
        let worker = std::env::var(WORKER_ID_ENV).ok()?;
        let millis = |name: &str| {
            std::env::var(name)
                .ok()
                .and_then(|ms| ms.trim().parse::<u64>().ok())
                .map(Duration::from_millis)
        };
        let interval = millis(SYNC_INTERVAL_ENV).unwrap_or(multicore_fuzz::DEFAULT_SYNC_INTERVAL);
        let mut sync = Self::new(
            root,
            &format!("worker-{worker}"),
            interval,
            work_dir,
            seeds,
            max_len,
        );
        if let Some(offset) = millis(SYNC_OFFSET_ENV) {
            sync.last += offset;
        }
        Some(sync)
    }

    pub(crate) fn new<'a>(
        root: PathBuf,
        name: &str,
        interval: Duration,
        work_dir: &Path,
        seeds: impl IntoIterator<Item = &'a [u8]>,
        max_len: usize,
    ) -> Self {
        let own = root.join(name);
        let _ = fs::create_dir_all(&own);
        let known: HashSet<String> = seeds.into_iter().map(hash).collect();
        let log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(work_dir.join(IMPORT_LOG))
            .ok();
        let now = Instant::now();
        Self {
            root,
            own,
            interval,
            started: now,
            last: now,
            exported_to: 0,
            known,
            at_peers: HashSet::new(),
            seen: HashSet::new(),
            pending: VecDeque::new(),
            max_len,
            log,
        }
    }

    /// Skip the first `count` pool entries when exporting: the seeds.
    pub(crate) fn skip_seeds(&mut self, count: usize) {
        self.exported_to = self.exported_to.max(count);
    }

    /// When the interval has passed: queue the peers' entries not seen yet,
    /// and export the pool entries kept since the last sync (`pool`, in the
    /// order the pool kept them) that no peer has.
    pub(crate) fn tick<'a>(&mut self, pool: impl ExactSizeIterator<Item = (&'a [u8], bool)>) {
        if Instant::now() < self.last + self.interval {
            return;
        }
        self.sync(pool);
    }

    /// Import and export now.
    pub(crate) fn sync<'a>(&mut self, pool: impl ExactSizeIterator<Item = (&'a [u8], bool)>) {
        self.last = Instant::now();
        let len = pool.len();
        let fresh: Vec<(String, &[u8])> = pool
            .skip(self.exported_to)
            .filter(|(bytes, retired)| !retired && !bytes.is_empty())
            .map(|(bytes, _)| (hash(bytes), bytes))
            .collect();
        // What this worker has is not run again when a peer has it too.
        for (digest, _) in &fresh {
            self.known.insert(digest.clone());
        }
        self.import();
        for (digest, bytes) in fresh {
            if !self.at_peers.contains(&digest) {
                self.export(&digest, bytes);
            }
        }
        self.exported_to = len;
    }

    fn export(&self, digest: &str, bytes: &[u8]) {
        let path = self.own.join(format!("{digest}.bin"));
        if path.exists() {
            return;
        }
        // Written aside and renamed in, so a peer never reads half of it.
        let partial = self
            .own
            .join(format!(".{digest}.{}.part", std::process::id()));
        if fs::write(&partial, bytes).is_ok() && fs::rename(&partial, &path).is_err() {
            let _ = fs::remove_file(&partial);
        }
    }

    fn import(&mut self) {
        let mut peers: Vec<PathBuf> = fs::read_dir(&self.root)
            .into_iter()
            .flatten()
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.is_dir() && *path != self.own)
            .collect();
        peers.sort();
        for peer in peers {
            let peer_name = peer
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            let mut files: Vec<PathBuf> = fs::read_dir(&peer)
                .into_iter()
                .flatten()
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "bin"))
                .collect();
            files.sort();
            for file in files {
                if !self.seen.insert(file.clone()) {
                    continue;
                }
                let too_long = fs::metadata(&file)
                    .map(|meta| meta.len() > self.max_len as u64)
                    .unwrap_or(true);
                if too_long {
                    continue;
                }
                let Ok(bytes) = fs::read(&file) else {
                    continue;
                };
                let digest = hash(&bytes);
                self.at_peers.insert(digest.clone());
                if !self.known.insert(digest.clone()) {
                    continue;
                }
                if let Some(log) = self.log.as_mut() {
                    let _ = writeln!(
                        log,
                        "{} {peer_name} {digest}",
                        self.started.elapsed().as_millis()
                    );
                }
                self.pending.push_back(bytes);
            }
        }
    }

    /// The next peer entry to run, if one is waiting.
    pub(crate) fn next_import(&mut self) -> Option<Vec<u8>> {
        self.pending.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(entries: &[&[u8]]) -> Vec<(Vec<u8>, bool)> {
        entries
            .iter()
            .map(|bytes| (bytes.to_vec(), false))
            .collect()
    }

    fn iter(pool: &[(Vec<u8>, bool)]) -> impl ExactSizeIterator<Item = (&[u8], bool)> {
        pool.iter()
            .map(|(bytes, retired)| (bytes.as_slice(), *retired))
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// A new pool entry of one worker reaches the other at its next sync,
    /// and is logged there; the seeds both started from are not exported.
    #[test]
    fn a_new_entry_of_one_worker_is_imported_by_the_other() {
        let dir = crate::test_support::TestDir::new("peer-sync");
        let root = dir.join("sync");
        let (work_a, work_b) = (dir.join("a"), dir.join("b"));
        fs::create_dir_all(&work_a).unwrap();
        fs::create_dir_all(&work_b).unwrap();
        let seeds: &[&[u8]] = &[b"seed"];
        let mut a = PeerSync::new(
            root.clone(),
            "worker-0",
            Duration::ZERO,
            &work_a,
            seeds.iter().copied(),
            64,
        );
        let mut b = PeerSync::new(
            root.clone(),
            "worker-1",
            Duration::ZERO,
            &work_b,
            seeds.iter().copied(),
            64,
        );
        a.skip_seeds(1);
        b.skip_seeds(1);
        let pool_a = pool(&[b"seed", b"found-by-a"]);
        a.sync(iter(&pool_a));
        assert_eq!(
            names(&root.join("worker-0")),
            [format!("{}.bin", hash(b"found-by-a"))]
        );
        let pool_b = pool(&[b"seed"]);
        b.sync(iter(&pool_b));
        assert_eq!(b.next_import(), Some(b"found-by-a".to_vec()));
        assert_eq!(b.next_import(), None);
        let log = fs::read_to_string(work_b.join(IMPORT_LOG)).unwrap();
        assert!(
            log.contains(&format!("worker-0 {}", hash(b"found-by-a"))),
            "{log}"
        );
    }

    /// An entry a worker imported and then kept is not exported again: each
    /// hash is in the sync directory once.
    #[test]
    fn imported_entry_is_not_re_exported() {
        let dir = crate::test_support::TestDir::new("peer-sync-once");
        let root = dir.join("sync");
        let (work_a, work_b) = (dir.join("a"), dir.join("b"));
        fs::create_dir_all(&work_a).unwrap();
        fs::create_dir_all(&work_b).unwrap();
        let mut a = PeerSync::new(root.clone(), "worker-0", Duration::ZERO, &work_a, [], 64);
        let mut b = PeerSync::new(root.clone(), "worker-1", Duration::ZERO, &work_b, [], 64);
        a.sync(iter(&pool(&[b"shared"])));
        b.sync(iter(&pool(&[])));
        let imported = b.next_import().unwrap();
        // B keeps it, and finds one of its own.
        let pool_b = pool(&[&imported, b"b-only"]);
        b.sync(iter(&pool_b));
        a.sync(iter(&pool(&[b"shared"])));
        let mut all: Vec<String> = ["worker-0", "worker-1"]
            .iter()
            .flat_map(|worker| names(&root.join(worker)))
            .collect();
        all.sort();
        let mut expected = vec![
            format!("{}.bin", hash(b"shared")),
            format!("{}.bin", hash(b"b-only")),
        ];
        expected.sort();
        assert_eq!(all, expected);
        // A takes B's own entry, and not its own back.
        assert_eq!(a.next_import(), Some(b"b-only".to_vec()));
        assert_eq!(a.next_import(), None);
    }

    /// An entry two workers found on their own is written once: the second
    /// to sync sees the first's and neither writes nor runs it.
    #[test]
    fn an_entry_both_workers_found_is_written_once() {
        let dir = crate::test_support::TestDir::new("peer-sync-both");
        let root = dir.join("sync");
        fs::create_dir_all(dir.join("a")).unwrap();
        fs::create_dir_all(dir.join("b")).unwrap();
        let mut a = PeerSync::new(
            root.clone(),
            "worker-0",
            Duration::ZERO,
            &dir.join("a"),
            [],
            64,
        );
        let mut b = PeerSync::new(
            root.clone(),
            "worker-1",
            Duration::ZERO,
            &dir.join("b"),
            [],
            64,
        );
        a.sync(iter(&pool(&[b"both"])));
        b.sync(iter(&pool(&[b"both", b"b-only"])));
        assert_eq!(b.next_import(), None, "B has it already");
        assert_eq!(
            names(&root.join("worker-0")),
            [format!("{}.bin", hash(b"both"))]
        );
        assert_eq!(
            names(&root.join("worker-1")),
            [format!("{}.bin", hash(b"b-only"))]
        );
    }

    /// A sync is not due before the interval, and an entry over the length
    /// cap is not imported.
    #[test]
    fn syncs_wait_for_the_interval_and_respect_the_length_cap() {
        let dir = crate::test_support::TestDir::new("peer-sync-interval");
        let root = dir.join("sync");
        fs::create_dir_all(dir.join("a")).unwrap();
        fs::create_dir_all(dir.join("b")).unwrap();
        let mut a = PeerSync::new(
            root.clone(),
            "worker-0",
            Duration::from_secs(3600),
            &dir.join("a"),
            [],
            4,
        );
        let mut b = PeerSync::new(
            root.clone(),
            "worker-1",
            Duration::ZERO,
            &dir.join("b"),
            [],
            4,
        );
        a.tick(iter(&pool(&[b"long-entry"])));
        assert!(!root
            .join("worker-0")
            .join(format!("{}.bin", hash(b"long-entry")))
            .exists());
        a.sync(iter(&pool(&[b"long-entry", b"ok"])));
        b.sync(iter(&pool(&[])));
        assert_eq!(b.next_import(), Some(b"ok".to_vec()));
        assert_eq!(b.next_import(), None);
        let log = fs::read_to_string(dir.join("b").join(IMPORT_LOG)).unwrap();
        assert_eq!(log.lines().count(), 1, "{log}");
    }
}
