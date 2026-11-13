// SPDX-License-Identifier: Apache-2.0

//! The built-in engine's side of seed lineage (see [`corpus::lineage`]): the
//! record of every input the in-process loop keeps in its mutation pool,
//! where each root came from, and the lineage written into each finding.
//!
//! Roots are named when the pass starts. A start input is, in order: a seed
//! the operator gave this `bhf fuzz` (`--seed-file`, `--seed-input`), a seed
//! `auto/seeds.json` lists (mined or user), either of those behind the
//! harness's layout prefix, one of bhf's built-in start inputs (generated),
//! an entry an earlier pass recorded in `lineage.jsonl` (its chain goes on),
//! a queue entry with no record (saved before lineage was kept, or dropped by
//! the record cap; an entry by its bytes, whatever its file is named), or
//! else a start input no seed list names. A worker of a
//! multi-worker campaign starts from the campaign's `lineage.jsonl` and
//! `auto/seeds.json`, and the copies the campaign hands it (the shared
//! queue's entries, the seeds it wrote behind the layout prefix) are not
//! seeds given to it, so they are named like the rest.
//!
//! A mutated input records the pool entry it was mutated from and, for a
//! splice, the entry it took bytes from; an input a generator built records
//! none.

use corpus::lineage::{
    digest, Digest, Entry, FindingLineage, LineageIndex, Origin, SeedOrigin, SeedSource,
    MAX_LINEAGE_RECORDS,
};
use fuzz_engine_builtin::MutationKind;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// bhf's built-in start inputs (`bhf auto` starts every target from them).
const BUILT_IN_STARTS: [&[u8]; 3] = [b"", b"A", b"AAAAAAAA"];

/// What the input of one iteration was made from, by pool index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InputParents {
    /// The pool entry itself, run unchanged.
    Queued(usize),
    /// Mutated from pool entry `base`; a splice also took bytes from `donor`.
    Mutated { base: usize, donor: Option<usize> },
    /// Built without reading any pool entry.
    Generated,
}

impl InputParents {
    /// The parents of an input mutated from `base` with `peer` as the peer,
    /// by the kind of mutation that made it (`None`: no mutation applied, and
    /// the loop made a random byte instead).
    pub(crate) fn from_mutation(base: usize, peer: usize, kind: Option<MutationKind>) -> Self {
        match kind {
            Some(kind) if kind.derives_from_base() => Self::Mutated {
                base,
                donor: kind.uses_peer().then_some(peer),
            },
            _ => Self::Generated,
        }
    }
}

/// The seeds this pass was handed that a seed list names, by sha256.
struct SeedCatalog {
    by_sha: HashMap<Digest, SeedOrigin>,
    layout_prefix: Option<usize>,
}

impl SeedCatalog {
    fn new(
        work_dir: &Path,
        harness_id: &str,
        operator: &[(Digest, Option<String>)],
        layout_prefix: Option<usize>,
    ) -> Self {
        use crate::auto::seed_manifest::SeedSource as Listed;
        let mut by_sha = HashMap::new();
        let mut prefix = layout_prefix;
        if let Some(manifest) = crate::auto::seed_manifest::read(work_dir) {
            for seed in &manifest.seeds {
                let Some(id) = corpus::lineage::parse_hex(&seed.sha256) else {
                    continue;
                };
                by_sha.entry(id).or_insert_with(|| SeedOrigin {
                    source: Some(match seed.source {
                        Listed::Mined => SeedSource::Mined,
                        Listed::User => SeedSource::User,
                    }),
                    path: Some(seed.path.clone()),
                    ..SeedOrigin::default()
                });
            }
            prefix = prefix.or_else(|| {
                manifest
                    .layout_variants
                    .iter()
                    .find(|variant| variant.harness_id == harness_id)
                    .map(|variant| variant.layout_prefix)
            });
        }
        // This `bhf fuzz` was handed these itself. A literal names no file, so
        // it does not displace a listed seed's path.
        for (id, path) in operator {
            if path.is_some() || !by_sha.contains_key(id) {
                by_sha.insert(
                    *id,
                    SeedOrigin {
                        source: Some(SeedSource::User),
                        path: path.clone(),
                        ..SeedOrigin::default()
                    },
                );
            }
        }
        Self {
            by_sha,
            layout_prefix: prefix.filter(|prefix| *prefix > 0),
        }
    }

    /// The listed seed `bytes` is, itself or behind the layout prefix.
    fn origin(&self, bytes: &[u8], id: &Digest) -> Option<SeedOrigin> {
        if let Some(seed) = self.by_sha.get(id) {
            return Some(seed.clone());
        }
        let prefix = self.layout_prefix?;
        if bytes.len() < prefix || bytes[..prefix].iter().any(|byte| *byte != 0) {
            return None;
        }
        let seed_id = digest(&bytes[prefix..]);
        let seed = self.by_sha.get(&seed_id)?;
        Some(SeedOrigin {
            layout_prefix: Some(prefix),
            seed_sha256: Some(seed_id),
            ..seed.clone()
        })
    }
}

/// The lineage of the pool of one in-process fuzz pass.
pub(crate) struct QueueLineage {
    index: LineageIndex,
    /// sha256 of each pool entry, by pool index.
    ids: Vec<Digest>,
    path: PathBuf,
    /// The harness's `queue/` beside the index.
    queue: PathBuf,
    max_records: usize,
}

impl QueueLineage {
    /// Name the roots of a pass whose pool starts as `seeds`. `operator`
    /// lists the seeds given to this `bhf fuzz` (sha256 and path, when one
    /// was read from a file); `layout_prefix` is the harness's (see
    /// [`crate::fuzz::layout_seed_prefix`]). Every record on file is read;
    /// [`Self::persist`] writes back at most `max_records`
    /// ([`corpus::lineage::record_cap`] of the queue's entry limit), or twice
    /// the files the queue holds when that is more, the pool's first.
    pub(crate) fn start<'a>(
        work_dir: &Path,
        harness_id: &str,
        operator: &[(Digest, Option<String>)],
        layout_prefix: Option<usize>,
        seeds: impl IntoIterator<Item = &'a [u8]>,
        max_records: usize,
    ) -> Self {
        let path = corpus::lineage::index_path(work_dir, harness_id);
        let mut index = LineageIndex::load(&path, MAX_LINEAGE_RECORDS).unwrap_or_else(|error| {
            bhfeprintln!(
                "bhf fuzz: warning: could not read the seed lineage in {}: {error}",
                path.display()
            );
            LineageIndex::new()
        });
        let catalog = SeedCatalog::new(work_dir, harness_id, operator, layout_prefix);
        let queue = work_dir.join("corpus").join(harness_id).join("queue");
        let mut ids = Vec::new();
        // Start inputs with no record yet, by sha256 and length.
        let mut unnamed = Vec::new();
        for bytes in seeds {
            let id = digest(bytes);
            ids.push(id);
            if let Some(seed) = catalog.origin(bytes, &id) {
                index.set_root(id, Origin::Seed(seed));
            } else if BUILT_IN_STARTS.contains(&bytes) {
                index.set_root(id, Origin::Generated);
            } else if index.get(&id).is_none() {
                unnamed.push((id, bytes.len() as u64));
            }
        }
        let queued = queued_among(&queue, &unnamed);
        for (id, _) in unnamed {
            let origin = if queued.contains(&id) {
                Origin::Corpus
            } else {
                Origin::Seed(SeedOrigin::default())
            };
            index.insert(id, Entry::Root(origin));
        }
        Self {
            index,
            ids,
            path,
            queue,
            max_records,
        }
    }

    /// The record of an input made from `parents`; `None` for a pool entry,
    /// which has its own.
    fn entry_for(&self, parents: InputParents) -> Option<Entry> {
        match parents {
            InputParents::Queued(_) => None,
            InputParents::Mutated { base, donor } => Some(Entry::Child {
                parent: *self.ids.get(base)?,
                donor: donor.and_then(|donor| self.ids.get(donor).copied()),
            }),
            InputParents::Generated => Some(Entry::Root(Origin::Generated)),
        }
    }

    /// Record the input about to be appended to the pool.
    pub(crate) fn retain(&mut self, input: &[u8], parents: InputParents) {
        let id = digest(input);
        if let Some(entry) = self.entry_for(parents) {
            self.index.insert(id, entry);
        }
        self.ids.push(id);
    }

    /// The lineage of this iteration's input.
    pub(crate) fn of(&self, input: &[u8], parents: InputParents) -> FindingLineage {
        let id = digest(input);
        if self.index.get(&id).is_some() {
            return self.index.resolve(&id);
        }
        match (parents, self.entry_for(parents)) {
            (_, Some(entry)) => self.index.resolve_entry(&id, &entry),
            (InputParents::Queued(index), None) => match self.ids.get(index) {
                Some(entry_id) => self.index.resolve(entry_id),
                None => FindingLineage::unknown("the input's pool entry has no record"),
            },
            (_, None) => FindingLineage::unknown("the input's parent has no record"),
        }
    }

    /// The lineage of an input known only by its bytes: one in the pool, or
    /// unknown.
    pub(crate) fn of_bytes(&self, input: &[u8]) -> FindingLineage {
        let id = digest(input);
        if self.index.get(&id).is_some() {
            return self.index.resolve(&id);
        }
        FindingLineage::unknown(
            "the input was not kept in the queue, so what it was mutated from was not recorded",
        )
    }

    /// Write the pool's records beside its queue. Best-effort, like the
    /// queue itself. A queue can hold more files than its entry limit (a
    /// multi-worker merge takes the union of the workers' queues), so the
    /// cap is twice its files when that is more than `max_records`; over the
    /// cap, what the pool needs is kept first, then what the queue's entries
    /// need.
    pub(crate) fn persist(&self) {
        let files = queue_files(&self.queue);
        let cap = self
            .max_records
            .max(corpus::lineage::record_cap(files.len()));
        // `save` takes `keep` from its end: the pool's entries go last.
        let mut keep = Vec::new();
        if self.index.len() > cap {
            keep = files
                .iter()
                .filter_map(|(file, _)| std::fs::read(file).ok())
                .map(|bytes| digest(&bytes))
                .collect();
        }
        keep.extend_from_slice(&self.ids);
        if let Err(error) = self.index.save(&self.path, &keep, cap) {
            bhfeprintln!(
                "bhf fuzz: warning: could not save the seed lineage to {}: {error}",
                self.path.display()
            );
        }
    }
}

/// Each file in the queue dir `queue` (every reader of `queue/` takes each
/// file there as an entry, whatever its name), with its length.
fn queue_files(queue: &Path) -> Vec<(PathBuf, u64)> {
    let Ok(entries) = std::fs::read_dir(queue) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            let meta = std::fs::metadata(&path).ok()?;
            meta.is_file().then_some((path, meta.len()))
        })
        .collect()
}

/// Which of `inputs` (sha256 and length) the queue dir `queue` holds. A
/// file is an entry by its bytes, not its name: bhf names a coverage input
/// by its sha256, a classified one by its signature, and the multi-worker
/// merge renames a colliding file `worker-N-<name>`. Only files of a wanted
/// length are read.
fn queued_among(queue: &Path, inputs: &[(Digest, u64)]) -> HashSet<Digest> {
    let mut found = HashSet::new();
    let mut wanted: HashMap<Digest, u64> = HashMap::new();
    for (id, len) in inputs {
        if queue
            .join(format!("{}.bin", corpus::lineage::hex(id)))
            .is_file()
        {
            found.insert(*id);
        } else {
            wanted.insert(*id, *len);
        }
    }
    if wanted.is_empty() {
        return found;
    }
    let lengths: HashSet<u64> = wanted.values().copied().collect();
    for (file, len) in queue_files(queue) {
        if !lengths.contains(&len) {
            continue;
        }
        let Ok(bytes) = std::fs::read(&file) else {
            continue;
        };
        let id = digest(&bytes);
        if wanted.remove(&id).is_some() {
            found.insert(id);
            if wanted.is_empty() {
                break;
            }
        }
    }
    found
}

/// A harness's queue as a lane that replays it sees it (the MSan and TSan
/// replays, the memory profile, the `--differential` post-pass): the lineage
/// of each entry it ran, from the index beside the queue, read once.
pub(crate) struct ReplayedQueue {
    index: LineageIndex,
}

impl ReplayedQueue {
    pub(crate) fn open(work_dir: &Path, harness_id: &str) -> Self {
        let path = corpus::lineage::index_path(work_dir, harness_id);
        let index = LineageIndex::load(&path, MAX_LINEAGE_RECORDS).unwrap_or_else(|error| {
            bhfeprintln!(
                "bhf: warning: could not read the seed lineage in {}: {error}",
                path.display()
            );
            LineageIndex::new()
        });
        Self { index }
    }

    /// The lineage of the queue entry `bytes`: its recorded chain, or, with
    /// no record, a corpus root, as a pass reseeded from the queue names it.
    pub(crate) fn lineage(&self, bytes: &[u8]) -> FindingLineage {
        let id = digest(bytes);
        match self.index.get(&id) {
            Some(entry) => self.index.resolve_entry(&id, entry),
            None => self.index.resolve_entry(&id, &Entry::Root(Origin::Corpus)),
        }
    }

    /// The queue entry at `input`, read back for a finding that saves no
    /// testcase of its own.
    pub(crate) fn entry(&self, input: &Path) -> ReplayedEntry {
        match std::fs::read(input) {
            Ok(bytes) => ReplayedEntry {
                sha256: Some(corpus::lineage::hex(&digest(&bytes))),
                lineage: self.lineage(&bytes),
            },
            Err(error) => ReplayedEntry {
                sha256: None,
                lineage: FindingLineage::unknown(format!(
                    "the queue entry {} could not be read again: {error}",
                    input.display()
                )),
            },
        }
    }
}

/// A queue entry a replay lane ran: its sha256 (`None` when it could not
/// be read back, which its lineage says) and its lineage.
pub(crate) struct ReplayedEntry {
    pub(crate) sha256: Option<String>,
    pub(crate) lineage: FindingLineage,
}

impl ReplayedEntry {
    /// The `input_sha256` evidence naming the entry, for a finding that
    /// saves no testcase; none when the entry could not be read back.
    pub(crate) fn evidence(&self) -> Option<serde_json::Value> {
        self.sha256
            .as_ref()
            .map(|sha256| serde_json::json!({"key": "input_sha256", "value": sha256}))
    }
}

/// The lineage of an input the operator handed a lane that runs it as it is
/// (the seed-replay engine of `bhf binary-fuzz`, `bhf differential`): a user
/// seed, 0 generations down, named by the file it was read from, if any.
pub(crate) fn of_operator_input(bytes: &[u8], path: Option<&Path>) -> FindingLineage {
    let path = path.map(|path| {
        std::path::absolute(path)
            .unwrap_or_else(|_| path.to_path_buf())
            .display()
            .to_string()
    });
    let seed = SeedOrigin {
        source: Some(SeedSource::User),
        path,
        ..SeedOrigin::default()
    };
    LineageIndex::new().resolve_entry(&digest(bytes), &Entry::Root(Origin::Seed(seed)))
}

/// The lineage of an input a lane made itself, from no seed (the empty input
/// `bhf binary-fuzz` runs when it is given none).
pub(crate) fn of_generated_input(bytes: &[u8]) -> FindingLineage {
    LineageIndex::new().resolve_entry(&digest(bytes), &Entry::Root(Origin::Generated))
}

/// Set `record`'s `lineage`, for a lane that builds its `finding.json`
/// itself.
pub(crate) fn insert(record: &mut serde_json::Value, lineage: &FindingLineage) {
    if let (Some(object), Ok(value)) = (record.as_object_mut(), serde_json::to_value(lineage)) {
        object.insert("lineage".to_owned(), value);
    }
}

/// Write `lineage` into finding `id`'s `finding.json`, warning when it cannot.
pub(crate) fn record(work_dir: &Path, id: &str, lineage: &FindingLineage) {
    let dir = corpus::layout::finding_dir(work_dir, id);
    if let Err(error) = corpus::lineage::record_in_finding(&dir, lineage) {
        bhfeprintln!("warning: could not record the seed lineage of {id}: {error}");
    }
}

/// Test fixture for the replay lanes: record `child` in `harness_id`'s
/// queue index as mutated from `seed`, a user seed read from `path`.
#[cfg(test)]
pub(crate) fn record_child_of_user_seed(
    work_dir: &Path,
    harness_id: &str,
    seed: &[u8],
    child: &[u8],
    path: &str,
) {
    let mut index = LineageIndex::new();
    index.insert(
        digest(seed),
        Entry::Root(Origin::Seed(SeedOrigin {
            source: Some(SeedSource::User),
            path: Some(path.to_owned()),
            ..SeedOrigin::default()
        })),
    );
    index.insert(
        digest(child),
        Entry::Child {
            parent: digest(seed),
            donor: None,
        },
    );
    index
        .save(
            &corpus::lineage::index_path(work_dir, harness_id),
            &[],
            MAX_LINEAGE_RECORDS,
        )
        .unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use corpus::lineage::{hex, LineageOrigin};

    fn seeds<'a>(inputs: &'a [&'a [u8]]) -> impl Iterator<Item = &'a [u8]> {
        inputs.iter().copied()
    }

    fn start(work: &Path, operator: &[(Digest, Option<String>)], pool: &[&[u8]]) -> QueueLineage {
        QueueLineage::start(
            work,
            "H-1",
            operator,
            None,
            seeds(pool),
            MAX_LINEAGE_RECORDS,
        )
    }

    fn write_manifest(work: &Path, seed: &[u8], path: &str, source: &str) {
        let manifest = serde_json::json!({
            "schema_version": 1, "mining": "ran",
            "seeds": [{"path": path, "source": source, "sha256": hex(&digest(seed)),
                       "size": seed.len(), "bytes_used": seed.len()}],
        });
        std::fs::create_dir_all(work.join("auto")).unwrap();
        std::fs::write(
            work.join("auto/seeds.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn a_seed_the_manifest_lists_is_a_root_with_its_source_and_path() {
        let work = tempfile::tempdir().unwrap();
        write_manifest(work.path(), b"MZ-seed", "/tree/tests/data/x.bin", "mined");
        let pool: &[&[u8]] = &[b"", b"A", b"AAAAAAAA", b"MZ-seed"];
        let lineage = start(work.path(), &[], pool);
        let seed = lineage.of(b"MZ-seed", InputParents::Queued(3));
        assert_eq!(seed.origin, LineageOrigin::MinedSeed);
        assert_eq!(seed.root_path.as_deref(), Some("/tree/tests/data/x.bin"));
        assert_eq!(seed.depth, Some(0));
        let child = lineage.of(
            b"MZ-seeX",
            InputParents::Mutated {
                base: 3,
                donor: None,
            },
        );
        assert_eq!(child.origin, LineageOrigin::MinedSeed);
        assert_eq!(child.depth, Some(1));
        assert_eq!(child.parent_sha256, Some(hex(&digest(b"MZ-seed"))));
        // The built-in start inputs are generated.
        for (index, built_in) in pool.iter().take(3).enumerate() {
            let built_in = lineage.of(built_in, InputParents::Queued(index));
            assert_eq!(built_in.origin, LineageOrigin::Generated, "{index}");
        }
    }

    #[test]
    fn a_seed_given_to_bhf_fuzz_is_a_user_root_even_when_it_looks_built_in() {
        let work = tempfile::tempdir().unwrap();
        let operator = [
            (digest(b"A"), None),
            (digest(b"file-seed"), Some("/seeds/one.bin".to_owned())),
        ];
        let lineage = start(work.path(), &operator, &[b"A", b"file-seed"]);
        let literal = lineage.of(b"A", InputParents::Queued(0));
        assert_eq!(
            (literal.origin, literal.root_path),
            (LineageOrigin::UserSeed, None)
        );
        let file = lineage.of(b"file-seed", InputParents::Queued(1));
        assert_eq!(file.origin, LineageOrigin::UserSeed);
        assert_eq!(file.root_path.as_deref(), Some("/seeds/one.bin"));
    }

    #[test]
    fn a_layout_prefixed_copy_of_a_seed_names_that_seed() {
        let work = tempfile::tempdir().unwrap();
        write_manifest(work.path(), b"payload", "/tree/p.bin", "user");
        let mut prefixed = vec![0u8; 8];
        prefixed.extend_from_slice(b"payload");
        let lineage = QueueLineage::start(
            work.path(),
            "H-1",
            &[],
            Some(8),
            seeds(&[b"payload", &prefixed]),
            MAX_LINEAGE_RECORDS,
        );
        let copy = lineage.of(&prefixed, InputParents::Queued(1));
        assert_eq!(copy.origin, LineageOrigin::UserSeed);
        assert_eq!(copy.root_path.as_deref(), Some("/tree/p.bin"));
        assert_eq!(copy.root_sha256, Some(hex(&digest(b"payload"))));
        assert_eq!(copy.layout_prefix, Some(8));
        // Without the prefix nothing names the copy.
        let unprefixed = start(work.path(), &[], &[&prefixed]);
        let unlisted = unprefixed.of(&prefixed, InputParents::Queued(0));
        assert_eq!(unlisted.origin, LineageOrigin::Seed);
        assert_eq!(unlisted.root_path, None);
    }

    #[test]
    fn a_queue_entry_with_no_record_is_a_corpus_root_and_an_unknown_start_is_unlisted() {
        let work = tempfile::tempdir().unwrap();
        let queue = work.path().join("corpus/H-1/queue");
        std::fs::create_dir_all(&queue).unwrap();
        std::fs::write(queue.join(format!("{}.bin", hex(&digest(b"old")))), b"old").unwrap();
        let lineage = start(work.path(), &[], &[b"old", b"symbolic"]);
        let old = lineage.of(
            b"old!",
            InputParents::Mutated {
                base: 0,
                donor: None,
            },
        );
        assert_eq!(old.origin, LineageOrigin::Corpus);
        assert_eq!(old.depth, Some(1));
        assert!(old.reason.is_some());
        let unlisted = lineage.of(b"symbolic", InputParents::Queued(1));
        assert_eq!(unlisted.origin, LineageOrigin::Seed);
        assert_eq!(unlisted.root_sha256, Some(hex(&digest(b"symbolic"))));
    }

    /// Whether a start input is a queue entry is decided by the bytes the
    /// queue holds, not by file name: bhf names a classified input's file by
    /// its signature, and the multi-worker merge renames a colliding file
    /// `worker-N-<name>`. Bytes the queue does not hold, even of the same
    /// length as an entry, are a start input no seed list names.
    #[test]
    fn a_queue_entry_with_no_record_is_a_corpus_root_whatever_its_file_is_named() {
        let work = tempfile::tempdir().unwrap();
        let queue = work.path().join("corpus/H-1/queue");
        std::fs::create_dir_all(&queue).unwrap();
        let signature = format!("{}.bin", hex(&digest(b"exception signature")));
        std::fs::write(queue.join(signature), b"signature-named").unwrap();
        std::fs::write(queue.join("worker-1-entry.bin"), b"merge-renamed").unwrap();
        std::fs::write(queue.join("entry.bin"), b"look-alike-AAAA").unwrap();
        let pool: &[&[u8]] = &[b"signature-named", b"merge-renamed", b"look-alike-BBBB"];
        let lineage = start(work.path(), &[], pool);
        for (index, entry) in pool.iter().take(2).enumerate() {
            let found = lineage.of(entry, InputParents::Queued(index));
            assert_eq!(found.origin, LineageOrigin::Corpus, "{index}: {found:?}");
            assert_eq!(found.root_sha256, Some(hex(&digest(entry))));
            assert!(found
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("no lineage record")));
        }
        let unlisted = lineage.of(pool[2], InputParents::Queued(2));
        assert_eq!(unlisted.origin, LineageOrigin::Seed, "{unlisted:?}");
    }

    /// A queue that holds more entries than its limit (a multi-worker merge
    /// takes the union of the workers' queues) keeps a record for each of
    /// them when a pass whose pool holds only some of them trims its file.
    #[test]
    fn a_pass_keeps_the_records_of_a_queue_larger_than_its_limit() {
        let work = tempfile::tempdir().unwrap();
        let path = corpus::lineage::index_path(work.path(), "H-1");
        let queue = work.path().join("corpus/H-1/queue");
        std::fs::create_dir_all(&queue).unwrap();
        let mut index = LineageIndex::new();
        index.insert(
            digest(b"seed"),
            Entry::Root(Origin::Seed(SeedOrigin {
                source: Some(SeedSource::User),
                path: Some("/seeds/seed.bin".to_owned()),
                ..SeedOrigin::default()
            })),
        );
        let entries: Vec<Vec<u8>> = (0..6).map(|n| format!("entry-{n}").into_bytes()).collect();
        for (n, entry) in entries.iter().enumerate() {
            index.insert(
                digest(entry),
                Entry::Child {
                    parent: digest(b"seed"),
                    donor: None,
                },
            );
            std::fs::write(queue.join(format!("w{n}.bin")), entry).unwrap();
        }
        // Records of inputs the queue no longer holds.
        for n in 0..10 {
            index.insert(
                digest(format!("gone-{n}").as_bytes()),
                Entry::Root(Origin::Generated),
            );
        }
        index.save(&path, &[], MAX_LINEAGE_RECORDS).unwrap();

        // A limit of 2 entries (so a cap of 4), and a pool of one entry.
        let lineage = QueueLineage::start(work.path(), "H-1", &[], None, seeds(&[&entries[0]]), 4);
        lineage.persist();
        let back = LineageIndex::load(&path, MAX_LINEAGE_RECORDS).unwrap();
        assert!(
            back.len() <= 12,
            "twice the queue's 6 files: {}",
            back.len()
        );
        for entry in &entries {
            let found = back.resolve(&digest(entry));
            assert_eq!(found.origin, LineageOrigin::UserSeed, "{found:?}");
            assert_eq!(found.depth, Some(1));
        }
    }

    #[test]
    fn retained_inputs_chain_and_a_splice_names_its_donor() {
        let work = tempfile::tempdir().unwrap();
        write_manifest(work.path(), b"seed", "/tree/seed.bin", "mined");
        let mut lineage = start(work.path(), &[], &[b"other", b"seed"]);
        lineage.retain(
            b"seed1",
            InputParents::Mutated {
                base: 1,
                donor: None,
            },
        );
        lineage.retain(
            b"seed12",
            InputParents::Mutated {
                base: 2,
                donor: Some(0),
            },
        );
        let finding = lineage.of(
            b"seed123",
            InputParents::Mutated {
                base: 3,
                donor: None,
            },
        );
        assert_eq!(finding.origin, LineageOrigin::MinedSeed);
        assert_eq!(finding.depth, Some(3));
        let spliced = lineage.of(b"seed12", InputParents::Queued(3));
        assert_eq!(spliced.donor_sha256, Some(hex(&digest(b"other"))));
        assert_eq!(spliced.parent_sha256, Some(hex(&digest(b"seed1"))));
        // A generated input descends from no entry.
        let generated = lineage.of(b"{\"k\":1}", InputParents::Generated);
        assert_eq!(
            (generated.origin, generated.depth),
            (LineageOrigin::Generated, Some(0))
        );
        // The bytes of a pool entry resolve as that entry; others are unknown.
        assert_eq!(lineage.of_bytes(b"seed12").depth, Some(2));
        let unknown = lineage.of_bytes(b"never kept");
        assert_eq!(unknown.origin, LineageOrigin::Unknown);
        assert!(unknown.reason.unwrap().contains("not kept"));
    }

    #[test]
    fn a_later_pass_resumes_the_chain_from_the_saved_index() {
        let work = tempfile::tempdir().unwrap();
        write_manifest(work.path(), b"seed", "/tree/seed.bin", "mined");
        let mut first = start(work.path(), &[], &[b"seed"]);
        first.retain(
            b"seed1",
            InputParents::Mutated {
                base: 0,
                donor: None,
            },
        );
        first.persist();
        let saved = corpus::lineage::index_path(work.path(), "H-1");
        assert!(saved.is_file());
        // The next pass is reseeded from the queue, and the manifest is gone:
        // only the saved index can say where `seed1` came from.
        std::fs::remove_file(work.path().join("auto/seeds.json")).unwrap();
        let second = start(work.path(), &[], &[b"A", b"seed1"]);
        let finding = second.of(
            b"seed1X",
            InputParents::Mutated {
                base: 1,
                donor: None,
            },
        );
        assert_eq!(finding.origin, LineageOrigin::MinedSeed);
        assert_eq!(finding.root_path.as_deref(), Some("/tree/seed.bin"));
        assert_eq!(finding.depth, Some(2));
        // A seed the manifest lists outranks an older record of the same bytes.
        write_manifest(work.path(), b"seed1", "/tree/seed1.bin", "user");
        let third = start(work.path(), &[], &[b"seed1"]);
        let direct = third.of(b"seed1", InputParents::Queued(0));
        assert_eq!(
            (direct.origin, direct.depth),
            (LineageOrigin::UserSeed, Some(0))
        );
    }

    /// A pass reads every record before it trims to its cap, so the chain
    /// its pool needs survives however the file sorts, and what it writes
    /// back holds that chain within the cap.
    #[test]
    fn a_small_record_cap_keeps_the_chain_the_pool_needs() {
        let work = tempfile::tempdir().unwrap();
        let path = corpus::lineage::index_path(work.path(), "H-1");
        // Ten records, written in sha256 order; the pool's entry and its
        // root sort last.
        let mut inputs: Vec<Vec<u8>> = (0..10)
            .map(|n| format!("record-{n}").into_bytes())
            .collect();
        inputs.sort_by_key(|input| digest(input));
        let (entry, root) = (inputs[8].clone(), inputs[9].clone());
        let mut index = LineageIndex::new();
        for other in &inputs[..8] {
            index.insert(digest(other), Entry::Root(Origin::Generated));
        }
        index.insert(
            digest(&root),
            Entry::Root(Origin::Seed(SeedOrigin {
                source: Some(SeedSource::User),
                path: Some("/seeds/root.bin".to_owned()),
                ..SeedOrigin::default()
            })),
        );
        index.insert(
            digest(&entry),
            Entry::Child {
                parent: digest(&root),
                donor: None,
            },
        );
        index.save(&path, &[], MAX_LINEAGE_RECORDS).unwrap();
        // The entry is in the queue, so a lost record would make it a corpus
        // root.
        let queue = work.path().join("corpus/H-1/queue");
        std::fs::create_dir_all(&queue).unwrap();
        std::fs::write(queue.join(format!("{}.bin", hex(&digest(&entry)))), &entry).unwrap();

        let lineage = QueueLineage::start(work.path(), "H-1", &[], None, seeds(&[&entry]), 4);
        let found = lineage.of(&entry, InputParents::Queued(0));
        assert_eq!(found.origin, LineageOrigin::UserSeed, "{found:?}");
        assert_eq!(found.root_path.as_deref(), Some("/seeds/root.bin"));
        assert_eq!(found.depth, Some(1));
        lineage.persist();
        let back = LineageIndex::load(&path, MAX_LINEAGE_RECORDS).unwrap();
        assert_eq!(back.len(), 4, "trimmed to the cap");
        assert_eq!(back.resolve(&digest(&entry)).depth, Some(1));
    }

    #[test]
    fn the_mutation_kind_decides_the_parents() {
        assert_eq!(
            InputParents::from_mutation(2, 3, Some(MutationKind::BitFlip)),
            InputParents::Mutated {
                base: 2,
                donor: None
            }
        );
        assert_eq!(
            InputParents::from_mutation(2, 3, Some(MutationKind::Splice)),
            InputParents::Mutated {
                base: 2,
                donor: Some(3)
            }
        );
        assert_eq!(
            InputParents::from_mutation(2, 3, Some(MutationKind::StructuredJson)),
            InputParents::Generated
        );
        assert_eq!(
            InputParents::from_mutation(2, 3, None),
            InputParents::Generated
        );
    }

    /// A libFuzzer-style shell harness (one input per process, like a
    /// `-fsanitize=fuzzer` binary) for `work/build/<id>/main` that reports an
    /// ASan crash when `crashes` (a shell test on the input file `$1`) holds.
    #[cfg(unix)]
    fn write_script_harness(work: &Path, id: &str, crashes: &str) {
        use std::os::unix::fs::PermissionsExt;
        let dir = work.join("build").join(id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("main.c"), "// marker for libFuzzer detection\n").unwrap();
        let main = dir.join("main");
        std::fs::write(
            &main,
            format!(
                "#!/bin/sh\n\
                 if {crashes}; then\n\
                 \x20 >&2 echo 'ERROR: AddressSanitizer: heap-buffer-overflow on address 0x601 at pc 0x333'\n\
                 \x20 >&2 echo '    #0 0x333 in parse_record /src/record.c:15'\n\
                 \x20 >&2 echo '    #1 0x334 in LLVMFuzzerTestOneInput /src/h.c:20'\n\
                 \x20 exit 1\n\
                 fi\n\
                 exit 0\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&main, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    fn fuzz(work: &Path, id: &str, seeds: Vec<Vec<u8>>) -> crate::fuzz::FuzzRunSummary {
        crate::fuzz::run_one_target_programmatic(
            work,
            id,
            seeds,
            64,
            None,
            Some(1),
            0,
            &[],
            actionability::RunMode::Reporting,
            None,
            &[],
            None,
        )
        .unwrap()
    }

    #[cfg(unix)]
    fn finding_lineage(work: &Path, id: &str) -> serde_json::Value {
        let record: serde_json::Value = serde_json::from_slice(
            &std::fs::read(corpus::layout::finding_dir(work, id).join("finding.json")).unwrap(),
        )
        .unwrap();
        record["lineage"].clone()
    }

    /// The in-process loop records what each finding's input was mutated
    /// from. Pass 1 keeps the listed seed in the queue and its record beside
    /// it; pass 2 is reseeded from that queue with the seed list gone, and
    /// its finding, a mutation of the reseeded entry, still names the seed.
    #[test]
    #[cfg(unix)]
    fn a_finding_mutated_from_a_reseeded_seed_names_the_seed_after_a_rerun() {
        let work = tempfile::tempdir().unwrap();
        let work = work.path();
        let seed = b"LINEAGE-SEED".to_vec();
        write_manifest(work, &seed, "/tree/tests/data/lineage.bin", "mined");
        write_script_harness(work, "H-LIN", "false");
        let first = fuzz(work, "H-LIN", vec![seed.clone()]);
        assert!(first.findings.is_empty());
        assert!(corpus::lineage::index_path(work, "H-LIN").is_file());

        std::fs::remove_file(work.join("auto/seeds.json")).unwrap();
        let seed_file = work.join("seed.bin");
        std::fs::write(&seed_file, &seed).unwrap();
        write_script_harness(
            work,
            "H-LIN",
            &format!(
                "[ \"$(head -c 7 \"$1\")\" = LINEAGE ] && ! cmp -s \"$1\" '{}'",
                seed_file.display()
            ),
        );
        let mut reseeded = Vec::new();
        crate::auto::attempt::reseed_from_corpus_queue(work, "H-LIN", &mut reseeded, 16);
        assert_eq!(reseeded, std::slice::from_ref(&seed));
        let second = fuzz(work, "H-LIN", reseeded);
        assert_eq!(second.findings.len(), 1, "{second:?}");
        let lineage = finding_lineage(work, &second.findings[0]);
        assert_eq!(lineage["origin"], "mined_seed", "{lineage}");
        assert_eq!(lineage["root_path"], "/tree/tests/data/lineage.bin");
        assert_eq!(lineage["root_sha256"], hex(&digest(&seed)));
        assert_eq!(lineage["parent_sha256"], hex(&digest(&seed)));
        assert_eq!(lineage["depth"], 1, "{lineage}");
    }

    /// A seed that crashes as it is: its finding is the seed, 0 generations
    /// down.
    #[test]
    #[cfg(unix)]
    fn a_finding_on_the_seed_itself_is_zero_generations_from_it() {
        let work = tempfile::tempdir().unwrap();
        let work = work.path();
        let seed = b"CRASH-AS-IS".to_vec();
        write_manifest(work, &seed, "/tree/tests/data/as-is.bin", "user");
        let seed_file = work.join("seed.bin");
        std::fs::write(&seed_file, &seed).unwrap();
        write_script_harness(
            work,
            "H-AS-IS",
            &format!("cmp -s \"$1\" '{}'", seed_file.display()),
        );
        let summary = fuzz(work, "H-AS-IS", vec![b"A".to_vec(), seed.clone()]);
        assert_eq!(summary.findings.len(), 1, "{summary:?}");
        let lineage = finding_lineage(work, &summary.findings[0]);
        assert_eq!(lineage["origin"], "user_seed", "{lineage}");
        assert_eq!(lineage["root_path"], "/tree/tests/data/as-is.bin");
        assert_eq!(lineage["depth"], 0);
        assert!(lineage.get("parent_sha256").is_none(), "{lineage}");
    }

    /// A replay lane names a queue entry it ran by that entry's record, or,
    /// with none, as a corpus root, as a pass reseeded from the queue does;
    /// an input the operator handed a lane as is is a user seed, 0
    /// generations down.
    #[test]
    fn a_replayed_entry_resolves_from_the_index_and_an_operator_input_is_a_user_seed() {
        let work = tempfile::tempdir().unwrap();
        record_child_of_user_seed(work.path(), "H-1", b"SEED", b"CHILD", "/seeds/seed.bin");
        let queue = ReplayedQueue::open(work.path(), "H-1");
        let child = queue.lineage(b"CHILD");
        assert_eq!(child.origin, LineageOrigin::UserSeed, "{child:?}");
        assert_eq!(child.root_path.as_deref(), Some("/seeds/seed.bin"));
        assert_eq!(child.depth, Some(1));
        assert_eq!(child.parent_sha256, Some(hex(&digest(b"SEED"))));
        let unrecorded = queue.lineage(b"NEVER");
        assert_eq!(unrecorded.origin, LineageOrigin::Corpus, "{unrecorded:?}");
        assert_eq!(unrecorded.root_sha256, Some(hex(&digest(b"NEVER"))));
        assert_eq!(unrecorded.depth, Some(0));
        assert!(unrecorded
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("no lineage record")));
        // No index beside the queue: every entry is a corpus root.
        let bare = ReplayedQueue::open(work.path(), "H-2").lineage(b"CHILD");
        assert_eq!(bare.origin, LineageOrigin::Corpus);

        let given = Path::new("/in/given.bin");
        let file = of_operator_input(b"given", Some(given));
        // Named by its absolute path: `C:\in\given.bin` on Windows.
        let absolute = std::path::absolute(given).unwrap().display().to_string();
        assert_eq!(
            (file.origin, file.root_path.as_deref(), file.depth),
            (LineageOrigin::UserSeed, Some(absolute.as_str()), Some(0))
        );
        assert_eq!(file.root_sha256, Some(hex(&digest(b"given"))));
        assert_eq!(file.parent_sha256, None);
        let literal = of_operator_input(b"given", None);
        assert_eq!(
            (literal.origin, literal.root_path),
            (LineageOrigin::UserSeed, None)
        );
        let fallback = of_generated_input(b"");
        assert_eq!(
            (fallback.origin, fallback.depth),
            (LineageOrigin::Generated, Some(0))
        );

        // An entry read back is named by sha256; one that cannot be read
        // back names none, and its lineage says why.
        let entry_file = work.path().join("child.bin");
        std::fs::write(&entry_file, b"CHILD").unwrap();
        let read = queue.entry(&entry_file);
        assert_eq!(read.sha256, Some(hex(&digest(b"CHILD"))));
        assert_eq!(
            read.evidence(),
            Some(serde_json::json!({"key": "input_sha256", "value": hex(&digest(b"CHILD"))}))
        );
        assert_eq!(read.lineage.depth, Some(1));
        let gone = queue.entry(&work.path().join("gone.bin"));
        assert_eq!(gone.sha256, None);
        assert_eq!(gone.evidence(), None);
        assert_eq!(gone.lineage.origin, LineageOrigin::Unknown);
        assert!(gone
            .lineage
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("could not be read again")));

        let mut record = serde_json::json!({"id": "F-0000-aaaaaaaa"});
        insert(&mut record, &file);
        assert_eq!(record["lineage"]["origin"], "user_seed");
        assert_eq!(record["lineage"]["root_path"], absolute.as_str());
        assert_eq!(record["id"], "F-0000-aaaaaaaa");
    }

    #[test]
    fn the_lineage_is_written_into_the_finding() {
        let work = tempfile::tempdir().unwrap();
        let dir = corpus::layout::finding_dir(work.path(), "F-0000-aaaaaaaa");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("finding.json"), br#"{"id": "F-0000-aaaaaaaa"}"#).unwrap();
        record(
            work.path(),
            "F-0000-aaaaaaaa",
            &FindingLineage::unknown("found by AFL++"),
        );
        let record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("finding.json")).unwrap()).unwrap();
        assert_eq!(record["lineage"]["origin"], "unknown");
        assert_eq!(record["lineage"]["reason"], "found by AFL++");
    }
}
