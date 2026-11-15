// SPDX-License-Identifier: Apache-2.0

//! Seed lineage of the coverage queue: which queue entry each retained input
//! was mutated from, back to the input the campaign started from.
//!
//! AFL++ keeps this in its queue file names (`id:000123,src:000045+000067`);
//! libFuzzer keeps none. bhf names queue files by content
//! (`corpus/<harness-id>/queue/<sha256>.bin`) and every reader of `queue/`
//! takes each file there as an input, so the lineage lives beside it in
//! `corpus/<harness-id>/lineage.jsonl`: one JSON line per entry, keyed by the
//! sha256 of its bytes. A line names either the entry's parents (`parent`, the
//! entry its mutation started from, and `donor` for a splice) or, for a root,
//! its `origin`: a `seed` the run was given (with `source` and `path` when
//! the run's seed lists name it), a `corpus` entry reseeded with no record of
//! its own (saved before lineage was kept, or dropped by the record cap), or
//! `generated` (no seed: an empty or built-in start input, or one a generator
//! built from the dictionary).
//!
//! The first record of an input's bytes stays: the same bytes met again (in
//! another pass or worker, or by another mutation) keep it, so the chain is
//! one real derivation of those bytes, not necessarily the latest. Only a
//! seed the run is handed is made a root again.
//!
//! Every writer reads the whole index (up to [`MAX_LINEAGE_RECORDS`]) and
//! writes back at most [`record_cap`] of the larger of the queue's entry
//! limit and the files its queue holds (a multi-worker merge takes the union
//! of the workers' queues, so a shared queue can hold more than the limit),
//! the records its pool and queue need first.
//!
//! A finding's lineage is resolved when it is saved, walking `parent` links
//! to the root with cycle and depth guards, and written into `finding.json`
//! as [`FindingLineage`].

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

/// File name of the lineage index, beside the harness's `queue/` directory.
pub const LINEAGE_FILE: &str = "lineage.jsonl";

/// The hard cap: records an index is read up to, and the most any writer
/// keeps (twice the largest coverage queue bhf keeps for one harness).
pub const MAX_LINEAGE_RECORDS: usize = 2 * 262_144;

/// Records an index keeps for a harness whose queue holds at most
/// `queue_entries`: twice that, within [`MAX_LINEAGE_RECORDS`]. A fuzz pass
/// and a multi-worker merge both trim to it, of the larger of the queue's
/// entry limit and the files it holds.
pub fn record_cap(queue_entries: usize) -> usize {
    queue_entries.saturating_mul(2).min(MAX_LINEAGE_RECORDS)
}

/// Why an entry has no record: it may predate lineage, or the record cap may
/// have dropped it.
const NO_RECORD: &str =
    "no lineage record (saved before lineage was kept, or dropped by the record cap)";

/// Generations a chain is walked before its lineage is reported unknown.
pub const MAX_LINEAGE_DEPTH: usize = 100_000;

/// Longest line read from an index; a longer one is skipped.
const MAX_LINE_BYTES: usize = 8 * 1024;

/// Longest seed path kept in a record.
const MAX_PATH_CHARS: usize = 4096;

/// Hex digits of a sha256 shown in reasons.
const SHORT_HEX: usize = 12;

/// sha256 of an input's bytes: the key of its record.
pub type Digest = [u8; 32];

pub fn digest(bytes: &[u8]) -> Digest {
    Sha256::digest(bytes).into()
}

pub fn hex(id: &Digest) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A lowercase 64-digit hex sha256, as the index and `finding.json` spell it.
pub fn parse_hex(text: &str) -> Option<Digest> {
    if text.len() != 64 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn short(id: &Digest) -> String {
    hex(id)[..SHORT_HEX].to_owned()
}

/// `<work>/corpus/<harness-id>/lineage.jsonl`.
pub fn index_path(work_dir: &Path, harness_id: &str) -> PathBuf {
    work_dir.join("corpus").join(harness_id).join(LINEAGE_FILE)
}

/// Who supplied a seed, as the run's seed manifest says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeedSource {
    /// Harvested from the tree's own test data.
    Mined,
    /// Given by the operator (`--seed-file`, `--seed-dir`, `--seed-input`).
    User,
}

/// A root that is a seed the run was given.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SeedOrigin {
    /// `None` when no seed list of the run names it.
    pub source: Option<SeedSource>,
    pub path: Option<String>,
    /// The entry is the seed behind this many zero bytes (the harness decodes
    /// fixed-width parameters before its buffer).
    pub layout_prefix: Option<usize>,
    /// sha256 of the seed itself, when it differs from the entry's (a
    /// layout-prefixed copy).
    pub seed_sha256: Option<Digest>,
}

/// Where a root entry came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    Seed(SeedOrigin),
    /// A queue entry, reseeded or replayed, with no record of its own.
    Corpus,
    /// No seed: an empty or built-in start input, or one a generator built.
    Generated,
}

/// One queue entry's record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Root(Origin),
    /// Mutated from `parent`; a splice also took bytes from `donor`.
    Child {
        parent: Digest,
        donor: Option<Digest>,
    },
}

/// What a finding's lineage starts from, as `finding.json` spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LineageOrigin {
    MinedSeed,
    UserSeed,
    /// A start input no seed list of the run names.
    Seed,
    /// A reseeded corpus entry whose own ancestry was not recorded.
    Corpus,
    Generated,
    Unknown,
}

/// `finding.json` `lineage`: what the finding's input descends from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingLineage {
    pub origin: LineageOrigin,
    /// sha256 of the root: the seed's own (as `auto/seeds.json` lists it) for
    /// a seed, else the root queue entry's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_path: Option<String>,
    /// The root entry was the seed behind this many zero bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layout_prefix: Option<usize>,
    /// Mutation generations from the root: 0 when the input is the root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depth: Option<usize>,
    /// The queue entry the input's last mutation started from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_sha256: Option<String>,
    /// The entry a splice took its second part from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub donor_sha256: Option<String>,
    /// Why the lineage is unknown or stops short of a seed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl FindingLineage {
    /// Lineage bhf does not know: `reason` says why. Nothing is guessed.
    pub fn unknown(reason: impl Into<String>) -> Self {
        Self {
            origin: LineageOrigin::Unknown,
            root_sha256: None,
            root_path: None,
            layout_prefix: None,
            depth: None,
            parent_sha256: None,
            donor_sha256: None,
            reason: Some(reason.into()),
        }
    }
}

/// The lineage records of one harness's queue.
#[derive(Debug, Default, Clone)]
pub struct LineageIndex {
    entries: HashMap<Digest, Entry>,
}

impl LineageIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, id: &Digest) -> Option<&Entry> {
        self.entries.get(id)
    }

    /// Record `id` unless it already has a record: the first record of an
    /// input stays (an input met again later is no younger). A child naming
    /// itself as its parent is refused. Returns whether it was recorded.
    pub fn insert(&mut self, id: Digest, entry: Entry) -> bool {
        let Some(entry) = normalized(&id, entry) else {
            return false;
        };
        match self.entries.entry(id) {
            std::collections::hash_map::Entry::Occupied(_) => false,
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(entry);
                true
            }
        }
    }

    /// Record `id` as a root, replacing whatever record it had: an input the
    /// run was handed as a seed starts there, whatever made it before.
    pub fn set_root(&mut self, id: Digest, origin: Origin) {
        self.entries.insert(id, Entry::Root(origin));
    }

    /// Add every record of `other` that this index lacks.
    pub fn absorb(&mut self, other: LineageIndex) {
        for (id, entry) in other.entries {
            self.insert(id, entry);
        }
    }

    /// The lineage of the recorded input `id`.
    pub fn resolve(&self, id: &Digest) -> FindingLineage {
        match self.entries.get(id) {
            Some(entry) => self.resolve_entry(id, entry),
            None => {
                FindingLineage::unknown(format!("the input {} has no lineage record", short(id)))
            }
        }
    }

    /// The lineage of input `id` whose own record is `entry` (recorded or
    /// not).
    pub fn resolve_entry(&self, id: &Digest, entry: &Entry) -> FindingLineage {
        let (parent, donor) = match entry {
            Entry::Child { parent, donor } => (Some(*parent), *donor),
            Entry::Root(_) => (None, None),
        };
        let unknown = |reason: String| FindingLineage {
            parent_sha256: parent.as_ref().map(hex),
            donor_sha256: donor.as_ref().map(hex),
            ..FindingLineage::unknown(reason)
        };
        let mut seen = HashSet::from([*id]);
        let mut current_id = *id;
        let mut current = entry;
        let mut depth = 0usize;
        loop {
            let next = match current {
                Entry::Root(origin) => {
                    let mut lineage = root_lineage(&current_id, origin);
                    lineage.depth = Some(depth);
                    lineage.parent_sha256 = parent.as_ref().map(hex);
                    lineage.donor_sha256 = donor.as_ref().map(hex);
                    return lineage;
                }
                Entry::Child { parent, .. } => *parent,
            };
            if depth >= MAX_LINEAGE_DEPTH {
                return unknown(format!(
                    "the recorded chain is longer than {MAX_LINEAGE_DEPTH} mutation generations"
                ));
            }
            if !seen.insert(next) {
                return unknown(format!(
                    "the recorded lineage loops back to queue entry {}",
                    short(&next)
                ));
            }
            depth += 1;
            match self.entries.get(&next) {
                Some(entry) => {
                    current_id = next;
                    current = entry;
                }
                None => return unknown(format!("queue entry {} has {NO_RECORD}", short(&next))),
            }
        }
    }

    /// Read an index, keeping at most `max_records` well-formed records. A
    /// missing file is an empty index; malformed or overlong lines are
    /// skipped. Records past `max_records` are not read at all, so a writer
    /// reads with [`MAX_LINEAGE_RECORDS`] and trims with [`Self::save`],
    /// which knows what it must keep.
    pub fn load(path: &Path, max_records: usize) -> io::Result<Self> {
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Self::new()),
            Err(error) => return Err(error),
        };
        let mut reader = io::BufReader::new(file);
        let mut index = Self::new();
        let mut line = Vec::new();
        while index.len() < max_records {
            let Some(fits) = next_line(&mut reader, &mut line)? else {
                break;
            };
            if !fits {
                continue;
            }
            let Ok(record) = serde_json::from_slice::<Line>(&line) else {
                continue;
            };
            if let Some((id, entry)) = record.into_entry() {
                index.insert(id, entry);
            }
        }
        Ok(index)
    }

    /// Write the index atomically. Over `max_records`, the records `keep`
    /// needs (they and their ancestors) are written first and the rest in
    /// sha256 order up to the cap. Returns the records written.
    pub fn save(&self, path: &Path, keep: &[Digest], max_records: usize) -> io::Result<usize> {
        let mut chosen: BTreeMap<Digest, &Entry> = BTreeMap::new();
        if self.entries.len() > max_records {
            let mut pending: Vec<Digest> = keep.to_vec();
            while let Some(id) = pending.pop() {
                if chosen.len() >= max_records || chosen.contains_key(&id) {
                    continue;
                }
                let Some(entry) = self.entries.get(&id) else {
                    continue;
                };
                chosen.insert(id, entry);
                if let Entry::Child { parent, donor } = entry {
                    pending.extend(donor.iter().copied());
                    pending.push(*parent);
                }
            }
            let mut rest: Vec<(&Digest, &Entry)> = self
                .entries
                .iter()
                .filter(|(id, _)| !chosen.contains_key(*id))
                .collect();
            rest.sort_by(|left, right| left.0.cmp(right.0));
            for (id, entry) in rest {
                if chosen.len() >= max_records {
                    break;
                }
                chosen.insert(*id, entry);
            }
        } else {
            chosen.extend(self.entries.iter().map(|(id, entry)| (*id, entry)));
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("jsonl.tmp");
        let mut out = io::BufWriter::new(std::fs::File::create(&tmp)?);
        for (id, entry) in &chosen {
            serde_json::to_writer(&mut out, &Line::from_entry(id, entry))?;
            out.write_all(b"\n")?;
        }
        out.flush()?;
        drop(out);
        std::fs::rename(&tmp, path)?;
        Ok(chosen.len())
    }
}

/// `entry` as `id`'s record: a child naming itself is no record, and a
/// splice donor that is the parent or the input itself adds nothing.
fn normalized(id: &Digest, entry: Entry) -> Option<Entry> {
    match entry {
        Entry::Child { parent, .. } if parent == *id => None,
        Entry::Child { parent, donor } => Some(Entry::Child {
            parent,
            donor: donor.filter(|donor| donor != &parent && donor != id),
        }),
        root => Some(root),
    }
}

fn root_lineage(id: &Digest, origin: &Origin) -> FindingLineage {
    let mut lineage = FindingLineage::unknown(String::new());
    lineage.reason = None;
    lineage.root_sha256 = Some(hex(id));
    match origin {
        Origin::Seed(seed) => {
            lineage.origin = match seed.source {
                Some(SeedSource::Mined) => LineageOrigin::MinedSeed,
                Some(SeedSource::User) => LineageOrigin::UserSeed,
                None => LineageOrigin::Seed,
            };
            if let Some(seed_sha) = &seed.seed_sha256 {
                lineage.root_sha256 = Some(hex(seed_sha));
            }
            lineage.root_path = seed.path.clone();
            lineage.layout_prefix = seed.layout_prefix;
        }
        Origin::Corpus => {
            lineage.origin = LineageOrigin::Corpus;
            lineage.reason = Some(format!(
                "the queue entry it starts from has {NO_RECORD}; what that entry grew from \
                 is unknown"
            ));
        }
        Origin::Generated => lineage.origin = LineageOrigin::Generated,
    }
    lineage
}

/// Read the next line into `line` (without its newline), reading at most
/// [`MAX_LINE_BYTES`] of it into memory. `None` at end of file; `Some(false)`
/// for a line that was too long (skipped).
fn next_line(reader: &mut impl BufRead, line: &mut Vec<u8>) -> io::Result<Option<bool>> {
    line.clear();
    let read = io::Read::take(&mut *reader, MAX_LINE_BYTES as u64 + 1).read_until(b'\n', line)?;
    if read == 0 {
        return Ok(None);
    }
    if line.last() == Some(&b'\n') {
        line.pop();
        return Ok(Some(true));
    }
    if line.len() <= MAX_LINE_BYTES {
        // The last line, with no newline after it.
        return Ok(Some(true));
    }
    // Too long: drop the rest of it.
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return Ok(Some(false));
        }
        match buffer.iter().position(|byte| *byte == b'\n') {
            Some(end) => {
                reader.consume(end + 1);
                return Ok(Some(false));
            }
            None => {
                let len = buffer.len();
                reader.consume(len);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LineOrigin {
    Seed,
    Corpus,
    Generated,
}

/// One line of the index.
#[derive(Debug, Serialize, Deserialize)]
struct Line {
    sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    donor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    origin: Option<LineOrigin>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<SeedSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    layout_prefix: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seed_sha256: Option<String>,
}

impl Line {
    fn from_entry(id: &Digest, entry: &Entry) -> Self {
        let mut line = Self {
            sha256: hex(id),
            parent: None,
            donor: None,
            origin: None,
            source: None,
            path: None,
            layout_prefix: None,
            seed_sha256: None,
        };
        match entry {
            Entry::Child { parent, donor } => {
                line.parent = Some(hex(parent));
                line.donor = donor.as_ref().map(hex);
            }
            Entry::Root(Origin::Seed(seed)) => {
                line.origin = Some(LineOrigin::Seed);
                line.source = seed.source;
                line.path = seed.path.clone();
                line.layout_prefix = seed.layout_prefix;
                line.seed_sha256 = seed.seed_sha256.as_ref().map(hex);
            }
            Entry::Root(Origin::Corpus) => line.origin = Some(LineOrigin::Corpus),
            Entry::Root(Origin::Generated) => line.origin = Some(LineOrigin::Generated),
        }
        line
    }

    fn into_entry(self) -> Option<(Digest, Entry)> {
        let id = parse_hex(&self.sha256)?;
        let entry = match (self.parent, self.origin) {
            (Some(parent), None) => Entry::Child {
                parent: parse_hex(&parent)?,
                donor: match self.donor {
                    Some(donor) => Some(parse_hex(&donor)?),
                    None => None,
                },
            },
            (None, Some(LineOrigin::Seed)) => Entry::Root(Origin::Seed(SeedOrigin {
                source: self.source,
                path: match self.path {
                    Some(path) if path.chars().count() > MAX_PATH_CHARS => return None,
                    path => path,
                },
                layout_prefix: self.layout_prefix,
                seed_sha256: match self.seed_sha256 {
                    Some(sha) => Some(parse_hex(&sha)?),
                    None => None,
                },
            })),
            (None, Some(LineOrigin::Corpus)) => Entry::Root(Origin::Corpus),
            (None, Some(LineOrigin::Generated)) => Entry::Root(Origin::Generated),
            _ => return None,
        };
        Some((id, entry))
    }
}

/// Write `lineage` into `<finding_dir>/finding.json`.
pub fn record_in_finding(finding_dir: &Path, lineage: &FindingLineage) -> io::Result<()> {
    let path = finding_dir.join("finding.json");
    let mut record: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    let Some(object) = record.as_object_mut() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not a JSON object", path.display()),
        ));
    };
    object.insert("lineage".to_owned(), serde_json::to_value(lineage)?);
    let tmp = finding_dir.join("finding.json.lineage.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&record)?)?;
    std::fs::rename(&tmp, &path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(tag: &str) -> Digest {
        digest(tag.as_bytes())
    }

    fn child(parent: &str) -> Entry {
        Entry::Child {
            parent: id(parent),
            donor: None,
        }
    }

    fn mined(path: &str) -> Origin {
        Origin::Seed(SeedOrigin {
            source: Some(SeedSource::Mined),
            path: Some(path.to_owned()),
            ..SeedOrigin::default()
        })
    }

    /// seed -> a -> b -> c, with c spliced from b and a.
    fn chain() -> LineageIndex {
        let mut index = LineageIndex::new();
        assert!(index.insert(id("seed"), Entry::Root(mined("/tree/tests/data/x.bin"))));
        assert!(index.insert(id("a"), child("seed")));
        assert!(index.insert(id("b"), child("a")));
        assert!(index.insert(
            id("c"),
            Entry::Child {
                parent: id("b"),
                donor: Some(id("a")),
            }
        ));
        index
    }

    #[test]
    fn a_chain_resolves_to_its_mined_seed_with_its_depth_and_parents() {
        let lineage = chain().resolve(&id("c"));
        assert_eq!(lineage.origin, LineageOrigin::MinedSeed);
        assert_eq!(lineage.root_sha256, Some(hex(&id("seed"))));
        assert_eq!(lineage.root_path.as_deref(), Some("/tree/tests/data/x.bin"));
        assert_eq!(lineage.depth, Some(3));
        assert_eq!(lineage.parent_sha256, Some(hex(&id("b"))));
        assert_eq!(lineage.donor_sha256, Some(hex(&id("a"))));
        assert_eq!(lineage.reason, None);
    }

    #[test]
    fn a_root_resolves_to_itself_at_depth_zero() {
        let lineage = chain().resolve(&id("seed"));
        assert_eq!(lineage.origin, LineageOrigin::MinedSeed);
        assert_eq!(lineage.depth, Some(0));
        assert_eq!(lineage.parent_sha256, None);
        assert_eq!(lineage.root_sha256, Some(hex(&id("seed"))));
    }

    #[test]
    fn every_root_kind_names_its_origin() {
        let mut index = LineageIndex::new();
        index.insert(
            id("user"),
            Entry::Root(Origin::Seed(SeedOrigin {
                source: Some(SeedSource::User),
                path: Some("/seeds/one.bin".to_owned()),
                ..SeedOrigin::default()
            })),
        );
        index.insert(
            id("unlisted"),
            Entry::Root(Origin::Seed(SeedOrigin::default())),
        );
        index.insert(id("generated"), Entry::Root(Origin::Generated));
        index.insert(id("corpus"), Entry::Root(Origin::Corpus));
        let seed = id("seed");
        index.insert(
            id("prefixed"),
            Entry::Root(Origin::Seed(SeedOrigin {
                source: Some(SeedSource::Mined),
                path: Some("/tree/x.bin".to_owned()),
                layout_prefix: Some(8),
                seed_sha256: Some(seed),
            })),
        );
        for (tag, root) in ["user", "unlisted", "generated", "corpus", "prefixed"]
            .iter()
            .enumerate()
        {
            let name = format!("child-{tag}");
            index.insert(id(&name), child(root));
        }

        let user = index.resolve(&id("child-0"));
        assert_eq!(
            (user.origin, user.root_path.as_deref(), user.depth),
            (LineageOrigin::UserSeed, Some("/seeds/one.bin"), Some(1))
        );
        let unlisted = index.resolve(&id("child-1"));
        assert_eq!(
            (unlisted.origin, unlisted.root_path),
            (LineageOrigin::Seed, None)
        );
        assert_eq!(unlisted.root_sha256, Some(hex(&id("unlisted"))));
        let generated = index.resolve(&id("child-2"));
        assert_eq!(
            (generated.origin, generated.depth),
            (LineageOrigin::Generated, Some(1))
        );
        // A reseeded entry with no record of its own: known up to it, and the
        // reason says the rest is not.
        let corpus = index.resolve(&id("child-3"));
        assert_eq!(corpus.origin, LineageOrigin::Corpus);
        assert_eq!(corpus.root_sha256, Some(hex(&id("corpus"))));
        assert_eq!(corpus.depth, Some(1));
        assert!(corpus
            .reason
            .as_deref()
            .unwrap()
            .contains("no lineage record"));
        // A layout-prefixed copy names the seed's own sha256 and the prefix.
        let prefixed = index.resolve(&id("child-4"));
        assert_eq!(prefixed.origin, LineageOrigin::MinedSeed);
        assert_eq!(prefixed.root_sha256, Some(hex(&seed)));
        assert_eq!(prefixed.layout_prefix, Some(8));
    }

    #[test]
    fn a_missing_ancestor_makes_the_lineage_unknown_and_says_which() {
        let mut index = LineageIndex::new();
        index.insert(id("orphan"), child("gone"));
        let lineage = index.resolve(&id("orphan"));
        assert_eq!(lineage.origin, LineageOrigin::Unknown);
        assert_eq!(lineage.depth, None);
        assert_eq!(lineage.root_sha256, None);
        // The immediate parent is still known.
        assert_eq!(lineage.parent_sha256, Some(hex(&id("gone"))));
        let reason = lineage.reason.unwrap();
        assert!(reason.contains(&hex(&id("gone"))[..12]), "{reason}");
        assert!(reason.contains("no lineage record"), "{reason}");
        // An input with no record at all.
        let none = index.resolve(&id("never"));
        assert_eq!(none.origin, LineageOrigin::Unknown);
        assert!(none.reason.is_some());
    }

    #[test]
    fn a_cycle_is_reported_not_walked_forever() {
        let mut index = LineageIndex::new();
        index.insert(id("x"), child("y"));
        index.insert(id("y"), child("x"));
        let lineage = index.resolve(&id("x"));
        assert_eq!(lineage.origin, LineageOrigin::Unknown);
        assert!(lineage.reason.unwrap().contains("loops"));
        // A child naming itself is never recorded.
        assert!(!index.insert(id("self"), child("self")));
        assert!(index.get(&id("self")).is_none());
    }

    #[test]
    fn a_chain_deeper_than_the_guard_is_unknown() {
        let mut index = LineageIndex::new();
        index.insert(id("0"), Entry::Root(Origin::Generated));
        for n in 1..=MAX_LINEAGE_DEPTH + 1 {
            index.insert(id(&n.to_string()), child(&(n - 1).to_string()));
        }
        let deep = index.resolve(&id(&(MAX_LINEAGE_DEPTH + 1).to_string()));
        assert_eq!(deep.origin, LineageOrigin::Unknown);
        assert!(deep.reason.unwrap().contains("generations"));
        let at_limit = index.resolve(&id(&MAX_LINEAGE_DEPTH.to_string()));
        assert_eq!(at_limit.depth, Some(MAX_LINEAGE_DEPTH));
    }

    #[test]
    fn the_first_record_of_an_input_stays_but_a_seed_root_replaces_it() {
        let mut index = chain();
        assert!(!index.insert(id("a"), child("c")), "a is already recorded");
        assert_eq!(index.get(&id("a")), Some(&child("seed")));
        // The run is handed `b` as a seed: it starts there.
        index.set_root(id("b"), mined("/tree/b.bin"));
        let lineage = index.resolve(&id("c"));
        assert_eq!(lineage.root_path.as_deref(), Some("/tree/b.bin"));
        assert_eq!(lineage.depth, Some(1));
    }

    #[test]
    fn a_splice_with_itself_records_no_donor() {
        let mut index = chain();
        index.insert(
            id("d"),
            Entry::Child {
                parent: id("c"),
                donor: Some(id("c")),
            },
        );
        assert_eq!(index.get(&id("d")), Some(&child("c")));
    }

    #[test]
    fn an_unrecorded_input_resolves_through_its_own_entry() {
        let index = chain();
        let lineage = index.resolve_entry(&id("new"), &child("c"));
        assert_eq!(lineage.depth, Some(4));
        assert_eq!(lineage.parent_sha256, Some(hex(&id("c"))));
        let generated = index.resolve_entry(&id("new"), &Entry::Root(Origin::Generated));
        assert_eq!(generated.origin, LineageOrigin::Generated);
        assert_eq!(generated.depth, Some(0));
    }

    #[test]
    fn a_saved_index_reloads_and_still_resolves() {
        let dir = tempfile::tempdir().unwrap();
        let path = index_path(dir.path(), "H-1");
        let mut index = chain();
        index.insert(id("gen"), Entry::Root(Origin::Generated));
        index.insert(id("old"), Entry::Root(Origin::Corpus));
        index.insert(
            id("prefixed"),
            Entry::Root(Origin::Seed(SeedOrigin {
                source: Some(SeedSource::User),
                path: Some("/s/x.bin".to_owned()),
                layout_prefix: Some(4),
                seed_sha256: Some(id("seed")),
            })),
        );
        assert_eq!(index.save(&path, &[], MAX_LINEAGE_RECORDS).unwrap(), 7);
        let back = LineageIndex::load(&path, MAX_LINEAGE_RECORDS).unwrap();
        assert_eq!(back.len(), 7);
        for tag in ["seed", "a", "b", "c", "gen", "old", "prefixed"] {
            assert_eq!(back.get(&id(tag)), index.get(&id(tag)), "{tag}");
        }
        assert_eq!(back.resolve(&id("c")), index.resolve(&id("c")));
        // One line per record, nothing left beside it.
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 7);
        let names: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, [LINEAGE_FILE]);
    }

    #[test]
    fn a_missing_index_loads_empty_and_bad_lines_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(LINEAGE_FILE);
        assert!(LineageIndex::load(&path, 10).unwrap().is_empty());
        let good = hex(&id("good"));
        let parent = hex(&id("parent"));
        let long_path = "p".repeat(MAX_LINE_BYTES * 2);
        std::fs::write(
            &path,
            format!(
                "not json\n\
                 {{\"sha256\":\"XYZ\",\"origin\":\"generated\"}}\n\
                 {{\"sha256\":\"{good}\"}}\n\
                 {{\"sha256\":\"{good}\",\"origin\":\"seed\",\"path\":\"{long_path}\"}}\n\
                 {{\"sha256\":\"{good}\",\"parent\":\"{good}\"}}\n\
                 {{\"sha256\":\"{good}\",\"parent\":\"{parent}\",\"origin\":\"generated\"}}\n\
                 {{\"sha256\":\"{good}\",\"parent\":\"{parent}\",\"future_key\":1}}\n"
            ),
        )
        .unwrap();
        let index = LineageIndex::load(&path, 10).unwrap();
        assert_eq!(index.len(), 1, "only the last line is a usable record");
        assert_eq!(index.get(&id("good")), Some(&child("parent")));
    }

    #[test]
    fn load_and_save_respect_the_record_cap_and_keep_what_is_needed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(LINEAGE_FILE);
        let mut index = chain();
        for n in 0..20 {
            index.insert(id(&format!("extra-{n}")), Entry::Root(Origin::Generated));
        }
        let written = index.save(&path, &[id("c")], 4).unwrap();
        assert_eq!(written, 4);
        let back = LineageIndex::load(&path, 100).unwrap();
        assert_eq!(back.resolve(&id("c")).depth, Some(3), "c's chain was kept");
        index.save(&path, &[], 100).unwrap();
        assert_eq!(LineageIndex::load(&path, 5).unwrap().len(), 5);
    }

    /// An entry with no record may be one the record cap dropped, not only
    /// one saved before lineage was kept, and the reason says both.
    #[test]
    fn a_missing_record_may_have_been_dropped_by_the_cap_and_the_reason_says_so() {
        let mut index = LineageIndex::new();
        index.insert(id("corpus"), Entry::Root(Origin::Corpus));
        index.insert(id("child"), child("corpus"));
        index.insert(id("orphan"), child("gone"));
        for tag in ["corpus", "child", "orphan"] {
            let reason = index.resolve(&id(tag)).reason.unwrap();
            assert!(
                reason.contains(
                    "no lineage record (saved before lineage was kept, or dropped by the \
                     record cap)"
                ),
                "{tag}: {reason}"
            );
            assert!(!reason.contains("saved without lineage"), "{tag}: {reason}");
        }
    }

    /// One cap for every writer: twice the queue's entry limit, never past
    /// the hard cap.
    #[test]
    fn the_record_cap_is_twice_the_queue_limit_within_the_hard_cap() {
        assert_eq!(record_cap(2), 4);
        assert_eq!(record_cap(4096), 8192);
        assert_eq!(record_cap(0), 0);
        assert_eq!(record_cap(usize::MAX), MAX_LINEAGE_RECORDS);
        assert_eq!(record_cap(MAX_LINEAGE_RECORDS), MAX_LINEAGE_RECORDS);
    }

    #[test]
    fn absorbing_another_index_keeps_existing_records() {
        let mut parent = LineageIndex::new();
        parent.insert(id("a"), Entry::Root(Origin::Generated));
        let mut worker = chain();
        worker.insert(id("w"), child("c"));
        parent.absorb(worker);
        assert_eq!(parent.get(&id("a")), Some(&Entry::Root(Origin::Generated)));
        assert_eq!(parent.get(&id("w")), Some(&child("c")));
        assert_eq!(parent.resolve(&id("w")).depth, Some(3));
    }

    #[test]
    fn the_lineage_lands_in_finding_json_beside_what_is_there() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("finding.json"),
            br#"{"id": "F-0000-aaaa", "rule_id": "BHF-201"}"#,
        )
        .unwrap();
        record_in_finding(dir.path(), &chain().resolve(&id("c"))).unwrap();
        let record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("finding.json")).unwrap())
                .unwrap();
        assert_eq!(record["id"], "F-0000-aaaa");
        assert_eq!(record["lineage"]["origin"], "mined_seed");
        assert_eq!(record["lineage"]["depth"], 3);
        assert_eq!(record["lineage"]["root_path"], "/tree/tests/data/x.bin");
        assert!(record["lineage"].get("reason").is_none());
        let unknown = FindingLineage::unknown("found by another engine");
        record_in_finding(dir.path(), &unknown).unwrap();
        let record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("finding.json")).unwrap())
                .unwrap();
        assert_eq!(
            record["lineage"],
            serde_json::json!({"origin": "unknown", "reason": "found by another engine"})
        );
    }
}
