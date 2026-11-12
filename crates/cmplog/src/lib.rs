// SPDX-License-Identifier: Apache-2.0

//! CmpLog / RedQueen-style magic-byte extraction scaffold.
//!
//! Tracks issue #294. v0.1 ships the data model + entry-point fn
//! signatures; the real instrumentation pass (LD_PRELOAD-style
//! intercepts of memcmp/strcmp/Ada.Strings.Equals plus an
//! offset-matching splicer) lands behind the `cmplog-runtime`
//! feature in a follow-up.

/// Set in a [`CmpEntry::site_id`] whose record named no site (a log line
/// without `"s"`): the low bits are then only the record's position.
pub const UNKNOWN_SITE: u64 = 1 << 63;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmpEntry {
    /// Identifier of the comparison site (PC value or AST node id), or
    /// [`UNKNOWN_SITE`] plus the record's position when none was recorded.
    pub site_id: u64,
    pub operand_a: Vec<u8>,
    pub operand_b: Vec<u8>,
    pub kind: CmpKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpKind {
    /// `memcmp` / `Ada.Strings.Equals` etc. — full-buffer equality.
    BufferEquality,
    /// `strcmp` — NUL-terminated equality.
    CStringEquality,
    /// Integer comparison via `cmp` instruction.
    IntegerCompare,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CmpLog {
    pub entries: Vec<CmpEntry>,
}

impl CmpLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, entry: CmpEntry) {
        self.entries.push(entry);
    }

    /// Return every unique operand byte sequence observed across
    /// the recorded cmp entries. Useful for feeding the fuzz
    /// engine's `Dictionary::from_tokens` — every magic-byte
    /// comparison the target performed becomes a candidate
    /// dictionary insertion. Empty operands and exact duplicates
    /// are filtered.
    pub fn dictionary_tokens(&self) -> Vec<Vec<u8>> {
        use std::collections::HashSet;
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        let mut out: Vec<Vec<u8>> = Vec::new();
        for entry in &self.entries {
            for operand in [&entry.operand_a, &entry.operand_b] {
                if operand.is_empty() {
                    continue;
                }
                if seen.insert(operand.clone()) {
                    out.push(operand.clone());
                }
            }
        }
        out
    }

    /// The operands that are comparison constants rather than input. At a
    /// site (the entries of one `site_id` and kind), a constant is an operand
    /// that met at least two distinct values, and more of them than any of
    /// those values met there: a constant is compared with input after input,
    /// while each input meets only the few constants it is checked against
    /// (one at a plain check, every entry of a keyword table at a lookup).
    /// When neither side has met more, neither counts. Entries with an
    /// [`UNKNOWN_SITE`] (the runtrace shim's, an older driver's) cannot tell
    /// one site from another, so they only confirm tokens of `known` (the
    /// harness's mined dictionary); any operand `known` lists is kept.
    /// Strongest evidence first (most distinct values compared against);
    /// a token that is a one-byte edit of a token kept with more evidence is
    /// dropped. A fuzz run compares a constant with many mutated inputs, so
    /// every operand of every record ([`CmpLog::dictionary_tokens`]) is
    /// mostly input fragments.
    pub fn constant_operands(&self, known: &[Vec<u8>]) -> Vec<Vec<u8>> {
        use std::collections::{BTreeMap, BTreeSet};
        let kind_code = |kind: CmpKind| match kind {
            CmpKind::BufferEquality => 0u8,
            CmpKind::CStringEquality => 1,
            CmpKind::IntegerCompare => 2,
        };
        // Per site, the distinct values each operand was compared with.
        type Partners<'a> = BTreeMap<&'a [u8], BTreeSet<&'a [u8]>>;
        let mut sites: BTreeMap<(u64, u8), Partners<'_>> = BTreeMap::new();
        let mut first_seen: BTreeMap<&[u8], usize> = BTreeMap::new();
        for (index, entry) in self.entries.iter().enumerate() {
            let (a, b) = (entry.operand_a.as_slice(), entry.operand_b.as_slice());
            for operand in [a, b] {
                first_seen.entry(operand).or_insert(index);
            }
            // An input equal to the constant says nothing about which is which.
            if entry.site_id & UNKNOWN_SITE != 0 || a == b {
                continue;
            }
            let partners = sites
                .entry((entry.site_id, kind_code(entry.kind)))
                .or_default();
            partners.entry(a).or_default().insert(b);
            partners.entry(b).or_default().insert(a);
        }
        // Each constant with the number of distinct operands it met.
        let mut evidence: BTreeMap<&[u8], usize> = BTreeMap::new();
        for partners in sites.values() {
            for (value, met) in partners {
                let most_met_by_a_partner = met
                    .iter()
                    .map(|other| partners.get(other).map_or(0, BTreeSet::len))
                    .max()
                    .unwrap_or(0);
                if met.len() >= 2 && met.len() > most_met_by_a_partner {
                    let count = evidence.entry(*value).or_default();
                    *count = (*count).max(met.len());
                }
            }
        }
        let known: BTreeSet<&[u8]> = known.iter().map(Vec::as_slice).collect();
        for value in first_seen.keys() {
            if known.contains(value) {
                evidence.entry(*value).or_insert(1);
            }
        }
        let mut ranked: Vec<(&[u8], usize)> = evidence
            .iter()
            .map(|(value, count)| (*value, *count))
            .collect();
        ranked.retain(|(value, _)| !value.is_empty());
        ranked.sort_by_key(|(value, count)| {
            (
                std::cmp::Reverse(*count),
                first_seen.get(value).copied().unwrap_or(usize::MAX),
            )
        });
        let mut out: Vec<(Vec<u8>, usize)> = Vec::new();
        for (value, count) in ranked {
            let variant = out
                .iter()
                .any(|(kept, kept_count)| *kept_count > count && one_byte_edit(kept, value));
            if !variant && !out.iter().any(|(kept, _)| kept == value) {
                out.push((value.to_vec(), count));
            }
        }
        out.into_iter().map(|(value, _)| value).collect()
    }

    /// Extract candidate splices: for each entry, if `input`
    /// contains `operand_a` at some offset, yield a candidate
    /// mutation replacing that occurrence with `operand_b` (and
    /// vice versa). Used by the builtin engine's mutator to
    /// learn magic-byte expectations from runtime evidence.
    pub fn splice_candidates(&self, input: &[u8]) -> Vec<SpliceCandidate> {
        let mut out = Vec::new();
        for entry in &self.entries {
            for (src, dst) in [
                (&entry.operand_a, &entry.operand_b),
                (&entry.operand_b, &entry.operand_a),
            ] {
                if src.is_empty() {
                    continue;
                }
                let mut search_from = 0usize;
                while let Some(pos) = find_subslice(&input[search_from..], src) {
                    let absolute = search_from + pos;
                    out.push(SpliceCandidate {
                        site_id: entry.site_id,
                        offset: absolute,
                        replacement: dst.clone(),
                        original_len: src.len(),
                    });
                    search_from = absolute + 1;
                }
            }
        }
        out
    }
}

/// Whether `a` and `b` differ by exactly one byte substituted, inserted or
/// removed.
pub fn one_byte_edit(a: &[u8], b: &[u8]) -> bool {
    let (short, long) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    match long.len() - short.len() {
        0 => short.iter().zip(long).filter(|(x, y)| x != y).count() == 1,
        1 => {
            let prefix = short.iter().zip(long).take_while(|(x, y)| x == y).count();
            short[prefix..] == long[prefix + 1..]
        }
        _ => false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpliceCandidate {
    pub site_id: u64,
    pub offset: usize,
    pub replacement: Vec<u8>,
    pub original_len: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum CmpLogError {
    #[error("I/O error reading cmplog log: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid hex in cmplog operand")]
    BadHex,
}

/// Ingest a CmpLog from the JSONL audit log produced by the
/// runtrace_shim's `cmplog` hook. Each `{"e":"cmplog","k":...,
/// "a":"<hex>","b":"<hex>"}` event becomes one `CmpEntry`. The shim
/// keys every audit event by `"e"` (see
/// `bhf_runtrace_shim::jsonl::Builder`), so cmplog records are
/// matched on `"e" == "cmplog"`. Lines that aren't valid JSON or
/// don't carry the cmplog category are silently skipped.
pub fn ingest_from_jsonl_log(path: &std::path::Path) -> Result<CmpLog, CmpLogError> {
    let bytes = std::fs::read(path)?;
    let mut log = CmpLog::new();
    for (line_no, line) in bytes.split(|b| *b == b'\n').enumerate() {
        if line.is_empty() {
            continue;
        }
        let value: serde_json::Value = match serde_json::from_slice(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Some(category) = value.get("e").and_then(|v| v.as_str()) else {
            continue;
        };
        if category != "cmplog" {
            continue;
        }
        let kind = match value.get("k").and_then(|v| v.as_str()).unwrap_or("") {
            "strcmp" | "strncmp" => CmpKind::CStringEquality,
            _ => CmpKind::BufferEquality,
        };
        let a_hex = value.get("a").and_then(|v| v.as_str()).unwrap_or("");
        let b_hex = value.get("b").and_then(|v| v.as_str()).unwrap_or("");
        let operand_a = hex_decode(a_hex).ok_or(CmpLogError::BadHex)?;
        let operand_b = hex_decode(b_hex).ok_or(CmpLogError::BadHex)?;
        // `"s"` names the comparison's site; without it, the record's line.
        let site_id = match value.get("s").and_then(|v| v.as_str()) {
            Some(site) => {
                let mut hash = 0xcbf2_9ce4_8422_2325u64;
                for byte in site.bytes() {
                    hash = (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3);
                }
                hash & !UNKNOWN_SITE
            }
            None => UNKNOWN_SITE | line_no as u64,
        };
        log.record(CmpEntry {
            site_id,
            operand_a,
            operand_b,
            kind,
        });
    }
    Ok(log)
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmplog_records_entries() {
        let mut log = CmpLog::new();
        log.record(CmpEntry {
            site_id: 1,
            operand_a: b"abcd".to_vec(),
            operand_b: b"MAGIC".to_vec(),
            kind: CmpKind::BufferEquality,
        });
        assert_eq!(log.entries.len(), 1);
    }

    #[test]
    fn splice_candidates_finds_operand_in_input() {
        let mut log = CmpLog::new();
        log.record(CmpEntry {
            site_id: 1,
            operand_a: b"abcd".to_vec(),
            operand_b: b"MAGIC".to_vec(),
            kind: CmpKind::BufferEquality,
        });
        let candidates = log.splice_candidates(b"xxabcdyy");
        assert!(!candidates.is_empty());
        let first = &candidates[0];
        assert_eq!(first.offset, 2);
        assert_eq!(first.replacement, b"MAGIC");
        assert_eq!(first.original_len, 4);
    }

    #[test]
    fn splice_candidates_handles_bidirectional() {
        let mut log = CmpLog::new();
        log.record(CmpEntry {
            site_id: 1,
            operand_a: b"in".to_vec(),
            operand_b: b"out".to_vec(),
            kind: CmpKind::CStringEquality,
        });
        let candidates = log.splice_candidates(b"out-of-bounds");
        assert!(candidates.iter().any(|c| c.replacement == b"in"));
    }

    #[test]
    fn ingest_from_jsonl_log_parses_cmplog_events() {
        let dir = std::env::temp_dir().join(format!(
            "bhf-cmplog-ingest-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("audit.jsonl");
        // Real audit-log format: the runtrace shim emits every event (incl.
        // cmplog) keyed by "e" (see bhf_runtrace_shim::jsonl::Builder),
        // NOT "c". Ingest must match what the shim actually produces.
        let jsonl = b"\
{\"e\":\"getenv\",\"n\":\"FOO\"}\n\
{\"e\":\"cmplog\",\"k\":\"memcmp\",\"a\":\"6162\",\"b\":\"4d41\"}\n\
not-json-just-noise\n\
{\"e\":\"cmplog\",\"k\":\"strcmp\",\"a\":\"68656c6c6f\",\"b\":\"776f726c64\"}\n\
";
        std::fs::write(&log_path, jsonl).unwrap();
        let log = ingest_from_jsonl_log(&log_path).unwrap();
        assert_eq!(log.entries.len(), 2);
        assert_eq!(log.entries[0].operand_a, b"ab");
        assert_eq!(log.entries[0].operand_b, b"MA");
        assert_eq!(log.entries[0].kind, CmpKind::BufferEquality);
        assert_eq!(log.entries[1].operand_a, b"hello");
        assert_eq!(log.entries[1].operand_b, b"world");
        assert_eq!(log.entries[1].kind, CmpKind::CStringEquality);
    }

    #[test]
    fn dictionary_tokens_deduplicates_operands() {
        let mut log = CmpLog::new();
        log.record(CmpEntry {
            site_id: 1,
            operand_a: b"MAGIC".to_vec(),
            operand_b: b"hello".to_vec(),
            kind: CmpKind::BufferEquality,
        });
        log.record(CmpEntry {
            site_id: 2,
            operand_a: b"MAGIC".to_vec(), // duplicate
            operand_b: b"world".to_vec(),
            kind: CmpKind::CStringEquality,
        });
        log.record(CmpEntry {
            site_id: 3,
            operand_a: b"".to_vec(), // empty skipped
            operand_b: b"hello".to_vec(),
            kind: CmpKind::BufferEquality,
        });
        let tokens = log.dictionary_tokens();
        assert_eq!(tokens.len(), 3); // MAGIC, hello, world
        assert!(tokens.iter().any(|t| t.as_slice() == b"MAGIC"));
        assert!(tokens.iter().any(|t| t.as_slice() == b"hello"));
        assert!(tokens.iter().any(|t| t.as_slice() == b"world"));
        assert!(!tokens.iter().any(|t| t.is_empty()));
    }

    fn entry(site_id: u64, a: &[u8], b: &[u8]) -> CmpEntry {
        CmpEntry {
            site_id,
            operand_a: a.to_vec(),
            operand_b: b.to_vec(),
            kind: CmpKind::BufferEquality,
        }
    }

    /// At a comparison whose one side varies with the input while the other
    /// stays the same, only the side that stays the same is a constant; the
    /// mutated inputs it was compared against are not.
    #[test]
    fn constant_operands_keep_the_side_that_stays_the_same() {
        let mut log = CmpLog::new();
        for a in [&b"ab12"[..], b"~~~~", b"\x91EY1", b"K\xe5Y1", b"KEY0"] {
            log.record(entry(0x10, a, b"KEY1"));
        }
        // The same pair again (another process wrote it) is one observation.
        log.record(entry(0x10, b"~~~~", b"KEY1"));
        assert_eq!(log.constant_operands(&[]), vec![b"KEY1".to_vec()]);
    }

    /// A comparison seen once says nothing on its own: an operand is kept
    /// only when it is a constant elsewhere or a known dictionary token, and
    /// a one-byte variant of a kept token is dropped.
    #[test]
    fn single_records_need_corroboration_and_variants_are_dropped() {
        let mut log = CmpLog::new();
        log.record(entry(0x10, b"abcd", b"WIDG"));
        log.record(entry(0x10, b"abce", b"WIDG"));
        log.record(entry(0x20, b"WIDG", b"zzzz"));
        log.record(entry(0x30, b"qqqq", b"HDR1"));
        log.record(entry(0x40, b"WIDH", b"rrrr"));
        let tokens = log.constant_operands(&[b"HDR1".to_vec()]);
        assert_eq!(tokens, vec![b"WIDG".to_vec(), b"HDR1".to_vec()]);
    }

    /// One site compares the input with each entry of a keyword table: every
    /// input meets every keyword, so meeting several values does not make an
    /// operand a constant. A keyword is one once it has met more distinct
    /// inputs than any of those inputs met keywords; until then neither side
    /// is.
    #[test]
    fn a_keyword_table_keeps_the_keywords_not_the_inputs() {
        let keywords = [&b"GET"[..], b"POST", b"PUT"];
        let mut log = CmpLog::new();
        for input in [&b"GXT"[..], b"P\x01ST", b"zzzz"] {
            for keyword in keywords {
                log.record(entry(0x10, input, keyword));
            }
        }
        assert_eq!(log.constant_operands(&[]), Vec::<Vec<u8>>::new());
        for input in [&b"abc"[..], b"qq", b"GEU\xff"] {
            for keyword in keywords {
                log.record(entry(0x10, input, keyword));
            }
        }
        assert_eq!(
            log.constant_operands(&[]),
            keywords.map(<[u8]>::to_vec).to_vec()
        );
        // The input happening to equal a keyword says nothing either way.
        log.record(entry(0x10, b"PUT", b"PUT"));
        assert_eq!(
            log.constant_operands(&[]),
            keywords.map(<[u8]>::to_vec).to_vec()
        );
    }

    /// Records without a site (the runtrace shim's, an older driver's) cannot
    /// tell one comparison from another: whatever the operands met, they only
    /// confirm tokens the mined dictionary lists.
    #[test]
    fn records_without_a_site_only_confirm_known_tokens() {
        let mut log = CmpLog::new();
        let mut index = 0u64;
        let mut unsited = |log: &mut CmpLog, a: &[u8], b: &[u8]| {
            log.record(entry(UNKNOWN_SITE | index, a, b));
            index += 1;
        };
        for input in [&b"abcd"[..], b"qrst"] {
            for constant in [&b"WIDG"[..], b"HDR1"] {
                unsited(&mut log, input, constant);
            }
        }
        for input in [&b"one1"[..], b"two2", b"six6", b"ten0"] {
            unsited(&mut log, input, b"KEEP");
        }
        assert_eq!(log.constant_operands(&[]), Vec::<Vec<u8>>::new());
        assert_eq!(
            log.constant_operands(&[b"HDR1".to_vec(), b"KEEP".to_vec(), b"ABSENT".to_vec()]),
            vec![b"HDR1".to_vec(), b"KEEP".to_vec()]
        );
    }

    /// The driver names each record's site; the ingested entries carry it.
    #[test]
    fn ingest_reads_the_recorded_site() {
        let dir = std::env::temp_dir().join(format!(
            "bhf-cmplog-site-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("records.jsonl");
        std::fs::write(
            &log_path,
            "{\"e\":\"cmplog\",\"k\":\"memcmp\",\"s\":\"00001a2b.00003c4d\",\"a\":\"6162\",\"b\":\"4d41\"}\n\
             {\"e\":\"cmplog\",\"k\":\"memcmp\",\"s\":\"00001a2b.00003c4d\",\"a\":\"6163\",\"b\":\"4d41\"}\n\
             {\"e\":\"cmplog\",\"k\":\"memcmp\",\"a\":\"6164\",\"b\":\"4d41\"}\n",
        )
        .unwrap();
        let log = ingest_from_jsonl_log(&log_path).unwrap();
        assert_eq!(log.entries[0].site_id, log.entries[1].site_id);
        assert_eq!(log.entries[0].site_id & UNKNOWN_SITE, 0);
        assert_ne!(log.entries[2].site_id & UNKNOWN_SITE, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn one_byte_edits_are_substitutions_insertions_and_removals() {
        assert!(one_byte_edit(b"KEY1", b"KEY2"));
        assert!(one_byte_edit(b"KEY1", b"KEY"));
        assert!(one_byte_edit(b"KY1", b"KEY1"));
        assert!(!one_byte_edit(b"KEY1", b"KEY1"));
        assert!(!one_byte_edit(b"KEY1", b"KXY2"));
        assert!(!one_byte_edit(b"KEY1", b"KE"));
    }

    #[test]
    fn ingest_skips_unrelated_categories() {
        let dir = std::env::temp_dir().join(format!(
            "bhf-cmplog-other-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("audit.jsonl");
        std::fs::write(
            &log_path,
            b"{\"c\":\"getenv\",\"n\":\"X\"}\n{\"c\":\"connect\",\"e\":\"x\"}\n",
        )
        .unwrap();
        let log = ingest_from_jsonl_log(&log_path).unwrap();
        assert!(log.entries.is_empty());
    }
}
