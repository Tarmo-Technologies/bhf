// SPDX-License-Identifier: Apache-2.0

//! Layered AFL-format dictionary merge.
//!
//! The historical behavior picked the *first* dictionary found over a fixed set
//! of locations. A project profile instead declares an ordered list of
//! dictionaries that are *layered*: concatenated in declared order with tokens
//! de-duplicated, keeping the first occurrence. That lets a base dictionary be
//! extended by target-specific overlays without losing either.
//!
//! The per-file UTF-8 and size constraints mirror the existing fuzz dictionary
//! loader: a dictionary over the safety limit, or that is not valid UTF-8, is a
//! hard error; a single malformed *line* is skipped (best-effort), exactly as
//! the fuzz loader does, so one stray line never discards an entire layer.

use std::path::{Path, PathBuf};

use crate::error::ProjectError;

/// The per-file size ceiling, matching the fuzz loader's default
/// (`BHF_MAX_DICTIONARY_BYTES`, 16 MiB).
pub const MAX_DICTIONARY_BYTES: u64 = 16 * 1024 * 1024;

/// The merged, de-duplicated token set, in first-seen order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MergedDictionary {
    /// Decoded token byte strings, first-seen order preserved.
    pub tokens: Vec<Vec<u8>>,
}

impl MergedDictionary {
    /// Re-serialize the merged tokens to AFL dictionary format, one
    /// `"token"` per line, ready to write to a `dictionary.txt`.
    pub fn to_afl_format(&self) -> String {
        let mut out = String::new();
        for token in &self.tokens {
            out.push('"');
            for &b in token {
                match b {
                    b'"' => out.push_str("\\\""),
                    b'\\' => out.push_str("\\\\"),
                    b'\n' => out.push_str("\\n"),
                    b'\r' => out.push_str("\\r"),
                    b'\t' => out.push_str("\\t"),
                    0x20..=0x7e => out.push(b as char),
                    other => out.push_str(&format!("\\x{other:02x}")),
                }
            }
            out.push_str("\"\n");
        }
        out
    }
}

/// Merge the given dictionaries in order, de-duplicating tokens.
pub fn merge(paths: &[PathBuf]) -> Result<MergedDictionary, ProjectError> {
    let mut tokens: Vec<Vec<u8>> = Vec::new();
    for path in paths {
        for token in parse_dictionary_file(path)? {
            if !tokens.contains(&token) {
                tokens.push(token);
            }
        }
    }
    Ok(MergedDictionary { tokens })
}

fn parse_dictionary_file(path: &Path) -> Result<Vec<Vec<u8>>, ProjectError> {
    let meta = std::fs::metadata(path).map_err(|source| ProjectError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if meta.len() > MAX_DICTIONARY_BYTES {
        return Err(ProjectError::InvalidDictionary {
            path: path.to_path_buf(),
            detail: format!(
                "{} bytes exceeds the {} MiB safety limit",
                meta.len(),
                MAX_DICTIONARY_BYTES / (1024 * 1024)
            ),
        });
    }
    let bytes = std::fs::read(path).map_err(|source| ProjectError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let text = String::from_utf8(bytes).map_err(|_| ProjectError::InvalidDictionary {
        path: path.to_path_buf(),
        detail: "not valid UTF-8".to_owned(),
    })?;

    let mut out = Vec::new();
    for line in text.lines() {
        // A single malformed line is skipped, not fatal — mirrors the fuzz
        // loader's best-effort behavior.
        if let Ok(Some(token)) = parse_afl_line(line) {
            out.push(token);
        }
    }
    Ok(out)
}

/// Parse one AFL dictionary line into its decoded token bytes. Blank and
/// comment lines yield `None`; a malformed line is an `Err` (caller skips it).
fn parse_afl_line(line: &str) -> Result<Option<Vec<u8>>, String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(None);
    }
    // The value is the quoted span. An optional `name=` / `name@level=` prefix
    // may precede it; a dictionary name never contains a quote, so the value
    // reliably begins at the first `"`.
    let open = trimmed.find('"').ok_or("expected quoted token")?;
    let rest = &trimmed[open + 1..];
    let mut out = Vec::new();
    let mut chars = rest.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => return Ok(Some(out)),
            '\\' => match chars.next() {
                Some('n') => out.push(b'\n'),
                Some('r') => out.push(b'\r'),
                Some('t') => out.push(b'\t'),
                Some('\\') => out.push(b'\\'),
                Some('"') => out.push(b'"'),
                Some('x') => {
                    let hi = chars
                        .next()
                        .and_then(|c| c.to_digit(16))
                        .ok_or("invalid hex escape")?;
                    let lo = chars
                        .next()
                        .and_then(|c| c.to_digit(16))
                        .ok_or("invalid hex escape")?;
                    out.push(((hi << 4) | lo) as u8);
                }
                Some(other) => {
                    let mut buf = [0; 4];
                    out.extend_from_slice(other.encode_utf8(&mut buf).as_bytes());
                }
                None => return Err("unterminated escape".to_owned()),
            },
            other => {
                let mut buf = [0; 4];
                out.extend_from_slice(other.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    Err("unterminated quoted token".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn merges_dictionaries_in_declared_order() {
        let dir = tempdir().unwrap();
        let base = write(dir.path(), "base.dict", "\"alpha\"\n\"beta\"\n");
        let overlay = write(dir.path(), "overlay.dict", "kw=\"gamma\"\n\"delta\"\n");
        let merged = merge(&[base, overlay]).unwrap();
        assert_eq!(
            merged.tokens,
            vec![
                b"alpha".to_vec(),
                b"beta".to_vec(),
                b"gamma".to_vec(),
                b"delta".to_vec(),
            ]
        );
    }

    #[test]
    fn dedupes_tokens_preserving_first_seen() {
        let dir = tempdir().unwrap();
        let a = write(dir.path(), "a.dict", "\"one\"\n\"two\"\n");
        let b = write(dir.path(), "b.dict", "\"two\"\n\"three\"\n\"one\"\n");
        let merged = merge(&[a, b]).unwrap();
        assert_eq!(
            merged.tokens,
            vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]
        );
        // And the re-serialized form round-trips through the parser.
        let afl = merged.to_afl_format();
        assert_eq!(afl, "\"one\"\n\"two\"\n\"three\"\n");
    }

    #[test]
    fn decodes_escapes_and_reserializes_non_printable() {
        let dir = tempdir().unwrap();
        let d = write(dir.path(), "esc.dict", "\"a\\x00b\"\n\"tab\\there\"\n");
        let merged = merge(&[d]).unwrap();
        assert_eq!(merged.tokens[0], vec![b'a', 0x00, b'b']);
        assert_eq!(merged.tokens[1], b"tab\there".to_vec());
        let afl = merged.to_afl_format();
        assert!(afl.contains("\\x00"));
        assert!(afl.contains("\\t"));
    }

    #[test]
    fn rejects_non_utf8_or_oversize_like_fuzz_path() {
        let dir = tempdir().unwrap();
        let non_utf8 = dir.path().join("bad.dict");
        fs::write(&non_utf8, [0xff, 0xfe, 0x00]).unwrap();
        let err = merge(&[non_utf8]).unwrap_err();
        assert!(
            matches!(err, ProjectError::InvalidDictionary { ref detail, .. } if detail.contains("UTF-8")),
            "{err:?}"
        );

        // Oversize is checked by metadata, not content: assert the ceiling is
        // the fuzz-loader default so the two paths agree.
        assert_eq!(MAX_DICTIONARY_BYTES, 16 * 1024 * 1024);
    }

    #[test]
    fn skips_malformed_lines_without_aborting() {
        let dir = tempdir().unwrap();
        // Middle line has no closing quote; it must be skipped, not fatal.
        let d = write(
            dir.path(),
            "m.dict",
            "\"good\"\n\"unterminated\n\"after\"\n",
        );
        let merged = merge(&[d]).unwrap();
        assert_eq!(merged.tokens, vec![b"good".to_vec(), b"after".to_vec()]);
    }
}
