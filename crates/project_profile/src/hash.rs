// SPDX-License-Identifier: Apache-2.0

//! Deterministic SHA-256 hashing for provenance.
//!
//! Every asset referenced by a run is hashed so findings, replay bundles, and
//! run summaries produced by importers (SARIF / vulnerability-management
//! tooling) can be tied back to the exact bytes that produced them. A seed
//! *directory* is hashed by a sorted walk so the digest is independent of the
//! order the filesystem happens to enumerate entries in.

use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::ProjectError;

/// Lower-case hex SHA-256 of an in-memory byte slice.
pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

/// Lower-case hex SHA-256 of a single file's contents.
pub fn sha256_file(path: &Path) -> Result<String, ProjectError> {
    let bytes = std::fs::read(path).map_err(|source| ProjectError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(sha256_bytes(&bytes))
}

/// Hash any asset path: a regular file by its bytes, a directory by its sorted
/// walk. Anything else (missing, special file) is reported as a missing asset.
pub fn sha256_asset(path: &Path) -> Result<String, ProjectError> {
    if path.is_dir() {
        sha256_seed_dir(path)
    } else if path.is_file() {
        sha256_file(path)
    } else {
        Err(ProjectError::MissingAsset(path.to_path_buf()))
    }
}

/// Deterministic digest of a seed directory.
///
/// Walks the tree, collects every regular file's path *relative to the root*
/// plus its content hash, sorts by that relative path, then folds the sorted
/// `(relative-path, content-hash)` pairs into one digest. The result does not
/// depend on filesystem enumeration order.
pub fn sha256_seed_dir(root: &Path) -> Result<String, ProjectError> {
    let mut entries: Vec<(String, String)> = Vec::new();
    collect_files(root, root, &mut entries)?;
    entries.sort();

    let mut hasher = Sha256::new();
    for (rel, content_hash) in entries {
        // Length-prefix the relative path so that distinct (path, hash)
        // boundaries cannot be forged by concatenation ambiguity.
        hasher.update((rel.len() as u64).to_le_bytes());
        hasher.update(rel.as_bytes());
        hasher.update(content_hash.as_bytes());
    }
    Ok(hex(&hasher.finalize()))
}

fn collect_files(
    root: &Path,
    dir: &Path,
    out: &mut Vec<(String, String)>,
) -> Result<(), ProjectError> {
    let read = std::fs::read_dir(dir).map_err(|source| ProjectError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    for entry in read {
        let entry = entry.map_err(|source| ProjectError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| ProjectError::Io {
            path: path.clone(),
            source,
        })?;
        if file_type.is_dir() {
            collect_files(root, &path, out)?;
        } else if file_type.is_file() {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                // Normalize separators so the digest is stable across platforms.
                .replace('\\', "/");
            out.push((rel, sha256_file(&path)?));
        }
        // Symlinks and other special entries are deliberately skipped: a seed
        // directory is data, and following links would make the digest depend
        // on targets outside the project.
    }
    Ok(())
}

fn hex(digest: &[u8]) -> String {
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn hashes_known_bytes_to_known_sha256() {
        assert_eq!(
            sha256_bytes(b"hello world"),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
        assert_eq!(
            sha256_bytes(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_file_matches_bytes() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("f");
        fs::write(&p, b"hello world").unwrap();
        assert_eq!(
            sha256_file(&p).unwrap(),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn hashes_seed_directory_deterministically() {
        // Build the same logical tree in two dirs, writing files in a different
        // order, and assert the digest is identical (order-independent).
        let a = tempdir().unwrap();
        let b = tempdir().unwrap();
        fs::create_dir_all(a.path().join("sub")).unwrap();
        fs::write(a.path().join("sub/two"), b"second").unwrap();
        fs::write(a.path().join("one"), b"first").unwrap();

        fs::create_dir_all(b.path().join("sub")).unwrap();
        fs::write(b.path().join("one"), b"first").unwrap();
        fs::write(b.path().join("sub/two"), b"second").unwrap();

        let ha = sha256_seed_dir(a.path()).unwrap();
        let hb = sha256_seed_dir(b.path()).unwrap();
        assert_eq!(ha, hb);

        // A content change must change the digest.
        fs::write(b.path().join("one"), b"changed").unwrap();
        assert_ne!(sha256_seed_dir(b.path()).unwrap(), ha);
    }

    #[test]
    fn hash_missing_file_errors() {
        let dir = tempdir().unwrap();
        let err = sha256_file(&dir.path().join("ghost")).unwrap_err();
        assert!(matches!(err, ProjectError::Io { .. }), "{err:?}");
        let err2 = sha256_asset(&dir.path().join("ghost")).unwrap_err();
        assert!(matches!(err2, ProjectError::MissingAsset(_)), "{err2:?}");
    }
}
