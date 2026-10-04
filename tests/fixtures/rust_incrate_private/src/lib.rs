// SPDX-License-Identifier: Apache-2.0
//
// §27.10 / #83 in-crate PRIVATE-harness fixture. `Database` is a crate-root PUBLIC
// type, but its opener `open_dir` is `pub(crate)` — unreachable from an external
// dependent crate (E0603). The opener takes a path-backed resource (`dir: &Path`),
// which has no byte-channel decoder, so the default external lane cannot drive it
// either. Only the opt-in IN-CRATE PRIVATE build mode — which injects the harness
// as a module of a copy of this crate AND materializes a bounded temp dir seeded
// with the fuzz input — reaches `crate::Database::open_dir` and drives it. Models
// zoxide's `Database::open_dir(dir: &Path)`.

use std::path::Path;

/// A crate-root PUBLIC type with a NON-PUBLIC path opener.
pub struct Database {
    bytes_seen: usize,
}

impl Database {
    /// Public constructor — the in-crate harness builds the receiver with this
    /// (a receiver ctor must be `pub`, like the external lane requires).
    pub fn new() -> Self {
        Database { bytes_seen: 0 }
    }

    /// Open a path-backed "database": read `<dir>/db` and parse it. NON-PUBLIC
    /// (`pub(crate)`), so reachable only from inside the crate — i.e. only from an
    /// in-crate injected harness module (`crate::Database::open_dir`). The fuzzer
    /// drives this by SEEDING the file the opener reads; a two-byte magic gate
    /// (`b"GF"`) guards a planted out-of-bounds index bug (BHF-201): the
    /// file-supplied `body_len` is trusted and indexes past the slice end. The
    /// magic + version branches give the coverage map real edges to grow before
    /// the crash is found — proving the in-crate harness drove a NON-PUBLIC
    /// path-opener past a multi-byte gate through a materialized path resource.
    pub(crate) fn open_dir(&mut self, dir: &Path) -> u32 {
        let data = match std::fs::read(dir.join("db")) {
            Ok(d) => d,
            Err(_) => return 0,
        };
        self.bytes_seen = self.bytes_seen.wrapping_add(data.len());
        if data.len() < 4 {
            return 0;
        }
        // Magic gate: only a file starting with "GF" reaches the deeper logic.
        if data[0] != b'G' || data[1] != b'F' {
            return 1;
        }
        let version = data[2];
        let body_len = data[3] as usize;
        let mut checksum: u32 = 0;
        if version == 1 {
            // PLANTED BUG (BHF-201): trusts the file-supplied `body_len` and indexes
            // past the slice end -> a bounds-check panic the native engine surfaces
            // as a crash. Reachable only after the magic + version gate.
            for i in 0..body_len {
                checksum = checksum.wrapping_add(data[4 + i] as u32);
            }
        } else {
            let end = (4 + body_len).min(data.len());
            for &b in &data[4..end] {
                checksum = checksum.wrapping_mul(31).wrapping_add(b as u32);
            }
        }
        checksum
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_db_is_safe() {
        let mut db = Database::new();
        assert_eq!(db.open_dir(Path::new("/nonexistent-bhf-fixture-path")), 0);
    }
}
