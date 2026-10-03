// SPDX-License-Identifier: Apache-2.0

//! Per-profile edge-coverage novelty.
//!
//! A coverage bitmap is a byte-per-edge array: a non-zero byte means that edge
//! was hit, so [`popcount`] (distinct non-zero bytes) is the per-run edge scalar.
//! [`UnionBitmap`] OR-folds each run's bitmap into a per-profile accumulator and
//! reports whether a run hit an edge never seen before *in that profile*. Keeping
//! one accumulator per profile means one profile's edges can never mask another
//! profile's novelty (acceptance: per-profile novelty bucketing).
//!
//! This is intentionally self-contained: it reads raw bitmap bytes and does not
//! depend on any fuzz-engine coverage type (those consume a structured testcase,
//! not an edge bitmap).

/// Count distinct hit edges: the number of non-zero bytes in `bitmap`.
#[must_use]
pub fn popcount(bitmap: &[u8]) -> u64 {
    bitmap.iter().filter(|b| **b != 0).count() as u64
}

/// A per-profile accumulated union of coverage bitmaps.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnionBitmap {
    acc: Vec<u8>,
}

impl UnionBitmap {
    /// An empty accumulator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// OR-fold `bitmap` into the accumulator. Returns `true` if any byte
    /// transitioned from zero to non-zero (i.e. a previously-unseen edge).
    pub fn fold(&mut self, bitmap: &[u8]) -> bool {
        if bitmap.len() > self.acc.len() {
            self.acc.resize(bitmap.len(), 0);
        }
        let mut novel = false;
        for (i, &byte) in bitmap.iter().enumerate() {
            if byte != 0 && self.acc[i] == 0 {
                novel = true;
            }
            self.acc[i] |= byte;
        }
        novel
    }

    /// Distinct edges accumulated so far.
    #[must_use]
    pub fn edges(&self) -> u64 {
        popcount(&self.acc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn popcount_counts_nonzero_bytes() {
        assert_eq!(popcount(&[0, 0, 0]), 0);
        assert_eq!(popcount(&[1, 0, 7, 0, 255]), 3);
    }

    #[test]
    fn union_reports_novelty_only_on_new_edges() {
        let mut u = UnionBitmap::new();
        assert!(u.fold(&[1, 0, 0, 0]), "first non-zero byte is novel");
        assert!(!u.fold(&[1, 0, 0, 0]), "same bitmap is not novel");
        assert!(u.fold(&[1, 0, 1, 0]), "a new edge is novel");
        assert!(!u.fold(&[0, 0, 1, 0]), "already-seen edge is not novel");
        assert_eq!(u.edges(), 2);
    }

    /// Acceptance #8 novelty bucketing: each profile keeps its OWN union, so an
    /// input novel in only one profile is detected there and one profile's edges
    /// never mask another's novelty.
    #[test]
    fn per_profile_unions_are_independent() {
        let mut admin = UnionBitmap::new();
        let mut viewer = UnionBitmap::new();

        // Admin hits edges 0 and 1.
        assert!(admin.fold(&[1, 1, 0, 0]));
        // Viewer hits only edge 0 — still novel for viewer even though admin
        // already covered it, because the accumulator is per profile.
        assert!(viewer.fold(&[1, 0, 0, 0]));
        // An input that hits edge 2 in viewer only is novel for viewer...
        assert!(viewer.fold(&[1, 0, 1, 0]));
        // ...and separately novel for admin when admin first reaches edge 2.
        assert!(admin.fold(&[0, 0, 1, 0]));
        // Re-folding viewer's edge 2 is no longer novel for viewer.
        assert!(!viewer.fold(&[0, 0, 1, 0]));
    }

    #[test]
    fn fold_handles_growing_bitmaps() {
        let mut u = UnionBitmap::new();
        assert!(u.fold(&[1]));
        assert!(u.fold(&[1, 1]), "a longer bitmap with a new edge is novel");
        assert_eq!(u.edges(), 2);
    }
}
