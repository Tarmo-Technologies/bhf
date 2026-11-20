// SPDX-License-Identifier: Apache-2.0

//! Basic-block edge coverage.
//!
//! The emulator calls [`EdgeMap::enter`] with the address of every basic
//! block it starts. The map counts block-to-block transitions the way AFL's
//! edge map does: each block address hashes to a 16-bit id, and the edge from
//! the previous block to this one is counted in slot `id ^ (previous >> 1)`
//! of a 64 KiB map of saturating hit counters, the size of bhf's other edge
//! maps. The hash is fixed, so a replay of an input fills the same slots.
//!
//! [`CoverageMap`] accumulates the edges of many runs, with AFL's hit-count
//! buckets, and says how many (edge, bucket) pairs a run reached first.

/// Slots in an edge map.
pub const EDGE_MAP_SIZE: usize = 1 << 16;
const SLOT_MASK: u32 = (EDGE_MAP_SIZE as u32) - 1;

/// The edges one run took, with saturating hit counts.
#[derive(Clone)]
pub struct EdgeMap {
    counts: Box<[u8]>,
    previous: u32,
}

impl std::fmt::Debug for EdgeMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EdgeMap")
            .field("edges", &self.edges())
            .finish()
    }
}

impl Default for EdgeMap {
    fn default() -> Self {
        Self::new()
    }
}

impl EdgeMap {
    pub fn new() -> Self {
        Self {
            counts: vec![0u8; EDGE_MAP_SIZE].into_boxed_slice(),
            previous: 0,
        }
    }

    /// Forget every edge, before a run.
    pub fn clear(&mut self) {
        self.counts.fill(0);
        self.previous = 0;
    }

    /// Count the edge from the previous block to the block at `address`.
    #[inline]
    pub fn enter(&mut self, address: u32) {
        let id = block_id(address);
        let slot = ((id ^ self.previous) & SLOT_MASK) as usize;
        self.counts[slot] = self.counts[slot].saturating_add(1);
        self.previous = id >> 1;
    }

    /// The edge context: the previous block's id, shifted.
    pub(crate) fn previous(&self) -> u32 {
        self.previous
    }

    /// Count the edge into the handler at `address` of exception `number`
    /// from the exception itself, not from the block it interrupted.
    pub(crate) fn enter_handler(&mut self, number: u32, address: u32) {
        self.previous = block_id(0xffff_ff00 | number) >> 1;
        self.enter(address);
    }

    /// Go back to an edge context [`EdgeMap::previous`] gave, counting no
    /// edge.
    pub(crate) fn resume(&mut self, previous: u32) {
        self.previous = previous;
    }

    /// The hit count of every slot.
    pub fn counts(&self) -> &[u8] {
        &self.counts
    }

    /// How many slots the run hit.
    pub fn edges(&self) -> usize {
        self.counts.iter().filter(|&&count| count != 0).count()
    }
}

/// The 16-bit id of the block at `address`: a fixed integer hash, so ids
/// spread over the map and do not change between runs.
fn block_id(address: u32) -> u32 {
    let mut x = address;
    x ^= x >> 16;
    x = x.wrapping_mul(0x7feb_352d);
    x ^= x >> 15;
    x = x.wrapping_mul(0x846c_a68b);
    x ^= x >> 16;
    x & SLOT_MASK
}

/// AFL's hit-count bucket of a count, as one bit: 1, 2, 3, 4-7, 8-15,
/// 16-31, 32-127 and 128+ each have their own.
fn bucket(count: u8) -> u8 {
    match count {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        4..=7 => 8,
        8..=15 => 16,
        16..=31 => 32,
        32..=127 => 64,
        _ => 128,
    }
}

/// The edges and hit-count buckets every run so far reached.
#[derive(Clone)]
pub struct CoverageMap {
    seen: Box<[u8]>,
}

impl std::fmt::Debug for CoverageMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoverageMap")
            .field("edges", &self.edges())
            .finish()
    }
}

impl Default for CoverageMap {
    fn default() -> Self {
        Self::new()
    }
}

impl CoverageMap {
    pub fn new() -> Self {
        Self {
            seen: vec![0u8; EDGE_MAP_SIZE].into_boxed_slice(),
        }
    }

    /// Add a run's edges; returns how many (edge, bucket) pairs are new.
    pub fn merge(&mut self, run: &EdgeMap) -> usize {
        let mut new = 0;
        for (seen, &count) in self.seen.iter_mut().zip(run.counts.iter()) {
            let bit = bucket(count);
            if bit != 0 && *seen & bit == 0 {
                *seen |= bit;
                new += 1;
            }
        }
        new
    }

    /// How many slots any run hit.
    pub fn edges(&self) -> usize {
        self.seen.iter().filter(|&&seen| seen != 0).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_edge_is_counted_in_one_slot_and_saturates() {
        let mut map = EdgeMap::new();
        map.enter(0x0800_0000);
        assert_eq!(map.edges(), 1);
        for _ in 0..300 {
            map.enter(0x0800_0010);
            map.enter(0x0800_0020);
        }
        assert_eq!(map.edges(), 4, "0->a, a->b, b->c, c->b");
        assert!(map.counts().contains(&255), "counts saturate at 255");
        map.clear();
        assert_eq!(map.edges(), 0);
    }

    #[test]
    fn the_same_blocks_in_another_order_are_other_edges() {
        let mut forward = EdgeMap::new();
        for address in [0x100, 0x200, 0x300] {
            forward.enter(address);
        }
        let mut backward = EdgeMap::new();
        for address in [0x300, 0x200, 0x100] {
            backward.enter(address);
        }
        assert_ne!(forward.counts(), backward.counts());
    }

    #[test]
    fn the_coverage_map_reports_new_edges_and_new_buckets() {
        let mut coverage = CoverageMap::new();
        let mut run = EdgeMap::new();
        run.enter(0x100);
        run.enter(0x200);
        assert_eq!(coverage.merge(&run), 2);
        assert_eq!(coverage.merge(&run), 0, "nothing new the second time");
        // The same edges taken more often reach a new bucket.
        let mut looped = EdgeMap::new();
        looped.enter(0x100);
        for _ in 0..4 {
            looped.enter(0x200);
            looped.enter(0x100);
        }
        assert!(coverage.merge(&looped) > 0);
        assert_eq!(coverage.edges(), 3);
    }
}
