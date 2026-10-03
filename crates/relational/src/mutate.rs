// SPDX-License-Identifier: Apache-2.0

//! A small, self-contained, deterministic byte mutator.
//!
//! The campaign engine needs *some* way to derive new testcases from a corpus.
//! To keep this crate pure and dependency-light, it ships its own minimal
//! byte-level mutator with a seeded PRNG rather than pulling in a fuzz-engine.
//! The strategy is pluggable via the [`Mutator`] trait, so a downstream driver
//! can swap in a richer mutator at the seam while reusing the campaign loop.

/// A deterministic xorshift64* PRNG. Reproducible from a seed.
#[derive(Debug, Clone)]
pub struct Rng {
    state: u64,
}

impl Rng {
    /// Create a PRNG from `seed` (0 is remapped to a non-zero constant).
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            },
        }
    }

    /// Next 64-bit value.
    pub fn next_u64(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A value in `[0, bound)`; returns 0 when `bound == 0`.
    pub fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next_u64() % bound as u64) as usize
        }
    }

    /// A random byte.
    pub fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }
}

/// A mutation strategy: derive a new input from `base` into `out` (cleared).
pub trait Mutator {
    /// Fill `out` with a mutated derivative of `base`, bounded to `max_len`.
    fn mutate(&mut self, base: &[u8], max_len: usize, out: &mut Vec<u8>);
}

/// The default byte-level mutator: bit flips, byte substitution, insertion and
/// deletion, driven by [`Rng`].
#[derive(Debug, Clone)]
pub struct ByteMutator {
    rng: Rng,
}

impl ByteMutator {
    /// Create a mutator seeded deterministically.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            rng: Rng::new(seed),
        }
    }
}

impl Mutator for ByteMutator {
    fn mutate(&mut self, base: &[u8], max_len: usize, out: &mut Vec<u8>) {
        out.clear();
        out.extend_from_slice(base);
        if out.is_empty() {
            out.push(self.rng.byte());
        }
        // Apply a handful of mutations so convergence does not need a huge budget.
        let rounds = 1 + self.rng.below(4);
        for _ in 0..rounds {
            match self.rng.below(5) {
                0 => {
                    // Flip a random bit.
                    let i = self.rng.below(out.len());
                    let bit = self.rng.below(8);
                    out[i] ^= 1u8 << bit;
                }
                1 => {
                    // Substitute a random byte.
                    let i = self.rng.below(out.len());
                    out[i] = self.rng.byte();
                }
                2 if out.len() < max_len => {
                    // Insert a random byte.
                    let i = self.rng.below(out.len() + 1);
                    out.insert(i, self.rng.byte());
                }
                3 if out.len() > 1 => {
                    // Delete a random byte.
                    let i = self.rng.below(out.len());
                    out.remove(i);
                }
                _ => {
                    // Substitute toward a printable ASCII letter — helps the
                    // engine climb toward structured markers in tests.
                    let i = self.rng.below(out.len());
                    out[i] = b'a' + (self.rng.byte() % 26);
                }
            }
        }
        if out.len() > max_len {
            out.truncate(max_len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rng_is_deterministic_for_a_seed() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        let mut c = Rng::new(43);
        // Different seed almost certainly diverges within a few draws.
        let a_seq: Vec<u64> = (0..8).map(|_| Rng::new(42).next_u64()).collect();
        let c_seq: Vec<u64> = (0..8).map(|_| c.next_u64()).collect();
        assert_ne!(a_seq, c_seq);
    }

    #[test]
    fn mutator_respects_max_len_and_is_reproducible() {
        let mut m1 = ByteMutator::new(7);
        let mut m2 = ByteMutator::new(7);
        let base = b"seed-input";
        let mut o1 = Vec::new();
        let mut o2 = Vec::new();
        for _ in 0..50 {
            m1.mutate(base, 6, &mut o1);
            m2.mutate(base, 6, &mut o2);
            assert!(o1.len() <= 6);
            assert_eq!(o1, o2, "same seed => same mutation sequence");
            assert!(!o1.is_empty());
        }
    }

    #[test]
    fn mutator_grows_from_empty_seed() {
        let mut m = ByteMutator::new(1);
        let mut out = Vec::new();
        m.mutate(&[], 8, &mut out);
        assert!(!out.is_empty());
    }
}
