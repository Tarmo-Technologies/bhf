// SPDX-License-Identifier: Apache-2.0

use std::ops::Range;

use type_model::TargetAbi;

use crate::dictionary::{Dictionary, DictionaryBucket};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypedValueKind {
    Boolean,
    SignedInteger,
    UnsignedInteger,
    Float64,
    Bytes,
    String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedSpan {
    pub range: Range<usize>,
    pub kind: TypedValueKind,
}

impl TypedSpan {
    pub fn new(range: Range<usize>, kind: TypedValueKind) -> Self {
        Self { range, kind }
    }

    pub fn valid_for(&self, len: usize) -> bool {
        self.range.start < self.range.end && self.range.end <= len
    }
}

/// Typed byte-range replacement candidates for the HOST ABI (little-endian on the
/// x86-64 lab host). Byte-for-byte the historical behavior; a thin wrapper over
/// [`typed_candidates_for_abi`] with [`TargetAbi::host`].
pub fn typed_candidates(kind: TypedValueKind, dictionary: &Dictionary) -> Vec<Vec<u8>> {
    typed_candidates_for_abi(kind, dictionary, TargetAbi::host())
}

/// Typed byte-range replacement candidates emitted in a TARGET's byte order.
///
/// Multi-byte scalar anchors (signed/unsigned 32-bit integers and 64-bit floats)
/// are serialized in `abi`'s endianness, so a big-endian target's `0x00000001`
/// lands as `00 00 00 01` rather than the host's `01 00 00 00`. Single-byte
/// (boolean) and dictionary-derived (bytes/string) candidates carry no byte
/// order and are unchanged. With `abi == TargetAbi::host()` on the little-endian
/// host this is identical to the pre-ABI output.
pub fn typed_candidates_for_abi(
    kind: TypedValueKind,
    dictionary: &Dictionary,
    abi: TargetAbi,
) -> Vec<Vec<u8>> {
    // A host-order (little-endian) fixed-width encoding, re-ordered into the
    // target's byte order. `x.to_be_bytes() == { let mut b = x.to_le_bytes();
    // b.reverse(); b }`, so reversing the little-endian bytes is exactly the
    // big-endian representation of the same value.
    let order = |bytes: &[u8]| -> Vec<u8> {
        let mut out = bytes.to_vec();
        if abi.is_big_endian() {
            out.reverse();
        }
        out
    };
    match kind {
        TypedValueKind::Boolean => vec![vec![0], vec![1]],
        TypedValueKind::SignedInteger => [
            0_i32.to_le_bytes(),
            1_i32.to_le_bytes(),
            (-1_i32).to_le_bytes(),
            i32::MIN.to_le_bytes(),
            i32::MAX.to_le_bytes(),
        ]
        .iter()
        .map(|bytes| order(bytes))
        .collect(),
        TypedValueKind::UnsignedInteger => [
            0_u32.to_le_bytes(),
            1_u32.to_le_bytes(),
            u32::MAX.to_le_bytes(),
        ]
        .iter()
        .map(|bytes| order(bytes))
        .collect(),
        TypedValueKind::Float64 => [
            0.0_f64.to_le_bytes(),
            (-0.0_f64).to_le_bytes(),
            f64::NAN.to_le_bytes(),
            f64::INFINITY.to_le_bytes(),
            f64::NEG_INFINITY.to_le_bytes(),
        ]
        .iter()
        .map(|bytes| order(bytes))
        .collect(),
        TypedValueKind::Bytes | TypedValueKind::String => {
            let tokens: Vec<Vec<u8>> =
                if kind == TypedValueKind::String && dictionary.has_curated_entries() {
                    dictionary
                        .tokens_for_bucket(&DictionaryBucket::String)
                        .map(Vec::from)
                        .collect()
                } else {
                    dictionary.tokens().map(Vec::from).collect()
                };
            if tokens.is_empty() {
                vec![Vec::new()]
            } else {
                tokens
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dictionary::Dictionary;

    #[test]
    fn typed_span_rejects_out_of_bounds_range() {
        let span = TypedSpan::new(1..4, TypedValueKind::Bytes);

        assert!(span.valid_for(4));
        assert!(!span.valid_for(3));
        assert!(!TypedSpan::new(2..2, TypedValueKind::Bytes).valid_for(4));
    }

    #[test]
    fn boolean_candidates_are_single_byte_anchors() {
        let candidates = typed_candidates(TypedValueKind::Boolean, &Dictionary::default());

        assert_eq!(candidates, vec![vec![0], vec![1]]);
    }

    #[test]
    fn signed_integer_candidates_are_little_endian_i32() {
        let candidates = typed_candidates(TypedValueKind::SignedInteger, &Dictionary::default());

        assert!(candidates.contains(&0_i32.to_le_bytes().to_vec()));
        assert!(candidates.contains(&1_i32.to_le_bytes().to_vec()));
        assert!(candidates.contains(&(-1_i32).to_le_bytes().to_vec()));
        assert!(candidates.contains(&i32::MIN.to_le_bytes().to_vec()));
        assert!(candidates.contains(&i32::MAX.to_le_bytes().to_vec()));
    }

    #[test]
    fn host_abi_candidates_are_byte_identical_to_the_default_path() {
        // Regression: threading the ABI must not perturb the host lane. The
        // explicit host ABI must reproduce the default (little-endian) output
        // byte-for-byte for every kind.
        let dict = Dictionary::from_tokens([&b"alpha"[..], &b"beta"[..]]);
        for kind in [
            TypedValueKind::Boolean,
            TypedValueKind::SignedInteger,
            TypedValueKind::UnsignedInteger,
            TypedValueKind::Float64,
            TypedValueKind::Bytes,
            TypedValueKind::String,
        ] {
            assert_eq!(
                typed_candidates(kind, &dict),
                typed_candidates_for_abi(kind, &dict, TargetAbi::host()),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn signed_integer_candidates_use_target_byte_order() {
        let dict = Dictionary::default();
        let be = TargetAbi::from_triple("powerpc64-linux-gnu").expect("ppc64 abi");
        let le = TargetAbi::from_triple("powerpc64le-linux-gnu").expect("ppc64le abi");

        let be_candidates = typed_candidates_for_abi(TypedValueKind::SignedInteger, &dict, be);
        let le_candidates = typed_candidates_for_abi(TypedValueKind::SignedInteger, &dict, le);

        // Big-endian anchors are the true big-endian representation of the value.
        assert!(be_candidates.contains(&1_i32.to_be_bytes().to_vec()));
        assert!(be_candidates.contains(&i32::MIN.to_be_bytes().to_vec()));
        assert!(be_candidates.contains(&i32::MAX.to_be_bytes().to_vec()));
        // Golden bytes: 1 = 00 00 00 01, MIN = 80 00 00 00, MAX = 7f ff ff ff.
        assert!(be_candidates.contains(&vec![0x00, 0x00, 0x00, 0x01]));
        assert!(be_candidates.contains(&vec![0x80, 0x00, 0x00, 0x00]));
        assert!(be_candidates.contains(&vec![0x7f, 0xff, 0xff, 0xff]));

        // The BE set is exactly the LE set with each anchor's bytes reversed.
        let le_reversed: Vec<Vec<u8>> = le_candidates
            .iter()
            .map(|c| {
                let mut r = c.clone();
                r.reverse();
                r
            })
            .collect();
        assert_eq!(be_candidates, le_reversed);
        // 0 and -1 are palindromic, so LE and BE agree on those two.
        assert!(be_candidates.contains(&0_i32.to_le_bytes().to_vec()));
        assert!(be_candidates.contains(&(-1_i32).to_le_bytes().to_vec()));
    }

    #[test]
    fn float_and_unsigned_candidates_reverse_for_big_endian() {
        let dict = Dictionary::default();
        let be = TargetAbi::from_triple("mips-linux-gnu").expect("mips abi");

        let unsigned = typed_candidates_for_abi(TypedValueKind::UnsignedInteger, &dict, be);
        assert!(unsigned.contains(&u32::MAX.to_be_bytes().to_vec()));
        assert!(unsigned.contains(&1_u32.to_be_bytes().to_vec()));
        assert!(unsigned.contains(&vec![0x00, 0x00, 0x00, 0x01]));

        let floats = typed_candidates_for_abi(TypedValueKind::Float64, &dict, be);
        assert!(floats.contains(&f64::INFINITY.to_be_bytes().to_vec()));
        assert!(floats.contains(&f64::NEG_INFINITY.to_be_bytes().to_vec()));
        // Booleans and bytes carry no byte order — unchanged under a BE ABI.
        assert_eq!(
            typed_candidates_for_abi(TypedValueKind::Boolean, &dict, be),
            vec![vec![0], vec![1]]
        );
    }

    #[test]
    fn string_candidates_use_dictionary_when_available() {
        let dictionary = Dictionary::from_tokens([&b"alpha"[..], &b"beta"[..]]);

        assert_eq!(
            typed_candidates(TypedValueKind::String, &dictionary),
            vec![b"alpha".to_vec(), b"beta".to_vec()]
        );
    }
}
