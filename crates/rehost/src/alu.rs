// SPDX-License-Identifier: Apache-2.0

//! The ARMv7-M pseudocode helpers the instructions are written in terms of:
//! `AddWithCarry`, `Shift_C`, `DecodeImmShift`, `ThumbExpandImm_C` and the
//! saturation functions.

/// The shift an operand goes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shift {
    Lsl,
    Lsr,
    Asr,
    Ror,
    Rrx,
}

/// `AddWithCarry(x, y, carry_in)`: the sum, its carry out and its overflow.
#[inline]
pub(crate) fn add_with_carry(x: u32, y: u32, carry: bool) -> (u32, bool, bool) {
    let unsigned = u64::from(x) + u64::from(y) + u64::from(carry);
    let signed = i64::from(x as i32) + i64::from(y as i32) + i64::from(carry);
    let result = unsigned as u32;
    (
        result,
        u64::from(result) != unsigned,
        i64::from(result as i32) != signed,
    )
}

/// `DecodeImmShift(type, imm5)`.
#[inline]
pub(crate) fn decode_imm_shift(kind: u32, imm5: u32) -> (Shift, u32) {
    match kind & 3 {
        0 => (Shift::Lsl, imm5),
        1 => (Shift::Lsr, if imm5 == 0 { 32 } else { imm5 }),
        2 => (Shift::Asr, if imm5 == 0 { 32 } else { imm5 }),
        _ if imm5 == 0 => (Shift::Rrx, 1),
        _ => (Shift::Ror, imm5),
    }
}

/// The register-shift kind a two-bit `type` field names.
#[inline]
pub(crate) fn shift_kind(kind: u32) -> Shift {
    match kind & 3 {
        0 => Shift::Lsl,
        1 => Shift::Lsr,
        2 => Shift::Asr,
        _ => Shift::Ror,
    }
}

/// `Shift_C(value, type, amount, carry_in)`: the shifted value and the
/// shifter's carry out. A zero amount leaves both unchanged.
#[inline]
pub(crate) fn shift_c(value: u32, kind: Shift, amount: u32, carry: bool) -> (u32, bool) {
    if amount == 0 {
        return (value, carry);
    }
    match kind {
        Shift::Lsl => match amount {
            1..=31 => (value << amount, (value >> (32 - amount)) & 1 != 0),
            32 => (0, value & 1 != 0),
            _ => (0, false),
        },
        Shift::Lsr => match amount {
            1..=31 => (value >> amount, (value >> (amount - 1)) & 1 != 0),
            32 => (0, value >> 31 != 0),
            _ => (0, false),
        },
        Shift::Asr => match amount {
            1..=31 => (
                ((value as i32) >> amount) as u32,
                (value >> (amount - 1)) & 1 != 0,
            ),
            _ => (((value as i32) >> 31) as u32, value >> 31 != 0),
        },
        Shift::Ror => {
            let result = value.rotate_right(amount % 32);
            (result, result >> 31 != 0)
        }
        Shift::Rrx => ((u32::from(carry) << 31) | (value >> 1), value & 1 != 0),
    }
}

/// `ThumbExpandImm_C(imm12, carry_in)`: the modified immediate and its carry.
#[inline]
pub(crate) fn thumb_expand_imm_c(imm12: u32, carry: bool) -> (u32, bool) {
    let imm8 = imm12 & 0xff;
    if imm12 >> 10 == 0 {
        let value = match (imm12 >> 8) & 3 {
            0 => imm8,
            1 => (imm8 << 16) | imm8,
            2 => (imm8 << 24) | (imm8 << 8),
            _ => (imm8 << 24) | (imm8 << 16) | (imm8 << 8) | imm8,
        };
        (value, carry)
    } else {
        let unrotated = 0x80 | (imm12 & 0x7f);
        let result = unrotated.rotate_right(imm12 >> 7);
        (result, result >> 31 != 0)
    }
}

/// `SignedSatQ(value, bits)`: `value` clamped to a `bits`-bit signed range
/// (1..=32), and whether it was clamped.
pub(crate) fn signed_sat(value: i64, bits: u32) -> (u32, bool) {
    let max = (1i64 << (bits - 1)) - 1;
    let min = -(1i64 << (bits - 1));
    if value > max {
        (max as u32, true)
    } else if value < min {
        (min as u32, true)
    } else {
        (value as u32, false)
    }
}

/// `UnsignedSatQ(value, bits)`: `value` clamped to `0..2^bits` (bits 0..=31).
pub(crate) fn unsigned_sat(value: i64, bits: u32) -> (u32, bool) {
    let max = (1i64 << bits) - 1;
    if value > max {
        (max as u32, true)
    } else if value < 0 {
        (0, true)
    } else {
        (value as u32, false)
    }
}

/// Sign-extend the low `bits` bits of `value`.
#[inline]
pub(crate) fn sign_extend(value: u32, bits: u32) -> u32 {
    let shift = 32 - bits;
    (((value << shift) as i32) >> shift) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_with_carry_sets_carry_and_overflow() {
        assert_eq!(add_with_carry(1, 2, false), (3, false, false));
        assert_eq!(add_with_carry(u32::MAX, 1, false), (0, true, false));
        assert_eq!(
            add_with_carry(0x7fff_ffff, 1, false),
            (0x8000_0000, false, true)
        );
        // Subtraction as x + !y + 1: 5 - 3 sets carry (no borrow).
        assert_eq!(add_with_carry(5, !3, true), (2, true, false));
        assert_eq!(add_with_carry(3, !5, true), (0xffff_fffe, false, false));
        assert_eq!(
            add_with_carry(0x8000_0000, !1, true),
            (0x7fff_ffff, true, true)
        );
    }

    #[test]
    fn shifts_follow_the_pseudocode_at_their_edges() {
        assert_eq!(shift_c(0x8000_0001, Shift::Lsl, 1, false), (2, true));
        assert_eq!(shift_c(1, Shift::Lsl, 32, false), (0, true));
        assert_eq!(shift_c(1, Shift::Lsl, 33, true), (0, false));
        assert_eq!(shift_c(3, Shift::Lsr, 1, false), (1, true));
        assert_eq!(shift_c(0x8000_0000, Shift::Lsr, 32, false), (0, true));
        assert_eq!(
            shift_c(0x8000_0000, Shift::Asr, 4, false),
            (0xf800_0000, false)
        );
        assert_eq!(
            shift_c(0x8000_0000, Shift::Asr, 40, false),
            (0xffff_ffff, true)
        );
        assert_eq!(
            shift_c(0x0000_0011, Shift::Ror, 4, false),
            (0x1000_0001, false)
        );
        assert_eq!(
            shift_c(0x8000_0001, Shift::Ror, 32, false),
            (0x8000_0001, true)
        );
        assert_eq!(shift_c(3, Shift::Rrx, 1, true), (0x8000_0001, true));
        assert_eq!(shift_c(7, Shift::Lsr, 0, true), (7, true));
        assert_eq!(decode_imm_shift(1, 0), (Shift::Lsr, 32));
        assert_eq!(decode_imm_shift(3, 0), (Shift::Rrx, 1));
        assert_eq!(decode_imm_shift(3, 5), (Shift::Ror, 5));
    }

    #[test]
    fn thumb_modified_immediates_expand() {
        assert_eq!(thumb_expand_imm_c(0x0ab, true), (0xab, true));
        assert_eq!(thumb_expand_imm_c(0x1ab, false), (0x00ab_00ab, false));
        assert_eq!(thumb_expand_imm_c(0x2ab, false), (0xab00_ab00, false));
        assert_eq!(thumb_expand_imm_c(0x3ab, false), (0xabab_abab, false));
        // 0x4ff: rotate '1':0x7f right by 9.
        assert_eq!(thumb_expand_imm_c(0x4ff, false), (0x7f80_0000, false));
        // imm12 = 0x400: 0x80 rotated right by 8 sets bit 31 and the carry.
        assert_eq!(thumb_expand_imm_c(0x400, false), (0x8000_0000, true));
    }

    #[test]
    fn saturation_clamps_and_reports() {
        assert_eq!(signed_sat(200, 8), (127, true));
        assert_eq!(signed_sat(-200, 8), ((-128i32) as u32, true));
        assert_eq!(signed_sat(5, 8), (5, false));
        assert_eq!(unsigned_sat(300, 8), (255, true));
        assert_eq!(unsigned_sat(-1, 8), (0, true));
        assert_eq!(unsigned_sat(17, 8), (17, false));
        assert_eq!(sign_extend(0x80, 8), 0xffff_ff80);
        assert_eq!(sign_extend(0x7f, 8), 0x7f);
    }
}
