// SPDX-License-Identifier: Apache-2.0

//! 32-bit Thumb-2 instructions (ARMv7-M ARM, A5.3).

use crate::alu::{
    add_with_carry, decode_imm_shift, shift_c, shift_kind, sign_extend, signed_sat,
    thumb_expand_imm_c, unsigned_sat,
};
use crate::cpu::{Core, Step};
use crate::fault::FaultKind;

/// The operation of a data-processing instruction with a register or
/// modified-immediate second operand.
enum Operation {
    And,
    Bic,
    Orr,
    Orn,
    Eor,
    Add,
    Adc,
    Sbc,
    Sub,
    Rsb,
}

impl Core {
    pub(crate) fn exec32(&mut self, first: u32, second: u32) -> Step {
        let op2 = (first >> 4) & 0x7f;
        match (first >> 11) & 3 {
            0b01 => {
                if op2 & 0b110_0100 == 0b000_0000 {
                    self.load_store_multiple(first, second)
                } else if op2 & 0b110_0100 == 0b000_0100 {
                    self.load_store_dual_exclusive(first, second)
                } else if op2 & 0b110_0000 == 0b010_0000 {
                    self.data_processing_shifted(first, second)
                } else {
                    self.coprocessor(Self::encoding(first, second))
                }
            }
            0b10 => {
                if second & 0x8000 != 0 {
                    self.branch_and_control(first, second)
                } else if op2 & 0b010_0000 == 0 {
                    self.data_processing_modified_immediate(first, second)
                } else {
                    self.data_processing_plain_immediate(first, second)
                }
            }
            _ => {
                if op2 & 0b100_0000 != 0 {
                    self.coprocessor(Self::encoding(first, second))
                } else if op2 & 0b111_0001 == 0b000_0000 || op2 & 0b110_0111 == 0b000_0001 {
                    // Store single item, load byte.
                    self.load_store_single(first, second)
                } else if op2 & 0b110_0111 == 0b000_0011 || op2 & 0b110_0111 == 0b000_0101 {
                    // Load halfword, load word.
                    self.load_store_single(first, second)
                } else if op2 & 0b111_0000 == 0b010_0000 {
                    self.data_processing_register(first, second)
                } else if op2 & 0b111_1000 == 0b011_0000 {
                    self.multiply(first, second)
                } else if op2 & 0b111_1000 == 0b011_1000 {
                    self.long_multiply_divide(first, second)
                } else {
                    Err(self.undefined())
                }
            }
        }
    }

    fn encoding(first: u32, second: u32) -> u32 {
        (first << 16) | second
    }

    /// Apply a data-processing operation to `a` and `b`, where `carry` is the
    /// shifter's or the immediate expansion's carry out; returns the result,
    /// and sets the flags when `setflags`.
    fn operate(
        &mut self,
        operation: Operation,
        a: u32,
        b: u32,
        carry: bool,
        setflags: bool,
    ) -> u32 {
        let (result, arithmetic) = match operation {
            Operation::And => (a & b, None),
            Operation::Bic => (a & !b, None),
            Operation::Orr => (a | b, None),
            Operation::Orn => (a | !b, None),
            Operation::Eor => (a ^ b, None),
            Operation::Add => {
                let (result, c, v) = add_with_carry(a, b, false);
                (result, Some((c, v)))
            }
            Operation::Adc => {
                let (result, c, v) = add_with_carry(a, b, self.c);
                (result, Some((c, v)))
            }
            Operation::Sbc => {
                let (result, c, v) = add_with_carry(a, !b, self.c);
                (result, Some((c, v)))
            }
            Operation::Sub => {
                let (result, c, v) = add_with_carry(a, !b, true);
                (result, Some((c, v)))
            }
            Operation::Rsb => {
                let (result, c, v) = add_with_carry(!a, b, true);
                (result, Some((c, v)))
            }
        };
        if setflags {
            match arithmetic {
                Some((c, v)) => self.set_nzcv(result, c, v),
                None => {
                    self.set_nz(result);
                    self.c = carry;
                }
            }
        }
        result
    }

    /// The shared decode of A5.3.1 and A5.3.11, given the second operand and
    /// its carry: `rn == 15` selects MOV/MVN, and `rd == 15` with S the
    /// compare forms.
    fn data_processing(&mut self, first: u32, second: u32, operand: u32, carry: bool) -> Step {
        let encoding = Self::encoding(first, second);
        let op = (first >> 5) & 0xf;
        let setflags = first & 0x10 != 0;
        let rn = first & 0xf;
        let rd = (second >> 8) & 0xf;
        let compare = rd == 15 && setflags;
        let (operation, a) = match op {
            0b0000 => (Operation::And, self.reg(rn)),
            0b0001 => (Operation::Bic, self.reg(rn)),
            0b0010 if rn == 15 => (Operation::Orr, 0),
            0b0010 => (Operation::Orr, self.reg(rn)),
            0b0011 if rn == 15 => (Operation::Orn, 0),
            0b0011 => (Operation::Orn, self.reg(rn)),
            0b0100 => (Operation::Eor, self.reg(rn)),
            0b1000 => (Operation::Add, self.reg(rn)),
            0b1010 => (Operation::Adc, self.reg(rn)),
            0b1011 => (Operation::Sbc, self.reg(rn)),
            0b1101 => (Operation::Sub, self.reg(rn)),
            0b1110 => (Operation::Rsb, self.reg(rn)),
            _ => return Err(self.undefined()),
        };
        // TST, TEQ, CMN and CMP only set the flags.
        let flags_only = compare && matches!(op, 0b0000 | 0b0100 | 0b1000 | 0b1101);
        if rd == 15 && !flags_only {
            return Err(self.unsupported(encoding, "data-processing write to the PC"));
        }
        let result = self.operate(operation, a, operand, carry, setflags);
        if !flags_only {
            self.set_reg(rd, result);
        }
        Ok(())
    }

    /// Data processing (shifted register), A5.3.11.
    fn data_processing_shifted(&mut self, first: u32, second: u32) -> Step {
        if (first >> 5) & 0xf == 0b0110 {
            // PKHBT/PKHTB; with S set the encoding is unallocated.
            return Err(if first & 0x10 == 0 {
                self.unsupported(Self::encoding(first, second), "PKHBT/PKHTB")
            } else {
                self.undefined()
            });
        }
        let imm5 = ((second >> 10) & 0x1c) | ((second >> 6) & 3);
        let (shift, amount) = decode_imm_shift((second >> 4) & 3, imm5);
        let (operand, carry) = shift_c(self.reg(second & 0xf), shift, amount, self.c);
        self.data_processing(first, second, operand, carry)
    }

    /// Data processing (modified immediate), A5.3.1.
    fn data_processing_modified_immediate(&mut self, first: u32, second: u32) -> Step {
        let imm12 = ((first >> 10) & 1) << 11 | ((second >> 12) & 7) << 8 | (second & 0xff);
        let (operand, carry) = thumb_expand_imm_c(imm12, self.c);
        self.data_processing(first, second, operand, carry)
    }

    /// Data processing (plain binary immediate), A5.3.3.
    fn data_processing_plain_immediate(&mut self, first: u32, second: u32) -> Step {
        let rn = first & 0xf;
        let rd = (second >> 8) & 0xf;
        let imm12 = ((first >> 10) & 1) << 11 | ((second >> 12) & 7) << 8 | (second & 0xff);
        let imm16 = (rn << 12) | imm12;
        let imm5 = ((second >> 10) & 0x1c) | ((second >> 6) & 3);
        let width = (second & 0x1f) + 1;
        match (first >> 4) & 0x1f {
            0b00000 => {
                let base = if rn == 15 {
                    self.literal_base()
                } else {
                    self.reg(rn)
                };
                self.set_reg(rd, base.wrapping_add(imm12));
            }
            0b01010 => {
                let base = if rn == 15 {
                    self.literal_base()
                } else {
                    self.reg(rn)
                };
                self.set_reg(rd, base.wrapping_sub(imm12));
            }
            0b00100 => self.set_reg(rd, imm16),
            0b01100 => {
                let value = (imm16 << 16) | (self.reg(rd) & 0xffff);
                self.set_reg(rd, value);
            }
            op @ (0b10000 | 0b10010 | 0b11000 | 0b11010) => {
                if op & 0b10 != 0 && imm5 == 0 {
                    return Err(self.unsupported(Self::encoding(first, second), "SSAT16/USAT16"));
                }
                let (shift, amount) = decode_imm_shift(op & 0b10, imm5);
                let (operand, _) = shift_c(self.reg(rn), shift, amount, self.c);
                let (result, saturated) = if op & 0b01000 == 0 {
                    signed_sat(i64::from(operand as i32), (second & 0x1f) + 1)
                } else {
                    unsigned_sat(i64::from(operand as i32), second & 0x1f)
                };
                self.set_reg(rd, result);
                if saturated {
                    self.q = true;
                }
            }
            op @ (0b10100 | 0b11100) => {
                // SBFX / UBFX
                let lsb = imm5;
                if lsb + width > 32 {
                    return Err(
                        self.unsupported(Self::encoding(first, second), "bitfield past bit 31")
                    );
                }
                let field = (self.reg(rn) >> lsb) & mask(width);
                let value = if op == 0b10100 {
                    sign_extend(field, width)
                } else {
                    field
                };
                self.set_reg(rd, value);
            }
            0b10110 => {
                // BFI / BFC
                let lsb = imm5;
                let msb = second & 0x1f;
                if msb < lsb {
                    return Err(
                        self.unsupported(Self::encoding(first, second), "bitfield msb below lsb")
                    );
                }
                let field = mask(msb - lsb + 1) << lsb;
                let insert = if rn == 15 { 0 } else { self.reg(rn) << lsb };
                let value = (self.reg(rd) & !field) | (insert & field);
                self.set_reg(rd, value);
            }
            _ => return Err(self.undefined()),
        }
        Ok(())
    }

    /// Branches and miscellaneous control, A5.3.4.
    fn branch_and_control(&mut self, first: u32, second: u32) -> Step {
        let op1 = (second >> 12) & 7;
        let op = (first >> 4) & 0x7f;
        let s = (first >> 10) & 1;
        let j1 = (second >> 13) & 1;
        let j2 = (second >> 11) & 1;
        let imm11 = second & 0x7ff;
        if op1 & 0b101 == 0b000 {
            if op & 0b011_1000 != 0b011_1000 {
                // B<c>.W
                let imm =
                    (s << 20) | (j2 << 19) | (j1 << 18) | ((first & 0x3f) << 12) | (imm11 << 1);
                self.block_end = true;
                self.direct_branch = true;
                if self.condition((first >> 6) & 0xf) {
                    self.branch(self.reg(15).wrapping_add(sign_extend(imm, 21)));
                }
                return Ok(());
            }
            return match op {
                0b011_1000 | 0b011_1001 => self.move_to_special(first & 0xf, second),
                0b011_1010 => {
                    if second & 0x700 != 0 {
                        return Err(self.undefined());
                    }
                    self.hint(second & 0xff)
                }
                0b011_1011 => match (second >> 4) & 0xf {
                    // CLREX
                    0b0010 => {
                        self.set_monitor(false);
                        Ok(())
                    }
                    // DSB, DMB, ISB
                    0b0100..=0b0110 => Ok(()),
                    _ => Err(self.undefined()),
                },
                0b011_1110 | 0b011_1111 => {
                    let value = self.read_special(second & 0xff);
                    self.set_reg((second >> 8) & 0xf, value);
                    Ok(())
                }
                _ => Err(self.undefined()),
            };
        }
        let i1 = !(j1 ^ s) & 1;
        let i2 = !(j2 ^ s) & 1;
        let imm = (s << 24) | (i1 << 23) | (i2 << 22) | ((first & 0x3ff) << 12) | (imm11 << 1);
        let target = self.reg(15).wrapping_add(sign_extend(imm, 25));
        match op1 & 0b101 {
            0b001 => {
                self.direct_branch = true;
                self.branch(target);
                Ok(())
            }
            0b101 => {
                self.r[14] = self.pc.wrapping_add(4) | 1;
                self.branch(target);
                Ok(())
            }
            // BLX (immediate) switches to ARM state, which ARMv7-M lacks.
            _ => Err(self.undefined()),
        }
    }

    /// `MSR`.
    fn move_to_special(&mut self, rn: u32, second: u32) -> Step {
        let value = self.reg(rn);
        match second & 0xff {
            0..=3 => {
                if (second >> 10) & 2 != 0 {
                    self.set_apsr(value);
                }
            }
            4..=7 => {}
            8 => self.set_msp(value),
            9 => self.set_psp(value),
            16 => self.primask = value & 1 != 0,
            17 => self.basepri = value & 0xff,
            18 => {
                let value = value & 0xff;
                if value != 0 && (self.basepri == 0 || value < self.basepri) {
                    self.basepri = value;
                }
            }
            19 => self.faultmask = value & 1 != 0,
            20 => self.set_control(value),
            _ => return Err(self.unsupported(second, "MSR to an unknown special register")),
        }
        Ok(())
    }

    /// `MRS`.
    fn read_special(&self, sysm: u32) -> u32 {
        match sysm {
            0..=7 => {
                let mut value = 0;
                if sysm & 1 != 0 {
                    value |= self.ipsr & 0x1ff;
                }
                if sysm & 4 == 0 {
                    value |= self.apsr();
                }
                value
            }
            8 => self.msp(),
            9 => self.psp(),
            16 => u32::from(self.primask),
            17 | 18 => self.basepri,
            19 => u32::from(self.faultmask),
            20 => self.control,
            _ => 0,
        }
    }

    /// Load/store multiple, A5.3.5.
    fn load_store_multiple(&mut self, first: u32, second: u32) -> Step {
        let rn = first & 0xf;
        let load = first & 0x10 != 0;
        let writeback = first & 0x20 != 0;
        let list = second & 0xdfff;
        let count = list.count_ones();
        let base = self.reg(rn);
        match ((first >> 7) & 3, load) {
            (0b01, false) => {
                let end = self.store_multiple(base, list)?;
                if writeback {
                    self.set_reg(rn, end);
                }
            }
            (0b01, true) => {
                let (end, pc) = self.load_multiple_deferring_pc(base, list)?;
                if writeback && list & (1 << rn) == 0 {
                    self.set_reg(rn, end);
                }
                if let Some(target) = pc {
                    self.branch_exchange(target);
                }
            }
            (0b10, false) => {
                let start = base.wrapping_sub(4 * count);
                self.store_multiple(start, list)?;
                if writeback {
                    self.set_reg(rn, start);
                }
            }
            (0b10, true) => {
                let start = base.wrapping_sub(4 * count);
                let (_, pc) = self.load_multiple_deferring_pc(start, list)?;
                if writeback && list & (1 << rn) == 0 {
                    self.set_reg(rn, start);
                }
                if let Some(target) = pc {
                    self.branch_exchange(target);
                }
            }
            _ => return Err(self.undefined()),
        }
        Ok(())
    }

    /// Load/store dual or exclusive, table branch, A5.3.6.
    fn load_store_dual_exclusive(&mut self, first: u32, second: u32) -> Step {
        let op1 = (first >> 7) & 3;
        let op2 = (first >> 4) & 3;
        let op3 = (second >> 4) & 0xf;
        let rn = first & 0xf;
        let rt = (second >> 12) & 0xf;
        let rt2 = (second >> 8) & 0xf;
        let imm8 = (second & 0xff) << 2;
        match (op1, op2) {
            (0b00, 0b00) => {
                // STREX Rd, Rt, [Rn, #imm]
                let address = self.reg(rn).wrapping_add(imm8);
                if address & 3 != 0 {
                    return Err(self.fault(FaultKind::Unaligned, Some(address)));
                }
                let status = if self.take_monitor() {
                    self.store(address, 4, self.reg(rt))?;
                    0
                } else {
                    1
                };
                self.set_reg(rt2, status);
            }
            (0b00, 0b01) => {
                let address = self.reg(rn).wrapping_add(imm8);
                let value = self.load_word_aligned(address)?;
                self.set_reg(rt, value);
                self.set_monitor(true);
            }
            (0b01, 0b00) => {
                // STREXB / STREXH Rd, Rt, [Rn]
                let size = match op3 {
                    0b0100 => 1,
                    0b0101 => 2,
                    _ => return Err(self.undefined()),
                };
                let address = self.reg(rn);
                if address & (size - 1) != 0 {
                    return Err(self.fault(FaultKind::Unaligned, Some(address)));
                }
                let status = if self.take_monitor() {
                    self.store(address, size, self.reg(rt))?;
                    0
                } else {
                    1
                };
                self.set_reg(second & 0xf, status);
            }
            (0b01, 0b01) => match op3 {
                0b0000 | 0b0001 => {
                    // TBB / TBH
                    let base = self.reg(rn);
                    let index = self.reg(second & 0xf);
                    let offset = if op3 == 0 {
                        self.load(base.wrapping_add(index), 1)?
                    } else {
                        self.load(base.wrapping_add(index << 1), 2)?
                    };
                    self.branch(self.reg(15).wrapping_add(offset << 1));
                }
                0b0100 | 0b0101 => {
                    let size = if op3 == 0b0100 { 1 } else { 2 };
                    let address = self.reg(rn);
                    if address & (size - 1) != 0 {
                        return Err(self.fault(FaultKind::Unaligned, Some(address)));
                    }
                    let value = self.load(address, size)?;
                    self.set_reg(rt, value);
                    self.set_monitor(true);
                }
                _ => return Err(self.undefined()),
            },
            _ => {
                // LDRD / STRD (immediate), and LDRD (literal).
                let index = first & 0x100 != 0;
                let add = first & 0x80 != 0;
                let writeback = first & 0x20 != 0;
                let load = first & 0x10 != 0;
                let base = if rn == 15 {
                    self.literal_base()
                } else {
                    self.reg(rn)
                };
                let offset_address = if add {
                    base.wrapping_add(imm8)
                } else {
                    base.wrapping_sub(imm8)
                };
                let address = if index { offset_address } else { base };
                if load {
                    let low = self.load_word_aligned(address)?;
                    let high = self.load_word_aligned(address.wrapping_add(4))?;
                    if writeback && rn != 15 {
                        self.set_reg(rn, offset_address);
                    }
                    self.set_reg(rt, low);
                    self.set_reg(rt2, high);
                } else {
                    if rn == 15 {
                        return Err(self.undefined());
                    }
                    self.store_word_aligned(address, self.reg(rt))?;
                    self.store_word_aligned(address.wrapping_add(4), self.reg(rt2))?;
                    if writeback {
                        self.set_reg(rn, offset_address);
                    }
                }
            }
        }
        Ok(())
    }

    /// Store single data item, load byte/halfword/word and memory hints
    /// (A5.3.7 - A5.3.10).
    fn load_store_single(&mut self, first: u32, second: u32) -> Step {
        let load = first & 0x10 != 0;
        let size = 1u32 << ((first >> 5) & 3);
        let signed = first & 0x100 != 0;
        let rn = first & 0xf;
        let rt = (second >> 12) & 0xf;
        if size == 8 || (!load && signed) {
            return Err(self.undefined());
        }
        let mut writeback = None;
        let address = if rn == 15 {
            if !load {
                return Err(self.undefined());
            }
            let imm12 = second & 0xfff;
            if first & 0x80 != 0 {
                self.literal_base().wrapping_add(imm12)
            } else {
                self.literal_base().wrapping_sub(imm12)
            }
        } else if first & 0x80 != 0 {
            self.reg(rn).wrapping_add(second & 0xfff)
        } else if second & 0x800 != 0 {
            let index = second & 0x400 != 0;
            let add = second & 0x200 != 0;
            let back = second & 0x100 != 0;
            if !index && !back {
                return Err(self.undefined());
            }
            let imm8 = second & 0xff;
            let base = self.reg(rn);
            let offset_address = if add {
                base.wrapping_add(imm8)
            } else {
                base.wrapping_sub(imm8)
            };
            if back {
                writeback = Some(offset_address);
            }
            if index {
                offset_address
            } else {
                base
            }
        } else if (second >> 6) & 0x3f == 0 {
            let shift = (second >> 4) & 3;
            self.reg(rn).wrapping_add(self.reg(second & 0xf) << shift)
        } else {
            return Err(self.undefined());
        };
        if load {
            if rt == 15 && size != 4 {
                // PLD, PLI and the unallocated memory hints.
                return Ok(());
            }
            let raw = self.load(address, size)?;
            let value = match (signed, size) {
                (true, 1) => sign_extend(raw, 8),
                (true, _) => sign_extend(raw, 16),
                _ => raw,
            };
            if let Some(updated) = writeback {
                self.set_reg(rn, updated);
            }
            if rt == 15 {
                self.branch_exchange(value);
            } else {
                self.set_reg(rt, value);
            }
        } else {
            if rt == 15 {
                return Err(self.unsupported(Self::encoding(first, second), "store of the PC"));
            }
            self.store(address, size, self.reg(rt))?;
            if let Some(updated) = writeback {
                self.set_reg(rn, updated);
            }
        }
        Ok(())
    }

    /// Data processing (register), A5.3.12, with the miscellaneous
    /// operations of A5.3.15.
    fn data_processing_register(&mut self, first: u32, second: u32) -> Step {
        let op1 = (first >> 4) & 0xf;
        let op2 = (second >> 4) & 0xf;
        let rn = first & 0xf;
        let rd = (second >> 8) & 0xf;
        let rm = second & 0xf;
        if second & 0xf000 != 0xf000 {
            return Err(self.undefined());
        }
        if rd == 15 {
            return Err(self.unsupported(
                Self::encoding(first, second),
                "data-processing write to the PC",
            ));
        }
        if op2 == 0 && op1 & 0b1000 == 0 {
            // LSL / LSR / ASR / ROR (register)
            let (result, carry) = shift_c(
                self.reg(rn),
                shift_kind(op1 >> 1),
                self.reg(rm) & 0xff,
                self.c,
            );
            self.set_reg(rd, result);
            if op1 & 1 != 0 {
                self.set_nz(result);
                self.c = carry;
            }
            return Ok(());
        }
        if op1 & 0b1000 == 0 && op2 & 0b1000 != 0 {
            // Extend, and extend and add.
            let rotated = self.reg(rm).rotate_right(((second >> 4) & 3) * 8);
            let value = match op1 {
                0b0000 => sign_extend(rotated, 16),
                0b0001 => rotated & 0xffff,
                0b0100 => sign_extend(rotated, 8),
                0b0101 => rotated & 0xff,
                0b0010 | 0b0011 => {
                    return Err(self.unsupported(Self::encoding(first, second), "SXTB16/UXTB16"))
                }
                _ => return Err(self.undefined()),
            };
            let result = if rn == 15 {
                value
            } else {
                self.reg(rn).wrapping_add(value)
            };
            self.set_reg(rd, result);
            return Ok(());
        }
        if op1 & 0b1100 == 0b1000 && op2 & 0b1100 == 0b1000 {
            let value = self.reg(rm);
            let result = match (op1 & 3, op2 & 3) {
                (0b01, 0b00) => value.swap_bytes(),
                (0b01, 0b01) => ((value & 0x00ff_00ff) << 8) | ((value >> 8) & 0x00ff_00ff),
                (0b01, 0b10) => value.reverse_bits(),
                (0b01, 0b11) => sign_extend(((value & 0xff) << 8) | ((value >> 8) & 0xff), 16),
                (0b11, 0b00) => value.leading_zeros(),
                (0b00, _) | (0b10, 0b00) => {
                    return Err(self.unsupported(
                        Self::encoding(first, second),
                        "saturating add/subtract or SEL",
                    ))
                }
                _ => return Err(self.undefined()),
            };
            self.set_reg(rd, result);
            return Ok(());
        }
        // Parallel add/subtract (A5.3.13, A5.3.14), but for the unallocated
        // op1 x11 and op2 x11.
        if op1 & 0b1000 != 0 && op2 & 0b1000 == 0 && op1 & 0b011 != 0b011 && op2 & 0b011 != 0b011 {
            return Err(self.unsupported(Self::encoding(first, second), "parallel add/subtract"));
        }
        Err(self.undefined())
    }

    /// Multiply, multiply accumulate, A5.3.16.
    fn multiply(&mut self, first: u32, second: u32) -> Step {
        let op1 = (first >> 4) & 7;
        let op2 = (second >> 4) & 3;
        let rn = first & 0xf;
        let ra = (second >> 12) & 0xf;
        let rd = (second >> 8) & 0xf;
        let rm = second & 0xf;
        if second & 0xc0 != 0 {
            return Err(self.undefined());
        }
        let (a, b) = (self.reg(rn), self.reg(rm));
        let result = match (op1, op2) {
            (0b000, 0b00) if ra == 15 => a.wrapping_mul(b),
            (0b000, 0b00) => a.wrapping_mul(b).wrapping_add(self.reg(ra)),
            (0b000, 0b01) => self.reg(ra).wrapping_sub(a.wrapping_mul(b)),
            (0b001, _) => {
                // SMULxy / SMLAxy
                let half = |value: u32, top: bool| -> i64 {
                    i64::from(if top {
                        (value >> 16) as i16
                    } else {
                        value as i16
                    })
                };
                let product = half(a, op2 & 2 != 0) * half(b, op2 & 1 != 0);
                if ra == 15 {
                    product as u32
                } else {
                    let sum = product + i64::from(self.reg(ra) as i32);
                    if sum != i64::from(sum as i32) {
                        self.q = true;
                    }
                    sum as u32
                }
            }
            (0b011, 0b00 | 0b01) => {
                // SMULWy / SMLAWy
                let half = i64::from(if op2 & 1 != 0 {
                    (b >> 16) as i16
                } else {
                    b as i16
                });
                let product = (i64::from(a as i32) * half) >> 16;
                if ra == 15 {
                    product as u32
                } else {
                    let sum = product + i64::from(self.reg(ra) as i32);
                    if sum != i64::from(sum as i32) {
                        self.q = true;
                    }
                    sum as u32
                }
            }
            (0b101 | 0b110, 0b00 | 0b01) => {
                // SMMUL / SMMLA / SMMLS, rounding with op2 bit 0.
                let product = i64::from(a as i32) * i64::from(b as i32);
                let accumulate = if ra == 15 {
                    0
                } else {
                    i64::from(self.reg(ra) as i32) << 32
                };
                let mut value = if op1 == 0b110 {
                    accumulate.wrapping_sub(product)
                } else {
                    accumulate.wrapping_add(product)
                };
                if op2 & 1 != 0 {
                    value = value.wrapping_add(0x8000_0000);
                }
                (value >> 32) as u32
            }
            (0b010 | 0b100, 0b00 | 0b01) | (0b111, 0b00) => {
                return Err(self.unsupported(
                    Self::encoding(first, second),
                    "dual or sum-of-absolute-differences multiply",
                ))
            }
            _ => return Err(self.undefined()),
        };
        self.set_reg(rd, result);
        Ok(())
    }

    /// Long multiply, long multiply accumulate, divide, A5.3.17.
    fn long_multiply_divide(&mut self, first: u32, second: u32) -> Step {
        let op1 = (first >> 4) & 7;
        let op2 = (second >> 4) & 0xf;
        let rn = first & 0xf;
        let rdlo = (second >> 12) & 0xf;
        let rdhi = (second >> 8) & 0xf;
        let rm = second & 0xf;
        let (a, b) = (self.reg(rn), self.reg(rm));
        let accumulated = (u64::from(self.reg(rdhi)) << 32) | u64::from(self.reg(rdlo));
        let result: u64 = match (op1, op2) {
            (0b000, 0b0000) => (i64::from(a as i32) * i64::from(b as i32)) as u64,
            (0b010, 0b0000) => u64::from(a) * u64::from(b),
            (0b100, 0b0000) => {
                ((i64::from(a as i32) * i64::from(b as i32)).wrapping_add(accumulated as i64))
                    as u64
            }
            (0b110, 0b0000) => (u64::from(a) * u64::from(b)).wrapping_add(accumulated),
            (0b110, 0b0110) => {
                // UMAAL
                u64::from(a) * u64::from(b) + u64::from(self.reg(rdhi)) + u64::from(self.reg(rdlo))
            }
            (0b001, 0b1111) => {
                let value = if b == 0 {
                    self.divide_by_zero()?
                } else {
                    (a as i32).wrapping_div(b as i32) as u32
                };
                self.set_reg(rdhi, value);
                return Ok(());
            }
            (0b011, 0b1111) => {
                let value = match a.checked_div(b) {
                    Some(quotient) => quotient,
                    None => self.divide_by_zero()?,
                };
                self.set_reg(rdhi, value);
                return Ok(());
            }
            (0b100, 0b1000..=0b1101) | (0b101, 0b1100 | 0b1101) => {
                return Err(self.unsupported(
                    Self::encoding(first, second),
                    "halfword or dual long multiply",
                ))
            }
            _ => return Err(self.undefined()),
        };
        self.set_reg(rdlo, result as u32);
        self.set_reg(rdhi, (result >> 32) as u32);
        Ok(())
    }
}

/// The low `width` bits set (1..=32).
fn mask(width: u32) -> u32 {
    if width >= 32 {
        u32::MAX
    } else {
        (1 << width) - 1
    }
}
