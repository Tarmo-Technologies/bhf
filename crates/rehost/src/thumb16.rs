// SPDX-License-Identifier: Apache-2.0

//! 16-bit Thumb instructions (ARMv7-M ARM, A5.2).

use crate::alu::{add_with_carry, shift_c, sign_extend, Shift};
use crate::cpu::{Core, Step, Trap};

impl Core {
    pub(crate) fn exec16(&mut self, hw: u32) -> Step {
        // 16-bit data processing sets the flags outside an IT block only.
        let setflags = !self.in_it_block();
        match hw >> 10 {
            0b00_0000..=0b00_1111 => self.shift_add_move_compare(hw, setflags),
            0b01_0000 => self.data_processing16(hw, setflags),
            0b01_0001 => self.special_data_and_branch(hw),
            0b01_0010 | 0b01_0011 => {
                let rt = (hw >> 8) & 7;
                let address = self.literal_base().wrapping_add((hw & 0xff) << 2);
                let value = self.load(address, 4)?;
                self.set_reg(rt, value);
                Ok(())
            }
            0b01_0100..=0b10_0111 => self.load_store16(hw),
            0b10_1000 | 0b10_1001 => {
                // ADR
                let value = self.literal_base().wrapping_add((hw & 0xff) << 2);
                self.set_reg((hw >> 8) & 7, value);
                Ok(())
            }
            0b10_1010 | 0b10_1011 => {
                // ADD Rd, SP, #imm8
                let value = self.reg(13).wrapping_add((hw & 0xff) << 2);
                self.set_reg((hw >> 8) & 7, value);
                Ok(())
            }
            0b10_1100..=0b10_1111 => self.miscellaneous16(hw),
            0b11_0000 | 0b11_0001 => {
                // STM Rn!, {list}
                let rn = (hw >> 8) & 7;
                let list = hw & 0xff;
                let end = self.store_multiple(self.reg(rn), list)?;
                self.set_reg(rn, end);
                Ok(())
            }
            0b11_0010 | 0b11_0011 => {
                // LDM Rn{!}, {list}: written back unless Rn is in the list.
                let rn = (hw >> 8) & 7;
                let list = hw & 0xff;
                let end = self.load_multiple(self.reg(rn), list)?;
                if list & (1 << rn) == 0 {
                    self.set_reg(rn, end);
                }
                Ok(())
            }
            0b11_0100..=0b11_0111 => {
                let cond = (hw >> 8) & 0xf;
                match cond {
                    0b1110 => Err(self.undefined()),
                    0b1111 => self.supervisor_call(),
                    _ => {
                        let offset = sign_extend((hw & 0xff) << 1, 9);
                        self.block_end = true;
                        self.direct_branch = true;
                        if self.condition(cond) {
                            self.branch(self.reg(15).wrapping_add(offset));
                        }
                        Ok(())
                    }
                }
            }
            0b11_1000 | 0b11_1001 => {
                let offset = sign_extend((hw & 0x7ff) << 1, 12);
                self.direct_branch = true;
                self.branch(self.reg(15).wrapping_add(offset));
                Ok(())
            }
            _ => Err(self.unsupported(hw, "16-bit encoding")),
        }
    }

    /// Shift (immediate), add, subtract, move and compare (A5.2.1).
    fn shift_add_move_compare(&mut self, hw: u32, setflags: bool) -> Step {
        let rd = hw & 7;
        let rn = (hw >> 3) & 7;
        let imm5 = (hw >> 6) & 0x1f;
        let rdn = (hw >> 8) & 7;
        let imm8 = hw & 0xff;
        match (hw >> 11) & 7 {
            kind @ 0b000..=0b010 => {
                let (shift, amount) = match kind {
                    0 => (Shift::Lsl, imm5),
                    1 => (Shift::Lsr, if imm5 == 0 { 32 } else { imm5 }),
                    _ => (Shift::Asr, if imm5 == 0 { 32 } else { imm5 }),
                };
                let (result, carry) = shift_c(self.reg(rn), shift, amount, self.c);
                self.set_reg(rd, result);
                if setflags {
                    self.set_nz(result);
                    self.c = carry;
                }
            }
            0b011 => {
                let operand = if hw & (1 << 10) != 0 {
                    (hw >> 6) & 7
                } else {
                    self.reg((hw >> 6) & 7)
                };
                let subtract = hw & (1 << 9) != 0;
                let (result, carry, overflow) = if subtract {
                    add_with_carry(self.reg(rn), !operand, true)
                } else {
                    add_with_carry(self.reg(rn), operand, false)
                };
                self.set_reg(rd, result);
                if setflags {
                    self.set_nzcv(result, carry, overflow);
                }
            }
            0b100 => {
                self.set_reg(rdn, imm8);
                if setflags {
                    self.set_nz(imm8);
                }
            }
            0b101 => {
                let (result, carry, overflow) = add_with_carry(self.reg(rdn), !imm8, true);
                self.set_nzcv(result, carry, overflow);
            }
            0b110 => {
                let (result, carry, overflow) = add_with_carry(self.reg(rdn), imm8, false);
                self.set_reg(rdn, result);
                if setflags {
                    self.set_nzcv(result, carry, overflow);
                }
            }
            _ => {
                let (result, carry, overflow) = add_with_carry(self.reg(rdn), !imm8, true);
                self.set_reg(rdn, result);
                if setflags {
                    self.set_nzcv(result, carry, overflow);
                }
            }
        }
        Ok(())
    }

    /// Data processing on low registers (A5.2.2).
    fn data_processing16(&mut self, hw: u32, setflags: bool) -> Step {
        let rdn = hw & 7;
        let rm = (hw >> 3) & 7;
        let a = self.reg(rdn);
        let b = self.reg(rm);
        let logical = |core: &mut Self, result: u32, carry: bool, write: bool| {
            if write {
                core.set_reg(rdn, result);
            }
            if setflags || !write {
                core.set_nz(result);
                core.c = carry;
            }
        };
        let arithmetic = |core: &mut Self, (result, carry, overflow): (u32, bool, bool), write| {
            if write {
                core.set_reg(rdn, result);
            }
            if setflags || !write {
                core.set_nzcv(result, carry, overflow);
            }
        };
        match (hw >> 6) & 0xf {
            0b0000 => logical(self, a & b, self.c, true),
            0b0001 => logical(self, a ^ b, self.c, true),
            0b0010 => {
                let (result, carry) = shift_c(a, Shift::Lsl, b & 0xff, self.c);
                logical(self, result, carry, true);
            }
            0b0011 => {
                let (result, carry) = shift_c(a, Shift::Lsr, b & 0xff, self.c);
                logical(self, result, carry, true);
            }
            0b0100 => {
                let (result, carry) = shift_c(a, Shift::Asr, b & 0xff, self.c);
                logical(self, result, carry, true);
            }
            0b0101 => arithmetic(self, add_with_carry(a, b, self.c), true),
            0b0110 => arithmetic(self, add_with_carry(a, !b, self.c), true),
            0b0111 => {
                let (result, carry) = shift_c(a, Shift::Ror, b & 0xff, self.c);
                logical(self, result, carry, true);
            }
            // TST
            0b1000 => logical(self, a & b, self.c, false),
            // RSB Rd, Rn, #0
            0b1001 => arithmetic(self, add_with_carry(!b, 0, true), true),
            // CMP
            0b1010 => arithmetic(self, add_with_carry(a, !b, true), false),
            // CMN
            0b1011 => arithmetic(self, add_with_carry(a, b, false), false),
            0b1100 => logical(self, a | b, self.c, true),
            0b1101 => logical(self, a.wrapping_mul(b), self.c, true),
            0b1110 => logical(self, a & !b, self.c, true),
            _ => logical(self, !b, self.c, true),
        }
        Ok(())
    }

    /// Special data instructions and branch and exchange (A5.2.3).
    fn special_data_and_branch(&mut self, hw: u32) -> Step {
        let rdn = ((hw >> 4) & 8) | (hw & 7);
        let rm = (hw >> 3) & 0xf;
        match (hw >> 6) & 0xf {
            0b0000..=0b0011 => {
                // ADD Rdn, Rm: no flags; a write to the PC branches.
                let result = self.reg(rdn).wrapping_add(self.reg(rm));
                self.set_reg(rdn, result);
            }
            0b0101..=0b0111 => {
                let (result, carry, overflow) = add_with_carry(self.reg(rdn), !self.reg(rm), true);
                self.set_nzcv(result, carry, overflow);
            }
            0b1000..=0b1011 => {
                // MOV Rd, Rm
                let value = self.reg(rm);
                self.set_reg(rdn, value);
            }
            0b1100 | 0b1101 => self.branch_exchange(self.reg(rm)),
            0b1110 | 0b1111 => {
                let target = self.reg(rm);
                self.r[14] = self.pc.wrapping_add(2) | 1;
                self.branch_link_exchange(target);
            }
            _ => return Err(self.unsupported(hw, "UNPREDICTABLE ADD encoding")),
        }
        Ok(())
    }

    /// Load and store a single item (A5.2.4).
    fn load_store16(&mut self, hw: u32) -> Step {
        let rt = hw & 7;
        let rn = (hw >> 3) & 7;
        let imm5 = (hw >> 6) & 0x1f;
        let load = hw & (1 << 11) != 0;
        match hw >> 12 {
            0b0101 => {
                let address = self.reg(rn).wrapping_add(self.reg((hw >> 6) & 7));
                match (hw >> 9) & 7 {
                    0 => self.store(address, 4, self.reg(rt))?,
                    1 => self.store(address, 2, self.reg(rt))?,
                    2 => self.store(address, 1, self.reg(rt))?,
                    3 => {
                        let value = sign_extend(self.load(address, 1)?, 8);
                        self.set_reg(rt, value);
                    }
                    4 => {
                        let value = self.load(address, 4)?;
                        self.set_reg(rt, value);
                    }
                    5 => {
                        let value = self.load(address, 2)?;
                        self.set_reg(rt, value);
                    }
                    6 => {
                        let value = self.load(address, 1)?;
                        self.set_reg(rt, value);
                    }
                    _ => {
                        let value = sign_extend(self.load(address, 2)?, 16);
                        self.set_reg(rt, value);
                    }
                }
            }
            0b0110 => self.load_or_store(load, self.reg(rn).wrapping_add(imm5 << 2), 4, rt)?,
            0b0111 => self.load_or_store(load, self.reg(rn).wrapping_add(imm5), 1, rt)?,
            0b1000 => self.load_or_store(load, self.reg(rn).wrapping_add(imm5 << 1), 2, rt)?,
            _ => {
                let address = self.reg(13).wrapping_add((hw & 0xff) << 2);
                self.load_or_store(load, address, 4, (hw >> 8) & 7)?;
            }
        }
        Ok(())
    }

    fn load_or_store(&mut self, load: bool, address: u32, size: u32, rt: u32) -> Step {
        if load {
            let value = self.load(address, size)?;
            self.set_reg(rt, value);
            Ok(())
        } else {
            self.store(address, size, self.reg(rt))
        }
    }

    /// Miscellaneous 16-bit instructions (A5.2.5).
    fn miscellaneous16(&mut self, hw: u32) -> Step {
        let op = (hw >> 5) & 0x7f;
        let rd = hw & 7;
        let rm = (hw >> 3) & 7;
        match op {
            0b000_0000..=0b000_0011 => {
                let value = self.reg(13).wrapping_add((hw & 0x7f) << 2);
                self.set_reg(13, value);
            }
            0b000_0100..=0b000_0111 => {
                let value = self.reg(13).wrapping_sub((hw & 0x7f) << 2);
                self.set_reg(13, value);
            }
            0b000_1000..=0b000_1111
            | 0b001_1000..=0b001_1111
            | 0b100_1000..=0b100_1111
            | 0b101_1000..=0b101_1111 => {
                // CBZ / CBNZ
                let nonzero = hw & (1 << 11) != 0;
                let offset = ((hw >> 3) & 0x40) | ((hw >> 2) & 0x3e);
                self.block_end = true;
                if (self.reg(hw & 7) != 0) == nonzero {
                    self.branch(self.reg(15).wrapping_add(offset));
                }
            }
            0b001_0000 | 0b001_0001 => self.set_reg(rd, sign_extend(self.reg(rm), 16)),
            0b001_0010 | 0b001_0011 => self.set_reg(rd, sign_extend(self.reg(rm), 8)),
            0b001_0100 | 0b001_0101 => self.set_reg(rd, self.reg(rm) & 0xffff),
            0b001_0110 | 0b001_0111 => self.set_reg(rd, self.reg(rm) & 0xff),
            0b010_0000..=0b010_1111 => {
                // PUSH {list, LR}
                let list = (hw & 0xff) | ((hw & 0x100) << 6);
                let start = self.reg(13).wrapping_sub(4 * list.count_ones());
                self.store_multiple(start, list)?;
                self.set_reg(13, start);
            }
            0b011_0011 => {
                // CPSIE / CPSID
                let disable = hw & 0x10 != 0;
                if hw & 2 != 0 {
                    self.primask = disable;
                }
                if hw & 1 != 0 {
                    self.faultmask = disable;
                }
            }
            0b101_0000 | 0b101_0001 => self.set_reg(rd, self.reg(rm).swap_bytes()),
            0b101_0010 | 0b101_0011 => {
                let value = self.reg(rm);
                self.set_reg(
                    rd,
                    ((value & 0x00ff_00ff) << 8) | ((value >> 8) & 0x00ff_00ff),
                );
            }
            0b101_0110 | 0b101_0111 => {
                let value = self.reg(rm);
                let swapped = ((value & 0xff) << 8) | ((value >> 8) & 0xff);
                self.set_reg(rd, sign_extend(swapped, 16));
            }
            0b110_0000..=0b110_1111 => {
                // POP {list, PC}
                let list = (hw & 0xff) | ((hw & 0x100) << 7);
                let start = self.reg(13);
                let end = self.load_multiple_deferring_pc(start, list)?;
                self.set_reg(13, end.0);
                if let Some(target) = end.1 {
                    self.branch_exchange(target);
                }
            }
            0b111_0000..=0b111_0111 => self.breakpoint(hw & 0xff)?,
            0b111_1000..=0b111_1111 => {
                if hw & 0xf != 0 {
                    self.it = (hw & 0xff) as u8;
                } else {
                    self.hint((hw >> 4) & 0xf)?;
                }
            }
            // 0110000-0110010, 0110100-0111111, 1000xxx and 101010x are
            // unallocated.
            _ => return Err(self.undefined()),
        }
        Ok(())
    }

    /// NOP, YIELD, WFE, WFI and SEV; other hints execute as NOP.
    pub(crate) fn hint(&mut self, hint: u32) -> Step {
        match hint {
            2 => self.wait_for_event(),
            3 => self.wait_for_interrupt(),
            4 => {
                self.send_event();
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Store the registers in `list` at ascending addresses from `start`,
    /// which must be word aligned; returns the address past the last.
    pub(crate) fn store_multiple(&mut self, start: u32, list: u32) -> Result<u32, Trap> {
        let mut address = start;
        for register in 0..16 {
            if list & (1 << register) != 0 {
                self.store_word_aligned(address, self.reg(register))?;
                address = address.wrapping_add(4);
            }
        }
        Ok(address)
    }

    /// Load the registers in `list` from ascending addresses from `start`;
    /// a loaded PC branches. Returns the address past the last.
    pub(crate) fn load_multiple(&mut self, start: u32, list: u32) -> Result<u32, Trap> {
        let (end, pc) = self.load_multiple_deferring_pc(start, list)?;
        if let Some(target) = pc {
            self.branch_exchange(target);
        }
        Ok(end)
    }

    /// As [`Self::load_multiple`], returning a loaded PC instead of
    /// branching to it, so the caller writes the base back first.
    pub(crate) fn load_multiple_deferring_pc(
        &mut self,
        start: u32,
        list: u32,
    ) -> Result<(u32, Option<u32>), Trap> {
        let mut address = start;
        let mut values = [0u32; 16];
        for (register, value) in values.iter_mut().enumerate() {
            if list & (1 << register) != 0 {
                *value = self.load_word_aligned(address)?;
                address = address.wrapping_add(4);
            }
        }
        for (register, value) in values.iter().enumerate().take(15) {
            if list & (1 << register) != 0 {
                self.set_reg(register as u32, *value);
            }
        }
        Ok((address, (list & 0x8000 != 0).then_some(values[15])))
    }
}
