// SPDX-License-Identifier: Apache-2.0

//! Faults: what the core does instead of the instruction a Cortex-M would
//! answer with a MemManage, BusFault, UsageFault or HardFault exception.
//! The emulator stops the run at the fault instead of entering a handler, so
//! the fault is reported with the state that caused it.

/// What went wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FaultKind {
    /// A load from an address no memory or peripheral window answers.
    ReadUnmapped,
    /// A store to an address no memory or peripheral window answers.
    WriteUnmapped,
    /// A store to read-only image memory.
    WriteReadOnly,
    /// An instruction fetch from an address that holds no code: unmapped,
    /// or in the peripheral, device or system space, which never executes.
    FetchInvalid,
    /// An interworking branch cleared the Thumb bit (UsageFault INVSTATE).
    InvalidState,
    /// `UDF` or an encoding the architecture leaves undefined (UNDEFINSTR).
    Undefined,
    /// A multi-word, exclusive or doubleword access at an address that is not
    /// word aligned, or any unaligned access with `CCR.UNALIGN_TRP` set.
    Unaligned,
    /// `SDIV`/`UDIV` by zero with `CCR.DIV_0_TRP` set.
    DivideByZero,
    /// A coprocessor (floating-point) instruction with the coprocessor
    /// disabled in `CPACR` (UsageFault NOCP).
    NoCoprocessor,
    /// `BKPT` with no debugger attached, which escalates to HardFault.
    Breakpoint,
    /// An exception return with an invalid `EXC_RETURN` (UsageFault INVPC).
    InvalidExceptionReturn,
    /// An `SVC` the core cannot take at the current execution priority, which
    /// escalates to HardFault.
    Escalation,
}

impl FaultKind {
    /// A stable name for the kind.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadUnmapped => "read_unmapped",
            Self::WriteUnmapped => "write_unmapped",
            Self::WriteReadOnly => "write_read_only",
            Self::FetchInvalid => "fetch_invalid",
            Self::InvalidState => "invalid_state",
            Self::Undefined => "undefined_instruction",
            Self::Unaligned => "unaligned_access",
            Self::DivideByZero => "divide_by_zero",
            Self::NoCoprocessor => "no_coprocessor",
            Self::Breakpoint => "breakpoint",
            Self::InvalidExceptionReturn => "invalid_exception_return",
            Self::Escalation => "escalation",
        }
    }

    /// The finding class the kind belongs to.
    pub fn class(self) -> FaultClass {
        match self {
            Self::ReadUnmapped | Self::WriteUnmapped | Self::WriteReadOnly | Self::Unaligned => {
                FaultClass::InvalidAccess
            }
            Self::FetchInvalid | Self::InvalidState | Self::InvalidExceptionReturn => {
                FaultClass::BadPc
            }
            Self::Undefined
            | Self::DivideByZero
            | Self::NoCoprocessor
            | Self::Breakpoint
            | Self::Escalation => FaultClass::HardFault,
        }
    }

    /// What the kind means, as a phrase.
    pub fn describe(self) -> &'static str {
        match self {
            Self::ReadUnmapped => "read of unmapped memory",
            Self::WriteUnmapped => "write to unmapped memory",
            Self::WriteReadOnly => "write to read-only image memory",
            Self::FetchInvalid => "instruction fetch from an address that holds no code",
            Self::InvalidState => "branch to an address without the Thumb bit",
            Self::Undefined => "undefined instruction",
            Self::Unaligned => "unaligned access",
            Self::DivideByZero => "divide by zero",
            Self::NoCoprocessor => "coprocessor instruction with the coprocessor disabled",
            Self::Breakpoint => "breakpoint with no debugger",
            Self::InvalidExceptionReturn => "invalid exception return",
            Self::Escalation => "SVC at a priority that cannot take it",
        }
    }
}

/// The finding class of a fault: what a report groups faults by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FaultClass {
    /// A load or store the memory map does not allow: unmapped, read-only,
    /// or misaligned for the instruction.
    InvalidAccess,
    /// Execution went where no code can run: a fetch from an address that
    /// holds none, a branch that cleared the Thumb bit, or an invalid
    /// exception-return value in the PC.
    BadPc,
    /// Any other condition a Cortex-M answers with a HardFault: an undefined
    /// instruction, a trapped divide by zero, a disabled coprocessor, a
    /// breakpoint, or an escalated SVC.
    HardFault,
}

impl FaultClass {
    /// A stable name for the class.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidAccess => "invalid_access",
            Self::BadPc => "bad_pc",
            Self::HardFault => "hard_fault",
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Self::InvalidAccess => "invalid memory access",
            Self::BadPc => "bad PC",
            Self::HardFault => "HardFault",
        }
    }
}

/// A fault and the core state at it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fault {
    pub kind: FaultKind,
    /// The address of the instruction that faulted. For a fetch fault, the
    /// address the core tried to execute.
    pub pc: u32,
    /// The data address of an access fault, or the target of a fetch or
    /// state fault.
    pub address: Option<u32>,
    /// For a fetch or state fault, the instruction that branched there.
    pub from: Option<u32>,
    /// `r0`-`r15` at the fault, `r15` being `pc`.
    pub registers: [u32; 16],
    pub xpsr: u32,
}

impl Fault {
    pub fn class(&self) -> FaultClass {
        self.kind.class()
    }

    /// The instruction the fault is attributed to: for a fetch or Thumb-state
    /// fault, the branch that went there (where it went depends on the
    /// input); otherwise the faulting instruction.
    pub fn site(&self) -> u32 {
        match self.kind {
            FaultKind::FetchInvalid | FaultKind::InvalidState => self.from.unwrap_or(self.pc),
            _ => self.pc,
        }
    }

    /// A stable identity: the class, the kind and the site. Two inputs that
    /// fault the same way at the same instruction share it, whatever address
    /// they touched, so it deduplicates findings and a replay matches on it.
    pub fn signature(&self) -> String {
        format!(
            "{}:{}:{:#010x}",
            self.class().as_str(),
            self.kind.as_str(),
            self.site()
        )
    }

    /// One line describing the fault.
    pub fn message(&self) -> String {
        let mut message = format!("{}: {}", self.class().describe(), self.kind.describe());
        if let Some(address) = self.address {
            message.push_str(&format!(" at {address:#010x}"));
        }
        match (self.kind, self.from) {
            (FaultKind::FetchInvalid | FaultKind::InvalidState, Some(from)) => {
                message.push_str(&format!(", branched to from pc {from:#010x}"));
            }
            _ => message.push_str(&format!(" (pc {:#010x})", self.pc)),
        }
        message
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fault(kind: FaultKind, pc: u32, address: Option<u32>, from: Option<u32>) -> Fault {
        Fault {
            kind,
            pc,
            address,
            from,
            registers: [0; 16],
            xpsr: 0x0100_0000,
        }
    }

    #[test]
    fn every_kind_has_one_of_the_three_classes() {
        use FaultKind::*;
        for (kind, class) in [
            (ReadUnmapped, FaultClass::InvalidAccess),
            (WriteUnmapped, FaultClass::InvalidAccess),
            (WriteReadOnly, FaultClass::InvalidAccess),
            (Unaligned, FaultClass::InvalidAccess),
            (FetchInvalid, FaultClass::BadPc),
            (InvalidState, FaultClass::BadPc),
            (InvalidExceptionReturn, FaultClass::BadPc),
            (Undefined, FaultClass::HardFault),
            (DivideByZero, FaultClass::HardFault),
            (NoCoprocessor, FaultClass::HardFault),
            (Breakpoint, FaultClass::HardFault),
            (Escalation, FaultClass::HardFault),
        ] {
            assert_eq!(kind.class(), class, "{kind:?}");
        }
    }

    #[test]
    fn an_access_fault_is_identified_by_its_instruction_not_its_address() {
        let one = fault(
            FaultKind::WriteUnmapped,
            0x0800_0120,
            Some(0x6000_0000),
            None,
        );
        let other = fault(
            FaultKind::WriteUnmapped,
            0x0800_0120,
            Some(0x7000_0004),
            None,
        );
        assert_eq!(one.signature(), "invalid_access:write_unmapped:0x08000120");
        assert_eq!(one.signature(), other.signature());
        assert_eq!(
            one.message(),
            "invalid memory access: write to unmapped memory at 0x60000000 (pc 0x08000120)"
        );
        let read = fault(
            FaultKind::ReadUnmapped,
            0x0800_0120,
            Some(0x6000_0000),
            None,
        );
        assert_ne!(read.signature(), one.signature());
    }

    #[test]
    fn a_bad_pc_is_identified_by_the_branch_that_went_there() {
        let one = fault(
            FaultKind::FetchInvalid,
            0x4000_0000,
            Some(0x4000_0000),
            Some(0x0800_0200),
        );
        let other = fault(
            FaultKind::FetchInvalid,
            0x9000_0000,
            Some(0x9000_0000),
            Some(0x0800_0200),
        );
        assert_eq!(one.signature(), "bad_pc:fetch_invalid:0x08000200");
        assert_eq!(one.signature(), other.signature());
        assert_eq!(
            one.message(),
            "bad PC: instruction fetch from an address that holds no code at 0x40000000, \
             branched to from pc 0x08000200"
        );
        let state = fault(
            FaultKind::InvalidState,
            0x0800_0300,
            Some(0x0800_0300),
            Some(0x0800_0200),
        );
        assert_eq!(state.signature(), "bad_pc:invalid_state:0x08000200");
    }

    #[test]
    fn a_hard_fault_names_its_cause() {
        let undefined = fault(FaultKind::Undefined, 0x0800_0042, None, None);
        assert_eq!(
            undefined.signature(),
            "hard_fault:undefined_instruction:0x08000042"
        );
        assert_eq!(
            undefined.message(),
            "HardFault: undefined instruction (pc 0x08000042)"
        );
    }
}
