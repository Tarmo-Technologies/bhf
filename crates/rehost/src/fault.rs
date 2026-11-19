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
