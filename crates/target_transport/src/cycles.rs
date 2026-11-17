// SPDX-License-Identifier: Apache-2.0

//! Target cycle counts for the deadline oracle (#251). The host's round-trip
//! time for an execution includes the debugger link, the snapshot reset and
//! the host's own load; the target's cycle counter measures the execution.
//!
//! Two counters are read through the gdbstub:
//!
//! * `Dwt`: the Cortex-M DWT cycle counter (`DWT_CYCCNT`). It is enabled
//!   (`DEMCR.TRCENA`, `DWT_CTRL.CYCCNTENA`) and zeroed before each run.
//!   Silicon implements it; QEMU's Cortex-M models read it as zero.
//! * `Counter(address)`: a free-running 32-bit up-counter at `address`, read
//!   before and after the run (for example the MPS2 FPGAIO `COUNTER` at
//!   `0x40028018`, which QEMU models).

use crate::error::Result;
use crate::gdb::{read_u32, GdbClient};
use std::io::{Read, Write};
use std::time::Duration;

/// Debug Exception and Monitor Control Register; bit 24 is `TRCENA`.
const DEMCR: u64 = 0xE000_EDFC;
const DEMCR_TRCENA: u32 = 1 << 24;
/// DWT control register; bit 0 is `CYCCNTENA`.
const DWT_CTRL: u64 = 0xE000_1000;
const DWT_CTRL_CYCCNTENA: u32 = 1;
/// DWT cycle counter.
const DWT_CYCCNT: u64 = 0xE000_1004;

/// Which counter to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CycleSource {
    /// The Cortex-M DWT cycle counter.
    Dwt,
    /// A free-running 32-bit up-counter at this address.
    Counter(u64),
}

/// A target cycle counter and, when known, the frequency it counts at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CycleCounter {
    pub source: CycleSource,
    /// Counts per second, to turn cycles into time (`cpu_hz=`).
    pub hz: Option<u64>,
}

impl CycleCounter {
    /// Prepare the counter before a run and return its starting value.
    pub fn start<C: Read + Write>(&self, gdb: &mut GdbClient<C>) -> Result<u32> {
        match self.source {
            CycleSource::Dwt => {
                let demcr = read_u32(gdb, DEMCR)?;
                write_u32(gdb, DEMCR, demcr | DEMCR_TRCENA)?;
                let ctrl = read_u32(gdb, DWT_CTRL)?;
                write_u32(gdb, DWT_CTRL, ctrl | DWT_CTRL_CYCCNTENA)?;
                write_u32(gdb, DWT_CYCCNT, 0)?;
                Ok(0)
            }
            CycleSource::Counter(address) => read_u32(gdb, address),
        }
    }

    /// The cycles since `start`, read after the run. A 32-bit counter that
    /// wrapped once in between is counted through the wrap.
    pub fn elapsed<C: Read + Write>(&self, gdb: &mut GdbClient<C>, start: u32) -> Result<u64> {
        let address = match self.source {
            CycleSource::Dwt => DWT_CYCCNT,
            CycleSource::Counter(address) => address,
        };
        Ok(u64::from(read_u32(gdb, address)?.wrapping_sub(start)))
    }

    /// `cycles` as time at the counter's frequency, when it is known.
    pub fn duration(&self, cycles: u64) -> Option<Duration> {
        self.hz.and_then(|hz| cycles_to_duration(cycles, hz))
    }
}

/// `cycles` at `hz` counts per second as a duration, to the nanosecond;
/// `None` for a zero frequency.
pub fn cycles_to_duration(cycles: u64, hz: u64) -> Option<Duration> {
    if hz == 0 {
        return None;
    }
    let nanos = u128::from(cycles) * 1_000_000_000 / u128::from(hz);
    Some(Duration::from_nanos(
        u64::try_from(nanos).unwrap_or(u64::MAX),
    ))
}

fn write_u32<C: Read + Write>(gdb: &mut GdbClient<C>, address: u64, value: u32) -> Result<()> {
    gdb.write_memory(address, &value.to_le_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cycles_convert_to_time_at_the_counter_frequency() {
        assert_eq!(
            cycles_to_duration(25_000_000, 25_000_000),
            Some(Duration::from_secs(1))
        );
        assert_eq!(
            cycles_to_duration(25_000, 25_000_000),
            Some(Duration::from_millis(1))
        );
        assert_eq!(
            cycles_to_duration(3, 3_000_000_000),
            Some(Duration::from_nanos(1))
        );
        assert_eq!(cycles_to_duration(1, 0), None);
        let counter = CycleCounter {
            source: CycleSource::Dwt,
            hz: Some(1_000_000),
        };
        assert_eq!(counter.duration(1_500), Some(Duration::from_micros(1_500)));
        let unknown = CycleCounter {
            source: CycleSource::Counter(0x4002_8018),
            hz: None,
        };
        assert_eq!(unknown.duration(1_500), None);
    }
}
