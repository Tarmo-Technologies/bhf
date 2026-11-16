// SPDX-License-Identifier: Apache-2.0

//! The workspace's other member, which `ws_parser` depends on.

/// Fold one byte into a running checksum.
pub fn fold(acc: u32, byte: u8) -> u32 {
    acc.wrapping_mul(31).wrapping_add(u32::from(byte))
}
