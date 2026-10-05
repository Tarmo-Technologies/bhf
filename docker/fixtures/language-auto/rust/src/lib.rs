// SPDX-License-Identifier: Apache-2.0
pub fn packet_checksum(data: &[u8]) -> u32 {
    data.iter().fold(0, |sum, byte| (sum + u32::from(*byte)) % 251)
}
