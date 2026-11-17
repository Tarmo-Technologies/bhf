// SPDX-License-Identifier: Apache-2.0

//! A byte-record parser in a private module, using the workspace's `checksum`
//! member.

/// A record parser.
pub struct Parser {
    seen: usize,
}

impl Parser {
    /// An empty parser.
    pub fn new() -> Self {
        Parser { seen: 0 }
    }

    /// Parse a record. Behind the `WS` magic, version 1 trusts the record's
    /// length byte and indexes past the end of the input.
    pub fn parse(&mut self, data: &[u8]) -> u32 {
        self.seen = self.seen.wrapping_add(data.len());
        if data.len() < 4 || data[0] != b'W' || data[1] != b'S' {
            return 0;
        }
        let body_len = data[3] as usize;
        let mut sum = 0;
        if data[2] == 1 {
            for i in 0..body_len {
                sum = checksum::fold(sum, data[4 + i]);
            }
        } else {
            for &b in &data[4..(4 + body_len).min(data.len())] {
                sum = checksum::fold(sum, b);
            }
        }
        sum
    }
}
