// SPDX-License-Identifier: Apache-2.0

pub struct Store {
    pub entries: usize,
}

impl Store {
    pub fn new() -> Self {
        Store { entries: 0 }
    }

    /// Decode a record count and its entries. A planted bug (BHF-201): the
    /// count after the `S` tag is trusted, so a short input indexes past
    /// the end.
    fn decode(bytes: &[u8]) -> usize {
        if bytes.len() < 2 || bytes[0] != b'S' {
            return 0;
        }
        let count = bytes[1] as usize;
        let mut total = 0;
        for i in 0..count {
            total += bytes[2 + i] as usize;
        }
        total
    }
}
