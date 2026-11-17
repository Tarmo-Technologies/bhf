// SPDX-License-Identifier: Apache-2.0
//
// Parameters the Rust lane had no decoder for (#338), each beside a planted
// out-of-bounds read: an owned project type with `Default` (built from
// `Location::default()`), an `Option<String>`, and an `i128`.

/// Where a token was read from: the input does not supply it.
#[derive(Debug, Default)]
pub struct Location {
    pub line: u32,
}

/// A planted bug: the offset after the `L` tag is trusted.
pub fn parse_at(input: &str, location: Location) -> usize {
    let bytes = input.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'L' {
        return location.line as usize;
    }
    bytes[bytes[1] as usize] as usize
}

/// A planted bug: a name's length indexes the input.
pub fn tag(name: Option<String>, input: &[u8]) -> u8 {
    match name {
        Some(name) => input[name.len()],
        None => 0,
    }
}

/// A planted bug: a wide value picks from a short table.
pub fn bucket(value: i128) -> u8 {
    let table = [1u8, 2, 3, 4];
    table[(value.unsigned_abs() % 7) as usize]
}
