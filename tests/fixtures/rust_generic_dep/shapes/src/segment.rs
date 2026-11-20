// SPDX-License-Identifier: Apache-2.0

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    pub start: i32,
    pub end: i32,
}

/// Pairs of bytes as segments; a trailing odd byte ends at 0.
pub fn segments(data: &[u8]) -> Vec<Segment> {
    data.chunks(2)
        .map(|pair| Segment {
            start: i32::from(pair[0]),
            end: i32::from(*pair.get(1).unwrap_or(&0)),
        })
        .collect()
}
