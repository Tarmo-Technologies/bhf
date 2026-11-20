// SPDX-License-Identifier: Apache-2.0

use crate::segment::Segment;
use generic_dep_keysort::KeySort;

pub struct Graph {
    pub segments: Vec<Segment>,
}

impl Graph {
    pub fn build(data: &[u8]) -> Graph {
        let mut segments = crate::segment::segments(data);
        segments.sort_keyed(|a, b| a.start.cmp(&b.start).then(a.end.cmp(&b.end)));
        Graph { segments }
    }

    pub fn reorder(&mut self) {
        self.segments.sort_keyed(|a, b| b.end.cmp(&a.end));
    }
}
