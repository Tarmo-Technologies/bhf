// SPDX-License-Identifier: Apache-2.0

use crate::graph::Graph;
use crate::segment::Segment;
use generic_dep_keysort::KeySort;

pub fn join(graph: &mut Graph) -> usize {
    let mut by_end: Vec<Segment> = graph.segments.clone();
    by_end.sort_keyed(|a, b| a.end.cmp(&b.end));
    graph.reorder();
    by_end.len() + graph.segments.len()
}

/// Build the graph of `data`'s segments and join it.
pub fn scan(data: &[u8]) -> usize {
    let mut graph = Graph::build(data);
    join(&mut graph)
}
