// SPDX-License-Identifier: Apache-2.0
//
// The target: a record decoder over its dependency's segment graph (#409).
// The harness staticlib links `generic_dep_shapes`, whose generic sort
// instances an instrumented build used to leave undefined.

use generic_dep_shapes::join::scan;
use generic_dep_shapes::segment::segments;

/// A planted bug: the segment index after the `S` tag is trusted.
pub fn parse_record(data: &[u8]) -> usize {
    let total = scan(data);
    if data.len() < 2 || data[0] != b'S' {
        return total;
    }
    let found = segments(&data[2..]);
    total + found[usize::from(data[1])].end as usize
}
