// SPDX-License-Identifier: Apache-2.0
//
// Segments sorted through `KeySort` from three modules, so the sort
// instances for `Segment` land in different codegen units of this crate.

pub mod graph;
pub mod join;
pub mod segment;
