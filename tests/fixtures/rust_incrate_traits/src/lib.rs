// SPDX-License-Identifier: Apache-2.0

//! The parsers live in a private module, so an external harness cannot reach
//! them (E0603).

mod internal;

/// A public function, so the crate has a public surface too.
pub fn version() -> u32 {
    1
}
