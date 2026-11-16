// SPDX-License-Identifier: Apache-2.0

//! The parser lives in a private module (`mod internal;`, not re-exported), so
//! an external harness cannot reach it (E0603) and the in-crate build mode
//! does.

mod internal;

/// A public function, so the crate has a public surface too.
pub fn version() -> u32 {
    1
}
