// SPDX-License-Identifier: Apache-2.0

//! The database lives in a private module, so an external harness cannot
//! reach it (E0603).

mod db;

/// A public function, so the crate has a public surface too.
pub fn version() -> u32 {
    1
}
