// SPDX-License-Identifier: Apache-2.0
//
// The in-crate lane's private associated function fixture: `Store::decode`
// has no visibility modifier, so only `store` and its descendants can call it
// (zoxide's `Database::deserialize` in `src/db/mod.rs` has this shape). A
// harness declared at the crate root gets E0624; one declared as a child of
// `store` reaches it.

mod store;

pub fn version() -> u32 {
    store::Store::new().entries as u32
}
