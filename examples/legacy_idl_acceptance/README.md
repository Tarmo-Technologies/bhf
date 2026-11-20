<!-- SPDX-License-Identifier: Apache-2.0 -->

# Legacy IDL Acceptance Fixture

Fixture for real-world legacy IDL. The IDL uses an include guard, object-like macros, conditional declarations, nested modules, vendor pragmas, repository pragmas, exceptions, attributes, inline sequences, `any`, `Object` and interface inheritance.

The Ada client in `src/` uses the generated Helper, Skel, Stub, sequence, Any, TypeCode and Object packages. `crates/cli/tests/m10_fake_corba.rs` runs `bhf fake-corba --idl` and `bhf build` on it, and the generated mapping builds with no manual edits and no real ORB.
