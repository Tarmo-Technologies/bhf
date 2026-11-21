<!-- SPDX-License-Identifier: Apache-2.0 -->

# Access Parameter

Fixture for an access-typed formal parameter. `Access_Param.Process` takes a `Node_Ptr` and raises and swallows `Constraint_Error` when the node's value is negative.

The generated harness decodes the parameter from a per-parameter table of four slots: the input selects either null or one of the slots. For an ordinary access type the slots start null, so the harness compiles and runs, and `Process` always receives null; the `Constraint_Error` branch needs a non-null node. A `not null` access subtype is decoded through its public constructor functions instead.

`crates/cli/tests/m8_access_param.rs` checks that the fixture parses and that the harness generates, and compiles it when GNAT is installed.
