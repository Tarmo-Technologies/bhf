<!-- SPDX-License-Identifier: Apache-2.0 -->

# Private State

Fixture for stateful sequence harnesses. `State.Pop` underflows, and swallows
the resulting `Constraint_Error`, only after earlier calls have changed
package-private state, so one direct call cannot reach the handler. bhf's
sequence harness calls `Push`, `Pop`, `Pop` and reaches it.

`crates/cli/tests/m9_private_state.rs` generates the sequence harness, and
builds and runs it when GNAT is installed.
