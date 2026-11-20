<!-- SPDX-License-Identifier: Apache-2.0 -->

# Missing Dependency

Single-file fixture for stub synthesis: `src.adb` calls
`External_Lib.Process`, and no `External_Lib` package exists. bhf's build loop
reads the compiler diagnostics, writes `generated_stubs/external_lib.ads`,
and the build then succeeds. `bhf stub` runs the same loop on a work
directory.

`tests/integration/m7_missing_dependency.rs` (run as the
`m7_missing_dependency` test of the `stub_gen` crate) checks this when
`gprbuild` is installed.
