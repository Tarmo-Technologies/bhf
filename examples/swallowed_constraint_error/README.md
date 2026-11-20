<!-- SPDX-License-Identifier: Apache-2.0 -->

# Swallowed Constraint Error

Fixture for cross-compiled Ada. `Pkg.Parse` converts its input string with
`Integer'Value` and swallows `Constraint_Error`. The generated harness gives
the same bhf finding when it runs as a host binary and when it runs as an
`aarch64-linux-gnu` binary under qemu-user.

`crates/cli/tests/m17_aarch64_cross_fixture.rs` runs both with the tools
installed on the host. The host run needs `gprbuild`; the cross run also
needs `aarch64-linux-gnu-gprbuild`, `aarch64-linux-gnu-gnat`, and
`qemu-aarch64` or `qemu-aarch64-static`. Each run is skipped when its tools
are missing.
