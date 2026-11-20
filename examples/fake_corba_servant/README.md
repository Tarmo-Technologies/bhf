<!-- SPDX-License-Identifier: Apache-2.0 -->

# Fake CORBA Servant Fixture

Fixture for fuzzing a CORBA servant without a real ORB. `Bar_Impl.Compute`
raises and swallows `Foo.BadInput` when its string argument is `"neg"`.
`bhf fake-corba` generates the missing `Foo` package and the base fake CORBA
packages, so the servant builds.

`crates/cli/tests/m10_fake_corba.rs` generates a servant-direct harness,
builds it when GNAT is installed, feeds it the `"neg"` testcase, and checks
that bhf emits a finding for the handled `Foo.BadInput`.
