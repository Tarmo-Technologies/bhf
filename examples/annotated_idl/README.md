<!-- SPDX-License-Identifier: Apache-2.0 -->

# Annotated IDL Validation Fixture

A reduced reproducer for DDS/OpenDDS-style IDL annotations found while validating bhf on real codebases.

The IDL parser ignores the `@topic` and `@key` annotations, records an `ignored IDL annotation` warning for each, and keeps the declarations they decorate. The fixture parses, and the IDL-to-Ada emitter that `bhf fake-corba --idl` uses generates its Ada mapping; `crates/cli/tests/m10_fake_corba.rs` checks both.
