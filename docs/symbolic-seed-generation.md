<!-- SPDX-License-Identifier: Apache-2.0 -->

# Symbolic Seed Generation

`bhf fuzz --symbolic-seed-source <file.adb>` mines seeds from the guards of an Ada source file and adds them to the builtin engine's seed list. The flag can be repeated. The mined seeds go through the normal corpus and finding flow.

How the seeds are built (`fuzz_engine_builtin::generate_symbolic_seeds`):

- the Ada source is lexed with bhf's existing parser stack;
- each non-empty string literal inside an `if`, `elsif`, `case` or `when` guard becomes a seed;
- duplicate seeds are removed in a deterministic order.

The strict-permissive core embeds no solver library, compiler front end or proprietary Ada analysis tool. Integrations that would go further run out of process, outside the core:

| Candidate | Boundary | Prerequisite or constraint |
| --- | --- | --- |
| SMT solver fed by generated harness constraints | separate subprocess | Needs an Ada-to-constraints front end |
| Compiler IR from a user-supplied LLVM/Ada toolchain | optional adapter | Needs a production-ready Ada/LLVM path |
| Libadalang-based path-condition mining | outside the core | Its license and distribution terms keep it out of the core |
| GNATfuzz or vendor tools | excluded from the core | Not redistributable as a core dependency |
