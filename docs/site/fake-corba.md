<!-- SPDX-License-Identifier: Apache-2.0 -->

# Fake-CORBA

Fake-CORBA lets bhf fuzz legacy Ada code that uses CORBA-style generated bindings, with no broker (ORB) runtime. bhf generates stand-in Ada packages for the CORBA surfaces the code uses, so enough of the project compiles to expose its servant logic to a harness. The packages are test scaffolding for fuzzing, not an ORB.

## Capabilities

- Parses a CORBA IDL 3.0 subset: modules, interfaces, sequences, unions, exceptions, `valuetype` and `fixed<>`.
- Applies the C++-style preprocessing that legacy IDL headers need (`#include`, `#define`, conditionals).
- Generates Ada packages for the Helper, skeleton, object reference, `Any` and `TypeCode` surfaces.
- Keeps the vendor pragmas found in imported interface definitions.
- Discovers servant entry points for direct-call harness generation.
- Translates ROS `.msg`, `.srv` and `.action` interface files through the same Ada mapping.

## Workflow

`bhf auto` runs fake-CORBA generation by itself when the source tree holds `.idl` files or Ada code that uses CORBA. It uses bhf's own IDL parser and runs no project code. Run `bhf fake-corba` by hand to regenerate the scaffolding on its own, or for an IDL file outside the tree:

```sh
bhf fake-corba bhf_work --idl idl/legacy.idl
bhf generate-harness src/legacy/servant.adb --target Legacy.Servant.Process \
  --output bhf_work/generated_harnesses
bhf build bhf_work --harness H-1A2B
```

`generate-harness` prints the harness id; use it in place of `H-1A2B`. Its ids have the form `H-<4 hex digits>`, a hash of the source path and the target. Ids of the form `H-A<line>-<hash>` come from `bhf auto`.

`bhf fake-corba` writes the generated Ada packages to `<work-dir>/fake_corba/`.

| Option | Use |
|---|---|
| `--idl <file>` | IDL file to map to Helper, skeleton and stub Ada packages |
| `--idl-include-dir <dir>` | directory to search for IDL `#include` files |
| `--idl-define NAME[=VALUE]` | predefine a preprocessor symbol, for IDL that relies on conditionals (repeatable) |
| `--ros-interface <file>` | ROS `.msg`, `.srv` or `.action` file to translate |
| `--source-dir <dir>` | source directory to scan for CORBA usage (default `<work-dir>/src_instrumented`) |
