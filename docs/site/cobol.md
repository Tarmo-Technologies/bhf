<!-- SPDX-License-Identifier: Apache-2.0 -->
# Fuzzing COBOL with bhf

Point bhf at COBOL source and it discovers fuzzable programs, generates the
harness, builds it and fuzzes it. You write no test harness. bhf translates
each program to C with GnuCOBOL and fuzzes it on its C engine.

```sh
bhf auto path/to/cobol --languages cobol
```

## How it works

The fuzzable unit is a COBOL subprogram: a `PROGRAM-ID` with a
`LINKAGE SECTION`, driven by `PROCEDURE DIVISION USING`. For each one, bhf:

1. **Discovers** the program and its `USING` operand list, typed per operand
   (byte buffer, numeric or group). A program is fuzzable when at least one
   operand is a `PIC X` byte buffer.
2. **Translates** it to C with `cobc -C -debug -fec=all` (GnuCOBOL). bhf
   detects free or fixed source format, and adds every directory holding a
   `.cpy` copybook as a `cobc -I` search path so `COPY` statements resolve.
   The search covers the project: the git checkout holding the program inside
   the tree you pass to `bhf auto`, else that tree. It never goes above that
   root, and it stops after a bounded number of directory entries.
3. **Generates a driver** (`LLVMFuzzerTestOneInput`). The driver fills the
   primary `PIC X` / `PIC X ANY LENGTH` buffer from the fuzz bytes, sets a
   length operand to the byte count and zeroes the other operands, so a
   program with a buffer, a length and a status operand is driven correctly.
4. **Fuzzes** it on bhf's C fork-server path: coverage-guided (edge coverage
   plus CmpLog/RedQueen comparison feedback) and built with AddressSanitizer
   (ASan).

### Crash oracles

- **ASan** on the generated C catches memory corruption.
- **libcob runtime checks** (`-fec=all`) catch COBOL-semantic violations:
  out-of-range reference modification (`X(i:n)`), `OCCURS` subscript
  overflow, `SIZE ERROR`, divide by zero and invalid numeric data. bhf
  reports each as a crash attributed to its `.cob` line and a CWE:
  out-of-bounds is CWE-125, zero divide CWE-369, size overflow CWE-190.
  `bhf replay`, `bhf minimize` and the `bhf auto` minimization pass read a
  replayed crash's libcob error the same way, so such a finding replays as
  a `MATCH` against the same error at the same `.cob` line, and is minimized
  against it.

### Behavioural and taint oracles

The COBOL harness runs on bhf's C path, so the runtime-virtualisation shim's
taint-confirmed [sink oracles](sink-oracles.md) apply. A program that passes
fuzz-controlled data to a shell (`CALL "SYSTEM"`), SQL or file-open sink is
reported as command injection (CWE-78), SQL injection (CWE-89) or path
control (CWE-22). Each such finding is confirmed at run time by the fuzz
input reaching the sink.

## Engines

`bhf auto --engine afl++` runs the same COBOL harness under AFL++. Its C glue
builds with `afl-clang-fast`, and a crash AFL++ saves is replayed and
attributed to the COBOL line, as the built-in engine's crashes are.

## Other approaches

- **Static analyzers** for COBOL (SonarSource, Micro Focus, IBM, Kiuwan)
  report candidate defects without running the program on input.
- **A manual setup** hand-writes a C driver, translates the program with
  `cobc -C`, instruments it and runs AFL on it. bhf automates those steps.

bhf reports a COBOL defect with the input that triggers it: a libcob or ASan
check that fires, or input that reaches a shell, SQL or file sink.

## Validation campaign

A campaign over 23 projects and 2925 COBOL files, including CobolCraft (a
GnuCOBOL Minecraft server) and several web and CLI COBOL projects, recorded:

- no bhf panics on any of the 2925 files;
- 30 of the 38 fuzzable programs discovered (79%) built and fuzzed. The
  others use mainframe-only features (embedded `EXEC SQL` or `CICS`) or
  copybooks outside the project tree;
- no false-positive crashes. A failed dynamic `CALL` to a sibling program
  that is not linked into the single-program harness (`module 'X' not found`)
  is recognized as an environment artifact and not reported;
- two taint-confirmed command-injection findings (CWE-78) in a COBOL program
  that runs an input-derived shell command.

## Requirements and licensing

- **GnuCOBOL** (`cobc`) on the host, for example `apt-get install gnucobol`.
  `cobc` is GPLv3, and bhf runs it as a subprocess (as it runs FSF GNAT and
  GCC). Its `libcob` runtime is LGPLv3 and links into your generated harness,
  like the GNAT or GCC runtime; it is never linked into bhf.
- `clang` and `make` for the C harness build.

## Limits

- The fuzz surface is the `LINKAGE` `PIC X` buffer. bhf does not discover
  programs that read input only through `ACCEPT` or a file `READ`, or that
  take no `USING` byte buffer.
- bhf fuzzes one program at a time. A dynamic `CALL` to a sibling program is
  not resolved: the crash it causes is suppressed, and fuzzing does not
  continue into the sibling.
- Mainframe-specific COBOL (embedded `EXEC SQL` or `CICS`, IBM extensions
  GnuCOBOL does not accept) fails the `cobc` translation and is reported as a
  failed build.
