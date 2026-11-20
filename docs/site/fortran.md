<!-- SPDX-License-Identifier: Apache-2.0 -->
# Fuzzing Fortran with bhf

Point bhf at Fortran source and it discovers fuzzable procedures, generates the harness, builds it with gfortran and fuzzes it, coverage-guided, with AddressSanitizer (ASan) as the memory oracle. You write no harness.

```sh
bhf auto path/to/fortran --languages fortran
```

## How it works

The fuzzable unit is a Fortran `subroutine` or `function` with a `character` (byte-buffer) dummy argument. For each one, bhf:

1. **Discovers** the procedure and its dummy-argument list, typed per argument (character buffer, integer or other). Discovery handles free-form continuation lines and `pure`, `recursive` and typed-`function` prefixes.
2. **Compiles** it with `gfortran -O1 -g -fsanitize=address -fsanitize-coverage=trace-pc,trace-cmp`. ASan instruments the Fortran for memory safety, and `trace-pc`/`trace-cmp` feed edge coverage and CmpLog. bhf first compiles the project's own modules (once per project, in dependency order) and links them, so a target that `use`s a sibling module builds. For FORTRAN 77 code with no modules, bhf indexes the procedures each file defines so the routines a target calls link.
3. **Generates a driver** (`LLVMFuzzerTestOneInput`) that calls the routine through the gfortran C ABI: the symbol `name_`, arguments by reference, and a hidden `size_t` length appended per character argument. The primary buffer is heap-allocated to the exact input size, so an out-of-bounds access relative to the length the routine is told lands in ASan's redzone. An integer length argument is set to the byte count. A `bind(C)` procedure is called by its binding name (`name="..."`, else its name in lower case) with the C ABI: a `character(kind=c_char), dimension(*)` (or explicit-size) buffer is a bare pointer to the input, an `integer(c_int), value` length is passed by value, and no hidden length is added. An assumed-shape array (`dimension(:)`) goes through a descriptor wrapper.
4. **Fuzzes** it on bhf's C fork-server engine, coverage-guided.

### Oracle

ASan is the primary oracle. A Fortran array or substring out-of-bounds read or write, or a bad pointer, is reported as a crash with its `.f90` line and a CWE (heap-buffer-overflow is CWE-122/787, a stack overflow CWE-121/125). bhf compiles with ASan rather than `-fcheck=all`, because a failed `-fcheck` exits with status 2 before the access happens, which bhf would classify as the input being rejected.

The runtime-virtualisation shim's taint-confirmed [sink oracles](sink-oracles.md) (command, SQL and path injection) also apply, because the harness runs on bhf's C path.

## Other approaches

A manual setup hand-writes a C or Fortran driver, compiles with `gfortran -fsanitize=address` and runs AFL on it; bhf automates that, including discovery, coverage, CmpLog and the taint oracles. gfortran's own `-Wall`/`-fcheck` warnings and commercial linters (forcheck, fpt) flag candidate issues without running the code on input. bhf reports a Fortran memory-safety defect with the input that triggers it.

## Validation campaign

A campaign over 20 projects and 40,367 Fortran files (highly starred Fortran projects: LAPACK, CP2K, NWChem, FDS, neural-fortran, flibs and others) recorded:

- no bhf panics while discovering targets in the 40,367 files;
- 13,406 fuzzable procedures discovered. Fortran has a large character-argument surface: string handling, file paths and format processing;
- standalone free-form subroutines fuzzed, and a heap out-of-bounds array access caught as an ASan crash (BHF-201, CWE-122/787) attributed to its `.f90` line. Benign procedures ran at more than 6,500 executions per second with no false positives.

The campaign also showed that preprocessor include-fragment "template" files (whose names are not valid Fortran identifiers) are skipped rather than compiled.

## Requirements and licensing

- **gfortran** on the host, for example `apt-get install gfortran`. bhf runs it as a subprocess. Its `libgfortran` runtime (LGPLv3 with the GCC Runtime Library Exception) links into your harness, like the C and GNAT runtimes; it is never linked into bhf.
- `clang` and `make` for the C driver build.
- On native Windows, bhf uses MinGW-w64's gfortran and gcc. That gfortran has no AddressSanitizer, so bhf compiles with `-fcheck=bounds,pointer` and turns a failed check into a crash. The finding's fidelity record says ASan was not available.

## Limits

- The fuzzable surface is a `character` dummy argument. bhf does not discover procedures that take only numeric (`real` or `integer`) arrays or that read input through Fortran I/O (`READ`).
- bhf fuzzes one procedure at a time. A project module that needs external dependencies or compile flags bhf does not know fails to compile, and so do the targets that `use` it.
- A character-array dummy of a procedure without `bind(C)` goes through a generated descriptor wrapper, which supports one `len=1` array returning an allocatable string. Any other such procedure is skipped, and the summary says `--force` cannot help (it builds the same harness).
