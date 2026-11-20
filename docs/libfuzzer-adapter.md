<!-- SPDX-License-Identifier: Apache-2.0 -->

# libFuzzer Adapter

## C and C++

Generated C and C++ harnesses define `LLVMFuzzerTestOneInput`. Their
Makefiles build two kinds of binary with `clang` / `clang++`:

| Make target | Binary | Links | Run by |
|---|---|---|---|
| `make` (default) | `main` | bhf's driver (`c_runtime/bhf_driver.c`), ASan/UBSan, `trace-pc-guard` / `trace-cmp` coverage; no libFuzzer | `bhf fuzz` (builtin engine, the default) |
| `make libfuzzer` | `main_libfuzzer` | `-fsanitize=fuzzer,address,undefined` (libFuzzer's own `main`) | `bhf fuzz --engine libfuzzer`, or libFuzzer-compatible external drivers |

The builtin engine drives `main` through a persistent framed fork server, with
single-input file mode as a fallback, and normalizes sanitizer reports into
bhf findings. Running `main` by hand runs bhf's driver loop.

`bhf fuzz --engine libfuzzer` runs `main_libfuzzer` in process, building it
with `make libfuzzer` when it is missing; it needs clang. To fuzz with AFL++
instead, build with `bhf build --c-engine afl++` and run
`bhf fuzz --engine afl++` with AFL++ installed.

The libFuzzer flags that the builtin engine mirrors are mapped in
[libFuzzer feature parity](site/libfuzzer-parity.md).

## Ada

The builtin engine is the fuzzer for Ada harnesses. A libFuzzer adapter for
Ada needs an LLVM-based Ada front end, which the strict-permissive core
profile neither ships nor requires. The adapter contract is:

- the user supplies a working LLVM/libFuzzer toolchain with a production-ready
  Ada front end;
- the generated harness is exposed through `LLVMFuzzerTestOneInput`;
- the testcase bytes reach the existing harness contract as stdin-equivalent
  bytes;
- the adapter's smoke tests skip when the host has no such Ada/LLVM path, and
  the Rust crate still tests the contract and the skip reason.
