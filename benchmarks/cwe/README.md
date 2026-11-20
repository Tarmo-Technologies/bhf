<!-- SPDX-License-Identifier: Apache-2.0 -->
# CWE-coverage benchmarks

The scripts in this directory produce the numbers in
[`docs/site/vulnerability-coverage.md`](../../docs/site/vulnerability-coverage.md)
and the white paper
[`docs/site/whitepaper-coverage.md`](../../docs/site/whitepaper-coverage.md)
("The bugs your fuzzer can't see"). The results in `results/` are the
scripts' output, unedited.

## What is measured

Each language has a small library with **one CWE per function**. Some of the
bugs crash; others produce **no crash** and are visible only to an oracle that
watches behaviour. bhf fuzzes each library against the most widely used fuzzer
for that language.

| Script | Comparison | What it shows |
|---|---|---|
| `run_c.sh` | bhf vs libFuzzer and AFL++ | **Detection**: CWE-121 and CWE-617 crash; CWE-22 (path traversal), CWE-377 (insecure temp file) and CWE-522 (secret read from the environment) do not. libFuzzer and AFL++ get a harness for each function and report only the crashing CWEs. |
| `run_rust.sh` | bhf vs cargo-fuzz | **Coverage**: bugs in three functions; one hand-written harness reaches one of them, and bhf generates harnesses for all three. |
| `run_java.sh` | bhf vs Jazzer | **Coverage**: the same comparison for Java. |
| `run_ada.sh` | bhf only | Findings in the two buggy Ada subprograms; no other fuzzer is run. |
| `run_timing.sh` | first (cold) vs second (warm) bhf run | Time saved by reusing built harnesses, and the time to a behavioural finding. |

## Setup

- The other tools run in their strongest configuration (AFL++ CMPLOG,
  libFuzzer value-profile). In the C suite each gets a harness for **every**
  vulnerable function, so the C result compares detection only.
- Every tool gets the same small seed corpus (`seed` for C, `seeds_rust/`,
  `seeds_java/`), so coverage does not depend on how fast an engine passes the
  input gates.
- The behavioural sinks are harmless: a read-only `open`, a file created in
  `/tmp`, a `getenv`. Nothing runs a command, deletes a file or opens a
  network connection, so every fuzzer can run them.
- The suite has no TOCTOU (CWE-367) case: it needs the checked path to exist,
  and random input rarely produces one.
- The runners put `--work-dir` outside the scanned tree. A work dir inside the
  tree can add bhf's own generated harnesses to the per-target build.

## Reproduce

```sh
cargo build --workspace
BUDGET=12 bash benchmarks/cwe/run_c.sh
BUDGET=15 bash benchmarks/cwe/run_rust.sh
BUDGET=15 bash benchmarks/cwe/run_java.sh
BUDGET=15 bash benchmarks/cwe/run_ada.sh
bash benchmarks/cwe/run_timing.sh
```

The scripts run `target/debug/bhf` and write `results/*.tsv`. Toolchains:
clang/libFuzzer 18, AFL++, cargo-fuzz 0.13 on Rust nightly, Jazzer, GNAT. The
published results were measured on 6 vCPU and 13 GB RAM.
