<!-- SPDX-License-Identifier: Apache-2.0 -->
# The bugs a crash-only fuzzer does not report

### A white paper on vulnerability-class coverage

---

## Executive summary

libFuzzer, AFL++ and cargo-fuzz decide they found a bug the same way: the
program crashed. That catches memory corruption and aborts. Path traversal,
command injection, insecure temporary files, secret exposure and SSRF
usually run without crashing, so a crash-only fuzzer gets no signal from
them.

bhf runs the same kind of coverage-guided engine and adds byte-origin
**taint** and a library of **behavioural oracles**. It reports CWE-tagged
findings for the dangerous behaviours a program performs on
attacker-controlled input, as well as for crashes. It also generates
harnesses for every fuzzable function in a tree, across sixteen languages,
instead of fuzzing only the entry points someone wrote a harness for. The
behavioural oracles run in twelve lanes: native C, C++, Ada, Rust, Go, COBOL
and Fortran harnesses, and the Python, Perl, Ruby, Lua and PHP interpreters.
Java, C#, JavaScript and TypeScript use their own coverage and crash or
exception signals.

In a measured comparison on a C library with one CWE per function, bhf
found **5 of 5** vulnerability classes, and libFuzzer and AFL++, each given a
harness for every vulnerable function, found **2**. In Rust and Java, bhf
found bugs in **3 of 3** functions where the other tool's single harness
found **1**. In Ada it found both planted bugs; none of the other fuzzers
measured supports Ada. The numbers and a reproducible suite are in the
companion [coverage comparison](vulnerability-coverage.md).

---

## A fuzzer is only as good as its oracle

A fuzzer has two halves. The **engine** drives execution into new code with
coverage feedback, and the established engines are good and broadly
interchangeable. The **oracle** decides whether an execution is a bug. In
the common tools it is a sanitizer crash or a process signal, so they find:

- **CWE-787 / CWE-125** out-of-bounds write and read (AddressSanitizer)
- **CWE-617** reachable assertions and aborts
- other memory-safety classes their sanitizers detect

These dangerous behaviours do not crash, so a crash oracle does not report
them:

- **CWE-22 / CWE-73**: an attacker-controlled path reaching `open()`, a
  traversal
- **CWE-78**: input flowing into `system()`, a command injection
- **CWE-377**: a predictable temporary file opened without `O_EXCL`, a
  symlink race
- **CWE-522**: reading a secret from the environment on an input-driven
  path
- **CWE-134**: a fuzz-controlled `printf` format string
- **CWE-918**: input steering an outbound `connect()`, an SSRF

These are everyday findings in a security review. A crash-only fuzzer runs
the code that has them, sees no crash, and reports nothing.

---

## What bhf adds

**Runtime taint.** bhf's `LD_PRELOAD` runtrace shim records the byte origin
of the arguments a program passes to sensitive calls. When fuzz-input bytes
reach the path argument of `open()`, the format argument of `printf()` or
the command of `system()`, the shim records it, and bhf checks across
executions that the value is not one of the program's own constants (see
[Sink oracles](sink-oracles.md)).

**Behavioural oracles.** A library of CWE-tagged oracles turns those runtime
events into findings: path-controlled open (`BHF-405`/CWE-22), command
injection (`BHF-304`/CWE-78), insecure temporary file (`BHF-417`/CWE-377),
sensitive-environment access (`BHF-305`/CWE-522), format string
(`BHF-408`/CWE-134), SSRF (`BHF-303`/CWE-918) and others. Each finding has a
severity, a confidence, a sink location, and the tainted byte range as
evidence. `bhf list oracles` prints the full inventory.

**Lanes with the oracles.** The shim's taint and behavioural oracles attach
to native C, C++, Ada, Rust, Go, COBOL and Fortran harnesses, and to the
Python, Perl, Ruby, Lua and PHP interpreters from target entry on, so the
interpreter's own start-up is not recorded. Java, C#, JavaScript and
TypeScript run without the shim, because their runtimes' start-up file
activity would trip the oracles; cross-compiled and emulated targets
(qemu-user, wine) also run without it. Those configurations are still
harnessed and fuzzed with their own coverage and crash or exception signals.

**Whole-tree harnessing.** A hand-written harness covers one entry point.
bhf discovers and harnesses every fuzzable function, so one command reaches
a bug anywhere in the library, without one harness per function.

---

## The evidence

We planted one CWE per function and measured each tool. The other tools ran
in their best configuration. The behavioural sinks are safe (a read-only
`open`, a `/tmp` create, a `getenv`, no command execution), so they run
under every fuzzer. The full method is in the
[comparison](vulnerability-coverage.md).

**Detection (C).** Given a libFuzzer and an AFL++ harness for each
vulnerable function, the crash-only tools found the two crashing CWEs:

| | **bhf** | libFuzzer | AFL++ |
|---|:--:|:--:|:--:|
| CWE-121 out-of-bounds write | found | found | found |
| CWE-617 reachable assertion | found | found | found |
| **CWE-22** path traversal | found | not found | not found |
| **CWE-377** insecure temp file | found | not found | not found |
| **CWE-522** sensitive-env access | found | not found | not found |
| **vulnerability classes found** | **5 / 5** | 2 / 5 | 2 / 5 |

**Coverage (Rust, Java).** One bug per function; the other tool's single
harness reaches one, and bhf harnesses all of them with no hand-written
harness code:

| Language | **bhf** (0 harnesses) | Other tool (1 harness) |
|---|:--:|:--:|
| Rust vs cargo-fuzz | **3 / 3** | 1 / 3 |
| Java vs Jazzer | **3 / 3** | 1 / 3 |

**Ada.** bhf found both planted `CONSTRAINT_ERROR`s; none of the other
fuzzers measured supports Ada. GNATfuzz, AdaCore's commercial Ada fuzzer,
fuzzes Ada from a buildable GNAT project; it was not measured.

**Timing.** bhf writes the harness on the first run and reuses it on the
second. On these targets its build is fast enough that the two runs take
about the same time to the memory bug (1.16 s and 1.12 s). On that shared
memory bug, libFuzzer's in-process engine is faster in wall-clock time
(0.69 s) and reaches the crash in a comparable number of executions. The
same bhf run also reports the three behavioural CWEs, which a crash-only
oracle does not report however long it runs.

---

## Why it matters

Many of the vulnerabilities that breach real systems are logic flaws: a
traversal that reads `/etc/shadow`, an injection that runs a command, a
temporary-file race that escalates privilege, a logged secret. A fuzzer
whose only oracle is a crash does not report these, however long it runs or
however good its mutator is. In legacy, defense and mission-critical
software, where the code is old and the languages are mixed, those classes
are part of what a review has to cover.

bhf fuzzes the whole tree across sixteen lanes and adds runtime behavioural
oracles in the twelve lanes named above. The measurements on this page cover
C, Rust, Java and Ada.

---

*Reproduce every figure with `benchmarks/cwe/` in the bhf repository (see
its [README](../../benchmarks/cwe/README.md)). clang/libFuzzer 18, AFL++,
cargo-fuzz 0.13 (Rust nightly), Jazzer, GNAT; 6 vCPU, 13 GB RAM.*
