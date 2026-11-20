<!-- SPDX-License-Identifier: Apache-2.0 -->
# Taint-confirmed sink oracles

A crash-only fuzzer reports a bug when a sanitizer aborts. Many
vulnerabilities do not crash: the program does what it was told, but what it
was told came from the attacker. It runs *this* command, opens *this* path,
connects to *this* host, loads *this* library or executes *this* SQL. bhf's
**sink oracles** watch the dangerous calls ("sinks") a program makes while
it is fuzzed, and report the ones whose argument the fuzz input controls.

A static scanner can flag `system(buf)` as a possible command injection
without knowing whether `buf` is ever attacker-controlled on a reachable
path. bhf confirms control with dynamic byte-origin taint: it compares the
exact bytes the fuzzer fed in this iteration with the sink's dangerous
argument, and checks whether a contiguous run of them reaches it. If one
does, and the call site is never reached without that taint, the finding is
confirmed with a source-to-sink path (`fuzz_input[N..] → system(command)`).

## How it works

The LD_PRELOAD runtrace shim interposes the sink APIs and emits an event for
each call. It tags the event when a run of at least 4 bytes of the argument
matches the live fuzz input. The CLI folds those events across the whole run
with one rule:

> A `(sink, subject)` pair is **confirmed fuzz-controlled** only if it
> carried byte-origin taint on at least one execution **and was never
> reached without that taint** during the run.

The second condition removes the program's own constants. bhf harvests a
target's string constants into its mutation dictionary, so a fixed path such
as `open("/etc/app.conf")` sometimes appears verbatim in an input and would
look controlled to a plain substring match. A program constant is reached on
nearly every execution, including inputs that do not contain it, so it
collects an untainted sighting and is suppressed. A value the target copies
from the input is reached only when its bytes are present, so it stays
tainted-only and is confirmed. A sanitized variant (canonicalization, an
allow-list, a bound parameter) breaks the byte-origin match and reports
nothing.

Confirmation happens once, at the end of the run, so a target that reaches a
fresh input-derived sink on every iteration produces one finding per defect.

The shim runs in native C, C++, Ada, Rust, Go, COBOL and Fortran harnesses,
and in the Python, Perl, Ruby, Lua and PHP interpreters from target entry
on. Java, C#, JavaScript and TypeScript harnesses, and cross-compiled or
emulated targets, run without it.

## The sink matrix

Every sink class below is confirmed by the same taint correlator, carries a
specific CWE, and records a source-to-sink taint path on the finding.

| Sink class | APIs interposed | Rule | CWE |
|---|---|---|---|
| **File-open path traversal** | `open`, `openat` | BHF-405 | CWE-22 |
| **Process execution** | `system`, `popen`, `execv`, `execvp`, `execvpe`, `execve`, `fexecve`, `posix_spawn`, `posix_spawnp` | BHF-431 | CWE-78 |
| **Network egress / SSRF** | `getaddrinfo` (hostname), `connect` (destination) | BHF-433 | CWE-918 |
| **Controlled library load** | `dlopen`, `dlmopen` | BHF-435 | CWE-427 |
| **SQL injection** | `sqlite3_exec`, `sqlite3_prepare[_v2/_v3]`, `PQexec`, `PQexecParams`, `mysql_query`, `mysql_real_query` | BHF-441 | CWE-89 |
| **Destructive filesystem operation** | `unlink`, `unlinkat`, `remove`, `rename`, `renameat`, `mkdir`, `mkdirat`, `rmdir`, `symlink`, `symlinkat`, `link`, `linkat`, `truncate` | BHF-440 | CWE-73 |
| **Format string** | `printf`, `fprintf`, `sprintf`, `snprintf`, `dprintf` | BHF-408 | CWE-134 |

`bhf list oracles` prints the full oracle inventory with the APIs each one
watches.

Notes on individual classes:

- **Process execution.** `system` and `popen` hand their whole argument to
  `/bin/sh -c`, so any controlled span is shell-interpreted: command
  injection without a shell metacharacter. A confirmed `system`/`popen`
  command that also holds shell syntax is reported a second time, under the
  shell-metacharacter rule BHF-304 (oracle `command-injection`). The
  `exec*` and `posix_spawn` forms run an attacker-chosen program or argument
  vector directly. The variadic `execl*` wrappers take arguments fixed at
  compile time (a dynamically controlled command uses the argv-array forms),
  so they are not interposed separately.
- **SSRF.** The `getaddrinfo` hostname is the usual attacker-controllable
  destination; `connect` also covers controlled `AF_UNIX` socket paths.
  Loopback destinations are not reported.
- **SQL injection.** The SQL client symbols belong to client libraries, not
  libc. The shim exports them, so an LD_PRELOAD run interposes them whenever
  the target links the client library dynamically, and forwards each call to
  the real symbol. Taint in the query text (rather than in a bound parameter)
  is the injection signal; a parameterized query keeps untrusted values out
  of the text and reports nothing.
- **Destructive filesystem operations.** Separate from the read and open
  traversal sink, this covers mutating operations where a controlled name
  lets an attacker delete, move, overwrite or link arbitrary files.
  Two-path operations (`rename`, `link`, `symlink`) check both the source
  and the destination.

## Classes covered elsewhere

The sink oracle watches what a program does through the C library and a few
widely used client libraries. These classes are left to other layers:

- **Deserialization (CWE-502)** has no common libc or library sink to
  interpose: every serializer (protobuf, msgpack, bespoke formats) has its
  own entry point. For native targets it is a design-review and static
  concern. Java's `ObjectInputStream` is a single sink, and bhf's static
  rules report it; the JVM lane runs without this shim.
- **XML external entity (CWE-611)** does not separate cases as a taint sink:
  a fuzzer's input usually is the XML, so "controlled input reached a
  parser" is true on every iteration. The static rule BHF-430 checks whether
  the parser is configured to resolve external entities.
- **LDAP injection (CWE-90)** and other less common library sinks are not
  interposed. They can be added with the same interposition pattern the SQL
  hook uses.

The shim confirms command execution, path traversal, destructive filesystem
operations, network egress, dynamic library loading, SQL and format strings
with byte-origin taint.
