<!-- SPDX-License-Identifier: Apache-2.0 -->

# Runtime Virtualisation

The runtrace shim (`libbhf_runtrace_shim.so`, also shipped as
`libbhf_runtrace.so`) is the `LD_PRELOAD` library that `bhf auto` loads into
each fuzz target. A target that cannot run because its environment is
missing (files, sockets, environment variables, libraries) runs instead
against a synthesised environment that the fuzzer drives.

The shim lives in `crates/bhf_runtrace_shim` and is Linux-only. On other
hosts the library is built empty, and `bhf auto` sweeps without the runtime
audit.

**Where it runs.** The shim is armed for native C, C++, Ada, Rust, Go, COBOL
and Fortran harnesses and for the Python, Perl, Ruby, Lua and PHP
interpreters. In the interpreters, `BHF_RUNTRACE_AFTER_TARGET_ENTRY=1` holds
every record until the process opens the file that `BHF_TARGET_ENTRY_SHM`
names, which the harness does just before its first call into the target,
so the interpreter's own start-up is not recorded. The driver writes each
input to `<BHF_SHIM_INPUT_FILE>.<pid>`, and the shim reads it from there to
match a sink's argument against the input; `bhf auto` sets both variables.
For these interpreters the shim also hooks the 64-bit and fortified
`open64`, `openat64`, `__open64_2` and `__openat64_2`, and the variadic
`execl`, `execlp` and `execle` a shell command goes through, and it treats
an `fopen` of the target-entry file (Lua's `io.open`) as the entry.

Java, C#, JavaScript and TypeScript use their own runtime's coverage and
crash signals and run without the shim, as do cross-compiled and emulated
runs (qemu-user, wine). For them, the runtime audit, the resource
virtualisation and the shim-fed executable oracles described below are
off.

## Intercept List

| Symbol | Behaviour |
|---|---|
| `getenv`, `secure_getenv` | Audit only. Logs the variable name, API, and whether a value was present; never logs the value. The auto loop injects fakes only for NULL results via the real `setenv` so secure-execution and threading semantics stay correct. |
| `open`, `openat` | Logs audited successful opens with fd/path evidence. On ENOENT for a path outside `/proc`, `/sys`, real `/dev`, or the work directory, substitute a `memfd_create` fd. On a path derived from the current fuzz input (a run of at least four input bytes), also appends byte-origin taint fields (`u`=1 controlled, `o`=input offset) to the path event so the CLI can confirm the BHF-405 path-controlled-open oracle. Also logs an `insecure_tempfile` event when a file is created (O_CREAT) without O_EXCL in a world-writable directory (`/tmp`, `/var/tmp`, `/dev/shm`) so executable oracles can flag predictable-temp-file/symlink races. |
| `close` | Logs successful descriptor closes so per-input executable oracles can detect opened descriptors that were not released. |
| `unlink`, `unlinkat`, `remove`, `rmdir`, `rename`, `renameat`, `symlink`, `symlinkat`, `link`, `linkat`, `truncate` | Audit only. Logs destructive filesystem operations (delete, rename, link, truncate) so the BHF-440 destructive-fs oracle can flag a parent-directory or otherwise dangerous mutation. |
| `stat` (via `__xstat`), `access`, `faccessat` | Audit only. The stat hook calls the real syscall and logs a `path_miss` on ENOENT (no synthesised stat is returned); `fstat`/`lstat` are not hooked. `access`/`faccessat` return the real result and log a `path_check` event on success (the TOCTOU time-of-check) so executable oracles can flag a path checked then opened. |
| `readlink`, `readlinkat` | Audit only. Calls the real syscall and logs a `path_miss` event on ENOENT; the real result is returned unchanged (no synthesised link target). |
| `connect` (AF_UNIX, AF_INET) | On ECONNREFUSED, replace the fd with one end of a `socketpair()` so a connection to an unreachable peer succeeds against a shim-controlled socket. |
| `dlopen`, `dlclose`, `dlmopen` | On NULL return, allocate a synthetic handle. `dlsym(handle, name)` returns a per-name weak stub that returns `NULL`; `dlclose(handle)` accepts synthetic handles. Disabled by setting `BHF_DISABLE_DLOPEN_FAKE=1`. |
| `getaddrinfo` | Audit only. Logs a `net_egress` / `getaddrinfo` event and returns the real result; no address is synthesised (name resolution is not faked). `gethostbyname` is not hooked. |
| `chmod`, `fchmod` | Audit only. Logs an `insecure_chmod` event when a setuid/setgid/world-writable mode is requested so executable oracles can flag incorrect-permission assignment (BHF-416, CWE-732). |
| `mkdir`, `mkdirat` | Audit only. Logs an `insecure_mkdir` event when a directory is created world-writable without the sticky bit (or setuid/setgid), promoted to the same BHF-416 incorrect-permission oracle (CWE-732). |
| `system`, `popen`, `execv`, `execvp`, `execvpe`, `execve`, `fexecve`, `posix_spawn`, `posix_spawnp` | Audit only. Logs shell command strings and process-execution argv, with the fuzz-input offset of any input-derived run in them, so executable oracles can flag a fuzz-controlled command (BHF-431) and one whose shell syntax comes with it (BHF-304). |
| `printf`, `fprintf`, `dprintf`, `sprintf`, `snprintf` | Audit only. Logs printf-style format strings and whether the observed bytes match the current fuzz input so executable oracles can flag controlled conversion formats. |
| `__assert_fail`, `__assert_perror_fail` | Audit then forward. Logs native assertion/contract failures before preserving libc's aborting assertion behavior. |
| `sqlite3_exec`, `sqlite3_prepare[_v2/_v3]`, `PQexec`, `PQexecParams`, `mysql_query`, `mysql_real_query` | Audit only. Logs SQL query strings passed to SQLite / libpq / MySQL so the BHF-441 SQL-injection oracle (CWE-89) can flag a fuzz-controlled query. |
| `getpid`, `getuid`, `getgid`, `getppid` | Env-gated on `BHF_FAKE_IDENTITY`. Returns deterministic identity constants so environment-driven crashes reproduce identically across runs. |
| `bind`, `listen`, `accept`, `accept4`, `getsockname`, `getpeername`, `setsockopt` | Env-gated on `BHF_DESOCKET` (#312): see [Desocketing a server](#desocketing-a-server). Without the gate every call goes to libc. |
| `clock_gettime`, `gettimeofday`, `time`, `clock`, `timespec_get` | Env-gated on `BHF_FAKE_CLOCK` (#342). A virtual clock: the wall clocks start at 2026-01-01T00:00:00Z, the monotonic ones at 1000 s and the CPU clocks at 0, every read is 1 ms after the one before, and every input the harness publishes starts the clock over, so the same input sees the same times on every run and a loop waiting for a deadline still reaches it. A clock it does not model (another process's CPU clock) reads the real one. Without the gate every call goes to the real clock. The real functions are resolved as the shim loads, never inside a call, and the gate is read from `environ` without calling `getenv`. A runtime that reads the clock itself in the same process (AddressSanitizer's allocator does when it maps memory) also advances it, so an input's times can shift when it runs after other inputs in one persistent process. `bhf fuzz --engine libfuzzer` ignores the gate, with a warning, and gives its children `BHF_FAKE_CLOCK=0`: libFuzzer runs in the harness process and times `-timeout` with the clock the shim would fake, so a hang would never time out. The builtin and AFL++ engines time inputs from their own process and keep the virtual clock. |
| `clock_nanosleep` (`TIMER_ABSTIME`), `pthread_cond_timedwait`, `pthread_cond_clockwait`, `sem_timedwait`, `sem_clockwait` | With `BHF_FAKE_CLOCK=1` (#342), an absolute deadline the target computed from the virtual clock is waited for on the kernel's real clock as far ahead as it was of the virtual time; one already past ends at once. Without this a monotonic deadline (the virtual clock starts at 1000 s) ended at once on a host up longer than that and slept until the uptime reached it on one just booted, and a wall-clock one ended at once. `pthread_cond_timedwait` cannot see the condition variable's clock, so it takes a deadline near the virtual wall clock as `CLOCK_REALTIME` and any other as `CLOCK_MONOTONIC`. Other absolute deadlines (`pthread_mutex_timedlock`, `pthread_rwlock_timed*`, `mq_timedreceive`, `timer_settime` and `timerfd_settime` with `TIMER_ABSTIME`) still compare the virtual deadline with the real clock. Relative sleeps and timeouts (`nanosleep`, `poll`, `select`) take real time. |
| `strcmp`, `strncmp`, `memcmp` | Env-gated on `BHF_CMPLOG`. Records comparison operands (cmplog / RedQueen) so the engine can splice them into inputs to defeat magic-byte and string gates. Off unless the fuzz loop enables it. |
| `mq_open`, `mq_receive`, `mq_timedreceive`, `mq_send`, `mq_getattr`, `mq_close`, `mq_unlink` | Message-queue virtualization (#440). Partitioned / message-driven systems on POSIX (cFS Software Bus, DDS, RTOS-on-Linux IPC) move data over POSIX message queues; a message loop normally blocks in `mq_receive` waiting for a peer that doesn't exist under fuzzing. During a faking pass `mq_open` returns a private fake descriptor and `mq_receive`/`mq_timedreceive` DELIVER the current fuzz input as a message (mode-driven: Empty → none, Rng → pseudo-random, FuzzDriven → the live input), feeding a partition's handler its input through the real IPC API. Delivery is bounded so a `while (1) mq_receive(...)` loop terminates instead of spinning. `mq_send` is swallowed; `mq_getattr` reports a sane message size. (Vendor message-bus structs such as cFE `CFE_SB_*` and ARINC 653 APEX sit above this and are generated against the target's own headers by stub-gen.) |
| `open`/`openat` of `/dev/mem`, `/dev/kmem`, `/dev/gpiomem`, `/dev/uio*`, `/dev/mtd*`, `/dev/i2c-*`, `/dev/spidev*`, `/dev/watchdog*` | MMIO / device-register virtualization (#441). A Linux MMIO driver `open`s one of these and `mmap`s it to reach device registers. During a faking pass the open is redirected to a private, mode-filled memfd (logged as an `mmio` event), so the unprivileged open that would fail with EACCES succeeds, the driver's `mmap` + register reads hit fuzz-controlled memory, and no real device memory is touched. Intercepting at `open` (not `mmap`) keeps this off the allocator/loader hot path. |
| `shm_open`, `shm_unlink`, `shmget`, `shmat`, `shmdt`, `shmctl` | Shared-memory virtualization (#438), POSIX and System V. During a faking pass, `shm_open` returns a harness-PRIVATE `memfd` and `shmget` returns a synthetic id backed by a private anonymous `mmap`; `shmat` returns that private pointer. Two unrelated processes opening the same name / key therefore get distinct memory: there is no foreign writer, runs are deterministic, and the cross-partition MSan-uninitialized / TSan-race false-positive classes disappear. The region is pre-filled with mode-driven bytes (Empty → zero, Rng → pseudo-random, FuzzDriven → the live input) so a target that READS shared memory (expecting a peer partition to have written it) is driven by the fuzz input and the fuzzer reaches content-dependent handlers, while the region stays private and "initialized" to MSan since the shim wrote it. System V segments are keyed and reused so a persistent-mode harness re-`shmget`-ing each input doesn't leak (bounded table); `shmctl(IPC_RMID)` frees, `shmdt`/`shm_unlink` are no-op successes. Audit mode passes all through. |
| `mmap`, `mmap64` | Anonymous-shared-mapping virtualization (#443), the last shared-memory path. A target that creates inter-process shared memory directly with `mmap(MAP_SHARED \| MAP_ANONYMOUS)` (no shm_open/shmget) would otherwise keep a shared region. During a faking pass that one case is rewritten to `MAP_PRIVATE` so it is harness-private (logged as `mmap_private`). Every other `mmap` (file maps, `MAP_PRIVATE`, and all allocator and loader maps) takes a fast path that issues the raw `SYS_mmap` syscall with no reentrancy guard, mode lookup, or allocation, to avoid allocator recursion in this interposer path. The real mapping is always the raw syscall (never the `mmap` libc symbol), so there is no self-recursion. |

Each event is appended as one JSONL line to the path in
`BHF_RUNTRACE_LOG`. The auto loop parses this between passes to populate
`needed_for_build` Layer C and, during built-in fuzzing, to evaluate
executable oracles against only the events appended by the current input.

Some paths are never logged or faked, even in a faking pass, because a
sanitizer's symbolizer opens them while it writes a report: the vDSO's
link-map name (`linux-vdso.so.1`, `linux-gate.so.1`, `linux-vdso64.so.1`),
separate debug files (`<object>.debug`, `<dir>/.debug/<object>`,
`/usr/lib/debug/...`) and the names of objects the process has loaded. Once
AddressSanitizer starts a report (bhf's C/C++ driver defines
`__asan_on_error`, which tells the shim), the shim fakes nothing more in that
process: a faked object handed to GCC's static libasan symbolizer made it
abort its own report, so the finding lost its stack and came back a second
time. A target that defines `__asan_on_error` itself would not link with the
driver's definition; add `-DBHF_NO_ASAN_ON_ERROR` to `toolchain.cflags`
(`--cflags`), which leaves the hook to the target.

`fopen` and `fopen64` are hooked too: glibc's `fopen` opens the file
through an internal call that the `open` hook never sees. They log the same
open and missing-file events as `open`, under their own event names (`fopen`,
`fopen64`); a missing file is reported, not replaced by a fake one. `fdopen`
logs an `fdopen` event naming the descriptor it wraps, and `fclose` logs the
`close` of the stream's descriptor, which glibc closes internally (nothing
for an invalid stream, `EBADF`), so a file opened and closed through stdio is
not reported as leaked.

Besides `printf`, `fprintf`, `dprintf`, `sprintf` and `snprintf`, the format
hooks cover `asprintf`, the `va_list` forms (`vprintf`, `vfprintf`,
`vsprintf`, `vsnprintf`, `vdprintf`, `vasprintf`) and the fortified
`__*printf_chk` entry points. Each event names the variadic API
(`vfprintf` and `__fprintf_chk` log as `fprintf`), so a format is named the
same in a plain, a fortified and a sanitized build: a sanitizer's `printf`
interceptor forwards to the `vprintf` it resolves with `dlsym(RTLD_NEXT)`,
which is the shim's. In an
AddressSanitizer harness the sanitizer runtime defines `fopen` in the
executable and resolves the real one with `dlsym(RTLD_NEXT, "fopen")`; the
shim's `dlsym` hook answers that call, from an object loaded before the shim,
with the shim's own `fopen` hook, as `RTLD_NEXT` means, so the hook runs there
as well.

The sanitizer runtime also defines `strcmp`, `strncmp`, `memcmp` and `bcmp`
in a sanitized executable, so the shim's comparison hooks do not run there.
bhf's C/C++ driver writes the same `cmplog` records from the sanitizer's
comparison hooks instead (they also cover `bcmp` and the `strcasecmp` family),
once per distinct operand pair per process, leaving out comparisons the shim
makes inside its own hooks. `strcmp`-family calls made by libc or a preloaded
library are left out as well; `memcmp` and `bcmp` calls are not, because the
sanitizer's interceptor reports a position inside itself rather than its
caller's.

### Collector-shaped view (`--collector auto` on Linux, #60)

On Linux, the same shim events also back the platform-neutral runtime-event
collector. `--collector auto` resolves to a **runtrace-to-collector
adapter** that re-expresses these effect events in the versioned
`bhf.collector-event.v1` contract (`crate::auto::runtrace::to_collector_event`,
`collector_jsonl_from_events`):

| Shim event | Collector family |
|---|---|
| `exec`, `system`, `popen` | `process_create` |
| `lib_load`, `dlopen` | `module_load` |
| `open`, `openat`, `fs_destroy` | the file families |
| `net_egress`, `connect` | `network` |

A sink family is marked taint-confirmed in the collector stream **only**
when a `CollectorTaintGate` confirms it through the same cross-execution
matching and constant suppression the runtime oracles use, never from a
single run's `taint_offset`. A program constant echoed into one input is
therefore never presented as a taint-confirmed finding.

The collector observes in a **dedicated replay pass**, separate from the
crash-detection loop, so `--runtime-oracles` behaves as before:

- On `bhf binary fuzz`, it replays the retained inputs one by one under the
  shim: the input behind each of the run's findings, then (with
  `--engine afl-qemu`) the AFL++ queue entries that found new coverage, then
  the seeds, at most 16. The gate uses the campaign's accumulated taint
  evidence plus every replay, and each finding keeps the input whose replay
  produced it.
- On `bhf fuzz`, it replays the campaign's retained inputs the same way (the
  harness's crash findings, then its saved corpus, at most 16), and the
  gate matches across the loop's own `runtrace.jsonl` and every replay. A
  sink that only the campaign's other inputs reached is reported from that
  log as an aggregate finding with no input.

The result feeds the same oracle registry and stored-evidence replay as the
native Windows ETW provider, as a second view of the same shim events.
`--collector auto` arms the runtrace shim for the run and stays inactive
when the shim is unavailable. A run in which the shim recorded no
`runtrace.jsonl` is recorded as degraded and **not observed**
(`observed: false`), never as `clean_assurance: true`.

## Desocketing a server

A network server's input arrives through `accept` and `recv`, so a harness
that calls its main loop (`serve(port)`) would wait in `accept` for a client
that never comes. With `BHF_DESOCKET=1` the runtrace shim stands in for the
network, as libdesock and preeny's desock do:

- `bind` of an IPv4 or IPv6 stream socket succeeds without binding, so no
  port is taken and a privileged port needs no privilege. `getsockname`
  reports the loopback address and the port the server asked for.
- `listen` succeeds, and the listener reads as ready to `poll`, `select` and
  `epoll`.
- The first `accept` (or `accept4`) returns a connection whose reads deliver
  the current fuzz input (the one the harness published, else stdin) and then
  end of file. Its peer is `127.0.0.1` (`::1`) port 40000; TCP and IP
  `setsockopt` calls on it succeed without effect, and what the server sends
  is absorbed.
- A later `accept` flushes stdio and ends the process with status 0 once the
  server is done with that connection: it closed it, in every thread and
  process that held it, or shut it down for writing. Until then a later
  `accept` on a non-blocking listener fails with `EAGAIN`, so an event loop
  that accepts until `EAGAIN` (libevent's listener, an edge-triggered
  `epoll`) goes on to read the connection; on a blocking listener it waits
  while another thread (a thread-per-connection server's handler) or the
  child the connection was forked to works on it, reading and dropping what
  the server sends meanwhile. When the server closes the connection, each
  faked listener becomes readable again, so an edge-triggered loop calls
  `accept` once more and the run ends. A single-threaded server that accepts
  again with the connection still open could never close it, and ends at
  once. Publishing a new input starts over.

The C driver runs each framed input in a forked child while the mode is on,
so the builtin engine's persistent fork-server keeps one process for the
campaign and the exit ends only the child; a child that crashes is passed on,
and the engine re-runs that input in a fresh process as it does any crash.

```sh
bhf generate-harness server.c --target serve --id H-SERVE --output work/generated_harnesses
bhf build work --harness H-SERVE
BHF_DESOCKET=1 bhf fuzz work --harness H-SERVE --runtime-oracles on --time 5m
```

`--runtime-oracles on` loads the shim. A finding records the shim modes its
campaign ran under (`"shim_env": {"BHF_DESOCKET": "1"}`, and `BHF_FAKE_CLOCK`
the same way), and `bhf replay`, `bhf minimize`, `bhf env-capsule`, the
capture replay of `bhf explain` and `bhf verify-poc` set them again, so the
finding replays in a clean environment. `replay.py` sets them too, and
preloads the shim `BHF_RUNTRACE_SHIM` names.

Scope of desocketing:

- It serves TCP servers; a UDP server's `recvfrom` reads the real socket.
- A connection carries what fits in a socket buffer (about 200 KiB), and a
  server that sends more than that in reply blocks.
- The C++ driver runs inputs without forking, so each run of a C++ server
  ends the persistent process and the next input starts a fresh one. The
  runs are slower and complete.

## Allocation Discipline

Every hook formats its event into a stack buffer and writes it with
`libc::write`. Hooks never call `malloc`, `free`, `Box::new`, `String` or
`Vec`, because the hooked process can be inside its own allocator on the
call path that reached the hook.

The copy of the current input that a harness publishes with
`bhf_shim_set_fuzz_input` (bhf's driver and every generated harness do, once
per input) is kept in a private anonymous mapping, never on the heap. In a
sanitized target `malloc` is the sanitizer's, and the driver allocates each
input with exactly its size just before publishing it, so a heap copy would sit
in the next chunk: a read past the input beyond its redzone would be reported
against the shim's allocation, as a heap-use-after-free of the copy the next
publication freed, or not at all for the live copy. With the copy mapped, an
AddressSanitizer report (kind, region, allocation stack) and the set of
findings are the same with and without the shim. The mapping is reused while
the input fits and replaced by a larger one when it does not.

## Pass Modes

The shim caches `BHF_RUNTRACE_MODE` on first use:

| Mode | Behaviour |
|---|---|
| `audit` (default) | Log on failure; do not substitute fakes. |
| `empty` | Create the fake but every `read()` returns EOF on the first call. |
| `rng` | Each fake resource gets a xorshift RNG seeded by `(harness_id, resource_name, fuzz_seed)`. |
| `fuzz_driven` | Reads pull from a shared memfd populated by the harness with the current fuzz input. The engine's coverage feedback learns to steer bytes to whichever fake gates a code path. |

`Mode::is_faking()` returns true for the last three.

## Environment Variables

The shim consumes these env vars. The auto loop sets them via
`Command::env` when spawning each harness, so they do not need to be exported
in the parent shell.

| Variable | Set by | Consumed by | Purpose |
|---|---|---|---|
| `BHF_RUNTRACE_LOG` | auto | shim | Path to the per-harness JSONL audit log |
| `BHF_RUNTRACE_MODE` | auto | shim | One of `audit` / `empty` / `rng` / `fuzz_driven` |
| `BHF_RUNTRACE_SEED` | auto (replay) | shim | Fuzz seed for the per-resource RNG; lets `bhf replay` reproduce a finding |
| `BHF_FUZZ_INPUT_FD` | harness | shim | File descriptor of the shared memfd carrying the current fuzz input (pass `fuzz_driven`) |
| `BHF_FUZZ_INPUT_LEN` | harness | shim | Length of the fuzz input in the shared memfd |
| `BHF_DISABLE_DLOPEN_FAKE` | user | shim | Opt out of synthetic `dlopen` / `dlsym` handles when a target uses struct-return-by-value through `dlsym` |
| `BHF_FAKE_IDENTITY` | auto (replay) | shim | Enable deterministic `getpid`/`getuid`/`getgid`/`getppid` constants |
| `BHF_DESOCKET` | user | shim, C driver | `1` serves a TCP server's first accepted connection from the fuzz input and ends the run at a later `accept` once the server has closed it; the C driver then runs each framed input in a forked child (#312) |
| `BHF_FAKE_CLOCK` | user | shim | `1` serves `clock_gettime`, `gettimeofday`, `time`, `clock` and `timespec_get` from the virtual clock each input starts over, and waits for an absolute deadline taken from it on the real clock (#342); ignored by `--engine libfuzzer` |
| `BHF_CMPLOG` | auto | shim, C/C++ driver | Enable `strcmp`/`strncmp`/`memcmp` comparison-operand recording (cmplog / RedQueen) into `BHF_RUNTRACE_LOG`. The shim records each distinct comparison once per process, and none once the log holds 8 MiB |
| `BHF_TARGET_EXE` | bhf (native harnesses) | shim | The harness executable. With it set, only a process running that file (the same device and inode as `/proc/self/exe`) records comparisons: the harness and the children it forks, such as the fork server's, but not a shell or tool it runs through `system`, `popen` or `exec` |
| `BHF_CMP_EVIDENCE` | bhf (capture replays) | C/C++ driver | File the driver records every comparison of one run into, for the comparison evidence of a finding's input; unset during fuzzing |
| `LD_PRELOAD` | auto | dynamic linker | Includes the absolute path to the runtrace shim; an existing value is kept. |

`bhf auto` looks for the shim in this order:

1. the path in `BHF_RUNTRACE_SHIM`;
2. Cargo's `libbhf_runtrace_shim.so` beside the `bhf` executable;
3. the release copy `libbhf_runtrace.so` beside it;
4. a sibling `bhf_runtrace_shim-*` directory extracted from a release
   archive.

When it finds none, it prints one warning and runs without the runtime
audit.

## Setenv Injection

After the audit pass, the auto loop reads every NULL-result `getenv("X")` or
`secure_getenv("X")` event and calls the real
`setenv("X", "/tmp/bhf/fake_env/X", 1)` in the spawned child for the next
pass. The shim does not synthesize values in the env lookup path; the fake
value comes from the actual process environment. This keeps secure-execution,
threading, and glibc internals correct and makes findings reproducible:
`export X=/tmp/bhf/fake_env/X` and re-run.

## Replay Envelope

Each finding carries enough state to reproduce the runtime conditions:

```json
"runtime_mode": {
  "pass": "rng",
  "fuzz_seed": "0x47564655_5a5a",
  "env_injected": { "ACME_CONFIG_DIR": "/tmp/bhf/fake_env/ACME_CONFIG_DIR" },
  "fakes_active": ["/etc/foo.conf", "unix:///var/run/acme.sock"]
}
```

`bhf replay --finding <F> --harness <bin>` rebuilds the same env and
re-loads the shim with the same mode. Reproduction is bit-stable for `rng`
and `empty`; `fuzz_driven` requires the same fuzz input bytes.

## Executable Oracles

Most of these oracles read the shim's audit stream, so they fire wherever
the shim is armed (the lanes listed under **Where it runs** above).
The Ada constraint-check oracles (BHF-102, BHF-103, BHF-104, BHF-105) are fed
by Ada source instrumentation compiled into the binary instead, so they
also run on cross-compiled Ada targets.

The shim's JSONL audit stream feeds the executable oracles of the built-in
fuzz engine. bhf reads only the runtrace lines that the current harness
execution appended, evaluates the registered oracles, and emits each unique
oracle hit as a normal finding with that execution's exact input bytes.

| Observed event | Finding |
|---|---|
| A file path with a `..` segment; a network egress destination from a connect or resolver event; a secret-like environment variable name from a redacted `getenv` or `secure_getenv` event (also when the value was already set) | an `oracle_hit` finding with the matched API and the runtime evidence |
| A `system` or `popen` command string that holds shell metacharacters and is fuzz-controlled | `command-injection` (BHF-304) |
| A file descriptor opened without a matching `close` before the execution ends | resource leak (BHF-306, below) |
| A successful `unlink`, `unlinkat` or `remove` of a path with a parent-directory segment | `file-deletion-runtime` (BHF-414) |
| A fuzz-controlled `printf`, `fprintf`, `dprintf`, `sprintf` or `snprintf` format with a conversion such as `%x`, `%p`, `%s` or `%n` | format-string oracle hit (BHF-408) |
| A `dlopen` of a bare name, a relative or parent-directory path, a temporary writable directory or another non-system absolute path | `dynamic-library-load-runtime` (BHF-413) |
| A native C/C++ assertion failure (`__assert_fail`, `__assert_perror_fail`) | `native-assertion-contract` (BHF-415), with the expression and source |
| `chmod` or `fchmod` asking for setuid, setgid or world-writable modes; `mkdir` or `mkdirat` creating a world-writable non-sticky or setuid/setgid directory | `insecure-permissions-runtime` (BHF-416, CWE-732) |
| A file created without `O_EXCL` in a world-writable directory | `insecure-temp-file-runtime` (BHF-417, CWE-377) |
| A `path_check` (`access`, `stat`) followed by an `open` of the same path in one execution | `toctou-runtime` (BHF-418, CWE-367) |
| An `open`, `openat` or `fopen` whose path carries byte-origin taint from the current input | `path-controlled-open-runtime` (BHF-405, CWE-22) |
| A fuzz-controlled SQL query string passed to SQLite, libpq or MySQL | SQL injection (BHF-441, CWE-89) |

**When input counts as controlling.**

- A command is fuzz-controlled when it carried fuzz-input bytes on one
  execution and never ran without them: the same cross-execution test as
  BHF-431, decided once at the end of the run. A constant command is never a
  finding, whatever shell syntax it holds, including when the
  auto-dictionary echoed it into an input; the run prints one note naming
  the constant commands it saw.
- A format string is fuzz-controlled when it is outside the program's
  read-only data (a string literal never qualifies, even when the fuzzer put
  its bytes in the input) and the whole format, at least 4 bytes long,
  occurs verbatim in the current input.
- BHF-405 also uses cross-execution matching: a path is reported only if it
  was tainted on at least one execution and never opened untainted during
  the run. The shim stamps the controlled flag and the input offset on the
  path event. The matching drops program-constant paths that the
  auto-dictionary (cmplog tokens taken from the target's own string
  constants) echoes back into inputs.

**Ada runtime checks.** Ada source instrumentation (the breadcrumb, handler
and raise probes, not the shim) can append `runtime_check` events for
handled `Constraint_Error` range and index checks, `Storage_Error`,
`Tasking_Error` and user-defined exceptions. The same executable-oracle
path turns them into `ada-runtime-constraint-check` (BHF-102),
`ada-runtime-storage-error` (BHF-103), `ada-runtime-tasking-error`
(BHF-104) and `ada-runtime-user-exception` (BHF-105) findings with handler
and source evidence.

The resource-leak oracle (BHF-306) is named for the harness it watched:
`resource-leak` (exception `ORACLE_RESOURCE_LEAK`) for a C, C++ or other
native harness, `resource-leak-ada` (`ORACLE_RESOURCE_LEAK_ADA`) for an Ada
one.

### Runtime confirmation

Static source scans emit candidate findings (for example BHF-405
path-controlled-file-open and BHF-408 format-string) with no confirmation marker.
When the runtrace shim observes the same data flow at runtime (fuzz-input
bytes reaching the sink unsanitized, tracked by byte-origin taint), the
resulting oracle-hit finding is stamped `"confirmation": "runtime"` and carries
a `taint_path` evidence value describing the source→sink flow:
`fuzz_input[offset..] → open(path)` for BHF-405, `fuzz_input → printf(format)`
for BHF-408. Static-scan findings carry no `confirmation` marker, so consumers
use the field to separate runtime-confirmed hits from static candidates.

### Platform-neutral collector (`--collector`)

The `LD_PRELOAD` runtrace shim above is the in-process Linux provider. The
`--collector` option (`bhf fuzz`, `bhf binary fuzz`, #60) adds a
**decoupled** provider that speaks a versioned JSONL wire contract
(`bhf.collector-event.v1`, with a JSON Schema in `schemas/`) instead of
linking into the target. It observes the same families of effects (process
execution, filesystem operations with resolved paths, and module loads)
from a separate provider: the native Windows ETW provider
`bhf-collector-win`, or any external sidecar that speaks the protocol.

The host attributes the observed events to the testcase's descendant
process tree within a bounded window after exit and maps them through the
**same executable-oracle registry**. A controlled process execution, path
escape or controlled library load becomes a `binary_semantic` finding with
no crash. The `input_derived` and `taint_offset` fields of a
`CollectorEvent` carry byte-origin taint forward, so a fixed program
constant is never taint-confirmed, as with the shim's cross-execution
matching.

The stream records dropped events, APIs the platform does not support and
permission denials, and any of them withholds a "clean" assurance. Each run
and finding records the collector's provenance: backend name, version and
hash, process-tree scope, observation window, the event classes the backend
declares it supports (kept separate from the classes seen firing in this
run) and fidelity. A collector finding stores its raw `CollectorSession`
evidence, so replay reproduces it deterministically and the attribution can
be audited.

## Audit-Only Fallback

If the shim cannot be loaded (host without `LD_PRELOAD` support, statically
linked harness, or `--no-stubs`-style diagnostics modes), the auto loop
falls back to running the harness without the shim. Layer C of
`needed_for_build` stays empty for that target; build-time layers A / B are
unaffected.

## Stderr Pattern Source

Auto also matches a small set of stderr patterns for messages the shim
cannot catch (a target that wrote a custom `No such file: /etc/myconf`
instead of relying on glibc's error string). Hits fold into Layer C with
`source: "stderr_pattern"`.

## Diagnostics

- Inspect `<work>/auto/<harness-id>/runtrace.jsonl` for the raw event log.
- Inspect `<work>/auto/<harness-id>/repairs/` for synthesised stubs, types,
  placeholder headers, and Ada package bodies the attempt loop applied.
- Inspect `<work>/auto/run.json` for the aggregate `needed_for_build`
  ledger and per-target build error classifications.

For the broader auto workflow that drives this shim, see [Auto](auto.md).
