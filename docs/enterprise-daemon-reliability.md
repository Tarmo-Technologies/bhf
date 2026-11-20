<!-- SPDX-License-Identifier: Apache-2.0 -->
# Daemon Reliability: Bounded Work and Owned Processes

This page describes how three long-running components bound their memory and
their child processes:

- the stdio daemon `bhf-daemon` (see [Daemon](site/daemon.md) for its
  protocol);
- the continuous scheduler (`continuous_daemon` crate), which runs queued fuzz
  jobs;
- the GNAT Studio client in `editors/gnatstudio/`, which talks to the daemon.

## Message size

`bhf-daemon` reads requests and writes responses under one limit,
`BHF_DAEMON_MAX_MESSAGE_BYTES`:

| Setting | Value |
|---|---|
| Default on Linux | 1/512 of available memory, clamped to 1–64 MiB |
| Default elsewhere | 8 MiB |
| Override | A positive integer in `BHF_DAEMON_MAX_MESSAGE_BYTES` |

Responses and both error fallbacks serialize directly into a buffer of that
size. A result too large for it becomes a small JSON-RPC error frame, and the
next request is read normally. When the request ID itself is too large for the
detailed error to fit, the compact error carries a null ID.

## Loading findings

The daemon loads findings through a read-only loader in the report library,
separate from the CLI's report loader. The loader:

- reads only `finding.json` records, never `testcase.bin` or reproducer
  bodies, and writes no reproducers;
- caps the bytes read from each opened file with `Read::take`, so a file that
  grows between `stat` and `read` stays bounded;
- caps the record count and the normalized serialized bytes before it keeps
  each record;
- rejects symlinked and non-regular finding directories and files.

With `limit` the message size above, its budget is:

| Budget | Value |
|---|---|
| Records | `clamp(limit / 16 KiB, 1, 4096)` |
| Raw JSON bytes, all records | `limit / 2` |
| Normalized JSON bytes, all records | `limit` |
| Directory entries scanned | `8 × records + 1024` |

The response limit still applies to the complete JSON-RPC envelope. The
budget bounds file input and retained results. While one capped finding is
parsed, the heap briefly holds extra copies of its JSON and derived fields
before the normalized-byte charge, so momentary heap use can exceed the
budget.

## Deadlines and child processes

**GNAT Studio client.** Each request has a deadline, 30 seconds by default,
set with the `BHF/daemon-timeout-seconds` preference. On a timeout the client
terminates the daemon's process tree and makes bounded attempts to reap the
child and join its reader worker. The client keeps one reader worker per
in-flight request and stops it when the daemon exits or times out.

**Scheduler.** The scheduler polls its fuzz children and its shutdown flag; a
child that ignores `--time` cannot block shutdown.

| Setting | Default | Set with |
|---|---|---|
| Wait to reap a child after its process tree is killed | 2 s | `Scheduler::start_with_shutdown_timeout` |
| Build and setup grace added to a job's wall deadline | 30 s | `Scheduler::start_with_limits` |

A job with a positive budget has its budget rounded up to whole seconds. Its
wall deadline is that budget plus the grace, followed by the reap wait. A job
with a zero budget runs until shutdown.

| Event | Stored job state |
|---|---|
| Wall deadline expires | `Failed` |
| Scheduler shuts down while the job runs | `Queued`, so a later start retries it |
| Scheduler shuts down while the job waits | Unchanged |

On Unix, the scheduler and the GNAT Studio client start each child in a new
process group and signal that group. On Windows they run `taskkill /T /F`,
with a bounded fallback to terminating the direct child.

## Job storage

The scheduler persists jobs to `<data_dir>/jobs.jsonl`. Each update atomically
replaces the file, and on Unix the parent directory is synced. A
directory-sync failure after the replacement reports uncertain durability and
blocks new submissions until the scheduler restarts. A malformed or truncated
log, a duplicate job ID, or a budget that cannot be represented fails startup
and leaves the file unchanged.

Default scheduler limits (`SchedulerLimits`):

| Limit | Default |
|---|---|
| Jobs kept in memory | 10,000 |
| Queued jobs | 1,024 |
| Snapshot size, at load and on write | 64 MiB |
| One job's serialized record | 64 KiB |
| Jobs per list page | 1,000 |

Soak testing of these limits is planned in
[Service soak plan](enterprise-service-soak-plan.md).

## Trust and platform boundaries

- Run the stdio daemon only on a workspace that untrusted users cannot write
  to. On Unix the loader opens finding directories and files without
  following links, which keeps each descriptor anchored while it reads. A
  concurrent replacement of an ancestor of the findings root is outside that
  check.
- On Unix, a descendant that creates its own session leaves the process group
  and is not signalled. If such a descendant keeps stdout open, the GNAT Studio
  client leaves its reader as a daemon thread and the UI does not wait on it.
  Process-tree termination on native Windows has not yet been validated.
- Scheduler webhooks use their own socket timeouts and synchronous DNS
  resolution. A webhook in progress can delay shutdown past the reap wait,
  which applies to fuzz children.
- A process stuck in uninterruptible kernel I/O can resist termination. After
  the reap wait, the scheduler logs it and returns from the worker.

## Tests

```sh
cargo test -p bhf-daemon -p report -p continuous_daemon --lib --offline
python3 -m unittest discover -s editors/gnatstudio/tests -v
```

The Rust tests cover bounded output, the oversized-ID fallback followed by a
valid frame, large and growing finding files, normalized expansion, symlink
rejection, scheduler wall deadlines, restart validation, and queued state kept
after a bounded shutdown of a child and grandchild. The GNAT Studio tests
cover a normal reply, a silent daemon, a partial frame, early daemon exit and
cleanup of an owned grandchild.
