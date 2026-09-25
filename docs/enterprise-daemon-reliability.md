<!-- SPDX-License-Identifier: Apache-2.0 -->
# Enterprise daemon reliability: bounded work and owned processes

Review baseline: current shared production-readiness worktree, 2026-09-24.
Scope: the stdio daemon, continuous scheduler, and GNAT Studio daemon client.

## Confirmed gaps and implemented controls

1. `run_json_rpc_with_security` serialized complete responses into an unbounded
   `Vec`. Responses and both error fallbacks now serialize directly into a
   bounded buffer using `BHF_DAEMON_MAX_MESSAGE_BYTES`; an oversized result
   yields a small JSON-RPC error frame without desynchronizing the next request.
   If a request ID itself prevents the detailed error from fitting, the compact
   error uses a null ID.
2. The daemon formerly called the CLI-oriented report loader, which read every
   finding and potentially read large `testcase.bin` bodies to generate
   reproducers. A metadata preflight was rejected after review because files can
   grow between stat and read. The daemon now calls a report-library read-only
   loader that caps bytes on opened finding descriptors with `Read::take`, caps
   count and normalized serialized bytes before retaining each record, and
   rejects symlink/nonregular finding records. It never reads auxiliary testcase
   or reproducer bodies or writes reproducers. The CLI report API is unchanged.
3. GNAT Studio's blocking frame read could freeze refresh indefinitely if its
   child stopped writing. Requests now have a finite configurable deadline;
   timeout terminates the owned process tree and makes bounded attempts to reap
   the child and join the reader worker.
4. The scheduler's blocking `Command::status` let a child ignoring `--time`
   block `Drop` forever. It now polls owned fuzz children and shutdown, kills
   their process group on shutdown, bounds reaping, and persists interrupted
   jobs as Queued for restart. The configurable shutdown wait was added without
   changing existing `DaemonConfig` literals.

## Intended defaults and limits

- Daemon input and output use the same memory-aware
  `BHF_DAEMON_MAX_MESSAGE_BYTES` value (1–64 MiB by default, depending on
  available memory; a positive environment value overrides it).
- The bounded report reader allows at most `clamp(limit / 16 KiB, 1, 4096)`
  records, `limit / 2` aggregate raw JSON bytes, `limit` normalized JSON
  bytes, and `8 × max_records + 1024` directory entries. It reads each opened
  finding file through a byte-limited stream. The serialized response cap
  remains authoritative for the complete JSON-RPC envelope.
- GNAT Studio defaults to a 30-second request deadline, configurable through
  `BHF/daemon-timeout-seconds`. The client keeps one reader worker per in-flight
  request and tears it down when the owned daemon exits or times out.
- Scheduler shutdown interrupts owned fuzz jobs. A stopped running job is
  persisted as Queued, so a later scheduler start can retry it. Queued jobs
  retain their previous durable state. `Scheduler::start` uses a two-second
  child-reap bound; `start_with_shutdown_timeout` lets an operator configure it.
  Positive job budgets are rounded up to whole seconds and have a scheduler
  wall deadline of the requested budget plus a default 30-second build/setup
  grace, followed by the child-reap bound. `start_with_limits` can configure
  that grace. Deadline expiry persists Failed; shutdown still persists Queued.

## Platform and trust limits

- The bounded report reader rejects symlinked finding directories and files.
  On Unix, no-follow directory/file opens keep the file descriptor anchored
  while reading. A concurrent replacement of an ancestor of the findings root
  still needs a dirfd-based workspace traversal to eliminate fully; do not
  expose the stdio daemon to untrusted writers of the workspace root.
- Parsing and normalizing a single capped finding can temporarily hold copies
  of its JSON and derived fields before the normalized-byte charge. The budget
  bounds file input and retained results, not a strict instantaneous heap peak.
- On Unix, the scheduler and GNAT Studio client signal a new process group.
  A descendant that deliberately creates a new session can escape that group.
  On Windows, `taskkill /T /F` is used with a finite fallback to direct-child
  termination. If a descendant escapes and keeps stdout open, GNAT Studio's
  daemon reader is left as a daemon thread rather than blocking the UI on join.
  Native Windows process-tree validation remains required.
- Scheduler webhooks use separate socket-operation timeouts and synchronous
  DNS resolution. A webhook already in progress may delay `Drop` beyond the
  configured fuzz-child reap bound; the bound applies to owned fuzz children.
- The jobs snapshot is atomically replaced and its parent directory synced on
  Unix; malformed, truncated, duplicate-ID, and unrepresentable-budget logs
  fail startup without modification. A directory-sync failure after replacement
  reports uncertain durability and blocks new submissions until restart. Queue
  size and snapshot loading remain unbounded; see `enterprise-service-soak-plan.md`.
- A kernel task stuck in uninterruptible I/O may resist termination. After the
  configured reap wait, the scheduler logs this and returns from its worker;
  userspace cannot guarantee reaping that task within a finite deadline.

## Validation

- `cargo test -p bhf-daemon -p report -p continuous_daemon --lib --offline`:
  daemon 24/24, report 71/71, scheduler 17/17 passed. Coverage includes
  bounded output and oversized-ID fallback followed by a valid frame, large
  and growing finding inputs, normalized expansion, tenant symlink rejection,
  and retained queued state after bounded child/grandchild shutdown.
- `python3 -m unittest discover -s editors/gnatstudio/tests -v`: 18/18 passed,
  including normal reply, silence, partial frame, early death, and owned
  grandchild cleanup.
- `cargo test -p continuous_daemon --lib --offline`: 22/22 passed after the
  restart-validation and scheduler wall-deadline slice.
