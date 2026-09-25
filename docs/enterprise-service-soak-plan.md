<!-- SPDX-License-Identifier: Apache-2.0 -->
# Enterprise service durability and soak plan

Source audit: 2026-09-24. This is a design and failure-injection plan, not a
claim that the fixtures below have run. Scope is `continuous_daemon::Scheduler`,
the daemon's JSON-RPC tenant policy, and their lifecycle boundaries. Fixtures
must use temporary local directories, temporary child scripts, and loopback
listeners only; they must never send an external webhook.

## Current contract and confirmed gaps

| Area | Source evidence and consequence | Next bounded slice |
| --- | --- | --- |
| Queue/backpressure | `SchedulerLimits` now caps retained jobs (10,000), waiting jobs (1,024), individual records (64 KiB), and snapshot bytes (64 MiB) by default; overload returns `Capacity` before consuming an ID or changing the snapshot. `list_jobs_page` caps a page at 1,000. The legacy `list_jobs` still clones up to the retained-job cap. Each start/finish still rewrites the bounded full snapshot under a global mutex, so latency can be high at the cap; there is no safe retention/export rotation yet. | Measure submit/list latency and move persistence to bounded-work records or compaction, then add explicit export/retention policy. |
| Acknowledged-job durability | `persist_jobs` writes a `NamedTempFile`, `sync_all`s the file, then persists it as `jobs.jsonl`; it does not sync the parent directory after rename. `submit` acknowledges only after this succeeds, but a power loss can still lose the directory entry on filesystems requiring directory fsync. On worker transitions, persistence failure is logged and execution continues, so in-memory Complete/Failed can disagree with durable Running/Queued and restart can repeat a job. | Sync the parent directory before acknowledgement on supported platforms; specify an explicit durability contract and error behavior for transition failures. Keep the existing no-ack-on-persist-failure behavior. |
| Startup recovery | `start` now reads at most the configured snapshot byte cap plus one, limits record length/count and reconstructed queue, and rejects duplicate numeric IDs. It still fails closed on any malformed/truncated row and requeues Running rows. A crash may leave an old fuzz process alive while a new scheduler starts a replacement. | Define trailing-partial recovery and quarantine policy without data loss; reconcile owned survivors before requeue where feasible. |
| Job time budget | `run_one_job` passes `--time` but only polls for shutdown and child exit; it has no scheduler-side wall deadline. A child ignoring `--time` runs until shutdown. `submit` persists `time_budget.as_secs()`, so a positive subsecond budget becomes zero and omits `--time` entirely. | Enforce a monotonic wall deadline around the owned process group, with documented zero/subsecond semantics and a bounded reap; expose timeout distinctly in diagnostics (or add a compatible state). |
| Entire shutdown | `Drop` sets shutdown and joins every worker. The configured `shutdown_timeout` covers killed fuzz-child reaping only. Webhook socket work now has an overall 10-second deadline and 64 KiB response cap, so silent/trickling/large-response loopback peers cannot hold a worker indefinitely through socket reads. Synchronous `to_socket_addrs` remains unbounded for hostnames, and the worker does not check shutdown during delivery. | Make resolution cancellable/bounded, check shutdown during delivery, and define one whole-scheduler shutdown deadline. Preserve at-least-once notification semantics with retry state if required; do not silently promise exactly-once. |
| Tenant policy scope | Shipped `bhf-daemon`/`daemon` stdio binaries call `run_json_rpc`, which selects `LocalSingleUser`; `--mcp` is also unauthenticated. The `run_json_rpc_with_security` library API enforces tokens and Viewer versus Operator/Admin methods. Operator and WorkspaceAdmin currently have the same method permissions. Paths are canonicalized for authorization, then opened/written later by raw path; writable ancestors can be swapped in between. `Scheduler::submit` has no identity/tenant parameter and can run a configured executable on caller-supplied project/harness inputs. | Document the shipped stdio interface as same-user trusted, not a multi-tenant service. For any shared front end, require explicit tenant-aware configuration and transport isolation, bind file operations to authorized directory handles (or isolate each tenant in an OS container/user), and gate scheduler submissions independently. Do not infer OS isolation from JSON-RPC tokens. |

The current scheduler is effectively **at-least-once**, not exactly-once: after
a crash, a persisted Running job is requeued, and a completion whose persistence
failed may also be replayed. Webhooks are best-effort and have no durable delivery
record. Any user-facing reliability promise should use these terms until the
durability and idempotency contract is implemented.

## Failure-injection fixtures and acceptance checks

Use public `Scheduler::start` / `start_with_shutdown_timeout`, `submit`,
`list_jobs`, and `Drop` in integration tests. Build fixture executables as
short-lived scripts under a `tempfile::TempDir` on Unix and a platform-appropriate
test helper on Windows; never use a production `bhf` binary. Synchronize through
local files/channels, not arbitrary sleeps, except for short bounded polling.

1. **Queue saturation and latency:** one fixture child waits on a local release
   file; submit many distinct jobs to one worker and record `submit`,
   `list_jobs`, RSS, and `jobs.jsonl` size at 100, 1,000, and 10,000 jobs. This
   establishes the present growth curve. After a cap is added, assert the next
   submission returns an overload error before mutating `seen`, disk, or ID;
   release the child, restart, and verify all acknowledged IDs occur once and
   newly available capacity accepts work. Run a bounded multi-producer variant
   to exercise mutex contention and preserve monotonic IDs.
2. **Ack/crash durability:** a helper process starts the scheduler in a temporary
   directory, submits one job, sends its returned ID to the parent over a pipe,
   and exits abruptly without `Drop`. Parent restarts from the same directory
   and finds the acknowledged ID. This tests ordinary crash recovery, **not**
   power-loss durability; directory-fsync behavior requires source review and a
   filesystem/fault-injection environment able to simulate a lost rename. Also
   force a persistence error using a `jobs.jsonl` directory and assert `submit`
   returns an error without acknowledging or consuming the ID.
3. **Corrupt/recovery input:** seed `jobs.jsonl` with valid rows followed by a
   truncated row, an invalid middle row, duplicate job IDs, an enormous line,
   and a numeric-ID overflow in separate cases. Record current `start` errors;
   after recovery policy is defined, assert that only a trailing partial row is
   recoverable, interior corruption is surfaced/quarantined, and no record is
   silently skipped or executed twice. Cap recovery memory before allocating a
   full hostile file.
4. **Wall deadline and process tree:** a fixture child ignores `--time`, writes
   its PID plus a grandchild PID to temporary files, then waits indefinitely.
   Submit a positive short budget without dropping the scheduler. Assert the
   scheduler itself terminates/reaps the owned tree by a bounded deadline,
   records a non-success outcome, and can dispatch the next queued job. Test a
   positive subsecond budget separately so it cannot silently become unlimited.
   Repeat across restart to verify no old child and new attempt overlap. Native
   Windows process-tree cleanup needs its own runner, not a Linux-only assertion.
5. **Webhook/shutdown:** bind `127.0.0.1:0`, configure that URL, and make one
   completed job trigger delivery. Separate loopback servers (a) accept and stay
   silent, (b) emit one response byte periodically without closing, and (c)
   stream a large response. Drop the scheduler while each is active and assert
   a whole-shutdown bound after the lifecycle fix, plus a byte cap. Do not use
   external DNS in tests: inject a resolver seam that deliberately blocks until
   cancelled, or test the resolution deadline with an in-process resolver stub.
   Verify a successful small 2xx response remains accepted.
6. **Tenant authorization:** exercise the public
   `run_json_rpc_with_security` with two temporary workspace roots and framed
   requests: missing/wrong token, Viewer operation denial, Operator/Admin
   operations, cross-root read/output denial, and a symlinked finding record.
   Assert no outside-workspace content or output is exposed. A separate
   adversarial fixture races replacement of a writable ancestor between
   authorization and use; any reproduction is a confinement failure, but a
   nondeterministic non-reproduction is **not** proof of safety. Once dirfd or
   OS isolation is implemented, make the race deterministic with an injected
   barrier. Test duplicate tenant tokens/configuration explicitly. Do not run
   untrusted fuzz code in this in-process tenant fixture: that boundary needs
   process/container isolation and its own integration environment.

## Implementable order and release gates

First, enforce a scheduler-side wall deadline and an overall webhook delivery
budget, because they are direct hangs under one job. Second, add queue/recovery
caps and API-visible backpressure before scale soak. Third, tighten crash
durability and corruption policy, including parent-directory sync and a
bounded recovery reader. Fourth, define a true shared-service boundary: tenant
config/transport, workspace handles or per-tenant OS isolation, and authenticated
scheduler submission. These slices are separable; no broad storage or service
redesign is required to establish each invariant.

A release soak should run the capped queue under sustained local submissions,
bounded crash/restart cycles, and loopback webhook faults while recording peak
RSS, `jobs.jsonl`/snapshot size, p95/p99 submit and list latency, child count,
time from shutdown request to return, and acknowledged-ID survival. Set numeric
SLO thresholds from measured baseline and host profile before claiming parity
with a production multi-tenant service. Do not label the current JSON-RPC token
checks as a sandbox for untrusted fuzz workloads.

## Implemented narrow slice: restart validation and wall deadline

The design below was recorded before code changes, then implemented in
`continuous_daemon`:

- Keep the existing JSONL snapshot format and API. On startup, reject a
  malformed/truncated or duplicate-ID row with its line number and path; do not
  overwrite, truncate, or skip the file. Accept the usual single final newline,
  but not an empty interior record. Validate numeric IDs and reject numeric
  aliases (for example `J-7` beside `J-000007`) before deriving the next ID;
  retain acceptance of legacy unpadded IDs. Running rows recover as Queued only after the
  *entire* snapshot validates.
- Keep atomic tempfile replacement. After replacement, sync the containing
  directory on Unix. A pre-replacement error leaves the existing snapshot and
  in-memory submission unchanged. A post-replacement directory-sync error has
  an **uncertain durability outcome**: do not roll back/reuse the ID or pretend
  the prior snapshot is still current. Report the uncertainty and fail closed
  for further submissions until restart; tests will inject this error at the
  sync boundary. Other platforms retain best-effort replacement and require
  native filesystem durability validation.
- For positive budgets, round fractional seconds up before persisting; reject
  an unrepresentable budget. Give the child its requested `--time` plus an
  explicit default 30-second build/setup grace as the scheduler wall limit;
  allow the separately configured child-reap bound after the deadline.
  Expose a bounded-grace start variant for deterministic fast tests. On wall
  expiry, kill/reap the owned process group, persist Failed, and continue to
  the next queued job. Shutdown still wins if concurrent and persists Queued.
  Zero budget retains the existing unlimited behavior. Reject any persisted
  positive budget that cannot form a monotonic deadline instead of panicking.

Validation: `cargo test -p continuous_daemon --lib --offline` passed 22/22,
including line-specific corrupt-snapshot errors without file modification,
legacy unpadded ID acceptance, injected post-replacement directory-sync error,
positive subsecond rounding, budget overflow, and an ignored-`--time` child
whose grandchild is stopped and Failed state persists. The preexisting shutdown
fixture still verifies that intentional shutdown requeues instead.

The later capacity slice added `SchedulerLimits`, bounded startup reads,
queued/retained/record/snapshot limits, a 64-worker cap, and `list_jobs_page`.
A zero poll interval is rejected. Tests reject
over-cap recovery without modifying the snapshot, reject a queued submission
without consuming an ID or writing the snapshot, and reject a retained-history
submission after the first job completes. `cargo test -p continuous_daemon
--lib` passed 28/28 after the webhook deadline/response-cap slice; `cargo check --workspace --all-targets` passed. This is a
memory and disk bound, not a throughput or multi-tenant soak. Full-snapshot
rewrite latency, cancellable DNS and whole-scheduler shutdown, retention/export,
and crash-time orphan reconciliation remain open.
