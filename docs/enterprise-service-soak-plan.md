<!-- SPDX-License-Identifier: Apache-2.0 -->
# Service durability and soak plan

This plan covers `continuous_daemon::Scheduler`, the daemon's JSON-RPC tenant
policy, and their lifecycle boundaries. It lists what the code does now, the
open items, the failure-injection fixtures, and the soak a release should
run. [Scheduler reliability](scheduler-reliability.md) and
[Daemon](site/daemon.md) describe the behavior in detail.

Fixtures use temporary local directories, temporary child scripts, and
loopback listeners only; they never send an external webhook.

## Current state

| Area | What the code does | Open |
| --- | --- | --- |
| Queue and backpressure | `SchedulerLimits` caps retained jobs (10,000), waiting jobs (1,024), a single record (64 KiB) and the snapshot (64 MiB) by default, and workers at 64. Overload returns `Capacity` before an ID is consumed or the snapshot changes. `list_jobs_page` (and the `listJobs` method) caps a page at 1,000. | `list_jobs` still clones up to the retained-job cap. Each start and finish rewrites the whole bounded snapshot under one mutex, so latency grows toward the cap. There is no retention, export or compaction policy. |
| Acknowledged-job durability | `jobs.jsonl` is written to a temporary file, synced, renamed into place, and on Unix the directory is synced before `submit` acknowledges. A sync error after the rename returns `DurabilityUncertain` and stops admission. A failed save on a worker transition latches a storage fault and stops new work. | Windows does not sync the directory. |
| Startup recovery | `start` reads at most the snapshot cap plus one byte, limits record length and count and the rebuilt queue, and rejects a malformed or truncated row, a duplicate numeric ID or a numeric alias (`J-7` beside `J-000007`) with its line number, without changing the file. Legacy unpadded IDs are accepted. A `Running` row is marked `Failed`; on Linux a leftover `bhf fuzz` process for it is killed. | No recovery policy for a trailing partial row. |
| Job time budget | A positive budget is rounded up to whole seconds; an unrepresentable one is rejected. The scheduler's wall limit is `--time` plus a 30-second build and setup grace. On expiry it kills and reaps the job's process group, persists `Failed`, and moves on; a concurrent shutdown wins and persists `Queued`. A zero budget runs until cancelled. | |
| Shutdown | Dropping the scheduler waits for its threads until the shutdown timeout plus a fixed slack, then leaves any still running to a background thread that holds the storage lease. A webhook delivery, DNS resolution included, has a 10-second deadline and a 64 KiB response cap. | |
| Tenant policy | `bhf-daemon` serves one local user by default. `--security-config` enables `workspace_shared` or `multi_tenant` with tokens and the `viewer`, `operator` and `workspace_admin` roles. Jobs record their tenant and workspace; tenants see and cancel only their workspace's jobs. On Linux, tenant paths are pinned with `openat2`. `--mcp` has no authentication and cannot be combined with `--security-config`. | Jobs run the configured `bhf` as the daemon's OS user: tokens separate tenants' requests, not their processes. Run untrusted fuzz workloads under OS or container isolation per tenant. |

Webhooks are best-effort and have no durable delivery record.

## Failure-injection fixtures

Use the public `Scheduler::start` / `start_with_shutdown_timeout`, `submit`,
`list_jobs` and `Drop` in integration tests. Build fixture executables as
short-lived scripts under a `tempfile::TempDir` on Unix and a
platform-appropriate helper on Windows; never use a production `bhf` binary.
Synchronize through local files or channels, with short bounded polling at
most, not arbitrary sleeps.

1. **Queue saturation and latency.** One fixture child waits on a local
   release file. Submit many distinct jobs to one worker and record `submit`
   and `list_jobs` latency, RSS, and `jobs.jsonl` size at 100, 1,000 and
   10,000 jobs. Assert that the submission past a cap returns an overload
   error without changing `seen`, the disk or the next ID. Release the child,
   restart, and check that each acknowledged ID appears once and that freed
   capacity accepts work. A bounded multi-producer variant checks mutex
   contention and monotonic IDs.
2. **Acknowledgement and crash.** A helper process starts the scheduler in a
   temporary directory, submits one job, sends the returned ID to the parent
   over a pipe, and exits without `Drop`. The parent restarts from the same
   directory and finds the acknowledged ID. This covers process-crash
   recovery; power-loss durability needs a filesystem fault-injection
   environment that can lose a rename. Separately, make `jobs.jsonl` a
   directory and assert that `submit` returns an error without acknowledging
   or consuming the ID.
3. **Corrupt input.** Seed `jobs.jsonl`, one case at a time, with valid rows
   followed by a truncated row, an invalid middle row, duplicate job IDs, an
   oversized line, and a numeric-ID overflow. Assert that each is reported
   with its line, that no record is skipped or run twice, and that recovery
   memory is capped before a hostile file is read in full.
4. **Wall deadline and process tree.** A fixture child ignores `--time`,
   writes its PID and a grandchild's PID to temporary files, and waits.
   Submit a short positive budget without dropping the scheduler. Assert that
   the scheduler kills and reaps the whole tree by a bounded deadline, records
   a non-success outcome, and dispatches the next queued job. Test a positive
   subsecond budget separately. Repeat across a restart to check that an old
   child and a new attempt never overlap. Windows process-tree cleanup needs
   its own runner.
5. **Webhook and shutdown.** Bind `127.0.0.1:0`, configure that URL, and let
   one completed job trigger delivery. Separate loopback servers (a) accept
   and stay silent, (b) send one byte at intervals without closing, and (c)
   stream a large response. Drop the scheduler while each is active and assert
   the shutdown bound and the response cap. Use an injected resolver that
   blocks until cancelled, never external DNS. Check that a small 2xx response
   is still accepted.
6. **Tenant authorization.** Drive `run_json_rpc_with_security` with two
   temporary workspace roots and framed requests: a missing or wrong token,
   a viewer denied an operator method, operator and admin methods, reads and
   outputs outside the root, and a symlinked finding record. Assert that no
   content or output outside the workspace is exposed. A separate fixture
   races the replacement of a writable ancestor between authorization and
   use, with an injected barrier so the race is deterministic. Test duplicate
   tenant tokens and configuration. Do not run untrusted fuzz code in this
   in-process fixture; that boundary needs process or container isolation and
   its own environment.

## Release soak

Run the capped queue under sustained local submissions, bounded crash and
restart cycles, and loopback webhook faults. Record peak RSS, the size of
`jobs.jsonl` and the snapshot, p95 and p99 submit and list latency, the child
count, the time from a shutdown request to its return, and the survival of
acknowledged IDs. Set numeric thresholds from a measured baseline on the
target host profile.

## Implemented changes

- **Restart validation and wall deadline.** The startup checks, Unix
  directory sync, `DurabilityUncertain` handling, budget rounding and wall
  deadline in the table above. Tests cover line-specific corrupt-snapshot
  errors without file changes, legacy unpadded IDs, an injected sync error
  after replacement, subsecond rounding, budget overflow, and a child that
  ignores `--time` whose grandchild is stopped and whose `Failed` state is
  persisted.
- **Capacity limits.** `SchedulerLimits`, bounded startup reads, the queued,
  retained, record and snapshot limits, the 64-worker cap and
  `list_jobs_page`. A zero poll interval is rejected. Tests reject over-cap
  recovery without changing the snapshot, a queued submission without
  consuming an ID or writing the snapshot, and a retained-history submission
  after the first job completes.
- **Webhook deadline and response cap**, and the shutdown deadline (#272).
- **Tenant-scoped jobs and orphan reconciliation** (#385).

```sh
cargo test -p continuous_daemon --lib --offline
```
