<!-- SPDX-License-Identifier: Apache-2.0 -->
# Scheduler reliability and operational health

This document describes the `continuous_daemon::Scheduler` library. It does not
introduce a network service, a new CLI subcommand, a multi-tenant security
boundary, or a guarantee of exactly-once execution.

## One owner per storage directory

`Scheduler::start` now acquires `.bhf-scheduler.lock` before loading `jobs.jsonl`.
A second cooperating scheduler using the same local directory receives
`DaemonError::DataDirInUse`, including when it uses an equivalent path spelling.
The lease stays open until the scheduler has joined its worker threads.

On Unix this uses a nonblocking exclusive `flock`; Windows uses an exclusive
file open. The operating system releases ownership when the owning process
terminates. The lock file is deliberately retained, never truncated or deleted.
Its presence alone does not mean the directory is locked. **Do not delete or
replace it to get around an active owner.** That can create independent lock
objects and defeat ownership coordination.

Use a trusted, dedicated local directory whose ownership and parent directories
cannot be changed by untrusted users or tested code. These cooperative locks do
not establish distributed leadership, NFS/SMB failover correctness, protection
against privileged administrators, or coordination with older versions that do
not acquire the lock. Stop an older instance before starting the new version.
A crashed parent's lock release does not prove all of its child processes have
exited; orphan reconciliation remains separate work.

The lock and existing snapshot must be regular files. Unix opens reject leaf
symlinks and use nonblocking opens so FIFOs are rejected instead of waiting for
a writer. Windows opens reparse points themselves and rejects them. Missing
history remains a valid empty scheduler; malformed history, directories, and
unsupported file objects are errors rather than an empty-history fallback.
Normal file and directory permissions still need to be administered externally.

## Fail-closed persistence

State changes are serialized under the scheduler mutex and saved using the
existing temporary-file, file-sync, replacement, and platform directory-sync
path. No transaction log or database migration is added; the `FuzzJob` JSONL
format is unchanged.

| Failed phase | Behavior |
| --- | --- |
| Admission before snapshot replacement | Reject the submission, remove its tentative record, preserve the next ID, latch the storage fault, and stop further admission. |
| Admission after replacement but before successful directory sync | Return `DurabilityUncertain`, reserve the ID and accounting for the installed record, stop admission, and do not dispatch the unacknowledged job. |
| Transition to Running | Save successfully before dequeue/dispatch; on failure keep the job queued in memory and stop the scheduler. |
| Completion or interruption | Keep the observed runtime state visible, latch a failed save, stop new work, and do not send a completion notification from that failed transition. |

The first storage error is retained until restart. After it is latched, workers
do not perform more snapshot writes that could obscure the uncertain state.
Already running children encounter the existing shutdown/cleanup path. A
nonjoining shutdown request does not retroactively cancel a notification already
being sent for an earlier, successfully committed transition.

**Execution remains at least once.** On restart, persisted Running records are
requeued. A child can finish just before a failed completion save or a process
crash; its work may therefore be repeated. An in-memory Complete row alongside a
storage fault is an observation, not a durable completion acknowledgment. A
successful save also retains the existing platform guarantees: Unix syncs the
parent directory, whereas the current non-Unix implementation does not add that
same directory-sync primitive. No stronger Windows power-loss guarantee is
claimed by the new health API.

## Health and shutdown APIs

`Scheduler::health()` returns a serializable `SchedulerHealth` snapshot with
`schema_version: 1`. It includes admission/shutdown state, counts for every job
state, queue/history/snapshot limits, reserved snapshot bytes, and the first
`StorageFault`, if one occurred. A fault records the phase, scheduler-assigned
job ID, whether replacement occurred, the I/O error kind, and optional OS error
code. It intentionally excludes project paths, harness names, raw error text,
and webhook URLs.

For example, an embedding application with an existing scheduler can expose an
appropriately access-controlled health observation:

```rust
use continuous_daemon::Scheduler;

pub fn health_json(scheduler: &Scheduler) -> Result<String, serde_json::Error> {
    serde_json::to_string(&scheduler.health())
}

pub fn begin_shutdown(scheduler: &Scheduler) {
    scheduler.request_shutdown();
}
```

`accepting_submissions` is a point-in-time observation of the shutdown flag and
coarse remaining capacity, not a reservation for the next submission. Its
success still depends on that request's size/budget, available storage, and any
concurrent submissions. Read `storage_fault` to distinguish a persistence
shutdown from an ordinary shutdown or exhausted retention capacity.

`request_shutdown()` is idempotent and does not join worker threads. It stops
admission and signals workers; waiting/interrupted jobs are retained for restart,
not permanently cancelled. Dropping the scheduler still joins workers and only
then releases storage ownership. Both APIs acquire the state mutex: they may
wait behind filesystem I/O. This is not a hard bounded shutdown API; synchronous
DNS in webhooks and blocking filesystem operations remain possible delays.

## Recovery procedure

Preserve the reported fault and the `jobs.jsonl` file, then stop the owning
service and its remaining children. Correct the underlying storage problem
(capacity, permissions, filesystem health, or an unexpected file type). Retain
the lock file and restart normally, without manually forcing a lock takeover.
A corrupt snapshot must be investigated or restored from an appropriate backup;
startup will not quietly discard it. Review jobs that may have completed before
the fault, because recovery can repeat them. An external supervisor should not
continuously restart on a persistent storage fault without operator visibility.

Completed records are still retained under the existing limits. This change does
not provide automatic history pruning, a durable webhook outbox, idempotent job
submission, tenant isolation, or a shared-service authentication layer.

## Regression coverage

The suite exercises rejected duplicate owners within a process and across real
processes, ownership recovery after killing the owner process, regular-file
checks, corrupted-history preservation, explicit shutdown, health serialization,
and injected failures both before and after snapshot replacement. A real Unix
worker test makes completion persistence fail and verifies that the next queued
job is not dispatched.

Run `cargo test --locked -p continuous_daemon --lib` on Linux. On Windows, run
`cargo test --locked -p continuous_daemon --lib health::tests`; the existing older
suite contains Unix-specific executable fixtures. The new cross-platform tests
compile and run natively on Windows; this selective command is not a claim that
the entire older scheduler suite is Windows-portable.

The regular CI workflow runs these Linux and Windows commands explicitly. The
Linux workspace suite continues to include them as well. Validation observations,
source blob hashes, and artifact digests are recorded in
[validation/scheduler-reliability-2026-09-25.json](validation/scheduler-reliability-2026-09-25.json).
These results do not establish full release-matrix acceptance, embedded-target
qualification, or enterprise-readiness certification.
