<!-- SPDX-License-Identifier: Apache-2.0 -->
# Scheduler reliability and operational health

This page describes the `continuous_daemon::Scheduler` library: how it owns its storage directory, persists job state, reports health, and shuts down. `bhf-daemon --jobs-dir DIR` serves it through the daemon's `submitJob`, `listJobs` and `cancelJob` JSON-RPC methods, and `--security-config` scopes each tenant to its workspace's jobs ([Daemon: Continuous Daemon](site/daemon.md#continuous-daemon)).

A clean shutdown queues an interrupted job again, and the job runs from the start after restart. A job left `Running` by a scheduler that stopped without stopping it is marked `Failed` on restart (see [Restart after a crash](#restart-after-a-crash)).

A job can be cancelled (`Scheduler::cancel`). A queued job becomes `Cancelled` and is persisted at once. A running job is stopped by its worker, which kills the job's process tree as it does at a deadline and records `Cancelled`. If persisting a queued cancellation fails, the `Cancellation` storage fault is latched.

## One owner per storage directory

`Scheduler::start` acquires `.bhf-scheduler.lock` before it loads `jobs.jsonl`. A second scheduler on the same local directory gets `DaemonError::DataDirInUse`, also when it spells the path differently. The lease stays held until the scheduler's threads have finished.

On Unix the lock is a nonblocking exclusive `flock`; on Windows it is an exclusive file open. The operating system releases it when the owning process ends. The lock file stays in place and is never truncated or deleted, so its presence does not mean the directory is locked. **Do not delete or replace the lock file to get around an active owner**: that creates a second lock object and defeats the ownership check.

The lock coordinates schedulers on one host that use this version. Use it under these conditions:

- Keep the directory local, trusted and dedicated, with an owner and parent directories that untrusted users and tested code cannot change.
- The lock does not coordinate across hosts or network filesystems (NFS, SMB), and a privileged administrator can override it.
- Older versions do not take the lock; stop an older instance before you start this one.
- The release of a crashed owner's lock says nothing about its child processes; [Restart after a crash](#restart-after-a-crash) describes how the next scheduler handles them.

The lock file and an existing snapshot must be regular files. Unix opens refuse a symlink at the final path component and are nonblocking, so a FIFO is rejected instead of waiting for a writer. Windows opens a reparse point itself and rejects it. A missing history is an empty scheduler; a malformed history, a directory, or another file type is an error. File and directory permissions are for you to administer.

## Fail-closed persistence

State changes are serialized under the scheduler mutex and saved through a temporary file, a file sync, an atomic replacement, and (on Unix) a directory sync. The `FuzzJob` JSONL format is unchanged.

| Failed phase | Behavior |
| --- | --- |
| Admission, before the snapshot is replaced | Reject the submission, remove its tentative record, keep the next ID, latch the storage fault, and stop further admission. |
| Admission, after replacement but before the directory sync succeeds | Return `DurabilityUncertain`, reserve the ID and accounting for the installed record, stop admission, and do not dispatch the unacknowledged job. |
| Transition to Running | Save before dequeue and dispatch; on failure, keep the job queued in memory and stop the scheduler. |
| Completion or interruption | Keep the observed runtime state visible, latch the failed save, stop new work, and send no completion notification for that transition. |

The first storage error is kept until restart. Once it is latched, workers make no more snapshot writes that could hide the uncertain state. Running children go through the normal shutdown and cleanup path. A shutdown request does not cancel a notification already being sent for an earlier, successfully committed transition.

An in-memory `Complete` row next to a storage fault is an observation, not a durable completion. On Unix a successful save also syncs the parent directory; on Windows the directory is not synced, so a save there carries the filesystem's own power-loss behavior.

## Restart after a crash

While a job runs, its worker records the process ID in `<jobs-dir>/running/<job-id>.pid`. On start, the scheduler marks every persisted `Running` record `Failed` with a reason, because a clean shutdown would have queued it again. On Linux, when the recorded process is still that job's `bhf fuzz` (checked by its command line), the scheduler kills its process group and says so in the reason. On other platforms the process cannot be told apart from one that reused its ID, so it is left alone and the reason says the process is gone. A job whose completion save failed before a crash is therefore reported `Failed`, even if its run finished.

## Health and shutdown APIs

`Scheduler::health()` returns a serializable `SchedulerHealth` snapshot with `schema_version: 1`. It holds the admission and shutdown state, a count for every job state, the queue, history and snapshot limits, the reserved snapshot bytes, and the first `StorageFault`, if any. A fault records the phase, the scheduler-assigned job ID, whether the snapshot was replaced, the I/O error kind, and the OS error code when there is one. It leaves out project paths, harness names, raw error text, and webhook URLs.

An application that embeds a scheduler can expose health behind its own access control:

```rust
use continuous_daemon::Scheduler;

pub fn health_json(scheduler: &Scheduler) -> Result<String, serde_json::Error> {
    serde_json::to_string(&scheduler.health())
}

pub fn begin_shutdown(scheduler: &Scheduler) {
    scheduler.request_shutdown();
}
```

`accepting_submissions` reflects the shutdown flag and the coarse remaining capacity at that moment; it does not reserve room for the next submission, which still depends on its size and budget, free storage, and concurrent submissions. Read `storage_fault` to tell a persistence shutdown from an ordinary shutdown or full retention capacity.

`request_shutdown()` is idempotent and returns without joining the worker threads. It stops admission and signals the workers; waiting and interrupted jobs are kept for restart, not cancelled. Dropping the scheduler waits for its threads until a deadline: the shutdown timeout (2 seconds by default) within which workers kill and reap their jobs, plus a fixed slack. A thread still running after that (posting a webhook, for example) is joined in the background, and that background thread holds the storage lease until it ends. Both calls take the state mutex, so they can wait behind filesystem I/O. A webhook delivery, DNS resolution included, has its own 10-second deadline and a 64 KiB response cap.

## Recovery procedure

1. Keep the reported fault and the `jobs.jsonl` file.
2. Stop the owning service and any children still running.
3. Fix the storage problem: capacity, permissions, filesystem health, or an unexpected file type.
4. Leave the lock file in place and restart normally. Do not force a lock takeover.
5. Investigate a corrupt snapshot or restore it from a backup; startup does not discard it.
6. Review jobs reported `Failed` after the restart; some may have finished before the fault.

Configure an external supervisor so that it does not restart in a loop on a persistent storage fault without telling an operator.

Completed records are kept within the existing limits. History is not pruned automatically, webhooks have no durable outbox, and job submission is not idempotent.

## Regression coverage

The tests cover a second owner rejected in the same process and in another process, recovery of ownership after the owner process is killed, regular-file checks, preservation of a corrupt history, explicit shutdown, health serialization, and injected failures before and after snapshot replacement. A Unix worker test makes completion persistence fail and checks that the next queued job is not dispatched.

```sh
# Linux
cargo test --locked -p continuous_daemon --lib
# Windows (the rest of the suite uses Unix executable fixtures)
cargo test --locked -p continuous_daemon --lib health::tests
```

The CI workflow runs both commands, and the Linux workspace suite includes them. [validation/scheduler-reliability-2026-09-25.json](validation/scheduler-reliability-2026-09-25.json) records the validation runs, source blob hashes, and artifact digests.
