<!-- SPDX-License-Identifier: Apache-2.0 -->
# Daemon and editor hardening (2026-09-24)

This page records the defects found in `crates/daemon`,
`crates/continuous_daemon`, `editors/` and `crates/cli/src/capsule.rs` at
commit `5528a41`, and what bhf does now. [Daemon JSON-RPC](daemon-json-rpc.md),
[VS Code Thin Client](vscode-thin-client.md) and [GNAT Studio
Plugin](gnatstudio-plugin.md) describe the current behavior.

## Defects and fixes

| # | Priority | Defect at `5528a41` | Current behavior |
|---|---|---|---|
| 1 | P1 | VS Code Replay sent a finding's stored `replay.command` to the terminal, so shell operators in on-disk finding JSON ran when the user clicked Replay. | Replay and minimize build the command from the configured CLI and the finding path, and ignore stored command text. |
| 2 | P1 | The scheduler restored `jobs.jsonl` on start but restarted job IDs at `J-000000`, so a new job could reuse an old ID and be stranded in `Queued` or misreported. | The next ID is derived from the restored records. |
| 3 | P1 | Job persistence wrote snapshots outside the state lock and ignored write errors, so concurrent writers could replace a newer snapshot with an older one. | `jobs.jsonl` is written to a temporary file, synced, and renamed into place (the directory is synced on Unix); a failed write is reported to the submitter. |
| 4 | P2 | An authenticated `staticScan` with no `out` wrote to `bhf_work/static` relative to the daemon's working directory, which could be outside the tenant's workspace. | For a tenant, the default `out` is `<workspace root>/bhf_work/static`, and every output path is authorized against the workspace. |
| 5 | P2 | The VS Code frame decoder and the GNAT Studio client read frames with no size bound; malformed frames threw from a stream event. | Both clients cap a header at 8192 bytes and a frame at 64 MiB, and treat protocol failures as request errors. |
| 6 | P1 | `build_capsule` joined an unvalidated finding ID to the output directory and called `remove_dir_all` on the result; the harness ID was also unvalidated. | Finding and harness IDs are validated before any filesystem access. |
| 7 | P1 | `verify-poc` removed a predictable `/tmp/bhf-verify-poc-<pid>` before use. | It uses a fresh `tempfile` directory owned by the current invocation. |
| 8 | P2 | `bhf capsule` printed build errors only in verbose mode, ignored `tar` failures, and always exited zero. | Each skipped or failed finding is printed with its reason, a failed `tar` run is an error, and the exit code reflects the failures. |
| 9 | P1 | VS Code sent a POSIX-quoted command string to the user's integrated shell; `cmd.exe` does not treat single quotes as delimiters. | Replay and minimize run as VS Code process tasks with a separate executable and argument vector; task terminals show the output and exit status. |

## Related changes since

- The daemon bounds a `findings` response: the number of findings and the raw
  and normalized bytes it loads scale with the daemon's memory budget.
- On Linux, a tenant's paths are pinned for the call with `openat2`
  (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`); see
  [Daemon: Security Modes](site/daemon.md#security-modes).
- The GNAT Studio plugin's `daemon-timeout-seconds` preference (default 30)
  bounds a findings refresh and terminates the daemon process when it passes.
- Scheduler shutdown signals the workers and waits for them until a deadline
  (the shutdown timeout within which workers kill and reap their jobs, plus a
  fixed slack). A thread still running after that is joined in the
  background, and that thread holds the data directory's lock until it ends.

## Open item

VS Code process tasks have unit tests for the argument vector and API shape;
they have not been run in a Windows extension host.

## Tests

```sh
npm test --prefix editors/vscode
python3 -m unittest discover -s editors/gnatstudio/tests
cargo test -p continuous_daemon -p bhf-daemon --lib --offline
cargo test -p bhf --lib capsule::tests --offline
```

The VS Code tests check that metacharacters stay literal arguments and that
stored replay text is ignored.
