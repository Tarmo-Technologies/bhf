<!-- SPDX-License-Identifier: Apache-2.0 -->
# PR-01: daemon and editor production-readiness handoff

Baseline: `5528a41`, reviewed 2026-09-24. Scope: `crates/daemon`,
`crates/continuous_daemon`, `editors`, and the separately assigned
`crates/cli/src/capsule.rs`. Findings below are based on source
inspection; validation results are recorded at the end.

## Confirmed defects and acceptance checks

1. **P1, VS Code finding command injection.** `editors/vscode/src/commands.ts`
   returns `finding.replay.command` verbatim when no harness override is set;
   `extension.ts` passes it to `Terminal.sendText(..., true)`. Findings are loaded
   from on-disk JSON through the daemon. A finding containing shell operators
   therefore executes those operators when the user invokes Replay. Build replay
   from the configured CLI and a finding path, and pass both through an
   argument-based process execution. Check that stored command text is ignored
   and that path metacharacters remain literal arguments.
2. **P1, scheduler reuses job IDs after restart.** `Scheduler::start` restores
   `jobs.jsonl` into `seen` but leaves `next_id = 0`; `submit` then issues
   `J-000000` again. Worker state transitions update the first matching ID,
   which can strand the new job in Queued or misreport the old job. Derive the
   next ID from restored records, and test submission after restart.
3. **P1, scheduler persistence can lose acknowledged jobs.** `submit` drops the
   state mutex before `persist`, and `persist_locked` also builds a snapshot
   under that mutex then writes after releasing it. Multiple writers can
   overwrite a newer snapshot with an older one; all write errors are ignored.
   Serialize persistence with state updates, use an atomic replacement, and
   surface submission persistence errors. Test restart visibility and failure.
4. **P2, authenticated static scan can write outside workspace.** In
   `crates/daemon/src/lib.rs`, `staticScan` validates an explicit `out` path
   but `static_scan` defaults absent `out` to relative `bhf_work/static`, resolved
   from the daemon process cwd. A tenant whose workspace differs from cwd can
   trigger an out-of-workspace write. Resolve the default within the authorized
   workspace or validate its actual resolved destination; add a tenant test.
5. **P2, editor protocol/lifecycle hardening.** The VS Code `FrameDecoder`
   accumulates stdout without a size bound and throws on malformed frames from
   a stream event; the GNAT Studio client reads frames without a size bound and
   pipes stderr without draining it. Confirm practical limits and handle protocol
   failures as request errors, with regression checks.
6. **P1, capsule path deletion from finding metadata.** `build_capsule` joins
   an unvalidated on-disk finding ID to the output directory and calls
   `remove_dir_all` on that result. Its unvalidated harness ID also feeds
   `harness_dir`. Reject IDs containing path separators, special components,
   or platform drive syntax before any filesystem access. A hostile ID test
   must preserve a sentinel outside the capsule output.
7. **P1, predictable verifier scratch deletion.** `ScratchDir::new` first
   removes `/tmp/bhf-verify-poc-<pid>`. Use a unique `tempfile::TempDir` whose
   ownership is tied to the current invocation; no preexisting directory may
   be removed.
8. **P2, capsule packaging failure appears successful.** `run` prints skipped
   build errors only in verbose mode and always exits zero; `make_tarball`
   ignores process launch and nonzero statuses. Report failures and return
   nonzero when requested packaging fails, including tar creation.
9. **P1, VS Code terminal command quoting depends on the user's shell.** After
   removing the stored replay command, `commands.ts` still builds a POSIX-quoted
   command string, and `extension.ts` sends it to the current integrated shell.
   `cmd.exe` does not treat single quotes as argument delimiters, so a finding
   ID or configured path with shell operators can be interpreted as commands.
   Replay/minimize now use a VS Code process task with a separate executable
   and argument vector. Task terminals show output and process exit status;
   tests confirm metacharacters remain literal arguments and stored replay
   text is ignored.

## Residual review areas

- The scheduler's `Drop` joins workers after signaling shutdown; a running
  `bhf fuzz` process may block shutdown until it exits. Its configured time
  budget is passed to the CLI only; verify CLI enforcement before promising a
  bounded shutdown.
- Tenant path authorization uses canonicalization followed by later file access,
  leaving a filesystem race if other principals can mutate workspace links.
  Containing this requires path handling shared with the called scan engines.
- The daemon returns response bodies without a corresponding output-size limit;
  a very large findings directory may exhaust memory or break editor clients.
- Native VS Code task execution on Windows still needs a Windows extension-host
  smoke check; unit tests verify the argument vector and TypeScript API shape,
  but this Linux review host cannot exercise the Windows task runner.
- GNAT Studio's synchronous `read_frame` has no deadline if the daemon stops
  responding without exiting; the new size limits do not solve that stall.

## Validation

- VS Code: `npm test --prefix editors/vscode` — 18/18 passed after the process
  task change, including literal metacharacter arguments.
- GNAT Studio: `python3 -m unittest discover -s editors/gnatstudio/tests`
  — 14/14 passed.
- `cargo test -p continuous_daemon -p bhf-daemon --lib --offline` —
  16/16 scheduler tests and 20/20 daemon tests passed.
- `cargo test -p bhf --lib capsule::tests --offline` — 12/12 matching
  capsule/environment tests passed.
- `git diff --check` — passed. Rust formatting was applied only to the three
  edited Rust source files because other review packages own concurrent changes.
