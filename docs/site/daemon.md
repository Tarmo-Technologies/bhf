<!-- SPDX-License-Identifier: Apache-2.0 -->

# Daemon

`bhf-daemon` is the JSON-RPC 2.0 server that IDE clients use. It speaks over
stdio with LSP-style framing:

```text
Content-Length: <bytes>\r\n
\r\n
<json body>
```

| Option | Effect |
|---|---|
| *(none)* | JSON-RPC over stdio for one local user, with no token. |
| `--security-config FILE` | JSON-RPC with workspace-scoped security (see [Security modes](#security-modes)). |
| `--jobs-dir DIR` | Also run the continuous fuzzing scheduler (see [Continuous daemon](#continuous-daemon)). |
| `--job-workers N` | Jobs the scheduler runs at once (default 1). |
| `--bhf PATH` | The `bhf` a job runs (default: the `bhf` beside `bhf-daemon`, else `bhf` on `PATH`). |
| `--mcp` | Model Context Protocol (MCP) over stdio instead of JSON-RPC. |

## MCP mode

`bhf-daemon --mcp` serves the Model Context Protocol over stdio. MCP messages
are newline-delimited JSON-RPC, not LSP-framed. An MCP host session (an
editor or agent client) calls bhf's deterministic tools without giving bhf an
API token; see [LLM Assistance](llm.md).

The MCP mode of a default build, the release binaries included, exposes three
read-only tools: `bhf_scan` (an Ada structure scan of a path),
`bhf_list_targets` (ranked Ada, C and C++ fuzz targets) and
`bhf_load_findings` (bounded normalized findings from a findings directory).
A build with `--features llm` adds `bhf_prepare_assistance` (task-prompt
preparation) and `bhf_preflight_harness` (an Ada, C and C++ structural
harness check). Build, fuzz, replay, minimization, file editing and shell
execution stay CLI actions. Every tool advertises read-only, non-destructive,
idempotent, closed-world annotations. The default result size of the target
and finding tools derives from the MCP message budget; a positive `top`
argument overrides it, and responses report totals and truncation.

MCP has no authentication and serves one local user, so `--mcp` is refused
together with `--security-config` or `--jobs-dir`.

## Methods

| Method | Result |
|---|---|
| `scan` | Summary of the Ada files under a path. |
| `listTargets` | Ranked fuzz targets (Ada, C, C++). |
| `findings` | Normalized finding directories loaded from a path. |
| `rankAt` | The ranked target containing a source location (Ada). |
| `instrumentPreview` | Rewritten source and probe breadcrumbs, without writing files (Ada). |
| `staticScan` | The CLI's offline static engine (the eight core static languages plus JavaScript/TypeScript and supported QML, config and IaC inputs). Writes JSON, Markdown and optional SARIF artifacts, and returns the static report plus a CI-style `exit_code`. |
| `submitJob`, `listJobs`, `cancelJob` | Drive the continuous fuzzing scheduler when the daemon runs one (`--jobs-dir`). |

The CLI `auto` command fuzzes all sixteen lanes; each narrower CLI command
states its language scope in `bhf <command> --help`. Long-running or mutating
operations are CLI actions, not daemon or MCP calls.

## IDE clients

The VS Code extension and the GNAT Studio plugin use the daemon for
analysis. They present findings at source locations and run the `bhf` CLI for
replay, minimization and reproducer workflows.

## Security modes

The default editor setup is local single-user mode and needs no token. A
shared or hosted deployment uses workspace-scoped security with
`bhf-daemon --security-config FILE`:

- `workspace_shared`: one token for one workspace.
- `multi_tenant`: one token, workspace root and role per tenant.

```json
{
  "mode": "multi_tenant",
  "tenants": [
    { "tenant": "alpha", "token_file": "alpha.token",
      "workspace_root": "/srv/alpha", "role": "operator" },
    { "tenant": "audit", "token_file": "audit.token",
      "workspace_root": "/srv/alpha", "role": "viewer" }
  ]
}
```

Each tenant's token is read from its `token_file`, never from the config.
Relative paths are relative to the config file. The daemon reads the config
before it serves anything, and exits `2` with the reason when it cannot use
it:

- an unknown field, or no tenant;
- more than one tenant under `workspace_shared`;
- a workspace root that is not a directory;
- two tenants sharing a name or a token;
- a token shorter than 16 characters;
- a token file its group or others can read or write (`chmod 600` it). On
  Windows the file's ACL is not checked: keep it readable by the service
  account only.

Secure JSON-RPC requests carry a top-level `auth` object with `tenant` and
`token`. Authorized secure responses include `bhfAudit`. Denied requests get
bhf server error codes `-32001`, `-32002` or `-32003`.

A tenant's role decides what it may call. Every path a request names must
also be inside the tenant's workspace root.

| Role | May call |
|---|---|
| `viewer` | `scan`, `listTargets`, `findings`, `rankAt`, `listJobs` |
| `operator` | the viewer's methods, `instrumentPreview`, `submitJob`, `cancelJob`, and `staticScan` without the overrides below |
| `workspace_admin` | the operator's methods, and `staticScan` with its own `policy`, `suppressions`, `baseline`, `enabled_rules` or `disabled_rules`: these decide which findings count or are hidden, and which rules run |

A call the role may not make gets `-32002`, naming the role.

On Linux a tenant's paths are pinned for the call: the daemon opens each one
beneath a handle on the workspace root without following a symlink
(`openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`) and works through
that handle. A component swapped for a symlink after the check cannot
redirect the call, and one swapped before the pin is refused with `-32003`.
Responses and the static scan's reports name the resolved paths. On other
platforms, and on Linux kernels before 5.6, the daemon checks the resolved
path and then uses the path the request named.

## Continuous daemon

`bhf-daemon --jobs-dir DIR` runs the continuous fuzzing scheduler for
on-premises continuous fuzzing. It queues fuzz jobs and dispatches them to a
worker pool (`--job-workers N`, default 1) that runs one `bhf fuzz` per job.
Jobs are kept in `DIR/jobs.jsonl`, so a restarted daemon recovers the known
job set:

- A job that was running when the daemon stopped is queued again.
- A job that a crashed daemon left `running` is `failed` on the next start,
  with a `reason` saying so. If its `bhf fuzz` still runs (each job records
  its process id under `DIR/running/`), that process is stopped.

The JSON-RPC methods:

- `submitJob` takes `project_dir`, `harness_id` and `time_budget_secs`
  (`0` runs until cancelled). It queues a job and returns its `job_id`.
- `listJobs` takes an optional `offset` and `limit` (default 100). It returns
  `total` and a page of `jobs`, each with its state: `queued`, `running`,
  `complete`, `failed` or `cancelled`.
- `cancelJob` takes a `job_id`. A queued job is `cancelled` at once and never
  starts. A running job is stopped: the reply's state is `running` while its
  worker kills the job's process tree and records `cancelled`. A finished
  job's state is returned as it is.

Without `--jobs-dir`, the job methods reply with how to start the scheduler.

Under `--security-config` a tenant submits jobs for projects inside its
workspace root. Each job records the tenant that submitted it and that
tenant's workspace root (`tenant`, `workspace`). That tenant and the other
tenants of the same workspace root, such as its viewer, see the job, and
those with the operator role can cancel it. To any other tenant, a nested
workspace root included, the job does not exist.

The library API is `continuous_daemon::Scheduler` (`submit`, `list_jobs`,
`cancel`). When the library's `webhook_url` is set, the scheduler POSTs a
notification to it once a job reaches a terminal state (`complete`, `failed`
or `cancelled`). The webhook supports `http://` URLs; put an `https://`
endpoint behind a TLS-terminating proxy. The post, host resolution included,
has a 10-second deadline. `bhf-daemon` sets no webhook.

Stopping the scheduler takes a bounded time. Each worker kills and reaps its
job within the shutdown timeout (2 s), and the job is queued again. The
scheduler waits that long for its workers plus 1 s, then 1 s more for the
results refresh. A thread still running after that, such as a webhook post
or a long results rebuild, finishes in the background. Until it has, the data
directory stays locked, so no other scheduler starts on it.

### Results refresh

Fuzz jobs run with `BHF_RESULTS_DEFER=1`, so they do not rebuild `results/`
themselves. A dedicated refresh thread records each finished job as one
`daemon fuzz` producer entry and rebuilds `<project>/results/`: within 60 s
once that project goes idle (nothing running or queued for it), or every
300 s while it stays busy. Whatever is still outstanding at shutdown is
recorded and rebuilt then. The webhook fires as soon as a job reaches a
terminal state, which can be before `<project>/results/` reflects that job.
If you need the index to be current, poll the producer history in
`results/manifest.json`, or wait for the next rebuild.
