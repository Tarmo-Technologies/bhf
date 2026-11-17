<!-- SPDX-License-Identifier: Apache-2.0 -->

# Daemon

`bhf-daemon` is the JSON-RPC daemon used by IDE clients. It speaks
JSON-RPC 2.0 over LSP-style stdio framing:

```text
Content-Length: <bytes>\r\n
\r\n
<json body>
```

The same binary also supports standards-based Model Context Protocol stdio with
`bhf-daemon --mcp`. MCP messages are newline-delimited JSON-RPC rather than
LSP-framed. This mode lets a Codex or Claude host session use deterministic
BHF tools without giving BHF an API token; see
[LLM Assistance](../llm/).

The MCP mode of a default build, the release binaries included, exposes three
read-only tools: `bhf_scan` (Ada structure scan), `bhf_list_targets` (ranked
Ada/C/C++ targets) and `bhf_load_findings` (bounded normalized-finding
loading). A build with `--features llm` adds two: `bhf_prepare_assistance`
(task-prompt preparation) and `bhf_preflight_harness` (an Ada/C/C++
structural harness preflight). It does not expose build, fuzz, replay,
minimization, file editing, or shell execution. Every tool advertises
read-only, non-destructive, idempotent, closed-world annotations. Target and
finding defaults derive from the current MCP message budget; explicit positive
`top` values override those breadth defaults, and responses report totals and
truncation.

## Methods

- `scan` summarizes Ada files under a path.
- `listTargets` returns ranked fuzz targets (Ada, C, C++).
- `findings` loads normalized finding directories.
- `rankAt` returns the ranked target containing a source location (Ada-only).
- `instrumentPreview` returns rewritten source and probe breadcrumbs without
  writing files (Ada-only).
- `staticScan` runs the same full offline static engine as the CLI (the eight
  core static languages plus JavaScript/TypeScript and supported QML/config/IaC
  inputs), writes JSON, Markdown, and optional SARIF artifacts, and returns the
  full static report plus a CI-style `exit_code`.
- `submitJob`, `listJobs` and `cancelJob` drive the continuous fuzzing
  scheduler, when the daemon runs one (`--jobs-dir`; see
  [Continuous Daemon](#continuous-daemon)).

`rankAt` and `instrumentPreview` are Ada-only today. The flagship CLI `auto`
command fuzzes all
sixteen current lanes; narrower manual commands state their exact language
scope in `bhf <command> --help`. Long-running or mutating operations remain
explicit CLI actions rather than daemon/MCP calls.

## IDE Clients

The VS Code extension and GNAT Studio plugin both use the daemon instead of
reimplementing analysis. They present findings at source locations and shell
out to the `bhf` CLI for replay, minimization, and reproducer workflows.

## Security Modes

The default editor path is local single-user mode and requires no token. Shared
or hosted deployments must opt into workspace-scoped security with
`bhf-daemon --security-config FILE`:

- `workspace_shared`: one token for one workspace.
- `multi_tenant`: one token, workspace root, and role per tenant.

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

`--security-config` applies to JSON-RPC; `--mcp` has no authentication and
serves one local user, so the two together are refused.

Secure JSON-RPC requests use a top-level `auth` object with `tenant` and
`token`. Authorized secure responses include `bhfAudit`; denied requests use
BHF server error codes `-32001`, `-32002`, or `-32003`.

A tenant's role decides what it may call. Every path a request names must
also be inside the tenant's workspace root.

| Role | May call |
|---|---|
| `viewer` | `scan`, `listTargets`, `findings`, `rankAt`, `listJobs` |
| `operator` | the viewer's methods, `instrumentPreview`, `submitJob`, `cancelJob`, and `staticScan` without the overrides below |
| `workspace_admin` | the operator's methods, and `staticScan` with its own `policy`, `suppressions`, `baseline`, `enabled_rules` or `disabled_rules`: these decide which findings count or are hidden, and which rules run |

A call the role may not make is `-32002`, naming the role.

On Linux a tenant's paths are pinned for the call: the daemon opens each one
beneath a handle on the workspace root without following a symlink
(`openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`) and works through
that handle. A component swapped for a symlink after the check cannot
redirect the call, and one swapped before the pin is refused with `-32003`.
Responses and the static scan's reports name the resolved paths. Elsewhere,
and on kernels before 5.6, the daemon checks the resolved path and then uses
the one the request named.

## Continuous Daemon

`bhf-daemon --jobs-dir DIR` runs the continuous fuzzing scheduler for
on-prem continuous fuzzing. It queues fuzz jobs and dispatches them to a
worker pool (`--job-workers N`, default 1) that spawns `bhf fuzz` per job:
the `bhf` beside `bhf-daemon`, else the one on `PATH`, or `--bhf PATH`. Jobs
are persisted to `DIR/jobs.jsonl`, so a daemon restart recovers the known job
set. Jobs that were running when the daemon stopped are queued again, since
in-flight work is assumed lost. A job a daemon that crashed left `running`
is `failed` on the next start, with a `reason` saying so. If its `bhf fuzz`
still runs (it records its process id under `DIR/running/`), that process
is stopped.

The JSON-RPC methods:
- `submitJob` takes `project_dir`, `harness_id` and `time_budget_secs`
  (`0` runs until cancelled). It queues a job and returns its `job_id`.
- `listJobs` takes an optional `offset` and `limit` (default 100). It returns
  `total` and a page of `jobs`, each with its state: `queued`, `running`,
  `complete`, `failed` or `cancelled`.
- `cancelJob` takes a `job_id`. A queued job is `cancelled` at once and never
  starts. A running one is stopped: the reply's state is `running` while its
  worker kills the job's process tree and records `cancelled`. A finished
  job's state is returned as it is.

Under `--security-config` a tenant submits jobs for projects inside its
workspace root. Each job records the tenant that submitted it and that
tenant's workspace root (`tenant`, `workspace`). That tenant and the other
tenants of the same workspace root, such as its viewer, see the job and,
with the operator role, cancel it. To any other tenant, a nested workspace
root included, it is "no job". Without `--jobs-dir` the job methods say how to start the
scheduler. The library API is `continuous_daemon::Scheduler` (`submit`,
`list_jobs`, `cancel`). When the library's `webhook_url` is configured, the
scheduler POSTs a notification to it once a job reaches a terminal state
(`complete`, `failed` or `cancelled`). That is HTTP only in v0.1: front an
`https://` endpoint with a TLS-terminating proxy. The post, resolving its host
included, has a 10 s deadline. `bhf-daemon` sets no webhook.

Stopping the scheduler is bounded too. Each worker kills and reaps its job
within the shutdown timeout (2 s), and the job is queued again. The scheduler
waits for its workers that long plus 1 s, then 1 s more for the results
refresh. A thread still running after that, such as a webhook post or a long
results rebuild, finishes in the background. Until it has, the data
directory stays locked, so no other scheduler starts on it.

### Results refresh

Fuzz jobs run with `BHF_RESULTS_DEFER=1`, so they never rebuild `results/`
themselves. A dedicated refresh thread records each finished job as one
`daemon fuzz` producer entry and rebuilds `<project>/results/` instead:
within 60s once that project goes idle (nothing running or queued for it), or
every 300s while it stays continuously busy. Whatever is still outstanding at
shutdown is recorded and rebuilt then. Because the webhook fires as soon as a
job reaches a terminal state, it can fire *before* `<project>/results/`
reflects that job — poll `results/manifest.json`'s producer history, or wait
for the next debounced rebuild, if you need the index itself to be current.
