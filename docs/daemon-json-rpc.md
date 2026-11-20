<!-- SPDX-License-Identifier: Apache-2.0 -->

# Daemon JSON-RPC

`bhf-daemon` (crate `crates/daemon`) serves JSON-RPC 2.0 over stdio with
LSP-style framing. Each message is encoded as:

```text
Content-Length: <bytes>\r\n
\r\n
<json body>
```

[Daemon](site/daemon.md) is the user guide: starting the daemon, the
security configuration file, tenant roles, and the continuous fuzzing
scheduler. This page is the method reference.

## Methods

| Method | Parameters | Result |
|---|---|---|
| `scan` | `path` | Summary of the Ada files under `path`. |
| `listTargets` | `path`, optional `top` | Ranked fuzz targets in the Ada, C and C++ files under `path`. |
| `findings` | optional `findings` (default `bhf_work/results/findings`) | The findings in that directory. |
| `rankAt` | `path`, `line`, optional `column` | The ranked Ada target that contains that position in `path`. |
| `instrumentPreview` | `path` | The instrumented Ada source and breadcrumbs for `path`; writes no files. |
| `staticScan` | `path`, optional `out`, `suppressions`, `baseline`, `policy`, `enabled_rules`, `disabled_rules`, `sarif`, `fail_on` | Runs the `bhf static-scan` engine on `path`, writes its reports under `out` (default `bhf_work/static`), and returns `summary`, `report` and `exit_code`. The optional parameters match the CLI flags. |
| `submitJob` | `project_dir`, `harness_id`, `time_budget_secs` (`0` runs until cancelled) | Queues a fuzzing job; returns `job_id` and `state`. |
| `listJobs` | optional `offset`, `limit` (default 100, at most 1000) | `total` and one page of `jobs`. |
| `cancelJob` | `job_id` | `job_id` and its new `state`. |

`rankAt` and `instrumentPreview` read Ada only. The job methods need a
daemon started with `bhf-daemon --jobs-dir DIR`; without one they return
`-32000`. Harness generation, build, and single fuzz runs are CLI commands.

Example request body:

```json
{"jsonrpc":"2.0","id":1,"method":"listTargets","params":{"path":"src","top":10}}
```

Static scan request body:

```json
{
  "jsonrpc": "2.0",
  "id": "static",
  "method": "staticScan",
  "params": {
    "path": "src",
    "out": "bhf_work/static",
    "sarif": true,
    "fail_on": "high"
  }
}
```

## Errors

Responses use standard JSON-RPC success and error objects.

| Code | Meaning |
|---|---|
| `-32600` | Invalid request. |
| `-32601` | Unknown method. |
| `-32602` | Invalid parameters. |
| `-32000` | Server error, such as a job method on a daemon without a scheduler. |
| `-32001` | Authentication missing or invalid. |
| `-32002` | The tenant's role may not call this method. |
| `-32003` | A path outside the tenant's workspace root. |

## Security modes

| Mode | How it starts | Auth |
|---|---|---|
| `local_single_user` | `bhf-daemon` (the default, for one local IDE user) | None. |
| `workspace_shared` | `bhf-daemon --security-config FILE` with `"mode": "workspace_shared"` | One token scoped to one workspace root. |
| `multi_tenant` | `bhf-daemon --security-config FILE` with `"mode": "multi_tenant"` | One token, workspace root, and role (`viewer`, `operator`, `workspace_admin`) per tenant. |

A secure request carries a top-level `auth` object:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "rankAt",
  "auth": { "tenant": "alpha", "token": "token-alpha" },
  "params": { "path": "src/pkg.adb", "line": 12 }
}
```

An authorized response carries a top-level `bhfAudit` object with the tenant,
role, method, and workspace root. [Daemon: Security
Modes](site/daemon.md#security-modes) lists the config file format and which
role may call which method.

## Model Context Protocol mode

`bhf-daemon --mcp` serves newline-delimited MCP over stdio instead of the
framed JSON-RPC above. A default build exposes three read-only tools: Ada
structure scan, Ada/C/C++ ranked targets, and bounded finding loading. A
build with `--features llm` adds assistance-prompt preparation and an
Ada/C/C++ structural harness preflight. The MCP tools do not build, fuzz,
replay, minimize, edit files, or run shell commands. MCP mode has no
authentication, so `--mcp` and `--security-config` cannot be combined.

The host model does the reasoning, so BHF receives no host API token. The
[LLM and MCP guide](site/llm.md) covers registration, schemas, provider
choices, memory limits, privacy boundaries, and verification workflows.
