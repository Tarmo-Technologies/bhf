<!-- SPDX-License-Identifier: Apache-2.0 -->

# VS Code Thin Client

The BHF VS Code extension lives in `editors/vscode`. It starts `bhf-daemon`
over stdio, loads findings through the daemon's `findings` JSON-RPC method
(see [Daemon JSON-RPC](daemon-json-rpc.md)), and shows each finding as a
diagnostic with CodeLens actions.

## Development

Install and test the extension package:

```sh
npm ci --prefix editors/vscode
npm test --prefix editors/vscode
```

The extension contributes Ada file associations for `.adb`, `.ads`, and `.ada`
files. It activates after VS Code starts and loads findings when the
configured findings directory exists.

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `bhf.daemonPath` | `bhf-daemon` | Daemon executable. |
| `bhf.cliPath` | `bhf` | BHF CLI executable for the replay and minimize tasks. |
| `bhf.findingsDir` | `findings` | Findings directory loaded through the daemon, relative to the workspace root unless absolute. `bhf auto` writes findings to `<work-dir>/results/findings`, so set this to that path (for example `bhf_work/results/findings`). |
| `bhf.harnessPath` | empty | Harness path passed as `--harness` to replay and minimize. |
| `bhf.minimizeStrategy` | `bytes` | `bytes` or `typed`, passed as `--strategy` to minimize. |

## Actions

A finding gets a diagnostic and CodeLens actions at its location: the
`actionability.fix_location` when the finding has one, otherwise the Ada
exception's handler, last breadcrumb or explicit raise site. The actions are:

- `Replay this finding` runs `bhf replay --finding <findings-dir>/<id>`.
- `Minimize` runs `bhf minimize --finding <findings-dir>/<id> --strategy
  <strategy>`.
- `Open repro.adb` opens the finding's `generated_repro_ada` file, resolved
  under the findings directory unless the finding stores an absolute path.
  It appears only when the finding has that field.

Replay and minimize run as process tasks in a `BHF` task terminal that shows
their exit status. The extension builds each command line from these settings
and the finding's ID; it ignores any command text stored in the finding JSON.
