<!-- SPDX-License-Identifier: Apache-2.0 -->

# GNAT Studio Plugin

The BHF GNAT Studio plugin lives in `editors/gnatstudio`. It loads findings
from `bhf-daemon` (see [Daemon JSON-RPC](daemon-json-rpc.md)), shows them as
GNAT Studio messages in the Locations view and the source gutter, and adds
replay, minimize and reproducer actions.

The plugin uses these parts of AdaCore's GNAT Studio Python API:

- `GPS.Action` for menu and interactive actions.
- `GPS.Message` for editor and Locations diagnostics.
- `GPS.Process` for replay and minimize subprocesses.
- `GPS.Preference` for the plugin settings.

## Installation

Copy both files, side by side, into a GNAT Studio plug-in directory (for
example `~/.gnatstudio/plug-ins/`):

```text
editors/gnatstudio/bhf_gnatstudio.py
editors/gnatstudio/bhf_gnatstudio_core.py
```

Restart GNAT Studio and choose `/Tools/BHF/Refresh Findings`.

## Settings

The plugin creates these preferences on the `BHF` page:

| Preference | Default | Meaning |
|---|---|---|
| `daemon-path` | `bhf-daemon` | Daemon executable. |
| `daemon-timeout-seconds` | `30` | Deadline for a findings refresh; the plugin terminates its daemon process when it passes. |
| `cli-path` | `bhf` | BHF CLI executable. |
| `findings-dir` | `findings` | Findings directory loaded through the daemon. `bhf auto` writes findings to `<work-dir>/results/findings`, so set this to that path (for example `bhf_work/results/findings`). |
| `harness-path` | empty | Harness path for replay and minimize. |
| `minimize-strategy` | `bytes` | `bytes` or `typed`. |

Relative paths resolve against the loaded project's directory, or against the
current working directory when no project is loaded.

## Workflow

Refresh asks the daemon for findings with the `findings` JSON-RPC method. Each
finding becomes a `BHF` message at the first source location it has, in this
order:

1. the finding's `actionability.fix_location`
2. the exception handler
3. the last breadcrumb
4. the explicit raise

Click the message's action icon to replay the finding. The plugin also adds a
menu per finding under `/Tools/BHF/Findings/<id>/` with:

- Replay this finding
- Minimize
- Open repro.adb

Replay runs the configured CLI on the finding under the configured findings
directory. The plugin builds the command line from its settings and ignores
any command text stored in the finding JSON.

GNAT Studio allows one action icon per message, so replay is the inline action
and the other actions are in the menus. [IDE parity](ide-parity.md) compares
the VS Code and GNAT Studio workflows.
