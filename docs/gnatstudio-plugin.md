<!-- SPDX-License-Identifier: Apache-2.0 -->

# GNAT Studio Plugin

The BHF GNAT Studio plugin lives in `editors/gnatstudio`. It loads findings
from the M18 daemon, shows them as GNAT Studio messages in the Locations view
and source gutter, and adds replay/minimize/reproducer actions.

The plugin follows the GNAT Studio Python API documented by AdaCore:

- `GPS.Action` for menu and interactive actions.
- `GPS.Message` for editor and Locations diagnostics.
- `GPS.Process` for replay/minimize subprocesses.
- `GPS.Preference` for visible plugin settings.

## Installation

Copy these files into a GNAT Studio plugin directory, preserving them side by
side:

```text
editors/gnatstudio/bhf_gnatstudio.py
editors/gnatstudio/bhf_gnatstudio_core.py
```

Then restart GNAT Studio and use `/Tools/BHF/Refresh Findings`.

## Settings

The plugin creates preferences under the `BHF` page:

- `daemon-path`: daemon executable path. Defaults to `bhf-daemon`.
- `daemon-timeout-seconds`: finite deadline for a findings refresh. Defaults
  to `30`; the plugin terminates its daemon process on timeout.
- `cli-path`: BHF CLI executable path. Defaults to `bhf`.
- `findings-dir`: findings directory loaded through the daemon. Defaults to
  `findings`.
- `harness-path`: optional harness path for replay/minimize.
- `minimize-strategy`: `bytes` or `typed`.

Relative paths resolve against the loaded project directory when GNAT Studio has
one, otherwise the current working directory.

## Workflow

Refresh asks the daemon for normalized findings with the `findings` JSON-RPC
method. Each finding becomes a `BHF` message at the first available source
location:

1. exception handler
2. last breadcrumb
3. explicit raise

Click the message action icon to replay the finding. The plugin also creates
per-finding menus under `/Tools/BHF/Findings/<id>/` for:

- Replay this finding
- Minimize
- Open repro.adb

Replay invokes the configured CLI with the finding under the configured
findings directory. Command text stored in finding JSON is not executed.

GNAT Studio supports one action icon per message, so replay gets the inline
message action and the rest are exposed through menus for this phase. The VS
Code and GNAT Studio workflow matrix is maintained in
[`ide-parity.md`](ide-parity.md).
