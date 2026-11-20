<!-- SPDX-License-Identifier: Apache-2.0 -->

# IDE Parity

The VS Code extension (`editors/vscode/`) and the GNAT Studio plugin
(`editors/gnatstudio/`) offer the same finding workflows. Both use
`bhf-daemon` (see [Daemon](site/daemon.md)) and the `bhf` CLI.

| Workflow | VS Code | GNAT Studio | Notes |
| --- | --- | --- | --- |
| Daemon path | `bhf.daemonPath` | `BHF/daemon-path` | Default `bhf-daemon` |
| CLI path | `bhf.cliPath` | `BHF/cli-path` | Default `bhf` |
| Findings directory | `bhf.findingsDir` | `BHF/findings-dir` | Default `results/findings`, where `bhf auto` writes findings in its work directory; a relative path resolves from the workspace or project root |
| Harness override | `bhf.harnessPath` | `BHF/harness-path` | Optional. Both editors build the replay arguments from the configured CLI and the finding ID, and ignore any command text stored in a finding |
| Minimize strategy | `bhf.minimizeStrategy` | `BHF/minimize-strategy` | `bytes` (default) or `typed` |
| Request deadline | none | `BHF/daemon-timeout-seconds` | GNAT Studio default 30 seconds; see [Daemon reliability](enterprise-daemon-reliability.md) |
| Refresh findings | Command palette action | `/Tools/BHF/Refresh Findings` | Both call the daemon's `findings` method |
| Finding location | Diagnostics | Locations window messages | Both use the handler, then the last breadcrumb, then the explicit raise |
| Replay a finding | CodeLens and command | Message action and menu action | VS Code runs a process task, GNAT Studio `GPS.Process`; both pass the arguments to `bhf replay` |
| Minimize a finding | CodeLens and command | Menu action | In GNAT Studio, replay is the one inline message action and minimize is in the finding's menu |
| Open `repro.adb` | CodeLens and command | Menu action | Shown only when the finding has `generated_repro_ada` |
| Daemon lifecycle | One long-lived stdio client, restarted when the configuration changes | One daemon subprocess per refresh | GNAT Studio keeps no background process between refreshes |
| Grouping | Per-file diagnostics and CodeLens | Per-message Locations entries and per-finding menus | Each follows its IDE's own UI model |

The differences in the table are in presentation and process lifecycle; both
editors cover the same finding workflows.
