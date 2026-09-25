// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import path from "node:path";

import * as vscode from "vscode";

import {
  buildMinimizeProcess,
  buildReplayProcess,
  resolveReproducerPath,
  type CommandConfig,
  type ProcessCommand,
} from "./commands";
import {
  codeLensDescriptors,
  diagnosticDescriptors,
  findingById,
  type DiagnosticSeverityName,
  type BhfFinding,
  type TextRange,
} from "./findings";
import { StdioJsonRpcClient } from "./jsonRpc";

interface FindingsResponse {
  findings?: BhfFinding[];
}

interface ExtensionConfig extends CommandConfig {
  daemonPath: string;
  resolvedFindingsDir: string;
}

let diagnostics: vscode.DiagnosticCollection | undefined;
let codeLensEmitter: vscode.EventEmitter<void> | undefined;
let client: StdioJsonRpcClient | undefined;
let clientKey: string | undefined;
let currentFindings: BhfFinding[] = [];

export function activate(context: vscode.ExtensionContext): void {
  diagnostics = vscode.languages.createDiagnosticCollection("bhf");
  codeLensEmitter = new vscode.EventEmitter<void>();

  context.subscriptions.push(
    diagnostics,
    codeLensEmitter,
    vscode.commands.registerCommand("bhf.refreshFindings", () =>
      refreshFindings(false),
    ),
    vscode.commands.registerCommand("bhf.replayFinding", (findingId: string) =>
      runProcessAction(findingId, "Replay", buildReplayProcess),
    ),
    vscode.commands.registerCommand("bhf.minimizeFinding", (findingId: string) =>
      runProcessAction(findingId, "Minimize", buildMinimizeProcess),
    ),
    vscode.commands.registerCommand("bhf.openReproducer", openReproducer),
    vscode.languages.registerCodeLensProvider(
      { scheme: "file" },
      {
        onDidChangeCodeLenses: codeLensEmitter.event,
        provideCodeLenses(document) {
          const root = workspaceRoot();
          if (!root) {
            return [];
          }
          return codeLensDescriptors(currentFindings, document.uri.fsPath, root).map(
            (descriptor) =>
              new vscode.CodeLens(toVsRange(descriptor.range), {
                title: descriptor.title,
                command: descriptor.command,
                arguments: [descriptor.findingId],
              }),
          );
        },
      },
    ),
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration("bhf")) {
        restartClient();
        void refreshFindings(true);
      }
    }),
  );

  void refreshFindings(true);
}

export function deactivate(): void {
  restartClient();
}

async function refreshFindings(skipMissingFindingsDir: boolean): Promise<void> {
  const config = readConfig(!skipMissingFindingsDir);
  if (!config) {
    return;
  }

  if (skipMissingFindingsDir && !fs.existsSync(config.resolvedFindingsDir)) {
    currentFindings = [];
    diagnostics?.clear();
    codeLensEmitter?.fire();
    return;
  }

  try {
    const response = await ensureClient(config).request<FindingsResponse>("findings", {
      findings: config.resolvedFindingsDir,
    });
    currentFindings = Array.isArray(response.findings) ? response.findings : [];
    applyDiagnostics(currentFindings, config.workspaceRoot);
    codeLensEmitter?.fire();
  } catch (error) {
    restartClient();
    vscode.window.showErrorMessage(`BHF refresh failed: ${errorMessage(error)}`);
  }
}

function applyDiagnostics(findings: BhfFinding[], workspaceRootPath: string): void {
  diagnostics?.clear();
  const byFile = new Map<string, vscode.Diagnostic[]>();

  for (const descriptor of diagnosticDescriptors(findings, workspaceRootPath)) {
    const diagnostic = new vscode.Diagnostic(
      toVsRange(descriptor.range),
      descriptor.message,
      toVsSeverity(descriptor.severity),
    );
    diagnostic.source = descriptor.source;
    diagnostic.code = descriptor.code;

    const fileDiagnostics = byFile.get(descriptor.file) ?? [];
    fileDiagnostics.push(diagnostic);
    byFile.set(descriptor.file, fileDiagnostics);
  }

  for (const [file, fileDiagnostics] of byFile) {
    diagnostics?.set(vscode.Uri.file(file), fileDiagnostics);
  }
}

async function runProcessAction(
  findingId: string,
  action: string,
  buildCommand: (finding: BhfFinding, config: CommandConfig) => ProcessCommand,
): Promise<void> {
  const config = readConfig(true);
  if (!config) {
    return;
  }
  const finding = findingById(currentFindings, findingId);
  if (!finding) {
    vscode.window.showWarningMessage(`BHF finding not loaded: ${findingId}`);
    return;
  }

  try {
    const command = buildCommand(finding, config);
    const execution = new vscode.ProcessExecution(command.executable, command.args, {
      cwd: config.workspaceRoot,
    });
    const task = new vscode.Task(
      { type: "bhf", action: action.toLowerCase(), findingId },
      vscode.TaskScope.Workspace,
      `BHF ${action} ${findingId}`,
      "BHF",
      execution,
    );
    task.presentationOptions = {
      reveal: vscode.TaskRevealKind.Always,
      panel: vscode.TaskPanelKind.New,
    };
    await vscode.tasks.executeTask(task);
  } catch (error) {
    vscode.window.showErrorMessage(`BHF action failed: ${errorMessage(error)}`);
  }
}

async function openReproducer(findingId: string): Promise<void> {
  const config = readConfig(true);
  if (!config) {
    return;
  }
  const finding = findingById(currentFindings, findingId);
  if (!finding) {
    vscode.window.showWarningMessage(`BHF finding not loaded: ${findingId}`);
    return;
  }

  const reproPath = resolveReproducerPath(finding, config);
  if (!reproPath) {
    vscode.window.showWarningMessage(`BHF finding has no repro.adb: ${findingId}`);
    return;
  }

  const document = await vscode.workspace.openTextDocument(vscode.Uri.file(reproPath));
  await vscode.window.showTextDocument(document);
}

function ensureClient(config: ExtensionConfig): StdioJsonRpcClient {
  const nextKey = `${config.daemonPath}\0${config.workspaceRoot}`;
  if (!client || clientKey !== nextKey) {
    restartClient();
    client = new StdioJsonRpcClient(config.daemonPath, [], config.workspaceRoot);
    clientKey = nextKey;
  }
  return client;
}

function restartClient(): void {
  client?.dispose();
  client = undefined;
  clientKey = undefined;
}

function readConfig(notifyNoWorkspace: boolean): ExtensionConfig | undefined {
  const root = workspaceRoot();
  if (!root) {
    if (notifyNoWorkspace) {
      vscode.window.showInformationMessage("Open a workspace folder to use BHF.");
    }
    return undefined;
  }

  const config = vscode.workspace.getConfiguration("bhf");
  const findingsDir = config.get<string>("findingsDir", "findings");
  return {
    daemonPath: config.get<string>("daemonPath", "bhf-daemon"),
    cliPath: config.get<string>("cliPath", "bhf"),
    findingsDir,
    resolvedFindingsDir: path.isAbsolute(findingsDir)
      ? findingsDir
      : path.resolve(root, findingsDir),
    harnessPath: config.get<string>("harnessPath", ""),
    minimizeStrategy: config.get<"bytes" | "typed">("minimizeStrategy", "bytes"),
    workspaceRoot: root,
  };
}

function workspaceRoot(): string | undefined {
  return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
}

function toVsRange(range: TextRange): vscode.Range {
  return new vscode.Range(
    range.start.line,
    range.start.character,
    range.end.line,
    range.end.character,
  );
}

function toVsSeverity(severity: DiagnosticSeverityName): vscode.DiagnosticSeverity {
  switch (severity) {
    case "error":
      return vscode.DiagnosticSeverity.Error;
    case "information":
      return vscode.DiagnosticSeverity.Information;
    case "hint":
      return vscode.DiagnosticSeverity.Hint;
    case "warning":
    default:
      return vscode.DiagnosticSeverity.Warning;
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
