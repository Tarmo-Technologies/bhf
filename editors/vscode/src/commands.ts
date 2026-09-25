// SPDX-License-Identifier: Apache-2.0

import path from "node:path";

import type { BhfFinding } from "./findings";

export interface CommandConfig {
  cliPath: string;
  findingsDir: string;
  harnessPath: string;
  minimizeStrategy: "bytes" | "typed";
  workspaceRoot: string;
}

export interface ProcessCommand {
  executable: string;
  args: string[];
}

export function buildReplayProcess(
  finding: BhfFinding,
  config: CommandConfig,
): ProcessCommand {
  const args = [
    "replay",
    "--finding",
    findingPath(finding, config),
  ];
  if (config.harnessPath.trim()) {
    args.push("--harness", config.harnessPath);
  }
  return { executable: config.cliPath, args };
}

export function buildMinimizeProcess(
  finding: BhfFinding,
  config: CommandConfig,
): ProcessCommand {
  const args = [
    "minimize",
    "--finding",
    findingPath(finding, config),
  ];
  if (config.harnessPath.trim()) {
    args.push("--harness", config.harnessPath);
  }
  args.push("--strategy", config.minimizeStrategy);
  return { executable: config.cliPath, args };
}

export function resolveReproducerPath(
  finding: BhfFinding,
  config: CommandConfig,
): string | undefined {
  const artifact = finding.generated_repro_ada;
  if (!artifact) {
    return undefined;
  }
  if (path.isAbsolute(artifact)) {
    return path.normalize(artifact);
  }

  const findingsRoot = path.isAbsolute(config.findingsDir)
    ? config.findingsDir
    : path.resolve(config.workspaceRoot, config.findingsDir);
  return path.normalize(path.resolve(findingsRoot, artifact));
}

function findingPath(finding: BhfFinding, config: CommandConfig): string {
  const findingsRoot = path.isAbsolute(config.findingsDir)
    ? config.findingsDir
    : path.resolve(config.workspaceRoot, config.findingsDir);
  if (
    !finding.id ||
    finding.id === "." ||
    finding.id === ".." ||
    finding.id.includes("\\") ||
    finding.id.includes(":") ||
    path.basename(finding.id) !== finding.id
  ) {
    throw new Error("BHF finding has an invalid ID");
  }
  return path.normalize(path.resolve(findingsRoot, finding.id));
}
