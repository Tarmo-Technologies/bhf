// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  buildMinimizeProcess,
  buildReplayProcess,
  resolveReproducerPath,
  type CommandConfig,
} from "../commands";
import type { BhfFinding } from "../findings";

const config: CommandConfig = {
  cliPath: "bhf",
  findingsDir: "findings",
  harnessPath: "build/H 1/main",
  minimizeStrategy: "typed",
  workspaceRoot: "/work/project",
};

const finding: BhfFinding = {
  id: "F-0001-alpha",
  severity: "medium",
  generated_repro_ada: "F-0001-alpha/repro.adb",
  replay: {
    command: "bhf replay --finding F-0001-alpha",
  },
};

test("buildReplayProcess adds configured harness path as an argument", () => {
  assert.deepEqual(
    buildReplayProcess(finding, config),
    {
      executable: "bhf",
      args: ["replay", "--finding", "/work/project/findings/F-0001-alpha", "--harness", "build/H 1/main"],
    },
  );
});

test("buildReplayProcess uses configured findings directory with harness override", () => {
  assert.deepEqual(
    buildReplayProcess(finding, {
      ...config,
      findingsDir: "custom/findings",
      harnessPath: "build/H 1/main",
    }),
    {
      executable: "bhf",
      args: ["replay", "--finding", "/work/project/custom/findings/F-0001-alpha", "--harness", "build/H 1/main"],
    },
  );
});

test("buildReplayProcess ignores stored shell command when no harness is configured", () => {
  assert.deepEqual(
    buildReplayProcess({ ...finding, replay: { command: "bhf replay; touch /tmp/owned" } }, { ...config, harnessPath: "" }),
    {
      executable: "bhf",
      args: ["replay", "--finding", "/work/project/findings/F-0001-alpha"],
    },
  );
});

test("buildReplayProcess keeps metacharacters literal in executable and arguments", () => {
  assert.deepEqual(
    buildReplayProcess(
      { ...finding, id: "F-1 & echo owned" },
      { ...config, cliPath: "C:\\Program Files\\BHF\\bhf.exe", harnessPath: "build/H 1/main; echo owned" },
    ),
    {
      executable: "C:\\Program Files\\BHF\\bhf.exe",
      args: ["replay", "--finding", "/work/project/findings/F-1 & echo owned", "--harness", "build/H 1/main; echo owned"],
    },
  );
});

test("buildReplayProcess rejects finding IDs that escape the findings directory", () => {
  assert.throws(
    () => buildReplayProcess({ ...finding, id: "../../outside" }, config),
    /invalid ID/,
  );
  assert.throws(() => buildReplayProcess({ ...finding, id: "..\\outside" }, config), /invalid ID/);
});

test("buildMinimizeProcess includes strategy and harness as arguments", () => {
  assert.deepEqual(
    buildMinimizeProcess(finding, config),
    {
      executable: "bhf",
      args: ["minimize", "--finding", "/work/project/findings/F-0001-alpha", "--harness", "build/H 1/main", "--strategy", "typed"],
    },
  );
});

test("buildMinimizeProcess uses configured findings directory", () => {
  assert.deepEqual(
    buildMinimizeProcess(finding, {
      ...config,
      findingsDir: "/tmp/bhf-findings",
      harnessPath: "",
    }),
    {
      executable: "bhf",
      args: ["minimize", "--finding", "/tmp/bhf-findings/F-0001-alpha", "--strategy", "typed"],
    },
  );
});

test("resolveReproducerPath resolves generated repro paths under findings root", () => {
  assert.equal(
    resolveReproducerPath(finding, config),
    "/work/project/findings/F-0001-alpha/repro.adb",
  );
});

test("resolveReproducerPath preserves absolute repro paths", () => {
  assert.equal(
    resolveReproducerPath(
      { ...finding, generated_repro_ada: "/tmp/repro.adb" },
      config,
    ),
    "/tmp/repro.adb",
  );
});
