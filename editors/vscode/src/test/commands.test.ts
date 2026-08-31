// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import {
  buildMinimizeCommand,
  buildReplayCommand,
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

test("buildReplayCommand adds configured harness path", () => {
  assert.equal(
    buildReplayCommand(finding, config),
    "bhf replay --finding /work/project/findings/F-0001-alpha --harness 'build/H 1/main'",
  );
});

test("buildReplayCommand uses configured findings directory with harness override", () => {
  assert.equal(
    buildReplayCommand(finding, {
      ...config,
      findingsDir: "custom/findings",
      harnessPath: "build/H 1/main",
    }),
    "bhf replay --finding /work/project/custom/findings/F-0001-alpha --harness 'build/H 1/main'",
  );
});

test("buildReplayCommand uses finding replay command when no harness overrides it", () => {
  assert.equal(
    buildReplayCommand(finding, { ...config, harnessPath: "" }),
    "bhf replay --finding F-0001-alpha",
  );
});

test("buildMinimizeCommand includes strategy and harness when configured", () => {
  assert.equal(
    buildMinimizeCommand(finding, config),
    "bhf minimize --finding /work/project/findings/F-0001-alpha --harness 'build/H 1/main' --strategy typed",
  );
});

test("buildMinimizeCommand uses configured findings directory", () => {
  assert.equal(
    buildMinimizeCommand(finding, {
      ...config,
      findingsDir: "/tmp/bhf-findings",
      harnessPath: "",
    }),
    "bhf minimize --finding /tmp/bhf-findings/F-0001-alpha --strategy typed",
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
