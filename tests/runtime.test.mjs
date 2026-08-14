import assert from "node:assert/strict";
import { execFile, execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import {
  pythonExecutable,
  require,
} from "./support.mjs";

const executeFile = promisify(execFile);

test("direct runtime is materialized in global storage and launches the MCP server", async () => {
  const { WorkbenchAdminClient } = require(
    "../out/packages/extension/src/workbench/workbenchClient.js",
  );
  const {
    getDirectLauncherPath,
    initializeDirectRuntime,
    inspectDirectRuntime,
    materializeDirectRuntime,
  } = require("../out/packages/extension/src/integration/integrationFiles.js");
  const temporary = await mkdtemp(join(tmpdir(), "kiro-direct-runtime-test-"));
  try {
    const stateRoot = join(temporary, "global-state");
    const scanRoot = join(stateRoot, "scans");
    const input = { extensionRoot: resolve("."), stateRoot };
    assert.equal((await materializeDirectRuntime(input)).changed, true);
    assert.equal((await materializeDirectRuntime(input)).changed, false);
    assert.equal((await inspectDirectRuntime(input)).ready, true);
    const launcherPath = getDirectLauncherPath(stateRoot);
    const python = pythonExecutable();
    await initializeDirectRuntime({ pythonExecutable: python, launcherPath, stateRoot, scanRoot });
    const transcript = execFileSync(python, ["-B", "-S", launcherPath], {
      encoding: "utf8",
      env: {
        ...process.env,
        KIRO_SECURITY_STATE_ROOT: stateRoot,
        KIRO_SECURITY_SCAN_ROOT: scanRoot,
      },
      input: [
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2025-11-25",
            capabilities: {},
            clientInfo: { name: "direct-runtime-test", version: "1" },
          },
        }),
        JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
        JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }),
        "",
      ].join("\n"),
    });
    const responses = transcript.trim().split(/\r?\n/).map((line) => JSON.parse(line));
    assert.equal(responses[0].result.serverInfo.name, "kiro-security-power");
    assert.ok(responses[1].result.tools.some((tool) => tool.name === "kiro_security_start_scan"));
    const dashboard = await new WorkbenchAdminClient(
      python,
      launcherPath,
      stateRoot,
      scanRoot,
    ).call("dashboard");
    assert.deepEqual(dashboard.scans, []);
    assert.deepEqual(dashboard.findings, []);
    assert.equal(existsSync(join(stateRoot, "runtime", "direct-mcp", "engine", "kiro_security", "__pycache__")), false);
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});

test("direct runtime materialization is serialized across extension hosts", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "kiro-runtime-lock-test-"));
  try {
    const stateRoot = join(temporary, "global-state");
    const modulePath = resolve(
      "out/packages/extension/src/integration/integrationFiles.js",
    );
    const program = `
      const { materializeDirectRuntime } = require(process.env.RUNTIME_MODULE);
      materializeDirectRuntime({
        extensionRoot: process.env.EXTENSION_ROOT,
        stateRoot: process.env.STATE_ROOT,
      }).then(
        (result) => process.stdout.write(JSON.stringify(result)),
        (error) => { console.error(error); process.exitCode = 1; },
      );
    `;
    const run = () =>
      executeFile(process.execPath, ["-e", program], {
        cwd: resolve("."),
        env: {
          ...process.env,
          EXTENSION_ROOT: resolve("."),
          RUNTIME_MODULE: modulePath,
          STATE_ROOT: stateRoot,
        },
      });

    const results = await Promise.all([run(), run()]);
    const changed = results
      .map(({ stdout }) => JSON.parse(stdout).changed)
      .sort();
    assert.deepEqual(changed, [false, true]);
    const { inspectDirectRuntime } = require(modulePath);
    assert.equal(
      (await inspectDirectRuntime({ extensionRoot: resolve("."), stateRoot })).ready,
      true,
    );

    const runtimeEntries = await readdir(join(stateRoot, "runtime"));
    assert.deepEqual(runtimeEntries.sort(), ["direct-mcp"]);
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});
