import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

import {
  manifest,
  pythonExecutable,
  require,
  TEST_SERVER_KEY,
} from "./support.mjs";

function runSourceMcp(python, stateRoot) {
  const transcript = execFileSync(
    python,
    ["-B", "-S", "-m", "kiro_security.mcp_server"],
    {
      encoding: "utf8",
      maxBuffer: 8 * 1024 * 1024,
      timeout: 30_000,
      env: {
        ...process.env,
        KIRO_SECURITY_STATE_ROOT: stateRoot,
        KIRO_SECURITY_SCAN_ROOT: join(stateRoot, "scans"),
        PYTHONPATH: resolve("engine"),
      },
      input: [
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2025-11-25",
            capabilities: {},
            clientInfo: { name: "contract-test", version: "1" },
          },
        }),
        JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
        JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }),
        "",
      ].join("\n"),
    },
  );
  return transcript.trim().split(/\r?\n/).map((line) => JSON.parse(line));
}

test("actual MCP, TypeScript, and Hook expose the same ordered tool contract", async () => {
  const {
    AUTO_APPROVED_MCP_TOOLS,
    MANUAL_APPROVAL_MCP_TOOLS,
    MCP_TOOL_NAMES,
  } = require("../out/packages/extension/src/integration/integrationConfig.js");
  const temporary = await mkdtemp(join(tmpdir(), "kiro-contract-test-"));
  try {
    const python = pythonExecutable();
    const responses = runSourceMcp(python, join(temporary, "state"));
    const actualMcpNames = responses[1].result.tools.map((tool) => tool.name);
    const hookNames = JSON.parse(
      execFileSync(
        python,
        [
          "-B",
          "-S",
          "-c",
          "import json,runpy,sys; bridge=runpy.run_path(sys.argv[1]); print(json.dumps(list(bridge['_direct_tool_map'](sys.argv[2]).values())))",
          resolve("hook/kiro_security_hook_bridge.py"),
          TEST_SERVER_KEY,
        ],
        { encoding: "utf8" },
      ),
    );

    assert.deepEqual([...MCP_TOOL_NAMES], actualMcpNames);
    assert.deepEqual(hookNames, actualMcpNames);
    assert.deepEqual(
      [...MANUAL_APPROVAL_MCP_TOOLS],
      ["kiro_security_start_scan", "kiro_security_cancel_scan"],
    );
    const manual = new Set(MANUAL_APPROVAL_MCP_TOOLS);
    assert.deepEqual(
      [...AUTO_APPROVED_MCP_TOOLS],
      actualMcpNames.filter((name) => !manual.has(name)),
    );
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});

test("VSIX, Python package, and actual MCP report one product version", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "kiro-version-test-"));
  try {
    const python = pythonExecutable();
    const responses = runSourceMcp(python, join(temporary, "state"));
    const pythonVersion = execFileSync(
      python,
      ["-B", "-S", "-c", "from kiro_security import __version__; print(__version__)"],
      {
        encoding: "utf8",
        env: { ...process.env, PYTHONPATH: resolve("engine") },
      },
    ).trim();

    assert.equal(responses[0].result.serverInfo.version, manifest.version);
    assert.equal(pythonVersion, manifest.version);
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});
