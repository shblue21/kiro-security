import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { parse } from "jsonc-parser";
import {
  AGENT_MCP_SERVER_NAME,
  AgentIntegrationError,
  AgentIntegrationManager,
  MANAGED_STEERING_MARKER,
  buildAgentSteering,
  mergeMcpServerConfigText,
  removeMcpServerConfigText,
} from "../packages/extension/src/agentIntegration";

const root = path.resolve(__dirname, "..", "..");
const python = process.env.KIRO_SECURITY_TEST_PYTHON || "python3";

async function tempRoot(name: string): Promise<string> {
  return mkdtemp(path.join(os.tmpdir(), `${name}-`));
}

test("JSONC MCP merge and removal preserve comments and unrelated servers", () => {
  const source = `{
  // keep this operator note
  "mcpServers": {
    "existing": { "command": "existing", "args": [] },
  },
}
`;
  const entry = {
    command: "/usr/bin/python3",
    args: ["-m", "kiro_security.mcp_server"],
    env: { PYTHONPATH: "/trusted/runtime" },
    disabled: false,
    autoApprove: ["security_get_scan"],
  };
  const merged = mergeMcpServerConfigText(source, "/tmp/mcp.json", AGENT_MCP_SERVER_NAME, entry);
  assert.match(merged, /keep this operator note/);
  const parsed = parse(merged) as any;
  assert.equal(parsed.mcpServers.existing.command, "existing");
  assert.deepEqual(parsed.mcpServers[AGENT_MCP_SERVER_NAME].args, entry.args);
  const removed = removeMcpServerConfigText(merged, "/tmp/mcp.json", AGENT_MCP_SERVER_NAME);
  assert.match(removed, /keep this operator note/);
  const final = parse(removed) as any;
  assert.equal(final.mcpServers.existing.command, "existing");
  assert.equal(final.mcpServers[AGENT_MCP_SERVER_NAME], undefined);
});

test("managed Agent steering is auto-included and describes the shared workbench", () => {
  const steering = buildAgentSteering("0.2.0");
  assert.match(steering, /inclusion: auto/);
  assert.match(steering, new RegExp(MANAGED_STEERING_MARKER.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.match(steering, /\.kiro\/security-power\/workbench\.sqlite/);
  assert.match(steering, /security_get_capabilities/);
  assert.match(steering, /not an official OpenAI, Codex, or Kiro product/);
});

test("one-click installer merges, verifies, prepares Power, and removes only managed entries", async () => {
  const sandbox = await tempRoot("kiro-security-agent");
  const workspace = path.join(sandbox, "workspace");
  const storage = path.join(sandbox, "global-storage");
  const home = path.join(sandbox, "home");
  await mkdir(path.join(workspace, ".kiro", "settings"), { recursive: true });
  await mkdir(home, { recursive: true });
  await writeFile(path.join(workspace, "app.py"), "print('safe')\n");
  const configPath = path.join(workspace, ".kiro", "settings", "mcp.json");
  await writeFile(configPath, `{
  // unrelated integration must survive
  "mcpServers": {
    "existing": { "command": "existing", "args": [], "disabled": false },
  },
}
`);

  const manager = new AgentIntegrationManager({
    extensionRoot: root,
    workspaceRoot: workspace,
    globalStorageRoot: storage,
    productVersion: "0.2.0",
    homeDirectory: home,
  });

  try {
    const installed = await manager.install({ pythonPath: python, scope: "workspace", autoApprovePolicy: "read_only" });
    assert.equal(installed.configPath, configPath);
    assert.ok(installed.toolCount >= 15);
    assert.match(installed.pythonVersion, /^3\./);
    const configText = await readFile(configPath, "utf8");
    assert.match(configText, /unrelated integration must survive/);
    const config = parse(configText) as any;
    assert.equal(config.mcpServers.existing.command, "existing");
    const managed = config.mcpServers[AGENT_MCP_SERVER_NAME];
    assert.equal(managed.command, installed.pythonExecutable);
    assert.deepEqual(managed.args, ["-B", "-S", "-m", "kiro_security.mcp_server"]);
    assert.deepEqual(managed.autoApprove, [
      "security_get_capabilities",
      "security_list_scans",
      "security_get_scan",
      "security_get_progress",
      "security_deep_get_status",
      "security_list_findings",
      "security_get_finding",
    ]);
    assert.equal(managed.autoApprove.includes("security_start_scan"), false);
    assert.match(await readFile(installed.steeringPath, "utf8"), /inclusion: auto/);
    for (const required of [
      path.join(installed.powerPath, "POWER.md"),
      path.join(installed.powerPath, "mcp.json"),
      path.join(installed.powerPath, "steering"),
      path.join(installed.powerPath, "runtime", "engine", "kiro_security", "mcp_server.py"),
    ]) {
      assert.ok((await stat(required)).isFile() || (await stat(required)).isDirectory());
    }

    const status = await manager.inspect(installed.pythonExecutable);
    assert.equal(status.configured, true);
    assert.equal(status.verified, true);
    assert.equal(status.state, "verified");
    assert.equal(status.power.prepared, true);
    assert.equal(status.power.manifestValid, true);
    const verified = await manager.verify(installed.pythonExecutable);
    assert.ok(verified.toolCount >= 15);
    await assert.rejects(stat(path.join(installed.powerPath, "runtime", "engine", "kiro_security", "__pycache__")), { code: "ENOENT" });

    const importShadow = path.join(installed.powerPath, "runtime", "engine", "json.py");
    await writeFile(importShadow, "raise RuntimeError('must never execute')\n");
    await assert.rejects(
      manager.verify(installed.pythonExecutable),
      (error: unknown) => error instanceof AgentIntegrationError && error.code === "prepared_payload_mismatch",
    );
    const tamperedStatus = await manager.inspect(installed.pythonExecutable);
    assert.equal(tamperedStatus.state, "needs_repair");
    assert.equal(tamperedStatus.verified, false);
    assert.equal(tamperedStatus.power.prepared, true);
    assert.equal(tamperedStatus.power.manifestValid, false);
    assert.match(tamperedStatus.details.join("\n"), /failed its integrity check/);
    await rm(importShadow, { force: true });
    const repairedStatus = await manager.inspect(installed.pythonExecutable);
    assert.equal(repairedStatus.state, "verified");
    assert.equal(repairedStatus.verified, true);

    const tampered = mergeMcpServerConfigText(
      configText,
      configPath,
      AGENT_MCP_SERVER_NAME,
      { ...managed, command: "definitely-not-the-verified-python" },
    );
    await writeFile(configPath, tampered);
    await assert.rejects(
      manager.verify(installed.pythonExecutable),
      (error: unknown) => error instanceof AgentIntegrationError && error.code === "untrusted_python",
    );
    await writeFile(configPath, configText);
    const restoredConfigStatus = await manager.inspect(installed.pythonExecutable);
    assert.equal(restoredConfigStatus.state, "verified");
    assert.equal(restoredConfigStatus.verified, true);

    const marker = path.join(sandbox, "tampered-mcp-command-ran");
    const tamperedArgs = mergeMcpServerConfigText(
      configText,
      configPath,
      AGENT_MCP_SERVER_NAME,
      {
        ...managed,
        args: [
          "-c",
          `from pathlib import Path; Path(${JSON.stringify(marker)}).write_text('unsafe')`,
          "kiro_security.mcp_server",
        ],
      },
    );
    await writeFile(configPath, tamperedArgs);
    await assert.rejects(
      manager.verify(installed.pythonExecutable),
      (error: unknown) => error instanceof AgentIntegrationError && error.code === "untrusted_mcp_args",
    );
    await assert.rejects(stat(marker), { code: "ENOENT" });

    const unsafeApproval = mergeMcpServerConfigText(
      configText,
      configPath,
      AGENT_MCP_SERVER_NAME,
      { ...managed, autoApprove: ["security_start_scan"] },
    );
    await writeFile(configPath, unsafeApproval);
    await assert.rejects(
      manager.verify(installed.pythonExecutable),
      (error: unknown) => error instanceof AgentIntegrationError && error.code === "unsafe_auto_approval",
    );
    await writeFile(configPath, configText);

    const removed = await manager.removeDirectIntegration();
    assert.deepEqual(removed.removedConfigPaths, [configPath]);
    const after = parse(await readFile(configPath, "utf8")) as any;
    assert.equal(after.mcpServers.existing.command, "existing");
    assert.equal(after.mcpServers[AGENT_MCP_SERVER_NAME], undefined);
    await assert.rejects(readFile(installed.steeringPath, "utf8"));
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
});

test("invalid existing MCP JSONC blocks installation without overwriting user data", async () => {
  const sandbox = await tempRoot("kiro-security-agent-invalid");
  const workspace = path.join(sandbox, "workspace");
  const configPath = path.join(workspace, ".kiro", "settings", "mcp.json");
  await mkdir(path.dirname(configPath), { recursive: true });
  await writeFile(configPath, "{ invalid-json: true\n");
  const manager = new AgentIntegrationManager({
    extensionRoot: root,
    workspaceRoot: workspace,
    globalStorageRoot: path.join(sandbox, "storage"),
    productVersion: "0.2.0",
    homeDirectory: path.join(sandbox, "home"),
  });
  try {
    await assert.rejects(
      manager.install({ pythonPath: python, scope: "workspace", autoApprovePolicy: "none" }),
      (error: unknown) => error instanceof AgentIntegrationError && error.code === "mcp_config_invalid",
    );
    assert.equal(await readFile(configPath, "utf8"), "{ invalid-json: true\n");
    await assert.rejects(stat(path.join(workspace, ".kiro", "steering", "kiro-security-power.md")));
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
});

test("user-scoped integration remains workspace-neutral and still verifies the current workspace", async () => {
  const sandbox = await tempRoot("kiro-security-agent-user");
  const workspace = path.join(sandbox, "workspace");
  const home = path.join(sandbox, "home");
  await mkdir(workspace, { recursive: true });
  await mkdir(home, { recursive: true });
  await writeFile(path.join(workspace, "app.py"), "print('safe')\n");
  const manager = new AgentIntegrationManager({
    extensionRoot: root,
    workspaceRoot: workspace,
    globalStorageRoot: path.join(sandbox, "storage"),
    productVersion: "0.2.0",
    homeDirectory: home,
  });
  try {
    const installed = await manager.install({ pythonPath: python, scope: "user", autoApprovePolicy: "none" });
    assert.equal(installed.configPath, path.join(home, ".kiro", "settings", "mcp.json"));
    const config = parse(await readFile(installed.configPath, "utf8")) as any;
    const managed = config.mcpServers[AGENT_MCP_SERVER_NAME];
    assert.equal(managed.env.KIRO_SECURITY_WORKSPACE, undefined);
    assert.equal(managed.autoApprove, undefined);
    assert.ok((await manager.verify(installed.pythonExecutable)).toolCount >= 15);
    const removed = await manager.removeDirectIntegration();
    assert.deepEqual(removed.removedConfigPaths, [installed.configPath]);
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
});

test("removal leaves a same-named unmanaged MCP server untouched", async () => {
  const sandbox = await tempRoot("kiro-security-agent-unmanaged");
  const workspace = path.join(sandbox, "workspace");
  const configPath = path.join(workspace, ".kiro", "settings", "mcp.json");
  await mkdir(path.dirname(configPath), { recursive: true });
  const original = `${JSON.stringify({
    mcpServers: {
      [AGENT_MCP_SERVER_NAME]: {
        command: "/custom/security-server",
        args: ["--stdio"],
        env: {},
        disabled: false,
      },
    },
  }, null, 2)}\n`;
  await writeFile(configPath, original);
  const manager = new AgentIntegrationManager({
    extensionRoot: root,
    workspaceRoot: workspace,
    globalStorageRoot: path.join(sandbox, "storage"),
    productVersion: "0.2.0",
    homeDirectory: path.join(sandbox, "home"),
  });
  try {
    const removed = await manager.removeDirectIntegration();
    assert.deepEqual(removed.removedConfigPaths, []);
    assert.deepEqual(removed.skippedUnmanagedConfigPaths, [configPath]);
    assert.equal(await readFile(configPath, "utf8"), original);
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
});
