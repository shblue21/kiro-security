import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { existsSync, readFileSync } from "node:fs";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

const require = createRequire(import.meta.url);
const manifest = JSON.parse(readFileSync("package.json", "utf8"));

test("extension manifest exposes a UI-only setup view and existing foundation commands", () => {
  assert.equal(manifest.main, "./out/packages/extension/src/extension.js");
  assert.deepEqual(manifest.extensionKind, ["workspace"]);
  assert.deepEqual(manifest.activationEvents, [
    "onStartupFinished",
    "onView:kiroSecurity.setup",
    "onCommand:kiroSecurity.openSetup",
    "onCommand:kiroSecurity.showFoundationStatus",
    "onCommand:kiroSecurity.preparePowerIntegration",
  ]);
  assert.deepEqual(
    manifest.contributes.commands.map((entry) => entry.command),
    [
      "kiroSecurity.openSetup",
      "kiroSecurity.showFoundationStatus",
      "kiroSecurity.preparePowerIntegration",
    ],
  );
  assert.equal(
    manifest.contributes.views.kiroSecurity[0].id,
    "kiroSecurity.setup",
  );
  assert.equal(
    manifest.contributes.viewsContainers.activitybar[0].icon,
    "media/security.svg",
  );
  assert.equal(
    manifest.contributes.configuration.properties[
      "kiroSecurity.pythonPath"
    ].scope,
    "machine",
  );
  assert.equal(existsSync(manifest.main), true);
});

test("setup view is a static preview with no Hook or Power actions", () => {
  const setup = readFileSync(
    "packages/extension/src/setupView.ts",
    "utf8",
  );
  const extension = readFileSync(
    "packages/extension/src/extension.ts",
    "utf8",
  );
  assert.match(setup, /UI preview only/);
  assert.match(setup, /does not install Hooks or change Kiro user settings/);
  assert.match(setup, /enableScripts: false/);
  assert.doesNotMatch(setup, /onDidReceiveMessage|preparePowerIntegration/);
  assert.doesNotMatch(extension, /ChatBindingManager|enableChatBinding/);
  assert.equal(
    existsSync("packages/extension/src/chatBinding.ts"),
    false,
  );
});

test("extension entry point prepares one external global workbench boundary", () => {
  const foundation = readFileSync(
    "packages/extension/src/foundation.ts",
    "utf8",
  );
  assert.match(foundation, /context\.globalStorageUri/);
  assert.match(foundation, /stateRoot\.scheme !== "file"/);
  assert.match(foundation, /workbench\.sqlite3/);
  assert.match(foundation, /Uri\.joinPath\(stateRoot, "scans"\)/);
  assert.doesNotMatch(foundation, /workspaceFolders|storageUri/);
});

test("Power entry point preserves the Agent-chat ownership boundary", () => {
  const power = readFileSync("powers/kiro-security-power/POWER.md", "utf8");
  assert.match(power, /Kiro Agent chat owns scan start/);
  assert.match(power, /does not provide a Dashboard Start action/);
  assert.match(power, /does not perform semantic security analysis/);
  assert.match(power, /scoped Deep scan selects that directory/);
  assert.match(power, /extension-global SQLite workbench/);
  assert.match(power, /Never create or require `\.kiro\/security-power`/);
  assert.match(power, /start_scan.*get_scan_context/s);
  assert.match(power, /does not yet include Standard, Diff, Deep/);
  assert.match(power, /workspace and scan identifiers as an explicit Kiro adaptation/);
  assert.equal(existsSync("powers/kiro-security-power/mcp.json"), true);
});

test("prepared Power MCP config shares global storage and auto-approves reads only", () => {
  const {
    buildPowerMcpConfiguration,
    READ_ONLY_MCP_TOOLS,
  } = require(
    "../out/packages/extension/src/powerIntegrationConfig.js",
  );
  const configuration = buildPowerMcpConfiguration({
    pythonExecutable: "/runtime/python3",
    engineRoot: "/global/power/runtime/engine",
    stateRoot: "/global/state",
    scanRoot: "/global/state/scans",
  });
  const server = configuration.mcpServers["kiro-security-workbench"];

  assert.equal(server.command, "/runtime/python3");
  assert.deepEqual(server.args, [
    "-B",
    "-S",
    "-m",
    "kiro_security.mcp_server",
  ]);
  assert.equal(server.env.KIRO_SECURITY_STATE_ROOT, "/global/state");
  assert.equal(server.env.KIRO_SECURITY_SCAN_ROOT, "/global/state/scans");
  assert.equal(server.timeout, 900_000);
  assert.deepEqual(server.autoApprove, [...READ_ONLY_MCP_TOOLS]);
  assert.ok(!server.autoApprove.includes("kiro_security_start_scan"));
  assert.ok(!server.autoApprove.includes("kiro_security_cancel_scan"));

  const template = JSON.parse(
    readFileSync("powers/kiro-security-power/mcp.json", "utf8"),
  );
  assert.deepEqual(
    template.mcpServers["kiro-security-workbench"].autoApprove,
    server.autoApprove,
  );
});

test("Power preparation stays in global storage and leaves Kiro registration to import", () => {
  const integration = readFileSync(
    "packages/extension/src/powerIntegration.ts",
    "utf8",
  );
  assert.match(integration, /paths\.stateRoot\.fsPath/);
  assert.match(integration, /agent-integration/);
  assert.match(integration, /Powers panel/);
  assert.doesNotMatch(integration, /\.kiro.*settings|settings.*mcp\.json/);
});

test("Power materialization copies a self-contained MCP runtime atomically", async () => {
  const { materializePowerIntegration } = require(
    "../out/packages/extension/src/powerIntegrationFiles.js",
  );
  const temporary = await mkdtemp(
    join(tmpdir(), "kiro-security-power-test-"),
  );
  try {
    const stateRoot = join(temporary, "global-state");
    const scanRoot = join(stateRoot, "scans");
    const integrationRoot = join(stateRoot, "agent-integration");
    const pythonExecutable = execFileSync(
      process.platform === "win32" ? "python" : "python3",
      ["-c", "import sys; print(sys.executable)"],
      { encoding: "utf8" },
    ).trim();
    const input = {
      extensionRoot: resolve("."),
      integrationRoot,
      pythonExecutable,
      stateRoot,
      scanRoot,
    };

    const first = await materializePowerIntegration(input);
    const second = await materializePowerIntegration(input);
    assert.equal(first, second);
    assert.equal(existsSync(join(second, "POWER.md")), true);
    assert.equal(existsSync(join(second, "mcp.json")), true);
    assert.equal(
      existsSync(
        join(
          second,
          "runtime",
          "engine",
          "kiro_security",
          "mcp_server.py",
        ),
      ),
      true,
    );
    assert.equal(
      existsSync(
        join(second, "runtime", "engine", "kiro_security", "__pycache__"),
      ),
      false,
    );

    const prepared = JSON.parse(
      readFileSync(join(second, "mcp.json"), "utf8"),
    ).mcpServers["kiro-security-workbench"];
    assert.equal(prepared.command, pythonExecutable);
    assert.equal(prepared.env.KIRO_SECURITY_STATE_ROOT, stateRoot);
    assert.equal(prepared.env.KIRO_SECURITY_SCAN_ROOT, scanRoot);
    assert.equal(
      prepared.env.PYTHONPATH,
      join(second, "runtime", "engine"),
    );
    const transcript = execFileSync(prepared.command, prepared.args, {
      encoding: "utf8",
      env: { ...process.env, ...prepared.env },
      input: [
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2025-11-25",
            capabilities: {},
            clientInfo: { name: "materialized-power-test", version: "1" },
          },
        }),
        JSON.stringify({
          jsonrpc: "2.0",
          method: "notifications/initialized",
        }),
        JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          method: "tools/list",
          params: {},
        }),
        "",
      ].join("\n"),
    });
    const responses = transcript
      .trim()
      .split(/\r?\n/)
      .map((line) => JSON.parse(line));
    assert.equal(
      responses[0].result.serverInfo.name,
      "kiro-security-power",
    );
    assert.ok(
      responses[1].result.tools.some(
        (tool) => tool.name === "kiro_security_start_scan",
      ),
    );
    if (process.platform !== "win32") {
      assert.equal((await stat(second)).mode & 0o777, 0o700);
      assert.equal(
        (await stat(join(second, "mcp.json"))).mode & 0o777,
        0o600,
      );
    }
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});

test("internal reference documents are excluded from the VSIX", () => {
  const ignored = readFileSync(".vscodeignore", "utf8").split(/\r?\n/);
  assert.ok(ignored.includes("docs/**"));
  assert.ok(ignored.includes("engine/tests/**"));
  assert.ok(ignored.includes("tests/**"));
  assert.ok(!ignored.includes("engine/**"));
  assert.ok(!ignored.includes("powers/**"));
});

test("actual VSIX file selection contains runtime files and no chat binding implementation", () => {
  const binary = resolve(
    "node_modules",
    ".bin",
    process.platform === "win32" ? "vsce.cmd" : "vsce",
  );
  const files = execFileSync(binary, ["ls"], { encoding: "utf8" })
    .trim()
    .split(/\r?\n/);

  assert.ok(files.includes("package.json"));
  assert.ok(files.includes("media/security.svg"));
  assert.ok(files.includes("powers/kiro-security-power/POWER.md"));
  assert.ok(files.includes("powers/kiro-security-power/mcp.json"));
  assert.ok(files.includes("engine/kiro_security/workbench.py"));
  assert.ok(files.includes("engine/kiro_security/mcp_server.py"));
  assert.ok(files.includes("engine/kiro_security/mcp_tools.py"));
  assert.ok(files.includes("out/packages/extension/src/extension.js"));
  assert.ok(files.includes("out/packages/extension/src/foundation.js"));
  assert.ok(
    files.includes(
      "out/packages/extension/src/powerIntegrationConfig.js",
    ),
  );
  assert.ok(
    files.includes(
      "out/packages/extension/src/powerIntegrationFiles.js",
    ),
  );
  assert.ok(
    files.includes("out/packages/extension/src/powerIntegration.js"),
  );
  assert.ok(files.includes("out/packages/extension/src/setupView.js"));
  assert.ok(!files.includes("out/packages/extension/src/chatBinding.js"));
  assert.ok(!files.includes("engine/kiro_security/identity.py"));
  assert.ok(!files.includes("engine/kiro_security/identity_hook.py"));
  assert.ok(!files.some((entry) => entry.startsWith("docs/")));
  assert.ok(!files.some((entry) => entry.startsWith("tests/")));
  assert.ok(!files.some((entry) => entry.startsWith("engine/tests/")));
  assert.ok(!files.some((entry) => entry.includes("__pycache__")));
  assert.ok(!files.some((entry) => entry.endsWith(".pyc")));
});
