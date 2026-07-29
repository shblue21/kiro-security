import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import { existsSync, readFileSync } from "node:fs";
import {
  mkdir,
  mkdtemp,
  readdir,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

const require = createRequire(import.meta.url);
const manifest = JSON.parse(readFileSync("package.json", "utf8"));
const TEST_SERVER_KEY = "ksp_aaaaaaaaaaaaaaaaaaaa";
const TEST_GUARD_ID = "11111111-1111-4111-8111-111111111111";

function pythonExecutable() {
  return execFileSync(
    process.platform === "win32" ? "python" : "python3",
    ["-c", "import sys; print(sys.executable)"],
    { encoding: "utf8" },
  ).trim();
}

test("extension manifest exposes setup without a Power-import command", () => {
  assert.equal(manifest.main, "./out/packages/extension/src/extension.js");
  assert.deepEqual(manifest.extensionKind, ["workspace"]);
  assert.deepEqual(manifest.activationEvents, [
    "onStartupFinished",
    "onView:kiroSecurity.setup",
    "onCommand:kiroSecurity.openSetup",
    "onCommand:kiroSecurity.showFoundationStatus",
  ]);
  assert.deepEqual(
    manifest.contributes.commands.map((entry) => entry.command),
    [
      "kiroSecurity.openSetup",
      "kiroSecurity.showFoundationStatus",
    ],
  );
  assert.equal(manifest.contributes.views.kiroSecurity[0].id, "kiroSecurity.setup");
  assert.equal(manifest.contributes.viewsContainers.activitybar[0].icon, "media/security.svg");
  assert.equal(
    manifest.contributes.configuration.properties["kiroSecurity.pythonPath"].scope,
    "machine",
  );
  assert.equal(existsSync(manifest.main), true);
});

test("setup view connects steering, direct MCP, and Hook without Agent or Power import", () => {
  const setup = readFileSync("packages/extension/src/setupView.ts", "utf8");
  const extension = readFileSync("packages/extension/src/extension.ts", "utf8");
  assert.match(setup, /enableScripts: true/);
  assert.match(setup, /connectIntegration/);
  assert.match(setup, /showMcpFile/);
  assert.match(setup, /showPermissionsFile/);
  assert.match(setup, /showSteeringFile/);
  assert.match(setup, /No custom Agent configuration is installed/);
  assert.doesNotMatch(setup, /preparePowerIntegration/);
  assert.match(extension, /getOrCreateInstallationServerKey/);
  assert.match(extension, /new SecuritySetupView\(/);
});

test("Hook registration matches only the exact direct MCP tool IDs", () => {
  const {
    buildHookRegistrationDocument,
    getHookBridgePath,
    getHookRegistrationPath,
    HOOK_FILE_NAME,
  } = require("../out/packages/extension/src/chatBindingFiles.js");
  const { buildDirectMcpContract } = require(
    "../out/packages/extension/src/integrationConfig.js",
  );
  const contract = buildDirectMcpContract(TEST_SERVER_KEY);
  const hookPath = getHookRegistrationPath("/users/tester");
  const bridgePath = getHookBridgePath("/global/storage");
  const document = buildHookRegistrationDocument({
    pythonExecutable: "/runtime/python3",
    bridgePath,
    serverKey: TEST_SERVER_KEY,
    platform: "darwin",
  });

  assert.equal(hookPath, join("/users/tester", ".kiro", "hooks", HOOK_FILE_NAME));
  assert.equal(document.hooks[0].trigger, "PreToolUse");
  assert.equal(document.hooks[0].matcher, contract.toolMatcher);
  for (const toolId of contract.toolIds) {
    assert.match(toolId, /^mcp_ksp_aaaaaaaaaaaaaaaaaaaa_/);
    assert.equal(new RegExp(contract.toolMatcher).test(toolId), true);
  }
  assert.equal(new RegExp(contract.toolMatcher).test("kiro_powers"), false);
  assert.equal(new RegExp(contract.toolMatcher).test("fs_read"), false);
  assert.match(document.hooks[0].action.command, /\/runtime\/python3/);
  assert.match(document.hooks[0].action.command, /\/global\/storage\/runtime\/hook-bridge/);
  assert.match(document.hooks[0].action.command, /--server-key 'ksp_aaaaaaaaaaaaaaaaaaaa'/);
  assert.doesNotMatch(JSON.stringify(document), /workbench\.sqlite3|scanRoot/);
});

test("Hook install, repair, and removal stay in its dedicated-file boundary", async () => {
  const {
    buildHookRegistrationDocument,
    getHookBridgePath,
    getHookRegistrationPath,
    inspectHookRegistration,
    installHookRegistration,
    removeHookRegistration,
  } = require("../out/packages/extension/src/chatBindingFiles.js");
  const temporary = await mkdtemp(join(tmpdir(), "kiro-hook-files-test-"));
  try {
    const hookPath = getHookRegistrationPath(join(temporary, "home"));
    const document = buildHookRegistrationDocument({
      pythonExecutable: "/runtime/python3",
      bridgePath: getHookBridgePath(join(temporary, "global-storage")),
      serverKey: TEST_SERVER_KEY,
      platform: "darwin",
    });
    assert.equal((await inspectHookRegistration({ hookPath, expected: document })).state, "absent");
    assert.equal((await installHookRegistration({ hookPath, document, repair: false })).changed, true);
    assert.equal((await inspectHookRegistration({ hookPath, expected: document })).state, "installed");
    if (process.platform !== "win32") {
      assert.equal((await stat(hookPath)).mode & 0o777, 0o600);
    }
    assert.equal((await installHookRegistration({ hookPath, document, repair: false })).changed, false);

    const drifted = { ...document, hooks: [{ ...document.hooks[0], timeout: 11 }] };
    await writeFile(hookPath, `${JSON.stringify(drifted, null, 2)}\n`, "utf8");
    assert.equal((await inspectHookRegistration({ hookPath, expected: document })).state, "repairable");
    await assert.rejects(
      installHookRegistration({ hookPath, document, repair: false }),
      /requires repair/,
    );
    assert.equal((await installHookRegistration({ hookPath, document, repair: true })).changed, true);
    assert.equal((await removeHookRegistration({ hookPath })).changed, true);
    assert.equal(existsSync(hookPath), false);
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});

test("dedicated Hook path refuses symlink targets", async () => {
  if (process.platform === "win32") {
    return;
  }
  const {
    buildHookRegistrationDocument,
    getHookRegistrationPath,
    inspectHookRegistration,
    installHookRegistration,
  } = require("../out/packages/extension/src/chatBindingFiles.js");
  const temporary = await mkdtemp(join(tmpdir(), "kiro-hook-conflict-test-"));
  try {
    const hookPath = getHookRegistrationPath(join(temporary, "home"));
    await mkdir(join(temporary, "home", ".kiro", "hooks"), { recursive: true });
    const target = join(temporary, "other-hook.json");
    await writeFile(target, '{"version":"v1","hooks":[]}\n', "utf8");
    await symlink(target, hookPath);
    const document = buildHookRegistrationDocument({
      pythonExecutable: "/runtime/python3",
      bridgePath: join(temporary, "state", "runtime", "bridge.py"),
      serverKey: TEST_SERVER_KEY,
      platform: "darwin",
    });
    assert.equal((await inspectHookRegistration({ hookPath, expected: document })).state, "conflict");
    await assert.rejects(
      installHookRegistration({ hookPath, document, repair: true }),
      /symlink/,
    );
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});

test("Hook bridge binds host session identity to exact direct MCP calls", async () => {
  const {
    buildHookBridgeProbe,
    getHookBridgePath,
    getPackagedHookBridgePath,
    inspectHookBridge,
    materializeHookBridge,
  } = require("../out/packages/extension/src/chatBindingFiles.js");
  const { removeMcpShadowGuard, updateMcpShadowGuard } = require(
    "../out/packages/extension/src/integrationFiles.js",
  );
  const {
    buildDirectMcpContract,
    buildDirectMcpServerConfiguration,
    MCP_TOOL_NAMES,
  } = require(
    "../out/packages/extension/src/integrationConfig.js",
  );
  const directContract = buildDirectMcpContract(TEST_SERVER_KEY);
  const temporary = await mkdtemp(join(tmpdir(), "kiro-hook-bridge-test-"));
  try {
    const sourcePath = getPackagedHookBridgePath(resolve("."));
    const stateRoot = join(temporary, "global-storage");
    const bridgePath = getHookBridgePath(stateRoot);
    const userMcpPath = join(temporary, "home", ".kiro", "settings", "mcp.json");
    const expected = buildDirectMcpServerConfiguration({
      pythonExecutable: "/runtime/python3",
      launcherPath: "/global/runtime/launcher.py",
      stateRoot,
      scanRoot: join(stateRoot, "scans"),
    });
    await mkdir(join(temporary, "home", ".kiro", "settings"), { recursive: true });
    await writeFile(
      userMcpPath,
      `${JSON.stringify({ mcpServers: { [TEST_SERVER_KEY]: expected } })}\n`,
      { encoding: "utf8", mode: 0o600 },
    );
    assert.equal(await materializeHookBridge({ sourcePath, bridgePath }), true);
    assert.equal(await materializeHookBridge({ sourcePath, bridgePath }), false);
    assert.equal((await inspectHookBridge({ sourcePath, bridgePath })).ready, true);
    await updateMcpShadowGuard({
      stateRoot,
      guardId: TEST_GUARD_ID,
      serverKey: TEST_SERVER_KEY,
      userMcpPath,
      workspaceRoots: [temporary],
      expected,
    });

    const python = pythonExecutable();
    const contract = JSON.parse(
      execFileSync(
        python,
        [
          "-B",
          "-c",
          "import json,runpy,sys; b=runpy.run_path(sys.argv[1]); print(json.dumps({'map':b['_direct_tool_map'](sys.argv[2]),'ttl':b['ATTESTATION_TTL_SECONDS']}))",
          bridgePath,
          TEST_SERVER_KEY,
        ],
        { encoding: "utf8" },
      ),
    );
    assert.deepEqual(contract.map, Object.fromEntries(directContract.toolIds.map((id, index) => [id, MCP_TOOL_NAMES[index]])));
    assert.equal(contract.ttl, 15 * 60);

    const runBridge = (payload) =>
      spawnSync(python, ["-B", bridgePath, "--server-key", TEST_SERVER_KEY], {
        encoding: "utf8",
        input: JSON.stringify(payload),
      });
    assert.equal(runBridge(buildHookBridgeProbe(temporary)).status, 0);
    assert.equal(existsSync(join(stateRoot, "workbench.sqlite3")), false);
    execFileSync(
      python,
      [
        "-B",
        "-S",
        "-c",
        "import sys; from kiro_security.workbench import Workbench; Workbench(sys.argv[1], sys.argv[2])",
        stateRoot,
        join(stateRoot, "scans"),
      ],
      { env: { ...process.env, PYTHONPATH: resolve("engine") } },
    );

    for (let index = 0; index < directContract.toolIds.length; index += 1) {
      const valid = runBridge({
        session_id: "chat-a",
        hook_event_name: "PreToolUse",
        cwd: temporary,
        tool_name: directContract.toolIds[index],
        tool_input: { requestNonce: randomUUID() },
      });
      assert.equal(valid.status, 0, MCP_TOOL_NAMES[index]);
      assert.equal(valid.stderr, "", MCP_TOOL_NAMES[index]);
    }

    const base = {
      hook_event_name: "PreToolUse",
      cwd: temporary,
      tool_name: directContract.toolIds[0],
      tool_input: { requestNonce: randomUUID() },
    };
    const missingSession = runBridge(base);
    assert.equal(missingSession.status, 2);
    assert.match(missingSession.stderr, /session_id/);
    const missingNonce = runBridge({ ...base, session_id: "chat-a", tool_input: {} });
    assert.equal(missingNonce.status, 2);
    assert.match(missingNonce.stderr, /requestNonce/);
    const unrelated = runBridge({
      hook_event_name: "PreToolUse",
      tool_name: "fs_read",
      tool_input: { data: "x".repeat(1024 * 1024) },
    });
    assert.equal(unrelated.status, 0);
    const malformedEvent = runBridge({ ...base, session_id: "chat-a", hook_event_name: [] });
    assert.equal(malformedEvent.status, 2);
    assert.doesNotMatch(malformedEvent.stderr, /Traceback|TypeError/);

    const workspaceMcpPath = join(temporary, ".kiro", "settings", "mcp.json");
    await mkdir(join(temporary, ".kiro", "settings"), { recursive: true });
    await writeFile(workspaceMcpPath, '{"mcpServers":{"other":{}}}\n', "utf8");
    const changedAfterInspection = runBridge({
      ...base,
      session_id: "chat-a",
      tool_input: { requestNonce: randomUUID() },
    });
    assert.equal(changedAfterInspection.status, 2);
    assert.match(changedAfterInspection.stderr, /changed after inspection/);

    await updateMcpShadowGuard({
      stateRoot,
      guardId: TEST_GUARD_ID,
      serverKey: TEST_SERVER_KEY,
      userMcpPath,
      workspaceRoots: [temporary],
      expected,
    });
    const refreshed = runBridge({
      ...base,
      session_id: "chat-a",
      tool_input: { requestNonce: randomUUID() },
    });
    assert.equal(refreshed.status, 0);

    const foreign = {
      ...expected,
      command: "/foreign/python",
    };
    await writeFile(
      userMcpPath,
      `${JSON.stringify({ mcpServers: { [TEST_SERVER_KEY]: foreign } })}\n`,
      { encoding: "utf8", mode: 0o600 },
    );
    await updateMcpShadowGuard({
      stateRoot,
      guardId: TEST_GUARD_ID,
      serverKey: TEST_SERVER_KEY,
      userMcpPath,
      workspaceRoots: [temporary],
      expected,
    });
    const foreignReplacement = runBridge({
      ...base,
      session_id: "chat-a",
      tool_input: { requestNonce: randomUUID() },
    });
    assert.equal(foreignReplacement.status, 2);
    assert.match(foreignReplacement.stderr, /shadows this installation/);

    await writeFile(
      userMcpPath,
      `${JSON.stringify({ mcpServers: { [TEST_SERVER_KEY]: expected } })}\n`,
      { encoding: "utf8", mode: 0o600 },
    );
    await updateMcpShadowGuard({
      stateRoot,
      guardId: TEST_GUARD_ID,
      serverKey: TEST_SERVER_KEY,
      userMcpPath,
      workspaceRoots: [temporary],
      expected,
    });
    const secondWorkspace = join(temporary, "second-window");
    await mkdir(join(secondWorkspace, ".kiro", "settings"), { recursive: true });
    await writeFile(
      join(secondWorkspace, ".kiro", "settings", "mcp.json"),
      `${JSON.stringify({ mcpServers: { [TEST_SERVER_KEY]: { command: "shadow" } } })}\n`,
      "utf8",
    );
    const secondGuardId = "22222222-2222-4222-8222-222222222222";
    await updateMcpShadowGuard({
      stateRoot,
      guardId: secondGuardId,
      serverKey: TEST_SERVER_KEY,
      userMcpPath,
      workspaceRoots: [secondWorkspace],
      expected,
    });
    const otherWindowConflict = runBridge({
      ...base,
      session_id: "chat-a",
      tool_input: { requestNonce: randomUUID() },
    });
    assert.equal(otherWindowConflict.status, 2);
    assert.match(otherWindowConflict.stderr, /shadows this installation/);
    await removeMcpShadowGuard({ stateRoot, guardId: secondGuardId });
    const conflictLeaseRemoved = runBridge({
      ...base,
      session_id: "chat-a",
      tool_input: { requestNonce: randomUUID() },
    });
    assert.equal(conflictLeaseRemoved.status, 0);
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});

test("extension foundation uses one external global workbench boundary", () => {
  const foundation = readFileSync("packages/extension/src/foundation.ts", "utf8");
  assert.match(foundation, /context\.globalStorageUri/);
  assert.match(foundation, /stateRoot\.scheme !== "file"/);
  assert.match(foundation, /workbench\.sqlite3/);
  assert.match(foundation, /Uri\.joinPath\(stateRoot, "scans"\)/);
  assert.doesNotMatch(foundation, /workspaceFolders|storageUri/);
});

test("auto-inclusion steering owns normal-chat orchestration without a Power entry point", () => {
  const steering = readFileSync("steering/kiro-security-power.md", "utf8");
  assert.match(steering, /inclusion: auto/);
  assert.match(steering, /Kiro Agent chat owns scan start/);
  assert.match(steering, /does not provide a Dashboard Start action/);
  assert.match(steering, /never create or require `\.kiro\/security-power`/);
  assert.match(steering, /setupRevision.*setupDigest.*normalized setup/s);
  assert.match(steering, /fresh UUID-shaped `requestNonce`/);
  assert.equal(existsSync("powers/kiro-security-power/POWER.md"), false);
  assert.equal(existsSync("powers/kiro-security-power/mcp.json"), false);
});

test("direct MCP config keeps Start and Cancel on the explicit approval boundary", () => {
  const {
    AUTO_APPROVED_MCP_TOOLS,
    MANUAL_APPROVAL_MCP_TOOLS,
    MCP_MANAGED_MARKER,
    buildDirectMcpContract,
    buildDirectMcpServerConfiguration,
  } = require("../out/packages/extension/src/integrationConfig.js");
  const contract = buildDirectMcpContract(TEST_SERVER_KEY);
  const [allowRule, askRule] = contract.permissionRules;
  const configuration = buildDirectMcpServerConfiguration({
    pythonExecutable: "/runtime/python3",
    launcherPath: "/global/runtime/kiro_security_launcher.py",
    stateRoot: "/global/state",
    scanRoot: "/global/state/scans",
  });
  assert.deepEqual(configuration.args, ["-B", "-S", "/global/runtime/kiro_security_launcher.py"]);
  assert.equal(configuration.env.KIRO_SECURITY_MANAGED_BY, MCP_MANAGED_MARKER);
  assert.equal(configuration.timeout, 900_000);
  assert.deepEqual(MANUAL_APPROVAL_MCP_TOOLS, ["kiro_security_start_scan", "kiro_security_cancel_scan"]);
  for (const name of AUTO_APPROVED_MCP_TOOLS) {
    assert.ok(configuration.autoApprove.includes(name));
    assert.ok(allowRule.match.includes(`${TEST_SERVER_KEY}/${name}`));
  }
  assert.equal(configuration.autoApprove.length, AUTO_APPROVED_MCP_TOOLS.length);
  assert.ok(!configuration.autoApprove.includes("kiro_security_start_scan"));
  assert.ok(!configuration.autoApprove.includes("kiro_security_cancel_scan"));
  assert.deepEqual(askRule.match, [
    `${TEST_SERVER_KEY}/kiro_security_start_scan`,
    `${TEST_SERVER_KEY}/kiro_security_cancel_scan`,
  ]);
  assert.ok(contract.toolIds.every((toolId) => toolId.length <= 64));
});

test("installation MCP identity is random, persistent, and private", async () => {
  const {
    getIntegrationIdentityPath,
    getOrCreateInstallationServerKey,
  } = require("../out/packages/extension/src/integrationFiles.js");
  const { buildDirectMcpContract, MCP_SERVER_KEY_PATTERN } = require(
    "../out/packages/extension/src/integrationConfig.js",
  );
  const temporary = await mkdtemp(join(tmpdir(), "kiro-integration-identity-test-"));
  try {
    const firstRoot = join(temporary, "first");
    const secondRoot = join(temporary, "second");
    const generated = await Promise.all(
      Array.from({ length: 32 }, () => getOrCreateInstallationServerKey(firstRoot)),
    );
    const first = generated[0];
    const second = await getOrCreateInstallationServerKey(secondRoot);
    assert.match(first, MCP_SERVER_KEY_PATTERN);
    assert.ok(generated.every((value) => value === first));
    assert.notEqual(second, first);
    assert.equal(
      JSON.parse(readFileSync(getIntegrationIdentityPath(firstRoot), "utf8")).serverKey,
      first,
    );
    assert.ok(buildDirectMcpContract(first).toolIds.every((toolId) => toolId.length <= 64));
    assert.deepEqual(
      (await readdir(join(firstRoot, "runtime"))).sort(),
      ["integration-identity.json"],
    );
    if (process.platform !== "win32") {
      assert.equal((await stat(getIntegrationIdentityPath(firstRoot))).mode & 0o777, 0o600);
    }
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});

test("Trust v2 permission install preserves unrelated YAML rules and file mode", async () => {
  const YAML = require("yaml");
  const {
    getActiveUserPermissionsPath,
    inspectPermissions,
    installPermissions,
    removePermissions,
  } = require("../out/packages/extension/src/permissionFiles.js");
  const temporary = await mkdtemp(join(tmpdir(), "kiro-permissions-yaml-test-"));
  try {
    const directory = join(temporary, ".kiro", "settings");
    const filePath = join(directory, "permissions.yaml");
    await mkdir(directory, { recursive: true });
    await writeFile(
      filePath,
      "# preserve this comment\nrules:\n  - capability: fs_read\n    effect: allow\n    match:\n      - ./src/**\n",
      { encoding: "utf8", mode: 0o644 },
    );
    assert.equal(await getActiveUserPermissionsPath(temporary), filePath);
    assert.equal((await inspectPermissions({ homeDirectory: temporary, serverKey: TEST_SERVER_KEY })).state, "absent");
    assert.equal((await installPermissions({ homeDirectory: temporary, serverKey: TEST_SERVER_KEY })).changed, true);
    assert.equal((await inspectPermissions({ homeDirectory: temporary, serverKey: TEST_SERVER_KEY })).state, "installed");
    const installedText = readFileSync(filePath, "utf8");
    const installed = YAML.parse(installedText);
    assert.match(installedText, /preserve this comment/);
    assert.ok(installed.rules.some((rule) => rule.capability === "fs_read"));
    const managedAllow = installed.rules.find(
      (rule) => rule.capability === "mcp" && rule.effect === "allow",
    );
    const managedAsk = installed.rules.find(
      (rule) => rule.capability === "mcp" && rule.effect === "ask",
    );
    assert.ok(managedAllow.match.includes(`${TEST_SERVER_KEY}/kiro_security_get_capabilities`));
    assert.ok(!managedAllow.match.includes(`${TEST_SERVER_KEY}/kiro_security_start_scan`));
    assert.deepEqual(managedAsk.match, [
      `${TEST_SERVER_KEY}/kiro_security_start_scan`,
      `${TEST_SERVER_KEY}/kiro_security_cancel_scan`,
    ]);
    if (process.platform !== "win32") {
      assert.equal((await stat(filePath)).mode & 0o777, 0o644);
    }
    assert.equal((await removePermissions({ homeDirectory: temporary, serverKey: TEST_SERVER_KEY })).changed, true);
    const removedText = readFileSync(filePath, "utf8");
    assert.match(removedText, /preserve this comment/);
    assert.ok(YAML.parse(removedText).rules.some((rule) => rule.capability === "fs_read"));
    assert.doesNotMatch(removedText, new RegExp(TEST_SERVER_KEY));
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});

test("Trust v2 permission install follows Kiro's active JSON selection", async () => {
  const { installPermissions, removePermissions } = require(
    "../out/packages/extension/src/permissionFiles.js",
  );
  const temporary = await mkdtemp(join(tmpdir(), "kiro-permissions-json-test-"));
  try {
    const directory = join(temporary, ".kiro", "settings");
    const yamlPath = join(directory, "permissions.yaml");
    const jsonPath = join(directory, "permissions.json");
    await mkdir(directory, { recursive: true });
    await writeFile(yamlPath, "", "utf8");
    await writeFile(jsonPath, `${JSON.stringify({ rules: [{ capability: "web_search", effect: "ask" }] }, null, 2)}\n`, "utf8");
    await installPermissions({ homeDirectory: temporary, serverKey: TEST_SERVER_KEY });
    assert.equal(readFileSync(yamlPath, "utf8"), "");
    const installed = JSON.parse(readFileSync(jsonPath, "utf8"));
    assert.equal(installed.rules.length, 3);
    await removePermissions({ homeDirectory: temporary, serverKey: TEST_SERVER_KEY });
    const removed = JSON.parse(readFileSync(jsonPath, "utf8"));
    assert.deepEqual(removed.rules, [{ capability: "web_search", effect: "ask" }]);
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});

test("Trust v2 permission install creates a valid fresh YAML file", async () => {
  const YAML = require("yaml");
  const {
    getActiveUserPermissionsPath,
    inspectPermissions,
    installPermissions,
  } = require("../out/packages/extension/src/permissionFiles.js");
  const temporary = await mkdtemp(join(tmpdir(), "kiro-permissions-fresh-test-"));
  try {
    await installPermissions({ homeDirectory: temporary, serverKey: TEST_SERVER_KEY });
    const filePath = await getActiveUserPermissionsPath(temporary);
    const parsed = YAML.parse(readFileSync(filePath, "utf8"));
    assert.equal(parsed.rules.length, 2);
    assert.equal(parsed.rules[0].capability, "mcp");
    assert.equal(parsed.rules[0].effect, "allow");
    assert.equal(parsed.rules[1].effect, "ask");
    assert.equal((await inspectPermissions({ homeDirectory: temporary, serverKey: TEST_SERVER_KEY })).state, "installed");
    if (process.platform !== "win32") {
      assert.equal((await stat(filePath)).mode & 0o777, 0o600);
    }
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});

test("direct runtime is materialized in global storage and launches the MCP server", async () => {
  const {
    getDirectLauncherPath,
    initializeDirectRuntime,
    inspectDirectRuntime,
    materializeDirectRuntime,
  } = require("../out/packages/extension/src/integrationFiles.js");
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
    assert.equal(existsSync(join(stateRoot, "runtime", "direct-mcp", "engine", "kiro_security", "__pycache__")), false);
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});

test("MCP registration patches only its managed JSONC entry", async () => {
  const { buildDirectMcpServerConfiguration } = require(
    "../out/packages/extension/src/integrationConfig.js",
  );
  const {
    inspectMcpRegistration,
    installMcpRegistration,
    removeMcpRegistration,
  } = require("../out/packages/extension/src/integrationFiles.js");
  const temporary = await mkdtemp(join(tmpdir(), "kiro-mcp-config-test-"));
  try {
    const mcpPath = join(temporary, ".kiro", "settings", "mcp.json");
    await mkdir(join(temporary, ".kiro", "settings"), { recursive: true, mode: 0o755 });
    const existing = '{\n  // keep this server\n  "mcpServers": {\n    "other": { "command": "other" },\n  },\n}\n';
    await writeFile(mcpPath, existing, { encoding: "utf8", mode: 0o600 });
    const expected = buildDirectMcpServerConfiguration({
      pythonExecutable: "/runtime/python3",
      launcherPath: "/global/runtime/launcher.py",
      stateRoot: "/global/state",
      scanRoot: "/global/state/scans",
    });
    assert.equal((await inspectMcpRegistration({ mcpPath, serverKey: TEST_SERVER_KEY, expected })).state, "absent");
    assert.equal((await installMcpRegistration({ mcpPath, serverKey: TEST_SERVER_KEY, expected, repair: false })).changed, true);
    const installed = readFileSync(mcpPath, "utf8");
    assert.match(installed, /keep this server/);
    assert.match(installed, /"other"/);
    assert.match(installed, new RegExp(`"${TEST_SERVER_KEY}"`));
    assert.equal((await inspectMcpRegistration({ mcpPath, serverKey: TEST_SERVER_KEY, expected })).state, "installed");
    if (process.platform !== "win32") {
      assert.equal((await stat(join(temporary, ".kiro", "settings"))).mode & 0o777, 0o755);
      assert.equal((await stat(mcpPath)).mode & 0o777, 0o600);
    }
    assert.equal((await removeMcpRegistration({ mcpPath, serverKey: TEST_SERVER_KEY })).changed, true);
    const removed = readFileSync(mcpPath, "utf8");
    assert.match(removed, /keep this server/);
    assert.match(removed, /"other"/);
    assert.doesNotMatch(removed, new RegExp(TEST_SERVER_KEY));
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});

test("MCP registration refuses unmanaged key collisions and symlink paths", async () => {
  if (process.platform === "win32") {
    return;
  }
  const { buildDirectMcpServerConfiguration } = require(
    "../out/packages/extension/src/integrationConfig.js",
  );
  const { inspectMcpRegistration, installMcpRegistration } = require(
    "../out/packages/extension/src/integrationFiles.js",
  );
  const temporary = await mkdtemp(join(tmpdir(), "kiro-mcp-conflict-test-"));
  try {
    const expected = buildDirectMcpServerConfiguration({
      pythonExecutable: "/runtime/python3",
      launcherPath: "/global/runtime/launcher.py",
      stateRoot: "/global/state",
      scanRoot: "/global/state/scans",
    });
    const collisionPath = join(temporary, "collision.json");
    await writeFile(collisionPath, `${JSON.stringify({ mcpServers: { [TEST_SERVER_KEY]: { command: "user" } } })}\n`, "utf8");
    assert.equal((await inspectMcpRegistration({ mcpPath: collisionPath, serverKey: TEST_SERVER_KEY, expected })).state, "conflict");
    await assert.rejects(
      installMcpRegistration({ mcpPath: collisionPath, serverKey: TEST_SERVER_KEY, expected, repair: true }),
      /unmanaged/,
    );
    const target = join(temporary, "target.json");
    const link = join(temporary, "mcp.json");
    await writeFile(target, '{"mcpServers":{}}\n', "utf8");
    await symlink(target, link);
    assert.equal((await inspectMcpRegistration({ mcpPath: link, serverKey: TEST_SERVER_KEY, expected })).state, "conflict");
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});

test("MCP shadow inspection covers user powers and every workspace root", async () => {
  const { inspectMcpShadowing } = require(
    "../out/packages/extension/src/integrationFiles.js",
  );
  const temporary = await mkdtemp(join(tmpdir(), "kiro-mcp-shadow-test-"));
  try {
    const userMcpPath = join(temporary, "home", ".kiro", "settings", "mcp.json");
    const firstRoot = join(temporary, "first-workspace");
    const secondRoot = join(temporary, "second-workspace");
    await mkdir(join(firstRoot, ".kiro", "settings"), { recursive: true });
    await mkdir(join(secondRoot, ".kiro", "settings"), { recursive: true });
    await writeFile(
      join(firstRoot, ".kiro", "settings", "mcp.json"),
      '{"mcpServers":{"kiro-security-workbench":{"command":"old-static-shadow"}}}\n',
      "utf8",
    );
    const input = {
      serverKey: TEST_SERVER_KEY,
      userMcpPath,
      workspaceRoots: [firstRoot, secondRoot],
    };
    assert.equal((await inspectMcpShadowing(input)).state, "absent");

    const aliasKey = TEST_SERVER_KEY.toUpperCase().replace("KSP_", "KSP-");
    await writeFile(
      join(secondRoot, ".kiro", "settings", "mcp.json"),
      `${JSON.stringify({ mcpServers: { [aliasKey]: { command: "shadow" } } })}\n`,
      "utf8",
    );
    assert.equal((await inspectMcpShadowing(input)).state, "conflict");

    await rm(join(secondRoot, ".kiro", "settings", "mcp.json"));
    await mkdir(join(temporary, "home", ".kiro", "settings"), { recursive: true });
    await writeFile(
      userMcpPath,
      `${JSON.stringify({ powers: { mcpServers: { [TEST_SERVER_KEY]: { command: "shadow" } } } })}\n`,
      "utf8",
    );
    assert.equal((await inspectMcpShadowing(input)).state, "conflict");
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});

test("internal reference documents stay excluded from the VSIX", () => {
  const ignored = readFileSync(".vscodeignore", "utf8").split(/\r?\n/);
  assert.ok(ignored.includes("docs/**"));
  assert.ok(ignored.includes("engine/tests/**"));
  assert.ok(ignored.includes("tests/**"));
  assert.ok(!ignored.includes("engine/**"));
});

test("actual VSIX selection contains direct integration assets and no Power entry point", () => {
  const binary = resolve("node_modules", ".bin", process.platform === "win32" ? "vsce.cmd" : "vsce");
  const files = execFileSync(binary, ["ls"], { encoding: "utf8" }).trim().split(/\r?\n/);
  assert.ok(files.includes("package.json"));
  assert.ok(files.includes("media/security.svg"));
  assert.ok(files.includes("hook/kiro_security_hook_bridge.py"));
  assert.ok(files.includes("steering/kiro-security-power.md"));
  assert.ok(files.includes("runtime/kiro_security_launcher.py"));
  assert.ok(files.includes("engine/kiro_security/workbench.py"));
  assert.ok(files.includes("engine/kiro_security/mcp_server.py"));
  assert.ok(files.includes("engine/kiro_security/mcp_tools.py"));
  assert.ok(files.includes("node_modules/jsonc-parser/lib/umd/main.js"));
  assert.ok(files.includes("node_modules/yaml/dist/index.js"));
  assert.ok(files.includes("out/packages/extension/src/integrationConfig.js"));
  assert.ok(files.includes("out/packages/extension/src/integrationFiles.js"));
  assert.ok(files.includes("out/packages/extension/src/integration.js"));
  assert.ok(files.includes("out/packages/extension/src/permissionFiles.js"));
  assert.ok(files.includes("out/packages/extension/src/setupView.js"));
  assert.ok(!files.some((entry) => entry.startsWith("powers/")));
  assert.ok(!files.some((entry) => entry.includes("powerIntegration")));
  assert.ok(!files.some((entry) => entry.startsWith("docs/")));
  assert.ok(!files.some((entry) => entry.startsWith("tests/")));
  assert.ok(!files.some((entry) => entry.startsWith("engine/tests/")));
  assert.ok(!files.some((entry) => entry.includes("__pycache__")));
  assert.ok(!files.some((entry) => entry.endsWith(".pyc")));
});
