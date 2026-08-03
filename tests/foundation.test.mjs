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

function pythonExecutable() {
  return execFileSync(
    process.platform === "win32" ? "python" : "python3",
    ["-c", "import sys; print(sys.executable)"],
    { encoding: "utf8" },
  ).trim();
}

function loadSetupViewModule() {
  const Module = require("node:module");
  const originalLoad = Module._load;
  Module._load = function loadWithVscodeStub(request, parent, isMain) {
    if (request === "vscode") {
      return {};
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  try {
    return require("../out/packages/extension/src/setupView.js");
  } finally {
    Module._load = originalLoad;
  }
}

test("extension manifest exposes setup without a Power-import command", () => {
  assert.equal(manifest.main, "./out/packages/extension/src/extension.js");
  assert.deepEqual(manifest.extensionKind, ["workspace"]);
  assert.deepEqual(manifest.activationEvents, [
    "onStartupFinished",
    "onView:kiroSecurity.setup",
    "onCommand:kiroSecurity.openSetup",
  ]);
  assert.deepEqual(
    manifest.contributes.commands.map((entry) => entry.command),
    [
      "kiroSecurity.openSetup",
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
  const integration = readFileSync("packages/extension/src/integration.ts", "utf8");
  assert.match(setup, /enableScripts: true/);
  assert.match(setup, /connectIntegration/);
  assert.match(setup, /showMcpFile/);
  assert.match(setup, /showSteeringFile/);
  assert.doesNotMatch(setup, /showPermissionsFile/);
  assert.match(setup, /Chat approvals/);
  assert.match(setup, /exact Kiro Trust rules/);
  assert.match(setup, /No custom Agent configuration is installed/);
  assert.doesNotMatch(setup, /preparePowerIntegration/);
  assert.doesNotMatch(setup, /verifyIntegration|Verify again/);
  assert.match(extension, /getOrCreateInstallationServerKey/);
  assert.match(extension, /new SecuritySetupView\(/);
  assert.doesNotMatch(integration, /before\.state === "mismatch"/);
  assert.match(setup, /input\.integration\.state === "unavailable"[\s\S]*\? "disabled"/);
});

test("Dashboard and Findings render exact recovery and follow-up controls", () => {
  const { renderSetupHtml } = loadSetupViewModule();
  const scans = [
    {
      id: "scan-one",
      workspaceId: "workspace-one",
      status: "running",
      phase: "discovery",
      mode: "standard",
      scope: ".",
      scanDir: "/global/scans/one",
      startedAt: "2026-07-30T00:00:00Z",
      updatedAt: "2026-07-30T00:01:00Z",
      target: {
        path: "/source/alpha",
        revision: "alpha-revision",
      },
      progress: {
        reviewItemsTotal: 2,
        reviewItemsCompleted: 1,
        reportableFindingsCount: 0,
      },
    },
    {
      id: "scan-two",
      workspaceId: "workspace-two",
      status: "complete",
      phase: "reporting",
      mode: "standard",
      scope: ".",
      scanDir: "/global/scans/two",
      startedAt: "2026-07-30T00:00:00Z",
      completedAt: "2026-07-30T00:02:00Z",
      updatedAt: "2026-07-30T00:02:00Z",
      target: {
        path: "/source/beta",
        revision: "beta-revision",
      },
      progress: {
        reviewItemsTotal: 1,
        reviewItemsCompleted: 1,
        reportableFindingsCount: 1,
      },
    },
  ];
  const dashboard = {
    scans,
    findings: [
      {
        occurrenceId: "occurrence-one",
        findingId: "finding-one",
        scanId: "scan-two",
        title: "Example finding",
        summary: "Example summary",
        severity: "high",
        confidence: "high",
        remediation: "Apply the reviewed fix.",
        details: { evidence: "validated" },
        locations: [
          {
            path: "src/example.ts",
            startLine: 4,
            endLine: 5,
          },
        ],
        triage: { status: "open" },
      },
    ],
    recoveryRequests: [
      {
        id: "recovery-one",
        scanId: "scan-one",
        status: "pending",
        version: 1,
        createdAt: "2026-07-30T00:01:00Z",
        updatedAt: "2026-07-30T00:01:00Z",
      },
    ],
    remediationRequests: [
      {
        requestId: "remediation-one",
        occurrenceId: "occurrence-one",
        state: "requested",
        version: 2,
        pendingAction: "generate",
        createdAt: "2026-07-30T00:02:00Z",
        updatedAt: "2026-07-30T00:02:00Z",
      },
    ],
  };
  const integration = {
    state: "ready",
    detail: "ready",
    serverKey: TEST_SERVER_KEY,
    hook: {
      state: "ready",
      registrationState: "installed",
      hookPath: "/home/.kiro/hooks/kiro-security-power.json",
      bridgePath: "/global/hook.py",
      detail: "ready",
    },
    mcp: { state: "installed", detail: "ready" },
    steering: { state: "installed", detail: "ready" },
    runtime: { ready: true, detail: "ready" },
    approval: {
      state: "installed",
      detail: "ready",
      path: "/home/.kiro/settings/permissions.yaml",
    },
    hookPath: "/home/.kiro/hooks/kiro-security-power.json",
    mcpPath: "/home/.kiro/settings/mcp.json",
    steeringPath: "/home/.kiro/steering/kiro-security-power.md",
    runtimeRoot: "/global/runtime",
  };
  const html = renderSetupHtml({
    webview: { cspSource: "vscode-webview:" },
    stateRoot: "/global",
    integration,
    activeTab: "findings",
    dashboard,
  });

  assert.match(html, /id="scan-filter"/);
  assert.match(html, /data-scan-id="scan-two"/);
  assert.match(html, /\/source\/beta/);
  assert.match(html, /beta-revision/);
  assert.match(html, /Copy generate prompt again/);
  assert.match(html, /data-command="copyRemediationPrompt"/);
  assert.match(html, /Copy resume prompt again/);
  assert.match(html, /data-command="cancelRecovery"/);
  assert.match(html, /data-request-id="recovery-one"/);
  assert.match(html, /data-command="trackFinding"/);
});

test("tracking action creates a durable backend request before copying a prompt", () => {
  const setup = readFileSync("packages/extension/src/setupView.ts", "utf8");
  assert.match(
    setup,
    /callWorkbench<[\s\S]*?>\("createTracking", \{\s*occurrenceId: exactOccurrence/,
  );
  assert.match(setup, /Tracking request: \$\{tracking\.requestId\}/);
  assert.match(setup, /Expected version: \$\{tracking\.version\}/);
  assert.match(setup, /Claim and deliver the exact tracking request/);
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

test("Hook install is idempotent and refuses to overwrite a changed dedicated file", async () => {
  const {
    buildHookRegistrationDocument,
    getHookBridgePath,
    getHookRegistrationPath,
    inspectHookRegistration,
    installHookRegistration,
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
    assert.equal((await installHookRegistration({ hookPath, document })).changed, true);
    assert.equal((await inspectHookRegistration({ hookPath, expected: document })).state, "installed");
    if (process.platform !== "win32") {
      assert.equal((await stat(hookPath)).mode & 0o777, 0o600);
    }
    assert.equal((await installHookRegistration({ hookPath, document })).changed, false);

    const drifted = { ...document, hooks: [{ ...document.hooks[0], timeout: 11 }] };
    await writeFile(hookPath, `${JSON.stringify(drifted, null, 2)}\n`, "utf8");
    assert.equal((await inspectHookRegistration({ hookPath, expected: document })).state, "mismatch");
    await assert.rejects(
      installHookRegistration({ hookPath, document }),
      /will not be overwritten/,
    );
    assert.deepEqual(JSON.parse(readFileSync(hookPath, "utf8")), drifted);
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
      installHookRegistration({ hookPath, document }),
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
  const {
    buildDirectMcpContract,
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
    assert.equal(await materializeHookBridge({ sourcePath, bridgePath }), true);
    assert.equal(await materializeHookBridge({ sourcePath, bridgePath }), false);
    assert.equal((await inspectHookBridge({ sourcePath, bridgePath })).ready, true);

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
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});

test("extension foundation uses one external global workbench boundary", () => {
  const foundation = readFileSync("packages/extension/src/foundation.ts", "utf8");
  assert.match(foundation, /context\.globalStorageUri/);
  assert.match(foundation, /stateRoot\.scheme !== "file"/);
  assert.match(foundation, /stateRoot\.scheme !== "vscode-userdata"/);
  assert.match(foundation, /workbench\.sqlite3/);
  assert.match(foundation, /Uri\.joinPath\(stateRoot, "scans"\)/);
  assert.doesNotMatch(foundation, /workspaceFolders|storageUri/);
});

test("auto-inclusion steering owns normal-chat orchestration without a Power entry point", () => {
  const steering = readFileSync("steering/kiro-security-power.md", "utf8");
  assert.match(steering, /inclusion: auto/);
  assert.match(steering, /ordinary Kiro\s+Agent chat/);
  assert.match(steering, /The VSIX and direct\s+`kiro_security_\*` MCP tools own workspace/);
  assert.match(steering, /Never create or require `\.kiro\/security-power`/);
  assert.match(steering, /exact returned setup revision,\s+digest, and normalized value/);
  assert.match(steering, /fresh UUID-shaped `requestNonce`/);
  assert.match(steering, /`phaseContract\.readAhead` equal to `false`/);
  assert.match(steering, /preflight -> discovery/);
  assert.match(steering, /kiro_security_complete_scan/);
  assert.doesNotMatch(steering, /^## (Threat-model|Validation|Attack-path) phase/m);
  assert.doesNotMatch(steering, /^## (Standard|Diff|Deep) discovery/m);
  assert.equal(existsSync("powers/kiro-security-power/POWER.md"), false);
  assert.equal(existsSync("powers/kiro-security-power/mcp.json"), false);
});

test("direct MCP config keeps Start and Cancel on the explicit approval boundary", () => {
  const {
    MANUAL_APPROVAL_MCP_TOOLS,
    MCP_MANAGED_MARKER,
    buildDirectMcpContract,
    buildDirectMcpServerConfiguration,
  } = require("../out/packages/extension/src/integrationConfig.js");
  const contract = buildDirectMcpContract(TEST_SERVER_KEY);
  const configuration = buildDirectMcpServerConfiguration({
    serverKey: TEST_SERVER_KEY,
    pythonExecutable: "/runtime/python3",
    launcherPath: "/global/runtime/kiro_security_launcher.py",
    stateRoot: "/global/state",
    scanRoot: "/global/state/scans",
  });
  assert.deepEqual(configuration.args, ["-B", "-S", "/global/runtime/kiro_security_launcher.py"]);
  assert.equal(configuration.env.KIRO_SECURITY_MANAGED_BY, MCP_MANAGED_MARKER);
  assert.equal(configuration.timeout, 900_000);
  assert.deepEqual(MANUAL_APPROVAL_MCP_TOOLS, ["kiro_security_start_scan", "kiro_security_cancel_scan"]);
  assert.ok(
    contract.toolIds.some((toolId) =>
      toolId.endsWith("_kiro_security_read_scan_artifact"),
    ),
  );
  assert.equal("autoApprove" in configuration, false);
  assert.ok(contract.toolIds.every((toolId) => toolId.length <= 64));
});

test("Trust v2 policy allows setup tools and asks only for Start and Cancel", async () => {
  const {
    buildApprovalPolicyRules,
    inspectApprovalPolicy,
    installApprovalPolicy,
  } = require("../out/packages/extension/src/approvalPolicy.js");
  const {
    AUTO_APPROVED_MCP_TOOLS,
    MANUAL_APPROVAL_MCP_TOOLS,
  } = require("../out/packages/extension/src/integrationConfig.js");
  const temporary = await mkdtemp(join(tmpdir(), "kiro-approval-policy-test-"));
  try {
    const settings = join(temporary, ".kiro", "settings");
    const policyPath = join(settings, "permissions.yaml");
    await mkdir(settings, { recursive: true });
    await writeFile(
      policyPath,
      [
        "# Preserve this user rule",
        "rules:",
        "  - capability: fs_read",
        "    match:",
        '      - "./**"',
        "    effect: allow",
        "",
      ].join("\n"),
      { encoding: "utf8", mode: 0o640 },
    );

    const required = buildApprovalPolicyRules(TEST_SERVER_KEY);
    assert.deepEqual(required[0], {
      capability: "skill",
      match: ["kiro-security"],
      effect: "allow",
    });
    assert.deepEqual(
      required[1].match,
      AUTO_APPROVED_MCP_TOOLS.map(
        (name) => `${TEST_SERVER_KEY}/${name}`,
      ),
    );
    assert.deepEqual(
      required[2].match,
      MANUAL_APPROVAL_MCP_TOOLS.map(
        (name) => `${TEST_SERVER_KEY}/${name}`,
      ),
    );
    assert.equal(required[2].effect, "ask");
    assert.equal(
      required[1].match.some((match) => /start_scan|cancel_scan/.test(match)),
      false,
    );
    assert.equal(
      required[1].match.some((match) =>
        match.endsWith("/kiro_security_read_scan_artifact"),
      ),
      true,
    );

    assert.equal(
      (await inspectApprovalPolicy({
        serverKey: TEST_SERVER_KEY,
        homeDirectory: temporary,
      })).state,
      "mismatch",
    );
    assert.equal(
      (await installApprovalPolicy({
        serverKey: TEST_SERVER_KEY,
        homeDirectory: temporary,
      })).changed,
      true,
    );
    const installed = readFileSync(policyPath, "utf8");
    assert.match(installed, /Preserve this user rule/);
    assert.match(installed, /capability: fs_read/);
    assert.match(installed, /capability: skill/);
    assert.match(installed, /effect: ask/);
    assert.doesNotMatch(installed, /rules:\s*\[/);
    assert.equal(
      (await inspectApprovalPolicy({
        serverKey: TEST_SERVER_KEY,
        homeDirectory: temporary,
      })).state,
      "installed",
    );
    assert.equal(
      (await installApprovalPolicy({
        serverKey: TEST_SERVER_KEY,
        homeDirectory: temporary,
      })).changed,
      false,
    );
    if (process.platform !== "win32") {
      assert.equal((await stat(policyPath)).mode & 0o777, 0o640);
    }

    const freshHome = join(temporary, "fresh-home");
    await installApprovalPolicy({
      serverKey: TEST_SERVER_KEY,
      homeDirectory: freshHome,
    });
    const freshPolicy = readFileSync(
      join(freshHome, ".kiro", "settings", "permissions.yaml"),
      "utf8",
    );
    assert.match(freshPolicy, /rules:\n  - capability: skill/);
    assert.doesNotMatch(freshPolicy, /rules:\s*\[/);
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});

test("Trust v2 policy supports JSON and refuses malformed shared files", async () => {
  const {
    inspectApprovalPolicy,
    installApprovalPolicy,
  } = require("../out/packages/extension/src/approvalPolicy.js");
  const temporary = await mkdtemp(join(tmpdir(), "kiro-approval-json-test-"));
  try {
    const settings = join(temporary, ".kiro", "settings");
    const jsonPath = join(settings, "permissions.json");
    await mkdir(settings, { recursive: true });
    await writeFile(jsonPath, '{"rules":[]}\n', "utf8");
    assert.equal(
      (await installApprovalPolicy({
        serverKey: TEST_SERVER_KEY,
        homeDirectory: temporary,
      })).changed,
      true,
    );
    const parsed = JSON.parse(readFileSync(jsonPath, "utf8"));
    assert.ok(
      parsed.rules.some(
        (rule) =>
          rule.capability === "mcp" &&
          rule.effect === "ask" &&
          rule.match.includes(
            `${TEST_SERVER_KEY}/kiro_security_start_scan`,
          ),
      ),
    );

    await writeFile(jsonPath, '{"rules":[],"rules":[]}\n', "utf8");
    const inspection = await inspectApprovalPolicy({
      serverKey: TEST_SERVER_KEY,
      homeDirectory: temporary,
    });
    assert.equal(inspection.state, "conflict");
    assert.match(inspection.detail, /duplicate JSON object key/);
    await assert.rejects(
      installApprovalPolicy({
        serverKey: TEST_SERVER_KEY,
        homeDirectory: temporary,
      }),
      /duplicate JSON object key/,
    );
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
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

test("direct runtime is materialized in global storage and launches the MCP server", async () => {
  const { WorkbenchAdminClient } = require(
    "../out/packages/extension/src/workbenchClient.js",
  );
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

test("MCP registration install preserves unrelated JSONC entries", async () => {
  const { buildDirectMcpServerConfiguration } = require(
    "../out/packages/extension/src/integrationConfig.js",
  );
  const {
    inspectMcpRegistration,
    installMcpRegistration,
  } = require("../out/packages/extension/src/integrationFiles.js");
  const temporary = await mkdtemp(join(tmpdir(), "kiro-mcp-config-test-"));
  try {
    const mcpPath = join(temporary, ".kiro", "settings", "mcp.json");
    await mkdir(join(temporary, ".kiro", "settings"), { recursive: true, mode: 0o755 });
    const existing = '{\n  // keep this server\n  "mcpServers": {\n    "other": { "command": "other" },\n  },\n}\n';
    await writeFile(mcpPath, existing, { encoding: "utf8", mode: 0o600 });
    const expected = buildDirectMcpServerConfiguration({
      serverKey: TEST_SERVER_KEY,
      pythonExecutable: "/runtime/python3",
      launcherPath: "/global/runtime/launcher.py",
      stateRoot: "/global/state",
      scanRoot: "/global/state/scans",
    });
    assert.equal((await inspectMcpRegistration({ mcpPath, serverKey: TEST_SERVER_KEY, expected })).state, "absent");
    assert.equal((await installMcpRegistration({ mcpPath, serverKey: TEST_SERVER_KEY, expected })).changed, true);
    const installed = readFileSync(mcpPath, "utf8");
    assert.match(installed, /keep this server/);
    assert.match(installed, /"other"/);
    assert.match(installed, new RegExp(`"${TEST_SERVER_KEY}"`));
    assert.equal((await inspectMcpRegistration({ mcpPath, serverKey: TEST_SERVER_KEY, expected })).state, "installed");
    if (process.platform !== "win32") {
      assert.equal((await stat(join(temporary, ".kiro", "settings"))).mode & 0o777, 0o755);
      assert.equal((await stat(mcpPath)).mode & 0o777, 0o600);
    }
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});

test("MCP registration refuses ambiguous duplicate JSONC keys without mutation", async () => {
  const { buildDirectMcpServerConfiguration } = require(
    "../out/packages/extension/src/integrationConfig.js",
  );
  const {
    inspectMcpRegistration,
    installMcpRegistration,
  } = require("../out/packages/extension/src/integrationFiles.js");
  const temporary = await mkdtemp(join(tmpdir(), "kiro-mcp-duplicate-test-"));
  try {
    const mcpPath = join(temporary, "mcp.json");
    const expected = buildDirectMcpServerConfiguration({
      serverKey: TEST_SERVER_KEY,
      pythonExecutable: "/runtime/python3",
      launcherPath: "/global/runtime/launcher.py",
      stateRoot: "/global/state",
      scanRoot: "/global/state/scans",
    });
    const cases = [
      `{
  "mcpServers": { "other": { "command": "other" } },
  "mcpServers": { "${TEST_SERVER_KEY}": ${JSON.stringify(expected)} }
}\n`,
      `{
  "mcpServers": {
    "${TEST_SERVER_KEY}": { "command": "unmanaged" },
    "${TEST_SERVER_KEY}": ${JSON.stringify(expected)}
  }
}\n`,
    ];

    for (const contents of cases) {
      await writeFile(mcpPath, contents, { encoding: "utf8", mode: 0o600 });
      const inspection = await inspectMcpRegistration({
        mcpPath,
        serverKey: TEST_SERVER_KEY,
        expected,
      });
      assert.equal(inspection.state, "conflict");
      assert.match(inspection.detail, /duplicate JSON object key/);
      await assert.rejects(
        installMcpRegistration({
          mcpPath,
          serverKey: TEST_SERVER_KEY,
          expected,
        }),
        /duplicate JSON object key/,
      );
      assert.equal(readFileSync(mcpPath, "utf8"), contents);
    }
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
      serverKey: TEST_SERVER_KEY,
      pythonExecutable: "/runtime/python3",
      launcherPath: "/global/runtime/launcher.py",
      stateRoot: "/global/state",
      scanRoot: "/global/state/scans",
    });
    const collisionPath = join(temporary, "collision.json");
    await writeFile(collisionPath, `${JSON.stringify({ mcpServers: { [TEST_SERVER_KEY]: { command: "user" } } })}\n`, "utf8");
    assert.equal((await inspectMcpRegistration({ mcpPath: collisionPath, serverKey: TEST_SERVER_KEY, expected })).state, "conflict");
    await assert.rejects(
      installMcpRegistration({ mcpPath: collisionPath, serverKey: TEST_SERVER_KEY, expected }),
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
  assert.ok(files.includes("engine/kiro_security/phase_contracts.py"));
  assert.ok(files.includes("node_modules/jsonc-parser/lib/umd/main.js"));
  assert.ok(files.includes("node_modules/yaml/dist/index.js"));
  assert.ok(files.includes("out/packages/extension/src/approvalPolicy.js"));
  assert.ok(files.includes("out/packages/extension/src/integrationConfig.js"));
  assert.ok(files.includes("out/packages/extension/src/integrationFiles.js"));
  assert.ok(files.includes("out/packages/extension/src/integration.js"));
  assert.ok(files.includes("out/packages/extension/src/setupView.js"));
  assert.ok(!files.some((entry) => entry.startsWith("powers/")));
  assert.ok(!files.some((entry) => entry.includes("powerIntegration")));
  assert.ok(!files.some((entry) => entry.startsWith("docs/")));
  assert.ok(!files.some((entry) => entry.startsWith("tests/")));
  assert.ok(!files.some((entry) => entry.startsWith("engine/tests/")));
  assert.ok(!files.some((entry) => entry.includes("__pycache__")));
  assert.ok(!files.some((entry) => entry.endsWith(".pyc")));
});
