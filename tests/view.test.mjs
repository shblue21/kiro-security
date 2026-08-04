import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  loadSetupViewHtmlModule,
  require,
  TEST_SERVER_KEY,
} from "./support.mjs";

test("setup view connects steering, direct MCP, and Hook without Agent or Power import", () => {
  const setup = readFileSync("packages/extension/src/setupView.ts", "utf8");
  const setupHtml = readFileSync(
    "packages/extension/src/setupViewHtml.ts",
    "utf8",
  );
  const setupSurface = `${setup}\n${setupHtml}`;
  const extension = readFileSync("packages/extension/src/extension.ts", "utf8");
  const integration = readFileSync("packages/extension/src/integration.ts", "utf8");
  const chatBinding = readFileSync(
    "packages/extension/src/chatBinding.ts",
    "utf8",
  );
  assert.match(setup, /enableScripts: true/);
  assert.match(setupSurface, /connectIntegration/);
  assert.match(setupSurface, /showMcpFile/);
  assert.match(setupSurface, /showSteeringFile/);
  assert.doesNotMatch(setupSurface, /showPermissionsFile/);
  assert.match(setupHtml, /Chat approvals/);
  assert.match(setup, /exact Kiro Trust rules/);
  assert.match(setup, /No custom Agent configuration is installed/);
  assert.doesNotMatch(setupSurface, /preparePowerIntegration/);
  assert.doesNotMatch(setupSurface, /verifyIntegration|Verify again/);
  assert.match(setupHtml, /<style>\$\{setupStyles\(\)\}<\/style>/);
  assert.match(setupHtml, /<script nonce="\$\{nonce\}">/);
  assert.match(setupHtml, /Content-Security-Policy/);
  assert.doesNotMatch(setup, /<!doctype html>|function setupStyles/);
  assert.match(extension, /getOrCreateInstallationServerKey/);
  assert.match(extension, /new SecuritySetupView\(/);
  assert.doesNotMatch(integration, /before\.state === "mismatch"/);
  assert.equal((integration.match(/resolvePythonExecutable\(\)/g) ?? []).length, 1);
  assert.doesNotMatch(chatBinding, /resolvePythonExecutable/);
  assert.doesNotMatch(integration, /WorkbenchAdminClient/);
  assert.match(setup, /new WorkbenchAdminClient\(/);
  assert.match(setupHtml, /input\.integration\.state === "unavailable"[\s\S]*\? "disabled"/);
});

test("integration manager coalesces concurrent Python resolution", async () => {
  const Module = require("node:module");
  const originalLoad = Module._load;
  const pythonRuntimePath = require.resolve(
    "../out/packages/extension/src/pythonRuntime.js",
  );
  const integrationPath = require.resolve(
    "../out/packages/extension/src/integration.js",
  );
  Module._load = function loadWithVscodeStub(request, parent, isMain) {
    if (request === "vscode") {
      return {};
    }
    return originalLoad.call(this, request, parent, isMain);
  };
  const pythonRuntime = require(pythonRuntimePath);
  const originalResolver = pythonRuntime.resolvePythonExecutable;
  let resolutions = 0;
  let selectedPython = "/runtime/python3";
  pythonRuntime.resolvePythonExecutable = async () => {
    resolutions += 1;
    return selectedPython;
  };
  delete require.cache[integrationPath];
  try {
    const { KiroIntegrationManager } = require(integrationPath);
    const manager = new KiroIntegrationManager(
      { extensionUri: { fsPath: "/extension" } },
      {
        stateRoot: { fsPath: "/global/state" },
        scanRoot: { fsPath: "/global/state/scans" },
      },
      TEST_SERVER_KEY,
    );
    const resolved = await Promise.all([
      manager.getPythonExecutable(),
      manager.getPythonExecutable(),
      manager.getPythonExecutable(),
    ]);
    assert.deepEqual(resolved, [
      "/runtime/python3",
      "/runtime/python3",
      "/runtime/python3",
    ]);
    assert.equal(resolutions, 1);
    selectedPython = "/runtime/python3-updated";
    assert.equal(
      await manager.getPythonExecutable(),
      "/runtime/python3-updated",
    );
    assert.equal(resolutions, 2);
  } finally {
    Module._load = originalLoad;
    pythonRuntime.resolvePythonExecutable = originalResolver;
    delete require.cache[integrationPath];
  }
});

test("Dashboard and Findings render exact recovery and follow-up controls", () => {
  const { renderSetupHtml } = loadSetupViewHtmlModule();
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
