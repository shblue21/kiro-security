import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  loadSetupViewHtmlModule,
  require,
  TEST_SERVER_KEY,
} from "./support.mjs";

test("setup view connects steering, direct MCP, and Hook without Agent or Power import", () => {
  const setup = readFileSync("packages/extension/src/view/setupView.ts", "utf8");
  const setupHtml = readFileSync(
    "packages/extension/src/view/setupViewHtml.ts",
    "utf8",
  );
  const setupScript = readFileSync(
    "packages/extension/src/view/setupViewScript.ts",
    "utf8",
  );
  const setupSurface = `${setup}\n${setupHtml}\n${setupScript}`;
  const extension = readFileSync("packages/extension/src/extension.ts", "utf8");
  const integration = readFileSync(
    "packages/extension/src/integration/integration.ts",
    "utf8",
  );
  assert.match(setup, /enableScripts: true/);
  assert.doesNotMatch(setup, /localResourceRoots|asWebviewUri/);
  assert.match(setupSurface, /connectIntegration/);
  assert.match(setupSurface, /copyScanPrompt/);
  assert.match(setupSurface, /showMcpFile/);
  assert.match(setupSurface, /showSteeringFile/);
  assert.doesNotMatch(setupSurface, /showPermissionsFile/);
  assert.doesNotMatch(setupSurface, /preparePowerIntegration/);
  assert.doesNotMatch(setupSurface, /verifyIntegration|Verify again/);
  assert.match(setupHtml, /<style>\$\{setupStyles\(\)\}<\/style>/);
  assert.match(
    setupHtml,
    /<script nonce="\$\{nonce\}">\$\{setupViewScript\(input\.activeTab\)\}<\/script>/,
  );
  assert.match(setupHtml, /Content-Security-Policy/);
  assert.match(extension, /getOrCreateInstallationServerKey/);
  assert.match(extension, /if \(!isSupportedKiroHost\(vscode\.env\)\)/);
  assert.ok(
    extension.indexOf("if (!isSupportedKiroHost(vscode.env))") <
      extension.indexOf("prepareFoundationStorage(context)"),
  );
  assert.match(extension, /new SecuritySetupView\(/);
  assert.doesNotMatch(extension, /promptForPendingUpdate/);
  assert.match(setup, /await this\.integration\.install\(\)/);
  assert.doesNotMatch(setup, /showWarningMessage/);
  assert.doesNotMatch(integration, /before\.state === "mismatch"/);
  assert.match(setup, /context\.workspaceState\.get<RepositoryScope>/);
  assert.match(setup, /vscode\.workspace\.workspaceFolders/);
  assert.match(setup, /dashboard: projectedDashboard/);
  assert.match(setup, /requireWorkspaceScanForOccurrence/);
  assert.match(setupHtml, /data-command="selectRepositoryScope"/);
  assert.doesNotMatch(setupHtml, /data-path=/);
  assert.doesNotMatch(setupHtml, /data-command="selectTab"/);
  assert.match(setupScript, /vscode\.setState\(\{ activeTab: name \}\)/);
  assert.match(setupScript, /vscode\.getState\(\)\?\.activeTab/);
  for (const key of ["ArrowRight", "ArrowLeft", "Home", "End"]) {
    assert.match(setupScript, new RegExp(`event\\.key === '${key}'`));
  }
  assert.match(
    setup,
    /if \(message\.command === "selectTab"\)[\s\S]*return;[\s\S]*if \(this\.busy\)/,
  );
});

test("host detection is deterministic and unsupported hosts render read-only guidance", () => {
  const { isSupportedKiroHost } = require(
    "../out/packages/extension/src/hostEnvironment.js",
  );
  const { renderUnsupportedHostHtml } = require(
    "../out/packages/extension/src/view/unsupportedHostView.js",
  );

  assert.equal(isSupportedKiroHost({ appName: "Kiro", uriScheme: "kiro" }), true);
  assert.equal(
    isSupportedKiroHost({ appName: "Visual Studio Code", uriScheme: "vscode" }),
    false,
  );
  assert.equal(isSupportedKiroHost({ appName: "Cursor", uriScheme: "cursor" }), false);

  const html = renderUnsupportedHostHtml({ cspSource: "vscode-webview:" });
  assert.match(html, /Kiro IDE is required/);
  assert.doesNotMatch(html, /connectIntegration|<script/);
  assert.match(
    html,
    /content="default-src 'none'; style-src vscode-webview: 'unsafe-inline'"/,
  );
});

test("integration manager coalesces concurrent Python resolution", async () => {
  const Module = require("node:module");
  const originalLoad = Module._load;
  const pythonRuntimePath = require.resolve(
    "../out/packages/extension/src/integration/pythonRuntime.js",
  );
  const integrationPath = require.resolve(
    "../out/packages/extension/src/integration/integration.js",
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
      {
        extensionUri: { fsPath: "/extension" },
        extension: { packageJSON: { version: "0.1.0" } },
      },
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
    {
      id: "scan-failed",
      workspaceId: "workspace-failed",
      status: "failed",
      phase: "validation",
      mode: "standard",
      scope: ".",
      scanDir: "/global/scans/failed",
      startedAt: "2026-07-30T00:00:00Z",
      updatedAt: "2026-07-30T00:03:00Z",
      target: {
        path: "/source/failed",
        revision: "failed-revision",
      },
      progress: {
        reviewItemsTotal: 40,
        reviewItemsCompleted: 40,
        reportableFindingsCount: 40,
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
      {
        occurrenceId: "occurrence-info",
        findingId: "finding-info",
        scanId: "scan-two",
        title: "Informational observation",
        summary: "Not reportable.",
        severity: "informational",
        confidence: "high",
        remediation: "No action required.",
        locations: [],
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
  const renderInput = {
    webview: { cspSource: "vscode-webview:" },
    stateRoot: "/global",
    integration,
    activeTab: "findings",
    dashboard,
    repositoryScope: "all",
    workspaceLabel: "Current workspace: alpha",
    hasWorkspace: true,
    globalScanCount: scans.length,
    sourceActionScanIds: ["scan-one", "scan-two", "scan-failed"],
  };
  const html = renderSetupHtml(renderInput);

  assert.match(html, /id="scan-filter"/);
  assert.match(html, /data-scan-id="scan-two"/);
  assert.match(html, /\/source\/beta/);
  assert.match(html, /beta-revision/);
  assert.match(html, /data-command="copyRemediationPrompt"/);
  assert.match(html, /data-command="cancelRecovery"/);
  assert.match(html, /data-request-id="recovery-one"/);
  assert.match(html, /data-command="trackFinding"/);
  assert.match(html, /data-artifact-kind="report"/);
  assert.match(html, /role="progressbar"/);
  assert.match(html, /data-od-id="run-security-scan"/);
  assert.match(html, /data-command="copyScanPrompt"/);
  assert.match(html, /class="dashboard-summary"/);
  assert.match(html, /class="scan-card"/);
  assert.match(html, /Filter findings/);
  assert.doesNotMatch(html, /<span class="eyebrow">(?:Workbench|Validated results)<\/span>/);
  assert.ok(
    html.indexOf('data-command="copyRemediationPrompt"') <
      html.indexOf('data-command="closeTriage"'),
    "remediation should appear before triage actions",
  );
  assert.match(
    html,
    /id="tab-findings"[^>]*aria-controls="panel-findings"[^>]*aria-selected="true"[^>]*tabindex="0"/,
  );
  assert.match(
    html,
    /id="tab-setup"[^>]*aria-controls="panel-setup"[^>]*aria-selected="false"[^>]*tabindex="-1"/,
  );
  assert.match(
    html,
    /id="panel-findings"[^>]*aria-labelledby="tab-findings"(?![^>]*hidden)/,
  );
  assert.match(
    html,
    /id="panel-dashboard"[^>]*aria-labelledby="tab-dashboard"[^>]*hidden/,
  );
  assert.match(html, /id="finding-filter-summary"/);
  assert.match(
    html,
    /<span>Reportable findings<\/span>\s*<strong>1<\/strong>/,
  );

  const needsAttentionHtml = renderSetupHtml({
    ...renderInput,
    integration: {
      ...integration,
      state: "mismatch",
      runtime: { ready: false, detail: "Runtime update required." },
    },
    activeTab: "setup",
  });
  assert.match(
    needsAttentionHtml,
    /class="summary-status pending">5\/6 needs attention<\/span>/,
  );
  assert.doesNotMatch(needsAttentionHtml, /data-od-id="run-security-scan"/);

  const { projectDashboard } = require(
    "../out/packages/extension/src/workbench/workspaceProjection.js",
  );
  const currentHtml = renderSetupHtml({
    webview: { cspSource: "vscode-webview:" },
    stateRoot: "/global",
    integration,
    activeTab: "dashboard",
    dashboard: projectDashboard(dashboard, ["/source/alpha"], "current"),
    repositoryScope: "current",
    workspaceLabel: "Current workspace: alpha",
    hasWorkspace: true,
    globalScanCount: scans.length,
    sourceActionScanIds: ["scan-one"],
  });
  assert.match(currentHtml, /\/source\/alpha/);
  assert.doesNotMatch(currentHtml, /\/source\/beta|beta-revision|scan-two/);

  const emptyCurrentHtml = renderSetupHtml({
    webview: { cspSource: "vscode-webview:" },
    stateRoot: "/global",
    integration,
    activeTab: "dashboard",
    dashboard: projectDashboard(dashboard, ["/source/gamma"], "current"),
    repositoryScope: "current",
    workspaceLabel: "Current workspace: gamma",
    hasWorkspace: true,
    globalScanCount: scans.length,
    sourceActionScanIds: [],
  });
  assert.match(emptyCurrentHtml, /3 scans are available in other repositories/);
  assert.match(emptyCurrentHtml, /data-repository-scope="all"/);

  const noWorkspaceHtml = renderSetupHtml({
    webview: { cspSource: "vscode-webview:" },
    stateRoot: "/global",
    integration,
    activeTab: "dashboard",
    dashboard: projectDashboard(dashboard, [], "current"),
    repositoryScope: "current",
    workspaceLabel: "Current workspaces (0)",
    hasWorkspace: false,
    globalScanCount: scans.length,
    sourceActionScanIds: [],
  });
  assert.match(noWorkspaceHtml, /No workspace is open/);

  const allWithOutsideActionsBlocked = renderSetupHtml({
    webview: { cspSource: "vscode-webview:" },
    stateRoot: "/global",
    integration,
    activeTab: "findings",
    dashboard,
    repositoryScope: "all",
    workspaceLabel: "Current workspace: alpha",
    hasWorkspace: true,
    globalScanCount: scans.length,
    sourceActionScanIds: ["scan-one"],
  });
  assert.match(allWithOutsideActionsBlocked, /<button disabled[^>]*>Generate fix<\/button>/);
  assert.doesNotMatch(
    allWithOutsideActionsBlocked,
    /data-command="copyRemediationPrompt"/,
  );
  assert.match(allWithOutsideActionsBlocked, /data-command="trackFinding"/);
  assert.match(allWithOutsideActionsBlocked, /data-command="exportScan"/);
});

test("workspace projection excludes unrelated repositories and linked requests", () => {
  const { projectDashboard, isScanInWorkspace } = require(
    "../out/packages/extension/src/workbench/workspaceProjection.js",
  );
  const scan = (id, target, scope = ".") => ({
    id,
    workspaceId: `workspace-${id}`,
    status: "complete",
    phase: "reporting",
    mode: "standard",
    scope,
    scanDir: `/global/${id}`,
    startedAt: "2026-08-11T00:00:00Z",
    updatedAt: "2026-08-11T00:00:00Z",
    target: { path: target, revision: "revision" },
    progress: {
      reviewItemsTotal: 1,
      reviewItemsCompleted: 1,
      reportableFindingsCount: 1,
    },
  });
  const alpha = scan("alpha", "/source/alpha");
  const beta = scan("beta", "/source/beta");
  const monorepo = scan("nested", "/source/mono", "packages/app");
  const dashboard = {
    scans: [alpha, beta, monorepo],
    findings: [
      { occurrenceId: "occ-alpha", scanId: "alpha" },
      { occurrenceId: "occ-beta", scanId: "beta" },
    ],
    recoveryRequests: [
      { id: "recovery-alpha", scanId: "alpha" },
      { id: "recovery-beta", scanId: "beta" },
    ],
    remediationRequests: [
      { requestId: "remediation-alpha", occurrenceId: "occ-alpha" },
      { requestId: "remediation-beta", occurrenceId: "occ-beta" },
    ],
  };

  const projected = projectDashboard(dashboard, ["/source/alpha"], "current");
  assert.deepEqual(projected.scans.map((item) => item.id), ["alpha"]);
  assert.deepEqual(projected.findings.map((item) => item.occurrenceId), [
    "occ-alpha",
  ]);
  assert.deepEqual(projected.recoveryRequests.map((item) => item.id), [
    "recovery-alpha",
  ]);
  assert.deepEqual(
    projected.remediationRequests.map((item) => item.requestId),
    ["remediation-alpha"],
  );
  assert.equal(
    isScanInWorkspace(monorepo, ["/source/mono/packages/app"]),
    true,
  );
  assert.equal(
    isScanInWorkspace(alpha, ["/source/application"]),
    false,
  );
  assert.equal(projectDashboard(dashboard, [], "current").scans.length, 0);
  assert.equal(projectDashboard(dashboard, [], "all").scans.length, 3);
  assert.deepEqual(
    projectDashboard(
      dashboard,
      ["/source/alpha", "/source/beta"],
      "current",
    ).scans.map((item) => item.id),
    ["alpha", "beta"],
  );
});

test("tracking action creates a durable backend request before copying a prompt", () => {
  const setup = readFileSync("packages/extension/src/view/setupView.ts", "utf8");
  assert.match(
    setup,
    /callWorkbench<[\s\S]*?>\("createTracking", \{\s*occurrenceId: exactOccurrence/,
  );
  assert.match(setup, /Tracking request: \$\{tracking\.requestId\}/);
  assert.match(setup, /Expected version: \$\{tracking\.version\}/);
  assert.match(setup, /Claim and deliver the exact tracking request/);
});
