import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { JSDOM } from "jsdom";

const root = path.resolve(__dirname, "..", "..");
const webviewBundle = readFileSync(path.join(root, "dist", "webview", "main.js"), "utf8");

function createHarness() {
  const messages: any[] = [];
  let persisted: any = undefined;
  const dom = new JSDOM(`<!doctype html><html><body><main id="app" aria-busy="true"></main><div id="live-region"></div></body></html>`, {
    runScripts: "outside-only",
    url: "https://webview.invalid/",
  });
  const window = dom.window as any;
  window.acquireVsCodeApi = () => ({
    postMessage: (message: any) => messages.push(message),
    getState: () => persisted,
    setState: (state: any) => { persisted = state; },
  });
  window.prompt = () => "markdown";
  window.requestAnimationFrame = (callback: FrameRequestCallback) => { callback(0); return 1; };
  window.eval(webviewBundle);
  return { dom, window, document: window.document as Document, messages, getPersisted: () => persisted };
}

function snapshot(overrides: any = {}) {
  const finding = {
    findingId: "kspf_test",
    occurrenceId: "occ_test",
    scanId: "scan_test",
    ruleId: "command-injection.shell-execution",
    fingerprint: "test",
    identity: { anchor: "command" },
    title: "Command injection reaches shell",
    summary: "A request value reaches shell execution.",
    severity: { level: "critical", score: 9.8, rationale: "source to sink" },
    confidence: { level: "high", rationale: "direct trace" },
    taxonomy: { category: "command-injection", cwe: ["CWE-78"] },
    locations: [{ path: "src/app.py", startLine: 10, endLine: 10, role: "sink" }],
    remediation: "Use an argument array.",
    validationStatus: "validated",
    triageStatus: "open",
    updatedAt: "2026-07-14T00:00:00Z",
  };
  const scan = {
    id: "scan_test",
    workspace_id: "ws_test",
    mode: "standard",
    scope: ".",
    diff_target_kind: null,
    diff_base_revision: null,
    diff_head_revision: null,
    status: "completed",
    phase: "reporting",
    phase_index: 5,
    artifact_dir: "/tmp/work/.kiro/security-power/artifacts/scan_test",
    target_revision: "abc",
    snapshot_digest: "digest",
    cancellation_requested: false,
    handoff_state: "none",
    failure_code: null,
    failure_message: null,
    started_at: "2026-07-14T00:00:00Z",
    completed_at: "2026-07-14T00:00:02Z",
    created_at: "2026-07-14T00:00:00Z",
    updated_at: "2026-07-14T00:00:02Z",
    files_total: 3,
    files_completed: 3,
    progress: { scan_id: "scan_test", phase_percent: 100, overall_percent: 100, review_items_total: 3, review_items_completed: 3, reportable_findings_count: 1, deep_review_pass: null, message: "Completed", updated_at: "2026-07-14T00:00:02Z" },
    artifacts: [],
    coverage: { completeness: "complete", surfaces: [], explicitExclusions: [], deferred: [] },
  };
  return {
    workspaceTrusted: true,
    workspaceRoot: "/tmp/work",
    engineStatus: "ready",
    dashboard: {
      workspace: { id: "ws_test", root_path: "/tmp/work", display_name: "work", default_scope: ".", default_mode: "standard" },
      engine: { engineVersion: "0.2.0", protocolVersion: "1.0", database: { schemaVersion: 6 }, modes: ["diff", "standard", "deep"], phases: [], exports: [], triageDecisions: [], supports: {}, workspaceRoot: "/tmp/work", stateDirectory: "/tmp/work/.kiro/security-power", product: "Kiro Security Power" },
      activeScan: null,
      selectedScan: scan,
      scans: [scan],
      findings: [finding],
      latestResumableScan: null,
    },
    selectedFinding: null,
    agentIntegration: {
      packaged: true,
      state: "not_configured",
      operation: "idle",
      configured: false,
      verified: false,
      serverName: "kiro-security-power",
      configLocations: [],
      dependencies: { python: { available: true, compatible: true, minimumVersion: "3.9.0", executable: "/usr/bin/python3", version: "3.12.4", sqliteVersion: "3.45.3" } },
      power: { packaged: true, prepared: false, manifestValid: false, registration: "not_prepared", importRequiresKiroConfirmation: true },
      autoApprovePolicy: "read_only",
      details: [],
    },
    secondarySidebarOnboarded: false,
    ...overrides,
  };
}

test("webview harness renders loading, dashboard, empty/error, filtering, and detail actions", () => {
  const harness = createHarness();
  assert.equal(harness.messages[0].type, "ready");
  assert.match(harness.document.body.textContent ?? "", /Connecting/);

  harness.window.dispatchEvent(new harness.window.MessageEvent("message", { data: { type: "snapshot", snapshot: snapshot() } }));
  assert.match(harness.document.body.textContent ?? "", /Fast \(deterministic\)/);
  assert.match(harness.document.body.textContent ?? "", /1\s*findings/);
  assert.ok(harness.document.querySelector('[aria-label="Security panel sections"]'));
  const initialMode = harness.document.getElementById("scan-mode") as HTMLSelectElement;
  assert.equal(initialMode.value, "fast");
  const unchangedMode = initialMode;
  harness.window.dispatchEvent(new harness.window.MessageEvent("message", { data: { type: "snapshot", snapshot: snapshot() } }));
  assert.equal(harness.document.getElementById("scan-mode"), unchangedMode, "unchanged snapshots should not replace the DOM");
  initialMode.value = "deep";
  initialMode.dispatchEvent(new harness.window.Event("change", { bubbles: true }));
  assert.equal(harness.document.getElementById("start-scan")?.textContent, "Continue in Kiro Agent");
  (harness.document.getElementById("start-scan") as HTMLElement).click();
  assert.deepEqual({ type: harness.messages.at(-1).type, mode: harness.messages.at(-1).mode, profile: harness.messages.at(-1).analysisProfile }, { type: "startScan", mode: "deep", profile: "model" });

  (harness.document.getElementById("scan-scope") as HTMLInputElement).value = "src/custom";
  const renamed = snapshot();
  renamed.dashboard = { ...renamed.dashboard, workspace: { ...renamed.dashboard.workspace, display_name: "renamed" } };
  harness.window.dispatchEvent(new harness.window.MessageEvent("message", { data: { type: "snapshot", snapshot: renamed } }));
  assert.equal((harness.document.getElementById("scan-scope") as HTMLInputElement).value, "src/custom", "edited inputs survive snapshot re-renders");

  const labeled = snapshot();
  const modelScan = { ...labeled.dashboard.selectedScan, capabilities: { analysisProfile: "model" } };
  const fastScan = { ...modelScan, id: "scan_fast", status: "running", capabilities: { analysisProfile: "fast" } };
  labeled.dashboard.activeScan = fastScan;
  labeled.dashboard.selectedScan = modelScan;
  labeled.dashboard.scans = [fastScan, modelScan];
  harness.window.dispatchEvent(new harness.window.MessageEvent("message", { data: { type: "snapshot", snapshot: labeled } }));
  assert.match(harness.document.querySelector(".active-scan")?.textContent ?? "", /Fast \(deterministic\)/);
  (harness.document.querySelector('[data-tab="history"]') as HTMLElement).click();
  assert.match(harness.document.querySelector(".history-list")?.textContent ?? "", /Fast \(deterministic\).*Standard \(Kiro Agent\)/s);

  (harness.document.querySelector('[data-tab="findings"]') as HTMLElement).click();
  assert.match(harness.document.body.textContent ?? "", /Command injection reaches shell/);
  assert.ok(harness.document.querySelector(".badge-critical"));
  assert.equal(harness.document.querySelector('[role="listitem"]'), null);
  (harness.document.querySelector('.severity-summary [data-severity="critical"]') as HTMLElement).click();
  assert.equal(harness.getPersisted().filters.severity, "critical");
  assert.equal(harness.document.querySelector('.severity-summary [data-severity="critical"]')?.getAttribute("aria-pressed"), "true");
  assert.equal((harness.document.getElementById("filter-severity") as HTMLSelectElement).value, "critical", "severity chips drive the severity filter");
  assert.match(harness.document.body.textContent ?? "", /Command injection reaches shell/);
  (harness.document.querySelector('.severity-summary [data-severity="critical"]') as HTMLElement).click();
  assert.equal(harness.getPersisted().filters.severity, "");
  const query = harness.document.getElementById("filter-query") as HTMLInputElement;
  query.value = "does-not-match";
  query.dispatchEvent(new harness.window.Event("input", { bubbles: true }));
  assert.match(harness.document.body.textContent ?? "", /No matching findings/);
  assert.equal(harness.getPersisted().filters.query, "does-not-match");

  const queryAfterRender = harness.document.getElementById("filter-query") as HTMLInputElement;
  queryAfterRender.value = "command";
  queryAfterRender.dispatchEvent(new harness.window.Event("input", { bubbles: true }));
  (harness.document.querySelector('[data-action="finding"]') as HTMLElement).click();
  assert.equal(harness.messages.at(-1).type, "openFinding");

  const detail = {
    ...snapshot().dashboard.findings[0],
    details: { sourceToSink: true },
    codeEvidence: [{ id: "ev", kind: "code", label: "Sink", path: "src/app.py", startLine: 10, endLine: 10, role: "sink", code: "subprocess.run(user, shell=True)", explanation: "Direct shell sink" }],
    validation: { id: "val", status: "validated", method: "static_trace", rationale: "Direct trace", evidence: [], createdAt: "2026-07-14T00:00:01Z" },
    attackPath: { id: "path", narrative: "Request to shell", path: [], exploitability: "high", impact: "command execution", severityRationale: "critical" },
    triage: null,
    remediationRecords: [],
    trackingRecords: [],
    artifactLinks: [],
    relatedFindings: [],
  };
  harness.window.dispatchEvent(new harness.window.MessageEvent("message", { data: { type: "snapshot", snapshot: snapshot({ selectedFinding: detail }) } }));
  assert.match(harness.document.body.textContent ?? "", /Direct shell sink/);
  (harness.document.querySelector('[data-action="open-source"]') as HTMLElement).click();
  assert.equal(harness.messages.at(-1).type, "openSource");
  (harness.document.querySelector('[data-action="export-finding"]') as HTMLElement).click();
  assert.equal(harness.messages.at(-1).type, "exportFinding");
  const beforeRisk = harness.messages.length;
  (harness.document.querySelector('[data-action="triage"][data-decision="accepted_risk"]') as HTMLElement).click();
  assert.equal(harness.messages.length, beforeRisk, "accepted risk requires an audit note");
  (harness.document.getElementById("triage-note") as HTMLTextAreaElement).value = "Compensating control is documented.";
  (harness.document.querySelector('[data-action="triage"][data-decision="accepted_risk"]') as HTMLElement).click();
  assert.equal(harness.messages.at(-1).note, "Compensating control is documented.");
  (harness.document.querySelector('[data-action="tracking"]') as HTMLElement).click();
  assert.equal(harness.messages.at(-1).type, "createTrackingHandoff");
  assert.equal(harness.messages.at(-1).provider, "manual");

  harness.window.dispatchEvent(new harness.window.MessageEvent("message", { data: { type: "navigate", tab: "setup" } }));
  assert.equal(harness.getPersisted().tab, "setup");
  assert.match(harness.document.body.textContent ?? "", /Connect Kiro Agent/);
  assert.match(harness.document.body.textContent ?? "", /read-only lookups only/i);
  assert.ok(harness.document.querySelector("#setup-installation-options"));
  assert.ok(harness.document.querySelector("#setup-power"));
  assert.equal(harness.document.querySelectorAll(".agent-setup > .button-row button").length, 1);
  (harness.document.querySelector('[data-action="install-agent"]') as HTMLElement).click();
  const installMessage = harness.messages.at(-1);
  assert.equal(installMessage.type, "installAgentIntegration");
  assert.equal(installMessage.scope, "workspace");
  assert.equal(installMessage.autoApprovePolicy, "read_only");

  const configured = snapshot();
  configured.agentIntegration = { ...configured.agentIntegration, configured: true, state: "needs_repair", configScope: "user", autoApprovePolicy: "none" };
  harness.window.dispatchEvent(new harness.window.MessageEvent("message", { data: { type: "snapshot", snapshot: configured } }));
  assert.equal((harness.document.getElementById("agent-scope") as HTMLSelectElement).value, "user");
  assert.equal((harness.document.getElementById("agent-scope") as HTMLSelectElement).disabled, true);
  assert.equal((harness.document.getElementById("agent-auto-approve") as HTMLSelectElement).value, "none");
  const advanced = harness.document.getElementById("setup-troubleshooting") as HTMLDetailsElement;
  advanced.open = true;
  advanced.dispatchEvent(new harness.window.Event("toggle"));
  harness.window.dispatchEvent(new harness.window.MessageEvent("message", { data: { type: "snapshot", snapshot: configured } }));
  assert.equal((harness.document.getElementById("setup-troubleshooting") as HTMLDetailsElement).open, true);
  (harness.document.getElementById("setup-primary-action") as HTMLButtonElement).focus();
  const checking = { ...configured, agentIntegration: { ...configured.agentIntegration, operation: "checking" } };
  harness.window.dispatchEvent(new harness.window.MessageEvent("message", { data: { type: "snapshot", snapshot: checking } }));
  assert.equal((harness.document.getElementById("setup-primary-action") as HTMLButtonElement).disabled, true);
  harness.window.dispatchEvent(new harness.window.MessageEvent("message", { data: { type: "snapshot", snapshot: configured } }));
  assert.equal((harness.document.activeElement as HTMLElement).id, "setup-primary-action");
  (harness.document.querySelector('.agent-setup > .button-row [data-action="install-agent"]') as HTMLElement).click();
  assert.equal(harness.messages.at(-1).type, "installAgentIntegration");
  assert.equal(harness.messages.at(-1).scope, "user");
  assert.equal(harness.messages.at(-1).autoApprovePolicy, "none");

  const blocked = snapshot({ workspaceTrusted: false, engineStatus: "stopped" });
  harness.window.dispatchEvent(new harness.window.MessageEvent("message", { data: { type: "snapshot", snapshot: blocked } }));
  const checks = harness.document.getElementById("setup-environment") as HTMLDetailsElement;
  assert.equal(checks.open, true);
  checks.open = false;
  checks.dispatchEvent(new harness.window.Event("toggle"));
  blocked.engineStatus = "error";
  harness.window.dispatchEvent(new harness.window.MessageEvent("message", { data: { type: "snapshot", snapshot: blocked } }));
  assert.equal((harness.document.getElementById("setup-environment") as HTMLDetailsElement).open, false);
  assert.equal((harness.document.querySelector('.agent-setup > .button-row [data-action="install-agent"]') as HTMLButtonElement).disabled, true);

  const verified = snapshot();
  verified.agentIntegration = { ...verified.agentIntegration, configured: true, verified: true, state: "verified", configScope: "workspace" };
  harness.window.dispatchEvent(new harness.window.MessageEvent("message", { data: { type: "snapshot", snapshot: verified } }));
  assert.match(harness.document.querySelector(".setup-status")?.textContent ?? "", /Start a new Kiro Agent conversation/);
  assert.equal(harness.document.querySelectorAll(".agent-setup > .button-row").length, 0);
  assert.ok(harness.document.querySelector('#setup-troubleshooting [data-action="verify-agent"]'));

  harness.window.dispatchEvent(new harness.window.MessageEvent("message", { data: { type: "snapshot", snapshot: snapshot({ engineStatus: "error", engineError: "Python missing", dashboard: null }) } }));
  assert.match(harness.document.body.textContent ?? "", /Python missing/);
  (harness.document.querySelector('[data-action="retry-engine"]') as HTMLElement).click();
  assert.equal(harness.messages.at(-1).type, "retryEngine");
});

test("packaged webview CSP and styles exclude remote script sources and include accessibility themes", () => {
  const provider = readFileSync(path.join(root, "packages", "extension", "src", "webviewProvider.ts"), "utf8");
  const styles = readFileSync(path.join(root, "packages", "webview", "src", "styles.css"), "utf8");
  assert.match(provider, /default-src 'none'/);
  assert.match(provider, /script-src 'nonce-/);
  assert.doesNotMatch(provider, /unsafe-inline|https?:\/\//);
  assert.match(styles, /--vscode-/);
  assert.match(styles, /forced-colors: active/);
  assert.match(styles, /focus-visible/);
  assert.doesNotMatch(styles, /font-size:\s*[89]px/);
});
