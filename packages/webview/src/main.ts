import { filterAndSortFindings, FindingFilters, progressLabel } from "./state";

declare function acquireVsCodeApi<T = unknown>(): {
  postMessage(message: unknown): void;
  getState(): T | undefined;
  setState(state: T): void;
};

type Tab = "setup" | "dashboard" | "findings" | "history";
interface PersistedState {
  tab: Tab;
  filters: FindingFilters;
  agentScope?: "workspace" | "user";
  agentAutoApprove?: "none" | "read_only";
}
interface SetupFocus {
  id?: string;
  action?: string;
  actionIndex: number;
  occurrenceId?: string;
  summary?: string;
  tab?: string;
}

const vscode = acquireVsCodeApi<PersistedState>();
const app = document.getElementById("app");
const liveRegion = document.getElementById("live-region");
const saved = vscode.getState();
const ui: PersistedState = saved ?? {
  tab: "dashboard",
  filters: { query: "", severity: "", confidence: "", validation: "", triage: "", sort: "severity" },
  agentScope: "workspace",
  agentAutoApprove: "read_only",
};
if (ui.tab === "history") ui.tab = "dashboard";
let snapshot: any = null;
let lastEvent = "";
let agentOptionsDirty = false;
let lastRenderKey = "";
const setupDisclosureState = new Map<string, boolean>();
let pendingSetupFocus: SetupFocus | undefined;

function h(value: unknown): string {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function attr(value: unknown): string { return h(value); }
function post(message: unknown): void { vscode.postMessage(message); }
function persist(): void { vscode.setState(ui); }
function date(value: unknown): string {
  if (!value) return "—";
  const parsed = new Date(String(value));
  return Number.isNaN(parsed.valueOf()) ? String(value) : parsed.toLocaleString();
}
function elapsed(scan: any): string {
  if (!scan?.started_at) return "—";
  const end = scan.completed_at ? Date.parse(scan.completed_at) : Date.now();
  const total = Math.max(0, Math.round((end - Date.parse(scan.started_at)) / 1000));
  const minutes = Math.floor(total / 60);
  const seconds = total % 60;
  return minutes ? `${minutes}m ${seconds}s` : `${seconds}s`;
}
function badge(text: unknown, kind = "neutral"): string {
  return `<span class="badge badge-${attr(kind)}">${h(text)}</span>`;
}
function statusBadge(status: string): string {
  const kind = ["completed", "validated", "ready", "verified"].includes(status) ? "success"
    : ["failed", "rejected", "critical", "high", "error"].includes(status) ? "danger"
      : ["running", "needs_review", "needs_repair", "configured"].includes(status) ? "warning" : "neutral";
  return badge(status.replaceAll("_", " "), kind);
}
function severityBadge(level: string): string {
  return badge(level, level === "critical" ? "critical" : level === "high" ? "danger" : level === "medium" ? "warning" : "neutral");
}
function severitySummary(findings: any[]): string {
  const levels: Array<[string, string, string]> = [["critical", "C", "critical"], ["high", "H", "danger"], ["medium", "M", "warning"], ["low", "L", "neutral"], ["informational", "I", "neutral"]];
  return `<div class="severity-summary" role="group" aria-label="Finding counts by severity">${levels.map(([level, prefix, kind]) => {
    const count = findings.filter((finding) => finding.severity?.level === level).length;
    const active = ui.filters.severity === level;
    return `<button class="badge badge-${kind}" data-action="filter-severity" data-severity="${level}" aria-pressed="${active}" title="${active ? "Clear severity filter" : `Show only ${level} findings`}">${prefix} ${count}</button>`;
  }).join("")}</div>`;
}
function scanLabel(scan: any): string {
  if (scan?.mode === "diff") return "Diff (Kiro Agent)";
  return `${scan?.mode === "deep" ? "Deep" : "Standard"} (Kiro Agent)`;
}

function nav(): string {
  return `<nav class="tabs" aria-label="Security panel sections">
    ${(["setup", "dashboard", "findings"] as Tab[]).map((tab) =>
      `<button class="tab ${ui.tab === tab ? "active" : ""}" data-tab="${tab}" ${ui.tab === tab ? `aria-current="page"` : ""}>${tab[0].toUpperCase()}${tab.slice(1)}</button>`).join("")}
  </nav>`;
}

function shell(content: string): string {
  return `<header class="topbar"><div><h1>Kiro Security Power</h1><p>${snapshot?.dashboard?.workspace?.display_name ? h(snapshot.dashboard.workspace.display_name) : "Repository security"}</p></div>
    <button class="icon-button" data-action="refresh" title="Refresh" aria-label="Refresh security state">↻</button></header>
    ${nav()}${snapshot?.engineError ? `<section class="global-error" role="alert"><strong>Engine error</strong><span>${h(snapshot.engineError)}</span><div class="button-row"><button data-action="retry-engine">Retry</button><button data-action="settings">Configure</button><button data-action="logs">Logs</button></div></section>` : ""}<section class="content">${content}</section>`;
}

function setupView(): string {
  const dashboard = snapshot?.dashboard;
  const integration = snapshot?.agentIntegration ?? {};
  const python = integration.dependencies?.python ?? {};
  const busy = integration.operation && integration.operation !== "idle";
  const integrationHealthy = integration.state === "verified";
  const powerImportRequired = integration.power?.registration === "import_required";
  const integrationLabel = integrationHealthy
    ? `Verified · ${integration.configScope ?? "workspace"} scope`
    : integration.state === "configured"
      ? powerImportRequired ? "MCP checked; native Power import required" : "Power detected; verification required"
      : integration.state === "needs_repair"
        ? "Needs repair"
        : integration.state === "error"
          ? `Error${integration.lastError ? ` · ${integration.lastError}` : ""}`
          : "Not installed";
  const pythonLabel = python.available
    ? `Python ${python.version ?? "detected"}${python.sqliteVersion ? ` · SQLite ${python.sqliteVersion}` : ""} · ${python.executable ?? ""}`
    : python.error ?? "Python 3.9+ with sqlite3 was not found";
  const hasWorkspace = Boolean(snapshot?.workspaceRoot ?? dashboard?.workspace?.root_path);
  const pythonReady = Boolean(python.available && python.compatible);
  const gitAvailable = Boolean(dashboard?.engine?.dependencies?.git?.available);
  const setupReady = hasWorkspace && Boolean(snapshot?.workspaceTrusted) && pythonReady;
  const checks: Array<[string, string, "ok" | "pending" | "neutral"]> = [
    ["Workspace", snapshot?.workspaceRoot ?? dashboard?.workspace?.root_path ?? "Open a local folder to continue", hasWorkspace ? "ok" : "pending"],
    ["Workspace trust", snapshot?.workspaceTrusted ? "Trusted" : "Trust this workspace in Kiro to continue", snapshot?.workspaceTrusted ? "ok" : "pending"],
    ["Scan engine", snapshot?.engineStatus ?? "stopped", snapshot?.engineStatus === "ready" ? "ok" : "neutral"],
    ["Python / SQLite", pythonLabel, pythonReady ? "ok" : "pending"],
    ["Git (optional)", gitAvailable ? "Available for Git changes scans" : "Not found; only Git changes scans need it", gitAvailable ? "ok" : "neutral"],
  ];
  if (agentOptionsDirty && integration.configured && !busy
    && integration.configScope === ui.agentScope && integration.autoApprovePolicy === ui.agentAutoApprove) agentOptionsDirty = false;
  const configuredScope = integration.configured && !agentOptionsDirty
    ? integration.configScope ?? ui.agentScope ?? "workspace"
    : ui.agentScope ?? integration.configScope ?? "workspace";
  const configuredPolicy = integration.configured && !agentOptionsDirty
    ? integration.autoApprovePolicy ?? ui.agentAutoApprove ?? "read_only"
    : ui.agentAutoApprove ?? integration.autoApprovePolicy ?? "read_only";
  const repairRequired = integration.state === "needs_repair" || integration.state === "error";
  const primaryAction = integration.configured && !repairRequired ? "verify-agent" : "install-agent";
  const operationLabel = busy
    ? `Working: ${String(integration.operation).replaceAll("_", " ")}…`
    : !integration.configured ? "Install and verify"
      : repairRequired ? "Repair and verify"
        : integrationHealthy ? "Verify again" : "Verify setup";
  const statusRole = integration.state === "error" ? `role="alert"`
    : busy && integration.operation !== "checking" ? `role="status"` : "";
  return `<div class="stack">
    <section class="card agent-setup" aria-busy="${busy ? "true" : "false"}"><div class="card-title"><div><h2>Connect Kiro Agent</h2><p>Connect once, then request repository security scans from Kiro Agent chat.</p></div>${statusBadge(integration.state ?? "not_configured")}</div>
      <p class="setup-status" ${statusRole}><strong>${h(busy ? operationLabel : integrationLabel)}</strong>${integrationHealthy && !busy ? " · Native Power and MCP tools are ready. Start a new Kiro Agent conversation, then ask for a Standard, Diff, or Deep scan." : powerImportRequired && !busy ? " · Open Kiro Powers → Add Custom Power → Import power from a folder. Import the prepared folder, then verify setup." : ""}</p>
      ${!setupReady ? `<p class="muted">Complete the required system checks below before connecting.</p>` : ""}
      ${integrationHealthy ? "" : powerImportRequired ? `<div class="button-row"><button id="setup-primary-action" class="primary" data-action="copy-power-path" ${busy || !setupReady ? "disabled" : ""}>Copy Power folder</button><button data-action="verify-agent" ${busy || !setupReady ? "disabled" : ""}>Verify after import</button></div>` : `<div class="button-row"><button id="setup-primary-action" class="primary" data-action="${primaryAction}" ${busy || !setupReady ? "disabled" : ""}>${h(operationLabel)}</button>${!pythonReady ? `<button data-action="settings">Configure Python</button>` : ""}</div>`}
      <details class="setup-options" id="setup-installation-options"><summary>Installation options</summary><div class="setup-options-body">
        <label>Installation scope<select id="agent-scope" ${busy || integration.configured ? "disabled" : ""}><option value="workspace" ${configuredScope === "workspace" ? "selected" : ""}>Current workspace (recommended)</option><option value="user" ${configuredScope === "user" ? "selected" : ""}>Current user (all workspaces)</option></select></label>
        ${integration.configured ? `<p class="muted">To change scope, remove the current integration, then install it again.</p>` : ""}
        <label>Tool approval policy<select id="agent-auto-approve" ${busy ? "disabled" : ""}><option value="read_only" ${configuredPolicy === "read_only" ? "selected" : ""}>Auto-approve read-only lookups only (recommended)</option><option value="none" ${configuredPolicy === "none" ? "selected" : ""}>Require approval for every tool</option></select></label>
        <p class="muted">Scans and changes always require approval. Installation preserves unrelated MCP servers and comments, creates backups, and rolls back if verification fails.</p>
        ${integration.configured ? `<button data-action="install-agent" ${busy || !setupReady ? "disabled" : ""}>Apply options and verify</button>` : ""}
      </div></details>
      <details class="setup-options" id="setup-troubleshooting"><summary>Advanced and troubleshooting</summary><div class="setup-options-body">
        <div class="button-row">${integrationHealthy ? `<button data-action="verify-agent" ${busy || !setupReady ? "disabled" : ""}>Verify again</button>` : ""}<button data-action="open-mcp" ${busy || !hasWorkspace || !snapshot?.workspaceTrusted ? "disabled" : ""}>Create or open MCP config</button><button class="secondary" data-action="copy-mcp" ${busy || !setupReady || !integration.power?.prepared ? "disabled" : ""}>Copy connection settings</button><button class="danger" data-action="remove-agent" ${busy || !integration.configured || !hasWorkspace || !snapshot?.workspaceTrusted ? "disabled" : ""}>Remove integration</button></div>
      ${integration.lastVerifiedAt ? `<p class="muted">Last verified: ${h(date(integration.lastVerifiedAt))}</p>` : ""}
      ${(integration.configLocations ?? []).length ? `<dl><dt>MCP config</dt><dd class="mono">${h(integration.configLocations.join("\n"))}</dd>${integration.steeringPath ? `<dt>Steering</dt><dd class="mono">${h(integration.steeringPath)}</dd>` : ""}</dl>` : ""}
      ${(integration.details ?? []).length ? `<ul class="detail-list">${integration.details.map((detail: string) => `<li>${h(detail)}</li>`).join("")}</ul>` : ""}
      </div></details>
    </section>
    <details class="card setup-disclosure" id="setup-environment" ${setupReady ? "" : "open"}><summary><span><strong>System checks</strong><small>${setupReady ? "Agent requirements passed" : "Action required"}</small></span>${badge(setupReady ? "ready" : "check setup", setupReady ? "success" : "warning")}</summary><div class="setup-disclosure-body">${checks.map(([name, value, state]) => `<div class="check"><span class="check-icon ${state}" aria-hidden="true">${state === "ok" ? "✓" : state === "neutral" ? "·" : "!"}</span><div><strong>${h(name)}</strong><div class="muted break-word">${h(value)}</div></div></div>`).join("")}</div></details>
    ${!snapshot?.secondarySidebarOnboarded ? `<details class="card setup-disclosure" id="setup-placement"><summary><strong>Panel placement</strong></summary><div class="setup-disclosure-body"><p>Run <strong>Kiro Security: Open Security Panel on Right</strong>. If Secondary Side Bar placement is unavailable, the command opens a separate panel beside the editor.</p></div></details>` : ""}
  </div>`;
}
function phaseStepper(scan: any): string {
  const phases = ["preflight", "threat_model", "discovery", "validation", "attack_path", "reporting"];
  const activeIndex = Math.max(0, phases.indexOf(scan?.phase));
  const complete = scan?.status === "completed";
  return `<ol class="stepper" aria-label="Scan phases">${phases.map((phase, index) => {
    const state = complete || index < activeIndex ? "done" : index === activeIndex ? "active" : "pending";
    return `<li class="step ${state}"><span>${state === "done" ? "✓" : index + 1}</span><small>${h(phase.replaceAll("_", " "))}</small></li>`;
  }).join("")}</ol>`;
}

function dashboardView(): string {
  const dashboard = snapshot?.dashboard;
  if (!dashboard) return `<div class="empty"><h2>Engine is not ready</h2><p>Open and trust a local workspace, then refresh.</p><button data-action="refresh">Refresh</button></div>`;
  const active = dashboard.activeScan;
  const selected = dashboard.selectedScan;
  const agentReady = snapshot?.agentIntegration?.state === "verified";
  const progress = active?.progress?.overall_percent ?? 0;
  const coverage = selected?.coverage;
  const history = (dashboard.scans ?? []).filter((scan: any) => scan.id !== active?.id && (active || scan.id !== selected?.id)).slice(0, 20);
  const state = active ? `<section class="card scan-state active-scan"><div class="card-title"><div><h2>Active scan</h2><p>${h(scanLabel(active))} · ${h(active.scope)}</p></div>${statusBadge(active.status)}</div>
      ${phaseStepper(active)}<div class="progress-label"><strong>${h(progressLabel(active.phase, progress))}</strong><span>${h(active.progress?.message ?? "Working…")}</span></div>
      <progress max="100" value="${attr(progress)}">${h(progress)}%</progress>
      <div class="metrics"><div><strong>${h(active.files_completed)}/${h(active.files_total)}</strong><span>files</span></div><div><strong>${h(active.progress?.reportable_findings_count ?? 0)}</strong><span>findings</span></div><div><strong>${h(elapsed(active))}</strong><span>elapsed</span></div></div>
      </section>` : selected ? `<section class="card scan-state"><div class="card-title"><div><h2>${h(scanLabel(selected))}</h2><p>${selected.status === "completed" ? "Completed" : "Updated"} ${h(date(selected.completed_at ?? selected.updated_at))}</p></div>${statusBadge(selected.status)}</div>
      <div class="metrics"><div><strong>${h(selected.files_total)}</strong><span>review inputs</span></div><div><strong>${h(dashboard.findings.length)}</strong><span>findings</span></div>${coverage?.completeness ? `<div><strong>${h(coverage.completeness)}</strong><span>coverage</span></div>` : ""}</div>
      ${severitySummary(dashboard.findings)}
      ${!agentReady ? `<div class="handoff-note"><strong>Finish Agent setup</strong><span>Install and verify the native Power before requesting Standard, Diff, or Deep scans.</span><div class="button-row"><button data-action="go-setup">Open setup</button></div></div>` : ""}
      <div class="button-row"><button class="primary" data-action="show-findings">View findings</button><details class="more-menu" id="dashboard-more-actions"><summary aria-label="More scan actions" title="More scan actions">⋯</summary><div class="more-menu-panel"><label>Export format<select id="export-format"><option value="markdown">Markdown</option><option value="json">JSON</option><option value="csv">CSV</option><option value="sarif">SARIF</option></select></label><button data-action="export" data-scan-id="${attr(selected.id)}">Export</button>${(selected.artifacts ?? []).length ? `<h3>Artifacts</h3><ul class="artifact-list">${selected.artifacts.map((artifact: any) => `<li><button class="link" data-action="artifact" data-path="${attr(artifact.path)}">${h(artifact.kind)}</button><span class="muted mono">${h(String(artifact.sha256).slice(0, 12))}</span></li>`).join("")}</ul>` : ""}</div></details></div>
    </section>` : `<section class="card scan-state empty"><h2>No scans yet</h2><p>Ask Kiro Agent to run a security scan for this repository.</p>${!agentReady ? `<button data-action="go-setup">Finish Agent setup</button>` : ""}</section>`;
  return `<div class="stack">${state}${history.length ? `<details class="card setup-disclosure" id="recent-scans"><summary><span><strong>Recent scans</strong><small>${h(history.length)} available</small></span></summary><div class="history-list setup-disclosure-body">${history.map((scan: any) => `<div class="history-row"><button class="link" data-action="select-scan" data-scan-id="${attr(scan.id)}">${h(scanLabel(scan))}</button><span class="muted">${h(elapsed(scan))} · ${h(scan.files_completed)}/${h(scan.files_total)} files</span>${statusBadge(scan.status)}${scan.status === "running" ? "" : `<button class="danger" data-action="cleanup" data-scan-id="${attr(scan.id)}">Cleanup</button>`}</div>`).join("")}</div></details>` : ""}
  </div>`;
}

function filters(): string {
  const f = ui.filters;
  return `<div class="filters">
    <label class="search">Search<input id="filter-query" value="${attr(f.query)}" placeholder="Title, category, path"></label>
    <label>Severity<select id="filter-severity"><option value="">All</option>${["critical","high","medium","low","informational"].map((value) => `<option ${f.severity === value ? "selected" : ""}>${value}</option>`).join("")}</select></label>
    <label>Confidence<select id="filter-confidence"><option value="">All</option>${["high","medium","low"].map((value) => `<option ${f.confidence === value ? "selected" : ""}>${value}</option>`).join("")}</select></label>
    <label>Validation<select id="filter-validation"><option value="">All</option>${["unvalidated","validated","rejected","needs_review"].map((value) => `<option ${f.validation === value ? "selected" : ""}>${value.replaceAll("_", " ")}</option>`).join("")}</select></label>
    <label>Triage<select id="filter-triage"><option value="">All</option>${["open","accepted_risk","false_positive","already_fixed","wont_fix"].map((value) => `<option ${f.triage === value ? "selected" : ""}>${value.replaceAll("_", " ")}</option>`).join("")}</select></label>
    <label>Sort<select id="filter-sort">${[["severity","Severity"],["confidence","Confidence"],["updated","Updated"],["title","Title"]].map(([value,label]) => `<option value="${value}" ${f.sort === value ? "selected" : ""}>${label}</option>`).join("")}</select></label>
  </div>`;
}

function findingsView(): string {
  const findings = snapshot?.dashboard?.findings ?? [];
  const visible = filterAndSortFindings(findings, ui.filters);
  const selected = snapshot?.selectedFinding;
  return `<div class="findings-layout"><section class="findings-list"><div class="card-title"><div><h2>Findings</h2><p>${visible.length} of ${findings.length}</p></div>${severitySummary(findings)}</div>${filters()}
    <div class="finding-cards">${visible.map((finding: any) => {
      const location = finding.locations?.find((item: any) => item.role === "sink") ?? finding.locations?.[0];
      const isSelected = selected?.occurrenceId === finding.occurrenceId;
      return `<button class="finding-card ${isSelected ? "selected" : ""}" data-action="finding" data-occurrence-id="${attr(finding.occurrenceId)}">
        <span class="finding-heading">${severityBadge(finding.severity.level)}<strong>${h(finding.title)}</strong></span>
        <span class="finding-summary">${h(finding.summary)}</span>
        <span class="finding-meta">${h(finding.confidence.level)} confidence · ${h(finding.validationStatus.replaceAll("_", " "))} · ${h(finding.triageStatus.replaceAll("_", " "))}</span>
        <span class="finding-path mono">${h(location ? `${location.path}:${location.startLine}` : "No location")}</span>
      </button>`;
    }).join("") || `<div class="empty compact"><h3>No matching findings</h3><p>Adjust filters or run a scan.</p></div>`}</div></section>
    <aside class="finding-detail">${selected ? detailView(selected) : `<div class="empty"><h2>Select a finding</h2><p>Review evidence, source-to-sink paths, validation, impact, and remediation.</p></div>`}</aside></div>`;
}

function evidenceView(evidence: any): string {
  return `<div class="evidence"><div class="card-title"><strong>${h(evidence.label)}</strong>${badge(evidence.role ?? evidence.kind)}</div><p class="mono">${h(evidence.path)}:${h(evidence.startLine)}</p><pre><code>${h(evidence.code)}</code></pre><p>${h(evidence.explanation)}</p></div>`;
}
function attackSteps(attackPath: any): string {
  const steps = Array.isArray(attackPath?.crossFilePath) ? attackPath.crossFilePath : Array.isArray(attackPath?.path) ? attackPath.path : [];
  if (!steps.length) return "";
  return `<ol class="detail-list attack-steps">${steps.map((step: any) => {
    const label = step.step ?? step.label ?? step.kind ?? "Attack step";
    const location = step.path ? `${step.path}${step.startLine ? `:${step.startLine}` : ""}` : "";
    return `<li><strong>${h(label)}</strong>${location ? `<span class="mono muted">${h(location)}</span>` : ""}</li>`;
  }).join("")}</ol>`;
}
function remediationHistory(records: any[]): string {
  if (!records.length) return "";
  return `<ol class="detail-list" aria-label="Remediation history">${records.map((record: any) => `<li><strong>Version ${h(record.version)} · ${h(String(record.state ?? "unknown").replaceAll("_", " "))}</strong><span class="muted"> · ${h(date(record.updated_at ?? record.updatedAt))}</span>${record.summary ? `<p>${h(record.summary)}</p>` : ""}${record.verification_summary ? `<p class="muted">Verification: ${h(record.verification_summary)}</p>` : ""}</li>`).join("")}</ol>`;
}
function trackingHistory(records: any[]): string {
  if (!records.length) return "";
  return `<ol class="detail-list" aria-label="Issue tracker history">${records.map((record: any) => { const url = String(record.external_url ?? record.externalUrl ?? ""); return `<li><strong>${h(record.provider)} · ${h(String(record.status ?? "unknown").replaceAll("_", " "))}</strong><span class="muted"> · ${h(date(record.updated_at ?? record.updatedAt))}</span>${record.destination ? `<p>${h(record.destination)}</p>` : ""}${/^https?:\/\/\S+$/i.test(url) ? `<a href="${attr(url)}" target="_blank" rel="noreferrer">Open tracked item</a>` : ""}</li>`; }).join("")}</ol>`;
}
function detailView(finding: any): string {
  const sink = finding.locations?.find((item: any) => item.role === "sink") ?? finding.locations?.[0];
  const evidence = finding.codeEvidence ?? [];
  const related = finding.relatedFindings ?? [];
  const artifacts = finding.artifactLinks ?? [];
  const attack = finding.attackPath;
  const severityRationale = attack?.severityRationale ?? attack?.severity?.rationale;
  return `<article class="detail card">
    <header class="card-title"><div><div class="badge-row">${severityBadge(finding.severity.level)}${statusBadge(finding.validationStatus)}${badge(finding.confidence.level + " confidence")}</div><h2>${h(finding.title)}</h2><p>${h(finding.summary)}</p><p class="mono break-word">${h(sink ? `${sink.path}:${sink.startLine}-${sink.endLine}` : "No location")}</p></div>
      <div class="button-row"><button class="primary" data-action="open-source" data-occurrence-id="${attr(finding.occurrenceId)}">Open source</button><details class="more-menu" id="finding-more-actions"><summary aria-label="More finding actions" title="More finding actions">⋯</summary><div class="more-menu-panel">
        <button data-action="copy-link" data-occurrence-id="${attr(finding.occurrenceId)}">Copy link</button><button data-action="export-finding" data-occurrence-id="${attr(finding.occurrenceId)}">Export finding JSON</button><button data-action="tracking" data-provider="manual" data-occurrence-id="${attr(finding.occurrenceId)}">Send to issue tracker</button><p class="muted">Copies a Kiro Agent prompt. No issue is created without your approval.</p>
        ${trackingHistory(finding.trackingRecords ?? [])}
        ${artifacts.length ? `<h3>Artifacts</h3><ul class="artifact-list">${artifacts.map((artifact: any) => `<li><button class="link" data-action="artifact" data-path="${attr(artifact.path)}">${h(artifact.kind)}</button><span class="muted mono">${h(String(artifact.sha256 ?? "").slice(0, 12))}</span></li>`).join("")}</ul>` : ""}
        <h3>Metadata</h3><dl><dt>Finding ID</dt><dd class="mono">${h(finding.findingId)}</dd><dt>Rule</dt><dd>${h(finding.ruleId)}</dd><dt>Category</dt><dd>${h(finding.taxonomy?.category)}</dd><dt>CWE</dt><dd>${h((finding.taxonomy?.cwe ?? []).join(", ") || "—")}</dd><dt>Scan ID</dt><dd class="mono">${h(finding.scanId)}</dd></dl>
      </div></details></div></header>
    <section class="setup-options"><h3>Evidence</h3>${evidence.length ? evidenceView(evidence[0]) : `<p class="muted">No evidence recorded.</p>`}${evidence.length > 1 ? `<details id="additional-evidence"><summary>${h(evidence.length - 1)} more evidence item${evidence.length === 2 ? "" : "s"}</summary><div class="setup-options-body">${evidence.slice(1).map(evidenceView).join("")}</div></details>` : ""}</section>
    <section class="setup-options"><h3>Why it matters</h3>${attack ? `<p>${h(attack.narrative)}</p><dl><dt>Exploitability</dt><dd>${h(attack.exploitability)}</dd><dt>Impact</dt><dd>${h(attack.impact)}</dd>${severityRationale ? `<dt>Severity rationale</dt><dd>${h(severityRationale)}</dd>` : ""}</dl>${attackSteps(attack)}` : `<p>${h(finding.summary)}</p><p class="muted">Attack-path analysis is not recorded yet.</p>`}</section>
    <details class="setup-options" id="finding-status"><summary><span>Status and validation</span>${statusBadge(finding.validationStatus)}</summary><div class="setup-options-body">
      ${finding.validation ? `<p>${h(finding.validation.rationale)}</p><p class="muted">Method: ${h(finding.validation.method)}${finding.validation.createdAt ? ` · ${h(date(finding.validation.createdAt))}` : ""}</p>` : `<p class="muted">No canonical validation record is available.</p>`}
      <div class="stack"><label>Mark as<select id="triage-decision">${[["open","Open"],["accepted_risk","Accept risk"],["false_positive","False positive"],["already_fixed","Already fixed"],["wont_fix","Won't fix"]].map(([value,label]) => `<option value="${value}" ${finding.triageStatus === value ? "selected" : ""}>${label}</option>`).join("")}</select></label><label>Decision note<textarea id="triage-note" data-occurrence-id="${attr(finding.occurrenceId)}" maxlength="4000" placeholder="Required for Accept risk and Won't fix">${h(finding.triage?.note ?? "")}</textarea></label><button data-action="triage" data-occurrence-id="${attr(finding.occurrenceId)}">Apply status</button></div>
    </div></details>
    <details class="setup-options" id="finding-remediation"><summary>Remediation</summary><div class="setup-options-body"><p>${h(finding.remediation)}</p><button data-action="remediation" data-occurrence-id="${attr(finding.occurrenceId)}">Create remediation guidance</button>${remediationHistory(finding.remediationRecords ?? [])}</div></details>
    ${related.length ? `<details class="setup-options" id="related-findings"><summary>Related findings (${h(related.length)})</summary><div class="setup-options-body">${related.map((item: any) => `<button class="related-finding" data-action="finding" data-occurrence-id="${attr(item.occurrenceId)}"><strong>${h(item.title)}</strong><span>${severityBadge(item.severity.level)} ${h(item.locations?.[0]?.path ?? "")}</span></button>`).join("")}</div></details>` : ""}
  </article>`;
}

function render(): void {
  if (!app) return;
  const viewState = ui.tab === "setup"
    ? [snapshot?.workspaceRoot, snapshot?.workspaceTrusted, snapshot?.engineStatus, snapshot?.secondarySidebarOnboarded, snapshot?.dashboard?.workspace, snapshot?.dashboard?.engine?.dependencies?.git, snapshot?.agentIntegration]
    : ui.tab === "findings" ? [snapshot?.dashboard?.findings, snapshot?.selectedFinding]
      : [snapshot?.dashboard, snapshot?.agentIntegration?.configured];
  const renderKey = JSON.stringify([ui, snapshot?.engineError, viewState]);
  if (app.firstElementChild && renderKey === lastRenderKey) return;
  const activeElement = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  const activeAction = activeElement?.dataset.action;
  const activeActionIndex = activeAction
    ? Array.from(document.querySelectorAll<HTMLElement>(`[data-action="${activeAction}"]`)).indexOf(activeElement)
    : -1;
  const activeSummary = activeElement?.tagName === "SUMMARY" ? activeElement.parentElement?.id : undefined;
  if (activeElement && (activeElement.id || activeAction || activeSummary || activeElement.dataset.tab)) {
    pendingSetupFocus = { id: activeElement.id || undefined, action: activeAction, actionIndex: activeActionIndex, occurrenceId: activeElement.dataset.occurrenceId, summary: activeSummary, tab: activeElement.dataset.tab };
  }
  const dirtyFields = new Map<string, string>();
  document.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>("input[id], textarea[id]").forEach((field) => {
    if (field.value !== field.defaultValue) dirtyFields.set(`${field.id}::${field.dataset.occurrenceId ?? ""}`, field.value);
  });
  app.setAttribute("aria-busy", "false");
  if (!snapshot) {
    app.innerHTML = `<div class="loading">Connecting to Kiro Security engine…</div>`;
    return;
  }
  const view = ui.tab === "setup" ? setupView() : ui.tab === "findings" ? findingsView() : dashboardView();
  app.innerHTML = shell(view);
  document.querySelectorAll<HTMLDetailsElement>("details[id]").forEach((detail) => {
    if (setupDisclosureState.has(detail.id)) detail.open = Boolean(setupDisclosureState.get(detail.id));
  });
  document.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>("input[id], textarea[id]").forEach((field) => {
    const dirty = dirtyFields.get(`${field.id}::${field.dataset.occurrenceId ?? ""}`);
    if (dirty !== undefined) field.value = dirty;
  });
  bindControls();
  lastRenderKey = renderKey;
  const pending = pendingSetupFocus;
  const actionMatches = pending?.action ? Array.from(document.querySelectorAll<HTMLElement>(`[data-action="${pending.action}"]`)) : [];
  const focusTarget = pending?.id ? document.getElementById(pending.id)
    : pending?.summary ? document.querySelector<HTMLElement>(`#${pending.summary} > summary`)
      : pending?.tab ? document.querySelector<HTMLElement>(`[data-tab="${pending.tab}"]`)
        : pending?.action && pending.occurrenceId ? actionMatches.find((match) => match.dataset.occurrenceId === pending.occurrenceId) ?? (pending.actionIndex >= 0 ? actionMatches[pending.actionIndex] : null)
          : pending && pending.actionIndex >= 0 ? actionMatches[pending.actionIndex] : null;
  const focusDisabled = focusTarget instanceof HTMLButtonElement || focusTarget instanceof HTMLSelectElement ? focusTarget.disabled : false;
  if (focusTarget && !focusDisabled) { focusTarget.focus(); pendingSetupFocus = undefined; }
  else if (!focusTarget) pendingSetupFocus = undefined;
}

function bindControls(): void {
  document.querySelectorAll<HTMLElement>("[data-tab]").forEach((element) => element.addEventListener("click", () => {
    ui.tab = element.dataset.tab as Tab;
    persist();
    render();
  }));
  const filterInputs: Array<[string, keyof FindingFilters]> = [
    ["filter-query", "query"], ["filter-severity", "severity"], ["filter-confidence", "confidence"],
    ["filter-validation", "validation"], ["filter-triage", "triage"], ["filter-sort", "sort"],
  ];
  for (const [id, key] of filterInputs) {
    const element = document.getElementById(id) as HTMLInputElement | HTMLSelectElement | null;
    element?.addEventListener(element instanceof HTMLInputElement ? "input" : "change", () => {
      (ui.filters as any)[key] = element.value;
      persist();
      render();
      if (id === "filter-query") requestAnimationFrame(() => (document.getElementById(id) as HTMLInputElement | null)?.focus());
    });
  }
  const agentScope = document.getElementById("agent-scope") as HTMLSelectElement | null;
  const agentApproval = document.getElementById("agent-auto-approve") as HTMLSelectElement | null;
  document.querySelectorAll<HTMLDetailsElement>("details[id]").forEach((detail) => detail.addEventListener("toggle", () => setupDisclosureState.set(detail.id, detail.open)));
  const rememberAgentOptions = () => {
    agentOptionsDirty = true;
    if (agentScope) ui.agentScope = agentScope.value as "workspace" | "user";
    if (agentApproval) ui.agentAutoApprove = agentApproval.value as "none" | "read_only";
    persist();
  };
  agentScope?.addEventListener("change", rememberAgentOptions);
  agentApproval?.addEventListener("change", rememberAgentOptions);
  document.getElementById("triage-note")?.addEventListener("input", (event) => (event.currentTarget as HTMLTextAreaElement).setCustomValidity(""));
  document.querySelectorAll<HTMLElement>("[data-action]").forEach((element) => element.addEventListener("click", () => void handleAction(element)));
}

async function handleAction(element: HTMLElement): Promise<void> {
  const action = element.dataset.action;
  if (action === "filter-severity") {
    const severity = element.dataset.severity ?? "";
    ui.filters.severity = ui.filters.severity === severity ? "" : severity;
    ui.tab = "findings";
    persist();
    render();
  }
  if (action === "refresh") post({ type: "refresh" });
  if (action === "settings") post({ type: "openSettings" });
  if (action === "logs") post({ type: "openLogs" });
  if (action === "copy-mcp") post({ type: "copyMcpConfig" });
  if (action === "copy-power-path") post({ type: "copyPowerPath" });
  if (action === "install-agent") {
    const scope = (document.getElementById("agent-scope") as HTMLSelectElement | null)?.value ?? "workspace";
    const autoApprovePolicy = (document.getElementById("agent-auto-approve") as HTMLSelectElement | null)?.value ?? "read_only";
    post({ type: "installAgentIntegration", scope, autoApprovePolicy });
  }
  if (action === "verify-agent") post({ type: "verifyAgentIntegration" });
  if (action === "remove-agent") post({ type: "removeAgentIntegration" });
  if (action === "open-mcp") post({ type: "openMcpConfig", scope: (document.getElementById("agent-scope") as HTMLSelectElement | null)?.value ?? "workspace" });
  if (action === "retry-engine") post({ type: "retryEngine" });
  if (action === "show-findings") { ui.tab = "findings"; persist(); render(); }
  if (action === "go-setup") { ui.tab = "setup"; persist(); render(); }
  if (action === "select-scan") { ui.tab = "dashboard"; persist(); post({ type: "selectScan", scanId: element.dataset.scanId }); }
  if (action === "finding") post({ type: "openFinding", occurrenceId: element.dataset.occurrenceId });
  if (action === "open-source") post({ type: "openSource", occurrenceId: element.dataset.occurrenceId });
  if (action === "triage") {
    const decision = element.dataset.decision ?? (document.getElementById("triage-decision") as HTMLSelectElement | null)?.value;
    const noteInput = document.getElementById("triage-note") as HTMLTextAreaElement | null;
    const note = noteInput?.value.trim() ?? "";
    if (["accepted_risk", "wont_fix"].includes(String(decision)) && !note) {
      noteInput?.setCustomValidity("Explain why this risk is accepted or will not be fixed.");
      noteInput?.reportValidity();
      return;
    }
    post({ type: "triageFinding", occurrenceId: element.dataset.occurrenceId, decision, note: note || undefined });
  }
  if (action === "remediation") post({ type: "createRemediation", occurrenceId: element.dataset.occurrenceId });
  if (action === "tracking") post({ type: "createTrackingHandoff", occurrenceId: element.dataset.occurrenceId, provider: element.dataset.provider });
  if (action === "cleanup") post({ type: "cleanupScan", scanId: element.dataset.scanId });
  if (action === "artifact") post({ type: "openArtifact", path: element.dataset.path });
  if (action === "copy-link") post({ type: "copyFindingLink", occurrenceId: element.dataset.occurrenceId });
  if (action === "export-finding") post({ type: "exportFinding", occurrenceId: element.dataset.occurrenceId, format: "json" });
  if (action === "export") {
    const format = (document.getElementById("export-format") as HTMLSelectElement | null)?.value ?? "markdown";
    if (["markdown", "json", "csv", "sarif"].includes(format)) post({ type: "exportReport", scanId: element.dataset.scanId, format });
  }
}

window.addEventListener("message", (event) => {
  const message = event.data;
  if (!message || typeof message !== "object") return;
  if (message.type === "snapshot") {
    snapshot = message.snapshot;
    render();
  }
  if (message.type === "event") {
    lastEvent = String(message.name ?? "");
    if (liveRegion) liveRegion.textContent = `Security event: ${lastEvent.replaceAll(".", " ")}`;
  }
  if (message.type === "navigate" && ["setup", "dashboard", "findings", "history"].includes(String(message.tab))) {
    ui.tab = message.tab === "history" ? "dashboard" : message.tab as Tab;
    persist();
    render();
  }
});

post({ type: "ready" });
render();
