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
let snapshot: any = null;
let lastEvent = "";

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
    : ["failed", "rejected", "critical", "high"].includes(status) ? "danger"
      : ["running", "needs_review", "needs_repair", "interrupted", "configured"].includes(status) ? "warning" : "neutral";
  return badge(status.replaceAll("_", " "), kind);
}
function severityBadge(level: string): string {
  return badge(level, ["critical", "high"].includes(level) ? "danger" : level === "medium" ? "warning" : "neutral");
}

function nav(): string {
  return `<nav class="tabs" aria-label="Security panel sections">
    ${(["setup", "dashboard", "findings", "history"] as Tab[]).map((tab) =>
      `<button class="tab ${ui.tab === tab ? "active" : ""}" data-tab="${tab}" aria-current="${ui.tab === tab ? "page" : "false"}">${tab[0].toUpperCase()}${tab.slice(1)}</button>`).join("")}
  </nav>`;
}

function shell(content: string): string {
  return `<header class="topbar"><div><h1>Kiro Security Power</h1><p>${snapshot?.dashboard?.workspace?.display_name ? h(snapshot.dashboard.workspace.display_name) : "Repository security workbench"}</p></div>
    <button class="icon-button" data-action="refresh" title="Refresh" aria-label="Refresh security state">↻</button></header>
    ${nav()}<section class="content">${content}</section>`;
}

function setupView(): string {
  const dashboard = snapshot?.dashboard;
  const integration = snapshot?.agentIntegration ?? {};
  const python = integration.dependencies?.python ?? {};
  const busy = integration.operation && integration.operation !== "idle";
  const integrationHealthy = integration.state === "verified";
  const integrationLabel = integrationHealthy
    ? `Verified · ${integration.configScope ?? "workspace"} scope`
    : integration.state === "configured"
      ? "Configured; verification required"
      : integration.state === "needs_repair"
        ? "Needs repair"
        : integration.state === "error"
          ? `Error${integration.lastError ? ` · ${integration.lastError}` : ""}`
          : "Not installed";
  const pythonLabel = python.available
    ? `Python ${python.version ?? "detected"}${python.sqliteVersion ? ` · SQLite ${python.sqliteVersion}` : ""} · ${python.executable ?? ""}`
    : python.error ?? "Python 3.9+ with sqlite3 was not found";
  const checks = [
    ["Workspace", snapshot?.workspaceRoot ?? dashboard?.workspace?.root_path ?? "No local workspace", Boolean(snapshot?.workspaceRoot ?? dashboard?.workspace?.root_path)],
    ["Workspace trust", snapshot?.workspaceTrusted ? "Trusted" : "Not trusted", snapshot?.workspaceTrusted],
    ["Engine", snapshot?.engineStatus ?? "stopped", snapshot?.engineStatus === "ready"],
    ["Python / SQLite", pythonLabel, Boolean(python.available && python.compatible)],
    ["Git", dashboard?.engine?.dependencies?.git?.available ? "Available for diff scans" : "Unavailable; Standard and Deep remain usable", Boolean(dashboard?.engine?.dependencies?.git?.available)],
    ["Agent MCP", integrationLabel, integrationHealthy],
  ];
  const configuredScope = ui.agentScope ?? integration.configScope ?? "workspace";
  const configuredPolicy = ui.agentAutoApprove ?? integration.autoApprovePolicy ?? "read_only";
  const operationLabel = busy
    ? `Working: ${String(integration.operation).replaceAll("_", " ")}…`
    : integration.configured ? "Repair and verify" : "Install and verify";
  return `<div class="stack">
    <section class="card"><h2>Environment</h2>${checks.map(([name, value, ok]) => `<div class="check"><span class="check-icon ${ok ? "ok" : "pending"}">${ok ? "✓" : "!"}</span><div><strong>${h(name)}</strong><div class="muted break-word">${h(value)}</div></div></div>`).join("")}</section>
    ${snapshot?.engineError ? `<section class="card danger-panel"><h2>Engine error</h2><p>${h(snapshot.engineError)}</p><div class="button-row"><button data-action="retry-engine">Retry engine</button><button data-action="settings">Configure Python</button><button data-action="logs">Open logs</button></div></section>` : ""}
    <section class="card agent-setup"><div class="card-title"><div><h2>Kiro Agent integration</h2><p>One approved setup connects the Agent panel to the same engine and SQLite workbench used by this VSIX.</p></div>${statusBadge(integration.state ?? "not_configured")}</div>
      <label>Installation scope<select id="agent-scope" ${busy ? "disabled" : ""}><option value="workspace" ${configuredScope === "workspace" ? "selected" : ""}>Current workspace (.kiro)</option><option value="user" ${configuredScope === "user" ? "selected" : ""}>Current user (~/.kiro)</option></select></label>
      <label>Tool approval policy<select id="agent-auto-approve" ${busy ? "disabled" : ""}><option value="read_only" ${configuredPolicy === "read_only" ? "selected" : ""}>Auto-approve read-only lookups only</option><option value="none" ${configuredPolicy === "none" ? "selected" : ""}>Require approval for every tool</option></select></label>
      <p class="muted">The installer preserves unrelated MCP servers and JSONC comments, creates backups, writes auto-inclusion steering, starts the packaged MCP server, and rolls everything back when verification fails. Scan, triage, remediation, tracking, hardening, and export tools are never auto-approved.</p>
      <div class="button-row"><button class="primary" data-action="install-agent" ${busy || !snapshot?.workspaceTrusted || !python.available || !python.compatible ? "disabled" : ""}>${h(operationLabel)}</button><button data-action="verify-agent" ${busy || !integration.configured ? "disabled" : ""}>Verify</button><button data-action="open-mcp" ${busy ? "disabled" : ""}>Open MCP config</button><button class="danger" data-action="remove-agent" ${busy || !integration.configured ? "disabled" : ""}>Remove</button></div>
      ${integration.lastVerifiedAt ? `<p class="muted">Last verified: ${h(date(integration.lastVerifiedAt))}</p>` : ""}
      ${(integration.configLocations ?? []).length ? `<dl><dt>MCP config</dt><dd class="mono">${h(integration.configLocations.join("\n"))}</dd>${integration.steeringPath ? `<dt>Steering</dt><dd class="mono">${h(integration.steeringPath)}</dd>` : ""}</dl>` : ""}
      ${(integration.details ?? []).length ? `<ul class="detail-list">${integration.details.map((detail: string) => `<li>${h(detail)}</li>`).join("")}</ul>` : ""}
    </section>
    <section class="card"><div class="card-title"><div><h2>Optional native Kiro Power entry</h2><p>The verified MCP tools and steering above are sufficient for Agent use. Importing the prepared folder additionally registers this integration in Kiro's Powers panel.</p></div>${badge(integration.power?.registration ?? "not prepared", integration.power?.registration === "detected" ? "success" : "neutral")}</div>
      <p class="muted break-word">${integration.power?.preparedPath ? h(integration.power.preparedPath) : "The Power folder is prepared during Agent integration installation."}</p>
      <div class="button-row"><button data-action="reveal-power" ${!integration.power?.prepared ? "disabled" : ""}>Show Power folder</button><button data-action="mark-power-imported" ${!integration.power?.prepared ? "disabled" : ""}>I imported it</button><button class="secondary" data-action="copy-mcp" ${!integration.power?.prepared ? "disabled" : ""}>Copy reviewed MCP JSON</button></div>
      <p class="muted">Kiro must display its own Power permission confirmation; this VSIX does not bypass that confirmation.</p>
    </section>
    ${!snapshot?.secondarySidebarOnboarded ? `<section class="card"><h2>Right-side placement</h2><p>Run <strong>Kiro Security: Open Security Panel on Right</strong>. If Secondary Side Bar placement is unavailable, the command opens a separate panel beside the editor.</p></section>` : ""}
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
  const progress = active?.progress?.overall_percent ?? 0;
  const coverage = selected?.coverage;
  return `<div class="stack">
    <section class="card scan-form"><h2>Start a scan</h2>
      <label>Mode<select id="scan-mode"><option value="standard" ${dashboard.workspace.default_mode === "standard" ? "selected" : ""}>Standard</option><option value="deep" ${dashboard.workspace.default_mode === "deep" ? "selected" : ""}>Deep</option><option value="diff" ${dashboard.workspace.default_mode === "diff" ? "selected" : ""}>Git changes</option></select></label>
      <label>Scope<input id="scan-scope" value="${attr(dashboard.workspace.default_scope || ".")}" maxlength="4096" autocomplete="off"></label>
      <div id="diff-options" class="diff-options hidden">
        <label>Diff target<select id="diff-kind"><option value="working_tree">Working tree</option><option value="commit">Commit</option><option value="range">Range</option></select></label>
        <label>Base revision<input id="diff-base" maxlength="256" placeholder="HEAD~1"></label>
        <label>Head revision<input id="diff-head" maxlength="256" placeholder="HEAD"></label>
      </div>
      <div class="button-row"><button class="primary" data-action="start" ${active ? "disabled" : ""}>Start scan</button>${dashboard.latestResumableScan ? `<button data-action="resume" data-scan-id="${attr(dashboard.latestResumableScan.id)}" ${active ? "disabled" : ""}>Resume interrupted</button>` : ""}</div>
    </section>
    ${active ? `<section class="card active-scan"><div class="card-title"><div><h2>Active scan</h2><p>${h(active.mode)} · ${h(active.scope)}</p></div>${statusBadge(active.status)}</div>
      ${phaseStepper(active)}<div class="progress-label"><strong>${h(progressLabel(active.phase, progress))}</strong><span>${h(active.progress?.message ?? "Working…")}</span></div>
      <progress max="100" value="${attr(progress)}">${h(progress)}%</progress>
      <div class="metrics"><div><strong>${h(active.files_completed)}/${h(active.files_total)}</strong><span>files</span></div><div><strong>${h(active.progress?.reportable_findings_count ?? 0)}</strong><span>findings</span></div><div><strong>${h(elapsed(active))}</strong><span>elapsed</span></div></div>
      <button class="danger" data-action="cancel" data-scan-id="${attr(active.id)}">Cancel scan</button></section>` : ""}
    ${selected ? `<section class="card"><div class="card-title"><div><h2>Selected scan</h2><p class="mono">${h(selected.id)}</p></div>${statusBadge(selected.status)}</div>
      <div class="metrics"><div><strong>${h(selected.files_total)}</strong><span>files inventoried</span></div><div><strong>${h(dashboard.findings.length)}</strong><span>findings</span></div><div><strong>${h(coverage?.completeness ?? "unknown")}</strong><span>coverage</span></div></div>
      <div class="button-row"><button data-action="show-findings">View findings</button><button data-action="hardening" data-scan-id="${attr(selected.id)}">Hardening proposal</button><label class="compact-label">Export<select id="export-format" aria-label="Export format"><option value="markdown">Markdown</option><option value="json">JSON</option><option value="csv">CSV</option><option value="sarif">SARIF</option></select></label><button data-action="export" data-scan-id="${attr(selected.id)}">Export</button></div>
      <details><summary>Artifacts (${selected.artifacts?.length ?? 0})</summary><ul class="artifact-list">${(selected.artifacts ?? []).map((artifact: any) => `<li><button class="link" data-action="artifact" data-path="${attr(artifact.path)}">${h(artifact.kind)}</button><span class="muted mono">${h(String(artifact.sha256).slice(0, 12))}</span></li>`).join("") || "<li>None yet</li>"}</ul></details>
    </section>` : `<div class="empty"><h2>No scan history</h2><p>Start a Standard, Deep, or Git changes scan.</p></div>`}
    ${lastEvent ? `<p class="event-line" aria-hidden="true">Latest event: ${h(lastEvent)}</p>` : ""}
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
  return `<div class="findings-layout"><section class="findings-list"><div class="card-title"><div><h2>Findings</h2><p>${visible.length} of ${findings.length}</p></div></div>${filters()}
    <div class="finding-cards" role="list">${visible.map((finding: any) => {
      const location = finding.locations?.find((item: any) => item.role === "sink") ?? finding.locations?.[0];
      const isSelected = selected?.occurrenceId === finding.occurrenceId;
      return `<button role="listitem" class="finding-card ${isSelected ? "selected" : ""}" data-action="finding" data-occurrence-id="${attr(finding.occurrenceId)}">
        <span class="finding-heading">${severityBadge(finding.severity.level)}<strong>${h(finding.title)}</strong></span>
        <span class="finding-summary">${h(finding.summary)}</span>
        <span class="finding-meta">${h(finding.confidence.level)} confidence · ${h(finding.validationStatus.replaceAll("_", " "))} · ${h(finding.triageStatus.replaceAll("_", " "))}</span>
        <span class="finding-path mono">${h(location ? `${location.path}:${location.startLine}` : "No location")}</span>
      </button>`;
    }).join("") || `<div class="empty compact"><h3>No matching findings</h3><p>Adjust filters or run a scan.</p></div>`}</div></section>
    <aside class="finding-detail">${selected ? detailView(selected) : `<div class="empty"><h2>Select a finding</h2><p>Review evidence, source-to-sink paths, validation, impact, and remediation.</p></div>`}</aside></div>`;
}

function jsonBlock(value: unknown): string {
  return `<pre><code>${h(JSON.stringify(value, null, 2))}</code></pre>`;
}
function detailView(finding: any): string {
  const sink = finding.locations?.find((item: any) => item.role === "sink") ?? finding.locations?.[0];
  return `<article class="detail stack">
    <section class="card"><div class="card-title"><div><div class="badge-row">${severityBadge(finding.severity.level)}${statusBadge(finding.validationStatus)}${badge(finding.confidence.level + " confidence")}</div><h2>${h(finding.title)}</h2></div></div>
      <p>${h(finding.summary)}</p><p class="mono break-word">${h(sink ? `${sink.path}:${sink.startLine}-${sink.endLine}` : "No location")}</p>
      <div class="button-row"><button class="primary" data-action="open-source" data-occurrence-id="${attr(finding.occurrenceId)}">Open source</button><button data-action="copy-link" data-occurrence-id="${attr(finding.occurrenceId)}">Copy link</button><button data-action="export-finding" data-occurrence-id="${attr(finding.occurrenceId)}">Export finding JSON</button></div></section>
    <section class="card"><h3>Evidence</h3>${(finding.codeEvidence ?? []).map((evidence: any) => `<div class="evidence"><div class="card-title"><strong>${h(evidence.label)}</strong>${badge(evidence.role ?? evidence.kind)}</div><p class="mono">${h(evidence.path)}:${h(evidence.startLine)}</p><pre><code>${h(evidence.code)}</code></pre><p>${h(evidence.explanation)}</p></div>`).join("") || "<p class=\"muted\">No evidence recorded.</p>"}</section>
    <section class="card"><h3>Source-to-sink / attack path</h3>${finding.attackPath ? `<p>${h(finding.attackPath.narrative)}</p><dl><dt>Exploitability</dt><dd>${h(finding.attackPath.exploitability)}</dd><dt>Impact</dt><dd>${h(finding.attackPath.impact)}</dd><dt>Severity rationale</dt><dd>${h(finding.attackPath.severityRationale)}</dd></dl>${jsonBlock(finding.attackPath.path)}` : `<p class="muted">Attack-path analysis is not recorded yet.</p>`}</section>
    <section class="card"><h3>Validation</h3>${finding.validation ? `<p>${statusBadge(finding.validation.status)} ${h(finding.validation.rationale)}</p><p class="muted">Method: ${h(finding.validation.method)} · ${h(date(finding.validation.createdAt))}</p>` : `<p class="muted">This finding has not been validated.</p><button data-action="validate" data-occurrence-id="${attr(finding.occurrenceId)}">Validate finding</button>`}</section>
    <section class="card"><h3>Triage</h3><div class="button-grid">${[["open","Open"],["accepted_risk","Accept risk"],["false_positive","False positive"],["already_fixed","Already fixed"],["wont_fix","Won't fix"]].map(([value,label]) => `<button class="${finding.triageStatus === value ? "selected-action" : ""}" data-action="triage" data-decision="${value}" data-occurrence-id="${attr(finding.occurrenceId)}">${label}</button>`).join("")}</div>${finding.triage?.note ? `<p>${h(finding.triage.note)}</p>` : ""}</section>
    <section class="card"><h3>Fix workflow and remediation</h3><p>${h(finding.remediation)}</p><button data-action="remediation" data-occurrence-id="${attr(finding.occurrenceId)}">Create remediation guidance</button>${(finding.remediationRecords ?? []).length ? jsonBlock(finding.remediationRecords) : ""}</section>
    <section class="card"><h3>Tracking handoff</h3><p class="muted">Prepare an approval-ready payload. No external issue is created automatically.</p><div class="button-grid">${[["manual","Manual"],["github","GitHub"],["linear","Linear"],["jira","Jira"]].map(([value,label]) => `<button data-action="tracking" data-provider="${value}" data-occurrence-id="${attr(finding.occurrenceId)}">${label}</button>`).join("")}</div>${(finding.trackingRecords ?? []).length ? jsonBlock(finding.trackingRecords) : ""}</section>
    <section class="card"><h3>Related findings</h3>${(finding.relatedFindings ?? []).map((related: any) => `<button class="related-finding" data-action="finding" data-occurrence-id="${attr(related.occurrenceId)}"><strong>${h(related.title)}</strong><span>${severityBadge(related.severity.level)} ${h(related.locations?.[0]?.path ?? "")}</span></button>`).join("") || `<p class="muted">No related findings in this scan.</p>`}</section>
    <section class="card"><h3>Artifact links</h3><ul class="artifact-list">${(finding.artifactLinks ?? []).map((artifact: any) => `<li><button class="link" data-action="artifact" data-path="${attr(artifact.path)}">${h(artifact.kind)}</button><span class="muted mono">${h(String(artifact.sha256 ?? "").slice(0, 12))}</span></li>`).join("") || "<li>No artifacts recorded.</li>"}</ul></section>
    <section class="card"><h3>Metadata</h3><dl><dt>Finding ID</dt><dd class="mono">${h(finding.findingId)}</dd><dt>Occurrence ID</dt><dd class="mono">${h(finding.occurrenceId)}</dd><dt>Rule</dt><dd>${h(finding.ruleId)}</dd><dt>Category</dt><dd>${h(finding.taxonomy?.category)}</dd><dt>CWE</dt><dd>${h((finding.taxonomy?.cwe ?? []).join(", ") || "—")}</dd><dt>Scan ID</dt><dd class="mono">${h(finding.scanId)}</dd></dl></section>
  </article>`;
}

function historyView(): string {
  const dashboard = snapshot?.dashboard;
  const scans = dashboard?.scans ?? [];
  return `<div class="stack"><section class="card"><h2>History and recovery</h2><p>Completed and interrupted scans are persisted in the shared SQLite workbench. Power and MCP scans appear here after reconciliation.</p></section>
    <section class="history-list">${scans.map((scan: any) => `<article class="card history-item"><div class="card-title"><div><h3>${h(scan.mode)} scan</h3><p class="mono">${h(scan.id)}</p></div>${statusBadge(scan.status)}</div>
      <dl class="history-grid"><dt>Scope</dt><dd>${h(scan.scope)}</dd><dt>Phase</dt><dd>${h(scan.phase.replaceAll("_", " "))}</dd><dt>Created</dt><dd>${h(date(scan.created_at))}</dd><dt>Elapsed</dt><dd>${h(elapsed(scan))}</dd><dt>Files</dt><dd>${h(scan.files_completed)}/${h(scan.files_total)}</dd><dt>Error</dt><dd>${h(scan.failure_message ?? "—")}</dd></dl>
      <div class="button-row"><button data-action="select-scan" data-scan-id="${attr(scan.id)}">Open</button>${["interrupted","failed"].includes(scan.status) ? `<button data-action="resume" data-scan-id="${attr(scan.id)}" ${dashboard?.activeScan ? "disabled" : ""}>Resume</button>` : ""}${scan.status === "running" ? `<button class="danger" data-action="cancel" data-scan-id="${attr(scan.id)}">Cancel</button>` : `<button class="danger" data-action="cleanup" data-scan-id="${attr(scan.id)}">Cleanup</button>`}</div></article>`).join("") || `<div class="empty"><h2>No scans yet</h2></div>`}</section><section class="card"><button data-action="logs">Open structured logs</button></section></div>`;
}

function render(): void {
  if (!app) return;
  app.setAttribute("aria-busy", "false");
  if (!snapshot) {
    app.innerHTML = `<div class="loading">Connecting to Kiro Security engine…</div>`;
    return;
  }
  const view = ui.tab === "setup" ? setupView() : ui.tab === "findings" ? findingsView() : ui.tab === "history" ? historyView() : dashboardView();
  app.innerHTML = shell(view);
  bindControls();
}

function bindControls(): void {
  document.querySelectorAll<HTMLElement>("[data-tab]").forEach((element) => element.addEventListener("click", () => {
    ui.tab = element.dataset.tab as Tab;
    persist();
    render();
  }));
  const mode = document.getElementById("scan-mode") as HTMLSelectElement | null;
  const diffOptions = document.getElementById("diff-options");
  const syncDiff = () => diffOptions?.classList.toggle("hidden", mode?.value !== "diff");
  mode?.addEventListener("change", syncDiff);
  syncDiff();
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
  agentScope?.addEventListener("change", () => { ui.agentScope = agentScope.value as "workspace" | "user"; persist(); });
  const agentApproval = document.getElementById("agent-auto-approve") as HTMLSelectElement | null;
  agentApproval?.addEventListener("change", () => { ui.agentAutoApprove = agentApproval.value as "none" | "read_only"; persist(); });
  document.querySelectorAll<HTMLElement>("[data-action]").forEach((element) => element.addEventListener("click", () => void handleAction(element)));
}

async function handleAction(element: HTMLElement): Promise<void> {
  const action = element.dataset.action;
  if (action === "refresh") post({ type: "refresh" });
  if (action === "settings") post({ type: "openSettings" });
  if (action === "logs") post({ type: "openLogs" });
  if (action === "copy-mcp") post({ type: "copyMcpConfig" });
  if (action === "install-agent") {
    const scope = (document.getElementById("agent-scope") as HTMLSelectElement | null)?.value ?? "workspace";
    const autoApprovePolicy = (document.getElementById("agent-auto-approve") as HTMLSelectElement | null)?.value ?? "read_only";
    post({ type: "installAgentIntegration", scope, autoApprovePolicy });
  }
  if (action === "verify-agent") post({ type: "verifyAgentIntegration" });
  if (action === "remove-agent") post({ type: "removeAgentIntegration" });
  if (action === "open-mcp") post({ type: "openMcpConfig", scope: (document.getElementById("agent-scope") as HTMLSelectElement | null)?.value ?? "workspace" });
  if (action === "reveal-power") post({ type: "revealPowerBundle" });
  if (action === "mark-power-imported") post({ type: "markPowerImported" });
  if (action === "retry-engine") post({ type: "retryEngine" });
  if (action === "show-findings") { ui.tab = "findings"; persist(); render(); }
  if (action === "start") {
    const mode = (document.getElementById("scan-mode") as HTMLSelectElement)?.value ?? "standard";
    const scope = (document.getElementById("scan-scope") as HTMLInputElement)?.value ?? ".";
    const message: any = { type: "startScan", mode, scope };
    if (mode === "diff") {
      message.diffTargetKind = (document.getElementById("diff-kind") as HTMLSelectElement)?.value ?? "working_tree";
      const base = (document.getElementById("diff-base") as HTMLInputElement)?.value;
      const head = (document.getElementById("diff-head") as HTMLInputElement)?.value;
      if (base) message.diffBaseRevision = base;
      if (head) message.diffHeadRevision = head;
    }
    post(message);
  }
  if (action === "resume") post({ type: "resumeScan", scanId: element.dataset.scanId });
  if (action === "cancel") post({ type: "cancelScan", scanId: element.dataset.scanId });
  if (action === "select-scan") { ui.tab = "dashboard"; persist(); post({ type: "selectScan", scanId: element.dataset.scanId }); }
  if (action === "finding") post({ type: "openFinding", occurrenceId: element.dataset.occurrenceId });
  if (action === "open-source") post({ type: "openSource", occurrenceId: element.dataset.occurrenceId });
  if (action === "validate") post({ type: "validateFinding", occurrenceId: element.dataset.occurrenceId });
  if (action === "triage") post({ type: "triageFinding", occurrenceId: element.dataset.occurrenceId, decision: element.dataset.decision });
  if (action === "remediation") post({ type: "createRemediation", occurrenceId: element.dataset.occurrenceId });
  if (action === "tracking") post({ type: "createTrackingHandoff", occurrenceId: element.dataset.occurrenceId, provider: element.dataset.provider });
  if (action === "hardening") post({ type: "createHardening", scanId: element.dataset.scanId });
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
    ui.tab = message.tab as Tab;
    persist();
    render();
  }
});

post({ type: "ready" });
render();
