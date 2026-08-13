import { randomBytes } from "node:crypto";

import type * as vscode from "vscode";

import type { KiroIntegrationInspection } from "./integration";
import type {
  DashboardProjection,
  FindingProjection,
  RecoveryRequestProjection,
  RemediationRequestProjection,
  ScanProjection,
} from "./workbenchClient";
import type { RepositoryScope } from "./workspaceProjection";

export type ViewTab = "setup" | "dashboard" | "findings";

export function renderSetupHtml(input: {
  readonly webview: vscode.Webview;
  readonly stateRoot: string;
  readonly integration: KiroIntegrationInspection;
  readonly activeTab: ViewTab;
  readonly dashboard?: DashboardProjection;
  readonly repositoryScope: RepositoryScope;
  readonly workspaceLabel: string;
  readonly hasWorkspace: boolean;
  readonly globalScanCount: number;
  readonly sourceActionScanIds: readonly string[];
  readonly feedback?: string;
}): string {
  const nonce = randomBytes(16).toString("base64");
  const csp = [
    "default-src 'none'",
    `style-src ${input.webview.cspSource} 'unsafe-inline'`,
    `script-src 'nonce-${nonce}'`,
  ].join("; ");
  const presentation = integrationPresentation(input.integration);
  const checks = [
    { name: "Global storage", detail: input.stateRoot, ready: true },
    { name: "Direct MCP runtime", detail: input.integration.runtime.detail, ready: input.integration.runtime.ready },
    { name: "Global steering", detail: input.integration.steering.detail, ready: input.integration.steering.state === "installed" },
    { name: "Direct MCP registration", detail: input.integration.mcp.detail, ready: input.integration.mcp.state === "installed" },
    { name: "Chat identity Hook", detail: input.integration.hook.detail, ready: input.integration.hook.state === "ready" },
    { name: "Chat approval rules", detail: input.integration.approval.detail, ready: input.integration.approval.state === "installed" },
  ];
  const readyCheckCount = checks.filter((check) => check.ready).length;
  const allChecksReady = readyCheckCount === checks.length;
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="${csp}">
  <title>Kiro Security Power</title>
  <style>${setupStyles()}</style>
</head>
<body>
  <header class="topbar" data-od-id="setup-topbar">
    <div class="brand-lockup">
      <h1>Kiro Security Power</h1>
    </div>
    <button class="icon-button" data-command="refresh" title="Refresh status" aria-label="Refresh status"><span aria-hidden="true">↻</span></button>
  </header>

  <nav class="tabs" aria-label="Security panel" role="tablist" data-od-id="primary-tabs">
    ${tabButton("setup", "Setup", input.activeTab)}
    ${tabButton("dashboard", "Dashboard", input.activeTab)}
    ${tabButton("findings", "Findings", input.activeTab)}
  </nav>

  <main class="content" data-od-id="setup-content">
    ${
      input.feedback
        ? `<div class="feedback" role="status" data-od-id="action-feedback">${escapeHtml(input.feedback)}</div>`
        : ""
    }

    <div class="page setup-page ${input.activeTab === "setup" ? "active" : ""}" id="panel-setup" data-tab-page="setup" role="tabpanel" aria-labelledby="tab-setup" ${input.activeTab === "setup" ? "" : "hidden"}>
    <section class="panel-section connection-panel" data-od-id="kiro-chat-connection">
      <div class="status-hero">
        <div>
          <h2 data-od-id="connection-heading">${escapeHtml(
            presentation.heading,
          )}</h2>
          <p class="muted">${escapeHtml(presentation.summary)}</p>
        </div>
        <span class="badge ${presentation.badgeClass}">${escapeHtml(
          presentation.badge,
        )}</span>
      </div>

      <div class="context-list" aria-label="Connection summary">
        <div class="context-row">
          <span>Scope</span>
          <strong>Current user, every Kiro Chat</strong>
        </div>
        <div class="context-row">
          <span>Mode</span>
          <strong>Automatically available. No Agent or Power selection.</strong>
        </div>
      </div>

      ${
        input.integration.state === "absent" || input.integration.state === "mismatch"
          ? `<div class="button-row">
        <button class="primary" data-command="connectIntegration" data-od-id="connect-kiro-chat">Connect Kiro Chat</button>
      </div>`
          : ""
      }
    </section>

      ${
        input.integration.state === "ready"
          ? `<section class="panel-section quick-start" data-od-id="run-security-scan">
        <h2>Run a security scan</h2>
        <p class="muted">Copy this prompt and paste it into Kiro Chat.</p>
        <div class="prompt-row">
          <code>Scan this repository for security vulnerabilities.</code>
          <button class="copy-button" data-command="copyScanPrompt" data-od-id="copy-scan-prompt">Copy</button>
        </div>
        <p class="muted result-note">Results appear in Dashboard and Findings.</p>
      </section>`
          : ""
      }

      <details class="panel-section diagnostic-panel" data-od-id="system-checks">
        <summary>
          <span>Connection details</span>
          <span class="summary-status ${allChecksReady ? "ready" : "pending"}">${readyCheckCount}/${checks.length} ${allChecksReady ? "ready" : "needs attention"}</span>
        </summary>
        <div class="details-body">
          <div class="compact-checks" aria-label="System checks">
            ${checks.map((check) => compactCheckRow(check.name, check.detail, check.ready)).join("")}
          </div>

          <details class="nested-details">
            <summary>Managed files</summary>
            <div class="details-body">
          <dl>
            <dt>MCP entry</dt>
            <dd class="mono">${escapeHtml(input.integration.serverKey)} in ${escapeHtml(
              input.integration.mcpPath,
            )}</dd>
            <dt>Steering</dt>
            <dd class="mono">${escapeHtml(input.integration.steeringPath)}</dd>
            <dt>Hook</dt>
            <dd class="mono">${escapeHtml(input.integration.hookPath)}</dd>
            <dt>Runtime</dt>
            <dd class="mono">${escapeHtml(input.integration.runtimeRoot)}</dd>
          </dl>
          <div class="button-row">
            <button data-command="showHookFile" ${
              input.integration.hook.registrationState === "absent"
                ? "disabled"
                : ""
            }>Open Hook</button>
            <button data-command="showMcpFile" ${
              input.integration.mcp.state === "absent" ? "disabled" : ""
            }>Open MCP config</button>
            <button data-command="showSteeringFile" ${
              input.integration.steering.state === "absent" ? "disabled" : ""
            }>Open Steering</button>
          </div>
            </div>
          </details>
        </div>
      </details>
    </div>
    <div class="page ${input.activeTab === "dashboard" ? "active" : ""}" id="panel-dashboard" data-tab-page="dashboard" role="tabpanel" aria-labelledby="tab-dashboard" ${input.activeTab === "dashboard" ? "" : "hidden"}>
      ${renderRepositoryScope(input)}
      ${renderDashboardPage(input)}
    </div>
    <div class="page ${input.activeTab === "findings" ? "active" : ""}" id="panel-findings" data-tab-page="findings" role="tabpanel" aria-labelledby="tab-findings" ${input.activeTab === "findings" ? "" : "hidden"}>
      ${renderRepositoryScope(input)}
      ${renderFindingsPage(input)}
    </div>
  </main>
  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    const tabNames = ['setup', 'dashboard', 'findings'];
    const serverActiveTab = '${input.activeTab}';
    const isTabName = (value) => tabNames.includes(value);
    const activateTab = (name, notifyHost = true) => {
      if (!isTabName(name)) return;
      for (const candidate of tabNames) {
        const selected = candidate === name;
        const tab = document.getElementById('tab-' + candidate);
        const panel = document.getElementById('panel-' + candidate);
        tab?.classList.toggle('active', selected);
        tab?.setAttribute('aria-selected', String(selected));
        tab?.setAttribute('tabindex', selected ? '0' : '-1');
        panel?.classList.toggle('active', selected);
        if (panel) panel.hidden = !selected;
      }
      vscode.setState({ activeTab: name });
      if (notifyHost) vscode.postMessage({ command: 'selectTab', tab: name });
    };
    for (const tab of document.querySelectorAll('[role="tab"][data-tab]')) {
      tab.addEventListener('click', () => activateTab(tab.dataset.tab));
      tab.addEventListener('keydown', (event) => {
        const current = tabNames.indexOf(tab.dataset.tab || '');
        if (current < 0) return;
        let next;
        if (event.key === 'ArrowRight') next = (current + 1) % tabNames.length;
        if (event.key === 'ArrowLeft') next = (current - 1 + tabNames.length) % tabNames.length;
        if (event.key === 'Home') next = 0;
        if (event.key === 'End') next = tabNames.length - 1;
        if (next === undefined) return;
        event.preventDefault();
        const name = tabNames[next];
        activateTab(name);
        document.getElementById('tab-' + name)?.focus();
      });
    }
    const savedTab = vscode.getState()?.activeTab;
    const initialTab = isTabName(savedTab) ? savedTab : serverActiveTab;
    activateTab(initialTab, initialTab !== serverActiveTab);
    for (const button of document.querySelectorAll('[data-command]')) {
      button.addEventListener('click', () => {
        if (!button.disabled) {
          vscode.postMessage({
            command: button.dataset.command,
            tab: button.dataset.tab,
            scanId: button.dataset.scanId,
            occurrenceId: button.dataset.occurrenceId,
            requestId: button.dataset.requestId,
            action: button.dataset.action,
            version: button.dataset.version,
            format: button.dataset.format,
            artifactKind: button.dataset.artifactKind,
            repositoryScope: button.dataset.repositoryScope
          });
        }
      });
    }
    const applyFindingFilters = () => {
      const scan = document.getElementById('scan-filter')?.value || '';
      const severity = document.getElementById('severity-filter')?.value || '';
      const triage = document.getElementById('triage-filter')?.value || '';
      let visibleCount = 0;
      for (const card of document.querySelectorAll('.finding-card')) {
        card.hidden =
          (scan && card.dataset.scanId !== scan) ||
          (severity && card.dataset.severity !== severity) ||
          (triage && card.dataset.triage !== triage);
        if (!card.hidden) visibleCount += 1;
      }
      const labels = [
        scan ? document.getElementById('scan-filter')?.selectedOptions[0]?.textContent : '',
        severity ? document.getElementById('severity-filter')?.selectedOptions[0]?.textContent : '',
        triage ? document.getElementById('triage-filter')?.selectedOptions[0]?.textContent : ''
      ].filter(Boolean);
      const summary = document.getElementById('finding-filter-summary');
      if (summary) {
        summary.textContent = labels.length
          ? labels.join(' · ') + ' · ' + visibleCount
          : 'All findings · ' + visibleCount;
      }
    };
    document.getElementById('scan-filter')?.addEventListener('change', applyFindingFilters);
    document.getElementById('severity-filter')?.addEventListener('change', applyFindingFilters);
    document.getElementById('triage-filter')?.addEventListener('change', applyFindingFilters);
  </script>
</body>
</html>`;
}

function tabButton(
  tab: ViewTab,
  label: string,
  activeTab: ViewTab,
): string {
  const active = tab === activeTab;
  return `<button class="tab ${active ? "active" : ""}" id="tab-${tab}" role="tab" data-tab="${tab}" aria-controls="panel-${tab}" aria-selected="${active}" tabindex="${active ? "0" : "-1"}">${label}</button>`;
}

type RepositoryViewInput = {
  readonly dashboard?: DashboardProjection;
  readonly repositoryScope: RepositoryScope;
  readonly workspaceLabel: string;
  readonly hasWorkspace: boolean;
  readonly globalScanCount: number;
  readonly sourceActionScanIds: readonly string[];
};

function renderRepositoryScope(input: RepositoryViewInput): string {
  return `<section class="scope-switch" aria-label="Repository scope">
    <span class="scope-label">${escapeHtml(
      input.repositoryScope === "current"
        ? input.workspaceLabel
        : "All repositories on this device",
    )}</span>
    <div class="scope-buttons">
      <button class="${input.repositoryScope === "current" ? "active" : ""}" data-command="selectRepositoryScope" data-repository-scope="current" aria-pressed="${input.repositoryScope === "current"}">Current</button>
      <button class="${input.repositoryScope === "all" ? "active" : ""}" data-command="selectRepositoryScope" data-repository-scope="all" aria-pressed="${input.repositoryScope === "all"}">All</button>
    </div>
  </section>`;
}

function renderDashboardPage(
  input: RepositoryViewInput,
): string {
  const dashboard = input.dashboard;
  if (!dashboard) {
    return emptyState(
      "Dashboard unavailable",
      "Connect Kiro Security Chat to initialize the global workbench.",
    );
  }
  if (dashboard.scans.length === 0) {
    if (input.repositoryScope === "current" && !input.hasWorkspace) {
      return emptyState(
        "No workspace is open",
        "Open a repository or select All to view previous scans.",
        input.globalScanCount > 0,
      );
    }
    if (input.repositoryScope === "current") {
      return emptyState(
        "No scans in the current workspace",
        input.globalScanCount > 0
          ? `${input.globalScanCount} scans are available in other repositories.`
          : "Start a security scan in Kiro Chat. This extension displays the results.",
        input.globalScanCount > 0,
      );
    }
    return emptyState(
      "No scans yet",
      "Start a security scan in Kiro Chat. This extension displays the results.",
    );
  }
  const running = dashboard.scans.filter((scan) => scan.status === "running").length;
  const complete = dashboard.scans.filter((scan) => scan.status === "complete").length;
  const findings = dashboard.findings.filter(
    (finding) => finding.severity !== "informational",
  ).length;
  const overview = `<section class="overview" data-od-id="dashboard-overview">
    <div class="section-heading">
      <div>
        <span class="eyebrow">Workbench</span>
        <h2>Security scans</h2>
      </div>
      <span class="muted">Latest state</span>
    </div>
    <div class="metric-grid">
      ${metricCard("Total", dashboard.scans.length)}
      ${metricCard("Running", running, "metric-warning")}
      ${metricCard("Complete", complete, "metric-success")}
      ${metricCard("Reportable findings", findings, findings > 0 ? "metric-danger" : "")}
    </div>
  </section>`;
  const scans = dashboard.scans
    .map((scan) =>
      renderScanCard(
        scan,
        dashboard.recoveryRequests.filter(
          (request) => request.scanId === scan.id,
        ),
        input.sourceActionScanIds.includes(scan.id),
      ),
    )
    .join("");
  return `${overview}<div class="section-divider"><span>Scan history</span></div>${scans}`;
}

function renderScanCard(
  scan: ScanProjection,
  recoveryRequests: readonly RecoveryRequestProjection[],
  sourceActionReady: boolean,
): string {
  const total = scan.progress.reviewItemsTotal;
  const complete = scan.progress.reviewItemsCompleted;
  const percent = total === 0 ? 0 : Math.floor((complete / total) * 100);
  const artifactButtons =
    scan.status === "complete"
      ? `
        <button data-command="openArtifact" data-scan-id="${escapeHtml(
          scan.id,
        )}" data-artifact-kind="report">Report</button>
        <button data-command="openArtifact" data-scan-id="${escapeHtml(
          scan.id,
        )}" data-artifact-kind="manifest">Manifest</button>
        <button data-command="openArtifact" data-scan-id="${escapeHtml(
          scan.id,
        )}" data-artifact-kind="coverage">Coverage</button>
        <button data-command="exportScan" data-scan-id="${escapeHtml(
          scan.id,
        )}" data-format="sarif">Export SARIF</button>
        <button data-command="exportScan" data-scan-id="${escapeHtml(
          scan.id,
        )}" data-format="csv">Export CSV</button>`
      : "";
  const recovery =
    scan.status === "running"
      ? renderRecoveryControls(scan.id, recoveryRequests[0], sourceActionReady)
      : "";
  return `<section class="card scan-card" data-od-id="scan-${escapeHtml(scan.id)}">
    <div class="card-title">
      <div>
        <h2>${escapeHtml(scan.target.path)}</h2>
        <p>${escapeHtml(scan.mode)} · Scope ${escapeHtml(scan.scope)}</p>
      </div>
      <span class="badge ${statusBadge(scan.status)}">${scanStatusLabel(scan.status)}</span>
    </div>
    <div class="progress-track" role="progressbar" aria-label="Scan progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${percent}">
      <span style="width: ${percent}%"></span>
    </div>
    <dl class="scan-facts">
      <dt>Phase</dt><dd>${escapeHtml(scan.phase)}</dd>
      <dt>Revision</dt><dd class="mono">${escapeHtml(
        scan.target.revision,
      )}</dd>
      <dt>Progress</dt><dd class="tabular">${complete}/${total} (${percent}%)</dd>
      <dt>Findings</dt><dd class="tabular">${scan.progress.reportableFindingsCount}</dd>
      <dt>Updated</dt><dd>${escapeHtml(scan.updatedAt)}</dd>
    </dl>
    ${
      scan.failureMessage
        ? `<p class="error-text">${escapeHtml(scan.failureMessage)}</p>`
        : ""
    }
    <div class="button-row">${recovery}${artifactButtons}</div>
  </section>`;
}

function renderRecoveryControls(
  scanId: string,
  request: RecoveryRequestProjection | undefined,
  sourceActionReady: boolean,
): string {
  if (!sourceActionReady) {
    return '<span class="request-state">Open this repository in the current workspace to resume in chat.</span>';
  }
  if (!request) {
    return `<button class="primary" data-command="createRecovery" data-scan-id="${escapeHtml(
      scanId,
    )}">Resume in chat</button>`;
  }
  if (request.status === "delivered" || request.status === "canceled") {
    return `<span class="request-state">Latest resume request ${escapeHtml(
      requestStateLabel(request.status),
    )} · v${request.version}</span>
      <button class="primary" data-command="createRecovery" data-scan-id="${escapeHtml(
        scanId,
      )}">Resume in chat</button>`;
  }
  return `<span class="request-state">Resume request ${escapeHtml(
    requestStateLabel(request.status),
  )} · v${request.version}</span>
    <button class="primary" data-command="createRecovery" data-scan-id="${escapeHtml(
      scanId,
    )}">Copy resume prompt again</button>
    <button data-command="cancelRecovery" data-request-id="${escapeHtml(
      request.id,
    )}">Cancel resume</button>`;
}

function renderFindingsPage(
  input: RepositoryViewInput,
): string {
  const dashboard = input.dashboard;
  if (!dashboard) {
    return emptyState(
      "Findings unavailable",
      "Connect Kiro Security Chat to initialize the global workbench.",
    );
  }
  if (dashboard.findings.length === 0) {
    if (input.repositoryScope === "current" && !input.hasWorkspace) {
      return emptyState(
        "No workspace is open",
        "Open a repository or select All to view previous findings.",
        input.globalScanCount > dashboard.scans.length,
      );
    }
    return emptyState(
      input.repositoryScope === "current"
        ? "No completed findings in the current workspace"
        : "No completed findings",
      input.repositoryScope === "current" &&
        input.globalScanCount > dashboard.scans.length
        ? "Select All to view results from other repositories."
        : "Validated findings appear here after a scan is finalized.",
      input.repositoryScope === "current" &&
        input.globalScanCount > dashboard.scans.length,
    );
  }
  const findingScans = dashboard.scans.filter((scan) =>
    dashboard.findings.some((finding) => finding.scanId === scan.id),
  );
  const urgent = dashboard.findings.filter((finding) =>
    finding.severity === "critical" || finding.severity === "high"
  ).length;
  const open = dashboard.findings.filter((finding) => finding.triage.status === "open").length;
  const overview = `<section class="overview" data-od-id="findings-overview">
    <div class="section-heading">
      <div>
        <span class="eyebrow">Validated results</span>
        <h2>Security findings</h2>
      </div>
      <span class="muted">Finalized scans only</span>
    </div>
    <div class="metric-strip" aria-label="Finding summary">
      ${findingMetric("Total", dashboard.findings.length)}
      ${findingMetric("High+", urgent, urgent > 0 ? "metric-danger" : "")}
      ${findingMetric("Open", open, open > 0 ? "metric-warning" : "")}
    </div>
  </section>`;
  const filters = `
    <details class="card finding-filter" data-od-id="finding-filters">
      <summary><span>Filters</span><span class="filter-summary" id="finding-filter-summary">All findings · ${dashboard.findings.length}</span></summary>
      <div class="finding-toolbar">
        <label>Scan
          <select id="scan-filter">
            <option value="">All scans</option>
            ${findingScans
              .map(
                (scan) =>
                  `<option value="${escapeHtml(scan.id)}">${escapeHtml(
                    `${scan.target.path} · ${scan.target.revision}`,
                  )}</option>`,
              )
              .join("")}
          </select>
        </label>
        <label>Severity
          <select id="severity-filter">
            <option value="">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </label>
        <label>Status
          <select id="triage-filter">
            <option value="">All</option>
            <option value="open">Open</option>
            <option value="closed">Closed</option>
          </select>
        </label>
      </div>
    </details>`;
  return `${overview}${filters}${dashboard.findings
    .map((finding) =>
      renderFindingCard(
        finding,
        dashboard,
        dashboard.scans.find((scan) => scan.id === finding.scanId),
        input.sourceActionScanIds.includes(finding.scanId),
      ),
    )
    .join("")}`;
}

function renderFindingCard(
  finding: FindingProjection,
  dashboard: DashboardProjection,
  scan: ScanProjection | undefined,
  sourceActionReady: boolean,
): string {
  const latest = dashboard.remediationRequests
    .filter(
      (request) => request.occurrenceId === finding.occurrenceId,
    )
    .sort((left, right) =>
      right.updatedAt.localeCompare(left.updatedAt),
    )[0];
  let remediationButton = "";
  if (!sourceActionReady) {
    remediationButton = `<div class="blocked-action">
      <span class="request-state">Open this repository in the current workspace to continue remediation.</span>
      <button disabled aria-label="Remediation cannot be generated outside the current workspace">Generate fix</button>
    </div>`;
  } else if (latest?.pendingAction) {
    remediationButton = remediationPromptButtonHtml(latest);
  } else if (
    !latest ||
    ["verified", "failed", "superseded"].includes(latest.state)
  ) {
    remediationButton = remediationButtonHtml(finding, "generate");
  } else if (latest.state === "generated") {
    remediationButton = remediationButtonHtml(
      finding,
      "apply",
      latest.requestId,
    );
  } else if (latest.state === "applied") {
    remediationButton = remediationButtonHtml(
      finding,
      "verify",
      latest.requestId,
    );
  }
  const triageButton =
    finding.triage.status === "open"
      ? `<button data-command="closeTriage" data-occurrence-id="${escapeHtml(
          finding.occurrenceId,
        )}">Close</button>`
      : `<button data-command="openTriage" data-occurrence-id="${escapeHtml(
          finding.occurrenceId,
        )}">Reopen</button>`;
  const locations = finding.locations
    .map(
      (location) =>
        `${escapeHtml(location.path)}:${location.startLine}${
          location.endLine !== location.startLine
            ? `-${location.endLine}`
            : ""
        }${location.role ? ` · ${escapeHtml(location.role)}` : ""}`,
    )
    .join("<br>");
  const primaryLocation = finding.locations[0]
    ? `${finding.locations[0].path}:${finding.locations[0].startLine}${
        finding.locations[0].endLine !== finding.locations[0].startLine
          ? `-${finding.locations[0].endLine}`
          : ""
      }`
    : "No location";
  return `<section class="card finding-card" data-od-id="finding-${escapeHtml(
    finding.occurrenceId,
  )}" data-scan-id="${escapeHtml(
    finding.scanId,
  )}" data-severity="${escapeHtml(
    finding.severity,
  )}" data-triage="${escapeHtml(finding.triage.status)}">
    <div class="card-title">
      <div>
        <h2>${escapeHtml(finding.title)}</h2>
      </div>
      <div class="badge-row">
        ${
          sourceActionReady
            ? ""
            : '<span class="badge badge-neutral">External repository</span>'
        }
        <span class="badge ${severityBadge(finding.severity)}">${severityLabel(finding.severity)}</span>
      </div>
    </div>
    <p class="finding-summary">${escapeHtml(finding.summary)}</p>
    <div class="quick-meta">
      <span>Status <strong>${triageLabel(finding.triage.status)}${
        finding.triage.closeReason
          ? ` · ${escapeHtml(finding.triage.closeReason)}`
          : ""
      }</strong></span>
      <span>Location <strong class="mono">${escapeHtml(primaryLocation)}</strong></span>
    </div>
    <details class="setup-options finding-details">
      <summary>Details</summary>
      <div class="setup-options-body">
        <dl class="scan-facts">
          <dt>Confidence</dt><dd>${escapeHtml(finding.confidence)}</dd>
          <dt>Target</dt><dd class="mono">${escapeHtml(
            scan?.target.path ?? "Unknown target",
          )}</dd>
          <dt>Revision</dt><dd class="mono">${escapeHtml(
            scan?.target.revision ?? "Unknown revision",
          )}</dd>
          <dt>Finding ID</dt><dd class="mono">${escapeHtml(finding.findingId)}</dd>
          <dt>All locations</dt><dd class="mono">${locations}</dd>
        </dl>
      </div>
    </details>
    <details class="setup-options finding-details">
      <summary>Recommended fix</summary>
      <div class="setup-options-body">
        <p>${escapeHtml(finding.remediation)}</p>
        <p class="muted">Full evidence, validation, and attack paths are available in the sealed JSON export.</p>
      </div>
    </details>
    <div class="button-row">
      ${triageButton}
      ${sourceActionReady ? remediationButton : ""}
    </div>
    ${sourceActionReady ? "" : remediationButton}
    <details class="setup-options finding-details">
      <summary>More actions</summary>
      <div class="button-row setup-options-body">
        <button data-command="trackFinding" data-occurrence-id="${escapeHtml(
          finding.occurrenceId,
        )}">Track</button>
        <button data-command="exportScan" data-scan-id="${escapeHtml(
          finding.scanId,
        )}" data-format="json">Export JSON</button>
      </div>
    </details>
  </section>`;
}

function remediationPromptButtonHtml(
  request: RemediationRequestProjection,
): string {
  const action = request.pendingAction;
  if (!action) {
    return "";
  }
  return `<button class="primary" data-command="copyRemediationPrompt" data-request-id="${escapeHtml(
    request.requestId,
  )}" data-action="${escapeHtml(action)}" data-version="${
    request.version
  }">Copy ${remediationActionLabel(action).toLowerCase()} prompt again</button>`;
}

function remediationButtonHtml(
  finding: FindingProjection,
  action: "generate" | "apply" | "verify",
  requestId?: string,
): string {
  return `<button class="${action === "apply" ? "primary" : ""}" data-command="requestRemediation" data-occurrence-id="${escapeHtml(
    finding.occurrenceId,
  )}" data-action="${action}" ${
    requestId ? `data-request-id="${escapeHtml(requestId)}"` : ""
  }>${remediationActionLabel(action)}</button>`;
}

function metricCard(label: string, value: number, tone = ""): string {
  return `<div class="metric ${tone}"><span>${escapeHtml(label)}</span><strong>${value}</strong></div>`;
}

function findingMetric(label: string, value: number, tone = ""): string {
  return `<span class="metric-inline ${tone}">${escapeHtml(label)} <strong>${value}</strong></span>`;
}

function remediationActionLabel(action: "generate" | "apply" | "verify"): string {
  switch (action) {
    case "generate":
      return "Generate fix";
    case "apply":
      return "Apply fix";
    case "verify":
      return "Verify fix";
  }
}

function scanStatusLabel(status: string): string {
  const labels: Readonly<Record<string, string>> = {
    running: "Running",
    complete: "Complete",
    failed: "Failed",
    canceled: "Canceled",
  };
  return escapeHtml(labels[status] ?? status);
}

function requestStateLabel(status: string): string {
  const labels: Readonly<Record<string, string>> = {
    pending: "Pending",
    claimed: "In progress",
    delivered: "Delivered",
    canceled: "Canceled",
  };
  return labels[status] ?? status;
}

function severityLabel(severity: string): string {
  const labels: Readonly<Record<string, string>> = {
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",
  };
  return escapeHtml(labels[severity] ?? severity);
}

function triageLabel(status: string): string {
  return status === "open" ? "Open" : status === "closed" ? "Closed" : escapeHtml(status);
}

function emptyState(
  title: string,
  detail: string,
  showAllRepositories = false,
): string {
  return `<section class="empty-state" data-od-id="empty-state"><h2>${escapeHtml(
    title,
  )}</h2><p class="muted">${escapeHtml(detail)}</p>${
    showAllRepositories
      ? '<button class="primary" data-command="selectRepositoryScope" data-repository-scope="all">View all repositories</button>'
      : ""
  }</section>`;
}

function statusBadge(status: string): string {
  if (status === "complete") {
    return "badge-ready";
  }
  if (status === "failed" || status === "canceled") {
    return "badge-error";
  }
  return "badge-warning";
}

function severityBadge(severity: string): string {
  return severity === "critical" || severity === "high"
    ? "badge-error"
    : severity === "medium"
      ? "badge-warning"
      : "badge-neutral";
}

function integrationPresentation(integration: KiroIntegrationInspection): {
  readonly badge: string;
  readonly badgeClass: string;
  readonly heading: string;
  readonly summary: string;
} {
  switch (integration.state) {
    case "ready":
      return {
        badge: "Connected",
        badgeClass: "badge-ready",
        heading: "Kiro Security is connected",
        summary: "The security workflow is available in every Kiro Chat for this user.",
      };
    case "mismatch":
      return {
        badge: "Review setup",
        badgeClass: "badge-warning",
        heading: "The integration needs an update",
        summary: "Reconnect to align the installed files with this extension version.",
      };
    case "conflict":
      return {
        badge: "Conflict",
        badgeClass: "badge-error",
        heading: "The Kiro integration has a conflict",
        summary: "A managed path or MCP key is already owned by another configuration.",
      };
    case "unavailable":
      return {
        badge: "Unavailable",
        badgeClass: "badge-error",
        heading: "Kiro Security cannot be configured",
        summary: "Resolve the reported runtime issue, then refresh this view.",
      };
    case "absent":
      return {
        badge: "Not connected",
        badgeClass: "badge-neutral",
        heading: "Connect Kiro Security",
        summary: "Install the workflow once to make it available in every Kiro Chat.",
      };
  }
}

function setupStyles(): string {
  return `
    :root {
      --bg:      oklch(98% 0.005 250);
      --surface: oklch(100% 0 0);
      --fg:      oklch(22% 0.02 240);
      --muted:   oklch(50% 0.018 240);
      --border:  oklch(90% 0.008 240);
      --accent:  oklch(58% 0.16 145);

      --font-display: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', system-ui, sans-serif;
      --font-body:    -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', system-ui, sans-serif;
      --font-mono:    'JetBrains Mono', 'IBM Plex Mono', ui-monospace, Menlo, monospace;
      color-scheme: light dark;
    }
    * { box-sizing: border-box; }
    html { min-width: 0; }
    body {
      margin: 0;
      min-width: 0;
      color: var(--vscode-foreground, var(--fg));
      background: var(--vscode-sideBar-background, var(--bg));
      font: 13px/1.5 var(--vscode-font-family, var(--font-body));
      -webkit-font-smoothing: antialiased;
    }
    button, summary, select { font: inherit; }
    button {
      min-height: 32px;
      border: 1px solid var(--vscode-button-border, transparent);
      border-radius: 4px;
      padding: 5px 10px;
      color: var(--vscode-button-secondaryForeground, var(--fg));
      background: var(--vscode-button-secondaryBackground, var(--border));
      cursor: pointer;
      letter-spacing: .02em;
      transition: background-color 120ms ease, border-color 120ms ease, transform 120ms ease;
    }
    button:hover:not(:disabled) { background: var(--vscode-button-secondaryHoverBackground, color-mix(in oklch, var(--border) 72%, var(--fg))); }
    button:active:not(:disabled) { transform: translateY(1px); }
    button:focus-visible, summary:focus-visible, select:focus-visible {
      outline: 1px solid var(--vscode-focusBorder, var(--accent));
      outline-offset: 2px;
    }
    button:disabled { opacity: .46; cursor: not-allowed; }
    button.primary {
      color: var(--vscode-button-foreground, var(--surface));
      background: var(--vscode-button-background, var(--accent));
    }
    button.primary:hover:not(:disabled) { background: var(--vscode-button-hoverBackground, color-mix(in oklch, var(--accent) 82%, var(--fg))); }
    code, .mono, .tabular { font-family: var(--vscode-editor-font-family, var(--font-mono)); font-variant-numeric: tabular-nums; }
    code { font-size: .92em; }
    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      min-height: 42px;
      padding: 7px 10px;
      background: var(--vscode-sideBar-background, var(--bg));
    }
    .brand-lockup { min-width: 0; }
    .topbar h1 { margin: 0; overflow: hidden; font-size: 13px; font-weight: 650; text-overflow: ellipsis; white-space: nowrap; }
    .card p { margin: 2px 0 0; }
    .icon-button { width: 32px; border-color: transparent; background: transparent; font-size: 17px; padding: 3px; }
    .tabs {
      display: flex;
      border-block: 1px solid var(--vscode-panel-border, var(--border));
      padding: 0 6px;
      background: var(--vscode-sideBar-background, var(--bg));
    }
    .tab { position: relative; flex: 1; min-height: 36px; border: 0; border-radius: 0; background: transparent; padding: 7px 5px; color: var(--vscode-descriptionForeground, var(--muted)); }
    .tab:hover:not(:disabled) { color: var(--vscode-foreground, var(--fg)); background: var(--vscode-list-hoverBackground, color-mix(in oklch, var(--border) 65%, transparent)); }
    .tab.active { color: var(--vscode-foreground, var(--fg)); font-weight: 600; }
    .tab.active::after { content: ""; position: absolute; inset: auto 7px -1px; height: 2px; background: var(--vscode-focusBorder, var(--accent)); }
    .content { width: min(100%, 760px); margin-inline: auto; padding: 12px 10px 16px; display: grid; gap: 12px; }
    .page { min-width: 0; display: none; gap: 12px; }
    .page.active { display: grid; }
    .setup-page.active { display: block; }
    .feedback {
      border: 1px solid var(--vscode-focusBorder, var(--accent));
      border-radius: 5px;
      padding: 8px 10px;
      background: var(--vscode-textBlockQuote-background, var(--surface));
      overflow-wrap: anywhere;
    }
    .card {
      min-width: 0;
      border: 1px solid var(--vscode-panel-border, var(--border));
      border-radius: 6px;
      padding: 14px;
      background: var(--vscode-editor-background, var(--surface));
    }
    .panel-section {
      min-width: 0;
      padding: 2px 2px 14px;
      border-bottom: 1px solid var(--vscode-panel-border, var(--border));
    }
    .status-hero, .card-title, .section-heading {
      display: flex;
      justify-content: space-between;
      gap: 12px;
    }
    .status-hero { align-items: center; }
    .card-title, .section-heading { align-items: flex-start; }
    .status-hero > div, .card-title > div, .section-heading > div { min-width: 0; }
    .status-hero h2 { margin: 0; font-size: 14px; line-height: 1.3; }
    .status-hero p { margin-top: 4px; }
    .card-title h2, .section-heading h2 { margin: 0; font-size: 14px; line-height: 1.35; overflow-wrap: anywhere; }
    .section-heading h2 { margin-top: 3px; font-size: 16px; }
    .card-title p { color: var(--vscode-descriptionForeground, var(--muted)); overflow-wrap: anywhere; }
    .eyebrow { color: var(--vscode-descriptionForeground, var(--muted)); font: 600 10px/1.2 var(--vscode-editor-font-family, var(--font-mono)); letter-spacing: .07em; text-transform: uppercase; }
    .badge {
      flex: none;
      border: 1px solid currentColor;
      border-radius: 999px;
      padding: 2px 7px;
      font: 600 10px/1.45 var(--vscode-editor-font-family, var(--font-mono));
      white-space: nowrap;
    }
    .badge-neutral { color: var(--vscode-descriptionForeground, var(--muted)); background: color-mix(in oklch, currentColor 7%, transparent); }
    .badge-ready { color: var(--vscode-testing-iconPassed, var(--accent)); background: color-mix(in oklch, currentColor 8%, transparent); }
    .badge-warning { color: var(--vscode-editorWarning-foreground, var(--muted)); background: color-mix(in oklch, currentColor 8%, transparent); }
    .badge-error { color: var(--vscode-errorForeground, var(--fg)); background: color-mix(in oklch, currentColor 8%, transparent); }
    .connection-panel .badge {
      border: 0;
      border-radius: 0;
      padding: 0;
      background: transparent;
      font: 600 11px/1.45 var(--vscode-font-family, var(--font-body));
    }
    .connection-panel .badge-ready::before { content: "✓"; margin-right: 4px; }
    .context-list {
      display: grid;
      gap: 6px;
      margin-top: 11px;
      padding-top: 10px;
      border-top: 1px solid var(--vscode-panel-border, var(--border));
    }
    .context-row { display: grid; grid-template-columns: 48px minmax(0, 1fr); gap: 8px; align-items: start; }
    .context-row > span { color: var(--vscode-descriptionForeground, var(--muted)); font-size: 11px; }
    .context-row > strong { min-width: 0; font-size: 12px; font-weight: 500; overflow-wrap: anywhere; }
    .quick-start { padding-top: 12px; }
    .quick-start > p { max-width: 46ch; }
    .prompt-row { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 6px; align-items: stretch; margin-top: 6px; }
    .prompt-row code {
      min-width: 0;
      padding: 7px 8px;
      border: 1px solid var(--vscode-input-border, var(--border));
      border-radius: 3px;
      color: var(--vscode-input-foreground, var(--fg));
      background: var(--vscode-input-background, var(--surface));
      font-size: 11px;
      line-height: 1.4;
      overflow-wrap: anywhere;
    }
    .copy-button { min-height: 0; padding-inline: 9px; }
    .result-note { margin-top: 7px; font-size: 11px; }
    .diagnostic-panel { padding: 0; }
    .diagnostic-panel > summary { display: flex; align-items: center; gap: 8px; min-height: 40px; padding: 8px 2px; color: var(--vscode-descriptionForeground, var(--muted)); }
    .summary-status { margin-left: auto; font: 600 10px/1.3 var(--vscode-editor-font-family, var(--font-mono)); white-space: nowrap; }
    .summary-status.ready { color: var(--vscode-testing-iconPassed, var(--accent)); }
    .summary-status.pending { color: var(--vscode-editorWarning-foreground, var(--muted)); }
    .details-body { padding: 10px 12px 12px; border-top: 1px solid var(--vscode-panel-border, var(--border)); }
    .diagnostic-panel > .details-body { padding: 2px 2px 14px; border-top: 0; }
    .compact-checks { display: grid; gap: 9px; }
    .compact-check { display: flex; align-items: flex-start; justify-content: space-between; gap: 8px; min-width: 0; }
    .compact-check > div { min-width: 0; }
    .compact-check strong { display: block; font-size: 12px; }
    .compact-check .muted { display: block; margin-top: 1px; font-size: 11px; }
    .compact-check > span:last-child { color: var(--vscode-testing-iconPassed, var(--accent)); font: 700 10px/1 var(--vscode-editor-font-family, var(--font-mono)); }
    .compact-check > span.pending { color: var(--vscode-editorWarning-foreground, var(--muted)); }
    .nested-details { margin-top: 10px; border-top: 1px solid var(--vscode-panel-border, var(--border)); padding-top: 9px; }
    .nested-details .details-body { padding-inline: 0; border-top: 0; }
    .muted { color: var(--vscode-descriptionForeground, var(--muted)); overflow-wrap: anywhere; }
    .mono { font-size: 11px; white-space: pre-wrap; overflow-wrap: anywhere; }
    .button-row { display: flex; flex-wrap: wrap; align-items: center; gap: 7px; margin-top: 12px; }
    .request-state { color: var(--vscode-descriptionForeground, var(--muted)); }
    .setup-options { margin-top: 12px; border-top: 1px solid var(--vscode-panel-border, var(--border)); padding-top: 9px; }
    .setup-options summary { border-radius: 3px; cursor: pointer; font-weight: 600; }
    .setup-options summary { color: var(--vscode-descriptionForeground, var(--muted)); }
    .setup-options-body { padding: 10px 0 2px; }
    dl { margin: 0; display: grid; grid-template-columns: minmax(90px, auto) minmax(0, 1fr); gap: 6px 10px; }
    dt { color: var(--vscode-descriptionForeground, var(--muted)); }
    dd { margin: 0; overflow-wrap: anywhere; }
    summary > span { display: inline-flex; flex-direction: column; }
    .overview { min-width: 0; padding: 3px 2px 2px; }
    .scope-switch { display: flex; align-items: center; justify-content: space-between; gap: 10px; min-width: 0; }
    .scope-label { min-width: 0; color: var(--vscode-descriptionForeground, var(--muted)); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .scope-buttons { display: flex; flex: none; gap: 2px; }
    .scope-buttons button { min-height: 28px; padding: 3px 8px; background: transparent; }
    .scope-buttons button.active { border-color: var(--vscode-focusBorder, var(--accent)); color: var(--vscode-foreground, var(--fg)); background: var(--vscode-list-activeSelectionBackground, var(--border)); }
    .metric-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 7px; margin-top: 11px; }
    .metric { min-width: 0; border: 1px solid var(--vscode-panel-border, var(--border)); border-radius: 5px; padding: 9px; background: var(--vscode-editor-background, var(--surface)); }
    .metric span { display: block; min-height: 2.8em; color: var(--vscode-descriptionForeground, var(--muted)); font-size: 11px; line-height: 1.35; }
    .metric strong { display: block; margin-top: 2px; font: 650 18px/1.2 var(--vscode-editor-font-family, var(--font-mono)); font-variant-numeric: tabular-nums; }
    .metric-success strong { color: var(--vscode-testing-iconPassed, var(--fg)); }
    .metric-warning strong { color: var(--vscode-editorWarning-foreground, var(--fg)); }
    .metric-danger strong { color: var(--vscode-errorForeground, var(--fg)); }
    .metric-strip { display: flex; align-items: center; min-width: 0; margin-top: 9px; padding: 8px 10px; border: 1px solid var(--vscode-panel-border, var(--border)); border-radius: 5px; background: var(--vscode-editor-background, var(--surface)); }
    .metric-inline { min-width: 0; display: inline-flex; align-items: baseline; gap: 5px; color: var(--vscode-descriptionForeground, var(--muted)); font-size: 10px; white-space: nowrap; }
    .metric-inline + .metric-inline { margin-left: 9px; padding-left: 9px; border-left: 1px solid var(--vscode-panel-border, var(--border)); }
    .metric-inline strong { color: var(--vscode-foreground, var(--fg)); font: 650 13px/1 var(--vscode-editor-font-family, var(--font-mono)); font-variant-numeric: tabular-nums; }
    .metric-inline.metric-warning strong { color: var(--vscode-editorWarning-foreground, var(--fg)); }
    .metric-inline.metric-danger strong { color: var(--vscode-errorForeground, var(--fg)); }
    .section-divider { display: flex; align-items: center; gap: 8px; color: var(--vscode-descriptionForeground, var(--muted)); font: 600 10px/1 var(--vscode-editor-font-family, var(--font-mono)); letter-spacing: .05em; text-transform: uppercase; }
    .section-divider::after { content: ""; height: 1px; flex: 1; background: var(--vscode-panel-border, var(--border)); }
    .scan-facts { margin-top: 12px; }
    .progress-track { height: 4px; margin-top: 12px; overflow: hidden; border-radius: 999px; background: var(--vscode-progressBar-background, var(--border)); }
    .progress-track span { display: block; height: 100%; border-radius: inherit; background: var(--vscode-focusBorder, var(--accent)); }
    .finding-filter { padding: 0; overflow: hidden; }
    .finding-filter > summary { min-height: 42px; display: flex; align-items: center; gap: 8px; padding: 9px 12px; list-style-position: inside; }
    .filter-summary { margin-left: auto; color: var(--vscode-descriptionForeground, var(--muted)); font: 500 10px/1.3 var(--vscode-editor-font-family, var(--font-mono)); white-space: nowrap; }
    .finding-toolbar { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 9px; padding: 10px 12px 12px; border-top: 1px solid var(--vscode-panel-border, var(--border)); }
    .finding-toolbar label { display: grid; gap: 4px; color: var(--vscode-descriptionForeground, var(--muted)); font-size: 11px; }
    .badge-row { display: flex; flex: none; flex-wrap: wrap; justify-content: flex-end; gap: 5px; }
    .finding-summary { margin-top: 10px !important; }
    .quick-meta { display: flex; flex-wrap: wrap; gap: 5px 10px; margin-top: 9px; color: var(--vscode-descriptionForeground, var(--muted)); font-size: 11px; }
    .quick-meta strong { color: var(--vscode-foreground, var(--fg)); font-weight: 500; }
    .finding-details { margin-top: 10px; padding-top: 8px; }
    .blocked-action { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: center; gap: 9px; margin-top: 11px; padding: 9px; border-radius: 4px; background: var(--vscode-textBlockQuote-background, var(--bg)); }
    .blocked-action button { min-height: 30px; color: var(--vscode-descriptionForeground, var(--muted)); }
    select { width: 100%; min-width: 0; min-height: 30px; border: 1px solid var(--vscode-dropdown-border, var(--border)); border-radius: 3px; padding: 4px 7px; color: var(--vscode-dropdown-foreground, var(--fg)); background: var(--vscode-dropdown-background, var(--surface)); }
    pre { max-height: 280px; overflow: auto; white-space: pre-wrap; overflow-wrap: anywhere; padding: 8px; background: var(--vscode-textCodeBlock-background, var(--bg)); font: 11px/1.4 var(--vscode-editor-font-family, var(--font-mono)); }
    .error-text { color: var(--vscode-errorForeground, var(--fg)); }
    .empty-state { min-height: 160px; padding: 22px 2px; }
    .empty-state h2 { margin: 0; font-size: 14px; }
    .empty-state p { max-width: 42ch; }
    .empty-state button { margin-top: 10px; }
    @media (max-width: 520px) {
      .content { padding: 11px; }
      .metric-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .finding-toolbar { grid-template-columns: 1fr; }
      .blocked-action { grid-template-columns: 1fr; }
      .blocked-action button { width: 100%; }
      dl { grid-template-columns: 1fr; gap: 2px; }
      dd + dt { margin-top: 6px; }
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after { scroll-behavior: auto !important; transition: none !important; }
    }
  `;
}

function compactCheckRow(name: string, value: string, ready: boolean): string {
  return `<div class="compact-check"><div><strong>${escapeHtml(
    name,
  )}</strong><span class="muted">${escapeHtml(value)}</span></div><span class="${
    ready ? "" : "pending"
  }" aria-label="${ready ? "Ready" : "Needs attention"}">${
    ready ? "✓" : "!"
  }</span></div>`;
}

function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
