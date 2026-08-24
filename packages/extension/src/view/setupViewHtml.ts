import { randomBytes } from "node:crypto";

import type * as vscode from "vscode";

import type { KiroIntegrationInspection } from "../integration/integration";
import type {
  DashboardProjection,
  FindingProjection,
  RecoveryRequestProjection,
  RemediationRequestProjection,
  ScanProjection,
} from "../workbench/workbenchClient";
import type { RepositoryScope } from "../workbench/workspaceProjection";
import { setupViewScript, type ViewTab } from "./setupViewScript";
import { setupStyles } from "./setupViewStyles";

export type { ViewTab } from "./setupViewScript";

export function baseCspDirectives(cspSource: string): readonly string[] {
  return ["default-src 'none'", `style-src ${cspSource} 'unsafe-inline'`];
}

export function documentStart(cspDirectives: readonly string[]): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="${cspDirectives.join("; ")}">
  <title>Kiro Security Power</title>
  <style>${setupStyles()}</style>
</head>`;
}

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
    ...baseCspDirectives(input.webview.cspSource),
    `script-src 'nonce-${nonce}'`,
  ];
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
  return `${documentStart(csp)}
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

      <p class="connection-note">Available to this user in every Kiro Chat. No Agent or Power selection.</p>

      ${
        input.integration.state === "absent" || input.integration.state === "mismatch"
          ? `<div class="button-row">
        <button class="primary" data-command="connectIntegration" data-od-id="connect-kiro-chat">Connect Kiro Chat</button>
      </div>`
          : ""
      }
      ${
        input.integration.state === "ready"
          ? `<div class="quick-start" data-od-id="run-security-scan">
        <h3>Run a security scan</h3>
        <p class="muted">Copy this prompt and paste it into Kiro Chat.</p>
        <div class="prompt-row">
          <code>Scan this repository for security vulnerabilities.</code>
          <button class="copy-button" data-command="copyScanPrompt" data-od-id="copy-scan-prompt">Copy</button>
        </div>
        <p class="muted result-note">Results appear in Dashboard and Findings.</p>
      </div>`
          : ""
      }
    </section>

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
  <script nonce="${nonce}">${setupViewScript(input.activeTab)}</script>
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
    <div class="section-heading section-heading-stacked">
      <h2>Security scans</h2>
      <p class="muted">Latest activity for the selected repositories.</p>
    </div>
    <div class="dashboard-summary" aria-label="Scan summary">
      <div class="summary-primary ${findings > 0 ? "metric-danger" : ""}">
        <span>Reportable findings</span>
        <strong>${findings}</strong>
      </div>
      <div class="summary-secondary">
        ${summaryMetric("Running", running, "metric-warning")}
        ${summaryMetric("Complete", complete, "metric-success")}
        ${summaryMetric("Total", dashboard.scans.length)}
      </div>
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
  return `<section class="scan-card" data-od-id="scan-${escapeHtml(scan.id)}">
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
  if (!request || request.status === "delivered" || request.status === "canceled") {
    return "";
  }
  if (!sourceActionReady) {
    return '<span class="request-state">Open this repository in the current workspace to resume in chat.</span>';
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
    <div class="section-heading section-heading-stacked">
      <h2>Security findings</h2>
      <p class="muted">Validated results from finalized scans.</p>
    </div>
    <div class="metric-strip" aria-label="Finding summary">
      ${findingMetric("Total", dashboard.findings.length)}
      ${findingMetric("High+", urgent, urgent > 0 ? "metric-danger" : "")}
      ${findingMetric("Open", open, open > 0 ? "metric-warning" : "")}
    </div>
  </section>`;
  const filters = `
    <details class="finding-filter" data-od-id="finding-filters">
      <summary><span>Filter findings</span><span class="filter-summary" id="finding-filter-summary">All findings · ${dashboard.findings.length}</span></summary>
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
      ${sourceActionReady ? remediationButton : ""}
      ${triageButton}
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
  )}">Copy ${remediationActionLabel(action).toLowerCase()} prompt again</button>`;
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

function summaryMetric(label: string, value: number, tone = ""): string {
  return `<span class="summary-metric ${tone}"><span>${escapeHtml(label)}</span><strong>${value}</strong></span>`;
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
