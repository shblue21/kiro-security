import { randomBytes } from "node:crypto";
import { lstat } from "node:fs/promises";

import * as vscode from "vscode";

import type { FoundationPaths } from "./foundation";
import {
  KiroIntegrationManager,
  type KiroIntegrationInspection,
} from "./integration";
import type {
  DashboardProjection,
  FindingProjection,
  RecoveryRequestProjection,
  RemediationRequestProjection,
  ScanProjection,
} from "./workbenchClient";

const VIEW_ID = "kiroSecurity.setup";

type ViewTab = "setup" | "dashboard" | "findings";
type SetupCommand =
  | "refresh"
  | "selectTab"
  | "connectIntegration"
  | "showHookFile"
  | "showMcpFile"
  | "showSteeringFile"
  | "createRecovery"
  | "cancelRecovery"
  | "openTriage"
  | "closeTriage"
  | "requestRemediation"
  | "copyRemediationPrompt"
  | "exportScan"
  | "openArtifact"
  | "trackFinding";

interface SetupMessage {
  readonly command: SetupCommand;
  readonly tab?: ViewTab;
  readonly scanId?: string;
  readonly occurrenceId?: string;
  readonly requestId?: string;
  readonly action?: "generate" | "apply" | "verify";
  readonly version?: string;
  readonly format?: "json" | "sarif" | "csv";
  readonly path?: string;
}

export class SecuritySetupView implements vscode.WebviewViewProvider {
  static readonly viewId = VIEW_ID;
  private readonly integration: KiroIntegrationManager;
  private busy = false;
  private feedback: string | undefined;
  private activeTab: ViewTab = "setup";
  private dashboard: DashboardProjection | undefined;

  constructor(
    context: vscode.ExtensionContext,
    private readonly paths: FoundationPaths,
    private readonly output: vscode.OutputChannel,
    serverKey: string,
  ) {
    this.integration = new KiroIntegrationManager(context, paths, serverKey);
  }

  resolveWebviewView(view: vscode.WebviewView): void {
    view.webview.options = { enableScripts: true };
    const messageSubscription = view.webview.onDidReceiveMessage(
      async (message: unknown) => this.handleMessage(view, message),
    );
    view.onDidDispose(() => messageSubscription.dispose());
    void this.refresh(view);
  }

  private async handleMessage(
    view: vscode.WebviewView,
    message: unknown,
  ): Promise<void> {
    if (this.busy || !isSetupMessage(message)) {
      return;
    }
    this.busy = true;
    this.feedback = undefined;
    try {
      switch (message.command) {
        case "refresh":
          break;
        case "selectTab":
          if (message.tab) {
            this.activeTab = message.tab;
          }
          break;
        case "connectIntegration":
          await this.connectIntegration();
          break;
        case "showHookFile":
          await this.showFile(
            this.integration.chatBinding.hookPath,
            "The Kiro Security Hook registration does not exist yet.",
          );
          break;
        case "showMcpFile":
          await this.showFile(
            this.integration.mcpPath,
            "The Kiro user MCP configuration does not exist yet.",
          );
          break;
        case "showSteeringFile":
          await this.showFile(
            this.integration.steeringPath,
            "The Kiro Security steering file does not exist yet.",
          );
          break;
        case "createRecovery":
          await this.createRecovery(message.scanId);
          break;
        case "cancelRecovery":
          await this.callWorkbench("cancelRecovery", {
            requestId: requiredValue(message.requestId, "requestId"),
          });
          this.feedback = "Recovery request canceled.";
          break;
        case "openTriage":
          await this.callWorkbench("setTriage", {
            occurrenceId: requiredValue(message.occurrenceId, "occurrenceId"),
            status: "open",
          });
          this.feedback = "Finding reopened.";
          break;
        case "closeTriage":
          await this.closeTriage(message.occurrenceId);
          break;
        case "requestRemediation":
          await this.requestRemediation(message);
          break;
        case "copyRemediationPrompt":
          await this.copyRemediationPrompt(
            requiredValue(message.requestId, "requestId"),
            requiredVersion(message.version),
            requiredValue(message.action, "remediation action"),
          );
          break;
        case "exportScan":
          await this.exportScan(message);
          break;
        case "openArtifact":
          await this.showFile(
            requiredValue(message.path, "artifact path"),
            "The selected scan artifact does not exist.",
          );
          break;
        case "trackFinding":
          await this.createTracking(message.occurrenceId);
          break;
      }
    } catch (error) {
      const detail = errorMessage(error);
      this.feedback = `Action failed: ${detail}`;
      this.output.appendLine(`Setup action ${message.command} failed: ${detail}`);
      await vscode.window.showErrorMessage(`Kiro Security setup failed: ${detail}`);
    } finally {
      try {
        await this.refresh(view);
      } finally {
        this.busy = false;
      }
    }
  }

  private async callWorkbench<T>(
    operation: string,
    args: Readonly<Record<string, unknown>>,
  ): Promise<T> {
    return this.integration.callWorkbench<T>(operation, args);
  }

  private async createRecovery(scanId: string | undefined): Promise<void> {
    const recovery = await this.callWorkbench<{
      readonly id: string;
      readonly scanId: string;
      readonly version: number;
    }>("createRecovery", {
      scanId: requiredValue(scanId, "scanId"),
    });
    const prompt = [
      "Resume this Kiro Security scan in this chat.",
      `Recovery request: ${recovery.id}`,
      `Expected version: ${recovery.version}`,
      "Claim the exact recovery request, then deliver it through the recovery form of kiro_security_get_scan_context.",
    ].join("\n");
    await vscode.env.clipboard.writeText(prompt);
    this.feedback = "Recovery prompt copied. Paste it into the Kiro chat that should resume the scan.";
  }

  private async closeTriage(
    occurrenceId: string | undefined,
  ): Promise<void> {
    const closeReason = await vscode.window.showQuickPick(
      [
        { label: "Already fixed", value: "already_fixed" },
        { label: "Won't fix", value: "wont_fix" },
        { label: "False positive", value: "false_positive" },
      ],
      { title: "Close security finding" },
    );
    if (!closeReason) {
      return;
    }
    const note =
      closeReason.value === "wont_fix"
        ? await vscode.window.showInputBox({
            title: "Why won't this finding be fixed?",
            validateInput: (value) =>
              value.trim() ? undefined : "A note is required.",
          })
        : undefined;
    if (closeReason.value === "wont_fix" && note === undefined) {
      return;
    }
    await this.callWorkbench("setTriage", {
      occurrenceId: requiredValue(occurrenceId, "occurrenceId"),
      status: "closed",
      closeReason: closeReason.value,
      note,
    });
    this.feedback = "Finding closed.";
  }

  private async requestRemediation(message: SetupMessage): Promise<void> {
    const action = requiredValue(message.action, "remediation action");
    const result = await this.callWorkbench<{
      readonly requestId: string;
      readonly version: number;
      readonly pendingAction: string;
    }>("requestRemediation", {
      occurrenceId: requiredValue(message.occurrenceId, "occurrenceId"),
      action,
      requestId: message.requestId,
    });
    await this.copyRemediationPrompt(
      result.requestId,
      result.version,
      requiredRemediationAction(result.pendingAction),
    );
  }

  private async copyRemediationPrompt(
    requestId: string,
    version: number,
    action: "generate" | "apply" | "verify",
  ): Promise<void> {
    const prompt = [
      `Continue Kiro Security remediation ${action}.`,
      `Request: ${requestId}`,
      `Expected version: ${version}`,
      "Claim the exact remediation action and load its authoritative context before changing any source.",
    ].join("\n");
    await vscode.env.clipboard.writeText(prompt);
    this.feedback = "Remediation prompt copied. Paste it into Kiro Chat.";
  }

  private async exportScan(message: SetupMessage): Promise<void> {
    const result = await this.callWorkbench<{ readonly path: string }>(
      "export",
      {
        scanId: requiredValue(message.scanId, "scanId"),
        format: requiredValue(message.format, "export format"),
      },
    );
    await this.showFile(result.path, "The generated export does not exist.");
    this.feedback = `Exported ${message.format?.toUpperCase()}.`;
  }

  private async createTracking(
    occurrenceId: string | undefined,
  ): Promise<void> {
    const exactOccurrence = requiredValue(occurrenceId, "occurrenceId");
    const tracking = await this.callWorkbench<{
      readonly requestId: string;
      readonly version: number;
    }>("createTracking", {
      occurrenceId: exactOccurrence,
    });
    const prompt = [
      "Track this completed Kiro Security finding.",
      `Tracking request: ${tracking.requestId}`,
      `Expected version: ${tracking.version}`,
      `Occurrence: ${exactOccurrence}`,
      "Claim and deliver the exact tracking request before provider access. Then verify the sealed source, check duplicates, preview the exact provider payload and visibility, ask for approval, write once, and read back using one selected provider.",
    ].join("\n");
    await vscode.env.clipboard.writeText(prompt);
    this.feedback = "Tracking workflow prompt copied. Paste it into Kiro Chat.";
  }

  private async connectIntegration(): Promise<void> {
    const approved = await vscode.window.showWarningMessage(
      "Connect Kiro Security to normal Kiro chats for this user?",
      {
        modal: true,
        detail: [
          `Adds only the installation-specific '${this.integration.serverKey}' entry in ${this.integration.mcpPath}.`,
          "Adds exact Kiro Trust rules that auto-approve only this steering file and this installation's non-Start/non-Cancel MCP tools.",
          "Start and Cancel always remain subject to explicit Kiro approval.",
          `Creates dedicated files at ${this.integration.chatBinding.hookPath} and ${this.integration.steeringPath}.`,
          "The Hook matches only exact Kiro Security direct MCP tool IDs. No custom Agent configuration is installed.",
          "Runtime, database, and scan artifacts remain in Extension global storage.",
        ].join("\n\n"),
      },
      "Connect",
    );
    if (approved !== "Connect") {
      return;
    }
    const result = await this.integration.install();
    this.feedback = result.changed
      ? "Kiro Security is connected to normal Kiro chats."
      : "Kiro Security integration was already current.";
    this.output.appendLine(this.feedback);
  }

  private async showFile(candidate: string, absentMessage: string): Promise<void> {
    if (!(await regularFileExists(candidate))) {
      await vscode.window.showInformationMessage(absentMessage);
      return;
    }
    await vscode.commands.executeCommand(
      "vscode.open",
      vscode.Uri.file(candidate),
    );
  }

  private async refresh(view: vscode.WebviewView): Promise<void> {
    let integration: KiroIntegrationInspection;
    try {
      integration = await this.integration.inspect();
    } catch (error) {
      integration = {
        state: "unavailable",
        detail: errorMessage(error),
        serverKey: this.integration.serverKey,
        hook: {
          state: "unavailable",
          registrationState: "absent",
          hookPath: this.integration.chatBinding.hookPath,
          bridgePath: this.integration.chatBinding.bridgePath,
          detail: errorMessage(error),
        },
        mcp: { state: "absent", detail: errorMessage(error) },
        steering: { state: "absent", detail: errorMessage(error) },
        runtime: { ready: false, detail: errorMessage(error) },
        approval: {
          state: "conflict",
          detail: errorMessage(error),
          path: "",
        },
        hookPath: this.integration.chatBinding.hookPath,
        mcpPath: this.integration.mcpPath,
        steeringPath: this.integration.steeringPath,
        runtimeRoot: this.integration.runtimeRoot,
      };
    }
    if (integration.runtime.ready) {
      try {
        this.dashboard =
          await this.integration.callWorkbench<DashboardProjection>(
            "dashboard",
          );
      } catch (error) {
        this.dashboard = undefined;
        this.output.appendLine(
          `Unable to read workbench dashboard: ${errorMessage(error)}`,
        );
      }
    } else {
      this.dashboard = undefined;
    }
    view.webview.html = renderSetupHtml({
      webview: view.webview,
      stateRoot: this.paths.stateRoot.fsPath,
      integration,
      activeTab: this.activeTab,
      dashboard: this.dashboard,
      feedback: this.feedback,
    });
  }
}

export function renderSetupHtml(input: {
  readonly webview: vscode.Webview;
  readonly stateRoot: string;
  readonly integration: KiroIntegrationInspection;
  readonly activeTab: ViewTab;
  readonly dashboard?: DashboardProjection;
  readonly feedback?: string;
}): string {
  const nonce = randomBytes(16).toString("base64");
  const csp = [
    "default-src 'none'",
    `style-src ${input.webview.cspSource} 'unsafe-inline'`,
    `script-src 'nonce-${nonce}'`,
  ].join("; ");
  const presentation = integrationPresentation(input.integration);
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
  <header class="topbar">
    <div>
      <h1>Kiro Security Power</h1>
      <p>Repository security</p>
    </div>
    <button class="icon-button" data-command="refresh" title="Refresh setup state" aria-label="Refresh setup state">↻</button>
  </header>

  <nav class="tabs" aria-label="Security panel sections">
    ${tabButton("setup", "Setup", input.activeTab)}
    ${tabButton("dashboard", "Dashboard", input.activeTab)}
    ${tabButton("findings", "Findings", input.activeTab)}
  </nav>

  <main class="content">
    ${
      input.feedback
        ? `<div class="feedback">${escapeHtml(input.feedback)}</div>`
        : ""
    }

    <div class="page ${input.activeTab === "setup" ? "active" : ""}">
    <section class="card">
      <div class="card-title">
        <div>
          <h2>Connect Kiro Chat</h2>
          <p>Enable normal chats without selecting a custom Agent or importing a Power.</p>
        </div>
        <span class="badge ${presentation.badgeClass}">${escapeHtml(
          presentation.badge,
        )}</span>
      </div>
      <p class="setup-status"><strong>${escapeHtml(
        presentation.heading,
      )}</strong></p>
      <p class="muted">${escapeHtml(input.integration.detail)}</p>
      <p class="scope-note">Auto-inclusion steering supplies the workflow. The exact direct-tool Hook binds each fresh request nonce to Kiro's <code>session_id</code>, and the MCP consumes it once to enforce chat-owned workspaces.</p>
      <div class="button-row">
        <button class="primary" data-command="connectIntegration" ${
          input.integration.state === "ready" ||
          input.integration.state === "conflict" ||
          input.integration.state === "unavailable"
            ? "disabled"
            : ""
        }>Connect Kiro Chat</button>
      </div>

      <details class="setup-options">
        <summary>Installation options</summary>
        <div class="setup-options-body">
          <dl>
            <dt>Installation scope</dt>
            <dd>Current user · all Kiro chats</dd>
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
        </div>
      </details>

      <details class="setup-options">
        <summary>Advanced and troubleshooting</summary>
        <div class="setup-options-body">
          <div class="button-row">
            <button data-command="showHookFile" ${
              input.integration.hook.registrationState === "absent"
                ? "disabled"
                : ""
            }>Show Hook</button>
            <button data-command="showMcpFile" ${
              input.integration.mcp.state === "absent" ? "disabled" : ""
            }>Show MCP config</button>
            <button data-command="showSteeringFile" ${
              input.integration.steering.state === "absent" ? "disabled" : ""
            }>Show steering</button>
          </div>
        </div>
      </details>
    </section>

    <details class="card setup-disclosure" open>
      <summary>
        <span>
          <strong>System checks</strong>
          <small>Storage and integration boundaries</small>
        </span>
      </summary>
      <div class="checks">
        ${checkRow("Global storage", input.stateRoot, true)}
        ${checkRow(
          "Direct MCP runtime",
          input.integration.runtime.detail,
          input.integration.runtime.ready,
        )}
        ${checkRow(
          "Global steering",
          input.integration.steering.detail,
          input.integration.steering.state === "installed",
        )}
        ${checkRow(
          "Direct MCP registration",
          input.integration.mcp.detail,
          input.integration.mcp.state === "installed",
        )}
        ${checkRow(
          "Chat identity Hook",
          input.integration.hook.detail,
          input.integration.hook.state === "ready",
        )}
        ${checkRow(
          "Chat approvals",
          input.integration.approval.detail,
          input.integration.approval.state === "installed",
        )}
      </div>
    </details>
    </div>
    <div class="page ${input.activeTab === "dashboard" ? "active" : ""}">
      ${renderDashboardPage(input.dashboard)}
    </div>
    <div class="page ${input.activeTab === "findings" ? "active" : ""}">
      ${renderFindingsPage(input.dashboard)}
    </div>
  </main>
  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
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
            path: button.dataset.path
          });
        }
      });
    }
    const applyFindingFilters = () => {
      const scan = document.getElementById('scan-filter')?.value || '';
      const severity = document.getElementById('severity-filter')?.value || '';
      const triage = document.getElementById('triage-filter')?.value || '';
      for (const card of document.querySelectorAll('.finding-card')) {
        card.hidden =
          (scan && card.dataset.scanId !== scan) ||
          (severity && card.dataset.severity !== severity) ||
          (triage && card.dataset.triage !== triage);
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
  return `<button class="tab ${active ? "active" : ""}" data-command="selectTab" data-tab="${tab}" ${
    active ? 'aria-current="page"' : ""
  }>${label}</button>`;
}

function renderDashboardPage(
  dashboard: DashboardProjection | undefined,
): string {
  if (!dashboard) {
    return emptyState(
      "Dashboard unavailable",
      "Connect Kiro Security Chat to initialize the extension-global workbench.",
    );
  }
  if (dashboard.scans.length === 0) {
    return emptyState(
      "No scans yet",
      "Start a Kiro Security scan from ordinary Kiro Chat. The Extension never starts scans.",
    );
  }
  return dashboard.scans
    .map((scan) =>
      renderScanCard(
        scan,
        dashboard.recoveryRequests.filter(
          (request) => request.scanId === scan.id,
        ),
      ),
    )
    .join("");
}

function renderScanCard(
  scan: ScanProjection,
  recoveryRequests: readonly RecoveryRequestProjection[],
): string {
  const total = scan.progress.reviewItemsTotal;
  const complete = scan.progress.reviewItemsCompleted;
  const percent = total === 0 ? 0 : Math.floor((complete / total) * 100);
  const artifactButtons =
    scan.status === "complete"
      ? `
        <button data-command="openArtifact" data-path="${escapeHtml(
          `${scan.scanDir}/report.md`,
        )}">Report</button>
        <button data-command="openArtifact" data-path="${escapeHtml(
          `${scan.scanDir}/scan-manifest.json`,
        )}">Manifest</button>
        <button data-command="openArtifact" data-path="${escapeHtml(
          `${scan.scanDir}/coverage.json`,
        )}">Coverage</button>
        <button data-command="exportScan" data-scan-id="${escapeHtml(
          scan.id,
        )}" data-format="sarif">SARIF</button>
        <button data-command="exportScan" data-scan-id="${escapeHtml(
          scan.id,
        )}" data-format="csv">CSV</button>`
      : "";
  const recovery =
    scan.status === "running"
      ? renderRecoveryControls(scan.id, recoveryRequests[0])
      : "";
  return `<section class="card scan-card">
    <div class="card-title">
      <div>
        <h2>${escapeHtml(scan.target.path)}</h2>
        <p>${escapeHtml(scan.mode)} · ${escapeHtml(scan.scope)}</p>
      </div>
      <span class="badge ${statusBadge(scan.status)}">${escapeHtml(
        scan.status,
      )}</span>
    </div>
    <dl class="scan-facts">
      <dt>Phase</dt><dd>${escapeHtml(scan.phase)}</dd>
      <dt>Revision</dt><dd class="mono">${escapeHtml(
        scan.target.revision,
      )}</dd>
      <dt>Progress</dt><dd>${complete}/${total} (${percent}%)</dd>
      <dt>Findings</dt><dd>${scan.progress.reportableFindingsCount}</dd>
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
): string {
  if (!request) {
    return `<button class="primary" data-command="createRecovery" data-scan-id="${escapeHtml(
      scanId,
    )}">Resume in chat</button>`;
  }
  if (request.status === "delivered" || request.status === "canceled") {
    return `<span class="request-state">Latest recovery ${escapeHtml(
      request.status,
    )} · v${request.version}</span>
      <button class="primary" data-command="createRecovery" data-scan-id="${escapeHtml(
        scanId,
      )}">Resume in chat</button>`;
  }
  return `<span class="request-state">Recovery ${escapeHtml(
    request.status,
  )} · v${request.version}</span>
    <button class="primary" data-command="createRecovery" data-scan-id="${escapeHtml(
      scanId,
    )}">Copy resume prompt again</button>
    <button data-command="cancelRecovery" data-request-id="${escapeHtml(
      request.id,
    )}">Cancel recovery</button>`;
}

function renderFindingsPage(
  dashboard: DashboardProjection | undefined,
): string {
  if (!dashboard) {
    return emptyState(
      "Findings unavailable",
      "Connect Kiro Security Chat to initialize the extension-global workbench.",
    );
  }
  if (dashboard.findings.length === 0) {
    return emptyState(
      "No completed findings",
      "Findings appear only after canonical scan finalization succeeds.",
    );
  }
  const findingScans = dashboard.scans.filter((scan) =>
    dashboard.findings.some((finding) => finding.scanId === scan.id),
  );
  const filters = `
    <section class="card finding-toolbar">
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
          <option value="informational">Informational</option>
        </select>
      </label>
      <label>State
        <select id="triage-filter">
          <option value="">All</option>
          <option value="open">Open</option>
          <option value="closed">Closed</option>
        </select>
      </label>
    </section>`;
  return `${filters}${dashboard.findings
    .map((finding) =>
      renderFindingCard(
        finding,
        dashboard,
        dashboard.scans.find((scan) => scan.id === finding.scanId),
      ),
    )
    .join("")}`;
}

function renderFindingCard(
  finding: FindingProjection,
  dashboard: DashboardProjection,
  scan: ScanProjection | undefined,
): string {
  const latest = dashboard.remediationRequests
    .filter(
      (request) => request.occurrenceId === finding.occurrenceId,
    )
    .sort((left, right) =>
      right.updatedAt.localeCompare(left.updatedAt),
    )[0];
  let remediationButton = "";
  if (latest?.pendingAction) {
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
  return `<section class="card finding-card" data-scan-id="${escapeHtml(
    finding.scanId,
  )}" data-severity="${escapeHtml(
    finding.severity,
  )}" data-triage="${escapeHtml(finding.triage.status)}">
    <div class="card-title">
      <div>
        <h2>${escapeHtml(finding.title)}</h2>
        <p>${escapeHtml(finding.findingId)}</p>
      </div>
      <span class="badge ${severityBadge(finding.severity)}">${escapeHtml(
        finding.severity,
      )}</span>
    </div>
    <p>${escapeHtml(finding.summary)}</p>
    <dl class="scan-facts">
      <dt>Confidence</dt><dd>${escapeHtml(finding.confidence)}</dd>
      <dt>Target</dt><dd class="mono">${escapeHtml(
        scan?.target.path ?? "Unknown target",
      )}</dd>
      <dt>Revision</dt><dd class="mono">${escapeHtml(
        scan?.target.revision ?? "Unknown revision",
      )}</dd>
      <dt>Triage</dt><dd>${escapeHtml(finding.triage.status)}${
        finding.triage.closeReason
          ? ` · ${escapeHtml(finding.triage.closeReason)}`
          : ""
      }</dd>
      <dt>Locations</dt><dd class="mono">${locations}</dd>
    </dl>
    <details class="setup-options">
      <summary>Recommended remediation</summary>
      <div class="setup-options-body">
        <p>${escapeHtml(finding.remediation)}</p>
        <p class="muted">Open the sealed JSON export for complete evidence, validation, and attack-path details.</p>
      </div>
    </details>
    <div class="button-row">
      ${triageButton}
      ${remediationButton}
      <button data-command="trackFinding" data-occurrence-id="${escapeHtml(
        finding.occurrenceId,
      )}">Track</button>
      <button data-command="exportScan" data-scan-id="${escapeHtml(
        finding.scanId,
      )}" data-format="json">JSON</button>
    </div>
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
  }">Copy ${escapeHtml(action)} prompt again</button>`;
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
  }>${action[0].toUpperCase()}${action.slice(1)}</button>`;
}

function emptyState(title: string, detail: string): string {
  return `<section class="card empty-state"><h2>${escapeHtml(
    title,
  )}</h2><p class="muted">${escapeHtml(detail)}</p></section>`;
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
} {
  switch (integration.state) {
    case "ready":
      return {
        badge: "installed",
        badgeClass: "badge-ready",
        heading: "Kiro Security is connected",
      };
    case "mismatch":
      return {
        badge: "setup incomplete",
        badgeClass: "badge-warning",
        heading: "Kiro Security setup is incomplete or differs from this Extension",
      };
    case "conflict":
      return {
        badge: "conflict",
        badgeClass: "badge-error",
        heading: "A Kiro integration path or MCP key conflicts",
      };
    case "unavailable":
      return {
        badge: "unavailable",
        badgeClass: "badge-error",
        heading: "Kiro Security cannot be configured",
      };
    case "absent":
      return {
        badge: "not installed",
        badgeClass: "badge-neutral",
        heading: "Kiro Security is not connected",
      };
  }
}

function setupStyles(): string {
  return `
    :root { color-scheme: light dark; }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      color: var(--vscode-foreground);
      background: var(--vscode-sideBar-background);
      font: 13px/1.45 var(--vscode-font-family);
    }
    button, summary { font: inherit; }
    button {
      border: 1px solid var(--vscode-button-border, transparent);
      border-radius: 3px;
      padding: 6px 10px;
      color: var(--vscode-button-secondaryForeground);
      background: var(--vscode-button-secondaryBackground);
      cursor: pointer;
    }
    button:disabled { opacity: .5; cursor: default; }
    button.primary {
      color: var(--vscode-button-foreground);
      background: var(--vscode-button-background);
    }
    code, .mono { font-family: var(--vscode-editor-font-family); }
    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 16px 16px 10px;
    }
    .topbar h1 { margin: 0; font-size: 16px; }
    .topbar p, .card p { margin: 3px 0 0; }
    .icon-button {
      border: 0;
      background: transparent;
      font-size: 18px;
      padding: 4px 8px;
    }
    .tabs {
      display: flex;
      border-bottom: 1px solid var(--vscode-panel-border);
      padding: 0 10px;
    }
    .tab {
      border: 0;
      border-radius: 0;
      background: transparent;
      padding: 8px 10px;
    }
    .tab.active {
      color: var(--vscode-foreground);
      border-bottom: 2px solid var(--vscode-focusBorder);
      opacity: 1;
    }
    .content { padding: 12px; display: grid; gap: 12px; }
    .page { display: none; gap: 12px; }
    .page.active { display: grid; }
    .feedback {
      border-left: 3px solid var(--vscode-focusBorder);
      padding: 7px 9px;
      background: var(--vscode-textBlockQuote-background);
      overflow-wrap: anywhere;
    }
    .card {
      border: 1px solid var(--vscode-panel-border);
      border-radius: 5px;
      padding: 14px;
      background: var(--vscode-editor-background);
    }
    .card-title {
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 12px;
    }
    .card-title h2 { margin: 0; font-size: 14px; }
    .card-title p { color: var(--vscode-descriptionForeground); }
    .badge {
      flex: none;
      border-radius: 999px;
      padding: 2px 7px;
      font-size: 11px;
      text-transform: lowercase;
      border: 1px solid currentColor;
    }
    .badge-neutral { color: var(--vscode-descriptionForeground); }
    .badge-ready { color: var(--vscode-testing-iconPassed); }
    .badge-warning { color: var(--vscode-editorWarning-foreground); }
    .badge-error { color: var(--vscode-errorForeground); }
    .setup-status { margin-top: 14px !important; }
    .scope-note {
      margin-top: 10px !important;
      padding: 8px;
      border-radius: 3px;
      color: var(--vscode-descriptionForeground);
      background: var(--vscode-textBlockQuote-background);
    }
    .muted {
      color: var(--vscode-descriptionForeground);
      overflow-wrap: anywhere;
    }
    .mono {
      font-size: 11px;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }
    .button-row {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 7px;
      margin-top: 12px;
    }
    .request-state { color: var(--vscode-descriptionForeground); }
    .setup-options {
      margin-top: 12px;
      border-top: 1px solid var(--vscode-panel-border);
      padding-top: 9px;
    }
    .setup-options summary, .setup-disclosure summary { cursor: pointer; }
    .setup-options-body { padding: 10px 0 2px; }
    dl {
      margin: 0;
      display: grid;
      grid-template-columns: minmax(92px, auto) 1fr;
      gap: 6px 10px;
    }
    dt { color: var(--vscode-descriptionForeground); }
    dd { margin: 0; overflow-wrap: anywhere; }
    .steps { padding-left: 19px; }
    .checks { margin-top: 10px; display: grid; gap: 9px; }
    .check {
      display: grid;
      grid-template-columns: 20px 1fr;
      gap: 8px;
      align-items: start;
    }
    .check-icon {
      width: 18px;
      height: 18px;
      border-radius: 50%;
      display: inline-grid;
      place-items: center;
      border: 1px solid var(--vscode-panel-border);
    }
    .check-icon.ok {
      color: var(--vscode-testing-iconPassed);
      border-color: currentColor;
    }
    .check-icon.pending {
      color: var(--vscode-editorWarning-foreground);
      border-color: currentColor;
    }
    .check strong { display: block; }
    .check span:last-child { display: block; }
    summary > span { display: inline-flex; flex-direction: column; }
    summary small {
      color: var(--vscode-descriptionForeground);
      font-weight: normal;
    }
    .scan-facts { margin-top: 12px; }
    .finding-toolbar {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
    }
    .finding-toolbar label {
      display: grid;
      gap: 4px;
      color: var(--vscode-descriptionForeground);
    }
    select {
      color: var(--vscode-dropdown-foreground);
      background: var(--vscode-dropdown-background);
      border: 1px solid var(--vscode-dropdown-border);
      padding: 4px 7px;
    }
    pre {
      max-height: 280px;
      overflow: auto;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      padding: 8px;
      background: var(--vscode-textCodeBlock-background);
      font: 11px/1.4 var(--vscode-editor-font-family);
    }
    .error-text { color: var(--vscode-errorForeground); }
    .empty-state h2 { margin: 0 0 6px; font-size: 14px; }
  `;
}

function checkRow(name: string, value: string, ready: boolean): string {
  return `<div class="check"><span class="check-icon ${
    ready ? "ok" : "pending"
  }" aria-hidden="true">${ready ? "✓" : "!"}</span><div><strong>${escapeHtml(
    name,
  )}</strong><span class="muted">${escapeHtml(value)}</span></div></div>`;
}

function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function isSetupMessage(value: unknown): value is SetupMessage {
  if (
    typeof value !== "object" ||
    value === null ||
    !("command" in value) ||
    typeof (value as { command?: unknown }).command !== "string"
  ) {
    return false;
  }
  return new Set<SetupCommand>([
    "refresh",
    "selectTab",
    "connectIntegration",
    "showHookFile",
    "showMcpFile",
    "showSteeringFile",
    "createRecovery",
    "cancelRecovery",
    "openTriage",
    "closeTriage",
    "requestRemediation",
    "copyRemediationPrompt",
    "exportScan",
    "openArtifact",
    "trackFinding",
  ]).has((value as { command: SetupCommand }).command);
}

function requiredValue<T>(value: T | undefined, name: string): T {
  if (value === undefined || value === "") {
    throw new Error(`Missing ${name}.`);
  }
  return value;
}

function requiredVersion(value: string | undefined): number {
  const version = Number(value);
  if (!Number.isSafeInteger(version) || version < 1) {
    throw new Error("Missing or invalid request version.");
  }
  return version;
}

function requiredRemediationAction(
  value: string,
): "generate" | "apply" | "verify" {
  if (value !== "generate" && value !== "apply" && value !== "verify") {
    throw new Error("Invalid remediation action.");
  }
  return value;
}

async function regularFileExists(candidate: string): Promise<boolean> {
  try {
    return (await lstat(candidate)).isFile();
  } catch {
    return false;
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
