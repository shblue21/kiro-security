import { randomBytes } from "node:crypto";
import { lstat } from "node:fs/promises";

import * as vscode from "vscode";

import type { FoundationPaths } from "./foundation";
import {
  KiroIntegrationManager,
  type KiroIntegrationInspection,
} from "./integration";

const VIEW_ID = "kiroSecurity.setup";

type SetupCommand =
  | "refresh"
  | "connectIntegration"
  | "showHookFile"
  | "showMcpFile"
  | "showSteeringFile";

export class SecuritySetupView implements vscode.WebviewViewProvider {
  static readonly viewId = VIEW_ID;
  private readonly integration: KiroIntegrationManager;
  private busy = false;
  private feedback: string | undefined;

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

  private async connectIntegration(): Promise<void> {
    const approved = await vscode.window.showWarningMessage(
      "Connect Kiro Security to normal Kiro chats for this user?",
      {
        modal: true,
        detail: [
          `Adds only the installation-specific '${this.integration.serverKey}' entry in ${this.integration.mcpPath}.`,
          "Auto-approves only this installation's non-Start/non-Cancel MCP tools. Start and Cancel remain subject to Kiro's approval policy.",
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
        hookPath: this.integration.chatBinding.hookPath,
        mcpPath: this.integration.mcpPath,
        steeringPath: this.integration.steeringPath,
        runtimeRoot: this.integration.runtimeRoot,
      };
    }
    view.webview.html = renderSetupHtml({
      webview: view.webview,
      stateRoot: this.paths.stateRoot.fsPath,
      integration,
      feedback: this.feedback,
    });
  }
}

export function renderSetupHtml(input: {
  readonly webview: vscode.Webview;
  readonly stateRoot: string;
  readonly integration: KiroIntegrationInspection;
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
    <button class="tab active" aria-current="page">Setup</button>
    <button class="tab" disabled>Dashboard</button>
    <button class="tab" disabled>Findings</button>
  </nav>

  <main class="content">
    ${
      input.feedback
        ? `<div class="feedback">${escapeHtml(input.feedback)}</div>`
        : ""
    }

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
      </div>
    </details>
  </main>
  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    for (const button of document.querySelectorAll('[data-command]')) {
      button.addEventListener('click', () => {
        if (!button.disabled) {
          vscode.postMessage({ command: button.dataset.command });
        }
      });
    }
  </script>
</body>
</html>`;
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
      gap: 7px;
      margin-top: 12px;
    }
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

function isSetupMessage(value: unknown): value is { command: SetupCommand } {
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
    "connectIntegration",
    "showHookFile",
    "showMcpFile",
    "showSteeringFile",
  ]).has((value as { command: SetupCommand }).command);
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
