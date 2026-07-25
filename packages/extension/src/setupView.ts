import * as path from "node:path";

import * as vscode from "vscode";

import type { FoundationPaths } from "./foundation";

const VIEW_ID = "kiroSecurity.setup";

export class SecuritySetupView implements vscode.WebviewViewProvider {
  static readonly viewId = VIEW_ID;

  constructor(private readonly paths: FoundationPaths) {}

  resolveWebviewView(view: vscode.WebviewView): void {
    view.webview.options = { enableScripts: false };
    view.webview.html = renderSetupHtml({
      webview: view.webview,
      stateRoot: this.paths.stateRoot.fsPath,
      powerRoot: path.join(
        this.paths.stateRoot.fsPath,
        "agent-integration",
        "kiro-security-power",
      ),
    });
  }
}

export function renderSetupHtml(input: {
  readonly webview: vscode.Webview;
  readonly stateRoot: string;
  readonly powerRoot: string;
}): string {
  const csp = [
    "default-src 'none'",
    `style-src ${input.webview.cspSource} 'unsafe-inline'`,
  ].join("; ");
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
    <button class="icon-button" disabled title="UI preview" aria-label="Refresh setup state">↻</button>
  </header>

  <nav class="tabs" aria-label="Security panel sections">
    <button class="tab active" aria-current="page">Setup</button>
    <button class="tab" disabled>Dashboard</button>
    <button class="tab" disabled>Findings</button>
  </nav>

  <main class="content">
    <div class="preview-note">
      <span class="preview-dot" aria-hidden="true"></span>
      UI preview only · setup actions are not connected yet
    </div>

    <section class="card">
      <div class="card-title">
        <div>
          <h2>Connect Kiro Chat</h2>
          <p>Bind security workspaces to the Kiro chat that started them.</p>
        </div>
        <span class="badge badge-neutral">not configured</span>
      </div>
      <p class="setup-status"><strong>Secure chat binding is not configured</strong></p>
      <p class="muted">This screen currently presents the intended setup experience only. It does not install Hooks or change Kiro user settings.</p>
      <div class="button-row">
        <button class="primary" disabled>Enable secure chat binding</button>
      </div>

      <details class="setup-options">
        <summary>Installation options</summary>
        <div class="setup-options-body">
          <dl>
            <dt>Installation scope</dt>
            <dd>Current user · all Kiro chats</dd>
            <dt>Changed file</dt>
            <dd>Not selected</dd>
            <dt>Matched tools</dt>
            <dd>Kiro Security workspace and scan calls</dd>
          </dl>
        </div>
      </details>

      <details class="setup-options">
        <summary>Advanced and troubleshooting</summary>
        <div class="setup-options-body">
          <div class="button-row">
            <button disabled>Verify again</button>
            <button disabled>Show changed file</button>
            <button disabled>Repair</button>
            <button class="danger" disabled>Remove chat binding</button>
          </div>
        </div>
      </details>
    </section>

    <section class="card">
      <div class="card-title">
        <div>
          <h2>Power integration</h2>
          <p>Prepare the self-contained Power, then import it in Kiro.</p>
        </div>
        <span class="badge badge-neutral">not configured</span>
      </div>
      <ol class="steps">
        <li>Prepare the Power folder from this Extension.</li>
        <li>Open Kiro Powers → Add Custom Power → Import power from a folder.</li>
        <li>Start a new normal chat after setup is complete.</li>
      </ol>
      <div class="button-row">
        <button class="primary" disabled>Prepare Power</button>
        <button disabled>Reveal folder</button>
      </div>
      <p class="mono muted">${escapeHtml(input.powerRoot)}</p>
    </section>

    <details class="card setup-disclosure" open>
      <summary>
        <span>
          <strong>System checks</strong>
          <small>Foundation and integration preview</small>
        </span>
      </summary>
      <div class="checks">
        ${checkRow("Global storage", input.stateRoot, true)}
        ${checkRow("Secure chat binding", "Not configured", false)}
        ${checkRow("Power runtime", "Not configured", false)}
      </div>
    </details>
  </main>
</body>
</html>`;
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
    }
    button:disabled { opacity: .5; cursor: default; }
    button.primary {
      color: var(--vscode-button-foreground);
      background: var(--vscode-button-background);
    }
    button.danger { color: var(--vscode-errorForeground); }
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
    .preview-note {
      display: flex;
      align-items: center;
      gap: 7px;
      color: var(--vscode-descriptionForeground);
      font-size: 12px;
    }
    .preview-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--vscode-editorWarning-foreground);
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
    }
    .badge-neutral {
      color: var(--vscode-descriptionForeground);
      border: 1px solid var(--vscode-panel-border);
      background: transparent;
    }
    .setup-status { margin-top: 14px !important; }
    .muted {
      color: var(--vscode-descriptionForeground);
      overflow-wrap: anywhere;
    }
    .mono {
      font-family: var(--vscode-editor-font-family);
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
