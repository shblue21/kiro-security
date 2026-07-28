import { randomBytes } from "node:crypto";
import { lstat } from "node:fs/promises";
import * as path from "node:path";

import * as vscode from "vscode";

import {
  ChatBindingManager,
  type ChatBindingInspection,
} from "./chatBinding";
import type { FoundationPaths } from "./foundation";
import { preparePowerIntegration } from "./powerIntegration";

const VIEW_ID = "kiroSecurity.setup";

type SetupCommand =
  | "refresh"
  | "enableChatBinding"
  | "verifyChatBinding"
  | "showHookFile"
  | "repairChatBinding"
  | "removeChatBinding"
  | "preparePower"
  | "revealPower";

export class SecuritySetupView implements vscode.WebviewViewProvider {
  static readonly viewId = VIEW_ID;
  private readonly chatBinding: ChatBindingManager;
  private readonly powerRoot: string;
  private busy = false;
  private feedback: string | undefined;

  constructor(
    private readonly context: vscode.ExtensionContext,
    private readonly paths: FoundationPaths,
    private readonly output: vscode.OutputChannel,
  ) {
    this.chatBinding = new ChatBindingManager(context, paths);
    this.powerRoot = path.join(
      paths.stateRoot.fsPath,
      "agent-integration",
      "kiro-security-power",
    );
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
        case "enableChatBinding":
          await this.enableChatBinding();
          break;
        case "verifyChatBinding":
          await this.chatBinding.verify();
          this.feedback = "Hook registration and bridge probe passed.";
          await vscode.window.showInformationMessage(
            "Kiro Security Hook transport verification passed.",
          );
          break;
        case "showHookFile":
          await this.showHookFile();
          break;
        case "repairChatBinding":
          await this.repairChatBinding();
          break;
        case "removeChatBinding":
          await this.removeChatBinding();
          break;
        case "preparePower":
          await this.preparePower();
          break;
        case "revealPower":
          await this.revealPower();
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

  private async enableChatBinding(): Promise<void> {
    const approved = await vscode.window.showWarningMessage(
      "Enable the Kiro Security Hook transport for this user?",
      {
        modal: true,
        detail: [
          `This creates only ${this.chatBinding.hookPath} outside Extension global storage.`,
          "The user-level Hook is visible to all Kiro chats, but it matches only the Kiro Powers wrapper and the bridge accepts only this Power's exact server and tools.",
          "No Agent configuration or other Hook file is changed.",
        ].join("\n\n"),
      },
      "Enable",
    );
    if (approved !== "Enable") {
      return;
    }
    const result = await this.chatBinding.install();
    this.feedback = result.changed
      ? "Hook transport installed and verified."
      : "Hook transport was already current and verified.";
    this.output.appendLine(this.feedback);
  }

  private async repairChatBinding(): Promise<void> {
    const approved = await vscode.window.showWarningMessage(
      "Repair the dedicated Kiro Security Hook registration?",
      {
        modal: true,
        detail:
          "The dedicated file will be replaced atomically. Other Hook and Agent files are not touched.",
      },
      "Repair",
    );
    if (approved !== "Repair") {
      return;
    }
    const result = await this.chatBinding.repair();
    this.feedback = result.changed
      ? "Hook transport repaired."
      : "Hook transport is current and verified.";
    this.output.appendLine(this.feedback);
  }

  private async removeChatBinding(): Promise<void> {
    const approved = await vscode.window.showWarningMessage(
      "Remove the dedicated Kiro Security Hook registration?",
      {
        modal: true,
        detail:
          "Only the dedicated ~/.kiro/hooks/kiro-security-power.json file is removed. Database and scan data are preserved.",
      },
      "Remove",
    );
    if (approved !== "Remove") {
      return;
    }
    const result = await this.chatBinding.remove();
    this.feedback = result.changed
      ? "Hook registration removed."
      : "Hook registration was already absent.";
    this.output.appendLine(this.feedback);
  }

  private async showHookFile(): Promise<void> {
    if (!(await regularFileExists(this.chatBinding.hookPath))) {
      await vscode.window.showInformationMessage(
        "The Kiro Security Hook registration does not exist yet.",
      );
      return;
    }
    await vscode.commands.executeCommand(
      "vscode.open",
      vscode.Uri.file(this.chatBinding.hookPath),
    );
  }

  private async preparePower(): Promise<void> {
    const prepared = await preparePowerIntegration(this.context, this.paths);
    this.feedback = `Power prepared at ${prepared.powerRoot}`;
    this.output.appendLine(this.feedback);
    this.output.appendLine(`Python runtime: ${prepared.pythonExecutable}`);
    const selection = await vscode.window.showInformationMessage(
      "Kiro Security Power is ready to import from its global-storage folder.",
      "Reveal Folder",
    );
    if (selection === "Reveal Folder") {
      await this.revealPower();
    }
  }

  private async revealPower(): Promise<void> {
    if (!(await regularDirectoryExists(this.powerRoot))) {
      await vscode.window.showInformationMessage(
        "Prepare the Power integration before revealing its folder.",
      );
      return;
    }
    await vscode.commands.executeCommand(
      "revealFileInOS",
      vscode.Uri.file(this.powerRoot),
    );
  }

  private async refresh(view: vscode.WebviewView): Promise<void> {
    let chatBinding: ChatBindingInspection;
    try {
      chatBinding = await this.chatBinding.inspect();
    } catch (error) {
      chatBinding = {
        state: "unavailable",
        registrationState: "absent",
        hookPath: this.chatBinding.hookPath,
        bridgePath: this.chatBinding.bridgePath,
        detail: errorMessage(error),
      };
    }
    view.webview.html = renderSetupHtml({
      webview: view.webview,
      stateRoot: this.paths.stateRoot.fsPath,
      powerRoot: this.powerRoot,
      powerReady: await regularDirectoryExists(this.powerRoot),
      chatBinding,
      feedback: this.feedback,
    });
  }
}

export function renderSetupHtml(input: {
  readonly webview: vscode.Webview;
  readonly stateRoot: string;
  readonly powerRoot: string;
  readonly powerReady: boolean;
  readonly chatBinding: ChatBindingInspection;
  readonly feedback?: string;
}): string {
  const nonce = randomBytes(16).toString("base64");
  const csp = [
    "default-src 'none'",
    `style-src ${input.webview.cspSource} 'unsafe-inline'`,
    `script-src 'nonce-${nonce}'`,
  ].join("; ");
  const presentation = bindingPresentation(input.chatBinding);
  const canRemove =
    input.chatBinding.registrationState === "installed" ||
    input.chatBinding.registrationState === "repairable";
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
          <p>Install the user-level Hook transport used by normal Kiro chats.</p>
        </div>
        <span class="badge ${presentation.badgeClass}">${escapeHtml(
          presentation.badge,
        )}</span>
      </div>
      <p class="setup-status"><strong>${escapeHtml(
        presentation.heading,
      )}</strong></p>
      <p class="muted">${escapeHtml(input.chatBinding.detail)}</p>
      <p class="scope-note">This phase validates Kiro's Hook-delivered <code>session_id</code> at the transport boundary. End-to-end one-time MCP attestation is not implemented yet, so this is not full trusted chat ownership parity.</p>
      <div class="button-row">
        <button class="primary" data-command="enableChatBinding" ${
          input.chatBinding.state === "absent" ? "" : "disabled"
        }>Enable Hook transport</button>
      </div>

      <details class="setup-options">
        <summary>Installation options</summary>
        <div class="setup-options-body">
          <dl>
            <dt>Installation scope</dt>
            <dd>Current user · all Kiro chats</dd>
            <dt>Changed Kiro file</dt>
            <dd class="mono">${escapeHtml(input.chatBinding.hookPath)}</dd>
            <dt>Matcher</dt>
            <dd><code>^kiro_powers$</code>; bridge filters exact Power, server, and tool names</dd>
            <dt>Bridge</dt>
            <dd class="mono">${escapeHtml(input.chatBinding.bridgePath)}</dd>
          </dl>
        </div>
      </details>

      <details class="setup-options">
        <summary>Advanced and troubleshooting</summary>
        <div class="setup-options-body">
          <div class="button-row">
            <button data-command="verifyChatBinding" ${
              input.chatBinding.state === "ready" ? "" : "disabled"
            }>Verify again</button>
            <button data-command="showHookFile" ${
              input.chatBinding.registrationState === "absent"
                ? "disabled"
                : ""
            }>Show changed file</button>
            <button data-command="repairChatBinding" ${
              input.chatBinding.state === "repairable" ? "" : "disabled"
            }>Repair</button>
            <button class="danger" data-command="removeChatBinding" ${
              canRemove ? "" : "disabled"
            }>Remove Hook transport</button>
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
        <span class="badge ${
          input.powerReady ? "badge-ready" : "badge-neutral"
        }">${input.powerReady ? "prepared" : "not prepared"}</span>
      </div>
      <ol class="steps">
        <li>Prepare the Power folder from this Extension.</li>
        <li>Open Kiro Powers → Add Custom Power → Import power from a folder.</li>
        <li>Start a new normal chat after setup is complete.</li>
      </ol>
      <div class="button-row">
        <button class="primary" data-command="preparePower">Prepare Power</button>
        <button data-command="revealPower" ${
          input.powerReady ? "" : "disabled"
        }>Reveal folder</button>
      </div>
      <p class="mono muted">${escapeHtml(input.powerRoot)}</p>
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
          "Kiro Hook transport",
          presentation.heading,
          input.chatBinding.state === "ready",
        )}
        ${checkRow(
          "Power runtime",
          input.powerReady ? "Prepared" : "Not prepared",
          input.powerReady,
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

function bindingPresentation(binding: ChatBindingInspection): {
  readonly badge: string;
  readonly badgeClass: string;
  readonly heading: string;
} {
  switch (binding.state) {
    case "ready":
      return {
        badge: "installed",
        badgeClass: "badge-ready",
        heading: "Hook transport is installed",
      };
    case "repairable":
      return {
        badge: "repair needed",
        badgeClass: "badge-warning",
        heading: "Dedicated Hook transport needs repair",
      };
    case "conflict":
      return {
        badge: "conflict",
        badgeClass: "badge-error",
        heading: "The dedicated Hook path is occupied",
      };
    case "unavailable":
      return {
        badge: "unavailable",
        badgeClass: "badge-error",
        heading: "Hook transport cannot be configured",
      };
    case "absent":
      return {
        badge: "not installed",
        badgeClass: "badge-neutral",
        heading: "Hook transport is not installed",
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
    button.danger { color: var(--vscode-errorForeground); }
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
    "enableChatBinding",
    "verifyChatBinding",
    "showHookFile",
    "repairChatBinding",
    "removeChatBinding",
    "preparePower",
    "revealPower",
  ]).has((value as { command: SetupCommand }).command);
}

async function regularFileExists(candidate: string): Promise<boolean> {
  try {
    return (await lstat(candidate)).isFile();
  } catch {
    return false;
  }
}

async function regularDirectoryExists(candidate: string): Promise<boolean> {
  try {
    const metadata = await lstat(candidate);
    return metadata.isDirectory() && !metadata.isSymbolicLink();
  } catch {
    return false;
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
