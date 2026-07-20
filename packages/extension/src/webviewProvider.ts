import * as crypto from "node:crypto";
import * as vscode from "vscode";
import { EngineEventName, WebviewMessage, WebviewSnapshot, validateWebviewMessage } from "../../protocol/src";
import { SecurityController, SecurityViewSink } from "./controller";

export class SecurityWebviewProvider implements vscode.WebviewViewProvider, SecurityViewSink, vscode.Disposable {
  private view: vscode.WebviewView | undefined;
  private readonly panels = new Set<vscode.WebviewPanel>();
  private readonly messageListeners = new Set<vscode.Disposable>();
  private disposed = false;

  constructor(
    private readonly context: vscode.ExtensionContext,
    private readonly controller: SecurityController,
  ) {}

  resolveWebviewView(view: vscode.WebviewView): void {
    this.view = view;
    const listener = this.configureWebview(view.webview);
    view.webview.html = this.html(view.webview);
    view.onDidDispose(() => {
      listener.dispose();
      this.messageListeners.delete(listener);
      if (this.view === view) this.view = undefined;
    });
    void view.webview.postMessage({ type: "snapshot", snapshot: this.controller.snapshot() });
  }

  async openBesidePanel(): Promise<void> {
    const panel = vscode.window.createWebviewPanel(
      "kiroSecurity.securityPanel",
      "Kiro Security Power",
      { viewColumn: vscode.ViewColumn.Beside, preserveFocus: false },
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        localResourceRoots: this.localResourceRoots(),
      },
    );
    this.panels.add(panel);
    const listener = this.configureWebview(panel.webview);
    panel.webview.html = this.html(panel.webview);
    panel.onDidDispose(() => {
      listener.dispose();
      this.messageListeners.delete(listener);
      this.panels.delete(panel);
    });
    await panel.webview.postMessage({ type: "snapshot", snapshot: this.controller.snapshot() });
  }

  postSnapshot(snapshot: WebviewSnapshot): void {
    if (this.disposed) return;
    void this.view?.webview.postMessage({ type: "snapshot", snapshot });
    for (const panel of this.panels) void panel.webview.postMessage({ type: "snapshot", snapshot });
  }

  postEvent(name: EngineEventName, params: Record<string, unknown>): void {
    if (this.disposed) return;
    const message = { type: "event", name, params };
    void this.view?.webview.postMessage(message);
    for (const panel of this.panels) void panel.webview.postMessage(message);
  }

  postNavigation(tab: "setup" | "dashboard" | "findings" | "history"): void {
    if (this.disposed) return;
    const message = { type: "navigate", tab };
    void this.view?.webview.postMessage(message);
    for (const panel of this.panels) void panel.webview.postMessage(message);
  }

  isVisible(): boolean {
    if (this.view?.visible) return true;
    for (const panel of this.panels) if (panel.visible) return true;
    return false;
  }

  private configureWebview(webview: vscode.Webview): vscode.Disposable {
    webview.options = {
      enableScripts: true,
      localResourceRoots: this.localResourceRoots(),
    };
    const listener = webview.onDidReceiveMessage((raw: unknown) => {
      const message = validateWebviewMessage(raw);
      if (!message) {
        this.controller.logger.log("warning", "Rejected malformed webview message");
        return;
      }
      void this.handleMessage(message).catch((error: unknown) => this.controller.reportError("Webview action failed", error));
    });
    this.messageListeners.add(listener);
    return listener;
  }

  private localResourceRoots(): vscode.Uri[] {
    return [
      vscode.Uri.joinPath(this.context.extensionUri, "dist", "webview"),
      vscode.Uri.joinPath(this.context.extensionUri, "media"),
    ];
  }

  private async handleMessage(message: WebviewMessage): Promise<void> {
    switch (message.type) {
      case "ready":
      case "refresh":
        await this.controller.refresh();
        return;
      case "startScan":
        await this.controller.startScan(message.mode, message);
        return;
      case "resumeScan":
        await this.controller.resumeScan(message.scanId);
        return;
      case "cancelScan":
        await this.controller.cancelScan(message.scanId);
        return;
      case "selectScan":
        await this.controller.selectScan(message.scanId);
        return;
      case "openFinding":
        await this.controller.openFinding(message.occurrenceId, false);
        return;
      case "openSource":
        await this.controller.openFinding(message.occurrenceId, true);
        return;
      case "validateFinding":
        await this.controller.validateFinding(message.occurrenceId);
        return;
      case "triageFinding":
        await this.controller.triageFinding(message.occurrenceId, message.decision, message.note);
        return;
      case "createRemediation":
        await this.controller.createRemediation(message.occurrenceId);
        return;
      case "createTrackingHandoff":
        await this.controller.createTrackingHandoff(message.occurrenceId, message.provider);
        return;
      case "createHardening":
        await this.controller.createHardening(message.scanId);
        return;
      case "cleanupScan":
        await this.controller.cleanupScan(message.scanId);
        return;
      case "exportReport":
        await this.controller.exportReport(message.scanId, message.format);
        return;
      case "exportFinding":
        await this.controller.exportFinding(message.occurrenceId, message.format);
        return;
      case "openArtifact":
        await this.controller.openArtifact(message.path);
        return;
      case "copyFindingLink":
        await this.controller.copyFindingLink(message.occurrenceId);
        return;
      case "openSettings":
        await this.controller.configure();
        return;
      case "openLogs":
        this.controller.logger.show();
        return;
      case "copyMcpConfig":
        await this.controller.copyMcpConfig();
        return;
      case "installAgentIntegration":
        await this.controller.installAgentIntegration(message.scope, message.autoApprovePolicy);
        return;
      case "verifyAgentIntegration":
        await this.controller.verifyAgentIntegration();
        return;
      case "removeAgentIntegration":
        await this.controller.removeAgentIntegration();
        return;
      case "openMcpConfig":
        await this.controller.openMcpConfig(message.scope);
        return;
      case "revealPowerBundle":
        await this.controller.revealPowerBundle();
        return;
      case "markPowerImported":
        await this.controller.markPowerImported();
        return;
      case "retryEngine":
        await this.controller.retryEngine();
        return;
    }
  }

  private html(webview: vscode.Webview): string {
    const nonce = crypto.randomBytes(18).toString("base64url");
    const scriptUri = webview.asWebviewUri(vscode.Uri.joinPath(this.context.extensionUri, "dist", "webview", "main.js"));
    const styleUri = webview.asWebviewUri(vscode.Uri.joinPath(this.context.extensionUri, "dist", "webview", "styles.css"));
    const csp = [
      "default-src 'none'",
      `img-src ${webview.cspSource} data:`,
      `style-src ${webview.cspSource}`,
      `font-src ${webview.cspSource}`,
      `script-src 'nonce-${nonce}'`,
      "connect-src 'none'",
      "frame-src 'none'",
    ].join("; ");
    return `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="${csp}">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="stylesheet" href="${styleUri}">
  <title>Kiro Security Power</title>
</head>
<body>
  <main id="app" aria-busy="true"><div class="loading">Loading Kiro Security Power…</div></main>
  <div id="live-region" class="sr-only" aria-live="polite"></div>
  <script nonce="${nonce}" src="${scriptUri}"></script>
</body>
</html>`;
  }

  dispose(): void {
    this.disposed = true;
    for (const panel of this.panels) panel.dispose();
    this.panels.clear();
    for (const listener of this.messageListeners) listener.dispose();
    this.messageListeners.clear();
  }
}
