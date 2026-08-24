import { lstat } from "node:fs/promises";
import * as path from "node:path";

import * as vscode from "vscode";

import type { FoundationPaths } from "../foundation";
import {
  KiroIntegrationManager,
  type KiroIntegrationInspection,
} from "../integration/integration";
import {
  SCAN_PROMPT,
  recoveryPrompt,
  remediationPrompt,
  trackingPrompt,
} from "./chatPrompts";
import { ScanAccess, currentWorkspace, requiredValue } from "./scanAccess";
import { renderSetupHtml, type ViewTab } from "./setupViewHtml";
import {
  WorkbenchAdminClient,
  type DashboardProjection,
} from "../workbench/workbenchClient";
import {
  isScanInWorkspace,
  projectDashboard,
  type RepositoryScope,
} from "../workbench/workspaceProjection";

export { renderSetupHtml } from "./setupViewHtml";

const VIEW_ID = "kiroSecurity.setup";
const REPOSITORY_SCOPE_KEY = "kiroSecurity.repositoryScope.v1";

type SetupCommand =
  | "refresh"
  | "selectTab"
  | "selectRepositoryScope"
  | "connectIntegration"
  | "copyScanPrompt"
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
  readonly repositoryScope?: RepositoryScope;
  readonly scanId?: string;
  readonly occurrenceId?: string;
  readonly requestId?: string;
  readonly action?: "generate" | "apply" | "verify";
  readonly format?: "json" | "sarif" | "csv";
  readonly artifactKind?: "report" | "manifest" | "coverage";
}

export class SecuritySetupView implements vscode.WebviewViewProvider {
  static readonly viewId = VIEW_ID;
  private readonly integration: KiroIntegrationManager;
  private busy = false;
  private feedback: string | undefined;
  private activeTab: ViewTab = "setup";
  private repositoryScope: RepositoryScope;
  private dashboard: DashboardProjection | undefined;
  private readonly workspaceState: vscode.Memento;

  constructor(
    context: vscode.ExtensionContext,
    private readonly paths: FoundationPaths,
    private readonly output: vscode.OutputChannel,
    serverKey: string,
  ) {
    this.integration = new KiroIntegrationManager(context, paths, serverKey);
    this.repositoryScope =
      context.workspaceState.get<RepositoryScope>(REPOSITORY_SCOPE_KEY) ??
      "current";
    this.workspaceState = context.workspaceState;
  }

  resolveWebviewView(view: vscode.WebviewView): void {
    view.webview.options = {
      enableScripts: true,
    };
    const messageSubscription = view.webview.onDidReceiveMessage(
      async (message: unknown) => this.handleMessage(view, message),
    );
    const workspaceSubscription = vscode.workspace.onDidChangeWorkspaceFolders(
      () => void this.refresh(view),
    );
    view.onDidDispose(() => {
      messageSubscription.dispose();
      workspaceSubscription.dispose();
    });
    void this.refresh(view);
  }

  private async handleMessage(
    view: vscode.WebviewView,
    message: unknown,
  ): Promise<void> {
    if (!isSetupMessage(message)) {
      return;
    }
    if (message.command === "selectTab") {
      const tab = validViewTab(message.tab);
      if (tab) {
        this.activeTab = tab;
      }
      return;
    }
    if (this.busy) {
      return;
    }
    this.busy = true;
    this.feedback = undefined;
    try {
      switch (message.command) {
        case "refresh":
          break;
        case "selectRepositoryScope":
          this.repositoryScope = requiredRepositoryScope(
            message.repositoryScope,
          );
          await this.workspaceState.update(
            REPOSITORY_SCOPE_KEY,
            this.repositoryScope,
          );
          break;
        case "connectIntegration":
          await this.connectIntegration();
          break;
        case "copyScanPrompt":
          await vscode.env.clipboard.writeText(SCAN_PROMPT);
          this.feedback = "Scan prompt copied. Paste it into Kiro Chat.";
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
          await this.access().requireWorkspaceScanById(message.scanId);
          await this.createRecovery(message.scanId);
          break;
        case "cancelRecovery":
          await this.access().requireWorkspaceScanForRecovery(message.requestId);
          await this.callWorkbench("cancelRecovery", {
            requestId: requiredValue(message.requestId, "requestId"),
          });
          this.feedback = "Recovery request canceled.";
          break;
        case "openTriage":
          await this.access().requireVisibleScanForOccurrence(message.occurrenceId);
          await this.callWorkbench("setTriage", {
            occurrenceId: requiredValue(message.occurrenceId, "occurrenceId"),
            status: "open",
          });
          this.feedback = "Finding reopened.";
          break;
        case "closeTriage":
          await this.access().requireVisibleScanForOccurrence(message.occurrenceId);
          await this.closeTriage(message.occurrenceId);
          break;
        case "requestRemediation":
          await this.access().requireWorkspaceScanForOccurrence(message.occurrenceId);
          await this.requestRemediation(message);
          break;
        case "copyRemediationPrompt":
          await this.access().requireWorkspaceScanForRemediation(message.requestId);
          await this.copyCurrentRemediationPrompt(
            requiredValue(message.requestId, "requestId"),
          );
          break;
        case "exportScan":
          await this.access().requireVisibleScanById(message.scanId);
          await this.exportScan(message);
          break;
        case "openArtifact":
          await this.openArtifact(message);
          break;
        case "trackFinding":
          await this.access().requireVisibleScanForOccurrence(message.occurrenceId);
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
    args: Readonly<Record<string, unknown>> = {},
  ): Promise<T> {
    const pythonExecutable = await this.integration.getPythonExecutable();
    return new WorkbenchAdminClient(
      pythonExecutable,
      this.integration.launcherPath,
      this.paths.stateRoot.fsPath,
      this.paths.scanRoot.fsPath,
    ).call<T>(operation, args);
  }

  private async createRecovery(scanId: string | undefined): Promise<void> {
    const recovery = await this.callWorkbench<{
      readonly id: string;
      readonly scanId: string;
      readonly version: number;
    }>("createRecovery", {
      scanId: requiredValue(scanId, "scanId"),
    });
    await vscode.env.clipboard.writeText(recoveryPrompt(recovery));
    this.feedback = "Recovery prompt copied. Paste it into the Kiro chat that should resume the scan.";
  }

  private async openArtifact(message: SetupMessage): Promise<void> {
    const scan = await this.access().requireVisibleScanById(message.scanId);
    if (scan.status !== "complete") {
      throw new Error("Only completed scan artifacts can be opened.");
    }
    const names = {
      report: "report.md",
      manifest: "scan-manifest.json",
      coverage: "coverage.json",
    } as const;
    const kind = requiredArtifactKind(message.artifactKind);
    await this.showFile(
      path.join(scan.scanDir, names[kind]),
      "The selected scan artifact does not exist.",
    );
  }

  private access(): ScanAccess {
    return new ScanAccess(this.dashboard, this.repositoryScope);
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
    await vscode.env.clipboard.writeText(
      remediationPrompt(requestId, version, action),
    );
    this.feedback = "Remediation prompt copied. Paste it into Kiro Chat.";
  }

  private async copyCurrentRemediationPrompt(requestId: string): Promise<void> {
    const dashboard = await this.callWorkbench<DashboardProjection>("dashboard");
    const request = dashboard.remediationRequests.find(
      (candidate) => candidate.requestId === requestId,
    );
    if (!request?.pendingAction) {
      throw new Error("The remediation action is no longer pending.");
    }
    await this.copyRemediationPrompt(
      requestId,
      request.version,
      requiredRemediationAction(request.pendingAction),
    );
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
    await vscode.env.clipboard.writeText(
      trackingPrompt(tracking, exactOccurrence),
    );
    this.feedback = "Tracking workflow prompt copied. Paste it into Kiro Chat.";
  }

  private async connectIntegration(): Promise<void> {
    const result = await this.integration.install();
    if (result.restartRecommended) {
      this.feedback =
        "Security runtime updated. Restart Kiro if an existing chat was already using it.";
    }
    this.output.appendLine(
      result.changed
        ? "Kiro Security is connected to normal Kiro chats."
        : "Kiro Security integration was already current.",
    );
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
        this.dashboard = await this.callWorkbench<DashboardProjection>(
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
    const workspace = await currentWorkspace();
    const projectedDashboard = this.dashboard
      ? projectDashboard(this.dashboard, workspace.roots, this.repositoryScope)
      : undefined;
    const sourceActionScanIds = this.dashboard
      ? this.dashboard.scans
          .filter((scan) => isScanInWorkspace(scan, workspace.roots))
          .map((scan) => scan.id)
      : [];
    view.webview.html = renderSetupHtml({
      webview: view.webview,
      stateRoot: this.paths.stateRoot.fsPath,
      integration,
      activeTab: this.activeTab,
      dashboard: projectedDashboard,
      repositoryScope: this.repositoryScope,
      workspaceLabel: workspace.label,
      hasWorkspace: workspace.roots.length > 0,
      globalScanCount: this.dashboard?.scans.length ?? 0,
      sourceActionScanIds,
      feedback: this.feedback,
    });
  }
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
    "selectRepositoryScope",
    "connectIntegration",
    "copyScanPrompt",
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

function requiredRemediationAction(
  value: string,
): "generate" | "apply" | "verify" {
  if (value !== "generate" && value !== "apply" && value !== "verify") {
    throw new Error("Invalid remediation action.");
  }
  return value;
}

function requiredRepositoryScope(
  value: RepositoryScope | undefined,
): RepositoryScope {
  if (value !== "current" && value !== "all") {
    throw new Error("Invalid repository scope.");
  }
  return value;
}

function validViewTab(value: ViewTab | undefined): ViewTab | undefined {
  return value === "setup" || value === "dashboard" || value === "findings"
    ? value
    : undefined;
}

function requiredArtifactKind(
  value: SetupMessage["artifactKind"],
): "report" | "manifest" | "coverage" {
  if (value !== "report" && value !== "manifest" && value !== "coverage") {
    throw new Error("Invalid artifact kind.");
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
