import * as vscode from "vscode";
import { FindingDetail } from "../../protocol/src";
import { SecurityCodeActionProvider } from "./codeActions";
import { SecurityController } from "./controller";
import { SecurityDiagnostics } from "./diagnostics";
import { StructuredLogger } from "./logger";
import { SecurityWebviewProvider } from "./webviewProvider";

let activeController: SecurityController | undefined;
let activeProvider: SecurityWebviewProvider | undefined;

function workspaceRoot(): string | undefined {
  const active = vscode.window.activeTextEditor?.document.uri;
  if (active) {
    const folder = vscode.workspace.getWorkspaceFolder(active);
    if (folder?.uri.scheme === "file") return folder.uri.fsPath;
  }
  return vscode.workspace.workspaceFolders?.find((folder) => folder.uri.scheme === "file")?.uri.fsPath;
}

function occurrenceFromArgument(argument: unknown, diagnostics: SecurityDiagnostics | undefined): string | undefined {
  if (typeof argument === "string") return argument;
  if (argument instanceof vscode.Diagnostic) return diagnostics?.occurrenceFor(argument);
  if (argument && typeof argument === "object") {
    const candidate = argument as Partial<FindingDetail> & { occurrenceId?: unknown };
    if (typeof candidate.occurrenceId === "string") return candidate.occurrenceId;
  }
  return undefined;
}

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  const output = vscode.window.createOutputChannel("Kiro Security Power", { log: true });
  const logger = new StructuredLogger(output);
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 80);
  const root = workspaceRoot();
  let diagnostics: SecurityDiagnostics | undefined;
  if (root) {
    diagnostics = new SecurityDiagnostics(
      vscode.languages.createDiagnosticCollection("kiro-security-power"),
      root,
      (occurrenceId) => activeController?.findingLink(occurrenceId) ?? vscode.Uri.parse("command:kiroSecurity.openPanel"),
    );
  }

  const controller = new SecurityController(context, root, statusBar, diagnostics, logger);
  const provider = new SecurityWebviewProvider(context, controller);
  activeController = controller;
  activeProvider = provider;
  controller.setViewSink(provider);

  context.subscriptions.push(
    output,
    statusBar,
    diagnostics ?? { dispose: () => undefined },
    provider,
    vscode.window.registerWebviewViewProvider("kiroSecurity.securityView", provider, {
      webviewOptions: { retainContextWhenHidden: true },
    }),
    vscode.window.registerUriHandler({ handleUri: (uri) => controller.handleUri(uri) }),
    vscode.languages.registerCodeActionsProvider(
      { scheme: "file" },
      new SecurityCodeActionProvider(diagnostics),
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] },
    ),
    vscode.commands.registerCommand("kiroSecurity.openPanel", async () => {
      await vscode.commands.executeCommand("workbench.view.extension.kiroSecurity");
      await vscode.commands.executeCommand("kiroSecurity.securityView.focus");
    }),
    vscode.commands.registerCommand("kiroSecurity.openPanelRight", async () => {
      try {
        await vscode.commands.executeCommand("workbench.view.extension.kiroSecurity");
        await vscode.commands.executeCommand("kiroSecurity.securityView.focus");
        await vscode.commands.executeCommand("workbench.action.moveViewToSecondarySideBar");
        await context.globalState.update("kiroSecurity.secondarySidebarOnboarded", true);
        await controller.refresh();
      } catch (error) {
        logger.log("warning", "Secondary Side Bar placement was unavailable; opening beside editor", { error: String(error) });
        await provider.openBesidePanel();
      }
    }),
    vscode.commands.registerCommand("kiroSecurity.startFastScan", (uri?: vscode.Uri) => controller.startScanForUri("standard", uri)),
    vscode.commands.registerCommand("kiroSecurity.startStandardScan", () => controller.startScan("standard", { analysisProfile: "model" })),
    vscode.commands.registerCommand("kiroSecurity.startDeepScan", (uri?: vscode.Uri) => controller.startScanForUri("deep", uri)),
    vscode.commands.registerCommand("kiroSecurity.scanGitChanges", () => controller.startScan("diff", { diffTargetKind: "working_tree" })),
    vscode.commands.registerCommand("kiroSecurity.refreshThreatModel", () => controller.refreshThreatModel()),
    vscode.commands.registerCommand("kiroSecurity.resumeLastScan", () => controller.resumeScan()),
    vscode.commands.registerCommand("kiroSecurity.cancelActiveScan", () => controller.cancelScan()),
    vscode.commands.registerCommand("kiroSecurity.openFinding", (argument?: unknown) => controller.openFinding(occurrenceFromArgument(argument, diagnostics))),
    vscode.commands.registerCommand("kiroSecurity.showFindingDetails", async (argument?: unknown) => {
      await vscode.commands.executeCommand("kiroSecurity.openPanel");
      await controller.openFinding(occurrenceFromArgument(argument, diagnostics), false);
    }),
    vscode.commands.registerCommand("kiroSecurity.validateFinding", async (argument?: unknown) => {
      const occurrenceId = occurrenceFromArgument(argument, diagnostics);
      const finding = occurrenceId ? await controller.openFinding(occurrenceId, false) : await controller.openFinding(undefined, false);
      if (finding) await controller.validateFinding(finding.occurrenceId);
    }),
    vscode.commands.registerCommand("kiroSecurity.createRemediation", async (argument?: unknown) => {
      const occurrenceId = occurrenceFromArgument(argument, diagnostics);
      const finding = occurrenceId ? await controller.openFinding(occurrenceId, false) : await controller.openFinding(undefined, false);
      if (finding) await controller.createRemediation(finding.occurrenceId);
    }),
    vscode.commands.registerCommand("kiroSecurity.createTrackingHandoff", async (argument?: unknown) => {
      const occurrenceId = occurrenceFromArgument(argument, diagnostics);
      const finding = occurrenceId ? await controller.openFinding(occurrenceId, false) : await controller.openFinding(undefined, false);
      if (finding) await controller.createTrackingHandoff(finding.occurrenceId);
    }),
    vscode.commands.registerCommand("kiroSecurity.exportReport", () => controller.exportReport()),
    vscode.commands.registerCommand("kiroSecurity.openLogs", () => logger.show()),
    vscode.commands.registerCommand("kiroSecurity.installAgentIntegration", () => controller.installAgentIntegration()),
    vscode.commands.registerCommand("kiroSecurity.verifyAgentIntegration", () => controller.verifyAgentIntegration()),
    vscode.commands.registerCommand("kiroSecurity.removeAgentIntegration", () => controller.removeAgentIntegration()),
    vscode.commands.registerCommand("kiroSecurity.openMcpConfig", () => controller.openMcpConfig()),
    vscode.commands.registerCommand("kiroSecurity.retryEngine", () => controller.retryEngine()),
    vscode.workspace.onDidGrantWorkspaceTrust(() => {
      void controller.initialize()
        .catch((error: unknown) => controller.reportError("Workspace trust initialization failed", error));
    }),
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration("kiroSecurity")) void controller.configurationChanged(event);
    }),
  );

  logger.log("info", "Kiro Security Power activated", {
    version: context.extension.packageJSON.version,
    workspace: root ?? null,
    trusted: vscode.workspace.isTrusted,
  });
  await controller.initialize();
  controller.startPolling();
}

export async function deactivate(): Promise<void> {
  activeProvider?.dispose();
  await activeController?.disposeAsync();
  activeProvider = undefined;
  activeController = undefined;
}
