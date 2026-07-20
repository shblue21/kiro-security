import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as vscode from "vscode";
import {
  AgentAutoApprovePolicy,
  AgentIntegrationOperation,
  AgentIntegrationScope,
  AgentIntegrationStatus,
  DashboardState,
  EngineEventName,
  ExportFormat,
  FindingDetail,
  FindingSummary,
  ScanMode,
  ScanRecord,
  TriageDecision,
  TrackingProvider,
  WebviewSnapshot,
} from "../../protocol/src";
import { AgentIntegrationError, AgentIntegrationManager } from "./agentIntegration";
import { SecurityDiagnostics } from "./diagnostics";
import { EngineClient, EngineEvent, EngineRpcError } from "./engineClient";
import { StructuredLogger } from "./logger";
import { isPathWithin, openSourceLocation } from "./navigation";

export interface SecurityViewSink {
  postSnapshot(snapshot: WebviewSnapshot): void;
  postEvent(name: EngineEventName, params: Record<string, unknown>): void;
  postNavigation(tab: "setup" | "dashboard" | "findings" | "history"): void;
  isVisible(): boolean;
}

export class SecurityController implements vscode.Disposable {
  private engine: EngineClient | undefined;
  private dashboard: DashboardState | null = null;
  private selectedFinding: FindingDetail | null = null;
  private selectedScanId: string | undefined;
  private selectedOccurrenceId: string | undefined;
  private viewSink: SecurityViewSink | undefined;
  private pollTimer: NodeJS.Timeout | undefined;
  private eventRefreshTimer: NodeJS.Timeout | undefined;
  private refreshPromise: Promise<void> | undefined;
  private lastEventSequence = 0;
  private lastSnapshotJson: string | undefined;
  private disposed = false;
  private registeredDefaultsKey: string | undefined;
  private readonly agentIntegration: AgentIntegrationManager;
  private agentIntegrationLastChecked = 0;
  private agentIntegrationStatus: AgentIntegrationStatus = {
    packaged: true, state: "not_configured", operation: "idle", configured: false, verified: false,
    serverName: "kiro-security-power", configLocations: [],
    dependencies: { python: { available: false, compatible: false, minimumVersion: "3.10.0" } },
    power: { packaged: true, prepared: false, manifestValid: false, registration: "not_prepared", importRequiresKiroConfirmation: true },
    details: [],
  };

  constructor(
    private readonly context: vscode.ExtensionContext,
    readonly workspaceRoot: string | undefined,
    private readonly statusBar: vscode.StatusBarItem,
    private readonly diagnostics: SecurityDiagnostics | undefined,
    readonly logger: StructuredLogger,
  ) {
    this.selectedScanId = context.workspaceState.get<string>("kiroSecurity.selectedScanId");
    this.selectedOccurrenceId = context.workspaceState.get<string>("kiroSecurity.selectedOccurrenceId");
    this.statusBar.command = "kiroSecurity.openPanel";
    this.statusBar.name = "Kiro Security Power";
    this.statusBar.show();
    this.agentIntegration = new AgentIntegrationManager({
      extensionRoot: context.extensionPath,
      workspaceRoot,
      globalStorageRoot: context.globalStorageUri.fsPath,
      productVersion: String(context.extension.packageJSON.version),
      logger,
    });
  }

  setViewSink(sink: SecurityViewSink): void {
    this.viewSink = sink;
    sink.postSnapshot(this.snapshot());
  }

  snapshot(): WebviewSnapshot {
    return {
      workspaceTrusted: vscode.workspace.isTrusted,
      workspaceRoot: this.workspaceRoot,
      engineStatus: this.engine?.status ?? "stopped",
      engineError: this.engine?.lastError,
      dashboard: this.dashboard,
      selectedFinding: this.selectedFinding,
      agentIntegration: this.agentIntegrationStatus,
      secondarySidebarOnboarded: this.context.globalState.get<boolean>("kiroSecurity.secondarySidebarOnboarded", false),
    };
  }

  async initialize(): Promise<void> {
    await this.refreshAgentIntegration(true, "checking");
    if (!this.workspaceRoot) {
      this.statusBar.text = "$(shield) Kiro Security: Open a folder";
      this.statusBar.tooltip = "Open a local workspace to use Kiro Security Power.";
      this.postSnapshot();
      return;
    }
    if (!vscode.workspace.isTrusted) {
      this.statusBar.text = "$(shield) Kiro Security: Workspace not trusted";
      this.statusBar.tooltip = "Trust this workspace before starting the security engine.";
      this.postSnapshot();
      return;
    }
    try {
      await this.ensureEngine();
      await this.refresh();
    } catch (error) {
      this.handleError("Engine initialization failed", error, false);
    }
  }

  startPolling(): void {
    if (this.pollTimer) clearInterval(this.pollTimer);
    const seconds = vscode.workspace.getConfiguration("kiroSecurity").get<number>("autoRefreshSeconds", 2);
    this.pollTimer = setInterval(() => void this.refresh(), Math.max(1, seconds) * 1000);
  }

  private async ensureEngine(): Promise<EngineClient> {
    if (!this.workspaceRoot) throw new Error("Open a local workspace before using Kiro Security Power.");
    if (!vscode.workspace.isTrusted) throw new Error("Workspace Trust is required before running security scans.");
    if (!this.engine) {
      const pythonPath = this.pythonPath();
      this.engine = new EngineClient(
        this.context.extensionPath,
        this.workspaceRoot,
        pythonPath,
        String(this.context.extension.packageJSON.version),
        this.logger,
      );
      this.context.subscriptions.push(this.engine.onEvent((event) => this.onEngineEvent(event)));
    }
    await this.engine.start();
    const config = vscode.workspace.getConfiguration("kiroSecurity");
    const defaultScope = this.validateScope(config.get<string>("defaultScope", "."));
    const defaultMode: ScanMode = "standard";
    const defaultsKey = `${defaultMode}\0${defaultScope}`;
    if (this.registeredDefaultsKey !== defaultsKey) {
      await this.engine.request("register_workspace", {
        workspaceRoot: this.workspaceRoot, defaultScope, defaultMode,
      }, 10_000, false);
      this.registeredDefaultsKey = defaultsKey;
    }
    return this.engine;
  }

  private onEngineEvent(event: EngineEvent): void {
    const sequence = event.params.sequence;
    if (typeof sequence === "number" && sequence > this.lastEventSequence) this.lastEventSequence = sequence;
    if (event.name === "engine.log") {
      const level = String(event.params.level ?? "info") as "debug" | "info" | "warning" | "error";
      this.logger.log(["debug", "info", "warning", "error"].includes(level) ? level : "info", String(event.params.message ?? "Engine log"), {
        scanId: event.params.scanId,
        code: event.params.code,
      });
    }
    this.viewSink?.postEvent(event.name, event.params);
    if (event.name === "scan.completed" && typeof event.params.scanId === "string") {
      void (async () => {
        if (this.viewSink?.isVisible()) {
          await this.selectScan(String(event.params.scanId));
          this.viewSink?.postNavigation("findings");
          return;
        }
        const choice = await vscode.window.showInformationMessage("Kiro Security scan completed.", "View findings");
        if (choice !== "View findings") return;
        await this.selectScan(String(event.params.scanId));
        await vscode.commands.executeCommand("kiroSecurity.openPanel");
        this.viewSink?.postNavigation("findings");
      })().catch((error: unknown) => this.handleError("Open completed scan", error, true));
    }
    this.scheduleRefresh();
  }

  private scheduleRefresh(): void {
    if (this.eventRefreshTimer) return;
    this.eventRefreshTimer = setTimeout(() => {
      this.eventRefreshTimer = undefined;
      void this.refresh();
    }, 200);
  }

  async refresh(): Promise<void> {
    if (this.disposed || !this.workspaceRoot || !vscode.workspace.isTrusted) {
      this.postSnapshot();
      return;
    }
    if (this.refreshPromise) return this.refreshPromise;
    this.refreshPromise = this.refreshInternal().finally(() => {
      this.refreshPromise = undefined;
    });
    return this.refreshPromise;
  }

  private async refreshInternal(): Promise<void> {
    try {
      if (this.engine?.status === "error") {
        await this.refreshAgentIntegration(false);
        this.postSnapshot();
        return;
      }
      const engine = await this.ensureEngine();
      const dashboard = await engine.request<DashboardState>("get_dashboard", { limit: 30 }, 20_000);
      if (this.selectedScanId && dashboard.selectedScan?.id !== this.selectedScanId) {
        const selected = dashboard.scans.find((scan) => scan.id === this.selectedScanId) ?? await engine.request<ScanRecord>("get_scan", { scanId: this.selectedScanId });
        const findings = await engine.request<FindingSummary[]>("list_findings", { scanId: selected.id, limit: 2000 });
        dashboard.selectedScan = selected;
        dashboard.findings = findings;
      } else if (dashboard.selectedScan) {
        this.selectedScanId = dashboard.selectedScan.id;
      }
      if (this.selectedOccurrenceId) {
        try {
          const detail = await engine.request<FindingDetail>("get_finding", { occurrenceId: this.selectedOccurrenceId });
          this.selectedFinding = detail.scanId === dashboard.selectedScan?.id ? detail : null;
        } catch {
          this.selectedFinding = null;
        }
      }
      this.dashboard = dashboard;
      await this.context.workspaceState.update("kiroSecurity.selectedScanId", this.selectedScanId);
      await this.refreshAgentIntegration(false);
      const showDiagnostics = vscode.workspace.getConfiguration("kiroSecurity").get<boolean>("showValidatedDiagnostics", true);
      await this.diagnostics?.refresh(dashboard.findings, showDiagnostics);
      await vscode.commands.executeCommand("setContext", "kiroSecurity.scanActive", Boolean(dashboard.activeScan));
      this.updateStatusBar();
      try {
        const events = await engine.request<Array<{ sequence: number; event: EngineEventName; payload: Record<string, unknown> }>>(
          "poll_events",
          { afterSequence: this.lastEventSequence, limit: 200 },
          10_000,
        );
        for (const event of events) {
          this.lastEventSequence = Math.max(this.lastEventSequence, event.sequence);
          this.viewSink?.postEvent(event.event, event.payload);
        }
      } catch (error) {
        this.logger.log("debug", "Event reconciliation skipped", { error: String(error) });
      }
      this.postSnapshot();
    } catch (error) {
      this.handleError("Failed to refresh security state", error, false);
    }
  }

  private updateStatusBar(): void {
    const active = this.dashboard?.activeScan;
    if (active) {
      const percent = Math.round(active.progress?.overall_percent ?? 0);
      this.statusBar.text = `$(sync~spin) Kiro Security: ${active.phase.replace(/_/g, " ")} ${percent}%`;
      this.statusBar.tooltip = active.progress?.message ?? `Scan ${active.id} is running.`;
      return;
    }
    const validated = this.dashboard?.findings.filter((finding) => finding.validationStatus === "validated" && !["false_positive", "already_fixed"].includes(finding.triageStatus)).length ?? 0;
    this.statusBar.text = `$(shield) Kiro Security: ${validated} validated`;
    this.statusBar.tooltip = this.dashboard?.selectedScan ? `Selected scan ${this.dashboard.selectedScan.id}` : "No scan selected.";
  }

  private postSnapshot(): void {
    const snapshot = this.snapshot();
    const serialized = JSON.stringify(snapshot);
    if (serialized === this.lastSnapshotJson) return;
    this.lastSnapshotJson = serialized;
    this.viewSink?.postSnapshot(snapshot);
  }

  private validateScope(scope: string): string {
    if (!this.workspaceRoot) throw new Error("No workspace is open.");
    if (!scope || scope.length > 4096 || scope.includes("\0") || path.isAbsolute(scope)) throw new Error("Scope must be a bounded workspace-relative path.");
    const resolved = path.resolve(this.workspaceRoot, scope);
    if (!isPathWithin(this.workspaceRoot, resolved)) throw new Error("Scope escapes the workspace boundary.");
    return path.relative(this.workspaceRoot, resolved) || ".";
  }

  private validateGitRef(value: string | undefined, field: string): string | undefined {
    if (value === undefined || value === "") return undefined;
    if (value.length > 256 || value.startsWith("-") || !/^[A-Za-z0-9._/@+\-~^:]+$/.test(value)) throw new Error(`${field} is not a safe Git revision.`);
    return value;
  }

  async startScan(
    mode: ScanMode,
    options: { scope?: string; analysisProfile?: "fast" | "model"; diffTargetKind?: "working_tree" | "commit" | "range"; diffBaseRevision?: string; diffHeadRevision?: string } = {},
  ): Promise<ScanRecord | undefined> {
    return this.userAction("Start scan", async () => {
      if (mode === "deep" || mode === "diff" || options.analysisProfile === "model") {
        const scope = this.validateScope(options.scope ?? vscode.workspace.getConfiguration("kiroSecurity").get<string>("defaultScope", "."));
        const label = mode === "diff" ? "Diff" : mode === "deep" ? "Deep" : "Standard";
        const prompt = [
          `Run a ${label} Kiro Security scan for workspace-relative scope ${JSON.stringify(scope)}.`,
          mode === "diff" ? `Diff target: ${options.diffTargetKind ?? "working_tree"}.` : undefined,
          options.diffBaseRevision ? `Base revision: ${this.validateGitRef(options.diffBaseRevision, "Base revision")}.` : undefined,
          options.diffHeadRevision ? `Head revision: ${this.validateGitRef(options.diffHeadRevision, "Head revision")}.` : undefined,
          "Use the installed kiro-security-power Agent tools and preserve their runtime attestation requirements.",
        ].filter(Boolean).join("\n");
        await vscode.env.clipboard.writeText(prompt);
        const choice = await vscode.window.showInformationMessage(
          `Prompt copied. Paste it into a Kiro Agent chat to run the ${label} scan.`,
          "Open Setup",
        );
        if (choice === "Open Setup") {
          await vscode.commands.executeCommand("kiroSecurity.openPanel");
          this.viewSink?.postNavigation("setup");
        }
        return undefined;
      }
      const engine = await this.ensureEngine();
      const config = vscode.workspace.getConfiguration("kiroSecurity");
      const scope = this.validateScope(options.scope ?? config.get<string>("defaultScope", "."));
      const scan = await engine.request<ScanRecord>("start_scan", {
        mode,
        analysisProfile: "fast",
        scope,
        maxFiles: config.get<number>("maxFiles", 10_000),
        maxFileBytes: config.get<number>("maxFileBytes", 1_048_576),
      });
      this.selectedScanId = scan.id;
      this.selectedOccurrenceId = undefined;
      this.selectedFinding = null;
      await this.context.workspaceState.update("kiroSecurity.selectedScanId", scan.id);
      await this.refresh();
      return scan;
    });
  }

  async startScanForUri(mode: ScanMode, uri?: vscode.Uri): Promise<void> {
    let scope: string | undefined;
    if (uri?.scheme === "file" && this.workspaceRoot && isPathWithin(this.workspaceRoot, uri.fsPath)) {
      scope = path.relative(this.workspaceRoot, uri.fsPath) || ".";
    }
    await this.startScan(mode, { scope });
  }

  async resumeScan(scanId?: string): Promise<ScanRecord | undefined> {
    return this.userAction("Resume scan", async () => {
      const engine = await this.ensureEngine();
      const target = scanId ?? this.dashboard?.latestResumableScan?.id;
      if (!target) throw new Error("No interrupted or failed scan is available to resume.");
      const scan = await engine.request<ScanRecord>("resume_scan", { scanId: target });
      this.selectedScanId = scan.id;
      await this.refresh();
      return scan;
    });
  }

  async cancelScan(scanId?: string): Promise<void> {
    await this.userAction("Cancel scan", async () => {
      const target = scanId ?? this.dashboard?.activeScan?.id;
      if (!target) throw new Error("No active scan is available to cancel.");
      await (await this.ensureEngine()).request("cancel_scan", { scanId: target });
      await this.refresh();
    });
  }

  async selectScan(scanId: string): Promise<void> {
    this.selectedScanId = scanId;
    this.selectedOccurrenceId = undefined;
    this.selectedFinding = null;
    await this.context.workspaceState.update("kiroSecurity.selectedScanId", scanId);
    await this.refresh();
  }

  async cleanupScan(scanId: string): Promise<void> {
    await this.userAction("Clean up scan", async () => {
      const scan = this.dashboard?.scans.find((item) => item.id === scanId);
      if (!scan) throw new Error("The scan is no longer present in the current workbench state.");
      if (["queued", "running"].includes(scan.status)) throw new Error("Cancel the active scan before cleanup.");
      const confirmation = await vscode.window.showWarningMessage(
        `Delete scan ${scanId}, its internal artifacts, and workbench records? External exports are retained.`,
        { modal: true },
        "Delete scan",
      );
      if (confirmation !== "Delete scan") return;
      await (await this.ensureEngine()).request("cleanup_scan", { scanId });
      if (this.selectedScanId === scanId) {
        this.selectedScanId = undefined;
        this.selectedOccurrenceId = undefined;
        this.selectedFinding = null;
        await this.context.workspaceState.update("kiroSecurity.selectedScanId", undefined);
        await this.context.workspaceState.update("kiroSecurity.selectedOccurrenceId", undefined);
      }
      await this.refresh();
      void vscode.window.showInformationMessage("Scan deleted.");
    });
  }

  async openFinding(occurrenceId?: string, openSource = true): Promise<FindingDetail | undefined> {
    return this.userAction("Open finding", async () => {
      const target = occurrenceId ?? await this.pickFinding();
      if (!target) return undefined;
      const finding = await (await this.ensureEngine()).request<FindingDetail>("get_finding", { occurrenceId: target });
      this.selectedScanId = finding.scanId;
      this.selectedOccurrenceId = finding.occurrenceId;
      this.selectedFinding = finding;
      await this.context.workspaceState.update("kiroSecurity.selectedScanId", finding.scanId);
      await this.context.workspaceState.update("kiroSecurity.selectedOccurrenceId", finding.occurrenceId);
      this.postSnapshot();
      if (openSource) {
        const location = finding.locations.find((item) => item.role === "sink") ?? finding.locations[0];
        if (location && this.workspaceRoot) {
          const opened = await openSourceLocation(this.workspaceRoot, location);
          if (!opened) throw new Error("The finding source path is outside the current workspace or no longer exists.");
        }
      }
      return finding;
    });
  }

  private async pickFinding(): Promise<string | undefined> {
    const findings = this.dashboard?.findings ?? [];
    if (!findings.length) throw new Error("The selected scan has no findings.");
    const selected = await vscode.window.showQuickPick(
      findings.map((finding) => ({ label: finding.title, description: `${finding.severity.level} · ${finding.validationStatus}`, detail: finding.locations[0]?.path, occurrenceId: finding.occurrenceId })),
      { title: "Kiro Security: Open Finding", matchOnDescription: true, matchOnDetail: true },
    );
    return selected?.occurrenceId;
  }

  async validateFinding(occurrenceId: string): Promise<void> {
    await this.userAction("Validate finding", async () => {
      this.selectedFinding = await (await this.ensureEngine()).request<FindingDetail>("validate_finding", { occurrenceId });
      this.selectedOccurrenceId = occurrenceId;
      await this.refresh();
    });
  }

  async triageFinding(occurrenceId: string, decision: TriageDecision, note?: string): Promise<void> {
    await this.userAction("Triage finding", async () => {
      this.selectedFinding = await (await this.ensureEngine()).request<FindingDetail>("triage_finding", { occurrenceId, decision, note });
      this.selectedOccurrenceId = occurrenceId;
      await this.refresh();
    });
  }

  async createRemediation(occurrenceId: string): Promise<void> {
    await this.userAction("Create remediation", async () => {
      this.selectedFinding = await (await this.ensureEngine()).request<FindingDetail>("create_remediation", { occurrenceId });
      this.selectedOccurrenceId = occurrenceId;
      await this.refresh();
    });
  }

  async createTrackingHandoff(occurrenceId: string, provider?: TrackingProvider): Promise<void> {
    await this.userAction("Create tracking handoff", async () => {
      const target = provider && provider !== "manual" ? ` for ${provider}` : "";
      const prompt = `Prepare a tracking handoff${target} in Kiro Agent for Kiro Security finding ${occurrenceId}. Verify connector identity, search for duplicates, show the exact preview, and request approval before creating or updating anything.`;
      await vscode.env.clipboard.writeText(prompt);
      await vscode.window.showInformationMessage(
        `A ready-to-paste Kiro Agent tracking prompt${target} was copied. No external record was created.`,
      );
    });
  }

  async createHardening(scanId: string): Promise<void> {
    await this.userAction("Create hardening proposal", async () => {
      const record = await (await this.ensureEngine()).request<{ artifactPath: string }>("create_hardening_proposal", { scanId });
      await this.refresh();
      await this.openTrustedEnginePath(record.artifactPath);
    });
  }

  async refreshThreatModel(): Promise<void> {
    await this.userAction("Refresh threat model", async () => {
      const scope = vscode.workspace.getConfiguration("kiroSecurity").get<string>("defaultScope", ".");
      const result = await (await this.ensureEngine()).request<{ path: string }>("refresh_threat_model", { scope: this.validateScope(scope) });
      await this.openTrustedEnginePath(result.path);
    });
  }

  async exportReport(scanId?: string, format?: ExportFormat): Promise<void> {
    await this.userAction("Export report", async () => {
      const target = scanId ?? this.dashboard?.selectedScan?.id;
      if (!target) throw new Error("Select a scan before exporting.");
      const chosenFormat = format ?? (await vscode.window.showQuickPick(["markdown", "json", "csv", "sarif"], { title: "Kiro Security: Export format" })) as ExportFormat | undefined;
      if (!chosenFormat) return;
      const extensions: Record<ExportFormat, string> = { markdown: "md", json: "json", csv: "csv", sarif: "sarif" };
      const destination = await vscode.window.showSaveDialog({
        title: `Export ${chosenFormat.toUpperCase()} security report`,
        defaultUri: vscode.Uri.file(path.join(this.workspaceRoot ?? "", `kiro-security-${target}.${extensions[chosenFormat]}`)),
        filters: { [chosenFormat.toUpperCase()]: [extensions[chosenFormat]] },
      });
      if (!destination) return;
      if (destination.scheme !== "file") throw new Error("Exports require a local file destination.");
      const result = await (await this.ensureEngine()).request<{ path: string }>("export_report", {
        scanId: target,
        format: chosenFormat,
        destination: destination.fsPath,
        allowedRoot: path.dirname(destination.fsPath),
      });
      await this.openTrustedEnginePath(result.path, true);
      await this.refresh();
    });
  }

  async exportFinding(occurrenceId: string, format?: ExportFormat): Promise<void> {
    await this.userAction("Export finding", async () => {
      const finding = await (await this.ensureEngine()).request<FindingDetail>("get_finding", { occurrenceId });
      const chosenFormat = format ?? (await vscode.window.showQuickPick(
        ["json", "markdown", "csv", "sarif"], { title: "Kiro Security: Finding export format" },
      )) as ExportFormat | undefined;
      if (!chosenFormat) return;
      const extensions: Record<ExportFormat, string> = { markdown: "md", json: "json", csv: "csv", sarif: "sarif" };
      const destination = await vscode.window.showSaveDialog({
        title: `Export ${chosenFormat.toUpperCase()} finding`,
        defaultUri: vscode.Uri.file(path.join(this.workspaceRoot ?? "", `kiro-security-${finding.findingId}.${extensions[chosenFormat]}`)),
        filters: { [chosenFormat.toUpperCase()]: [extensions[chosenFormat]] },
      });
      if (!destination) return;
      if (destination.scheme !== "file") throw new Error("Exports require a local file destination.");
      const result = await (await this.ensureEngine()).request<{ path: string }>("export_report", {
        scanId: finding.scanId, occurrenceId: finding.occurrenceId, format: chosenFormat,
        destination: destination.fsPath, allowedRoot: path.dirname(destination.fsPath),
      });
      await this.openTrustedEnginePath(result.path, true);
      await this.refresh();
    });
  }

  async openArtifact(artifactPath: string): Promise<void> {
    if (!this.isKnownArtifact(artifactPath)) throw new Error("The requested artifact path is not present in the current engine state.");
    await this.openTrustedEnginePath(artifactPath, true);
  }

  private isKnownArtifact(candidate: string): boolean {
    const normalized = path.resolve(candidate);
    for (const scan of this.dashboard?.scans ?? []) {
      for (const artifact of scan.artifacts ?? []) {
        if (path.resolve(artifact.path) === normalized) return true;
      }
    }
    for (const record of this.selectedFinding?.remediationRecords ?? []) {
      const artifact = typeof record.artifact_path === "string" ? record.artifact_path : undefined;
      if (artifact && path.resolve(artifact) === normalized) return true;
    }
    return false;
  }

  private async openTrustedEnginePath(filePath: string, allowExternal = false): Promise<void> {
    const resolved = path.resolve(filePath);
    if (!allowExternal && this.workspaceRoot && !isPathWithin(this.workspaceRoot, resolved)) throw new Error("Engine artifact escaped the workspace boundary.");
    const stat = await fs.stat(resolved);
    if (!stat.isFile()) throw new Error("Artifact is not a regular file.");
    const document = await vscode.workspace.openTextDocument(vscode.Uri.file(resolved));
    await vscode.window.showTextDocument(document, { preview: false });
  }

  findingLink(occurrenceId: string): vscode.Uri {
    return vscode.Uri.from({
      scheme: vscode.env.uriScheme,
      authority: this.context.extension.id,
      path: `/finding/${encodeURIComponent(occurrenceId)}`,
    });
  }

  async copyFindingLink(occurrenceId: string): Promise<void> {
    await vscode.env.clipboard.writeText(this.findingLink(occurrenceId).toString(true));
    void vscode.window.showInformationMessage("Kiro Security finding link copied.");
  }

  async handleUri(uri: vscode.Uri): Promise<void> {
    const match = /^\/finding\/([^/]+)$/.exec(uri.path);
    if (!match) return;
    await vscode.commands.executeCommand("kiroSecurity.openPanel");
    await this.openFinding(decodeURIComponent(match[1]), true);
  }

  private pythonPath(): string {
    return vscode.workspace.getConfiguration("kiroSecurity").get<string>("pythonPath", "python3");
  }

  private configuredAgentScope(): AgentIntegrationScope {
    return vscode.workspace.getConfiguration("kiroSecurity").get<AgentIntegrationScope>("agentIntegration.scope", "workspace");
  }

  private configuredAutoApprovePolicy(): AgentAutoApprovePolicy {
    return vscode.workspace.getConfiguration("kiroSecurity").get<AgentAutoApprovePolicy>("agentIntegration.autoApprove", "read_only");
  }

  private requireTrustedWorkspace(action: string): string {
    if (!this.workspaceRoot) throw new Error(`Open a local workspace before ${action}.`);
    if (!vscode.workspace.isTrusted) throw new Error(`Workspace Trust is required before ${action}.`);
    return this.workspaceRoot;
  }

  private async refreshAgentIntegration(force: boolean, operation: AgentIntegrationOperation = "checking"): Promise<void> {
    if (!this.workspaceRoot || !vscode.workspace.isTrusted) {
      const reason = !this.workspaceRoot
        ? "Open a local workspace to inspect or install Kiro Agent integration."
        : "Trust this workspace before Kiro Security Power probes local runtimes or reads Agent integration files.";
      this.agentIntegrationStatus = {
        ...this.agentIntegrationStatus,
        operation: "idle",
        verified: false,
        details: [reason],
      };
      this.postSnapshot();
      return;
    }
    if (!force && Date.now() - this.agentIntegrationLastChecked < 15_000) return;
    const previous = this.agentIntegrationStatus;
    this.agentIntegrationStatus = { ...previous, operation };
    this.postSnapshot();
    try {
      const inspected = await this.agentIntegration.inspect(this.pythonPath());
      this.agentIntegrationStatus = inspected;
      this.agentIntegrationLastChecked = Date.now();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.agentIntegrationStatus = {
        ...previous,
        state: "error",
        operation: "idle",
        verified: false,
        lastError: message,
        details: [...previous.details.filter((detail) => detail !== message), message],
      };
      this.logger.log("error", "Failed to inspect Kiro Agent integration", { error: message });
    }
    this.postSnapshot();
  }

  async installAgentIntegration(
    scope: AgentIntegrationScope = this.configuredAgentScope(),
    autoApprovePolicy: AgentAutoApprovePolicy = this.configuredAutoApprovePolicy(),
  ): Promise<void> {
    await this.userAction("Install Agent integration", async () => {
      this.requireTrustedWorkspace("installing Kiro Agent integration");
      await this.refreshAgentIntegration(true, "checking");
      const runtime = this.agentIntegrationStatus.dependencies.python;
      if (!runtime.available || !runtime.compatible || !runtime.executable) {
        throw new Error(runtime.error ?? "Python 3.10 or newer with sqlite3 is required.");
      }
      const configPath = scope === "workspace" ? this.agentIntegration.workspaceConfigPath : this.agentIntegration.userConfigPath;
      if (!configPath) throw new Error("A workspace is required for workspace-scoped Agent integration.");
      const steeringPath = this.agentIntegration.steeringPath(scope);
      const approvalDescription = autoApprovePolicy === "read_only"
        ? "Read-only lookups are pre-approved; scans and changes always require approval."
        : "Every tool requires approval.";
      const existing = this.agentIntegrationStatus.configured ? "Repair and verify" : "Install and verify";
      const confirmation = await vscode.window.showInformationMessage(
        `${existing} the Kiro Agent connection? Files are backed up and restored automatically if verification fails.`,
        {
          modal: true,
          detail: [
            approvalDescription,
            `Config: ${configPath}`,
            `Steering: ${steeringPath}`,
            `Runtime: ${runtime.executable} (${runtime.version ?? "version unknown"})`,
          ].join("\n"),
        },
        existing,
      );
      if (confirmation !== existing) return;
      this.agentIntegrationStatus = { ...this.agentIntegrationStatus, operation: "installing", lastError: undefined };
      this.postSnapshot();
      const result = await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: `${existing} Kiro Security Agent integration`,
        cancellable: false,
      }, async (progress) => {
        progress.report({ message: "Writing reviewed integration files…" });
        const installed = await this.agentIntegration.install({ pythonPath: this.pythonPath(), scope, autoApprovePolicy });
        this.agentIntegrationLastChecked = 0;
        progress.report({ message: "Verifying Agent tools…" });
        await this.refreshAgentIntegration(true, "verifying");
        return installed;
      });
      const choice = await vscode.window.showInformationMessage(
        `Kiro Agent integration is ready. Verified ${result.toolCount} tools with Python ${result.pythonVersion}. Kiro should reload the MCP configuration automatically.`,
        "Open MCP config",
      );
      if (choice === "Open MCP config") await this.openMcpConfig(scope);
    });
  }

  async verifyAgentIntegration(): Promise<void> {
    await this.userAction("Verify Agent integration", async () => {
      this.requireTrustedWorkspace("verifying Kiro Agent integration");
      this.agentIntegrationStatus = { ...this.agentIntegrationStatus, operation: "verifying", lastError: undefined };
      this.postSnapshot();
      const result = await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "Verifying Kiro Security Agent integration",
        cancellable: false,
      }, async (progress) => {
        progress.report({ message: "Checking MCP tools…" });
        const verified = await this.agentIntegration.verify(this.pythonPath());
        this.agentIntegrationLastChecked = 0;
        await this.refreshAgentIntegration(true, "verifying");
        return verified;
      });
      void vscode.window.showInformationMessage(
        `Kiro Security Agent integration verified: ${result.toolCount} tools, MCP ${result.serverVersion}, engine ${result.engineVersion}.`,
      );
    });
  }

  async removeAgentIntegration(): Promise<void> {
    await this.userAction("Remove Agent integration", async () => {
      this.requireTrustedWorkspace("removing Kiro Agent integration");
      const confirmation = await vscode.window.showWarningMessage(
        "Remove the VSIX-managed MCP entry and auto-inclusion steering? Other MCP servers and native Power registrations are left unchanged.",
        { modal: true },
        "Remove integration",
      );
      if (confirmation !== "Remove integration") return;
      this.agentIntegrationStatus = { ...this.agentIntegrationStatus, operation: "removing" };
      this.postSnapshot();
      const result = await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "Removing Kiro Security Agent integration",
        cancellable: false,
      }, async (progress) => {
        progress.report({ message: "Removing managed MCP entries…" });
        const removed = await this.agentIntegration.removeDirectIntegration();
        this.agentIntegrationLastChecked = 0;
        progress.report({ message: "Refreshing integration status…" });
        await this.refreshAgentIntegration(true, "checking");
        return removed;
      });
      const skipped = result.skippedUnmanagedConfigPaths.length
        ? ` ${result.skippedUnmanagedConfigPaths.length} same-named but unmanaged MCP entry was left unchanged.`
        : "";
      void vscode.window.showInformationMessage(
        `Removed ${result.removedConfigPaths.length} MCP entr${result.removedConfigPaths.length === 1 ? "y" : "ies"} and ${result.removedSteeringPaths.length} managed steering file(s).${skipped}`,
      );
    });
  }

  async openMcpConfig(scope: AgentIntegrationScope = this.configuredAgentScope()): Promise<void> {
    this.requireTrustedWorkspace("opening Kiro Agent MCP configuration");
    const filePath = await this.agentIntegration.ensureMcpConfig(scope);
    const document = await vscode.workspace.openTextDocument(vscode.Uri.file(filePath));
    await vscode.window.showTextDocument(document, { preview: false });
  }

  async retryEngine(): Promise<void> {
    await this.userAction("Retry engine", async () => {
      if (!this.engine) {
        await this.ensureEngine();
      } else {
        await this.engine.retry();
      }
      await this.refresh();
    });
  }

  async configurationChanged(event: vscode.ConfigurationChangeEvent): Promise<void> {
    if (event.affectsConfiguration("kiroSecurity.pythonPath")) {
      await this.engine?.stop();
      this.engine?.dispose();
      this.engine = undefined;
      this.registeredDefaultsKey = undefined;
      this.dashboard = null;
      this.agentIntegrationLastChecked = 0;
      await this.refreshAgentIntegration(true, "checking");
    }
    this.startPolling();
    await this.refresh();
  }

  async copyMcpConfig(): Promise<void> {
    this.requireTrustedWorkspace("preparing Kiro Agent MCP configuration");
    if (!this.agentIntegrationStatus.power.prepared) {
      throw new Error("Run Install Agent Integration first so the copied configuration points to a verified packaged runtime.");
    }
    const config = await this.agentIntegration.configForClipboard(this.pythonPath(), this.configuredAutoApprovePolicy());
    await vscode.env.clipboard.writeText(JSON.stringify(config, null, 2));
    void vscode.window.showInformationMessage("Reviewed Kiro Security Power MCP configuration copied. Existing settings were not modified.");
  }

  private async userAction<T>(label: string, action: () => Promise<T>): Promise<T | undefined> {
    try {
      return await action();
    } catch (error) {
      this.handleError(label, error, true);
      if (this.agentIntegrationStatus.operation !== "idle") {
        this.agentIntegrationLastChecked = 0;
        await this.refreshAgentIntegration(true, "checking").catch(() => undefined);
      }
      return undefined;
    }
  }

  reportError(context: string, error: unknown, visible = true): void {
    this.handleError(context, error, visible);
  }

  private handleError(context: string, error: unknown, visible: boolean): void {
    const message = error instanceof EngineRpcError
      ? `${error.message}${error.data?.engineCode ? ` (${String(error.data.engineCode)})` : ""}`
      : error instanceof AgentIntegrationError
        ? `${error.message} (${error.code})`
        : error instanceof Error ? error.message : String(error);
    this.logger.log("error", context, { error: message });
    if (error instanceof AgentIntegrationError || context.includes("Agent integration")) {
      this.agentIntegrationStatus = {
        ...this.agentIntegrationStatus,
        state: "error",
        operation: "idle",
        verified: false,
        lastError: message,
        details: [...this.agentIntegrationStatus.details.filter((detail) => detail !== message), message],
      };
    }
    if (visible) void vscode.window.showErrorMessage(`Kiro Security: ${message}`);
    this.postSnapshot();
  }

  async disposeAsync(): Promise<void> {
    this.disposed = true;
    if (this.pollTimer) clearInterval(this.pollTimer);
    if (this.eventRefreshTimer) clearTimeout(this.eventRefreshTimer);
    await this.engine?.stop();
    this.statusBar.dispose();
  }

  dispose(): void {
    void this.disposeAsync();
  }
}
