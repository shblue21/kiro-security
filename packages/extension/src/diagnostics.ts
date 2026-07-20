import * as vscode from "vscode";
import { FindingSummary, Severity } from "../../protocol/src";
import { safeWorkspaceUri } from "./navigation";

export function diagnosticSeverity(severity: Severity): vscode.DiagnosticSeverity {
  switch (severity) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

export class SecurityDiagnostics implements vscode.Disposable {
  private readonly occurrenceByDiagnostic = new WeakMap<vscode.Diagnostic, string>();
  private lastSignature: string | undefined;

  constructor(
    private readonly collection: vscode.DiagnosticCollection,
    private readonly workspaceRoot: string,
    private readonly linkForFinding: (occurrenceId: string) => vscode.Uri,
  ) {}

  async refresh(findings: FindingSummary[], enabled: boolean): Promise<void> {
    const visible = enabled ? findings.filter((finding) => finding.validationStatus === "validated" && !["false_positive", "already_fixed"].includes(finding.triageStatus)) : [];
    const signature = JSON.stringify([enabled, visible.map((finding) => [
      finding.occurrenceId, finding.title, finding.summary, finding.severity.level, finding.triageStatus, finding.locations,
    ])]);
    if (signature === this.lastSignature) return;
    this.lastSignature = signature;
    this.collection.clear();
    if (!enabled) return;
    const grouped = new Map<string, { uri: vscode.Uri; diagnostics: vscode.Diagnostic[] }>();
    for (const finding of visible) {
      const sink = finding.locations.find((item) => item.role === "sink") ?? finding.locations[0];
      if (!sink) continue;
      const uri = await safeWorkspaceUri(this.workspaceRoot, sink.path);
      if (!uri) continue;
      const startLine = Math.max(0, sink.startLine - 1);
      const endLine = Math.max(startLine, (sink.endLine || sink.startLine) - 1);
      const diagnostic = new vscode.Diagnostic(
        new vscode.Range(startLine, 0, endLine, Number.MAX_SAFE_INTEGER),
        `${finding.title}: ${finding.summary}`,
        diagnosticSeverity(finding.severity.level),
      );
      diagnostic.source = "Kiro Security Power";
      diagnostic.code = { value: finding.findingId, target: this.linkForFinding(finding.occurrenceId) };
      diagnostic.tags = finding.triageStatus === "accepted_risk" ? [vscode.DiagnosticTag.Unnecessary] : undefined;
      this.occurrenceByDiagnostic.set(diagnostic, finding.occurrenceId);
      const key = uri.toString();
      const item = grouped.get(key) ?? { uri, diagnostics: [] };
      item.diagnostics.push(diagnostic);
      grouped.set(key, item);
    }
    for (const item of grouped.values()) this.collection.set(item.uri, item.diagnostics);
  }

  occurrenceFor(diagnostic: vscode.Diagnostic): string | undefined {
    return this.occurrenceByDiagnostic.get(diagnostic);
  }

  dispose(): void {
    this.collection.dispose();
  }
}
