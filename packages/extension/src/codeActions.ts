import * as vscode from "vscode";
import { SecurityDiagnostics } from "./diagnostics";

export class SecurityCodeActionProvider implements vscode.CodeActionProvider {
  static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

  constructor(private readonly diagnostics?: SecurityDiagnostics) {}

  provideCodeActions(
    _document: vscode.TextDocument,
    _range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];
    if (!this.diagnostics) return actions;
    for (const diagnostic of context.diagnostics) {
      if (diagnostic.source !== "Kiro Security Power") continue;
      const occurrenceId = this.diagnostics.occurrenceFor(diagnostic);
      if (!occurrenceId) continue;
      const details = new vscode.CodeAction("Show Kiro Security finding details", vscode.CodeActionKind.QuickFix);
      details.command = { command: "kiroSecurity.showFindingDetails", title: "Show finding details", arguments: [occurrenceId] };
      details.diagnostics = [diagnostic];
      actions.push(details);

      const remediation = new vscode.CodeAction("Create Kiro Security remediation guidance", vscode.CodeActionKind.QuickFix);
      remediation.command = { command: "kiroSecurity.createRemediation", title: "Create remediation guidance", arguments: [occurrenceId] };
      remediation.diagnostics = [diagnostic];
      actions.push(remediation);
    }
    return actions;
  }
}
