import * as vscode from "vscode";

import {
  describeFoundation,
  prepareFoundationStorage,
} from "./foundation";
import { preparePowerIntegration } from "./powerIntegration";
import { SecuritySetupView } from "./setupView";

export async function activate(
  context: vscode.ExtensionContext,
): Promise<void> {
  const output = vscode.window.createOutputChannel("Kiro Security Power");
  const paths = await prepareFoundationStorage(context);
  const status = describeFoundation(paths);
  output.appendLine(status.join("\n"));
  const setupView = new SecuritySetupView(context, paths, output);
  const setupRegistration = vscode.window.registerWebviewViewProvider(
    SecuritySetupView.viewId,
    setupView,
  );

  const openSetupCommand = vscode.commands.registerCommand(
    "kiroSecurity.openSetup",
    async () => {
      await vscode.commands.executeCommand(
        "workbench.view.extension.kiroSecurity",
      );
    },
  );
  const statusCommand = vscode.commands.registerCommand(
    "kiroSecurity.showFoundationStatus",
    async () => {
      output.show(true);
      output.appendLine(status.join("\n"));
      await vscode.window.showInformationMessage(status[0]);
    },
  );

  const preparePowerCommand = vscode.commands.registerCommand(
    "kiroSecurity.preparePowerIntegration",
    async () => {
      try {
        const prepared = await preparePowerIntegration(context, paths);
        output.show(true);
        output.appendLine(`Prepared custom Power: ${prepared.powerRoot}`);
        output.appendLine(`Python runtime: ${prepared.pythonExecutable}`);
        output.appendLine(
          "Import that folder with Kiro Powers → Add Custom Power → Import power from a folder.",
        );
        const selection = await vscode.window.showInformationMessage(
          "Kiro Security Power integration is ready to import.",
          "Reveal Folder",
        );
        if (selection === "Reveal Folder") {
          await vscode.commands.executeCommand(
            "revealFileInOS",
            vscode.Uri.file(prepared.powerRoot),
          );
        }
      } catch (error) {
        const message =
          error instanceof Error ? error.message : "Unknown preparation error.";
        output.appendLine(`Power integration preparation failed: ${message}`);
        await vscode.window.showErrorMessage(
          `Kiro Security Power integration failed: ${message}`,
        );
      }
    },
  );

  context.subscriptions.push(
    output,
    setupRegistration,
    openSetupCommand,
    statusCommand,
    preparePowerCommand,
  );

  if (!context.globalState.get<boolean>("kiroSecurity.onboardingShown.v1")) {
    void vscode.commands
      .executeCommand("workbench.view.extension.kiroSecurity")
      .then(
        async () =>
          context.globalState.update(
            "kiroSecurity.onboardingShown.v1",
            true,
          ),
        (error: unknown) => {
          output.appendLine(
            `Unable to open first-run setup automatically: ${
              error instanceof Error ? error.message : String(error)
            }`,
          );
        },
      );
  }
}

export function deactivate(): void {
  // Kiro owns the Power MCP process; the Extension owns no server process.
}
