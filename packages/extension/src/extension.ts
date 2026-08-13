import * as vscode from "vscode";

import { prepareFoundationStorage } from "./foundation";
import { getOrCreateInstallationServerKey } from "./integrationFiles";
import { SecuritySetupView } from "./setupView";

export async function activate(
  context: vscode.ExtensionContext,
): Promise<void> {
  const output = vscode.window.createOutputChannel("Kiro Security Power");
  const paths = await prepareFoundationStorage(context);
  const serverKey = await getOrCreateInstallationServerKey(
    paths.stateRoot.fsPath,
  );
  const setupView = new SecuritySetupView(
    context,
    paths,
    output,
    serverKey,
  );
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
  context.subscriptions.push(
    output,
    setupRegistration,
    openSetupCommand,
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
