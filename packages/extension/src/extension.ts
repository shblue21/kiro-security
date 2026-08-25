import * as vscode from "vscode";

import { prepareFoundationStorage } from "./foundation";
import { isSupportedKiroHost } from "./hostEnvironment";
import { getOrCreateInstallationServerKey } from "./integration/integrationFiles";
import { SecuritySetupView } from "./view/setupView";
import { renderUnsupportedHostHtml } from "./view/unsupportedHostView";

export async function activate(
  context: vscode.ExtensionContext,
): Promise<void> {
  const output = vscode.window.createOutputChannel("Kiro Security");
  context.subscriptions.push(output);
  context.subscriptions.push(
    vscode.commands.registerCommand("kiroSecurity.openSetup", async () => {
      await vscode.commands.executeCommand(
        "workbench.view.extension.kiroSecurity",
      );
    }),
  );
  if (!isSupportedKiroHost(vscode.env)) {
    const unsupportedView = vscode.window.registerWebviewViewProvider(
      SecuritySetupView.viewId,
      {
        resolveWebviewView(view): void {
          view.webview.options = { enableScripts: false };
          view.webview.html = renderUnsupportedHostHtml(view.webview);
        },
      },
    );
    context.subscriptions.push(unsupportedView);
    return;
  }
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

  context.subscriptions.push(setupRegistration);
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
