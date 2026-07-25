import { chmod } from "node:fs/promises";

import * as vscode from "vscode";

export interface FoundationPaths {
  readonly stateRoot: vscode.Uri;
  readonly database: vscode.Uri;
  readonly scanRoot: vscode.Uri;
  readonly runtimeRoot: vscode.Uri;
}

/**
 * Prepare the extension-global storage boundary shared by the Extension and the
 * later MCP/Engine process. Nothing is written beneath a scanned repository.
 */
export async function prepareFoundationStorage(
  context: vscode.ExtensionContext,
): Promise<FoundationPaths> {
  const stateRoot = context.globalStorageUri;
  if (stateRoot.scheme !== "file") {
    throw new Error(
      "Kiro Security requires a filesystem-backed extension global storage directory.",
    );
  }
  const scanRoot = vscode.Uri.joinPath(stateRoot, "scans");
  const runtimeRoot = vscode.Uri.joinPath(stateRoot, "runtime");

  await vscode.workspace.fs.createDirectory(stateRoot);
  await vscode.workspace.fs.createDirectory(scanRoot);
  await vscode.workspace.fs.createDirectory(runtimeRoot);

  await Promise.all([
    restrictDirectory(stateRoot),
    restrictDirectory(scanRoot),
    restrictDirectory(runtimeRoot),
  ]);

  return {
    stateRoot,
    database: vscode.Uri.joinPath(stateRoot, "workbench.sqlite3"),
    scanRoot,
    runtimeRoot,
  };
}

function displayPath(uri: vscode.Uri): string {
  return uri.fsPath;
}

export function describeFoundation(paths: FoundationPaths): readonly string[] {
  return [
    "Kiro Security workbench foundation is ready.",
    `Global workbench: ${displayPath(paths.database)}`,
    `External scan artifacts: ${displayPath(paths.scanRoot)}`,
    "Security scans remain Agent-chat-only; no Dashboard Start action is installed.",
    "Open the Kiro Security setup view to preview the planned onboarding experience.",
  ];
}

async function restrictDirectory(uri: vscode.Uri): Promise<void> {
  if (process.platform === "win32") {
    return;
  }
  await chmod(uri.fsPath, 0o700);
}
