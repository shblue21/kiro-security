import { realpath } from "node:fs/promises";

import * as vscode from "vscode";

import type {
  DashboardProjection,
  ScanProjection,
} from "../workbench/workbenchClient";
import {
  isScanInWorkspace,
  type RepositoryScope,
} from "../workbench/workspaceProjection";

export interface WorkspaceView {
  readonly roots: readonly string[];
  readonly label: string;
}

export async function currentWorkspace(): Promise<WorkspaceView> {
  const folders = (vscode.workspace.workspaceFolders ?? []).filter(
    (folder) => folder.uri.scheme === "file",
  );
  const entries = (
    await Promise.all(
      folders.map(async (folder) => {
        try {
          return { name: folder.name, root: await realpath(folder.uri.fsPath) };
        } catch {
          return undefined;
        }
      }),
    )
  ).filter(
    (entry): entry is { readonly name: string; readonly root: string } =>
      entry !== undefined,
  );
  const roots = entries.map((entry) => entry.root);
  const label =
    entries.length === 1
      ? `Current workspace: ${entries[0].name}`
      : `Current workspaces (${entries.length})`;
  return { roots, label };
}

export function requiredValue<T>(value: T | undefined, name: string): T {
  if (value === undefined || value === "") {
    throw new Error(`Missing ${name}.`);
  }
  return value;
}

export class ScanAccess {
  constructor(
    private readonly dashboard: DashboardProjection | undefined,
    private readonly repositoryScope: RepositoryScope,
  ) {}

  private scanById(scanId: string): ScanProjection {
    const scan = this.dashboard?.scans.find((candidate) => candidate.id === scanId);
    if (!scan) {
      throw new Error("The selected scan is no longer available.");
    }
    return scan;
  }

  async requireWorkspaceScanById(
    scanId: string | undefined,
  ): Promise<ScanProjection> {
    const scan = this.scanById(requiredValue(scanId, "scanId"));
    const workspace = await currentWorkspace();
    if (!isScanInWorkspace(scan, workspace.roots)) {
      throw new Error("Open this scan's repository in the current workspace to continue.");
    }
    return scan;
  }

  async requireVisibleScanById(
    scanId: string | undefined,
  ): Promise<ScanProjection> {
    const scan = this.scanById(requiredValue(scanId, "scanId"));
    if (this.repositoryScope === "all") {
      return scan;
    }
    const workspace = await currentWorkspace();
    if (!isScanInWorkspace(scan, workspace.roots)) {
      throw new Error("The selected item is outside the current workspace view.");
    }
    return scan;
  }

  private requireOccurrenceScanId(occurrenceId: string): string {
    const finding = this.dashboard?.findings.find(
      (candidate) => candidate.occurrenceId === occurrenceId,
    );
    if (!finding) {
      throw new Error("The selected finding is no longer available.");
    }
    return finding.scanId;
  }

  async requireWorkspaceScanForOccurrence(
    occurrenceId: string | undefined,
  ): Promise<void> {
    const exactOccurrence = requiredValue(occurrenceId, "occurrenceId");
    await this.requireWorkspaceScanById(
      this.requireOccurrenceScanId(exactOccurrence),
    );
  }

  async requireVisibleScanForOccurrence(
    occurrenceId: string | undefined,
  ): Promise<void> {
    const exactOccurrence = requiredValue(occurrenceId, "occurrenceId");
    await this.requireVisibleScanById(
      this.requireOccurrenceScanId(exactOccurrence),
    );
  }

  async requireWorkspaceScanForRecovery(
    requestId: string | undefined,
  ): Promise<void> {
    const exactRequest = requiredValue(requestId, "requestId");
    const request = this.dashboard?.recoveryRequests.find(
      (candidate) => candidate.id === exactRequest,
    );
    if (!request) {
      throw new Error("The selected recovery request is no longer available.");
    }
    await this.requireWorkspaceScanById(request.scanId);
  }

  async requireWorkspaceScanForRemediation(
    requestId: string | undefined,
  ): Promise<void> {
    const exactRequest = requiredValue(requestId, "requestId");
    const request = this.dashboard?.remediationRequests.find(
      (candidate) => candidate.requestId === exactRequest,
    );
    if (!request) {
      throw new Error("The selected remediation request is no longer available.");
    }
    await this.requireWorkspaceScanForOccurrence(request.occurrenceId);
  }
}
