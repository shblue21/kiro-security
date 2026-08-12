import * as path from "node:path";

import type {
  DashboardProjection,
  ScanProjection,
} from "./workbenchClient";

export type RepositoryScope = "current" | "all";

export function projectDashboard(
  dashboard: DashboardProjection,
  workspaceRoots: readonly string[],
  scope: RepositoryScope,
): DashboardProjection {
  if (scope === "all") {
    return dashboard;
  }
  const scans = dashboard.scans.filter((scan) =>
    isScanInWorkspace(scan, workspaceRoots),
  );
  const scanIds = new Set(scans.map((scan) => scan.id));
  const findings = dashboard.findings.filter((finding) =>
    scanIds.has(finding.scanId),
  );
  const occurrenceIds = new Set(
    findings.map((finding) => finding.occurrenceId),
  );
  return {
    scans,
    findings,
    recoveryRequests: dashboard.recoveryRequests.filter((request) =>
      scanIds.has(request.scanId),
    ),
    remediationRequests: dashboard.remediationRequests.filter((request) =>
      occurrenceIds.has(request.occurrenceId),
    ),
  };
}

export function isScanInWorkspace(
  scan: ScanProjection,
  workspaceRoots: readonly string[],
): boolean {
  const target = normalizePath(scan.target.path);
  const effectiveScope =
    scan.scope === "." ? target : normalizePath(path.join(target, scan.scope));
  return workspaceRoots.some((root) => {
    const normalizedRoot = normalizePath(root);
    return (
      isSameOrDescendant(normalizedRoot, target) ||
      isSameOrDescendant(normalizedRoot, effectiveScope)
    );
  });
}

function normalizePath(candidate: string): string {
  const resolved = path.resolve(candidate);
  return process.platform === "win32" ? resolved.toLowerCase() : resolved;
}

function isSameOrDescendant(parent: string, candidate: string): boolean {
  const relative = path.relative(parent, candidate);
  return (
    relative === "" ||
    (relative !== ".." &&
      !relative.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(relative))
  );
}
