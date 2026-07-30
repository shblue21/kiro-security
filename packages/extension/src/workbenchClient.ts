import { spawn } from "node:child_process";

const MAX_OUTPUT_BYTES = 4 * 1024 * 1024;
const ADMIN_TIMEOUT_MS = 30_000;

export interface ScanProjection {
  readonly id: string;
  readonly workspaceId: string;
  readonly status: "running" | "complete" | "failed" | "canceled";
  readonly phase: string;
  readonly mode: "standard" | "diff" | "deep";
  readonly scope: string;
  readonly scanDir: string;
  readonly failureMessage?: string | null;
  readonly startedAt: string;
  readonly completedAt?: string | null;
  readonly updatedAt: string;
  readonly target: {
    readonly path: string;
    readonly revision: string;
    readonly snapshotDigest?: string | null;
  };
  readonly progress: {
    readonly reviewItemsTotal: number;
    readonly reviewItemsCompleted: number;
    readonly reportableFindingsCount: number;
    readonly deepReviewPass?: number | null;
  };
}

export interface FindingProjection {
  readonly occurrenceId: string;
  readonly findingId: string;
  readonly scanId: string;
  readonly title: string;
  readonly summary: string;
  readonly severity: string;
  readonly confidence: string;
  readonly remediation: string;
  readonly locations: readonly {
    readonly path: string;
    readonly startLine: number;
    readonly endLine: number;
    readonly role?: string | null;
  }[];
  readonly triage: {
    readonly status: "open" | "closed";
    readonly closeReason?: string | null;
    readonly note?: string | null;
  };
}

export interface RecoveryRequestProjection {
  readonly id: string;
  readonly scanId: string;
  readonly status: "pending" | "claimed" | "delivered" | "canceled";
  readonly version: number;
  readonly claimedAt?: number | null;
  readonly deliveredAt?: number | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface RemediationRequestProjection {
  readonly requestId: string;
  readonly occurrenceId: string;
  readonly state: string;
  readonly version: number;
  readonly pendingAction?: "generate" | "apply" | "verify" | null;
  readonly patchPath?: string | null;
  readonly summary?: string | null;
  readonly verificationSummary?: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface DashboardProjection {
  readonly scans: readonly ScanProjection[];
  readonly findings: readonly FindingProjection[];
  readonly recoveryRequests: readonly RecoveryRequestProjection[];
  readonly remediationRequests: readonly RemediationRequestProjection[];
}

export class WorkbenchAdminClient {
  constructor(
    private readonly pythonExecutable: string,
    private readonly launcherPath: string,
    private readonly stateRoot: string,
    private readonly scanRoot: string,
  ) {}

  call<T>(
    operation: string,
    args: Readonly<Record<string, unknown>> = {},
  ): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const child = spawn(
        this.pythonExecutable,
        ["-B", "-S", this.launcherPath, "--admin"],
        {
          env: {
            ...process.env,
            PYTHONIOENCODING: "utf-8",
            PYTHONUNBUFFERED: "1",
            KIRO_SECURITY_STATE_ROOT: this.stateRoot,
            KIRO_SECURITY_SCAN_ROOT: this.scanRoot,
          },
          stdio: ["pipe", "pipe", "pipe"],
          windowsHide: true,
        },
      );
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      let outputBytes = 0;
      let settled = false;
      const finish = (error?: Error, value?: T) => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timer);
        if (error) {
          reject(error);
        } else {
          resolve(value as T);
        }
      };
      const append = (target: Buffer[], chunk: Buffer) => {
        outputBytes += chunk.length;
        if (outputBytes > MAX_OUTPUT_BYTES) {
          child.kill();
          finish(new Error("Kiro Security workbench response is too large."));
          return;
        }
        target.push(chunk);
      };
      child.stdout.on("data", (chunk: Buffer) => append(stdout, chunk));
      child.stderr.on("data", (chunk: Buffer) => append(stderr, chunk));
      child.on("error", (error) => finish(error));
      child.on("close", (code) => {
        if (settled) {
          return;
        }
        if (code !== 0) {
          finish(
            new Error(
              Buffer.concat(stderr).toString("utf8").trim() ||
                `Kiro Security workbench exited with code ${code}.`,
            ),
          );
          return;
        }
        try {
          finish(
            undefined,
            JSON.parse(Buffer.concat(stdout).toString("utf8")) as T,
          );
        } catch {
          finish(new Error("Kiro Security workbench returned invalid JSON."));
        }
      });
      const timer = setTimeout(() => {
        child.kill();
        finish(new Error("Kiro Security workbench request timed out."));
      }, ADMIN_TIMEOUT_MS);
      child.stdin.end(
        `${JSON.stringify({ operation, arguments: args })}\n`,
        "utf8",
      );
    });
  }
}
