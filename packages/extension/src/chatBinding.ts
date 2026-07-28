import { spawn } from "node:child_process";

import * as vscode from "vscode";

import type { FoundationPaths } from "./foundation";
import {
  buildHookRegistrationDocument,
  getHookBridgePath,
  getHookRegistrationPath,
  getPackagedHookBridgePath,
  inspectHookBridge,
  inspectHookRegistration,
  installHookRegistration,
  materializeHookBridge,
  removeHookRegistration,
  type HookRegistrationMutation,
  type HookRegistrationState,
} from "./chatBindingFiles";
import { resolvePythonExecutable } from "./powerIntegration";

const PROBE_TIMEOUT_MS = 10_000;

export type ChatBindingState =
  | "absent"
  | "ready"
  | "repairable"
  | "conflict"
  | "unavailable";

export interface ChatBindingInspection {
  readonly state: ChatBindingState;
  readonly registrationState: HookRegistrationState;
  readonly hookPath: string;
  readonly bridgePath: string;
  readonly detail: string;
  readonly pythonExecutable?: string;
}

export class ChatBindingManager {
  readonly hookPath: string;
  readonly bridgePath: string;
  private readonly sourceBridgePath: string;

  constructor(
    context: vscode.ExtensionContext,
    private readonly paths: FoundationPaths,
  ) {
    this.hookPath = getHookRegistrationPath();
    this.bridgePath = getHookBridgePath(paths.stateRoot.fsPath);
    this.sourceBridgePath = getPackagedHookBridgePath(
      context.extensionUri.fsPath,
    );
  }

  async inspect(): Promise<ChatBindingInspection> {
    let pythonExecutable: string;
    try {
      pythonExecutable = await resolvePythonExecutable();
    } catch (error) {
      const registration = await inspectHookRegistration({
        hookPath: this.hookPath,
      });
      return {
        state: "unavailable",
        registrationState: registration.state,
        hookPath: this.hookPath,
        bridgePath: this.bridgePath,
        detail:
          error instanceof Error
            ? error.message
            : "Python 3.9 or newer is unavailable.",
      };
    }

    const document = buildHookRegistrationDocument({
      pythonExecutable,
      bridgePath: this.bridgePath,
    });
    const [registration, bridge] = await Promise.all([
      inspectHookRegistration({
        hookPath: this.hookPath,
        expected: document,
      }),
      inspectHookBridge({
        sourcePath: this.sourceBridgePath,
        bridgePath: this.bridgePath,
      }),
    ]);
    return combineInspection({
      registrationState: registration.state,
      registrationDetail: registration.detail,
      bridgeReady: bridge.ready,
      bridgeDetail: bridge.detail,
      hookPath: this.hookPath,
      bridgePath: this.bridgePath,
      pythonExecutable,
    });
  }

  async install(): Promise<HookRegistrationMutation> {
    return this.prepareAndPublish(false);
  }

  async repair(): Promise<HookRegistrationMutation> {
    return this.prepareAndPublish(true);
  }

  async verify(): Promise<ChatBindingInspection> {
    const inspection = await this.inspect();
    if (inspection.state !== "ready" || !inspection.pythonExecutable) {
      throw new Error(inspection.detail);
    }
    await runBridgeProbe({
      pythonExecutable: inspection.pythonExecutable,
      bridgePath: this.bridgePath,
      cwd: this.paths.stateRoot.fsPath,
    });
    return inspection;
  }

  async remove(): Promise<HookRegistrationMutation> {
    return removeHookRegistration({
      hookPath: this.hookPath,
    });
  }

  private async prepareAndPublish(
    repair: boolean,
  ): Promise<HookRegistrationMutation> {
    const pythonExecutable = await resolvePythonExecutable();
    await materializeHookBridge({
      sourcePath: this.sourceBridgePath,
      bridgePath: this.bridgePath,
    });
    await runBridgeProbe({
      pythonExecutable,
      bridgePath: this.bridgePath,
      cwd: this.paths.stateRoot.fsPath,
    });
    const document = buildHookRegistrationDocument({
      pythonExecutable,
      bridgePath: this.bridgePath,
    });
    return installHookRegistration({
      hookPath: this.hookPath,
      document,
      repair,
    });
  }
}

function combineInspection(input: {
  readonly registrationState: HookRegistrationState;
  readonly registrationDetail: string;
  readonly bridgeReady: boolean;
  readonly bridgeDetail: string;
  readonly hookPath: string;
  readonly bridgePath: string;
  readonly pythonExecutable: string;
}): ChatBindingInspection {
  const common = {
    registrationState: input.registrationState,
    hookPath: input.hookPath,
    bridgePath: input.bridgePath,
    pythonExecutable: input.pythonExecutable,
  };
  if (input.registrationState === "conflict") {
    return {
      ...common,
      state: "conflict",
      detail: input.registrationDetail,
    };
  }
  if (input.registrationState === "absent") {
    return {
      ...common,
      state: "absent",
      detail: input.registrationDetail,
    };
  }
  if (input.registrationState === "repairable" || !input.bridgeReady) {
    return {
      ...common,
      state: "repairable",
      detail: [input.registrationDetail, input.bridgeDetail].join(" "),
    };
  }
  return {
    ...common,
    state: "ready",
    detail:
      "Kiro Hook transport is installed and its global-storage bridge is current.",
  };
}

function runBridgeProbe(input: {
  readonly pythonExecutable: string;
  readonly bridgePath: string;
  readonly cwd: string;
}): Promise<void> {
  const probe = JSON.stringify({
    session_id: "kiro-security-installation-probe",
    hook_event_name: "PreToolUse",
    cwd: input.cwd,
    tool_name: "kiro_powers",
    tool_input: {
      action: "use",
      powerName: "kiro-security-power",
      serverName: "kiro-security-workbench",
      toolName: "kiro_security_get_capabilities",
      arguments: {},
    },
  });

  return new Promise((resolve, reject) => {
    const child = spawn(
      input.pythonExecutable,
      ["-B", input.bridgePath],
      {
        cwd: input.cwd,
        env: { ...process.env, PYTHONIOENCODING: "utf-8" },
        stdio: ["pipe", "pipe", "pipe"],
        windowsHide: true,
      },
    );
    const stderr: Buffer[] = [];
    const stdout: Buffer[] = [];
    const timeout = setTimeout(() => {
      child.kill();
      reject(new Error("Hook bridge verification timed out."));
    }, PROBE_TIMEOUT_MS);
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.on("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    child.on("close", (code) => {
      clearTimeout(timeout);
      const output = Buffer.concat(stdout).toString("utf8").trim();
      const errorOutput = Buffer.concat(stderr).toString("utf8").trim();
      if (code === 0 && output === "" && errorOutput === "") {
        resolve();
        return;
      }
      reject(
        new Error(
          errorOutput ||
            output ||
            `Hook bridge verification exited with code ${String(code)}.`,
        ),
      );
    });
    child.stdin.end(probe);
  });
}
