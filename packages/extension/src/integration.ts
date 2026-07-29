import * as vscode from "vscode";

import {
  ChatBindingManager,
  type ChatBindingInspection,
} from "./chatBinding";
import type { FoundationPaths } from "./foundation";
import {
  buildDirectMcpContract,
  buildDirectMcpServerConfiguration,
  type DirectMcpContract,
} from "./integrationConfig";
import {
  getDirectLauncherPath,
  getDirectRuntimeRoot,
  getPackagedSteeringPath,
  getUserMcpConfigPath,
  getUserSteeringPath,
  initializeDirectRuntime,
  inspectDirectRuntime,
  inspectMcpRegistration,
  inspectSteering,
  installMcpRegistration,
  installSteering,
  materializeDirectRuntime,
  type IntegrationFileInspection,
  type RuntimeInspection,
} from "./integrationFiles";
import { resolvePythonExecutable } from "./pythonRuntime";

export type KiroIntegrationState =
  | "absent"
  | "ready"
  | "mismatch"
  | "conflict"
  | "unavailable";

export interface KiroIntegrationInspection {
  readonly state: KiroIntegrationState;
  readonly detail: string;
  readonly serverKey: string;
  readonly hook: ChatBindingInspection;
  readonly mcp: IntegrationFileInspection;
  readonly steering: IntegrationFileInspection;
  readonly runtime: RuntimeInspection;
  readonly hookPath: string;
  readonly mcpPath: string;
  readonly steeringPath: string;
  readonly runtimeRoot: string;
  readonly pythonExecutable?: string;
}

export interface KiroIntegrationMutation {
  readonly changed: boolean;
}

export class KiroIntegrationManager {
  readonly chatBinding: ChatBindingManager;
  readonly contract: DirectMcpContract;
  readonly serverKey: string;
  readonly mcpPath = getUserMcpConfigPath();
  readonly steeringPath = getUserSteeringPath();
  readonly runtimeRoot: string;
  readonly launcherPath: string;
  private readonly extensionRoot: string;
  private readonly steeringSourcePath: string;

  constructor(
    context: vscode.ExtensionContext,
    private readonly paths: FoundationPaths,
    serverKey: string,
  ) {
    this.extensionRoot = context.extensionUri.fsPath;
    this.contract = buildDirectMcpContract(serverKey);
    this.serverKey = this.contract.serverKey;
    this.chatBinding = new ChatBindingManager(context, paths, this.contract);
    this.runtimeRoot = getDirectRuntimeRoot(paths.stateRoot.fsPath);
    this.launcherPath = getDirectLauncherPath(paths.stateRoot.fsPath);
    this.steeringSourcePath = getPackagedSteeringPath(this.extensionRoot);
  }

  async inspect(): Promise<KiroIntegrationInspection> {
    let pythonExecutable: string;
    try {
      pythonExecutable = await resolvePythonExecutable();
    } catch (error) {
      const hook = await this.chatBinding.inspect();
      return {
        state: "unavailable",
        detail: errorMessage(error),
        serverKey: this.serverKey,
        hook,
        mcp: { state: "absent", detail: "Python is unavailable." },
        steering: await inspectSteering({
          sourcePath: this.steeringSourcePath,
          steeringPath: this.steeringPath,
        }),
        runtime: { ready: false, detail: "Python is unavailable." },
        hookPath: this.chatBinding.hookPath,
        mcpPath: this.mcpPath,
        steeringPath: this.steeringPath,
        runtimeRoot: this.runtimeRoot,
      };
    }
    const expected = this.expectedMcpConfiguration(pythonExecutable);
    const [hook, mcp, steering, runtime] = await Promise.all([
      this.chatBinding.inspect(),
      inspectMcpRegistration({
        mcpPath: this.mcpPath,
        serverKey: this.serverKey,
        expected,
      }),
      inspectSteering({
        sourcePath: this.steeringSourcePath,
        steeringPath: this.steeringPath,
      }),
      inspectDirectRuntime({
        extensionRoot: this.extensionRoot,
        stateRoot: this.paths.stateRoot.fsPath,
      }),
    ]);
    const state = combinedState({ hook, mcp, steering, runtime });
    return {
      state,
      detail: [hook.detail, mcp.detail, steering.detail, runtime.detail].join(
        " ",
      ),
      serverKey: this.serverKey,
      hook,
      mcp,
      steering,
      runtime,
      hookPath: this.chatBinding.hookPath,
      mcpPath: this.mcpPath,
      steeringPath: this.steeringPath,
      runtimeRoot: this.runtimeRoot,
      pythonExecutable,
    };
  }

  async install(): Promise<KiroIntegrationMutation> {
    const before = await this.inspect();
    if (before.state === "conflict" || before.state === "unavailable") {
      throw new Error(before.detail);
    }
    if (before.state === "ready") {
      return { changed: false };
    }
    const pythonExecutable =
      before.pythonExecutable ?? (await resolvePythonExecutable());
    let changed = false;
    changed =
      (
        await materializeDirectRuntime({
          extensionRoot: this.extensionRoot,
          stateRoot: this.paths.stateRoot.fsPath,
        })
      ).changed || changed;
    await this.initializeRuntime(pythonExecutable);
    changed =
      (
        await installSteering({
          sourcePath: this.steeringSourcePath,
          steeringPath: this.steeringPath,
        })
      ).changed || changed;
    changed = (await this.chatBinding.install()).changed || changed;
    changed =
      (
        await installMcpRegistration({
          mcpPath: this.mcpPath,
          serverKey: this.serverKey,
          expected: this.expectedMcpConfiguration(pythonExecutable),
        })
      ).changed || changed;
    const after = await this.inspect();
    if (after.state !== "ready") {
      throw new Error(after.detail);
    }
    return { changed };
  }

  private expectedMcpConfiguration(pythonExecutable: string) {
    return buildDirectMcpServerConfiguration({
      serverKey: this.serverKey,
      pythonExecutable,
      launcherPath: this.launcherPath,
      stateRoot: this.paths.stateRoot.fsPath,
      scanRoot: this.paths.scanRoot.fsPath,
    });
  }

  private initializeRuntime(pythonExecutable: string): Promise<void> {
    return initializeDirectRuntime({
      pythonExecutable,
      launcherPath: this.launcherPath,
      stateRoot: this.paths.stateRoot.fsPath,
      scanRoot: this.paths.scanRoot.fsPath,
    });
  }

}

function combinedState(input: {
  readonly hook: ChatBindingInspection;
  readonly mcp: IntegrationFileInspection;
  readonly steering: IntegrationFileInspection;
  readonly runtime: RuntimeInspection;
}): KiroIntegrationState {
  if (
    input.hook.state === "conflict" ||
    input.mcp.state === "conflict" ||
    input.steering.state === "conflict"
  ) {
    return "conflict";
  }
  if (input.hook.state === "unavailable") {
    return "unavailable";
  }
  if (
    input.hook.state === "ready" &&
    input.mcp.state === "installed" &&
    input.steering.state === "installed" &&
    input.runtime.ready
  ) {
    return "ready";
  }
  if (
    input.hook.state === "absent" &&
    input.mcp.state === "absent" &&
    input.steering.state === "absent"
  ) {
    return "absent";
  }
  return "mismatch";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
