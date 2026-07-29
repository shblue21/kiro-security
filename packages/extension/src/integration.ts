import { randomUUID } from "node:crypto";
import * as path from "node:path";

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
  removeMcpRegistration,
  removeMcpShadowGuard,
  removeSteering,
  updateMcpShadowGuard,
  type IntegrationFileInspection,
  type RuntimeInspection,
} from "./integrationFiles";
import { resolvePythonExecutable } from "./pythonRuntime";
import {
  getActiveUserPermissionsPath,
  inspectPermissions,
  installPermissions,
  removePermissions,
} from "./permissionFiles";

export type KiroIntegrationState =
  | "absent"
  | "ready"
  | "repairable"
  | "conflict"
  | "unavailable";

export interface KiroIntegrationInspection {
  readonly state: KiroIntegrationState;
  readonly detail: string;
  readonly serverKey: string;
  readonly hook: ChatBindingInspection;
  readonly mcp: IntegrationFileInspection;
  readonly permissions: IntegrationFileInspection;
  readonly steering: IntegrationFileInspection;
  readonly runtime: RuntimeInspection;
  readonly hookPath: string;
  readonly mcpPath: string;
  readonly permissionsPath: string;
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
  private readonly shadowGuardId = randomUUID();
  private shadowGuardArmed = true;
  private shadowRefreshTail: Promise<void> = Promise.resolve();

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
      const [hook, permissions, permissionsPath] = await Promise.all([
        this.chatBinding.inspect(),
        inspectPermissions({ serverKey: this.serverKey }),
        getActiveUserPermissionsPath(),
      ]);
      return {
        state: "unavailable",
        detail: errorMessage(error),
        serverKey: this.serverKey,
        hook,
        mcp: { state: "absent", detail: "Python is unavailable." },
        permissions,
        steering: await inspectSteering({
          sourcePath: this.steeringSourcePath,
          steeringPath: this.steeringPath,
        }),
        runtime: { ready: false, detail: "Python is unavailable." },
        hookPath: this.chatBinding.hookPath,
        mcpPath: this.mcpPath,
        permissionsPath,
        steeringPath: this.steeringPath,
        runtimeRoot: this.runtimeRoot,
      };
    }
    const expected = this.expectedMcpConfiguration(pythonExecutable);
    const [hook, registration, shadowing, permissions, permissionsPath, steering, runtime] = await Promise.all([
      this.chatBinding.inspect(),
      inspectMcpRegistration({
        mcpPath: this.mcpPath,
        serverKey: this.serverKey,
        expected,
      }),
      this.refreshMcpShadowGuard(expected),
      inspectPermissions({ serverKey: this.serverKey }),
      getActiveUserPermissionsPath(),
      inspectSteering({
        sourcePath: this.steeringSourcePath,
        steeringPath: this.steeringPath,
      }),
      inspectDirectRuntime({
        extensionRoot: this.extensionRoot,
        stateRoot: this.paths.stateRoot.fsPath,
      }),
    ]);
    const mcp = shadowing.state === "conflict" ? shadowing : registration;
    const state = combinedState({ hook, mcp, permissions, steering, runtime });
    return {
      state,
      detail: [hook.detail, mcp.detail, permissions.detail, steering.detail, runtime.detail].join(
        " ",
      ),
      serverKey: this.serverKey,
      hook,
      mcp,
      permissions,
      steering,
      runtime,
      hookPath: this.chatBinding.hookPath,
      mcpPath: this.mcpPath,
      permissionsPath,
      steeringPath: this.steeringPath,
      runtimeRoot: this.runtimeRoot,
      pythonExecutable,
    };
  }

  async install(repair = false): Promise<KiroIntegrationMutation> {
    this.shadowGuardArmed = true;
    const before = await this.inspect();
    if (before.state === "conflict" || before.state === "unavailable") {
      throw new Error(before.detail);
    }
    if (before.state === "repairable" && !repair) {
      throw new Error(
        "The Kiro Security integration requires the explicit Repair action.",
      );
    }
    if (before.state === "ready") {
      return { changed: false };
    }
    const pythonExecutable =
      before.pythonExecutable ?? (await resolvePythonExecutable());
    let changed = false;
    changed =
      (await installPermissions({ serverKey: this.serverKey })).changed || changed;
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
          repair,
        })
      ).changed || changed;
    changed =
      (repair
        ? (await this.chatBinding.repair()).changed
        : (await this.chatBinding.install()).changed) || changed;
    changed =
      (
        await installMcpRegistration({
          mcpPath: this.mcpPath,
          serverKey: this.serverKey,
          expected: this.expectedMcpConfiguration(pythonExecutable),
          repair,
        })
      ).changed || changed;
    const after = await this.inspect();
    if (after.state !== "ready") {
      throw new Error(after.detail);
    }
    return { changed };
  }

  async verify(): Promise<KiroIntegrationInspection> {
    const inspection = await this.inspect();
    if (inspection.state !== "ready" || !inspection.pythonExecutable) {
      throw new Error(inspection.detail);
    }
    await this.initializeRuntime(inspection.pythonExecutable);
    await this.chatBinding.verify();
    return inspection;
  }

  async refreshMcpShadowGuard(
    expectedConfiguration?: ReturnType<typeof buildDirectMcpServerConfiguration>,
  ): Promise<IntegrationFileInspection> {
    const operation = this.shadowRefreshTail.then(async () => {
      let expected = expectedConfiguration;
      if (this.shadowGuardArmed && expected === undefined) {
        try {
          expected = this.expectedMcpConfiguration(
            await resolvePythonExecutable(),
          );
        } catch {
          expected = undefined;
        }
      }
      return updateMcpShadowGuard({
        stateRoot: this.paths.stateRoot.fsPath,
        guardId: this.shadowGuardId,
        serverKey: this.serverKey,
        userMcpPath: this.mcpPath,
        workspaceRoots: this.workspaceRoots(),
        expected: this.shadowGuardArmed ? expected : undefined,
      });
    });
    this.shadowRefreshTail = operation.then(
      () => undefined,
      () => undefined,
    );
    return (await operation).inspection;
  }

  startShadowMonitoring(output: vscode.OutputChannel): vscode.Disposable {
    const refresh = (): void => {
      void this.refreshMcpShadowGuard().catch((error: unknown) => {
        output.appendLine(
          `Unable to refresh the MCP shadow guard: ${errorMessage(error)}`,
        );
      });
    };
    const workspaceWatcher = vscode.workspace.createFileSystemWatcher(
      "**/.kiro/settings/mcp.json",
    );
    const userWatcher = vscode.workspace.createFileSystemWatcher(
      new vscode.RelativePattern(
        path.dirname(this.mcpPath),
        path.basename(this.mcpPath),
      ),
    );
    const subscriptions = [
      workspaceWatcher.onDidCreate(refresh),
      workspaceWatcher.onDidChange(refresh),
      workspaceWatcher.onDidDelete(refresh),
      userWatcher.onDidCreate(refresh),
      userWatcher.onDidChange(refresh),
      userWatcher.onDidDelete(refresh),
      vscode.workspace.onDidChangeWorkspaceFolders(refresh),
    ];
    const timer = setInterval(refresh, 15_000);
    return vscode.Disposable.from(
      workspaceWatcher,
      userWatcher,
      ...subscriptions,
      new vscode.Disposable(() => {
        clearInterval(timer);
        void removeMcpShadowGuard({
          stateRoot: this.paths.stateRoot.fsPath,
          guardId: this.shadowGuardId,
        }).catch((error: unknown) => {
          output.appendLine(
            `Unable to remove the MCP shadow guard: ${errorMessage(error)}`,
          );
        });
      }),
    );
  }

  async disconnect(): Promise<KiroIntegrationMutation> {
    this.shadowGuardArmed = false;
    let changed = false;
    const failures: string[] = [];
    const attempt = async (
      action: () => Promise<KiroIntegrationMutation>,
    ): Promise<boolean> => {
      try {
        changed = (await action()).changed || changed;
        return true;
      } catch (error) {
        failures.push(errorMessage(error));
        return false;
      }
    };
    let guardRevoked = true;
    try {
      await this.refreshMcpShadowGuard();
    } catch (error) {
      guardRevoked = false;
      failures.push(errorMessage(error));
    }
    const permissionsRemoved = await attempt(() =>
      removePermissions({ serverKey: this.serverKey }),
    );
    const mcpRemoved = await attempt(() =>
      removeMcpRegistration({
        mcpPath: this.mcpPath,
        serverKey: this.serverKey,
      }),
    );
    await attempt(() =>
      removeSteering({ steeringPath: this.steeringPath }),
    );
    if (guardRevoked && permissionsRemoved && mcpRemoved) {
      await attempt(() => this.chatBinding.remove());
    } else {
      failures.push(
        "The Hook was retained to keep incomplete revocation fail-closed.",
      );
    }
    if (failures.length > 0) {
      throw new Error(
        `Kiro Security was revoked where possible, but cleanup was incomplete: ${failures.join(" ")}`,
      );
    }
    this.shadowGuardArmed = true;
    return { changed };
  }

  private expectedMcpConfiguration(pythonExecutable: string) {
    return buildDirectMcpServerConfiguration({
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

  private workspaceRoots(): readonly string[] {
    return (
      vscode.workspace.workspaceFolders?.map((folder) => folder.uri.fsPath) ?? []
    );
  }
}

function combinedState(input: {
  readonly hook: ChatBindingInspection;
  readonly mcp: IntegrationFileInspection;
  readonly permissions: IntegrationFileInspection;
  readonly steering: IntegrationFileInspection;
  readonly runtime: RuntimeInspection;
}): KiroIntegrationState {
  if (
    input.hook.state === "conflict" ||
    input.mcp.state === "conflict" ||
    input.permissions.state === "conflict" ||
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
    input.permissions.state === "installed" &&
    input.steering.state === "installed" &&
    input.runtime.ready
  ) {
    return "ready";
  }
  if (
    input.hook.state === "absent" &&
    input.mcp.state === "absent" &&
    input.permissions.state === "absent" &&
    input.steering.state === "absent"
  ) {
    return "absent";
  }
  return "repairable";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
