import {
  chmod,
  lstat,
  mkdir,
  readFile,
  rename,
  rm,
  unlink,
  writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import * as path from "node:path";
import { isDeepStrictEqual } from "node:util";
import { randomUUID } from "node:crypto";

export const HOOK_FILE_NAME = "kiro-security-power.json";
export const HOOK_NAME = "Kiro Security Power chat identity bridge";
export const HOOK_DESCRIPTION =
  "Managed by the Kiro Security Power VSIX; runtime state remains in extension global storage.";
export const POWER_TOOL_MATCHER = "^kiro_powers$";
export const HOOK_BRIDGE_FILE_NAME = "kiro_security_hook_bridge.py";
export const MAX_HOOK_FILE_BYTES = 1024 * 1024;

export interface HookRegistrationDocument {
  readonly version: "v1";
  readonly hooks: readonly [
    {
      readonly name: string;
      readonly description: string;
      readonly trigger: "PreToolUse";
      readonly matcher: string;
      readonly action: {
        readonly type: "command";
        readonly command: string;
      };
      readonly timeout: number;
      readonly enabled: true;
    },
  ];
}

export type HookRegistrationState =
  | "absent"
  | "installed"
  | "repairable"
  | "conflict";

export interface HookRegistrationInspection {
  readonly state: HookRegistrationState;
  readonly detail: string;
}

export interface HookRegistrationMutation {
  readonly changed: boolean;
}

export interface BridgeInspection {
  readonly ready: boolean;
  readonly detail: string;
}

export function getHookRegistrationPath(
  homeDirectory: string = homedir(),
): string {
  return path.join(homeDirectory, ".kiro", "hooks", HOOK_FILE_NAME);
}

export function getHookBridgePath(stateRoot: string): string {
  return path.join(
    stateRoot,
    "runtime",
    "hook-bridge",
    HOOK_BRIDGE_FILE_NAME,
  );
}

export function getPackagedHookBridgePath(extensionRoot: string): string {
  return path.join(extensionRoot, "hook", HOOK_BRIDGE_FILE_NAME);
}

export function buildHookRegistrationDocument(input: {
  readonly pythonExecutable: string;
  readonly bridgePath: string;
  readonly platform?: NodeJS.Platform;
}): HookRegistrationDocument {
  requireAbsolutePath(input.pythonExecutable, "Python executable");
  requireAbsolutePath(input.bridgePath, "Hook bridge");
  const platform = input.platform ?? process.platform;
  return {
    version: "v1",
    hooks: [
      {
        name: HOOK_NAME,
        description: HOOK_DESCRIPTION,
        trigger: "PreToolUse",
        matcher: POWER_TOOL_MATCHER,
        action: {
          type: "command",
          command: [
            quoteCommandArgument(input.pythonExecutable, platform),
            "-B",
            quoteCommandArgument(input.bridgePath, platform),
          ].join(" "),
        },
        timeout: 10,
        enabled: true,
      },
    ],
  };
}

export async function inspectHookRegistration(input: {
  readonly hookPath: string;
  readonly expected?: HookRegistrationDocument;
}): Promise<HookRegistrationInspection> {
  const inspected = await readRegistration(input.hookPath);
  if (inspected.kind === "absent") {
    return {
      state: "absent",
      detail: "The Kiro user Hook registration is not installed.",
    };
  }
  if (inspected.kind === "unsafe") {
    return {
      state: "conflict",
      detail: inspected.detail,
    };
  }

  const permissionsReady =
    process.platform === "win32" || (inspected.mode & 0o077) === 0;
  const parsed =
    inspected.contents === undefined
      ? undefined
      : parseJson(inspected.contents);
  if (
    input.expected !== undefined &&
    isDeepStrictEqual(parsed, input.expected) &&
    permissionsReady
  ) {
    return {
      state: "installed",
      detail: "The dedicated Kiro Hook registration is current.",
    };
  }
  return {
    state: "repairable",
    detail: permissionsReady
      ? "The dedicated Kiro Hook registration differs from the current Extension configuration."
      : "The dedicated Kiro Hook registration has permissions that are too broad.",
  };
}

export async function installHookRegistration(input: {
  readonly hookPath: string;
  readonly document: HookRegistrationDocument;
  readonly repair: boolean;
}): Promise<HookRegistrationMutation> {
  const inspection = await inspectHookRegistration({
    hookPath: input.hookPath,
    expected: input.document,
  });
  if (inspection.state === "installed") {
    return { changed: false };
  }
  if (inspection.state === "conflict") {
    throw new Error(inspection.detail);
  }
  if (inspection.state === "repairable" && !input.repair) {
    throw new Error(
      "The dedicated Hook registration requires repair. Use the explicit Repair action to replace it.",
    );
  }

  const hookDirectory = path.dirname(input.hookPath);
  await ensureDirectory(hookDirectory);
  const stagingPath = path.join(
    hookDirectory,
    `.${HOOK_FILE_NAME}.staging-${randomUUID()}`,
  );
  try {
    await writeFile(
      stagingPath,
      `${JSON.stringify(input.document, null, 2)}\n`,
      { encoding: "utf8", flag: "wx", mode: 0o600 },
    );
    await restrictFile(stagingPath, 0o600);
    await rename(stagingPath, input.hookPath);
  } catch (error) {
    await rm(stagingPath, { force: true });
    throw error;
  }

  return { changed: true };
}

export async function removeHookRegistration(input: {
  readonly hookPath: string;
}): Promise<HookRegistrationMutation> {
  const inspection = await inspectHookRegistration({
    hookPath: input.hookPath,
  });
  if (inspection.state === "absent") {
    return { changed: false };
  }
  if (inspection.state === "conflict") {
    throw new Error(inspection.detail);
  }

  await unlink(input.hookPath);
  return { changed: true };
}

export async function inspectHookBridge(input: {
  readonly sourcePath: string;
  readonly bridgePath: string;
}): Promise<BridgeInspection> {
  const source = await readRegularFile(input.sourcePath, "Packaged Hook bridge");
  const destination = await readOptionalRegularFile(
    input.bridgePath,
    "Materialized Hook bridge",
  );
  if (destination === undefined) {
    return {
      ready: false,
      detail: "The Hook bridge has not been materialized in extension global storage.",
    };
  }
  if (bridgeIsCurrent(source, destination)) {
    return {
      ready: true,
      detail: "The global-storage Hook bridge is current.",
    };
  }
  const permissionsReady =
    process.platform === "win32" || (destination.mode & 0o077) === 0;
  return {
    ready: false,
    detail: permissionsReady
      ? "The global-storage Hook bridge differs from the packaged bridge."
      : "The global-storage Hook bridge has permissions that are too broad.",
  };
}

export async function materializeHookBridge(input: {
  readonly sourcePath: string;
  readonly bridgePath: string;
}): Promise<boolean> {
  const source = await readRegularFile(input.sourcePath, "Packaged Hook bridge");
  const destination = await readOptionalRegularFile(
    input.bridgePath,
    "Materialized Hook bridge",
  );
  if (destination !== undefined && bridgeIsCurrent(source, destination)) {
    return false;
  }

  const bridgeDirectory = path.dirname(input.bridgePath);
  await ensureDirectory(bridgeDirectory);
  const stagingPath = path.join(
    bridgeDirectory,
    `.${HOOK_BRIDGE_FILE_NAME}.staging-${randomUUID()}`,
  );
  try {
    await writeFile(stagingPath, source.contents, {
      flag: "wx",
      mode: 0o700,
    });
    await restrictFile(stagingPath, 0o700);
    await rename(stagingPath, input.bridgePath);
  } catch (error) {
    await rm(stagingPath, { force: true });
    throw error;
  }
  return true;
}

function bridgeIsCurrent(
  source: { readonly contents: Buffer },
  destination: { readonly contents: Buffer; readonly mode: number },
): boolean {
  const permissionsReady =
    process.platform === "win32" || (destination.mode & 0o077) === 0;
  return destination.contents.equals(source.contents) && permissionsReady;
}

function quoteCommandArgument(
  value: string,
  platform: NodeJS.Platform,
): string {
  if (value.includes("\0") || value.includes("\n") || value.includes("\r")) {
    throw new Error("Hook command paths cannot contain control characters.");
  }
  if (platform === "win32") {
    if (/["%!]/.test(value)) {
      throw new Error(
        "Hook command paths containing Windows shell metacharacters are unsupported.",
      );
    }
    return `"${value}"`;
  }
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}

function requireAbsolutePath(value: string, label: string): void {
  if (!path.isAbsolute(value)) {
    throw new Error(`${label} path must be absolute.`);
  }
}

async function readRegistration(
  hookPath: string,
): Promise<
  | { readonly kind: "absent" }
  | { readonly kind: "unsafe"; readonly detail: string }
  | {
      readonly kind: "file";
      readonly contents?: string;
      readonly mode: number;
    }
> {
  let metadata;
  try {
    metadata = await lstat(hookPath);
  } catch (error) {
    if (isMissing(error)) {
      return { kind: "absent" };
    }
    throw error;
  }
  if (metadata.isSymbolicLink() || !metadata.isFile()) {
    return {
      kind: "unsafe",
      detail:
        "The dedicated Hook path is a symlink or non-regular file and will not be modified.",
    };
  }
  if (metadata.size > MAX_HOOK_FILE_BYTES) {
    return {
      kind: "file",
      mode: metadata.mode,
    };
  }
  return {
    kind: "file",
    contents: await readFile(hookPath, "utf8"),
    mode: metadata.mode,
  };
}

function parseJson(contents: string): unknown {
  try {
    return JSON.parse(contents.replace(/^\uFEFF/, ""));
  } catch {
    return undefined;
  }
}

async function ensureDirectory(directoryPath: string): Promise<void> {
  try {
    const metadata = await lstat(directoryPath);
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
      throw new Error(
        `Refusing to use a symlink or non-directory path: ${directoryPath}`,
      );
    }
    return;
  } catch (error) {
    if (!isMissing(error)) {
      throw error;
    }
  }
  await mkdir(directoryPath, { recursive: true, mode: 0o700 });
  if (process.platform !== "win32") {
    await chmod(directoryPath, 0o700);
  }
}

async function readRegularFile(
  filePath: string,
  label: string,
): Promise<{ readonly contents: Buffer; readonly mode: number }> {
  const value = await readOptionalRegularFile(filePath, label);
  if (value === undefined) {
    throw new Error(`${label} does not exist: ${filePath}`);
  }
  return value;
}

async function readOptionalRegularFile(
  filePath: string,
  label: string,
): Promise<
  | { readonly contents: Buffer; readonly mode: number }
  | undefined
> {
  let metadata;
  try {
    metadata = await lstat(filePath);
  } catch (error) {
    if (isMissing(error)) {
      return undefined;
    }
    throw error;
  }
  if (metadata.isSymbolicLink() || !metadata.isFile()) {
    throw new Error(`${label} must be a regular file: ${filePath}`);
  }
  return {
    contents: await readFile(filePath),
    mode: metadata.mode,
  };
}

async function restrictFile(filePath: string, mode: number): Promise<void> {
  if (process.platform !== "win32") {
    await chmod(filePath, mode);
  }
}

function isMissing(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as NodeJS.ErrnoException).code === "ENOENT"
  );
}
