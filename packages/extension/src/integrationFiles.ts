import { execFile } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import {
  access,
  chmod,
  cp,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import * as path from "node:path";
import { promisify } from "node:util";
import { isDeepStrictEqual } from "node:util";

import {
  applyEdits,
  modify,
  parse,
  type ParseError,
} from "jsonc-parser";

import {
  MCP_MANAGED_MARKER,
  requireMcpServerKey,
  type DirectMcpServerConfiguration,
} from "./integrationConfig";
import { findDuplicateJsonObjectKey } from "./jsonSafety";
import { withSharedFileLock } from "./sharedFileLock";

const executeFile = promisify(execFile);
const MAX_CONFIG_BYTES = 1024 * 1024;

export const STEERING_FILE_NAME = "kiro-security-power.md";
export const LAUNCHER_FILE_NAME = "kiro_security_launcher.py";
export const INTEGRATION_IDENTITY_FILE_NAME = "integration-identity.json";

export type IntegrationFileState =
  | "absent"
  | "installed"
  | "mismatch"
  | "conflict";

export interface IntegrationFileInspection {
  readonly state: IntegrationFileState;
  readonly detail: string;
}

export interface IntegrationMutation {
  readonly changed: boolean;
}

export interface RuntimeInspection {
  readonly ready: boolean;
  readonly detail: string;
}

export function getUserMcpConfigPath(
  homeDirectory: string = homedir(),
): string {
  return path.join(homeDirectory, ".kiro", "settings", "mcp.json");
}

export function getUserSteeringPath(
  homeDirectory: string = homedir(),
): string {
  return path.join(homeDirectory, ".kiro", "steering", STEERING_FILE_NAME);
}

export function getDirectRuntimeRoot(stateRoot: string): string {
  return path.join(stateRoot, "runtime", "direct-mcp");
}

export function getDirectLauncherPath(stateRoot: string): string {
  return path.join(getDirectRuntimeRoot(stateRoot), LAUNCHER_FILE_NAME);
}

export function getPackagedLauncherPath(extensionRoot: string): string {
  return path.join(extensionRoot, "runtime", LAUNCHER_FILE_NAME);
}

export function getPackagedSteeringPath(extensionRoot: string): string {
  return path.join(extensionRoot, "steering", STEERING_FILE_NAME);
}

export function getIntegrationIdentityPath(stateRoot: string): string {
  return path.join(stateRoot, "runtime", INTEGRATION_IDENTITY_FILE_NAME);
}

export async function getOrCreateInstallationServerKey(
  stateRoot: string,
): Promise<string> {
  const identityPath = getIntegrationIdentityPath(stateRoot);
  const existing = await readOptionalRegularFile(
    identityPath,
    "Kiro Security integration identity",
  );
  if (existing !== undefined) {
    return parseInstallationServerKey(existing.contents);
  }
  await ensureDirectory(path.dirname(identityPath));
  const serverKey = `ksp_${base32(randomBytes(12))}`;
  const contents = `${JSON.stringify({ version: 1, serverKey }, null, 2)}\n`;
  const stagingPath = path.join(
    path.dirname(identityPath),
    `.${INTEGRATION_IDENTITY_FILE_NAME}.staging-${randomUUID()}`,
  );
  try {
    await writeFile(stagingPath, contents, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    await restrictFile(stagingPath, 0o600);
    try {
      await link(stagingPath, identityPath);
      return serverKey;
    } catch (error) {
      if (!isAlreadyExists(error)) {
        throw error;
      }
      const raced = await readRequiredRegularFile(
        identityPath,
        "Kiro Security integration identity",
      );
      return parseInstallationServerKey(raced.contents);
    }
  } finally {
    await rm(stagingPath, { force: true });
  }
}

export async function inspectDirectRuntime(input: {
  readonly extensionRoot: string;
  readonly stateRoot: string;
}): Promise<RuntimeInspection> {
  const sourceLauncher = await readRequiredRegularFile(
    getPackagedLauncherPath(input.extensionRoot),
    "Packaged MCP launcher",
  );
  const destinationLauncher = await readOptionalRegularFile(
    getDirectLauncherPath(input.stateRoot),
    "Materialized MCP launcher",
  );
  const destinationEngine = path.join(
    getDirectRuntimeRoot(input.stateRoot),
    "engine",
    "kiro_security",
  );
  if (destinationLauncher === undefined || !(await exists(destinationEngine))) {
    return {
      ready: false,
      detail: "The direct MCP runtime has not been materialized in Extension global storage.",
    };
  }
  const sourceEngine = path.join(input.extensionRoot, "engine", "kiro_security");
  const [sourceDigest, destinationDigest] = await Promise.all([
    digestPythonTree(sourceEngine),
    digestPythonTree(destinationEngine),
  ]);
  const permissionsReady =
    process.platform === "win32" ||
    (destinationLauncher.mode & 0o077) === 0;
  if (
    sourceLauncher.contents.equals(destinationLauncher.contents) &&
    sourceDigest === destinationDigest &&
    permissionsReady
  ) {
    return {
      ready: true,
      detail: "The Extension global-storage MCP runtime is current.",
    };
  }
  return {
    ready: false,
    detail: "The Extension global-storage MCP runtime differs from the packaged runtime.",
  };
}

export async function materializeDirectRuntime(input: {
  readonly extensionRoot: string;
  readonly stateRoot: string;
}): Promise<IntegrationMutation> {
  const runtimeRoot = getDirectRuntimeRoot(input.stateRoot);
  return withSharedFileLock(
    runtimeRoot,
    "The Kiro Security runtime",
    () => materializeDirectRuntimeLocked(input),
  );
}

async function materializeDirectRuntimeLocked(input: {
  readonly extensionRoot: string;
  readonly stateRoot: string;
}): Promise<IntegrationMutation> {
  if ((await inspectDirectRuntime(input)).ready) {
    return { changed: false };
  }
  const runtimeRoot = getDirectRuntimeRoot(input.stateRoot);
  const parent = path.dirname(runtimeRoot);
  await ensureDirectory(parent);
  const stagingRoot = await mkdtemp(
    path.join(parent, ".direct-mcp-staging-"),
  );
  try {
    await cp(
      getPackagedLauncherPath(input.extensionRoot),
      path.join(stagingRoot, LAUNCHER_FILE_NAME),
      { errorOnExist: true, force: false },
    );
    await mkdir(path.join(stagingRoot, "engine"), {
      recursive: true,
      mode: 0o700,
    });
    await cp(
      path.join(input.extensionRoot, "engine", "kiro_security"),
      path.join(stagingRoot, "engine", "kiro_security"),
      {
        recursive: true,
        errorOnExist: true,
        force: false,
        filter: (source) =>
          path.basename(source) !== "__pycache__" && !source.endsWith(".pyc"),
      },
    );
    await restrictTree(stagingRoot);
    await replaceDirectory(stagingRoot, runtimeRoot);
  } catch (error) {
    await rm(stagingRoot, { force: true, recursive: true });
    throw error;
  }
  return { changed: true };
}

export async function initializeDirectRuntime(input: {
  readonly pythonExecutable: string;
  readonly launcherPath: string;
  readonly stateRoot: string;
  readonly scanRoot: string;
}): Promise<void> {
  const { stdout } = await executeFile(
    input.pythonExecutable,
    ["-B", "-S", input.launcherPath, "--initialize"],
    {
      encoding: "utf8",
      maxBuffer: 64 * 1024,
      timeout: 15_000,
      windowsHide: true,
      env: {
        ...process.env,
        PYTHONIOENCODING: "utf-8",
        PYTHONUNBUFFERED: "1",
        KIRO_SECURITY_STATE_ROOT: input.stateRoot,
        KIRO_SECURITY_SCAN_ROOT: input.scanRoot,
      },
    },
  );
  const state = JSON.parse(stdout.trim()) as { schemaVersion?: unknown };
  if (state.schemaVersion !== 1) {
    throw new Error("The direct MCP runtime did not initialize schema v1.");
  }
}

export async function inspectSteering(input: {
  readonly sourcePath: string;
  readonly steeringPath: string;
}): Promise<IntegrationFileInspection> {
  const source = await readRequiredRegularFile(
    input.sourcePath,
    "Packaged Kiro Security steering",
  );
  return inspectDedicatedFile(input.steeringPath, source.contents);
}

export async function installSteering(input: {
  readonly sourcePath: string;
  readonly steeringPath: string;
}): Promise<IntegrationMutation> {
  const source = await readRequiredRegularFile(
    input.sourcePath,
    "Packaged Kiro Security steering",
  );
  const inspection = await inspectDedicatedFile(
    input.steeringPath,
    source.contents,
  );
  if (inspection.state === "conflict") {
    throw new Error(inspection.detail);
  }
  if (inspection.state === "installed") {
    return { changed: false };
  }
  await writeDedicatedFile(input.steeringPath, source.contents, 0o600);
  return { changed: true };
}

export async function inspectMcpRegistration(input: {
  readonly mcpPath: string;
  readonly serverKey: string;
  readonly expected: DirectMcpServerConfiguration;
}): Promise<IntegrationFileInspection> {
  const document = await readMcpDocument(input.mcpPath);
  if (document.kind === "absent") {
    return {
      state: "absent",
      detail: "The Kiro user MCP registration is not installed.",
    };
  }
  if (document.kind === "unsafe") {
    return { state: "conflict", detail: document.detail };
  }
  const server = getServerEntry(document.parsed, input.serverKey);
  if (server === undefined) {
    return {
      state: "absent",
      detail: "The Kiro user MCP configuration has no Kiro Security server entry.",
    };
  }
  const permissionsReady =
    process.platform === "win32" || (document.mode & 0o077) === 0;
  if (isDeepStrictEqual(server, input.expected) && permissionsReady) {
    return {
      state: "installed",
      detail: "The Kiro user MCP registration is current.",
    };
  }
  if (isManagedServerEntry(server)) {
    return {
      state: "mismatch",
      detail: permissionsReady
        ? "The managed Kiro Security MCP entry differs from this Extension version."
        : "The Kiro user MCP configuration permissions are too broad.",
    };
  }
  return {
    state: "conflict",
    detail: `The MCP server key '${input.serverKey}' is already used by an unmanaged configuration.`,
  };
}

export async function installMcpRegistration(input: {
  readonly mcpPath: string;
  readonly serverKey: string;
  readonly expected: DirectMcpServerConfiguration;
}): Promise<IntegrationMutation> {
  return withSharedFileLock(
    input.mcpPath,
    "The Kiro user MCP configuration",
    () => installMcpRegistrationLocked(input),
  );
}

async function installMcpRegistrationLocked(input: {
  readonly mcpPath: string;
  readonly serverKey: string;
  readonly expected: DirectMcpServerConfiguration;
}): Promise<IntegrationMutation> {
  const inspection = await inspectMcpRegistration(input);
  if (inspection.state === "conflict") {
    throw new Error(inspection.detail);
  }
  if (inspection.state === "installed") {
    return { changed: false };
  }
  const snapshot = await readMcpDocument(input.mcpPath);
  if (snapshot.kind === "unsafe") {
    throw new Error(snapshot.detail);
  }
  const source =
    snapshot.kind === "absent"
      ? '{\n  "mcpServers": {}\n}\n'
      : snapshot.contents;
  const updated = applyEdits(
    source,
    modify(
      source,
      ["mcpServers", input.serverKey],
      input.expected,
      { formattingOptions: { insertSpaces: true, tabSize: 2, eol: "\n" } },
    ),
  );
  await writeSharedConfig(input.mcpPath, snapshot, updated);
  return { changed: true };
}

async function inspectDedicatedFile(
  filePath: string,
  expected: Buffer,
): Promise<IntegrationFileInspection> {
  let current;
  try {
    current = await readOptionalRegularFile(filePath, "Dedicated integration file");
  } catch (error) {
    return { state: "conflict", detail: errorMessage(error) };
  }
  if (current === undefined) {
    return { state: "absent", detail: "The dedicated file is not installed." };
  }
  const permissionsReady =
    process.platform === "win32" || (current.mode & 0o077) === 0;
  if (current.contents.equals(expected) && permissionsReady) {
    return { state: "installed", detail: "The dedicated file is current." };
  }
  return {
    state: "mismatch",
    detail: permissionsReady
      ? "The dedicated file differs from this Extension version."
      : "The dedicated file permissions are too broad.",
  };
}

type McpDocument =
  | { readonly kind: "absent" }
  | { readonly kind: "unsafe"; readonly detail: string }
  | {
      readonly kind: "file";
      readonly contents: string;
      readonly parsed: unknown;
      readonly mode: number;
    };

async function readMcpDocument(filePath: string): Promise<McpDocument> {
  let metadata;
  try {
    metadata = await lstat(filePath);
  } catch (error) {
    if (isMissing(error)) {
      return { kind: "absent" };
    }
    throw error;
  }
  if (metadata.isSymbolicLink() || !metadata.isFile()) {
    return {
      kind: "unsafe",
      detail: "The Kiro user MCP path is a symlink or non-regular file and will not be modified.",
    };
  }
  if (metadata.size > MAX_CONFIG_BYTES) {
    return {
      kind: "unsafe",
      detail: "The Kiro user MCP configuration is too large to modify safely.",
    };
  }
  const contents = await readFile(filePath, "utf8");
  const errors: ParseError[] = [];
  const parsed = parse(contents, errors, {
    allowTrailingComma: true,
    disallowComments: false,
  });
  if (
    errors.length > 0 ||
    typeof parsed !== "object" ||
    parsed === null ||
    Array.isArray(parsed)
  ) {
    return {
      kind: "unsafe",
      detail: "The Kiro user MCP configuration is not a valid JSONC object.",
    };
  }
  const duplicateKey = findDuplicateJsonObjectKey(contents, {
    allowTrailingComma: true,
    disallowComments: false,
  });
  if (duplicateKey !== undefined) {
    return {
      kind: "unsafe",
      detail: `The Kiro user MCP configuration contains duplicate JSON object key ${JSON.stringify(duplicateKey)} and will not be modified.`,
    };
  }
  const servers = (parsed as { mcpServers?: unknown }).mcpServers;
  if (
    servers !== undefined &&
    (typeof servers !== "object" || servers === null || Array.isArray(servers))
  ) {
    return {
      kind: "unsafe",
      detail: "The Kiro user MCP mcpServers value must be an object.",
    };
  }
  return { kind: "file", contents, parsed, mode: metadata.mode };
}

function getServerEntry(parsed: unknown, serverKey: string): unknown {
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return undefined;
  }
  const servers = (parsed as { mcpServers?: unknown }).mcpServers;
  if (typeof servers !== "object" || servers === null || Array.isArray(servers)) {
    return undefined;
  }
  return (servers as Readonly<Record<string, unknown>>)[serverKey];
}

function isManagedServerEntry(value: unknown): boolean {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const env = (value as { env?: unknown }).env;
  return (
    typeof env === "object" &&
    env !== null &&
    !Array.isArray(env) &&
    (env as Record<string, unknown>).KIRO_SECURITY_MANAGED_BY ===
      MCP_MANAGED_MARKER
  );
}

async function writeSharedConfig(
  filePath: string,
  snapshot: McpDocument,
  contents: string,
): Promise<void> {
  const directory = path.dirname(filePath);
  await ensureDirectory(directory, false);
  const stagingPath = path.join(
    directory,
    `.mcp.json.staging-${randomUUID()}`,
  );
  try {
    await writeFile(stagingPath, contents, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    await restrictFile(stagingPath, 0o600);
    if (snapshot.kind === "absent") {
      try {
        await access(filePath);
        throw new Error("The Kiro user MCP configuration changed during installation.");
      } catch (error) {
        if (!isMissing(error)) {
          throw error;
        }
      }
    } else if (snapshot.kind === "file") {
      const latest = await readOptionalRegularFile(
        filePath,
        "Kiro user MCP configuration",
      );
      if (
        latest === undefined ||
        latest.contents.toString("utf8") !== snapshot.contents
      ) {
        throw new Error("The Kiro user MCP configuration changed during installation.");
      }
    } else {
      throw new Error(snapshot.detail);
    }
    await rename(stagingPath, filePath);
  } catch (error) {
    await rm(stagingPath, { force: true });
    throw error;
  }
}

async function writeDedicatedFile(
  filePath: string,
  contents: Buffer,
  mode: number,
): Promise<void> {
  const directory = path.dirname(filePath);
  await ensureDirectory(directory, false);
  const stagingPath = path.join(
    directory,
    `.${path.basename(filePath)}.staging-${randomUUID()}`,
  );
  try {
    await writeFile(stagingPath, contents, { flag: "wx", mode });
    await restrictFile(stagingPath, mode);
    await rename(stagingPath, filePath);
  } catch (error) {
    await rm(stagingPath, { force: true });
    throw error;
  }
}

async function replaceDirectory(
  source: string,
  destination: string,
): Promise<void> {
  const previous = `${destination}.previous-${randomUUID()}`;
  const destinationExists = await exists(destination);
  if (destinationExists) {
    await rename(destination, previous);
  }
  try {
    await rename(source, destination);
  } catch (error) {
    if (destinationExists) {
      await rename(previous, destination);
    }
    throw error;
  }
  if (destinationExists) {
    await rm(previous, { force: true, recursive: true });
  }
}

async function digestPythonTree(root: string): Promise<string> {
  const hash = createHash("sha256");
  const visit = async (directory: string, relative: string): Promise<void> => {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      if (entry.name === "__pycache__" || entry.name.endsWith(".pyc")) {
        continue;
      }
      const absolute = path.join(directory, entry.name);
      const childRelative = path.join(relative, entry.name);
      if (entry.isSymbolicLink()) {
        throw new Error(`Runtime source must not contain symlinks: ${absolute}`);
      }
      if (entry.isDirectory()) {
        await visit(absolute, childRelative);
      } else if (entry.isFile()) {
        hash.update(childRelative.split(path.sep).join("/"));
        hash.update("\0");
        hash.update(await readFile(absolute));
        hash.update("\0");
      } else {
        throw new Error(`Runtime source contains an unsupported entry: ${absolute}`);
      }
    }
  };
  await visit(root, "");
  return hash.digest("hex");
}

async function restrictTree(root: string): Promise<void> {
  if (process.platform === "win32") {
    return;
  }
  await chmod(root, 0o700);
  const entries = await readdir(root, { withFileTypes: true });
  for (const entry of entries) {
    const candidate = path.join(root, entry.name);
    if (entry.isDirectory()) {
      await restrictTree(candidate);
    } else if (entry.isFile()) {
      await chmod(
        candidate,
        entry.name === LAUNCHER_FILE_NAME ? 0o700 : 0o600,
      );
    }
  }
}

async function ensureDirectory(
  directoryPath: string,
  restrictExisting = true,
): Promise<void> {
  let created = false;
  try {
    const metadata = await lstat(directoryPath);
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
      throw new Error(
        `Refusing to use a symlink or non-directory path: ${directoryPath}`,
      );
    }
  } catch (error) {
    if (!isMissing(error)) {
      throw error;
    }
    await mkdir(directoryPath, { recursive: true, mode: 0o700 });
    created = true;
  }
  if (process.platform !== "win32" && (created || restrictExisting)) {
    await chmod(directoryPath, 0o700);
  }
}

async function readRequiredRegularFile(
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
    throw new Error(`${label} must be a regular non-symlink file: ${filePath}`);
  }
  return { contents: await readFile(filePath), mode: metadata.mode };
}

async function restrictFile(filePath: string, mode: number): Promise<void> {
  if (process.platform !== "win32") {
    await chmod(filePath, mode);
  }
}

async function exists(candidate: string): Promise<boolean> {
  try {
    await access(candidate);
    return true;
  } catch {
    return false;
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

function isAlreadyExists(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as NodeJS.ErrnoException).code === "EEXIST"
  );
}

function parseInstallationServerKey(contents: Buffer): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(contents.toString("utf8"));
  } catch {
    throw new Error("Kiro Security integration identity is invalid JSON.");
  }
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    Array.isArray(parsed) ||
    (parsed as { version?: unknown }).version !== 1
  ) {
    throw new Error("Kiro Security integration identity has an unsupported format.");
  }
  return requireMcpServerKey((parsed as { serverKey?: unknown }).serverKey);
}

function base32(value: Buffer): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let bits = 0;
  let accumulator = 0;
  let output = "";
  for (const byte of value) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += alphabet[(accumulator >>> bits) & 31];
    }
    accumulator &= bits === 0 ? 0 : (1 << bits) - 1;
  }
  if (bits > 0) {
    output += alphabet[(accumulator << (5 - bits)) & 31];
  }
  if (output.length !== 20) {
    throw new Error("Kiro Security installation key generation failed.");
  }
  return output;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
