import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  access,
  chmod,
  cp,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rename,
  rm,
} from "node:fs/promises";
import * as path from "node:path";
import { promisify } from "node:util";

import {
  ensurePrivateDirectory,
  readOptionalRegularFile,
  readRequiredRegularFile,
} from "./localFileSafety";
import { withSharedFileLock } from "./sharedFileLock";

const executeFile = promisify(execFile);

export const LAUNCHER_FILE_NAME = "kiro_security_launcher.py";

export interface RuntimeInspection {
  readonly ready: boolean;
  readonly detail: string;
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
}): Promise<{ readonly changed: boolean }> {
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
}): Promise<{ readonly changed: boolean }> {
  if ((await inspectDirectRuntime(input)).ready) {
    return { changed: false };
  }
  const runtimeRoot = getDirectRuntimeRoot(input.stateRoot);
  const parent = path.dirname(runtimeRoot);
  await ensurePrivateDirectory(parent);
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

async function exists(candidate: string): Promise<boolean> {
  try {
    await access(candidate);
    return true;
  } catch {
    return false;
  }
}
