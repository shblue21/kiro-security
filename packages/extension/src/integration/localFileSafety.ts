import { randomUUID } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import * as path from "node:path";

export interface RegularFileSnapshot {
  readonly contents: Buffer;
  readonly mode: number;
}

export async function ensurePrivateDirectory(
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

export async function readRequiredRegularFile(
  filePath: string,
  label: string,
  unsafeKind = "regular non-symlink file",
): Promise<RegularFileSnapshot> {
  const value = await readOptionalRegularFile(filePath, label, unsafeKind);
  if (value === undefined) {
    throw new Error(`${label} does not exist: ${filePath}`);
  }
  return value;
}

export async function readOptionalRegularFile(
  filePath: string,
  label: string,
  unsafeKind = "regular non-symlink file",
): Promise<RegularFileSnapshot | undefined> {
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
    throw new Error(`${label} must be a ${unsafeKind}: ${filePath}`);
  }
  return { contents: await readFile(filePath), mode: metadata.mode };
}

export async function restrictFile(
  filePath: string,
  mode: number,
): Promise<void> {
  if (process.platform !== "win32") {
    await chmod(filePath, mode);
  }
}

export function isMissing(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as NodeJS.ErrnoException).code === "ENOENT"
  );
}

export type IntegrationFileState =
  | "absent"
  | "installed"
  | "mismatch"
  | "conflict";

export interface IntegrationFileInspection {
  readonly state: IntegrationFileState;
  readonly detail: string;
}

export async function inspectDedicatedFile(
  filePath: string,
  expected: Buffer,
): Promise<IntegrationFileInspection> {
  let current;
  try {
    current = await readOptionalRegularFile(filePath, "Dedicated integration file");
  } catch (error) {
    return {
      state: "conflict",
      detail: error instanceof Error ? error.message : String(error),
    };
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

export async function writeDedicatedFile(
  filePath: string,
  contents: Buffer,
  mode: number,
): Promise<void> {
  const directory = path.dirname(filePath);
  await ensurePrivateDirectory(directory, false);
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
