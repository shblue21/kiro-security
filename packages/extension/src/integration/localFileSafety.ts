import {
  chmod,
  lstat,
  mkdir,
  readFile,
} from "node:fs/promises";

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
