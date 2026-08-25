import { mkdir, realpath } from "node:fs/promises";
import * as path from "node:path";

import { lock } from "proper-lockfile";

export async function withSharedFileLock<T>(
  filePath: string,
  label: string,
  operation: () => Promise<T>,
  options: { readonly retries?: number } = {},
): Promise<T> {
  const directory = path.dirname(filePath);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const lockTarget = path.join(
    await realpath(directory),
    path.basename(filePath),
  );

  let release: () => Promise<void>;
  try {
    release = await lock(lockTarget, {
      realpath: false,
      retries: options.retries ?? 3,
    });
  } catch (error) {
    if (
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      (error as NodeJS.ErrnoException).code === "ELOCKED"
    ) {
      throw new Error(`${label} is busy in another Kiro window. Try again.`);
    }
    throw error;
  }

  try {
    return await operation();
  } finally {
    await release();
  }
}
