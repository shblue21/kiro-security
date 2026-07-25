import { randomUUID } from "node:crypto";
import {
  access,
  chmod,
  cp,
  mkdir,
  mkdtemp,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import * as path from "node:path";

import { buildPowerMcpConfiguration } from "./powerIntegrationConfig";

export interface MaterializePowerInput {
  readonly extensionRoot: string;
  readonly integrationRoot: string;
  readonly pythonExecutable: string;
  readonly stateRoot: string;
  readonly scanRoot: string;
}

export async function materializePowerIntegration(
  input: MaterializePowerInput,
): Promise<string> {
  const sourcePower = path.join(
    input.extensionRoot,
    "powers",
    "kiro-security-power",
  );
  const sourceEngine = path.join(
    input.extensionRoot,
    "engine",
    "kiro_security",
  );
  const powerRoot = path.join(input.integrationRoot, "kiro-security-power");
  const stagingRoot = await createStagingDirectory(input.integrationRoot);
  const runtimeEngineRoot = path.join(stagingRoot, "runtime", "engine");

  try {
    await cp(
      path.join(sourcePower, "POWER.md"),
      path.join(stagingRoot, "POWER.md"),
      {
        force: false,
        errorOnExist: true,
      },
    );
    await cp(
      path.join(sourcePower, "mcp.json"),
      path.join(stagingRoot, "mcp.json"),
      {
        force: false,
        errorOnExist: true,
      },
    );
    await mkdir(runtimeEngineRoot, { recursive: true, mode: 0o700 });
    await cp(sourceEngine, path.join(runtimeEngineRoot, "kiro_security"), {
      recursive: true,
      force: false,
      filter: (source) =>
        path.basename(source) !== "__pycache__" && !source.endsWith(".pyc"),
    });

    const mcpConfiguration = buildPowerMcpConfiguration({
      pythonExecutable: input.pythonExecutable,
      engineRoot: path.join(powerRoot, "runtime", "engine"),
      stateRoot: input.stateRoot,
      scanRoot: input.scanRoot,
    });
    const mcpPath = path.join(stagingRoot, "mcp.json");
    await writeFile(
      mcpPath,
      `${JSON.stringify(mcpConfiguration, null, 2)}\n`,
      { encoding: "utf8", mode: 0o600 },
    );
    await restrictPreparedTree(stagingRoot);
    await replaceDirectory(stagingRoot, powerRoot);
  } catch (error) {
    await rm(stagingRoot, { force: true, recursive: true });
    throw error;
  }
  return powerRoot;
}

async function createStagingDirectory(parent: string): Promise<string> {
  await mkdir(parent, { recursive: true, mode: 0o700 });
  return mkdtemp(path.join(parent, ".power-staging-"));
}

async function replaceDirectory(
  source: string,
  destination: string,
): Promise<void> {
  const backup = `${destination}.backup-${randomUUID()}`;
  const destinationExists = await exists(destination);
  if (destinationExists) {
    await rename(destination, backup);
  }
  try {
    await rename(source, destination);
  } catch (error) {
    if (destinationExists) {
      await rename(backup, destination);
    }
    throw error;
  }
  if (destinationExists) {
    await rm(backup, { force: true, recursive: true });
  }
}

async function restrictPreparedTree(root: string): Promise<void> {
  if (process.platform === "win32") {
    return;
  }
  await chmod(root, 0o700);
  await chmod(path.join(root, "mcp.json"), 0o600);
}

async function exists(candidate: string): Promise<boolean> {
  try {
    await access(candidate);
    return true;
  } catch {
    return false;
  }
}
