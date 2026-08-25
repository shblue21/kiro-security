import { rm } from "node:fs/promises";

import { getHookRegistrationPath } from "./integration/chatBindingFiles";
import {
  getUserMcpConfigPath,
  getUserSteeringPath,
  removeManagedMcpRegistrations,
} from "./integration/integrationFiles";

async function main(): Promise<void> {
  const results = await Promise.allSettled([
    removeManagedMcpRegistrations({ mcpPath: getUserMcpConfigPath() }),
    rm(getHookRegistrationPath(), { force: true }),
    rm(getUserSteeringPath(), { force: true }),
  ]);
  const failures = results.filter(
    (result): result is PromiseRejectedResult => result.status === "rejected",
  );
  for (const failure of failures) {
    process.stderr.write(`Kiro Security uninstall: ${String(failure.reason)}\n`);
  }
  if (failures.length > 0) process.exitCode = 1;
}

void main().catch((error: unknown) => {
  process.stderr.write(`Kiro Security uninstall: ${String(error)}\n`);
  process.exitCode = 1;
});
