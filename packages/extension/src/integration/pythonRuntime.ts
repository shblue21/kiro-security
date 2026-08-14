import { execFile } from "node:child_process";
import * as path from "node:path";
import { promisify } from "node:util";

import * as vscode from "vscode";

const executeFile = promisify(execFile);

export async function resolvePythonExecutable(): Promise<string> {
  const configured = vscode.workspace
    .getConfiguration("kiroSecurity")
    .get<string>("pythonPath", "")
    .trim();
  const candidates = [
    configured,
    process.platform === "win32" ? "python" : "python3",
    "python",
  ].filter((value, index, all) => value && all.indexOf(value) === index);

  for (const candidate of candidates) {
    try {
      const { stdout } = await executeFile(
        candidate,
        [
          "-B",
          "-c",
          "import json,sys; print(json.dumps({'executable':sys.executable,'ok':sys.version_info >= (3,9)}))",
        ],
        {
          encoding: "utf8",
          maxBuffer: 64 * 1024,
          timeout: 10_000,
          windowsHide: true,
        },
      );
      const inspected = JSON.parse(stdout.trim()) as {
        executable?: unknown;
        ok?: unknown;
      };
      if (
        inspected.ok === true &&
        typeof inspected.executable === "string" &&
        path.isAbsolute(inspected.executable)
      ) {
        return inspected.executable;
      }
    } catch {
      // Try the next configured or platform-default executable.
    }
  }
  throw new Error(
    "Python 3.9 or newer was not found. Configure kiroSecurity.pythonPath and retry.",
  );
}
