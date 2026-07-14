import { spawn } from "node:child_process";
import * as path from "node:path";

export const MINIMUM_PYTHON = "3.10.0";

export interface PythonInvocation {
  executable: string;
  args: string[];
}

export interface PythonRuntimeProbe {
  available: boolean;
  supported: boolean;
  executable: string;
  version?: string;
  versionTuple?: [number, number, number];
  sqliteVersion?: string;
  source?: "configured" | "environment" | "path" | "common_location";
  error?: string;
}

const PROBE_CODE = [
  "import json, sqlite3, sys",
  "print(json.dumps({",
  "  'executable': sys.executable,",
  "  'version': '.'.join(str(x) for x in sys.version_info[:3]),",
  "  'versionTuple': list(sys.version_info[:3]),",
  "  'sqliteVersion': sqlite3.sqlite_version,",
  "}))",
].join("\n");

function uniqueInvocations(invocations: Array<PythonInvocation & { source: PythonRuntimeProbe["source"] }>): Array<PythonInvocation & { source: PythonRuntimeProbe["source"] }> {
  const seen = new Set<string>();
  return invocations.filter((candidate) => {
    const key = `${candidate.executable}\0${candidate.args.join("\0")}`;
    if (!candidate.executable || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function pythonCandidates(configuredExecutable: string, configuredArgs: string[] = []): Array<PythonInvocation & { source: PythonRuntimeProbe["source"] }> {
  const candidates: Array<PythonInvocation & { source: PythonRuntimeProbe["source"] }> = [];
  if (configuredExecutable) candidates.push({ executable: configuredExecutable, args: configuredArgs, source: "configured" });
  if (process.env.KIRO_SECURITY_PYTHON) candidates.push({ executable: process.env.KIRO_SECURITY_PYTHON, args: [], source: "environment" });
  candidates.push({ executable: "python3", args: [], source: "path" }, { executable: "python", args: [], source: "path" });

  if (process.platform === "darwin") {
    for (const prefix of ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"]) {
      for (const name of ["python3.13", "python3.12", "python3.11", "python3.10", "python3.9", "python3"]) {
        candidates.push({ executable: path.join(prefix, name), args: [], source: "common_location" });
      }
    }
  } else if (process.platform === "win32") {
    candidates.push({ executable: "py", args: ["-3"], source: "path" });
    const local = process.env.LOCALAPPDATA;
    if (local) {
      for (const version of ["313", "312", "311", "310", "39"]) {
        candidates.push({ executable: path.join(local, "Programs", "Python", `Python${version}`, "python.exe"), args: [], source: "common_location" });
      }
    }
  } else {
    for (const name of ["python3.13", "python3.12", "python3.11", "python3.10", "python3.9"]) {
      candidates.push({ executable: name, args: [], source: "path" });
    }
  }
  return uniqueInvocations(candidates);
}

function supported(tuple: [number, number, number]): boolean {
  return tuple[0] > 3 || (tuple[0] === 3 && tuple[1] >= 9);
}

export async function probePythonRuntime(
  invocation: PythonInvocation,
  source: PythonRuntimeProbe["source"] = "configured",
  timeoutMs = 6_000,
): Promise<PythonRuntimeProbe> {
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let settled = false;
    let timer: NodeJS.Timeout | undefined;
    const finish = (result: PythonRuntimeProbe): void => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve(result);
    };

    let child;
    try {
      child = spawn(invocation.executable, [...invocation.args, "-c", PROBE_CODE], {
        shell: false,
        windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"],
        env: minimalProcessEnvironment(),
      });
    } catch (error) {
      finish({ available: false, supported: false, executable: invocation.executable, source, error: String(error) });
      return;
    }

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
      if (stdout.length > 64 * 1024) child.kill();
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
      if (stderr.length > 64 * 1024) child.kill();
    });
    child.once("error", (error) => finish({ available: false, supported: false, executable: invocation.executable, source, error: error.message }));
    child.once("exit", (code) => {
      if (code !== 0) {
        finish({
          available: false,
          supported: false,
          executable: invocation.executable,
          source,
          error: stderr.trim() || `Python probe exited with code ${code ?? "unknown"}.`,
        });
        return;
      }
      try {
        const parsed = JSON.parse(stdout.trim()) as { executable?: unknown; version?: unknown; versionTuple?: unknown; sqliteVersion?: unknown };
        const tuple = Array.isArray(parsed.versionTuple) && parsed.versionTuple.length >= 3
          ? parsed.versionTuple.slice(0, 3).map((value) => Number(value))
          : undefined;
        if (!tuple || tuple.some((value) => !Number.isInteger(value))) throw new Error("Python probe returned an invalid version tuple.");
        const versionTuple: [number, number, number] = [tuple[0], tuple[1], tuple[2]];
        const isSupported = supported(versionTuple);
        finish({
          available: true,
          supported: isSupported,
          executable: typeof parsed.executable === "string" && parsed.executable ? parsed.executable : invocation.executable,
          version: typeof parsed.version === "string" ? parsed.version : versionTuple.join("."),
          versionTuple,
          sqliteVersion: typeof parsed.sqliteVersion === "string" ? parsed.sqliteVersion : undefined,
          source,
          error: isSupported ? undefined : `Python ${MINIMUM_PYTHON} or newer is required; detected ${versionTuple.join(".")}.`,
        });
      } catch (error) {
        finish({ available: false, supported: false, executable: invocation.executable, source, error: error instanceof Error ? error.message : String(error) });
      }
    });

    timer = setTimeout(() => {
      child.kill();
      finish({ available: false, supported: false, executable: invocation.executable, source, error: "Python probe timed out." });
    }, timeoutMs);
  });
}

export async function resolvePythonRuntime(
  configuredExecutable: string,
  configuredArgs: string[] = [],
): Promise<{ invocation: PythonInvocation; probe: PythonRuntimeProbe; attempts: PythonRuntimeProbe[] }> {
  const attempts: PythonRuntimeProbe[] = [];
  let firstAvailable: PythonRuntimeProbe | undefined;
  for (const candidate of pythonCandidates(configuredExecutable, configuredArgs)) {
    const probe = await probePythonRuntime(candidate, candidate.source);
    attempts.push(probe);
    if (probe.available) firstAvailable ??= probe;
    if (probe.available && probe.supported) {
      return { invocation: { executable: probe.executable, args: [] }, probe, attempts };
    }
  }
  const failed = firstAvailable ?? attempts[0] ?? {
    available: false,
    supported: false,
    executable: configuredExecutable || "python3",
    source: "configured" as const,
    error: "No supported Python runtime was found.",
  };
  return { invocation: { executable: configuredExecutable || "python3", args: configuredArgs }, probe: failed, attempts };
}

export function minimalProcessEnvironment(extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const key of ["PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL", "PATHEXT", "COMSPEC"]) {
    if (process.env[key] !== undefined) env[key] = process.env[key];
  }
  env.LANG ??= "C.UTF-8";
  env.LC_ALL ??= "C.UTF-8";
  return { ...env, ...extra };
}
