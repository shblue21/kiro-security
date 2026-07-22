import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { applyEdits, modify, parse, printParseErrorCode, type ParseError } from "jsonc-parser";
import type {
  AgentAutoApprovePolicy,
  AgentIntegrationScope,
  AgentIntegrationStatus,
  RuntimeDependencyStatus,
} from "../../protocol/src";
import { minimalProcessEnvironment, resolvePythonRuntime, type PythonInvocation, type PythonRuntimeProbe } from "./pythonRuntime";

export const AGENT_MCP_SERVER_NAME = "kiro-security-power";
export const POWER_MCP_SERVER_NAME = "kiro-security-power-runtime";
export const MANAGED_STEERING_MARKER = "<!-- managed-by: kiro-security-power-vsix -->";
const MAX_CONFIG_BYTES = 2 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
const READ_ONLY_TOOLS = [
  "security_get_capabilities",
  "security_get_scan",
  "security_get_progress",
  "security_get_scan_context",
  "security_list_findings",
  "security_get_finding",
] as const;
const REQUIRED_TOOLS = [
  "security_get_capabilities",
  "security_start_scan",
  "security_acquire_scan_coordinator",
  "security_renew_scan_coordinator",
  "security_release_scan_coordinator",
  "security_cancel_scan",
  "security_get_scan",
  "security_get_progress",
  "security_get_scan_context",
  "security_update_scan_progress",
  "security_complete_scan",
  "security_fail_scan",
  "security_list_findings",
  "security_get_finding",
  "security_triage_finding",
  "security_create_remediation",
  "security_prepare_remediation_patch",
  "security_apply_remediation_patch",
  "security_verify_remediation_patch",
  "security_create_triage_intake",
  "security_submit_triage_assessment",
  "security_create_tracking_handoff",
  "security_record_tracking_result",
  "security_export_report",
] as const;

interface McpServerConfig {
  command: string;
  args: string[];
  env: Record<string, string>;
  disabled: boolean;
  autoApprove?: string[];
  disabledTools?: string[];
}

interface CapturedFile {
  existed: boolean;
  bytes?: Buffer;
  mode?: number;
}

interface TrustedPayloadEntry {
  source: string;
  destinationRelative: string;
}

interface ConfigInspection {
  path: string;
  scope?: AgentIntegrationScope;
  direct?: McpServerConfig;
  powerManaged?: McpServerConfig;
  parseError?: string;
}

interface IntegrationState {
  schemaVersion: 1;
  productVersion: string;
  verifiedAt?: string;
  configPath?: string;
  configDigest?: string;
  steeringPath?: string;
  powerConfigDigest?: string;
  powerVerifiedAt?: string;
  autoApprovePolicy?: AgentAutoApprovePolicy;
}

export interface AgentIntegrationOptions {
  extensionRoot: string;
  workspaceRoot?: string;
  globalStorageRoot: string;
  productVersion: string;
  homeDirectory?: string;
  logger?: { log(level: "debug" | "info" | "warning" | "error", message: string, fields?: Record<string, unknown>): void };
}

export interface AgentIntegrationInstallOptions {
  pythonPath: string;
  scope: AgentIntegrationScope;
  autoApprovePolicy: AgentAutoApprovePolicy;
}

export interface AgentIntegrationInstallResult {
  configPath: string;
  steeringPath: string;
  powerPath: string;
  backupPaths: string[];
  pythonExecutable: string;
  pythonVersion: string;
  sqliteVersion?: string;
  toolCount: number;
  verifiedAt: string;
}

export interface AgentIntegrationVerifyResult {
  serverVersion: string;
  engineVersion: string;
  toolCount: number;
  verifiedAt: string;
  configPath?: string;
  powerPath: string;
}

export interface AgentIntegrationRemovalResult {
  removedConfigPaths: string[];
  removedSteeringPaths: string[];
  skippedUnmanagedConfigPaths: string[];
  backupPaths: string[];
}

type ResolvedPythonRuntime = Awaited<ReturnType<typeof resolvePythonRuntime>>;

export class AgentIntegrationError extends Error {
  constructor(readonly code: string, message: string, readonly details: Record<string, unknown> = {}) {
    super(message);
    this.name = "AgentIntegrationError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseServer(value: unknown): McpServerConfig | undefined {
  if (!isRecord(value) || typeof value.command !== "string" || !Array.isArray(value.args) || !value.args.every((entry) => typeof entry === "string")) return undefined;
  const env: Record<string, string> = {};
  if (isRecord(value.env)) for (const [key, entry] of Object.entries(value.env)) if (typeof entry === "string") env[key] = entry;
  return {
    command: value.command,
    args: [...value.args] as string[],
    env,
    disabled: value.disabled === true,
    autoApprove: Array.isArray(value.autoApprove) && value.autoApprove.every((entry) => typeof entry === "string") ? [...value.autoApprove] as string[] : undefined,
    disabledTools: Array.isArray(value.disabledTools) && value.disabledTools.every((entry) => typeof entry === "string") ? [...value.disabledTools] as string[] : undefined,
  };
}

function formatting(text: string): { insertSpaces: boolean; tabSize: number; eol: string } {
  const eol = text.includes("\r\n") ? "\r\n" : "\n";
  const indent = /(?:^|\r?\n)([ \t]+)"/.exec(text)?.[1] ?? "  ";
  return indent.includes("\t") ? { insertSpaces: false, tabSize: 1, eol } : { insertSpaces: true, tabSize: Math.max(1, indent.length), eol };
}

function describeParseError(text: string, errors: ParseError[]): string {
  const first = errors[0];
  if (!first) return "Invalid JSON/JSONC.";
  const before = text.slice(0, first.offset);
  const line = before.split(/\r?\n/).length;
  const column = first.offset - Math.max(before.lastIndexOf("\n"), before.lastIndexOf("\r"));
  return `${printParseErrorCode(first.error)} at line ${line}, column ${column}.`;
}

function parseConfig(text: string, filePath: string): Record<string, unknown> {
  const source = text.trim() ? text : "{}\n";
  const errors: ParseError[] = [];
  const value = parse(source, errors, { allowTrailingComma: true, disallowComments: false });
  if (errors.length) throw new AgentIntegrationError("mcp_config_invalid", `MCP configuration is not valid JSON/JSONC: ${describeParseError(source, errors)}`, { path: filePath });
  if (!isRecord(value)) throw new AgentIntegrationError("mcp_config_root", "MCP configuration root must be a JSON object.", { path: filePath });
  if (value.mcpServers !== undefined && !isRecord(value.mcpServers)) throw new AgentIntegrationError("mcp_servers_root", "mcpServers must be a JSON object.", { path: filePath });
  return value;
}

export function mergeMcpServerConfigText(text: string, filePath: string, name: string, entry: McpServerConfig): string {
  const source = text.trim() ? text : "{}\n";
  parseConfig(source, filePath);
  const options = formatting(source);
  let output = applyEdits(source, modify(source, ["mcpServers", name], entry, { formattingOptions: options }));
  if (!output.endsWith("\n")) output += options.eol;
  parseConfig(output, filePath);
  return output;
}

export function removeMcpServerConfigText(text: string, filePath: string, name: string): string {
  const source = text.trim() ? text : "{}\n";
  const parsed = parseConfig(source, filePath);
  if (!isRecord(parsed.mcpServers) || !(name in parsed.mcpServers)) return source;
  const options = formatting(source);
  let output = applyEdits(source, modify(source, ["mcpServers", name], undefined, { formattingOptions: options }));
  if (!output.endsWith("\n")) output += options.eol;
  parseConfig(output, filePath);
  return output;
}

export function buildAgentSteering(version: string): string {
  return `---
inclusion: auto
name: kiro-security-power
description: Use Kiro Security Power for Skill-driven repository, deep, or Git-diff security scans, triage, remediation, tracking, and exports.
---
${MANAGED_STEERING_MARKER}

# Kiro Security Power

Use the MCP server named \`${AGENT_MCP_SERVER_NAME}\` for repository security work. The MCP tools and the installed VSIX share the same durable SQLite workbench at \`<workspace>/.kiro/security-power/workbench.sqlite\`.

This auto steering is only an activation and safety bridge; it is not the scan methodology. MCP availability alone does not make scans ready. Do not start Standard, Diff, or Deep unless Kiro has activated the installed native Power and the current context contains its \`POWER.md\` plus the selected mode steering. If those instructions are absent, stop before \`security_start_scan\` and tell the user to import the prepared folder from Powers → Add Custom Power → Import power from a folder.

## Workflow

1. Pass the canonical current workspace as \`workspaceRoot\` to every security tool.
2. Call \`security_get_capabilities\` before substantive work.
3. Generate one opaque \`taskId\` for the current Kiro task and use it on every \`security_start_scan\` call in that task. Omit \`sessionId\` to create a new logical workspace; reuse the returned \`sessionId\` only to rerun that immutable setup. Start Standard, Diff, and Deep only with \`security_start_scan\`; every mode is owned by its mode-specific Power workflow. Keep the one-time coordinator lease token only in the top-level coordinator context and never pass it to a subagent or artifact.
4. A scan returned with a busy lease is read-only. Acquire an available or expired lease through \`security_acquire_scan_coordinator\`, renew it at phase boundaries through \`security_renew_scan_coordinator\`, and release unfinished work through \`security_release_scan_coordinator\`. Engine shutdown never changes scan status.
5. Load \`security_get_scan_context\`, then follow the mode-specific Power steering one phase at a time. The coordinator owns native \`invoke_sub_agent\` calls, phase barriers, semantic merge, novelty, validation, attack paths, writeups, hardening, and canonical assembly. The Engine owns no worker jobs or next-action plan. Do not substitute another analysis path if delegation is unavailable.
6. Use \`security_update_scan_progress\` only for user-visible progress and always provide the current lease token and generation. After fixed canonical artifacts are complete, call \`security_complete_scan\` once with that credential. Use \`security_fail_scan\` for explicit failure and \`security_cancel_scan\` for cooperative cancellation; both require and atomically release the lease.
7. Read evidence with \`security_list_findings\` and \`security_get_finding\`.
8. Validation, attack-path evidence, writeups, and collection hardening are Agent-authored phase artifacts sealed by canonical completion.
9. Record user-directed triage through \`security_triage_finding\`; never silently suppress a finding.
10. Use remediation, tracking-handoff, and export tools only after reading the sealed canonical finding.
11. Do not create a second scanner, database, or fixture-backed result path.

## Safety

- Ask before expensive deep scans, material triage changes, or exports outside the workspace.
- Never claim that an external issue or code fix was created when only a handoff or recommendation exists.
- Kiro Security Power is not an official OpenAI, Codex, or Kiro product.

Managed integration version: ${version}
`;
}

function buildServerConfig(
  invocation: PythonInvocation,
  pythonPath: string,
  engineRoot: string,
  workspaceRoot: string | undefined,
  policy: AgentAutoApprovePolicy,
): McpServerConfig {
  const env: Record<string, string> = {
    PYTHONPATH: engineRoot,
    PYTHONIOENCODING: "utf-8",
    PYTHONUNBUFFERED: "1",
    KIRO_SECURITY_PYTHON: pythonPath,
  };
  if (workspaceRoot) env.KIRO_SECURITY_WORKSPACE = workspaceRoot;
  const config: McpServerConfig = {
    command: invocation.executable,
    args: [...invocation.args, "-B", "-S", "-m", "kiro_security.mcp_server"],
    env,
    disabled: false,
  };
  if (policy === "read_only") config.autoApprove = [...READ_ONLY_TOOLS];
  return config;
}

function configDigest(config: McpServerConfig): string {
  return createHash("sha256").update(JSON.stringify(config)).digest("hex");
}

function approvalPolicyFor(config: McpServerConfig): AgentAutoApprovePolicy {
  return (config.autoApprove ?? []).length ? "read_only" : "none";
}

function approvalListMatches(config: McpServerConfig, policy: AgentAutoApprovePolicy): boolean {
  const actual = config.autoApprove ?? [];
  const expected = policy === "read_only" ? [...READ_ONLY_TOOLS] : [];
  return actual.length === expected.length && actual.every((value, index) => value === expected[index]);
}

function normalizedRelative(value: string): string {
  return value.split(path.sep).join("/");
}

async function collectTrustedPayloadTree(
  source: string,
  destinationPrefix: string,
  extensionRoot: string,
  allow: (relative: string) => boolean,
  prefix = "",
): Promise<TrustedPayloadEntry[]> {
  const trustedRoot = await fs.realpath(extensionRoot);
  const sourceRoot = await fs.realpath(source);
  const sourceRelative = path.relative(trustedRoot, sourceRoot);
  if (sourceRelative.startsWith("..") || path.isAbsolute(sourceRelative)) {
    throw new AgentIntegrationError("source_escape", "Packaged Agent source escapes the extension root.", { source });
  }
  const sourceInfo = await fs.lstat(sourceRoot);
  if (!sourceInfo.isDirectory() || sourceInfo.isSymbolicLink()) {
    throw new AgentIntegrationError("source_not_directory", "Packaged Agent source must be a regular directory.", { source });
  }
  const result: TrustedPayloadEntry[] = [];
  for (const entry of await fs.readdir(sourceRoot, { withFileTypes: true })) {
    if (entry.name === "__pycache__" || entry.name.startsWith(".")) continue;
    const relative = prefix ? path.join(prefix, entry.name) : entry.name;
    const from = path.join(sourceRoot, entry.name);
    const info = await fs.lstat(from);
    if (info.isSymbolicLink()) {
      throw new AgentIntegrationError("source_symlink", "Packaged Power contains an unsupported symbolic link.", { source: from });
    }
    if (entry.isDirectory()) {
      result.push(...await collectTrustedPayloadTree(from, destinationPrefix, extensionRoot, allow, relative));
    } else if (entry.isFile() && allow(relative)) {
      result.push({ source: from, destinationRelative: path.join(destinationPrefix, relative) });
    }
  }
  return result;
}

async function listPreparedFiles(root: string, prefix = ""): Promise<string[]> {
  const info = await fs.lstat(root);
  if (info.isSymbolicLink()) {
    throw new AgentIntegrationError("prepared_symlink", "Prepared Agent runtime contains an unsupported symbolic link.", { path: root });
  }
  if (!info.isDirectory()) {
    throw new AgentIntegrationError("prepared_not_directory", "Prepared Agent runtime root is not a directory.", { path: root });
  }
  const result: string[] = [];
  for (const entry of await fs.readdir(root, { withFileTypes: true })) {
    const relative = prefix ? path.join(prefix, entry.name) : entry.name;
    const fullPath = path.join(root, entry.name);
    const childInfo = await fs.lstat(fullPath);
    if (childInfo.isSymbolicLink()) {
      throw new AgentIntegrationError("prepared_symlink", "Prepared Agent runtime contains an unsupported symbolic link.", { path: fullPath });
    }
    if (entry.isDirectory()) result.push(...await listPreparedFiles(fullPath, relative));
    else if (entry.isFile()) result.push(relative);
    else throw new AgentIntegrationError("prepared_special_file", "Prepared Agent runtime contains an unsupported special file.", { path: fullPath });
  }
  return result;
}

async function capture(filePath: string): Promise<CapturedFile> {
  try {
    const info = await fs.lstat(filePath);
    if (info.isSymbolicLink()) throw new AgentIntegrationError("symlink_rejected", "Refusing to modify a symbolic-link integration file.", { path: filePath });
    if (!info.isFile()) throw new AgentIntegrationError("not_regular_file", "Integration target is not a regular file.", { path: filePath });
    if (info.size > MAX_CONFIG_BYTES) throw new AgentIntegrationError("file_too_large", "Integration target exceeds the 2 MiB safety limit.", { path: filePath });
    return { existed: true, bytes: await fs.readFile(filePath), mode: info.mode & 0o777 };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { existed: false };
    throw error;
  }
}

async function atomicWrite(filePath: string, data: Buffer | string, mode = 0o600): Promise<void> {
  await fs.mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const temporary = path.join(path.dirname(filePath), `.${path.basename(filePath)}.${process.pid}.${randomUUID()}.tmp`);
  const handle = await fs.open(temporary, "wx", mode);
  try {
    await handle.writeFile(data);
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await fs.rename(temporary, filePath);
  } catch (error) {
    if (process.platform !== "win32") {
      await fs.rm(temporary, { force: true });
      throw error;
    }
    try {
      const existing = await fs.lstat(filePath);
      if (existing.isSymbolicLink()) throw new AgentIntegrationError("symlink_race", "Refusing to replace a symbolic-link integration file.", { path: filePath });
      await fs.rm(filePath, { force: true });
      await fs.rename(temporary, filePath);
    } catch (replacementError) {
      await fs.rm(temporary, { force: true });
      throw replacementError;
    }
  }
}

async function restore(filePath: string, previous: CapturedFile): Promise<void> {
  if (!previous.existed) {
    await fs.rm(filePath, { force: true });
    return;
  }
  await atomicWrite(filePath, previous.bytes ?? Buffer.alloc(0), previous.mode ?? 0o600);
}

async function ensureNoSymlinkComponents(targetPath: string, boundaryPath: string): Promise<void> {
  const boundary = path.resolve(boundaryPath);
  const target = path.resolve(targetPath);
  const relative = path.relative(boundary, target);
  if (relative.startsWith("..") || path.isAbsolute(relative)) throw new AgentIntegrationError("path_escape", "Agent integration path escapes its allowed boundary.", { target, boundary });
  try {
    const boundaryInfo = await fs.lstat(boundary);
    if (boundaryInfo.isSymbolicLink()) throw new AgentIntegrationError("symlink_rejected", "Refusing to install Agent integration through a symbolic-link boundary.", { path: boundary });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  let current = boundary;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    try {
      const info = await fs.lstat(current);
      if (info.isSymbolicLink()) throw new AgentIntegrationError("symlink_rejected", "Refusing to traverse a symbolic link while installing Agent integration.", { path: current });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") break;
      throw error;
    }
  }
}

async function copyTrustedFile(source: string, destination: string, extensionRoot: string): Promise<void> {
  const trustedRoot = await fs.realpath(extensionRoot);
  const resolved = await fs.realpath(source);
  const relative = path.relative(trustedRoot, resolved);
  if (relative.startsWith("..") || path.isAbsolute(relative)) throw new AgentIntegrationError("source_escape", "Packaged Agent source escapes the extension root.", { source });
  const info = await fs.lstat(resolved);
  if (!info.isFile() || info.isSymbolicLink()) throw new AgentIntegrationError("source_not_regular", "Packaged Agent source must be a regular file.", { source });
  await fs.mkdir(path.dirname(destination), { recursive: true, mode: 0o700 });
  await fs.copyFile(resolved, destination);
  await fs.chmod(destination, 0o600).catch(() => undefined);
}

async function copyTrustedTree(source: string, destination: string, extensionRoot: string, allow: (relative: string) => boolean, prefix = ""): Promise<void> {
  for (const entry of await fs.readdir(source, { withFileTypes: true })) {
    if (entry.name === "__pycache__" || entry.name.startsWith(".")) continue;
    const relative = prefix ? path.join(prefix, entry.name) : entry.name;
    const from = path.join(source, entry.name);
    const to = path.join(destination, entry.name);
    const info = await fs.lstat(from);
    if (info.isSymbolicLink()) throw new AgentIntegrationError("source_symlink", "Packaged Power contains an unsupported symbolic link.", { source: from });
    if (entry.isDirectory()) await copyTrustedTree(from, to, extensionRoot, allow, relative);
    else if (entry.isFile() && allow(relative)) await copyTrustedFile(from, to, extensionRoot);
  }
}

class LineRpcClient {
  private nextId = 1;
  private buffer = "";
  private stderr = "";
  private stopPromise: Promise<void> | undefined;
  private exited = false;
  private readonly exitPromise: Promise<void>;
  private readonly pending = new Map<number, { resolve(value: Record<string, unknown>): void; reject(error: Error): void; timer: NodeJS.Timeout }>();

  constructor(private readonly child: ChildProcessWithoutNullStreams) {
    let resolveExit: (() => void) | undefined;
    this.exitPromise = new Promise<void>((resolve) => { resolveExit = resolve; });
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => this.consume(chunk));
    child.stderr.on("data", (chunk: string) => { this.stderr = `${this.stderr}${chunk}`.slice(-32_768); });
    child.on("error", (error) => this.fail(error));
    child.on("exit", (code, signal) => {
      this.exited = true;
      resolveExit?.();
      this.fail(new Error(`MCP server exited with code ${code ?? "unknown"} (${signal ?? "no signal"}). ${this.stderr}`.trim()));
    });
  }

  private consume(chunk: string): void {
    this.buffer += chunk;
    if (Buffer.byteLength(this.buffer, "utf8") > MAX_RESPONSE_BYTES) {
      this.fail(new Error("MCP verification output exceeded the 4 MiB safety limit."));
      this.child.kill();
      return;
    }
    for (;;) {
      const index = this.buffer.indexOf("\n");
      if (index < 0) return;
      const line = this.buffer.slice(0, index).trim();
      this.buffer = this.buffer.slice(index + 1);
      if (!line) continue;
      try {
        const message = JSON.parse(line) as Record<string, unknown>;
        if (message.jsonrpc !== "2.0" || typeof message.id !== "number") continue;
        const pending = this.pending.get(message.id);
        if (!pending) continue;
        clearTimeout(pending.timer);
        this.pending.delete(message.id);
        if (isRecord(message.error)) pending.reject(new Error(String(message.error.message ?? "MCP error")));
        else pending.resolve(message);
      } catch {
        // Ignore non-protocol diagnostics and rely on the bounded request timeout.
      }
    }
  }

  private fail(error: Error): void {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.pending.clear();
  }

  request(method: string, params: Record<string, unknown>, timeoutMs = 15_000): Promise<Record<string, unknown>> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`MCP verification timed out: ${method}`));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`, (error) => {
        if (!error) return;
        clearTimeout(timer);
        this.pending.delete(id);
        reject(error);
      });
    });
  }

  notify(method: string): void {
    if (this.child.stdin.writable) this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method, params: {} })}\n`);
  }

  async stop(): Promise<void> {
    if (!this.stopPromise) this.stopPromise = this.stopInternal();
    return this.stopPromise;
  }

  private async stopInternal(): Promise<void> {
    const child = this.child;
    this.fail(new Error("MCP verification client stopped."));
    try {
      if (child.exitCode === null && child.signalCode === null && !child.stdin.destroyed) {
        child.stdin.end();
      }
      if (!await this.waitForExit(2_500)) {
        child.kill("SIGTERM");
        if (!await this.waitForExit(2_500)) {
          if (process.platform !== "win32") child.kill("SIGKILL");
          else child.kill();
          if (!await this.waitForExit(1_500)) {
            throw new AgentIntegrationError(
              "mcp_shutdown_timeout",
              "The temporary MCP verification process did not exit after forced shutdown.",
              { pid: child.pid },
            );
          }
        }
      }
    } finally {
      child.stdin.destroy();
      child.stdout.destroy();
      child.stderr.destroy();
      child.stdout.removeAllListeners();
      child.stderr.removeAllListeners();
      child.removeAllListeners("error");
      child.removeAllListeners("exit");
    }
  }

  private waitForExit(timeoutMs: number): Promise<boolean> {
    if (this.exited || this.child.exitCode !== null || this.child.signalCode !== null) return Promise.resolve(true);
    return new Promise((resolve) => {
      let settled = false;
      const finish = (value: boolean): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(value);
      };
      const timer = setTimeout(() => finish(false), timeoutMs);
      void this.exitPromise.then(() => finish(true));
    });
  }
}

function dependency(probe: PythonRuntimeProbe): RuntimeDependencyStatus {
  return {
    available: probe.available,
    compatible: probe.supported,
    minimumVersion: "3.10.0",
    executable: probe.executable,
    version: probe.version,
    sqliteVersion: probe.sqliteVersion,
    source: probe.source,
    error: probe.error,
  };
}

function sameExecutablePath(left: string, right: string): boolean {
  const normalize = (value: string): string => {
    const resolved = path.resolve(value);
    return process.platform === "win32" ? resolved.toLowerCase() : resolved;
  };
  return normalize(left) === normalize(right);
}

function managedServerShapeIssue(
  config: McpServerConfig,
  expectedEngine: string,
  expectedWorkspace: string | undefined,
  expectedPython?: string,
): string | undefined {
  if (path.resolve(config.env.PYTHONPATH ?? "") !== path.resolve(expectedEngine)) return "runtime path";
  if (config.args.length !== 4
    || config.args[0] !== "-B"
    || config.args[1] !== "-S"
    || config.args[2] !== "-m"
    || config.args[3] !== "kiro_security.mcp_server") return "argument list";
  if (expectedPython && !sameExecutablePath(config.command, expectedPython)) return "Python command";
  const declaredPython = config.env.KIRO_SECURITY_PYTHON;
  if (!declaredPython || !sameExecutablePath(declaredPython, config.command)) return "Python environment";
  const allowedEnvironment = new Set(["PYTHONPATH", "KIRO_SECURITY_WORKSPACE", "PYTHONIOENCODING", "PYTHONUNBUFFERED", "KIRO_SECURITY_PYTHON"]);
  if (Object.keys(config.env).some((key) => !allowedEnvironment.has(key))) return "environment keys";
  const configuredWorkspace = config.env.KIRO_SECURITY_WORKSPACE;
  if (expectedWorkspace) {
    if (!configuredWorkspace || path.resolve(configuredWorkspace) !== path.resolve(expectedWorkspace)) return "workspace binding";
  } else if (configuredWorkspace !== undefined) {
    return "unexpected workspace binding";
  }
  if (config.env.PYTHONIOENCODING !== "utf-8" || config.env.PYTHONUNBUFFERED !== "1") return "Python environment";
  if ((config.autoApprove ?? []).some((name) => !(READ_ONLY_TOOLS as readonly string[]).includes(name))) return "auto-approval list";
  return undefined;
}

export class AgentIntegrationManager {
  private readonly extensionRoot: string;
  private readonly workspaceRoot?: string;
  private readonly globalStorageRoot: string;
  private readonly productVersion: string;
  private readonly home: string;
  private readonly logger?: AgentIntegrationOptions["logger"];
  private runtimeCache: { key: string; expiresAt: number; value: Promise<ResolvedPythonRuntime> } | undefined;

  constructor(options: AgentIntegrationOptions) {
    this.extensionRoot = path.resolve(options.extensionRoot);
    this.workspaceRoot = options.workspaceRoot ? path.resolve(options.workspaceRoot) : undefined;
    this.globalStorageRoot = path.resolve(options.globalStorageRoot);
    this.productVersion = options.productVersion;
    this.home = path.resolve(options.homeDirectory ?? os.homedir());
    this.logger = options.logger;
  }

  get powerPath(): string {
    return path.join(this.globalStorageRoot, "agent-integration", "kiro-security-power");
  }

  get workspaceConfigPath(): string | undefined {
    return this.workspaceRoot ? path.join(this.workspaceRoot, ".kiro", "settings", "mcp.json") : undefined;
  }

  get userConfigPath(): string {
    return path.join(this.home, ".kiro", "settings", "mcp.json");
  }

  steeringPath(scope: AgentIntegrationScope): string {
    if (scope === "workspace") {
      if (!this.workspaceRoot) throw new AgentIntegrationError("workspace_required", "Open a local workspace before installing workspace Agent integration.");
      return path.join(this.workspaceRoot, ".kiro", "steering", "kiro-security-power.md");
    }
    return path.join(this.home, ".kiro", "steering", "kiro-security-power.md");
  }

  private get statePath(): string {
    return path.join(this.globalStorageRoot, "agent-integration", "state.json");
  }

  private get sourcePowerPath(): string {
    return path.join(this.extensionRoot, "powers", "kiro-security-power");
  }

  private configCandidates(): Array<{ path: string; scope?: AgentIntegrationScope }> {
    const result: Array<{ path: string; scope?: AgentIntegrationScope }> = [];
    if (this.workspaceConfigPath) result.push({ path: this.workspaceConfigPath, scope: "workspace" });
    result.push({ path: this.userConfigPath, scope: "user" });
    if (this.workspaceRoot) {
      result.push({ path: path.join(this.workspaceRoot, ".kiro", "mcp.json") });
      result.push({ path: path.join(this.workspaceRoot, ".vscode", "mcp.json") });
    }
    return result;
  }

  private targetConfig(scope: AgentIntegrationScope): string {
    if (scope === "workspace") {
      if (!this.workspaceConfigPath) throw new AgentIntegrationError("workspace_required", "Open a local workspace before installing workspace Agent integration.");
      return this.workspaceConfigPath;
    }
    return this.userConfigPath;
  }

  private resolveRuntime(pythonPath: string): Promise<ResolvedPythonRuntime> {
    const key = pythonPath || "python3";
    const now = Date.now();
    if (this.runtimeCache && this.runtimeCache.key === key && this.runtimeCache.expiresAt > now) return this.runtimeCache.value;
    const value = resolvePythonRuntime(pythonPath);
    this.runtimeCache = { key, expiresAt: now + 30_000, value };
    void value.then((runtime) => {
      if (this.runtimeCache?.value === value && (!runtime.probe.available || !runtime.probe.supported)) {
        this.runtimeCache.expiresAt = Date.now() + 5_000;
      }
    }, () => {
      if (this.runtimeCache?.value === value) this.runtimeCache = undefined;
    });
    return value;
  }

  private async readState(): Promise<IntegrationState | undefined> {
    try {
      const value = JSON.parse(await fs.readFile(this.statePath, "utf8")) as unknown;
      return isRecord(value) && value.schemaVersion === 1 ? value as unknown as IntegrationState : undefined;
    } catch {
      return undefined;
    }
  }

  private async writeState(value: IntegrationState): Promise<void> {
    await atomicWrite(this.statePath, `${JSON.stringify(value, null, 2)}\n`, 0o600);
  }

  private async inspectConfig(candidate: { path: string; scope?: AgentIntegrationScope }): Promise<ConfigInspection> {
    try {
      const captured = await capture(candidate.path);
      if (!captured.existed) return { ...candidate };
      const parsed = parseConfig((captured.bytes ?? Buffer.alloc(0)).toString("utf8"), candidate.path);
      const servers = isRecord(parsed.mcpServers) ? parsed.mcpServers : {};
      const direct = parseServer(servers[AGENT_MCP_SERVER_NAME]);
      let powerManaged: McpServerConfig | undefined;
      for (const [key, value] of Object.entries(servers)) {
        if (key === AGENT_MCP_SERVER_NAME) continue;
        const entry = parseServer(value);
        if (!entry) continue;
        const managedName = key === POWER_MCP_SERVER_NAME
          || key.includes("power-kiro-security-power")
          || key.endsWith(`.${POWER_MCP_SERVER_NAME}`)
          || key.endsWith(`/${POWER_MCP_SERVER_NAME}`);
        if (managedName
          && entry.args.length === 4
          && entry.args[0] === "-B"
          && entry.args[1] === "-S"
          && entry.args[2] === "-m"
          && entry.args[3] === "kiro_security.mcp_server") {
          powerManaged = entry;
          break;
        }
      }
      return { ...candidate, direct, powerManaged };
    } catch (error) {
      return { ...candidate, parseError: error instanceof Error ? error.message : String(error) };
    }
  }

  private async sourcePackaged(): Promise<boolean> {
    try {
      const [power, steering, references] = await Promise.all([
        fs.stat(path.join(this.sourcePowerPath, "POWER.md")),
        fs.stat(path.join(this.sourcePowerPath, "steering")),
        fs.stat(path.join(this.sourcePowerPath, "references")),
      ]);
      return power.isFile() && steering.isDirectory() && references.isDirectory();
    } catch {
      return false;
    }
  }

  private async trustedPayloadEntries(): Promise<TrustedPayloadEntry[]> {
    const entries: TrustedPayloadEntry[] = [
      { source: path.join(this.sourcePowerPath, "POWER.md"), destinationRelative: "POWER.md" },
    ];
    try {
      const notice = path.join(this.sourcePowerPath, "NOTICE.md");
      const info = await fs.lstat(notice);
      if (info.isSymbolicLink() || !info.isFile()) throw new AgentIntegrationError("source_not_regular", "Packaged NOTICE must be a regular file.", { source: notice });
      entries.push({ source: notice, destinationRelative: "NOTICE.md" });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    entries.push(
      ...await collectTrustedPayloadTree(
        path.join(this.sourcePowerPath, "steering"),
        "steering",
        this.extensionRoot,
        (relative) => relative.toLowerCase().endsWith(".md"),
      ),
      ...await collectTrustedPayloadTree(
        path.join(this.sourcePowerPath, "references"),
        "references",
        this.extensionRoot,
        (relative) => relative.toLowerCase().endsWith(".md"),
      ),
      ...await collectTrustedPayloadTree(
        path.join(this.extensionRoot, "engine", "kiro_security"),
        path.join("runtime", "engine", "kiro_security"),
        this.extensionRoot,
        (relative) => relative.endsWith(".py"),
      ),
      ...await collectTrustedPayloadTree(
        path.join(this.extensionRoot, "engine", "migrations"),
        path.join("runtime", "engine", "migrations"),
        this.extensionRoot,
        (relative) => relative.endsWith(".sql"),
      ),
      ...await collectTrustedPayloadTree(
        path.join(this.extensionRoot, "engine", "schemas"),
        path.join("runtime", "engine", "schemas"),
        this.extensionRoot,
        (relative) => relative.endsWith(".json"),
      ),
    );
    return entries.sort((left, right) => normalizedRelative(left.destinationRelative).localeCompare(normalizedRelative(right.destinationRelative)));
  }

  private async verifyPreparedPayload(
    root = this.powerPath,
    expectedPython?: string,
    expectedPolicy?: AgentAutoApprovePolicy,
    expectedEngine = path.join(root, "runtime", "engine"),
  ): Promise<string> {
    const entries = await this.trustedPayloadEntries();
    const allowed = new Set(entries.map((entry) => normalizedRelative(entry.destinationRelative)));
    allowed.add("mcp.json");
    allowed.add("INSTALL.md");
    const actual = (await listPreparedFiles(root)).map(normalizedRelative).sort();
    const unexpected = actual.filter((relative) => !allowed.has(relative));
    const missing = [...allowed].filter((relative) => !actual.includes(relative));
    if (unexpected.length || missing.length) {
      throw new AgentIntegrationError(
        "prepared_payload_mismatch",
        "Prepared Agent runtime does not match the packaged Power payload. Run Repair Agent Integration.",
        { unexpected, missing },
      );
    }
    const digest = createHash("sha256");
    for (const entry of entries) {
      const relative = normalizedRelative(entry.destinationRelative);
      const [sourceInfo, destinationInfo] = await Promise.all([
        fs.lstat(entry.source),
        fs.lstat(path.join(root, entry.destinationRelative)),
      ]);
      if (sourceInfo.isSymbolicLink() || destinationInfo.isSymbolicLink() || !sourceInfo.isFile() || !destinationInfo.isFile()) {
        throw new AgentIntegrationError("prepared_payload_type", "Prepared Agent runtime contains an invalid payload file type.", { relative });
      }
      const [sourceBytes, destinationBytes] = await Promise.all([
        fs.readFile(entry.source),
        fs.readFile(path.join(root, entry.destinationRelative)),
      ]);
      const sourceHash = createHash("sha256").update(sourceBytes).digest("hex");
      const destinationHash = createHash("sha256").update(destinationBytes).digest("hex");
      if (sourceHash !== destinationHash) {
        throw new AgentIntegrationError(
          "prepared_payload_tampered",
          `Prepared Agent runtime file changed after packaging: ${relative}. Run Repair Agent Integration.`,
          { relative },
        );
      }
      digest.update(`${relative}\0${sourceHash}\n`);
    }
    const powerConfigPath = path.join(root, "mcp.json");
    const powerConfigText = await fs.readFile(powerConfigPath, "utf8");
    const powerConfigDocument = parseConfig(powerConfigText, powerConfigPath);
    const servers = isRecord(powerConfigDocument.mcpServers) ? powerConfigDocument.mcpServers : {};
    if (Object.keys(servers).length !== 1 || !(POWER_MCP_SERVER_NAME in servers)) {
      throw new AgentIntegrationError("prepared_mcp_manifest", "Prepared Power mcp.json contains unexpected server entries. Run Repair Agent Integration.");
    }
    const powerServer = parseServer(servers[POWER_MCP_SERVER_NAME]);
    if (!powerServer || powerServer.disabled) {
      throw new AgentIntegrationError("prepared_mcp_manifest", "Prepared Power mcp.json does not contain an enabled managed server. Run Repair Agent Integration.");
    }
    const shapeIssue = managedServerShapeIssue(
      powerServer,
      expectedEngine,
      undefined,
      expectedPython,
    );
    if (shapeIssue) {
      throw new AgentIntegrationError("prepared_mcp_manifest", `Prepared Power mcp.json has an invalid ${shapeIssue}. Run Repair Agent Integration.`);
    }
    if (expectedPolicy && !approvalListMatches(powerServer, expectedPolicy)) {
      throw new AgentIntegrationError("prepared_mcp_manifest", "Prepared Power mcp.json does not match the approved tool policy. Run Repair Agent Integration.");
    }
    digest.update(`mcp.json\0${createHash("sha256").update(powerConfigText).digest("hex")}\n`);
    return digest.digest("hex");
  }

  private async preparedStatus(expectedPython?: string, expectedPolicy?: AgentAutoApprovePolicy): Promise<{ prepared: boolean; valid: boolean }> {
    try {
      const rootInfo = await fs.lstat(this.powerPath);
      if (rootInfo.isSymbolicLink() || !rootInfo.isDirectory()) return { prepared: true, valid: false };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return { prepared: false, valid: false };
      return { prepared: true, valid: false };
    }
    try {
      const required = [
        path.join(this.powerPath, "POWER.md"),
        path.join(this.powerPath, "mcp.json"),
        path.join(this.powerPath, "steering"),
        path.join(this.powerPath, "references"),
        path.join(this.powerPath, "runtime", "engine", "kiro_security", "mcp_server.py"),
      ];
      const info = await Promise.all(required.map((entry) => fs.lstat(entry)));
      const shapeValid = info[0].isFile() && info[1].isFile() && info[2].isDirectory()
        && info[3].isDirectory() && info[4].isFile()
        && !info.some((entry) => entry.isSymbolicLink());
      if (!shapeValid) return { prepared: true, valid: false };
      await this.verifyPreparedPayload(this.powerPath, expectedPython, expectedPolicy);
      return { prepared: true, valid: true };
    } catch {
      return { prepared: true, valid: false };
    }
  }

  async inspect(pythonPath: string): Promise<AgentIntegrationStatus> {
    const runtime = await this.resolveRuntime(pythonPath);
    const [configs, state, packaged] = await Promise.all([
      Promise.all(this.configCandidates().map((candidate) => this.inspectConfig(candidate))),
      this.readState(),
      this.sourcePackaged(),
    ]);
    const prepared = await this.preparedStatus(
      runtime.probe.available ? runtime.probe.executable : undefined,
      state?.autoApprovePolicy,
    );
    const direct = configs.find((entry) => entry.direct && !entry.direct.disabled);
    const anyDirect = configs.find((entry) => entry.direct);
    const managed = configs.find((entry) => entry.powerManaged && !entry.powerManaged.disabled);
    const active = managed?.powerManaged ?? direct?.direct;
    const expectedEngine = path.join(this.powerPath, "runtime", "engine");
    const directDigestMismatch = Boolean(anyDirect?.direct && state?.configDigest && state.configDigest !== configDigest(anyDirect.direct));
    const versionStale = Boolean(anyDirect?.direct && state?.productVersion && state.productVersion !== this.productVersion);
    const expectedDirectWorkspace = anyDirect?.scope === "workspace" ? this.workspaceRoot : undefined;
    const directShapeIssue = anyDirect?.direct
      ? managedServerShapeIssue(anyDirect.direct, expectedEngine, expectedDirectWorkspace, runtime.probe.available ? runtime.probe.executable : undefined)
      : undefined;
    const stale = Boolean(anyDirect?.direct && (
      anyDirect.direct.disabled
      || directShapeIssue
      || directDigestMismatch
      || versionStale
    ));
    const parseFailure = configs.find((entry) => entry.parseError);
    const configured = Boolean(active);
    const verified = Boolean(
      managed?.powerManaged
      && prepared.valid
      && !stale
      && state?.powerVerifiedAt
      && state.powerConfigDigest === configDigest(managed.powerManaged)
      && state.productVersion === this.productVersion
    );
    let stateName: AgentIntegrationStatus["state"] = "not_configured";
    if (parseFailure || (configured && (!runtime.probe.available || !runtime.probe.supported))) stateName = "error";
    else if (stale || (prepared.prepared && !prepared.valid) || (configured && !prepared.prepared)) stateName = "needs_repair";
    else if (verified) stateName = "verified";
    else if (configured) stateName = "configured";
    const details: string[] = [];
    if (!runtime.probe.available || !runtime.probe.supported) details.push(runtime.probe.error ?? "Python 3.10+ with sqlite3 was not found.");
    if (parseFailure) details.push(parseFailure.parseError!);
    if (versionStale) details.push(`The managed runtime was installed by version ${state?.productVersion}; repair it for version ${this.productVersion}.`);
    else if (directDigestMismatch) details.push("The managed MCP entry changed after verification; review it and run Repair Agent Integration.");
    else if (stale) details.push(`The managed MCP entry does not match this VSIX version${directShapeIssue ? ` (${directShapeIssue})` : ""}; run Repair Agent Integration.`);
    if (configured && !prepared.prepared) details.push("The managed MCP entry points to a missing prepared runtime; run Repair Agent Integration.");
    else if (prepared.prepared && !prepared.valid) details.push("The prepared Agent runtime failed its integrity check; run Repair Agent Integration before using it.");
    if (managed) details.push("A Kiro-managed native Power registration was detected and its MCP runtime can be verified.");
    else if (prepared.prepared) details.push("MCP runtime preparation passed, but scans are not ready until the prepared folder is imported from Kiro's Powers panel.");
    const steering = state?.steeringPath;
    return {
      packaged,
      state: stateName,
      operation: "idle",
      configured,
      verified,
      serverName: AGENT_MCP_SERVER_NAME,
      configScope: direct?.scope ?? managed?.scope,
      configLocations: configs.filter((entry) => entry.direct || entry.powerManaged).map((entry) => entry.path),
      directConfigPath: anyDirect?.path,
      steeringPath: steering,
      dependencies: { python: dependency(runtime.probe) },
      power: {
        packaged,
        prepared: prepared.prepared,
        preparedPath: prepared.prepared ? this.powerPath : undefined,
        manifestValid: prepared.valid,
        registration: managed ? "detected" : prepared.prepared ? "import_required" : "not_prepared",
        importRequiresKiroConfirmation: !managed,
      },
      autoApprovePolicy: state?.autoApprovePolicy,
      lastVerifiedAt: verified ? state?.powerVerifiedAt : undefined,
      lastError: parseFailure?.parseError,
      details,
    };
  }

  private async backup(filePath: string, previous: CapturedFile): Promise<string | undefined> {
    if (!previous.existed || !previous.bytes) return undefined;
    const name = `${new Date().toISOString().replace(/[:.]/g, "-")}-${createHash("sha256").update(filePath).digest("hex").slice(0, 12)}-${path.basename(filePath)}`;
    const backup = path.join(this.globalStorageRoot, "agent-integration", "backups", name);
    await atomicWrite(backup, previous.bytes, previous.mode ?? 0o600);
    return backup;
  }

  private async buildPowerStaging(invocation: PythonInvocation, pythonPath: string, policy: AgentAutoApprovePolicy): Promise<string> {
    if (!this.workspaceRoot) throw new AgentIntegrationError("workspace_required", "Open a local workspace before preparing Agent integration.");
    if (!await this.sourcePackaged()) throw new AgentIntegrationError("power_missing", "The VSIX does not contain a valid Kiro Power source bundle.");
    const root = path.join(this.globalStorageRoot, "agent-integration");
    await fs.mkdir(root, { recursive: true, mode: 0o700 });
    const staging = path.join(root, `.power-staging-${randomUUID()}`);
    await fs.mkdir(staging, { mode: 0o700 });
    try {
      await copyTrustedFile(path.join(this.sourcePowerPath, "POWER.md"), path.join(staging, "POWER.md"), this.extensionRoot);
      await copyTrustedTree(path.join(this.sourcePowerPath, "steering"), path.join(staging, "steering"), this.extensionRoot, (relative) => relative.toLowerCase().endsWith(".md"));
      await copyTrustedTree(path.join(this.sourcePowerPath, "references"), path.join(staging, "references"), this.extensionRoot, (relative) => relative.toLowerCase().endsWith(".md"));
      try { await copyTrustedFile(path.join(this.sourcePowerPath, "NOTICE.md"), path.join(staging, "NOTICE.md"), this.extensionRoot); } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
      await copyTrustedTree(path.join(this.extensionRoot, "engine", "kiro_security"), path.join(staging, "runtime", "engine", "kiro_security"), this.extensionRoot, (relative) => relative.endsWith(".py"));
      await copyTrustedTree(path.join(this.extensionRoot, "engine", "migrations"), path.join(staging, "runtime", "engine", "migrations"), this.extensionRoot, (relative) => relative.endsWith(".sql"));
      await copyTrustedTree(path.join(this.extensionRoot, "engine", "schemas"), path.join(staging, "runtime", "engine", "schemas"), this.extensionRoot, (relative) => relative.endsWith(".json"));
      const engineRoot = path.join(this.powerPath, "runtime", "engine");
      const entry = buildServerConfig(invocation, pythonPath, engineRoot, undefined, policy);
      await atomicWrite(path.join(staging, "mcp.json"), `${JSON.stringify({ mcpServers: { [POWER_MCP_SERVER_NAME]: entry } }, null, 2)}\n`);
      await atomicWrite(path.join(staging, "INSTALL.md"), [
        "# Required native Kiro Power registration",
        "",
        "The VSIX Setup prepared and probed the MCP runtime. Standard, Diff, and Deep scans remain unavailable until Kiro installs the Power and can load POWER.md plus phase steering.",
        "To enable the Skill-driven scan workflows:",
        "",
        "1. Open Powers → Add Custom Power.",
        "2. Choose Import power from a folder.",
        `3. Select: \`${this.powerPath}\``,
        "4. Review permissions and click Install.",
        "",
      ].join("\n"));
      await this.verifyPreparedPayload(
        staging,
        pythonPath,
        policy,
        path.join(this.powerPath, "runtime", "engine"),
      );
      return staging;
    } catch (error) {
      await fs.rm(staging, { recursive: true, force: true });
      throw error;
    }
  }

  private async activatePower(staging: string): Promise<string | undefined> {
    const previous = `${this.powerPath}.previous-${randomUUID()}`;
    let moved = false;
    try {
      await fs.rename(this.powerPath, previous);
      moved = true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    try {
      await fs.rename(staging, this.powerPath);
      return moved ? previous : undefined;
    } catch (error) {
      if (moved) await fs.rename(previous, this.powerPath).catch(() => undefined);
      throw error;
    }
  }

  private assertTrustedServer(config: McpServerConfig, expectedPython: string, expectedWorkspace: string | undefined): void {
    if (!this.workspaceRoot) throw new AgentIntegrationError("workspace_required", "Open a local workspace before verifying Agent integration.");
    const expectedEngine = path.resolve(this.powerPath, "runtime", "engine");
    const issue = managedServerShapeIssue(config, expectedEngine, expectedWorkspace, expectedPython);
    if (!issue) return;
    const codes: Record<string, string> = {
      "runtime path": "untrusted_mcp_path",
      "Python command": "untrusted_python",
      "argument list": "untrusted_mcp_args",
      "auto-approval list": "unsafe_auto_approval",
    };
    throw new AgentIntegrationError(
      codes[issue] ?? "untrusted_mcp_environment",
      `The configured MCP server no longer matches the approved ${issue}. Run Repair Agent Integration after reviewing the change.`,
      { issue },
    );
  }

  private async verifyServer(
    config: McpServerConfig,
    expectedPython: string,
    expectedWorkspace: string | undefined,
    configPath?: string,
  ): Promise<AgentIntegrationVerifyResult> {
    if (!this.workspaceRoot) throw new AgentIntegrationError("workspace_required", "Open a local workspace before verifying Agent integration.");
    await this.verifyPreparedPayload(this.powerPath, expectedPython, approvalPolicyFor(config));
    this.assertTrustedServer(config, expectedPython, expectedWorkspace);
    const child = spawn(config.command, config.args, {
      cwd: this.workspaceRoot,
      env: minimalProcessEnvironment(config.env),
      shell: false,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    });
    const client = new LineRpcClient(child);
    try {
      const initialized = await client.request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "kiro-security-power-installer", version: this.productVersion } });
      const init = isRecord(initialized.result) ? initialized.result : {};
      const serverInfo = isRecord(init.serverInfo) ? init.serverInfo : {};
      if (serverInfo.name !== "kiro-security-power") throw new AgentIntegrationError("mcp_identity", "The packaged MCP server returned an unexpected identity.");
      client.notify("notifications/initialized");
      const listed = await client.request("tools/list", {});
      const result = isRecord(listed.result) ? listed.result : {};
      const tools = Array.isArray(result.tools) ? result.tools : [];
      const names = new Set(tools.filter(isRecord).map((tool) => String(tool.name ?? "")));
      const missing = REQUIRED_TOOLS.filter((name) => !names.has(name));
      if (missing.length) throw new AgentIntegrationError("mcp_tools_missing", `Packaged MCP server is missing required tools: ${missing.join(", ")}.`);
      const capabilities = await client.request("tools/call", { name: "security_get_capabilities", arguments: { workspaceRoot: this.workspaceRoot } }, 25_000);
      const call = isRecord(capabilities.result) ? capabilities.result : {};
      if (call.isError === true) {
        const message = Array.isArray(call.content) && isRecord(call.content[0]) ? String(call.content[0].text ?? "") : "";
        throw new AgentIntegrationError("engine_health", message || "The MCP server could not initialize the security engine.");
      }
      const structured = isRecord(call.structuredContent) && isRecord(call.structuredContent.result) ? call.structuredContent.result : {};
      return {
        serverVersion: typeof serverInfo.version === "string" ? serverInfo.version : "unknown",
        engineVersion: typeof structured.engineVersion === "string" ? structured.engineVersion : "unknown",
        toolCount: tools.length,
        verifiedAt: new Date().toISOString(),
        configPath,
        powerPath: this.powerPath,
      };
    } finally {
      await client.stop();
    }
  }

  async install(options: AgentIntegrationInstallOptions): Promise<AgentIntegrationInstallResult> {
    if (!this.workspaceRoot) throw new AgentIntegrationError("workspace_required", "Open a local workspace before installing Agent integration.");
    const runtime = await this.resolveRuntime(options.pythonPath);
    if (!runtime.probe.available || !runtime.probe.supported) throw new AgentIntegrationError("python_incompatible", runtime.probe.error ?? "Python 3.10+ with sqlite3 is required.");
    const configPath = this.targetConfig(options.scope);
    const steeringPath = this.steeringPath(options.scope);
    const boundary = options.scope === "workspace" ? this.workspaceRoot : this.home;
    await ensureNoSymlinkComponents(configPath, boundary);
    await ensureNoSymlinkComponents(steeringPath, boundary);
    const previousConfig = await capture(configPath);
    const previousSteering = await capture(steeringPath);
    if (previousSteering.existed && !previousSteering.bytes?.toString("utf8").includes(MANAGED_STEERING_MARKER)) {
      throw new AgentIntegrationError("steering_conflict", `Refusing to replace an unmanaged steering file: ${steeringPath}`);
    }
    const backupPaths = (await Promise.all([this.backup(configPath, previousConfig), this.backup(steeringPath, previousSteering)])).filter((value): value is string => Boolean(value));
    const previousState = await this.readState();
    const staging = await this.buildPowerStaging(runtime.invocation, runtime.probe.executable, options.autoApprovePolicy);
    let previousPower: string | undefined;
    let powerActivated = false;
    let configWritten = false;
    let steeringWritten = false;
    try {
      previousPower = await this.activatePower(staging);
      powerActivated = true;
      const config = buildServerConfig(
        runtime.invocation,
        runtime.probe.executable,
        path.join(this.powerPath, "runtime", "engine"),
        options.scope === "workspace" ? this.workspaceRoot : undefined,
        options.autoApprovePolicy,
      );
      const current = previousConfig.existed ? (previousConfig.bytes ?? Buffer.alloc(0)).toString("utf8") : "{}\n";
      await atomicWrite(configPath, mergeMcpServerConfigText(current, configPath, AGENT_MCP_SERVER_NAME, config), previousConfig.mode ?? 0o600);
      configWritten = true;
      await atomicWrite(steeringPath, buildAgentSteering(this.productVersion), previousSteering.mode ?? 0o600);
      steeringWritten = true;
      const verified = await this.verifyServer(
        config,
        runtime.probe.executable,
        options.scope === "workspace" ? this.workspaceRoot : undefined,
        configPath,
      );
      await this.writeState({
        schemaVersion: 1,
        productVersion: this.productVersion,
        verifiedAt: verified.verifiedAt,
        configPath,
        configDigest: configDigest(config),
        steeringPath,
        autoApprovePolicy: options.autoApprovePolicy,
      });
      if (previousPower) await fs.rm(previousPower, { recursive: true, force: true });
      this.logger?.log("info", "Kiro Agent integration installed and verified", { configPath, steeringPath, toolCount: verified.toolCount });
      return {
        configPath,
        steeringPath,
        powerPath: this.powerPath,
        backupPaths,
        pythonExecutable: runtime.probe.executable,
        pythonVersion: runtime.probe.version ?? "unknown",
        sqliteVersion: runtime.probe.sqliteVersion,
        toolCount: verified.toolCount,
        verifiedAt: verified.verifiedAt,
      };
    } catch (error) {
      if (configWritten) await restore(configPath, previousConfig).catch(() => undefined);
      if (steeringWritten) await restore(steeringPath, previousSteering).catch(() => undefined);
      if (powerActivated) {
        await fs.rm(this.powerPath, { recursive: true, force: true }).catch(() => undefined);
        if (previousPower) await fs.rename(previousPower, this.powerPath).catch(() => undefined);
      } else {
        await fs.rm(staging, { recursive: true, force: true }).catch(() => undefined);
      }
      if (previousState) await this.writeState(previousState).catch(() => undefined);
      else await fs.rm(this.statePath, { force: true }).catch(() => undefined);
      this.logger?.log("error", "Kiro Agent integration installation rolled back", { error: error instanceof Error ? error.message : String(error) });
      throw error;
    }
  }

  async verify(pythonPath: string): Promise<AgentIntegrationVerifyResult> {
    const runtime = await this.resolveRuntime(pythonPath);
    if (!runtime.probe.available || !runtime.probe.supported) throw new AgentIntegrationError("python_incompatible", runtime.probe.error ?? "Python 3.10+ with sqlite3 is required.");
    const inspections = await Promise.all(this.configCandidates().map((candidate) => this.inspectConfig(candidate)));
    const direct = inspections.find((entry) => entry.direct);
    if (direct?.direct) {
      const expectedWorkspace = direct.scope === "workspace" ? this.workspaceRoot : undefined;
      this.assertTrustedServer(direct.direct, runtime.probe.executable, expectedWorkspace);
      const prior = await this.readState();
      if (prior?.configDigest && prior.configDigest !== configDigest(direct.direct)) {
        throw new AgentIntegrationError("managed_config_changed", "The VSIX-managed MCP entry changed after setup. Run Repair Agent Integration.");
      }
    }
    const selected = inspections.find((entry) => entry.powerManaged && !entry.powerManaged.disabled);
    const config = selected?.powerManaged;
    if (!config) {
      throw new AgentIntegrationError(
        "power_not_registered",
        `Import the prepared folder from Kiro's Powers panel before verifying scan readiness: ${this.powerPath}`,
      );
    }
    const result = await this.verifyServer(config, runtime.probe.executable, undefined, selected?.path);
    const previous = await this.readState();
    await this.writeState({
      schemaVersion: 1,
      productVersion: this.productVersion,
      verifiedAt: result.verifiedAt,
      configPath: previous?.configPath,
      configDigest: previous?.configDigest,
      steeringPath: previous?.steeringPath,
      powerConfigDigest: configDigest(config),
      powerVerifiedAt: result.verifiedAt,
      autoApprovePolicy: previous?.autoApprovePolicy,
    });
    return result;
  }

  async removeDirectIntegration(): Promise<AgentIntegrationRemovalResult> {
    const removedConfigPaths: string[] = [];
    const removedSteeringPaths: string[] = [];
    const skippedUnmanagedConfigPaths: string[] = [];
    const backupPaths: string[] = [];
    for (const candidate of this.configCandidates().filter((entry) => entry.scope)) {
      const inspection = await this.inspectConfig(candidate);
      if (!inspection.direct || !candidate.scope) continue;
      const expectedWorkspace = candidate.scope === "workspace" ? this.workspaceRoot : undefined;
      const issue = managedServerShapeIssue(inspection.direct, path.join(this.powerPath, "runtime", "engine"), expectedWorkspace);
      if (issue) {
        skippedUnmanagedConfigPaths.push(candidate.path);
        continue;
      }
      const boundary = candidate.scope === "workspace" ? this.workspaceRoot! : this.home;
      await ensureNoSymlinkComponents(candidate.path, boundary);
      const previous = await capture(candidate.path);
      const backup = await this.backup(candidate.path, previous);
      if (backup) backupPaths.push(backup);
      await atomicWrite(candidate.path, removeMcpServerConfigText((previous.bytes ?? Buffer.alloc(0)).toString("utf8"), candidate.path, AGENT_MCP_SERVER_NAME), previous.mode ?? 0o600);
      removedConfigPaths.push(candidate.path);
    }
    for (const scope of ["workspace", "user"] as const) {
      if (scope === "workspace" && !this.workspaceRoot) continue;
      const steeringPath = this.steeringPath(scope);
      const boundary = scope === "workspace" ? this.workspaceRoot! : this.home;
      await ensureNoSymlinkComponents(steeringPath, boundary);
      const previous = await capture(steeringPath);
      if (!previous.existed || !previous.bytes?.toString("utf8").includes(MANAGED_STEERING_MARKER)) continue;
      const backup = await this.backup(steeringPath, previous);
      if (backup) backupPaths.push(backup);
      await fs.rm(steeringPath, { force: true });
      removedSteeringPaths.push(steeringPath);
    }
    const state = await this.readState();
    if (state) await this.writeState({ ...state, verifiedAt: undefined, configPath: undefined, configDigest: undefined, steeringPath: undefined });
    return { removedConfigPaths, removedSteeringPaths, skippedUnmanagedConfigPaths, backupPaths };
  }

  async ensureMcpConfig(scope: AgentIntegrationScope): Promise<string> {
    const filePath = this.targetConfig(scope);
    const boundary = scope === "workspace" ? this.workspaceRoot! : this.home;
    await ensureNoSymlinkComponents(filePath, boundary);
    const previous = await capture(filePath);
    if (!previous.existed) await atomicWrite(filePath, '{\n  "mcpServers": {}\n}\n', 0o600);
    return filePath;
  }

  async configForClipboard(pythonPath: string, policy: AgentAutoApprovePolicy = "read_only"): Promise<Record<string, unknown>> {
    if (!this.workspaceRoot) throw new AgentIntegrationError("workspace_required", "Open a local workspace before creating MCP configuration.");
    const runtime = await this.resolveRuntime(pythonPath);
    if (!runtime.probe.available || !runtime.probe.supported) throw new AgentIntegrationError("python_incompatible", runtime.probe.error ?? "Python 3.10+ with sqlite3 is required.");
    return {
      mcpServers: {
        [AGENT_MCP_SERVER_NAME]: buildServerConfig(runtime.invocation, runtime.probe.executable, path.join(this.powerPath, "runtime", "engine"), this.workspaceRoot, policy),
      },
    };
  }
}
