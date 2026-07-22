import { spawn, ChildProcessWithoutNullStreams } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { PROTOCOL_VERSION as ENGINE_PROTOCOL_VERSION, isRpcEnvelope } from "../../protocol/src";

const MAX_LINE_BYTES = 2 * 1024 * 1024;
const SERVER_VERSION = "0.3.0";
const MCP_PROTOCOLS = new Set(["2024-11-05", "2025-03-26", "2025-06-18"]);
const extensionRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

type JsonRpcId = string | number;
interface JsonRpcRequest { jsonrpc: "2.0"; id: JsonRpcId; method: string; params?: Record<string, unknown>; }
interface Pending { resolve(value: unknown): void; reject(error: Error): void; timer: NodeJS.Timeout; }

class EngineRpcError extends Error {
  constructor(message: string, readonly engineCode?: string) {
    super(engineCode ? `${message} (${engineCode})` : message);
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function isRequestId(value: unknown): value is JsonRpcId {
  return typeof value === "string" || (typeof value === "number" && Number.isInteger(value));
}
function boundedString(value: unknown, max = 8192): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= max && !value.includes("\0");
}
function canonicalWorkspace(value: unknown): string {
  if (!boundedString(value)) throw new Error("workspaceRoot must identify a bounded local directory path.");
  const requested = value;
  const resolved = fs.realpathSync(path.resolve(requested));
  if (!fs.statSync(resolved).isDirectory()) throw new Error("workspaceRoot must identify a local directory.");
  return resolved;
}
function safeGitRef(value: unknown, field: string): string | undefined {
  if (value === undefined || value === "") return undefined;
  if (!boundedString(value, 256) || value.startsWith("-") || !/^[A-Za-z0-9._/@+\-~^:]+$/.test(value)) {
    throw new Error(`${field} is not a safe Git revision.`);
  }
  return value;
}
function requiredString(params: Record<string, unknown>, name: string, max = 4096): string {
  const value = params[name];
  if (!boundedString(value, max)) throw new Error(`${name} must be a non-empty bounded string.`);
  return value;
}
function requiredInteger(params: Record<string, unknown>, name: string, minimum = 1): number {
  const value = params[name];
  if (typeof value !== "number" || !Number.isInteger(value) || value < minimum) {
    throw new Error(`${name} must be an integer of at least ${minimum}.`);
  }
  return value;
}

class EngineProcess {
  private child: ChildProcessWithoutNullStreams | undefined;
  private buffer = "";
  private nextId = 1;
  private readonly pending = new Map<number, Pending>();
  private started: Promise<void> | undefined;
  private stopPromise: Promise<void> | undefined;
  private stopping = false;

  constructor(readonly workspaceRoot: string) {}

  async start(): Promise<void> {
    if (this.child) return;
    if (this.started) return this.started;
    this.started = this.startInternal().finally(() => { this.started = undefined; });
    return this.started;
  }

  private async startInternal(): Promise<void> {
    const python = process.env.KIRO_SECURITY_PYTHON || "python3";
    const engineRoot = path.join(extensionRoot, "engine");
    const env: NodeJS.ProcessEnv = {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      USERPROFILE: process.env.USERPROFILE,
      SYSTEMROOT: process.env.SYSTEMROOT,
      TMPDIR: process.env.TMPDIR,
      TEMP: process.env.TEMP,
      TMP: process.env.TMP,
      LANG: process.env.LANG || "C.UTF-8",
      LC_ALL: process.env.LC_ALL || "C.UTF-8",
      PYTHONIOENCODING: "utf-8",
      PYTHONUNBUFFERED: "1",
      PYTHONPATH: engineRoot,
    };
    const child = spawn(python, ["-B", "-S", "-m", "kiro_security.server", "--workspace", this.workspaceRoot, "--client-kind", "mcp"], {
      cwd: this.workspaceRoot,
      env,
      shell: false,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    this.child = child;
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => this.consume(chunk));
    child.stderr.on("data", (chunk: string) => process.stderr.write(`[kiro-security-engine] ${chunk}`));
    child.on("error", (error) => this.fail(error));
    child.on("exit", (code, signal) => {
      if (this.child === child) this.child = undefined;
      const reason = this.stopping
        ? new Error("Security engine stopped.")
        : new Error(`Security engine exited with code ${code ?? "unknown"} (${signal ?? "no signal"}).`);
      this.fail(reason);
    });
    await this.request("initialize", { protocolVersion: ENGINE_PROTOCOL_VERSION, clientInfo: { name: "kiro-security-mcp", version: SERVER_VERSION } }, 15_000, false);
  }

  private consume(chunk: string): void {
    this.buffer += chunk;
    if (Buffer.byteLength(this.buffer, "utf8") > 8 * 1024 * 1024) {
      this.fail(new Error("Security engine output buffer exceeded safety limit."));
      this.child?.kill();
      return;
    }
    for (;;) {
      const index = this.buffer.indexOf("\n");
      if (index < 0) break;
      const line = this.buffer.slice(0, index).trim();
      this.buffer = this.buffer.slice(index + 1);
      if (!line) continue;
      try {
        const message: unknown = JSON.parse(line);
        if (!isRpcEnvelope(message) || "method" in message || typeof message.id !== "number") continue;
        const pending = this.pending.get(message.id);
        if (!pending) continue;
        clearTimeout(pending.timer);
        this.pending.delete(message.id);
        if ("error" in message) {
          const data = isObject(message.error.data) ? message.error.data : {};
          const engineCode = typeof data.engineCode === "string" && /^[a-z0-9_]{1,128}$/.test(data.engineCode)
            ? data.engineCode
            : undefined;
          pending.reject(new EngineRpcError(String(message.error.message ?? "Engine error"), engineCode));
        }
        else pending.resolve(message.result);
      } catch {
        // The engine contract requires one JSON object per line; malformed output is ignored and logged on stderr.
        process.stderr.write("[kiro-security-mcp] Rejected malformed engine output.\n");
      }
    }
  }

  async request<T>(method: string, params: Record<string, unknown> = {}, timeout = 30_000, autoStart = true): Promise<T> {
    if (autoStart) await this.start();
    const child = this.child;
    if (!child?.stdin.writable) throw new Error("Security engine is not available.");
    const id = this.nextId++;
    const encoded = JSON.stringify({ jsonrpc: "2.0", protocolVersion: ENGINE_PROTOCOL_VERSION, id, method, params });
    if (Buffer.byteLength(encoded, "utf8") > MAX_LINE_BYTES) throw new Error("Engine request exceeds the 2 MiB limit.");
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Engine request timed out: ${method}`));
      }, timeout);
      this.pending.set(id, { resolve, reject, timer });
      child.stdin.write(encoded + "\n", (error) => {
        if (!error) return;
        const pending = this.pending.get(id);
        if (pending) {
          clearTimeout(pending.timer);
          this.pending.delete(id);
          pending.reject(error);
        }
      });
    });
  }

  private fail(error: Error): void {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.pending.clear();
  }

  async stop(): Promise<void> {
    if (this.stopPromise) return this.stopPromise;
    this.stopPromise = this.stopInternal().finally(() => { this.stopPromise = undefined; });
    return this.stopPromise;
  }

  private async stopInternal(): Promise<void> {
    const child = this.child;
    if (!child) return;
    this.stopping = true;
    try {
      if (child.exitCode === null && child.signalCode === null && child.stdin.writable) {
        try { await this.request("shutdown", {}, 5_000, false); } catch { /* graceful shutdown is best effort */ }
      }
      if (!child.stdin.destroyed) child.stdin.end();
      if (!await this.waitForExit(child, 2_500)) {
        child.kill("SIGTERM");
        if (!await this.waitForExit(child, 2_500) && process.platform !== "win32") {
          child.kill("SIGKILL");
          await this.waitForExit(child, 1_000);
        }
      }
    } finally {
      this.fail(new Error("Security engine stopped."));
      child.stdin.destroy();
      child.stdout.destroy();
      child.stderr.destroy();
      if (this.child === child) this.child = undefined;
      this.stopping = false;
    }
  }

  private waitForExit(child: ChildProcessWithoutNullStreams, timeoutMs: number): Promise<boolean> {
    if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve(true);
    return new Promise((resolve) => {
      const finish = (exited: boolean): void => {
        clearTimeout(timer);
        child.off("exit", onExit);
        resolve(exited);
      };
      const onExit = (): void => finish(true);
      const timer = setTimeout(() => finish(false), timeoutMs);
      child.once("exit", onExit);
    });
  }
}

const engines = new Map<string, EngineProcess>();
function engineFor(params: Record<string, unknown>): EngineProcess {
  const workspace = canonicalWorkspace(params.workspaceRoot);
  let engine = engines.get(workspace);
  if (!engine) {
    engine = new EngineProcess(workspace);
    engines.set(workspace, engine);
  }
  return engine;
}

const toolDefinitions = [
  {
    name: "security_get_capabilities",
    description: "Report deterministic Engine, Python, SQLite, Git, workspace, supported-mode, and canonical-finalizer facts only.",
    inputSchema: { type: "object", properties: { workspaceRoot: { type: "string" } }, required: ["workspaceRoot"], additionalProperties: false },
  },
  {
    name: "security_start_scan",
    description: "Start a chat-coordinated scan in a new logical workspace, or rerun the immutable setup identified by sessionId.",
    inputSchema: { type: "object", properties: { workspaceRoot: { type: "string" }, sessionId: { type: "string", description: "Optional logical workspace id returned by an earlier scan." }, taskId: { type: "string", description: "Stable opaque identity for the current Kiro task; reuse it with sessionId." }, mode: { type: "string", enum: ["standard", "deep", "diff"] }, scope: { type: "string", minLength: 1, default: "." }, diffTargetKind: { type: "string", enum: ["working_tree", "commit", "range"] }, diffBaseRevision: { type: "string" }, diffHeadRevision: { type: "string" }, userContext: { type: "string", maxLength: 4000 } }, required: ["workspaceRoot", "taskId", "mode"], additionalProperties: false },
  },
  { name: "security_acquire_scan_coordinator", description: "Acquire an available or expired transient coordinator lease for a durable running scan.", inputSchema: idSchema("scanId") },
  { name: "security_renew_scan_coordinator", description: "Renew the current transient coordinator lease with generation-based CAS.", inputSchema: leaseSchema() },
  { name: "security_release_scan_coordinator", description: "Release coordinator execution authority without changing scan lifecycle state.", inputSchema: leaseSchema() },
  { name: "security_cancel_scan", description: "Cancel a running scan while atomically releasing its coordinator lease.", inputSchema: leaseSchema() },
  { name: "security_get_scan", description: "Get scan lifecycle, progress, coverage, and artifact records.", inputSchema: idSchema("scanId") },
  { name: "security_get_progress", description: "Get the latest progress record for a scan.", inputSchema: idSchema("scanId") },
  { name: "security_get_scan_context", description: "Get immutable target identity, phase artifact paths, deterministic worklists, canonical output paths, lifecycle, and other running Deep scans.", inputSchema: idSchema("scanId") },
  { name: "security_update_scan_progress", description: "Update user-visible lifecycle progress under the current coordinator lease; accepts no result or receipt bodies.", inputSchema: leaseSchema({ phase: { type: "string", enum: ["preflight", "threat_model", "discovery", "validation", "attack_path", "reporting"] }, phasePercent: { type: "number", minimum: 0, maximum: 100 }, itemsTotal: { type: "integer", minimum: 0 }, itemsCompleted: { type: "integer", minimum: 0 }, reportableFindingsCount: { type: "integer", minimum: 0 }, message: { type: "string", maxLength: 1000 } }) },
  { name: "security_complete_scan", description: "One-shot validate, index, project, and seal fixed Agent-authored canonical artifacts under the current coordinator lease.", inputSchema: leaseSchema() },
  { name: "security_fail_scan", description: "Fail a running scan and atomically release its coordinator lease.", inputSchema: leaseSchema({ reason: { type: "string", minLength: 1, maxLength: 4000 } }, ["reason"]) },
  { name: "security_list_findings", description: "List findings indexed from the sealed canonical document.", inputSchema: { type: "object", properties: { workspaceRoot: { type: "string" }, scanId: { type: "string" }, search: { type: "string", minLength: 1, maxLength: 200 }, limit: { type: "integer", minimum: 1, maximum: 2000 } }, required: ["workspaceRoot", "scanId"], additionalProperties: false } },
  { name: "security_get_finding", description: "Get one finding with evidence, validation, attack path, triage, and remediation records.", inputSchema: idSchema("occurrenceId") },
  { name: "security_triage_finding", description: "Record an auditable triage decision for a finding.", inputSchema: { type: "object", properties: { workspaceRoot: { type: "string" }, occurrenceId: { type: "string" }, decision: { type: "string", enum: ["open", "accepted_risk", "false_positive", "already_fixed", "wont_fix"] }, note: { type: "string", maxLength: 4000 } }, required: ["workspaceRoot", "occurrenceId", "decision"], additionalProperties: false } },
  { name: "security_create_remediation", description: "Create finding-specific remediation guidance in the shared artifact directory.", inputSchema: idSchema("occurrenceId") },
  { name: "security_prepare_remediation_patch", description: "Prepare and drift-check a bounded existing-file unified diff without changing the workspace.", inputSchema: { type: "object", properties: { workspaceRoot: { type: "string" }, occurrenceId: { type: "string" }, patch: { type: "string", maxLength: 600000 }, plan: { type: "string", maxLength: 12000 }, verificationPlan: { type: "array", minItems: 1, maxItems: 50, items: { type: "string", maxLength: 2000 } } }, required: ["workspaceRoot", "occurrenceId", "patch", "plan", "verificationPlan"], additionalProperties: false } },
  { name: "security_apply_remediation_patch", description: "Apply exactly one prepared patch after digest, revision, file-drift, and state revalidation.", inputSchema: { type: "object", properties: { workspaceRoot: { type: "string" }, remediationId: { type: "string" }, expectedVersion: { type: "integer", minimum: 1 } }, required: ["workspaceRoot", "remediationId", "expectedVersion"], additionalProperties: false } },
  { name: "security_verify_remediation_patch", description: "Record bounded Agent verification proof; incomplete gates cannot become verified.", inputSchema: { type: "object", properties: { workspaceRoot: { type: "string" }, remediationId: { type: "string" }, expectedVersion: { type: "integer", minimum: 1 }, verification: { type: "object" } }, required: ["workspaceRoot", "remediationId", "expectedVersion", "verification"], additionalProperties: false } },
  { name: "security_create_triage_intake", description: "Persist one bounded untrusted external finding intake.", inputSchema: { type: "object", properties: { workspaceRoot: { type: "string" }, occurrenceId: { type: "string" }, sourceType: { type: "string", enum: ["sarif", "cve", "advisory", "scanner_ticket", "bug_bounty", "kiro_security_finding", "freeform", "unknown"] }, inputId: { type: "string", maxLength: 512 }, input: { type: "object" } }, required: ["workspaceRoot", "sourceType", "inputId", "input"], additionalProperties: false } },
  { name: "security_submit_triage_assessment", description: "Complete one pending intake with a static proof-chain result.", inputSchema: { type: "object", properties: { workspaceRoot: { type: "string" }, assessmentId: { type: "string" }, result: { type: "object" } }, required: ["workspaceRoot", "assessmentId", "result"], additionalProperties: false } },
  { name: "security_create_tracking_handoff", description: "Seal an approved connector/destination/duplicate-search proof without an external write.", inputSchema: { type: "object", properties: { workspaceRoot: { type: "string" }, occurrenceId: { type: "string" }, provider: { type: "string", enum: ["manual", "github", "linear", "jira"] }, destination: { type: "string", maxLength: 512 }, stableLink: { type: "string", maxLength: 4096 }, trackingProof: { type: "object" } }, required: ["workspaceRoot", "occurrenceId", "provider", "trackingProof"], additionalProperties: false } },
  { name: "security_record_tracking_result", description: "Record sanitized connector readback for an approved handoff; performs no provider network write.", inputSchema: { type: "object", properties: { workspaceRoot: { type: "string" }, recordId: { type: "string" }, payloadSha256: { type: "string", pattern: "^[a-f0-9]{64}$" }, outcome: { type: "string", enum: ["created", "updated", "reused", "blocked", "failed", "uncertain"] }, externalMutationPerformed: { type: "boolean" }, externalId: { type: "string", maxLength: 512 }, externalUrl: { type: "string", maxLength: 4096 }, reason: { type: "string", maxLength: 4000 }, approval: { type: "object", properties: { approved: { const: true }, approvedPreviewDigest: { type: "string", pattern: "^[a-f0-9]{64}$" }, approvedPayloadSha256: { type: "string", pattern: "^[a-f0-9]{64}$" }, approvedBy: { type: "string", maxLength: 512 }, approvedAt: { type: "string", maxLength: 128 }, scope: { type: "string", maxLength: 2000 } }, required: ["approved", "approvedPreviewDigest", "approvedPayloadSha256", "approvedBy", "approvedAt", "scope"], additionalProperties: false }, readback: { type: "object" } }, required: ["workspaceRoot", "recordId", "payloadSha256", "outcome", "externalMutationPerformed"], additionalProperties: false } },
  { name: "security_export_report", description: "Export a scan or one finding as Markdown, JSON, CSV, or SARIF.", inputSchema: { type: "object", properties: { workspaceRoot: { type: "string" }, scanId: { type: "string" }, occurrenceId: { type: "string" }, format: { type: "string", enum: ["markdown", "json", "csv", "sarif"] }, destination: { type: "string" } }, required: ["workspaceRoot", "scanId", "format"], additionalProperties: false } },
];

const TOOL_STRING_LIMITS: Record<string, number> = {
  workspaceRoot: 8192, sessionId: 128, taskId: 512, mode: 16, scope: 4096,
  diffTargetKind: 32, diffBaseRevision: 256, diffHeadRevision: 256,
  userContext: 4000, scanId: 256, coordinatorToken: 128, reason: 4000, phase: 32, message: 1000,
  search: 200, occurrenceId: 256, findingId: 256,
  decision: 32, sourceType: 64, inputId: 512, assessmentId: 256,
  patch: 600000, plan: 12000, remediationId: 256, recordId: 256,
  payloadSha256: 64, outcome: 32, externalId: 512, externalUrl: 4096,
  provider: 32, destination: 8192, stableLink: 4096, format: 16,
};
for (const tool of toolDefinitions) {
  const properties = tool.inputSchema.properties as Record<string, Record<string, unknown>>;
  for (const [name, schema] of Object.entries(properties)) {
    if (schema.type === "string" && schema.maxLength === undefined && TOOL_STRING_LIMITS[name] !== undefined) schema.maxLength = TOOL_STRING_LIMITS[name];
    if (name === "workspaceRoot" && schema.minLength === undefined) schema.minLength = 1;
  }
}

function idSchema(name: string): Record<string, unknown> {
  return { type: "object", properties: { workspaceRoot: { type: "string" }, [name]: { type: "string" } }, required: ["workspaceRoot", name], additionalProperties: false };
}

function leaseSchema(extra: Record<string, unknown> = {}, requiredExtra: string[] = []): Record<string, unknown> {
  return {
    type: "object",
    properties: {
      workspaceRoot: { type: "string" }, scanId: { type: "string" },
      coordinatorToken: { type: "string", minLength: 64, maxLength: 128 },
      coordinatorGeneration: { type: "integer", minimum: 1 }, ...extra,
    },
    required: ["workspaceRoot", "scanId", "coordinatorToken", "coordinatorGeneration", ...requiredExtra],
    additionalProperties: false,
  };
}

function leaseRequest(params: Record<string, unknown>): Record<string, unknown> {
  return {
    scanId: requiredString(params, "scanId", 256),
    coordinatorToken: requiredString(params, "coordinatorToken", 128),
    coordinatorGeneration: requiredInteger(params, "coordinatorGeneration"),
  };
}

async function callTool(name: string, rawArguments: unknown): Promise<unknown> {
  if (!isObject(rawArguments)) throw new Error("Tool arguments must be an object.");
  const params = rawArguments;
  const tool = toolDefinitions.find((item) => item.name === name);
  if (!tool) throw new Error(`Unknown security tool: ${name}`);
  const allowed = new Set(Object.keys(tool.inputSchema.properties as Record<string, unknown>));
  const unexpected = Object.keys(params).filter((key) => !allowed.has(key)).sort();
  if (unexpected.length) throw new Error(`Unexpected tool argument(s): ${unexpected.join(", ")}.`);
  const engine = engineFor(params);
  switch (name) {
    case "security_get_capabilities": return engine.request("get_capabilities", {});
    case "security_start_scan": {
      const mode = requiredString(params, "mode", 16);
      if (!["standard", "deep", "diff"].includes(mode)) throw new Error("mode must be standard, deep, or diff.");
      const scope = params.scope === undefined ? "." : requiredString(params, "scope");
      const scan = await engine.request<Record<string, unknown>>("start_scan", {
        workspaceId: params.sessionId === undefined ? undefined : requiredString(params, "sessionId", 128),
        taskId: requiredString(params, "taskId", 512),
        mode,
        scope,
        userContext: params.userContext === undefined ? undefined : requiredString(params, "userContext", 4000),
        diffTargetKind: mode === "diff" ? (params.diffTargetKind ?? "working_tree") : undefined,
        diffBaseRevision: mode === "diff" ? safeGitRef(params.diffBaseRevision, "diffBaseRevision") : undefined,
        diffHeadRevision: mode === "diff" ? safeGitRef(params.diffHeadRevision, "diffHeadRevision") : undefined,
      });
      return { ...scan, sessionId: scan.workspace_id };
    }
    case "security_acquire_scan_coordinator": return engine.request("acquire_scan_coordinator", { scanId: requiredString(params, "scanId", 256) });
    case "security_renew_scan_coordinator": return engine.request("renew_scan_coordinator", leaseRequest(params));
    case "security_release_scan_coordinator": return engine.request("release_scan_coordinator", leaseRequest(params));
    case "security_cancel_scan": return engine.request("cancel_scan", leaseRequest(params));
    case "security_get_scan": return engine.request("get_scan", { scanId: requiredString(params, "scanId", 256) });
    case "security_get_progress": return engine.request("get_progress", { scanId: requiredString(params, "scanId", 256) });
    case "security_get_scan_context": return engine.request("get_scan_context", { scanId: requiredString(params, "scanId", 256) });
    case "security_update_scan_progress": return engine.request("update_scan_progress", { ...leaseRequest(params), phase: params.phase, phasePercent: params.phasePercent, itemsTotal: params.itemsTotal, itemsCompleted: params.itemsCompleted, reportableFindingsCount: params.reportableFindingsCount, message: params.message });
    case "security_complete_scan": return engine.request("complete_scan", leaseRequest(params), 120_000);
    case "security_fail_scan": return engine.request("fail_scan", { ...leaseRequest(params), reason: requiredString(params, "reason", 4000) });
    case "security_list_findings": return engine.request("list_findings", { scanId: requiredString(params, "scanId", 256), search: params.search === undefined ? undefined : requiredString(params, "search", 200), limit: params.limit });
    case "security_get_finding": return engine.request("get_finding", { occurrenceId: requiredString(params, "occurrenceId", 256) });
    case "security_triage_finding": {
      const decision = requiredString(params, "decision", 32);
      if (!["open", "accepted_risk", "false_positive", "already_fixed", "wont_fix"].includes(decision)) throw new Error("Invalid triage decision.");
      return engine.request("triage_finding", { occurrenceId: requiredString(params, "occurrenceId", 256), decision, note: params.note });
    }
    case "security_create_remediation": return engine.request("create_remediation", { occurrenceId: requiredString(params, "occurrenceId", 256) });
    case "security_prepare_remediation_patch": return engine.request("prepare_remediation_patch", { occurrenceId: requiredString(params, "occurrenceId", 256), patch: requiredString(params, "patch", 600000), plan: requiredString(params, "plan", 12000), verificationPlan: params.verificationPlan });
    case "security_apply_remediation_patch": return engine.request("apply_remediation_patch", { remediationId: requiredString(params, "remediationId", 256), expectedVersion: params.expectedVersion });
    case "security_verify_remediation_patch": return engine.request("verify_remediation_patch", { remediationId: requiredString(params, "remediationId", 256), expectedVersion: params.expectedVersion, verification: params.verification });
    case "security_create_triage_intake": return engine.request("create_triage_intake", { occurrenceId: params.occurrenceId, sourceType: requiredString(params, "sourceType", 64), inputId: requiredString(params, "inputId", 512), input: params.input });
    case "security_submit_triage_assessment": return engine.request("submit_triage_assessment", { assessmentId: requiredString(params, "assessmentId", 256), result: params.result });
    case "security_create_tracking_handoff": {
      const provider = requiredString(params, "provider", 32);
      if (!["manual", "github", "linear", "jira"].includes(provider)) throw new Error("Invalid tracking provider.");
      const destination = params.destination === undefined ? "manual-review" : requiredString(params, "destination", 512);
      const stableLink = params.stableLink === undefined ? undefined : requiredString(params, "stableLink", 4096);
      return engine.request("create_tracking_handoff", { occurrenceId: requiredString(params, "occurrenceId", 256), provider, destination, stableLink, trackingProof: params.trackingProof });
    }
    case "security_record_tracking_result": return engine.request("record_tracking_result", { recordId: requiredString(params, "recordId", 256), payloadSha256: requiredString(params, "payloadSha256", 64), outcome: requiredString(params, "outcome", 32), externalMutationPerformed: params.externalMutationPerformed, externalId: params.externalId, externalUrl: params.externalUrl, reason: params.reason, approval: params.approval, readback: params.readback });
    case "security_export_report": {
      const format = requiredString(params, "format", 16);
      if (!["markdown", "json", "csv", "sarif"].includes(format)) throw new Error("Invalid export format.");
      const destination = params.destination;
      if (destination !== undefined && !boundedString(destination)) throw new Error("destination must be a bounded local path.");
      return engine.request("export_report", {
        scanId: requiredString(params, "scanId", 256),
        occurrenceId: params.occurrenceId === undefined ? undefined : requiredString(params, "occurrenceId", 256),
        format, destination,
        allowedRoot: typeof destination === "string" ? path.dirname(path.resolve(destination)) : undefined,
      });
    }
    default: throw new Error(`Unknown security tool: ${name}`);
  }
}

let initialized = false;
let negotiatedProtocol = "2024-11-05";
function write(payload: Record<string, unknown>): void {
  process.stdout.write(JSON.stringify(payload) + "\n");
}
function success(id: JsonRpcId, result: unknown): void { write({ jsonrpc: "2.0", id, result }); }
function failure(id: JsonRpcId | null, code: number, message: string, data?: unknown): void { write({ jsonrpc: "2.0", id, error: { code, message, ...(data === undefined ? {} : { data }) } }); }

async function handle(request: unknown): Promise<void> {
  let id: JsonRpcId | null = null;
  try {
    if (!isObject(request) || request.jsonrpc !== "2.0" || !boundedString(request.method, 256)) throw new Error("Invalid JSON-RPC request.");
    const method = request.method;
    const params = request.params === undefined ? {} : request.params;
    if (!isObject(params)) throw new Error("params must be a JSON object.");
    if (method === "notifications/initialized" || method === "notifications/cancelled") {
      if ("id" in request) throw new Error("JSON-RPC notifications must not include an id.");
      return;
    }
    if (!isRequestId(request.id)) throw new Error("JSON-RPC requests require a string or integer id.");
    id = request.id;
    if (method === "initialize") {
      const requested = typeof params.protocolVersion === "string" ? params.protocolVersion : "2024-11-05";
      negotiatedProtocol = MCP_PROTOCOLS.has(requested) ? requested : "2024-11-05";
      initialized = true;
      success(id, { protocolVersion: negotiatedProtocol, capabilities: { tools: { listChanged: false } }, serverInfo: { name: "kiro-security-power", version: SERVER_VERSION }, instructions: "Use the security_* tools to operate the same durable workbench shown by the Kiro Security Power VSIX." });
      return;
    }
    if (!initialized) { failure(id, -32002, "MCP server has not been initialized."); return; }
    if (method === "ping") { success(id, {}); return; }
    if (method === "tools/list") { success(id, { tools: toolDefinitions }); return; }
    if (method === "tools/call") {
      if (!boundedString(params.name, 128)) throw new Error("tools/call requires a tool name.");
      try {
        const result = await callTool(params.name, params.arguments);
        const text = JSON.stringify(result, null, 2);
        success(id, { content: [{ type: "text", text }], structuredContent: { result }, isError: false });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        success(id, { content: [{ type: "text", text: message }], isError: true });
      }
      return;
    }
    if (method === "resources/list" || method === "prompts/list") { success(id, { [method.startsWith("resources") ? "resources" : "prompts"]: [] }); return; }
    failure(id, -32601, `Method not found: ${method}`);
  } catch (error) {
    failure(id, -32602, error instanceof Error ? error.message : String(error));
  }
}

let inputBuffer = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk: string) => {
  inputBuffer += chunk;
  if (Buffer.byteLength(inputBuffer, "utf8") > 8 * 1024 * 1024) {
    failure(null, -32600, "Input buffer exceeded safety limit.");
    inputBuffer = "";
  }
  for (;;) {
    const newline = inputBuffer.indexOf("\n");
    if (newline < 0) break;
    const line = inputBuffer.slice(0, newline).trim();
    inputBuffer = inputBuffer.slice(newline + 1);
    if (!line) continue;
    if (Buffer.byteLength(line, "utf8") > MAX_LINE_BYTES) { failure(null, -32600, "Message exceeds 2 MiB limit."); continue; }
    try {
      const request: unknown = JSON.parse(line);
      void handle(request).catch((error) => {
        failure(null, -32603, error instanceof Error ? error.message : String(error));
      });
    } catch (error) {
      failure(null, -32700, `Invalid JSON: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
});

let shutdownPromise: Promise<void> | undefined;
function shutdown(): Promise<void> {
  if (!shutdownPromise) {
    const active = [...engines.values()];
    engines.clear();
    shutdownPromise = Promise.allSettled(active.map((engine) => engine.stop())).then(() => undefined);
  }
  return shutdownPromise;
}
function shutdownAndExit(): void {
  process.stdin.pause();
  void shutdown().finally(() => process.exit(0));
}
process.once("SIGTERM", shutdownAndExit);
process.once("SIGINT", shutdownAndExit);
process.stdin.once("end", shutdownAndExit);
