import { ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import * as path from "node:path";
import * as vscode from "vscode";
import { EngineEventName, PROTOCOL_VERSION, RpcEnvelope, isRpcEnvelope } from "../../protocol/src";
import { StructuredLogger, redact } from "./logger";
import { minimalProcessEnvironment, resolvePythonRuntime, type PythonRuntimeProbe } from "./pythonRuntime";

interface PendingRequest {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
}

export interface EngineEvent {
  name: EngineEventName;
  params: Record<string, unknown>;
}

export class EngineRpcError extends Error {
  constructor(
    message: string,
    readonly code: number,
    readonly data?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "EngineRpcError";
  }
}

export class EngineClient implements vscode.Disposable {
  private child: ChildProcessWithoutNullStreams | undefined;
  private stdoutBuffer = "";
  private stderrBuffer = "";
  private nextId = 1;
  private pending = new Map<number, PendingRequest>();
  private startPromise: Promise<void> | undefined;
  private disposed = false;
  private failureLatched = false;
  private readonly eventEmitter = new vscode.EventEmitter<EngineEvent>();
  readonly onEvent = this.eventEmitter.event;
  status: "stopped" | "starting" | "ready" | "error" = "stopped";
  lastError: string | undefined;
  runtimeProbe: PythonRuntimeProbe | undefined;

  constructor(
    private readonly extensionPath: string,
    private readonly workspaceRoot: string,
    private readonly pythonPath: string,
    private readonly productVersion: string,
    private readonly logger: StructuredLogger,
  ) {}

  async start(): Promise<void> {
    if (this.status === "ready" && this.child) return;
    if (this.failureLatched && this.status === "error") {
      throw new Error(this.lastError ?? "Security engine startup previously failed. Use Retry Engine after correcting the runtime.");
    }
    if (this.startPromise) return this.startPromise;
    this.startPromise = this.startInternal().catch((error: unknown) => {
      const message = error instanceof Error ? error.message : String(error);
      this.status = "error";
      this.failureLatched = true;
      this.lastError = message;
      throw error;
    }).finally(() => {
      this.startPromise = undefined;
    });
    return this.startPromise;
  }

  private async startInternal(): Promise<void> {
    if (this.disposed) throw new Error("Engine client is disposed.");
    this.status = "starting";
    this.lastError = undefined;
    const engineRoot = path.join(this.extensionPath, "engine");
    const resolved = await resolvePythonRuntime(this.pythonPath);
    this.runtimeProbe = resolved.probe;
    if (!resolved.probe.available || !resolved.probe.supported) {
      const attempted = resolved.attempts
        .map((attempt) => `${attempt.executable}${attempt.version ? ` (${attempt.version})` : ""}`)
        .slice(0, 8)
        .join(", ");
      const message = `${resolved.probe.error ?? "Python 3.9 or newer with sqlite3 is required."} Configure kiroSecurity.pythonPath, then run Kiro Security: Retry Engine.${attempted ? ` Checked: ${attempted}.` : ""}`;
      this.status = "error";
      this.failureLatched = true;
      this.lastError = message;
      throw new Error(message);
    }
    const env = minimalProcessEnvironment({
      PYTHONPATH: engineRoot,
      PYTHONUNBUFFERED: "1",
      PYTHONIOENCODING: "utf-8",
    });
    this.logger.log("info", "Starting security engine", {
      executable: resolved.invocation.executable,
      pythonVersion: resolved.probe.version,
      workspace: this.workspaceRoot,
    });
    const child = spawn(
      resolved.invocation.executable,
      [...resolved.invocation.args, "-B", "-S", "-m", "kiro_security.server", "--workspace", this.workspaceRoot, "--client-kind", "extension"],
      {
        cwd: this.workspaceRoot,
        env,
        shell: false,
        windowsHide: true,
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    this.child = child;
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => this.consumeStdout(chunk));
    child.stderr.on("data", (chunk: string) => this.consumeStderr(chunk));
    child.on("error", (error) => this.handleProcessFailure(error));
    child.on("exit", (code, signal) => this.handleExit(code, signal));
    try {
      await this.request("initialize", {
        protocolVersion: PROTOCOL_VERSION,
        clientInfo: { name: "kiro-security-power-vsix", version: this.productVersion },
      }, 15_000, false);
      this.status = "ready";
      this.failureLatched = false;
      this.logger.log("info", "Security engine initialized", { pid: child.pid, protocolVersion: PROTOCOL_VERSION });
    } catch (error) {
      this.status = "error";
      this.failureLatched = true;
      this.lastError = error instanceof Error ? error.message : String(error);
      child.kill();
      throw error;
    }
  }

  async retry(): Promise<void> {
    this.failureLatched = false;
    this.lastError = undefined;
    this.runtimeProbe = undefined;
    if (this.child) await this.stop();
    this.status = "stopped";
    await this.start();
  }

  async request<T>(method: string, params: Record<string, unknown> = {}, timeoutMs = 30_000, autoStart = true): Promise<T> {
    if (autoStart) await this.start();
    const child = this.child;
    if (!child || !child.stdin.writable) throw new Error("Security engine is not running.");
    const id = this.nextId++;
    const payload = JSON.stringify({ jsonrpc: "2.0", protocolVersion: PROTOCOL_VERSION, id, method, params });
    if (Buffer.byteLength(payload, "utf8") > 2 * 1024 * 1024) throw new Error("RPC request exceeds the 2 MiB limit.");
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Security engine request timed out: ${method}`));
      }, timeoutMs);
      this.pending.set(id, { resolve: resolve as (value: unknown) => void, reject, timer });
      child.stdin.write(payload + "\n", "utf8", (error) => {
        if (error) {
          const pending = this.pending.get(id);
          if (pending) {
            clearTimeout(pending.timer);
            this.pending.delete(id);
            reject(error);
          }
        }
      });
    });
  }

  private consumeStdout(chunk: string): void {
    this.stdoutBuffer += chunk;
    if (this.stdoutBuffer.length > 8 * 1024 * 1024) {
      this.handleProcessFailure(new Error("Security engine stdout buffer exceeded safety limit."));
      return;
    }
    while (true) {
      const newline = this.stdoutBuffer.indexOf("\n");
      if (newline < 0) break;
      const line = this.stdoutBuffer.slice(0, newline).trim();
      this.stdoutBuffer = this.stdoutBuffer.slice(newline + 1);
      if (!line) continue;
      try {
        const parsed: unknown = JSON.parse(line);
        if (!isRpcEnvelope(parsed)) {
          this.logger.log("warning", "Rejected malformed engine envelope", { preview: redact(line.slice(0, 500)) });
          continue;
        }
        this.handleEnvelope(parsed);
      } catch (error) {
        this.logger.log("warning", "Rejected non-JSON engine output", { error: String(error), preview: redact(line.slice(0, 500)) });
      }
    }
  }

  private consumeStderr(chunk: string): void {
    this.stderrBuffer += chunk;
    while (true) {
      const newline = this.stderrBuffer.indexOf("\n");
      if (newline < 0) break;
      const line = this.stderrBuffer.slice(0, newline).trim();
      this.stderrBuffer = this.stderrBuffer.slice(newline + 1);
      if (line) this.logger.log("warning", "Engine stderr", { line: redact(line) });
    }
  }

  private handleEnvelope(envelope: RpcEnvelope): void {
    if ("method" in envelope) {
      this.eventEmitter.fire({ name: envelope.method, params: envelope.params });
      return;
    }
    if (envelope.id === null) {
      this.logger.log("warning", "Engine returned an uncorrelated error", { envelope });
      return;
    }
    const pending = this.pending.get(envelope.id);
    if (!pending) return;
    clearTimeout(pending.timer);
    this.pending.delete(envelope.id);
    if ("error" in envelope) {
      pending.reject(new EngineRpcError(envelope.error.message, envelope.error.code, envelope.error.data));
    } else {
      pending.resolve(envelope.result);
    }
  }

  private handleProcessFailure(error: Error): void {
    this.status = "error";
    this.failureLatched = true;
    this.lastError = error.message;
    this.logger.log("error", "Security engine process error", { error: redact(error.message) });
    this.rejectAll(error);
  }

  private handleExit(code: number | null, signal: NodeJS.Signals | null): void {
    const expected = this.disposed || this.status === "stopped";
    this.child = undefined;
    if (!expected) {
      this.status = code === 0 ? "stopped" : "error";
      this.failureLatched = code !== 0;
      this.lastError = code === 0 ? undefined : `Engine exited with code ${code ?? "unknown"} (${signal ?? "no signal"}).`;
      this.logger.log(code === 0 ? "info" : "error", "Security engine exited", { code, signal });
    }
    this.rejectAll(new Error(this.lastError ?? "Security engine exited."));
  }

  private rejectAll(error: Error): void {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.pending.clear();
  }

  async stop(): Promise<void> {
    if (!this.child) {
      this.status = "stopped";
      return;
    }
    try {
      if (this.status === "ready") await this.request("shutdown", {}, 7_000, false);
    } catch (error) {
      this.logger.log("warning", "Graceful engine shutdown failed", { error: String(error) });
    }
    const child = this.child;
    if (child && !child.killed) {
      await new Promise<void>((resolve) => {
        const timer = setTimeout(() => {
          if (!child.killed) child.kill();
          resolve();
        }, 2_000);
        child.once("exit", () => {
          clearTimeout(timer);
          resolve();
        });
      });
    }
    this.status = "stopped";
    this.child = undefined;
  }

  dispose(): void {
    this.disposed = true;
    void this.stop();
    this.eventEmitter.dispose();
  }
}
