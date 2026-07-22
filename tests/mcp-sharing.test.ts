import test from "node:test";
import assert from "node:assert/strict";
import { ChildProcessWithoutNullStreams, spawn, spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { PROTOCOL_VERSION } from "../packages/protocol/src";

const root = path.resolve(__dirname, "..", "..");
class LineRpc {
  private nextId = 1;
  private buffer = "";
  private pending = new Map<number, { resolve(value: any): void; reject(error: Error): void; timer: NodeJS.Timeout }>();
  constructor(readonly child: ChildProcessWithoutNullStreams, readonly engineProtocol = false) {
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => this.consume(chunk));
    child.stderr.setEncoding("utf8");
  }
  private consume(chunk: string): void {
    this.buffer += chunk;
    for (;;) {
      const index = this.buffer.indexOf("\n");
      if (index < 0) break;
      const line = this.buffer.slice(0, index).trim();
      this.buffer = this.buffer.slice(index + 1);
      if (!line) continue;
      const message = JSON.parse(line);
      if (typeof message.id !== "number") continue;
      const pending = this.pending.get(message.id);
      if (!pending) continue;
      clearTimeout(pending.timer);
      this.pending.delete(message.id);
      if (message.error) pending.reject(new Error(message.error.message));
      else pending.resolve(message.result);
    }
  }
  request(method: string, params: Record<string, unknown> = {}, timeoutMs = 30_000): Promise<any> {
    const id = this.nextId++;
    const request: any = { jsonrpc: "2.0", id, method, params };
    if (this.engineProtocol) request.protocolVersion = PROTOCOL_VERSION;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error(`timeout: ${method}`)); }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.child.stdin.write(JSON.stringify(request) + "\n");
    });
  }
  async stop(): Promise<void> {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error("RPC client stopped."));
    }
    this.pending.clear();
    if (!this.child.stdin.destroyed) this.child.stdin.end();
    if (!await waitForChildExit(this.child, 7_500)) {
      this.child.kill("SIGTERM");
      if (!await waitForChildExit(this.child, 2_500) && process.platform !== "win32") {
        this.child.kill("SIGKILL");
        await waitForChildExit(this.child, 1_000);
      }
    }
    this.child.stdout.destroy();
    this.child.stderr.destroy();
  }
}

function waitForChildExit(child: ChildProcessWithoutNullStreams, timeoutMs: number): Promise<boolean> {
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

function git(cwd: string, args: string[]): void {
  const result = spawnSync("git", args, { cwd, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
}

async function waitForScan(mcp: LineRpc, workspaceRoot: string, scanId: string): Promise<any> {
  const deadline = Date.now() + 30_000;
  for (;;) {
    const response = await mcp.request("tools/call", { name: "security_get_scan", arguments: { workspaceRoot, scanId } });
    assert.equal(response.isError, false, response.content?.[0]?.text);
    const scan = response.structuredContent.result;
    if (scan.status !== "running") return scan;
    if (Date.now() > deadline) throw new Error(`scan ${scanId} did not finish`);
    await new Promise((resolve) => setTimeout(resolve, 80));
  }
}

test("MCP and a second engine client share Skill-driven scan lifecycle state", { timeout: 45_000 }, async () => {
  const temporary = mkdtempSync(path.join(os.tmpdir(), "kiro-security-mcp-"));
  const workspace = path.join(temporary, "workspace");
  cpSync(path.join(root, "fixtures", "vulnerable-repo"), workspace, { recursive: true, filter: (source) => !source.includes(`${path.sep}.git`) && !source.includes(`${path.sep}.kiro`) });
  git(workspace, ["init"]);
  git(workspace, ["config", "user.email", "test@example.invalid"]);
  git(workspace, ["config", "user.name", "Test"]);
  git(workspace, ["add", "."]);
  git(workspace, ["commit", "-m", "fixture"]);

  const mcpChild = spawn(process.execPath, [path.join(root, "dist", "mcp", "server.mjs")], { cwd: root, env: { ...process.env, KIRO_SECURITY_PYTHON: "python3" }, stdio: ["pipe", "pipe", "pipe"] });
  const mcp = new LineRpc(mcpChild);
  const engineChild = spawn("python3", ["-m", "kiro_security.server", "--workspace", workspace, "--client-kind", "test"], { cwd: workspace, env: { ...process.env, PYTHONPATH: path.join(root, "engine"), PYTHONUNBUFFERED: "1" }, stdio: ["pipe", "pipe", "pipe"] });
  const engine = new LineRpc(engineChild, true);
  try {
    const init = await mcp.request("initialize", { protocolVersion: "2025-06-18", clientInfo: { name: "contract-test", version: "1" }, capabilities: {} });
    assert.equal(init.serverInfo.name, "kiro-security-power");
    const tools = await mcp.request("tools/list", {});
    assert.equal(tools.tools.some((tool: any) => tool.name === "security_start_scan"), true);
    assert.equal(tools.tools.some((tool: any) => tool.name === "security_create_tracking_handoff"), true);
    assert.equal(tools.tools.some((tool: any) => tool.name === "security_validate_finding"), false);

    await engine.request("initialize", { protocolVersion: PROTOCOL_VERSION, clientInfo: { name: "sharing-test", version: "1" } });
    const started = await mcp.request("tools/call", {
      name: "security_start_scan",
      arguments: {
        workspaceRoot: workspace, taskId: "contract-task", mode: "standard", scope: ".",
      },
    });
    assert.equal(started.isError, false, started.content?.[0]?.text);
    const startedScan = started.structuredContent.result;
    assert.equal(startedScan.sessionId, startedScan.workspace_id);
    const scanId = startedScan.id;
    const mcpLease = startedScan.coordinatorLease;

    const sharedDuringRun = await engine.request("get_scan", { scanId });
    assert.equal(sharedDuringRun.id, scanId);
    await assert.rejects(engine.request("cancel_scan", { scanId }), /coordinatorToken/);
    const cancelledThroughMcp = await mcp.request("tools/call", {
      name: "security_cancel_scan",
      arguments: {
        workspaceRoot: workspace, scanId,
        coordinatorToken: mcpLease.token,
        coordinatorGeneration: mcpLease.generation,
      },
    });
    assert.equal(cancelledThroughMcp.isError, false, cancelledThroughMcp.content?.[0]?.text);
    const cancelled = await waitForScan(mcp, workspace, scanId);
    assert.equal(cancelled.status, "cancelled", cancelled.failure_message);

    const startedByExtensionSide = await engine.request(
      "start_scan", { taskId: "contract-task", mode: "standard", scope: "." },
    );
    const visibleThroughMcp = await mcp.request("tools/call", {
      name: "security_get_scan", arguments: { workspaceRoot: workspace, scanId: startedByExtensionSide.id },
    });
    assert.equal(visibleThroughMcp.isError, false, visibleThroughMcp.content?.[0]?.text);
    assert.equal(visibleThroughMcp.structuredContent.result.id, startedByExtensionSide.id);
    assert.equal(visibleThroughMcp.structuredContent.result.status, "running");
    const repeatedThroughMcp = await mcp.request("tools/call", {
      name: "security_start_scan",
      arguments: {
        workspaceRoot: workspace, taskId: "contract-task",
        sessionId: startedByExtensionSide.workspace_id,
        mode: "standard", scope: ".",
      },
    });
    assert.equal(repeatedThroughMcp.isError, false, repeatedThroughMcp.content?.[0]?.text);
    assert.equal(repeatedThroughMcp.structuredContent.result.id, startedByExtensionSide.id);
    assert.equal(repeatedThroughMcp.structuredContent.result.coordinatorLease.state, "busy");
    assert.equal(repeatedThroughMcp.structuredContent.result.coordinatorLease.token, undefined);

    const shutdown = await engine.request("shutdown", {});
    assert.deepEqual(shutdown.releasedCoordinatorLeaseScanIds, [startedByExtensionSide.id]);
    const durable = await mcp.request("tools/call", {
      name: "security_get_scan",
      arguments: { workspaceRoot: workspace, scanId: startedByExtensionSide.id },
    });
    assert.equal(durable.structuredContent.result.status, "running");

    const acquired = await mcp.request("tools/call", {
      name: "security_acquire_scan_coordinator",
      arguments: { workspaceRoot: workspace, scanId: startedByExtensionSide.id },
    });
    assert.equal(acquired.isError, false, acquired.content?.[0]?.text);
    const acquiredLease = acquired.structuredContent.result.coordinatorLease;
    const progressed = await mcp.request("tools/call", {
      name: "security_update_scan_progress",
      arguments: {
        workspaceRoot: workspace,
        scanId: startedByExtensionSide.id,
        coordinatorToken: acquiredLease.token,
        coordinatorGeneration: acquiredLease.generation,
        phasePercent: 25,
      },
    });
    assert.equal(progressed.isError, false, progressed.content?.[0]?.text);
    assert.equal(progressed.structuredContent.result.phase_percent, 25);
    const cancelledAfterHandoff = await mcp.request("tools/call", {
      name: "security_cancel_scan",
      arguments: {
        workspaceRoot: workspace,
        scanId: startedByExtensionSide.id,
        coordinatorToken: acquiredLease.token,
        coordinatorGeneration: acquiredLease.generation,
      },
    });
    assert.equal(cancelledAfterHandoff.isError, false, cancelledAfterHandoff.content?.[0]?.text);
    assert.equal(cancelledAfterHandoff.structuredContent.result.status, "cancelled");

  } finally {
    try { await engine.request("shutdown", {}, 10_000); } catch { /* ignored */ }
    await Promise.allSettled([engine.stop(), mcp.stop()]);
    rmSync(temporary, { recursive: true, force: true });
  }
});
