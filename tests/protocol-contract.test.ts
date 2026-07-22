import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";
import {
  PROTOCOL_VERSION,
  SCAN_MODES,
  SCAN_PHASES,
  isRpcEnvelope,
  validateWebviewMessage,
} from "../packages/protocol/src";

const root = path.resolve(__dirname, "..", "..");

test("TypeScript and Python expose the same protocol constants", () => {
  const result = spawnSync("python3", ["-c", [
    "import json",
    "from kiro_security.constants import PROTOCOL_VERSION, MODES, PHASES",
    "print(json.dumps({'protocol': PROTOCOL_VERSION, 'modes': MODES, 'phases': PHASES}))",
  ].join("; ")], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, PYTHONPATH: path.join(root, "engine") },
  });
  assert.equal(result.status, 0, result.stderr);
  const python = JSON.parse(result.stdout.trim());
  assert.equal(python.protocol, PROTOCOL_VERSION);
  assert.deepEqual(python.modes, [...SCAN_MODES]);
  assert.deepEqual(python.phases, [...SCAN_PHASES]);
});

test("protocol JSON schema declares the engine protocol version", () => {
  const schema = JSON.parse(readFileSync(path.join(root, "engine", "schemas", "protocol.schema.json"), "utf8"));
  const serialized = JSON.stringify(schema);
  assert.match(serialized, new RegExp(PROTOCOL_VERSION.replace(".", "\\.")));
  assert.match(serialized, /scan\.phaseChanged/);
  assert.match(serialized, /artifact\.created/);
});

test("RPC envelope validation rejects version mismatches and malformed notifications", () => {
  assert.equal(isRpcEnvelope({ jsonrpc: "2.0", protocolVersion: PROTOCOL_VERSION, id: 1, result: {} }), true);
  assert.equal(isRpcEnvelope({ jsonrpc: "2.0", protocolVersion: "0.9", id: 1, result: {} }), false);
  assert.equal(isRpcEnvelope({ jsonrpc: "2.0", protocolVersion: PROTOCOL_VERSION, method: "unknown.event", params: {} }), false);
  assert.equal(isRpcEnvelope({ jsonrpc: "2.0", protocolVersion: PROTOCOL_VERSION, method: "scan.progress", params: [] }), false);
  assert.equal(isRpcEnvelope({ jsonrpc: "2.0", protocolVersion: PROTOCOL_VERSION, method: "scan.integrityIssue", params: {} }), true);
  assert.equal(isRpcEnvelope({ jsonrpc: "2.0", protocolVersion: PROTOCOL_VERSION, id: 1, result: {}, error: { code: -32000, message: "bad" } }), false);
  assert.equal(isRpcEnvelope({ jsonrpc: "2.0", protocolVersion: PROTOCOL_VERSION, method: "scan.progress", params: {}, id: 1 }), false);
  assert.equal(isRpcEnvelope({ jsonrpc: "2.0", protocolVersion: PROTOCOL_VERSION, id: null, error: { code: -32000, message: "bad" } }), false);
});

test("webview messages are allowlisted and bounded", () => {
  assert.deepEqual(validateWebviewMessage({ type: "openSource", occurrenceId: "occ_123" }), { type: "openSource", occurrenceId: "occ_123" });
  assert.deepEqual(validateWebviewMessage({ type: "createTrackingHandoff", occurrenceId: "occ_123", provider: "github" }), { type: "createTrackingHandoff", occurrenceId: "occ_123", provider: "github" });
  assert.deepEqual(validateWebviewMessage({ type: "cleanupScan", scanId: "scan_123" }), { type: "cleanupScan", scanId: "scan_123" });
  assert.deepEqual(validateWebviewMessage({ type: "exportFinding", occurrenceId: "occ_123", format: "json" }), { type: "exportFinding", occurrenceId: "occ_123", format: "json" });
  assert.deepEqual(validateWebviewMessage({ type: "installAgentIntegration", scope: "workspace", autoApprovePolicy: "read_only" }), { type: "installAgentIntegration", scope: "workspace", autoApprovePolicy: "read_only" });
  assert.deepEqual(validateWebviewMessage({ type: "openMcpConfig", scope: "user" }), { type: "openMcpConfig", scope: "user" });
  assert.deepEqual(validateWebviewMessage({ type: "copyPowerPath" }), { type: "copyPowerPath" });
  assert.equal(validateWebviewMessage({ type: "installAgentIntegration", scope: "workspace", autoApprovePolicy: "all" }), undefined);
  assert.equal(validateWebviewMessage({ type: "installAgentIntegration", scope: "outside", autoApprovePolicy: "none" }), undefined);
  assert.equal(validateWebviewMessage({ type: "installAgentIntegration", scope: "system", autoApprovePolicy: "all" }), undefined);
  assert.equal(validateWebviewMessage({ type: "createTrackingHandoff", occurrenceId: "occ_123", provider: "unknown" }), undefined);
  assert.equal(validateWebviewMessage({ type: "startScan", mode: "deep", scope: "src" }), undefined);
  assert.equal(validateWebviewMessage({ type: "resumeScan", scanId: "scan_123" }), undefined);
  assert.equal(validateWebviewMessage({ type: "cancelScan", scanId: "scan_123" }), undefined);
  assert.equal(validateWebviewMessage({ type: "openArtifact", path: "x\0y" }), undefined);
  assert.equal(validateWebviewMessage({ type: "prototype", __proto__: { polluted: true } }), undefined);
});
