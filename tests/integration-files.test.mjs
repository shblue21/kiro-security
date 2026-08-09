import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import {
  mkdir,
  mkdtemp,
  readdir,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  require,
  TEST_SERVER_KEY,
} from "./support.mjs";

test("extension foundation uses one external global workbench boundary", () => {
  const foundation = readFileSync("packages/extension/src/foundation.ts", "utf8");
  assert.match(foundation, /context\.globalStorageUri/);
  assert.match(foundation, /stateRoot\.scheme !== "file"/);
  assert.match(foundation, /stateRoot\.scheme !== "vscode-userdata"/);
  assert.match(foundation, /workbench\.sqlite3/);
  assert.match(foundation, /Uri\.joinPath\(stateRoot, "scans"\)/);
  assert.doesNotMatch(foundation, /workspaceFolders|storageUri/);
});

test("auto-inclusion steering owns normal-chat orchestration without a Power entry point", () => {
  const steering = readFileSync("steering/kiro-security-power.md", "utf8");
  assert.match(steering, /inclusion: auto/);
  assert.match(steering, /Use only when the user explicitly invokes Kiro Security/);
  assert.match(steering, /ordinary Kiro\s+Agent chat/);
  assert.match(steering, /The VSIX and direct\s+`kiro_security_\*` MCP tools own workspace/);
  assert.match(steering, /Never create or require `\.kiro\/security-power`/);
  assert.match(steering, /Use direct `kiro_security_\*` MCP tools only for Kiro Security workspace/);
  assert.match(steering, /Use Kiro's native read, search, directory, terminal, and context-gathering\s+tools to inspect the target repository/);
  assert.doesNotMatch(steering, /Use only direct MCP tools whose names begin/);
  assert.match(steering, /exact returned setup revision,\s+digest, and normalized value/);
  assert.match(steering, /fresh UUID-shaped `requestNonce`/);
  assert.match(steering, /`phaseContract\.readAhead` equal to `false`/);
  assert.match(steering, /preflight -> discovery/);
  assert.match(steering, /kiro_security_complete_scan/);
  assert.ok(
    steering.indexOf("## Activation gate") < steering.indexOf("## Intent routing"),
  );
  assert.match(steering, /Loading this file does not establish that intent/);
  assert.match(steering, /general code, PR, commit, branch, Diff/);
  assert.match(steering, /Security terminology introduced by the Agent, a subagent/);
  assert.match(steering, /do not call any `kiro_security_\*` tool while asking/);
  assert.match(steering, /Only after the activation gate passes, choose one route/);
  assert.match(steering, /Security review of a PR, commit, range, branch, patch, or working tree: Diff/);
  assert.doesNotMatch(
    steering,
    /^- PR, commit, range, branch, patch, or working-tree review: Diff\.$/m,
  );
  assert.doesNotMatch(steering, /^## (Threat-model|Validation|Attack-path) phase/m);
  assert.doesNotMatch(steering, /^## (Standard|Diff|Deep) discovery/m);
  assert.equal(existsSync("powers/kiro-security-power/POWER.md"), false);
  assert.equal(existsSync("powers/kiro-security-power/mcp.json"), false);
});

test("steering install refreshes its changed dedicated file", async () => {
  const { inspectSteering, installSteering } = require(
    "../out/packages/extension/src/integrationFiles.js",
  );
  const temporary = await mkdtemp(join(tmpdir(), "kiro-steering-files-test-"));
  try {
    const sourcePath = join(temporary, "packaged.md");
    const steeringPath = join(temporary, ".kiro", "steering", "kiro-security-power.md");
    await writeFile(sourcePath, "current steering\n", "utf8");

    assert.equal((await inspectSteering({ sourcePath, steeringPath })).state, "absent");
    assert.equal((await installSteering({ sourcePath, steeringPath })).changed, true);
    assert.equal((await inspectSteering({ sourcePath, steeringPath })).state, "installed");

    await writeFile(steeringPath, "previous steering\n", "utf8");
    assert.equal((await inspectSteering({ sourcePath, steeringPath })).state, "mismatch");
    assert.equal((await installSteering({ sourcePath, steeringPath })).changed, true);
    assert.equal(readFileSync(steeringPath, "utf8"), "current steering\n");
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});

test("installation MCP identity is random, persistent, and private", async () => {
  const {
    getIntegrationIdentityPath,
    getOrCreateInstallationServerKey,
  } = require("../out/packages/extension/src/integrationFiles.js");
  const { buildDirectMcpContract, MCP_SERVER_KEY_PATTERN } = require(
    "../out/packages/extension/src/integrationConfig.js",
  );
  const temporary = await mkdtemp(join(tmpdir(), "kiro-integration-identity-test-"));
  try {
    const firstRoot = join(temporary, "first");
    const secondRoot = join(temporary, "second");
    const generated = await Promise.all(
      Array.from({ length: 32 }, () => getOrCreateInstallationServerKey(firstRoot)),
    );
    const first = generated[0];
    const second = await getOrCreateInstallationServerKey(secondRoot);
    assert.match(first, MCP_SERVER_KEY_PATTERN);
    assert.ok(generated.every((value) => value === first));
    assert.notEqual(second, first);
    assert.equal(
      JSON.parse(readFileSync(getIntegrationIdentityPath(firstRoot), "utf8")).serverKey,
      first,
    );
    assert.ok(buildDirectMcpContract(first).toolIds.every((toolId) => toolId.length <= 64));
    assert.deepEqual(
      (await readdir(join(firstRoot, "runtime"))).sort(),
      ["integration-identity.json"],
    );
    if (process.platform !== "win32") {
      assert.equal((await stat(getIntegrationIdentityPath(firstRoot))).mode & 0o777, 0o600);
    }
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});

test("MCP registration install preserves unrelated JSONC entries", async () => {
  const { buildDirectMcpServerConfiguration } = require(
    "../out/packages/extension/src/integrationConfig.js",
  );
  const {
    inspectMcpRegistration,
    installMcpRegistration,
  } = require("../out/packages/extension/src/integrationFiles.js");
  const temporary = await mkdtemp(join(tmpdir(), "kiro-mcp-config-test-"));
  try {
    const mcpPath = join(temporary, ".kiro", "settings", "mcp.json");
    await mkdir(join(temporary, ".kiro", "settings"), { recursive: true, mode: 0o755 });
    const existing = '{\n  // keep this server\n  "mcpServers": {\n    "other": { "command": "other" },\n  },\n}\n';
    await writeFile(mcpPath, existing, { encoding: "utf8", mode: 0o600 });
    const expected = buildDirectMcpServerConfiguration({
      serverKey: TEST_SERVER_KEY,
      pythonExecutable: "/runtime/python3",
      launcherPath: "/global/runtime/launcher.py",
      stateRoot: "/global/state",
      scanRoot: "/global/state/scans",
    });
    assert.equal((await inspectMcpRegistration({ mcpPath, serverKey: TEST_SERVER_KEY, expected })).state, "absent");
    assert.equal((await installMcpRegistration({ mcpPath, serverKey: TEST_SERVER_KEY, expected })).changed, true);
    const installed = readFileSync(mcpPath, "utf8");
    assert.match(installed, /keep this server/);
    assert.match(installed, /"other"/);
    assert.match(installed, new RegExp(`"${TEST_SERVER_KEY}"`));
    assert.equal((await inspectMcpRegistration({ mcpPath, serverKey: TEST_SERVER_KEY, expected })).state, "installed");
    if (process.platform !== "win32") {
      assert.equal((await stat(join(temporary, ".kiro", "settings"))).mode & 0o777, 0o755);
      assert.equal((await stat(mcpPath)).mode & 0o777, 0o600);
    }
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});

test("MCP registration refuses ambiguous duplicate JSONC keys without mutation", async () => {
  const { buildDirectMcpServerConfiguration } = require(
    "../out/packages/extension/src/integrationConfig.js",
  );
  const {
    inspectMcpRegistration,
    installMcpRegistration,
  } = require("../out/packages/extension/src/integrationFiles.js");
  const temporary = await mkdtemp(join(tmpdir(), "kiro-mcp-duplicate-test-"));
  try {
    const mcpPath = join(temporary, "mcp.json");
    const expected = buildDirectMcpServerConfiguration({
      serverKey: TEST_SERVER_KEY,
      pythonExecutable: "/runtime/python3",
      launcherPath: "/global/runtime/launcher.py",
      stateRoot: "/global/state",
      scanRoot: "/global/state/scans",
    });
    const cases = [
      `{
  "mcpServers": { "other": { "command": "other" } },
  "mcpServers": { "${TEST_SERVER_KEY}": ${JSON.stringify(expected)} }
}\n`,
      `{
  "mcpServers": {
    "${TEST_SERVER_KEY}": { "command": "unmanaged" },
    "${TEST_SERVER_KEY}": ${JSON.stringify(expected)}
  }
}\n`,
    ];

    for (const contents of cases) {
      await writeFile(mcpPath, contents, { encoding: "utf8", mode: 0o600 });
      const inspection = await inspectMcpRegistration({
        mcpPath,
        serverKey: TEST_SERVER_KEY,
        expected,
      });
      assert.equal(inspection.state, "conflict");
      assert.match(inspection.detail, /duplicate JSON object key/);
      await assert.rejects(
        installMcpRegistration({
          mcpPath,
          serverKey: TEST_SERVER_KEY,
          expected,
        }),
        /duplicate JSON object key/,
      );
      assert.equal(readFileSync(mcpPath, "utf8"), contents);
    }
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});

test("MCP registration refuses unmanaged key collisions and symlink paths", async () => {
  if (process.platform === "win32") {
    return;
  }
  const { buildDirectMcpServerConfiguration } = require(
    "../out/packages/extension/src/integrationConfig.js",
  );
  const { inspectMcpRegistration, installMcpRegistration } = require(
    "../out/packages/extension/src/integrationFiles.js",
  );
  const temporary = await mkdtemp(join(tmpdir(), "kiro-mcp-conflict-test-"));
  try {
    const expected = buildDirectMcpServerConfiguration({
      serverKey: TEST_SERVER_KEY,
      pythonExecutable: "/runtime/python3",
      launcherPath: "/global/runtime/launcher.py",
      stateRoot: "/global/state",
      scanRoot: "/global/state/scans",
    });
    const collisionPath = join(temporary, "collision.json");
    await writeFile(collisionPath, `${JSON.stringify({ mcpServers: { [TEST_SERVER_KEY]: { command: "user" } } })}\n`, "utf8");
    assert.equal((await inspectMcpRegistration({ mcpPath: collisionPath, serverKey: TEST_SERVER_KEY, expected })).state, "conflict");
    await assert.rejects(
      installMcpRegistration({ mcpPath: collisionPath, serverKey: TEST_SERVER_KEY, expected }),
      /unmanaged/,
    );
    const target = join(temporary, "target.json");
    const link = join(temporary, "mcp.json");
    await writeFile(target, '{"mcpServers":{}}\n', "utf8");
    await symlink(target, link);
    assert.equal((await inspectMcpRegistration({ mcpPath: link, serverKey: TEST_SERVER_KEY, expected })).state, "conflict");
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});
