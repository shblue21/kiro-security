import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import {
  mkdir,
  mkdtemp,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

import {
  pythonExecutable,
  require,
  TEST_SERVER_KEY,
} from "./support.mjs";

test("Hook registration matches only the exact direct MCP tool IDs", () => {
  const {
    buildHookRegistrationDocument,
    getHookBridgePath,
    getHookRegistrationPath,
    HOOK_FILE_NAME,
  } = require("../out/packages/extension/src/integration/chatBindingFiles.js");
  const { buildDirectMcpContract } = require(
    "../out/packages/extension/src/integration/integrationConfig.js",
  );
  const contract = buildDirectMcpContract(TEST_SERVER_KEY);
  const hookPath = getHookRegistrationPath("/users/tester");
  const bridgePath = getHookBridgePath("/global/storage");
  const document = buildHookRegistrationDocument({
    pythonExecutable: "/runtime/python3",
    bridgePath,
    serverKey: TEST_SERVER_KEY,
    platform: "darwin",
  });

  assert.equal(hookPath, join("/users/tester", ".kiro", "hooks", HOOK_FILE_NAME));
  assert.equal(document.hooks[0].trigger, "PreToolUse");
  assert.equal(document.hooks[0].matcher, contract.toolMatcher);
  for (const toolId of contract.toolIds) {
    assert.match(toolId, /^mcp_ksp_aaaaaaaaaaaaaaaaaaaa_/);
    assert.equal(new RegExp(contract.toolMatcher).test(toolId), true);
  }
  assert.equal(new RegExp(contract.toolMatcher).test("kiro_powers"), false);
  assert.equal(new RegExp(contract.toolMatcher).test("fs_read"), false);
  assert.match(document.hooks[0].action.command, /\/runtime\/python3/);
  assert.match(document.hooks[0].action.command, /\/global\/storage\/runtime\/hook-bridge/);
  assert.match(document.hooks[0].action.command, /--server-key 'ksp_aaaaaaaaaaaaaaaaaaaa'/);
  assert.doesNotMatch(JSON.stringify(document), /workbench\.sqlite3|scanRoot/);
});

test("Hook install is idempotent and refreshes its changed dedicated file", async () => {
  const {
    buildHookRegistrationDocument,
    getHookBridgePath,
    getHookRegistrationPath,
    inspectHookRegistration,
    installHookRegistration,
  } = require("../out/packages/extension/src/integration/chatBindingFiles.js");
  const temporary = await mkdtemp(join(tmpdir(), "kiro-hook-files-test-"));
  try {
    const hookPath = getHookRegistrationPath(join(temporary, "home"));
    const document = buildHookRegistrationDocument({
      pythonExecutable: "/runtime/python3",
      bridgePath: getHookBridgePath(join(temporary, "global-storage")),
      serverKey: TEST_SERVER_KEY,
      platform: "darwin",
    });
    assert.equal((await inspectHookRegistration({ hookPath, expected: document })).state, "absent");
    assert.equal((await installHookRegistration({ hookPath, document })).changed, true);
    assert.equal((await inspectHookRegistration({ hookPath, expected: document })).state, "installed");
    if (process.platform !== "win32") {
      assert.equal((await stat(hookPath)).mode & 0o777, 0o600);
    }
    assert.equal((await installHookRegistration({ hookPath, document })).changed, false);

    const drifted = { ...document, hooks: [{ ...document.hooks[0], timeout: 11 }] };
    await writeFile(hookPath, `${JSON.stringify(drifted, null, 2)}\n`, "utf8");
    assert.equal((await inspectHookRegistration({ hookPath, expected: document })).state, "mismatch");
    assert.equal((await installHookRegistration({ hookPath, document })).changed, true);
    assert.deepEqual(JSON.parse(readFileSync(hookPath, "utf8")), document);
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});

test("dedicated Hook path refuses symlink targets", async () => {
  if (process.platform === "win32") {
    return;
  }
  const {
    buildHookRegistrationDocument,
    getHookRegistrationPath,
    inspectHookRegistration,
    installHookRegistration,
  } = require("../out/packages/extension/src/integration/chatBindingFiles.js");
  const temporary = await mkdtemp(join(tmpdir(), "kiro-hook-conflict-test-"));
  try {
    const hookPath = getHookRegistrationPath(join(temporary, "home"));
    await mkdir(join(temporary, "home", ".kiro", "hooks"), { recursive: true });
    const target = join(temporary, "other-hook.json");
    await writeFile(target, '{"version":"v1","hooks":[]}\n', "utf8");
    await symlink(target, hookPath);
    const document = buildHookRegistrationDocument({
      pythonExecutable: "/runtime/python3",
      bridgePath: join(temporary, "state", "runtime", "bridge.py"),
      serverKey: TEST_SERVER_KEY,
      platform: "darwin",
    });
    assert.equal((await inspectHookRegistration({ hookPath, expected: document })).state, "conflict");
    await assert.rejects(
      installHookRegistration({ hookPath, document }),
      /symlink/,
    );
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});

test("Hook bridge binds host session identity to exact direct MCP calls", async () => {
  const {
    buildHookBridgeProbe,
    getHookBridgePath,
    getPackagedHookBridgePath,
    inspectHookBridge,
    materializeHookBridge,
  } = require("../out/packages/extension/src/integration/chatBindingFiles.js");
  const {
    buildDirectMcpContract,
    MCP_TOOL_NAMES,
  } = require(
    "../out/packages/extension/src/integration/integrationConfig.js",
  );
  const directContract = buildDirectMcpContract(TEST_SERVER_KEY);
  const temporary = await mkdtemp(join(tmpdir(), "kiro-hook-bridge-test-"));
  try {
    const sourcePath = getPackagedHookBridgePath(resolve("."));
    const stateRoot = join(temporary, "global-storage");
    const bridgePath = getHookBridgePath(stateRoot);
    assert.equal(await materializeHookBridge({ sourcePath, bridgePath }), true);
    assert.equal(await materializeHookBridge({ sourcePath, bridgePath }), false);
    assert.equal((await inspectHookBridge({ sourcePath, bridgePath })).ready, true);

    const python = pythonExecutable();
    const contract = JSON.parse(
      execFileSync(
        python,
        [
          "-B",
          "-c",
          "import json,runpy,sys; b=runpy.run_path(sys.argv[1]); print(json.dumps({'map':b['_direct_tool_map'](sys.argv[2]),'ttl':b['ATTESTATION_TTL_SECONDS']}))",
          bridgePath,
          TEST_SERVER_KEY,
        ],
        { encoding: "utf8" },
      ),
    );
    assert.deepEqual(contract.map, Object.fromEntries(directContract.toolIds.map((id, index) => [id, MCP_TOOL_NAMES[index]])));
    assert.equal(contract.ttl, 15 * 60);

    const runBridge = (payload) =>
      spawnSync(python, ["-B", bridgePath, "--server-key", TEST_SERVER_KEY], {
        encoding: "utf8",
        input: JSON.stringify(payload),
      });
    assert.equal(runBridge(buildHookBridgeProbe(temporary)).status, 0);
    assert.equal(existsSync(join(stateRoot, "workbench.sqlite3")), false);
    execFileSync(
      python,
      [
        "-B",
        "-S",
        "-c",
        "import sys; from kiro_security.workbench import Workbench; Workbench(sys.argv[1], sys.argv[2])",
        stateRoot,
        join(stateRoot, "scans"),
      ],
      { env: { ...process.env, PYTHONPATH: resolve("engine") } },
    );

    for (let index = 0; index < directContract.toolIds.length; index += 1) {
      const valid = runBridge({
        session_id: "chat-a",
        hook_event_name: "PreToolUse",
        cwd: temporary,
        tool_name: directContract.toolIds[index],
        tool_input: { requestNonce: randomUUID() },
      });
      assert.equal(valid.status, 0, MCP_TOOL_NAMES[index]);
      assert.equal(valid.stderr, "", MCP_TOOL_NAMES[index]);
    }

    const base = {
      hook_event_name: "PreToolUse",
      cwd: temporary,
      tool_name: directContract.toolIds[0],
      tool_input: { requestNonce: randomUUID() },
    };
    const missingSession = runBridge(base);
    assert.equal(missingSession.status, 2);
    assert.match(missingSession.stderr, /session_id/);
    const missingNonce = runBridge({ ...base, session_id: "chat-a", tool_input: {} });
    assert.equal(missingNonce.status, 2);
    assert.match(missingNonce.stderr, /requestNonce/);
    const unrelated = runBridge({
      hook_event_name: "PreToolUse",
      tool_name: "fs_read",
      tool_input: { data: "x".repeat(1024 * 1024) },
    });
    assert.equal(unrelated.status, 0);
    const malformedEvent = runBridge({ ...base, session_id: "chat-a", hook_event_name: [] });
    assert.equal(malformedEvent.status, 2);
    assert.doesNotMatch(malformedEvent.stderr, /Traceback|TypeError/);
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});
