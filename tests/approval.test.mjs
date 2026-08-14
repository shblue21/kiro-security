import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import {
  mkdir,
  mkdtemp,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  require,
  TEST_SERVER_KEY,
} from "./support.mjs";

test("direct MCP config keeps Start and Cancel on the explicit approval boundary", () => {
  const {
    MCP_MANAGED_MARKER,
    buildDirectMcpContract,
    buildDirectMcpServerConfiguration,
  } = require("../out/packages/extension/src/integration/integrationConfig.js");
  const contract = buildDirectMcpContract(TEST_SERVER_KEY);
  const configuration = buildDirectMcpServerConfiguration({
    serverKey: TEST_SERVER_KEY,
    pythonExecutable: "/runtime/python3",
    launcherPath: "/global/runtime/kiro_security_launcher.py",
    stateRoot: "/global/state",
    scanRoot: "/global/state/scans",
  });
  assert.deepEqual(configuration.args, ["-B", "-S", "/global/runtime/kiro_security_launcher.py"]);
  assert.equal(configuration.env.KIRO_SECURITY_MANAGED_BY, MCP_MANAGED_MARKER);
  assert.equal(configuration.timeout, 900_000);
  assert.equal("autoApprove" in configuration, false);
  assert.ok(contract.toolIds.every((toolId) => toolId.length <= 64));
});

test("Trust v2 policy allows setup tools and asks only for Start and Cancel", async () => {
  const {
    buildApprovalPolicyRules,
    inspectApprovalPolicy,
    installApprovalPolicy,
  } = require("../out/packages/extension/src/integration/approvalPolicy.js");
  const {
    AUTO_APPROVED_MCP_TOOLS,
    MANUAL_APPROVAL_MCP_TOOLS,
  } = require("../out/packages/extension/src/integration/integrationConfig.js");
  const temporary = await mkdtemp(join(tmpdir(), "kiro-approval-policy-test-"));
  try {
    const settings = join(temporary, ".kiro", "settings");
    const policyPath = join(settings, "permissions.yaml");
    await mkdir(settings, { recursive: true });
    await writeFile(
      policyPath,
      [
        "# Preserve this user rule",
        "rules:",
        "  - capability: fs_read",
        "    match:",
        '      - "./**"',
        "    effect: allow",
        "",
      ].join("\n"),
      { encoding: "utf8", mode: 0o640 },
    );

    const required = buildApprovalPolicyRules(TEST_SERVER_KEY);
    assert.deepEqual(required[0], {
      capability: "skill",
      match: ["kiro-security"],
      effect: "allow",
    });
    assert.deepEqual(
      required[1].match,
      AUTO_APPROVED_MCP_TOOLS.map(
        (name) => `${TEST_SERVER_KEY}/${name}`,
      ),
    );
    assert.deepEqual(
      required[2].match,
      MANUAL_APPROVAL_MCP_TOOLS.map(
        (name) => `${TEST_SERVER_KEY}/${name}`,
      ),
    );
    assert.equal(required[2].effect, "ask");
    assert.equal(
      required[1].match.some((match) => /start_scan|cancel_scan/.test(match)),
      false,
    );
    assert.equal(
      required[1].match.some((match) =>
        match.endsWith("/kiro_security_read_scan_artifact"),
      ),
      true,
    );

    assert.equal(
      (await inspectApprovalPolicy({
        serverKey: TEST_SERVER_KEY,
        homeDirectory: temporary,
      })).state,
      "mismatch",
    );
    assert.equal(
      (await installApprovalPolicy({
        serverKey: TEST_SERVER_KEY,
        homeDirectory: temporary,
      })).changed,
      true,
    );
    const installed = readFileSync(policyPath, "utf8");
    assert.match(installed, /Preserve this user rule/);
    assert.match(installed, /capability: fs_read/);
    assert.equal(
      (await inspectApprovalPolicy({
        serverKey: TEST_SERVER_KEY,
        homeDirectory: temporary,
      })).state,
      "installed",
    );
    assert.equal(
      (await installApprovalPolicy({
        serverKey: TEST_SERVER_KEY,
        homeDirectory: temporary,
      })).changed,
      false,
    );
    if (process.platform !== "win32") {
      assert.equal((await stat(policyPath)).mode & 0o777, 0o640);
    }

    const freshHome = join(temporary, "fresh-home");
    await installApprovalPolicy({
      serverKey: TEST_SERVER_KEY,
      homeDirectory: freshHome,
    });
    const freshPolicy = readFileSync(
      join(freshHome, ".kiro", "settings", "permissions.yaml"),
      "utf8",
    );
    assert.match(freshPolicy, /rules:\n  - capability: skill/);
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});

test("Trust v2 policy removes only stale generated MCP matches", async () => {
  const { installApprovalPolicy } = require(
    "../out/packages/extension/src/integration/approvalPolicy.js",
  );
  const { parse } = require("yaml");
  const temporary = await mkdtemp(join(tmpdir(), "kiro-approval-stale-test-"));
  const staleKey = "ksp_bbbbbbbbbbbbbbbbbbbb";
  try {
    const settings = join(temporary, ".kiro", "settings");
    const policyPath = join(settings, "permissions.yaml");
    await mkdir(settings, { recursive: true });
    await writeFile(
      policyPath,
      `# Preserve user policy
rules:
  - capability: mcp
    match: [${staleKey}/kiro_security_get_capabilities]
    effect: allow
  - capability: mcp
    match: [${staleKey}/kiro_security_start_scan]
    effect: ask
  - capability: mcp
    match: [${staleKey}/kiro_security_get_workspace, company/custom_tool]
    effect: allow
`,
      "utf8",
    );

    assert.equal(
      (await installApprovalPolicy({
        serverKey: TEST_SERVER_KEY,
        staleServerKeys: [staleKey],
        homeDirectory: temporary,
      })).changed,
      true,
    );
    const installed = readFileSync(policyPath, "utf8");
    const rules = parse(installed).rules;
    assert.match(installed, /Preserve user policy/);
    assert.ok(
      rules.some(
        (rule) =>
          rule.effect === "allow" &&
          rule.match?.includes("company/custom_tool") &&
          rule.match?.includes(`${staleKey}/kiro_security_get_workspace`),
      ),
    );
    assert.equal(
      rules.some(
        (rule) =>
          rule.match?.includes(`${staleKey}/kiro_security_get_capabilities`) ||
          rule.match?.includes(`${staleKey}/kiro_security_start_scan`),
      ),
      false,
    );
    assert.equal(
      (await installApprovalPolicy({
        serverKey: TEST_SERVER_KEY,
        staleServerKeys: [staleKey],
        homeDirectory: temporary,
      })).changed,
      false,
    );
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});

test("Trust v2 policy supports JSON and refuses malformed shared files", async () => {
  const {
    inspectApprovalPolicy,
    installApprovalPolicy,
  } = require("../out/packages/extension/src/integration/approvalPolicy.js");
  const temporary = await mkdtemp(join(tmpdir(), "kiro-approval-json-test-"));
  const staleKey = "ksp_bbbbbbbbbbbbbbbbbbbb";
  try {
    const settings = join(temporary, ".kiro", "settings");
    const jsonPath = join(settings, "permissions.json");
    await mkdir(settings, { recursive: true });
    await writeFile(
      jsonPath,
      `${JSON.stringify({
        rules: [{
          capability: "mcp",
          match: [`${staleKey}/kiro_security_get_capabilities`],
          effect: "allow",
        }],
      })}\n`,
      "utf8",
    );
    assert.equal(
      (await installApprovalPolicy({
        serverKey: TEST_SERVER_KEY,
        staleServerKeys: [staleKey],
        homeDirectory: temporary,
      })).changed,
      true,
    );
    const parsed = JSON.parse(readFileSync(jsonPath, "utf8"));
    assert.doesNotMatch(readFileSync(jsonPath, "utf8"), new RegExp(staleKey));
    assert.ok(
      parsed.rules.some(
        (rule) =>
          rule.capability === "mcp" &&
          rule.effect === "ask" &&
          rule.match.includes(
            `${TEST_SERVER_KEY}/kiro_security_start_scan`,
          ),
      ),
    );

    await writeFile(jsonPath, '{"rules":[],"rules":[]}\n', "utf8");
    const inspection = await inspectApprovalPolicy({
      serverKey: TEST_SERVER_KEY,
      homeDirectory: temporary,
    });
    assert.equal(inspection.state, "conflict");
    assert.match(inspection.detail, /duplicate JSON object key/);
    await assert.rejects(
      installApprovalPolicy({
        serverKey: TEST_SERVER_KEY,
        homeDirectory: temporary,
      }),
      /duplicate JSON object key/,
    );
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});

test("Trust v2 policy reports effective Kiro Security conflicts without changing user rules", async () => {
  const {
    inspectApprovalPolicy,
    installApprovalPolicy,
  } = require("../out/packages/extension/src/integration/approvalPolicy.js");
  const temporary = await mkdtemp(join(tmpdir(), "kiro-approval-conflict-test-"));
  try {
    async function assertConflict(name, rule, effect) {
      const homeDirectory = join(temporary, name);
      const settings = join(homeDirectory, ".kiro", "settings");
      const policyPath = join(settings, "permissions.yaml");
      await mkdir(settings, { recursive: true });
      const original = `# User-owned policy\nrules:\n${rule}\n`;
      await writeFile(policyPath, original, "utf8");
      const inspection = await inspectApprovalPolicy({
        serverKey: TEST_SERVER_KEY,
        homeDirectory,
      });
      assert.equal(inspection.state, "conflict", name);
      assert.match(inspection.detail, effect);
      await assert.rejects(
        installApprovalPolicy({ serverKey: TEST_SERVER_KEY, homeDirectory }),
        effect,
      );
      assert.equal(readFileSync(policyPath, "utf8"), original, name);
    }

    await assertConflict(
      "manual-deny",
      `  - capability: mcp\n    match: [\"${TEST_SERVER_KEY}/kiro_security_start_scan\"]\n    effect: deny`,
      /apply deny/,
    );
    await assertConflict(
      "wildcard-ask",
      `  - capability: mcp\n    match: [\"${TEST_SERVER_KEY}/**\"]\n    effect: ask`,
      /apply ask/,
    );

    const compatibleHome = join(temporary, "compatible");
    const compatibleSettings = join(compatibleHome, ".kiro", "settings");
    const compatiblePath = join(compatibleSettings, "permissions.yaml");
    await mkdir(compatibleSettings, { recursive: true });
    await writeFile(
      compatiblePath,
      `rules:\n  - capability: all\n    match: [\"*\"]\n    exclude: [\"${TEST_SERVER_KEY}/**\", \"kiro-security\"]\n    effect: deny\n  - capability: mcp\n    match: [\"${TEST_SERVER_KEY}/kiro_security_start_scan\"]\n    effect: allow\n`,
      "utf8",
    );
    assert.equal(
      (await installApprovalPolicy({
        serverKey: TEST_SERVER_KEY,
        homeDirectory: compatibleHome,
      })).changed,
      true,
    );
    assert.equal(
      (await inspectApprovalPolicy({
        serverKey: TEST_SERVER_KEY,
        homeDirectory: compatibleHome,
      })).state,
      "installed",
    );
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});

test("concurrent Trust v2 installs preserve every Kiro Security rule", async () => {
  const { installApprovalPolicy } = require(
    "../out/packages/extension/src/integration/approvalPolicy.js",
  );
  const temporary = await mkdtemp(join(tmpdir(), "kiro-approval-lock-test-"));
  try {
    const settings = join(temporary, ".kiro", "settings");
    const policyPath = join(settings, "permissions.yaml");
    await mkdir(settings, { recursive: true });
    await writeFile(
      policyPath,
      "rules:\n  - capability: fs_read\n    match: [\"./**\"]\n    effect: allow\n",
      "utf8",
    );
    const serverKeys = [
      "ksp_aaaaaaaaaaaaaaaaaaaa",
      "ksp_bbbbbbbbbbbbbbbbbbbb",
    ];
    await Promise.all(
      serverKeys.map((serverKey) =>
        installApprovalPolicy({ serverKey, homeDirectory: temporary }),
      ),
    );
    const installed = readFileSync(policyPath, "utf8");
    assert.match(installed, /capability: fs_read/);
    for (const serverKey of serverKeys) {
      assert.match(installed, new RegExp(`${serverKey}/kiro_security_start_scan`));
      assert.match(installed, new RegExp(`${serverKey}/kiro_security_get_capabilities`));
    }
    assert.equal(existsSync(`${policyPath}.lock`), false);
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});
