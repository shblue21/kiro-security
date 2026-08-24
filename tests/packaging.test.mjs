import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";

import { manifest } from "./support.mjs";

test("extension manifest exposes setup without a Power-import command", () => {
  assert.equal(manifest.main, "./out/packages/extension/src/extension.js");
  assert.deepEqual(manifest.extensionKind, ["workspace"]);
  assert.deepEqual(manifest.activationEvents, [
    "onStartupFinished",
    "onView:kiroSecurity.setup",
    "onCommand:kiroSecurity.openSetup",
  ]);
  assert.deepEqual(
    manifest.contributes.commands.map((entry) => entry.command),
    ["kiroSecurity.openSetup"],
  );
  assert.equal(manifest.contributes.views.kiroSecurity[0].id, "kiroSecurity.setup");
  assert.equal(manifest.contributes.viewsContainers.activitybar[0].icon, "media/security.svg");
  assert.equal(
    manifest.contributes.configuration.properties["kiroSecurity.pythonPath"].scope,
    "machine",
  );
  assert.equal(existsSync(manifest.main), true);
});

test("actual VSIX selection contains direct integration assets and no Power entry point", () => {
  const binary = resolve("node_modules", ".bin", process.platform === "win32" ? "vsce.cmd" : "vsce");
  const files = execFileSync(binary, ["ls"], { encoding: "utf8" }).trim().split(/\r?\n/);
  assert.ok(files.includes("package.json"));
  assert.ok(files.includes("media/security.svg"));
  assert.ok(files.includes("hook/kiro_security_hook_bridge.py"));
  assert.ok(files.includes("steering/kiro-security-power.md"));
  assert.ok(files.includes("runtime/kiro_security_launcher.py"));
  assert.ok(files.includes("engine/kiro_security/workbench.py"));
  assert.ok(files.includes("engine/kiro_security/mcp_server.py"));
  assert.ok(files.includes("engine/kiro_security/mcp_tools.py"));
  assert.ok(files.includes("engine/kiro_security/phase_contracts.py"));
  assert.ok(files.includes("engine/kiro_security/scan_files.py"));
  assert.ok(files.includes("engine/kiro_security/semantic_materialization.py"));
  assert.ok(files.includes("node_modules/jsonc-parser/lib/umd/main.js"));
  assert.ok(files.includes("node_modules/graceful-fs/LICENSE"));
  assert.ok(files.includes("node_modules/proper-lockfile/LICENSE"));
  assert.ok(files.includes("node_modules/proper-lockfile/index.js"));
  assert.ok(files.includes("node_modules/retry/License"));
  assert.ok(files.includes("node_modules/signal-exit/LICENSE.txt"));
  assert.ok(files.includes("node_modules/yaml/LICENSE"));
  assert.ok(files.includes("node_modules/yaml/dist/index.js"));
  assert.ok(
    files.includes("out/packages/extension/src/integration/approvalPolicy.js"),
  );
  assert.ok(
    files.includes("out/packages/extension/src/integration/directRuntimeFiles.js"),
  );
  assert.ok(
    files.includes("out/packages/extension/src/integration/integrationConfig.js"),
  );
  assert.ok(
    files.includes("out/packages/extension/src/integration/integrationFiles.js"),
  );
  assert.ok(
    files.includes("out/packages/extension/src/integration/integration.js"),
  );
  assert.ok(
    files.includes("out/packages/extension/src/integration/localFileSafety.js"),
  );
  assert.ok(files.includes("out/packages/extension/src/view/setupView.js"));
  assert.ok(files.includes("out/packages/extension/src/view/setupViewHtml.js"));
  assert.ok(
    files.includes("out/packages/extension/src/view/setupViewScript.js"),
  );
  assert.ok(!files.some((entry) => entry.startsWith("powers/")));
  assert.ok(!files.some((entry) => entry.includes("powerIntegration")));
  assert.ok(!files.some((entry) => entry.startsWith("docs/")));
  assert.ok(!files.some((entry) => entry.startsWith("tests/")));
  assert.ok(!files.some((entry) => entry.startsWith("engine/tests/")));
  assert.ok(!files.some((entry) => entry.startsWith(".od-skills/")));
  assert.ok(!files.some((entry) => entry.startsWith("plugin-source/")));
  assert.ok(!files.some((entry) => /^kiro-security-.*\.html(?:\.artifact\.json)?$/.test(entry)));
  assert.ok(!files.some((entry) => /^image(?:-\d+)?\.png$/.test(entry)));
  assert.ok(!files.some((entry) => entry.includes("__pycache__")));
  assert.ok(!files.some((entry) => entry.endsWith(".pyc")));
});
