import test from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { validateWebviewMessage } from "../packages/protocol/src";

const root = path.resolve(__dirname, "..", "..");
const manifest = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
const commands = new Set(manifest.contributes.commands.map((entry: { command: string }) => entry.command));

const required = [
  "kiroSecurity.openPanel",
  "kiroSecurity.openPanelRight",
  "kiroSecurity.refreshThreatModel",
  "kiroSecurity.resumeLastScan",
  "kiroSecurity.cancelActiveScan",
  "kiroSecurity.exportReport",
  "kiroSecurity.openLogs",
  "kiroSecurity.installAgentIntegration",
];

test("manifest contributes every required command and activation route", () => {
  for (const command of required) {
    assert.equal(commands.has(command), true, `missing ${command}`);
    assert.equal(manifest.activationEvents.includes(`onCommand:${command}`) || ["kiroSecurity.openFinding", "kiroSecurity.validateFinding"].includes(command), true, `missing activation for ${command}`);
  }
  assert.equal(manifest.contributes.views.kiroSecurity[0].type, "webview");
  assert.equal(manifest.contributes.viewsWelcome, undefined);
  const commandIds = manifest.contributes.commands.map((entry: { command: string }) => entry.command);
  assert.equal(commandIds.length, 8, "the Command Palette surface stays focused");
  for (const removed of [
    "kiroSecurity.configure",
    "kiroSecurity.revealPowerBundle",
    "kiroSecurity.startFastScan",
    "kiroSecurity.startStandardScan",
    "kiroSecurity.startDeepScan",
    "kiroSecurity.scanGitChanges",
  ]) {
    assert.equal(commandIds.includes(removed), false, `${removed} should be removed`);
  }
  for (const removedSetting of ["kiroSecurity.defaultMode", "kiroSecurity.telemetry.enabled"]) {
    assert.equal(manifest.contributes.configuration.properties[removedSetting], undefined, `${removedSetting} should be removed`);
  }
  assert.equal(manifest.contributes.commands.every((entry: { title: string }) => !entry.title.includes("Kiro Security")), true);
  assert.equal(manifest.capabilities.untrustedWorkspaces.supported, false);
});

test("activation stays quiet: no onboarding notification, Agent setup lives in the panel", () => {
  const extensionSource = readFileSync(path.join(root, "packages", "extension", "src", "extension.ts"), "utf8");
  const controllerSource = readFileSync(path.join(root, "packages", "extension", "src", "controller.ts"), "utf8");
  assert.doesNotMatch(extensionSource, /offerAgentOnboarding/);
  assert.doesNotMatch(controllerSource, /offerAgentOnboarding/);
  assert.match(extensionSource, /onDidGrantWorkspaceTrust/);
});

test("webview command routes reject forged scan modes and traversal scope is left for host validation", () => {
  assert.equal(validateWebviewMessage({ type: "startScan", mode: "standard", scope: "src" })?.type, "startScan");
  assert.equal(validateWebviewMessage({ type: "startScan", mode: "arbitrary", scope: "src" }), undefined);
  const traversal = validateWebviewMessage({ type: "startScan", mode: "standard", scope: "../outside" });
  assert.equal(traversal?.type, "startScan", "shape validation should pass bounded strings; extension host enforces workspace containment");
  const controllerSource = readFileSync(path.join(root, "packages", "extension", "src", "controller.ts"), "utf8");
  const startScan = controllerSource.slice(controllerSource.indexOf("async startScan("), controllerSource.indexOf("async startScanForUri"));
  assert.match(startScan, /clipboard\.writeText\(prompt\)/);
  assert.doesNotMatch(startScan, /must be started from Kiro Agent/);
});


test("Bash Kiro verification handoff resolves the configured extension ID", { skip: process.platform === "win32" }, () => {
  const temp = mkdtempSync(path.join(os.tmpdir(), "kiro-security-script-test-"));
  const fakeKiro = path.join(temp, "kiro");
  const dummyVsix = path.join(temp, "product.vsix");
  writeFileSync(dummyVsix, "not a real archive", "utf8");
  writeFileSync(fakeKiro, `#!/usr/bin/env bash
case " $* " in
  *" --list-extensions "*) printf '%s\\n' '${manifest.publisher}.${manifest.name}@${manifest.version}' ;;
esac
exit 0
`, "utf8");
  chmodSync(fakeKiro, 0o755);

  const result = spawnSync("bash", [path.join(root, "scripts", "verify-in-kiro.sh"), dummyVsix], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, KIRO_CLI: fakeKiro },
    timeout: 30_000,
  });
  try {
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stdout, /VSIX installation was reported by Kiro/);
    assert.doesNotMatch(`${result.stdout}\n${result.stderr}`, /bad substitution/i);
    const workDir = result.stdout.match(/Using isolated profile: (.+)/)?.[1]?.trim();
    if (workDir) rmSync(workDir, { recursive: true, force: true });
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
});
