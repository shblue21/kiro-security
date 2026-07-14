import { createHash } from "node:crypto";
import { readFile, writeFile, readdir, stat } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
const filename = `kiro-security-power-${manifest.version}.vsix`;
const output = path.join(root, "dist", filename);
const vsceEntrypoint = path.join(root, "node_modules", "@vscode", "vsce", "vsce");
const result = spawnSync(process.execPath, [vsceEntrypoint, "package", "--no-dependencies", "--allow-missing-repository", "--out", output], {
  cwd: root,
  stdio: "inherit",
  shell: false,
});
if (result.status !== 0) process.exit(result.status ?? 1);
const bytes = await readFile(output);
const digest = createHash("sha256").update(bytes).digest("hex");
await writeFile(path.join(root, "dist", "SHA256SUMS"), `${digest}  ${filename}\n`, "utf8");

async function findForbidden(directory, relative = "") {
  const forbidden = [];
  for (const name of await readdir(directory)) {
    const full = path.join(directory, name);
    const rel = path.join(relative, name);
    const info = await stat(full);
    if (info.isDirectory()) forbidden.push(...await findForbidden(full, rel));
    else if (/codex-security-reference|\.sqlite(?:$|-)|\.pyc$|\.env$|secret/i.test(rel)) forbidden.push(rel);
  }
  return forbidden;
}
const forbidden = await findForbidden(path.join(root, "dist"));
if (forbidden.length) {
  console.error(`Forbidden package artifacts detected: ${forbidden.join(", ")}`);
  process.exit(1);
}
console.log(`VSIX: ${output}`);
console.log(`SHA-256: ${digest}`);
