import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";

export const require = createRequire(import.meta.url);
export const manifest = JSON.parse(readFileSync("package.json", "utf8"));
export const TEST_SERVER_KEY = "ksp_aaaaaaaaaaaaaaaaaaaa";

export function pythonExecutable() {
  return execFileSync(
    process.platform === "win32" ? "python" : "python3",
    ["-c", "import sys; print(sys.executable)"],
    { encoding: "utf8" },
  ).trim();
}

export function loadSetupViewHtmlModule() {
  return require("../out/packages/extension/src/view/setupViewHtml.js");
}
