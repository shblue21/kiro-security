import * as esbuild from "esbuild";
import { cp, mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const watch = process.argv.includes("--watch");
await mkdir(path.join(root, "dist", "extension"), { recursive: true });
await mkdir(path.join(root, "dist", "webview"), { recursive: true });
await mkdir(path.join(root, "dist", "mcp"), { recursive: true });
await mkdir(path.join(root, "dist", "tests"), { recursive: true });

const builds = [
  {
    entryPoints: [path.join(root, "packages/extension/src/extension.ts")],
    outfile: path.join(root, "dist/extension/extension.js"),
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node18",
    mainFields: ["module", "main"],
    external: ["vscode"],
    sourcemap: false,
    logLevel: "info",
  },
  {
    entryPoints: [path.join(root, "packages/webview/src/main.ts")],
    outfile: path.join(root, "dist/webview/main.js"),
    bundle: true,
    platform: "browser",
    format: "iife",
    target: "es2022",
    sourcemap: false,
    minify: true,
    logLevel: "info",
  },
  {
    entryPoints: [path.join(root, "packages/mcp/src/server.ts")],
    outfile: path.join(root, "dist/mcp/server.mjs"),
    bundle: true,
    platform: "node",
    format: "esm",
    target: "node18",
    sourcemap: false,
    minify: false,
    banner: { js: "import { createRequire as __createRequire } from 'node:module'; const require = __createRequire(import.meta.url);" },
    logLevel: "info",
  },
];

const testEntries = [
  "tests/protocol-contract.test.ts",
  "tests/webview-state.test.ts",
  "tests/webview-harness.test.ts",
  "tests/mcp-sharing.test.ts",
  "tests/extension-routing.test.ts",
  "tests/agent-integration.test.ts",
].map((entry) => path.join(root, entry));

builds.push({
  entryPoints: testEntries,
  outdir: path.join(root, "dist/tests"),
  bundle: true,
  platform: "node",
  format: "cjs",
  target: "node18",
  mainFields: ["module", "main"],
  external: ["vscode", "jsdom"],
  sourcemap: false,
  logLevel: "info",
});

await cp(path.join(root, "packages/webview/src/styles.css"), path.join(root, "dist/webview/styles.css"));

if (watch) {
  const contexts = await Promise.all(builds.map((options) => esbuild.context(options)));
  await Promise.all(contexts.map((context) => context.watch()));
  process.stdout.write("Kiro Security Power build watcher started.\n");
} else {
  await Promise.all(builds.map((options) => esbuild.build(options)));
}
