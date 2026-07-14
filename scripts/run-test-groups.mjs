import { spawn } from "node:child_process";

const group = process.argv[2];
if (!new Set(["unit", "integration"]).has(group)) {
  console.error("Usage: node scripts/run-test-groups.mjs <unit|integration>");
  process.exit(2);
}

const python = process.env.KIRO_SECURITY_TEST_PYTHON
  || process.env.PYTHON
  || (process.platform === "win32" ? "python" : "python3");

const nodeTests = group === "unit"
  ? [
      "dist/tests/protocol-contract.test.js",
      "dist/tests/webview-state.test.js",
      "dist/tests/webview-harness.test.js",
      "dist/tests/extension-routing.test.js",
      "dist/tests/agent-integration.test.js",
    ]
  : [
      "dist/tests/mcp-sharing.test.js",
    ];

const commands = group === "unit"
  ? [
      { label: "Node unit and contract tests", command: process.execPath, args: ["--test", "--test-concurrency=1", ...nodeTests] },
      { label: "Python unit and contract tests", command: python, args: ["-m", "pytest", "-q", "engine/tests", "-m", "not integration"] },
    ]
  : [
      { label: "Node MCP shared-workbench integration test", command: process.execPath, args: ["--test", "--test-concurrency=1", ...nodeTests] },
      { label: "Python integration tests", command: python, args: ["-m", "pytest", "-q", "engine/tests", "-m", "integration"] },
    ];

const children = new Set();
let requestedSignal;

function terminateChildren(signal = "SIGTERM") {
  for (const child of children) {
    if (child.exitCode === null && child.signalCode === null) child.kill(signal);
  }
  if (signal === "SIGTERM" && process.platform !== "win32") {
    const escalation = setTimeout(() => {
      for (const child of children) {
        if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
      }
    }, 5_000);
    escalation.unref();
  }
}

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.once(signal, () => {
    requestedSignal = signal;
    terminateChildren("SIGTERM");
  });
}

function launch({ label, command, args }) {
  console.log(`[test-runner] Starting ${label}.`);
  const started = Date.now();
  const child = spawn(command, args, {
    cwd: process.cwd(),
    env: process.env,
    shell: false,
    windowsHide: true,
    stdio: "inherit",
  });
  children.add(child);

  return new Promise((resolve) => {
    let settled = false;
    const heartbeat = setInterval(() => {
      const elapsed = Math.max(1, Math.round((Date.now() - started) / 1_000));
      console.log(`[test-runner] ${label} is still running (${elapsed}s).`);
    }, 10_000);

    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearInterval(heartbeat);
      children.delete(child);
      resolve(result);
    };

    child.once("error", (error) => finish({ label, code: 1, error }));
    child.once("exit", (code, signal) => finish({ label, code: code ?? (signal ? 1 : 0), signal }));
  });
}

const results = await Promise.all(commands.map(launch));
const failures = results.filter((result) => result.code !== 0);
if (requestedSignal || failures.length) {
  terminateChildren("SIGTERM");
  for (const failure of failures) {
    console.error(`${failure.label} failed${failure.signal ? ` with signal ${failure.signal}` : ` with exit code ${failure.code}`}${failure.error ? `: ${failure.error.message}` : ""}.`);
  }
  process.exitCode = requestedSignal === "SIGINT" ? 130 : requestedSignal === "SIGTERM" ? 143 : failures[0]?.code || 1;
} else {
  for (const result of results) console.log(`[test-runner] Completed ${result.label}.`);
}
