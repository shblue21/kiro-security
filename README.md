# Kiro Security Power

Kiro Security Power is a VSIX-first security workbench for Kiro IDE. It provides standard, deep, and Git-diff scans; durable SQLite state; threat models; source-to-sink findings; validation and attack paths; Problems diagnostics; remediation and hardening guidance; approval-ready finding-tracking handoffs; scan history, cleanup, and resume; and JSON, CSV, SARIF, Markdown, and per-finding exports.

The VSIX is the product. The companion Power and MCP server delegate to the same Python engine and `<workspace>/.kiro/security-power/workbench.sqlite`, so scans started through either surface are visible in the other.

## Agent panel setup

Version 0.2.0 provides an approval-driven one-click Agent integration:

1. Open a trusted repository and select **Kiro Security → Setup**.
2. Review the detected Python/SQLite runtime, workspace or user scope, and read-only approval policy.
3. Select **Install and verify** and approve the exact MCP and steering paths shown.
4. Wait for **Verified**. The installer checks the copied runtime against the VSIX, launches the packaged Python MCP server, and verifies its tools and shared workbench before reporting success.
5. Start a new Kiro Agent conversation or refresh MCP servers, then ask it to run a standard, deep, or diff security scan.

The functional setup does not require a separate Node installation. An optional native custom-Power folder is prepared for import through Kiro's Powers panel; Kiro's own permission confirmation is intentionally not bypassed. Details and rollback behavior are documented in `docs/agent-integration.md`.

## Build and verify

```bash
npm ci
npm run lint
npm test
npm run test:integration
npm run package
python3 -m pytest
python3 -m compileall engine
```

The package command writes `dist/kiro-security-power-<version>.vsix` and `dist/SHA256SUMS`.

## Publisher

The development publisher is defined once in the root `package.json` as `kiro-security-power-dev`. Replace that value with the approved publisher before controlled distribution. Do not publish to Marketplace or Open VSX without the review described in `LICENSE-NOTICE.md` and `docs/provenance.md`.

## Kiro desktop validation

Cloud build and VS Code-compatible API tests do not prove Kiro desktop behavior. Use `scripts/verify-in-kiro.sh` or `scripts/verify-in-kiro.ps1` and follow `docs/local-kiro-smoke-test.md`. The exact cloud command record is in `docs/cloud-verification.md`.
