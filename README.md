# Kiro Security Power

Kiro Security Power is a VSIX-first security workbench for Kiro IDE. Standard, Diff, and four-worker iterative Deep scans are Skill-driven workflows coordinated from Kiro Agent chat. The Engine provides deterministic target inventory, immutable snapshots, lifecycle storage, canonical validation/projection/sealing, and finding indexing; it performs no heuristic analysis. The workbench retains results, diagnostics, triage, remediation, tracking, history, cleanup, durable coordinator handoff, and JSON, CSV, SARIF, Markdown, and per-finding exports.

The VSIX is the product. The companion Power and MCP server delegate to the same Python engine and `<workspace>/.kiro/security-power/workbench.sqlite`, so scans started through either surface are visible in the other.

## Agent panel setup

Version 0.3.0 provides an approval-driven one-click Agent integration:

1. Open a trusted repository and select **Kiro Security → Setup**.
2. Review the detected Python/SQLite runtime, workspace or user scope, and read-only approval policy.
3. Select **Install and verify** and approve the exact MCP and steering paths shown.
4. Copy the prepared Power folder, then in Kiro choose **Powers → Add Custom Power → Import power from a folder** and install it.
5. Return to Setup and select **Verify after import**. Setup reports **Verified** only after it detects and probes Kiro's native Power registration.
6. Start a new Kiro Agent conversation, then ask it to run a Standard, Diff, or Deep scan. Scan starts are chat-only and Power-coordinated; the Dashboard consumes lifecycle and sealed results.

The functional setup does not require a separate Node installation. Native Power import is required because `POWER.md` and phase steering—not the MCP runtime—own Standard, Diff, and Deep semantics. Kiro's own permission confirmation is intentionally not bypassed. Details and rollback behavior are documented in `docs/agent-integration.md`.

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

Native workers and connectors remain separate trust boundaries. The Engine validates bounded Agent-authored canonical artifacts and can apply only an explicitly prepared remediation patch after revision and drift checks; it does not execute Agent-submitted commands. Tracking creates an exact, digest-bound handoff and stores sanitized connector readback, while provider credentials and network writes remain the responsibility of a separately authorized connector.

## Publisher

The development publisher is defined once in the root `package.json` as `kiro-security-power-dev`. Replace that value with the approved publisher before controlled distribution. Do not publish to Marketplace or Open VSX without the review described in `LICENSE-NOTICE.md` and `docs/provenance.md`.

## Kiro desktop validation

Cloud build and VS Code-compatible API tests do not prove Kiro desktop behavior. Use `scripts/verify-in-kiro.sh` or `scripts/verify-in-kiro.ps1` and follow `docs/local-kiro-smoke-test.md`. Installation automation does not by itself prove a delegated multi-round Deep run; retain the manual result record and receipt digests. The exact cloud command record is in `docs/cloud-verification.md`.
