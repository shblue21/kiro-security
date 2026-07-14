# Cloud verification record

Verification date: 2026-07-14

This record separates repository/cloud checks from Kiro desktop checks. The current environment has no `kiro` executable, no `KIRO_CLI`, and no `/Applications/Kiro.app`, so installation, Activity Bar rendering, Secondary Side Bar placement, Kiro Agent reconnection, source navigation inside Kiro, and interactive lifecycle checks are not marked complete here.

## Reproducible commands and observed results

| Command | Observed result |
|---|---|
| `npm ci --ignore-scripts` | PASS; 356 packages installed, 357 audited, 0 vulnerabilities; three transitive deprecation notices |
| `npm run lint` | PASS; TypeScript no-emit check and Python compile check |
| `npm test` | PASS; 19 Node tests and 22 non-integration Python tests; 6 Python integration tests deselected |
| `npm run test:integration` | PASS; 6 Python integration tests plus the Node MCP/engine shared-workbench test; the real Agent installer runs in `npm test` |
| `python3 -m pytest -q engine/tests` | PASS; 28 engine tests |
| `python3 -m pytest -q` | PASS; 29 tests including the fixture negative case |
| `python3 -m compileall -q engine` | PASS |
| Python 3.9 grammar check | PASS; every packaged engine module parses with `ast.parse(..., feature_version=(3, 9))` and no `dataclass(slots=True)` remains |
| `npm audit` | PASS; 0 vulnerabilities |
| `npm audit --omit=dev` | PASS; 0 production vulnerabilities |
| `npm run verify` | Cloud wrapper did not complete; the host sent SIGTERM during the long foreground chain. Every constituent command was run independently and passed. |
| `npm run package` | PASS; version 0.2.0 VSIX and `SHA256SUMS` generated |
| VSIX archive content audit | PASS; 66 entries, required engine/Power/Webview files present, forbidden fixtures/tests/databases/caches/source maps absent |
| extracted-VSIX MCP smoke | PASS; MCP 2025-06-18, 16 tools, packaged engine 0.2.0, Standard scan completed with 6 findings, SQLite and SARIF created |
| local verification JSON Schema check | PASS; example validates against the draft 2020-12 schema |
| CI workflow parse | PASS; package job and dedicated Python 3.9 compatibility job are present |

The canonical `npm run verify` script remains the documented sequential composition of the independently passing commands. In this cloud host, repeated long foreground invocations were terminated by the host watchdog (one after integration while packaging began, another during integration), so the chained command is not reported as a pass. The standalone lint, unit, integration, and package commands and their real exit statuses are recorded above.

A Python 3.9 executable is not installed in this cloud image. An attempted `uv python install 3.9` could not resolve the external download host because outbound DNS was unavailable, so that failed download is not counted as a product-test failure or as a Python 3.9 runtime pass. The repository includes a dedicated GitHub Actions Python 3.9 job, and the local cloud checks cover Python 3.9 grammar plus the specific runtime incompatibility that appeared in version 0.1.0.

## Agent integration coverage

The automated Agent installer test uses a real temporary workspace and global-storage directory. It:

- preserves an unrelated MCP server and JSONC comment;
- writes only the managed `kiro-security-power` server entry and managed steering file;
- copies a stable Python engine runtime outside the version-specific VSIX directory;
- launches the copied Python MCP server without a separate Node dependency;
- negotiates MCP, lists and verifies the required tools, and calls `security_get_capabilities` against the shared SQLite workbench;
- confirms only read-only lookup tools are pre-approved;
- prepares a Kiro-compatible `POWER.md`, `mcp.json`, steering directory, provenance notice, and runtime;
- removes only managed MCP/steering entries; and
- rejects malformed existing configuration without overwriting it.

The integration suite also starts a scan through MCP and observes the same scan and findings from a second engine client using the same workspace database.

## Broader coverage represented by the checks

The automated suite covers scan state transitions; mode and phase handling; schema and RPC validation; malformed messages and protocol version mismatch; SQLite migrations, backup, locking, corruption reporting, cancellation, interrupted recovery and resume; Standard, Deep, and Diff scans over a real fixture Git repository; threat-model, discovery, validation, attack-path, report, hardening, writeup, tracking, and export artifacts; JSON, CSV, SARIF, Markdown, and per-finding export; source URI/range mapping; diagnostic routing; Webview loading, error, empty, filter, Agent Setup, detail action, theme, CSP, keyboard, and basic accessibility behavior; and MCP/extension-like clients sharing one SQLite workbench in both directions.

The Webview tests use a JSDOM harness. They are not evidence of Kiro desktop rendering. The repository does not contain a Kiro or VS Code desktop binary, so desktop-host execution was not performed in this environment.
