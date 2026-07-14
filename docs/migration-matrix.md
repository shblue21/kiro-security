# Migration and parity matrix

Status vocabulary: **Reused**, **Adapted**, **Rewritten**, **Replaced**, **Unsupported**, or **Excluded with reason**.

| Reference component or capability | Status | Kiro Security Power implementation | Notes / residual difference |
|---|---|---|---|
| Plugin manifest | Rewritten | Root `package.json` VSIX manifest | Product identity changed; no OpenAI/Codex branding |
| Skill/workflow instructions | Adapted | Python phase engine plus `powers/kiro-security-power/POWER.md` | Operational invariants retained; agent-specific wording condensed |
| Python scripts | Adapted | `engine/kiro_security/` | State, Git, artifact, export, and safety concepts retained in a smaller cohesive package |
| JSON findings schema | Adapted | `engine/schemas/findings.schema.json` | Compatible core fields; Kiro provenance and management extensions |
| Coverage schema | Adapted | `engine/schemas/coverage.schema.json` | Compatible receipt model and Kiro document type |
| Scan manifest schema | Adapted | `engine/schemas/scan-manifest.schema.json` | Compatible sealed artifact inventory and lifecycle fields |
| SQLite workbench | Adapted | `engine/kiro_security/db.py`, `engine/migrations/` | WAL, migrations, transactions, backup, sessions, heartbeat, recovery |
| Scan lifecycle | Reused | `state_machine.py`, `runner.py`, DB constraints | Same mode/phase ordering; explicit interrupted state added |
| Progress | Reused | `scan_progress`, RPC events, UI polling | Cross-process reconciliation supports MCP-started scans |
| Handoff | Adapted | owner/session heartbeat and `handoff_state` | Host delivery claims are replaced by process-neutral durable ownership |
| Finding discovery | Rewritten | Real static source/data-flow scanner in `scanner.py` | Deterministic local analysis; no model-dependent worker fan-out |
| Validation | Rewritten | `validator.py` and validation records | Static targeted validation; dynamic PoC execution intentionally bounded |
| Attack-path analysis | Rewritten | `attack_path.py` | Structured source-to-sink facts generated from evidence |
| Triage | Adapted | `triage_decisions`, `triage_finding` RPC | Supports open, accepted risk, false positive, already fixed, won't fix |
| Remediation | Adapted | `remediation_records`, generated guidance artifact | Does not silently apply patches; IDE entry point is implemented |
| Hardening proposals | Adapted | `hardening.py`, Markdown artifacts | Category-driven portfolio and alternatives |
| Vulnerability writeup | Adapted | Per-finding Markdown writeup artifacts | No autonomous exploit construction; evidence-backed report is produced |
| Finding tracking | Adapted | `tracking_records`, approval-ready handoff artifacts, MCP/Power workflow | External ticket writes remain approval-gated; the product never writes to GitHub, Linear, or Jira implicitly |
| JSON export | Reused | `exports.py` | Implemented and tested |
| CSV export | Reused | `exports.py` | Implemented and tested |
| SARIF export | Reused | `exports.py` | SARIF 2.1.0 projection implemented and tested |
| Markdown report | Reused | `reporting.py` | Implemented and tested |
| Threat model artifact | Adapted | `threat_model.py` | Repository-derived inventory and trust-boundary summary |
| Discovery output | Reused | `discovery.json` | Implemented |
| Validation output | Reused | `validation.json` | Implemented |
| Attack-path output | Reused | `attack-path.json` | Implemented |
| Scan manifest JSON | Reused | `scan-manifest.json` | Implemented and sealed with artifact hashes |
| Coverage JSON | Reused | `coverage.json` | Implemented |
| Findings JSON | Reused | `findings.json` | Implemented |
| MCP server | Rewritten | `engine/kiro_security/mcp_server.py` plus `packages/mcp/src/server.mjs` compatibility adapter | One-click Setup uses Python directly and the same SQLite service; no compressed reference runtime reused |
| MCP App UI | Replaced | VSIX Webview/WebviewView | Product lifecycle belongs to VSIX; MCP remains companion adapter |
| Kiro Power | Rewritten | `powers/kiro-security-power/` and Setup-prepared native bundle | Delegates all stateful actions to MCP/engine; native Powers-panel import remains an explicit Kiro confirmation |
| Bundled assets | Excluded with reason | New `media/security.svg` | Reference logo is proprietary product branding |
| Tests and fixtures | Rewritten | Node and Python tests; generated vulnerable fixture | Reference example is not hardcoded into production |
| Capability preflight | Adapted | Engine capabilities and setup state | Local dependency/workspace/Git checks surfaced to UI |
| Git target identity | Adapted | Canonical path, Git revision, diff refs, snapshot digest | Direct subprocess argument arrays; environment minimized |
| Source excerpts | Reused | Evidence records and finding detail payload | Bounded context only |
| Sealed manifest digest | Reused | Artifact hashes plus manifest SHA-256 stored in SQLite | Implemented during reporting |
| Cancellation | Reused | DB cancellation flag, thread checks, event and terminal state | Race-safe idempotent cancellation |
| Interrupted recovery/resume | Adapted | Session heartbeat, stale-owner recovery, phase resume | Resume continues from durable current phase |
| Secondary Side Bar experience | Adapted | View container plus stable workbench move command; beside panel fallback | Manifest cannot guarantee initial right-side placement |
| Problems diagnostics | New integration | `DiagnosticCollection` for validated findings | IDE-native parity feature |
| Code actions | New integration | Details and remediation actions | IDE-native parity feature |
| Status bar/output channel | New integration | Active phase/progress/count and structured logs | IDE-native parity feature |
| History cleanup | New integration | `cleanup_scan` RPC, History UI action, artifact boundary checks | Only completed/failed/cancelled/interrupted scans are removable; explicit external exports are retained |
| Per-finding export | New integration | `export_report` with `occurrenceId`, Finding detail action | JSON handoff is generated from the selected durable finding only |
| Secret storage | New integration | Optional analyzer credential stored in `SecretStorage` | No secret is written to settings or logs |
| Agent one-click installation | Adapted | Setup JSONC merge, managed steering, stable runtime, MCP verification and rollback | Recreates Codex-like low-friction setup without private Kiro APIs or bypassing Kiro permission confirmation |
| Telemetry | Replaced | Off by default; no transmission in 0.2.0 | Opt-in setting reserved |
