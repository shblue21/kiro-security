# Migration and parity matrix

Status vocabulary: **Reused**, **Adapted**, **Rewritten**, **Replaced**, **Unsupported**, or **Excluded with reason**.

Schema compatibility targets canonical lifecycle meaning and structural safety, not byte-for-byte Codex product identity. Kiro keeps its `kiro-security-power.*` document types, `scan_`/`kspf_`/`occ_` identifiers, `kiro-security/(deep-)?v1` fingerprints, WS-A row coverage, canonical/supporting/derived artifact roles, Kiro and Deep/tail provenance, and Kiro RPC/event names. Python `validate_method()` remains the authoritative engine-method parameter validator, MCP schemas validate agent-facing arguments, and the shared TypeScript protocol validates envelopes, events, and document DTOs; these layers intentionally apply the reference safety properties in the Kiro dialect rather than adopting Codex/OpenAI branding or identifiers.

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
| Finding discovery | Rewritten | `scanner.py` Fast profile plus durable six-worker model discovery and semantic merge | Fast is deterministic pre-screening; Standard/Diff use one model round and Deep iterates to zero novelty or cap |
| Validation | Rewritten | `validator.py` for Fast; durable model tail assignments for model scans | The engine validates bounded proof results and never executes a model-submitted command |
| Attack-path analysis | Rewritten | `attack_path.py` for Fast; durable model tail assignments for model scans | Model results require evidence-backed control, sink, impact, severity, counterevidence, and uncertainty |
| Triage | Adapted | `triage_decisions` plus bounded external intake and proof-chain assessment | User disposition remains separate from untrusted imported evidence and model assessment |
| Remediation | Adapted | Guidance plus prepared patch, drift gate, explicit apply, and verification receipt | No silent patching; repository mutation requires a digest-bound prepared patch and explicit apply call |
| Hardening proposals | Adapted | `hardening.py` for Fast; normalized JSON and deterministic Markdown model portfolio | Report and hardening remain derived projections outside the canonical seal |
| Vulnerability writeup | Adapted | Template writeups for Fast; dedicated bounded model writeup/PoC materialization | The engine controls the artifact path and does not autonomously construct or execute an exploit |
| Finding tracking | Adapted | Digest-bound exact handoff preview plus sanitized connector readback | Provider credentials, duplicate search, approval, and network writes stay in a separately authorized connector |
| JSON export | Reused | `exports.py` | Implemented and tested |
| CSV export | Reused | `exports.py` | Implemented and tested |
| SARIF export | Reused | `exports.py` | SARIF 2.1.0 projection implemented and tested |
| Markdown report | Reused | `reporting.py` | Implemented and tested |
| Threat model artifact | Adapted | deterministic repository context plus post-discovery canonical model synthesis | Context observations remain hints/unknowns until model proof; Standard/Diff/Deep reuse one tail kind |
| Discovery output | Reused | `discovery.json` | Implemented |
| Validation output | Reused | `validation.json` | Implemented |
| Attack-path output | Reused | `attack-path.json` | Implemented |
| Scan manifest JSON | Reused | `scan-manifest.json` | Implemented and sealed with artifact hashes |
| Coverage JSON | Reused | `coverage.json` | Implemented |
| Findings JSON | Reused | `findings.json` | Implemented |
| MCP server | Rewritten | `engine/kiro_security/mcp_server.py` plus TypeScript source `packages/mcp/src/server.ts` | One-click Setup uses Python directly and the same SQLite service; no compressed reference runtime reused |
| MCP App UI | Replaced | VSIX Webview/WebviewView | Product lifecycle belongs to VSIX; MCP remains companion adapter |
| Kiro Power | Rewritten | `powers/kiro-security-power/` and Setup-prepared native bundle | Delegates all stateful actions to MCP/engine; native Powers-panel import remains an explicit Kiro confirmation |
| Bundled assets | Excluded with reason | New `media/security.svg` | Reference logo is proprietary product branding |
| Tests and fixtures | Rewritten | Node and Python tests; generated vulnerable fixture; Desktop verification record schema | Reference example is not hardcoded into production; actual Kiro delegated multi-round evidence remains outstanding |
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
| Telemetry | Replaced | Off by default; current implementation contains no telemetry transport | Opt-in setting is reserved and would require a separate consent and data-minimization review |
