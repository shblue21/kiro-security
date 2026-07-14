# Codex Security migration inventory

## Migration input

| Field | Value |
|---|---|
| Supplied attachment | `/mnt/data/codex-security-reference-0.1.11.zip` |
| Expected SHA-256 | `028349a53c19790e182279f44c20d7780c64594a8d5b5f034b461035a297d34d` |
| Calculated SHA-256 | `028349a53c19790e182279f44c20d7780c64594a8d5b5f034b461035a297d34d` |
| ZIP entries | 129 |
| Unsafe absolute or `..` entries | 0 |
| Internal root | `codex-security/0.1.11/` |
| Reference license metadata | `Proprietary` |
| Migration treatment | Read-only input extracted outside the product tree; not copied wholesale or committed |

The attachment was identified by filename, exact SHA-256, internal root, plugin manifest, MCP manifest, workbench scripts, schemas, and the standard/deep scan skill files. It was extracted to a temporary read-only directory for analysis. The extraction directory and source ZIP are excluded from the product and package.

## Verified anchor files

- `.codex-plugin/plugin.json`
- `.mcp.json`
- `.app.json`
- `scripts/workbench_cli.py`
- `scripts/workbench_db.py`
- `scripts/workbench_schema.py`
- `schemas/findings.schema.json`
- `schemas/coverage.schema.json`
- `schemas/scan-manifest.schema.json`
- `skills/security-scan/SKILL.md`
- `skills/deep-security-scan/SKILL.md`

## Top-level inventory

| Area | Contents observed | Migration relevance |
|---|---|---|
| Plugin manifest | Product metadata, skills directory, app integrations, MCP server, proprietary license | Identity and capability inventory only; rewritten as a VSIX manifest |
| Workflow skills | 11 workflows covering scan, diff, deep scan, threat model, discovery, validation, attack path, triage, remediation, hardening, writeup, and tracking | Workflow sequencing and output contracts adapted into engine phases and companion Power guidance |
| Python workbench | SQLite workbench, state transitions, Git target identity, progress, source excerpts, remediation state, artifact sealing, exports | Durable state model and safety properties adapted into the new engine |
| JSON schemas | Findings, coverage, completed scan manifest | Field model adapted under Kiro Security Power schema IDs, preserving compatible data shapes where practical |
| References | Scan contract, artifact layout, finding detail fields, report format, SARIF adapter, preflight, security guidance | Used to define protocol, artifacts, reports, and parity requirements |
| MCP runtime | Small loader plus Brotli-compressed runtime chunks and compressed MCP App HTML | Compressed implementation not decompressed or reverse engineered; MCP and UI rewritten against documented/visible contracts |
| Examples | One completed scan bundle | Used only as schema and contract examples; not shipped as production data |
| Assets | Codex Security logo | Excluded; a new neutral shield icon is used |
| App connectors | Linear, GitHub, Atlassian connector identifiers | Not copied; tracking is represented as an adapter boundary and export/handoff capability |

## Reference workbench state model

The reference schema contains ten migrations. Its durable model includes:

- `workspaces` with target, scope, mode, user context, diff target, capability preflight, active scan, thread association, and diff-resolution state.
- `scans` with target identity, revision/snapshot digest, scan directory, status, phase, handoff delivery/claim state, sealed manifest digest, filesystem identity, and cancellation timestamp.
- `scan_progress` with review totals, reportable count, and deep-review pass.
- `scan_artifacts` for coverage, findings, manifest, and Markdown report.
- Canonical `findings`, per-scan `finding_occurrences`, and ordered `finding_locations`.
- `finding_triage` with open/closed state and closure reasons.
- Versioned `finding_remediation_attempts` with generate/apply/verify actions, claims, delivery state, patch metadata, and verification summaries.
- A partial unique index enforcing one running scan per workspace.

Kiro Security Power preserves these concepts and extends them with explicit evidence, validation, attack-path, hardening, export, engine-session, and event records needed by the IDE, MCP, and recovery model.

## Reference scan and artifact contracts

Observed modes and phases:

- Modes: `diff`, `standard`, `deep`.
- Phases: `preflight`, `threat_model`, `discovery`, `validation`, `attack_path`, `reporting`.

Observed canonical artifacts:

- `scan-manifest.json`
- `coverage.json`
- `findings.json`
- `report.md`

Additional workflow artifacts described by the reference include threat models, discovery output, validation closure, attack-path facts, source excerpts/evidence, vulnerability writeups, hardening proposals, tracking handoffs, and SARIF projections.

## Reference workflow inventory

| Workflow | Primary retained behavior |
|---|---|
| Security scan | Repository/scoped scan orchestration and single canonical reporting tail |
| Deep security scan | Multiple independent discovery passes, semantic merge, canonical validation, one reporting tail |
| Security diff scan | Git target resolution and change-scoped analysis |
| Threat model | Assets, trust boundaries, attacker-controlled inputs, invariants, and high-impact failure modes |
| Finding discovery | Source-to-sink candidate production with evidence and a reportability bar |
| Validation | Reproduction or focused code tracing; evidence-backed validated/rejected/needs-review outcome |
| Attack-path analysis | Attacker story, preconditions, source/sink path, impact, severity calibration |
| Finding triage | Open/closed decision, accepted-risk/false-positive/already-fixed/won't-fix reasons, notes |
| Fix finding | Minimal remediation lifecycle with generation, application, verification, and failure states |
| Hardening proposal | Structural alternatives, tradeoffs, migration plan, and decision-ready portfolio |
| Vulnerability writeup | Self-contained source-backed per-finding report and PoC/evidence handoff |
| Finding tracking | Approval-gated external handoff with exact payload, duplicate checks, and readback |

## Exclusions from the product package

The following migration inputs are intentionally excluded:

- The source ZIP and complete extracted reference tree.
- Brotli-compressed MCP runtime chunks and compressed MCP App UI.
- The Codex Security logo and OpenAI/Codex product branding.
- Connector application identifiers tied to the reference product.
- Reference examples as production fixtures.
- Any declaration that Kiro Security Power is an official OpenAI or Codex product.
