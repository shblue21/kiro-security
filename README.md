# Kiro Security Power

A security workbench for [Kiro](https://kiro.dev). Run Standard, Diff, and Deep security scans of your repositories from an ordinary Kiro Agent chat, and manage the results — findings, triage, remediation, and exports — from a dedicated side panel.

> **Alpha.** This is an early release. Contracts, schemas, and UI may change between versions, and scan state from one version may not carry over to the next.

## What it does

- **Three scan modes** — `standard` (full repository or scoped directory), `diff` (a specific Git-backed change), and `deep` (multi-round, multi-worker discovery for higher coverage).
- **Agent-driven analysis, engine-owned state** — your Kiro Agent performs the semantic security analysis in chat, while a local Python engine owns workspaces, scan lifecycle, target snapshots, and sealed canonical results in a single SQLite workbench. Progress display never overrides the verified result.
- **Durable scans** — scans survive process or chat loss. Resume, recover, or cancel them explicitly from a new Agent chat; the side panel tracks lifecycle and recovery requests.
- **Findings workflow** — browse findings in the panel, then hand off exact triage, fix, and tracking requests back to the Agent.
- **Exports** — completed scans export to SARIF 2.1.0 and CSV, derived from the sealed canonical JSON.

## Requirements

- **Kiro** — the extension activates only in a Kiro host. In other VS Code-compatible editors it shows read-only guidance and stays inert.
- **Python 3.9+** — auto-detected from `python3`/`python` on your PATH, or set `kiroSecurity.pythonPath` explicitly.

## Getting started

1. Install the extension and open the **Kiro Security** icon in the activity bar (the setup view opens automatically on first run).
2. Review and approve the one-time setup. This is explicit and user-approved — nothing is written until you confirm.
3. Ask your Kiro Agent in a normal chat, e.g. *"Run a security scan of this repository"* or *"Review this change for security issues."*
4. Follow progress, browse findings, and export results from the side panel.

## What setup changes on your machine

Setup prepares a self-contained runtime under the extension's own global storage and registers exactly these user-level files, preserving your existing entries and comments:

- `~/.kiro/settings/mcp.json` — one MCP server entry with a per-installation key
- `~/.kiro/steering/kiro-security-power.md` — auto-inclusion steering that defines the scan workflows
- `~/.kiro/hooks/kiro-security-power.json` — a hook matching only this extension's MCP tools, used to attest that calls come from your real chat session
- Kiro trust permissions — scan **start** and **cancel** always ask for approval; routine reads and progress updates are allowed

Unrelated user configuration is never overwritten or removed. All workspace and scan state lives locally in the extension's global storage; the extension itself sends nothing anywhere — analysis happens through your own Kiro Agent.

## Configuration

| Setting | Description |
| --- | --- |
| `kiroSecurity.pythonPath` | Absolute path to a Python 3.9+ executable used by the MCP engine. Leave empty to auto-detect. |

## Provenance and license

Kiro Security Power is an independent open-source reimplementation of the workspace/scan-lifecycle workbench architecture observed in Codex Security 0.1.11 — a pattern shared by many security tools. No source, runtime bundles, or assets from that proprietary reference implementation are included; see `LICENSE-NOTICE.md` in this package. This is not an official OpenAI, Codex, or Kiro product.

Licensed under the Apache License 2.0 — see the packaged `LICENSE` file.
