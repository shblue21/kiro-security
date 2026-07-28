---
name: "kiro-security-power"
displayName: "Kiro Security Power"
description: "Run Standard, Diff, and Deep repository security workflows through Kiro Agent chat and the Kiro Security workbench."
keywords: ["security", "security scan", "vulnerability", "threat model", "diff review", "deep scan", "kiro security"]
author: "Kiro Security Power"
---

# Kiro Security Power

Kiro Agent chat owns scan start and every semantic security workflow. The VSIX does not provide a Dashboard Start action.

The deterministic Engine owns logical workspace state, immutable scan snapshots, target identity, lifecycle persistence, and later canonical validation boundaries. It does not perform semantic security analysis.

The Extension and the Power MCP share one extension-global SQLite workbench under the VSIX `globalStorageUri`. Scan artifacts are external to the selected target. Never create or require `.kiro/security-power` in a repository.

The selected target is an explicit absolute directory and is not confined to whichever folder happens to be open in the IDE. As in Codex Security 0.1.11, a scoped Deep scan selects that directory as its target and keeps scope `.`.

## Onboarding

1. Install the Kiro Security Power VSIX.
2. Open the Kiro Security setup view and explicitly enable the Hook transport. The Extension creates only `~/.kiro/hooks/kiro-security-power.json` in Kiro user configuration; its bridge and all runtime state remain under VSIX `globalStorageUri`.
3. Prepare the Power from the same setup view (or run **Kiro Security: Prepare Power Integration** from the command palette).
4. Import the revealed folder with **Powers → Add Custom Power → Import power from a folder**. The prepared copy contains an absolute Python runtime and storage configuration; the repository `mcp.json` is only its portable template.
5. Start a new normal Kiro chat.

The user-level `PreToolUse` Hook matches the exact outer `kiro_powers` tool name. The bridge passes unrelated Powers unchanged and accepts only calls whose Power name, MCP server name, and inner Kiro Security tool name exactly match this Power. Setup can verify, repair, or remove the dedicated registration without modifying other Hook or Agent files.

## Workbench continuation

1. Create a provisional logical workspace with `kiro_security_create_workspace`.
2. Save an exact setup with `kiro_security_save_workspace`.
3. Start through `kiro_security_start_scan`.
4. Immediately call `kiro_security_get_scan_context` with the returned `scanId`.
5. Publish lifecycle telemetry with `kiro_security_update_scan_progress`. On an unrecoverable workflow error, call `kiro_security_fail_scan`.

The MCP server owns deterministic state and snapshot operations only. Phase 2 does not yet include Standard, Diff, Deep, completion/finalization, reporting, or finding workflows. A durable running row is not proof that semantic analysis completed; do not claim a completed security scan until those later contracts and artifacts exist.

The installed Hook bridge validates that Kiro supplied a `session_id`, but this phase does not yet issue and atomically consume the one-time MCP attestation. Until that identity phase is implemented, the MCP still uses possession of opaque logical workspace and scan identifiers as an explicit Kiro adaptation. Do not describe this phase as trusted chat-session parity with Codex Security.
