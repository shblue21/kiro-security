# Kiro Agent integration

Kiro Security Power 0.2.0 adds an approval-driven Setup flow that connects Kiro's Agent panel to the same Python engine and SQLite workbench used by the VSIX.

## User flow

1. Install the VSIX and open a trusted local workspace.
2. Open **Kiro Security → Setup**.
3. Review the detected Python/SQLite runtime, installation scope, exact target files, and tool approval policy.
4. Select **Install and verify** and approve the modal confirmation.
5. The installer merges one MCP server entry, writes auto-inclusion steering, prepares a stable local Power folder, verifies every allowlisted runtime file against the VSIX payload, starts the packaged MCP process, negotiates the MCP protocol, lists tools, calls `security_get_capabilities`, and reports `Verified` only after the shared workbench passes its health check.
6. Open a new Agent conversation or refresh MCP servers if a conversation was already open before setup.

No separate Node installation is required by this flow. The MCP process uses the same detected Python 3.9+ runtime as the VSIX engine.

## Files written after approval

Workspace scope:

```text
<workspace>/.kiro/settings/mcp.json
<workspace>/.kiro/steering/kiro-security-power.md
<extension-global-storage>/agent-integration/kiro-security-power/
```

User scope uses `~/.kiro/settings/mcp.json` and `~/.kiro/steering/kiro-security-power.md`. Its MCP entry is workspace-neutral: the steering contract passes the current canonical `workspaceRoot` to every tool instead of pinning the global server to the workspace used during installation. The prepared runtime remains in extension global storage so VSIX upgrades do not leave the MCP configuration pointing at a version-specific extension installation directory.

The JSONC-aware merge preserves comments, trailing commas, and unrelated MCP servers. Existing target files are backed up before modification. Installation rolls back the MCP config, steering, prepared Power, and installer state if payload integrity, process startup, tool discovery, or engine health verification fails.

The prepared Python process is launched with `-B -S -m kiro_security.mcp_server`. This disables bytecode output and the ambient `site` initialization path. Before every verification, the extension rejects symbolic links, special files, unexpected import-shadow files, changed engine/schema/migration content, an altered Power `mcp.json`, unsafe environment keys, and a command or tool-approval policy that differs from the approved installation.

## Approval policy

- `none`: every MCP tool requires Agent approval.
- `read_only`: only capability, scan/status/progress, and finding lookup tools are pre-approved.

Starting or cancelling scans, validation, triage, remediation, tracking handoff, hardening, threat-model generation, and export are never pre-approved by the VSIX.

## Native Powers-panel registration

The Setup flow makes Agent tools functional through MCP plus auto-inclusion steering. It also prepares a Kiro-compatible custom Power folder containing `POWER.md`, `mcp.json`, `steering/`, provenance notice, and the local runtime.

Kiro's own **Powers → Add Custom Power → Import power from a folder** confirmation remains optional and cannot be bypassed by the VSIX. Importing the prepared folder adds the native Powers-panel entry; it is not required for Agent tool use after Setup reports `Verified`.

## Repair and removal

**Install and verify** changes to **Repair and verify** when an entry already exists. Repair refreshes the stable runtime, exact MCP command, steering, and verification state. **Remove Agent integration** removes only VSIX-managed MCP and steering entries; unrelated servers, scan history, exports, and separately imported native Powers are retained.
