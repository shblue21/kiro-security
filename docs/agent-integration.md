# Kiro Agent integration

Kiro Security Power 0.2.0 adds an approval-driven Setup flow that connects Kiro's Agent panel to the same Python engine and SQLite workbench used by the VSIX.

## User flow

1. Install the VSIX and open a trusted local workspace.
2. Open **Kiro Security → Setup**.
3. Review the detected Python/SQLite runtime, installation scope, exact target files, and tool approval policy.
4. Select **Install and verify** and approve the modal confirmation.
5. The installer merges one bootstrap MCP server entry, writes safety/activation steering, prepares a stable local Power folder, verifies every allowlisted runtime file against the VSIX payload, starts the packaged MCP process, negotiates the MCP protocol, lists tools, and calls `security_get_capabilities`. This proves only the deterministic MCP runtime.
6. Copy the prepared folder path. In Kiro select **Powers → Add Custom Power → Import power from a folder**, choose that folder, review permissions, and click Install.
7. Return to Setup and select **Verify after import**. Setup reports `Verified` only after it detects Kiro's namespaced native-Power MCP registration and probes that exact registration.
8. Open a new Agent conversation so Kiro can activate the installed `POWER.md` and mode steering.

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

Starting or cancelling scans, triage, remediation, tracking handoff, and export are never pre-approved by the VSIX.

## Native Powers-panel registration

The Setup flow prepares a Kiro-compatible custom Power folder containing `POWER.md`, `mcp.json`, `steering/`, references, provenance notice, and the local runtime. Its bootstrap MCP probe checks deterministic infrastructure only. The auto-inclusion steering refuses to start a scan when the native Power instructions are absent.

Kiro's own **Powers → Add Custom Power → Import power from a folder** confirmation is required and cannot be bypassed by the VSIX. Kiro registers the Power MCP under a namespaced entry. Setup does not equate a direct MCP probe with scan readiness; it remains `Configured` until that native registration is detected and verified.

## Repair and removal

**Install and verify** changes to **Repair and verify** when an entry already exists. Repair refreshes the stable runtime, exact MCP command, steering, and verification state; Kiro Power registration must still be present and reverified. **Remove Agent integration** removes only VSIX-managed bootstrap MCP and steering entries; unrelated servers, scan history, exports, and separately imported native Powers are retained.
