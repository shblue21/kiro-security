# Security model

## Trust boundaries

| Boundary | Untrusted input | Enforcement |
|---|---|---|
| Workspace → extension host | Paths, files, Git state, settings | Workspace Trust required; URI canonicalization; workspace containment; no automatic execution in untrusted workspaces |
| Webview → extension host | Every posted message and field | Discriminated message validator, size limits, command allowlist, nonce CSP, no direct filesystem/DB access |
| Extension host → engine | Workspace path, scope, Git refs, export destination, finding IDs | Versioned RPC schema, canonical paths, regex and length constraints, subprocess argument arrays |
| Engine → workspace | Source reads, artifact writes, and explicitly approved remediation patches | Scope containment, symlink resolution, bounded input, atomic artifact writes, prepared-patch digest/revision/file-drift gates, existing-file-only patch policy |
| Engine → SQLite | All persisted values | Parameterized SQL, transactions, foreign keys, WAL, busy timeout, migrations and backup |
| MCP client → Python MCP server | Tool names and JSON arguments | MCP method/tool allowlist, strict argument validation, canonical workspace root, same service/workbench |
| VSIX → Kiro Agent configuration | Existing JSONC, target paths, prepared runtime | Explicit modal consent, JSONC-preserving merge, symlink/boundary checks, backups, atomic writes, end-to-end verification and rollback |
| Engine logs → UI/files | Source fragments and errors may contain secrets | Structured fields, token/key redaction, bounded excerpts, no environment dump |

## Controls

- **Workspace trust:** activation may render setup information, but scanning commands fail closed until the workspace is trusted.
- **Command execution:** Python and Git are spawned with executable plus argument arrays. No shell command strings are built.
- **Environment:** engine processes receive a minimal allowlist plus `PYTHONPATH`, locale, and required platform variables. Python is started with `-B -S` so it neither writes bytecode into the packaged runtime nor loads ambient `site`/user-site customization. Secret values are not forwarded by default.
- **Path traversal:** scope and source paths are resolved against the canonical workspace. Absolute paths, NUL bytes, `..` escapes, and symlink escapes are rejected.
- **Webview CSP:** `default-src 'none'`; scripts require a per-render nonce; style/image/font resources are limited to the Webview source and approved schemes; no CDN or remote network origin is used.
- **Local resource roots:** limited to packaged Webview/media output.
- **Secrets:** optional analyzer credentials use VS Code `SecretStorage`. Settings and logs contain only a presence flag.
- **Exports:** default to the workspace export directory. An external destination is accepted only with an explicit allow-root selected by the extension host and revalidated in the engine. Per-finding exports use the same boundary.
- **Tracking:** the engine creates an exact digest-bound handoff and records bounded, sanitized connector readback. It does not receive provider credentials, search providers, or make GitHub, Linear, Jira, or other provider network writes; those actions require a separately authorized integration.
- **Remediation:** the engine never executes commands supplied by a model. It may apply only the exact prepared existing-file patch after explicit approval and fresh revision, digest, path, symlink, and file-drift validation. Verification commands and tests run in Kiro Agent under its own consent boundary, and only bounded results are submitted to the engine.
- **History cleanup:** only terminal or interrupted scans can be deleted. Every artifact path is revalidated against the canonical state directory, symlink targets outside that boundary are rejected, and explicit external exports are retained.
- **SQLite:** all queries are parameterized. Migrations are versioned and preceded by a backup. Corruption is surfaced as a structured engine error.
- **Cancellation:** cancellation is idempotent and durable. A terminal state wins over late worker events.
- **Deactivation:** the extension requests graceful handoff, waits for acknowledgement, disposes channels/providers, and only terminates the process as a last resort.
- **Telemetry:** disabled by default. The current implementation contains no telemetry transport.
- **Dependencies:** Node dependencies are pinned in `package-lock.json`; Python runtime uses only the standard library for production.

## Residual risks

Fast Scan is deterministic static analysis. Standard, Diff, and Deep delegate bounded discovery and tail assignments to Kiro Agent, but the engine is not a sandbox and does not execute repository build scripts, package managers, arbitrary tests, proof-of-concept payloads, or model-submitted commands. Agent-reported tests, PoCs, connector readback, and completion attestations remain host-supplied evidence subject to contract validation rather than independently reproduced engine facts.

Patch materialization and SQLite state transitions cannot form one operating-system transaction. The implementation drift-checks before apply, records digests and state transitions, and fails closed, but a process or filesystem failure can still leave workspace bytes changed before the durable verification state advances. Tracking has the analogous external-system boundary: the engine can bind and record sanitized readback, but cannot atomically prove a separately authorized provider mutation. Actual Kiro Desktop delegated multi-round behavior also remains an explicit release verification gate.

## Agent setup controls

The Setup UI displays exact target paths and approval policy before modification. Workspace Trust is mandatory. MCP and steering files must be regular files beneath the selected workspace or user boundary; symbolic-link traversal is rejected. Existing JSONC is parsed before any write, unrelated entries and comments are retained, and backups are stored under extension global storage. The installer copies only allowlisted `.py`, `.sql`, `.json`, and Power Markdown files from the trusted extension root. Before every process launch it compares the complete prepared payload with the packaged VSIX, rejects changed or missing files and unexpected import-shadow files, and validates the generated Power `mcp.json`. It then verifies the exact Python executable, `-B -S -m kiro_security.mcp_server` argument list, allowlisted environment keys, prepared-runtime `PYTHONPATH`, workspace binding rules, and read-only approval set. A changed or same-named unmanaged server is never executed by verification and is not deleted by removal. Read-only auto-approval never includes scan start/cancel, validation, triage, remediation, tracking, hardening, threat model, or export tools.
