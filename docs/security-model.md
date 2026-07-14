# Security model

## Trust boundaries

| Boundary | Untrusted input | Enforcement |
|---|---|---|
| Workspace → extension host | Paths, files, Git state, settings | Workspace Trust required; URI canonicalization; workspace containment; no automatic execution in untrusted workspaces |
| Webview → extension host | Every posted message and field | Discriminated message validator, size limits, command allowlist, nonce CSP, no direct filesystem/DB access |
| Extension host → engine | Workspace path, scope, Git refs, export destination, finding IDs | Versioned RPC schema, canonical paths, regex and length constraints, subprocess argument arrays |
| Engine → workspace | Source reads and artifact writes | Scope containment, symlink resolution, ignored runtime directories, bounded file size/count, atomic writes |
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
- **Tracking:** the engine creates approval-ready handoff artifacts only. It does not send credentials or write to GitHub, Linear, Jira, or another tracker; submission requires a separately authorized integration.
- **History cleanup:** only terminal or interrupted scans can be deleted. Every artifact path is revalidated against the canonical state directory, symlink targets outside that boundary are rejected, and explicit external exports are retained.
- **SQLite:** all queries are parameterized. Migrations are versioned and preceded by a backup. Corruption is surfaced as a structured engine error.
- **Cancellation:** cancellation is idempotent and durable. A terminal state wins over late worker events.
- **Deactivation:** the extension requests graceful handoff, waits for acknowledgement, disposes channels/providers, and only terminates the process as a last resort.
- **Telemetry:** disabled by default. Version 0.2.0 contains no telemetry transport.
- **Dependencies:** Node dependencies are pinned in `package-lock.json`; Python runtime uses only the standard library for production.

## Residual risks

The built-in analyzer is deterministic static analysis, not a sandbox. It intentionally does not execute repository build scripts, package managers, arbitrary tests, or proof-of-concept payloads. This reduces code-execution risk but means some findings remain `needs_review`. Dynamic validation requires an explicit future adapter and separate consent boundary.

## Agent setup controls

The Setup UI displays exact target paths and approval policy before modification. Workspace Trust is mandatory. MCP and steering files must be regular files beneath the selected workspace or user boundary; symbolic-link traversal is rejected. Existing JSONC is parsed before any write, unrelated entries and comments are retained, and backups are stored under extension global storage. The installer copies only allowlisted `.py`, `.sql`, `.json`, and Power Markdown files from the trusted extension root. Before every process launch it compares the complete prepared payload with the packaged VSIX, rejects changed or missing files and unexpected import-shadow files, and validates the generated Power `mcp.json`. It then verifies the exact Python executable, `-B -S -m kiro_security.mcp_server` argument list, allowlisted environment keys, prepared-runtime `PYTHONPATH`, workspace binding rules, and read-only approval set. A changed or same-named unmanaged server is never executed by verification and is not deleted by removal. Read-only auto-approval never includes scan start/cancel, validation, triage, remediation, tracking, hardening, threat model, or export tools.
