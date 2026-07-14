# Changelog

## 0.2.0 — 2026-07-14

- Added an approval-driven **Install or Repair Agent Integration** flow to the VSIX Setup view, plus a one-time per-workspace onboarding prompt after upgrade.
- Added safe workspace/user MCP configuration merging with JSONC preservation, backups, rollback, repair, verification, and managed-only removal. User-scoped MCP stays workspace-neutral.
- Added auto-inclusion Kiro steering and a prepared custom-Power folder for optional native Powers-panel registration.
- Added a dependency-light Python MCP server that uses the same engine and SQLite workbench as the VSIX.
- Added runtime discovery for macOS, Windows, and Linux; Python 3.9 with `sqlite3` is now the supported minimum.
- Removed Python 3.10-only `dataclass(slots=True)` usage and latched engine startup failures to prevent retry loops.
- Added prepared-runtime integrity validation, import-shadow rejection, `-B -S` Python isolation, and symlink-safe MCP/steering file handling.
- Added Agent integration, Python 3.9 grammar, MCP contract, rollback-safety, and shared-workbench tests.

## 0.1.0 — 2026-07-14

- Initial VSIX-first Kiro Security Power implementation.
