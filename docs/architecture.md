# Architecture

## Ownership model

Kiro Security Power is a VSIX-first product. The extension host owns activation, workspace trust, commands, Kiro/VS Code UI integration, engine lifecycle, diagnostics, navigation, cancellation, and cleanup. The Webview owns presentation only. The Python engine owns analysis workflows, artifact generation, and durable SQLite state. The Power and MCP server are companion agent interfaces over the same engine and database.

```text
Kiro IDE
└── Kiro Security Power VSIX
    ├── commands / status bar / output / diagnostics / code actions
    ├── Security WebviewView and beside WebviewPanel fallback
    ├── typed Webview message validation
    └── EngineProcessManager (spawn executable + argument array)
             │ JSON-RPC 2.0, protocol kiro-security-rpc/1.0
             ▼
    Python Security Engine
    ├── preflight → threat_model → discovery → validation
    │                    → attack_path → reporting
    ├── standard / deep / diff runners
    ├── JSON, CSV, SARIF, Markdown and per-finding exports
    ├── approval-ready tracking handoffs and safe history cleanup
    └── SQLite workbench in <workspace>/.kiro/security-power/
             ▲
             │ same RPC and workbench
    Kiro Agent integration
    ├── Python MCP stdio server (one-click Setup path)
    ├── auto-inclusion steering
    ├── optional native Kiro Power registration
    └── Node MCP compatibility adapter
```

## Packages

- `packages/extension`: VSIX extension host, commands, view provider, diagnostics, source navigation, status and logging.
- `packages/protocol`: shared TypeScript request/event/domain types and strict boundary validation.
- `packages/webview`: CSP-constrained HTML/CSS/JavaScript UI and testable state helpers.
- `packages/mcp`: Node stdio compatibility adapter that delegates to the Python RPC server.
- `engine/kiro_security/mcp_server.py`: dependency-light Python MCP server used by the one-click Agent Setup path.
- `engine/kiro_security`: Python engine, migrations, scanner, validation, attack paths, reporting, exports, and RPC server.
- `powers/kiro-security-power`: companion Power instructions and opt-in MCP configuration template.

## Durable state

Default workspace state:

```text
<workspace>/.kiro/security-power/
├── workbench.sqlite
├── workbench.sqlite-wal
├── artifacts/<scan-id>/
│   ├── scan-manifest.json
│   ├── coverage.json
│   ├── findings.json
│   ├── report.md
│   ├── threat-model.md
│   ├── discovery.json
│   ├── validation.json
│   ├── attack-path.json
│   ├── hardening/hardening.md
│   ├── writeups/<finding-id>.md
│   └── tracking/<finding-id>-<provider>.json
├── exports/
└── logs/
```

SQLite uses foreign keys, WAL journaling, a busy timeout, parameterized statements, explicit transactions, schema migrations, and a backup before migration. Engine sessions heartbeat into the database. Scans owned by stale sessions become `interrupted`, retain phase/progress/artifacts, and are eligible for `resume_scan`. Terminal or interrupted scans can be removed through `cleanup_scan`; cleanup is confined to the canonical state directory and intentionally preserves explicitly selected exports outside it.

## RPC lifecycle

The transport is one UTF-8 JSON object per line over stdio. The first request must be `initialize` with `protocolVersion: "1.0"`. Requests and responses use JSON-RPC 2.0. Events are notifications with the required names:

- `engine.ready`
- `scan.started`
- `scan.phaseChanged`
- `scan.progress`
- `finding.discovered`
- `finding.updated`
- `artifact.created`
- `scan.completed`
- `scan.cancelled`
- `scan.failed`
- `engine.log`

The extension also polls durable state so events emitted by an MCP-owned engine process appear in the VSIX.

## Scan execution

Standard mode performs one repository or scoped-path pass. Deep mode performs three independent deterministic passes—taint/source-to-sink, dangerous API/configuration, and authorization/boundary review—then merges findings by stable fingerprint before the centralized validation/reporting tail. Diff mode resolves changed files and line ranges from Git using argument arrays and analyzes only the requested working tree, commit, or range.

Each phase commits progress and artifacts independently. Cancellation is represented in SQLite and checked between files and phase work. Shutdown asks runner threads to hand off, persists `interrupted`, and exits without deleting partial state.

## Webview data flow

The Webview cannot read files or SQLite. It sends a small allowlisted message union to the extension. The extension validates message shape, workspace-relative scope, Git refs, finding identifiers, and export URIs before calling the engine. The extension sends full typed snapshots and incremental event messages back to the Webview.

## Secondary Side Bar behavior

The extension contributes a normal Activity Bar view container. The `Open Security Panel on Right` command first opens the view and invokes the stable workbench command to move it to the Secondary Side Bar. Because a manifest cannot guarantee initial right-side placement, onboarding records successful guidance in global state. When movement is unavailable, the extension opens a distinct `WebviewPanel` in `ViewColumn.Beside` and labels it as a fallback rather than claiming it is the Secondary Side Bar.


## Tracking boundary

Finding tracking is implemented as an approval-ready handoff rather than an implicit external write. The engine records a provider-neutral or GitHub/Linear/Jira-shaped payload, duplicate-check metadata, source links, and a digest in SQLite and under the scan artifact directory. A human or separately authorized connector can review and submit that payload. This preserves the reference approval boundary without embedding connector credentials or duplicating scan logic in MCP.

## Agent integration lifecycle

The extension host owns Agent installation. After explicit modal approval it resolves Python 3.9+ with SQLite, copies only approved Power and engine files into extension global storage, performs a JSONC-preserving merge into workspace or user MCP configuration, writes managed auto-inclusion steering, and verifies the process through MCP initialize, tools/list, and `security_get_capabilities`. The prepared runtime path is stable across VSIX version-directory replacement. Before execution, its complete allowlisted payload is compared with the installed VSIX and unexpected import-shadow files, symlinks, special files, altered schemas/migrations, or changed Power MCP settings are rejected. Python runs with `-B -S` and a minimal environment. Any failed verification restores captured files and the previous prepared runtime. The Kiro-native Powers-panel import remains a separate optional host confirmation.
