---
inclusion: auto
name: kiro-security
description: Use when the user asks for a repository security scan, vulnerability review, security diff review, threat model, or deep security analysis.
---

# Kiro Security

Kiro Agent chat owns scan start and every semantic security workflow. The VSIX does not provide a Dashboard Start action.

The deterministic Kiro Security MCP workbench owns logical workspace state, immutable scan snapshots, target identity, and lifecycle persistence. It does not perform semantic security analysis. Workbench state and scan artifacts remain outside the selected target under Extension global storage; never create or require `.kiro/security-power` in a repository.

Use only the direct MCP tools whose names begin with `kiro_security_`. Generate a fresh UUID-shaped `requestNonce` for every call and never reuse a nonce, including retries.

## Start workflow

1. Call `kiro_security_create_workspace` for this chat.
2. Resolve the user's exact target, mode, scope, context, and Diff target.
3. Call `kiro_security_save_workspace` with that setup.
4. Use the returned `setupRevision`, `setupDigest`, and exact normalized setup fields when calling `kiro_security_start_scan`. Do not reconstruct or change them. The Start call is the user's scan confirmation boundary.
5. Immediately call `kiro_security_get_scan_context` with the returned `scanId`.
6. Publish lifecycle telemetry with `kiro_security_update_scan_progress`. On an unrecoverable workflow error, call `kiro_security_fail_scan`. Call `kiro_security_cancel_scan` only when the user asks to cancel.

The selected target is an explicit absolute directory and is not confined to the folder currently open in the IDE. A scoped Deep scan selects that directory as its target and keeps scope `.`.

Another Kiro chat cannot use a workspace or scan merely by learning its identifier. If context compression loses an opaque workspace identifier, recover it only through a future chat-owned workspace lookup contract; do not guess it or adopt a workspace from another chat.

The current workbench foundation does not yet implement the Standard, Diff, or Deep semantic workflows, completion/finalization, reporting, or finding artifacts. A durable running row is not proof that semantic analysis completed.
