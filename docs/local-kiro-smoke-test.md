# Local Kiro desktop smoke test

Cloud checks prove build, engine behavior, protocol contracts, state sharing, and VSIX packaging. They do not prove Kiro desktop rendering or interaction. Run this checklist on a machine with Kiro installed.

## Prepare an isolated profile

From the project root, build the VSIX and launch the verification helper:

```bash
npm ci
npm run package
scripts/verify-in-kiro.sh
```

Windows PowerShell:

```powershell
npm ci
npm run package
.\scripts\verify-in-kiro.ps1
```

The scripts search `KIRO_CLI`, then `kiro` on `PATH`, then common platform installation locations. They create isolated user-data and extensions directories, force-install the VSIX, verify that Kiro lists the extension, create a clean Git copy of the vulnerable fixture, and launch it. They do not mark visual or interactive checks as passed.

## Interactive checklist

Record each result in a copy of `docs/local-verification-result.example.json` and validate it against `docs/local-verification-result.schema.json`.

1. Confirm **Kiro Security** appears in the Activity Bar with the shield icon.
2. Run **Kiro Security: Open Security Panel on Right**. Confirm the Security view is in the Secondary Side Bar. When the environment cannot move views, confirm the separately labeled beside-editor panel fallback appears instead; do not record the fallback as Secondary Side Bar success.
3. In Setup, confirm workspace, trust, engine, Python/SQLite, and Agent MCP status use the isolated fixture path.
4. Select **Install and verify**, review the exact workspace-scoped MCP and steering paths, and approve. Confirm the status becomes **Verified**, no separate Node dependency is requested, and an optional native Power folder is prepared.
5. Open a new Agent conversation or refresh Kiro MCP servers. Confirm `kiro-security-power` tools are visible and `security_get_capabilities` reports the same workbench database path shown by the VSIX.
6. Start a **Standard** scan. Confirm the six phases advance in order and progress changes without reloading the view.
7. Confirm findings are produced from the fixture source, not placeholder data. Expected categories include command injection, SQL injection, path traversal, and missing authorization.
8. Select a finding. Confirm evidence, source/sink locations, validation record, attack path, rationale, remediation, and metadata are populated from the engine.
9. Select **Open source**. Confirm Kiro opens the exact fixture file and line/range.
10. Confirm validated findings appear in **Problems**, use the finding ID as diagnostic code, and offer details/remediation Code Actions.
11. Triage a finding and generate remediation guidance. Refresh and confirm state persists.
12. Export Markdown, JSON, CSV, and SARIF. Open each generated file and confirm the selected scan ID and findings are present.
13. Restart Kiro with the same isolated profile. Confirm scan history, selected scan, findings, artifacts, and Agent integration status remain available.
14. Start a Deep scan, close Kiro during execution, reopen the same profile, and confirm the interrupted scan is offered for resume. Resume it and confirm completion.
15. Start a scan through the Agent's `security_start_scan`; confirm it appears in the VSIX History/Dashboard without manually editing MCP JSON.
16. Start a scan in the VSIX and query it through `security_get_scan`; confirm IDs and status match.
17. Disable and re-enable the extension. Confirm engine cleanup and recovery are normal. Remove Agent integration and confirm unrelated MCP entries remain. Then uninstall from the isolated profile and confirm no Activity Bar contribution remains after reload.

## Evidence to retain

Keep the completed result JSON, Kiro version, OS version, VSIX SHA-256, Output channel log with secrets reviewed/redacted, and screenshots only as supplementary evidence. A Webview browser harness or screenshot is not a substitute for these Kiro desktop checks.
