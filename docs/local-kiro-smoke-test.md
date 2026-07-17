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
6. Start a **Fast** scan from the VSIX. Confirm it is explicitly described as deterministic heuristic pre-screening, the six phases advance in order, and progress changes without reloading the view.
7. Confirm findings are produced from the fixture source, not placeholder data. Expected categories include command injection, SQL injection, path traversal, and missing authorization.
8. Select a finding. Confirm evidence, source/sink locations, validation record, attack path, rationale, remediation, and metadata are populated from the engine.
9. Select **Open source**. Confirm Kiro opens the exact fixture file and line/range.
10. Confirm validated findings appear in **Problems**, use the finding ID as diagnostic code, and offer details/remediation Code Actions.
11. Triage a finding and generate remediation guidance. Refresh and confirm state persists.
12. Export Markdown, JSON, CSV, and SARIF. Open each generated file and confirm the selected scan ID and findings are present.
13. Restart Kiro with the same isolated profile. Confirm scan history, selected scan, findings, artifacts, and Agent integration status remain available.
14. Through Kiro Agent, start a model **Standard** scan with truthful model/runtime attestation. Confirm six fresh discovery workers share one profile, all-six claim completes before submission, one semantic merge closes the round as saturated, and validation/attack-path/writeup/hardening assignments finish before finalization.
15. Create a Git change that removes a security control and renames an affected file. Through Kiro Agent, start a model **Diff** scan and confirm the immutable assignment includes bounded hunk/deleted-control/rename context plus repository caller or sibling review paths.
16. Start a **Deep** scan through Kiro Agent. Confirm exactly six independent workers are assigned per round, at least one novel first round creates another round, and a zero-novelty round saturates discovery. Close Kiro with a worker or tail assignment claimed, reopen the same profile, resume, and confirm the orphaned claim is replaced without duplicating completed assignments. If the first round has zero novelty, leave `deepMultiRound` false or null and record the observed scan ID; do not substitute a single-round run as PASS.
17. Confirm the completed Deep tail contains canonical threat model, validation proof and counterevidence, attack-path severity reassessment, dedicated finding writeup, and hardening JSON/Markdown. Confirm `coverage.json`, `findings.json`, and `scan-manifest.json` validate and the manifest seal matches the durable DB digest.
18. Confirm scans started through Agent `security_start_scan` appear in VSIX History/Dashboard, and a VSIX Fast scan can be queried through `security_get_scan` with matching ID/status.
19. Disable and re-enable the extension. Confirm engine cleanup and recovery are normal. Remove Agent integration and confirm unrelated MCP entries remain. Then uninstall from the isolated profile and confirm no Activity Bar contribution remains after reload.

## Evidence to retain

Keep the completed result JSON, Kiro version, OS version, VSIX SHA-256, scan IDs, worker/merge and tail receipt digests, sealed manifest digest, Output channel log with secrets reviewed/redacted, and screenshots only as supplementary evidence. Set `testedAt` when recording results and include the retained evidence identifiers in `notes`. A Webview browser harness or screenshot is not a substitute for these Kiro desktop checks.
