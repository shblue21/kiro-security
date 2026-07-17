---
name: "kiro-security-power"
displayName: "Kiro Security Power"
description: "Run repository security scans, threat modeling, finding validation, attack-path analysis, triage, remediation, hardening, tracking handoffs, and report exports through the Kiro Security Power VSIX and shared workbench."
keywords: ["security", "appsec", "vulnerability", "threat model", "security scan", "SARIF", "CWE", "attack path", "triage", "remediation", "hardening"]
author: "Kiro Security Power project"
---

# Kiro Security Power

Kiro Security Power is the Agent workflow layer for the installed **Kiro Security Power** VSIX. It is not an official OpenAI, Codex, or Kiro product. The VSIX owns lifecycle, workspace trust, IDE UI, diagnostics, source navigation, and the durable workbench. The MCP server delegates to the same Python engine and `<workspace>/.kiro/security-power/workbench.sqlite` used by the VSIX.

## Onboarding

1. Confirm the **Kiro Security Power** VSIX is installed and the current workspace is trusted.
2. Open the VSIX Setup screen and run **Install Agent Integration**.
3. Call `security_get_capabilities` before substantive work. Do not continue if the tool reports an incompatible Python runtime, inaccessible workspace, or damaged workbench.
4. Never create a second findings database or substitute ad-hoc grep output for the shared scan engine.
5. Do not claim that a scan, external issue, patch, or report exists unless the corresponding tool returned its durable record or artifact path.

## Operating contract

1. Use VSIX Fast Scan only for deterministic heuristic pre-screening. Start model `standard`, `deep`, or `diff` through Kiro Agent with `analysisProfile: "model"`, the selected model identity, and truthful host runtime attestation.
2. For Deep mode, follow `steering/deep-security-scan.md`: operate six independent model workers per round, submit exhaustive receipts, perform semantic merge, and repeat until a complete zero-novelty round or the explicit round-10 cap. Never substitute Standard output.
3. Standard/Diff model discovery reuses one six-worker round, semantic merge, and the same durable model tail; Deep repeats six-worker rounds to zero novelty or its cap. Use `security_deep_get_status` and the worker/merge/tail tools for all model profiles, then poll `security_get_scan` for finalization. Honor cooperative cancellation and interrupted/resumable state.
4. Read findings through `security_list_findings` and full evidence through `security_get_finding`.
5. Treat discovery output as candidate evidence. For VSIX Fast findings, use `security_validate_finding` before representing a finding as verified. Model scans already use authoritative tail validation and attack-path proof; read it through `security_get_finding` and do not overwrite it with deterministic validation.
6. Record user-directed dispositions through `security_triage_finding`; never silently suppress or relabel findings.
7. Use remediation and tracking tools for durable workflow records. Use `security_create_hardening_proposal` only for Fast scans; model scans already materialize the immutable tail hardening portfolio.
8. Use `security_export_report` for Markdown, JSON, CSV, or SARIF deliverables and report the exact returned path.
9. Scans started by the Agent and VSIX remain mutually visible because both use the same SQLite workbench.

## Workflow steering

- Repository-wide standard scan → `steering/repository-security-scan.md`
- Multi-pass deep scan → `steering/deep-security-scan.md`
- Git working-tree, commit, or range scan → `steering/security-diff-scan.md`
- Threat model creation or refresh → `steering/threat-model.md`
- Finding evidence review → `steering/finding-review.md`
- Finding validation and attack-path closure → `steering/finding-validation.md`
- Triage or risk acceptance → `steering/finding-triage.md`
- Remediation guidance → `steering/finding-remediation.md`
- Structural hardening portfolio → `steering/hardening-proposal.md`
- Markdown, JSON, CSV, or SARIF export → `steering/report-export.md`
- Approval-gated tracking handoff → `steering/finding-tracking.md`
