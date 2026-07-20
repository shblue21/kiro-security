from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from . import __version__
from .constants import ARTIFACT_KINDS, is_model_scan
from .coverage import coverage_finding_reference, expected_coverage_frontier, make_coverage_row
from .db import Workbench
from .security import atomic_write, write_json


def coverage_mode(scan: dict[str, Any]) -> str:
    if scan["mode"] == "deep":
        return "deep_repository" if scan["scope"] == "." else "scoped_path"
    if scan["mode"] == "diff":
        kind = scan.get("diff_target_kind") or "working_tree"
        return {"working_tree": "working_tree", "commit": "commit", "range": "branch_diff"}.get(kind, "diff")
    return "repository" if scan["scope"] == "." else "scoped_path"


def _finding_is_reportable(finding: dict[str, Any]) -> bool:
    attack = finding.get("attackPath") if isinstance(finding.get("attackPath"), dict) else {}
    return finding.get("validationStatus") != "rejected" and finding.get("triageStatus") not in (
        "false_positive",
        "already_fixed",
    ) and attack.get("policyDecision", "reportable") == "reportable"


def _finding_is_policy_deferred(finding: dict[str, Any]) -> bool:
    attack = finding.get("attackPath") if isinstance(finding.get("attackPath"), dict) else {}
    return attack.get("policyDecision") == "deferred"


def _markdown_text(value: Any) -> str:
    text = " ".join(value.split()) if isinstance(value, str) else ""
    if re.match(r"^(?:#{1,6}\s|[-+*]\s|>\s|```|\d+\.\s|\|)", text):
        text = f"Text: {text}"
    return re.sub(r"([\\`*\[\]<>])", r"\\\1", text)


def _finding_references_for_path(
    findings: list[dict[str, Any]], path: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    related = [
        finding
        for finding in findings
        if any(isinstance(location, dict) and location.get("path") == path for location in finding.get("locations") or [])
    ]
    reportable = [finding for finding in related if _finding_is_reportable(finding)]
    deferred = [finding for finding in related if _finding_is_policy_deferred(finding)]
    suppressed = [finding for finding in related if not _finding_is_reportable(finding) and not _finding_is_policy_deferred(finding)]
    evidence_refs = sorted(
        {
            str(evidence["id"])
            for finding in related
            for evidence in finding.get("codeEvidence") or []
            if isinstance(evidence, dict) and evidence.get("id") and evidence.get("path") == path
        }
    )
    return reportable, suppressed, deferred, evidence_refs


def synchronize_coverage_ledger(
    workbench: Workbench,
    scan: dict[str, Any],
    inventory_data: dict[str, Any],
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Materialize final row-level coverage receipts for reporting.

    Standard/Diff rows are closed by the deterministic scanner's exhaustive
    supported-file traversal. Deep rows must already have a merged row receipt;
    this function never invents a clean Deep receipt for a missing row.
    """

    frontier = expected_coverage_frontier(workbench, scan, inventory_data)
    supported = list(frontier["supported"].values())
    deferred = list(frontier["deferred"].values())
    final_rows: list[dict[str, Any]] = []
    existing = {item["rowId"]: item for item in workbench.list_coverage_rows(scan["id"])}

    for item in supported:
        row_id = str(item["rowId"])
        path = str(item["path"])
        surface = str(item.get("surface") or f"source_review:{item.get('language') or 'text'}")
        reportable, suppressed, policy_deferred, evidence_refs = _finding_references_for_path(findings, path)
        prior = existing.get(row_id)
        if is_model_scan(scan) and prior is not None and prior["disposition"] == "deferred":
            related = [*reportable, *suppressed, *policy_deferred]
            candidate_ids = (
                sorted({coverage_finding_reference(finding) for finding in related})
                if related
                else list(prior.get("candidateIds") or [])
            )
            final_rows.append(
                make_coverage_row(
                    row_id=row_id,
                    path=path,
                    surface=surface,
                    disposition="deferred",
                    reason=prior["reason"],
                    evidence_refs=sorted(set(prior.get("evidenceRefs") or []) | set(evidence_refs)),
                    candidate_ids=candidate_ids,
                    entrypoint=prior.get("entrypoint"),
                    root_control=prior.get("rootControl"),
                    sink=prior.get("sink"),
                    worker_id=prior.get("workerId"),
                )
            )
            continue
        if policy_deferred:
            related = [*policy_deferred, *reportable]
            candidate_ids = sorted({coverage_finding_reference(finding) for finding in related})
            final_rows.append(
                make_coverage_row(
                    row_id=row_id,
                    path=path,
                    surface=surface,
                    disposition="deferred",
                    reason=f"The completed attack-path review deferred {len(policy_deferred)} candidate(s) pending additional proof.",
                    evidence_refs=evidence_refs,
                    candidate_ids=candidate_ids,
                    entrypoint=(existing.get(row_id) or {}).get("entrypoint"),
                    root_control=(existing.get(row_id) or {}).get("rootControl"),
                    sink=(existing.get(row_id) or {}).get("sink"),
                )
            )
            continue
        if reportable:
            candidate_ids = sorted({coverage_finding_reference(finding) for finding in reportable})
            final_rows.append(
                make_coverage_row(
                    row_id=row_id,
                    path=path,
                    surface=surface,
                    disposition="reportable",
                    reason=f"The completed scan linked {len(candidate_ids)} reportable finding(s) to this reviewed row.",
                    evidence_refs=evidence_refs,
                    candidate_ids=candidate_ids,
                    entrypoint=(existing.get(row_id) or {}).get("entrypoint"),
                    root_control=(existing.get(row_id) or {}).get("rootControl"),
                    sink=(existing.get(row_id) or {}).get("sink"),
                )
            )
            continue
        if suppressed:
            candidate_ids = sorted({coverage_finding_reference(finding) for finding in suppressed})
            final_rows.append(
                make_coverage_row(
                    row_id=row_id,
                    path=path,
                    surface=surface,
                    disposition="suppressed",
                    reason=f"The completed scan linked {len(candidate_ids)} candidate(s) to this row, but final validation or triage suppressed them.",
                    evidence_refs=evidence_refs,
                    candidate_ids=candidate_ids,
                    entrypoint=(existing.get(row_id) or {}).get("entrypoint"),
                    root_control=(existing.get(row_id) or {}).get("rootControl"),
                    sink=(existing.get(row_id) or {}).get("sink"),
                )
            )
            continue
        if is_model_scan(scan):
            if prior is not None:
                final_rows.append(
                    make_coverage_row(
                        row_id=row_id,
                        path=path,
                        surface=surface,
                        disposition=prior["disposition"],
                        reason=prior["reason"],
                        evidence_refs=prior.get("evidenceRefs") or [],
                        candidate_ids=prior.get("candidateIds") or [],
                        entrypoint=prior.get("entrypoint"),
                        root_control=prior.get("rootControl"),
                        sink=prior.get("sink"),
                        worker_id=prior.get("workerId"),
                    )
                )
            # Missing Deep rows stay absent and therefore become unclosed/partial.
            continue
        final_rows.append(
            make_coverage_row(
                row_id=row_id,
                path=path,
                surface=surface,
                disposition="not_applicable",
                reason=(
                    "The bounded deterministic scanner completed its configured rule-family review for this source row "
                    "and produced no candidate. This receipt proves execution, not that the file is vulnerability-free."
                ),
            )
        )

    final_rows.extend(deferred)
    return workbench.replace_coverage_rows(scan["id"], final_rows)


def build_coverage_document(
    workbench: Workbench,
    scan: dict[str, Any],
    inventory_data: dict[str, Any],
) -> dict[str, Any]:
    frontier = expected_coverage_frontier(workbench, scan, inventory_data)
    expected_supported = list(frontier["supported"].values())
    expected = frontier["all"]
    ledger_rows = workbench.list_coverage_rows(scan["id"])
    ledger_by_id = {item["rowId"]: item for item in ledger_rows}
    unclosed = [
        {
            "rowId": row_id,
            "path": str(item.get("path") or scan["scope"]),
            "surface": str(item.get("surface") or "unknown"),
            "reason": "No disposition receipt was recorded for this in-scope row.",
        }
        for row_id, item in sorted(expected.items())
        if row_id not in ledger_by_id
    ]
    surfaces = []
    for row_id, item in sorted(ledger_by_id.items(), key=lambda pair: (pair[1]["path"], pair[0])):
        if row_id not in expected:
            continue
        surface = {
            "id": item["id"],
            "rowId": item["rowId"],
            "path": item["path"],
            "label": f"{item['path']} — {item['surface'].replace('_', ' ')}",
            "surface": item["surface"],
            "disposition": item["disposition"],
            "reason": item["reason"],
            "receiptDigest": item["receiptDigest"],
            "receiptRefs": [item["receiptDigest"]],
            "evidenceRefs": item.get("evidenceRefs") or [],
            "candidateIds": item.get("candidateIds") or [],
            "workerId": item.get("workerId"),
        }
        for optional in ("entrypoint", "rootControl", "sink"):
            if item.get(optional):
                surface[optional] = item[optional]
        surfaces.append(surface)

    deferred = [
        {
            "id": item["id"],
            "rowId": item["rowId"],
            "path": item["path"],
            "reason": item["reason"],
            "receiptDigest": item["receiptDigest"],
        }
        for item in ledger_rows
        if item["rowId"] in expected and item["disposition"] == "deferred"
    ]
    deep_state = workbench.get_deep_scan_state(scan["id"]) if is_model_scan(scan) else None
    deep_status = deep_state.get("status") if deep_state else None
    supported_count = len(expected_supported)
    if supported_count == 0:
        completeness = "unknown"
    elif deep_status == "capped":
        completeness = "partial"
    elif unclosed or deferred:
        completeness = "partial"
    else:
        completeness = "complete"

    open_questions: list[dict[str, str]] = []
    for warning in inventory_data.get("warnings") or []:
        open_questions.append({"question": str(warning)})
    if supported_count == 0:
        open_questions.append(
            {"question": "No supported source files were reviewed; coverage completeness is unknown."}
        )
    if deep_status == "capped":
        open_questions.append(
            {
                "question": (
                    f"Deep discovery reached its round cap at round {deep_state.get('current_round')}; "
                    "coverage is partial even when every current row has a receipt."
                )
            }
        )
    if unclosed:
        open_questions.append(
            {"question": f"{len(unclosed)} in-scope row(s) have no disposition receipt."}
        )
    if deferred:
        open_questions.append(
            {"question": f"{len(deferred)} in-scope row(s) were explicitly deferred and not reviewed."}
        )
    unexpected = sorted(set(ledger_by_id) - set(expected))
    if unexpected:
        open_questions.append(
            {"question": f"{len(unexpected)} stale or unexpected ledger row(s) were excluded from this coverage projection."}
        )

    return {
        "documentType": "kiro-security-power.coverage",
        "schemaVersion": "1.0",
        "scanId": scan["id"],
        "mode": coverage_mode(scan),
        "completeness": completeness,
        "inventoryStrategy": "diff" if scan["mode"] == "diff" else ("repository" if scan["scope"] == "." else "scoped_path"),
        "includePaths": inventory_data.get("includePaths", [scan["scope"]]),
        "excludePaths": inventory_data.get("excludePaths", []),
        "supportedFileCount": supported_count,
        "inScopeRowCount": len(expected),
        "closedRowCount": len(expected) - len(unclosed),
        "deepStatus": deep_status,
        "surfaces": surfaces,
        "unclosedRows": unclosed,
        "explicitExclusions": [
            {"pattern": item, "reason": "The resolved path was outside the canonical workspace boundary."}
            for item in inventory_data.get("excludePaths", [])
        ],
        "deferred": deferred,
        "openQuestions": open_questions,
    }


def build_findings_document(
    scan_id: str,
    findings: list[dict[str, Any]],
    writeup_paths: dict[str, str] | None = None,
    tail_results: dict[str, dict[str, dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    writeup_paths = writeup_paths or {}
    result: list[dict[str, Any]] = []
    for item in findings:
        validation = (tail_results or {}).get("validation", {}).get(item["occurrenceId"], item.get("validation"))
        attack = (tail_results or {}).get("attack_path", {}).get(item["occurrenceId"], item.get("attackPath"))
        locations = item.get("locations", [])
        source = next((location for location in locations if location.get("role") == "source"), None)
        sink = next((location for location in locations if location.get("role") == "sink"), None)
        details = item.get("details") or {}
        root_cause = {
            "summary": item["summary"],
            "evidenceRefs": [evidence["id"] for evidence in item.get("codeEvidence", [])],
        }
        provenance = {"source": "kiro_security_power", "engineVersion": __version__}
        deep_provenance = details.get("deepProvenance")
        if isinstance(deep_provenance, dict):
            provenance["deep"] = deep_provenance
        deep_tail_provenance = details.get("deepTailProvenance")
        if isinstance(deep_tail_provenance, dict):
            provenance["deepTail"] = deep_tail_provenance
        finding = {
            "findingId": item["findingId"],
            "occurrenceId": item["occurrenceId"],
            "ruleId": item["ruleId"],
            "identity": item["identity"],
            "fingerprints": {
                "algorithm": "kiro-security/deep-v1" if str(item["fingerprint"]).startswith("kiro-security/deep-v1:") else "kiro-security/v1",
                "primary": item["fingerprint"],
            },
            "title": item["title"],
            "summary": item["summary"],
            "severity": item["severity"],
            "confidence": item["confidence"],
            "taxonomy": item["taxonomy"],
            "locations": locations,
            "codeEvidence": item.get("codeEvidence", []),
            "remediation": item["remediation"],
            "validation": validation,
            "attackPath": attack,
            "remediationTests": ["Add a regression test proving the original attacker-controlled input no longer reaches the sink."],
            "preventiveControls": ["Centralize the affected security boundary and block unsafe direct use in review or linting."],
            "provenance": provenance,
            "extensions": {
                "validationStatus": item.get("validationStatus"),
                "triageStatus": item.get("triageStatus"),
                "source": source,
                "sink": sink,
            },
        }
        explicit_root_cause = details.get("rootCause")
        structured_root_cause = isinstance(explicit_root_cause, dict) and (
            set(explicit_root_cause).issubset({"summary", "evidenceRefs"})
            and isinstance(explicit_root_cause.get("summary"), str)
            and bool(explicit_root_cause["summary"].strip())
            and (
                "evidenceRefs" not in explicit_root_cause
                or isinstance(explicit_root_cause["evidenceRefs"], list)
                and all(isinstance(reference, str) for reference in explicit_root_cause["evidenceRefs"])
            )
        )
        if structured_root_cause or (
            isinstance(explicit_root_cause, str) and explicit_root_cause.strip()
        ):
            finding["rootCause"] = explicit_root_cause
        elif details.get("legacyContract") is not True and details.get("discoveryEngine") != "kiro-agent-deep-orchestration":
            finding["rootCause"] = root_cause
        if item["findingId"] in writeup_paths:
            finding["writeup"] = {"reportPath": writeup_paths[item["findingId"]]}
        result.append(finding)
    return {
        "documentType": "kiro-security-power.findings",
        "schemaVersion": "1.0",
        "scanId": scan_id,
        "findings": result,
    }


def _write_writeups(artifact_dir: Path, findings: list[dict[str, Any]]) -> dict[str, str]:
    paths: dict[str, str] = {}
    for item in findings:
        if item.get("validationStatus") == "rejected" or item.get("triageStatus") in ("false_positive", "already_fixed"):
            continue
        relative = Path("writeups") / f"{item['findingId']}.md"
        path = artifact_dir / relative
        locations = item.get("locations", [])
        lines = [
            f"# {_markdown_text(item['title'])}",
            "",
            f"- Finding ID: `{item['findingId']}`",
            f"- Severity: **{item['severity']['level']}**",
            f"- Confidence: **{item['confidence']['level']}**",
            f"- Validation: **{item.get('validationStatus', 'unvalidated')}**",
            "",
            "## Summary",
            "",
            _markdown_text(item["summary"]),
            "",
            "## Evidence",
            "",
        ]
        for location in locations:
            lines.append(
                f"- {_markdown_text(location['path'])}:{location['startLine']} "
                f"({_markdown_text(location.get('role', 'evidence'))})"
            )
        if item.get("attackPath"):
            lines.extend(["", "## Attack path", "", _markdown_text(item["attackPath"]["narrative"]), "", "## Impact", "", _markdown_text(item["attackPath"]["impact"])])
        lines.extend(["", "## Remediation", "", _markdown_text(item["remediation"]), "", "## Verification", "", _markdown_text(item.get("validation", {}).get("rationale", "Targeted validation has not been run.")), ""])
        atomic_write(path, "\n".join(lines))
        paths[item["findingId"]] = relative.as_posix()
    return paths


def write_canonical_documents(
    workbench: Workbench,
    scan_id: str,
    inventory_data: dict[str, Any],
    threat_model: dict[str, Any],
    *,
    writeup_paths: dict[str, str] | None = None,
    tail_results: dict[str, dict[str, dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    scan = workbench.get_scan(scan_id)
    artifact_dir = Path(scan["artifact_dir"])
    artifact_dir.mkdir(parents=True, exist_ok=True)
    findings = [workbench.get_finding(item["occurrenceId"]) for item in workbench.list_findings(scan_id)]
    writeup_paths = _write_writeups(artifact_dir, findings) if writeup_paths is None else writeup_paths
    synchronize_coverage_ledger(workbench, scan, inventory_data, findings)
    coverage = build_coverage_document(workbench, scan, inventory_data)
    findings_document = build_findings_document(scan_id, findings, writeup_paths, tail_results)
    discovery_document = {
        "documentType": "kiro-security-power.discovery",
        "schemaVersion": "1.0",
        "scanId": scan_id,
        "candidates": [
            {
                "findingId": item["findingId"],
                "occurrenceId": item["occurrenceId"],
                "ruleId": item["ruleId"],
                "title": item["title"],
                "locations": item["locations"],
            }
            for item in findings
        ],
    }
    validation_document = {
        "documentType": "kiro-security-power.validation",
        "schemaVersion": "1.0",
        "scanId": scan_id,
        "records": [
            (tail_results or {}).get("validation", {}).get(item["occurrenceId"], item["validation"])
            for item in findings if item.get("validation")
        ],
    }
    attack_document = {
        "documentType": "kiro-security-power.attack-paths",
        "schemaVersion": "1.0",
        "scanId": scan_id,
        "paths": [
            {
                "findingId": item["findingId"], "occurrenceId": item["occurrenceId"],
                **(tail_results or {}).get("attack_path", {}).get(item["occurrenceId"], item["attackPath"]),
            }
            for item in findings
            if item.get("attackPath")
        ],
    }
    paths = {
        "coverage": artifact_dir / ARTIFACT_KINDS["coverage"],
        "findings": artifact_dir / ARTIFACT_KINDS["findings"],
        "discovery": artifact_dir / ARTIFACT_KINDS["discovery"],
        "validation": artifact_dir / ARTIFACT_KINDS["validation"],
        "attackPath": artifact_dir / ARTIFACT_KINDS["attackPath"],
    }
    documents = {
        "coverage": coverage,
        "findings": findings_document,
        "discovery": discovery_document,
        "validation": validation_document,
        "attackPath": attack_document,
    }
    for kind, path in paths.items():
        write_json(path, documents[kind])
    # The inventory is the durable proof of the coverage frontier. It is
    # (re)written here so finalization can seal it as a supporting artifact
    # that byte-matches the frontier used for canonical coverage validation.
    inventory_path = artifact_dir / "inventory.json"
    write_json(inventory_path, inventory_data)
    workbench.add_artifact(scan_id, "inventory", inventory_path, "application/json")
    return {
        "scanId": scan_id,
        "artifactDir": artifact_dir,
        "paths": {**paths, "inventory": inventory_path},
        "documents": documents,
        "findings": findings,
        "writeupPaths": writeup_paths,
        "threatModel": threat_model,
        "inventory": inventory_data,
    }
