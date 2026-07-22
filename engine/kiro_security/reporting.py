from __future__ import annotations

from typing import Any


def coverage_mode(scan: dict[str, Any]) -> str:
    if scan["mode"] == "deep":
        return "deep_repository" if scan["scope"] == "." else "scoped_path"
    if scan["mode"] == "diff":
        kind = scan.get("diff_target_kind") or "working_tree"
        return {"working_tree": "working_tree", "commit": "commit", "range": "branch_diff"}.get(kind, "diff")
    return "repository" if scan["scope"] == "." else "scoped_path"


def build_findings_document(scan_id: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Project indexed canonical findings without inventing scan semantics."""

    result: list[dict[str, Any]] = []
    for item in findings:
        details = item.get("details") if isinstance(item.get("details"), dict) else {}
        validation = details.get("validation") if isinstance(details.get("validation"), dict) else item.get("validation")
        attack_path = details.get("attackPath") if isinstance(details.get("attackPath"), dict) else item.get("attackPath")
        projected = {
            "findingId": item["findingId"],
            "occurrenceId": item["occurrenceId"],
            "ruleId": item["ruleId"],
            "identity": item["identity"],
            "fingerprints": {"algorithm": "kiro-security/v1", "primary": item["fingerprint"]},
            "title": item["title"],
            "summary": item["summary"],
            "severity": item["severity"],
            "confidence": item["confidence"],
            "taxonomy": item["taxonomy"],
            "locations": item.get("locations") or [],
            "codeEvidence": item.get("codeEvidence") or [],
            "rootCause": details.get("rootCause"),
            "validation": validation,
            "attackPath": attack_path,
            "remediation": item["remediation"],
            "remediationTests": details.get("remediationTests") or [],
            "preventiveControls": details.get("preventiveControls") or [],
            "provenance": details["provenance"],
        }
        if isinstance(details.get("writeup"), dict):
            projected["writeup"] = details["writeup"]
        result.append(projected)
    return {
        "documentType": "kiro-security-power.findings",
        "schemaVersion": "1.0",
        "scanId": scan_id,
        "findings": result,
    }
