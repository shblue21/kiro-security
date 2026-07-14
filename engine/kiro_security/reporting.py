from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from . import __version__
from .constants import ARTIFACT_KINDS
from .db import Workbench
from .hardening import create_hardening_proposal
from .security import atomic_write, sha256_file, utc_now, write_json

_MEDIA_TYPES = {
    "manifest": "application/json",
    "coverage": "application/json",
    "findings": "application/json",
    "markdownReport": "text/markdown",
    "threatModel": "text/markdown",
    "discovery": "application/json",
    "validation": "application/json",
    "attackPath": "application/json",
    "hardening": "text/markdown",
}


def coverage_mode(scan: dict[str, Any]) -> str:
    if scan["mode"] == "deep":
        return "deep_repository" if scan["scope"] == "." else "scoped_path"
    if scan["mode"] == "diff":
        kind = scan.get("diff_target_kind") or "working_tree"
        return {"working_tree": "working_tree", "commit": "commit", "range": "branch_diff"}.get(kind, "diff")
    return "repository" if scan["scope"] == "." else "scoped_path"


def build_coverage_document(scan: dict[str, Any], inventory_data: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    categories = Counter(item["taxonomy"]["category"] for item in findings)
    surfaces = [
        {
            "id": f"surface_{category.replace('-', '_')}",
            "label": category.replace("-", " ").title(),
            "disposition": "reported" if count else "no_issue_found",
            "receiptRefs": [item["occurrenceId"] for item in findings if item["taxonomy"]["category"] == category],
            "riskArea": category,
            "notes": f"{count} candidate finding(s) discovered.",
        }
        for category, count in sorted(categories.items())
    ]
    if not surfaces:
        surfaces = [{"id": "surface_source_review", "label": "Supported source review", "disposition": "no_issue_found", "receiptRefs": []}]
    return {
        "documentType": "kiro-security-power.coverage",
        "schemaVersion": "1.0",
        "scanId": scan["id"],
        "mode": coverage_mode(scan),
        "completeness": "partial" if inventory_data.get("deferred") else "complete",
        "inventoryStrategy": "diff" if scan["mode"] == "diff" else ("repository" if scan["scope"] == "." else "scoped_path"),
        "includePaths": inventory_data.get("includePaths", [scan["scope"]]),
        "excludePaths": inventory_data.get("excludePaths", []),
        "surfaces": surfaces,
        "explicitExclusions": [{"pattern": item, "reason": "Outside canonical workspace or unsupported path"} for item in inventory_data.get("excludePaths", [])],
        "deferred": inventory_data.get("deferred", []),
        "openQuestions": [{"question": warning} for warning in inventory_data.get("warnings", [])],
    }


def build_findings_document(scan_id: str, findings: list[dict[str, Any]], writeup_paths: dict[str, str] | None = None) -> dict[str, Any]:
    writeup_paths = writeup_paths or {}
    result: list[dict[str, Any]] = []
    for item in findings:
        validation = item.get("validation")
        attack = item.get("attackPath")
        locations = item.get("locations", [])
        source = next((location for location in locations if location.get("role") == "source"), None)
        sink = next((location for location in locations if location.get("role") == "sink"), None)
        root_cause = {
            "summary": (
                f"The {item['taxonomy']['category']} boundary does not establish a safe transition before the privileged sink."
            ),
            "evidenceRefs": [evidence["id"] for evidence in item.get("codeEvidence", [])],
        }
        finding = {
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
            "locations": locations,
            "codeEvidence": item.get("codeEvidence", []),
            "rootCause": root_cause,
            "remediation": item["remediation"],
            "validation": validation,
            "attackPath": attack,
            "remediationTests": ["Add a regression test proving the original attacker-controlled input no longer reaches the sink."],
            "preventiveControls": ["Centralize the affected security boundary and block unsafe direct use in review or linting."],
            "provenance": {"source": "kiro_security_power", "engineVersion": __version__},
            "extensions": {
                "validationStatus": item.get("validationStatus"),
                "triageStatus": item.get("triageStatus"),
                "source": source,
                "sink": sink,
            },
        }
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
            f"# {item['title']}",
            "",
            f"- Finding ID: `{item['findingId']}`",
            f"- Severity: **{item['severity']['level']}**",
            f"- Confidence: **{item['confidence']['level']}**",
            f"- Validation: **{item.get('validationStatus', 'unvalidated')}**",
            "",
            "## Summary",
            "",
            item["summary"],
            "",
            "## Evidence",
            "",
        ]
        for location in locations:
            lines.append(f"- `{location['path']}:{location['startLine']}` ({location.get('role', 'evidence')})")
        if item.get("attackPath"):
            lines.extend(["", "## Attack path", "", item["attackPath"]["narrative"], "", "## Impact", "", item["attackPath"]["impact"]])
        lines.extend(["", "## Remediation", "", item["remediation"], "", "## Verification", "", item.get("validation", {}).get("rationale", "Targeted validation has not been run."), ""])
        atomic_write(path, "\n".join(lines))
        paths[item["findingId"]] = relative.as_posix()
    return paths


def _markdown_report(scan: dict[str, Any], findings: list[dict[str, Any]], coverage: dict[str, Any], threat_model: dict[str, Any]) -> str:
    counts = Counter(item["severity"]["level"] for item in findings if item.get("validationStatus") != "rejected")
    lines = [
        "# Kiro Security Power report",
        "",
        f"- Scan ID: `{scan['id']}`",
        f"- Mode: `{scan['mode']}`",
        f"- Scope: `{scan['scope']}`",
        f"- Revision: `{scan.get('target_revision') or 'filesystem snapshot'}`",
        f"- Coverage: `{coverage['completeness']}` across {scan.get('files_total', 0)} supported files",
        "",
        "## Executive summary",
        "",
    ]
    reportable = [item for item in findings if item.get("validationStatus") != "rejected" and item.get("triageStatus") not in ("false_positive", "already_fixed")]
    if reportable:
        lines.append(
            f"The scan produced {len(reportable)} reportable or review-required finding(s): "
            + ", ".join(f"{level} {counts[level]}" for level in ("critical", "high", "medium", "low", "informational") if counts[level])
            + "."
        )
    else:
        lines.append("No reportable findings remained after static validation. This does not prove the repository is vulnerability-free.")
    lines.extend(["", "## Threat model", "", threat_model["summary"], "", "## Findings", ""])
    for index, item in enumerate(reportable, start=1):
        sink = next((location for location in item.get("locations", []) if location.get("role") == "sink"), None)
        lines.extend([
            f"### {index}. {item['title']}",
            "",
            f"- ID: `{item['findingId']}`",
            f"- Severity: `{item['severity']['level']}`",
            f"- Confidence: `{item['confidence']['level']}`",
            f"- Validation: `{item.get('validationStatus')}`",
            f"- Location: `{sink['path']}:{sink['startLine']}`" if sink else "- Location: unavailable",
            "",
            item["summary"],
            "",
            f"**Remediation:** {item['remediation']}",
            "",
        ])
    lines.extend([
        "## Coverage and limitations",
        "",
        f"Inventory strategy: `{coverage['inventoryStrategy']}`. Deferred items: {len(coverage['deferred'])}.",
        "",
        "The engine performs bounded deterministic static analysis and does not execute repository build scripts or dynamic exploit payloads.",
        "",
    ])
    return "\n".join(lines)


def write_reporting_bundle(
    workbench: Workbench,
    scan_id: str,
    inventory_data: dict[str, Any],
    threat_model: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    scan = workbench.get_scan(scan_id)
    artifact_dir = Path(scan["artifact_dir"])
    artifact_dir.mkdir(parents=True, exist_ok=True)
    findings = [workbench.get_finding(item["occurrenceId"]) for item in workbench.list_findings(scan_id)]
    writeup_paths = _write_writeups(artifact_dir, findings)
    coverage = build_coverage_document(scan, inventory_data, findings)
    findings_document = build_findings_document(scan_id, findings, writeup_paths)

    discovery_document = {
        "documentType": "kiro-security-power.discovery",
        "schemaVersion": "1.0",
        "scanId": scan_id,
        "candidates": [
            {"findingId": item["findingId"], "occurrenceId": item["occurrenceId"], "ruleId": item["ruleId"], "title": item["title"], "locations": item["locations"]}
            for item in findings
        ],
    }
    validation_document = {
        "documentType": "kiro-security-power.validation",
        "schemaVersion": "1.0",
        "scanId": scan_id,
        "records": [item["validation"] for item in findings if item.get("validation")],
    }
    attack_document = {
        "documentType": "kiro-security-power.attack-paths",
        "schemaVersion": "1.0",
        "scanId": scan_id,
        "paths": [
            {"findingId": item["findingId"], "occurrenceId": item["occurrenceId"], **item["attackPath"]}
            for item in findings if item.get("attackPath")
        ],
    }

    hardening_path = artifact_dir / ARTIFACT_KINDS["hardening"]
    hardening = create_hardening_proposal(scan_id, findings, hardening_path)
    workbench.save_hardening(scan_id, hardening["title"], hardening["summary"], hardening_path)

    paths = {
        "coverage": artifact_dir / ARTIFACT_KINDS["coverage"],
        "findings": artifact_dir / ARTIFACT_KINDS["findings"],
        "markdownReport": artifact_dir / ARTIFACT_KINDS["markdownReport"],
        "discovery": artifact_dir / ARTIFACT_KINDS["discovery"],
        "validation": artifact_dir / ARTIFACT_KINDS["validation"],
        "attackPath": artifact_dir / ARTIFACT_KINDS["attackPath"],
        "hardening": hardening_path,
    }
    write_json(paths["coverage"], coverage)
    write_json(paths["findings"], findings_document)
    write_json(paths["discovery"], discovery_document)
    write_json(paths["validation"], validation_document)
    write_json(paths["attackPath"], attack_document)
    atomic_write(paths["markdownReport"], _markdown_report(scan, findings, coverage, threat_model) + "\n")

    records: list[dict[str, Any]] = []
    threat_path = artifact_dir / ARTIFACT_KINDS["threatModel"]
    if threat_path.exists():
        records.append(workbench.add_artifact(scan_id, "threatModel", threat_path, _MEDIA_TYPES["threatModel"]))
    for kind, path in paths.items():
        records.append(workbench.add_artifact(scan_id, kind, path, _MEDIA_TYPES[kind]))

    scan = workbench.get_scan(scan_id)
    artifacts_for_manifest = []
    for record in records:
        path = Path(record["path"])
        artifacts_for_manifest.append(
            {
                "path": path.relative_to(artifact_dir).as_posix(),
                "sha256": record["sha256"],
                "mediaType": record["mediaType"],
            }
        )
    completed_at = utc_now()
    manifest = {
        "documentType": "kiro-security-power.scan-manifest",
        "schemaVersion": "1.0",
        "scan": {
            "id": scan_id,
            "producer": {"name": "kiro-security-power", "version": __version__},
            "status": "completed",
            "startedAt": scan["started_at"],
            "completedAt": completed_at,
            "sealedAt": completed_at,
            "target": {
                "kind": "git_diff" if scan["mode"] == "diff" else ("git_worktree" if scan.get("target_revision") else "directory_snapshot"),
                "targetId": scan.get("snapshot_digest") or scan_id,
                "displayName": workbench.workspace.name,
                "revision": scan.get("target_revision"),
                "baseRevision": scan.get("diff_base_revision"),
                "headRevision": scan.get("diff_head_revision"),
                "snapshotDigest": scan.get("snapshot_digest"),
            },
            "scope": {
                "includePaths": coverage["includePaths"],
                "excludePaths": coverage["excludePaths"],
                "summary": f"{scan['mode']} scan of {scan['scope']}",
                "artifactsReviewed": [source.get("id") for source in coverage.get("deferred", [])],
                "runtimeStatus": "static-only",
                "validationMode": "deterministic-static-trace",
                "limitations": [question["question"] for question in coverage.get("openQuestions", [])],
            },
            "threatModel": threat_model,
            "hardening": {"portfolioPath": ARTIFACT_KINDS["hardening"]},
            "coverageRef": ARTIFACT_KINDS["coverage"],
            "findingsRef": ARTIFACT_KINDS["findings"],
            "artifacts": artifacts_for_manifest,
        },
    }
    manifest_path = artifact_dir / ARTIFACT_KINDS["manifest"]
    write_json(manifest_path, manifest)
    manifest_record = workbench.add_artifact(scan_id, "manifest", manifest_path, _MEDIA_TYPES["manifest"])
    workbench.save_manifest_digest(scan_id, sha256_file(manifest_path))
    records.append(manifest_record)
    workbench.set_coverage(scan_id, coverage)
    return records, findings_document, coverage
