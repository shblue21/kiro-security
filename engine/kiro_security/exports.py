from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

from . import __version__
from .db import Workbench
from .errors import EngineError
from .reporting import build_findings_document
from .security import atomic_write, require_export_destination, write_json

_EXTENSIONS = {"json": ".json", "csv": ".csv", "sarif": ".sarif", "markdown": ".md"}


def _sarif_level(severity: str) -> str:
    if severity in ("critical", "high"):
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def build_sarif(findings: list[dict[str, Any]]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for item in findings:
        rules.setdefault(
            item["ruleId"],
            {
                "id": item["ruleId"],
                "name": item["title"],
                "shortDescription": {"text": item["title"]},
                "fullDescription": {"text": item["summary"]},
                "help": {"text": item["remediation"]},
                "properties": {"tags": ["security", item["taxonomy"]["category"], *item["taxonomy"].get("cwe", [])]},
            },
        )
        locations = []
        for location in item.get("locations", []):
            locations.append(
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": location["path"], "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": location["startLine"], "endLine": location.get("endLine", location["startLine"])},
                    },
                    "properties": {"role": location.get("role")},
                }
            )
        results.append(
            {
                "ruleId": item["ruleId"],
                "level": _sarif_level(item["severity"]["level"]),
                "message": {"text": item["summary"]},
                "locations": locations[:1],
                "relatedLocations": locations[1:],
                "partialFingerprints": {"primaryLocationLineHash": item["fingerprint"]},
                "properties": {
                    "findingId": item["findingId"],
                    "occurrenceId": item["occurrenceId"],
                    "severity": item["severity"]["level"],
                    "confidence": item["confidence"]["level"],
                    "validationStatus": item.get("validationStatus"),
                    "triageStatus": item.get("triageStatus"),
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Kiro Security Power", "version": __version__, "rules": list(rules.values())}},
                "originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///"}},
                "results": results,
            }
        ],
    }


def _csv_text(findings: list[dict[str, Any]]) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow([
        "finding_id", "occurrence_id", "rule_id", "title", "severity", "confidence", "validation_status",
        "triage_status", "category", "cwe", "path", "line", "summary", "remediation",
    ])
    for item in findings:
        sink = next((location for location in item.get("locations", []) if location.get("role") == "sink"), None)
        writer.writerow([
            item["findingId"], item["occurrenceId"], item["ruleId"], item["title"], item["severity"]["level"],
            item["confidence"]["level"], item.get("validationStatus"), item.get("triageStatus"),
            item["taxonomy"]["category"], ",".join(item["taxonomy"].get("cwe", [])), sink["path"] if sink else "",
            sink["startLine"] if sink else "", item["summary"], item["remediation"],
        ])
    return output.getvalue()


def _markdown_text(scan: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    lines = ["# Kiro Security Power export", "", f"Scan: `{scan['id']}`", ""]
    for index, item in enumerate(findings, start=1):
        sink = next((location for location in item.get("locations", []) if location.get("role") == "sink"), None)
        lines.extend([
            f"## {index}. {item['title']}", "", f"- Finding: `{item['findingId']}`", f"- Severity: `{item['severity']['level']}`",
            f"- Validation: `{item.get('validationStatus')}`", f"- Location: `{sink['path']}:{sink['startLine']}`" if sink else "- Location: unavailable",
            "", item["summary"], "", f"Remediation: {item['remediation']}", "",
        ])
    return "\n".join(lines)


def export_report(
    workbench: Workbench,
    scan_id: str,
    format_name: str,
    *,
    destination: str | None = None,
    allowed_root: str | None = None,
    occurrence_id: str | None = None,
) -> dict[str, Any]:
    if format_name not in _EXTENSIONS:
        raise EngineError("unsupported_export", f"Unsupported export format: {format_name}")
    scan = workbench.get_scan(scan_id)
    if occurrence_id:
        finding = workbench.get_finding(occurrence_id)
        if finding["scanId"] != scan_id:
            raise EngineError("finding_scan_mismatch", "The requested finding does not belong to the requested scan.")
        findings = [finding]
        output_stem = f"finding-{finding['findingId']}"
    else:
        findings = [workbench.get_finding(item["occurrenceId"]) for item in workbench.list_findings(scan_id)]
        output_stem = "findings"
    if destination:
        if not allowed_root:
            raise EngineError("export_root_required", "An explicit allowedRoot is required for a custom export destination.")
        path = require_export_destination(destination, allowed_root)
    else:
        directory = workbench.exports_dir / scan_id
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{output_stem}{_EXTENSIONS[format_name]}"
    if path.suffix.lower() != _EXTENSIONS[format_name]:
        path = path.with_suffix(_EXTENSIONS[format_name])
    if format_name == "json":
        write_json(path, build_findings_document(scan_id, findings))
    elif format_name == "csv":
        atomic_write(path, _csv_text(findings))
    elif format_name == "sarif":
        write_json(path, build_sarif(findings))
    else:
        atomic_write(path, _markdown_text(scan, findings))
    return workbench.save_export(scan_id, format_name, path)
