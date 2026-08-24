"""Deterministic Markdown, SARIF, and CSV projections of sealed artifacts."""

from __future__ import annotations

import csv
import io
import re
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple
from urllib.parse import quote

from .scan_files import ArtifactContractError


SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/"
    "sarif-schema-2.1.0.json"
)
SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
}
REPORTABLE_SEVERITIES = frozenset(("critical", "high", "medium", "low"))
SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "informational": "note",
}
TRIAGE_STATUSES = {"open", "closed"}
CLOSE_REASONS = {"already_fixed", "wont_fix", "false_positive"}


def build_findings_csv(
    findings_document: Mapping[str, Any],
    triage_by_occurrence: Mapping[str, Mapping[str, Any]],
    deep_scan: bool = False,
) -> bytes:
    """Build deterministic spreadsheet-safe CSV from current local triage state."""

    findings = findings_document.get("findings")
    if not isinstance(findings, list):
        raise ArtifactContractError("findings.findings: expected an array")
    known_occurrences = {
        finding.get("occurrenceId")
        for finding in findings
        if isinstance(finding, dict)
    }
    unknown_triage = sorted(set(triage_by_occurrence) - known_occurrences)
    if unknown_triage:
        raise ArtifactContractError(
            "triage state references unknown occurrences: %s"
            % ", ".join(unknown_triage)
        )

    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    columns = [
        "occurrence_id",
        "finding_id",
    ]
    if deep_scan:
        columns.append("candidate_id")
    columns.extend(
        [
            "title",
            "summary",
            "severity",
            "confidence",
            "status",
            "close_reason",
            "note",
            "remediation",
            "path",
            "start_line",
            "end_line",
        ]
    )
    writer.writerow(columns)
    for finding in sorted(findings, key=lambda item: str(item.get("occurrenceId", ""))):
        if not isinstance(finding, dict):
            raise ArtifactContractError("findings.findings: entries must be objects")
        occurrence_id = str(finding["occurrenceId"])
        triage = triage_by_occurrence.get(occurrence_id, {})
        status, close_reason, note = _validate_triage(triage, occurrence_id)
        primary = _primary_location(finding)
        row: List[Any] = [
            occurrence_id,
            finding["findingId"],
        ]
        if deep_scan:
            extensions = finding.get("extensions")
            candidate_id = (
                extensions.get("candidateId") if isinstance(extensions, dict) else ""
            )
            row.append(candidate_id or "")
        row.extend(
            [
                finding["title"],
                finding["summary"],
                finding["severity"]["level"],
                finding["confidence"]["level"],
                status,
                close_reason or "",
                note or "",
                finding["remediation"],
                primary["path"],
                primary["startLine"],
                primary.get("endLine", primary["startLine"]),
            ]
        )
        writer.writerow([_csv_cell(value) for value in row])
    return output.getvalue().encode("utf-8")


def build_report_markdown(
    manifest: Mapping[str, Any],
    findings_document: Mapping[str, Any],
    coverage: Mapping[str, Any],
) -> bytes:
    """Build the required deterministic human-readable projection."""

    scan = manifest["scan"]
    target = scan["target"]
    scope = scan["scope"]
    findings = sorted(
        (
            finding
            for finding in findings_document["findings"]
            if finding["severity"]["level"] in REPORTABLE_SEVERITIES
        ),
        key=lambda finding: (
            SEVERITY_ORDER[finding["severity"]["level"]],
            finding["occurrenceId"],
            finding["title"],
        ),
    )
    severity_counts = [
        "%s: %d" % (level, sum(f["severity"]["level"] == level for f in findings))
        for level in SEVERITY_ORDER
        if any(f["severity"]["level"] == level for f in findings)
    ]
    lines = [
        "# Security Review: %s" % _markdown_text(target["displayName"]),
        "",
        "## Scope",
        "",
        _markdown_text(
            scope.get("summary")
            or "The scan reviewed the canonical include paths and exclusions below."
        ),
        "",
        "- Scan mode: %s" % _markdown_text(coverage["mode"]),
        "- Target kind: %s" % _markdown_text(target["kind"]),
        "- Target ID: %s" % _markdown_text(target["targetId"]),
        "- Inventory strategy: %s"
        % _markdown_text(coverage["inventoryStrategy"]),
        "- Included paths: %s"
        % _markdown_text(", ".join(coverage["includePaths"]) or "none"),
        "- Excluded paths: %s"
        % _markdown_text(", ".join(coverage["excludePaths"]) or "none"),
    ]
    for label, key in (
        ("Revision", "revision"),
        ("Base revision", "baseRevision"),
        ("Head revision", "headRevision"),
        ("Snapshot digest", "snapshotDigest"),
    ):
        if target.get(key):
            lines.append("- %s: %s" % (label, _markdown_text(target[key])))
    limitations = scope.get("limitations", [])
    if limitations:
        lines.extend(["", "Limitations and exclusions:"])
        lines.extend("- %s" % _markdown_text(item) for item in limitations)
    lines.extend(
        [
            "",
            "### Scan Summary",
            "",
            "| Field | Value |",
            "| --- | --- |",
            "| Reportable findings | %d |" % len(findings),
            "| Severity mix | %s |"
            % _markdown_cell(", ".join(severity_counts) or "none"),
            "| Coverage | %s |" % _markdown_cell(coverage["completeness"]),
            "",
            "Canonical artifacts: `scan-manifest.json`, `findings.json`, and "
            "`coverage.json`. This report is a deterministic projection of those files.",
            "",
            "## Threat Model",
            "",
        ]
    )
    threat_model = scan.get("threatModel")
    if isinstance(threat_model, dict):
        lines.append(
            _markdown_text(
                threat_model.get("summary")
                or "No explicit canonical threat-model summary was recorded."
            )
        )
        for heading, key in (
            ("Assets", "assets"),
            ("Trust Boundaries", "trustBoundaries"),
            ("Attacker Capabilities", "attackerCapabilities"),
            ("Security Objectives", "securityObjectives"),
            ("Assumptions", "assumptions"),
        ):
            values = threat_model.get(key)
            if isinstance(values, list) and values:
                lines.extend(["", "### %s" % heading, ""])
                lines.extend("- %s" % _markdown_text(value) for value in values)
    else:
        lines.append("No explicit canonical threat-model summary was recorded.")
    lines.extend(["", "## Findings", ""])
    if not findings:
        lines.extend(
            [
                "### No findings",
                "",
                "No reportable findings survived the canonical discovery, validation, "
                "and reportability gates.",
            ]
        )
    else:
        lines.extend(
            [
                "| Finding | Severity | Confidence | Location |",
                "| --- | --- | --- | --- |",
            ]
        )
        for number, finding in enumerate(findings, 1):
            primary = _primary_location(finding)
            location = "%s:%s" % (primary["path"], primary["startLine"])
            lines.append(
                "| [%s](#finding-%d) | %s | %s | %s |"
                % (
                    _markdown_cell(finding["title"]),
                    number,
                    _markdown_cell(finding["severity"]["level"]),
                    _markdown_cell(finding["confidence"]["level"]),
                    _markdown_cell(location),
                )
            )
        for number, finding in enumerate(findings, 1):
            primary = _primary_location(finding)
            writeup = finding.get("writeup")
            writeup_path = (
                writeup.get("reportPath") if isinstance(writeup, dict) else None
            )
            lines.extend(
                [
                    "",
                    '<a id="finding-%d"></a>' % number,
                    "",
                    "### [%d] %s" % (number, _markdown_text(finding["title"])),
                    "",
                    "| Field | Value |",
                    "| --- | --- |",
                    "| Finding ID | %s |"
                    % _markdown_cell(finding["findingId"]),
                    "| Severity | %s |"
                    % _markdown_cell(finding["severity"]["level"]),
                    "| Confidence | %s |"
                    % _markdown_cell(finding["confidence"]["level"]),
                    "| Category | %s |"
                    % _markdown_cell(finding["taxonomy"]["category"]),
                    "| CWE | %s |"
                    % _markdown_cell(", ".join(finding["taxonomy"]["cwe"]) or "none"),
                    "| Primary location | %s:%s |"
                    % (
                        _markdown_cell(primary["path"]),
                        primary["startLine"],
                    ),
                    "",
                    "#### Summary",
                    "",
                    (
                        "See the [detailed technical write-up](%s)."
                        % writeup_path
                        if writeup_path
                        else _markdown_text(finding["summary"])
                    ),
                    "",
                    "#### Validation",
                    "",
                    (
                        "See the [detailed technical write-up](%s)."
                        % writeup_path
                        if writeup_path
                        else _section_summary(
                            finding.get("validation"),
                            finding["confidence"]["rationale"],
                        )
                    ),
                    "",
                    "#### Attack Path",
                    "",
                    (
                        "See the [detailed technical write-up](%s)."
                        % writeup_path
                        if writeup_path
                        else _section_summary(
                            finding.get("attackPath"),
                            "No expanded attack-path narrative was recorded.",
                        )
                    ),
                    "",
                    "#### Remediation",
                    "",
                    (
                        "See the [detailed technical write-up](%s)."
                        % writeup_path
                        if writeup_path
                        else _markdown_text(finding["remediation"])
                    ),
                ]
            )
    hardening = scan.get("hardening")
    if isinstance(hardening, dict):
        lines.extend(
            [
                "",
                "## Structural Hardening",
                "",
                "The scan produced derived, unsealed design guidance. It does not "
                "indicate that findings have been remediated.",
                "",
                "[Open the structural hardening portfolio](%s)"
                % hardening["portfolioPath"],
            ]
        )
    surfaces = coverage.get("surfaces", [])
    if surfaces:
        lines.extend(
            [
                "",
                "## Reviewed Surfaces",
                "",
                "| Surface | Risk area | Outcome | Evidence |",
                "| --- | --- | --- | --- |",
            ]
        )
        for surface in surfaces:
            lines.append(
                "| %s | %s | %s | %s |"
                % (
                    _markdown_cell(surface["label"]),
                    _markdown_cell(surface.get("riskArea", "not recorded")),
                    _markdown_cell(surface["disposition"]),
                    _markdown_cell(", ".join(surface.get("receiptRefs", [])) or "none"),
                )
            )
    deferred = coverage.get("deferred", [])
    open_questions = coverage.get("openQuestions", [])
    if deferred or open_questions:
        lines.extend(["", "## Open Questions And Follow Up", ""])
        for item in deferred:
            lines.append(
                "- Deferred `%s`: %s"
                % (_markdown_text(item["id"]), _markdown_text(item["reason"]))
            )
        for item in open_questions:
            lines.append("- %s" % _markdown_text(item["question"]))
    return ("\n".join(lines).rstrip() + "\n").encode("utf-8")


def build_sarif(
    manifest: Mapping[str, Any],
    findings_document: Mapping[str, Any],
    source_root: Optional[Path] = None,
) -> Dict[str, Any]:
    """Build deterministic SARIF 2.1.0 from canonical findings."""

    del source_root  # Reserved for a future bounded source-line hash projection.
    scan = manifest["scan"]
    findings = sorted(
        findings_document["findings"], key=lambda item: item["occurrenceId"]
    )
    rule_ids = sorted({finding["ruleId"] for finding in findings})
    rule_index = {rule_id: index for index, rule_id in enumerate(rule_ids)}
    results: List[Dict[str, Any]] = []
    for finding in findings:
        primary = _primary_location(finding)
        related = [
            _sarif_location(location, index)
            for index, location in enumerate(finding["locations"])
            if location is not primary
        ]
        result: Dict[str, Any] = {
            "ruleId": finding["ruleId"],
            "ruleIndex": rule_index[finding["ruleId"]],
            "level": SARIF_LEVELS[finding["severity"]["level"]],
            "message": {"text": finding["summary"]},
            "locations": [_sarif_location(primary)],
            "partialFingerprints": {
                "codexSecurity/v1": finding["fingerprints"]["primary"]
            },
            "properties": {
                "category": finding["taxonomy"]["category"],
                "confidence": finding["confidence"]["level"],
                "findingId": finding["findingId"],
                "occurrenceId": finding["occurrenceId"],
                "severity": finding["severity"]["level"],
            },
        }
        extensions = finding.get("extensions")
        if isinstance(extensions, dict) and extensions.get("candidateId"):
            result["properties"]["candidateId"] = extensions["candidateId"]
        if related:
            result["relatedLocations"] = related
        results.append(result)
    run: Dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "Kiro Security",
                "version": scan["producer"]["version"],
                "rules": [
                    {
                        "id": rule_id,
                        "name": rule_id,
                        "shortDescription": {"text": rule_id},
                        "properties": {"tags": ["security"]},
                    }
                    for rule_id in rule_ids
                ],
            }
        },
        "automationDetails": {"id": scan["id"]},
        "results": results,
        "properties": {
            "codexSecuritySchemaVersion": manifest["schemaVersion"],
            "codexSecurityTargetKind": scan["target"]["kind"],
        },
    }
    target = scan["target"]
    if (
        target["kind"] == "git_revision"
        and target.get("remote")
        and target.get("revision")
    ):
        run["versionControlProvenance"] = [
            {
                "repositoryUri": target["remote"],
                "revisionId": target["revision"],
            }
        ]
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}


def validate_sarif(sarif: Mapping[str, Any]) -> None:
    if sarif.get("version") != "2.1.0":
        raise ArtifactContractError("SARIF: expected version 2.1.0")
    runs = sarif.get("runs")
    if not isinstance(runs, list) or len(runs) != 1:
        raise ArtifactContractError("SARIF: expected exactly one run")
    rule_ids = {
        rule["id"] for rule in runs[0]["tool"]["driver"].get("rules", [])
    }
    for result in runs[0].get("results", []):
        if result.get("ruleId") not in rule_ids:
            raise ArtifactContractError(
                "SARIF: result references an unknown rule"
            )
        if not result.get("partialFingerprints"):
            raise ArtifactContractError(
                "SARIF: result is missing partialFingerprints"
            )


def _sarif_location(
    location: Mapping[str, Any], location_id: Optional[int] = None
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": quote(location["path"], safe="/")},
            "region": {
                "startLine": location["startLine"],
                "endLine": location.get("endLine", location["startLine"]),
            },
        }
    }
    if location_id is not None:
        result["id"] = location_id
    if location.get("role"):
        result["message"] = {"text": location["role"]}
    return result


def _primary_location(finding: Mapping[str, Any]) -> Mapping[str, Any]:
    for location in finding["locations"]:
        if location.get("role") == "root_control":
            return location
    return finding["locations"][0]


def _validate_triage(
    triage: Mapping[str, Any], occurrence_id: str
) -> Tuple[str, Optional[str], Optional[str]]:
    if not isinstance(triage, Mapping):
        raise ArtifactContractError(
            "triage[%s]: expected an object" % occurrence_id
        )
    status = triage.get("status", "open")
    close_reason = triage.get("closeReason", triage.get("close_reason"))
    note = triage.get("note")
    if status not in TRIAGE_STATUSES:
        raise ArtifactContractError(
            "triage[%s].status: expected open or closed" % occurrence_id
        )
    if close_reason is not None and close_reason not in CLOSE_REASONS:
        raise ArtifactContractError(
            "triage[%s].closeReason: unsupported close reason" % occurrence_id
        )
    if note is not None and not isinstance(note, str):
        raise ArtifactContractError(
            "triage[%s].note: expected a string" % occurrence_id
        )
    if status == "open" and close_reason is not None:
        raise ArtifactContractError(
            "triage[%s]: open findings cannot have a close reason" % occurrence_id
        )
    if status == "closed" and close_reason is None:
        raise ArtifactContractError(
            "triage[%s]: closed findings require a close reason" % occurrence_id
        )
    if close_reason == "wont_fix" and not note:
        raise ArtifactContractError(
            "triage[%s]: wont_fix requires a note" % occurrence_id
        )
    return status, close_reason, note


def _csv_cell(value: Any) -> Any:
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'%s" % value
    return value


def _section_summary(value: Any, fallback: str) -> str:
    if isinstance(value, dict) and isinstance(value.get("summary"), str):
        return _markdown_text(value["summary"])
    if isinstance(value, str) and value.strip():
        return _markdown_text(value)
    return _markdown_text(fallback)


def _markdown_text(value: Any) -> str:
    text = " ".join(str(value).split())
    text = re.sub(r"([\\`*\[\]<>])", r"\\\1", text)
    if re.match(r"^(?:#{1,6}\s|[-*+]\s|>\s|```|\d+\.\s|\|)", text):
        return "Text: %s" % text
    return text


def _markdown_cell(value: Any) -> str:
    return _markdown_text(value).replace("|", "\\|")
