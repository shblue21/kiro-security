"""Canonical scan artifacts, deterministic projections, and sealing.

This module deliberately does not perform semantic security analysis.  It
validates the artifacts authored by the scan workflow, derives stable finding
identity, seals canonical evidence, and writes reproducible projections.

The manifest is not part of its own artifact list.  ``manifest_digest`` from
``FinalizationResult`` is the external pin that the workbench stores.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple
from urllib.parse import quote, urlsplit


SCHEMA_VERSION = "1.0"
FINGERPRINT_ALGORITHM = "codex-security/v1"
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
SARIF_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "informational": "note",
}
CONFIDENCES = {"high", "medium", "low"}
TARGET_KINDS = {"git_revision", "git_worktree", "git_diff", "directory_snapshot"}
COVERAGE_MODES = {
    "repository",
    "scoped_path",
    "diff",
    "commit",
    "branch_diff",
    "working_tree",
    "deep_repository",
}
INVENTORY_STRATEGIES = {"repository", "scoped_path", "diff", "directory", "custom"}
COMPLETENESS = {"complete", "partial", "unknown"}
DISPOSITIONS = {
    "reported",
    "no_issue_found",
    "rejected",
    "not_applicable",
    "needs_follow_up",
}
TRIAGE_STATUSES = {"open", "closed"}
CLOSE_REASONS = {"already_fixed", "wont_fix", "false_positive"}

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]*$")
_ID_RE = re.compile(r"^(?:csf|occ)_[a-f0-9]{24}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_SNAPSHOT_RE = re.compile(r"^codex-security-snapshot/v1:sha256:[a-f0-9]{64}$")
_FINGERPRINT_RE = re.compile(r"^codex-security/v1:sha256:[a-f0-9]{64}$")
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$"
)
_WRITEUP_RE = re.compile(r"^findings/([a-z0-9][a-z0-9._-]*)/\1\.md$")


class ArtifactContractError(ValueError):
    """A canonical artifact violates the scan contract."""


@dataclass(frozen=True)
class FindingIdentity:
    """Derived logical and per-scan identities for a finding."""

    fingerprint: str
    finding_id: str
    occurrence_id: str


@dataclass(frozen=True)
class FinalizationResult:
    """Filesystem finalization result ready for the DB completion transaction."""

    manifest: Dict[str, Any]
    findings: Dict[str, Any]
    coverage: Dict[str, Any]
    manifest_digest: str
    report_path: Path
    sarif_path: Optional[Path]
    reused_seal: bool


def canonical_json_bytes(payload: Any) -> bytes:
    """Encode canonical JSON and reject NaN or infinity."""

    try:
        encoded = json.dumps(payload, allow_nan=False, indent=2, sort_keys=True)
    except (TypeError, ValueError) as exc:
        raise ArtifactContractError("cannot encode canonical JSON: %s" % exc) from exc
    return (encoded + "\n").encode("utf-8")


def derive_finding_identity(
    target_id: str, scan_id: str, finding: Mapping[str, Any]
) -> FindingIdentity:
    """Derive Codex Security v1 stable and per-scan finding identities."""

    identity = _required_object(finding, "identity", "finding")
    anchor = _required_string(identity, "anchor", "finding.identity")
    instance = identity.get("instance", "")
    rule_id = _required_string(finding, "ruleId", "finding")
    if not _SLUG_RE.fullmatch(rule_id):
        raise ArtifactContractError("finding.ruleId: expected a lowercase semantic slug")
    if not _SLUG_RE.fullmatch(anchor):
        raise ArtifactContractError(
            "finding.identity.anchor: expected a lowercase semantic slug"
        )
    if not isinstance(instance, str) or (instance and not _SLUG_RE.fullmatch(instance)):
        raise ArtifactContractError(
            "finding.identity.instance: expected a lowercase semantic slug"
        )
    material = "\0".join(
        (FINGERPRINT_ALGORITHM, target_id, rule_id, anchor, instance)
    )
    fingerprint = "%s:sha256:%s" % (
        FINGERPRINT_ALGORITHM,
        _sha256(material.encode("utf-8")),
    )
    return FindingIdentity(
        fingerprint=fingerprint,
        finding_id=_stable_id("csf", fingerprint),
        occurrence_id=_stable_id("occ", scan_id, fingerprint),
    )


def finalize_scan(
    scan_dir: Path,
    source_root: Optional[Path] = None,
    expected_coverage_mode: Optional[str] = None,
) -> FinalizationResult:
    """Validate, seal, and project one completed scan.

    New seals write ``findings.json``, ``coverage.json``, ``report.md``, then
    ``scan-manifest.json``.  Every individual replacement is atomic.  A retry
    of an existing seal verifies all digest-bound artifacts and only
    regenerates the unsealed projections.
    """

    root = _require_scan_directory(scan_dir)
    manifest = _read_json(root, "scan-manifest.json")
    scan = _required_object(manifest, "scan", "manifest")
    _validate_contract_references(scan)
    findings, findings_input = _read_json_with_bytes(root, scan["findingsRef"])
    coverage, coverage_input = _read_json_with_bytes(root, scan["coverageRef"])

    if manifest.get("schemaVersion") != SCHEMA_VERSION:
        raise ArtifactContractError(
            "manifest.schemaVersion: expected %s" % SCHEMA_VERSION
        )
    if scan.get("status") != "completed":
        raise ArtifactContractError(
            "manifest.scan.status: expected completed before sealing"
        )
    if (
        expected_coverage_mode is not None
        and coverage.get("mode") != expected_coverage_mode
    ):
        raise ArtifactContractError(
            "coverage.mode: must match selected scan mode %s"
            % expected_coverage_mode
        )

    already_sealed = scan.get("sealedAt") is not None or scan.get("artifacts") is not None
    if already_sealed:
        _validate_seal(
            root,
            scan,
            {
                str(scan["findingsRef"]): findings_input,
                str(scan["coverageRef"]): coverage_input,
            },
        )

    scan["sealedAt"] = _required_string(scan, "completedAt", "manifest.scan")
    _validate_manifest_base(manifest, require_artifacts=False)
    _enrich_findings(manifest, findings)
    _validate_findings(manifest, findings)
    _validate_coverage(manifest, coverage, root)
    _validate_derived_references(root, manifest, findings)

    if already_sealed:
        _validate_manifest_base(manifest, require_artifacts=True)
        _validate_coverage_receipts_are_sealed(scan, coverage)
        report = build_report_markdown(manifest, findings, coverage)
        _atomic_write(root, "report.md", report)
        sarif_path = _write_sarif_best_effort(root, manifest, findings, source_root)
        manifest_bytes = canonical_json_bytes(manifest)
        return FinalizationResult(
            manifest=manifest,
            findings=findings,
            coverage=coverage,
            manifest_digest="sha256:%s" % _sha256(manifest_bytes),
            report_path=root / "report.md",
            sarif_path=sarif_path,
            reused_seal=True,
        )

    findings_bytes = canonical_json_bytes(findings)
    coverage_bytes = canonical_json_bytes(coverage)
    scan["artifacts"] = [
        _artifact_record("findings.json", "application/json", findings_bytes),
        _artifact_record("coverage.json", "application/json", coverage_bytes),
    ]
    for receipt in _coverage_receipt_refs(coverage):
        scan["artifacts"].append(
            _artifact_record(
                receipt,
                "application/octet-stream",
                _read_regular_file(root, receipt),
            )
        )
    scan["artifacts"] = sorted(scan["artifacts"], key=lambda item: item["path"])
    _validate_manifest_base(manifest, require_artifacts=True)
    _validate_coverage_receipts_are_sealed(scan, coverage)
    report = build_report_markdown(manifest, findings, coverage)
    manifest_bytes = canonical_json_bytes(manifest)

    _atomic_write(root, "findings.json", findings_bytes)
    _atomic_write(root, "coverage.json", coverage_bytes)
    _atomic_write(root, "report.md", report)
    _atomic_write(root, "scan-manifest.json", manifest_bytes)
    _validate_seal(root, scan)
    sarif_path = _write_sarif_best_effort(root, manifest, findings, source_root)
    return FinalizationResult(
        manifest=manifest,
        findings=findings,
        coverage=coverage,
        manifest_digest="sha256:%s" % _sha256(manifest_bytes),
        report_path=root / "report.md",
        sarif_path=sarif_path,
        reused_seal=False,
    )


def verify_seal(scan_dir: Path) -> FinalizationResult:
    """Verify an existing seal without changing any file."""

    root = _require_scan_directory(scan_dir)
    manifest, manifest_bytes = _read_json_with_bytes(root, "scan-manifest.json")
    scan = _required_object(manifest, "scan", "manifest")
    _validate_contract_references(scan)
    findings = _read_json(root, scan["findingsRef"])
    coverage = _read_json(root, scan["coverageRef"])
    _validate_seal(root, scan)
    _validate_manifest_base(manifest, require_artifacts=True)
    _enrich_findings(manifest, findings)
    _validate_findings(manifest, findings)
    _validate_coverage(manifest, coverage, root)
    _validate_coverage_receipts_are_sealed(scan, coverage)
    _validate_derived_references(root, manifest, findings)
    return FinalizationResult(
        manifest=manifest,
        findings=findings,
        coverage=coverage,
        manifest_digest="sha256:%s" % _sha256(manifest_bytes),
        report_path=root / "report.md",
        sarif_path=(root / "exports" / "results.sarif")
        if (root / "exports" / "results.sarif").is_file()
        else None,
        reused_seal=True,
    )


def write_sarif_projection(
    scan_dir: Path, source_root: Optional[Path] = None
) -> Path:
    """Strictly validate a sealed scan and atomically write SARIF."""

    result = verify_seal(scan_dir)
    sarif = build_sarif(result.manifest, result.findings, source_root)
    _validate_sarif(sarif)
    root = _require_scan_directory(scan_dir)
    _atomic_write(root, "exports/results.sarif", canonical_json_bytes(sarif))
    return root / "exports" / "results.sarif"


def write_csv_projection(
    scan_dir: Path,
    triage_by_occurrence: Optional[Mapping[str, Mapping[str, Any]]] = None,
    deep_scan: Optional[bool] = None,
) -> Path:
    """Write CSV from sealed canonical findings plus supplied current triage state."""

    result = verify_seal(scan_dir)
    if deep_scan is None:
        deep_scan = result.coverage.get("mode") == "deep_repository" or any(
            isinstance(finding.get("extensions"), dict)
            and bool(finding["extensions"].get("candidateId"))
            for finding in result.findings["findings"]
        )
    content = build_findings_csv(
        result.findings,
        triage_by_occurrence or {},
        deep_scan=deep_scan,
    )
    root = _require_scan_directory(scan_dir)
    _atomic_write(root, "exports/findings.csv", content)
    return root / "exports" / "findings.csv"


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
            if finding["severity"]["level"] != "informational"
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


def _validate_manifest_base(
    manifest: Mapping[str, Any], require_artifacts: bool
) -> None:
    if manifest.get("documentType") != "codex-security.scan-manifest":
        raise ArtifactContractError(
            "manifest.documentType: expected codex-security.scan-manifest"
        )
    if manifest.get("schemaVersion") != SCHEMA_VERSION:
        raise ArtifactContractError(
            "manifest.schemaVersion: expected %s" % SCHEMA_VERSION
        )
    scan = _required_object(manifest, "scan", "manifest")
    for key in ("id", "startedAt", "completedAt", "sealedAt"):
        value = _required_string(scan, key, "manifest.scan")
        if key.endswith("At"):
            _validate_timestamp(value, "manifest.scan.%s" % key)
    if scan["sealedAt"] != scan["completedAt"]:
        raise ArtifactContractError(
            "manifest.scan.sealedAt: must match completedAt"
        )
    if scan.get("status") != "completed":
        raise ArtifactContractError("manifest.scan.status: expected completed")
    producer = _required_object(scan, "producer", "manifest.scan")
    _required_string(producer, "name", "manifest.scan.producer")
    _required_string(producer, "version", "manifest.scan.producer")
    _validate_target(_required_object(scan, "target", "manifest.scan"))
    scope = _required_object(scan, "scope", "manifest.scan")
    for key in ("includePaths", "excludePaths"):
        values = _required_array(scope, key, "manifest.scan.scope")
        for index, value in enumerate(values):
            if not isinstance(value, str):
                raise ArtifactContractError(
                    "manifest.scan.scope.%s[%d]: expected a string" % (key, index)
                )
            _safe_relative_path(
                value,
                "manifest.scan.scope.%s[%d]" % (key, index),
                allow_dot=True,
            )
    for key in ("summary", "runtimeStatus", "validationMode", "context"):
        _optional_nonempty_string(scope, key, "manifest.scan.scope")
    if "artifactsReviewed" in scope:
        _string_array(
            scope["artifactsReviewed"],
            "manifest.scan.scope.artifactsReviewed",
            non_empty_items=True,
        )
    if "limitations" in scope:
        _string_array(
            scope["limitations"],
            "manifest.scan.scope.limitations",
            non_empty_items=True,
        )
    _validate_contract_references(scan)
    threat_model = scan.get("threatModel")
    if threat_model is not None:
        _validate_threat_model(threat_model)
    hardening = scan.get("hardening")
    if hardening is not None:
        if not isinstance(hardening, dict) or hardening.get("portfolioPath") != (
            "hardening/hardening.md"
        ):
            raise ArtifactContractError(
                "manifest.scan.hardening.portfolioPath: expected "
                "'hardening/hardening.md'"
            )
    if require_artifacts:
        artifacts = _required_array(scan, "artifacts", "manifest.scan")
        if not artifacts:
            raise ArtifactContractError(
                "manifest.scan.artifacts: expected sealed artifact records"
            )
        seen: Set[str] = set()
        for index, artifact in enumerate(artifacts):
            context = "manifest.scan.artifacts[%d]" % index
            if not isinstance(artifact, dict):
                raise ArtifactContractError("%s: expected an object" % context)
            path = _safe_relative_path(
                _required_string(artifact, "path", context),
                "%s.path" % context,
            )
            if path in seen:
                raise ArtifactContractError("%s.path: duplicate artifact path" % context)
            seen.add(path)
            digest = _required_string(artifact, "sha256", context)
            if not _SHA256_RE.fullmatch(digest):
                raise ArtifactContractError("%s.sha256: invalid SHA-256" % context)
            _required_string(artifact, "mediaType", context)
        for required in ("findings.json", "coverage.json"):
            if required not in seen:
                raise ArtifactContractError(
                    "manifest.scan.artifacts: missing required artifact: %s"
                    % required
                )


def _validate_target(target: Mapping[str, Any]) -> None:
    kind = _required_string(target, "kind", "manifest.scan.target")
    if kind not in TARGET_KINDS:
        raise ArtifactContractError(
            "manifest.scan.target.kind: unsupported target kind: %s" % kind
        )
    _required_string(target, "targetId", "manifest.scan.target")
    _required_string(target, "displayName", "manifest.scan.target")
    remote = target.get("remote")
    if remote is not None:
        if not isinstance(remote, str):
            raise ArtifactContractError(
                "manifest.scan.target.remote: expected a string"
            )
        parsed = urlsplit(remote)
        if (
            not parsed.scheme
            or not parsed.netloc
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ArtifactContractError(
                "manifest.scan.target.remote: expected a sanitized absolute URL"
            )
    if kind == "git_revision":
        _required_string(target, "revision", "manifest.scan.target")
    else:
        digest = _required_string(target, "snapshotDigest", "manifest.scan.target")
        if not _SNAPSHOT_RE.fullmatch(digest):
            raise ArtifactContractError(
                "manifest.scan.target.snapshotDigest: invalid snapshot digest"
            )
    for key in ("revision", "baseRevision", "headRevision"):
        if key in target and not isinstance(target[key], str):
            raise ArtifactContractError(
                "manifest.scan.target.%s: expected a string" % key
            )


def _validate_threat_model(value: Any) -> None:
    if not isinstance(value, dict):
        raise ArtifactContractError("manifest.scan.threatModel: expected an object")
    _required_string(value, "summary", "manifest.scan.threatModel")
    for key in (
        "assets",
        "trustBoundaries",
        "attackerCapabilities",
        "securityObjectives",
        "assumptions",
    ):
        if key in value:
            _string_array(
                value[key],
                "manifest.scan.threatModel.%s" % key,
                non_empty_items=True,
            )


def _enrich_findings(
    manifest: Mapping[str, Any], findings_document: Dict[str, Any]
) -> None:
    scan = manifest["scan"]
    if findings_document.get("scanId") != scan["id"]:
        raise ArtifactContractError(
            "findings.scanId: must match manifest scan id"
        )
    findings = _required_array(findings_document, "findings", "findings")
    finding_ids: Set[str] = set()
    occurrence_ids: Set[str] = set()
    for index, finding in enumerate(findings):
        context = "findings.findings[%d]" % index
        if not isinstance(finding, dict):
            raise ArtifactContractError("%s: expected an object" % context)
        identity = derive_finding_identity(
            scan["target"]["targetId"], scan["id"], finding
        )
        for key, expected in (
            ("findingId", identity.finding_id),
            ("occurrenceId", identity.occurrence_id),
        ):
            if finding.get(key) not in (None, expected):
                raise ArtifactContractError(
                    "%s.%s: does not match derived identity" % (context, key)
                )
            finding[key] = expected
        expected_fingerprints = {
            "algorithm": FINGERPRINT_ALGORITHM,
            "primary": identity.fingerprint,
        }
        if finding.get("fingerprints") not in (None, expected_fingerprints):
            raise ArtifactContractError(
                "%s.fingerprints: does not match derived fingerprint" % context
            )
        finding["fingerprints"] = expected_fingerprints
        if identity.occurrence_id in occurrence_ids:
            raise ArtifactContractError(
                "%s: duplicate occurrence identity; use identity.instance" % context
            )
        finding_ids.add(identity.finding_id)
        occurrence_ids.add(identity.occurrence_id)
    if len(finding_ids) != len(occurrence_ids):
        raise ArtifactContractError(
            "findings: duplicate logical findings in one scan"
        )


def _validate_findings(
    manifest: Mapping[str, Any], findings_document: Mapping[str, Any]
) -> None:
    if findings_document.get("documentType") != "codex-security.findings":
        raise ArtifactContractError(
            "findings.documentType: expected codex-security.findings"
        )
    if findings_document.get("schemaVersion") != SCHEMA_VERSION:
        raise ArtifactContractError(
            "findings.schemaVersion: expected %s" % SCHEMA_VERSION
        )
    if findings_document.get("scanId") != manifest["scan"]["id"]:
        raise ArtifactContractError(
            "findings.scanId: must match manifest scan id"
        )
    seen_findings: Set[str] = set()
    seen_occurrences: Set[str] = set()
    for index, finding in enumerate(
        _required_array(findings_document, "findings", "findings")
    ):
        context = "findings.findings[%d]" % index
        if not isinstance(finding, dict):
            raise ArtifactContractError("%s: expected an object" % context)
        _validate_finding(finding, context)
        if (
            finding["findingId"] in seen_findings
            or finding["occurrenceId"] in seen_occurrences
        ):
            raise ArtifactContractError(
                "%s: duplicate finding or occurrence id" % context
            )
        seen_findings.add(finding["findingId"])
        seen_occurrences.add(finding["occurrenceId"])


def _validate_finding(finding: Mapping[str, Any], context: str) -> None:
    for key in (
        "findingId",
        "occurrenceId",
        "ruleId",
        "title",
        "summary",
        "remediation",
    ):
        _required_string(finding, key, context)
    if not _ID_RE.fullmatch(finding["findingId"]) or not _ID_RE.fullmatch(
        finding["occurrenceId"]
    ):
        raise ArtifactContractError("%s: invalid finding identity" % context)
    identity = _required_object(finding, "identity", context)
    _required_string(identity, "anchor", "%s.identity" % context)
    fingerprints = _required_object(finding, "fingerprints", context)
    if fingerprints.get("algorithm") != FINGERPRINT_ALGORITHM:
        raise ArtifactContractError(
            "%s.fingerprints.algorithm: unsupported algorithm" % context
        )
    primary = _required_string(
        fingerprints, "primary", "%s.fingerprints" % context
    )
    if not _FINGERPRINT_RE.fullmatch(primary):
        raise ArtifactContractError(
            "%s.fingerprints.primary: invalid fingerprint" % context
        )

    severity = _required_object(finding, "severity", context)
    severity_level = _required_string(severity, "level", "%s.severity" % context)
    if severity_level not in SEVERITY_ORDER:
        raise ArtifactContractError(
            "%s.severity.level: unsupported severity" % context
        )
    score = severity.get("score")
    if score is not None:
        if (
            isinstance(score, bool)
            or not isinstance(score, (int, float))
            or not 0 <= score <= 10
        ):
            raise ArtifactContractError(
                "%s.severity.score: expected a number from 0 through 10" % context
            )
        _required_string(severity, "scoringSystem", "%s.severity" % context)
    for key in (
        "scoringSystem",
        "vector",
        "rationale",
        "changeConditions",
    ):
        _optional_nonempty_string(severity, key, "%s.severity" % context)
    confidence = _required_object(finding, "confidence", context)
    confidence_level = _required_string(
        confidence, "level", "%s.confidence" % context
    )
    if confidence_level not in CONFIDENCES:
        raise ArtifactContractError(
            "%s.confidence.level: unsupported confidence" % context
        )
    _required_string(confidence, "rationale", "%s.confidence" % context)
    taxonomy = _required_object(finding, "taxonomy", context)
    _required_string(taxonomy, "category", "%s.taxonomy" % context)
    _string_array(
        taxonomy.get("cwe"), "%s.taxonomy.cwe" % context, non_empty_items=True
    )

    locations = _required_array(finding, "locations", context)
    if not locations:
        raise ArtifactContractError(
            "%s.locations: expected at least one location" % context
        )
    for index, location in enumerate(locations):
        _validate_location(location, "%s.locations[%d]" % (context, index))

    evidence_ids: Set[str] = set()
    code_evidence = finding.get("codeEvidence", [])
    if not isinstance(code_evidence, list):
        raise ArtifactContractError("%s.codeEvidence: expected an array" % context)
    for index, evidence in enumerate(code_evidence):
        evidence_context = "%s.codeEvidence[%d]" % (context, index)
        if not isinstance(evidence, dict):
            raise ArtifactContractError("%s: expected an object" % evidence_context)
        for key in ("id", "label", "path", "code", "explanation"):
            _required_string(evidence, key, evidence_context)
        if not _SLUG_RE.fullmatch(evidence["id"]):
            raise ArtifactContractError(
                "%s.id: expected a lowercase semantic slug" % evidence_context
            )
        _safe_relative_path(evidence["path"], "%s.path" % evidence_context)
        start = evidence.get("startLine")
        end = evidence.get("endLine", start)
        if not isinstance(start, int) or isinstance(start, bool) or start < 1:
            raise ArtifactContractError(
                "%s.startLine: expected a positive integer" % evidence_context
            )
        if not isinstance(end, int) or isinstance(end, bool) or end < start:
            raise ArtifactContractError(
                "%s.endLine: expected an integer >= startLine" % evidence_context
            )
        if evidence["id"] in evidence_ids:
            raise ArtifactContractError(
                "%s.id: duplicate code-evidence id" % evidence_context
            )
        evidence_ids.add(evidence["id"])
        for key in ("language", "role"):
            _optional_nonempty_string(evidence, key, evidence_context)
    for section_name in ("rootCause", "validation", "attackPath"):
        section = finding.get(section_name)
        if section_name == "rootCause":
            if section is not None and not isinstance(section, (dict, str)):
                raise ArtifactContractError(
                    "%s.rootCause: expected an object or string" % context
                )
            if isinstance(section, dict):
                _required_string(section, "summary", "%s.rootCause" % context)
                for key in ("code", "language"):
                    _optional_nonempty_string(
                        section, key, "%s.rootCause" % context
                    )
        elif section is not None and not isinstance(section, dict):
            raise ArtifactContractError(
                "%s.%s: expected an object or null" % (context, section_name)
            )
        if isinstance(section, dict) and "evidenceRefs" in section:
            refs = _string_array(
                section["evidenceRefs"],
                "%s.%s.evidenceRefs" % (context, section_name),
            )
            unknown = sorted(set(refs) - evidence_ids)
            if unknown:
                raise ArtifactContractError(
                    "%s.%s.evidenceRefs: unknown code-evidence ids: %s"
                    % (context, section_name, ", ".join(unknown))
                )
    for array_name in ("remediationTests", "preventiveControls"):
        if array_name in finding:
            _string_array(
                finding[array_name],
                "%s.%s" % (context, array_name),
                non_empty_items=True,
            )
    _required_string(
        _required_object(finding, "provenance", context),
        "source",
        "%s.provenance" % context,
    )
    writeup = finding.get("writeup")
    if writeup is not None:
        if not isinstance(writeup, dict):
            raise ArtifactContractError("%s.writeup: expected an object" % context)
        report_path = _required_string(writeup, "reportPath", "%s.writeup" % context)
        if not _WRITEUP_RE.fullmatch(report_path):
            raise ArtifactContractError(
                "%s.writeup.reportPath: invalid writeup path" % context
            )
    extensions = finding.get("extensions")
    if extensions is not None and not isinstance(extensions, dict):
        raise ArtifactContractError("%s.extensions: expected an object" % context)
    if isinstance(extensions, dict):
        for key in ("candidateId", "ledgerRowId", "reportId"):
            if key in extensions and (
                not isinstance(extensions[key], str) or not extensions[key]
            ):
                raise ArtifactContractError(
                    "%s.extensions.%s: expected a non-empty string" % (context, key)
                )


def _validate_location(value: Any, context: str) -> None:
    if not isinstance(value, dict):
        raise ArtifactContractError("%s: expected an object" % context)
    _safe_relative_path(_required_string(value, "path", context), "%s.path" % context)
    start = value.get("startLine")
    end = value.get("endLine", start)
    if not isinstance(start, int) or isinstance(start, bool) or start < 1:
        raise ArtifactContractError(
            "%s.startLine: expected a positive integer" % context
        )
    if not isinstance(end, int) or isinstance(end, bool) or end < start:
        raise ArtifactContractError(
            "%s.endLine: expected an integer >= startLine" % context
        )
    if "role" in value and (
        not isinstance(value["role"], str) or not value["role"]
    ):
        raise ArtifactContractError("%s.role: expected a non-empty string" % context)


def _validate_coverage(
    manifest: Mapping[str, Any],
    coverage: Mapping[str, Any],
    root: Path,
) -> None:
    if coverage.get("documentType") != "codex-security.coverage":
        raise ArtifactContractError(
            "coverage.documentType: expected codex-security.coverage"
        )
    if coverage.get("schemaVersion") != SCHEMA_VERSION:
        raise ArtifactContractError(
            "coverage.schemaVersion: expected %s" % SCHEMA_VERSION
        )
    if coverage.get("scanId") != manifest["scan"]["id"]:
        raise ArtifactContractError("coverage.scanId: must match manifest scan id")
    mode = _required_string(coverage, "mode", "coverage")
    if mode not in COVERAGE_MODES:
        raise ArtifactContractError("coverage.mode: unsupported mode: %s" % mode)
    completeness = _required_string(coverage, "completeness", "coverage")
    if completeness not in COMPLETENESS:
        raise ArtifactContractError(
            "coverage.completeness: unsupported value: %s" % completeness
        )
    strategy = _required_string(coverage, "inventoryStrategy", "coverage")
    if strategy not in INVENTORY_STRATEGIES:
        raise ArtifactContractError(
            "coverage.inventoryStrategy: unsupported value: %s" % strategy
        )
    include_paths = _string_array(coverage.get("includePaths"), "coverage.includePaths")
    exclude_paths = _string_array(coverage.get("excludePaths"), "coverage.excludePaths")
    if include_paths != manifest["scan"]["scope"]["includePaths"]:
        raise ArtifactContractError(
            "coverage.includePaths: must match manifest scope"
        )
    if exclude_paths != manifest["scan"]["scope"]["excludePaths"]:
        raise ArtifactContractError(
            "coverage.excludePaths: must match manifest scope"
        )
    for context, values in (
        ("coverage.includePaths", include_paths),
        ("coverage.excludePaths", exclude_paths),
    ):
        for index, value in enumerate(values):
            _safe_relative_path(value, "%s[%d]" % (context, index), allow_dot=True)

    surface_ids: Set[str] = set()
    needs_follow_up = False
    for index, surface in enumerate(
        _required_array(coverage, "surfaces", "coverage")
    ):
        context = "coverage.surfaces[%d]" % index
        if not isinstance(surface, dict):
            raise ArtifactContractError("%s: expected an object" % context)
        surface_id = _required_string(surface, "id", context)
        if surface_id in surface_ids:
            raise ArtifactContractError("%s.id: duplicate surface id" % context)
        surface_ids.add(surface_id)
        _required_string(surface, "label", context)
        disposition = _required_string(surface, "disposition", context)
        if disposition not in DISPOSITIONS:
            raise ArtifactContractError(
                "%s.disposition: unsupported value" % context
            )
        needs_follow_up = needs_follow_up or disposition == "needs_follow_up"
        for key in ("riskArea", "notes"):
            _optional_nonempty_string(surface, key, context)
        refs = _string_array(surface.get("receiptRefs"), "%s.receiptRefs" % context)
        for ref_index, ref in enumerate(refs):
            normalized = _safe_relative_path(
                ref, "%s.receiptRefs[%d]" % (context, ref_index)
            )
            if not normalized.startswith("artifacts/"):
                raise ArtifactContractError(
                    "%s.receiptRefs[%d]: expected a file under artifacts/"
                    % (context, ref_index)
                )
            _read_regular_file(root, normalized)

    exclusions = _required_array(coverage, "explicitExclusions", "coverage")
    for index, exclusion in enumerate(exclusions):
        context = "coverage.explicitExclusions[%d]" % index
        if not isinstance(exclusion, dict):
            raise ArtifactContractError("%s: expected an object" % context)
        _required_string(exclusion, "pattern", context)
        _required_string(exclusion, "reason", context)
    deferred = _required_array(coverage, "deferred", "coverage")
    for index, item in enumerate(deferred):
        context = "coverage.deferred[%d]" % index
        if not isinstance(item, dict):
            raise ArtifactContractError("%s: expected an object" % context)
        _required_string(item, "id", context)
        _required_string(item, "reason", context)
        if "paths" in item:
            _string_array(
                item["paths"], "%s.paths" % context, non_empty_items=True
            )
        if "surfaceIds" in item:
            _string_array(
                item["surfaceIds"],
                "%s.surfaceIds" % context,
                non_empty_items=True,
            )
    open_questions = coverage.get("openQuestions", [])
    if not isinstance(open_questions, list):
        raise ArtifactContractError("coverage.openQuestions: expected an array")
    for index, item in enumerate(open_questions):
        context = "coverage.openQuestions[%d]" % index
        if not isinstance(item, dict):
            raise ArtifactContractError("%s: expected an object" % context)
        _required_string(item, "question", context)
        _optional_nonempty_string(item, "followUpPrompt", context)
    if completeness == "complete" and (needs_follow_up or deferred):
        raise ArtifactContractError(
            "coverage.completeness: complete coverage cannot have deferred work"
        )


def _validate_derived_references(
    root: Path,
    manifest: Mapping[str, Any],
    findings_document: Mapping[str, Any],
) -> None:
    seen_writeups: Set[str] = set()
    for index, finding in enumerate(findings_document["findings"]):
        writeup = finding.get("writeup")
        if not isinstance(writeup, dict):
            continue
        path = writeup["reportPath"]
        if path in seen_writeups:
            raise ArtifactContractError(
                "findings.findings[%d].writeup.reportPath: duplicate reference" % index
            )
        seen_writeups.add(path)
        _read_regular_file(root, path)
    hardening = manifest["scan"].get("hardening")
    if isinstance(hardening, dict):
        _read_regular_file(root, hardening["portfolioPath"])


def _validate_contract_references(scan: Mapping[str, Any]) -> None:
    for key, expected in (
        ("coverageRef", "coverage.json"),
        ("findingsRef", "findings.json"),
    ):
        if _required_string(scan, key, "manifest.scan") != expected:
            raise ArtifactContractError(
                "manifest.scan.%s: expected %r" % (key, expected)
            )


def _validate_seal(
    root: Path,
    scan: Mapping[str, Any],
    known_contents: Optional[Mapping[str, bytes]] = None,
) -> None:
    if scan.get("sealedAt") != scan.get("completedAt"):
        raise ArtifactContractError(
            "manifest.scan.sealedAt: must match completedAt"
        )
    artifacts = scan.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ArtifactContractError(
            "manifest.scan.artifacts: sealed manifest requires artifact records"
        )
    seen: Set[str] = set()
    for index, artifact in enumerate(artifacts):
        context = "manifest.scan.artifacts[%d]" % index
        if not isinstance(artifact, dict):
            raise ArtifactContractError("%s: expected an object" % context)
        path = _safe_relative_path(
            _required_string(artifact, "path", context), "%s.path" % context
        )
        if path in seen:
            raise ArtifactContractError("%s.path: duplicate artifact path" % context)
        seen.add(path)
        expected = _required_string(artifact, "sha256", context)
        content = (known_contents or {}).get(path)
        if content is None:
            content = _read_regular_file(root, path)
        if _sha256(content) != expected:
            raise ArtifactContractError(
                "%s: sealed artifact changed or is missing" % context
            )


def _validate_coverage_receipts_are_sealed(
    scan: Mapping[str, Any], coverage: Mapping[str, Any]
) -> None:
    artifact_paths = {artifact["path"] for artifact in scan["artifacts"]}
    for ref in _coverage_receipt_refs(coverage):
        if ref not in artifact_paths:
            raise ArtifactContractError(
                "coverage receipt is missing from sealed artifacts: %s" % ref
            )


def _coverage_receipt_refs(coverage: Mapping[str, Any]) -> List[str]:
    refs = {
        ref
        for surface in coverage["surfaces"]
        for ref in surface.get("receiptRefs", [])
    }
    return sorted(refs)


def _artifact_record(path: str, media_type: str, content: bytes) -> Dict[str, str]:
    return {
        "path": _safe_relative_path(path, "artifact path"),
        "sha256": _sha256(content),
        "mediaType": media_type,
    }


def _validate_sarif(sarif: Mapping[str, Any]) -> None:
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


def _write_sarif_best_effort(
    root: Path,
    manifest: Mapping[str, Any],
    findings: Mapping[str, Any],
    source_root: Optional[Path],
) -> Optional[Path]:
    try:
        sarif = build_sarif(manifest, findings, source_root)
        _validate_sarif(sarif)
        _atomic_write(root, "exports/results.sarif", canonical_json_bytes(sarif))
    except (ArtifactContractError, OSError, TypeError, ValueError):
        return None
    return root / "exports" / "results.sarif"


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


def _stable_id(prefix: str, *parts: str) -> str:
    return "%s_%s" % (
        prefix,
        _sha256("\0".join(parts).encode("utf-8"))[:24],
    )


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _validate_timestamp(value: str, context: str) -> None:
    if not _RFC3339_RE.fullmatch(value):
        raise ArtifactContractError("%s: expected an RFC 3339 timestamp" % context)
    try:
        datetime.fromisoformat(value[:-1] + "+00:00" if value[-1] in "Zz" else value)
    except ValueError as exc:
        raise ArtifactContractError(
            "%s: expected an RFC 3339 timestamp" % context
        ) from exc


def _required_object(
    value: Mapping[str, Any], key: str, context: str
) -> Dict[str, Any]:
    result = value.get(key)
    if not isinstance(result, dict):
        raise ArtifactContractError("%s.%s: expected an object" % (context, key))
    return result


def _required_array(
    value: Mapping[str, Any], key: str, context: str
) -> List[Any]:
    result = value.get(key)
    if not isinstance(result, list):
        raise ArtifactContractError("%s.%s: expected an array" % (context, key))
    return result


def _required_string(value: Mapping[str, Any], key: str, context: str) -> str:
    result = value.get(key)
    if not isinstance(result, str) or not result.strip():
        raise ArtifactContractError(
            "%s.%s: expected a non-empty string" % (context, key)
        )
    return result


def _optional_nonempty_string(
    value: Mapping[str, Any], key: str, context: str
) -> None:
    if key in value and (
        not isinstance(value[key], str) or not value[key]
    ):
        raise ArtifactContractError(
            "%s.%s: expected a non-empty string" % (context, key)
        )


def _string_array(
    value: Any, context: str, non_empty_items: bool = False
) -> List[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or (non_empty_items and not item) for item in value
    ):
        raise ArtifactContractError("%s: expected an array of strings" % context)
    return value


def _safe_relative_path(
    value: str, context: str, allow_dot: bool = False
) -> str:
    if not isinstance(value, str):
        raise ArtifactContractError("%s: expected a string" % context)
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ArtifactContractError(
            "%s: expected a safe relative POSIX path" % context
        ) from exc
    path = PurePosixPath(value)
    normalized = path.as_posix()
    if (
        not value
        or (normalized == "." and not allow_dot)
        or "\\" in value
        or "\0" in value
        or path.is_absolute()
        or ".." in path.parts
    ):
        raise ArtifactContractError(
            "%s: expected a safe relative POSIX path" % context
        )
    return normalized


def _require_scan_directory(scan_dir: Path) -> Path:
    root = Path(scan_dir).absolute()
    try:
        metadata = root.lstat()
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise ArtifactContractError(
            "scan directory: expected an existing non-symlink directory"
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode) or resolved != root:
        raise ArtifactContractError(
            "scan directory: expected a canonical non-symlink directory"
        )
    return root


def _open_root(root: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(str(root), flags)
    except OSError as exc:
        raise ArtifactContractError("scan directory: could not open safely") from exc
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ArtifactContractError("scan directory: expected a directory")
    return descriptor


def _open_parent(
    root_fd: int, parts: Sequence[str], create: bool
) -> int:
    descriptor = os.dup(root_fd)
    try:
        for part in parts:
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            expected = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            if not stat.S_ISDIR(expected.st_mode):
                raise ArtifactContractError(
                    "scan-local path: expected a regular directory"
                )
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            opened = os.fstat(next_descriptor)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or (expected.st_dev, expected.st_ino) != (opened.st_dev, opened.st_ino)
            ):
                os.close(next_descriptor)
                raise ArtifactContractError(
                    "scan-local path: expected a regular directory"
                )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except (OSError, ArtifactContractError) as exc:
        os.close(descriptor)
        if isinstance(exc, ArtifactContractError):
            raise
        raise ArtifactContractError(
            "scan-local path: expected non-symlink directories"
        ) from exc


def _read_regular_file(root: Path, relative_path: str) -> bytes:
    normalized = _safe_relative_path(relative_path, relative_path)
    parts = PurePosixPath(normalized).parts
    root_fd = _open_root(root)
    parent_fd = -1
    file_fd = -1
    try:
        parent_fd = _open_parent(root_fd, parts[:-1], create=False)
        expected = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(expected.st_mode):
            raise ArtifactContractError(
                "%s: missing or unsafe regular file" % normalized
            )
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        file_fd = os.open(parts[-1], flags, dir_fd=parent_fd)
        opened = os.fstat(file_fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (expected.st_dev, expected.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise ArtifactContractError("%s: expected a regular file" % normalized)
        chunks = []
        while True:
            chunk = os.read(file_fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    except (OSError, ArtifactContractError) as exc:
        if isinstance(exc, ArtifactContractError) and str(exc).startswith(normalized):
            raise
        raise ArtifactContractError(
            "%s: missing or unsafe regular file" % normalized
        ) from exc
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
        os.close(root_fd)


def _read_json(root: Path, relative_path: str) -> Dict[str, Any]:
    return _read_json_with_bytes(root, relative_path)[0]


def _read_json_with_bytes(
    root: Path, relative_path: str
) -> Tuple[Dict[str, Any], bytes]:
    content = _read_regular_file(root, relative_path)
    try:
        payload = json.loads(content, parse_constant=_reject_non_finite)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ArtifactContractError(
            "%s: invalid JSON: %s" % (relative_path, exc)
        ) from exc
    if not isinstance(payload, dict):
        raise ArtifactContractError("%s: expected a JSON object" % relative_path)
    return payload, content


def _reject_non_finite(value: str) -> None:
    raise ValueError("non-finite JSON number %r is not supported" % value)


def _atomic_write(root: Path, relative_path: str, content: bytes) -> None:
    normalized = _safe_relative_path(relative_path, "scan-local output path")
    parts = PurePosixPath(normalized).parts
    root_fd = _open_root(root)
    parent_fd = -1
    temp_name = ".%s.%s.tmp" % (parts[-1], secrets.token_hex(8))
    try:
        parent_fd = _open_parent(root_fd, parts[:-1], create=True)
        try:
            existing = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            raise ArtifactContractError(
                "%s: expected a regular non-symlink output" % normalized
            )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        temp_fd = os.open(temp_name, flags, 0o600, dir_fd=parent_fd)
        try:
            offset = 0
            while offset < len(content):
                offset += os.write(temp_fd, content[offset:])
            os.fsync(temp_fd)
        finally:
            os.close(temp_fd)
        os.replace(temp_name, parts[-1], src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    except OSError as exc:
        raise ArtifactContractError(
            "%s: could not write atomically" % normalized
        ) from exc
    finally:
        if parent_fd >= 0:
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            os.close(parent_fd)
        os.close(root_fd)


__all__ = [
    "ArtifactContractError",
    "FinalizationResult",
    "FindingIdentity",
    "build_findings_csv",
    "build_report_markdown",
    "build_sarif",
    "canonical_json_bytes",
    "derive_finding_identity",
    "finalize_scan",
    "verify_seal",
    "write_csv_projection",
    "write_sarif_projection",
]
