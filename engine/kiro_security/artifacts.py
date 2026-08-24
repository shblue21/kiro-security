"""Canonical scan artifacts, deterministic projections, and sealing.

This module deliberately does not perform semantic security analysis.  It
validates the artifacts authored by the scan workflow, derives stable finding
identity, seals canonical evidence, and writes reproducible projections.

The manifest is not part of its own artifact list.  ``manifest_digest`` from
``FinalizationResult`` is the external pin that the workbench stores.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple
from urllib.parse import urlsplit

from .artifact_projections import (
    REPORTABLE_SEVERITIES,
    SEVERITY_ORDER,
    build_findings_csv,
    build_report_markdown,
    build_sarif,
    validate_sarif as _validate_sarif,
)

from .scan_files import (
    ArtifactContractError,
    atomic_write,
    read_regular_file,
    require_scan_directory,
    validate_scan_relative_path,
)


SCHEMA_VERSION = "1.0"
FINGERPRINT_ALGORITHM = "codex-security/v1"
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

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]*$")
REPOSITORY_PATH_PATTERN = (
    r"^(?:\./)?(?!/)(?![A-Za-z]:)(?!.*\\)(?!.*(?:^|/)\.\.?(/|$))"
    r"(?!.*//)(?!.*[\u0000-\u001f\u007f])(?!.*\/$).+$"
)
_ID_RE = re.compile(r"^(?:csf|occ)_[a-f0-9]{24}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_SNAPSHOT_RE = re.compile(r"^codex-security-snapshot/v1:sha256:[a-f0-9]{64}$")
_FINGERPRINT_RE = re.compile(r"^codex-security/v1:sha256:[a-f0-9]{64}$")
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$"
)
_WRITEUP_RE = re.compile(r"^findings/([a-z0-9][a-z0-9._-]*)/\1\.md$")


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


def finding_authoring_schema(
    required_sections=(), required_extension_fields=()
):
    """Return the locally authored finding schema used before finalization.

    The field shapes intentionally follow Codex Security 0.1.21's scan-draft
    authoring contract. Kiro-only phase lineage is supplied by the caller.
    """

    text = {"type": "string", "minLength": 1, "pattern": r"\S"}
    text_list = {"type": "array", "items": dict(text)}
    slug = {
        "type": "string",
        "pattern": _SLUG_RE.pattern,
    }
    repository_path = {
        "type": "string",
        "minLength": 1,
        "maxLength": 4096,
        "pattern": REPOSITORY_PATH_PATTERN,
        "description": "A safe POSIX path relative to the scan target.",
    }
    location = {
        "type": "object",
        "required": ["path", "startLine"],
        "properties": {
            "path": repository_path,
            "startLine": {"type": "integer", "minimum": 1},
            "endLine": {
                "type": "integer",
                "minimum": 1,
                "description": "When present, must be greater than or equal to startLine.",
            },
            "role": dict(text),
        },
        "additionalProperties": True,
    }
    evidence = {
        "type": "object",
        "required": [
            "id",
            "label",
            "path",
            "startLine",
            "code",
            "explanation",
        ],
        "properties": {
            "id": dict(slug),
            "label": dict(text),
            "path": repository_path,
            "startLine": {"type": "integer", "minimum": 1},
            "endLine": {
                "type": "integer",
                "minimum": 1,
                "description": "When present, must be greater than or equal to startLine.",
            },
            "language": dict(text),
            "role": dict(text),
            "code": {
                **text,
                "description": "The genuine source snippet at this evidence location.",
            },
            "explanation": dict(text),
        },
        "additionalProperties": True,
    }
    evidence_section = {
        "type": "object",
        "properties": {
            "evidenceRefs": {
                **text_list,
                "description": "Every value must name an id in codeEvidence.",
            }
        },
        "additionalProperties": True,
    }
    extension_properties = {
        key: dict(text) for key in required_extension_fields
    }
    required = [
        "ruleId",
        "identity",
        "title",
        "summary",
        "severity",
        "confidence",
        "taxonomy",
        "locations",
        "remediation",
        "provenance",
    ]
    required.extend(required_sections)
    if required_extension_fields:
        required.append("extensions")

    return {
        "type": "object",
        "required": required,
        "properties": {
            "findingId": False,
            "occurrenceId": False,
            "fingerprints": False,
            "ruleId": {
                **slug,
                "description": (
                    "A stable lowercase vulnerability-family slug; CWE belongs "
                    "in taxonomy, not in ruleId."
                ),
                "examples": ["java.mqtt.server-redirect"],
            },
            "identity": {
                "type": "object",
                "required": ["anchor"],
                "properties": {
                    "anchor": {
                        **slug,
                        "description": "A stable semantic root-control anchor.",
                        "examples": ["mqtt-client-impl.pick-server"],
                    },
                    "instance": {
                        **slug,
                        "description": (
                            "An independently attackable sibling instance. Omit "
                            "this field when no instance is needed."
                        ),
                        "examples": ["connack-redirect"],
                    },
                },
                "additionalProperties": True,
            },
            "title": dict(text),
            "summary": dict(text),
            "severity": {
                "type": "object",
                "required": ["level"],
                "properties": {
                    "level": {"enum": sorted(SEVERITY_ORDER)},
                    "score": {"type": "number", "minimum": 0, "maximum": 10},
                    "scoringSystem": dict(text),
                    "vector": dict(text),
                    "rationale": dict(text),
                    "changeConditions": dict(text),
                },
                "dependentRequired": {"score": ["scoringSystem"]},
                "additionalProperties": True,
            },
            "confidence": {
                "type": "object",
                "required": ["level", "rationale"],
                "properties": {
                    "level": {"enum": sorted(CONFIDENCES)},
                    "rationale": dict(text),
                },
                "additionalProperties": True,
            },
            "taxonomy": {
                "type": "object",
                "required": ["category", "cwe"],
                "properties": {
                    "category": dict(text),
                    "cwe": {
                        **text_list,
                        "description": (
                            "Use an empty array when no CWE is established; do not "
                            "invent one."
                        ),
                    },
                },
                "additionalProperties": True,
            },
            "locations": {"type": "array", "minItems": 1, "items": location},
            "codeEvidence": {"type": "array", "items": evidence},
            "rootCause": {
                "anyOf": [
                    dict(text),
                    {
                        **evidence_section,
                        "required": ["summary"],
                        "properties": {
                            **evidence_section["properties"],
                            "summary": dict(text),
                            "code": dict(text),
                            "language": dict(text),
                        },
                    },
                ]
            },
            "validation": evidence_section,
            "attackPath": evidence_section,
            "remediation": dict(text),
            "remediationTests": text_list,
            "preventiveControls": text_list,
            "provenance": {
                "type": "object",
                "required": ["source"],
                "properties": {"source": dict(text)},
                "additionalProperties": True,
            },
            "writeup": {
                "type": "object",
                "required": ["reportPath"],
                "properties": {
                    "reportPath": {
                        "type": "string",
                        "pattern": _WRITEUP_RE.pattern,
                    }
                },
                "additionalProperties": True,
            },
            "extensions": {
                "type": "object",
                "required": list(required_extension_fields),
                "properties": extension_properties,
                "additionalProperties": True,
            },
        },
        "additionalProperties": True,
        "allOf": [
            {
                "if": {
                    "type": "object",
                    "required": ["severity"],
                    "properties": {
                        "severity": {
                            "type": "object",
                            "required": ["level"],
                            "properties": {
                                "level": {"enum": sorted(REPORTABLE_SEVERITIES)},
                            },
                        }
                    },
                },
                "then": {"required": ["writeup"]},
            }
        ],
    }


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
    if "instance" in identity and (
        not isinstance(instance, str) or not _SLUG_RE.fullmatch(instance)
    ):
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


def validate_finding_authoring(
    finding: Mapping[str, Any], context: str
) -> FindingIdentity:
    """Validate one unsealed finding while keeping derived identity server-owned."""

    if not isinstance(finding, dict):
        raise ArtifactContractError("%s: expected an object" % context)
    for key in ("findingId", "occurrenceId", "fingerprints"):
        if key in finding:
            raise ArtifactContractError(
                "%s.%s: finalizer-owned field is not accepted" % (context, key)
            )
    identity = derive_finding_identity("authoring-target", "authoring-scan", finding)
    materialized = dict(finding)
    materialized["findingId"] = identity.finding_id
    materialized["occurrenceId"] = identity.occurrence_id
    materialized["fingerprints"] = {
        "algorithm": FINGERPRINT_ALGORITHM,
        "primary": identity.fingerprint,
    }
    _validate_finding(materialized, context)
    return identity


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

    root = require_scan_directory(scan_dir)
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
        atomic_write(root, "report.md", report)
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
                read_regular_file(root, receipt),
            )
        )
    scan["artifacts"] = sorted(scan["artifacts"], key=lambda item: item["path"])
    _validate_manifest_base(manifest, require_artifacts=True)
    _validate_coverage_receipts_are_sealed(scan, coverage)
    report = build_report_markdown(manifest, findings, coverage)
    manifest_bytes = canonical_json_bytes(manifest)

    atomic_write(root, "findings.json", findings_bytes)
    atomic_write(root, "coverage.json", coverage_bytes)
    atomic_write(root, "report.md", report)
    atomic_write(root, "scan-manifest.json", manifest_bytes)
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

    root = require_scan_directory(scan_dir)
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


def has_sealed_manifest(scan_dir: Path) -> bool:
    """Return whether finalization has crossed the immutable seal boundary."""

    try:
        manifest = _read_json(require_scan_directory(scan_dir), "scan-manifest.json")
    except ArtifactContractError:
        return False
    scan = manifest.get("scan")
    return (
        isinstance(scan, dict)
        and scan.get("sealedAt") is not None
        and scan.get("artifacts") is not None
    )


def write_sarif_projection(
    scan_dir: Path, source_root: Optional[Path] = None
) -> Path:
    """Strictly validate a sealed scan and atomically write SARIF."""

    result = verify_seal(scan_dir)
    sarif = build_sarif(result.manifest, result.findings, source_root)
    _validate_sarif(sarif)
    root = require_scan_directory(scan_dir)
    atomic_write(root, "exports/results.sarif", canonical_json_bytes(sarif))
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
    root = require_scan_directory(scan_dir)
    atomic_write(root, "exports/findings.csv", content)
    return root / "exports" / "findings.csv"


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
            validate_scan_relative_path(
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
            path = validate_scan_relative_path(
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
        validate_scan_relative_path(evidence["path"], "%s.path" % evidence_context)
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
    validate_scan_relative_path(
        _required_string(value, "path", context), "%s.path" % context
    )
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
            validate_scan_relative_path(
                value, "%s[%d]" % (context, index), allow_dot=True
            )

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
            normalized = validate_scan_relative_path(
                ref, "%s.receiptRefs[%d]" % (context, ref_index)
            )
            if not normalized.startswith("artifacts/"):
                raise ArtifactContractError(
                    "%s.receiptRefs[%d]: expected a file under artifacts/"
                    % (context, ref_index)
                )
            read_regular_file(root, normalized)

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
        read_regular_file(root, path)
    hardening = manifest["scan"].get("hardening")
    if isinstance(hardening, dict):
        read_regular_file(root, hardening["portfolioPath"])


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
        path = validate_scan_relative_path(
            _required_string(artifact, "path", context), "%s.path" % context
        )
        if path in seen:
            raise ArtifactContractError("%s.path: duplicate artifact path" % context)
        seen.add(path)
        expected = _required_string(artifact, "sha256", context)
        content = (known_contents or {}).get(path)
        if content is None:
            content = read_regular_file(root, path)
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
        "path": validate_scan_relative_path(path, "artifact path"),
        "sha256": _sha256(content),
        "mediaType": media_type,
    }


def _write_sarif_best_effort(
    root: Path,
    manifest: Mapping[str, Any],
    findings: Mapping[str, Any],
    source_root: Optional[Path],
) -> Optional[Path]:
    try:
        sarif = build_sarif(manifest, findings, source_root)
        _validate_sarif(sarif)
        atomic_write(root, "exports/results.sarif", canonical_json_bytes(sarif))
    except (ArtifactContractError, OSError, TypeError, ValueError):
        return None
    return root / "exports" / "results.sarif"


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


def _read_json(root: Path, relative_path: str) -> Dict[str, Any]:
    return _read_json_with_bytes(root, relative_path)[0]


def _read_json_with_bytes(
    root: Path, relative_path: str
) -> Tuple[Dict[str, Any], bytes]:
    content = read_regular_file(root, relative_path)
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
    "has_sealed_manifest",
    "verify_seal",
    "write_csv_projection",
    "write_sarif_projection",
]
